#define _GNU_SOURCE
#include "previous.h"

#include "fsops.h"
#include "ident.h"

#include "belay/error.h"
#include "belay/hash.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* The first bytes of each file. `order` is 0x0102030405060708 as the writer
 * held it: an index of another byte order, record size or version is not
 * this build's, and is made again. */
struct ix_head {
    char     magic[8];
    uint64_t order;
    uint32_t rec_size, head_size;
    uint64_t n;                     /* entries */
    uint64_t paths_bytes;           /* the paths file's, after its header */
    int64_t  newest_validated_ns;   /* over every entry: nothing excluded */
    uint64_t files;
    uint32_t fine;                  /* some recorded ctime has a nanosecond part */
    uint32_t pad;
    char     sha256[72];            /* the manifest's, 64 hex digits and NULs */
};
#define ORDER_PROBE 0x0102030405060708ULL
static const char MAGIC_RECS[8] = { 'b', 'e', 'l', 'a', 'y', 'i', 'x', '1' };
static const char MAGIC_PATHS[8] = { 'b', 'e', 'l', 'a', 'y', 'p', 't', '1' };

struct prev_index {
    void *map_recs, *map_paths;
    size_t len_recs, len_paths;
    const struct ix_head *head;
    const struct prev_rec *rec;     /* n of them */
    const uint64_t *order;          /* n: the record of each sequence number */
    const char *paths;              /* head->paths_bytes */
    size_t n;
    FILE *keep[2];                  /* temporaries that live as long as the index */
};

static int nomem(void) {
    belay_err_set(BELAY_ERR_NOMEM, 0, "mark: out of memory");
    return -1;
}

/* ---- reading ---- */

static bool rec_ok(const struct prev_index *p, const struct prev_rec *r) {
    const uint64_t end = r->path_off + r->path_len + 1 + (uint64_t)r->tail_len;
    return r->path_off <= p->head->paths_bytes && end <= p->head->paths_bytes && end >= r->path_off &&
           (uint64_t)r->link_len + r->caps_len <= r->tail_len && p->paths[r->path_off + r->path_len] == '\0';
}

size_t prev_count(const struct prev_index *p) { return p == NULL ? 0 : p->n; }
const struct prev_rec *prev_at(const struct prev_index *p, size_t i) { return i < p->n ? &p->rec[i] : NULL; }
const char *prev_path(const struct prev_index *p, const struct prev_rec *r) { return p->paths + r->path_off; }

/*
 *  SEAM (capture-scale SC-M3a): an event capture will write the index of its
 *  result as the previous index and an overlay of the records it changed,
 *  "looked up first". Nothing writes one yet. When something does, the
 *  overlay is a second prev_index held here, and prev_find and
 *  prev_find_path ask it before the base (a record there for an inode or a
 *  path hides the base's).
 */
const struct prev_rec *prev_find(const struct prev_index *p, uint64_t dev, uint64_t ino) {
    if (p == NULL || p->n == 0) return NULL;
    size_t lo = 0, hi = p->n;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        const struct prev_rec *r = &p->rec[mid];
        if (r->dev < dev || (r->dev == dev && r->ino < ino)) lo = mid + 1;
        else hi = mid;
    }
    if (lo == p->n) return NULL;
    const struct prev_rec *r = &p->rec[lo];
    if (r->dev != dev || r->ino != ino) return NULL;
    /* Two entries, one inode: trusted by neither (SC-M4). */
    if (lo + 1 < p->n && p->rec[lo + 1].dev == dev && p->rec[lo + 1].ino == ino) return NULL;
    const uint32_t no = PF_RACED | PF_UNSTABLE | PF_WRITER_OPEN | PF_DISTRUST;
    if (r->type != BELAY_T_REG || !(r->flags & PF_HAS_HASH) || (r->flags & no) || !rec_ok(p, r)) return NULL;
    return r;
}

const struct prev_rec *prev_find_path(const struct prev_index *p, const char *path, size_t len) {
    if (p == NULL) return NULL;
    size_t lo = 0, hi = p->n;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (p->order[mid] >= p->n) return NULL;
        const struct prev_rec *r = &p->rec[p->order[mid]];
        if (!rec_ok(p, r)) return NULL;
        const size_t m = r->path_len < len ? r->path_len : len;
        int c = memcmp(p->paths + r->path_off, path, m);
        if (c == 0) c = (r->path_len > len) - (r->path_len < len);
        if (c == 0) return r;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

static void hex_of(const uint8_t *d, char out[65]) {
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2 * i] = H[d[i] >> 4]; out[2 * i + 1] = H[d[i] & 15]; }
    out[64] = '\0';
}
static int hexv(char c) { return c <= '9' ? c - '0' : c - 'a' + 10; }

void prev_hex(const struct prev_rec *r, char out[65]) { hex_of(r->sha256, out); }

/* Times as the manifest records them (ident.c: saturated, portable). */
bool prev_trusted(const struct prev_rec *r, const struct stat *st, int64_t reference_ns) {
    if (r == NULL) return false;
    const struct ident s = ident_of_stat(st);
    return r->dev == s.dev && r->ino == s.ino && r->mode == s.mode && r->size == s.size &&
           r->mtime_ns == s.mtime_ns && r->ctime_ns == s.ctime_ns && r->ctime_ns < reference_ns;
}

void prev_free(struct prev_index *p) {
    if (p == NULL) return;
    if (p->map_recs != NULL) munmap(p->map_recs, p->len_recs);
    if (p->map_paths != NULL) munmap(p->map_paths, p->len_paths);
    for (int i = 0; i < 2; i++)
        if (p->keep[i] != NULL) fclose(p->keep[i]);
    free(p);
}

static bool head_ok(const struct ix_head *h, const char magic[8], const char *sha256) {
    return memcmp(h->magic, magic, 8) == 0 && h->order == ORDER_PROBE && h->rec_size == sizeof(struct prev_rec) &&
           h->head_size == sizeof *h && h->sha256[64] == '\0' && (sha256 == NULL || strcmp(h->sha256, sha256) == 0);
}

/* The two files as an index, when they are one of the manifest `sha256`
 * (NULL: of any) and each is as long as its header says: else NULL, and
 * nothing is said -- a file that is not an index is made again. */
static struct prev_index *map_index(int rfd, int pfd, const char *sha256) {
    struct stat rs, ps;
    if (fstat(rfd, &rs) == -1 || fstat(pfd, &ps) == -1 || !S_ISREG(rs.st_mode) || !S_ISREG(ps.st_mode)) return NULL;
    if ((uint64_t)rs.st_size < sizeof(struct ix_head) || (uint64_t)ps.st_size < sizeof(struct ix_head)) return NULL;
    struct prev_index *p = calloc(1, sizeof *p);
    if (p == NULL) return NULL;
    p->len_recs = (size_t)rs.st_size;
    p->len_paths = (size_t)ps.st_size;
    p->map_recs = mmap(NULL, p->len_recs, PROT_READ, MAP_SHARED, rfd, 0);
    p->map_paths = mmap(NULL, p->len_paths, PROT_READ, MAP_SHARED, pfd, 0);
    if (p->map_recs == MAP_FAILED) p->map_recs = NULL;
    if (p->map_paths == MAP_FAILED) p->map_paths = NULL;
    if (p->map_recs == NULL || p->map_paths == NULL) { prev_free(p); return NULL; }
    const struct ix_head *h = p->map_recs, *hp = p->map_paths;
    const uint64_t per = sizeof(struct prev_rec) + sizeof(uint64_t);
    if (!head_ok(h, MAGIC_RECS, sha256) || !head_ok(hp, MAGIC_PATHS, h->sha256) || h->n != hp->n ||
        h->paths_bytes != hp->paths_bytes || h->n > (UINT64_MAX - sizeof *h) / per ||
        (uint64_t)p->len_recs != sizeof *h + h->n * per || (uint64_t)p->len_paths != sizeof *hp + h->paths_bytes) {
        prev_free(p);
        return NULL;
    }
    p->head = h;
    p->n = (size_t)h->n;
    p->rec = (const struct prev_rec *)(h + 1);
    p->order = (const uint64_t *)(const void *)((const char *)(h + 1) + p->n * sizeof(struct prev_rec));
    p->paths = (const char *)(hp + 1);
    return p;
}

static struct prev_index *open_named(const char *dir, const char *sha256) {
    char rp[PATH_MAX + 96], pp[PATH_MAX + 96];
    snprintf(rp, sizeof rp, "%s/%s.recs", dir, sha256);
    snprintf(pp, sizeof pp, "%s/%s.paths", dir, sha256);
    const int rfd = open(rp, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    const int pfd = rfd == -1 ? -1 : open(pp, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct prev_index *p = pfd == -1 ? NULL : map_index(rfd, pfd, sha256);
    if (rfd != -1) close(rfd);
    if (pfd != -1) close(pfd);
    return p;
}

int prev_file_sha256(const char *path, char hex[65]) {
    const int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    static const size_t CHUNK = 1u << 18;
    unsigned char *buf = fd == -1 ? NULL : malloc(CHUNK);
    if (buf == NULL) {
        if (fd != -1) close(fd);
        belay_err_set(fd == -1 ? BELAY_ERR_IO : BELAY_ERR_NOMEM, errno, "mark: cannot read %s", path);
        return -1;
    }
    struct belay_sha256 c;
    belay_sha256_init(&c);
    ssize_t k;
    for (;;) {
        k = read(fd, buf, CHUNK);
        if (k == -1 && errno == EINTR) continue;
        if (k <= 0) break;
        belay_sha256_update(&c, buf, (size_t)k);
    }
    const int e = errno;
    close(fd);
    free(buf);
    if (k == -1) {
        belay_err_set(BELAY_ERR_IO, e, "mark: cannot read %s", path);
        return -1;
    }
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_final(&c, d);
    hex_of(d, hex);
    return 0;
}

/* ---- building ---- */

struct ixb {
    char dir[PATH_MAX];
    bool named;
    char tmp_recs[PATH_MAX + 64], tmp_paths[PATH_MAX + 64];
    bool live_recs, live_paths;
    FILE *paths, *recs;
    struct runs *runs;
    runs_tmpfile_fn tmp;
    void *tmp_ctx;
    struct ix_head h;
    uint64_t at;                /* bytes of the paths file so far, its header aside */
};

/* Everything in the directory but `keep_a` and `keep_b`: an index of
 * another manifest, what a killed run left. */
static void sweep(const char *dir, const char *keep_a, const char *keep_b) {
    DIR *d = opendir(dir);
    if (d == NULL) return;
    for (struct dirent *e; (e = readdir(d)) != NULL;) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if ((keep_a != NULL && strcmp(e->d_name, keep_a) == 0) || (keep_b != NULL && strcmp(e->d_name, keep_b) == 0))
            continue;
        char p[PATH_MAX + 300];
        snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        unlink(p);
    }
    closedir(d);
}

static FILE *create_in(const char *path) {
    unlink(path);
    const int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    FILE *f = fd == -1 ? NULL : fdopen(fd, "w+b");
    if (f == NULL && fd != -1) close(fd);
    return f;
}

struct ixb *ixb_new(const char *dir, runs_tmpfile_fn tmp, void *tmp_ctx, size_t run_bytes) {
    struct ixb *b = calloc(1, sizeof *b);
    if (b == NULL) { nomem(); return NULL; }
    b->tmp = tmp;
    b->tmp_ctx = tmp_ctx;
    b->h.newest_validated_ns = INT64_MIN;
    if (dir != NULL) {
        if (strlen(dir) >= sizeof b->dir) {
            belay_err_set(BELAY_ERR_RANGE, 0, "mark: the index directory's path is too long");
            free(b);
            return NULL;
        }
        snprintf(b->dir, sizeof b->dir, "%s", dir);
        b->named = true;
        if (mkdir(dir, 0700) == -1 && errno != EEXIST) {
            belay_err_set(BELAY_ERR_IO, errno, "mark: cannot create %s", dir);
            free(b);
            return NULL;
        }
        snprintf(b->tmp_recs, sizeof b->tmp_recs, "%s/tmp.%ld.recs", dir, (long)getpid());
        snprintf(b->tmp_paths, sizeof b->tmp_paths, "%s/tmp.%ld.paths", dir, (long)getpid());
        b->paths = create_in(b->tmp_paths);
        b->live_paths = b->paths != NULL;
        b->recs = b->paths == NULL ? NULL : create_in(b->tmp_recs);
        b->live_recs = b->recs != NULL;
    } else {
        b->paths = tmp(tmp_ctx);
        b->recs = b->paths == NULL ? NULL : tmp(tmp_ctx);
    }
    if (b->recs == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "mark: cannot create the previous checkpoint's index%s%s",
                      dir != NULL ? " in " : "", dir != NULL ? dir : "");
        ixb_free(b);
        return NULL;
    }
    b->runs = runs_new(run_bytes == 0 ? (size_t)4 << 20 : run_bytes, 24, sizeof(struct prev_rec), tmp, tmp_ctx);
    if (b->runs == NULL || fwrite(&b->h, sizeof b->h, 1, b->paths) != 1) {
        if (b->runs != NULL) belay_err_set(BELAY_ERR_IO, errno, "mark: cannot write the previous checkpoint's index");
        ixb_free(b);
        return NULL;
    }
    return b;
}

void ixb_free(struct ixb *b) {
    if (b == NULL) return;
    if (b->paths != NULL) fclose(b->paths);
    if (b->recs != NULL) fclose(b->recs);
    if (b->live_paths) unlink(b->tmp_paths);
    if (b->live_recs) unlink(b->tmp_recs);
    runs_free(b->runs);
    free(b);
}

static void be64(unsigned char *o, uint64_t v) {
    for (int i = 7; i >= 0; i--) { o[i] = (unsigned char)v; v >>= 8; }
}

int ixb_add(struct ixb *b, const struct belay_entry *e) {
    /* A mount root's times are the mounted filesystem's (manifest-v1): they
     * say nothing of the scope's clock, as R or as its grain (review
     * 2026-11-01, D1). */
    if (!e->is_mount && e->ctime_ns % 1000000000 != 0) b->h.fine = 1;
    if (!e->is_mount && !e->raced && !e->unstable && !e->unreadable && e->ctime_ns > b->h.newest_validated_ns)
        b->h.newest_validated_ns = e->ctime_ns;
    struct prev_rec r;
    memset(&r, 0, sizeof r);
    r.dev = e->dev;
    r.ino = e->ino;
    r.seq = b->h.n;
    r.path_off = b->at;
    r.size = e->size;
    r.mtime_ns = e->mtime_ns;
    r.ctime_ns = e->ctime_ns;
    r.nlink = e->nlink;
    r.iflags = e->iflags;
    r.rdev = e->rdev;
    r.path_len = (uint32_t)e->path_len;
    r.mode = e->mode;
    r.uid = e->uid;
    r.gid = e->gid;
    r.type = (uint16_t)e->type;
    r.flags = (e->has_iflags ? PF_HAS_IFLAGS : 0) | (e->has_caps ? PF_HAS_CAPS : 0) | (e->has_xattrs ? PF_HAS_XATTRS : 0) |
              (e->xattrs_inline ? PF_XATTRS_INLINE : 0) | (e->xattrs_unknown ? PF_XATTRS_UNKNOWN : 0) |
              (e->has_hash ? PF_HAS_HASH : 0) | (e->unverified ? PF_UNVERIFIED : 0) |
              (e->has_link_target ? PF_HAS_LINK : 0) | (e->target_outside_scope ? PF_TARGET_OUTSIDE : 0) |
              (e->has_stored ? PF_HAS_STORED : 0) | (e->is_mount ? PF_MOUNT : 0) | (e->has_rdev ? PF_HAS_RDEV : 0) |
              (e->unstable ? PF_UNSTABLE : 0) | (e->unreadable ? PF_UNREADABLE : 0) | (e->raced ? PF_RACED : 0) |
              (e->writer_open ? PF_WRITER_OPEN : 0) | (e->not_read ? PF_NOT_READ : 0) | (e->partial ? PF_PARTIAL : 0) |
              (e->meta ? PF_META : 0) | (e->sealed ? PF_SEALED : 0);
    if (e->has_hash)                        /* the reader and the writer checked: 64 lowercase hex digits */
        for (int k = 0; k < 32; k++)
            r.sha256[k] = (uint8_t)(hexv(e->sha256_hex[2 * k]) << 4 | hexv(e->sha256_hex[2 * k + 1]));
    const size_t caps = e->has_caps ? strlen(e->caps_hex) : 0;
    const size_t link = e->has_link_target ? e->link_target_len : 0;
    const size_t xsha = e->has_xattrs ? 64 : 0, xin = e->xattrs_inline ? e->xattrs_len : 0;
    r.link_len = (uint32_t)link;
    r.caps_len = (uint16_t)caps;
    r.tail_len = (uint32_t)(link + caps + xsha + xin);
    if (e->type == BELAY_T_REG && e->has_hash && !e->raced && !e->unstable && !e->writer_open) b->h.files++;
    if (fwrite(e->path, 1, e->path_len, b->paths) != e->path_len || fputc('\0', b->paths) == EOF ||
        fwrite(e->link_target, 1, link, b->paths) != link || fwrite(e->caps_hex, 1, caps, b->paths) != caps ||
        fwrite(e->xattrs_sha256_hex, 1, xsha, b->paths) != xsha || fwrite(e->xattrs, 1, xin, b->paths) != xin) {
        belay_err_set(BELAY_ERR_IO, errno, "mark: cannot write the previous checkpoint's index");
        return -1;
    }
    b->at += e->path_len + 1 + r.tail_len;
    unsigned char key[24];
    be64(key, r.dev);
    be64(key + 8, r.ino);
    be64(key + 16, r.seq);
    if (runs_add(b->runs, key, sizeof key, &r, sizeof r) == -1) return -1;
    b->h.n++;
    return 0;
}

static int cannot_write(void) {
    belay_err_set(BELAY_ERR_IO, errno, "mark: cannot write the previous checkpoint's index");
    return -1;
}

int ixb_finish(struct ixb *b, const char *sha256, ixb_racy_fn racy, void *racy_ctx, struct prev_index **out) {
    if (out != NULL) *out = NULL;
    if (strlen(sha256) != 64) {
        belay_err_set(BELAY_ERR_INTERNAL, 0, "mark: internal error: an index of no manifest");
        return -1;
    }
    memcpy(b->h.sha256, sha256, 64);
    b->h.order = ORDER_PROBE;
    b->h.rec_size = sizeof(struct prev_rec);
    b->h.head_size = sizeof b->h;
    b->h.paths_bytes = b->at;
    /* The paths file: its header now that it is known. */
    memcpy(b->h.magic, MAGIC_PATHS, 8);
    if (fflush(b->paths) != 0 || fseek(b->paths, 0, SEEK_SET) != 0 || fwrite(&b->h, sizeof b->h, 1, b->paths) != 1 ||
        fflush(b->paths) != 0)
        return cannot_write();
    /* The records file, written through a mapping of it: each record at its
     * place in the sort, and at its sequence number where that is. A
     * mapping of a file is no heap. */
    memcpy(b->h.magic, MAGIC_RECS, 8);
    const size_t n = (size_t)b->h.n;
    const size_t len = sizeof b->h + n * (sizeof(struct prev_rec) + sizeof(uint64_t));
    const int rfd = fileno(b->recs);
    if (ftruncate(rfd, (off_t)len) == -1) return cannot_write();
    char *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, rfd, 0);
    if (map == MAP_FAILED) return cannot_write();
    memcpy(map, &b->h, sizeof b->h);
    struct prev_rec *rec = (struct prev_rec *)(void *)(map + sizeof b->h);
    uint64_t *order = (uint64_t *)(void *)(map + sizeof b->h + n * sizeof(struct prev_rec));
    int rc = -1;
    if (runs_seal(b->runs) == -1 || runs_rewind(b->runs) == -1) goto unmap;
    const unsigned char *key, *val;
    uint32_t klen, vlen;
    size_t i = 0;
    int got;
    while ((got = runs_next(b->runs, &key, &klen, &val, &vlen)) == 1) {
        if (i >= n || vlen != sizeof(struct prev_rec)) {
            belay_err_set(BELAY_ERR_INTERNAL, 0, "mark: internal error: the index's sort gave another count");
            goto unmap;
        }
        memcpy(&rec[i], val, sizeof rec[i]);
        if (rec[i].seq >= n) {
            belay_err_set(BELAY_ERR_INTERNAL, 0, "mark: internal error: an index record out of sequence");
            goto unmap;
        }
        order[rec[i].seq] = i;
        i++;
    }
    if (got == -1) goto unmap;
    if (i != n) {
        belay_err_set(BELAY_ERR_INTERNAL, 0, "mark: internal error: the index's sort gave another count");
        goto unmap;
    }
    /* V5-E7, V5-A2: an entry the manifest names racy is never trusted. The
     * racy lines follow the entries, so each is found by its path now. */
    if (racy != NULL) {
        struct prev_index *w = map_index(rfd, fileno(b->paths), NULL);
        if (w == NULL) { cannot_write(); goto unmap; }
        const char *path;
        size_t pl;
        for (size_t k = 0; (pl = racy(racy_ctx, k, &path)) != 0; k++) {
            const struct prev_rec *r = prev_find_path(w, path, pl);
            if (r != NULL) rec[r - w->rec].flags |= PF_DISTRUST;
        }
        prev_free(w);
    }
    rc = 0;
unmap:
    if (rc == 0 && b->named && msync(map, len, MS_SYNC) != 0) rc = cannot_write();
    munmap(map, len);
    if (rc == -1) return -1;
    if (!b->named) {
        if (out == NULL) return 0;
        *out = map_index(rfd, fileno(b->paths), sha256);
        if (*out == NULL) return cannot_write();
        (*out)->keep[0] = b->recs;              /* anonymous: they live as long as the index */
        (*out)->keep[1] = b->paths;
        b->recs = b->paths = NULL;
        return 0;
    }
    /* Durable before they have their names: an index is trusted for hashes. */
    char rn[80], pn[80], rp[PATH_MAX + 96], pp[PATH_MAX + 96];
    snprintf(rn, sizeof rn, "%s.recs", sha256);
    snprintf(pn, sizeof pn, "%s.paths", sha256);
    snprintf(rp, sizeof rp, "%s/%s", b->dir, rn);
    snprintf(pp, sizeof pp, "%s/%s", b->dir, pn);
    if (fsync(rfd) != 0 || fsync(fileno(b->paths)) != 0) return cannot_write();
    if (rename(b->tmp_paths, pp) != 0) return cannot_write();
    b->live_paths = false;
    if (rename(b->tmp_recs, rp) != 0) {
        cannot_write();
        unlink(pp);
        return -1;
    }
    b->live_recs = false;
    const int dfd = open(b->dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd != -1) {
        if (fsync(dfd) != 0) { /* in place; only its durability is in doubt */ }
        close(dfd);
    }
    sweep(b->dir, rn, pn);
    if (out != NULL) {
        *out = open_named(b->dir, sha256);
        if (*out == NULL) return cannot_write();
    }
    return 0;
}

/* ---- the previous manifest's ---- */

/* Whether `path` is at or below a path this capture excludes (opts). */
static bool now_excluded(const struct belay_manifest_opts *opts, const char *path, size_t len) {
    for (size_t i = 0; i < opts->n_exclude_paths; i++) {
        const size_t n = strlen(opts->exclude_paths[i]);
        if (len >= n && memcmp(path, opts->exclude_paths[i], n) == 0 && (len == n || path[n] == '/'))
            return true;
    }
    return false;
}

static size_t racy_of_reader(void *ctx, size_t i, const char **path) { return belay_manifest_racy(ctx, i, path); }

/* Whether the index of `sha256` in `dir` is missing or was written before
 * the manifest at `path` last was. */
static bool index_older(const char *dir, const char *sha256, const char *path) {
    static const char *const PART[] = { "recs", "paths" };
    struct stat ms, is;
    if (stat(path, &ms) == -1) return true;
    const struct ident m = ident_of_stat(&ms);
    for (int i = 0; i < 2; i++) {
        char ip[PATH_MAX + 96];
        snprintf(ip, sizeof ip, "%s/%s.%s", dir, sha256, PART[i]);
        if (lstat(ip, &is) == -1 || ident_of_stat(&is).mtime_ns < m.mtime_ns) return true;
    }
    return false;
}

/* The index of the manifest `rd` reads, built from its entries. 0; 1 when
 * the manifest cannot be read; -1. */
static int build(struct belay_manifest_reader *rd, const struct belay_manifest_opts *opts, runs_tmpfile_fn tmp,
                 void *tmp_ctx, struct prev_index **out) {
    struct ixb *b = ixb_new(opts->index_dir, tmp, tmp_ctx, opts->run_bytes);     /* 0: the default budget */
    struct belay_entry *e = b == NULL ? NULL : malloc(sizeof *e);
    if (e == NULL) {
        if (b != NULL) nomem();
        ixb_free(b);
        return -1;
    }
    int got, rc = 0;
    while ((got = belay_manifest_next(rd, e)) == 1)
        if (ixb_add(b, e) == -1) { rc = -1; break; }
    free(e);
    char sha[65];
    if (rc == 0 && (got == -1 || belay_manifest_digest(rd, sha) == -1)) {
        belay_err_clear();
        rc = 1;
    }
    if (rc == 0) rc = ixb_finish(b, sha, racy_of_reader, rd, out);
    ixb_free(b);
    return rc;
}

int prev_load(const struct fsops *ops, const char *path, const char *scope, uint64_t root_dev,
              const struct belay_manifest_opts *opts, runs_tmpfile_fn tmp, void *tmp_ctx,
              struct prev_index **out, struct prev_info *info, const char **why) {
    (void)ops;
    (void)root_dev;
    *out = NULL;
    *why = NULL;
    memset(info, 0, sizeof *info);
    info->newest_validated_ns = INT64_MIN;
    struct belay_manifest_reader *rd = NULL;
    if (belay_manifest_open(path, &rd) == -1) {
        belay_err_clear();
        *why = "the previous checkpoint cannot be read";
        return 1;
    }
    const struct belay_manifest_header *h = belay_manifest_header(rd);
    if (strcmp(h->scope, scope) != 0) { *why = "the previous checkpoint is of another scope"; goto refuse; }
    if (h->hash_max_bytes != opts->hash_max_bytes || h->store_max_bytes != opts->store_max_bytes) {
        *why = "the previous checkpoint used other limits";
        goto refuse;
    }
    info->hash_max_bytes = h->hash_max_bytes;
    info->walk_start_ns = h->walk_start_ns;              /* v2's header; 0 for v1 (one source) */
    info->store_max_bytes = h->store_max_bytes;
    memcpy(info->sealed_key, h->sealed_key, sizeof info->sealed_key);

    /* The index kept for this very manifest, or one built now (SC-M3a). The
     * sha256 the caller has recorded for the manifest is taken for the
     * file's only while the index is not older than the file (SC-M3): a
     * manifest written since is read for its own. */
    struct prev_index *p = NULL;
    if (opts->index_dir != NULL) {
        char sha[65];
        if (opts->previous_sha256 != NULL && strlen(opts->previous_sha256) == 64 &&
            !index_older(opts->index_dir, opts->previous_sha256, path))
            memcpy(sha, opts->previous_sha256, 65);
        else if (prev_file_sha256(path, sha) == -1) {
            belay_err_clear();
            *why = "the previous checkpoint cannot be read";
            goto refuse;
        }
        p = open_named(opts->index_dir, sha);
    }
    if (p == NULL) {
        const int rc = build(rd, opts, tmp, tmp_ctx, &p);
        if (rc != 0) {
            belay_manifest_close(rd);
            if (rc == 1) *why = "the previous checkpoint cannot be read";
            return rc;
        }
        info->built = true;
    }
    belay_manifest_close(rd);

    info->files = (size_t)p->head->files;
    info->newest_validated_ns = p->head->newest_validated_ns;
    /* A path excluded now is not walked now: its ctime cannot be this
     * walk's newest, so it is no measure of the clock going backwards
     * (review 2026-11-02, S2: an exclude added after the newest file read
     * as "ctime went backwards"). The header's newest is over every entry. */
    if (opts->n_exclude_paths > 0) {
        info->newest_validated_ns = INT64_MIN;
        for (size_t i = 0; i < p->n; i++) {
            const struct prev_rec *r = &p->rec[i];
            if ((r->flags & (PF_MOUNT | PF_RACED | PF_UNSTABLE | PF_UNREADABLE)) || r->ctime_ns <= info->newest_validated_ns)
                continue;
            if (rec_ok(p, r) && !now_excluded(opts, prev_path(p, r), r->path_len)) info->newest_validated_ns = r->ctime_ns;
        }
    }
    /* R: the previous walk's start on the scope's clock, when its header says (v2);
     * else its newest validated ctime (decision Q2's fallback). That fallback
     * misses a same-size rewrite made during the previous walk in its file's
     * own tick, which needs coarse timestamps: when every recorded ctime has
     * a zero nanosecond part (whole seconds), every file is read instead
     * (decision 2026-11-01, 2). Timestamps coarse at a kernel tick or 10 ms
     * carry a nanosecond part and are not caught: there the fallback can
     * still miss that rewrite (review 2026-11-01, D1; left to the author). */
    if (info->walk_start_ns <= 0 && !p->head->fine) {
        prev_free(p);
        *why = "the previous walk's start is unknown and the scope's timestamps are coarse";
        return 1;
    }
    info->reference_ns = info->walk_start_ns > 0 ? info->walk_start_ns : info->newest_validated_ns;
    *out = p;
    return 0;
refuse:
    belay_manifest_close(rd);
    return 1;
}
