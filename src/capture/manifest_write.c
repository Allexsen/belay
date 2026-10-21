/*
 *  Manifest writer.
 *
 *  BLAST RADIUS. Reads the user's real filesystem; writes only its own
 *  manifest file and unlinked temporaries beside it. Containment is by
 *  construction (BELAY_DESIGN.md §5.1.1):
 *
 *    - realpath() runs exactly once, on the scope, then the result is opened
 *      as a dirfd and never used as a string again.
 *    - Every descent is openat(parent_fd, name, O_DIRECTORY|O_NOFOLLOW|...).
 *      O_NOFOLLOW means a directory replaced by a symlink mid-walk fails with
 *      ELOOP rather than redirecting the walk.
 *    - Every stat is fstatat(parent_fd, name, ..., AT_SYMLINK_NOFOLLOW), so a
 *      symlink is described as a symlink and never followed.
 *    - st_dev is compared against the scope root's. A boundary is recorded and
 *      not descended into.
 *
 *  MEMORY IS BOUNDED, independent of entry count. Each entry is serialized as
 *  it is visited and appended to an in-memory run buffer of RUN_BYTES. A full
 *  buffer is sorted by raw path bytes and spilled to an unlinked temporary
 *  file. Runs are kept by level: FANIN runs at one level merge into one run at
 *  the next, so each byte is rewritten about log16(runs) times and open
 *  descriptors stay bounded. At the end the remaining runs are merged into the
 *  output. Peak memory is roughly RUN_BYTES plus FANIN merge cursors.
 *  (Earlier designs held every entry in RAM at ~8.4 KB each, then re-merged one
 *  ever-growing run at every cascade; independent review defects 4 and 6.)
 *
 *  The output is written to a temporary name and renamed into place, so a
 *  crash or a full disk never leaves a partial manifest at `out_path`.
 */
#define _GNU_SOURCE

#include "belay/manifest.h"
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/interp.h"
#include "belay/json.h"
#include "belay/path.h"
#include "belay/store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/sysmacros.h>
#endif
#include <time.h>
#include <unistd.h>

#define MAX_DEPTH  128
#define READ_CHUNK (64u * 1024u)
#define PATH_CAP   4096u               /* == sizeof(struct belay_entry).path */
#define LINE_CAP   (64u * 1024u)       /* one serialized entry; worst case < 50 KB */
#define RUN_BYTES  (4u * 1024u * 1024u)
#define FANIN      16
#define LEVELS     12                  /* 16^12 runs: unreachable in practice */
#define SNIFF_BYTES 8000u              /* git's binary heuristic: a NUL in the
                                          first 8000 bytes means not text */

/* ------------------------------------------------------------------------ */
/* Serialization                                                             */
/* ------------------------------------------------------------------------ */

static int ap(char *buf, size_t cap, size_t *w, const char *fmt, ...) {
    va_list a;
    va_start(a, fmt);
    const int n = vsnprintf(buf + *w, cap - *w, fmt, a);
    va_end(a);
    if (n < 0 || (size_t)n >= cap - *w) {
        belay_err_set(BELAY_ERR_RANGE, 0, "manifest: entry exceeds %zu bytes", cap);
        return -1;
    }
    *w += (size_t)n;
    return 0;
}

/* Appends `len` raw bytes as a JSON string value under `key`, or as base64
 * under `key_b64` when they are not valid UTF-8. */
static int ap_bytes(char *buf, size_t cap, size_t *w, const char *key,
                    const char *key_b64, const char *bytes, size_t len) {
    if (belay_utf8_valid(bytes, len)) {
        if (ap(buf, cap, w, "\"%s\":\"", key) == -1) return -1;
        if (belay_json_escape(buf + *w, cap - *w, bytes, len) == -1) return -1;
    } else {
        if (ap(buf, cap, w, "\"%s\":\"", key_b64) == -1) return -1;
        if (belay_base64_encode(buf + *w, cap - *w, bytes, len) == -1) return -1;
    }
    *w += strlen(buf + *w);
    return ap(buf, cap, w, "\"");
}

static const char *type_name(enum belay_entry_type t) {
    switch (t) {
    case BELAY_T_REG:  return "reg";
    case BELAY_T_DIR:  return "dir";
    case BELAY_T_LNK:  return "lnk";
    case BELAY_T_FIFO: return "fifo";
    case BELAY_T_SOCK: return "sock";
    case BELAY_T_BLK:  return "blk";
    default:           return "chr";
    }
}

/* One entry as one NDJSON line, newline included. */
static int serialize(const struct belay_entry *e, char *buf, size_t cap, size_t *len) {
    size_t w = 0;
    if (ap(buf, cap, &w, "{") == -1) return -1;
    if (ap_bytes(buf, cap, &w, "path", "path_b64", e->path, e->path_len) == -1) return -1;

    if (ap(buf, cap, &w,
           ",\"type\":\"%s\",\"mode\":%u,\"uid\":%u,\"gid\":%u"
           ",\"size\":%llu,\"mtime_ns\":%lld,\"ctime_ns\":%lld"
           ",\"ino\":%llu,\"dev\":%llu,\"nlink\":%llu",
           type_name(e->type), e->mode, e->uid, e->gid,
           (unsigned long long)e->size, (long long)e->mtime_ns, (long long)e->ctime_ns,
           (unsigned long long)e->ino, (unsigned long long)e->dev,
           (unsigned long long)e->nlink) == -1) return -1;

    if (e->has_hash && ap(buf, cap, &w, ",\"sha256\":\"%s\"", e->sha256_hex) == -1) return -1;
    if (e->unverified && ap(buf, cap, &w, ",\"unverified\":true") == -1) return -1;
    if (e->unstable && ap(buf, cap, &w, ",\"unstable\":true") == -1) return -1;
    if (e->has_rdev &&
        ap(buf, cap, &w, ",\"rdev\":%llu", (unsigned long long)e->rdev) == -1) return -1;

    if (e->has_link_target) {
        if (ap(buf, cap, &w, ",") == -1) return -1;
        if (ap_bytes(buf, cap, &w, "link_target", "link_target_b64",
                     e->link_target, e->link_target_len) == -1) return -1;
        if (e->target_outside_scope &&
            ap(buf, cap, &w, ",\"target_outside_scope\":true") == -1) return -1;
    }

    if (e->has_stored && ap(buf, cap, &w, ",\"stored\":\"%s\"", e->stored_hex) == -1) return -1;
    if (e->is_mount && ap(buf, cap, &w, ",\"mount\":true") == -1) return -1;
    if (e->unreadable && ap(buf, cap, &w, ",\"unreadable\":true") == -1) return -1;

    if (ap(buf, cap, &w, "}\n") == -1) return -1;
    *len = w;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Spill: bounded-memory external sort                                      */
/* ------------------------------------------------------------------------ */

/*
 *  A record is [u32 path_len][path bytes][u32 line_len][line bytes]. The raw
 *  path travels with the line because the sort key is the raw path, which the
 *  serialized line may hold only as escaped JSON or base64.
 */
struct spill {
    unsigned char *arena;
    size_t budget;
    size_t used;
    size_t *offs, *scratch;
    size_t n, cap;
    /* Runs by level: level k holds runs merged from 16^k first-level runs. A
     * full level merges into ONE run at the next level, so each byte is
     * rewritten about log16(runs) times. (The first version re-merged a
     * single ever-growing run at every cascade: temporary I/O grew with the
     * square of the entry count, 13x the manifest size at 80k entries.) */
    FILE *runs[LEVELS][FANIN];
    size_t nruns[LEVELS];
    char tmpl[PATH_MAX + 32];   /* mkstemp template for runs */
};

static int rec_cmp(const unsigned char *a, const unsigned char *b) {
    uint32_t la, lb;
    memcpy(&la, a, 4);
    memcpy(&lb, b, 4);
    const int r = memcmp(a + 4, b + 4, la < lb ? la : lb);
    if (r != 0) return r;
    return (la > lb) - (la < lb);
}

/* Bottom-up merge sort of record offsets. Written out rather than qsort()
 * because the comparator needs the arena base and qsort_r differs between
 * glibc and macOS; a file-static context would make the writer non-reentrant. */
static void sort_offs(const unsigned char *base, size_t *a, size_t *tmp, size_t n) {
    for (size_t width = 1; width < n; width *= 2) {
        for (size_t lo = 0; lo < n; lo += 2 * width) {
            const size_t mid = lo + width < n ? lo + width : n;
            const size_t hi  = lo + 2 * width < n ? lo + 2 * width : n;
            size_t i = lo, j = mid, k = lo;
            while (i < mid && j < hi)
                tmp[k++] = rec_cmp(base + a[i], base + a[j]) <= 0 ? a[i++] : a[j++];
            while (i < mid) tmp[k++] = a[i++];
            while (j < hi)  tmp[k++] = a[j++];
        }
        memcpy(a, tmp, n * sizeof *a);
    }
}

/* Creates an anonymous temporary file beside the output. It is unlinked at
 * once, so nothing is left behind on a crash and nothing else can open it. */
static FILE *open_tmp(const char *tmpl) {
    char name[PATH_MAX + 32];
    snprintf(name, sizeof name, "%s", tmpl);
    const int fd = mkstemp(name);
    if (fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot create temporary file");
        return NULL;
    }
    unlink(name);
    FILE *f = fdopen(fd, "w+b");
    if (f == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: fdopen");
        close(fd);
    }
    return f;
}

struct cursor {
    FILE *f;
    uint32_t plen, llen;
    unsigned char *buf;         /* PATH_CAP bytes of path, then LINE_CAP of line */
    int live;
};

static int cur_next(struct cursor *c) {
    uint32_t pl, ll;
    const size_t r = fread(&pl, 1, 4, c->f);
    if (r == 0 && feof(c->f)) { c->live = 0; return 0; }
    if (r != 4 || pl == 0 || pl >= PATH_CAP) goto bad;
    if (fread(c->buf, 1, pl, c->f) != pl) goto bad;
    if (fread(&ll, 1, 4, c->f) != 4 || ll == 0 || ll > LINE_CAP) goto bad;
    if (fread(c->buf + PATH_CAP, 1, ll, c->f) != ll) goto bad;
    c->plen = pl;
    c->llen = ll;
    c->live = 1;
    return 0;
bad:
    belay_err_set(BELAY_ERR_IO, errno, "manifest: temporary run is unreadable");
    return -1;
}

static int cur_cmp(const struct cursor *a, const struct cursor *b) {
    const int r = memcmp(a->buf, b->buf, a->plen < b->plen ? a->plen : b->plen);
    if (r != 0) return r;
    return (a->plen > b->plen) - (a->plen < b->plen);
}

/*
 *  K-way merge of `k` runs. With `lines_only` the output is manifest lines;
 *  otherwise it is records, for a cascaded run. Paths are unique by
 *  construction, so an equal pair is an internal error, not a tie to break.
 *  `*count` receives the number of records emitted.
 */
static int merge(FILE **in, size_t k, FILE *out, int lines_only, size_t *count) {
    struct cursor cur[FANIN];
    int rc = 0;
    size_t emitted = 0;
    unsigned char prev[PATH_CAP];
    uint32_t prev_len = 0;

    memset(cur, 0, sizeof cur);
    for (size_t i = 0; i < k; i++) {
        cur[i].f = in[i];
        cur[i].buf = malloc(PATH_CAP + LINE_CAP);
        if (cur[i].buf == NULL) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory in merge");
            rc = -1;
            goto done;
        }
        if (fseek(in[i], 0, SEEK_SET) != 0 || cur_next(&cur[i]) == -1) { rc = -1; goto done; }
    }

    for (;;) {
        struct cursor *m = NULL;
        for (size_t i = 0; i < k; i++)
            if (cur[i].live && (m == NULL || cur_cmp(&cur[i], m) < 0)) m = &cur[i];
        if (m == NULL) break;

        if (emitted > 0) {
            const int c = memcmp(prev, m->buf, prev_len < m->plen ? prev_len : m->plen);
            if (c > 0 || (c == 0 && prev_len >= m->plen)) {
                belay_err_set(BELAY_ERR_CORRUPT, 0,
                              "manifest: the filesystem listed one name twice; refusing");
                rc = -1;
                goto done;
            }
        }
        memcpy(prev, m->buf, m->plen);
        prev_len = m->plen;

        int ok;
        if (lines_only) {
            ok = fwrite(m->buf + PATH_CAP, 1, m->llen, out) == m->llen;
        } else {
            ok = fwrite(&m->plen, 1, 4, out) == 4 &&
                 fwrite(m->buf, 1, m->plen, out) == m->plen &&
                 fwrite(&m->llen, 1, 4, out) == 4 &&
                 fwrite(m->buf + PATH_CAP, 1, m->llen, out) == m->llen;
        }
        if (!ok) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: write failed during merge");
            rc = -1;
            goto done;
        }
        emitted++;
        if (cur_next(m) == -1) { rc = -1; goto done; }
    }

    if (count != NULL) *count = emitted;
done:
    for (size_t i = 0; i < k; i++) free(cur[i].buf);
    return rc;
}

static int spill_flush(struct spill *s) {
    if (s->n == 0) return 0;
    sort_offs(s->arena, s->offs, s->scratch, s->n);

    FILE *f = open_tmp(s->tmpl);
    if (f == NULL) return -1;
    for (size_t i = 0; i < s->n; i++) {
        const unsigned char *r = s->arena + s->offs[i];
        uint32_t pl, ll;
        memcpy(&pl, r, 4);
        memcpy(&ll, r + 4 + pl, 4);
        const size_t sz = 8 + (size_t)pl + ll;
        if (fwrite(r, 1, sz, f) != sz) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: temporary run write failed");
            fclose(f);
            return -1;
        }
    }
    if (fflush(f) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: temporary run write failed");
        fclose(f);
        return -1;
    }
    s->runs[0][s->nruns[0]++] = f;
    s->used = 0;
    s->n = 0;

    /* Cascade: a full level becomes one run one level up. Open descriptors
     * stay bounded by FANIN per level. */
    for (size_t lv = 0; lv + 1 < LEVELS && s->nruns[lv] == FANIN; lv++) {
        FILE *merged = open_tmp(s->tmpl);
        if (merged == NULL) return -1;
        if (merge(s->runs[lv], FANIN, merged, 0, NULL) == -1 || fflush(merged) != 0) {
            fclose(merged);
            return -1;
        }
        for (size_t i = 0; i < FANIN; i++) fclose(s->runs[lv][i]);
        s->nruns[lv] = 0;
        s->runs[lv + 1][s->nruns[lv + 1]++] = merged;
    }
    if (s->nruns[LEVELS - 1] == FANIN) {
        belay_err_set(BELAY_ERR_RANGE, 0, "manifest: too many entries to sort");
        return -1;
    }
    return 0;
}

static size_t spill_total_runs(const struct spill *s) {
    size_t t = 0;
    for (size_t lv = 0; lv < LEVELS; lv++) t += s->nruns[lv];
    return t;
}

/*
 *  Merges whatever runs remain, across levels, into `out` as manifest lines.
 *  At most FANIN-1 runs per level remain, so with several levels populated
 *  there can be more than FANIN: those are first merged lowest level first
 *  (the smallest runs, so the least data is rewritten) until FANIN remain.
 */
static int spill_finish(struct spill *s, FILE *out, size_t *count) {
    FILE *all[LEVELS * FANIN];
    size_t n = 0;
    for (size_t lv = 0; lv < LEVELS; lv++) {
        for (size_t i = 0; i < s->nruns[lv]; i++) all[n++] = s->runs[lv][i];
        s->nruns[lv] = 0;
    }
    int rc = 0;
    while (n > FANIN) {
        FILE *merged = open_tmp(s->tmpl);
        if (merged == NULL || merge(all, FANIN, merged, 0, NULL) == -1 || fflush(merged) != 0) {
            if (merged != NULL) fclose(merged);
            rc = -1;
            break;
        }
        for (size_t i = 0; i < FANIN; i++) fclose(all[i]);
        memmove(all, all + FANIN, (n - FANIN) * sizeof *all);
        n -= FANIN;
        all[n++] = merged;
    }
    if (rc == 0) rc = merge(all, n, out, 1, count);
    for (size_t i = 0; i < n; i++) fclose(all[i]);
    return rc;
}

static int spill_add(struct spill *s, const char *path, size_t plen,
                     const char *line, size_t llen) {
    const size_t sz = 8 + plen + llen;
    if (s->used + sz > s->budget && spill_flush(s) == -1) return -1;

    if (s->n == s->cap) {
        const size_t ncap = s->cap ? s->cap * 2 : 4096;
        size_t *no = realloc(s->offs, ncap * sizeof *no);
        if (no == NULL) goto nomem;
        s->offs = no;
        size_t *ns = realloc(s->scratch, ncap * sizeof *ns);
        if (ns == NULL) goto nomem;
        s->scratch = ns;
        s->cap = ncap;
    }

    unsigned char *r = s->arena + s->used;
    const uint32_t pl = (uint32_t)plen, ll = (uint32_t)llen;
    memcpy(r, &pl, 4);
    memcpy(r + 4, path, plen);
    memcpy(r + 4 + plen, &ll, 4);
    memcpy(r + 8 + plen, line, llen);
    s->offs[s->n++] = s->used;
    s->used += sz;
    return 0;
nomem:
    belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
    return -1;
}

static void spill_free(struct spill *s) {
    for (size_t lv = 0; lv < LEVELS; lv++)
        for (size_t i = 0; i < s->nruns[lv]; i++) fclose(s->runs[lv][i]);
    free(s->arena);
    free(s->offs);
    free(s->scratch);
}

/* ------------------------------------------------------------------------ */
/* Walk                                                                      */
/* ------------------------------------------------------------------------ */

struct walk_ctx {
    const struct belay_manifest_opts *opts;
    uint64_t root_dev;
    const char *scope;
    struct spill *spill;
    struct belay_entry e;       /* scratch; finished before any recursion */
    char *line;                 /* LINE_CAP */
    unsigned char *readbuf;     /* READ_CHUNK */
    size_t n_entries;
    size_t n_vanished;
    size_t n_unreadable;
    size_t n_unstable;

    struct belay_store *store;  /* NULL when content storage is off */
    char  *abs;                 /* scope + "/" + rel, for interpreter claims */
    size_t scope_len;
};

static enum belay_entry_type type_of(mode_t m) {
    if (S_ISREG(m))  return BELAY_T_REG;
    if (S_ISDIR(m))  return BELAY_T_DIR;
    if (S_ISLNK(m))  return BELAY_T_LNK;
    if (S_ISFIFO(m)) return BELAY_T_FIFO;
    if (S_ISSOCK(m)) return BELAY_T_SOCK;
    if (S_ISBLK(m))  return BELAY_T_BLK;
    return BELAY_T_CHR;
}

/* Hashes by fd: no path is re-resolved, so there is no window between the
 * open and the read. */
/* Hashes by fd, and when `tx` is non-NULL stages the same bytes into the
 * store in the same pass: what is stored is exactly what was hashed. `*binary`
 * reports a NUL within the first SNIFF_BYTES. */
static int hash_fd(int fd, unsigned char *buf, char hex_out[65], uint64_t *nread,
                   struct belay_store_tx *tx, bool *binary) {
    struct belay_sha256 c;
    belay_sha256_init(&c);
    *nread = 0;
    *binary = false;
    for (;;) {
        const ssize_t n = read(fd, buf, READ_CHUNK);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            belay_err_set(BELAY_ERR_IO, errno, "hash: read failed");
            return -2;                      /* the file's problem, not belay's */
        }
        if (*nread < SNIFF_BYTES) {
            const size_t span = (size_t)n < SNIFF_BYTES - *nread ? (size_t)n
                                                                 : (size_t)(SNIFF_BYTES - *nread);
            if (memchr(buf, '\0', span) != NULL) *binary = true;
        }
        belay_sha256_update(&c, buf, (size_t)n);
        if (tx != NULL && belay_store_write(tx, buf, (size_t)n) == -1) return -1;
        *nread += (uint64_t)n;
    }
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_final(&c, d);
    belay_hex_encode(hex_out, d, sizeof d);
    return 0;
}

static int64_t ts_ns(const struct stat *st, int which) {
#ifdef __APPLE__
    const struct timespec *t = which ? &st->st_ctimespec : &st->st_mtimespec;
#else
    const struct timespec *t = which ? &st->st_ctim : &st->st_mtim;
#endif
    return (int64_t)t->tv_sec * 1000000000 + t->tv_nsec;
}

static void fill_from_stat(struct belay_entry *e, const struct stat *st) {
    e->type     = type_of(st->st_mode);
    e->mode     = (uint32_t)st->st_mode;
    e->uid      = (uint32_t)st->st_uid;
    e->gid      = (uint32_t)st->st_gid;
    e->size     = (uint64_t)st->st_size;
    e->ino      = (uint64_t)st->st_ino;
    e->dev      = (uint64_t)st->st_dev;
    e->nlink    = (uint64_t)st->st_nlink;
    e->mtime_ns = ts_ns(st, 0);
    e->ctime_ns = ts_ns(st, 1);
    if (e->type == BELAY_T_BLK || e->type == BELAY_T_CHR) {
        e->has_rdev = true;
        e->rdev = (uint64_t)st->st_rdev;
    }
}

/*
 *  Advisory only (§5.1.1): does a RELATIVE link target leave the scope,
 *  judged lexically from the link's own directory? ".." pops a component;
 *  popping above the scope root means outside. Symlinks along the way are
 *  not followed, so this can be wrong in both directions -- which is why it
 *  is an annotation and never an input to a decision. Previously only
 *  absolute targets were analysed, so a relative escape such as "../../etc"
 *  carried no annotation at all.
 */
static bool rel_target_escapes(const char *link_path, size_t link_len,
                               const char *target, size_t tlen) {
    /* depth = number of directory components above the link, inside scope */
    long depth = 0;
    for (size_t i = 0; i < link_len; i++) if (link_path[i] == '/') depth++;

    size_t i = 0;
    while (i < tlen) {
        size_t j = i;
        while (j < tlen && target[j] != '/') j++;
        const size_t n = j - i;
        if (n == 2 && target[i] == '.' && target[i + 1] == '.') {
            if (--depth < 0) return true;
        } else if (!(n == 0 || (n == 1 && target[i] == '.'))) {
            depth++;
        }
        i = j + 1;
    }
    return false;
}

static ssize_t rel_join(char *rel, size_t relsz, size_t rel_len, const char *name) {
    const size_t nlen = strlen(name);
    const size_t need = rel_len + (rel_len ? 1 : 0) + nlen;
    if (need >= relsz) {
        belay_err_set(BELAY_ERR_RANGE, 0, "manifest: path exceeds %zu bytes", relsz);
        return -1;
    }
    size_t w = rel_len;
    if (rel_len) rel[w++] = '/';
    memcpy(rel + w, name, nlen);
    w += nlen;
    rel[w] = '\0';
    return (ssize_t)w;
}

static int emit_one(struct walk_ctx *wc, const struct belay_entry *e) {
    size_t llen = 0;
    if (serialize(e, wc->line, LINE_CAP, &llen) == -1) return -1;
    if (spill_add(wc->spill, e->path, e->path_len, wc->line, llen) == -1) return -1;
    wc->n_entries++;
    return 0;
}

static int emit_entry(struct walk_ctx *wc) { return emit_one(wc, &wc->e); }

static int walk(int dfd, char *rel, size_t relsz, size_t rel_len,
                int depth, struct walk_ctx *wc);

/*
 *  lstat, plus whether the entry is a mount root. st_dev alone misses a bind
 *  mount from the same filesystem -- verified: a same-device bind of a
 *  directory from outside the scope was walked and hashed with no flag. On
 *  Linux statx's STATX_ATTR_MOUNT_ROOT reports every mount root, bind mounts
 *  included. Elsewhere, or on a kernel without it, st_dev is the fallback.
 */
static int stat_entry(int dfd, const char *name, struct stat *st, bool *mount_root) {
    *mount_root = false;
#if defined(__linux__) && defined(STATX_ATTR_MOUNT_ROOT)
    struct statx sx;
    if (statx(dfd, name, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &sx) == 0) {
        memset(st, 0, sizeof *st);
        st->st_mode  = sx.stx_mode;
        st->st_ino   = sx.stx_ino;
        st->st_dev   = makedev(sx.stx_dev_major, sx.stx_dev_minor);
        st->st_rdev  = makedev(sx.stx_rdev_major, sx.stx_rdev_minor);
        st->st_nlink = sx.stx_nlink;
        st->st_uid   = sx.stx_uid;
        st->st_gid   = sx.stx_gid;
        st->st_size  = (off_t)sx.stx_size;
        st->st_mtim.tv_sec  = sx.stx_mtime.tv_sec;
        st->st_mtim.tv_nsec = sx.stx_mtime.tv_nsec;
        st->st_ctim.tv_sec  = sx.stx_ctime.tv_sec;
        st->st_ctim.tv_nsec = sx.stx_ctime.tv_nsec;
        *mount_root = (sx.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT) &&
                      (sx.stx_attributes & STATX_ATTR_MOUNT_ROOT);
        return 0;
    }
    if (errno != ENOSYS) return -1;
#endif
    return fstatat(dfd, name, st, AT_SYMLINK_NOFOLLOW);
}

/* Errors that are belay's own resource exhaustion rather than a property of
 * one entry: these stay fatal, loudly. Everything else about one entry is
 * recorded on that entry and the walk goes on. */
static bool fatal_errno(int err) {
    return err == EMFILE || err == ENFILE || err == ENOMEM;
}

enum { V_OK = 0, V_VANISHED = 2, V_RACED = 3 };

/*
 *  Symlink. readlinkat reads the link itself, never its target. The link is
 *  re-stat'ed afterwards: the target read must belong to the link whose
 *  metadata was recorded (same inode, unchanged ctime, size equal to the
 *  target's length), or a swapped link would record one link's target with
 *  another's metadata.
 */
static int read_link(int pfd, const char *name, const struct stat *st, const char *rel,
                     struct walk_ctx *wc) {
    struct belay_entry *e = &wc->e;
    /* Buffer of PATH_CAP: a target of exactly PATH_CAP-1 (4095, the most
     * Linux allows) fits with its NUL. A full buffer means truncation. */
    const ssize_t n = readlinkat(pfd, name, e->link_target, sizeof e->link_target);
    if (n < 0) {
        if (errno == ENOENT) return V_VANISHED;
        if (errno == EINVAL) return V_RACED;           /* no longer a symlink */
        belay_err_set(BELAY_ERR_IO, errno, "manifest: readlinkat %s", rel);
        return -1;
    }
    if ((size_t)n >= sizeof e->link_target) {
        belay_err_set(BELAY_ERR_RANGE, 0, "manifest: link target too long at %s", rel);
        return -1;
    }
    e->link_target[n] = '\0';
    e->link_target_len = (size_t)n;
    e->has_link_target = true;

    struct stat again;
    bool mr;
    if (stat_entry(pfd, name, &again, &mr) == -1) {
        if (errno == ENOENT) return V_VANISHED;
        belay_err_set(BELAY_ERR_IO, errno, "manifest: stat %s", rel);
        return -1;
    }
    if (again.st_ino != st->st_ino || again.st_dev != st->st_dev ||
        ts_ns(&again, 1) != ts_ns(st, 1) || (uint64_t)again.st_size != (uint64_t)n)
        return V_RACED;

    /* Advisory only (§5.1.1): computed lexically, never used to decide. */
    if (e->link_target[0] == '/') {
        const int within = belay_path_within_lexical(wc->scope, e->link_target);
        e->target_outside_scope = (within != 1);
        if (within == -1) belay_err_clear();
    } else {
        e->target_outside_scope = rel_target_escapes(e->path, e->path_len,
                                                     e->link_target, e->link_target_len);
    }
    return V_OK;
}

static void mark_unreadable_file(struct walk_ctx *wc) {
    wc->e.unverified = true;
    wc->e.unreadable = true;
    wc->n_unreadable++;
}

/*
 *  Regular file. Hashes by fd and, when content is kept, stages the copy in
 *  the same read. The (size, sha256) pair must describe one real state of the
 *  file, so the fd is checked against the fstatat (inode, size, mtime, ctime)
 *  before reading and against itself after; any mismatch records no hash.
 */
static int read_file(int pfd, const char *name, const struct stat *st, const char *rel,
                     size_t rel_len, struct walk_ctx *wc) {
    struct belay_entry *e = &wc->e;

    /* O_NOFOLLOW closes the swap window; O_NONBLOCK stops a FIFO swapped in
     * from blocking the open forever. */
    const int fd = openat(pfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd == -1) {
        if (errno == ENOENT) return V_VANISHED;
        if (fatal_errno(errno)) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: openat %s", rel);
            return -1;
        }
        /* EACCES, EPERM, ELOOP (swapped for a link), EAGAIN (a lease),
         * ETXTBSY, EIO...: one entry's property, recorded on it. */
        mark_unreadable_file(wc);
        return V_OK;
    }

    struct stat before, after;
    if (fstat(fd, &before) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: fstat %s", rel);
        close(fd);
        return -1;
    }
    /* Same file, same moment as the fstatat whose metadata was recorded --
     * including mtime and ctime, so a same-size rewrite in between cannot
     * pair the old timestamps with the new content's hash. */
    const bool same = before.st_ino == st->st_ino && before.st_dev == st->st_dev &&
                      S_ISREG(before.st_mode) && before.st_size == st->st_size &&
                      ts_ns(&before, 0) == ts_ns(st, 0) && ts_ns(&before, 1) == ts_ns(st, 1);
    if (!same) {
        e->unverified = true;
        e->unstable = true;
        wc->n_unstable++;
        close(fd);
        return V_OK;
    }
    if (e->size > wc->opts->hash_max_bytes) {
        e->unverified = true;
        close(fd);
        return V_OK;
    }

    /* What must be kept: an interpreter's claim overrides the size threshold
     * (stored whatever its size) or forbids storing (hash only); unclaimed
     * files are kept if small and text. */
    struct belay_claim claim = { BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT };
    if (wc->store != NULL) {
        const size_t sep = wc->scope_len > 1 ? 1 : 0;
        if (wc->scope_len + sep + rel_len < PATH_MAX * 2) {
            if (sep) wc->abs[wc->scope_len] = '/';
            memcpy(wc->abs + wc->scope_len + sep, rel, rel_len);
            belay_interp_classify(wc->abs, wc->scope_len + sep + rel_len, &claim);
        }
    }
    const bool want = wc->store != NULL && claim.keep != BELAY_KEEP_HASH &&
                      (claim.keep == BELAY_KEEP_STORE || e->size <= wc->opts->store_max_bytes);

    struct belay_store_tx tx;
    if (want && belay_store_begin(wc->store, &tx) == -1) {
        close(fd);
        return -1;
    }

    uint64_t nread = 0;
    bool binary = false;
    const int h = hash_fd(fd, wc->readbuf, e->sha256_hex, &nread, want ? &tx : NULL, &binary);
    if (h != 0) {
        if (want) belay_store_abort(&tx);
        close(fd);
        if (h == -2) {
            /* The file could not be read (EIO and friends): record it. */
            belay_err_clear();
            e->sha256_hex[0] = '\0';
            mark_unreadable_file(wc);
            return V_OK;
        }
        return -1;                                      /* store write failed */
    }
    if (fstat(fd, &after) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: fstat %s", rel);
        if (want) belay_store_abort(&tx);
        close(fd);
        return -1;
    }
    close(fd);

    const bool stable = after.st_size == before.st_size &&
                        ts_ns(&after, 0) == ts_ns(&before, 0) &&
                        ts_ns(&after, 1) == ts_ns(&before, 1) &&
                        nread == (uint64_t)before.st_size;
    if (!stable) {
        /* The bytes read -- and any staged copy -- match no state of the file. */
        if (want) belay_store_abort(&tx);
        e->sha256_hex[0] = '\0';
        e->unverified = true;
        e->unstable = true;
        wc->n_unstable++;
        return V_OK;
    }

    e->has_hash = true;
    /* Unclaimed binary content is not kept: the text interpreter could not
     * use it. Claimed content is kept whatever it is. */
    if (want && !(claim.keep == BELAY_KEEP_DEFAULT && binary)) {
        if (belay_store_commit(&tx, e->sha256_hex) == -1) return -1;
        e->has_stored = true;
        memcpy(e->stored_hex, e->sha256_hex, sizeof e->stored_hex);
    } else if (want) {
        belay_store_abort(&tx);
    }
    return V_OK;
}

/* A name can be at most this long, so a directory whose path is longer than
 * PATH_CAP - 2 - NAME_BYTES might hold children whose paths do not fit. */
#define NAME_BYTES 255

/*
 *  Directory. Opened, and checked, BEFORE its entry is emitted, so whatever
 *  goes wrong is recorded on the entry itself. Any condition that keeps belay
 *  from capturing the contents is a flag on this one entry ("contents
 *  unknown"), never a failure of the whole check.
 */
static int open_dir(int pfd, const char *name, const struct stat *st, const char *rel,
                    size_t rel_len, int depth, struct walk_ctx *wc, int *out_fd) {
    struct belay_entry *e = &wc->e;
    *out_fd = -1;

    if (depth >= MAX_DEPTH || rel_len > PATH_CAP - 2 - NAME_BYTES) {
        e->unreadable = true;
        wc->n_unreadable++;
        return V_OK;
    }

    const int cfd = openat(pfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cfd == -1) {
        if (fatal_errno(errno)) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: openat dir %s", rel);
            return -1;
        }
        if (errno == ENOENT) wc->n_vanished++;
        /* ENOENT (gone), ELOOP/ENOTDIR (swapped), EACCES/EPERM: the subtree is
         * absent, and unflagged it would read as an empty directory. */
        e->unreadable = true;
        wc->n_unreadable++;
        return V_OK;
    }

    /* The directory opened must be the one stat'ed. Verified before this
     * check: swapping two directories between the stat and the open recorded
     * A's mode and inode with B's contents, and lost A's contents, with a
     * clean trailer. */
    struct stat cs, probe;
    if (fstat(cfd, &cs) == -1 || cs.st_ino != st->st_ino || cs.st_dev != st->st_dev ||
        /* Readable but not searchable (r without x): its names can be listed
         * but none of them can be stat'ed. */
        fstatat(cfd, ".", &probe, AT_SYMLINK_NOFOLLOW) == -1) {
        close(cfd);
        e->unreadable = true;
        wc->n_unreadable++;
        return V_OK;
    }
    /* Changed between its stat and its open: its listing will not describe
     * the state its metadata records. Still walked, but flagged. */
    if (ts_ns(&cs, 0) != ts_ns(st, 0) || ts_ns(&cs, 1) != ts_ns(st, 1)) {
        e->unstable = true;
        wc->n_unstable++;
    }
    (void)rel;
    *out_fd = cfd;
    return V_OK;
}

#define MAX_RACE_RETRIES 3

/* Records one entry and, for directories, recurses. Takes the parent dirfd and
 * the entry name; never a path string. */
static int visit(int parent_fd, const char *name, char *rel, size_t relsz,
                 size_t rel_len, int depth, struct walk_ctx *wc) {
    struct belay_entry *e = &wc->e;
    int cfd = -1;

    for (int attempt = 0; ; attempt++) {
        struct stat st;
        bool mount_root;
        if (stat_entry(parent_fd, name, &st, &mount_root) == -1) {
            /* Vanished between readdir and stat: the tree changed under us. */
            if (errno == ENOENT) { wc->n_vanished++; return 0; }
            belay_err_set(BELAY_ERR_IO, errno, "manifest: stat %s", rel);
            return -1;
        }

        memset(e, 0, sizeof *e);
        if (rel_len >= sizeof e->path) {
            belay_err_set(BELAY_ERR_RANGE, 0, "manifest: path too long");
            return -1;
        }
        memcpy(e->path, rel, rel_len);
        e->path_len = rel_len;
        fill_from_stat(e, &st);

        /* A mount root of ANY type is a capture boundary: recorded, never read
         * or descended. Before, only directories were checked, so a file
         * bind-mounted from elsewhere was hashed and stored as if local. */
        const bool crossed = mount_root || (uint64_t)st.st_dev != wc->root_dev;

        int r = V_OK;
        if (crossed) {
            e->is_mount = true;
            if (e->type == BELAY_T_REG) e->unverified = true;
            if (e->type == BELAY_T_LNK) r = read_link(parent_fd, name, &st, rel, wc);
        } else if (e->type == BELAY_T_LNK) {
            r = read_link(parent_fd, name, &st, rel, wc);
        } else if (e->type == BELAY_T_REG) {
            r = read_file(parent_fd, name, &st, rel, rel_len, wc);
        } else if (e->type == BELAY_T_DIR) {
            r = open_dir(parent_fd, name, &st, rel, rel_len, depth, wc, &cfd);
        }

        if (r == -1) return -1;
        if (r == V_VANISHED) { wc->n_vanished++; return 0; }
        if (r == V_RACED) {
            if (attempt + 1 < MAX_RACE_RETRIES) continue;     /* stat it again */
            /* Still changing after several tries. Keep what was read, flagged;
             * if no target was ever read the entry is counted as vanished. */
            if (!e->has_link_target) { wc->n_vanished++; return 0; }
            e->unreadable = true;
            wc->n_unreadable++;
        }
        break;
    }

    if (cfd == -1) return emit_entry(wc);

    /*
     *  A walked directory is emitted AFTER its subtree (order is fixed by the
     *  sort, so this costs nothing) so that a change during its own listing
     *  can still be recorded on it. Verified before this: a file moved, mid-
     *  walk, from a not-yet-listed directory into an already-listed one was
     *  recorded nowhere while the trailer claimed a clean walk. Now the
     *  directory it left is flagged unstable: its listing describes no single
     *  instant. The scratch entry is reused by the children, so keep a copy.
     */
    struct belay_entry *dir = malloc(sizeof *dir);
    if (dir == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        close(cfd);
        return -1;
    }
    memcpy(dir, e, sizeof *dir);

    int r = walk(cfd, rel, relsz, rel_len, depth + 1, wc);
    if (r == 0) {
        struct stat post;
        if (fstat(cfd, &post) == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: fstat %s", rel);
            r = -1;
        } else if (!dir->unstable &&
                   (ts_ns(&post, 0) != dir->mtime_ns || ts_ns(&post, 1) != dir->ctime_ns)) {
            dir->unstable = true;
            wc->n_unstable++;
        }
    }
    close(cfd);
    if (r == 0) r = emit_one(wc, dir);
    free(dir);
    return r;
}

static int walk(int dfd, char *rel, size_t relsz, size_t rel_len,
                int depth, struct walk_ctx *wc) {
    /* closedir closes the fd it was given; dup so the caller's stays valid. */
    const int ddup = dup(dfd);
    if (ddup == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: dup");
        return -1;
    }
    DIR *d = fdopendir(ddup);
    if (d == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: fdopendir");
        close(ddup);
        return -1;
    }

    int rc = 0;
    for (;;) {
        errno = 0;
        const struct dirent *de = readdir(d);
        if (de == NULL) {
            if (errno != 0) {
                belay_err_set(BELAY_ERR_IO, errno, "manifest: readdir");
                rc = -1;
            }
            break;
        }
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

        const ssize_t nlen = rel_join(rel, relsz, rel_len, de->d_name);
        if (nlen == -1) { rc = -1; break; }

        rc = visit(dfd, de->d_name, rel, relsz, (size_t)nlen, depth, wc);
        rel[rel_len] = '\0';
        if (rc != 0) break;
    }

    closedir(d);
    return rc;
}

/* ------------------------------------------------------------------------ */
/* Entry point                                                               */
/* ------------------------------------------------------------------------ */

static int write_header(FILE *f, const char *scope_real,
                        const struct belay_manifest_opts *opts, char *buf) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    const long long created = (long long)now.tv_sec * 1000000000LL + now.tv_nsec;

    /* Same rule as entry paths: JSON for valid UTF-8, base64 otherwise.
     * Before, a non-UTF-8 scope was written raw and the line was not JSON. */
    const size_t sl = strlen(scope_real);
    const bool utf8 = belay_utf8_valid(scope_real, sl);
    if ((utf8 ? belay_json_escape(buf, LINE_CAP, scope_real, sl)
              : belay_base64_encode(buf, LINE_CAP, scope_real, sl)) == -1) return -1;
    if (fprintf(f,
                "{\"belay_manifest\":%d,\"created_ns\":%lld,\"%s\":[\"%s\"]"
                ",\"hash\":\"sha256\",\"hash_max_bytes\":%llu"
                ",\"store_max_bytes\":%llu}\n",
                BELAY_MANIFEST_VERSION, created, utf8 ? "scopes" : "scopes_b64", buf,
                (unsigned long long)opts->hash_max_bytes,
                (unsigned long long)opts->store_max_bytes) < 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: header write failed");
        return -1;
    }
    return 0;
}

int belay_manifest_write(const char *out_path, const char *scope,
                         const struct belay_manifest_opts *opts,
                         struct belay_manifest_stats *stats) {
    if (out_path == NULL || scope == NULL || opts == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_write: null argument");
        return -1;
    }
    if (strlen(out_path) > PATH_MAX - 32) {
        belay_err_set(BELAY_ERR_RANGE, 0, "manifest_write: output path too long");
        return -1;
    }

    /* Lexical validation first, so a ".." scope never reaches realpath. */
    char nscope[4096];
    if (belay_path_normalize(nscope, sizeof nscope, scope) == -1) return -1;

    char *real = realpath(nscope, NULL);
    if (real == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot resolve scope %s", nscope);
        return -1;
    }
    const int root_fd = open(real, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot open scope %s", real);
        free(real);
        return -1;
    }
    struct stat rst;
    if (fstat(root_fd, &rst) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: fstat scope");
        close(root_fd);
        free(real);
        return -1;
    }

    int rc = -1;
    struct spill sp;
    memset(&sp, 0, sizeof sp);
    snprintf(sp.tmpl, sizeof sp.tmpl, "%s.run.XXXXXX", out_path);

    struct walk_ctx *wc = calloc(1, sizeof *wc);
    char *rel = malloc(PATH_CAP);
    char outtmp[PATH_MAX + 32];
    bool outtmp_live = false;   /* a temp output exists on disk and must go */
    FILE *out = NULL;
    snprintf(outtmp, sizeof outtmp, "%s.tmp.XXXXXX", out_path);

    /* The budget must hold at least one maximal record. */
    const size_t min_budget = 8 + PATH_CAP + LINE_CAP;
    sp.budget = opts->run_bytes == 0 ? RUN_BYTES
              : opts->run_bytes < min_budget ? min_budget : opts->run_bytes;
    sp.arena = malloc(sp.budget);
    if (wc == NULL || rel == NULL || sp.arena == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        goto cleanup;
    }
    wc->line = malloc(LINE_CAP);
    wc->readbuf = malloc(READ_CHUNK);
    if (wc->line == NULL || wc->readbuf == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        goto cleanup;
    }
    wc->opts = opts;
    wc->root_dev = (uint64_t)rst.st_dev;
    wc->scope = real;
    wc->spill = &sp;
    wc->scope_len = strlen(real);

    if (opts->store_dir != NULL) {
        wc->abs = malloc(PATH_MAX * 2);
        if (wc->abs == NULL) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
            goto cleanup;
        }
        memcpy(wc->abs, real, wc->scope_len);
        if (belay_store_open(opts->store_dir, &wc->store) == -1) goto cleanup;
    }

    /* The scope root itself is an entry, path ".". Without it a chmod or
     * chown on the root is invisible: verified, the manifest body was
     * byte-identical before and after `chmod 700` on the root. */
    memset(&wc->e, 0, sizeof wc->e);
    fill_from_stat(&wc->e, &rst);
    wc->e.path[0] = '.';
    wc->e.path_len = 1;
    /* A scope root that can be listed but not searched has contents belay
     * cannot stat: flag it, rather than fail on its first child. */
    struct stat probe;
    const bool searchable = fstatat(root_fd, ".", &probe, AT_SYMLINK_NOFOLLOW) == 0;
    if (!searchable) {
        wc->e.unreadable = true;
        wc->n_unreadable++;
    }
    if (emit_entry(wc) == -1) goto cleanup;

    rel[0] = '\0';
    if (searchable && walk(root_fd, rel, PATH_CAP, 0, 0, wc) != 0) goto cleanup;

    /* Output goes to a temporary name and is renamed into place. */
    const int ofd = mkstemp(outtmp);
    if (ofd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot create %s", outtmp);
        goto cleanup;
    }
    outtmp_live = true;
    out = fdopen(ofd, "wb");
    if (out == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: fdopen");
        close(ofd);
        goto cleanup;
    }
    if (write_header(out, real, opts, wc->line) == -1) goto cleanup;

    size_t written = 0;
    if (spill_total_runs(&sp) == 0) {
        /* Everything fit in one run: sort in memory, write straight out --
         * with the same strict-order check merge() applies, so a name the
         * filesystem returns twice fails here too instead of producing a
         * manifest the reader rejects. */
        sort_offs(sp.arena, sp.offs, sp.scratch, sp.n);
        for (size_t i = 0; i < sp.n; i++) {
            const unsigned char *r = sp.arena + sp.offs[i];
            if (i > 0 && rec_cmp(sp.arena + sp.offs[i - 1], r) >= 0) {
                belay_err_set(BELAY_ERR_CORRUPT, 0,
                              "manifest: the filesystem listed one name twice; refusing");
                goto cleanup;
            }
            uint32_t pl, ll;
            memcpy(&pl, r, 4);
            memcpy(&ll, r + 4 + pl, 4);
            if (fwrite(r + 8 + pl, 1, ll, out) != ll) {
                belay_err_set(BELAY_ERR_IO, errno, "manifest: write failed");
                goto cleanup;
            }
        }
        written = sp.n;
    } else {
        if (spill_flush(&sp) == -1) goto cleanup;
        if (spill_finish(&sp, out, &written) == -1) goto cleanup;
    }

    if (written != wc->n_entries) {
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "manifest: internal error, %zu entries walked but %zu written",
                      wc->n_entries, written);
        goto cleanup;
    }

    /* The trailer makes a manifest self-delimiting: a file cut off at a line
     * boundary would otherwise be indistinguishable from a complete one with
     * fewer entries. It also records what the walk could not capture. */
    if (fprintf(out,
                "{\"belay_manifest_end\":%zu,\"vanished\":%zu"
                ",\"unreadable\":%zu,\"unstable\":%zu}\n",
                wc->n_entries, wc->n_vanished, wc->n_unreadable, wc->n_unstable) < 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: trailer write failed");
        goto cleanup;
    }

    if (fflush(out) != 0 || fsync(fileno(out)) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: flush failed");
        goto cleanup;
    }
    const int cerr = fclose(out);
    out = NULL;
    if (cerr != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: close failed");
        goto cleanup;
    }
    if (rename(outtmp, out_path) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot rename into %s", out_path);
        goto cleanup;
    }
    outtmp_live = false;

    if (stats != NULL) {
        stats->entries    = wc->n_entries;
        stats->vanished   = wc->n_vanished;
        stats->unreadable = wc->n_unreadable;
        stats->unstable   = wc->n_unstable;
    }
    rc = 0;

cleanup:
    if (out != NULL) fclose(out);
    if (outtmp_live) unlink(outtmp);
    spill_free(&sp);
    if (wc != NULL) {
        free(wc->line);
        free(wc->readbuf);
        free(wc->abs);
        belay_store_close(wc->store);
    }
    free(wc);
    free(rel);
    close(root_fd);
    free(real);
    return rc;
}
