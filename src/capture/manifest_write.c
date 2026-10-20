/*
 *  Manifest writer.
 *
 *  BLAST RADIUS. Reads the user's real filesystem; writes only its own
 *  manifest file. Containment is by construction (BELAY_DESIGN.md §5.1.1):
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
 *  The walk is depth-first and recursive. Depth is bounded by MAX_DEPTH
 *  because the kernel's own fd limit would otherwise be the only brake, and
 *  running out of fds mid-walk is a worse failure than refusing to go deeper.
 */
#define _GNU_SOURCE

#include "belay/manifest.h"
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"
#include "belay/path.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_DEPTH 128
#define READ_CHUNK (64u * 1024u)

/* Collected entries, sorted before emission. The spec requires bytewise path
 * order so the comparator can stream a merge; sorting here is the cost of
 * that guarantee. A streaming sorted walk is possible (sort each directory's
 * names, emit depth-first) but produces a different order than a global
 * bytewise sort, because '/' (0x2f) sorts below most name bytes. */
struct collect {
    struct belay_entry *v;
    size_t n;
    size_t cap;
};

static int collect_push(struct collect *c, const struct belay_entry *e) {
    if (c->n == c->cap) {
        size_t ncap = c->cap ? c->cap * 2 : 1024;
        struct belay_entry *nv = realloc(c->v, ncap * sizeof *nv);
        if (nv == NULL) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory at %zu entries", c->n);
            return -1;
        }
        c->v = nv;
        c->cap = ncap;
    }
    c->v[c->n++] = *e;
    return 0;
}

/* Bytewise, length-tiebreak. memcmp over the shorter length then length, so
 * "a" sorts before "a/b" and before "ab". */
static int entry_cmp(const void *pa, const void *pb) {
    const struct belay_entry *a = pa, *b = pb;
    const size_t n = a->path_len < b->path_len ? a->path_len : b->path_len;
    const int r = memcmp(a->path, b->path, n);
    if (r != 0) return r;
    if (a->path_len < b->path_len) return -1;
    if (a->path_len > b->path_len) return 1;
    return 0;
}

static enum belay_entry_type type_of(mode_t m) {
    if (S_ISREG(m))  return BELAY_T_REG;
    if (S_ISDIR(m))  return BELAY_T_DIR;
    if (S_ISLNK(m))  return BELAY_T_LNK;
    if (S_ISFIFO(m)) return BELAY_T_FIFO;
    if (S_ISSOCK(m)) return BELAY_T_SOCK;
    if (S_ISBLK(m))  return BELAY_T_BLK;
    return BELAY_T_CHR;
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

/*
 *  Hashes a regular file by fd. The fd is already open from openat with
 *  O_NOFOLLOW, so there is no path to re-resolve and no TOCTOU window between
 *  the stat and the read.
 */
static int hash_fd(int fd, char hex_out[65]) {
    struct belay_sha256 c;
    belay_sha256_init(&c);

    unsigned char *buf = malloc(READ_CHUNK);
    if (buf == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "hash: out of memory");
        return -1;
    }

    for (;;) {
        const ssize_t n = read(fd, buf, READ_CHUNK);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            belay_err_set(BELAY_ERR_IO, errno, "hash: read failed");
            free(buf);
            return -1;
        }
        belay_sha256_update(&c, buf, (size_t)n);
    }

    free(buf);

    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_final(&c, d);
    belay_hex_encode(hex_out, d, sizeof d);
    return 0;
}

struct walk_ctx {
    struct collect *out;
    const struct belay_manifest_opts *opts;
    uint64_t root_dev;
    const char *scope;
    size_t n_vanished;   /* entries that disappeared mid-walk (a real race) */
    size_t n_unreadable; /* entries flagged unreadable */
};

/*
 *  Appends `name` to the relative path in `rel` (length `rel_len`), returning
 *  the new length or -1 if it would not fit. Byte-exact: no normalization,
 *  since these bytes came from readdir and are already canonical.
 */
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

static int walk(int dfd, char *rel, size_t relsz, size_t rel_len,
                int depth, struct walk_ctx *wc);

/* Records one entry and, for directories, recurses. Takes the parent dirfd and
 * the entry name; never a path string. */
static int visit(int parent_fd, const char *name, char *rel, size_t relsz,
                 size_t rel_len, int depth, struct walk_ctx *wc) {
    struct stat st;
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) == -1) {
        /* A file that vanished between readdir and fstatat is a race, not a
         * failure: the tree genuinely changed under us. Skip it rather than
         * abort the whole walk, which would make check unusable on a live
         * tree -- but count it, so the caller can report that the manifest is
         * not a complete picture. */
        if (errno == ENOENT) { wc->n_vanished++; return 0; }
        belay_err_set(BELAY_ERR_IO, errno, "manifest: fstatat %s", rel);
        return -1;
    }

    struct belay_entry e;
    memset(&e, 0, sizeof e);

    if (rel_len >= sizeof e.path) {
        belay_err_set(BELAY_ERR_RANGE, 0, "manifest: path too long");
        return -1;
    }
    memcpy(e.path, rel, rel_len);
    e.path_len = rel_len;

    e.type     = type_of(st.st_mode);
    e.mode     = (uint32_t)st.st_mode;
    e.uid      = (uint32_t)st.st_uid;
    e.gid      = (uint32_t)st.st_gid;
    e.size     = (uint64_t)st.st_size;
    e.ino      = (uint64_t)st.st_ino;
    e.dev      = (uint64_t)st.st_dev;
    e.nlink    = (uint64_t)st.st_nlink;
#ifdef __APPLE__
    e.mtime_ns = (int64_t)st.st_mtimespec.tv_sec * 1000000000 + st.st_mtimespec.tv_nsec;
    e.ctime_ns = (int64_t)st.st_ctimespec.tv_sec * 1000000000 + st.st_ctimespec.tv_nsec;
#else
    e.mtime_ns = (int64_t)st.st_mtim.tv_sec * 1000000000 + st.st_mtim.tv_nsec;
    e.ctime_ns = (int64_t)st.st_ctim.tv_sec * 1000000000 + st.st_ctim.tv_nsec;
#endif

    /* Mount boundary: record it, do not descend (§5.1.1). */
    const bool crossed = ((uint64_t)st.st_dev != wc->root_dev);

    if (e.type == BELAY_T_LNK) {
        /* readlinkat with the parent fd: the link itself is read, never
         * followed. Does not NUL-terminate, and truncation is silent, so a
         * full buffer must be treated as an error. */
        const ssize_t n = readlinkat(parent_fd, name, e.link_target,
                                     sizeof e.link_target - 1);
        if (n < 0) {
            if (errno == ENOENT) return 0;
            belay_err_set(BELAY_ERR_IO, errno, "manifest: readlinkat %s", rel);
            return -1;
        }
        if ((size_t)n >= sizeof e.link_target - 1) {
            belay_err_set(BELAY_ERR_RANGE, 0, "manifest: link target too long at %s", rel);
            return -1;
        }
        e.link_target[n] = '\0';
        e.link_target_len = (size_t)n;
        e.has_link_target = true;

        /* Advisory only. Computed lexically and never used for a decision. An
         * absolute target outside the scope, or a relative one that cannot be
         * shown to stay inside, is annotated. Errors here are not failures:
         * a target with ".." is simply not analysable lexically. */
        if (e.link_target[0] == '/') {
            const int within = belay_path_within_lexical(wc->scope, e.link_target);
            e.target_outside_scope = (within == 0);
            if (within == -1) belay_err_clear();
        }
    } else if (e.type == BELAY_T_REG) {
        /* O_NOFOLLOW is redundant after an lstat saying "regular", but the
         * file could have been swapped in between; it costs nothing and
         * closes the window. O_NONBLOCK guards against a FIFO swapped in,
         * which would otherwise block forever on open. */
        const int fd = openat(parent_fd, name,
                              O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd == -1) {
            if (errno == ENOENT) return 0;
            if (errno == EACCES || errno == EPERM || errno == ELOOP) {
                /* Unreadable or swapped for a link: record the metadata that
                 * fstatat already gave us, without a hash, and mark it so diff
                 * cannot read the absence of a hash as "unchanged". */
                e.unverified = true;
                e.unreadable = true;
                wc->n_unreadable++;
            } else {
                belay_err_set(BELAY_ERR_IO, errno, "manifest: openat %s", rel);
                return -1;
            }
        } else {
            if (e.size > wc->opts->hash_max_bytes) {
                /* Too large to hash: diff must report any change to this as
                 * "modified (unverified)", never as unchanged. */
                e.unverified = true;
            } else if (hash_fd(fd, e.sha256_hex) == 0) {
                e.has_hash = true;
            } else {
                close(fd);
                return -1;
            }
            close(fd);
        }
    }

    if (e.type == BELAY_T_DIR && crossed) e.is_mount = true;

    if (collect_push(wc->out, &e) == -1) return -1;
    const size_t idx = wc->out->n - 1;

    if (e.type == BELAY_T_DIR && !crossed) {
        if (depth >= MAX_DEPTH) {
            belay_err_set(BELAY_ERR_RANGE, 0,
                          "manifest: directory depth exceeds %d at %s", MAX_DEPTH, rel);
            return -1;
        }
        /* O_NOFOLLOW: if this name is a symlink now (swapped since fstatat),
         * the open fails rather than escaping the scope. */
        const int cfd = openat(parent_fd, name,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (cfd == -1) {
            if (errno == ENOENT) { wc->n_vanished++; return 0; }
            if (errno == ELOOP || errno == ENOTDIR) {
                /* Replaced by a symlink or a non-directory between the fstatat
                 * and this open. The entry is already recorded with its old
                 * type; mark it so the inconsistency is visible. */
                wc->out->v[idx].unreadable = true;
                wc->n_unreadable++;
                return 0;
            }
            if (errno == EACCES || errno == EPERM) {
                /* THE SUBTREE IS ABSENT FROM THE MANIFEST. Flagging is
                 * mandatory: without it this is byte-identical to an empty
                 * directory, and diff would report "unchanged" about files it
                 * never saw. Found by independent review (§0.4b). */
                wc->out->v[idx].unreadable = true;
                wc->n_unreadable++;
                return 0;
            }
            belay_err_set(BELAY_ERR_IO, errno, "manifest: openat dir %s", rel);
            return -1;
        }
        const int r = walk(cfd, rel, relsz, rel_len, depth + 1, wc);
        close(cfd);
        if (r != 0) return r;
    }

    return 0;
}

static int walk(int dfd, char *rel, size_t relsz, size_t rel_len,
                int depth, struct walk_ctx *wc) {
    /* fdopendir takes ownership of the fd for readdir purposes but the caller
     * still closes it, so dup it: closedir would otherwise close a descriptor
     * the caller also closes. */
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
        rel[rel_len] = '\0';   /* restore for the next sibling */
        if (rc != 0) break;
    }

    closedir(d);
    return rc;
}

/* Emits one entry as a JSON object followed by a newline. */
static int emit(FILE *f, const struct belay_entry *e) {
    char escaped[4096 * 6 + 1];

    if (fputc('{', f) == EOF) goto io;

    if (belay_utf8_valid(e->path, e->path_len)) {
        if (belay_json_escape(escaped, sizeof escaped, e->path, e->path_len) == -1) return -1;
        if (fprintf(f, "\"path\":\"%s\"", escaped) < 0) goto io;
    } else {
        /* Not valid UTF-8: raw bytes go in path_b64 so nothing is lost. */
        char b64[4096 * 2];
        if (belay_base64_encode(b64, sizeof b64, e->path, e->path_len) == -1) return -1;
        if (fprintf(f, "\"path_b64\":\"%s\"", b64) < 0) goto io;
    }

    if (fprintf(f,
                ",\"type\":\"%s\",\"mode\":%u,\"uid\":%u,\"gid\":%u"
                ",\"size\":%llu,\"mtime_ns\":%lld,\"ctime_ns\":%lld"
                ",\"ino\":%llu,\"dev\":%llu,\"nlink\":%llu",
                type_name(e->type), e->mode, e->uid, e->gid,
                (unsigned long long)e->size,
                (long long)e->mtime_ns, (long long)e->ctime_ns,
                (unsigned long long)e->ino, (unsigned long long)e->dev,
                (unsigned long long)e->nlink) < 0) goto io;

    if (e->has_hash && fprintf(f, ",\"sha256\":\"%s\"", e->sha256_hex) < 0) goto io;
    if (e->unverified && fprintf(f, ",\"unverified\":true") < 0) goto io;

    if (e->has_link_target) {
        if (belay_utf8_valid(e->link_target, e->link_target_len)) {
            if (belay_json_escape(escaped, sizeof escaped,
                                  e->link_target, e->link_target_len) == -1) return -1;
            if (fprintf(f, ",\"link_target\":\"%s\"", escaped) < 0) goto io;
        } else {
            char b64[4096 * 2];
            if (belay_base64_encode(b64, sizeof b64,
                                    e->link_target, e->link_target_len) == -1) return -1;
            if (fprintf(f, ",\"link_target_b64\":\"%s\"", b64) < 0) goto io;
        }
        if (e->target_outside_scope &&
            fprintf(f, ",\"target_outside_scope\":true") < 0) goto io;
    }

    if (e->has_stored && fprintf(f, ",\"stored\":\"%s\"", e->stored_hex) < 0) goto io;
    if (e->is_mount && fprintf(f, ",\"mount\":true") < 0) goto io;
    if (e->unreadable && fprintf(f, ",\"unreadable\":true") < 0) goto io;

    if (fputs("}\n", f) == EOF) goto io;
    return 0;

io:
    belay_err_set(BELAY_ERR_IO, errno, "manifest: write failed");
    return -1;
}

int belay_manifest_write(const char *out_path, const char *scope,
                         const struct belay_manifest_opts *opts,
                         size_t *n_entries) {
    if (out_path == NULL || scope == NULL || opts == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_write: null argument");
        return -1;
    }

    /* Argument validation is lexical (§5.1.1): reject ".." before touching
     * the filesystem, so a malformed scope never reaches realpath. */
    char nscope[4096];
    if (belay_path_normalize(nscope, sizeof nscope, scope) == -1) return -1;

    /* The one and only realpath. Everything after this is relative to the fd
     * it produces. */
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

    struct collect c = { NULL, 0, 0 };
    struct walk_ctx wc = { &c, opts, (uint64_t)rst.st_dev, real, 0, 0 };

    char rel[4096];
    rel[0] = '\0';

    int rc = walk(root_fd, rel, sizeof rel, 0, 0, &wc);
    close(root_fd);

    if (rc == 0) {
        /* Bytewise order is a format guarantee the comparator depends on. */
        qsort(c.v, c.n, sizeof *c.v, entry_cmp);

        FILE *f = fopen(out_path, "wb");
        if (f == NULL) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot create %s", out_path);
            rc = -1;
        } else {
            char esc_scope[4096 * 6 + 1];
            if (belay_json_escape(esc_scope, sizeof esc_scope, real, strlen(real)) == -1) {
                rc = -1;
            } else if (fprintf(f,
                        "{\"belay_manifest\":%d,\"created_ns\":0,\"scopes\":[\"%s\"]"
                        ",\"hash\":\"sha256\",\"hash_max_bytes\":%llu"
                        ",\"store_max_bytes\":%llu}\n",
                        BELAY_MANIFEST_VERSION, esc_scope,
                        (unsigned long long)opts->hash_max_bytes,
                        (unsigned long long)opts->store_max_bytes) < 0) {
                belay_err_set(BELAY_ERR_IO, errno, "manifest: header write failed");
                rc = -1;
            } else {
                for (size_t i = 0; i < c.n; i++) {
                    if (emit(f, &c.v[i]) == -1) { rc = -1; break; }
                }
            }
            if (fclose(f) != 0 && rc == 0) {
                belay_err_set(BELAY_ERR_IO, errno, "manifest: close failed");
                rc = -1;
            }
        }
    }

    if (rc == 0 && n_entries != NULL) *n_entries = c.n;

    free(c.v);
    free(real);
    return rc;
}
