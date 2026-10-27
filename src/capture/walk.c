/*
 *  Traversal: lists each directory and visits each name, depth first; a
 *  directory is emitted after its subtree, so a change during its own listing
 *  can still be recorded on it.
 */
#define _GNU_SOURCE
#include "capture_internal.h"

#include "belay/error.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

int cap_emit_scratch(struct walk_ctx *wc) { return cap_emit(wc, &wc->e); }



/* Records one entry and, for directories, recurses. Takes the parent dirfd and
 * the entry name; never a path string. */
static int visit(int parent_fd, const char *name, char *rel, size_t relsz,
                 size_t rel_len, int depth, struct walk_ctx *wc) {
    struct belay_entry *e = &wc->e;
    int cfd = -1;

    for (int attempt = 0; ; attempt++) {
        struct stat st;
        bool mount_root, mount_known;
        if (cap_stat_entry(wc, parent_fd, name, &st, &mount_root, &mount_known) == -1) {
            /* Vanished between readdir and stat: the tree changed under us. */
            if (errno == ENOENT) {
                outcome_apply(NULL, FACET_ENTRY, OUT_GONE, &wc->tally);
                return 0;
            }
            if (cap_fatal_errno(errno)) {
                belay_err_set(BELAY_ERR_IO, errno, "manifest: stat %s", rel);
                return -1;
            }
            /* EIO, or EACCES from an LSM: this entry cannot be recorded at all,
             * so the PARENT's listing is incomplete -- reported to cap_walk(). */
            return W_INCOMPLETE;
        }

        memset(e, 0, sizeof *e);
        wc->extras_done = false;
        if (rel_len >= sizeof e->path) {
            belay_err_set(BELAY_ERR_RANGE, 0, "manifest: path too long");
            return -1;
        }
        memcpy(e->path, rel, rel_len);
        e->path_len = rel_len;
        cap_fill_from_stat(e, &st);

        /* A mount root of ANY type is a capture boundary: recorded, never read
         * or descended. Where statx can say whether this is a mount root, its
         * answer is used alone: st_dev is only a proxy, and a wrong one both
         * ways -- a btrfs subvolume is a directory with its own st_dev but no
         * mount, and on overlayfs (xino off) every non-directory carries its
         * layer's device. Without statx (kernels before 5.8, or statx
         * blocked), st_dev decides for every type, except non-directories of
         * an overlayfs scope. (Directories-only everywhere hashed a file
         * bind-mounted from another filesystem as a local file -- verified.) */
        const bool crossed = mount_known ? mount_root
            : (uint64_t)st.st_dev != wc->root_dev &&
              (e->type == BELAY_T_DIR || !wc->scope_overlay);

        int r = V_OK;
        if (crossed) {
            outcome_apply(e, FACET_ENTRY, OUT_BOUNDARY, &wc->tally);
            if (e->type == BELAY_T_LNK) r = cap_read_link(parent_fd, name, &st, rel, wc);
        } else if (e->type == BELAY_T_LNK) {
            r = cap_read_link(parent_fd, name, &st, rel, wc);
        } else if (e->type == BELAY_T_REG) {
            r = cap_read_file(parent_fd, name, &st, rel, rel_len, wc);
        } else if (e->type == BELAY_T_DIR) {
            r = cap_open_dir(parent_fd, name, &st, rel, rel_len, depth, wc, &cfd);
        }

        if (r == -1) return -1;
        if (r == V_VANISHED) {
            outcome_apply(NULL, FACET_ENTRY, OUT_GONE, &wc->tally);
            return 0;
        }
        if (r == V_RACED && attempt + 1 < MAX_RACE_RETRIES) continue;   /* stat again */
        /* A symlink whose target could not be read reliably -- an I/O error, a
         * target too long, or still changing after several tries -- is
         * recorded unreadable, never dropped: dropping a link that never went
         * away would read as a deletion. Its target is recorded empty, which
         * no real symlink can have, so "unknown" stays unambiguous -- or, after
         * the retries ran out, the last one read. */
        if (r == V_UNREADABLE) outcome_apply(e, FACET_TARGET, OUT_DENIED, &wc->tally);
        if (r == V_RACED)      outcome_apply(e, FACET_TARGET, OUT_CHANGED, &wc->tally);
        /* Entries not reached through an open fd -- symlinks, FIFOs,
         * devices, anything that could not be opened -- get their extras
         * through O_PATH. Mount points are never read. */
        if (!e->is_mount && !wc->extras_done &&
            cap_read_extras(wc, -1, parent_fd, name, &st) == -1) {
            if (cfd != -1) close(cfd);
            return -1;
        }
        break;
    }

    /*
     *  A directory whose ctime falls between the start of the walk and NOW
     *  changed while belay was walking. Together with the per-directory window
     *  check below, this covers a file moved between two directories listed
     *  at different moments -- which otherwise vanishes from both listings
     *  with a clean trailer (verified).
     *
     *  The upper bound matters. A ctime in the FUTURE is not a change during
     *  the walk: it is left over from a backward clock step before the walk.
     *  WSL steps its clock back ~100 s at a time (measured twice: 101 s and
     *  108 s); with only a lower bound, every directory edited in the last
     *  ~100 s was flagged after each step. "Now" is read after the stat, so a
     *  change during the walk lands at or below it unless the clock stepped
     *  back meanwhile -- and then this rule merely misses it: the end-of-walk
     *  re-check, which compares by equality, does not depend on the clock.
     */
    if (cfd != -1 && !e->unstable && e->ctime_ns >= wc->walk_start_ns) {
        struct timespec now;
        wc->ops->clock(wc->ops->ctx, BELAY_CLOCK_REAL, &now);
        if (e->ctime_ns <= ident_ns((int64_t)now.tv_sec, now.tv_nsec))
            outcome_apply(e, FACET_LISTING, OUT_CHANGED, &wc->tally);
    }

    if (cfd == -1) return cap_emit_scratch(wc);

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

    int r = cap_walk(cfd, rel, relsz, rel_len, depth + 1, wc);
    if (r == 0 || r == W_INCOMPLETE) {
        struct stat post;
        const struct ident di = ident_of_entry(dir);
        struct ident pi;
        const bool incomplete = (r == W_INCOMPLETE) ||
            wc->ops->fstat(wc->ops->ctx, cfd, &post) == -1 ||
            (pi = ident_of_stat(&post), !ident_same(&pi, &di, ID_TIMES));
        if (incomplete) outcome_apply(dir, FACET_LISTING, OUT_CHANGED, &wc->tally);
        r = 0;
    }
    close(cfd);
    if (r == 0) r = cap_emit(wc, dir);
    free(dir);
    return r;
}

/*
 *  Lists one directory and visits each entry. Returns 0, -1 (fatal: belay's
 *  own resource exhaustion or an output error), or W_INCOMPLETE when the
 *  listing could not be fully captured -- a readdir error part way through,
 *  or a child that could not even be stat'ed. The caller then flags the
 *  directory unstable rather than failing the whole check.
 */
int cap_walk(int dfd, char *rel, size_t relsz, size_t rel_len,
                int depth, struct walk_ctx *wc) {
    const struct fsops *ops = wc->ops;
    void *d = ops->dir_open(ops->ctx, dfd);
    if (d == NULL) {
        if (cap_fatal_errno(errno)) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: fdopendir");
            return -1;
        }
        return W_INCOMPLETE;
    }

    int rc = 0;
    bool incomplete = false;
    for (;;) {
        const char *dname = ops->dir_next(ops->ctx, d);
        if (dname == NULL) {
            if (errno != 0) {
                if (cap_fatal_errno(errno)) {
                    belay_err_set(BELAY_ERR_IO, errno, "manifest: readdir");
                    rc = -1;
                } else {
                    incomplete = true;         /* EIO part way through */
                }
            }
            break;
        }
        if (strcmp(dname, ".") == 0 || strcmp(dname, "..") == 0) continue;

        const ssize_t nlen = rel_join(rel, relsz, rel_len, dname);
        if (nlen == -1) {
            belay_err_clear();
            incomplete = true;                 /* cannot be named within PATH_CAP */
            continue;
        }

        const int v = visit(dfd, dname, rel, relsz, (size_t)nlen, depth, wc);
        rel[rel_len] = '\0';
        if (v == W_INCOMPLETE) { incomplete = true; continue; }
        if (v != 0) { rc = v; break; }
    }

    ops->dir_close(ops->ctx, d);
    if (rc != 0) return rc;
    return incomplete ? W_INCOMPLETE : 0;
}
