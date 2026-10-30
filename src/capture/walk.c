/*
 *  Traversal: lists each directory and visits each name, depth first; a
 *  directory is emitted after its subtree, so a listing that failed part way
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

int cap_emit_scratch(struct walk_ctx *wc) { return cap_emit(wc, &wc->e, NULL); }

/* What visit() did with one name. Only a RECORDED name goes into its
 * directory's listing (`seen`), which the end-of-walk re-list must match: a
 * name that vanished and came back before the walk ended is then a listing
 * change, never a file missing from a directory recorded as complete. */
enum visited { VISIT_RECORDED = 1, VISIT_GONE, VISIT_INCOMPLETE };

/* Records one entry and, for directories, recurses. Takes the parent dirfd and
 * the entry name; never a path string. Returns an enum visited, or -1. */
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
                return VISIT_GONE;
            }
            if (cap_fatal_errno(errno)) {
                belay_err_set(BELAY_ERR_IO, errno, "manifest: stat %s", rel);
                return -1;
            }
            /* EIO, or EACCES from an LSM: this entry cannot be recorded at all,
             * so the PARENT's listing is incomplete -- reported to cap_walk(). */
            return VISIT_INCOMPLETE;
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

        /* A mount root of any type is a capture boundary (cap_crossed). */
        const bool crossed = cap_crossed(wc, &st, mount_root, mount_known);

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
            return VISIT_GONE;
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

    if (cfd == -1) return cap_emit_scratch(wc) == -1 ? -1 : VISIT_RECORDED;

    /*
     *  A walked directory is emitted AFTER its subtree (order is fixed by the
     *  sort, so this costs nothing) so that a listing that failed part way can
     *  still be recorded on it. Whether it changed after it was recorded is
     *  the end-of-walk validator's question (consistency.c). The scratch
     *  entry is reused by the children, so keep a copy.
     */
    struct belay_entry *dir = malloc(sizeof *dir);
    if (dir == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        close(cfd);
        return -1;
    }
    memcpy(dir, e, sizeof *dir);

    struct listing seen = { 0, 0, 0 };
    int r = cap_walk(cfd, rel, relsz, rel_len, depth + 1, wc, &seen);
    if (r == W_INCOMPLETE) {
        outcome_apply(dir, FACET_LISTING, OUT_CHANGED, &wc->tally);
        r = 0;
    }
    close(cfd);
    if (r == 0) r = cap_emit(wc, dir, &seen);
    free(dir);
    return r == 0 ? VISIT_RECORDED : -1;
}

/*
 *  Lists one directory and visits each entry, adding each recorded name to
 *  `seen`.
 *  Returns 0, -1 (fatal: belay's
 *  own resource exhaustion or an output error), or W_INCOMPLETE when the
 *  listing could not be fully captured -- a readdir error part way through,
 *  or a child that could not even be stat'ed. The caller then flags the
 *  directory unstable rather than failing the whole check.
 */
int cap_walk(int dfd, char *rel, size_t relsz, size_t rel_len,
                int depth, struct walk_ctx *wc, struct listing *seen) {
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
        if (v == -1) { rc = -1; break; }
        if (v == VISIT_RECORDED) cons_listing_add(seen, dname);   /* what the re-list must match */
        else if (v == VISIT_INCOMPLETE) incomplete = true;
    }

    ops->dir_close(ops->ctx, d);
    if (rc != 0) return rc;
    return incomplete ? W_INCOMPLETE : 0;
}
