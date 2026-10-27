#define _GNU_SOURCE
#include "capture_internal.h"

#include "belay/error.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------------ */
/* End-of-walk re-check                                                      */
/* ------------------------------------------------------------------------ */

/*
 *  A walk is not a snapshot. An entry recorded early can change while the
 *  walk goes on, and a directory already listed can gain or lose entries: a
 *  file moved from a directory not yet listed into one already listed was
 *  recorded nowhere, with a clean trailer. The ctime window rule catches part
 *  of that, but only where file timestamps come from this machine's clock,
 *  finely enough -- not on NFS, SMB, WSL's /mnt/c, FUSE, or one-second
 *  filesystems (review round 3, F1). A file rewritten after it was hashed,
 *  while another is rewritten before it is reached, gave a state that never
 *  existed, again with a clean trailer (F2).
 *
 *  So when the walk is over, every recorded entry is stat'ed again and
 *  compared with what was recorded -- by EQUALITY, so no clock is involved.
 *  A directory whose listing may no longer hold is flagged unstable; any
 *  other entry that changed is flagged raced. This runs before the output
 *  file is created, so belay's own output is never seen as a change.
 *
 *  Entries are reached the way the walk reached them: component by component
 *  with openat(O_NOFOLLOW) from the scope root, never as a path string the
 *  kernel would resolve through symlinks. A stack of open directories is
 *  shared between neighbouring paths, and runs are sorted, so this costs
 *  about one open per directory. Depth is bounded by MAX_DEPTH: nothing is
 *  recorded below a directory the walk did not open.
 *
 *  What equality cannot see: a change within one timestamp tick of the
 *  recorded stat, on a filesystem whose timestamps are coarser than the
 *  change. The window rule covers part of that for local filesystems.
 */
struct rstack {
    const struct fsops *ops;
    int    root_fd;
    int    fd[MAX_DEPTH + 1];
    size_t end[MAX_DEPTH + 1];      /* fd[i] is the directory path[0..end[i]) */
    size_t n;
    char   path[PATH_CAP];
};

static void rs_pop_to(struct rstack *rs, size_t keep) {
    while (rs->n > keep) close(rs->fd[--rs->n]);
}

/* Makes the top of the stack the directory `dir` (dir_len bytes; 0 is the
 * scope root). Returns 0; 1 when a component can no longer be opened as a
 * directory, so nothing at or below it can be verified; -1 on a fatal error. */
static int rs_to(struct rstack *rs, const char *dir, size_t dir_len) {
    size_t keep = 0;                /* deepest level that is a component prefix */
    for (size_t i = rs->n; i > 0; i--) {
        const size_t e = rs->end[i - 1];
        if (e <= dir_len && memcmp(rs->path, dir, e) == 0 && (e == dir_len || dir[e] == '/')) {
            keep = i;
            break;
        }
    }
    rs_pop_to(rs, keep);
    for (size_t pos = keep ? rs->end[keep - 1] + 1 : 0; pos < dir_len; ) {
        size_t j = pos;
        while (j < dir_len && dir[j] != '/') j++;
        const size_t nl = j - pos;
        if (nl == 0 || nl > NAME_BYTES || rs->n == MAX_DEPTH + 1) return 1;
        char name[NAME_BYTES + 1];
        memcpy(name, dir + pos, nl);
        name[nl] = '\0';
        const int parent = rs->n ? rs->fd[rs->n - 1] : rs->root_fd;
        const int fd = rs->ops->openat(rs->ops->ctx, parent, name,
                                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd == -1) {
            if (cap_fatal_errno(errno)) {
                belay_err_set(BELAY_ERR_IO, errno, "manifest: re-check: openat");
                return -1;
            }
            return 1;
        }
        if (pos > 0) rs->path[pos - 1] = '/';
        memcpy(rs->path + pos, dir + pos, nl);
        rs->fd[rs->n] = fd;
        rs->end[rs->n] = j;
        rs->n++;
        pos = j + 1;
    }
    return 0;
}

/* How the end-of-walk re-check treats an entry: a directory whose listing
 * was recorded is re-checked as a listing (a change flags it unstable),
 * unless it is unstable already; everything else as an entry (a change flags
 * it raced). The verdict of each record goes, one byte per record in sorted
 * order, to a side stream the output pass reads back. */
enum { RC_NONE, RC_LISTING, RC_ENTRY };

static int recheck_kind(const struct belay_entry *e) {
    if (e->type == BELAY_T_DIR && !e->unreadable && !e->is_mount)
        return e->unstable ? RC_NONE : RC_LISTING;
    return RC_ENTRY;
}

/* Re-checks one entry: *changed set. 0, or -1 if fatal. */
static int recheck_one(struct rstack *rs, struct walk_ctx *wc, const struct belay_entry *e,
                       int kind, bool *changed) {
    *changed = false;
    if (kind == RC_NONE) return 0;
    const struct ident rec = ident_of_entry(e);
    const unsigned char *path = (const unsigned char *)e->path;
    const size_t plen = e->path_len;

    struct stat st;
    bool same = false;
    if (plen == 1 && path[0] == '.') {
        same = wc->ops->fstat(wc->ops->ctx, rs->root_fd, &st) == 0;
    } else if (kind == RC_LISTING) {
        const int r = rs_to(rs, (const char *)path, plen);
        if (r == -1) return -1;
        same = r == 0 && wc->ops->fstat(wc->ops->ctx, rs->fd[rs->n - 1], &st) == 0;
    } else {
        size_t base = plen;                             /* start of the last component */
        while (base > 0 && path[base - 1] != '/') base--;
        const int r = rs_to(rs, (const char *)path, base ? base - 1 : 0);
        if (r == -1) return -1;
        const size_t nl = plen - base;
        if (r == 0 && nl > 0 && nl <= NAME_BYTES) {
            char name[NAME_BYTES + 1];
            memcpy(name, path + base, nl);
            name[nl] = '\0';
            bool mr, mk;
            const int parent = rs->n ? rs->fd[rs->n - 1] : rs->root_fd;
            if (cap_stat_entry(wc, parent, name, &st, &mr, &mk) == 0) {
                same = true;
            } else if (cap_fatal_errno(errno)) {
                belay_err_set(BELAY_ERR_IO, errno, "manifest: re-check: stat");
                return -1;
            }
        }
    }
    if (same) {
        const struct ident now = ident_of_stat(&st);
        same = ident_same(&now, &rec, ID_ALL);
    }
    *changed = !same;
    return 0;
}

/* Re-checks every recorded entry, in sorted order, into `verdicts`. */
int cap_recheck(struct walk_ctx *wc, int root_fd, struct belay_entry *e, FILE *verdicts) {
    struct rstack *rs = calloc(1, sizeof *rs);
    int rc = -1;
    if (rs == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        return -1;
    }
    rs->root_fd = root_fd;
    rs->ops = wc->ops;
    if (runs_rewind(wc->runs) == -1) goto done;
    const unsigned char *key, *val;
    uint32_t klen, vlen;
    int got;
    while ((got = runs_next(wc->runs, &key, &klen, &val, &vlen)) == 1) {
        if (entry_unpack(val, vlen, key, klen, e) == -1) goto done;
        const int kind = recheck_kind(e);
        bool changed;
        if (recheck_one(rs, wc, e, kind, &changed) == -1) goto done;
        const int v = !changed ? VERDICT_NONE : kind == RC_LISTING ? VERDICT_LISTING : VERDICT_ENTRY;
        if (fputc(v, verdicts) == EOF) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: re-check: write failed");
            goto done;
        }
    }
    if (got == -1) goto done;
    if (fflush(verdicts) != 0 || fseek(verdicts, 0, SEEK_SET) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: re-check: write failed");
        goto done;
    }
    rc = 0;
done:
    rs_pop_to(rs, 0);
    free(rs);
    return rc;
}
