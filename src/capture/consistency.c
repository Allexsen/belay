/*
 *  Walk consistency: every judgment of whether something changed while belay
 *  was looking at it, and the end-of-walk validator. Capture code reports
 *  what these decide through outcome_apply; nothing else decides it. No clock
 *  is read here: every judgment compares two observations of the same entry.
 */
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
 *  recorded nowhere, with a clean trailer (verified).
 *
 *  So when the walk is over -- at T_w, the instant the manifest describes --
 *  every recorded entry is stat'ed again and compared with what was
 *  recorded, by EQUALITY. Recorded at t <= T_w and validated at v >= T_w,
 *  unchanged in between, it held at T_w. A directory whose listing may no
 *  longer hold is flagged unstable; any other entry that changed is flagged
 *  raced. This runs before the output file is created, so belay's own output
 *  is never seen as a change.
 *
 *  A listed directory is also LISTED again and its names compared with the
 *  ones the walk saw (struct listing). Equal attributes do not prove an
 *  equal listing: an NFS client served a listing older than the attributes
 *  it reported for the same directory, so a file moved between two
 *  directories was in neither, with every timestamp equal (measured in CI,
 *  2026-10-28: 6 such clean manifests in 3,400 under a same-client writer;
 *  a fresh listing right after showed the file). The comparison checks the
 *  listing itself, so it needs no timestamp and no clock.
 *
 *  This one pass replaced two earlier rules whose catches it also makes: a
 *  ctime window ("changed between the walk's start and now", which read the
 *  wall clock and misfired when WSL stepped it) and a per-directory check
 *  after each subtree (a change there leaves the directory's ctime unequal
 *  at validation too).
 *
 *  Entries are reached the way the walk reached them: component by component
 *  with openat(O_NOFOLLOW) from the scope root, never as a path string the
 *  kernel would resolve through symlinks, and never into a mount the walk
 *  would not have entered (cap_crossed: a mount that appeared during the walk
 *  is stat'ed, as its root was, but nothing below it is touched). A stack of
 *  open directories is shared between neighbouring paths, and runs are
 *  sorted, so this costs about one open per directory. Depth is bounded by
 *  MAX_DEPTH: nothing is recorded below a directory the walk did not open.
 *
 *  What equality cannot see (known limits, NOTES/known-issues.md): a change
 *  within one timestamp tick of the recorded stat, where timestamps are
 *  coarser than the change (FAT, HFS+, kernels before 6.13); changes a
 *  remote client made that this machine's attribute cache has not seen.
 */
struct rstack {
    const struct walk_ctx *wc;
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
 * directory, or is now a capture boundary, so nothing at or below it can be
 * verified; -1 on a fatal error. */
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
        const struct fsops *ops = rs->wc->ops;
        /* Stat before opening: a mount root is a boundary, as in the walk.
         * Then the opened directory must be the one stat'ed. */
        struct stat st, ost;
        bool mr, mk;
        if (cap_stat_entry(rs->wc, parent, name, &st, &mr, &mk) == -1) {
            if (cap_fatal_errno(errno)) {
                belay_err_set(BELAY_ERR_IO, errno, "manifest: re-check: stat");
                return -1;
            }
            return 1;
        }
        if (!S_ISDIR(st.st_mode) || cap_crossed(rs->wc, &st, mr, mk)) return 1;
        const int fd = ops->openat(ops->ctx, parent, name,
                                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd == -1) {
            if (cap_fatal_errno(errno)) {
                belay_err_set(BELAY_ERR_IO, errno, "manifest: re-check: openat");
                return -1;
            }
            return 1;
        }
        const struct ident si = ident_of_stat(&st);
        struct ident oi;
        if (ops->fstat(ops->ctx, fd, &ost) == -1 ||
            (oi = ident_of_stat(&ost), !ident_same(&oi, &si, ID_OBJECT))) {
            close(fd);
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

/* Two FNV-1a lanes with different offsets, summed over names so that the
 * order readdir returns them in does not matter. */
void cons_listing_add(struct listing *l, const char *name) {
    uint64_t a = 0xcbf29ce484222325ull, b = 0x84222325cbf29ce4ull;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        a = (a ^ *p) * 0x100000001b3ull;
        b = (b ^ *p) * 0x100000001b3ull;
        b ^= b >> 29;
    }
    l->n++;
    l->a += a;
    l->b += b;
}

/* The names in directory `fd` now, through a new open of it: a stream
 * shares its file offset with every dup of the fd, and the walk's ran to
 * the end. 0, 1 if it can no longer be listed, -1 if fatal. */
static int relist(const struct fsops *ops, int fd, struct listing *now) {
    const int d = ops->openat(ops->ctx, fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (d == -1) {
        if (cap_fatal_errno(errno)) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: re-check: openat");
            return -1;
        }
        return 1;
    }
    void *dir = ops->dir_open(ops->ctx, d);
    close(d);
    if (dir == NULL) return cap_fatal_errno(errno) ? -1 : 1;
    const char *name;
    while ((name = ops->dir_next(ops->ctx, dir)) != NULL)
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) cons_listing_add(now, name);
    const int err = errno;
    ops->dir_close(ops->ctx, dir);
    return err != 0 ? 1 : 0;
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

/* Re-checks one entry: *changed set. 0, or -1 if fatal. `seen` is the
 * listing the walk recorded for a directory. */
static int recheck_one(struct rstack *rs, struct walk_ctx *wc, const struct belay_entry *e,
                       const struct listing *seen, int kind, bool *changed) {
    *changed = false;
    if (kind == RC_NONE) return 0;
    const struct ident rec = ident_of_entry(e);
    const unsigned char *path = (const unsigned char *)e->path;
    const size_t plen = e->path_len;

    struct stat st;
    bool same = false;
    if (plen == 1 && path[0] == '.') {
        /* Through the held fd, and again by the scope's path: a mount placed
         * over the scope during the walk leaves the fd as it was. */
        struct stat by_path;
        same = wc->ops->fstat(wc->ops->ctx, rs->root_fd, &st) == 0 &&
               wc->ops->fstatat(wc->ops->ctx, AT_FDCWD, wc->scope, &by_path,
                                AT_SYMLINK_NOFOLLOW) == 0;
        if (same) {
            const struct ident f = ident_of_stat(&st), p = ident_of_stat(&by_path);
            same = ident_same(&f, &p, ID_OBJECT);
        }
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
    if (same && kind == RC_LISTING) {
        const int fd = rs->n && !(plen == 1 && path[0] == '.') ? rs->fd[rs->n - 1] : rs->root_fd;
        struct listing now = { 0, 0, 0 };
        const int r = relist(wc->ops, fd, &now);
        if (r == -1) return -1;
        same = r == 0 && now.n == seen->n && now.a == seen->a && now.b == seen->b;
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
    rs->wc = wc;
    if (runs_rewind(wc->runs) == -1) goto done;
    const unsigned char *key, *val;
    uint32_t klen, vlen;
    int got;
    while ((got = runs_next(wc->runs, &key, &klen, &val, &vlen)) == 1) {
        struct listing seen;
        if (cap_record_unpack(val, vlen, key, klen, e, &seen) == -1) goto done;
        const int kind = recheck_kind(e);
        bool changed;
        if (recheck_one(rs, wc, e, &seen, kind, &changed) == -1) goto done;
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

/* ------------------------------------------------------------------------ */
/* Judgments during the walk                                                 */
/* ------------------------------------------------------------------------ */

/* A regular file's open fd against the fstatat whose metadata was recorded:
 * same file, same moment -- including mtime and ctime, so a same-size
 * rewrite in between cannot pair the old timestamps with the new content's
 * hash. */
bool cons_file_opened(const struct stat *recorded, const struct stat *opened) {
    const struct ident o = ident_of_stat(opened), r = ident_of_stat(recorded);
    return ident_same(&o, &r, ID_OBJECT | ID_TYPE | ID_SIZE | ID_TIMES);
}

/* The read pass: size and timestamps unchanged across it, and every byte the
 * size promised was read. (Not proof the bytes are one state: a write already
 * in flight when the read began updates the timestamps first -- see the spec,
 * "What a hash, and a stored copy, prove".) */
bool cons_file_read(const struct stat *opened, const struct stat *after, uint64_t nread) {
    const struct ident a = ident_of_stat(after), b = ident_of_stat(opened);
    return ident_same(&a, &b, ID_SIZE | ID_TIMES) && nread == b.size;
}

/* A symlink re-stat'ed after its target was read: the target must belong to
 * the link whose metadata was recorded (same inode, unchanged ctime, size
 * equal to the target's length), or a swapped link would record one link's
 * target with another's metadata. */
bool cons_link_read(const struct stat *recorded, const struct stat *again, size_t target_len) {
    const struct ident a = ident_of_stat(again), r = ident_of_stat(recorded);
    return ident_same(&a, &r, ID_OBJECT | ID_CTIME) && a.size == (uint64_t)target_len;
}

/* A directory's open fd against its recorded stat. Not the same object:
 * DENIED -- swapping two directories between the stat and the open recorded
 * A's mode and inode with B's contents, and lost A's contents, with a clean
 * trailer (verified). Same object, changed since: CHANGED -- its listing will
 * not describe the state its metadata records; still walked, but flagged. */
enum outcome cons_dir_opened(const struct stat *recorded, const struct stat *opened) {
    const struct ident o = ident_of_stat(opened), r = ident_of_stat(recorded);
    if (!ident_same(&o, &r, ID_OBJECT)) return OUT_DENIED;
    return ident_same(&o, &r, ID_TIMES) ? OUT_OK : OUT_CHANGED;
}
