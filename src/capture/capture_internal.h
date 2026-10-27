/*
 *  What the capture stages share: limits, the walk context, and the stage
 *  functions. Private to src/capture/.
 *
 *    walk.c         traversal: order, depth, descent, retries
 *    capture.c      one entry: stat and mount boundary, file, link, directory,
 *                   extended metadata
 *    consistency.c  the end-of-walk re-check
 *    publish.c      temporaries, header, the output file
 *    manifest_write.c  the pipeline: walk -> capture -> sort -> consistency
 *                   -> serialize -> publish
 */
#ifndef BELAY_CAPTURE_INTERNAL_H
#define BELAY_CAPTURE_INTERNAL_H

#include "belay/manifest.h"
#include "belay/store.h"

#include "entry.h"
#include "fsops.h"
#include "ident.h"
#include "outcome.h"
#include "runs.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MAX_DEPTH  128
#define READ_CHUNK (64u * 1024u)
#define PATH_CAP   4096u               /* == sizeof(struct belay_entry).path */
#define LINE_CAP   (64u * 1024u)       /* one serialized entry; worst case < 50 KB */
#define RUN_BYTES  (4u * 1024u * 1024u)
#define SNIFF_BYTES 8000u              /* git's binary heuristic: a NUL in the
                                          first 8000 bytes means not text */
#define XLIST_CAP  (64u * 1024u)       /* XATTR_LIST_MAX: longest xattr name list */
#define NAME_BYTES 255                 /* longest entry name: a directory whose
                                          path exceeds PATH_CAP - 2 - NAME_BYTES
                                          may hold children that do not fit */
#define MAX_RACE_RETRIES 3

struct walk_ctx {
    const struct fsops *ops;
    const struct belay_manifest_opts *opts;
    uint64_t root_dev;
    const char *scope;
    struct runs *runs;          /* every entry, packed, sorted by path */
    unsigned char *pack;        /* ENTRY_PACK_MAX: one entry being packed */
    struct belay_entry e;       /* scratch; finished before any recursion */
    char *line;                 /* LINE_CAP */
    unsigned char *readbuf;     /* READ_CHUNK; also holds one xattr value */
    char  *xlist;               /* XLIST_CAP + 1: an entry's xattr name list */
    const char **xnames;        /* pointers into xlist, sorted */
    bool   extras_done;         /* this attempt already read the entry's extras */
    struct walk_tally tally;    /* what no emitted entry carries: vanished */

    /* Walk start, realtime ns (see belay_manifest_write): a directory whose
     * ctime lies between this and "now" changed during the walk. */
    int64_t walk_start_ns;

    /* Decided once per walk, never by one entry's error: whether statx works
     * here (a seccomp profile may answer EPERM for it), and whether the scope
     * root is on overlayfs, where non-directories carry their layer's
     * st_dev. Process-global state set by one entry's EPERM used to switch
     * mount detection off for every later walk. */
    bool statx_ok;
    bool scope_overlay;

    struct belay_store *store;  /* NULL when content storage is off */
    char  *abs;                 /* scope + "/" + rel, for interpreter claims */
    size_t scope_len;
};

/* Results of capturing one entry (0 is success; -1 is fatal). */
enum { V_OK = 0, V_VANISHED = 2, V_RACED = 3, V_UNREADABLE = 4,
       W_INCOMPLETE = 5 /* walk(): the listing could not be fully captured */ };

/* Verdicts of the end-of-walk re-check, one byte per record. */
enum { VERDICT_NONE, VERDICT_LISTING, VERDICT_ENTRY };

struct tmpdir {
    const struct fsops *ops;
    char dir[PATH_MAX + 32];
    char tmpl[PATH_MAX + 32];
};

/* capture.c */
bool cap_fatal_errno(int err);
int  cap_stat_entry(const struct walk_ctx *wc, int dfd, const char *name, struct stat *st,
                    bool *mount_root, bool *mount_known);
void cap_fill_from_stat(struct belay_entry *e, const struct stat *st);
int  cap_read_extras(struct walk_ctx *wc, int fd, int pfd, const char *name,
                     const struct stat *st);
int  cap_read_link(int pfd, const char *name, const struct stat *st, const char *rel,
                   struct walk_ctx *wc);
int  cap_read_file(int pfd, const char *name, const struct stat *st, const char *rel,
                   size_t rel_len, struct walk_ctx *wc);
int  cap_open_dir(int pfd, const char *name, const struct stat *st, const char *rel,
                  size_t rel_len, int depth, struct walk_ctx *wc, int *out_fd);
int  cap_emit(struct walk_ctx *wc, const struct belay_entry *e);

/* walk.c */
int  cap_walk(int dfd, char *rel, size_t relsz, size_t rel_len, int depth, struct walk_ctx *wc);

/* consistency.c: every judgment of "did it change while belay looked". */
void cons_walk_begin(struct walk_ctx *wc);
bool cons_file_opened(const struct stat *recorded, const struct stat *opened);
bool cons_file_read(const struct stat *opened, const struct stat *after, uint64_t nread);
bool cons_link_read(const struct stat *recorded, const struct stat *again, size_t target_len);
enum outcome cons_dir_opened(const struct stat *recorded, const struct stat *opened);
bool cons_changed_during_walk(const struct walk_ctx *wc, const struct belay_entry *dir);
bool cons_listing_held(const struct walk_ctx *wc, int dfd, const struct belay_entry *dir);
int  cap_recheck(struct walk_ctx *wc, int root_fd, struct belay_entry *e, FILE *verdicts);

/* publish.c */
FILE *cap_tmpfile(void *ctx);
int  cap_write_header(const struct fsops *ops, FILE *f, const char *scope_real,
                      const struct belay_manifest_opts *opts, char *buf);

#endif
