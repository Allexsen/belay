/*
 *  The platform adapter: every filesystem and clock call capture makes.
 *
 *  Capture never calls the OS directly. It calls these, through a table, so
 *  (a) platform differences live in src/platform/fsops_<os>.c and nowhere
 *  else, and (b) tests can wrap the table -- a decorator that makes one call
 *  fail, or changes the tree at the exact moment of another -- on every
 *  platform, without linker tricks.
 *
 *  Contract: the POSIX one. Each call returns what its POSIX counterpart
 *  returns and sets errno the same way, so a decorator can reproduce any
 *  failure exactly. `ctx` is passed back untouched.
 */
#ifndef BELAY_CAPTURE_FSOPS_H
#define BELAY_CAPTURE_FSOPS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

/* Where an entry's extended attributes are read from: its open fd, or a
 * handle the platform opened for the purpose (see xattr_source_open). */
struct xsrc { int fd; const char *path; int own; char buf[64]; };

struct fsops {
    void *ctx;

    /* lstat that also says whether the entry is a mount root. Where the
     * platform cannot say (no statx, an old kernel), *mount_known is false
     * and the caller decides by st_dev. "" with dfd stats dfd itself.
     * -1/ENOSYS when the facility is missing altogether. */
    int (*stat_mount)(void *ctx, int dfd, const char *name, struct stat *st,
                      bool *mount_root, bool *mount_known);
    int (*fstatat)(void *ctx, int dfd, const char *name, struct stat *st, int flags);
    int (*fstat)(void *ctx, int fd, struct stat *st);
    int (*openat)(void *ctx, int dfd, const char *name, int flags);
    ssize_t (*readlinkat)(void *ctx, int dfd, const char *name, char *buf, size_t n);
    ssize_t (*read)(void *ctx, int fd, void *buf, size_t n);

    /* A directory stream over dfd (which stays open and owned by the caller).
     * dir_next returns the next name, or NULL with errno 0 at the end and
     * errno set on an error. */
    void       *(*dir_open)(void *ctx, int dfd);
    const char *(*dir_next)(void *ctx, void *dir);
    void        (*dir_close)(void *ctx, void *dir);

    /* Extended metadata. xattr_source_open reaches an entry that has no
     * open fd (from its parent and name) without following a symlink, and
     * checks it is the object `st` describes: 0, or -1 with errno (EXDEV for
     * "not the recorded object", ENOTSUP for "no safe way on this platform").
     * The list and get calls behave like flistxattr/fgetxattr. */
    int     (*xattr_source_open)(void *ctx, int pfd, const char *name, const struct stat *st,
                                 struct xsrc *x);
    void    (*xattr_source_close)(void *ctx, struct xsrc *x);
    ssize_t (*xattr_list)(void *ctx, const struct xsrc *x, char *buf, size_t n);
    ssize_t (*xattr_get)(void *ctx, const struct xsrc *x, const char *name, void *buf, size_t n);
    /* Inode flags of the entry, through its fd (-1 when it has none) or its
     * stat: 0, or -1 when this platform or filesystem has none to report. */
    int     (*inode_flags)(void *ctx, int fd, const struct stat *st, uint64_t *out);

    /* Scope properties, asked once per walk. */
    bool (*is_overlay)(void *ctx, int root_fd);

    /* Whether, at this instant, some process has the regular file open for
     * writing or mapped shared-writable: 1 yes, 0 no, -1 cannot tell (no
     * facility on this platform or filesystem, or not permitted). Must not
     * leave anything held on the file. Gates the content store (capture.c). */
    int (*writer_present)(void *ctx, int fd);
    /* Bracket every writer_present call of one capture: begin prepares what
     * the probe needs, end puts it back (Linux: SIGIO, see fsops_linux.c).
     * Captures may overlap in one process; the platform counts them. */
    void (*probe_begin)(void *ctx);
    void (*probe_end)(void *ctx);

    /* Wall-clock time, for the header's created_ns only: walk consistency
     * reads no clock (consistency.c). */
    int (*clock)(void *ctx, struct timespec *ts);

    /* An anonymous temporary file in `dir`, never linked into it where the
     * platform allows (so the directory does not change), else created from
     * `tmpl` and unlinked at once. A stdio stream, or NULL with errno. */
    FILE *(*tmpfile_in)(void *ctx, const char *dir, const char *tmpl);
};

/* The table for this platform. */
const struct fsops *fsops_default(void);

#endif
