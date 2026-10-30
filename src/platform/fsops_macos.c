/*
 *  Platform adapter, macOS.
 *
 *  No statx: mount roots are decided by st_dev. Inode flags are st_flags
 *  (chflags), available for every type from the stat. Extended attributes go
 *  through an fd; a symlink is opened with O_SYMLINK, which opens the link
 *  itself. FIFOs, sockets and devices have no safe fd (opening them has side
 *  effects), so their attributes are reported as unreachable.
 */
#define _DARWIN_C_SOURCE
#include "fsops_posix.h"
#include "capture/ident.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <unistd.h>

static int macos_stat_mount(void *ctx, int dfd, const char *name, struct stat *st,
                            bool *mount_root, bool *mount_known) {
    (void)ctx; (void)dfd; (void)name; (void)st;
    *mount_root = *mount_known = false;
    errno = ENOSYS;
    return -1;
}

static int macos_xattr_source_open(void *ctx, int pfd, const char *name, const struct stat *st,
                                   struct xsrc *x) {
    (void)ctx;
    x->fd = -1;
    x->path = NULL;
    x->own = -1;
    if (!S_ISLNK(st->st_mode)) {
        errno = ENOTSUP;
        return -1;
    }
    x->own = openat(pfd, name, O_RDONLY | O_SYMLINK | O_CLOEXEC);
    if (x->own == -1) return -1;
    struct stat os;
    if (fstat(x->own, &os) == -1) return -1;
    const struct ident oi = ident_of_stat(&os), ri = ident_of_stat(st);
    if (!ident_same(&oi, &ri, ID_OBJECT)) {
        errno = EXDEV;
        return -1;
    }
    x->fd = x->own;
    return 0;
}

static void macos_xattr_source_close(void *ctx, struct xsrc *x) {
    (void)ctx;
    if (x->own != -1) close(x->own);
    x->own = -1;
}

static ssize_t macos_xattr_list(void *ctx, const struct xsrc *x, char *buf, size_t n) {
    (void)ctx;
    return flistxattr(x->fd, buf, n, 0);
}

static ssize_t macos_xattr_get(void *ctx, const struct xsrc *x, const char *name, void *buf,
                               size_t n) {
    (void)ctx;
    return fgetxattr(x->fd, name, buf, n, 0, 0);
}

static int macos_inode_flags(void *ctx, int fd, const struct stat *st, uint64_t *out) {
    (void)ctx; (void)fd;
    *out = (uint64_t)st->st_flags;      /* uchg, schg, hidden... */
    return 0;
}

static bool macos_is_overlay(void *ctx, int root_fd) {
    (void)ctx; (void)root_fd;
    return false;
}

/* No lease API: macOS cannot tell whether a writer has the file open, so
 * the content store is unguarded here (spec, "What a hash, and a stored
 * copy, prove"). */
static int macos_writer_present(void *ctx, int fd) {
    (void)ctx; (void)fd;
    return -1;
}

static void macos_probe_noop(void *ctx) { (void)ctx; }

static int macos_clock(void *ctx, struct timespec *ts) {
    (void)ctx;
    return clock_gettime(CLOCK_REALTIME, ts);
}

static FILE *macos_tmpfile_in(void *ctx, const char *dir, const char *tmpl) {
    (void)ctx; (void)dir;
    return posix_tmpfile_named(tmpl);
}

static const struct fsops macos_ops = {
    .ctx = NULL,
    .stat_mount = macos_stat_mount,
    .fstatat = posix_fstatat,
    .fstat = posix_fstat,
    .openat = posix_openat,
    .readlinkat = posix_readlinkat,
    .read = posix_read,
    .dir_open = posix_dir_open,
    .dir_next = posix_dir_next,
    .dir_close = posix_dir_close,
    .xattr_source_open = macos_xattr_source_open,
    .xattr_source_close = macos_xattr_source_close,
    .xattr_list = macos_xattr_list,
    .xattr_get = macos_xattr_get,
    .inode_flags = macos_inode_flags,
    .is_overlay = macos_is_overlay,
    .writer_present = macos_writer_present,
    .probe_begin = macos_probe_noop,
    .probe_end = macos_probe_noop,
    .clock = macos_clock,
    .tmpfile_in = macos_tmpfile_in,
    .fsync = posix_fsync,   /* reaches neither the disk nor an order: no F_FULLFSYNC (decided) */
};

const struct fsops *fsops_default(void) { return &macos_ops; }
