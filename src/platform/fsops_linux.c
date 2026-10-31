/*
 *  Platform adapter, Linux.
 *
 *  statx reports mount roots (STATX_ATTR_MOUNT_ROOT), bind mounts from the
 *  same filesystem included. AT_NO_AUTOMOUNT: walking a scope must not
 *  trigger autofs mounts (fstatat implies it since Linux 4.14; statx does
 *  not). An entry without an open fd is reached for its extended attributes
 *  through /proc/self/fd of an O_PATH|O_NOFOLLOW fd, which acts on the entry
 *  itself -- a symlink, never its target (verified).
 */
#define _GNU_SOURCE
#include "fsops_posix.h"
#include "capture/ident.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <linux/fs.h>                   /* FS_IOC_GETFLAGS */
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#define OVERLAYFS_MAGIC 0x794c7630      /* <linux/magic.h> OVERLAYFS_SUPER_MAGIC */

static int linux_stat_mount(void *ctx, int dfd, const char *name, struct stat *st,
                            bool *mount_root, bool *mount_known) {
    (void)ctx;
    *mount_root = *mount_known = false;
#ifdef STATX_ATTR_MOUNT_ROOT
    struct statx sx;
    const int flags = AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | (name[0] == '\0' ? AT_EMPTY_PATH : 0);
    if (statx(dfd, name, flags, STATX_BASIC_STATS, &sx) != 0) return -1;
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
    *mount_known = (sx.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT) != 0;
    *mount_root  = *mount_known && (sx.stx_attributes & STATX_ATTR_MOUNT_ROOT);
    return 0;
#else
    (void)dfd; (void)name; (void)st;
    errno = ENOSYS;
    return -1;
#endif
}

static int linux_xattr_source_open(void *ctx, int pfd, const char *name, const struct stat *st,
                                   struct xsrc *x) {
    (void)ctx;
    x->fd = -1;
    x->path = NULL;
    x->own = openat(pfd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (x->own == -1) return -1;
    struct stat os;
    if (fstat(x->own, &os) == -1) return -1;
    const struct ident oi = ident_of_stat(&os), ri = ident_of_stat(st);
    if (!ident_same(&oi, &ri, ID_OBJECT)) {           /* not the entry recorded */
        errno = EXDEV;
        return -1;
    }
    snprintf(x->buf, sizeof x->buf, "/proc/self/fd/%d", x->own);
    x->path = x->buf;
    return 0;
}

static void linux_xattr_source_close(void *ctx, struct xsrc *x) {
    (void)ctx;
    if (x->own != -1) close(x->own);
    x->own = -1;
}

static ssize_t linux_xattr_list(void *ctx, const struct xsrc *x, char *buf, size_t n) {
    (void)ctx;
    return x->path != NULL ? listxattr(x->path, buf, n) : flistxattr(x->fd, buf, n);
}

static ssize_t linux_xattr_get(void *ctx, const struct xsrc *x, const char *name, void *buf,
                               size_t n) {
    (void)ctx;
    return x->path != NULL ? getxattr(x->path, name, buf, n) : fgetxattr(x->fd, name, buf, n);
}

/* Through an fd only: a symlink, FIFO or device has no safe one to ask. */
static int linux_inode_flags(void *ctx, int fd, const struct stat *st, uint64_t *out) {
    (void)ctx; (void)st;
    int fl;
    if (fd == -1 || ioctl(fd, FS_IOC_GETFLAGS, &fl) != 0) return -1;
    *out = (uint32_t)fl;
    return 0;
}

static bool linux_is_overlay(void *ctx, int root_fd) {
    (void)ctx;
    struct statfs sfs;
    return fstatfs(root_fd, &sfs) == 0 && sfs.f_type == OVERLAYFS_MAGIC;
}

/*
 *  A read lease is granted only while no process has the file open for
 *  writing or mapped shared-writable (both keep the inode's write count up),
 *  so taking one and releasing it at once answers the question without
 *  holding anything: a writer is never blocked by more than these two calls.
 *  A write(2) in flight holds its file open, so one already copying data
 *  when the read begins is always seen.
 *
 *  Any other error means "cannot tell": EACCES (the file is not ours and we
 *  lack CAP_LEASE), EINVAL (a filesystem that does not support leases).
 */
static int linux_writer_present(void *ctx, int fd) {
    (void)ctx;
    if (fcntl(fd, F_SETLEASE, F_RDLCK) == 0) {
        fcntl(fd, F_SETLEASE, F_UNLCK);
        return 0;
    }
    return errno == EAGAIN ? 1 : -1;
}

/*
 *  A writer opening the file inside the probe's window breaks the lease, and
 *  the kernel tells the holder with SIGIO, whose default action ends the
 *  process. So while a capture probes, SIGIO at its default action is set to
 *  ignored; a handler the host installed is left alone (it may see a
 *  spurious SIGIO). When the last overlapping capture ends, the disposition
 *  is put back -- unless the host changed it meanwhile. libbelay is a
 *  library: the host must not inherit a process-wide signal change.
 */
static pthread_mutex_t sigio_lock = PTHREAD_MUTEX_INITIALIZER;
static int sigio_captures;
static bool sigio_changed;
static struct sigaction sigio_saved;

static void linux_probe_begin(void *ctx) {
    (void)ctx;
    pthread_mutex_lock(&sigio_lock);
    if (sigio_captures++ == 0) {
        struct sigaction cur;
        sigio_changed = false;
        if (sigaction(SIGIO, NULL, &cur) == 0 && !(cur.sa_flags & SA_SIGINFO) &&
            cur.sa_handler == SIG_DFL) {
            struct sigaction ign;
            memset(&ign, 0, sizeof ign);
            ign.sa_handler = SIG_IGN;
            sigemptyset(&ign.sa_mask);
            sigio_changed = sigaction(SIGIO, &ign, &sigio_saved) == 0;
        }
    }
    pthread_mutex_unlock(&sigio_lock);
}

static void linux_probe_end(void *ctx) {
    (void)ctx;
    pthread_mutex_lock(&sigio_lock);
    if (sigio_captures > 0 && --sigio_captures == 0 && sigio_changed) {
        struct sigaction cur;
        if (sigaction(SIGIO, NULL, &cur) == 0 && !(cur.sa_flags & SA_SIGINFO) &&
            cur.sa_handler == SIG_IGN)
            sigaction(SIGIO, &sigio_saved, NULL);
        sigio_changed = false;
    }
    pthread_mutex_unlock(&sigio_lock);
}

static int linux_clock(void *ctx, struct timespec *ts) {
    (void)ctx;
    return clock_gettime(CLOCK_REALTIME, ts);
}

/* O_TMPFILE is never linked into the directory, so the directory does not
 * change -- which matters when it lies inside the scope being walked. */
static FILE *linux_tmpfile_in(void *ctx, const char *dir, const char *tmpl) {
    (void)ctx;
#ifdef O_TMPFILE
    const int fd = open(dir, O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    if (fd != -1) {
        FILE *f = fdopen(fd, "w+b");
        if (f == NULL) close(fd);
        return f;
    }
    if (errno == EMFILE || errno == ENFILE || errno == ENOMEM) return NULL;
#else
    (void)dir;
#endif
    return posix_tmpfile_named(tmpl);
}

static const struct fsops linux_ops = {
    .ctx = NULL,
    .stat_mount = linux_stat_mount,
    .fstatat = posix_fstatat,
    .fstat = posix_fstat,
    .openat = posix_openat,
    .readlinkat = posix_readlinkat,
    .read = posix_read,
    .dir_open = posix_dir_open,
    .dir_next = posix_dir_next,
    .dir_close = posix_dir_close,
    .xattr_source_open = linux_xattr_source_open,
    .xattr_source_close = linux_xattr_source_close,
    .xattr_list = linux_xattr_list,
    .xattr_get = linux_xattr_get,
    .inode_flags = linux_inode_flags,
    .is_overlay = linux_is_overlay,
    .writer_present = linux_writer_present,
    .probe_begin = linux_probe_begin,
    .probe_end = linux_probe_end,
    .clock = linux_clock,
    .tmpfile_in = linux_tmpfile_in,
    .fsync = posix_fsync,
    .barrier = posix_fsync,     /* fsync reaches the disk here: nothing more to order */
};

const struct fsops *fsops_default(void) { return &linux_ops; }
