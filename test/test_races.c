/*
 *  Race tests for the manifest writer.
 *
 *  Each race found by independent review fires in a window of microseconds,
 *  so waiting for it by luck would make a flaky test. Instead the writer runs
 *  on a decorated platform adapter (src/capture/fsops.h): the default table
 *  with some calls replaced by hooks that perform the hostile change at the
 *  exact moment between two of the writer's own calls, then pass through.
 *  The hooks are disarmed except while one test runs, and fire at most once.
 *  Portable: tests that need a Linux facility (namespaces, statx, file
 *  capabilities) say so and skip elsewhere.
 *
 *  Fixtures live under /tmp (§0.4d).
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/manifest.h"
#include "belay/error.h"
#include "belay/hash.h"
#include "capture/capture.h"

#include <errno.h>
#include <signal.h>
#ifdef __linux__
#include <sched.h>
#include <sys/mount.h>
#endif
#include <sys/wait.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

enum arm { NONE, SWAP_ON_DIR_OPEN, SWAP_ON_READLINK, REPLACE_LINK_WITH_FILE,
           DUP_READDIR, REWRITE_ON_FILE_OPEN, MOVE_BETWEEN_DIRS,
           MOVE_ON_ROOT_READDIR,     /* move a file into an already-walked sibling */
           TOUCH_ROOT_ON_DIR_OPEN,   /* change the root while a child is walked */
           LINK_KEEPS_CHANGING,      /* every readlinkat: new target, new length */
           LINK_FLICKERS,            /* every readlinkat: briefly a regular file */
           LINK_EIO,                 /* readlinkat fails with EIO */
           SUBDIR_READDIR_EIO,       /* a subdirectory's readdir fails with EIO */
           CLOCK_STEP,               /* wall clock steps once the walk has begun */
           CLOCK_BEHIND,             /* wall clock 100 s behind the files' stamps */
           APPEND_TO_FIRST_FILE,     /* on the 2nd file opened, append to the 1st */
           STATX_EPERM_ONCE,         /* statx of one name fails with EPERM, once */
           STATX_ENOSYS,             /* statx missing altogether */
           LINK_EMPTY,               /* readlinkat returns an empty target */
           XATTR_EIO,                /* the first fd xattr listing fails with EIO */
           WRITER_DURING_READ,       /* a writer opens g_x while belay reads it */
           WRITER_LEAVES_DURING_READ,  /* g_x's writer closes while belay reads it */
           MOUNT_AFTER_WALK,         /* tmpfs over g_x once the walk is done */
           STALE_LISTING,            /* the walk's listing of g_x omits g_y, once */
           VANISH_ON_STAT,           /* g_x's stat fails ENOENT once; the file stays */
           STORE_GONE_ON_OPEN,       /* the store directory is removed as g_x is opened */
           VANISH_ON_OPEN,           /* g_x is unlinked between its stat and its open */
           SHORT_READ,               /* reading g_x yields one byte, then end of file */
           XATTR_GET_EIO,            /* the first fd listing names one attribute; its get fails */
           XSRC_FAIL,                /* g_x cannot be reached for its attributes (EXDEV) */
           ROOT_READDIR_EIO };       /* the root's listing fails with EIO after one name */
static int g_flip;

static char g_root[256], g_m[300];
static const char *g_first;      /* MOVE_BETWEEN_DIRS: the directory walked first */

static enum arm g_arm;
static char g_store[300];        /* check_store's content store */
static const char *g_x, *g_y;
static int g_fired;

/* The default adapter, and the decorated copy the writer runs on. */
static const struct fsops *g_real;
static struct fsops g_ops;

/* Two names in one directory exchanged atomically. */
static int swap_at(int fd, const char *a, const char *b) {
#ifdef __linux__
    return renameat2(fd, a, fd, b, RENAME_EXCHANGE);
#else
    return renameatx_np(fd, a, fd, b, RENAME_SWAP);
#endif
}

static dev_t g_watch_dev;
static int g_entered;

/* WRITER_DURING_READ: the fd belay read g_x through, and the writer's. */
static int g_target_fd = -1, g_writer = -1;

static void watch(int dfd);
static int g_last_open_was_x;
static void *g_stale_dir;
static int t_openat(void *ctx, int fd, const char *name, int flags) {
    (void)ctx;
    watch(fd);
    if (g_arm == STALE_LISTING && (flags & O_DIRECTORY) && g_x != NULL && strcmp(name, g_x) == 0)
        g_last_open_was_x = 1;
    /* MOVE_BETWEEN_DIRS: when the second of A/B is opened, move its file into
     * the first, already-listed one -- so the file is in neither listing. */
    if (g_arm == MOVE_BETWEEN_DIRS && !g_fired && (flags & O_DIRECTORY) &&
        (strcmp(name, "A") == 0 || strcmp(name, "B") == 0)) {
        if (g_first == NULL) {
            g_first = name[0] == 'A' ? "A" : "B";
        } else {
            char from[600], to[600];
            snprintf(from, sizeof from, "%s/%s/m_%s", g_root, name, name);
            snprintf(to, sizeof to, "%s/%s/m_%s", g_root, g_first, name);
            if (rename(from, to) == 0) g_fired = 1;
        }
    }
    if (g_arm == APPEND_TO_FIRST_FILE && !g_fired && !(flags & O_DIRECTORY) &&
        (flags & O_ACCMODE) == O_RDONLY) {
        if (g_first == NULL) {
            static char first[256];
            snprintf(first, sizeof first, "%s", name);
            g_first = first;
        } else {
            char p[600];
            snprintf(p, sizeof p, "%s/%s", g_root, g_first);
            const int w = openat(AT_FDCWD, p, O_WRONLY | O_APPEND, 0);
            if (w >= 0) { if (write(w, "!", 1) == 1) g_fired = 1; close(w); }
        }
    }
    if (g_arm == TOUCH_ROOT_ON_DIR_OPEN && !g_fired && (flags & O_DIRECTORY) &&
        g_x != NULL && strcmp(name, g_x) == 0) {
        g_fired = 1;
        char p[600];
        snprintf(p, sizeof p, "%s/created_mid_walk", g_root);
        const int w = openat(AT_FDCWD, p, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (w >= 0) close(w);
    }
    if (!g_fired && g_x != NULL && strcmp(name, g_x) == 0) {
        if (g_arm == SWAP_ON_DIR_OPEN && (flags & O_DIRECTORY)) {
            g_fired = 1;
            swap_at(fd, g_x, g_y);
        } else if (g_arm == REWRITE_ON_FILE_OPEN && !(flags & O_DIRECTORY)) {
            g_fired = 1;
            /* Same size, new content, between the stat and this open. */
            const int w = openat(fd, name, O_WRONLY, 0);
            if (w >= 0) { if (write(w, "NEW!", 4) != 4) { /* best effort */ } close(w); }
        }
    }
    if (g_arm == STORE_GONE_ON_OPEN && !g_fired && !(flags & O_DIRECTORY) && g_x != NULL &&
        strcmp(name, g_x) == 0 && rmdir(g_store) == 0)
        g_fired = 1;                     /* the store, still empty, is gone */
    if (g_arm == VANISH_ON_OPEN && !g_fired && !(flags & O_DIRECTORY) && g_x != NULL &&
        strcmp(name, g_x) == 0 && unlinkat(fd, name, 0) == 0)
        g_fired = 1;
    const int r = g_real->openat(g_real->ctx, fd, name, flags);
    if ((g_arm == WRITER_DURING_READ || g_arm == WRITER_LEAVES_DURING_READ ||
         g_arm == SHORT_READ) && r >= 0 &&
        !(flags & O_DIRECTORY) && g_x != NULL &&
        strcmp(name, g_x) == 0)
        g_target_fd = r;
    return r;
}

static ssize_t t_readlinkat(void *ctx, int fd, const char *name, char *buf, size_t n) {
    (void)ctx;
    if (g_x != NULL && strcmp(name, g_x) == 0) {
        if (g_arm == LINK_EMPTY) {
            g_fired = 1;
            return 0;
        }
        if (g_arm == LINK_EIO) {
            g_fired = 1;
            errno = EIO;
            return -1;
        }
        if (g_arm == LINK_KEEPS_CHANGING) {
            /* Fires on every call, so all retries see a different link. */
            g_fired = 1;
            unlinkat(fd, g_x, 0);
            if (symlinkat((g_flip++ & 1) ? "short" : "a-much-longer-target-than-before", fd, g_x) != 0) { /* fixture */ }
        } else if (g_arm == LINK_FLICKERS) {
            /* The link is a regular file at the moment it is read, and a
             * symlink again afterwards: it never went away. */
            g_fired = 1;
            unlinkat(fd, g_x, 0);
            const int w = openat(fd, g_x, O_WRONLY | O_CREAT | O_EXCL, 0644);
            if (w >= 0) close(w);
            const ssize_t r = readlinkat(fd, name, buf, n);
            const int saved = errno;
            unlinkat(fd, g_x, 0);
            if (symlinkat("target", fd, g_x) != 0) { /* fixture */ }
            errno = saved;
            return r;
        }
    }
    if (!g_fired && g_x != NULL && strcmp(name, g_x) == 0) {
        if (g_arm == SWAP_ON_READLINK) {
            g_fired = 1;
            swap_at(fd, g_x, g_y);
        } else if (g_arm == REPLACE_LINK_WITH_FILE) {
            g_fired = 1;
            unlinkat(fd, g_x, 0);
            const int w = openat(fd, g_x, O_WRONLY | O_CREAT | O_EXCL, 0644);
            if (w >= 0) close(w);
        }
    }
    return g_real->readlinkat(g_real->ctx, fd, name, buf, n);
}

/*
 *  The wall clock as the writer sees it; monotonic time is never touched.
 *  CLOCK_STEP: once the walk's first directory read has run, every realtime
 *  read is off by g_step_s -- the clock stepped during the walk. CLOCK_BEHIND:
 *  every realtime read is 100 s behind the clock that stamped the files --
 *  the clock was stepped back before the walk, so directories changed just
 *  before it carry ctimes "in the future". Walk consistency reads no clock
 *  any more (only the header's created_ns does); g_clock_reads counts.
 */
static int g_step_s, g_stepped, g_clock_reads;
/* g_skew_s: every realtime read is off by this much, whatever is armed -- as
 * on a filesystem whose timestamps come from another machine's clock. */
static int g_skew_s;
static int t_clock(void *ctx, struct timespec *ts) {
    (void)ctx;
    g_clock_reads++;
    const int r = g_real->clock(g_real->ctx, ts);
    if (r != 0) return r;
    ts->tv_sec += g_skew_s;
    if (g_arm == CLOCK_STEP && g_stepped) {
        ts->tv_sec += g_step_s;
        g_fired = 1;
    }
    if (g_arm == CLOCK_BEHIND) {
        ts->tv_sec -= 100;
        g_fired = 1;
    }
    return r;
}

/* Mount-aware stat (statx on Linux): calls are counted, and those after an
 * armed failure separately -- so a test can see that one entry's error did
 * not switch statx off. */
static size_t g_statx_calls, g_statx_after;
/* MOUNT_AFTER_WALK: the new mount's device (g_watch_dev), and how many
 * stats and opens were made inside it, from a directory fd on it
 * (g_entered). The walk never enters a mount; neither may the end-of-walk
 * validator (R4-F4a). */
static void watch(int dfd) {
    struct stat ds;
    if (g_watch_dev != 0 && dfd >= 0 && fstat(dfd, &ds) == 0 && ds.st_dev == g_watch_dev)
        g_entered++;
}

/* As STATX_ENOSYS, but alongside another arm. */
static int g_no_statx;

static int t_stat_mount(void *ctx, int dfd, const char *name, struct stat *st,
                        bool *mount_root, bool *mount_known) {
    (void)ctx;
    watch(dfd);
    if (g_arm == STATX_ENOSYS || g_no_statx) {
        *mount_root = *mount_known = false;
        errno = ENOSYS;
        return -1;
    }
    if (g_arm == STATX_EPERM_ONCE && !g_fired && g_x != NULL && strcmp(name, g_x) == 0) {
        g_fired = 1;
        errno = EPERM;
        return -1;
    }
    if (g_arm == VANISH_ON_STAT && !g_fired && g_x != NULL && strcmp(name, g_x) == 0) {
        g_fired = 1;
        errno = ENOENT;
        return -1;
    }
    g_statx_calls++;
    if (g_fired) g_statx_after++;
    const int r = g_real->stat_mount(g_real->ctx, dfd, name, st, mount_root, mount_known);
    /* LINK_EMPTY: the filesystem presents the link as empty, size included. */
    if (r == 0 && g_arm == LINK_EMPTY && g_x != NULL && strcmp(name, g_x) == 0) st->st_size = 0;
    return r;
}

/* The plain stat path (no statx, as on macOS) presents the same empty link. */
static int t_fstatat(void *ctx, int dfd, const char *name, struct stat *st, int flags) {
    (void)ctx;
    watch(dfd);
    if (g_arm == VANISH_ON_STAT && !g_fired && g_x != NULL && strcmp(name, g_x) == 0) {
        g_fired = 1;
        errno = ENOENT;
        return -1;
    }
    const int r = g_real->fstatat(g_real->ctx, dfd, name, st, flags);
    if (r == 0 && g_arm == LINK_EMPTY && g_x != NULL && strcmp(name, g_x) == 0) st->st_size = 0;
    return r;
}

/* XATTR_EIO: the first attribute listing through an open fd fails. */
static ssize_t t_xattr_list(void *ctx, const struct xsrc *x, char *buf, size_t n) {
    (void)ctx;
    if (g_arm == XATTR_EIO && !g_fired && x->path == NULL) {
        g_fired = 1;
        errno = EIO;
        return -1;
    }
    if (g_arm == XATTR_GET_EIO && !g_fired && x->path == NULL && n >= 7) {
        g_fired = 1;                     /* one name, whatever the filesystem holds */
        memcpy(buf, "user.t", 7);
        return 7;
    }
    return g_real->xattr_list(g_real->ctx, x, buf, n);
}

/* XATTR_GET_EIO: the get of the name the listing above invented fails. */
static ssize_t t_xattr_get(void *ctx, const struct xsrc *x, const char *name, void *buf,
                           size_t n) {
    (void)ctx;
    if (g_arm == XATTR_GET_EIO && strcmp(name, "user.t") == 0) {
        errno = EIO;
        return -1;
    }
    return g_real->xattr_get(g_real->ctx, x, name, buf, n);
}

/* XSRC_FAIL: g_x, which has no open fd, cannot be reached for its attributes. */
static int t_xattr_source_open(void *ctx, int pfd, const char *name, const struct stat *st,
                               struct xsrc *x) {
    (void)ctx;
    if (g_arm == XSRC_FAIL && g_x != NULL && strcmp(name, g_x) == 0) {
        g_fired = 1;
        x->fd = -1;
        x->own = -1;
        errno = EXDEV;
        return -1;
    }
    return g_real->xattr_source_open(g_real->ctx, pfd, name, st, x);
}

static void *g_rootdir;
static const char *g_walked;   /* first of A/B returned by the root's listing */
static char g_saved[256];
static int g_replay;
static void *g_dir;
static const char *t_dir_next(void *ctx, void *d) {
    (void)ctx;
    if (g_arm == DUP_READDIR && g_replay == 1 && d == g_dir) {
        g_replay = 2;
        return g_saved;                   /* the same name, a second time */
    }
    if (g_arm == SUBDIR_READDIR_EIO && !g_fired && g_rootdir != NULL && d != g_rootdir) {
        g_fired = 1;
        errno = EIO;
        return NULL;
    }
    if (g_arm == ROOT_READDIR_EIO && !g_fired && g_rootdir != NULL && d == g_rootdir) {
        g_fired = 1;
        errno = EIO;
        return NULL;
    }
    if (g_arm == CLOCK_STEP) g_stepped = 1;
    const char *e = g_real->dir_next(g_real->ctx, d);
    if (g_rootdir == NULL) g_rootdir = d;     /* the first stream opened is the root's */
    /* STALE_LISTING: the walk is served a listing of g_x without g_y, as an
     * NFS client served one older than the directory's own attributes. */
    if (g_arm == STALE_LISTING && !g_fired && e != NULL && g_y != NULL && strcmp(e, g_y) == 0 &&
        g_stale_dir == d) {
        g_fired = 1;
        e = g_real->dir_next(g_real->ctx, d);
    }
#ifdef __linux__
    if (g_arm == MOUNT_AFTER_WALK && !g_fired && e == NULL && d == g_rootdir && g_x != NULL) {
        char p[600];
        struct stat ms;
        snprintf(p, sizeof p, "%s/%s", g_root, g_x);
        if (mount("none", p, "tmpfs", 0, NULL) == 0 && stat(p, &ms) == 0) {
            g_watch_dev = ms.st_dev;
            g_fired = 1;
        }
    }
#endif
    /* The reviewer's ordering: when the root listing returns the SECOND of
     * A/B, move that one's file into the first, which is fully walked by now
     * and will not be re-checked. The second is not stat'ed yet. */
    if (g_arm == MOVE_ON_ROOT_READDIR && !g_fired && e != NULL && d == g_rootdir &&
        (strcmp(e, "A") == 0 || strcmp(e, "B") == 0)) {
        if (g_walked == NULL) {
            g_walked = e[0] == 'A' ? "A" : "B";
        } else {
            char from[1200], to[1200];
            snprintf(from, sizeof from, "%s/%s/m_%s", g_root, e, e);
            snprintf(to, sizeof to, "%s/%s/m_%s", g_root, g_walked, e);
            if (rename(from, to) == 0) g_fired = 1;
        }
    }
    if (g_arm == DUP_READDIR && e != NULL && g_replay == 0 && g_x != NULL &&
        strcmp(e, g_x) == 0) {
        snprintf(g_saved, sizeof g_saved, "%s", e);
        g_replay = 1;
        g_dir = d;
    }
    return e;
}

/* WRITER_DURING_READ: once belay has started reading g_x, some other
 * process opens it for writing and keeps it open -- after the probe at open,
 * before the one at EOF. */
static ssize_t t_read(void *ctx, int fd, void *buf, size_t n) {
    (void)ctx;
    if (g_arm == WRITER_DURING_READ && !g_fired && fd == g_target_fd) {
        char p[600];
        snprintf(p, sizeof p, "%s/%s", g_root, g_x);
        g_writer = open(p, O_WRONLY);
        if (g_writer != -1) g_fired = 1;
    }
    if (g_arm == WRITER_LEAVES_DURING_READ && !g_fired && fd == g_target_fd && g_writer != -1) {
        close(g_writer);                         /* the in-flight write completed */
        g_writer = -1;
        g_fired = 1;
    }
    if (g_arm == SHORT_READ && fd == g_target_fd) {
        if (g_fired) {                           /* end of file, early -- once: the fd */
            g_target_fd = -1;                    /* number is reused after its close */
            return 0;
        }
        g_fired = 1;
        return g_real->read(g_real->ctx, fd, buf, 1);
    }
    return g_real->read(g_real->ctx, fd, buf, n);
}

/* The SIGIO disposition each writer probe ran under. */
static void (*g_sigio_during)(int);
static int t_writer_present(void *ctx, int fd) {
    (void)ctx;
    struct sigaction cur;
    if (sigaction(SIGIO, NULL, &cur) == 0) g_sigio_during = cur.sa_handler;
    return g_real->writer_present(g_real->ctx, fd);
}

static void *t_dir_open(void *ctx, int dfd) {
    (void)ctx;
    void *d = g_real->dir_open(g_real->ctx, dfd);
    if (g_arm == STALE_LISTING && g_last_open_was_x && g_stale_dir == NULL) g_stale_dir = d;
    g_last_open_was_x = 0;
    return d;
}

static void decorate(void) {
    g_real = fsops_default();
    g_ops = *g_real;
    g_ops.openat = t_openat;
    g_ops.readlinkat = t_readlinkat;
    g_ops.clock = t_clock;
    g_ops.stat_mount = t_stat_mount;
    g_ops.fstatat = t_fstatat;
    g_ops.xattr_list = t_xattr_list;
    g_ops.xattr_get = t_xattr_get;
    g_ops.xattr_source_open = t_xattr_source_open;
    g_ops.dir_next = t_dir_next;
    g_ops.read = t_read;
    g_ops.dir_open = t_dir_open;
    g_ops.writer_present = t_writer_present;
}

static void arm(enum arm a, const char *x, const char *y) {
    g_arm = a; g_x = x; g_y = y; g_fired = 0; g_replay = 0; g_dir = NULL; g_first = NULL;
    g_rootdir = NULL; g_walked = NULL; g_flip = 0; g_stepped = 0; g_step_s = 0; g_skew_s = 0; g_clock_reads = 0;
    g_statx_calls = 0; g_statx_after = 0; g_target_fd = -1; g_watch_dev = 0; g_entered = 0;
    g_stale_dir = NULL; g_last_open_was_x = 0;
}

static void path(char *out, size_t n, const char *rel) { snprintf(out, n, "%s/%s", g_root, rel); }

static void mk(const char *rel) { char p[512]; path(p, sizeof p, rel); mkdir(p, 0755); }

static void touch(const char *rel, const char *content) {
    char p[512];
    path(p, sizeof p, rel);
    FILE *f = fopen(p, "wb");
    if (f) { fputs(content, f); fclose(f); }
}

static void lnk(const char *target, const char *rel) {
    char p[512];
    path(p, sizeof p, rel);
    if (symlink(target, p) != 0) { /* reported by assertions */ }
}

static void reset(void) {
    char cmd[600];
    snprintf(cmd, sizeof cmd, "rm -rf '%s' '%s'", g_root, g_m);
    if (system(cmd) != 0) { /* best effort */ }
    mkdir(g_root, 0755);
}

static struct belay_entry g_e[64];
static size_t g_n;
static int collect(const struct belay_entry *e, void *c) {
    (void)c;
    if (g_n < 64) g_e[g_n++] = *e;
    return 0;
}

static const struct belay_entry *find(const char *p) {
    for (size_t i = 0; i < g_n; i++)
        if (strcmp(g_e[i].path, p) == 0) return &g_e[i];
    return NULL;
}

static int check(struct belay_manifest_stats *st) {
    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
    };
    const int rc = capture_write(&g_ops, g_m, g_root, &o, st);
    g_arm = NONE;                 /* disarm, but keep g_fired for the assertions */
    g_skew_s = 0;
    if (rc != 0) return rc;
    g_n = 0;
    return belay_manifest_read(g_m, collect, NULL);   /* the reader must accept it */
}

/* As check(), with the content store on. */
static int check_store_max(struct belay_manifest_stats *st, uint64_t store_max) {
    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = store_max,
        .store_dir = g_store,
    };
    const int rc = capture_write(&g_ops, g_m, g_root, &o, st);
    g_arm = NONE;
    if (rc != 0) return rc;
    g_n = 0;
    return belay_manifest_read(g_m, collect, NULL);
}
static int check_store(struct belay_manifest_stats *st) {
    return check_store_max(st, BELAY_STORE_MAX_BYTES_DEFAULT);
}

/* An empty content store for the next check_store (nothing of it exists). */
static void fresh_store(void) {
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_store);
    if (system(cmd) != 0) { /* best effort */ }
}

/* D1: a directory swapped between its stat and its open. Before, A's mode and
 * inode were recorded with B's contents, A's own contents were lost, and the
 * trailer reported a clean walk. */
TEST(directory_swapped_between_stat_and_open_is_flagged) {
    reset();
    mk("A"); mk("B");
    touch("A/x_marker", "");
    touch("B/y_marker", "");
    arm(SWAP_ON_DIR_OPEN, "A", "B");
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *a = find("A");
    ASSERT_TRUE(a != NULL && a->unreadable);
    /* Nothing is listed under A: its recorded identity has no known contents. */
    for (size_t i = 0; i < g_n; i++)
        if (strncmp(g_e[i].path, "A/", 2) == 0) BELAY_FAIL("listed under A: %s", g_e[i].path);
    ASSERT_TRUE(st.unreadable >= 1);
}

/* D1, symlinks: a link swapped for another link between reading its target and
 * re-stat'ing it. Every recorded link must pair its own metadata with its own
 * target: size equals target length (the reader enforces it too). */
TEST(symlink_swapped_mid_read_is_never_recorded_mismatched) {
    reset();
    lnk("target-one", "l");
    lnk("a-much-longer-other-target", "k");
    arm(SWAP_ON_READLINK, "l", "k");
    ASSERT_EQ_INT(0, check(NULL));
    ASSERT_TRUE(g_fired);
    for (size_t i = 0; i < g_n; i++)
        if (g_e[i].type == BELAY_T_LNK)
            ASSERT_EQ_INT((int)g_e[i].link_target_len, (int)g_e[i].size);
}

/* D5: a symlink replaced by a regular file mid-read used to abort the whole
 * check with EINVAL from readlinkat. Now it is re-stat'ed and recorded as what
 * it has become. */
TEST(symlink_replaced_by_file_mid_read_does_not_abort) {
    reset();
    lnk("somewhere", "l");
    touch("other", "x");
    arm(REPLACE_LINK_WITH_FILE, "l", NULL);
    ASSERT_EQ_INT(0, check(NULL));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *l = find("l");
    ASSERT_TRUE(l != NULL && l->type == BELAY_T_REG);
}

/* D3: a filesystem listing one name twice. The in-memory path used to write a
 * manifest the reader then rejected; now both paths refuse the same way and
 * leave nothing at the output path. */
TEST(name_listed_twice_is_refused_cleanly) {
    reset();
    mk("a");
    touch("a/k", "");
    arm(DUP_READDIR, "a", NULL);
    ASSERT_EQ_INT(-1, check(NULL));
    ASSERT_TRUE(strstr(belay_err_msg(), "twice") != NULL);
    ASSERT_TRUE(access(g_m, F_OK) != 0);
    belay_err_clear();
}

/* D7: a same-size rewrite between the stat and the open used to record the old
 * timestamps with the new content's hash. Now the entry is unstable. */
TEST(rewrite_between_stat_and_open_is_unstable) {
    reset();
    touch("f", "OLD!");
    usleep(20000);                /* so the rewrite's timestamps differ */
    arm(REWRITE_ON_FILE_OPEN, "f", NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *f = find("f");
    ASSERT_TRUE(f != NULL && f->unstable && f->unverified && !f->has_hash);
    ASSERT_EQ_INT(1, (int)st.unstable);
}

/* Found by the defect-class sweep of review D7 (not by the review itself): a
 * file moved mid-walk from a not-yet-listed directory into an already-listed
 * one is in neither listing. A non-snapshot walk cannot see it -- but before
 * this, the manifest also CLAIMED a clean walk. Now the directory it left is
 * flagged unstable. */
TEST(directory_changed_during_the_walk_is_flagged_unstable) {
    reset();
    mk("A"); mk("B");
    touch("A/m_A", "");
    touch("B/m_B", "");
    usleep(250000);   /* let the fixture age past the walk-start margin */
    arm(MOVE_BETWEEN_DIRS, NULL, NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    const char *second = (g_first != NULL && g_first[0] == 'A') ? "B" : "A";
    const struct belay_entry *d = find(second);
    ASSERT_TRUE(d != NULL && d->unstable);
    /* The first was already listed when the file arrived: its listing no
     * longer held at the end of the walk, and the end-of-walk re-check says
     * so (round 3). Before, only the second was flagged. */
    const struct belay_entry *f = find(g_first != NULL ? g_first : "A");
    ASSERT_TRUE(f != NULL && f->unstable);
    ASSERT_EQ_INT(2, (int)st.unstable);
}

/* ===== Independent review, round 2 ===== */

/* R2-1: the reviewer's ordering. B is fully walked and closed; then the root's
 * listing returns A, and A's file moves into B. The file is in neither
 * listing. Before the walk-start rule, the trailer claimed a clean walk. */
TEST(r2_move_into_an_already_walked_sibling_is_not_a_clean_walk) {
    reset();
    mk("A"); mk("B");
    touch("A/m_A", "");
    touch("B/m_B", "");
    usleep(250000);
    arm(MOVE_ON_ROOT_READDIR, NULL, NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    ASSERT_TRUE(st.unstable >= 1);
}

/* R2-1, the root instance: the root has no parent to flag it, so a change to
 * the root during the walk must flag "." itself. */
TEST(r2_root_changed_during_the_walk_is_flagged) {
    reset();
    mk("A");
    touch("A/f", "");
    usleep(250000);
    arm(TOUCH_ROOT_ON_DIR_OPEN, "A", NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *r = find(".");
    ASSERT_TRUE(r != NULL && r->unstable);
}

/* R2-2: a link that changes on every read exhausts the retries. Its fallback
 * used to pair one link's size with another's target, and the reader rejected
 * the whole manifest. Now: recorded unreadable, and the reader accepts it. */
TEST(r2_link_that_keeps_changing_is_unreadable_and_readable_back) {
    reset();
    lnk("initial", "L");
    arm(LINK_KEEPS_CHANGING, "L", NULL);
    ASSERT_EQ_INT(0, check(NULL));            /* check() also runs the reader */
    ASSERT_TRUE(g_fired);
    const struct belay_entry *l = find("L");
    ASSERT_TRUE(l != NULL && l->type == BELAY_T_LNK && l->unreadable);
}

/* R2-3: a link that is briefly a file whenever it is read never went away.
 * It used to be dropped and counted vanished -- a diff would call it deleted. */
TEST(r2_link_that_flickers_is_recorded_not_dropped) {
    reset();
    lnk("target", "L");
    arm(LINK_FLICKERS, "L", NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *l = find("L");
    ASSERT_TRUE(l != NULL);
    ASSERT_EQ_INT(0, (int)st.vanished);
}

/* R3: the wall clock stepped DURING the walk (WSL here steps it +108 s and
 * back every 5.4 s; NTP can step it too). A step is not a change: nothing
 * may be flagged for it. Round 2 flagged the root on any step; with the
 * end-of-walk re-check comparing by equality that protected nothing, and on
 * WSL it flagged every check longer than ~7 s. Both directions. */
TEST(r3_clock_step_during_the_walk_is_not_a_change) {
    static const int steps[] = { 2, -2 };
    for (size_t i = 0; i < sizeof steps / sizeof steps[0]; i++) {
        reset();
        mk("A");
        touch("A/f", "x");
        usleep(20000);
        arm(CLOCK_STEP, NULL, NULL);
        g_step_s = steps[i];
        struct belay_manifest_stats st;
        ASSERT_EQ_INT(0, check(&st));
        ASSERT_TRUE(g_fired);
        ASSERT_EQ_INT(0, (int)st.unstable);
        ASSERT_EQ_INT(0, (int)st.raced);
    }
}

/* R3: the clock was stepped BACK before the walk. Directories changed just
 * before it then carry ctimes later than "now" -- not a change during the
 * walk. With only a lower bound on ctime every such directory was flagged:
 * the flake WSL produced. Nothing may be flagged here. */
TEST(r3_clock_behind_the_files_flags_nothing) {
    reset();
    mk("A"); mk("A/B"); mk("C");
    touch("A/B/f", "x");
    usleep(20000);
    arm(CLOCK_BEHIND, NULL, NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    ASSERT_EQ_INT(0, (int)st.unstable);
}

/* Walk consistency reads no clock: the only read in a whole check is the
 * header's created_ns, whatever the tree holds. (The window rule read it
 * once per directory and misfired when WSL stepped it; deleted with the
 * end-of-walk validator in its place.) */
TEST(walk_consistency_reads_no_clock) {
    reset();
    mk("A"); mk("A/B"); mk("C");
    touch("A/B/f", "x");
    touch("C/g", "y");
    arm(NONE, NULL, NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_EQ_INT(1, g_clock_reads);
}

/* A writer that opens the file while belay reads it -- after the probe at
 * open -- is seen by the probe at EOF: the hash is recorded, the copy is not
 * kept (Linux; macOS cannot tell and stores unguarded, as documented). */
TEST(store_keeps_no_copy_when_a_writer_opens_during_the_read) {
#ifdef __linux__
    const bool guarded = true;
#else
    const bool guarded = false;
#endif
    reset();
    touch("f", "text a writer is about to change\n");
    arm(WRITER_DURING_READ, "f", NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check_store(&st));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *e = find("f");
    ASSERT_TRUE(e != NULL && e->has_hash);
    ASSERT_EQ_INT(!guarded, e != NULL && e->has_stored);
    if (g_writer != -1) { close(g_writer); g_writer = -1; }

    arm(NONE, NULL, NULL);                       /* writer gone: kept */
    ASSERT_EQ_INT(0, check_store(&st));
    e = find("f");
    ASSERT_TRUE(e != NULL && e->has_stored);
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_store);
    if (system(cmd) != 0) { /* best effort */ }
}

/* The shape of a torn read: a writer whose write(2) is in flight when belay
 * starts reading, and which finishes and closes before belay reaches EOF.
 * Only the probe at open can see it. */
TEST(store_keeps_no_copy_when_a_writer_leaves_during_the_read) {
#ifdef __linux__
    const bool guarded = true;
#else
    const bool guarded = false;
#endif
    reset();
    touch("f", "text a writer is still writing\n");
    char p[600];
    snprintf(p, sizeof p, "%s/f", g_root);
    arm(WRITER_LEAVES_DURING_READ, "f", NULL);
    g_writer = open(p, O_WRONLY);
    ASSERT_TRUE(g_writer != -1);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check_store(&st));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *e = find("f");
    ASSERT_TRUE(e != NULL && e->has_hash);
    ASSERT_EQ_INT(!guarded, e != NULL && e->has_stored);
    if (g_writer != -1) { close(g_writer); g_writer = -1; }
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_store);
    if (system(cmd) != 0) { /* best effort */ }
}

/* A listing older than the directory's own attributes (an NFS client did
 * this under a same-client writer, CI 2026-10-28): the walk is served A's
 * listing without A/f, while A's mtime and ctime stay as recorded. f is in
 * no listing, and every timestamp agrees. The validator lists A again and
 * compares names, so A is unstable. */
TEST(listing_older_than_its_directory_is_flagged) {
    reset();
    mk("A");
    touch("A/f", "x");
    touch("A/g", "y");
    arm(STALE_LISTING, "A", "f");
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    ASSERT_TRUE(find("A/f") == NULL);           /* the walk really missed it */
    const struct belay_entry *a = find("A");
    ASSERT_TRUE(a != NULL && a->unstable);
}

/* The writer probe's lease can make the kernel send SIGIO, whose default
 * action ends the process, so on Linux SIGIO at its default is ignored while
 * a capture probes -- and put back when it ends: libbelay is a library, and
 * its host must not inherit a process-wide signal change. A handler the
 * host installed is never touched. (macOS: no probe, nothing changes.) */
static void host_sigio(int sig) { (void)sig; }
TEST(sigio_is_ignored_only_while_a_capture_probes) {
#ifdef __linux__
    const bool probes = true;
#else
    const bool probes = false;
#endif
    reset();
    touch("f", "kept\n");
    struct sigaction dfl, mine, cur;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    mine = dfl;
    mine.sa_handler = host_sigio;
    struct belay_manifest_stats st;

    ASSERT_EQ_INT(0, sigaction(SIGIO, &dfl, NULL));
    g_sigio_during = NULL;
    arm(NONE, NULL, NULL);
    ASSERT_EQ_INT(0, check_store(&st));
    ASSERT_TRUE(g_sigio_during == (probes ? SIG_IGN : SIG_DFL));    /* during */
    ASSERT_EQ_INT(0, sigaction(SIGIO, NULL, &cur));
    ASSERT_TRUE(cur.sa_handler == SIG_DFL);                         /* after: restored */

    ASSERT_EQ_INT(0, sigaction(SIGIO, &mine, NULL));
    g_sigio_during = NULL;
    arm(NONE, NULL, NULL);
    ASSERT_EQ_INT(0, check_store(&st));
    ASSERT_TRUE(g_sigio_during == host_sigio);                      /* never touched */
    ASSERT_EQ_INT(0, sigaction(SIGIO, NULL, &cur));
    ASSERT_TRUE(cur.sa_handler == host_sigio);
    sigaction(SIGIO, &dfl, NULL);
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_store);
    if (system(cmd) != 0) { /* best effort */ }
}

/* R2-5: I/O errors on one entry are recorded on it, not fatal. */
TEST(r2_readlink_eio_is_recorded_not_fatal) {
    reset();
    lnk("target", "L");
    arm(LINK_EIO, "L", NULL);
    ASSERT_EQ_INT(0, check(NULL));
    const struct belay_entry *l = find("L");
    ASSERT_TRUE(l != NULL && l->unreadable && l->link_target_len == 0);
}

TEST(r2_readdir_eio_marks_the_directory_unstable_not_fatal) {
    reset();
    mk("sub");
    touch("sub/f", "");
    usleep(250000);
    arm(SUBDIR_READDIR_EIO, NULL, NULL);
    ASSERT_EQ_INT(0, check(NULL));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *d = find("sub");
    ASSERT_TRUE(d != NULL && d->unstable);
}

/*
 *  R2-4, the regression: on overlayfs (xino off) regular files carry their
 *  layer's st_dev, not the overlay's. The D4 fix compared st_dev for every
 *  type, so every file of an overlay scope was flagged a mount and none was
 *  hashed -- and belay's own session engine runs on such overlays.
 *
 *  Needs an unprivileged user + mount namespace; skipped where the host
 *  forbids it (e.g. Ubuntu 24.04's AppArmor default). Runs in a child so the
 *  mounts die with it.
 */
#ifdef __linux__
/* Enters a new user + mount namespace with ourselves mapped to root, as
 * `unshare -r` does (an unmapped user cannot mount). 0, or 77 to skip. */
static int enter_userns(void) {
    const uid_t uid = getuid();
    const gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) return 77;
    char map[64];
    int fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) { if (write(fd, "deny", 4) != 4) { /* best effort */ } close(fd); }
    snprintf(map, sizeof map, "0 %u 1\n", (unsigned)uid);
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0 || write(fd, map, strlen(map)) < 0) return 77;
    close(fd);
    snprintf(map, sizeof map, "0 %u 1\n", (unsigned)gid);
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd < 0 || write(fd, map, strlen(map)) < 0) return 77;
    close(fd);
    return 0;
}

/* W6: a file capability is the privilege-change route `setcap` takes, and
 * it used to change nothing recorded but ctime. Setting one needs
 * CAP_SETFCAP, which a user namespace's root has over its own files. */
static int caps_child(void) {
    char f[400];
    snprintf(f, sizeof f, "%s/capfile", g_root);
    if (enter_userns() != 0) return 77;
    /* VFS_CAP_REVISION_2 | effective; permitted = CAP_NET_RAW (13). */
    const uint32_t v[5] = { 0x02000001u, 1u << 13, 0, 0, 0 };
    if (setxattr(f, "security.capability", v, sizeof v, 0) != 0) return 77;
    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
    };
    if (capture_write(&g_ops, g_m, g_root, &o, NULL) != 0) return 1;
    g_n = 0;
    if (belay_manifest_read(g_m, collect, NULL) != 0) return 2;
    const struct belay_entry *e = find("capfile");
    if (e == NULL || !e->has_caps || strlen(e->caps_hex) < 40) return 3;
    if (e->has_xattrs && strstr(e->xattrs, "security.capability") != NULL) return 4;
    return 0;
}

static int overlay_child(void) {
    char lower[300], up[300], merged[300], p[400];
    snprintf(lower, sizeof lower, "%s/lower", g_root);
    snprintf(up, sizeof up, "%s/up", g_root);
    snprintf(merged, sizeof merged, "%s/merged", g_root);
    if (enter_userns() != 0) return 77;
    if (mount("none", up, "tmpfs", 0, NULL) != 0) return 77;
    snprintf(p, sizeof p, "%s/u", up); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/w", up); mkdir(p, 0755);
    char opts[1200];
    snprintf(opts, sizeof opts, "lowerdir=%s,upperdir=%s/u,workdir=%s/w", lower, up, up);
    if (mount("overlay", merged, "overlay", 0, opts) != 0) return 77;
    snprintf(p, sizeof p, "%s/upper.txt", merged);
    FILE *f = fopen(p, "wb");
    if (f) { fputs("upper", f); fclose(f); }

    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
    };
    /* With statx, and again as on a kernel without it (round 3, F5: the
     * st_dev fallback must still exempt an overlay's files). */
    for (int pass = 0; pass < 2; pass++) {
        g_arm = pass ? STATX_ENOSYS : NONE;
        const int w = capture_write(&g_ops, g_m, merged, &o, NULL);
        g_arm = NONE;
        if (w != 0) return 1;
        g_n = 0;
        if (belay_manifest_read(g_m, collect, NULL) != 0) return 2;
        const struct belay_entry *a = find("lower.txt"), *u = find("upper.txt");
        if (a == NULL || u == NULL) return 3;
        if (a->is_mount || u->is_mount || !a->has_hash || !u->has_hash) return 4 + pass;
    }
    return 0;
}

/*
 *  R3-F5: a FILE bind-mounted into the scope from another filesystem is a
 *  boundary: recorded, never read. With statx it is a mount root; without
 *  statx (kernels before 5.8, or statx blocked) only st_dev can tell, and
 *  the round-2 rule compared st_dev for directories only -- so the file was
 *  hashed as a local one. Both ways now.
 */
static int bind_child(void) {
    char fs[300], scope[300], src[400], dst[400];
    snprintf(fs, sizeof fs, "%s/fs", g_root);
    snprintf(scope, sizeof scope, "%s/scope", g_root);
    snprintf(src, sizeof src, "%s/outside.txt", fs);
    snprintf(dst, sizeof dst, "%s/f", scope);
    if (enter_userns() != 0) return 77;
    if (mount("none", fs, "tmpfs", 0, NULL) != 0) return 77;
    FILE *f = fopen(src, "wb");
    if (f == NULL) return 10;
    fputs("from another filesystem", f);
    fclose(f);
    if (mount(src, dst, NULL, MS_BIND, NULL) != 0) return 77;

    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
    };
    for (int pass = 0; pass < 2; pass++) {
        g_arm = pass ? STATX_ENOSYS : NONE;
        const int w = capture_write(&g_ops, g_m, scope, &o, NULL);
        g_arm = NONE;
        if (w != 0) return 1;
        g_n = 0;
        if (belay_manifest_read(g_m, collect, NULL) != 0) return 2;
        const struct belay_entry *e = find("f");
        if (e == NULL) return 3;
        if (!e->is_mount || e->has_hash) return 4 + pass;
    }
    return 0;
}

/*
 *  R4-F4a: a mount that appears over an already-walked directory before the
 *  end-of-walk validator runs. The validator used to open it and stat the
 *  recorded children inside (could hang on a dead network mount; §5.1.1
 *  says mounts are never descended). It must stat the directory, as the walk
 *  stat'ed every mount root, and stop there: the directory is unstable, its
 *  children raced, nothing inside the mount touched. With statx and without.
 */
static int mount_after_walk_child(void) {
    char scope[300];
    snprintf(scope, sizeof scope, "%s/scope", g_root);
    if (enter_userns() != 0) return 77;
    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
    };
    for (int pass = 0; pass < 2; pass++) {
        char p[400];
        snprintf(p, sizeof p, "%s/D", scope);
        umount2(p, MNT_DETACH);
        arm(MOUNT_AFTER_WALK, "scope/D", NULL);
        g_rootdir = NULL;
        g_no_statx = pass;                      /* pass 1: the st_dev fallback */
        const int w = capture_write(&g_ops, g_m, scope, &o, NULL);
        g_arm = NONE;
        g_no_statx = 0;
        if (w != 0) return 1;
        if (!g_fired) return 2;
        if (g_entered != 0) return 3;
        g_n = 0;
        if (belay_manifest_read(g_m, collect, NULL) != 0) return 4;
        const struct belay_entry *d = find("D"), *in = find("D/inner.txt");
        if (d == NULL || in == NULL) return 5;
        if (!d->unstable) return 6;
        if (!in->raced) return 7;
    }
    return 0;
}

/* R4-F4b: a mount placed over the scope root itself during the walk. The
 * root used to be re-checked only through the fd held since the start,
 * which still sees the old directory -- a clean manifest of a scope whose
 * path now shows something else. The validator also resolves the scope
 * path: the root is flagged. */
static int mount_over_scope_child(void) {
    char scope[300];
    snprintf(scope, sizeof scope, "%s/scope", g_root);
    if (enter_userns() != 0) return 77;
    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
    };
    arm(MOUNT_AFTER_WALK, "scope", NULL);
    g_rootdir = NULL;
    const int w = capture_write(&g_ops, g_m, scope, &o, NULL);
    g_arm = NONE;
    if (w != 0) return 1;
    if (!g_fired) return 2;
    g_n = 0;
    if (belay_manifest_read(g_m, collect, NULL) != 0) return 4;
    const struct belay_entry *root = find(".");
    if (root == NULL) return 5;
    if (!root->unstable) return 6;
    return 0;
}

#endif

#ifdef __linux__
/* The child's exit status: 0 passed, 77 cannot run here (no namespace), else
 * the step that failed. The TEST decides what a 77 means (SKIP). */
static int run_child(int (*child)(void)) {
    const pid_t pid = fork();
    if (pid == 0) _exit(child());
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 99;
}
#endif

TEST(r4_validator_never_enters_a_mount_that_appeared) {
#ifndef __linux__
    SKIP("Linux only -- mounts in a user namespace");
#else
    reset();
    mk("scope"); mk("scope/D");
    touch("scope/D/inner.txt", "recorded before the mount");
    const int rc = run_child(mount_after_walk_child);
    if (rc == 77) SKIP("no unprivileged user+mount namespace here");
    ASSERT_EQ_INT(0, rc);
#endif
}

TEST(r4_mount_over_the_scope_root_flags_the_root) {
#ifndef __linux__
    SKIP("Linux only -- mounts in a user namespace");
#else
    reset();
    mk("scope"); mk("scope/A");
    touch("scope/A/f", "x");
    const int rc = run_child(mount_over_scope_child);
    if (rc == 77) SKIP("no unprivileged user+mount namespace here");
    ASSERT_EQ_INT(0, rc);
#endif
}

TEST(w6_file_capability_is_recorded) {
#ifndef __linux__
    SKIP("Linux only -- file capabilities need a user namespace");
#else
    reset();
    touch("capfile", "#!/bin/true\n");
    const pid_t pid = fork();
    if (pid == 0) _exit(caps_child());
    int status = 0;
    waitpid(pid, &status, 0);
    const int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 99;
    if (rc == 77) SKIP("cannot set a file capability here");
    ASSERT_EQ_INT(0, rc);
#endif
}

/* W6: attributes that could not be read are recorded as unknown, never as
 * "none" -- an absent field would read as "no ACL, no capability". */
TEST(w6_unreadable_xattrs_are_unknown_not_none) {
    reset();
    touch("f", "x");
    arm(XATTR_EIO, NULL, NULL);
    ASSERT_EQ_INT(0, check(NULL));            /* check() also runs the reader */
    ASSERT_TRUE(g_fired);
    size_t unknown = 0;
    for (size_t i = 0; i < g_n; i++) if (g_e[i].xattrs_unknown) unknown++;
    ASSERT_EQ_INT(1, (int)unknown);
}

TEST(r2_overlay_scope_files_are_hashed_not_flagged_as_mounts) {
#ifndef __linux__
    SKIP("Linux only -- overlayfs in a user namespace");
#else
    reset();
    mk("lower"); mk("up"); mk("merged");
    touch("lower/lower.txt", "lower");
    const pid_t pid = fork();
    if (pid == 0) _exit(overlay_child());
    int status = 0;
    waitpid(pid, &status, 0);
    const int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 99;
    if (rc == 77) SKIP("no unprivileged user+mount namespace here");
    ASSERT_EQ_INT(0, rc);
#endif
}

TEST(r3_file_bind_mounted_from_another_fs_is_a_boundary_with_or_without_statx) {
#ifndef __linux__
    SKIP("Linux only -- bind mounts in a user namespace");
#else
    reset();
    mk("fs"); mk("scope");
    touch("scope/f", "local");
    const pid_t pid = fork();
    if (pid == 0) _exit(bind_child());
    int status = 0;
    waitpid(pid, &status, 0);
    const int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 99;
    if (rc == 77) SKIP("no unprivileged user+mount namespace here");
    ASSERT_EQ_INT(0, rc);
#endif
}

/* R3-F1: the round-2 rule needed file timestamps from this machine's clock.
 * With the file clock 5 s off either way (NFS, SMB, WSL's /mnt/c, FUSE), a
 * file moved from an unlisted directory into an already-listed one was again
 * recorded nowhere, with a clean trailer. The end-of-walk re-check compares
 * by equality, so the directory it arrived in is flagged whatever the clock. */
TEST(r3_move_into_a_listed_directory_is_caught_whatever_the_file_clock) {
    static const int skew[] = { 5, -5 };
    for (size_t i = 0; i < sizeof skew / sizeof skew[0]; i++) {
        reset();
        mk("A"); mk("B");
        touch("A/m_A", "");
        touch("B/m_B", "");
        usleep(250000);
        arm(MOVE_ON_ROOT_READDIR, NULL, NULL);
        g_skew_s = skew[i];
        struct belay_manifest_stats st;
        ASSERT_EQ_INT(0, check(&st));
        ASSERT_TRUE(g_fired);
        ASSERT_TRUE(g_walked != NULL);
        const struct belay_entry *dest = find(g_walked != NULL ? g_walked : "A");
        ASSERT_TRUE(dest != NULL && dest->unstable);
    }
}

/* R3-F2: a file changed after it was hashed, while the walk went on, gave a
 * manifest of a state that never existed -- with a clean trailer. It is now
 * flagged raced, and the hash it carries is still the one it had when read. */
TEST(r3_file_changed_after_it_was_read_is_raced) {
    reset();
    touch("f1", "one");
    touch("f2", "two");
    usleep(20000);
    arm(APPEND_TO_FIRST_FILE, NULL, NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *f = find(g_first != NULL ? g_first : "f1");
    ASSERT_TRUE(f != NULL && f->raced && f->has_hash);
    ASSERT_EQ_INT(1, (int)st.raced);
    const struct belay_entry *r = find(".");
    ASSERT_TRUE(r != NULL && !r->unstable);
}

/* R3-F3: one entry's statx EPERM used to switch statx off for the rest of the
 * process -- and with it mount-root detection, for every later walk. Now the
 * entry is not recorded (its directory is flagged, as for any entry that
 * cannot be stat'ed), and statx stays in use, in this walk and the next. */
TEST(r3_one_statx_eperm_is_recorded_and_does_not_switch_statx_off) {
#ifndef __linux__
    SKIP("Linux only -- statx");
#else
    reset();
    mk("d");
    touch("d/denied", "x");
    touch("d/other", "y");
    usleep(20000);
    arm(STATX_EPERM_ONCE, "denied", NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *d = find("d");
    ASSERT_TRUE(d != NULL && d->unstable);
    ASSERT_TRUE(find("d/denied") == NULL);
    ASSERT_TRUE(g_statx_after > 0);
    arm(NONE, NULL, NULL);
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_statx_calls > 0);
#endif
}

/* R3-F6: a filesystem presenting an empty symlink (FUSE, NFS) made the writer
 * emit a manifest its own reader rejected. It is recorded unreadable, with
 * the empty "unknown" target, and reads back. */
TEST(r3_empty_link_target_is_recorded_unreadable) {
    reset();
    lnk("target", "L");
    arm(LINK_EMPTY, "L", NULL);
    ASSERT_EQ_INT(0, check(NULL));            /* check() also runs the reader */
    ASSERT_TRUE(g_fired);
    const struct belay_entry *l = find("L");
    ASSERT_TRUE(l != NULL && l->unreadable && l->link_target_len == 0);
}

/* F2 (audit 2026-10): a name gone between the listing and its stat, back
 * before the walk ended. The manifest cannot record it, so its directory's
 * listing must not pass the end-of-walk re-list. Before, every listed name
 * went into what the re-list is compared with, recorded or not, and the file
 * was missing from a directory recorded as complete. */
TEST(a_name_that_vanished_and_came_back_flags_its_directory) {
    reset();
    mk("d");
    touch("d/x", "x");
    touch("d/y", "y");
    usleep(20000);
    arm(VANISH_ON_STAT, "x", NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    ASSERT_TRUE(find("d/x") == NULL);
    ASSERT_EQ_INT(1, (int)st.vanished);
    const struct belay_entry *d = find("d"), *r = find("."), *y = find("d/y");
    ASSERT_TRUE(d != NULL && d->unstable);        /* its listing no longer holds */
    ASSERT_TRUE(r != NULL && !r->unstable);       /* the root's does */
    ASSERT_TRUE(y != NULL && !y->unstable && !y->raced);
}

/* R11 (audit 2026-10): the content store degrades, it never costs the
 * capture. A store that cannot begin a copy, fails mid-copy or cannot
 * publish it keeps no copy: the entry is recorded and hashed, without
 * `stored`, and the failure is counted. Before, each failed the capture.
 * The faults are ones root cannot bypass. */
TEST(a_store_that_cannot_begin_a_copy_keeps_the_entry) {
    reset();
    touch("f.txt", "content\n");
    usleep(20000);
    fresh_store();
    arm(STORE_GONE_ON_OPEN, "f.txt", NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check_store(&st));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *f = find("f.txt");
    ASSERT_TRUE(f != NULL && f->has_hash && !f->has_stored);
    ASSERT_EQ_INT(1, (int)st.store_failed);
}

TEST(a_store_that_cannot_publish_a_copy_keeps_the_entry) {
    reset();
    touch("f.txt", "content\n");
    usleep(20000);
    fresh_store();
    REQUIRE(mkdir(g_store, 0700) == 0);
    /* The copy's fan-out directory name is taken by a regular file. */
    struct belay_sha256 h;
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    char hex[65], p[400];
    belay_sha256_init(&h);
    belay_sha256_update(&h, "content\n", 8);
    belay_sha256_final(&h, d);
    belay_hex_encode(hex, d, sizeof d);
    snprintf(p, sizeof p, "%s/%.2s", g_store, hex);
    FILE *blocker = fopen(p, "wb");
    REQUIRE(blocker != NULL);
    fclose(blocker);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check_store(&st));
    const struct belay_entry *f = find("f.txt");
    ASSERT_TRUE(f != NULL && f->has_hash && !f->has_stored);
    ASSERT_EQ_INT(1, (int)st.store_failed);
}

TEST(a_store_that_fails_mid_copy_keeps_the_entry) {
    reset();
    /* 256 KiB of text: the copy outgrows a 64 KiB file-size limit, while the
     * manifest and the walk's temporary files stay far below it. */
    char p[512];
    path(p, sizeof p, "big.txt");
    FILE *f = fopen(p, "wb");
    REQUIRE(f != NULL);
    for (int i = 0; i < 16384; i++) fputs("fifteen bytes.\n", f);
    fclose(f);
    usleep(20000);
    fresh_store();
    int fds[2];
    REQUIRE(pipe(fds) == 0);
    const pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid == 0) {
        close(fds[0]);
        signal(SIGXFSZ, SIG_IGN);
        const struct rlimit rl = { 64 * 1024, 64 * 1024 };
        struct belay_manifest_stats st;
        memset(&st, 0, sizeof st);
        const int rc = setrlimit(RLIMIT_FSIZE, &rl) == 0 ? check_store_max(&st, 1024 * 1024) : -2;
        const size_t out[2] = { (size_t)(rc + 2), st.store_failed };
        _exit(write(fds[1], out, sizeof out) == (ssize_t)sizeof out ? 0 : 1);
    }
    close(fds[1]);
    size_t got[2] = { 0, 0 };
    const ssize_t n = read(fds[0], got, sizeof got);
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    REQUIRE(n == (ssize_t)sizeof got && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    ASSERT_EQ_INT(2, (int)got[0]);                  /* the capture succeeded */
    ASSERT_EQ_INT(1, (int)got[1]);                  /* and counted the dropped copy */
    g_n = 0;
    ASSERT_EQ_INT(0, belay_manifest_read(g_m, collect, NULL));
    const struct belay_entry *e = find("big.txt");
    ASSERT_TRUE(e != NULL && e->has_hash && !e->has_stored);
    DIR *sd = opendir(g_store);                     /* the staged part is gone */
    REQUIRE(sd != NULL);
    for (struct dirent *de; (de = readdir(sd)) != NULL; )
        ASSERT_FALSE(strncmp(de->d_name, ".tmp-", 5) == 0);
    closedir(sd);
}

/* Audit 2026-10, the capture's surviving mutants: each case below passed
 * every check with its decision removed (CAP-WALK-08, CONS-08, CAP-X-02,
 * CAP-X-03, CAP-WALK-09). */

/* Gone between its stat and its open: not recorded, counted as vanished;
 * its directory changed while it was walked. */
TEST(a_file_gone_between_its_stat_and_open_is_counted) {
    reset();
    mk("d");
    touch("d/x", "x");
    touch("d/y", "y");
    usleep(20000);
    arm(VANISH_ON_OPEN, "x", NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    ASSERT_TRUE(find("d/x") == NULL);
    ASSERT_EQ_INT(1, (int)st.vanished);
    const struct belay_entry *d = find("d"), *y = find("d/y");
    ASSERT_TRUE(d != NULL && d->unstable);
    ASSERT_TRUE(y != NULL && y->has_hash && !y->unstable);
}

/* A read that ends before the file's size: the bytes hashed are not the
 * file, so there is no hash, never a wrong one. */
TEST(a_short_read_is_unstable_never_a_wrong_hash) {
    reset();
    touch("f", "hello");
    usleep(20000);
    arm(SHORT_READ, "f", NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *f = find("f");
    ASSERT_TRUE(f != NULL && f->unstable && f->unverified && !f->has_hash);
    ASSERT_EQ_INT(1, (int)st.unstable);
}

/* An attribute listed but not readable: the set is unknown, not the set
 * without it. */
TEST(an_attribute_that_cannot_be_read_makes_them_unknown) {
    reset();
    touch("f", "x");
    arm(XATTR_GET_EIO, NULL, NULL);
    ASSERT_EQ_INT(0, check(NULL));
    ASSERT_TRUE(g_fired);
    size_t unknown = 0;
    for (size_t i = 0; i < g_n; i++) if (g_e[i].xattrs_unknown) unknown++;
    ASSERT_EQ_INT(1, (int)unknown);
}

/* An entry without an open fd that cannot be reached for its attributes. */
TEST(an_entry_unreachable_for_its_attributes_has_them_unknown) {
    reset();
    lnk("target", "L");
    touch("f", "x");
    arm(XSRC_FAIL, "L", NULL);
    ASSERT_EQ_INT(0, check(NULL));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *l = find("L"), *f = find("f");
    ASSERT_TRUE(l != NULL && l->xattrs_unknown);
    ASSERT_TRUE(f != NULL && !f->xattrs_unknown);
}

/* The scope root's own listing cut short by EIO. */
TEST(a_root_listing_cut_short_flags_the_root) {
    reset();
    touch("a", "a");
    touch("b", "b");
    touch("c", "c");
    usleep(20000);
    arm(ROOT_READDIR_EIO, NULL, NULL);
    ASSERT_EQ_INT(0, check(NULL));
    ASSERT_TRUE(g_fired);
    const struct belay_entry *r = find(".");
    ASSERT_TRUE(r != NULL && r->unstable);
}

/* R7 and M6 (audit 2026-10): each per-entry decision, made on one entry of
 * the same tree, flags exactly what this table says -- the entry, or its
 * directory when the entry itself cannot be recorded -- and nothing else.
 * The expectations are written by hand from the spec, never from a run. */
enum { X_UNV = 1, X_UNS = 2, X_UNR = 4, X_RAC = 8, X_XU = 16, X_MNT = 32 };
/* A file whose open was abandoned has its attributes read without an fd
 * (fsops.h, xattr_source_open): Linux reaches it through O_PATH, checked to be
 * the recorded inode; macOS has no safe way for a regular file (ENOTSUP), so
 * they are unknown there. */
#ifdef __linux__
#define X_XU_WITHOUT_FD 0
#else
#define X_XU_WITHOUT_FD X_XU
#endif
static unsigned flags_of(const struct belay_entry *e) {
    return (e->unverified ? X_UNV : 0) | (e->unstable ? X_UNS : 0) | (e->unreadable ? X_UNR : 0) |
           (e->raced ? X_RAC : 0) | (e->xattrs_unknown ? X_XU : 0) | (e->is_mount ? X_MNT : 0);
}

TEST(each_per_entry_decision_flags_only_what_it_should) {
    static const struct {
        const char *name;
        enum arm arm;
        const char *x, *y;
        bool linux_only;
        const char *flagged;
        unsigned flags;
        const char *absent;
        int vanished;
    } rows[] = {
        { "nothing happens",         NONE, NULL, NULL, false, NULL, 0, NULL, 0 },
        /* rewritten after its stat: the bytes read are not the recorded
         * file's, and the recorded fields are not its state at the end */
        { "rewritten before its open", REWRITE_ON_FILE_OPEN, "x", NULL, false, "d/x",
          X_UNV | X_UNS | X_RAC | X_XU_WITHOUT_FD, NULL, 0 },
        { "read short",              SHORT_READ, "x", NULL, false, "d/x", X_UNV | X_UNS, NULL, 0 },
        { "link unreadable",         LINK_EIO, "L", NULL, false, "d/L", X_UNR, NULL, 0 },
        { "attributes unreachable",  XSRC_FAIL, "L", NULL, false, "d/L", X_XU, NULL, 0 },
        /* the entry cannot be recorded: its directory's listing is what is
         * incomplete (or, for a file that is really gone, changed) */
        { "gone before its stat",    VANISH_ON_STAT, "x", NULL, false, "d", X_UNS, "d/x", 1 },
        { "gone before its open",    VANISH_ON_OPEN, "x", NULL, false, "d", X_UNS, "d/x", 1 },
        { "stat denied",             STATX_EPERM_ONCE, "x", NULL, true, "d", X_UNS, "d/x", 0 },
        { "listing stale",           STALE_LISTING, "d", "x", false, "d", X_UNS, "d/x", 0 },
    };
    static const char *const all[] = { ".", "a.txt", "d", "d/L", "d/x", "d/y", "e", "e/z" };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
#ifndef __linux__
        if (rows[i].linux_only) continue;          /* statx only */
#endif
        reset();
        touch("a.txt", "alpha");
        mk("d");
        touch("d/x", "x-content");
        touch("d/y", "yy");
        lnk("x", "d/L");
        mk("e");
        touch("e/z", "zz");
        usleep(20000);
        arm(rows[i].arm, rows[i].x, rows[i].y);
        struct belay_manifest_stats st;
        if (check(&st) != 0) {
            BELAY_FAIL("%s: capture failed: %s", rows[i].name, belay_err_msg());
            belay_err_clear();
            continue;
        }
        if (rows[i].arm != NONE && !g_fired) BELAY_FAIL("%s: the fault never fired", rows[i].name);
        for (size_t k = 0; k < sizeof all / sizeof all[0]; k++) {
            const struct belay_entry *e = find(all[k]);
            if (rows[i].absent != NULL && strcmp(all[k], rows[i].absent) == 0) {
                if (e != NULL) BELAY_FAIL("%s: %s recorded", rows[i].name, all[k]);
                continue;
            }
            if (e == NULL) {
                BELAY_FAIL("%s: %s not recorded", rows[i].name, all[k]);
                continue;
            }
            const unsigned want = rows[i].flagged != NULL && strcmp(rows[i].flagged, all[k]) == 0
                                ? rows[i].flags : 0;
            if (flags_of(e) != want)
                BELAY_FAIL("%s: %s has flags %u, want %u", rows[i].name, all[k], flags_of(e), want);
        }
        if ((int)st.vanished != rows[i].vanished)
            BELAY_FAIL("%s: %zu vanished, want %d", rows[i].name, st.vanished, rows[i].vanished);
    }
}

int main(void) {
    decorate();
    snprintf(g_root, sizeof g_root, "/tmp/belay_races_%d", (int)getpid());
    snprintf(g_m, sizeof g_m, "/tmp/belay_races_%d.ndjson", (int)getpid());
    snprintf(g_store, sizeof g_store, "/tmp/belay_races_store_%d", (int)getpid());

    RUN(directory_swapped_between_stat_and_open_is_flagged);
    RUN(symlink_swapped_mid_read_is_never_recorded_mismatched);
    RUN(symlink_replaced_by_file_mid_read_does_not_abort);
    RUN(name_listed_twice_is_refused_cleanly);
    RUN(rewrite_between_stat_and_open_is_unstable);
    RUN(directory_changed_during_the_walk_is_flagged_unstable);
    RUN(r2_move_into_an_already_walked_sibling_is_not_a_clean_walk);
    RUN(r2_root_changed_during_the_walk_is_flagged);
    RUN(r2_link_that_keeps_changing_is_unreadable_and_readable_back);
    RUN(r2_link_that_flickers_is_recorded_not_dropped);
    RUN(r2_readlink_eio_is_recorded_not_fatal);
    RUN(r2_readdir_eio_marks_the_directory_unstable_not_fatal);
    RUN(r2_overlay_scope_files_are_hashed_not_flagged_as_mounts);
    RUN(r3_clock_step_during_the_walk_is_not_a_change);
    RUN(r3_clock_behind_the_files_flags_nothing);
    RUN(walk_consistency_reads_no_clock);
    RUN(listing_older_than_its_directory_is_flagged);
    RUN(sigio_is_ignored_only_while_a_capture_probes);
    RUN(store_keeps_no_copy_when_a_writer_opens_during_the_read);
    RUN(store_keeps_no_copy_when_a_writer_leaves_during_the_read);
    RUN(r4_validator_never_enters_a_mount_that_appeared);
    RUN(r4_mount_over_the_scope_root_flags_the_root);
    RUN(r3_file_bind_mounted_from_another_fs_is_a_boundary_with_or_without_statx);
    RUN(r3_move_into_a_listed_directory_is_caught_whatever_the_file_clock);
    RUN(r3_file_changed_after_it_was_read_is_raced);
    RUN(r3_one_statx_eperm_is_recorded_and_does_not_switch_statx_off);
    RUN(r3_empty_link_target_is_recorded_unreadable);
    RUN(a_name_that_vanished_and_came_back_flags_its_directory);
    RUN(a_store_that_cannot_begin_a_copy_keeps_the_entry);
    RUN(a_store_that_cannot_publish_a_copy_keeps_the_entry);
    RUN(a_store_that_fails_mid_copy_keeps_the_entry);
    RUN(a_file_gone_between_its_stat_and_open_is_counted);
    RUN(a_short_read_is_unstable_never_a_wrong_hash);
    RUN(an_attribute_that_cannot_be_read_makes_them_unknown);
    RUN(an_entry_unreachable_for_its_attributes_has_them_unknown);
    RUN(a_root_listing_cut_short_flags_the_root);
    RUN(each_per_entry_decision_flags_only_what_it_should);
    RUN(w6_file_capability_is_recorded);
    RUN(w6_unreadable_xattrs_are_unknown_not_none);

    char cmd[1000];
    snprintf(cmd, sizeof cmd, "rm -rf '%s' '%s' '%s'", g_root, g_m, g_store);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
