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
#include "capture/capture.h"

#include <errno.h>
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
           XATTR_EIO };              /* the first fd xattr listing fails with EIO */
static int g_flip;

static char g_root[256], g_m[300];
static const char *g_first;      /* MOVE_BETWEEN_DIRS: the directory walked first */

static enum arm g_arm;
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

static int t_openat(void *ctx, int fd, const char *name, int flags) {
    (void)ctx;
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
    return g_real->openat(g_real->ctx, fd, name, flags);
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
 *  every realtime read, fine and coarse, is 100 s behind the clock that
 *  stamped the files -- the clock was stepped back before the walk, so
 *  directories changed just before it carry ctimes "in the future".
 */
static int g_step_s, g_stepped;
/* g_skew_s: every realtime read is off by this much, whatever is armed -- as
 * on a filesystem whose timestamps come from another machine's clock. */
static int g_skew_s;
static int t_clock(void *ctx, enum belay_clock which, struct timespec *ts) {
    (void)ctx;
    const int r = g_real->clock(g_real->ctx, which, ts);
    if (r != 0) return r;
    ts->tv_sec += g_skew_s;
    if (g_arm == CLOCK_STEP && g_stepped && which == BELAY_CLOCK_REAL) {
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
static int t_stat_mount(void *ctx, int dfd, const char *name, struct stat *st,
                        bool *mount_root, bool *mount_known) {
    (void)ctx;
    if (g_arm == STATX_ENOSYS) {
        *mount_root = *mount_known = false;
        errno = ENOSYS;
        return -1;
    }
    if (g_arm == STATX_EPERM_ONCE && !g_fired && g_x != NULL && strcmp(name, g_x) == 0) {
        g_fired = 1;
        errno = EPERM;
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
    return g_real->xattr_list(g_real->ctx, x, buf, n);
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
    if (g_arm == CLOCK_STEP) g_stepped = 1;
    const char *e = g_real->dir_next(g_real->ctx, d);
    if (g_rootdir == NULL) g_rootdir = d;     /* the first stream opened is the root's */
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

static void decorate(void) {
    g_real = fsops_default();
    g_ops = *g_real;
    g_ops.openat = t_openat;
    g_ops.readlinkat = t_readlinkat;
    g_ops.clock = t_clock;
    g_ops.stat_mount = t_stat_mount;
    g_ops.fstatat = t_fstatat;
    g_ops.xattr_list = t_xattr_list;
    g_ops.dir_next = t_dir_next;
}

static void arm(enum arm a, const char *x, const char *y) {
    g_arm = a; g_x = x; g_y = y; g_fired = 0; g_replay = 0; g_dir = NULL; g_first = NULL;
    g_rootdir = NULL; g_walked = NULL; g_flip = 0; g_stepped = 0; g_step_s = 0; g_skew_s = 0;
    g_statx_calls = 0; g_statx_after = 0;
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

#endif

TEST(w6_file_capability_is_recorded) {
#ifndef __linux__
    printf("      (skipped: Linux only -- file capabilities need a user namespace)\n");
    return;
#else
    reset();
    touch("capfile", "#!/bin/true\n");
    const pid_t pid = fork();
    if (pid == 0) _exit(caps_child());
    int status = 0;
    waitpid(pid, &status, 0);
    const int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 99;
    if (rc == 77) { printf("      (skipped: cannot set a file capability here)\n"); return; }
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
    printf("      (skipped: Linux only -- overlayfs in a user namespace)\n");
    return;
#else
    reset();
    mk("lower"); mk("up"); mk("merged");
    touch("lower/lower.txt", "lower");
    const pid_t pid = fork();
    if (pid == 0) _exit(overlay_child());
    int status = 0;
    waitpid(pid, &status, 0);
    const int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 99;
    if (rc == 77) { printf("      (skipped: no unprivileged user+mount namespace here)\n"); return; }
    ASSERT_EQ_INT(0, rc);
#endif
}

TEST(r3_file_bind_mounted_from_another_fs_is_a_boundary_with_or_without_statx) {
#ifndef __linux__
    printf("      (skipped: Linux only -- bind mounts in a user namespace)\n");
    return;
#else
    reset();
    mk("fs"); mk("scope");
    touch("scope/f", "local");
    const pid_t pid = fork();
    if (pid == 0) _exit(bind_child());
    int status = 0;
    waitpid(pid, &status, 0);
    const int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 99;
    if (rc == 77) { printf("      (skipped: no unprivileged user+mount namespace here)\n"); return; }
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
    printf("      (skipped: Linux only -- statx)\n");
    return;
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

int main(void) {
    decorate();
    snprintf(g_root, sizeof g_root, "/tmp/belay_races_%d", (int)getpid());
    snprintf(g_m, sizeof g_m, "/tmp/belay_races_%d.ndjson", (int)getpid());

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
    RUN(r3_file_bind_mounted_from_another_fs_is_a_boundary_with_or_without_statx);
    RUN(r3_move_into_a_listed_directory_is_caught_whatever_the_file_clock);
    RUN(r3_file_changed_after_it_was_read_is_raced);
    RUN(r3_one_statx_eperm_is_recorded_and_does_not_switch_statx_off);
    RUN(r3_empty_link_target_is_recorded_unreadable);
    RUN(w6_file_capability_is_recorded);
    RUN(w6_unreadable_xattrs_are_unknown_not_none);

    char cmd[600];
    snprintf(cmd, sizeof cmd, "rm -rf '%s' '%s'", g_root, g_m);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
