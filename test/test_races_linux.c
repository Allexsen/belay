/*
 *  Race tests for the manifest writer. Linux only.
 *
 *  Each race found by independent review fires in a window of microseconds,
 *  so waiting for it by luck would make a flaky test. Instead GNU ld's --wrap
 *  (see RACE_WRAP in the Makefile) interposes the libc calls the writer makes,
 *  and a wrapper performs the hostile change at the exact moment between two
 *  of the writer's own calls. The wrappers are disarmed except while one test
 *  runs, and fire at most once.
 *
 *  Fixtures live under /tmp (§0.4d).
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/manifest.h"
#include "belay/error.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum arm { NONE, SWAP_ON_DIR_OPEN, SWAP_ON_READLINK, REPLACE_LINK_WITH_FILE,
           DUP_READDIR, REWRITE_ON_FILE_OPEN, MOVE_BETWEEN_DIRS };

static char g_root[256], g_m[300];
static const char *g_first;      /* MOVE_BETWEEN_DIRS: the directory walked first */

static enum arm g_arm;
static const char *g_x, *g_y;
static int g_fired;

int __real_openat(int, const char *, int, ...);
int __wrap_openat(int fd, const char *name, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    const int mode = va_arg(ap, int);
    va_end(ap);
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
    if (!g_fired && g_x != NULL && strcmp(name, g_x) == 0) {
        if (g_arm == SWAP_ON_DIR_OPEN && (flags & O_DIRECTORY)) {
            g_fired = 1;
            renameat2(fd, g_x, fd, g_y, RENAME_EXCHANGE);
        } else if (g_arm == REWRITE_ON_FILE_OPEN && !(flags & O_DIRECTORY)) {
            g_fired = 1;
            /* Same size, new content, between the stat and this open. */
            const int w = __real_openat(fd, name, O_WRONLY, 0);
            if (w >= 0) { if (write(w, "NEW!", 4) != 4) { /* best effort */ } close(w); }
        }
    }
    return __real_openat(fd, name, flags, mode);
}

ssize_t __real_readlinkat(int, const char *, char *, size_t);
ssize_t __wrap_readlinkat(int fd, const char *name, char *buf, size_t n) {
    if (!g_fired && g_x != NULL && strcmp(name, g_x) == 0) {
        if (g_arm == SWAP_ON_READLINK) {
            g_fired = 1;
            renameat2(fd, g_x, fd, g_y, RENAME_EXCHANGE);
        } else if (g_arm == REPLACE_LINK_WITH_FILE) {
            g_fired = 1;
            unlinkat(fd, g_x, 0);
            const int w = __real_openat(fd, g_x, O_WRONLY | O_CREAT | O_EXCL, 0644);
            if (w >= 0) close(w);
        }
    }
    if (buf == NULL) return 0;                         /* probe from the _chk wrapper */
    return __real_readlinkat(fd, name, buf, n);
}

/* With _FORTIFY_SOURCE the writer's readlinkat call is compiled to the checked
 * variant, so it needs the same interposition or the race never fires. */
ssize_t __real___readlinkat_chk(int, const char *, char *, size_t, size_t);
ssize_t __wrap___readlinkat_chk(int fd, const char *name, char *buf, size_t n, size_t buflen) {
    (void)__wrap_readlinkat(fd, name, NULL, 0);        /* fire the armed race, if any */
    return __real___readlinkat_chk(fd, name, buf, n, buflen);
}

struct dirent *__real_readdir(DIR *);
static struct dirent g_saved;
static int g_replay;
static DIR *g_dir;
struct dirent *__wrap_readdir(DIR *d) {
    if (g_arm == DUP_READDIR && g_replay == 1 && d == g_dir) {
        g_replay = 2;
        return &g_saved;                  /* the same name, a second time */
    }
    struct dirent *e = __real_readdir(d);
    if (g_arm == DUP_READDIR && e != NULL && g_replay == 0 && g_x != NULL &&
        strcmp(e->d_name, g_x) == 0) {
        g_saved = *e;
        g_replay = 1;
        g_dir = d;
    }
    return e;
}

static void arm(enum arm a, const char *x, const char *y) {
    g_arm = a; g_x = x; g_y = y; g_fired = 0; g_replay = 0; g_dir = NULL; g_first = NULL;
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
    const int rc = belay_manifest_write(g_m, g_root, &o, st);
    g_arm = NONE;                 /* disarm, but keep g_fired for the assertions */
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
    arm(MOVE_BETWEEN_DIRS, NULL, NULL);
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, check(&st));
    ASSERT_TRUE(g_fired);
    const char *second = (g_first != NULL && g_first[0] == 'A') ? "B" : "A";
    const struct belay_entry *d = find(second);
    ASSERT_TRUE(d != NULL && d->unstable);
    ASSERT_EQ_INT(1, (int)st.unstable);
}

int main(void) {
    snprintf(g_root, sizeof g_root, "/tmp/belay_races_%d", (int)getpid());
    snprintf(g_m, sizeof g_m, "/tmp/belay_races_%d.ndjson", (int)getpid());

    RUN(directory_swapped_between_stat_and_open_is_flagged);
    RUN(symlink_swapped_mid_read_is_never_recorded_mismatched);
    RUN(symlink_replaced_by_file_mid_read_does_not_abort);
    RUN(name_listed_twice_is_refused_cleanly);
    RUN(rewrite_between_stat_and_open_is_unstable);
    RUN(directory_changed_during_the_walk_is_flagged_unstable);

    char cmd[600];
    snprintf(cmd, sizeof cmd, "rm -rf '%s' '%s'", g_root, g_m);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
