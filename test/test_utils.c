/*
 *  mkdir_p (src/utils.c): every directory it makes has its parent synced,
 *  so a power loss on a first run cannot take a directory that later syncs
 *  assume exists (decided 2026-10-30). Fixtures live under /tmp (§0.4d).
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "utils.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[256];

/* Each sync: the directory synced (by its fd) and whether the directory
 * just made existed at that moment. */
static struct { dev_t dev; ino_t ino; bool made_exists; } g_sync[8];
static int g_n;

static int record(void *ctx, int dirfd, const char *made) {
    (void)ctx;
    struct stat st, m;
    if (g_n < 8 && fstat(dirfd, &st) == 0) {
        g_sync[g_n].dev = st.st_dev;
        g_sync[g_n].ino = st.st_ino;
        g_sync[g_n].made_exists = lstat(made, &m) == 0 && S_ISDIR(m.st_mode);
    }
    g_n++;
    return 0;
}

/* Whether sync `i` was of the directory at `path`, once the one made in it
 * existed. */
static bool synced(int i, const char *path) {
    struct stat d;
    return i < g_n && stat(path, &d) == 0 && g_sync[i].dev == d.st_dev &&
           g_sync[i].ino == d.st_ino && g_sync[i].made_exists;
}

static void fresh(void) {
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* the assertions say */ }
    g_n = 0;
}

/* Each directory made has its parent synced, right after it is made and in
 * order; a directory that is there already syncs nothing. */
TEST(each_directory_made_has_its_parent_synced) {
    fresh();
    char path[512], a[512], ab[512];
    snprintf(path, sizeof path, "%s/a/b/c", g_dir);
    snprintf(a, sizeof a, "%s/a", g_dir);
    snprintf(ab, sizeof ab, "%s/a/b", g_dir);
    ASSERT_EQ_INT(0, mkdir_p_with(path, 0700, record, NULL));
    ASSERT_EQ_INT(4, g_n);
    ASSERT_TRUE(synced(0, "/tmp"));
    ASSERT_TRUE(synced(1, g_dir));
    ASSERT_TRUE(synced(2, a));
    ASSERT_TRUE(synced(3, ab));
    struct stat st;
    ASSERT_EQ_INT(0, stat(path, &st));
    ASSERT_EQ_INT(0700, (int)(st.st_mode & 07777));
    g_n = 0;
    ASSERT_EQ_INT(0, mkdir_p_with(path, 0700, record, NULL));
    ASSERT_EQ_INT(0, g_n);                              /* nothing made, nothing synced */
    snprintf(path, sizeof path, "%s/a/b/d/", g_dir);    /* one more level; trailing slash */
    ASSERT_EQ_INT(0, mkdir_p_with(path, 0700, record, NULL));
    ASSERT_EQ_INT(1, g_n);
    ASSERT_TRUE(synced(0, ab));
    ASSERT_EQ_INT(0, stat(path, &st));
    ASSERT_EQ_INT(0700, (int)(st.st_mode & 07777));     /* the target's mode, not 0755 */
}

/* Review r3, F8: an entry that exists but is not a directory -- a file, a
 * dangling symlink -- is an error (ENOTDIR), never a directory made. A
 * symlink to a directory is one, as for mkdir -p. */
TEST(an_existing_entry_that_is_not_a_directory_is_an_error) {
    fresh();
    REQUIRE(mkdir(g_dir, 0700) == 0);
    char f[512], l[512], d[512], ld[512];
    snprintf(f, sizeof f, "%s/f", g_dir);
    snprintf(l, sizeof l, "%s/l", g_dir);
    snprintf(d, sizeof d, "%s/d", g_dir);
    snprintf(ld, sizeof ld, "%s/ld", g_dir);
    FILE *fp = fopen(f, "w");
    REQUIRE(fp != NULL);
    fclose(fp);
    REQUIRE(symlink("nowhere", l) == 0);
    REQUIRE(mkdir(d, 0700) == 0 && symlink("d", ld) == 0);
    errno = 0;
    ASSERT_EQ_INT(-1, mkdir_p(f, 0700));
    ASSERT_EQ_INT(ENOTDIR, errno);
    errno = 0;
    ASSERT_EQ_INT(-1, mkdir_p(l, 0700));
    ASSERT_EQ_INT(ENOTDIR, errno);
    ASSERT_EQ_INT(0, mkdir_p(ld, 0700));
}

/* mkdir_p itself (the real sync) makes the whole path. */
TEST(mkdir_p_makes_every_directory) {
    fresh();
    char path[512];
    snprintf(path, sizeof path, "%s/x/y", g_dir);
    ASSERT_EQ_INT(0, mkdir_p(path, 0700));
    struct stat st;
    ASSERT_EQ_INT(0, stat(path, &st));
    ASSERT_TRUE(S_ISDIR(st.st_mode));
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_utils_%d", (int)getpid());
    RUN(each_directory_made_has_its_parent_synced);
    RUN(an_existing_entry_that_is_not_a_directory_is_an_error);
    RUN(mkdir_p_makes_every_directory);
    fresh();
    return belay_test_report();
}
