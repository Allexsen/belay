/*
 *  mkdir_p (src/utils.c): every directory it makes has its parent synced,
 *  so a power loss on a first run cannot take a directory that later syncs
 *  assume exists (decided 2026-10-30). Fixtures live under /tmp (§0.4d).
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[256];
static char g_synced[8][512];
static int g_n;

static void record(const char *dir, void *ctx) {
    (void)ctx;
    if (g_n < 8) snprintf(g_synced[g_n], sizeof g_synced[g_n], "%s", dir);
    g_n++;
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
    char path[512], want[4][512];
    snprintf(path, sizeof path, "%s/a/b/c", g_dir);
    snprintf(want[0], sizeof want[0], "/tmp");
    snprintf(want[1], sizeof want[1], "%s", g_dir);
    snprintf(want[2], sizeof want[2], "%s/a", g_dir);
    snprintf(want[3], sizeof want[3], "%s/a/b", g_dir);
    ASSERT_EQ_INT(0, mkdir_p_with(path, 0700, record, NULL));
    ASSERT_EQ_INT(4, g_n);
    for (int i = 0; i < 4 && i < g_n; i++)
        if (strcmp(g_synced[i], want[i]) != 0)
            BELAY_FAIL("sync %d: %s, want %s", i, g_synced[i], want[i]);
    struct stat st;
    ASSERT_EQ_INT(0, stat(path, &st));
    ASSERT_EQ_INT(0700, (int)(st.st_mode & 07777));
    g_n = 0;
    ASSERT_EQ_INT(0, mkdir_p_with(path, 0700, record, NULL));
    ASSERT_EQ_INT(0, g_n);                              /* nothing made, nothing synced */
    snprintf(path, sizeof path, "%s/a/b/d/", g_dir);    /* one more level; trailing slash */
    ASSERT_EQ_INT(0, mkdir_p_with(path, 0700, record, NULL));
    ASSERT_EQ_INT(1, g_n);
    ASSERT_TRUE(strcmp(g_synced[0], want[3]) == 0);
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
    RUN(mkdir_p_makes_every_directory);
    fresh();
    return belay_test_report();
}
