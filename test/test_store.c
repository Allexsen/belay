/*
 *  Content store tests. BLAST RADIUS unit: it writes copies of user files.
 *  Everything here runs in a throwaway directory under /tmp (§0.4d).
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/store.h"
#include "belay/hash.h"
#include "belay/error.h"
#include "capture/store_internal.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[512];

static void sha_hex(const char *data, size_t n, char out[65]) {
    struct belay_sha256 c;
    uint8_t d[32];
    belay_sha256_init(&c);
    belay_sha256_update(&c, data, n);
    belay_sha256_final(&c, d);
    belay_hex_encode(out, d, sizeof d);
}

static void obj_path(const char *hex, char *out, size_t n) {
    snprintf(out, n, "%s/%.2s/%s", g_dir, hex, hex + 2);
}

/* A staging file left behind is a leak of user content into the state dir
 * under a name nothing will ever clean up. */
static int count_tmp(void) {
    DIR *d = opendir(g_dir);
    if (d == NULL) return -1;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL)
        if (strncmp(de->d_name, ".tmp-", 5) == 0) n++;
    closedir(d);
    return n;
}

static int put(struct belay_store *s, const char *data, const char *hex) {
    struct belay_store_tx tx;
    if (belay_store_begin(s, &tx) == -1) return -1;
    if (belay_store_write(&tx, data, strlen(data)) == -1) { belay_store_abort(&tx); return -1; }
    return belay_store_commit(&tx, hex);
}

TEST(open_creates_private_directory) {
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(0, belay_store_open(g_dir, &s));
    struct stat st;
    ASSERT_EQ_INT(0, stat(g_dir, &st));
    ASSERT_EQ_INT(0700, (int)(st.st_mode & 07777));
    belay_store_close(s);
}

TEST(commit_publishes_exact_content_as_private_object) {
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(0, belay_store_open(g_dir, &s));
    const char *data = "hello store\n";
    char hex[65];
    sha_hex(data, strlen(data), hex);
    ASSERT_EQ_INT(0, put(s, data, hex));

    char p[1024];
    obj_path(hex, p, sizeof p);
    struct stat st;
    ASSERT_EQ_INT(0, stat(p, &st));
    ASSERT_EQ_INT(0600, (int)(st.st_mode & 07777));
    ASSERT_EQ_INT((int)strlen(data), (int)st.st_size);
    ASSERT_EQ_INT(1, belay_store_verify(s, hex));
    ASSERT_EQ_INT(0, count_tmp());
    belay_store_close(s);
}

/* A name that is not 64 lowercase hex must never become a path. */
TEST(hostile_object_names_are_rejected_and_cleaned_up) {
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(0, belay_store_open(g_dir, &s));
    const char *bad[] = {
        "../../../../tmp/belay_escape_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "e3b0c442",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855ff",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85/",
        "",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        if (put(s, "x", bad[i]) != -1) BELAY_FAIL("accepted object name: %s", bad[i]);
        belay_err_clear();
    }
    ASSERT_EQ_INT(-1, put(s, "x", NULL));
    belay_err_clear();
    ASSERT_EQ_INT(0, count_tmp());
    ASSERT_TRUE(access("/tmp/belay_escape_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", F_OK) != 0);
    belay_store_close(s);
}

/* Dedup keeps the existing object: same inode, not rewritten. */
TEST(duplicate_content_is_not_rewritten) {
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(0, belay_store_open(g_dir, &s));
    const char *data = "dedup me";
    char hex[65], p[1024];
    sha_hex(data, strlen(data), hex);
    ASSERT_EQ_INT(0, put(s, data, hex));
    obj_path(hex, p, sizeof p);
    struct stat a, b;
    ASSERT_EQ_INT(0, stat(p, &a));
    ASSERT_EQ_INT(0, put(s, data, hex));
    ASSERT_EQ_INT(0, stat(p, &b));
    ASSERT_EQ_INT((long long)a.st_ino, (long long)b.st_ino);
    ASSERT_EQ_INT(0, count_tmp());
    belay_store_close(s);
}

/* Something other than a regular file at an object's name was not put there
 * by belay. It must be refused, never followed and never moved aside. */
TEST(planted_symlink_at_object_name_is_refused_not_followed) {
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(0, belay_store_open(g_dir, &s));
    const char *data = "target of a planted link";
    char hex[65], p[1024], prefix[1024], victim[600];
    sha_hex(data, strlen(data), hex);

    snprintf(victim, sizeof victim, "%s_victim", g_dir);
    FILE *f = fopen(victim, "wb");
    if (f) { fputs("do not touch", f); fclose(f); }

    snprintf(prefix, sizeof prefix, "%s/%.2s", g_dir, hex);
    mkdir(prefix, 0700);
    obj_path(hex, p, sizeof p);
    ASSERT_EQ_INT(0, symlink(victim, p));

    ASSERT_EQ_INT(-1, put(s, data, hex));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    belay_err_clear();

    /* The victim is untouched and the link is still a link. */
    char buf[64] = {0};
    f = fopen(victim, "rb");
    if (f) { if (fread(buf, 1, sizeof buf - 1, f) == 0) buf[0] = 0; fclose(f); }
    ASSERT_EQ_STR("do not touch", buf);
    struct stat st;
    ASSERT_EQ_INT(0, lstat(p, &st));
    ASSERT_TRUE(S_ISLNK(st.st_mode));
    ASSERT_EQ_INT(0, belay_store_verify(s, hex));   /* a symlink is not an object */
    belay_err_clear();
    ASSERT_EQ_INT(0, count_tmp());

    unlink(p);
    unlink(victim);
    belay_store_close(s);
}

/* Dedup trusts nothing at write time, so a planted object with the wrong
 * content survives a commit -- and verify is what must catch it. */
TEST(planted_wrong_content_is_caught_by_verify) {
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(0, belay_store_open(g_dir, &s));
    const char *data = "the real content";
    char hex[65], p[1024], prefix[1024];
    sha_hex(data, strlen(data), hex);

    snprintf(prefix, sizeof prefix, "%s/%.2s", g_dir, hex);
    mkdir(prefix, 0700);
    obj_path(hex, p, sizeof p);
    FILE *f = fopen(p, "wb");
    if (f) { fputs("forged content!!", f); fclose(f); }   /* the real content's size */

    ASSERT_EQ_INT(0, put(s, data, hex));        /* kept, not rewritten */
    ASSERT_EQ_INT(0, belay_store_verify(s, hex));
    ASSERT_TRUE(strstr(belay_err_msg(), "hashing to") != NULL);
    belay_err_clear();

    unlink(p);
    belay_store_close(s);
}

/* Decided 2026-10-30: a copy's bytes are not synced, so a power loss can
 * empty a copy or cut it short. Either fails verification on read, loudly
 * (CORRUPT, naming what it hashes to), and never passes for the content its
 * name promises. */
TEST(a_copy_a_crash_emptied_or_cut_short_fails_verification) {
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(0, belay_store_open(g_dir, &s));
    const char *data = "content a power loss may take";
    char hex[65], p[1024];
    sha_hex(data, strlen(data), hex);
    ASSERT_EQ_INT(0, put(s, data, hex));
    ASSERT_EQ_INT(1, belay_store_verify(s, hex));
    obj_path(hex, p, sizeof p);
    const off_t lengths[] = { 7, 0 };                /* cut short, then emptied */
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        REQUIRE(truncate(p, lengths[i]) == 0);
        ASSERT_EQ_INT(0, belay_store_verify(s, hex));
        ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
        ASSERT_TRUE(strstr(belay_err_msg(), "has content hashing to") != NULL);
        belay_err_clear();
    }
    unlink(p);
    belay_store_close(s);
}

/* Review r3, F3: dedup kept any regular file at an object's name, so a copy a
 * power loss emptied (its name synced, its bytes not) stayed lost for every
 * later capture. A commit of the same content replaces an object whose size
 * is not the staged size; one of the right size is kept, as before. */
TEST(a_later_commit_restores_a_copy_a_crash_emptied) {
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(0, belay_store_open(g_dir, &s));
    const char *data = "content a power loss emptied";
    char hex[65], p[1024];
    sha_hex(data, strlen(data), hex);
    ASSERT_EQ_INT(0, put(s, data, hex));
    obj_path(hex, p, sizeof p);
    REQUIRE(truncate(p, 0) == 0);
    ASSERT_EQ_INT(0, belay_store_verify(s, hex));
    belay_err_clear();
    ASSERT_EQ_INT(0, put(s, data, hex));             /* the next capture stores it again */
    ASSERT_EQ_INT(1, belay_store_verify(s, hex));
    ASSERT_EQ_INT(0, count_tmp());
    struct stat st;
    ASSERT_EQ_INT(0, stat(p, &st));
    ASSERT_EQ_INT(0600, (int)(st.st_mode & 07777));
    unlink(p);
    belay_store_close(s);
}

TEST(abort_leaves_nothing) {
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(0, belay_store_open(g_dir, &s));
    struct belay_store_tx tx;
    ASSERT_EQ_INT(0, belay_store_begin(s, &tx));
    ASSERT_EQ_INT(0, belay_store_write(&tx, "partial", 7));
    ASSERT_EQ_INT(1, count_tmp());
    belay_store_abort(&tx);
    ASSERT_EQ_INT(0, count_tmp());
    belay_store_abort(&tx);                     /* idempotent */
    ASSERT_EQ_INT(-1, belay_store_write(&tx, "x", 1));
    ASSERT_EQ_INT(-1, belay_store_commit(&tx, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    belay_err_clear();
    belay_store_close(s);
}

TEST(verify_reports_missing_object) {
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(0, belay_store_open(g_dir, &s));
    ASSERT_EQ_INT(0, belay_store_verify(s, "0000000000000000000000000000000000000000000000000000000000000000"));
    belay_err_clear();
    ASSERT_EQ_INT(-1, belay_store_verify(s, "../x"));
    belay_err_clear();
    belay_store_close(s);
}

/* The store directory itself being a symlink would redirect every write. */
TEST(store_directory_that_is_a_symlink_is_refused) {
    char real[600], link[600];
    snprintf(real, sizeof real, "%s_real", g_dir);
    snprintf(link, sizeof link, "%s_link", g_dir);
    mkdir(real, 0700);
    ASSERT_EQ_INT(0, symlink(real, link));
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(-1, belay_store_open(link, &s));
    ASSERT_TRUE(s == NULL);
    belay_err_clear();
    unlink(link);
    rmdir(real);
}

/* A store writable by group or others would let another user plant objects. */
TEST(store_directory_writable_by_others_is_refused) {
    char d[600];
    snprintf(d, sizeof d, "%s_open", g_dir);
    mkdir(d, 0700);
    chmod(d, 0777);
    struct belay_store *s = NULL;
    ASSERT_EQ_INT(-1, belay_store_open(d, &s));
    ASSERT_TRUE(s == NULL);
    belay_err_clear();
    chmod(d, 0750);
    ASSERT_EQ_INT(0, belay_store_open(d, &s));   /* group-readable is fine */
    belay_store_close(s);
    rmdir(d);
}

/* ---- what belay_store_sync syncs: the adapter, with every fsync recorded ---- */

static const struct fsops *g_real;
static struct fsops g_ops;
static struct { dev_t dev; ino_t ino; } g_synced[64];
static size_t g_nsynced;

static int rec_fsync(void *ctx, int fd) {
    (void)ctx;
    struct stat st;
    if (fstat(fd, &st) == 0 && g_nsynced < sizeof g_synced / sizeof g_synced[0]) {
        g_synced[g_nsynced].dev = st.st_dev;
        g_synced[g_nsynced].ino = st.st_ino;
        g_nsynced++;
    }
    return g_real->fsync(g_real->ctx, fd);
}

/* How many recorded syncs were of the directory at `path`. */
static int synced(const char *path) {
    struct stat d;
    if (stat(path, &d) != 0) return -1;
    int n = 0;
    for (size_t i = 0; i < g_nsynced; i++)
        n += g_synced[i].dev == d.st_dev && g_synced[i].ino == d.st_ino;
    return n;
}

/* A fresh store at g_dir, its syncs recorded. */
static struct belay_store *open_recorded(bool fresh) {
    if (fresh) {
        char cmd[600];
        snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
        if (system(cmd) != 0) return NULL;
    }
    g_real = fsops_default();
    g_ops = *g_real;
    g_ops.fsync = rec_fsync;
    g_nsynced = 0;
    struct belay_store *s = NULL;
    return store_open(&g_ops, g_dir, &s) == 0 ? s : NULL;
}

/* Review F2: a capture relies on every copy its manifest names, including one
 * its commit found already there -- which an earlier capture may have renamed
 * and never synced, failing first. The sync covers that name's directory and
 * the levels above it, up to the store directory's parent. */
TEST(a_sync_covers_a_copy_found_already_stored) {
    char hex[65], prefix[600];
    sha_hex("found\n", 6, hex);
    snprintf(prefix, sizeof prefix, "%s/%.2s", g_dir, hex);
    struct belay_store *a = open_recorded(true);           /* commits, never syncs */
    REQUIRE(a != NULL);
    ASSERT_EQ_INT(0, put(a, "found\n", hex));
    belay_store_close(a);
    struct belay_store *b = open_recorded(false);
    REQUIRE(b != NULL);
    ASSERT_EQ_INT(0, put(b, "found\n", hex));              /* found: kept as it is */
    belay_store_sync(b);
    ASSERT_EQ_INT(1, synced(prefix));
    ASSERT_EQ_INT(1, synced(g_dir));
    ASSERT_EQ_INT(1, synced("/tmp"));
    belay_store_close(b);
}

/* Review F3: a fan-out directory is made by the first commit that needs it,
 * and stays when that commit fails. The commit that later lands in it relies
 * on its name in the store directory, so the sync covers that too. */
TEST(a_sync_covers_a_fan_out_directory_a_failed_commit_made) {
    char hex[65], prefix[600], tmp[700];
    sha_hex("made\n", 5, hex);
    snprintf(prefix, sizeof prefix, "%s/%.2s", g_dir, hex);
    struct belay_store *s = open_recorded(true);
    REQUIRE(s != NULL);
    struct belay_store_tx tx;
    REQUIRE(belay_store_begin(s, &tx) == 0);
    REQUIRE(belay_store_write(&tx, "made\n", 5) == 0);
    snprintf(tmp, sizeof tmp, "%s/%s", g_dir, tx.tmp);
    REQUIRE(unlink(tmp) == 0);                    /* the rename will fail: ENOENT */
    ASSERT_EQ_INT(-1, belay_store_commit(&tx, hex));
    belay_err_clear();
    struct stat st;
    ASSERT_EQ_INT(0, stat(prefix, &st));          /* made by the failed commit */
    ASSERT_EQ_INT(0, put(s, "made\n", hex));
    g_nsynced = 0;
    belay_store_sync(s);
    ASSERT_EQ_INT(1, synced(prefix));
    ASSERT_EQ_INT(1, synced(g_dir));
    belay_store_close(s);
}

/* Review F4: the first capture makes the store directory, whose name is in
 * its parent: the sync covers the parent. */
TEST(a_sync_covers_the_store_directory_in_its_parent) {
    char hex[65];
    sha_hex("first\n", 6, hex);
    struct belay_store *s = open_recorded(true);
    REQUIRE(s != NULL);
    ASSERT_EQ_INT(0, put(s, "first\n", hex));
    belay_store_sync(s);
    ASSERT_EQ_INT(1, synced(g_dir));
    ASSERT_EQ_INT(1, synced("/tmp"));
    belay_store_close(s);
}

/* The sync covers what was committed since the last one: twice in a row, the
 * second syncs nothing. */
TEST(a_second_sync_with_nothing_new_syncs_nothing) {
    char hex[65];
    sha_hex("once\n", 5, hex);
    struct belay_store *s = open_recorded(true);
    REQUIRE(s != NULL);
    ASSERT_EQ_INT(0, put(s, "once\n", hex));
    belay_store_sync(s);
    ASSERT_TRUE(g_nsynced > 0);
    g_nsynced = 0;
    belay_store_sync(s);
    ASSERT_EQ_INT(0, (int)g_nsynced);
    belay_store_close(s);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_store_%d", (int)getpid());

    RUN(open_creates_private_directory);
    RUN(commit_publishes_exact_content_as_private_object);
    RUN(hostile_object_names_are_rejected_and_cleaned_up);
    RUN(duplicate_content_is_not_rewritten);
    RUN(planted_symlink_at_object_name_is_refused_not_followed);
    RUN(planted_wrong_content_is_caught_by_verify);
    RUN(a_copy_a_crash_emptied_or_cut_short_fails_verification);
    RUN(a_later_commit_restores_a_copy_a_crash_emptied);
    RUN(abort_leaves_nothing);
    RUN(verify_reports_missing_object);
    RUN(store_directory_that_is_a_symlink_is_refused);
    RUN(store_directory_writable_by_others_is_refused);
    RUN(a_sync_covers_a_copy_found_already_stored);
    RUN(a_sync_covers_a_fan_out_directory_a_failed_commit_made);
    RUN(a_sync_covers_the_store_directory_in_its_parent);
    RUN(a_second_sync_with_nothing_new_syncs_nothing);

    char cmd[600];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
