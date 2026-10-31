/*
 *  mark's prefilter (NOTES/phase5-structure.md §4; decisions Q2, Q6, Q8) at
 *  the capture level. The proof the proposal promised: a differential test
 *  -- random changes to a tree, and after each a prefiltered capture and a
 *  full one, whose entries must be the same bytes -- run with the
 *  filesystem's own timestamps and through an adapter that rounds every
 *  stat's times to 1 s and to 2 s (coarse filesystems), changing files
 *  within one tick of the previous capture, where only the racy rule
 *  catches a same-size rewrite. Then the exclusion and the root identity.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "capture/capture.h"
#include "capture/fsops.h"

#include "belay/error.h"
#include "belay/manifest.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char g_dir[256], g_tree[300];
static const struct fsops *g_real;
static struct fsops g_ops;
static long g_round_ns;          /* 0: the filesystem's own times */

static void round_st(struct stat *st) {
    if (g_round_ns == 0) return;
#ifdef __APPLE__
    struct timespec *m = &st->st_mtimespec, *c = &st->st_ctimespec;
#else
    struct timespec *m = &st->st_mtim, *c = &st->st_ctim;
#endif
    const long long gm = ((long long)m->tv_sec * 1000000000LL + m->tv_nsec) / g_round_ns * g_round_ns;
    const long long gc = ((long long)c->tv_sec * 1000000000LL + c->tv_nsec) / g_round_ns * g_round_ns;
    m->tv_sec = (time_t)(gm / 1000000000LL);
    m->tv_nsec = (long)(gm % 1000000000LL);
    c->tv_sec = (time_t)(gc / 1000000000LL);
    c->tv_nsec = (long)(gc % 1000000000LL);
}
static int r_stat_mount(void *ctx, int dfd, const char *name, struct stat *st, bool *mr, bool *mk) {
    const int r = g_real->stat_mount(ctx, dfd, name, st, mr, mk);
    if (r == 0) round_st(st);
    return r;
}
static int r_fstatat(void *ctx, int dfd, const char *name, struct stat *st, int flags) {
    const int r = g_real->fstatat(ctx, dfd, name, st, flags);
    if (r == 0) round_st(st);
    return r;
}
static int r_fstat(void *ctx, int fd, struct stat *st) {
    const int r = g_real->fstat(ctx, fd, st);
    if (r == 0) round_st(st);
    return r;
}

static void decorate(void) {
    g_real = fsops_default();
    g_ops = *g_real;
    g_ops.stat_mount = r_stat_mount;
    g_ops.fstatat = r_fstatat;
    g_ops.fstat = r_fstat;
}

static void writef(const char *rel, const char *data, size_t n) {
    char p[600];
    snprintf(p, sizeof p, "%s/%s", g_tree, rel);
    FILE *f = fopen(p, "wb");
    if (f == NULL) return;
    if (n && fwrite(data, 1, n, f) != n) { /* the assertions say */ }
    fclose(f);
}

/* A capture of g_tree into `out`, with `previous` (NULL: full), given the
 * last capture's walk start as the CLI gives it (meta.json). */
static int64_t g_last_start;
static int capture(const char *out, const char *previous, struct belay_manifest_stats *st) {
    char store[300];
    snprintf(store, sizeof store, "%s/store", g_dir);
    const struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20, .store_max_bytes = 4096,
                                           .store_dir = store, .previous = previous,
                                           .previous_start_ns = previous ? g_last_start : 0 };
    const int r = capture_write(&g_ops, out, g_tree, &o, st);
    if (r == 0) g_last_start = st->walk_start_ns;
    return r;
}

/* The manifest's entry lines (everything but the header). */
static char *body(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    char *all = NULL;
    size_t cap = 0;
    if (getline(&all, &cap, f) == -1) { fclose(f); free(all); return NULL; }   /* the header */
    size_t n = 0, sz = 1 << 16;
    char *b = malloc(sz);
    size_t k;
    while ((k = fread(b + n, 1, sz - n, f)) > 0) {
        n += k;
        if (n == sz) b = realloc(b, sz *= 2);
    }
    b[n] = '\0';
    fclose(f);
    free(all);
    return b;
}

static unsigned g_seed = 20261031;
static unsigned rnd(void) { g_seed = g_seed * 1103515245u + 12345u; return g_seed >> 8; }

/* One random change to the tree: the kinds a prefilter can get wrong. */
static void mutate(void) {
    char rel[64], data[64];
    const unsigned f = rnd() % 12;
    snprintf(rel, sizeof rel, "d%u/f%u", f % 3, f);
    const unsigned op = rnd() % 7;
    if (op == 0) {                                   /* same size, new bytes: only a read sees it */
        snprintf(data, sizeof data, "content %08u", rnd() % 100000000u);
        writef(rel, data, strlen(data));
    } else if (op == 1) {                            /* another size */
        const size_t n = rnd() % 60;
        memset(data, 'a' + (int)(rnd() % 26), n);
        writef(rel, data, n);
    } else if (op == 2) {
        char p[600];
        snprintf(p, sizeof p, "%s/%s", g_tree, rel);
        if (chmod(p, (rnd() & 1) ? 0600 : 0644) != 0) { /* absent: fine */ }
    } else if (op == 3) {                            /* gone */
        char p[600];
        snprintf(p, sizeof p, "%s/%s", g_tree, rel);
        unlink(p);
    } else if (op == 4) {                            /* renamed over another */
        char a[600], b[600];
        snprintf(a, sizeof a, "%s/%s", g_tree, rel);
        snprintf(b, sizeof b, "%s/d%u/f%u", g_tree, (f + 1) % 3, (f + 5) % 12);
        if (rename(a, b) != 0) { /* absent: fine */ }
    } else if (op == 6) {                            /* the root itself: a file at its top level */
        char p[600];
        snprintf(p, sizeof p, "%s/top%u", g_tree, f % 3);
        if (rnd() & 1) unlink(p);
        else { FILE *t = fopen(p, "w"); if (t) { fputs("top", t); fclose(t); } }
    } else {                                         /* the same bytes written again */
        snprintf(data, sizeof data, "content %08u", f);
        writef(rel, data, strlen(data));
    }
}

static void fresh_tree(void) {
    char cmd[2000];
    snprintf(cmd, sizeof cmd, "rm -rf '%s' '%s/store' '%s'/*.ndjson && mkdir -p '%s/d0' '%s/d1' '%s/d2'",
             g_tree, g_dir, g_dir, g_tree, g_tree, g_tree);
    if (system(cmd) != 0) { /* the assertions say */ }
    for (unsigned f = 0; f < 12; f++) {
        char rel[32], data[32];
        snprintf(rel, sizeof rel, "d%u/f%u", f % 3, f);
        snprintf(data, sizeof data, "content %08u", f);
        writef(rel, data, strlen(data));
    }
}

/* Each step: a change, then mark against the previous manifest and a full
 * check; the two must agree on every entry. */
/* Waits for the next tick of `ns`, so the tree just written is older than
 * any capture after it: without that, a coarse run inside one tick trusts
 * nothing (correctly) and the test proves nothing. */
static void next_tick(long ns) {
    if (ns == 0) return;
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    const long long now = (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
    const long long wait = ns - now % ns + 10000000LL;
    const struct timespec d = { (time_t)(wait / 1000000000LL), (long)(wait % 1000000000LL) };
    nanosleep(&d, NULL);
}

static void differential(long round_ns, int steps) {
    g_round_ns = round_ns;
    fresh_tree();
    next_tick(round_ns);
    char prev[400], mark[400], full[400];
    snprintf(prev, sizeof prev, "%s/m0.ndjson", g_dir);
    struct belay_manifest_stats st;
    REQUIRE(capture(prev, NULL, &st) == 0);
    size_t trusted = 0, racy = 0;
    for (int i = 1; i <= steps; i++) {
        mutate();
        if (rnd() % 2) mutate();
        snprintf(mark, sizeof mark, "%s/m%d.ndjson", g_dir, i);
        snprintf(full, sizeof full, "%s/f%d.ndjson", g_dir, i);
        if (capture(mark, prev, &st) != 0) { BELAY_FAIL("mark %d: %s", i, belay_err_msg()); return; }
        if (!st.prefilter) BELAY_FAIL("step %d: the prefilter was not used (%s)", i,
                                      st.prefilter_skipped ? st.prefilter_skipped : "?");
        trusted += st.trusted;
        racy += st.racy;
        const int64_t mark_start = g_last_start;
        if (capture(full, NULL, &st) != 0) { BELAY_FAIL("check %d: %s", i, belay_err_msg()); return; }
        g_last_start = mark_start;
        char *a = body(mark), *b = body(full);
        if (a == NULL || b == NULL || strcmp(a, b) != 0) {
            BELAY_FAIL("step %d (round %ld ns): mark and check differ", i, round_ns);
            if (getenv("MARK_DEBUG")) {
                char cmd[1000];
                snprintf(cmd, sizeof cmd, "diff %s %s | cut -c1-400 | head -12", mark, full);
                if (system(cmd) != 0) { /* shown */ }
            }
            free(a);
            free(b);
            return;
        }
        free(a);
        free(b);
        snprintf(prev, sizeof prev, "%s", mark);
    }
    /* Not vacuous: files were trusted, and (coarse) some were racy. */
    if (trusted == 0) BELAY_FAIL("round %ld ns: no file was ever trusted", round_ns);
    if (round_ns >= 1000000000L && racy == 0) BELAY_FAIL("round %ld ns: no file was ever racy", round_ns);
}

TEST(mark_agrees_with_check_on_every_change) { differential(0, 40); }
TEST(mark_agrees_with_check_on_one_second_timestamps) { differential(1000000000L, 40); }
TEST(mark_agrees_with_check_on_two_second_timestamps) { differential(2000000000L, 40); }

/* The rule's clauses, each: a stat field that differs, or a ctime at the
 * reference point, means the file is read. */
TEST(an_unchanged_file_is_trusted_and_a_racy_one_read) {
    g_round_ns = 0;
    fresh_tree();
    char prev[400], next[400];
    snprintf(prev, sizeof prev, "%s/p.ndjson", g_dir);
    snprintf(next, sizeof next, "%s/n.ndjson", g_dir);
    struct belay_manifest_stats st;
    /* The kernel stamps ctimes from a coarse clock (a few ms): a file
     * written in the tick the walk began is at R and read, correctly. */
    const struct timespec tick = { 0, 50000000L };
    nanosleep(&tick, NULL);
    REQUIRE(capture(prev, NULL, &st) == 0);
    REQUIRE(capture(next, prev, &st) == 0);
    ASSERT_TRUE(st.prefilter);
    ASSERT_EQ_INT(12, (int)st.trusted);                 /* all older than the previous walk's start */
    ASSERT_TRUE(st.reference_ns > st.previous_newest_ns);
    /* Coarse: the files were written in the tick the previous walk began:
     * at the reference point, so read. */
    g_round_ns = 2000000000L;
    fresh_tree();
    REQUIRE(capture(prev, NULL, &st) == 0);
    REQUIRE(capture(next, prev, &st) == 0);
    ASSERT_EQ_INT(12, (int)(st.trusted + st.racy));
    g_round_ns = 0;
}

/* Review 2026-10-31, Phase 5, 4: a change directly in the scope root moves
 * the newest ctime the walk reports -- else mark read every file again and
 * said the clock went backwards. */
TEST(a_change_in_the_root_is_the_newest_ctime) {
    g_round_ns = 0;
    fresh_tree();
    char prev[400], next[400], p[600];
    snprintf(prev, sizeof prev, "%s/p.ndjson", g_dir);
    snprintf(next, sizeof next, "%s/n.ndjson", g_dir);
    struct belay_manifest_stats st;
    snprintf(p, sizeof p, "%s/top", g_tree);
    FILE *f = fopen(p, "w");
    if (f) { fputs("t", f); fclose(f); }
    REQUIRE(capture(prev, NULL, &st) == 0);
    unlink(p);                                               /* the root's ctime moves; no file's does */
    REQUIRE(capture(next, prev, &st) == 0);
    ASSERT_TRUE(st.newest_ctime_ns >= st.previous_newest_ns);
}

/* Review 2026-10-31, Phase 5, 5: on 1-second timestamps, a file rewritten at
 * the same size during the walk, after it was read and within its own
 * ctime tick, keeps the stat the walk recorded. Every mark after must read
 * it: its ctime is not before the walk began. */
static int g_rewrite_armed;   /* 1: waiting for f0's open; 2: f0 read, rewrite at the next open */
static int w_openat(void *ctx, int dfd, const char *name, int flags) {
    if (g_rewrite_armed == 2) {                              /* the walk is past d0/f0 */
        g_rewrite_armed = 0;
        writef("d0/f0", "content 9999999X", 16);
    }
    if (g_rewrite_armed == 1 && strcmp(name, "f0") == 0) g_rewrite_armed = 2;
    return g_real->openat(ctx, dfd, name, flags);
}

TEST(a_rewrite_during_the_walk_after_its_read_is_read_by_every_mark) {
    g_round_ns = 1000000000L;
    next_tick(g_round_ns);                                   /* tree, walk and rewrite in one tick */
    fresh_tree();
    char prev[400], next[400], full[400];
    snprintf(prev, sizeof prev, "%s/p.ndjson", g_dir);
    snprintf(next, sizeof next, "%s/n.ndjson", g_dir);
    snprintf(full, sizeof full, "%s/f.ndjson", g_dir);
    struct belay_manifest_stats st;
    g_ops.openat = w_openat;
    g_rewrite_armed = 1;
    const int r = capture(prev, NULL, &st);
    g_ops.openat = g_real->openat;
    REQUIRE(r == 0);
    if (g_rewrite_armed) BELAY_FAIL("%s", "the rewrite never happened: the test proves nothing");
    next_tick(g_round_ns);
    REQUIRE(capture(next, prev, &st) == 0);
    const int64_t start = g_last_start;
    REQUIRE(capture(full, NULL, &st) == 0);
    g_last_start = start;
    char *a = body(next), *b = body(full);
    if (a == NULL || b == NULL || strcmp(a, b) != 0) BELAY_FAIL("%s", "mark trusted a file rewritten during the walk");
    free(a);
    free(b);
    g_round_ns = 0;
}

/* Review 2026-10-31, Phase 5, 6: only the hash is reused; whether a copy is
 * kept is decided anew. A writer present at the first capture kept the copy
 * out; a store object deleted since; a claim that changed by a directory
 * rename (the file's ctime unmoved): each mark must keep the copy a full
 * capture would. */
static int g_writer_on;
static int w_writer(void *ctx, int fd) { return g_writer_on ? 1 : g_real->writer_present(ctx, fd); }

TEST(a_mark_keeps_the_copies_a_full_capture_would) {
    g_round_ns = 0;
    fresh_tree();
    char prev[400], next[400], full[400], cmd[1400];
    snprintf(prev, sizeof prev, "%s/p.ndjson", g_dir);
    snprintf(next, sizeof next, "%s/n.ndjson", g_dir);
    snprintf(full, sizeof full, "%s/f.ndjson", g_dir);
    struct belay_manifest_stats st;
    g_ops.writer_present = w_writer;
    g_writer_on = 1;                                         /* every copy kept out */
    const int r = capture(prev, NULL, &st);
    g_writer_on = 0;
    g_ops.writer_present = g_real->writer_present;
    REQUIRE(r == 0);
    REQUIRE(capture(next, prev, &st) == 0);
    REQUIRE(capture(full, NULL, &st) == 0);
    char *a = body(next), *b = body(full);
    if (a == NULL || b == NULL || strcmp(a, b) != 0) BELAY_FAIL("%s", "a writer at the first capture: mark differs");
    free(a); free(b);

    snprintf(cmd, sizeof cmd, "rm -rf '%s/store'", g_dir);    /* every object gone */
    if (system(cmd) != 0) { /* the assertions say */ }
    snprintf(prev, sizeof prev, "%s", full);
    REQUIRE(capture(next, prev, &st) == 0);
    REQUIRE(capture(full, NULL, &st) == 0);
    a = body(next); b = body(full);
    if (a == NULL || b == NULL || strcmp(a, b) != 0) BELAY_FAIL("%s", "store objects gone: mark differs");
    free(a); free(b);

    /* A large file, unclaimed, then claimed by pip's RECORD rule through a
     * directory rename: stored whatever its size once claimed. */
    snprintf(cmd, sizeof cmd, "mkdir -p '%s/staging' && head -c 9000 /dev/zero | tr '\\\\0' x > '%s/staging/RECORD'",
             g_tree, g_tree);
    if (system(cmd) != 0) { /* the assertions say */ }
    REQUIRE(capture(full, NULL, &st) == 0);
    snprintf(prev, sizeof prev, "%s", full);
    snprintf(cmd, sizeof cmd, "mv '%s/staging' '%s/foo-1.0.dist-info'", g_tree, g_tree);
    if (system(cmd) != 0) { /* the assertions say */ }
    REQUIRE(capture(next, prev, &st) == 0);
    REQUIRE(capture(full, NULL, &st) == 0);
    a = body(next); b = body(full);
    if (a == NULL || b == NULL || strcmp(a, b) != 0) BELAY_FAIL("%s", "a claim by rename: mark differs");
    if (b != NULL && strstr(b, "\"path\":\"foo-1.0.dist-info/RECORD\"") != NULL && strstr(b, "\"stored\"") == NULL)
        BELAY_FAIL("%s", "the claimed RECORD was not stored by the full capture either");
    free(a); free(b);
}

/* A small unclaimed binary file has no copy, as a full capture keeps none:
 * mark trusts it after reading its first SNIFF_BYTES, not the whole file
 * (measured 2026-10-31: the Go tree's 756 such files were read on every
 * mark). A small text file without a copy is read whole and stored. */
TEST(a_small_binary_file_without_a_copy_is_trusted) {
    g_round_ns = 0;
    fresh_tree();
    writef("d0/bin", "ab\0cd", 5);
    const struct timespec tick = { 0, 50000000L };
    nanosleep(&tick, NULL);
    char prev[400], next[400], full[400];
    snprintf(prev, sizeof prev, "%s/p.ndjson", g_dir);
    snprintf(next, sizeof next, "%s/n.ndjson", g_dir);
    snprintf(full, sizeof full, "%s/f.ndjson", g_dir);
    struct belay_manifest_stats st;
    REQUIRE(capture(prev, NULL, &st) == 0);
    REQUIRE(capture(next, prev, &st) == 0);
    ASSERT_EQ_INT(13, (int)st.trusted);
    const int64_t start = g_last_start;
    REQUIRE(capture(full, NULL, &st) == 0);
    g_last_start = start;
    char *a = body(next), *b = body(full);
    if (a == NULL || b == NULL || strcmp(a, b) != 0) BELAY_FAIL("%s", "mark and check differ");
    free(a);
    free(b);
}

/* S3 (M3): a file rewritten at the same size with its mtime put back -- the
 * classic case only ctime reveals -- is read, and its new hash recorded. */
TEST(a_same_size_rewrite_with_its_mtime_restored_is_read) {
    g_round_ns = 0;
    fresh_tree();
    char prev[400], next[400], full[400], p[600];
    snprintf(prev, sizeof prev, "%s/p.ndjson", g_dir);
    snprintf(next, sizeof next, "%s/n.ndjson", g_dir);
    snprintf(full, sizeof full, "%s/f.ndjson", g_dir);
    struct belay_manifest_stats st;
    REQUIRE(capture(prev, NULL, &st) == 0);
    snprintf(p, sizeof p, "%s/d0/f0", g_tree);
    struct stat before;
    REQUIRE(stat(p, &before) == 0);
    writef("d0/f0", "CONTENT 0000000X", 16);                 /* same size, other bytes */
#ifdef __APPLE__
    const struct timespec t[2] = { before.st_atimespec, before.st_mtimespec };
#else
    const struct timespec t[2] = { before.st_atim, before.st_mtim };
#endif
    REQUIRE(utimensat(AT_FDCWD, p, t, 0) == 0);               /* mtime put back; ctime moves */
    REQUIRE(capture(next, prev, &st) == 0);
    REQUIRE(capture(full, NULL, &st) == 0);
    char *a = body(next), *b = body(full);
    ASSERT_TRUE(a != NULL && b != NULL && strcmp(a, b) == 0);
    free(a);
    free(b);
}

/* A previous manifest with other limits, or another scope's, is not used:
 * a full walk, said. */
TEST(an_unusable_previous_manifest_means_a_full_walk) {
    g_round_ns = 0;
    fresh_tree();
    char prev[400], next[400], store[300];
    snprintf(prev, sizeof prev, "%s/p.ndjson", g_dir);
    snprintf(next, sizeof next, "%s/n.ndjson", g_dir);
    snprintf(store, sizeof store, "%s/store", g_dir);
    struct belay_manifest_stats st;
    const struct belay_manifest_opts other = { .hash_max_bytes = 100, .store_max_bytes = 4096, .store_dir = store };
    REQUIRE(capture_write(&g_ops, prev, g_tree, &other, &st) == 0);
    REQUIRE(capture(next, prev, &st) == 0);
    ASSERT_FALSE(st.prefilter);
    ASSERT_TRUE(st.prefilter_skipped != NULL && strstr(st.prefilter_skipped, "limits") != NULL);
    ASSERT_EQ_INT(0, (int)st.trusted);
}

/* Q8's inputs: the walk reports the newest ctime it saw and the previous
 * manifest's, so a caller can tell ctime went backwards. */
TEST(the_walk_reports_the_newest_ctime_it_saw) {
    g_round_ns = 0;
    fresh_tree();
    char prev[400], next[400];
    snprintf(prev, sizeof prev, "%s/p.ndjson", g_dir);
    snprintf(next, sizeof next, "%s/n.ndjson", g_dir);
    struct belay_manifest_stats st;
    REQUIRE(capture(prev, NULL, &st) == 0);
    const int64_t first = st.newest_ctime_ns;
    REQUIRE(capture(next, prev, &st) == 0);
    ASSERT_TRUE(first > 0 && st.newest_ctime_ns == first);
    ASSERT_TRUE(st.previous_newest_ns == first);
}

/* Q6: a directory excluded by identity is not walked; its name stays in its
 * parent's listing, so the parent is not "unstable". */
TEST(an_excluded_directory_is_not_recorded) {
    g_round_ns = 0;
    fresh_tree();
    char p[600], out[400];
    snprintf(p, sizeof p, "%s/.belay-state", g_tree);
    mkdir(p, 0700);
    snprintf(p, sizeof p, "%s/.belay-state/secret", g_tree);
    FILE *f = fopen(p, "w");
    if (f) { fputs("x", f); fclose(f); }
    snprintf(p, sizeof p, "%s/.belay-state", g_tree);
    struct stat sd;
    REQUIRE(stat(p, &sd) == 0);
    snprintf(out, sizeof out, "%s/x.ndjson", g_dir);
    const struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20, .exclude = true,
                                           .exclude_dev = (uint64_t)sd.st_dev, .exclude_ino = (uint64_t)sd.st_ino };
    struct belay_manifest_stats st;
    REQUIRE(capture_write(&g_ops, out, g_tree, &o, &st) == 0);
    ASSERT_EQ_INT(1, (int)st.excluded);
    ASSERT_EQ_INT(0, (int)st.unstable);
    char *b = body(out);
    REQUIRE(b != NULL);
    ASSERT_TRUE(strstr(b, ".belay-state") == NULL);
    free(b);
}

/* §5.1.1: the root the caller resolved must be the one the walk opens. */
TEST(a_root_that_is_not_the_one_resolved_is_refused) {
    g_round_ns = 0;
    fresh_tree();
    struct stat sd;
    REQUIRE(stat(g_tree, &sd) == 0);
    char out[400];
    snprintf(out, sizeof out, "%s/r.ndjson", g_dir);
    const struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20, .expect_root = true,
                                           .root_dev = (uint64_t)sd.st_dev, .root_ino = (uint64_t)sd.st_ino + 1 };
    ASSERT_EQ_INT(-1, capture_write(&g_ops, out, g_tree, &o, NULL));
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "changed during resolution") != NULL);
    ASSERT_TRUE(access(out, F_OK) != 0);
    belay_err_clear();
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_mark_%d", (int)getpid());
    snprintf(g_tree, sizeof g_tree, "%s/tree", g_dir);
    mkdir(g_dir, 0700);
    decorate();
    RUN(mark_agrees_with_check_on_every_change);
    RUN(mark_agrees_with_check_on_one_second_timestamps);
    RUN(mark_agrees_with_check_on_two_second_timestamps);
    RUN(an_unchanged_file_is_trusted_and_a_racy_one_read);
    RUN(a_same_size_rewrite_with_its_mtime_restored_is_read);
    RUN(a_change_in_the_root_is_the_newest_ctime);
    RUN(a_rewrite_during_the_walk_after_its_read_is_read_by_every_mark);
    RUN(a_mark_keeps_the_copies_a_full_capture_would);
    RUN(a_small_binary_file_without_a_copy_is_trusted);
    RUN(an_unusable_previous_manifest_means_a_full_walk);
    RUN(the_walk_reports_the_newest_ctime_it_saw);
    RUN(an_excluded_directory_is_not_recorded);
    RUN(a_root_that_is_not_the_one_resolved_is_refused);
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
