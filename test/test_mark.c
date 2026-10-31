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

/* A capture of g_tree into `out`, with `previous` (NULL: full). */
static int capture(const char *out, const char *previous, struct belay_manifest_stats *st) {
    char store[300];
    snprintf(store, sizeof store, "%s/store", g_dir);
    const struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20, .store_max_bytes = 4096,
                                           .store_dir = store, .previous = previous };
    return capture_write(&g_ops, out, g_tree, &o, st);
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
    const unsigned op = rnd() % 6;
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
        if (capture(full, NULL, &st) != 0) { BELAY_FAIL("check %d: %s", i, belay_err_msg()); return; }
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
    REQUIRE(capture(prev, NULL, &st) == 0);
    REQUIRE(capture(next, prev, &st) == 0);
    ASSERT_TRUE(st.prefilter);
    ASSERT_EQ_INT(12, (int)st.trusted);                 /* all older than the manifest's ctime */
    ASSERT_TRUE(st.reference_ns >= st.previous_newest_ns);
    /* Coarse: the files were written in the tick the previous manifest was:
     * at the reference point, so read. */
    g_round_ns = 2000000000L;
    fresh_tree();
    REQUIRE(capture(prev, NULL, &st) == 0);
    REQUIRE(capture(next, prev, &st) == 0);
    ASSERT_EQ_INT(12, (int)(st.trusted + st.racy));
    g_round_ns = 0;
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
    RUN(an_unusable_previous_manifest_means_a_full_walk);
    RUN(the_walk_reports_the_newest_ctime_it_saw);
    RUN(an_excluded_directory_is_not_recorded);
    RUN(a_root_that_is_not_the_one_resolved_is_refused);
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
