/*
 *  Stress test (gap d, 2026-10-26). Linux only.
 *
 *  Every race in test_races_linux.c is forced at one exact point. This one is
 *  not: a background thread hammers the tree for the whole duration of many
 *  back-to-back checks, moving files between directories and replacing their
 *  contents, with no coordination at all.
 *
 *  What must hold, whatever the timing:
 *    - no check crashes or fails, and the reader accepts every manifest;
 *    - NO SILENT "NO CHANGE": a manifest whose trailer claims a clean, single
 *      instant (vanished, unreadable, unstable and raced all zero) must be a
 *      state the tree really had. Every mutation is atomic (rename), so at any
 *      instant each file exists exactly once and holds one of its variants;
 *      a clean manifest that shows a file twice, not at all, or with bytes it
 *      never held is the defect class this tool exists to prevent.
 *
 *  Fixtures live under /tmp, or under $BELAY_TEST_ROOT (§0.4d).
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/manifest.h"
#include "belay/error.h"
#include "belay/hash.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { FILES = 300, VARIANTS = 4, CHECKS = 400 };

static char g_base[256], g_scope[300], g_out[300], g_m[300];
static char g_hex[FILES][VARIANTS][65];
static atomic_int g_stop;
static atomic_long g_ops;

static void variant(char *buf, size_t n, int f, int v) {
    /* Same size for every variant, so only the content tells them apart. */
    snprintf(buf, n, "file %03d variant %d ..........\n", f, v);
}

static void put(const char *path, int f, int v) {
    char c[64];
    variant(c, sizeof c, f, v);
    FILE *fp = fopen(path, "wb");
    if (fp) { fputs(c, fp); fclose(fp); }
}

/* Moves a file between A and B, or replaces its content by renaming a fully
 * written file from outside the scope over it. Both are atomic. */
static void *mutator(void *arg) {
    (void)arg;
    unsigned seed = 12345;
    char from[600], to[600];
    int burst = 0;
    while (!atomic_load(&g_stop)) {
        /* Bursts of activity separated by idle gaps, so checks overlap the
         * mutations fully, partly, or not at all -- the partial overlaps are
         * where a walk could be fooled into a clean claim. */
        if (burst-- <= 0) {
            usleep((useconds_t)(rand_r(&seed) % 8000));
            burst = (int)(rand_r(&seed) % 40);
        }
        const int f = (int)(rand_r(&seed) % FILES);
        if (rand_r(&seed) % 2) {
            for (int k = 0; k < 2; k++) {
                const char *a = k ? "B" : "A", *b = k ? "A" : "B";
                snprintf(from, sizeof from, "%s/%s/f%03d", g_scope, a, f);
                snprintf(to, sizeof to, "%s/%s/f%03d", g_scope, b, f);
                if (rename(from, to) == 0) break;
            }
        } else {
            /* The mutator is the only writer, so where the file is now is
             * where it will be at the rename: no duplicate can appear. */
            snprintf(from, sizeof from, "%s/tmp%03d", g_out, f);
            put(from, f, (int)(rand_r(&seed) % VARIANTS));
            for (int k = 0; k < 2; k++) {
                snprintf(to, sizeof to, "%s/%s/f%03d", g_scope, k ? "B" : "A", f);
                if (access(to, F_OK) == 0 && rename(from, to) == 0) break;
            }
        }
        atomic_fetch_add(&g_ops, 1);
        usleep(20);
    }
    return NULL;
}

static int g_seen[FILES];
static int g_bad;
static int collect(const struct belay_entry *e, void *ctx) {
    (void)ctx;
    int f;
    char d;
    if (e->type != BELAY_T_REG || sscanf(e->path, "%c/f%d", &d, &f) != 2 || f < 0 || f >= FILES)
        return 0;
    g_seen[f]++;
    if (e->has_hash) {
        int ok = 0;
        for (int v = 0; v < VARIANTS; v++) ok |= strcmp(e->sha256_hex, g_hex[f][v]) == 0;
        if (!ok) g_bad++;
    }
    return 0;
}

TEST(clean_manifest_under_a_mutating_tree_is_a_real_state) {
    char p[600];
    snprintf(p, sizeof p, "%s/A", g_scope); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/B", g_scope); mkdir(p, 0755);
    for (int f = 0; f < FILES; f++) {
        for (int v = 0; v < VARIANTS; v++) {
            char c[64];
            variant(c, sizeof c, f, v);
            struct belay_sha256 h;
            uint8_t d[BELAY_SHA256_DIGEST_LEN];
            belay_sha256_init(&h);
            belay_sha256_update(&h, c, strlen(c));
            belay_sha256_final(&h, d);
            belay_hex_encode(g_hex[f][v], d, sizeof d);
        }
        snprintf(p, sizeof p, "%s/%s/f%03d", g_scope, (f % 2) ? "A" : "B", f);
        put(p, f, 0);
    }

    pthread_t th;
    ASSERT_EQ_INT(0, pthread_create(&th, NULL, mutator, NULL));
    int clean = 0, flagged = 0, failed = 0, inconsistent = 0;
    for (int i = 0; i < CHECKS; i++) {
        struct belay_manifest_opts o = {
            .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
            .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
        };
        struct belay_manifest_stats st;
        if (belay_manifest_write(g_m, g_scope, &o, &st) != 0 ||
            (memset(g_seen, 0, sizeof g_seen), g_bad = 0,
             belay_manifest_read(g_m, collect, NULL) != 0)) {
            printf("      check %d failed: %s\n", i, belay_err_msg());
            belay_err_clear();
            failed++;
            continue;
        }
        if (st.vanished || st.unreadable || st.unstable || st.raced) { flagged++; continue; }
        clean++;
        for (int f = 0; f < FILES; f++) if (g_seen[f] != 1) { inconsistent++; break; }
        if (g_bad) inconsistent++;
    }
    atomic_store(&g_stop, 1);
    pthread_join(th, NULL);
    printf("      %d checks: %d flagged, %d claimed clean, %ld mutations\n",
           CHECKS, flagged, clean, (long)atomic_load(&g_ops));
    ASSERT_EQ_INT(0, failed);
    ASSERT_EQ_INT(0, inconsistent);          /* no silent "no change" */
    ASSERT_TRUE(atomic_load(&g_ops) > CHECKS);
    ASSERT_TRUE(flagged > 0);                /* the mutator really raced the walks */
    ASSERT_TRUE(clean > 0);                  /* and the clean-claim check really ran */
}

int main(void) {
    /* BELAY_TEST_ROOT lets CI run this on other filesystems (btrfs, NFS). */
    const char *root = getenv("BELAY_TEST_ROOT");
    snprintf(g_base, sizeof g_base, "%s/belay_stress_%d", root != NULL ? root : "/tmp", (int)getpid());
    snprintf(g_scope, sizeof g_scope, "%s/scope", g_base);
    snprintf(g_out, sizeof g_out, "%s/out", g_base);
    snprintf(g_m, sizeof g_m, "%s/m.ndjson", g_base);
    mkdir(g_base, 0755);
    mkdir(g_scope, 0755);
    mkdir(g_out, 0755);

    RUN(clean_manifest_under_a_mutating_tree_is_a_real_state);

    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_base);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
