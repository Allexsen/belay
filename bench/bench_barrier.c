/*
 *  What F_BARRIERFSYNC costs a first capture (macOS): 2,000 new small files
 *  with the content store on, timed with the platform adapter as it is and
 *  with every sync it makes issuing F_BARRIERFSYNC instead -- the store's
 *  batched sync and the manifest's sync before its rename, plus the one
 *  after it, so an upper bound. Rounds alternate; the medians are printed.
 *  Elsewhere F_BARRIERFSYNC does not exist and both columns are fsync.
 *
 *    bench_barrier [files] [rounds]
 */
#define _GNU_SOURCE
#include "capture/capture.h"

#include "belay/error.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const struct fsops *g_real;

static int barrier_fsync(void *ctx, int fd) {
    (void)ctx;
#ifdef F_BARRIERFSYNC
    if (fcntl(fd, F_BARRIERFSYNC) == 0) return 0;
#endif
    return fsync(fd);
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static int cmp(const void *a, const void *b) {
    const double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv) {
    const int files = argc > 1 ? atoi(argv[1]) : 2000;
    const int rounds = argc > 2 ? atoi(argv[2]) : 5;
    char base[256], tree[300], cmd[700];
    snprintf(base, sizeof base, "%s/belay_barrier_%d", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp",
             (int)getpid());
    snprintf(tree, sizeof tree, "%s/tree", base);
    if (mkdir(base, 0700) != 0 || mkdir(tree, 0700) != 0) { perror(base); return 1; }
    for (int i = 0; i < files; i++) {
        char p[400], d[350];
        snprintf(d, sizeof d, "%s/d%02d", tree, i / 50);
        mkdir(d, 0700);
        snprintf(p, sizeof p, "%s/f%04d.txt", d, i);
        FILE *f = fopen(p, "w");
        if (f == NULL) { perror(p); return 1; }
        for (int k = 0; k < 20; k++) fprintf(f, "line %d of file %d\n", k, i);
        fclose(f);
    }
    g_real = fsops_default();
    struct fsops barrier = *g_real;
    barrier.fsync = barrier_fsync;
    const struct fsops *variant[2] = { g_real, &barrier };
    double *t[2] = { calloc((size_t)rounds, sizeof(double)), calloc((size_t)rounds, sizeof(double)) };
    for (int r = 0; r < rounds; r++)
        for (int v = 0; v < 2; v++) {
            char store[300], out[300];
            snprintf(store, sizeof store, "%s/store", base);
            snprintf(out, sizeof out, "%s/m.ndjson", base);
            snprintf(cmd, sizeof cmd, "rm -rf '%s' '%s'", store, out);
            if (system(cmd) != 0) return 1;
            struct belay_manifest_opts o = { .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
                                             .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
                                             .store_dir = store };
            struct belay_manifest_stats st;
            const double a = now();
            if (capture_write(variant[v], out, tree, &o, &st) != 0) {
                fprintf(stderr, "capture: %s\n", belay_err_msg());
                return 1;
            }
            t[v][r] = now() - a;
        }
    for (int v = 0; v < 2; v++) qsort(t[v], (size_t)rounds, sizeof(double), cmp);
    const double m0 = t[0][rounds / 2], m1 = t[1][rounds / 2];
#ifdef F_BARRIERFSYNC
    const char *what = "F_BARRIERFSYNC";
#else
    const char *what = "fsync (no F_BARRIERFSYNC here)";
#endif
    printf("bench_barrier: %d files, %d rounds, first capture with the store\n", files, rounds);
    printf("  fsync:   median %.3f s (min %.3f, max %.3f)\n", m0, t[0][0], t[0][rounds - 1]);
    printf("  barrier: median %.3f s (min %.3f, max %.3f) -- %s\n", m1, t[1][0], t[1][rounds - 1], what);
    printf("  overhead: %+.1f%%\n", (m1 - m0) / m0 * 100.0);
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", base);
    return system(cmd) == 0 ? 0 : 1;
}
