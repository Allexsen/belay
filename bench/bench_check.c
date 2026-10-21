/*
 *  Baseline timing for the manifest writer.
 *
 *  Reports wall time, files/s and manifest size on disk. No optimisation has
 *  been attempted; these numbers exist to establish a baseline, per
 *  BELAY_DESIGN.md §10 (targets live in NOTES/targets.md and are never
 *  published until measured).
 *
 *  Usage: bench_check <scope> [label]
 */
#define _GNU_SOURCE

#include "belay/manifest.h"
#include "belay/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <scope> [label]\n", argv[0]);
        return 2;
    }
    const char *scope = argv[1];
    const char *label = argc > 2 ? argv[2] : scope;

    char mpath[4096];
    snprintf(mpath, sizeof mpath, "/tmp/belay_bench_%d.ndjson", (int)getpid());

    struct belay_manifest_opts o = { .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT, .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT };

    size_t n = 0;
    const double t0 = now_s();
    const int rc = belay_manifest_write(mpath, scope, &o, &n);
    const double t1 = now_s();

    if (rc == -1) {
        fprintf(stderr, "%s: FAILED: %s\n", label, belay_err_msg());
        return 1;
    }

    struct stat st;
    const long long bytes = (stat(mpath, &st) == 0) ? (long long)st.st_size : -1;
    const double secs = t1 - t0;

    printf("%-28s %8zu files  %7.3f s  %9.0f files/s  %8.2f MB manifest  %6.0f B/entry\n",
           label, n, secs,
           secs > 0 ? (double)n / secs : 0.0,
           bytes >= 0 ? (double)bytes / (1024.0 * 1024.0) : 0.0,
           n > 0 && bytes >= 0 ? (double)bytes / (double)n : 0.0);

    unlink(mpath);
    return 0;
}
