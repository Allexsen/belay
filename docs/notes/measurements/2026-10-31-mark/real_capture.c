#define _GNU_SOURCE
/* Capture-level mark vs check, no store: what the proposal estimated. */
#include "belay/manifest.h"
#include "belay/error.h"
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
int main(int argc, char **argv) {   /* m <check|mark> <scope> <out> [prev] */
    struct belay_manifest_opts o = { .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
                                     .previous = argc > 4 ? argv[4] : NULL };
    struct belay_manifest_stats s;
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    if (belay_manifest_write(argv[3], argv[2], &o, &s) != 0) { fprintf(stderr, "%s\n", belay_err_msg()); return 1; }
    clock_gettime(CLOCK_MONOTONIC, &b);
    struct rusage u; getrusage(RUSAGE_SELF, &u);
    printf("%-6s %7.3f s %6ld KiB  entries %zu trusted %zu racy %zu prefilter %d\n", argv[1],
           (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9, u.ru_maxrss, s.entries, s.trusted, s.racy, s.prefilter);
    return 0;
}
