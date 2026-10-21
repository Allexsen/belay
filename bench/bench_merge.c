/*
 *  Spike, not the comparator: proves two sorted manifests can be compared as
 *  a streaming merge in constant memory, using the pull iterator. Step 3.1
 *  (the real comparator) builds on this shape.
 *
 *  Classification here is deliberately crude -- added / removed / changed by
 *  hash or metadata -- and exists only to show every entry is paired exactly
 *  once. It also re-checks strict ordering on both inputs, since the merge is
 *  only correct if that holds.
 *
 *  Usage: bench_merge <old.ndjson> <new.ndjson>
 */
#define _GNU_SOURCE

#include "belay/manifest.h"
#include "belay/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int path_cmp(const struct belay_entry *a, const struct belay_entry *b) {
    const size_t n = a->path_len < b->path_len ? a->path_len : b->path_len;
    const int r = memcmp(a->path, b->path, n);
    if (r != 0) return r;
    return (a->path_len > b->path_len) - (a->path_len < b->path_len);
}

static int same_state(const struct belay_entry *a, const struct belay_entry *b) {
    if (a->type != b->type || a->mode != b->mode || a->uid != b->uid ||
        a->gid != b->gid || a->size != b->size) return 0;
    if (a->has_hash != b->has_hash) return 0;
    if (a->has_hash && strcmp(a->sha256_hex, b->sha256_hex) != 0) return 0;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <old> <new>\n", argv[0]);
        return 2;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    struct belay_manifest_reader *ra, *rb;
    if (belay_manifest_open(argv[1], &ra) == -1 || belay_manifest_open(argv[2], &rb) == -1) {
        fprintf(stderr, "open: %s\n", belay_err_msg());
        return 1;
    }

    /* Two current entries and two previous ones, on the heap: four structs,
     * whatever the manifest size. */
    struct belay_entry *a = malloc(sizeof *a), *b = malloc(sizeof *b);
    struct belay_entry *pa = malloc(sizeof *pa), *pb = malloc(sizeof *pb);
    if (!a || !b || !pa || !pb) return 1;

    int ga = belay_manifest_next(ra, a);
    int gb = belay_manifest_next(rb, b);
    int have_pa = 0, have_pb = 0;
    size_t same = 0, changed = 0, added = 0, removed = 0;

    while (ga == 1 || gb == 1) {
        int c;
        if (ga != 1) c = 1;
        else if (gb != 1) c = -1;
        else c = path_cmp(a, b);

        if (c <= 0) {
            if (have_pa && path_cmp(pa, a) >= 0) { fprintf(stderr, "old not sorted\n"); return 1; }
            memcpy(pa, a, sizeof *a); have_pa = 1;
        }
        if (c >= 0) {
            if (have_pb && path_cmp(pb, b) >= 0) { fprintf(stderr, "new not sorted\n"); return 1; }
            memcpy(pb, b, sizeof *b); have_pb = 1;
        }

        if (c == 0)      { if (same_state(a, b)) same++; else changed++; }
        else if (c < 0)  removed++;
        else             added++;

        if (c <= 0) ga = belay_manifest_next(ra, a);
        if (c >= 0) gb = belay_manifest_next(rb, b);
    }

    if (ga == -1 || gb == -1) {
        fprintf(stderr, "read: %s\n", belay_err_msg());
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    const double s = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("same %zu  changed %zu  added %zu  removed %zu  in %.3f s\n",
           same, changed, added, removed, s);

    belay_manifest_close(ra);
    belay_manifest_close(rb);
    free(a); free(b); free(pa); free(pb);
    return 0;
}
