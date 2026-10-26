/*
 *  SPIKE -- measurement only, not feature code (decision 2b, 2026-10-26).
 *
 *  Question: what does git's racy rule cost on a tree nobody is writing to?
 *  The rule: a regular file whose timestamp may lie in the filesystem's
 *  CURRENT tick could be rewritten again within that tick without its ctime
 *  moving, so its hash is not trusted -- it is re-read (or marked unverified).
 *
 *  "Current tick" needs the filesystem's notion of now. Two ways to bound it:
 *    - clock-free: the newest ctime seen so far in the walk is a lower bound
 *      on the filesystem's now, so a file whose ctime is OLDER than some
 *      ctime already seen cannot be in the current tick; a file whose ctime
 *      is the newest seen so far might be. No system clock is consulted,
 *      so it holds for filesystems stamped by another machine's clock too.
 *    - clock: ctime within one tick (clock_getres of CLOCK_REALTIME_COARSE)
 *      of the coarse realtime clock at the moment of the read. Shown for
 *      comparison only: the walk must not depend on the clock.
 *
 *  Reports, for each: how many files are racy, their bytes, and the time to
 *  re-hash them, against the time to hash every regular file once.
 *
 *  Usage: spike_racy <scope>
 */
#define _GNU_SOURCE
#include "belay/hash.h"

#include <fcntl.h>
#include <ftw.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef __linux__
#error "spike_racy is Linux-only (st_ctim)"
#endif

static int64_t ns(const struct timespec *t) { return (int64_t)t->tv_sec * 1000000000LL + t->tv_nsec; }
static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static unsigned char g_buf[1 << 16];
static uint64_t hash_file(const char *p) {
    const int fd = open(p, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd == -1) return 0;
    struct belay_sha256 c;
    belay_sha256_init(&c);
    uint64_t total = 0;
    ssize_t n;
    while ((n = read(fd, g_buf, sizeof g_buf)) > 0) {
        belay_sha256_update(&c, g_buf, (size_t)n);
        total += (uint64_t)n;
    }
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_final(&c, d);
    close(fd);
    return total;
}

struct list { char **p; size_t n, cap; uint64_t bytes; };
static void push(struct list *l, const char *p, uint64_t size) {
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 64;
        l->p = realloc(l->p, l->cap * sizeof *l->p);
        if (l->p == NULL) { perror("realloc"); exit(1); }
    }
    l->p[l->n++] = strdup(p);
    l->bytes += size;
}

static struct list g_all, g_free, g_clock;
static int64_t g_max_ctime = INT64_MIN, g_tick_ns;
static size_t g_entries;

static int visit(const char *p, const struct stat *st, int flag, struct FTW *f) {
    (void)flag; (void)f;
    g_entries++;
    const int64_t c = ns(&st->st_ctim);
    if (c > g_max_ctime) g_max_ctime = c;
    if (!S_ISREG(st->st_mode)) return 0;
    push(&g_all, p, (uint64_t)st->st_size);
    if (c >= g_max_ctime) push(&g_free, p, (uint64_t)st->st_size);   /* newest seen so far */
    struct timespec t;
    clock_gettime(CLOCK_REALTIME_COARSE, &t);
    if (c >= ns(&t) - g_tick_ns) push(&g_clock, p, (uint64_t)st->st_size);
    return 0;
}

static double rehash(const struct list *l) {
    const double t0 = now_s();
    for (size_t i = 0; i < l->n; i++) hash_file(l->p[i]);
    return now_s() - t0;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: spike_racy <scope>\n"); return 2; }
    struct timespec res;
    clock_getres(CLOCK_REALTIME_COARSE, &res);
    g_tick_ns = ns(&res);

    const double t0 = now_s();
    if (nftw(argv[1], visit, 64, FTW_PHYS | FTW_MOUNT) != 0) { perror("nftw"); return 1; }
    const double t_walk = now_s() - t0;
    rehash(&g_all);                                  /* warm the cache like a real check */
    const double t_all = rehash(&g_all);
    const double t_free = rehash(&g_free), t_clock = rehash(&g_clock);

    printf("scope %s: %zu entries, %zu regular files, %.1f MB; tick %.1f ms\n", argv[1], g_entries,
           g_all.n, g_all.bytes / 1e6, g_tick_ns / 1e6);
    printf("  walk (stat only)            %8.3f s\n", t_walk);
    printf("  hash every file once        %8.3f s\n", t_all);
    printf("  racy, clock-free rule       %8zu files %10.3f MB  re-read %.4f s (%.2f%% of hashing)\n",
           g_free.n, g_free.bytes / 1e6, t_free, 100.0 * t_free / t_all);
    printf("  racy, clock rule (compare)  %8zu files %10.3f MB  re-read %.4f s\n",
           g_clock.n, g_clock.bytes / 1e6, t_clock);
    return 0;
}
