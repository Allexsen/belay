/*
 *  SPIKE -- measurement only, not feature code (M1 step 5.4 is not built).
 *
 *  Question: what does `belay mark` cost if it re-walks and re-hashes
 *  everything, versus a prefilter that stats everything but opens and hashes
 *  only regular files whose (ino, dev, size, mtime_ns, ctime_ns) differ from
 *  the previous manifest?
 *
 *  Rules the prefilter obeys, so the numbers are not flattering:
 *    - ctime is a PREFILTER only. Protected paths are always hashed (§6);
 *      this spike has no protected set, so the protected-path cost is the
 *      cost of hashing that set, measured separately as "full".
 *    - Racy rule (git's racy-clean problem): a file whose ctime lies within
 *      RACY_NS of the previous manifest's creation is re-hashed even if
 *      nothing differs, because a same-size rewrite within one timestamp tick
 *      leaves ctime unchanged on kernels with coarse timestamps.
 *    - A file absent from the previous manifest is hashed.
 *
 *  Simplification a real implementation must not keep: the previous manifest
 *  is loaded into a hash table, which is O(entries) memory. Production would
 *  merge the sorted previous manifest against a sorted walk instead.
 *
 *  Usage:
 *    spike_mark <scope> <prev.ndjson> prefilter
 *    spike_mark <scope> <prev.ndjson> statonly    (walk + stat, no hashing at all)
 */
#define _GNU_SOURCE

#ifndef __linux__
#error "spike_mark is a Linux-only measurement spike (st_mtim/st_ctim)"
#endif

#include "belay/manifest.h"
#include "belay/error.h"
#include "belay/hash.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define RACY_NS (1000000000LL)

struct rec {
    char    *path;
    size_t   len;
    uint64_t ino, dev, size;
    int64_t  mtime, ctime;
    bool     has_hash;
};

static struct rec *tab;
static size_t tabcap;

static uint64_t fnv(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char)s[i]; h *= 1099511628211ULL; }
    return h;
}

static void put(const struct belay_entry *e) {
    size_t i = fnv(e->path, e->path_len) & (tabcap - 1);
    while (tab[i].path != NULL) i = (i + 1) & (tabcap - 1);
    tab[i].path = malloc(e->path_len);
    memcpy(tab[i].path, e->path, e->path_len);
    tab[i].len = e->path_len;
    tab[i].ino = e->ino; tab[i].dev = e->dev; tab[i].size = e->size;
    tab[i].mtime = e->mtime_ns; tab[i].ctime = e->ctime_ns;
    tab[i].has_hash = e->has_hash;
}

static const struct rec *get(const char *p, size_t n) {
    size_t i = fnv(p, n) & (tabcap - 1);
    while (tab[i].path != NULL) {
        if (tab[i].len == n && memcmp(tab[i].path, p, n) == 0) return &tab[i];
        i = (i + 1) & (tabcap - 1);
    }
    return NULL;
}

static int64_t ns(const struct timespec *t) { return (int64_t)t->tv_sec * 1000000000 + t->tv_nsec; }

struct stats {
    size_t entries, regular, candidates, racy, absent;
    uint64_t hashed_bytes;
};

static int64_t g_prev_created;
static int g_statonly;
static unsigned char g_buf[1 << 16];

static void hash_fd(int fd, uint64_t *bytes) {
    struct belay_sha256 c;
    belay_sha256_init(&c);
    ssize_t n;
    while ((n = read(fd, g_buf, sizeof g_buf)) > 0) {
        belay_sha256_update(&c, g_buf, (size_t)n);
        *bytes += (uint64_t)n;
    }
    uint8_t d[32];
    belay_sha256_final(&c, d);
}

static void walk(int dfd, char *rel, size_t rlen, struct stats *s) {
    int dd = dup(dfd);
    DIR *d = fdopendir(dd);
    if (d == NULL) { close(dd); return; }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        const size_t nl = strlen(de->d_name);
        size_t w = rlen;
        if (rlen) rel[w++] = '/';
        memcpy(rel + w, de->d_name, nl);
        w += nl;
        rel[w] = '\0';

        struct stat st;
        if (fstatat(dfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            s->entries++;
            if (S_ISREG(st.st_mode)) {
                s->regular++;
                if (!g_statonly) {
                    const struct rec *r = get(rel, w);
                    bool cand;
                    if (r == NULL) { cand = true; s->absent++; }
                    else {
                        cand = r->ino != (uint64_t)st.st_ino || r->dev != (uint64_t)st.st_dev ||
                               r->size != (uint64_t)st.st_size ||
                               r->mtime != ns(&st.st_mtim) || r->ctime != ns(&st.st_ctim) ||
                               !r->has_hash;
                        if (!cand && ns(&st.st_ctim) >= g_prev_created - RACY_NS) {
                            cand = true;
                            s->racy++;
                        }
                    }
                    if (cand) {
                        s->candidates++;
                        const int fd = openat(dfd, de->d_name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
                        if (fd != -1) { hash_fd(fd, &s->hashed_bytes); close(fd); }
                    }
                }
            } else if (S_ISDIR(st.st_mode)) {
                const int cfd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                if (cfd != -1) { walk(cfd, rel, w, s); close(cfd); }
            }
        }
        rel[rlen] = '\0';
    }
    closedir(d);
}

static int load_cb(const struct belay_entry *e, void *c) { (void)c; put(e); return 0; }

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <scope> <prev.ndjson> prefilter|statonly\n", argv[0]);
        return 2;
    }
    g_statonly = strcmp(argv[3], "statonly") == 0;

    struct timespec t0, t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    struct belay_manifest_reader *r;
    if (belay_manifest_open(argv[2], &r) == -1) { fprintf(stderr, "%s\n", belay_err_msg()); return 1; }
    g_prev_created = belay_manifest_header(r)->created_ns;
    belay_manifest_close(r);

    tabcap = 1 << 22;
    tab = calloc(tabcap, sizeof *tab);
    if (!g_statonly && belay_manifest_read(argv[2], load_cb, NULL) == -1) {
        fprintf(stderr, "%s\n", belay_err_msg());
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    char *real = realpath(argv[1], NULL);
    const int root = open(real, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    char rel[4096] = "";
    struct stats s = {0};
    walk(root, rel, 0, &s);
    clock_gettime(CLOCK_MONOTONIC, &t2);

    const double load = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    const double walk_s = (double)(t2.tv_sec - t1.tv_sec) + (double)(t2.tv_nsec - t1.tv_nsec) / 1e9;
    printf("%-9s entries %7zu  regular %7zu  hashed %6zu (absent %zu, racy %zu)  %8.1f MB  "
           "load %.3f s  walk+hash %.3f s  total %.3f s\n",
           argv[3], s.entries, s.regular, s.candidates, s.absent, s.racy,
           (double)s.hashed_bytes / 1e6, load, walk_s, load + walk_s);
    return 0;
}
