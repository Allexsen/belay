/*
 *  SPIKE -- measurement only, for the Phase 5 proposal (no product code).
 *
 *  `mark` with a prefilter on an aging reference point: R = the newest
 *  ctime_ns among the previous manifest's entries that its validation
 *  passed (not raced, unstable or unreadable) -- derivable from the frozen
 *  manifest format, as git derives "racily clean" from its index's own
 *  timestamp. A regular file is trusted unchanged, and not read, when its
 *  (dev, ino, type, mode, size, mtime_ns, ctime_ns) equal the previous
 *  entry's, the previous entry had a hash, and ctime_ns < R: any write
 *  after that capture moves ctime to at least the filesystem time the
 *  capture had already seen (>= R). One with ctime_ns >= R is racy:
 *  re-hashed.
 *
 *    spike check     <scope> <out>     the real belay_manifest_write (full walk)
 *    spike prefilter <scope> <prev>    stat everything, hash what the rule needs
 *    spike hashall   <scope> <prev>    the same walk, hashing every file
 *
 *  The previous manifest is loaded into a hash table (path -> stat, sha):
 *  the simplification production must replace with a compact index (path
 *  hash -> manifest offset, 16 B an entry) or a sorted merge.
 */
#define _GNU_SOURCE
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/manifest.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct rec { char *path; size_t len; uint64_t dev, ino, size; uint32_t mode; int64_t mtime, ctime;
             bool has_hash; uint8_t type; struct rec *next; };
#define NB (1u << 21)
static struct rec *tab[NB];
static int64_t R = INT64_MIN;
static size_t nprev, hashed, trusted, racy, missing, changed, files;

static uint64_t fnv(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char)s[i]; h *= 1099511628211ULL; }
    return h;
}

static int load(const struct belay_entry *e, void *ctx) {
    (void)ctx;
    struct rec *r = calloc(1, sizeof *r);
    r->path = malloc(e->path_len + 1);
    memcpy(r->path, e->path, e->path_len);
    r->path[e->path_len] = 0;
    r->len = e->path_len;
    r->dev = e->dev; r->ino = e->ino; r->size = e->size; r->mode = e->mode;
    r->mtime = e->mtime_ns; r->ctime = e->ctime_ns; r->has_hash = e->has_hash; r->type = (uint8_t)e->type;
    const uint64_t h = fnv(r->path, r->len) & (NB - 1);
    r->next = tab[h];
    tab[h] = r;
    nprev++;
    if (!e->raced && !e->unstable && !e->unreadable && e->ctime_ns > R) R = e->ctime_ns;
    return 0;
}

static struct rec *find(const char *p, size_t n) {
    for (struct rec *r = tab[fnv(p, n) & (NB - 1)]; r; r = r->next)
        if (r->len == n && memcmp(r->path, p, n) == 0) return r;
    return NULL;
}

static void hash_file(int dfd, const char *name) {
    const int fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd == -1) return;
    struct belay_sha256 c;
    belay_sha256_init(&c);
    static unsigned char buf[1 << 16];
    ssize_t r;
    while ((r = read(fd, buf, sizeof buf)) > 0) belay_sha256_update(&c, buf, (size_t)r);
    uint8_t d[32];
    belay_sha256_final(&c, d);
    close(fd);
    hashed++;
}

static int mode_all;

static void walk(int dfd, char *path, size_t pl) {
    DIR *d = fdopendir(dfd);
    if (d == NULL) { close(dfd); return; }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        const size_t nl = strlen(de->d_name);
        size_t np = pl;                      /* pl 0: the scope root, no prefix */
        if (pl) path[np++] = '/';
        memcpy(path + np, de->d_name, nl);
        np += nl;
        path[np] = 0;
        struct stat st;
        if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) == -1) continue;
        if (S_ISDIR(st.st_mode)) {
            const int sub = openat(dirfd(d), de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (sub != -1) walk(sub, path, np);
        } else if (S_ISREG(st.st_mode)) {
            files++;
            if (mode_all) { hash_file(dirfd(d), de->d_name); continue; }
            const struct rec *r = find(path, np);
            const int64_t ct = (int64_t)st.st_ctim.tv_sec * 1000000000LL + st.st_ctim.tv_nsec;
            const int64_t mt = (int64_t)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
            if (r == NULL) { missing++; hash_file(dirfd(d), de->d_name); continue; }
            const bool same = r->has_hash && r->dev == (uint64_t)st.st_dev && r->ino == (uint64_t)st.st_ino &&
                              r->size == (uint64_t)st.st_size && r->mtime == mt && r->ctime == ct &&
                              (r->mode & 07777) == (st.st_mode & 07777);
            if (!same) { changed++; hash_file(dirfd(d), de->d_name); }
            else if (ct >= R) { racy++; hash_file(dirfd(d), de->d_name); }
            else trusted++;
        }
        path[pl] = 0;
    }
    closedir(d);
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static long rss_kib(void) { struct rusage u; getrusage(RUSAGE_SELF, &u); return u.ru_maxrss; }

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    if (!strcmp(argv[1], "check") || !strcmp(argv[1], "nohash")) {
        struct belay_manifest_opts o = { .hash_max_bytes = strcmp(argv[1], "check") ? 0 : 64u << 20,
                                         .store_max_bytes = 0 };
        struct belay_manifest_stats st;
        const double t0 = now();
        if (belay_manifest_write(argv[3], argv[2], &o, &st) != 0) { fprintf(stderr, "%s\n", belay_err_msg()); return 1; }
        printf("%-9s %8.3f s  %7ld KiB  entries %zu raced %zu\n", argv[1], now() - t0, rss_kib(), st.entries, st.raced);
        return 0;
    }
    const double t0 = now();
    if (belay_manifest_read(argv[3], load, NULL) != 0) { fprintf(stderr, "%s\n", belay_err_msg()); return 1; }
    const double t1 = now();
    mode_all = !strcmp(argv[1], "hashall");
    char *path = malloc(1 << 16);
    path[0] = 0;
    const int root = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    walk(root, path, 0);
    const double t2 = now();
    size_t racy_set = 0;                 /* entries of the previous manifest at R's tick */
    for (size_t b = 0; b < NB; b++)
        for (struct rec *r = tab[b]; r; r = r->next) racy_set += r->type == BELAY_T_REG && r->ctime >= R;
    printf("%-9s %8.3f s  %7ld KiB  load %.3f s walk %.3f s  files %zu hashed %zu trusted %zu racy %zu "
           "changed %zu new %zu  (prev %zu entries, %zu at R)\n",
           argv[1], t2 - t0, rss_kib(), t1 - t0, t2 - t1, files, hashed, trusted, racy, changed, missing,
           nprev, racy_set);
    return 0;
}
