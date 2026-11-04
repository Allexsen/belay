/*
 *  SPIKE -- evidence, not feature code (2026-10-26). Does a read that overlaps ONE
 *  in-flight write pass belay's before/after fstat stability check? Usage:
 *  spike_torn <file-on-target-fs> [reads] [pwrite|mmap]. Prints how many reads were torn
 *  and passed. pwrite (the default): one in-place rewrite after another. mmap: a shared
 *  mapping, its descriptor closed, stored through for ever; that writer's reads also say
 *  what a read lease answers, as belay's writer probe asks it (Linux).
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
enum { SZ = 4 << 20 };
static atomic_int stop; static atomic_int started; static const char *path; static int use_mmap;
static void *wr(void *a) { (void)a; char *b = malloc(SZ); int k = 0;
    if (use_mmap) { int md = open(path, O_RDWR); char *m = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, md, 0); close(md);
        if (m == MAP_FAILED) { perror("mmap"); exit(1); }
        while (!atomic_load(&stop)) { memset(m, (k++ & 1) ? 'B' : 'A', SZ); atomic_store(&started, 1); }
        munmap(m, SZ); free(b); return NULL; }
    int fd = open(path, O_WRONLY); atomic_store(&started, 1);
    while (!atomic_load(&stop)) { memset(b, (k++ & 1) ? 'B' : 'A', SZ); if (pwrite(fd, b, SZ, 0) != SZ) break; }
    close(fd); free(b); return NULL; }
static int same(struct stat *x, struct stat *y) { return x->st_size == y->st_size && x->st_mtim.tv_sec == y->st_mtim.tv_sec && x->st_mtim.tv_nsec == y->st_mtim.tv_nsec && x->st_ctim.tv_sec == y->st_ctim.tv_sec && x->st_ctim.tv_nsec == y->st_ctim.tv_nsec; }
int main(int argc, char **argv) {
    path = argv[1]; int n = argc > 2 ? atoi(argv[2]) : 2000; use_mmap = argc > 3 && !strcmp(argv[3], "mmap");
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644); char *b = malloc(SZ); memset(b, 'A', SZ); if (pwrite(fd, b, SZ, 0) != SZ) return 1; close(fd);
    pthread_t t; pthread_create(&t, NULL, wr, NULL); while (!atomic_load(&started)) usleep(100);
    long passed_stable = 0, torn_and_passed = 0, torn_total = 0, refused = 0;
    for (int i = 0; i < n; i++) {
        int rfd = open(path, O_RDONLY); struct stat s1, s2; fstat(rfd, &s1);
#ifdef F_SETLEASE
        if (fcntl(rfd, F_SETLEASE, F_RDLCK) == 0) fcntl(rfd, F_SETLEASE, F_UNLCK); else refused++;
#endif
        ssize_t got = 0, r; while (got < SZ && (r = read(rfd, b + got, SZ - got)) > 0) got += r;
        fstat(rfd, &s2); close(rfd);
        int mixed = memchr(b, 'A', SZ) && memchr(b, 'B', SZ);
        if (mixed) torn_total++;
        if (same(&s1, &s2)) { passed_stable++; if (mixed) torn_and_passed++; }
    }
    atomic_store(&stop, 1); pthread_join(t, NULL);
    printf("%s, %d reads: %ld passed the stat check, %ld torn, %ld TORN AND PASSED; the lease refused %ld\n",
           use_mmap ? "mmap" : "pwrite", n, passed_stable, torn_total, torn_and_passed, refused);
    return 0;
}
