/* LD_PRELOAD write logger (measurement only): every pwrite/pwrite64/write and
 * ftruncate on a file whose path ends in $WLOG_SUFFIX is appended to $WLOG
 * with CLOCK_REALTIME before and after the call and the bytes written. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
struct rec { uint64_t t0, t1; int64_t off, len; int32_t kind, pad; };  /* kind 1 write, 2 truncate */
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int logfd = -2;
static signed char watched[4096];   /* 0 unknown, 1 yes, -1 no */
static uint64_t now(void) { struct timespec t; clock_gettime(CLOCK_REALTIME, &t); return (uint64_t)t.tv_sec * 1000000000u + t.tv_nsec; }
static int is_db(int fd) {
    if (fd < 0 || fd >= 4096) return 0;
    char l[64], p[4096]; snprintf(l, sizeof l, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(l, p, sizeof p - 1); if (n <= 0) return 0; p[n] = 0;
    const char *suf = getenv("WLOG_SUFFIX"); size_t sl = suf ? strlen(suf) : 0;
    return suf && (size_t)n >= sl && strcmp(p + n - sl, suf) == 0;
}
static void emit(struct rec *r, const void *buf) {
    if (logfd == -2) { const char *f = getenv("WLOG"); logfd = f ? open(f, O_WRONLY | O_CREAT | O_APPEND, 0644) : -1; }
    if (logfd < 0) return;
    ssize_t (*w)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    w(logfd, r, sizeof *r);
    if (r->kind == 1 && r->len > 0) w(logfd, buf, (size_t)r->len);
}
ssize_t pwrite64(int fd, const void *buf, size_t n, off_t off) {
    static ssize_t (*real)(int, const void *, size_t, off_t); if (!real) real = dlsym(RTLD_NEXT, "pwrite64");
    if (!is_db(fd)) return real(fd, buf, n, off);
    pthread_mutex_lock(&mu);
    struct rec r = { now(), 0, off, 0, 1, 0 };
    ssize_t k = real(fd, buf, n, off); r.t1 = now(); r.len = k > 0 ? k : 0;
    emit(&r, buf); pthread_mutex_unlock(&mu); return k;
}
ssize_t pwrite(int fd, const void *buf, size_t n, off_t off) { return pwrite64(fd, buf, n, off); }
int ftruncate64(int fd, off_t len) {
    static int (*real)(int, off_t); if (!real) real = dlsym(RTLD_NEXT, "ftruncate64");
    if (!is_db(fd)) return real(fd, len);
    pthread_mutex_lock(&mu);
    struct rec r = { now(), 0, len, 0, 2, 0 }; int k = real(fd, len); r.t1 = now();
    if (k == 0) emit(&r, NULL); pthread_mutex_unlock(&mu); return k;
}
int ftruncate(int fd, off_t len) { return ftruncate64(fd, len); }
