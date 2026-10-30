/*
 *  The portable POSIX half of the platform adapter, shared by every OS.
 *  The OS-specific half (fsops_<os>.c) builds the table.
 */
#define _GNU_SOURCE
#include "fsops_posix.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int posix_fstatat(void *ctx, int dfd, const char *name, struct stat *st, int flags) {
    (void)ctx;
    return fstatat(dfd, name, st, flags);
}

int posix_fstat(void *ctx, int fd, struct stat *st) {
    (void)ctx;
    return fstat(fd, st);
}

int posix_openat(void *ctx, int dfd, const char *name, int flags) {
    (void)ctx;
    return openat(dfd, name, flags, 0);
}

ssize_t posix_readlinkat(void *ctx, int dfd, const char *name, char *buf, size_t n) {
    (void)ctx;
    return readlinkat(dfd, name, buf, n);
}

ssize_t posix_read(void *ctx, int fd, void *buf, size_t n) {
    (void)ctx;
    return read(fd, buf, n);
}

int posix_fsync(void *ctx, int fd) {
    (void)ctx;
    return fsync(fd);
}

/* closedir closes the fd it was given; dup so the caller's stays valid. */
void *posix_dir_open(void *ctx, int dfd) {
    (void)ctx;
    const int d = dup(dfd);
    if (d == -1) return NULL;
    DIR *dir = fdopendir(d);
    if (dir == NULL) {
        const int err = errno;
        close(d);
        errno = err;
    }
    return dir;
}

const char *posix_dir_next(void *ctx, void *dir) {
    (void)ctx;
    errno = 0;
    const struct dirent *de = readdir(dir);
    return de != NULL ? de->d_name : NULL;
}

void posix_dir_close(void *ctx, void *dir) {
    (void)ctx;
    closedir(dir);
}

FILE *posix_tmpfile_named(const char *tmpl) {
    char name[4200];
    if ((size_t)snprintf(name, sizeof name, "%s", tmpl) >= sizeof name) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    const int fd = mkstemp(name);
    if (fd == -1) return NULL;
    unlink(name);
    FILE *f = fdopen(fd, "w+b");
    if (f == NULL) {
        const int err = errno;
        close(fd);
        errno = err;
    }
    return f;
}
