/* Portable building blocks of the platform adapter (see capture/fsops.h). */
#ifndef BELAY_PLATFORM_FSOPS_POSIX_H
#define BELAY_PLATFORM_FSOPS_POSIX_H

#include "capture/fsops.h"

int         posix_fstatat(void *ctx, int dfd, const char *name, struct stat *st, int flags);
int         posix_fstat(void *ctx, int fd, struct stat *st);
int         posix_openat(void *ctx, int dfd, const char *name, int flags);
ssize_t     posix_readlinkat(void *ctx, int dfd, const char *name, char *buf, size_t n);
ssize_t     posix_read(void *ctx, int fd, void *buf, size_t n);
int         posix_fsync(void *ctx, int fd);
void       *posix_dir_open(void *ctx, int dfd);
const char *posix_dir_next(void *ctx, void *dir);
void        posix_dir_close(void *ctx, void *dir);
FILE       *posix_tmpfile_named(const char *tmpl);

#endif
