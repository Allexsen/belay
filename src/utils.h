#pragma once
#include <sys/types.h>
#include <stddef.h>

int mkdir_p(const char *path, mode_t mode);
/* mkdir_p with the sync given: right after each directory the call makes,
 * sync(ctx, fd, made) runs on its parent, opened read-only. mkdir_p passes
 * fsync; tests a recorder. */
int mkdir_p_with(const char *path, mode_t mode,
                 int (*sync)(void *ctx, int dirfd, const char *made), void *ctx);
int contains(const char *list[], size_t len, const char *entry);