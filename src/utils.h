#pragma once
#include <sys/types.h>
#include <stddef.h>

int mkdir_p(const char *path, mode_t mode);
/* mkdir_p with the directory sync given: sync(parent, ctx) runs right after
 * each directory the call makes. mkdir_p passes an fsync; tests a recorder. */
int mkdir_p_with(const char *path, mode_t mode, void (*sync)(const char *dir, void *ctx),
                 void *ctx);
int contains(const char *list[], size_t len, const char *entry);