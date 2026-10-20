#pragma once
#include <unistd.h>

#define MOUNTS_MAX      256
#define MOUNT_PATH_MAX  256

struct mount_table{
    char paths[MOUNTS_MAX][MOUNT_PATH_MAX];
    size_t n;
};

int mounts_load(struct mount_table *mt);
int mounts_has_nested(const struct mount_table *mt, const char *dir);