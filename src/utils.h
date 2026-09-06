#pragma once
#include <sys/types.h>
#include <stddef.h>

int mkdir_p(const char *path, mode_t mode);
int contains(const char *list[], size_t len, const char *entry);