#define _GNU_SOURCE
#include "utils.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>

/* 
 *  mkdir_p(const char*, mode_t) takes a fs path,
 *  traverses it, and creates the directories along the way.
*/
int mkdir_p(const char *path, mode_t mode) {
    if (strlen(path) == 0) {
        errno = ENOENT;
        return -1;
    }

    // Copy the string for inplace modification;
    // Don't alter the original, passed string.
    char path_c[PATH_MAX];
    if (strlen(path) >= sizeof path_c) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(path_c, path);

    // Eliminate the trailing slashes, replace with nullterm.
    size_t idx = strlen(path_c) - 1;
    while (idx > 0 && path_c[idx] == '/') {
        path_c[idx--] = '\0';
    }

    // Traverse down the path tree, create a dir at each slash;
    // Mark the path end with nullterm at each slash so the mkdir() doesn't try full-string path creation.
    for (size_t i=1; path_c[i] != '\0'; i++) {
        if (path_c[i] == '/') {
            path_c[i] = '\0';
            // Only the target dir gets the "mode" mode,
            // the rest on the path to it get a permissive 0755.
            if (mkdir(path_c, 0755) == -1 && errno != EEXIST) {
                return -1;
            }

            path_c[i] = '/';
        }
    }

    // The target directory
    if (mkdir(path_c, mode) == -1 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

/*
 *  Check if the list contains the given entry.
 *
*/
int contains(const char *list[], size_t len, const char *entry) {
    for (size_t i = 0; i < len; i++) {
        if (strcmp(entry, list[i]) == 0)
            return 1;
    }

    return 0;
}