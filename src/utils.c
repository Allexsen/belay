#define _GNU_SOURCE
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* fsync(2) of directory `dir`, where it can be opened: a name made in it
 * survives a power loss only then. Never a failure (as the diff's output
 * sync): the directory made in it exists either way. */
static void sync_dir(const char *dir, void *ctx) {
    (void)ctx;
    const int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd == -1) return;
    if (fsync(fd) != 0) { /* nothing to undo: see above */ }
    close(fd);
}

/* Makes `path` and syncs its parent, when this call made it. 0, or -1 with
 * errno when it cannot be made and is not there already. */
static int make_one(const char *path, mode_t mode, void (*sync)(const char *, void *),
                    void *ctx) {
    if (mkdir(path, mode) == -1) return errno == EEXIST ? 0 : -1;
    char parent[PATH_MAX];
    const char *slash = strrchr(path, '/');
    if (slash == NULL) snprintf(parent, sizeof parent, ".");
    else if (slash == path) snprintf(parent, sizeof parent, "/");
    else snprintf(parent, sizeof parent, "%.*s", (int)(slash - path), path);
    sync(parent, ctx);
    return 0;
}

/* 
 *  mkdir_p(const char*, mode_t) takes a fs path,
 *  traverses it, and creates the directories along the way.
 *  Each directory it creates has its parent synced, so a power loss on a
 *  first run cannot take a directory that later syncs assume exists
 *  (decided 2026-10-30).
*/
int mkdir_p(const char *path, mode_t mode) {
    return mkdir_p_with(path, mode, sync_dir, NULL);
}

int mkdir_p_with(const char *path, mode_t mode, void (*sync)(const char *dir, void *ctx),
                 void *ctx) {
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
            if (make_one(path_c, 0755, sync, ctx) == -1) {
                return -1;
            }

            path_c[i] = '/';
        }
    }

    // The target directory
    if (make_one(path_c, mode, sync, ctx) == -1) {
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