#define _GNU_SOURCE
#include "rootfs.h"
#include "utils.h"
#include "session.h"

#include <sys/syscall.h>
#include <errno.h>
#include <sys/mount.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>

/*
 *  minimalistic static wrapper for pivot_root syscall;
 *  
*/
static int pivot_root(const char *new_root, const char *put_old) {
    return (int)syscall(SYS_pivot_root, new_root, put_old);
}

/*
 * Recreate the system root's entry dirs in the current session temproot.
 * 
*/
int make_entry_dirs(const char *sesh_dir, const char *entrydir) {
    const char *layout_dirs[] = {SESH_UPPER, SESH_WORK, SESH_TEMPROOT};
    char buf[PATH_MAX];
    for (size_t i = 0; i < sizeof layout_dirs / sizeof layout_dirs[0]; i++) {
        if (sesh_entry_path(buf, sizeof buf, sesh_dir, layout_dirs[i], entrydir) == -1) {
            return -1;
        }
        if (mkdir(buf, 0755) == -1 && errno != EEXIST) {
            return -1;
        }
    }

    return 0;
}

/*
 *  Mount temproot dirs on the actual root dirs.
 *
*/
int mount_entry_overlay(const char *sesh_dir, const char *entrydir) {
    char temprootdir[PATH_MAX];
    if (sesh_entry_path(temprootdir, sizeof temprootdir, sesh_dir, SESH_TEMPROOT, entrydir) == -1) {
        return -1;
    }
    
    char upperdir[PATH_MAX];
    if (sesh_entry_path(upperdir, sizeof upperdir, sesh_dir, SESH_UPPER, entrydir) == -1) {
        return -1;
    }

    char workdir[PATH_MAX];
    if (sesh_entry_path(workdir, sizeof workdir, sesh_dir, SESH_WORK, entrydir) == -1) {
        return -1;
    }

    char opts[2 * PATH_MAX + 64];
    int wrsz = snprintf(opts, sizeof opts,
        "userxattr,lowerdir=/%s,upperdir=%s,workdir=%s",
        entrydir, upperdir, workdir
    );

    if (wrsz < 0) {
        return -1;
    }

    if (wrsz >= (int)sizeof opts) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (mount("overlay", temprootdir, "overlay", 0, opts) == -1) {
        return -1;
    }

    return 0;
}

/*
 *  Clone symlinks from the system root to the current session's temproot.
 *
*/
int clone_symlink(const char *sesh_dir, const char *symlnk) {
    char symlnk_path[PATH_MAX];
    int wrsz = snprintf(symlnk_path, sizeof symlnk_path, "/%s", symlnk);
    if (wrsz < 0) {
        return -1;
    }

    if (wrsz >= (int)sizeof symlnk_path) {
        errno = ENAMETOOLONG;
        return -1;
    }

    char buf[PATH_MAX];
    ssize_t rdsz = readlink(symlnk_path, buf, sizeof buf);
    if (rdsz == -1) {
        return -1;
    }
    
    if (rdsz >= (ssize_t)sizeof buf) {
        errno = ENAMETOOLONG;
        return -1;
    }
    
    buf[rdsz] = '\0';


    char targetdir[PATH_MAX];
    if (sesh_entry_path(targetdir, sizeof targetdir, sesh_dir, SESH_TEMPROOT, symlnk) == -1) {
        return -1;
    }

    if (symlink(buf, targetdir) == -1) {
        return -1;
    }

    return 0;
}

/*
 *  Remap the root to point at the ns root,
 *  then change the workdir to the new root.
 * 
*/
int switch_root(const char *path) {
    if (chdir(path) == -1) {
        return -1;
    }

    if (pivot_root(".", ".") == -1) {
        return -1;
    }

    if (umount2(".", MNT_DETACH) == -1) {
        return -1;
    }

    if (chdir("/") == -1) {
        return -1;
    }

    return 0;
}

/*
 * Walk the system root and recreate its dir structure in the given dir;
 * Precisely, mkdir() the directory entries, and readlink() + symlink() the symlinks.
 * 
*/
int construct_temproot(const char *path) {
    DIR *dir = opendir("/");
    if (dir == NULL) {
        return -1;
    }

    const char *must_exclude[] = {".", "..", "proc", "dev", "sys"};
    struct dirent *entry;
    errno = 0; // cleared so the dirend and error are differentiable as both report entry == NULL otherwise.
    while ((entry = readdir(dir)) != NULL) {
        struct stat st;
        if (fstatat(dirfd(dir), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == -1) {
            fprintf(stderr, "fstatat failed on %s\n", entry->d_name);
            return -1;
        }

        if (S_ISDIR(st.st_mode)) {
            if (contains(must_exclude, sizeof must_exclude / sizeof must_exclude[0], entry->d_name)) {
                continue;
            }

            if (make_entry_dirs(path, entry->d_name) == -1) {
                fprintf(stderr, "entry dir creation failed on %s\n", entry->d_name);
                return -1;
            }
            if (mount_entry_overlay(path, entry->d_name) == -1) {
                fprintf(stderr, "mount overlay failed on %s\n", entry->d_name);
                return -1;
            }
        } else {
            if (S_ISLNK(st.st_mode)) {
                if (clone_symlink(path, entry->d_name) == -1) {
                    fprintf(stderr, "symlink cloning failed on %s\n", entry->d_name);
                    return -1;
                }
            }
        }
    }

    if (errno != 0) {
        return -1;
    }

    return 0;
}