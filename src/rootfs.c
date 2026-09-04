#define _GNU_SOURCE
#include "rootfs.h"
#include "childerr.h"

#include <sys/syscall.h>
#include <errno.h>
#include <sys/mount.h>
#include <unistd.h>

/*
 *  minimalistic static wrapper for pivot_root syscall;
 *  
*/
static int pivot_root(const char *new_root, const char *put_old) {
    return (int)syscall(SYS_pivot_root, new_root, put_old);
}

void switch_root(int errfd, const char *path) {
    if (chdir(path) == -1) {
        child_fail(errfd, STAGE_PIVOT, errno);
    }

    if (pivot_root(".", ".") == -1) {
        child_fail(errfd, STAGE_PIVOT, errno);
    }

    if (umount2(".", MNT_DETACH) == -1) {
        child_fail(errfd, STAGE_PIVOT, errno);
    }

    if (chdir("/") == -1) {
        child_fail(errfd, STAGE_PIVOT, errno);
    }
}