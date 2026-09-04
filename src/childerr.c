#define _GNU_SOURCE
#include "childerr.h"

#include <stddef.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

// string representations of the child process stage errors enum
static const char *stage_names[] = {
    "unshare",
    "setgroups",
    "uid_map",
    "gid_map",
    "mount_private",
    "mount_overlay",
    "pivot_root",
    "remount",
    "exec"
};

_Static_assert(sizeof stage_names / sizeof stage_names[0] == STAGE_COUNT, "stage_names out of sync with enum child_stage");

/*
 *  Helper func for failing child gracefully;
 *  Notifies the parent about the fail mode.
*/
_Noreturn void child_fail(int errfd, enum child_stage stage, int err) {
    struct child_err e = { stage, err };
    ssize_t wrsz = write(errfd, &e, sizeof e);
    if (wrsz == -1 || (wrsz > 0 && wrsz < (ssize_t)sizeof e)) {
        fprintf(stderr, "writing error to the parent from the child failed\n");
    }
    _exit(1);
}

/*
 * Decodes child's stage enum into a corresponding string.
*/
const char *stage_name(enum child_stage stage) {
    return (stage < STAGE_COUNT) ? stage_names[stage] : "unknown";
}