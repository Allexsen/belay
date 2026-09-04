#pragma once
#include <stdnoreturn.h>

// error enums for child process stages
enum child_stage {
    STAGE_UNSHARE,
    STAGE_SETGROUPS,
    STAGE_UID_MAP,
    STAGE_GID_MAP,
    STAGE_MOUNT_PRIVATE,
    STAGE_MOUNT_OVERLAY,
    STAGE_PIVOT,
    STAGE_REMOUNT_PROC,
    STAGE_EXEC,
    STAGE_COUNT
};

/*
 * error struct for child to notify the parent what failed.
*/
struct child_err {
    enum child_stage stage; // which step failed
    int err; // captured errno
};

_Noreturn void child_fail(int, enum child_stage, int);
const char *stage_name(enum child_stage stage);