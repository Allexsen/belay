#define _GNU_SOURCE
#include "fork.h"
#include "childerr.h"
#include "rootfs.h"
#include "session.h"

#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <pwd.h>
#include <string.h>
#include <time.h>
#include <stdnoreturn.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/syscall.h>


/*
 *  Child process branch after the fork;
 *  unshares, writes deny setgroups, maps uid & gid, mounts the overlay and execls.
 * 
*/
_Noreturn void child_main(const char *curr_sesh_dir, int errfd, uid_t uid, gid_t gid) {
    int errval = unshare(CLONE_NEWUSER | CLONE_NEWNS);
    if (errval == -1) {
        child_fail(errfd, STAGE_UNSHARE, errno);
    }

    int fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd == -1) {
        if (errno == ENOENT) {
            fprintf(stderr, "warn: setgroups not supported, continuing\n");
        } else {
            child_fail(errfd, STAGE_SETGROUPS, errno);
        }
    } else {
        int wrsz = write(fd, "deny", 4);
        if (wrsz != 4) {
            if (wrsz == -1) {
                child_fail(errfd, STAGE_SETGROUPS, errno);
            } else {
                child_fail(errfd, STAGE_SETGROUPS, 0);
            }
        }
        close(fd);
    }

    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd == -1) {
        child_fail(errfd, STAGE_UID_MAP, errno);
    }
    char buf[64];
    int bufsz = snprintf(buf, sizeof buf, "%u %u 1\n", uid, uid);
    if (bufsz >= (int)sizeof buf) {
        child_fail(errfd, STAGE_UID_MAP, 0);
    }
    int wrsz = write(fd, buf, bufsz);
    if (wrsz != bufsz) {
        if (wrsz == -1) {
            child_fail(errfd, STAGE_UID_MAP, errno);
        } else {
            child_fail(errfd, STAGE_UID_MAP, 0);
        }
    }
    close(fd);

    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd == -1) {
        child_fail(errfd, STAGE_GID_MAP, errno);
    }
    bufsz = snprintf(buf, sizeof buf, "%u %u 1\n", gid, gid);
    if (bufsz >= (int)sizeof buf) {
        child_fail(errfd, STAGE_GID_MAP, 0);
    }
    wrsz = write(fd, buf, bufsz);
    if (wrsz != bufsz) {
        if (wrsz == -1) {
            child_fail(errfd, STAGE_GID_MAP, errno);
        } else {
            child_fail(errfd, STAGE_GID_MAP, 0);
        }
    }
    close(fd);

    if (mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        child_fail(errfd, STAGE_MOUNT_PRIVATE, errno);
    }

    if (construct_temproot(curr_sesh_dir) == -1) {
        child_fail(errfd, STAGE_MOUNT_OVERLAY, errno);
    }

    char temproot_path[PATH_MAX];
    if (sesh_layout_path(temproot_path, sizeof temproot_path, curr_sesh_dir, SESH_TEMPROOT) == -1) {
        child_fail(errfd, STAGE_PIVOT, errno);
    }

    if (switch_root(temproot_path) == -1) {
        child_fail(errfd, STAGE_PIVOT, errno);
    }

    /*  
     *  TODO(fork): move to $SHELL instead of hardcoding bash before public release.
     *  argv[0] must NOT be a leading '-': it's a login shell, which re-reads profile scripts;
     *  belay wants non-login. Fallback chain == getpwuid(getuid)) -> pw_shell, then hardcoding /bin/sh.
     * 
    */
    execl("/bin/bash", "bash", (char *)NULL);
    child_fail(errfd, STAGE_EXEC, errno);
}

/*
 *  Parent process branch after the fork;
 *  Awaits read buffer from child, decodes and prints error if present.
 *  Also awaits waitpid(), checks status and reports back accordingly.
 *
*/
int parent_main(int errfd, pid_t pid) {
    struct child_err e;
    ssize_t readsz = read(errfd, &e, sizeof e);

    int setup_failed = 0;
    if (readsz != 0) {
        setup_failed = 1;
        if (readsz == (ssize_t)sizeof e) {
            const char *stg_name = stage_name(e.stage);
            fprintf(stderr, "child process failed: %s\n", stg_name);
            if (e.err != 0) {
                fprintf(stderr, "errno: %s\n", strerror(e.err));
            }
        } else {
            if (readsz == -1) {
                perror("error reading child");
            } else {
                fprintf(stderr, "partial read of error from the child process\n");
            }
        }
    }
    close(errfd);

    int status;
    pid_t rpid = waitpid(pid, &status, 0);
    if (rpid == -1) {
        perror("waitpid");
        return 1;
    }

    if (setup_failed)
        return 126;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);

    return 1;
}

/*
 *  Captures global uid/gid and establishes a pipe,
 *  then forks the process and splits the flow into the corresponding branches.
*/
int forkp(const char *curr_sesh_dir) {
    // Save the OS-level user and group ids;
    // Captured before unshare to record the original uid/gid instead of the in-ns ones.
    const uid_t uid = getuid();
    const gid_t gid = getgid();

    // Piping for setup comms between the parent and the child process after forking;
    // Either child reports an error, or empty + EOF on success.
    int fd[2];
    if (pipe2(fd, O_CLOEXEC) == -1) {
        perror("pipe2");
        return -1;
    }

    // fork() before the unshare is deliberate;
    // It's supposed to keep the parent as a supervisor, so something can monitor the child setup,
    // and later allow major belay capabilities.
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return -1;
    }

    // pid 0 == this is a child process.
    // any actual pid == the parent process.
    if (pid == 0) {
        close(fd[0]);
        child_main(curr_sesh_dir, fd[1], uid, gid);
    } else {
        close(fd[1]); // MUST BE CLOSED, otherwise waits indefinitely for EOF - a deadlock scenario.
        return parent_main(fd[0], pid);
    }

    return 0;
}
