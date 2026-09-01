#define _GNU_SOURCE
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
 * error struct for child to notify the parent what failed.
 *
*/
struct child_err {
    enum child_stage stage; // which step failed
    int err; // captured errno
};

/*
 *  minimalistic static wrapper for pivot_root syscall;
 *  
*/
static int pivot_root(const char *new_root, const char *put_old) {
    return (int)syscall(SYS_pivot_root, new_root, put_old);
}

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
            if (mkdir(path_c, 0755) == -1 && errno != EEXIST) {
                return -1;
            }

            path_c[i] = '/';
        }
    }

    // Create the final, target directory
    if (mkdir(path_c, mode) == -1 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

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

    /*
     *  BLOCKED 2026-09-01: this single-overlay design cannot reach v0.1.
     *  `lowerdir=/` is refused by overlayfs -- bare EINVAL here, and
     *  "overlayfs: failed to clone lowerpath" in dmesg. Verified NOT caused by
     *  upper's location (tmpfs upper on its own mount fails the same) nor by uid
     *  mapping (identity map and map-root both fail). binpash/try hit this too
     *  and says so at try:145.
     *
     *  Replacement is one overlay per top-level directory of /, each with its own
     *  upper/<name> and work/<name>, mounted onto temproot/<name>; pivot_root then
     *  targets temproot. Enumerate / at runtime (opendir/readdir), never a
     *  hardcoded list. Symlinked top-level entries (/bin, /lib) get recreated as
     *  symlinks, not overlaid. /proc /dev /sys are skipped here -- STAGE_REMOUNT_PROC.
     *  Design + eliminated alternatives: NOTES/BELAY_REFERENCE.md, "Per-directory overlays".
     *
     *  Until that lands, lowerdir stays a single directory so the fork still runs
     *  end to end and pivot_root remains exercisable.
     */
    char opts[PATH_MAX + 64];
    char merged_path[PATH_MAX];

    wrsz = snprintf(merged_path, sizeof merged_path, "%s/merged", curr_sesh_dir);
    if (wrsz >= (int)sizeof merged_path) {
        child_fail(errfd, STAGE_MOUNT_OVERLAY, 0);
    }

    wrsz = snprintf(opts, sizeof opts, "userxattr,lowerdir=%s/lower,upperdir=%s/upper,workdir=%s/work", curr_sesh_dir, curr_sesh_dir, curr_sesh_dir);
    if (wrsz >= (int)sizeof opts) {
        child_fail(errfd, STAGE_MOUNT_OVERLAY, 0);
    }

    if (mount("overlay", merged_path, "overlay", 0, opts) == -1) {
        child_fail(errfd, STAGE_MOUNT_OVERLAY, errno);
    }

    if (chdir(merged_path) == -1) {
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
            const char *stage_name = (e.stage < STAGE_COUNT) ? stage_names[e.stage] : "unknown";
            fprintf(stderr, "child process failed: %s\n", stage_name);
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


int main(void) {
    // Get XDG_STATE_HOME env var; If not present, default to HOME;
    // Construct belay's session dirs there.
    const char *state_dir = getenv("XDG_STATE_HOME");
    char fallback_buf[PATH_MAX];
    if (!state_dir || state_dir[0] != '/') {
        printf("$XDG_STATE_HOME env var not set, defaulting to $HOME\n");

        char *homedir = getenv("HOME");
        if (!homedir || homedir[0] == '\0') {
            fprintf(stderr, "$HOME env var not set or is empty\n");
            return 1;
        }

        if (homedir[0] != '/') {
            fprintf(stderr, "$HOME env var path is not absolute\n");
            return 1;
        }

        int n = snprintf(fallback_buf, sizeof fallback_buf, "%s/.local/state", homedir);
        if (n >= (int)sizeof fallback_buf) {
            fprintf(stderr, "fallback buffer write truncated\n");
            return 1;
        }

        state_dir = fallback_buf;
    }

    char sessions_dir[PATH_MAX];
    int n = snprintf(sessions_dir, sizeof sessions_dir, "%s/belay/sessions", state_dir);
    if (n >= (int)sizeof sessions_dir) {
        fprintf(stderr, "sessions dir over the path max limit\n");
        return 1;
    }
    
    if (mkdir_p(sessions_dir, 0755) == -1) {
        perror("sessions dir");
        return 1;
    }
    
    // Generate the current session dir name, timestamp + random suffix;
    // Ensures human-readable sorting and collision-free naming.
    char ts[32];
    time_t now = time(NULL);
    n = strftime(ts, sizeof ts, "%Y%m%d-%H%M%S", localtime(&now));
    if (n == 0) {
        fprintf(stderr, "timestamp couldn't be formatted, strftime failed\n");
        return 1;
    }
    char curr_sesh_dir[PATH_MAX];
    n = snprintf(curr_sesh_dir, sizeof curr_sesh_dir, "%s/%s-XXXXXX", sessions_dir, ts);
    if (n >= (int)sizeof curr_sesh_dir) {
        fprintf(stderr, "current session dir size over the path max limit\n");
        return 1;
    }
    if (mkdtemp(curr_sesh_dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }

    // Construct the session's internal dirs
    const char *dirs[] = {"lower", "upper", "merged", "work"};
    for (size_t i=0; i < sizeof dirs / sizeof dirs[0]; i++) {
        char path_abs[PATH_MAX];
        n = snprintf(path_abs, sizeof path_abs, "%s/%s", curr_sesh_dir, dirs[i]);
        if (n >= (int)sizeof path_abs) {
            fprintf(stderr, "dir %s over the path max limit\n", dirs[i]);
            return 1;
        }

        if (mkdir(path_abs, 0755) == -1 && errno != EEXIST) {
            perror("mkdir");
            return 1;
        }
    }

    // Save the OS-level user and group ids;
    // Captured before unshare to record the original uid/gid instead of the in-ns ones.
    const uid_t uid = getuid();
    const gid_t gid = getgid();

    // Piping for setup comms between the parent and the child process after forking;
    // Either child reports an error, or empty + EOF on success.
    int fd[2];
    if (pipe2(fd, O_CLOEXEC) == -1) {
        perror("pipe2");
        return 1;
    }

    // fork() before the unshare is deliberate;
    // It's supposed to keep the parent as a supervisor, so something can monitor the child setup,
    // and later allow major belay capabilities.
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        close(fd[0]);
        child_main(curr_sesh_dir, fd[1], uid, gid);
    } else {
        close(fd[1]); // MUST BE CLOSED, otherwise waits indefinitely for EOF - a deadlock scenario.
        return parent_main(fd[0], pid);
    }

    return 0;
}
