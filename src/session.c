#define _GNU_SOURCE
#include "session.h"
#include "utils.h"

#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

/*
 *  Constructs belay's sessions dir under $XDG_STATE_HOME if present, otherwise under $HOME env var;
 *  Then consturcts the current session dir based on timestamp + randomized suffix,
 *  and hands back the current session dir path.
*/
int construct_sesh_dir(char *out, size_t outsz) {
    // Get XDG_STATE_HOME env var; If not present, default to HOME;
    const char *state_dir = getenv("XDG_STATE_HOME");
    char fallback_buf[PATH_MAX];
    if (!state_dir || state_dir[0] != '/') {
        printf("$XDG_STATE_HOME env var not set, defaulting to $HOME\n");

        char *homedir = getenv("HOME");
        if (!homedir || homedir[0] == '\0') {
            fprintf(stderr, "$HOME env var not set or is empty\n");
            return -1;
        }

        if (homedir[0] != '/') {
            fprintf(stderr, "$HOME env var path is not absolute\n");
            return -1;
        }

        int wrsz = snprintf(fallback_buf, sizeof fallback_buf, "%s/.local/state", homedir);
        if (wrsz >= (int)sizeof fallback_buf) {
            fprintf(stderr, "fallback buffer write truncated\n");
            return -1;
        }

        state_dir = fallback_buf;
    }

    // Construct the belay's sessions dir.
    char sessions_dir[PATH_MAX];
    int wrsz = snprintf(sessions_dir, sizeof sessions_dir, "%s/belay/sessions", state_dir);
    if (wrsz >= (int)sizeof sessions_dir) {
        fprintf(stderr, "sessions dir over the path max limit\n");
        return -1;
    }
    
    if (mkdir_p(sessions_dir, 0755) == -1) {
        perror("sessions dir");
        return -1;
    }
    
    // Generate the current session dir name, timestamp + random suffix;
    // Ensures human-readable sorting and collision-free naming.
    char ts[32];
    time_t now = time(NULL);
    size_t ts_len = strftime(ts, sizeof ts, "%Y%m%d-%H%M%S", localtime(&now));
    if (ts_len == 0) {
        fprintf(stderr, "timestamp couldn't be formatted, strftime failed\n");
        return -1;
    }
    wrsz = snprintf(out, outsz, "%s/%s-XXXXXX", sessions_dir, ts);
    if (wrsz >= (int)outsz) {
        fprintf(stderr, "current session dir size over the path max limit\n");
        return -1;
    }
    // mkdtemp() is intentional, meant to create dir with 0700 permissions.
    // This ensures belay's root remains private on the system, preventing unwanted access.
    if (mkdtemp(out) == NULL) {
        perror("mkdtemp");
        return -1;
    }

    return 0;
}

/*
 *  Creates the mount layout;
 *  upper/ - new content;
 *  temproot/ - temporary root to host all fs present in the real root;
 *  work/ - clean dir required by kernel for mounting operations.
*/
int create_sesh_layout(const char *curr_sesh_dir) {
    const char *dirs[] = {"upper", "work", "temproot"};
    for (size_t i=0; i < sizeof dirs / sizeof dirs[0]; i++) {
        char path_abs[PATH_MAX];
        int wrsz = snprintf(path_abs, sizeof path_abs, "%s/%s", curr_sesh_dir, dirs[i]);
        if (wrsz >= (int)sizeof path_abs) {
            fprintf(stderr, "dir %s over the path max limit\n", dirs[i]);
            return -1;
        }
        
        // Hardcoded 0755 mode
        if (mkdir(path_abs, 0755) == -1 && errno != EEXIST) {
            perror(path_abs);
            return -1;
        }
    }

    return 0;
}