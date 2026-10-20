/*
 *  belay entry point.
 *
 *  Placeholder until the CLI dispatch layer lands (M1 phase 5). Today it runs
 *  the session engine's fork directly.
 *
 *  The session engine is Linux-only by nature -- userns, mountns, overlayfs,
 *  pivot_root -- so it is compiled in only on Linux (BELAY_DESIGN.md §9.1).
 *  On other platforms belay builds the portable core and this binary reports
 *  that the session commands are unavailable, rather than failing to link.
 *  Fail loud, never silent (§5.5).
 */
#ifdef __linux__
#define _GNU_SOURCE
#include "session/session.h"
#include "session/fork.h"

#include <limits.h>

int main(void) {
    char curr_sesh_dir[PATH_MAX];
    if (construct_sesh_dir(curr_sesh_dir, sizeof curr_sesh_dir) == -1) {
        return 1;
    }

    if (create_sesh_layout(curr_sesh_dir) == -1) {
        return 1;
    }

    return forkp(curr_sesh_dir);
}

#else /* !__linux__ */

#include <stdio.h>

int main(void) {
    fprintf(stderr,
            "belay: the session engine (fork/commit/discard) is Linux-only.\n"
            "The portable engine (check/diff/mark) is not wired to the CLI yet.\n");
    return 1;
}

#endif /* __linux__ */
