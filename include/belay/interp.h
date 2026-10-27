/*
 *  Interpreter dispatch (M1 step 4.1).
 *
 *  Decides, from a path alone, which interpreter owns a regular file and what
 *  the capture side must keep for it. Pure: no filesystem access, so not on
 *  the blast-radius list.
 *
 *  Why capture needs this before any interpreter exists: an interpreter can
 *  only explain a change if the BEFORE content was kept. dpkg's status file,
 *  pip's RECORD and git's refs must therefore be stored at check time
 *  regardless of the size threshold, or the later diff has nothing to compare
 *  against (decision 2026-10-20). Some claimed files are only hashed: git's
 *  index can be hundreds of MB, and M1's git scope needs only to know it
 *  changed.
 *
 *  Matching is on the ABSOLUTE path (scope root + relative path), so
 *  "/var/lib/dpkg/status" is recognised whether the scope is "/", "/var" or a
 *  container root. Patterns are fnmatch(3) without FNM_PATHNAME, so "*" spans
 *  "/". Matching is bytewise: belay never calls setlocale.
 */
#ifndef BELAY_INTERP_H
#define BELAY_INTERP_H

#include <stddef.h>

enum belay_interp_id {
    BELAY_INTERP_BINARY = 0,    /* fallback: size + hash; claims nothing */
    BELAY_INTERP_TEXT,          /* unified diff for stored small text files */
    BELAY_INTERP_PIP,
    BELAY_INTERP_DPKG,
    BELAY_INTERP_GIT,
    BELAY_INTERP_COUNT
};

enum belay_keep {
    BELAY_KEEP_DEFAULT = 0,     /* store only if under the size threshold and text */
    BELAY_KEEP_HASH,            /* claimed, hash only, never stored */
    BELAY_KEEP_STORE            /* claimed, always stored whatever its size */
};

struct belay_claim {
    enum belay_interp_id interp;
    enum belay_keep keep;
};

/* Classifies `abs_path` (`len` bytes, need not be NUL-terminated). Never
 * fails: an unclaimed path gets {BINARY, KEEP_DEFAULT}. */
void belay_interp_classify(const char *abs_path, size_t len, struct belay_claim *out);

const char *belay_interp_name(enum belay_interp_id id);

#endif /* BELAY_INTERP_H */
