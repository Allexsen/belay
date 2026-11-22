/*
 *  Interpreter explanations (belay/interp.h): the built-in for each id, one
 *  file each (text.c, pip.c, dpkg.c, git.c); one with no explain declines.
 */
#include "builtins.h"

#include <string.h>

/* The binary fallback declines: size and hash are already in the record. */
static const struct belay_interp BINARY = { BELAY_INTERP_BINARY, NULL, NULL, NULL, NULL };

static const struct belay_interp *const BUILTIN[BELAY_INTERP_COUNT] = {
    [BELAY_INTERP_BINARY] = &BINARY,
    [BELAY_INTERP_TEXT]   = &INTERP_TEXT,
    [BELAY_INTERP_PIP]    = &INTERP_PIP,
    [BELAY_INTERP_DPKG]   = &INTERP_DPKG,
    [BELAY_INTERP_GIT]    = &INTERP_GIT,
    [BELAY_INTERP_ACCOUNTS] = &INTERP_ACCOUNTS,
    [BELAY_INTERP_SUDOERS]  = &INTERP_SUDOERS,
    [BELAY_INTERP_CRON]     = &INTERP_CRON,
    [BELAY_INTERP_SYSTEMD]  = &INTERP_SYSTEMD,
    [BELAY_INTERP_SSHKEYS]  = &INTERP_SSHKEYS,
    [BELAY_INTERP_TRUST]    = &INTERP_TRUST,
};

/* An id whose interpreter is not built declines, as binary does. */
const struct belay_interp *belay_interp_builtin(enum belay_interp_id id) {
    return (unsigned)id < BELAY_INTERP_COUNT && BUILTIN[id] != NULL ? BUILTIN[id] : BUILTIN[BELAY_INTERP_BINARY];
}
