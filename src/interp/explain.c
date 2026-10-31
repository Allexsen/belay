/*
 *  Interpreter explanations (belay/interp.h). One built-in per interpreter;
 *  one with no explain declines. Every built-in declines until each lands in
 *  its own file: the binary fallback has nothing to add to the core's
 *  outcome.
 */
#include "belay/interp.h"

#include <string.h>

static const struct belay_interp BUILTIN[BELAY_INTERP_COUNT] = {
    [BELAY_INTERP_BINARY] = { BELAY_INTERP_BINARY, NULL, NULL, NULL },
    [BELAY_INTERP_TEXT]   = { BELAY_INTERP_TEXT, NULL, NULL, NULL },
    [BELAY_INTERP_PIP]    = { BELAY_INTERP_PIP, NULL, NULL, NULL },
    [BELAY_INTERP_DPKG]   = { BELAY_INTERP_DPKG, NULL, NULL, NULL },
    [BELAY_INTERP_GIT]    = { BELAY_INTERP_GIT, NULL, NULL, NULL },
};

const struct belay_interp *belay_interp_builtin(enum belay_interp_id id) {
    return (unsigned)id < BELAY_INTERP_COUNT ? &BUILTIN[id] : &BUILTIN[BELAY_INTERP_BINARY];
}
