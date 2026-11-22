/*
 *  The trust interpreter (test/expect/system-interpreters.md). Not built yet:
 *  it claims its files (dispatch.c), so a capture keeps them, and declines.
 */
#include "builtins.h"

const struct belay_interp INTERP_TRUST = { BELAY_INTERP_TRUST, NULL, NULL, NULL, NULL };
