/*
 *  The systemd interpreter (test/expect/system-interpreters.md). Not built yet:
 *  it claims its files (dispatch.c), so a capture keeps them, and declines.
 */
#include "builtins.h"

const struct belay_interp INTERP_SYSTEMD = { BELAY_INTERP_SYSTEMD, NULL, NULL, NULL, NULL };
