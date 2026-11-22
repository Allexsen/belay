/*
 *  The accounts interpreter (test/expect/system-interpreters.md). Not built yet:
 *  it claims its files (dispatch.c), so a capture keeps them, and declines.
 */
#include "builtins.h"

const struct belay_interp INTERP_ACCOUNTS = { BELAY_INTERP_ACCOUNTS, NULL, NULL, NULL, NULL };
