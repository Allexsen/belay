/*
 *  The built-in interpreters, one file each (finding-kinds.md says what each
 *  reports). explain.c lists them by id.
 */
#ifndef BELAY_INTERP_BUILTINS_H
#define BELAY_INTERP_BUILTINS_H

#include "belay/interp.h"

extern const struct belay_interp INTERP_TEXT, INTERP_PIP, INTERP_DPKG, INTERP_GIT;

#endif
