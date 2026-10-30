/*
 *  belay_diff with the interpreters given rather than the built-ins: what
 *  tests use to run an interpreter that fails, or writes what it must not.
 */
#ifndef BELAY_DIFF_RUN_H
#define BELAY_DIFF_RUN_H

#include "belay/diff.h"
#include "belay/interp.h"

int diff_run(const char *before, const char *after, const char *out_path,
             struct belay_diff_stats *stats,
             const struct belay_interp *const interp[BELAY_INTERP_COUNT]);

#endif
