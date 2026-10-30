/*
 *  Internal invariants that fail closed (audit 2026-10, R1).
 *
 *  BELAY_CHECK(cond, fail) returns `fail` from the enclosing function, with
 *  BELAY_ERR_INTERNAL set, when `cond` does not hold. It is compiled into every
 *  build: assert(3) disappears under -DNDEBUG, and a check that disappears
 *  leaves the fall-back value -- "not compared", "unchanged" -- as the answer.
 */
#ifndef BELAY_UTIL_CHECK_H
#define BELAY_UTIL_CHECK_H

#include "belay/error.h"

#define BELAY_CHECK(cond, fail)                                                    \
    do {                                                                           \
        if (!(cond)) {                                                             \
            belay_err_set(BELAY_ERR_INTERNAL, 0, "internal error: %s (%s:%d)", #cond, \
                          __FILE__, __LINE__);                                     \
            return fail;                                                           \
        }                                                                          \
    } while (0)

#endif
