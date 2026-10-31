/*
 *  A side's stored copy, for an interpreter: read whole within the
 *  interpreter's bound, or the reason it cannot be (finding kind
 *  content_unavailable). Shared by every interpreter that reads content, so
 *  each says "unavailable" the same way and none declines silently.
 */
#ifndef BELAY_INTERP_STORED_H
#define BELAY_INTERP_STORED_H

#include "belay/interp.h"

enum stored_why {
    SW_OK,
    SW_NO_STORE,        /* the diff was given no store */
    SW_MISSING,         /* the manifest records no copy, or the store lacks it */
    SW_TOO_LARGE,       /* over the interpreter's bound */
    SW_CORRUPT,         /* does not hash to its name, or is not a regular file */
    SW_ERROR,           /* cannot be read (I/O, memory): could_not_interpret */
    SW_COUNT
};

enum side { SIDE_BEFORE, SIDE_AFTER };

/* The entry of `side`, NULL where the path is absent. */
const struct belay_entry *side_entry(const struct belay_interp_input *in, enum side s);

/* The copy of `side`'s entry (which must exist), at most `max` bytes, into
 * *buf (malloc'd, NUL after the end; the caller frees it). SW_OK, or why
 * not, with belay_err cleared. */
enum stored_why stored_read(const struct belay_interp_input *in, enum side s, size_t max,
                            unsigned char **buf, size_t *len);

/* The finding-kinds.md word for a reason ("no_store", ...) and a side
 * ("before", "after"). */
const char *stored_why_name(enum stored_why w);
const char *side_name(enum side s);

/* Adds content_unavailable {reason, side} to `out`. 0, or -1 (memory). */
int stored_unavailable(struct belay_findings *out, enum stored_why w, enum side s);

#endif
