/*
 *  Outcomes of observing an entry, and the one place they become flags.
 *
 *  Capture code reports what it found -- "this directory's listing changed",
 *  "this file's content could not be read" -- and outcome_apply turns that
 *  into the entry's flags, through one table. Nothing else sets a capture
 *  flag. Trailer counts are tallied from the entries as they are emitted, so
 *  no code path can count an entry twice or forget to count it.
 */
#ifndef BELAY_CAPTURE_OUTCOME_H
#define BELAY_CAPTURE_OUTCOME_H

#include "belay/manifest.h"

#include <stddef.h>

/* What was observed. */
enum facet {
    FACET_CONTENT,      /* a regular file's bytes */
    FACET_LISTING,      /* a directory's listing */
    FACET_TARGET,       /* a symlink's target */
    FACET_ENTRY,        /* the entry as a whole */
    FACET_EXTRAS,       /* extended metadata: xattrs, ACLs, capabilities */
    FACET_N
};

/* What was found. */
enum outcome {
    OUT_OK,
    OUT_GONE,           /* vanished between being listed and being read */
    OUT_CHANGED,        /* changed while being read, or since it was recorded */
    OUT_DENIED,         /* could not be read: permission, I/O, limits, a swap */
    OUT_TOO_LARGE,      /* over hash_max_bytes: deliberately not hashed */
    OUT_BOUNDARY,       /* a mount root: recorded, never read */
    OUT_N
};

/* What the walk saw that no emitted entry carries; `invalid` counts outcomes
 * the effect table does not define, and fails the write. */
struct walk_tally { size_t vanished; size_t invalid; };

/* The effect of (facet, outcome): flag bits, and EFF_DEFINED on every cell
 * the capture may apply. A cell without it is a combination nothing defines:
 * applying one fails the write instead of recording nothing (audit 2026-10). */
#define EFF_DEFINED (1u << 15)
extern const unsigned OUTCOME_EFFECT[FACET_N][OUT_N];

/* Applies what was found to `e`'s flags (e may be NULL for an entry that is
 * not recorded at all, e.g. one gone before it could be stat'ed). */
void outcome_apply(struct belay_entry *e, enum facet f, enum outcome o, struct walk_tally *t);

/* Trailer counts, from entries as emitted. */
void outcome_count(struct belay_manifest_stats *s, const struct belay_entry *e);

#endif
