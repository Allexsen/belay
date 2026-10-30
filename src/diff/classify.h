/*
 *  The only place an outcome is decided: docs/spec/diff-v1.md, "How an
 *  outcome is decided", over the tables of src/schema/diff_schema.c.
 */
#ifndef BELAY_DIFF_CLASSIFY_H
#define BELAY_DIFF_CLASSIFY_H

#include "ancestry.h"
#include "schema/diff_schema.h"

#include <stdint.h>

/* What every comparison in one diff shares: each scope root's device, and
 * whether the scope root was remounted between the manifests (its dev
 * differs), in which case no inode is compared. */
struct diff_ctx {
    uint64_t root_dev_before, root_dev_after;
    bool remounted;
};

struct verdict {
    enum diff_outcome outcome;
    uint32_t changed;           /* FBIT: compared fields that differ */
    uint32_t reasons;           /* DRBIT: why unknown (outcome unknown only) */
};

/* A path present on both sides. 0, or -1 with BELAY_ERR_INTERNAL when the
 * schema's tables or the verdict are incomplete (a bug, never a pass). */
int classify_both(const struct diff_ctx *ctx, const struct belay_entry *before,
                  const struct belay_entry *after, struct verdict *v);

/* A path present on one side only; `absent` is what the other side's
 * nearest recorded ancestor says. 0, or -1 as above. */
int classify_one(const struct belay_entry *present, bool is_after, enum anc absent,
                 struct verdict *v);

#endif
