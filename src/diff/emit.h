/*
 *  Writes the diff.v1 stream (docs/spec/diff-v1.md) with the names of
 *  src/schema/diff_schema.c. Counts every outcome it is given, emitted or
 *  not, and writes the trailer from those counts: no count is kept by hand
 *  anywhere else.
 */
#ifndef BELAY_DIFF_EMIT_H
#define BELAY_DIFF_EMIT_H

#include "classify.h"

#include "belay/interp.h"
#include "belay/manifest.h"

#include <stdio.h>

struct emitter {
    FILE *f;
    char *line;                 /* EMIT_LINE_CAP */
    size_t count[D_OUTCOME_COUNT];
    size_t dir_timestamps;      /* of count[D_UNCHANGED] */
    size_t records;
    bool provisional;           /* set by emit_trailer */
};

int  emit_open(struct emitter *em, FILE *f);
void emit_close(struct emitter *em);

int emit_header(struct emitter *em, const struct belay_manifest_header *before,
                const struct belay_manifest_header *after, bool scope_remounted);

/* One path's verdict: counted, and written unless unchanged. `findings` may
 * be NULL. */
int emit_path(struct emitter *em, const struct belay_entry *before,
              const struct belay_entry *after, const struct verdict *v,
              const struct belay_findings *findings);

/* What the two manifests said, read to their ends: their trailers and their
 * digests. */
struct diff_inputs {
    const struct belay_manifest_stats *before, *after;
    const char *before_sha256, *after_sha256;
};

/* The trailer: the counts, then the inputs. Sets em->provisional. */
int emit_trailer(struct emitter *em, const struct diff_inputs *in);

#endif
