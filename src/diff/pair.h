/*
 *  The streaming merge: from two strictly ordered manifest iterators, every
 *  path exactly once, in path order, as (before, after) with one side NULL
 *  when the path is on the other side only. Holds one current entry per
 *  side, whatever the manifests' size. Knows nothing of fields or outcomes.
 */
#ifndef BELAY_DIFF_PAIR_H
#define BELAY_DIFF_PAIR_H

#include "belay/manifest.h"

struct pair_state;

/* Takes the two open readers (not owned). NULL on out of memory. */
struct pair_state *pair_new(struct belay_manifest_reader *before,
                            struct belay_manifest_reader *after);
void pair_free(struct pair_state *p);

/* 1 a pair (*before or *after may be NULL, never both), 0 both manifests
 * ended cleanly (trailers validated), -1 error. The entries stay valid until
 * the next call. */
int pair_next(struct pair_state *p, const struct belay_entry **before,
              const struct belay_entry **after);

#endif
