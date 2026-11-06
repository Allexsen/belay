/*
 *  Checkpoints stored as deltas (test/expect/state-retention.md, ST-1..ST-6).
 *  A delta holds what turns its base's manifest into this one, byte for byte,
 *  line by line: manifests of one scope differ in a few lines. Its format is
 *  the state directory's own, and nothing outside belay reads it:
 *
 *    {"belay_delta":1,"base":N,"base_sha256":"..","sha256":"..","size":S,"chain":K}
 *    =COUNT    copy COUNT lines of the base
 *    -COUNT    skip COUNT lines of the base
 *    +LINE     this line, as it is
 *
 *  `chain` is how many deltas lie between this checkpoint and a full copy.
 */
#ifndef BELAY_CLI_DELTA_H
#define BELAY_CLI_DELTA_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include "state.h"

/* At most this many deltas between a checkpoint and a full copy (ST-2). */
#define DELTA_CHAIN_MAX 255

/* A manifest to read: a checkpoint's own file, or a checked rebuild in a
 * private temporary file. */
struct manifest_file { char path[PATH_MAX + 200]; bool temporary; };

/* Checkpoint `id`'s manifest as a path to read, rebuilt and checked byte for
 * byte first when it is a delta (ST-4). 0, or -1 with belay_err (CORRUPT: a
 * link, a missing base, a rebuild that doesn't hash). manifest_release always
 * after a 0. */
int  manifest_acquire(const struct state *st, long id, struct manifest_file *m);
void manifest_release(struct manifest_file *m);

/* As manifest_acquire, for a reader that wants the manifest's header line
 * alone, as `log` does for each checkpoint: a delta holds that line as it is,
 * so nothing is rebuilt. The file holds no more than the header. */
int  manifest_acquire_header(const struct state *st, long id, struct manifest_file *m);

/* Whether checkpoint `id` is stored as a delta alone: no whole file. */
bool manifest_is_delta(const struct state *st, long id);

/* After checkpoint `id` is written, with `prev` the one before it, 0 if none:
 * writes id's delta against prev, checked, and only then removes prev's whole
 * file if prev has a delta of its own (ST-2, ST-5). A failure leaves whole
 * files, which are always right, and is not a failed capture. */
void manifest_store_delta(const struct state *st, long prev, long id);

/* Makes a delta a whole file again, checked, before its base goes (PR-4). */
int  manifest_make_whole(const struct state *st, long id);

/* The base a delta names into *base; 0 when it is a whole file. -1 with
 * belay_err when it can't be read. *size and *stored: the manifest's size and
 * the delta's own. */
int  manifest_delta_base(const struct state *st, long id, long *base, uint64_t *size, uint64_t *stored);

#endif
