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
 * temporary file of the scope's state directory (tmp/ there: capture-scale
 * SC-M3), held locked until it is released -- a file found there unlocked
 * is a killed run's, and the next rebuild removes it. `held`: the lock's
 * descriptor plus one; 0, as an initializer leaves it, is none. */
struct manifest_file { char path[PATH_MAX + 200]; bool temporary; int held; long skip; };

/* Checkpoint `id`'s manifest as a path to read, rebuilt and checked byte for
 * byte first when it is a delta (ST-4). 0, or -1 with belay_err (CORRUPT: a
 * link, a missing base, a rebuild that doesn't hash). manifest_release always
 * after a 0. */
int  manifest_acquire(const struct state *st, long id, struct manifest_file *m);
void manifest_release(struct manifest_file *m);

/* As manifest_acquire, for a reader that wants the manifest's header line
 * alone, as `log` does for each checkpoint: a delta holds that line as it is,
 * so nothing is rebuilt and nothing written -- the path is then the delta's
 * own and `skip` where in it the header line starts
 * (belay_manifest_open_header_at). */
int  manifest_acquire_header(const struct state *st, long id, struct manifest_file *m);

/* Whether checkpoint `id` is stored as a delta alone: no whole file. */
bool manifest_is_delta(const struct state *st, long id);

/* After checkpoint `id` is written, with `prev` the one before it, 0 if none:
 * writes id's delta against prev, checked, and only then removes prev's whole
 * file if prev has a delta of its own (ST-2, ST-5). A failure leaves whole
 * files, which are always right, and is not a failed capture. */
void manifest_store_delta(const struct state *st, long prev, long id);

/* The sha256 of checkpoint `id`'s manifest as its delta records it (the
 * newest checkpoint has both a whole file and a delta): true with `hex`, or
 * false when it has no delta or that cannot be read. */
bool manifest_recorded_sha256(const struct state *st, long id, char hex[65]);

/* A manifest's identity (ST-3): the sha256 of its bytes, or for one stored as
 * a delta of version 2 the sha256 of its base's identity and its operations'
 * digest, each as 64 hex digits. `bytes`: whether it is the former. Read from
 * the delta's first line when the checkpoint has one, else by hashing the
 * whole file. 0, or -1 with belay_err. */
int  manifest_identity(const struct state *st, long id, char hex[65], bool *bytes);
/* True with the identity when it is not a digest of bytes (a version 2
 * delta's, or a whole file one was made into): diff-fields ID-1. */
bool manifest_event_identity(const struct state *st, long id, char hex[65]);
void manifest_identity_of(const char base[65], const char ops[65], char out[65]);
/* Makes a delta a whole file again, checked, before its base goes (PR-4). */
int  manifest_make_whole(const struct state *st, long id);

/* The base a delta names into *base; 0 when it is a whole file. -1 with
 * belay_err when it can't be read. *size and *stored: the manifest's size and
 * the delta's own. */
int  manifest_delta_base(const struct state *st, long id, long *base, uint64_t *size, uint64_t *stored);

#endif
