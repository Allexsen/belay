/*
 *  Rules over the sequence of entries, not any one line: strictly increasing
 *  path order, nothing below a sealed directory, the scope root, and the
 *  trailer's counts against what was read. The reader calls stream_entry for
 *  every entry that passed its own checks, and stream_end with the trailer.
 */
#ifndef BELAY_CAPTURE_MANIFEST_STREAM_H
#define BELAY_CAPTURE_MANIFEST_STREAM_H

#include "belay/manifest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 *  Directories recorded but not descended (unreadable, or a mount point):
 *  nothing may appear below them.
 *
 *  Entries are strictly sorted, so a sealed directory D can still have an
 *  entry below it only while the reader sits between D and D + "/" -- and
 *  every path in that range starts with D. ("D!x" sorts there too, which is
 *  why D cannot be dropped at its first non-descendant.) So the sealed
 *  directories still open are all prefixes of the previous path, a stack of
 *  their lengths is enough, and lengths strictly increase up the stack: at
 *  most one per byte of a path, however many directories the manifest seals.
 *  (The first version kept every sealed path: memory grew with the manifest,
 *  and scanning the list made 40k sealed directories take 1.9 s.)
 */
#define SEALED_MAX 4096     /* > the longest path, so the stack cannot fill */

struct stream {
    size_t n_entries, n_unreadable, n_unstable, n_mounts, n_raced;
    bool   have_root;
    bool   root_unreadable;

    char   prev[4096];
    size_t prev_len;
    bool   have_prev;

    size_t sealed[SEALED_MAX];  /* lengths of sealed prefixes of prev */
    size_t n_sealed;
};

/* One entry, in file order. 0, or -1 with the error set. */
int stream_entry(struct stream *s, const struct belay_entry *e);

/* The trailer's six values, in TRAILER order (entries, vanished, unreadable,
 * unstable, mounts, raced), against what was read. 0, or -1. */
int stream_end(const struct stream *s, const uint64_t v[6]);

#endif
