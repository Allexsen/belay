/*
 *  Comparing two manifests of the same scope (docs/spec/diff-v1.md).
 *
 *  belay_diff merges the two sorted manifests one path at a time, in bounded
 *  memory however many entries they hold, and writes a diff.v1 stream: a
 *  header, one record per path whose outcome is not "unchanged", then the
 *  event records, and a trailer of counts. Every path gets one outcome; a path that cannot be
 *  shown unchanged is never reported unchanged.
 */
#ifndef BELAY_DIFF_H
#define BELAY_DIFF_H

#include <stdbool.h>
#include <stddef.h>

/* What one diff decided, path by path. */
struct belay_diff_stats {
    size_t records;             /* path records emitted */
    size_t events;              /* event records emitted, after the path records */
    size_t unchanged, added, removed, modified, type_changed, metadata_only, unknown;
    size_t dir_timestamps_only; /* of unchanged: directories whose own timestamps alone differ */
    bool provisional;           /* either tree changed while it was walked (trailer) */
    size_t runtime;             /* runtime records, after the events (runtime-v1 RT-D1) */
};

/* How a diff is run. All optional: NULL options mean the defaults. */
struct belay_diff_opts {
    const char *store_dir;      /* the content store captures kept copies in; NULL: none,
                                   and a path whose interpreter needs content gets the
                                   finding content_unavailable, reason no_store */
    /* The per-line digest files of the two captures (system-interpreters.md
     * SA-6; a checkpoint's `shadow.lines`), for the accounts interpreter's
     * password_entry_* events; NULL where a capture kept none: then no such
     * event is given. Read, never written. */
    const char *shadow_lines_before, *shadow_lines_after;
    /* The runtime records of the two captures (runtime-v1.md; a
     * checkpoint's `runtime.ndjson`), each checked against the sha256 its
     * checkpoint recorded; NULL where a capture has none. Either given:
     * the diff has a `runtime` section (RT-D1, RT-D5). Read, never written. */
    const char *runtime_before, *runtime_after;
    /* What the trailer's before_sha256 and after_sha256 carry in place of
     * the digest of the bytes read, for a manifest whose identity is not
     * one (diff-fields ID-1: an event capture's); NULL: the bytes' digest. */
    const char *before_identity, *after_identity;
    /* kernel-record K13. `touched_path`: a file of (dev, ino) pairs, two
     * uint64_t each in this machine's byte order, sorted and unique: the
     * inodes the journal has a write for between the two checkpoints. A
     * regular file read on both sides with equal size and sha256 whose
     * inode is among them gives a `touched` event. `touched_unavailable`:
     * that cannot be told for this pair, and the trailer says so. Neither:
     * the diff is not of a system watch's checkpoints, and says nothing. */
    const char *touched_path;
    bool touched_unavailable;
};

/*
 *  Compares the manifests at `before` and `after` and writes diff.v1 to
 *  `out_path` (through a temporary name, renamed into place on success, then
 *  its directory synced where the directory can be opened; on macOS fsync
 *  does not reach the disk: manifest-v1, "What survives a power loss").
 *  Manifests of different scopes are refused before any entry is read.
 *  0, or -1 with belay_err set and no output file; `stats` may be NULL.
 */
int belay_diff(const char *before, const char *after, const char *out_path,
               const struct belay_diff_opts *opts, struct belay_diff_stats *stats);

#endif
