/*
 *  Comparing two manifests of the same scope (docs/spec/diff-v1.md).
 *
 *  belay_diff merges the two sorted manifests one path at a time, in bounded
 *  memory however many entries they hold, and writes a diff.v1 stream: a
 *  header, one record per path whose outcome is not "unchanged", and a
 *  trailer of counts. Every path gets one outcome; a path that cannot be
 *  shown unchanged is never reported unchanged.
 */
#ifndef BELAY_DIFF_H
#define BELAY_DIFF_H

#include <stdbool.h>
#include <stddef.h>

/* What one diff decided, path by path. */
struct belay_diff_stats {
    size_t records;             /* lines emitted between header and trailer */
    size_t unchanged, added, removed, modified, type_changed, metadata_only, unknown;
    bool provisional;           /* either tree changed while it was walked (trailer) */
};

/*
 *  Compares the manifests at `before` and `after` and writes diff.v1 to
 *  `out_path` (through a temporary name, renamed into place on success).
 *  Manifests of different scopes are refused before any entry is read.
 *  0, or -1 with belay_err set and no output file; `stats` may be NULL.
 */
int belay_diff(const char *before, const char *after, const char *out_path,
               struct belay_diff_stats *stats);

#endif
