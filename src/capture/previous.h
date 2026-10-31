/*
 *  The previous manifest, for mark's prefilter (NOTES/phase5-structure.md §4,
 *  decisions Q2, Q8): its regular files with a hash, keyed by (dev, ino),
 *  and the reference point R. A file whose (dev, ino, mode, size, mtime_ns,
 *  ctime_ns) equal its entry's, with ctime_ns < R, is not read again: any
 *  write after that capture gives the file a ctime at or past R. Keyed by
 *  inode, not path: a key that matches names the same inode, so no
 *  collision can lend a file another's hash.
 */
#ifndef BELAY_CAPTURE_PREVIOUS_H
#define BELAY_CAPTURE_PREVIOUS_H

#include "belay/manifest.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#define PREV_BYTES_MAX (64u * 1024u * 1024u)    /* the index's memory: past it, a full walk */

struct prev_rec {
    uint64_t dev, ino, size;
    int64_t mtime_ns, ctime_ns;
    uint32_t mode;
    bool has_stored;
    uint8_t sha256[32];
};

struct prev_index;

struct prev_info {
    int64_t newest_validated_ns;    /* the newest ctime_ns of an entry validation passed */
    int64_t reference_ns;           /* R: the previous walk's start, else newest_validated_ns */
    uint64_t hash_max_bytes, store_max_bytes;
    size_t files;                   /* regular files indexed */
};

/* Loads `path`, written for a scope whose root is on `root_dev`. 0; 1 when
 * the prefilter cannot be used (another scope, other limits, unreadable or
 * corrupt, the index over PREV_BYTES_MAX: *why says which); -1 with
 * belay_err (memory). */
struct fsops;
int prev_load(const struct fsops *ops, const char *path, const char *scope, uint64_t root_dev,
              const struct belay_manifest_opts *opts, struct prev_index **out,
              struct prev_info *info, const char **why);
void prev_free(struct prev_index *p);

/* The indexed entry for this inode, or NULL. */
const struct prev_rec *prev_find(const struct prev_index *p, uint64_t dev, uint64_t ino);

/* r's sha256 as 64 lowercase hex digits. */
void prev_hex(const struct prev_rec *r, char out[65]);

/* Is a file with stat `st` unchanged since `r` was recorded, by the rule? */
bool prev_trusted(const struct prev_rec *r, const struct stat *st, int64_t reference_ns);

#endif
