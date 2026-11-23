/*
 *  The previous manifest's index, for mark's prefilter (decisions Q2, Q8;
 *  test/expect/capture-scale.md SC-M1 to SC-M4): every entry of a manifest,
 *  of every type and under every name, as two files that are mapped, never
 *  read into the heap.
 *
 *    <sha256>.recs    a header; the entries as fixed records sorted by
 *                     (dev, ino, sequence), `sequence` being the entry's
 *                     place in the manifest; then, for each sequence in
 *                     turn, the number of its record
 *    <sha256>.paths   a header; then for each entry, in the manifest's
 *                     order, its path, a NUL, and the fields of it that
 *                     have no fixed size (a link's target, capabilities,
 *                     extended attributes)
 *
 *  An inode is found by bisection over the records, a path by bisection
 *  over the sequence numbers, and a record with its path's tail is the
 *  whole entry: no manifest need be read to have an old entry. The files
 *  are named by the sha256 of the manifest they stand for, say it in their
 *  headers, and are used for no other manifest; they can always be made
 *  again from it. They are built with the capture's own external sort
 *  (runs.h), so building one needs no more memory than a walk does.
 *
 *  The trust rule is what it was: a regular file whose (dev, ino, mode,
 *  size, mtime_ns, ctime_ns) equal its entry's, with ctime_ns before the
 *  reference point R, is not read again -- any write after that capture
 *  gives the file a ctime at or past R. Keyed by inode, not path: a key that
 *  matches names the same inode, so no collision can lend a file another's
 *  hash. An inode with two names is trusted by neither.
 */
#ifndef BELAY_CAPTURE_PREVIOUS_H
#define BELAY_CAPTURE_PREVIOUS_H

#include "belay/manifest.h"
#include "runs.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

/* A record's flags: the entry's own, and one of the index's. */
enum {
    PF_HAS_IFLAGS = 1u << 0, PF_HAS_CAPS = 1u << 1, PF_HAS_XATTRS = 1u << 2, PF_XATTRS_INLINE = 1u << 3,
    PF_XATTRS_UNKNOWN = 1u << 4, PF_HAS_HASH = 1u << 5, PF_UNVERIFIED = 1u << 6, PF_HAS_LINK = 1u << 7,
    PF_TARGET_OUTSIDE = 1u << 8, PF_HAS_STORED = 1u << 9, PF_MOUNT = 1u << 10, PF_HAS_RDEV = 1u << 11,
    PF_UNSTABLE = 1u << 12, PF_UNREADABLE = 1u << 13, PF_RACED = 1u << 14, PF_WRITER_OPEN = 1u << 15,
    PF_NOT_READ = 1u << 16, PF_PARTIAL = 1u << 17, PF_META = 1u << 18, PF_SEALED = 1u << 19,
    /* Never to be trusted, whatever it matches: the manifest names it racy
     * (manifest-v5 V5-E7, V5-A2). */
    PF_DISTRUST = 1u << 31,
};

/* One entry, as it lies in the file: 144 bytes, no padding. */
struct prev_rec {
    uint64_t dev, ino, seq;     /* what the records are sorted by */
    uint64_t path_off;          /* of its path in the paths file */
    uint64_t size;
    int64_t  mtime_ns, ctime_ns;
    uint64_t nlink, iflags, rdev;
    uint32_t path_len;
    uint32_t tail_len;          /* after the path's NUL: the target, the capabilities, the attributes */
    uint32_t mode, uid, gid;
    uint32_t flags;             /* PF_* */
    uint32_t link_len;          /* the tail's first part: a link's target */
    uint16_t caps_len;          /* its second: capabilities, hex */
    uint16_t type;              /* enum belay_entry_type */
    uint8_t  sha256[32];
};

_Static_assert(sizeof(struct prev_rec) == 144, "an index record is 144 bytes, without padding");

struct prev_index;

struct prev_info {
    int64_t newest_validated_ns;    /* the newest ctime_ns of an entry validation passed */
    int64_t reference_ns;           /* R: the previous walk's start, else newest_validated_ns */
    int64_t walk_start_ns;          /* the previous header's walk_start_ns; 0: unknown (v1, or not read) */
    uint64_t hash_max_bytes, store_max_bytes;
    size_t files;                   /* regular files with a hash, neither raced nor unstable */
    char sealed_key[BELAY_SEALED_KEY_HEX + 1];   /* the previous header's; "" when it has none */
    bool built;                     /* the index was made by this call, not found in opts->index_dir */
};

/*
 *  The index of the manifest `path`, written for a scope whose root is on
 *  `root_dev`. With opts->index_dir it is the one kept there when that names
 *  this manifest's sha256 (opts->previous_sha256, or the file's own, read
 *  for it), and is otherwise built there, in place of whatever was; without,
 *  it is built in temporaries from `tmp`, gone when it is freed. 0; 1 when
 *  the prefilter cannot be used (another scope, other limits, unreadable or
 *  corrupt, or the previous walk's start unknown on coarse timestamps: *why
 *  says which); -1 with belay_err (memory, or the index cannot be written).
 */
struct fsops;
int prev_load(const struct fsops *ops, const char *path, const char *scope, uint64_t root_dev,
              const struct belay_manifest_opts *opts, runs_tmpfile_fn tmp, void *tmp_ctx,
              struct prev_index **out, struct prev_info *info, const char **why);
void prev_free(struct prev_index *p);

/* The entry of this inode a file may be trusted by, or NULL: a regular file
 * with a hash that was neither raced, unstable nor held by a writer, is not
 * named racy, and is the inode's only name in the manifest. */
const struct prev_rec *prev_find(const struct prev_index *p, uint64_t dev, uint64_t ino);

/* The entry at `path`, of any type, or NULL. */
const struct prev_rec *prev_find_path(const struct prev_index *p, const char *path, size_t len);

/* The records, in (dev, ino, sequence) order. */
size_t prev_count(const struct prev_index *p);
const struct prev_rec *prev_at(const struct prev_index *p, size_t i);
/* r's path (not NUL-terminated within its length; a NUL follows it). */
const char *prev_path(const struct prev_index *p, const struct prev_rec *r);

/* r's sha256 as 64 lowercase hex digits. */
void prev_hex(const struct prev_rec *r, char out[65]);

/* Is a file with stat `st` unchanged since `r` was recorded, by the rule? */
bool prev_trusted(const struct prev_rec *r, const struct stat *st, int64_t reference_ns);

/*
 *  Building one: the entries in the manifest's order, then finish. With a
 *  directory the two files are left there under `sha256`, durable, and
 *  every other file of the directory is removed (an index of another
 *  manifest, what a killed run left: captures of one scope run one at a
 *  time, under its lock). ixb_free always.
 */
struct ixb;
struct ixb *ixb_new(const char *dir, runs_tmpfile_fn tmp, void *tmp_ctx, size_t run_bytes);
int  ixb_add(struct ixb *b, const struct belay_entry *e);
/* The paths the manifest names racy, by number: 0 past the last (as
 * belay_manifest_racy). `sha256`: the manifest's, 64 hex digits. With `out`
 * the index is also opened. 0, or -1 with belay_err. */
typedef size_t (*ixb_racy_fn)(void *ctx, size_t i, const char **path);
int  ixb_finish(struct ixb *b, const char *sha256, ixb_racy_fn racy, void *racy_ctx, struct prev_index **out);
void ixb_free(struct ixb *b);

/* The sha256 of a file's bytes, read through: 0 with `hex`, or -1. */
int prev_file_sha256(const char *path, char hex[65]);

#endif
