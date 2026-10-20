/*
 *  Manifest writing and reading. See docs/spec/manifest-v1.md.
 *
 *  BLAST RADIUS: the writer walks the user's real filesystem. Containment is
 *  by construction per BELAY_DESIGN.md §5.1.1 -- realpath() once on each
 *  scope, then openat/fstatat relative to a held dirfd, with
 *  AT_SYMLINK_NOFOLLOW and O_NOFOLLOW. Paths are never re-resolved from
 *  strings during a walk, so a swapped directory or a symlink cannot redirect
 *  it. M1 reads only; nothing here writes into a scope.
 */
#ifndef BELAY_MANIFEST_H
#define BELAY_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BELAY_MANIFEST_VERSION 1

/* Defaults; overridable per run. */
#define BELAY_HASH_MAX_BYTES_DEFAULT   (64u * 1024u * 1024u)  /* hash up to 64MB */
#define BELAY_STORE_MAX_BYTES_DEFAULT  (64u * 1024u)          /* copy up to 64KB */

enum belay_entry_type {
    BELAY_T_REG,
    BELAY_T_DIR,
    BELAY_T_LNK,
    BELAY_T_FIFO,
    BELAY_T_SOCK,
    BELAY_T_BLK,
    BELAY_T_CHR
};

/*
 *  One manifest entry.
 *
 *  `path` holds raw bytes with `path_len` as the authority -- not NUL
 *  termination -- because a path is a byte string. The writer encodes it as
 *  JSON `path` when valid UTF-8 and `path_b64` otherwise.
 */
struct belay_entry {
    char     path[4096];
    size_t   path_len;

    enum belay_entry_type type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    int64_t  mtime_ns;
    int64_t  ctime_ns;
    uint64_t ino;
    uint64_t dev;
    uint64_t nlink;

    bool     has_hash;                  /* sha256 computed */
    char     sha256_hex[65];
    bool     unverified;                /* too large to hash (> hash_max_bytes) */

    bool     has_link_target;
    char     link_target[4096];
    size_t   link_target_len;
    bool     target_outside_scope;      /* advisory only, §5.1.1 */

    bool     has_stored;                /* content copied into store/ */
    char     stored_hex[65];

    bool     is_mount;                  /* dev differs from scope root; not descended */

    /*
     *  Set when belay could not enumerate or read this entry: an unreadable
     *  directory (EACCES on opendir) or an unreadable file. The subtree below
     *  an unreadable directory is ABSENT from the manifest, so `diff` must
     *  report it as "contents unknown" and never as "unchanged".
     *
     *  Without this flag an unreadable directory is byte-identical to an empty
     *  one, which would make diff claim nothing changed about files it never
     *  saw -- the false-negative class §5.3 rules worst.
     */
    bool     unreadable;
};

struct belay_manifest_opts {
    uint64_t hash_max_bytes;
    uint64_t store_max_bytes;
    const char *store_dir;              /* NULL disables content storage */
};

/*
 *  Walks `scope` and writes a manifest to `out_path`.
 *
 *  Entries are emitted sorted by raw path bytes. Returns 0 on success, -1 with
 *  belay_err_* set. On failure `out_path` may exist partially written; callers
 *  treat a failed check as having produced no manifest.
 *
 *  `*n_entries` receives the count written.
 */
int belay_manifest_write(const char *out_path, const char *scope,
                         const struct belay_manifest_opts *opts,
                         size_t *n_entries);

/*
 *  Streaming reader. `fn` is called once per entry, in file order; a non-zero
 *  return from `fn` stops the walk and is returned by this function.
 *
 *  Rejects: an unknown format version, a malformed line, a truncated final
 *  line, and -- per §5.1.1 -- any decoded path containing a NUL byte, which
 *  is BELAY_ERR_CORRUPT rather than a silent truncation.
 */
typedef int (*belay_entry_fn)(const struct belay_entry *e, void *ctx);

int belay_manifest_read(const char *path, belay_entry_fn fn, void *ctx);

#endif /* BELAY_MANIFEST_H */
