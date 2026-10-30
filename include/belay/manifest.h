/*
 *  Manifest writing and reading. See docs/spec/manifest-v1.md.
 *
 *  BLAST RADIUS: the writer walks the user's real filesystem. Containment is
 *  by construction per BELAY_DESIGN.md §5.1.1 -- realpath() once on each
 *  scope, then openat/fstatat relative to a held dirfd, with
 *  AT_SYMLINK_NOFOLLOW and O_NOFOLLOW. Paths are never re-resolved from
 *  strings during a walk, so a swapped directory or a symlink cannot redirect
 *  it. The writer writes only the manifest (a temporary beside it, renamed
 *  into place), its unlinked temporary runs, and objects in the store. If
 *  those lie inside the scope, the next check records them as changes:
 *  excluding belay's own state directory is phase 5 work.
 */
#ifndef BELAY_MANIFEST_H
#define BELAY_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BELAY_MANIFEST_VERSION 1

/* Defaults; overridable per run. */
#define BELAY_XATTRS_INLINE_MAX 8192u   /* larger sets: digest only */
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

    /*
     *  Extended metadata (decided 2026-10-26: `setcap` on a binary and
     *  `chattr +i` on a grader file are tampering routes, and both used to
     *  change nothing but ctime). Absent on mount points, which are never
     *  read.
     *
     *  iflags: inode flags -- FS_IOC_GETFLAGS on Linux (regular files and
     *  directories), st_flags on macOS (every type). Absent where the
     *  filesystem has none.
     *  caps: the raw security.capability value, lowercase hex.
     *  xattrs: every other extended attribute (POSIX ACLs included, as
     *  system.posix_acl_*): xattrs_sha256_hex is the digest of the canonical
     *  set, and when xattrs_inline the set itself is in xattrs[] -- the body
     *  of the manifest's "xattrs" array, one "name=<sha256 of value>" per
     *  attribute, sorted by name. Large sets are recorded by digest only.
     *  xattrs_unknown: the attributes could not be read; none of the above is
     *  recorded, and "none" must not be assumed.
     */
    bool     has_iflags;
    uint64_t iflags;
    bool     has_caps;
    char     caps_hex[129];
    bool     has_xattrs;
    char     xattrs_sha256_hex[65];
    bool     xattrs_inline;
    char     xattrs[8193];
    size_t   xattrs_len;
    bool     xattrs_unknown;

    bool     has_hash;                  /* sha256 computed */
    char     sha256_hex[65];
    bool     unverified;                /* no hash: too large (> hash_max_bytes),
                                           unstable, unreadable, or a mount */

    bool     has_link_target;
    char     link_target[4096];
    size_t   link_target_len;
    bool     target_outside_scope;      /* advisory only, §5.1.1 */

    bool     has_stored;                /* content copied into store/ */
    char     stored_hex[65];

    bool     is_mount;                  /* a mount root (statx; for directories also a
                                           dev differing from the scope root's);
                                           recorded, never read or descended */

    /* Device number, for blk and chr entries only. Without it a device node
     * replaced by another with the same mode and owner differs only in
     * ino/ctime, and an overlayfs whiteout (char 0,0) is indistinguishable
     * from a real device. */
    bool     has_rdev;
    uint64_t rdev;

    /*
     *  Regular file: it changed while being hashed (size, mtime or ctime
     *  moved, or the inode opened was not the one stat'ed). No hash is
     *  recorded -- the bytes read describe no state the file was ever in --
     *  so it is also unverified.
     *
     *  Directory: its listing is not one complete, single-instant listing. It
     *  changed during the walk (including after it was listed: the
     *  end-of-walk re-check), or listing it failed part way. Entries may be
     *  missing below it or recorded under another directory.
     */
    bool     unstable;

    /*
     *  Set when belay could not enumerate or read this entry: an unreadable
     *  directory (EACCES on opendir) or an unreadable file, or a symlink
     *  whose target could not be read reliably: its link_target is empty
     *  ("unknown") when none could be read, otherwise the last one read,
     *  which may be stale. The subtree below
     *  an unreadable directory is ABSENT from the manifest, so `diff` must
     *  report it as "contents unknown" and never as "unchanged".
     *
     *  Without this flag an unreadable directory is byte-identical to an empty
     *  one, which would make diff claim nothing changed about files it never
     *  saw -- the false-negative class §5.3 rules worst.
     */
    bool     unreadable;

    /*
     *  The entry changed after it was recorded, before the walk ended: the
     *  end-of-walk re-check found its inode, type, mode, size, mtime or ctime
     *  different, or it was gone. What is recorded held at the moment belay
     *  read it, but not at the end, so the manifest as a whole is not one
     *  instant. (A directory whose listing changed is flagged unstable
     *  instead; this appears on directories only when they are unreadable or
     *  mount points.)
     */
    bool     raced;
};

struct belay_manifest_opts {
    uint64_t hash_max_bytes;
    uint64_t store_max_bytes;
    /*
     *  NULL disables content storage. On Linux a copy is kept only if no
     *  process has the file open for writing at the start and end of its
     *  read (a lease probe; nothing is held). A writer opening the file
     *  during the probe makes the kernel send SIGIO to belay's process, so
     *  while the write runs, SIGIO at its default action is ignored; it is
     *  put back when the write returns. A handler the host installed is
     *  never touched.
     */
    const char *store_dir;

    /*
     *  Memory budget for the writer's sort buffer. 0 selects the default
     *  (4 MiB). Values below the minimum (one maximal entry, ~70 KB) are
     *  raised to it. Peak writer memory is roughly this plus ~1 MiB of merge
     *  cursors, independent of how many entries the scope holds.
     */
    size_t   run_bytes;
};

/* What one write observed. Also recorded in the manifest's trailer line. */
struct belay_manifest_stats {
    size_t entries;     /* entries written, including the scope root "." */
    size_t vanished;    /* disappeared between readdir and stat/open: the walk
                           saw a tree that was changing under it */
    size_t unreadable;  /* entries flagged unreadable */
    size_t unstable;    /* entries flagged unstable: files that changed while
                           hashed, directories whose listing changed */
    size_t mounts;      /* mount points: recorded, contents not captured */
    size_t raced;     /* entries that changed after being recorded, before
                           the walk ended (the end-of-walk re-check) */
    size_t store_failed;  /* capture only, 0 from a trailer: copies the content
                             store failed to keep; those entries are recorded
                             without `stored` */
};

/*
 *  Walks `scope` and writes a manifest to `out_path`.
 *
 *  Entries are emitted sorted by raw path bytes. Returns 0 on success, -1 with
 *  belay_err_* set. The output is written to a temporary name, synced, and
 *  renamed into place, so on failure nothing is left at `out_path`; then its
 *  directory is synced where it can be opened (a sync that fails is not an
 *  error: the manifest is already in place).
 *
 *  `*stats`, if non-NULL, receives what the walk observed.
 */
int belay_manifest_write(const char *out_path, const char *scope,
                         const struct belay_manifest_opts *opts,
                         struct belay_manifest_stats *stats);

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

/*
 *  Pull interface. A diff advances two manifests side by side; with callbacks
 *  alone one of them would have to be held in memory.
 *
 *    belay_manifest_open   reads and validates the header. 0 / -1.
 *    belay_manifest_next   1 = an entry was stored in *e, 0 = clean end of
 *                          manifest, -1 = error. Errors are sticky.
 *    belay_manifest_close  always safe, including on NULL.
 *
 *  The same validation applies as for belay_manifest_read.
 */
struct belay_manifest_reader;

/* The manifest's header line. Available as soon as open succeeds. */
struct belay_manifest_header {
    uint64_t version;
    int64_t  created_ns;
    char     scope[4096];       /* the resolved scope root, NUL-terminated */
    uint64_t hash_max_bytes;
    uint64_t store_max_bytes;
};

/*
 *  A comparator MUST check that two manifests describe the same scope before
 *  pairing their entries: relative paths from different roots line up by
 *  name and would otherwise compare as "unchanged".
 */
const struct belay_manifest_header *
belay_manifest_header(const struct belay_manifest_reader *r);

/* The trailer's counts. Valid only after belay_manifest_next has returned 0;
 * NULL before that. */
const struct belay_manifest_stats *
belay_manifest_trailer(const struct belay_manifest_reader *r);

/* The sha256 of the bytes read, header to trailer -- the manifest's identity,
 * which a consumer can record (the diff's trailer does). 0 with `hex` set
 * once belay_manifest_next has returned 0; -1 before. */
int belay_manifest_digest(const struct belay_manifest_reader *r, char hex[65]);

/* Back to the first entry, through the same open file: the header is read
 * again and must be the one read at open, and the digest restarts. A
 * consumer that reads a manifest twice (the diff finds the scope root first)
 * reads one file, never a path opened twice. 0, or -1. */
int belay_manifest_rewind(struct belay_manifest_reader *r);

int  belay_manifest_open(const char *path, struct belay_manifest_reader **out);
int  belay_manifest_next(struct belay_manifest_reader *r, struct belay_entry *e);
void belay_manifest_close(struct belay_manifest_reader *r);

#endif /* BELAY_MANIFEST_H */
