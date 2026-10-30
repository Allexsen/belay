#include "entry.h"

#include "belay/error.h"
#include "belay/path.h"

#include <string.h>

/* ------------------------------------------------------------------------ */
/* Schema                                                                    */
/* ------------------------------------------------------------------------ */

const struct entry_type_def ENTRY_TYPES[ENTRY_TYPE_COUNT] = {
    [BELAY_T_REG]  = { "reg",  0100000u }, [BELAY_T_DIR]  = { "dir",  0040000u },
    [BELAY_T_LNK]  = { "lnk",  0120000u }, [BELAY_T_FIFO] = { "fifo", 0010000u },
    [BELAY_T_SOCK] = { "sock", 0140000u }, [BELAY_T_BLK]  = { "blk",  0060000u },
    [BELAY_T_CHR]  = { "chr",  0020000u },
};

/* Each description is the field's row in the spec's Entries table. Which
 * types carry it is derived from the rules; don't restate them here. */
const struct entry_field_def ENTRY_FIELDS[F_COUNT] = {
    [F_PATH] = { "path", "path_b64", "string", true,
        "Path relative to its scope root, `/`-separated; `.` is the root itself. Written as "
        "`path_b64`, base64 of the raw bytes, when they are not valid UTF-8." },
    [F_TYPE] = { "type", NULL, "string", true,
        "The entry's type. The spellings, and the `mode` bits that go with each, are listed "
        "under the field rules." },
    [F_MODE] = { "mode", NULL, "int", true, "`st_mode`, full value including type bits." },
    [F_UID] = { "uid", NULL, "int", true, "Owner." },
    [F_GID] = { "gid", NULL, "int", true, "Group." },
    [F_SIZE] = { "size", NULL, "int", true,
        "`st_size`. For `lnk`, the target length -- except on an `unreadable` link, whose "
        "target is unknown or stale." },
    [F_MTIME] = { "mtime_ns", NULL, "int", true,
        "Modification time, nanoseconds. Times outside the int64 range (before 1678, after "
        "2262) saturate at its bounds." },
    [F_CTIME] = { "ctime_ns", NULL, "int", true,
        "Change time, nanoseconds, saturating like `mtime_ns`. **`ctime_ns` is the change "
        "prefilter**: an unprivileged process can set mtime but not ctime (§6.3). Never the "
        "sole evidence for a protected path — hash those." },
    [F_INO] = { "ino", NULL, "int", true, "Inode number; with `dev`, the entry's identity." },
    [F_DEV] = { "dev", NULL, "int", true,
        "Device. On a directory, `dev` differing from the scope root's means a mount boundary; "
        "on other types it need not (see `mount`)." },
    [F_NLINK] = { "nlink", NULL, "int", true,
        "Link count. `> 1` on a regular file means hard links exist." },
    [F_IFLAGS] = { "iflags", NULL, "int", false,
        "Inode flags, where the filesystem has them. Linux: `FS_IOC_GETFLAGS` (`chattr`: "
        "immutable, append-only, nodump...), on regular files and directories. macOS: "
        "`st_flags` (`chflags`), on every type." },
    [F_CAPS] = { "caps", NULL, "string", false,
        "The file capability: the raw `security.capability` value, lowercase hex. `setcap` on "
        "an interpreter is a privilege change; this is where it shows." },
    [F_XATTRS] = { "xattrs", NULL, "array", false,
        "One string per extended attribute other than `security.capability`, "
        "`\"<name>=<sha256 of value>\"`, sorted strictly by name bytes; absent when there are "
        "none. POSIX ACLs appear here as `system.posix_acl_access` / "
        "`system.posix_acl_default`. A name is written as itself when it is printable ASCII "
        "without `\"`, `\\` or `=` and does not start `x:`; otherwise as `x:` followed by its "
        "bytes in hex. At most 8192 bytes of array body; a larger set is recorded as "
        "`xattrs_sha256` instead." },
    [F_XATTRS_SHA256] = { "xattrs_sha256", NULL, "string", false,
        "For a set too large for `xattrs`: the sha256 of the array body `xattrs` would have "
        "held, so a set recorded inline in one manifest and by digest in another still "
        "compares." },
    [F_XATTRS_UNKNOWN] = { "xattrs_unknown", NULL, "bool", false,
        "`true`: the attributes could not be read. An absent `xattrs` means \"none\", so "
        "failing to read must say so. `diff` reports the entry's metadata as `unknown`, never "
        "unchanged." },
    [F_SHA256] = { "sha256", NULL, "string", false,
        "Lowercase hex content digest, of a file within `hash_max_bytes` read in one stable "
        "pass (see \"What a hash, and a stored copy, prove\")." },
    [F_UNVERIFIED] = { "unverified", NULL, "bool", false,
        "`true`: no hash is recorded. The file is larger than `hash_max_bytes`, or it is also "
        "flagged `unstable`, `unreadable` or `mount`, which say why. `diff` must report any "
        "change to it as **modified (unverified)**, never as unchanged." },
    [F_UNSTABLE] = { "unstable", NULL, "bool", false,
        "`true`. On a regular file: it changed while being read (size, mtime or ctime moved, "
        "or the inode opened was not the one stat'ed); no hash is recorded, because the bytes "
        "read describe no state the file ever had. On a directory: **its listing is not its "
        "listing at the end of the walk** -- the end-of-walk validator found it changed since "
        "it was recorded (its inode, device, mode, mtime or ctime differ, it is now a mount, or "
        "it can no longer be reached), or the listing failed part way (it could not be "
        "read as a directory stream, a `readdir` error, a child that could not be stat'ed at "
        "all, or a child name too long to fit the path limit). Entries may be missing from it "
        "or recorded under another directory; the comparator MUST NOT read its children as a "
        "complete listing." },
    [F_RDEV] = { "rdev", NULL, "int", false,
        "The device number. Without it a replaced device node, or an overlayfs whiteout (char "
        "0,0), is indistinguishable from the original." },
    [F_LINK_TARGET] = { "link_target", "link_target_b64", "string", false,
        "The link's bytes, verbatim and unresolved; `link_target_b64`, base64, when they are "
        "not valid UTF-8. Empty only on an `unreadable` link, meaning the target is unknown." },
    [F_TARGET_OUTSIDE] = { "target_outside_scope", NULL, "bool", false,
        "`true` when the target resolves lexically outside the scope. **Advisory only** — "
        "never drives a decision (§5.1.1)." },
    [F_STORED] = { "stored", NULL, "string", false,
        "Present when content was copied: the `store/` key, which is the content's sha256. "
        "On Linux no copy is kept of a file another process had open for writing while belay "
        "read it (see \"What a hash, and a stored copy, prove\")." },
    [F_MOUNT] = { "mount", NULL, "bool", false,
        "`true`. The entry is the root of another mount. Where statx can say so "
        "(`STATX_ATTR_MOUNT_ROOT`, Linux 5.8+), its answer is used alone: it catches bind "
        "mounts from the same filesystem, and it does not mistake a btrfs subvolume (a "
        "directory with its own `dev`, not a mount) for one. Without it, an entry whose `dev` "
        "differs from the scope root's is a mount -- except a non-directory in an overlayfs "
        "scope, where every file carries its layer's device. A mount is recorded and **never "
        "read or descended** (§5.1.1): a mounted regular file carries `unverified` and no "
        "hash, and **for a directory the subtree below it is ABSENT**: `diff` MUST report it "
        "as *not captured*, never as *unchanged*." },
    [F_UNREADABLE] = { "unreadable", NULL, "bool", false,
        "`true`. belay could not capture this entry's contents: a directory it could not open "
        "or search (permission, or readable-but-not-searchable), a directory swapped for "
        "another between its stat and its open, a directory beyond the depth limit (128) or "
        "whose path leaves no room for a child name, a file it could not open or read, or a "
        "symlink whose target could not be read or kept changing while being read. **For a "
        "directory, the entire subtree below it is ABSENT.** `diff` MUST report such a subtree "
        "as *contents unknown* and never as *unchanged*. Without this field an unreadable "
        "directory is byte-identical to an empty one." },
    [F_RACED] = { "raced", NULL, "bool", false,
        "`true`. The entry changed after it was recorded, before the walk ended: re-stat'ed "
        "at the end of the walk, its inode, device, mode, size, mtime or ctime differed, or it "
        "could not be reached without entering a mount. What is recorded held when belay read "
        "it, but not at the end. (A "
        "listed directory that changed is flagged `unstable` instead, since its listing is "
        "what no longer holds.)" },
};

const struct line_field_def HEADER_FIELDS[H_COUNT] = {
    [H_VERSION] = { "belay_manifest", NULL, "int",
        "Format version. A reader MUST reject a version it does not know." },
    [H_CREATED] = { "created_ns", NULL, "int",
        "Wall clock at creation, nanoseconds since the epoch. Informational only -- never used "
        "for comparison, per §6.3." },
    [H_SCOPES] = { "scopes", "scopes_b64", "array",
        "The resolved scope root, exactly one in this version. A scope that is not valid UTF-8 "
        "is written as `scopes_b64` (base64 elements) instead, never both." },
    [H_HASH] = { "hash", NULL, "string", "Digest algorithm for the `sha256` field." },
    [H_HASH_MAX] = { "hash_max_bytes", NULL, "int",
        "Regular files larger than this are recorded without a hash (see `unverified`)." },
    [H_STORE_MAX] = { "store_max_bytes", NULL, "int",
        "Size threshold for copying content into `store/`." },
};

const struct line_field_def TRAILER_FIELDS[TR_COUNT] = {
    [TR_ENTRIES] = { "belay_manifest_end", NULL, "int", "Number of entries, including `.`." },
    [TR_VANISHED] = { "vanished", NULL, "int",
        "Entries that disappeared between being listed and being read. Non-zero means the tree "
        "was changing during the walk, so the manifest is not a single instant." },
    [TR_UNREADABLE] = { "unreadable", NULL, "int", "Entries carrying `unreadable`." },
    [TR_UNSTABLE] = { "unstable", NULL, "int",
        "Entries carrying `unstable` (files and directories). Non-zero means the manifest is "
        "not a consistent single-instant snapshot." },
    [TR_MOUNTS] = { "mounts", NULL, "int",
        "Entries carrying `mount`: boundaries whose contents were not captured." },
    [TR_RACED] = { "raced", NULL, "int",
        "Entries carrying `raced`. Non-zero means the tree was changing during the walk, so the "
        "manifest is not a single instant." },
};

#define T_REG  TBIT(BELAY_T_REG)
#define T_DIR  TBIT(BELAY_T_DIR)
#define T_LNK  TBIT(BELAY_T_LNK)
#define T_DEV  (TBIT(BELAY_T_BLK) | TBIT(BELAY_T_CHR))
#define T_NODE (TBIT(BELAY_T_FIFO) | TBIT(BELAY_T_SOCK) | T_DEV)
#define HASHES (FBIT(F_SHA256) | FBIT(F_UNVERIFIED) | FBIT(F_STORED))
#define EXTRAS (FBIT(F_IFLAGS) | FBIT(F_CAPS) | FBIT(F_XATTRS) | FBIT(F_XATTRS_SHA256) | \
                FBIT(F_XATTRS_UNKNOWN))

static bool mode_disagrees(const struct belay_entry *e) {
    return (e->mode & ENTRY_IFMT) != ENTRY_TYPES[e->type].ifmt;
}
static bool stored_differs(const struct belay_entry *e) {
    return e->has_stored && (!e->has_hash || strcmp(e->stored_hex, e->sha256_hex) != 0);
}
static bool link_empty(const struct belay_entry *e) {
    return !e->unreadable && e->link_target_len == 0;
}
static bool link_size_differs(const struct belay_entry *e) {
    return !e->unreadable && e->size != e->link_target_len;
}
static bool outside_without_target(const struct belay_entry *e) {
    return e->target_outside_scope && e->link_target_len == 0;
}

/* In the order the reader has always applied them, so its first error
 * message for a malformed entry is unchanged. */
const struct entry_rule ENTRY_RULES[] = {
    { R_CHECK, T_ALL, 0, 0, mode_disagrees, "mode's type bits disagree with type", NULL,
      "`mode`'s type bits match `type` (`S_IFMT`; the same values on Linux and macOS)." },
    { R_EXCLUDES, T_ALL, FBIT(F_XATTRS), FBIT(F_XATTRS_SHA256), NULL,
      "both xattrs and xattrs_sha256", NULL,
      "`xattrs` and `xattrs_sha256` are never both present." },
    { R_EXCLUDES, T_ALL, FBIT(F_XATTRS_UNKNOWN), FBIT(F_XATTRS) | FBIT(F_XATTRS_SHA256) | FBIT(F_CAPS),
      NULL, "xattrs_unknown with recorded attributes", NULL,
      "`xattrs_unknown` excludes `xattrs`, `xattrs_sha256` and `caps`." },
    { R_FORBID, T_ALL & ~T_REG, FBIT(F_CAPS), 0, NULL, "caps on a non-regular file", NULL,
      "`caps` appears only on `reg`." },
    { R_EXACTLY_ONE, T_REG, FBIT(F_SHA256) | FBIT(F_UNVERIFIED), 0, NULL,
      "both sha256 and unverified", "regular file with neither sha256 nor unverified",
      "A `reg` carries exactly one of `sha256` and `unverified`." },
    { R_IMPLIES, T_REG, FBIT(F_UNSTABLE) | FBIT(F_UNREADABLE), FBIT(F_UNVERIFIED), NULL,
      "unstable or unreadable file without unverified", NULL,
      "On a `reg`, `unstable` and `unreadable` each require `unverified`." },
    { R_EXCLUSIVE, T_REG, FBIT(F_UNSTABLE) | FBIT(F_UNREADABLE), 0, NULL,
      "file both unstable and unreadable", NULL,
      "On a `reg`, `unstable` and `unreadable` are never both present." },
    { R_EXCLUDES, T_REG, FBIT(F_MOUNT), FBIT(F_UNSTABLE) | FBIT(F_UNREADABLE), NULL,
      "mounted file with read flags", NULL,
      "A mounted `reg` carries neither `unstable` nor `unreadable`." },
    { R_FORBID, T_DIR, HASHES, 0, NULL, "hash fields on a directory", NULL,
      "A `dir` carries no `sha256`, `unverified` or `stored`." },
    { R_IMPLIES, T_DIR, FBIT(F_RACED), FBIT(F_UNREADABLE) | FBIT(F_MOUNT), NULL,
      "raced on a listed directory", NULL,
      "A `dir` carries `raced` only with `unreadable` or `mount` (a listed one that changed is `unstable`)." },
    { R_EXCLUSIVE, T_DIR, FBIT(F_UNREADABLE) | FBIT(F_UNSTABLE) | FBIT(F_MOUNT), 0, NULL,
      "directory flags unreadable, unstable and mount are exclusive", NULL,
      "A `dir` carries at most one of `unreadable`, `unstable` and `mount`." },
    { R_FORBID, T_LNK, HASHES | FBIT(F_UNSTABLE), 0, NULL, "file-only fields on a symlink", NULL,
      "A `lnk` carries no `sha256`, `unverified`, `stored` or `unstable`." },
    { R_FORBID, T_NODE, HASHES | FBIT(F_UNSTABLE) | FBIT(F_UNREADABLE), 0, NULL,
      "read flags on a node that is never read", NULL,
      "A `fifo`, `sock`, `blk` or `chr` carries no hash fields, `unstable` or `unreadable`." },
    { R_CHECK, T_ALL, 0, 0, stored_differs, "stored key does not match sha256", NULL,
      "`stored` appears only with `sha256`, and equals it." },
    { R_PRESENT_IFF, T_DEV, FBIT(F_RDEV), 0, NULL, "device without rdev", "rdev on a non-device",
      "`rdev` appears exactly on `blk` and `chr`." },
    { R_PRESENT_IFF, T_LNK, FBIT(F_LINK_TARGET), 0, NULL,
      "symlink without a target", "non-symlink with a link target",
      "`link_target` (or `link_target_b64`) appears exactly on `lnk`." },
    { R_FORBID, T_ALL & ~T_LNK, FBIT(F_TARGET_OUTSIDE), 0, NULL,
      "target_outside_scope on a non-symlink", NULL,
      "`target_outside_scope` appears only on `lnk`." },
    { R_CHECK, T_LNK, 0, 0, link_empty, "symlink with an empty target", NULL,
      "A `lnk`'s target is empty only when the link is `unreadable` (empty means unknown)." },
    { R_CHECK, T_LNK, 0, 0, link_size_differs, "symlink size disagrees with its target's length", NULL,
      "A `lnk`'s `size` equals its target's length, unless the link is `unreadable`." },
    { R_CHECK, T_ALL, 0, 0, outside_without_target, "target_outside_scope on an unknown target", NULL,
      "`target_outside_scope` never accompanies an empty (unknown) target." },
    { R_EXCLUDES, T_ALL, FBIT(F_MOUNT), FBIT(F_SHA256), NULL, "hash on a mount point", NULL,
      "A `mount` carries no `sha256`." },
    { R_EXCLUDES, T_ALL, FBIT(F_MOUNT), EXTRAS, NULL, "extended metadata on a mount point", NULL,
      "A `mount` carries no extended metadata (`iflags`, `caps`, `xattrs`, `xattrs_sha256`, `xattrs_unknown`)." },
};
const size_t ENTRY_RULE_COUNT = sizeof ENTRY_RULES / sizeof ENTRY_RULES[0];

uint32_t entry_present(const struct belay_entry *e) {
    uint32_t p = 0;
    for (int f = F_PATH; f <= F_NLINK; f++) p |= FBIT(f);
    if (e->has_iflags) p |= FBIT(F_IFLAGS);
    if (e->has_caps) p |= FBIT(F_CAPS);
    if (e->has_xattrs) p |= e->xattrs_inline ? FBIT(F_XATTRS) : FBIT(F_XATTRS_SHA256);
    if (e->xattrs_unknown) p |= FBIT(F_XATTRS_UNKNOWN);
    if (e->has_hash) p |= FBIT(F_SHA256);
    if (e->unverified) p |= FBIT(F_UNVERIFIED);
    if (e->unstable) p |= FBIT(F_UNSTABLE);
    if (e->has_rdev) p |= FBIT(F_RDEV);
    if (e->has_link_target) p |= FBIT(F_LINK_TARGET);
    if (e->target_outside_scope) p |= FBIT(F_TARGET_OUTSIDE);
    if (e->has_stored) p |= FBIT(F_STORED);
    if (e->is_mount) p |= FBIT(F_MOUNT);
    if (e->unreadable) p |= FBIT(F_UNREADABLE);
    if (e->raced) p |= FBIT(F_RACED);
    return p;
}

static bool violated(const struct entry_rule *r, const struct belay_entry *e, uint32_t present,
                     const char **msg) {
    const bool applies = (r->types & TBIT(e->type)) != 0;
    *msg = r->msg;
    switch (r->kind) {
    case R_UNSET:
        *msg = "internal error: a schema rule without a kind";
        return true;
    case R_FORBID:      return applies && (present & r->a);
    case R_IMPLIES:     return applies && (present & r->a) && !(present & r->b);
    case R_EXCLUSIVE:   return applies && __builtin_popcount(present & r->a) > 1;
    case R_EXCLUDES:    return applies && (present & r->a) && (present & r->b);
    case R_CHECK:       return applies && r->check(e);
    case R_EXACTLY_ONE: {
        const int n = __builtin_popcount(present & r->a);
        if (n == 0) *msg = r->msg2;
        return applies && n != 1;
    }
    case R_PRESENT_IFF:
        if (!applies) *msg = r->msg2;
        return applies != ((present & r->a) != 0);
    }
    *msg = "internal error: a schema rule of an unknown kind";
    return true;                         /* fails closed: never "not violated" */
}

int entry_check(const struct belay_entry *e, uint32_t present) {
    for (size_t i = 0; i < ENTRY_RULE_COUNT; i++) {
        const char *msg;
        if (violated(&ENTRY_RULES[i], e, present, &msg)) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s", msg);
            return -1;
        }
    }
    return 0;
}

/*
 *  Rules that need the header. The writer hashes a regular file exactly when
 *  its size is within hash_max_bytes and nothing else prevents it, and it
 *  computes target_outside_scope from the scope with one shared function, so
 *  both are checked rather than taken on trust: otherwise one state would have
 *  two encodings (review round 3, F7). Each returns its message, or NULL.
 */
static const char *hash_limit(const struct belay_manifest_header *h, const struct belay_entry *e) {
    if (e->type != BELAY_T_REG) return NULL;
    if (e->has_hash && e->size > h->hash_max_bytes)
        return "hash on a file larger than hash_max_bytes";
    if (e->unverified && !e->unstable && !e->unreadable && !e->is_mount &&
        e->size <= h->hash_max_bytes)
        return "unverified file within hash_max_bytes, with no reason";
    return NULL;
}
static const char *outside_annotation(const struct belay_manifest_header *h,
                                      const struct belay_entry *e) {
    if (e->type != BELAY_T_LNK) return NULL;
    /* An unreadable link's target is unknown or stale: never annotated. */
    const bool want = !e->unreadable &&
        belay_link_target_outside(h->scope, e->path, e->path_len,
                                  e->link_target, e->link_target_len);
    if (e->target_outside_scope == want) return NULL;
    return want ? "target_outside_scope missing on a link leaving the scope"
                : "target_outside_scope on a link that stays in the scope";
}

const struct entry_header_rule ENTRY_HEADER_RULES[] = {
    { hash_limit,
      "A `reg` carries `sha256` only if its `size` is within `hash_max_bytes`, and a bare "
      "`unverified` (no `unstable`, `unreadable` or `mount` giving another reason) only if it "
      "is larger." },
    { outside_annotation,
      "A `lnk` carries `target_outside_scope` exactly when the lexical rule says its target "
      "leaves the scope (an absolute target outside it; a relative one whose `..` climbs above "
      "the scope root, resolved from the link's own directory; a target the rule cannot "
      "judge), and never when it is `unreadable`. Writer and reader share one implementation "
      "of that rule, so the annotation has one value per state." },
};
const size_t ENTRY_HEADER_RULE_COUNT = sizeof ENTRY_HEADER_RULES / sizeof ENTRY_HEADER_RULES[0];

int entry_check_header(const struct belay_manifest_header *h, const struct belay_entry *e) {
    for (size_t i = 0; i < ENTRY_HEADER_RULE_COUNT; i++) {
        const char *msg = ENTRY_HEADER_RULES[i].check(h, e);
        if (msg != NULL) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s", msg);
            return -1;
        }
    }
    return 0;
}

/* Fixed part of a packed entry; variable parts follow in this order: link
 * target, xattrs text, caps hex, then the 64-hex digests that are present
 * (sha256, stored, xattrs digest). */
struct head {
    uint64_t size, ino, dev, nlink, iflags, rdev;
    int64_t  mtime_ns, ctime_ns;
    uint32_t mode, uid, gid, type;
    uint32_t link_len, xattrs_len, caps_len, bits;
};

enum {
    B_IFLAGS = 1u << 0, B_CAPS = 1u << 1, B_XATTRS = 1u << 2, B_XINLINE = 1u << 3,
    B_XUNKNOWN = 1u << 4, B_HASH = 1u << 5, B_UNVERIFIED = 1u << 6, B_LINK = 1u << 7,
    B_OUTSIDE = 1u << 8, B_STORED = 1u << 9, B_MOUNT = 1u << 10, B_RDEV = 1u << 11,
    B_UNSTABLE = 1u << 12, B_UNREADABLE = 1u << 13, B_RACED = 1u << 14,
};

struct w { unsigned char *p; size_t n, cap; int ok; };
static void put(struct w *w, const void *src, size_t len) {
    if (!w->ok || w->n + len > w->cap) { w->ok = 0; return; }
    memcpy(w->p + w->n, src, len);
    w->n += len;
}

size_t entry_pack(const struct belay_entry *e, unsigned char *buf, size_t cap) {
    const size_t caps_len = e->has_caps ? strlen(e->caps_hex) : 0;
    const struct head h = {
        .size = e->size, .ino = e->ino, .dev = e->dev, .nlink = e->nlink,
        .iflags = e->iflags, .rdev = e->rdev, .mtime_ns = e->mtime_ns, .ctime_ns = e->ctime_ns,
        .mode = e->mode, .uid = e->uid, .gid = e->gid, .type = (uint32_t)e->type,
        .link_len = e->has_link_target ? (uint32_t)e->link_target_len : 0,
        .xattrs_len = e->xattrs_inline ? (uint32_t)e->xattrs_len : 0,
        .caps_len = (uint32_t)caps_len,
        .bits = (e->has_iflags ? B_IFLAGS : 0) | (e->has_caps ? B_CAPS : 0) |
                (e->has_xattrs ? B_XATTRS : 0) | (e->xattrs_inline ? B_XINLINE : 0) |
                (e->xattrs_unknown ? B_XUNKNOWN : 0) | (e->has_hash ? B_HASH : 0) |
                (e->unverified ? B_UNVERIFIED : 0) | (e->has_link_target ? B_LINK : 0) |
                (e->target_outside_scope ? B_OUTSIDE : 0) | (e->has_stored ? B_STORED : 0) |
                (e->is_mount ? B_MOUNT : 0) | (e->has_rdev ? B_RDEV : 0) |
                (e->unstable ? B_UNSTABLE : 0) | (e->unreadable ? B_UNREADABLE : 0) |
                (e->raced ? B_RACED : 0),
    };
    struct w w = { buf, 0, cap, 1 };
    put(&w, &h, sizeof h);
    put(&w, e->link_target, h.link_len);
    put(&w, e->xattrs, h.xattrs_len);
    put(&w, e->caps_hex, caps_len);
    if (e->has_hash)   put(&w, e->sha256_hex, 64);
    if (e->has_stored) put(&w, e->stored_hex, 64);
    if (e->has_xattrs) put(&w, e->xattrs_sha256_hex, 64);
    return w.ok ? w.n : 0;
}

struct r { const unsigned char *p; size_t n, len; int ok; };
static void get(struct r *r, void *dst, size_t len) {
    if (!r->ok || r->n + len > r->len) { r->ok = 0; return; }
    memcpy(dst, r->p + r->n, len);
    r->n += len;
}

static void get_hex64(struct r *r, char out[65], int present) {
    out[0] = '\0';
    if (!present) return;
    get(r, out, 64);
    out[64] = '\0';
}

int entry_unpack(const unsigned char *buf, size_t len, const unsigned char *path,
                 size_t path_len, struct belay_entry *e) {
    struct r r = { buf, 0, len, 1 };
    struct head h;
    get(&r, &h, sizeof h);
    if (!r.ok || path_len > ENTRY_PATH_MAX || h.link_len >= sizeof e->link_target ||
        h.xattrs_len >= sizeof e->xattrs || h.caps_len >= sizeof e->caps_hex) goto bad;
    memcpy(e->path, path, path_len);
    e->path[path_len] = '\0';
    e->path_len = path_len;
    e->size = h.size; e->ino = h.ino; e->dev = h.dev; e->nlink = h.nlink;
    e->iflags = h.iflags; e->rdev = h.rdev; e->mtime_ns = h.mtime_ns; e->ctime_ns = h.ctime_ns;
    e->mode = h.mode; e->uid = h.uid; e->gid = h.gid; e->type = (enum belay_entry_type)h.type;
    e->has_iflags = h.bits & B_IFLAGS;   e->has_caps = h.bits & B_CAPS;
    e->has_xattrs = h.bits & B_XATTRS;   e->xattrs_inline = h.bits & B_XINLINE;
    e->xattrs_unknown = h.bits & B_XUNKNOWN; e->has_hash = h.bits & B_HASH;
    e->unverified = h.bits & B_UNVERIFIED; e->has_link_target = h.bits & B_LINK;
    e->target_outside_scope = h.bits & B_OUTSIDE; e->has_stored = h.bits & B_STORED;
    e->is_mount = h.bits & B_MOUNT;      e->has_rdev = h.bits & B_RDEV;
    e->unstable = h.bits & B_UNSTABLE;   e->unreadable = h.bits & B_UNREADABLE;
    e->raced = h.bits & B_RACED;
    get(&r, e->link_target, h.link_len);
    e->link_target[h.link_len] = '\0';
    e->link_target_len = h.link_len;
    get(&r, e->xattrs, h.xattrs_len);
    e->xattrs[h.xattrs_len] = '\0';
    e->xattrs_len = h.xattrs_len;
    get(&r, e->caps_hex, h.caps_len);
    e->caps_hex[h.caps_len] = '\0';
    get_hex64(&r, e->sha256_hex, e->has_hash);
    get_hex64(&r, e->stored_hex, e->has_stored);
    get_hex64(&r, e->xattrs_sha256_hex, e->has_xattrs);
    if (r.ok && r.n == len) return 0;
bad:
    belay_err_set(BELAY_ERR_IO, 0, "manifest: temporary record is malformed");
    return -1;
}
