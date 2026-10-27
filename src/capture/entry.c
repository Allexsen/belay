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

const struct entry_field_def ENTRY_FIELDS[F_COUNT] = {
    [F_PATH]   = { "path", "path_b64", "string", true,
                   "relative to the scope root; `.` is the root itself" },
    [F_TYPE]   = { "type", NULL, "string", true,
                   "`reg`, `dir`, `lnk`, `fifo`, `sock`, `blk`, `chr`" },
    [F_MODE]   = { "mode", NULL, "int", true, "`st_mode`, type bits included" },
    [F_UID]    = { "uid", NULL, "int", true, "owner" },
    [F_GID]    = { "gid", NULL, "int", true, "group" },
    [F_SIZE]   = { "size", NULL, "int", true, "`st_size`; for `lnk`, the target length" },
    [F_MTIME]  = { "mtime_ns", NULL, "int", true, "modification time, nanoseconds" },
    [F_CTIME]  = { "ctime_ns", NULL, "int", true, "change time, nanoseconds" },
    [F_INO]    = { "ino", NULL, "int", true, "inode number" },
    [F_DEV]    = { "dev", NULL, "int", true, "device" },
    [F_NLINK]  = { "nlink", NULL, "int", true, "link count" },
    [F_IFLAGS] = { "iflags", NULL, "int", false, "inode flags (`chattr`, `chflags`)" },
    [F_CAPS]   = { "caps", NULL, "string", false, "the raw `security.capability` value, hex" },
    [F_XATTRS] = { "xattrs", NULL, "array", false,
                   "`name=<sha256 of value>` per attribute, sorted by name" },
    [F_XATTRS_SHA256] = { "xattrs_sha256", NULL, "string", false,
                   "digest of the `xattrs` body, for a set too large to inline" },
    [F_XATTRS_UNKNOWN] = { "xattrs_unknown", NULL, "bool", false,
                   "the attributes could not be read" },
    [F_SHA256] = { "sha256", NULL, "string", false, "content digest, lowercase hex" },
    [F_UNVERIFIED] = { "unverified", NULL, "bool", false, "no hash recorded" },
    [F_UNSTABLE] = { "unstable", NULL, "bool", false,
                   "changed while being read; a directory's listing is incomplete" },
    [F_RDEV]   = { "rdev", NULL, "int", false, "device number of a device node" },
    [F_LINK_TARGET] = { "link_target", "link_target_b64", "string", false,
                   "the symlink's target, verbatim; empty means unknown" },
    [F_TARGET_OUTSIDE] = { "target_outside_scope", NULL, "bool", false,
                   "advisory: the target leaves the scope lexically" },
    [F_STORED] = { "stored", NULL, "string", false, "the store key, equal to `sha256`" },
    [F_MOUNT]  = { "mount", NULL, "bool", false, "a mount root: recorded, never read" },
    [F_UNREADABLE] = { "unreadable", NULL, "bool", false, "contents could not be captured" },
    [F_RACED]  = { "raced", NULL, "bool", false,
                   "changed after it was recorded, before the walk ended" },
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
    return (e->mode & 0170000u) != ENTRY_TYPES[e->type].ifmt;
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
    return false;
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
