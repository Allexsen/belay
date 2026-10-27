#include "entry.h"

#include "belay/error.h"

#include <string.h>

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
