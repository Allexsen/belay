/*
 *  One entry as one canonical NDJSON line (manifest format v1).
 */
#include "serialize.h"

#include "belay/error.h"
#include "belay/json.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int ap(char *buf, size_t cap, size_t *w, const char *fmt, ...) {
    va_list a;
    va_start(a, fmt);
    const int n = vsnprintf(buf + *w, cap - *w, fmt, a);
    va_end(a);
    if (n < 0 || (size_t)n >= cap - *w) {
        belay_err_set(BELAY_ERR_RANGE, 0, "manifest: entry exceeds %zu bytes", cap);
        return -1;
    }
    *w += (size_t)n;
    return 0;
}

/* Appends `len` raw bytes as a JSON string value under `key`, or as base64
 * under `key_b64` when they are not valid UTF-8. */
static int ap_bytes(char *buf, size_t cap, size_t *w, const char *key,
                    const char *key_b64, const char *bytes, size_t len) {
    if (belay_utf8_valid(bytes, len)) {
        if (ap(buf, cap, w, "\"%s\":\"", key) == -1) return -1;
        if (belay_json_escape(buf + *w, cap - *w, bytes, len) == -1) return -1;
    } else {
        if (ap(buf, cap, w, "\"%s\":\"", key_b64) == -1) return -1;
        if (belay_base64_encode(buf + *w, cap - *w, bytes, len) == -1) return -1;
    }
    *w += strlen(buf + *w);
    return ap(buf, cap, w, "\"");
}

static const char *type_name(enum belay_entry_type t) {
    switch (t) {
    case BELAY_T_REG:  return "reg";
    case BELAY_T_DIR:  return "dir";
    case BELAY_T_LNK:  return "lnk";
    case BELAY_T_FIFO: return "fifo";
    case BELAY_T_SOCK: return "sock";
    case BELAY_T_BLK:  return "blk";
    default:           return "chr";
    }
}

/* One entry as one NDJSON line, newline included. */
int entry_serialize(const struct belay_entry *e, char *buf, size_t cap, size_t *len) {
    size_t w = 0;
    if (ap(buf, cap, &w, "{") == -1) return -1;
    if (ap_bytes(buf, cap, &w, "path", "path_b64", e->path, e->path_len) == -1) return -1;

    if (ap(buf, cap, &w,
           ",\"type\":\"%s\",\"mode\":%u,\"uid\":%u,\"gid\":%u"
           ",\"size\":%llu,\"mtime_ns\":%lld,\"ctime_ns\":%lld"
           ",\"ino\":%llu,\"dev\":%llu,\"nlink\":%llu",
           type_name(e->type), e->mode, e->uid, e->gid,
           (unsigned long long)e->size, (long long)e->mtime_ns, (long long)e->ctime_ns,
           (unsigned long long)e->ino, (unsigned long long)e->dev,
           (unsigned long long)e->nlink) == -1) return -1;

    if (e->has_iflags &&
        ap(buf, cap, &w, ",\"iflags\":%llu", (unsigned long long)e->iflags) == -1) return -1;
    if (e->has_caps && ap(buf, cap, &w, ",\"caps\":\"%s\"", e->caps_hex) == -1) return -1;
    if (e->has_xattrs) {
        if (e->xattrs_inline ? ap(buf, cap, &w, ",\"xattrs\":[%s]", e->xattrs)
                             : ap(buf, cap, &w, ",\"xattrs_sha256\":\"%s\"", e->xattrs_sha256_hex))
            return -1;
    }
    if (e->xattrs_unknown && ap(buf, cap, &w, ",\"xattrs_unknown\":true") == -1) return -1;

    if (e->has_hash && ap(buf, cap, &w, ",\"sha256\":\"%s\"", e->sha256_hex) == -1) return -1;
    if (e->unverified && ap(buf, cap, &w, ",\"unverified\":true") == -1) return -1;
    if (e->unstable && ap(buf, cap, &w, ",\"unstable\":true") == -1) return -1;
    if (e->has_rdev &&
        ap(buf, cap, &w, ",\"rdev\":%llu", (unsigned long long)e->rdev) == -1) return -1;

    if (e->has_link_target) {
        if (ap(buf, cap, &w, ",") == -1) return -1;
        if (ap_bytes(buf, cap, &w, "link_target", "link_target_b64",
                     e->link_target, e->link_target_len) == -1) return -1;
        if (e->target_outside_scope &&
            ap(buf, cap, &w, ",\"target_outside_scope\":true") == -1) return -1;
    }

    if (e->has_stored && ap(buf, cap, &w, ",\"stored\":\"%s\"", e->stored_hex) == -1) return -1;
    if (e->is_mount && ap(buf, cap, &w, ",\"mount\":true") == -1) return -1;
    if (e->unreadable && ap(buf, cap, &w, ",\"unreadable\":true") == -1) return -1;
    if (e->raced && ap(buf, cap, &w, ",\"raced\":true") == -1) return -1;

    if (ap(buf, cap, &w, "}\n") == -1) return -1;
    *len = w;
    return 0;
}
