/*
 *  One entry as one canonical NDJSON line (manifest format v1).
 */
#include "serialize.h"
#include "schema/entry.h"

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

/* One field, key included. Fields are encoded in the schema's order
 * (entry.c); byte strings use their base64 spelling when not UTF-8. */
static int put_field(const struct belay_entry *e, enum entry_field f, char *buf, size_t cap,
                     size_t *w) {
    const char *k = ENTRY_FIELDS[f].name, *alt = ENTRY_FIELDS[f].alt;
    switch (f) {
    case F_PATH:   return ap_bytes(buf, cap, w, k, alt, e->path, e->path_len);
    case F_LINK_TARGET:
        return ap_bytes(buf, cap, w, k, alt, e->link_target, e->link_target_len);
    case F_TYPE:   return ap(buf, cap, w, "\"%s\":\"%s\"", k, ENTRY_TYPES[e->type].name);
    case F_MODE:   return ap(buf, cap, w, "\"%s\":%u", k, e->mode);
    case F_UID:    return ap(buf, cap, w, "\"%s\":%u", k, e->uid);
    case F_GID:    return ap(buf, cap, w, "\"%s\":%u", k, e->gid);
    case F_SIZE:   return ap(buf, cap, w, "\"%s\":%llu", k, (unsigned long long)e->size);
    case F_MTIME:  return ap(buf, cap, w, "\"%s\":%lld", k, (long long)e->mtime_ns);
    case F_CTIME:  return ap(buf, cap, w, "\"%s\":%lld", k, (long long)e->ctime_ns);
    case F_INO:    return ap(buf, cap, w, "\"%s\":%llu", k, (unsigned long long)e->ino);
    case F_DEV:    return ap(buf, cap, w, "\"%s\":%llu", k, (unsigned long long)e->dev);
    case F_NLINK:  return ap(buf, cap, w, "\"%s\":%llu", k, (unsigned long long)e->nlink);
    case F_IFLAGS: return ap(buf, cap, w, "\"%s\":%llu", k, (unsigned long long)e->iflags);
    case F_RDEV:   return ap(buf, cap, w, "\"%s\":%llu", k, (unsigned long long)e->rdev);
    case F_CAPS:   return ap(buf, cap, w, "\"%s\":\"%s\"", k, e->caps_hex);
    case F_XATTRS: return ap(buf, cap, w, "\"%s\":[%s]", k, e->xattrs);
    case F_XATTRS_SHA256: return ap(buf, cap, w, "\"%s\":\"%s\"", k, e->xattrs_sha256_hex);
    case F_SHA256: return ap(buf, cap, w, "\"%s\":\"%s\"", k, e->sha256_hex);
    case F_STORED: return ap(buf, cap, w, "\"%s\":\"%s\"", k, e->stored_hex);
    default:       return ap(buf, cap, w, "\"%s\":true", k);   /* the flags */
    }
}

int entry_serialize(const struct belay_entry *e, char *buf, size_t cap, size_t *len) {
    const uint32_t present = entry_present(e);
    size_t w = 0;
    if (ap(buf, cap, &w, "{") == -1) return -1;
    for (int f = 0; f < F_COUNT; f++) {
        if (!(present & FBIT(f))) continue;
        if (f > 0 && ap(buf, cap, &w, ",") == -1) return -1;
        if (put_field(e, (enum entry_field)f, buf, cap, &w) == -1) return -1;
    }
    if (ap(buf, cap, &w, "}\n") == -1) return -1;
    *len = w;
    return 0;
}
