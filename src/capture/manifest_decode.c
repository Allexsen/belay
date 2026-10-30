/*
 *  The manifest's decoding layer (manifest_decode.h): objects to fields.
 */
#define _GNU_SOURCE
#include "manifest_decode.h"

#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"
#include "belay/path.h"

#include <stdbool.h>
#include <string.h>

/* Entry keys in canonical order: the schema's fields, each followed by its
 * base64 spelling where it has one. */
static size_t entry_keys(const char *keys[2 * F_COUNT]) {
    size_t n = 0;
    for (size_t f = 0; f < F_COUNT; f++) {
        keys[n++] = ENTRY_FIELDS[f].name;
        if (ENTRY_FIELDS[f].alt != NULL) keys[n++] = ENTRY_FIELDS[f].alt;
    }
    return n;
}

/* Which schema fields the line carries, by key. */
static uint32_t present_fields(const struct obj *o) {
    uint32_t p = 0;
    for (size_t f = 0; f < F_COUNT; f++)
        if (lex_get(o, ENTRY_FIELDS[f].name) != NULL ||
            (ENTRY_FIELDS[f].alt != NULL && lex_get(o, ENTRY_FIELDS[f].alt) != NULL))
            p |= FBIT(f);
    return p;
}
/* Header and trailer keys in canonical order, from the schema; the header's
 * fields each followed by their base64 spelling where they have one. */
static size_t header_keys(const char *keys[2 * H_COUNT]) {
    size_t n = 0;
    for (size_t f = 0; f < H_COUNT; f++) {
        keys[n++] = HEADER_FIELDS[f].name;
        if (HEADER_FIELDS[f].alt != NULL) keys[n++] = HEADER_FIELDS[f].alt;
    }
    return n;
}

static int bad_kind(const char *key, const char *want) {
    belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: \"%s\" must be %s", key, want);
    return -1;
}

/* Field accessors. `required` decides whether absence is an error. */
static int get_u64(const struct obj *o, const char *key, bool required, uint64_t *out, bool *present) {
    const struct pair *p = lex_get(o, key);
    if (present) *present = (p != NULL);
    if (p == NULL) {
        if (!required) return 0;
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: missing %s", key);
        return -1;
    }
    if (p->kind != V_INT || p->val[0] == '-') return bad_kind(key, "a non-negative integer");
    uint64_t v = 0;
    for (size_t i = 0; i < p->vlen; i++) {
        const unsigned d = (unsigned)(p->val[i] - '0');
        if (v > (UINT64_MAX - d) / 10) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s out of range", key);
            return -1;
        }
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}

static int get_i64(const struct obj *o, const char *key, int64_t *out) {
    const struct pair *p = lex_get(o, key);
    if (p == NULL) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: missing %s", key);
        return -1;
    }
    if (p->kind != V_INT) return bad_kind(key, "an integer");
    const bool neg = p->val[0] == '-';
    uint64_t mag = 0;
    for (size_t i = neg ? 1 : 0; i < p->vlen; i++) {
        const unsigned d = (unsigned)(p->val[i] - '0');
        if (mag > ((uint64_t)INT64_MAX + 1 - d) / 10) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s out of range", key);
            return -1;
        }
        mag = mag * 10 + d;
    }
    if (!neg && mag > (uint64_t)INT64_MAX) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s out of range", key);
        return -1;
    }
    *out = neg ? (int64_t)(0 - mag) : (int64_t)mag;
    return 0;
}

static int get_u32(const struct obj *o, const char *key, uint32_t *out) {
    uint64_t v;
    if (get_u64(o, key, true, &v, NULL) == -1) return -1;
    if (v > 0xffffffffu) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s out of range", key);
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

/* A flag is either absent or exactly `true`; the parser already rejects
 * `false`, `null`, quoted forms and anything else. */
static int get_flag(const struct obj *o, const char *key, bool *out) {
    const struct pair *p = lex_get(o, key);
    *out = false;
    if (p == NULL) return 0;
    if (p->kind != V_TRUE) return bad_kind(key, "exactly true");
    *out = true;
    return 0;
}

/* Reads a byte string stored as JSON `key` or base64 `key_b64`, enforcing the
 * writer's choice: `key` only for valid UTF-8, `key_b64` only for anything
 * else. One encoding per byte string, never two. NUL bytes are rejected: they
 * cannot occur in a path or link target, and the lexical path functions
 * cannot see past one (§5.1.1). */
static int get_bytes(const struct obj *o, const char *key, const char *key_b64,
                     char *out, size_t cap, size_t *outlen, bool *present) {
    const struct pair *pj = lex_get(o, key);
    const struct pair *pb = lex_get(o, key_b64);
    *present = false;
    if (pj != NULL && pb != NULL) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: both %s and %s", key, key_b64);
        return -1;
    }
    if (pj != NULL) {
        if (pj->kind != V_STR) return bad_kind(key, "a string");
        if (lex_decode_string(pj->val, pj->vlen, out, cap - 1, outlen) == -1) return -1;
        if (memchr(out, '\0', *outlen) != NULL) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s contains a NUL byte", key);
            return -1;
        }
        if (!belay_utf8_valid(out, *outlen)) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s is not UTF-8 (would be %s)", key, key_b64);
            return -1;
        }
    } else if (pb != NULL) {
        if (pb->kind != V_STR) return bad_kind(key_b64, "a string");
        char b64[8192];
        if (pb->vlen >= sizeof b64) return lex_corrupt("base64 value too long");
        memcpy(b64, pb->val, pb->vlen);   /* base64 alphabet needs no unescaping */
        b64[pb->vlen] = '\0';
        if (belay_base64_decode(out, cap - 1, outlen, b64) == -1) return -1;
        if (memchr(out, '\0', *outlen) != NULL) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s contains a NUL byte", key_b64);
            return -1;
        }
        if (belay_utf8_valid(out, *outlen)) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s is valid UTF-8 (would be %s)", key_b64, key);
            return -1;
        }
    } else {
        return 0;
    }
    out[*outlen] = '\0';
    *present = true;
    return 0;
}

static int get_hex64(const struct obj *o, const char *key, char out[65], bool *present) {
    const struct pair *p = lex_get(o, key);
    *present = (p != NULL);
    if (p == NULL) return 0;
    if (p->kind != V_STR || p->vlen != BELAY_SHA256_HEX_LEN) return bad_kind(key, "64 lowercase hex");
    for (size_t i = 0; i < p->vlen; i++)
        if (!lex_is_lhex(p->val[i])) return bad_kind(key, "64 lowercase hex");
    memcpy(out, p->val, 64);
    out[64] = '\0';
    return 0;
}

/*
 *  Extended metadata. Each "xattrs" element is "<name>=<sha256 of value>":
 *  the name as itself when it is printable ASCII without '"', '\\' or '='
 *  and does not start "x:", otherwise "x:" + its bytes in hex -- one
 *  spelling per name, never escaped. Sorted strictly by name bytes; the
 *  file capability is never in the list (it has its own field, "caps").
 */
static int hexval(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; }

static bool plain_xname(const char *n, size_t l) {
    if (l == 0 || (l >= 2 && n[0] == 'x' && n[1] == ':')) return false;
    for (size_t i = 0; i < l; i++) {
        const unsigned char c = (unsigned char)n[i];
        if (c < 0x21 || c > 0x7e || c == '"' || c == '\\' || c == '=') return false;
    }
    return true;
}

static int parse_xattrs(const struct pair *p, struct belay_entry *e) {
    if (p->kind != V_ARR || p->nelem == 0) return bad_kind("xattrs", "a non-empty array");
    if (p->vlen > BELAY_XATTRS_INLINE_MAX) return lex_corrupt("xattrs longer than the inline limit");
    char prev[256], cur[256];
    size_t prev_len = 0;
    bool have_prev = false;
    const char *q = p->val, *end = p->val + p->vlen;
    while (q < end) {
        if (*q == ',') q++;
        if (q >= end || *q != '"') return lex_corrupt("malformed xattrs element");
        const char *b = ++q;
        while (q < end && *q != '"') {
            if (*q == '\\') return lex_corrupt("escape in an xattrs element");
            q++;
        }
        if (q >= end) return lex_corrupt("malformed xattrs element");
        const char *el_end = q++;                     /* past the closing quote */
        const char *eq = el_end - 1 - BELAY_SHA256_HEX_LEN;
        if (eq < b + 1 || *eq != '=') return lex_corrupt("xattrs element is not name=sha256");
        for (const char *h = eq + 1; h < el_end; h++)
            if (hexval(*h) < 0) return lex_corrupt("xattrs element is not name=sha256");
        const size_t raw = (size_t)(eq - b);
        size_t cl;
        if (raw >= 2 && b[0] == 'x' && b[1] == ':') {
            const size_t hx = raw - 2;
            if (hx == 0 || hx % 2 || hx / 2 > 255) return lex_corrupt("bad hex xattr name");
            cl = hx / 2;
            for (size_t i = 0; i < cl; i++) {
                const int hi = hexval(b[2 + 2 * i]), lo = hexval(b[3 + 2 * i]);
                if (hi < 0 || lo < 0) return lex_corrupt("bad hex xattr name");
                cur[i] = (char)(hi * 16 + lo);
                if (cur[i] == '\0') return lex_corrupt("NUL in an xattr name");
            }
            if (plain_xname(cur, cl)) return lex_corrupt("xattr name hex-encoded but printable");
        } else {
            if (raw > 255 || !plain_xname(b, raw)) return lex_corrupt("bad xattr name");
            cl = raw;
            memcpy(cur, b, cl);
        }
        if (cl == 19 && memcmp(cur, "security.capability", 19) == 0)
            return lex_corrupt("security.capability belongs in caps, not xattrs");
        if (have_prev) {
            const size_t m = prev_len < cl ? prev_len : cl;
            const int c = memcmp(prev, cur, m);
            if (c > 0 || (c == 0 && prev_len >= cl)) return lex_corrupt("xattrs not strictly sorted");
        }
        memcpy(prev, cur, cl);
        prev_len = cl;
        have_prev = true;
    }
    /* The digest of the canonical set is the digest of this array body:
     * what the writer records instead when the set is too large to inline. */
    struct belay_sha256 h;
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_init(&h);
    belay_sha256_update(&h, p->val, p->vlen);
    belay_sha256_final(&h, d);
    belay_hex_encode(e->xattrs_sha256_hex, d, sizeof d);
    memcpy(e->xattrs, p->val, p->vlen);
    e->xattrs[p->vlen] = '\0';
    e->xattrs_len = p->vlen;
    e->xattrs_inline = true;
    e->has_xattrs = true;
    return 0;
}

/* "caps": the raw security.capability value, lowercase hex, even length. */
static int get_caps(const struct obj *o, const char *key, struct belay_entry *e) {
    const struct pair *c = lex_get(o, key);
    if (c == NULL) return 0;
    if (c->kind != V_STR || c->vlen == 0 || c->vlen % 2 || c->vlen >= sizeof e->caps_hex)
        return bad_kind(key, "lowercase hex");
    for (size_t i = 0; i < c->vlen; i++)
        if (hexval(c->val[i]) < 0) return bad_kind(key, "lowercase hex");
    memcpy(e->caps_hex, c->val, c->vlen);
    e->caps_hex[c->vlen] = '\0';
    e->has_caps = true;
    return 0;
}

/*
 *  Entry paths are relative, with no empty, "." or ".." component, except
 *  that the scope root itself is exactly ".". A non-canonical path is a
 *  second key for the same file; ".." or an absolute path becomes an
 *  arbitrary write the moment anything restores from a manifest.
 */
static int check_canonical(const char *path, size_t len) {
    if (len == 1 && path[0] == '.') return 0;
    if (path[0] == '/') return lex_corrupt("entry path is absolute");
    size_t i = 0;
    while (i <= len) {
        size_t j = i;
        while (j < len && path[j] != '/') j++;
        const size_t n = j - i;
        if (n == 0) return lex_corrupt("entry path has an empty component");
        if (n == 1 && path[i] == '.') return lex_corrupt("entry path has a \".\" component");
        if (n == 2 && path[i] == '.' && path[i + 1] == '.')
            return lex_corrupt("entry path contains a \"..\" component");
        i = j + 1;
    }
    return 0;
}

static int type_from(const struct pair *p, enum belay_entry_type *t) {
    if (p->kind != V_STR) return bad_kind("type", "a string");
    for (int i = 0; i < ENTRY_TYPE_COUNT; i++) {
        const char *n = ENTRY_TYPES[i].name;
        if (strlen(n) == p->vlen && memcmp(n, p->val, p->vlen) == 0) {
            *t = (enum belay_entry_type)i;
            return 0;
        }
    }
    belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: unknown type \"%.*s\"", (int)p->vlen, p->val);
    return -1;
}

/* One schema field from the line into `e`. The mirror of serialize.c's
 * put_field: every case of enum entry_field, no default. */
static int decode_field(const struct obj *o, enum entry_field f, struct belay_entry *e) {
    const char *k = ENTRY_FIELDS[f].name, *alt = ENTRY_FIELDS[f].alt;
    bool have;
    switch (f) {
    case F_PATH:
        if (get_bytes(o, k, alt, e->path, sizeof e->path, &e->path_len, &have) == -1) return -1;
        if (!have) return lex_corrupt("entry has no path");
        if (e->path_len == 0) return lex_corrupt("empty path");
        return check_canonical(e->path, e->path_len);
    case F_TYPE: {
        const struct pair *tp = lex_get(o, k);
        if (tp == NULL) return lex_corrupt("entry has no type");
        return type_from(tp, &e->type);
    }
    case F_MODE:  return get_u32(o, k, &e->mode);
    case F_UID:   return get_u32(o, k, &e->uid);
    case F_GID:   return get_u32(o, k, &e->gid);
    case F_SIZE:  return get_u64(o, k, true, &e->size, NULL);
    case F_MTIME: return get_i64(o, k, &e->mtime_ns);
    case F_CTIME: return get_i64(o, k, &e->ctime_ns);
    case F_INO:   return get_u64(o, k, true, &e->ino, NULL);
    case F_DEV:   return get_u64(o, k, true, &e->dev, NULL);
    case F_NLINK: return get_u64(o, k, true, &e->nlink, NULL);
    case F_IFLAGS: return get_u64(o, k, false, &e->iflags, &e->has_iflags);
    case F_CAPS:  return get_caps(o, k, e);
    case F_XATTRS: {
        const struct pair *x = lex_get(o, k);
        return x != NULL ? parse_xattrs(x, e) : 0;
    }
    case F_XATTRS_SHA256: {
        char digest[65];
        if (get_hex64(o, k, digest, &have) == -1) return -1;
        if (have && lex_get(o, ENTRY_FIELDS[F_XATTRS].name) == NULL) {
            /* both forms: the schema rejects it */
            memcpy(e->xattrs_sha256_hex, digest, sizeof digest);
            e->has_xattrs = true;
        }
        return 0;
    }
    case F_XATTRS_UNKNOWN: return get_flag(o, k, &e->xattrs_unknown);
    case F_SHA256:
        if (get_hex64(o, k, e->sha256_hex, &have) == -1) return -1;
        e->has_hash = have;
        return 0;
    case F_UNVERIFIED: return get_flag(o, k, &e->unverified);
    case F_UNSTABLE:   return get_flag(o, k, &e->unstable);
    case F_RDEV:
        if (get_u64(o, k, false, &e->rdev, &have) == -1) return -1;
        e->has_rdev = have;
        return 0;
    case F_LINK_TARGET:
        if (get_bytes(o, k, alt, e->link_target, sizeof e->link_target, &e->link_target_len,
                      &have) == -1)
            return -1;
        e->has_link_target = have;
        return 0;
    case F_TARGET_OUTSIDE: return get_flag(o, k, &e->target_outside_scope);
    case F_STORED:
        if (get_hex64(o, k, e->stored_hex, &have) == -1) return -1;
        e->has_stored = have;
        return 0;
    case F_MOUNT:      return get_flag(o, k, &e->is_mount);
    case F_UNREADABLE: return get_flag(o, k, &e->unreadable);
    case F_RACED:      return get_flag(o, k, &e->raced);
    case F_COUNT:      break;
    }
    return lex_corrupt("internal error: no decoder for a field");
}

const enum entry_field DECODE_ORDER[F_COUNT] = {
    F_PATH, F_TYPE, F_MODE, F_UID, F_GID, F_SIZE, F_INO, F_DEV, F_NLINK, F_MTIME, F_CTIME,
    F_SHA256, F_STORED, F_UNVERIFIED, F_UNSTABLE, F_TARGET_OUTSIDE, F_MOUNT, F_UNREADABLE,
    F_RACED, F_RDEV, F_IFLAGS, F_CAPS, F_XATTRS, F_XATTRS_SHA256, F_XATTRS_UNKNOWN,
    F_LINK_TARGET,
};

int decode_entry(const struct obj *o, struct belay_entry *e) {
    memset(e, 0, sizeof *e);
    const char *keys[2 * F_COUNT];
    if (lex_order(o, keys, entry_keys(keys)) == -1) return -1;
    for (size_t i = 0; i < F_COUNT; i++)
        if (decode_field(o, DECODE_ORDER[i], e) == -1) return -1;
    /* Which fields and flags belong to which types -- exactly the
     * combinations the writer can produce, and no others: the schema. */
    return entry_check(e, present_fields(o));
}

int decode_trailer(const struct obj *o, uint64_t v[TR_COUNT]) {
    const char *keys[TR_COUNT];
    for (size_t i = 0; i < TR_COUNT; i++) keys[i] = TRAILER_FIELDS[i].name;
    if (lex_order(o, keys, TR_COUNT) == -1) return -1;
    for (size_t i = 0; i < TR_COUNT; i++)
        if (get_u64(o, keys[i], true, &v[i], NULL) == -1) return -1;
    return 0;
}

int decode_header(const struct obj *o, struct belay_manifest_header *h) {
    memset(h, 0, sizeof *h);
    uint64_t ver;
    bool present;
    if (get_u64(o, HEADER_FIELDS[H_VERSION].name, false, &ver, &present) == -1) return -1;
    if (!present) return lex_corrupt("missing header");
    if (ver != BELAY_MANIFEST_VERSION) {
        /* Refused rather than read: a newer writer may use fields whose
         * absence an older reader would read as "unchanged". */
        belay_err_set(BELAY_ERR_UNSUPPORTED, 0, "manifest: format version %llu, expected %d",
                      (unsigned long long)ver, BELAY_MANIFEST_VERSION);
        return -1;
    }
    h->version = ver;
    const char *keys[2 * H_COUNT];
    if (lex_order(o, keys, header_keys(keys)) == -1) return -1;

    if (get_i64(o, HEADER_FIELDS[H_CREATED].name, &h->created_ns) == -1 ||
        get_u64(o, HEADER_FIELDS[H_HASH_MAX].name, true, &h->hash_max_bytes, NULL) == -1 ||
        get_u64(o, HEADER_FIELDS[H_STORE_MAX].name, true, &h->store_max_bytes, NULL) == -1)
        return -1;

    const struct pair *hp = lex_get(o, HEADER_FIELDS[H_HASH].name);
    if (hp == NULL || hp->kind != V_STR || hp->vlen != 6 || memcmp(hp->val, "sha256", 6) != 0)
        return lex_corrupt("header hash is not sha256");

    /* The scope is what makes two manifests comparable at all. Exactly one in
     * this version, as JSON or (not UTF-8) base64. */
    const char *sk = HEADER_FIELDS[H_SCOPES].name, *sk64 = HEADER_FIELDS[H_SCOPES].alt;
    const struct pair *sj = lex_get(o, sk);
    const struct pair *sb = lex_get(o, sk64);
    if ((sj == NULL) == (sb == NULL)) return lex_corrupt("header needs exactly one of scopes, scopes_b64");
    const struct pair *sp = sj ? sj : sb;
    if (sp->kind != V_ARR) return bad_kind(sj ? sk : sk64, "an array");
    if (sp->nelem != 1) {
        belay_err_set(sp->nelem == 0 ? BELAY_ERR_CORRUPT : BELAY_ERR_UNSUPPORTED, 0,
                      "manifest: header must name exactly one scope");
        return -1;
    }
    /* Element body: the array span is '"' body '"'. */
    struct obj one = { .n = 1 };
    one.p[0] = (struct pair){ .key = sj ? "scope" : "scope_b64", .klen = sj ? 5 : 9,
                              .kind = V_STR, .val = sp->val + 1, .vlen = sp->vlen - 2 };
    size_t slen;
    bool have;
    if (get_bytes(&one, "scope", "scope_b64", h->scope, sizeof h->scope, &slen, &have) == -1)
        return -1;
    if (slen == 0 || h->scope[0] != '/') return lex_corrupt("scope is not an absolute path");
    /* The writer records realpath()'s output: absolute and canonical. "/" is
     * the only scope ending in a slash. */
    if (slen > 1 && check_canonical(h->scope + 1, slen - 1) == -1) {
        belay_err_clear();
        return lex_corrupt("scope is not a canonical absolute path");
    }
    if (slen > 1 && h->scope[1] == '.' && slen == 2) return lex_corrupt("scope is not canonical");
    return 0;
}

