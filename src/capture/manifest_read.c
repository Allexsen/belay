/*
 *  Manifest reader.
 *
 *  A strict parser for exactly the language the writer emits; the grammar,
 *  and why it is a grammar rather than a key search, are in manifest_lex.h.
 *
 *  Treat input as hostile: a manifest can be hand-edited, truncated by a full
 *  disk, or crafted. Strictness is the point -- a reader that repairs what it
 *  can lets two different files mean the same thing.
 */
#define _GNU_SOURCE

#include "belay/manifest.h"
#include "capture/entry.h"
#include "capture/manifest_lex.h"
#include "belay/path.h"
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
static const char *const HEADER_ORDER[] = {
    "belay_manifest", "created_ns", "scopes", "scopes_b64", "hash", "hash_max_bytes",
    "store_max_bytes"
};
static const char *const TRAILER_ORDER[] = {
    "belay_manifest_end", "vanished", "unreadable", "unstable", "mounts", "raced"
};

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

static int parse_extras(const struct obj *o, struct belay_entry *e) {
    if (get_u64(o, "iflags", false, &e->iflags, &e->has_iflags) == -1) return -1;
    const struct pair *c = lex_get(o, "caps");
    if (c != NULL) {
        if (c->kind != V_STR || c->vlen == 0 || c->vlen % 2 || c->vlen >= sizeof e->caps_hex)
            return bad_kind("caps", "lowercase hex");
        for (size_t i = 0; i < c->vlen; i++)
            if (hexval(c->val[i]) < 0) return bad_kind("caps", "lowercase hex");
        memcpy(e->caps_hex, c->val, c->vlen);
        e->caps_hex[c->vlen] = '\0';
        e->has_caps = true;
    }
    const struct pair *x = lex_get(o, "xattrs");
    bool have_digest;
    if (x != NULL && parse_xattrs(x, e) == -1) return -1;
    char digest[65];
    if (get_hex64(o, "xattrs_sha256", digest, &have_digest) == -1) return -1;
    if (have_digest && x == NULL) {         /* both forms: the schema rejects it */
        memcpy(e->xattrs_sha256_hex, digest, sizeof digest);
        e->has_xattrs = true;
    }
    return get_flag(o, "xattrs_unknown", &e->xattrs_unknown);
}

/* ------------------------------------------------------------------------ */
/* Semantic layer                                                            */
/* ------------------------------------------------------------------------ */

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

static int parse_entry(const struct obj *o, struct belay_entry *e) {
    memset(e, 0, sizeof *e);
    const char *keys[2 * F_COUNT];
    if (lex_order(o, keys, entry_keys(keys)) == -1) return -1;

    bool have_path;
    if (get_bytes(o, "path", "path_b64", e->path, sizeof e->path, &e->path_len, &have_path) == -1)
        return -1;
    if (!have_path) return lex_corrupt("entry has no path");
    if (e->path_len == 0) return lex_corrupt("empty path");
    if (check_canonical(e->path, e->path_len) == -1) return -1;

    const struct pair *tp = lex_get(o, "type");
    if (tp == NULL) return lex_corrupt("entry has no type");
    if (type_from(tp, &e->type) == -1) return -1;

    if (get_u32(o, "mode", &e->mode) == -1 || get_u32(o, "uid", &e->uid) == -1 ||
        get_u32(o, "gid", &e->gid) == -1 ||
        get_u64(o, "size", true, &e->size, NULL) == -1 ||
        get_u64(o, "ino", true, &e->ino, NULL) == -1 ||
        get_u64(o, "dev", true, &e->dev, NULL) == -1 ||
        get_u64(o, "nlink", true, &e->nlink, NULL) == -1 ||
        get_i64(o, "mtime_ns", &e->mtime_ns) == -1 ||
        get_i64(o, "ctime_ns", &e->ctime_ns) == -1)
        return -1;


    bool have_sha, have_stored, have_target;
    if (get_hex64(o, "sha256", e->sha256_hex, &have_sha) == -1) return -1;
    if (get_hex64(o, "stored", e->stored_hex, &have_stored) == -1) return -1;
    e->has_hash = have_sha;
    e->has_stored = have_stored;

    if (get_flag(o, "unverified", &e->unverified) == -1 ||
        get_flag(o, "unstable", &e->unstable) == -1 ||
        get_flag(o, "target_outside_scope", &e->target_outside_scope) == -1 ||
        get_flag(o, "mount", &e->is_mount) == -1 ||
        get_flag(o, "unreadable", &e->unreadable) == -1 ||
        get_flag(o, "raced", &e->raced) == -1)
        return -1;

    bool have_rdev;
    if (get_u64(o, "rdev", false, &e->rdev, &have_rdev) == -1) return -1;
    e->has_rdev = have_rdev;
    if (parse_extras(o, e) == -1) return -1;

    if (get_bytes(o, "link_target", "link_target_b64", e->link_target, sizeof e->link_target,
                  &e->link_target_len, &have_target) == -1)
        return -1;
    e->has_link_target = have_target;

    /* Which fields and flags belong to which types -- exactly the
     * combinations the writer can produce, and no others: the schema. */
    return entry_check(e, present_fields(o));
}

static int parse_header(const struct obj *o, struct belay_manifest_header *h) {
    memset(h, 0, sizeof *h);
    uint64_t ver;
    bool present;
    if (get_u64(o, "belay_manifest", false, &ver, &present) == -1) return -1;
    if (!present) return lex_corrupt("missing header");
    if (ver != BELAY_MANIFEST_VERSION) {
        /* Refused rather than read: a newer writer may use fields whose
         * absence an older reader would read as "unchanged". */
        belay_err_set(BELAY_ERR_UNSUPPORTED, 0, "manifest: format version %llu, expected %d",
                      (unsigned long long)ver, BELAY_MANIFEST_VERSION);
        return -1;
    }
    h->version = ver;
    if (lex_order(o, HEADER_ORDER, sizeof HEADER_ORDER / sizeof HEADER_ORDER[0]) == -1) return -1;

    if (get_i64(o, "created_ns", &h->created_ns) == -1 ||
        get_u64(o, "hash_max_bytes", true, &h->hash_max_bytes, NULL) == -1 ||
        get_u64(o, "store_max_bytes", true, &h->store_max_bytes, NULL) == -1)
        return -1;

    const struct pair *hp = lex_get(o, "hash");
    if (hp == NULL || hp->kind != V_STR || hp->vlen != 6 || memcmp(hp->val, "sha256", 6) != 0)
        return lex_corrupt("header hash is not sha256");

    /* The scope is what makes two manifests comparable at all. Exactly one in
     * this version, as JSON or (not UTF-8) base64. */
    const struct pair *sj = lex_get(o, "scopes");
    const struct pair *sb = lex_get(o, "scopes_b64");
    if ((sj == NULL) == (sb == NULL)) return lex_corrupt("header needs exactly one of scopes, scopes_b64");
    const struct pair *sp = sj ? sj : sb;
    if (sp->kind != V_ARR) return bad_kind(sj ? "scopes" : "scopes_b64", "an array");
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

/* ------------------------------------------------------------------------ */
/* Iterator                                                                  */
/* ------------------------------------------------------------------------ */

/*
 *  Directories recorded but not descended (unreadable, or a mount point):
 *  nothing may appear below them.
 *
 *  Entries are strictly sorted, so a sealed directory D can still have an
 *  entry below it only while the reader sits between D and D + "/" -- and
 *  every path in that range starts with D. ("D!x" sorts there too, which is
 *  why D cannot be dropped at its first non-descendant.) So the sealed
 *  directories still open are all prefixes of the previous path, a stack of
 *  their lengths is enough, and lengths strictly increase up the stack: at
 *  most one per byte of a path, however many directories the manifest seals.
 *  (The first version kept every sealed path: memory grew with the manifest,
 *  and scanning the list made 40k sealed directories take 1.9 s.)
 */
#define SEALED_MAX 4096     /* > the longest path, so the stack cannot fill */

struct belay_manifest_reader {
    FILE  *f;
    char  *line;            /* LINE_MAX_BYTES + 1 */
    size_t len;
    size_t lineno;
    int    state;           /* 0 open, 1 ended cleanly, -1 failed (sticky) */

    struct belay_manifest_header header;
    struct belay_manifest_stats  trailer;
    bool   have_trailer;

    size_t n_entries, n_unreadable, n_unstable, n_mounts, n_raced;
    bool   have_root;
    bool   root_unreadable;

    char   prev[4096];
    size_t prev_len;
    bool   have_prev;

    size_t sealed[SEALED_MAX];  /* lengths of sealed prefixes of prev */
    size_t n_sealed;
};

const struct belay_manifest_header *
belay_manifest_header(const struct belay_manifest_reader *r) {
    return r == NULL ? NULL : &r->header;
}

const struct belay_manifest_stats *
belay_manifest_trailer(const struct belay_manifest_reader *r) {
    return (r != NULL && r->have_trailer) ? &r->trailer : NULL;
}

static void err_at_line(size_t lineno) {
    char msg[600];
    snprintf(msg, sizeof msg, "%s (line %zu)", belay_err_msg(), lineno);
    belay_err_set(belay_err_code(), belay_err_errno(), "%s", msg);
}

void belay_manifest_close(struct belay_manifest_reader *r) {
    if (r == NULL) return;
    if (r->f != NULL) fclose(r->f);
    free(r->line);
    free(r);
}

int belay_manifest_open(const char *path, struct belay_manifest_reader **out) {
    if (path == NULL || out == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_open: null argument");
        return -1;
    }
    *out = NULL;

    struct belay_manifest_reader *r = calloc(1, sizeof *r);
    if (r == NULL || (r->line = malloc(LINE_MAX_BYTES + 1)) == NULL) {
        free(r);
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        return -1;
    }
    r->f = fopen(path, "rb");
    if (r->f == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot open %s", path);
        belay_manifest_close(r);
        return -1;
    }

    const int got = lex_line(r->f, r->line, &r->len, &r->lineno);
    if (got == -1) { belay_manifest_close(r); return -1; }
    if (got == 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: file is empty");
        belay_manifest_close(r);
        return -1;
    }
    struct obj o;
    if (lex_object(r->line, r->len, &o) == -1 || parse_header(&o, &r->header) == -1) {
        err_at_line(r->lineno);
        belay_manifest_close(r);
        return -1;
    }
    *out = r;
    return 0;
}

static int fail(struct belay_manifest_reader *r) {
    err_at_line(r->lineno);
    r->state = -1;
    return -1;
}

static int parse_trailer(struct belay_manifest_reader *r, const struct obj *o) {
    if (lex_order(o, TRAILER_ORDER, sizeof TRAILER_ORDER / sizeof TRAILER_ORDER[0]) == -1) return -1;
    enum { N = sizeof TRAILER_ORDER / sizeof TRAILER_ORDER[0] };
    uint64_t v[N];
    for (size_t i = 0; i < N; i++)
        if (get_u64(o, TRAILER_ORDER[i], true, &v[i], NULL) == -1) return -1;
    if (v[0] != r->n_entries || v[2] != r->n_unreadable || v[3] != r->n_unstable ||
        v[4] != r->n_mounts || v[5] != r->n_raced) {
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "manifest: trailer says %llu entries / %llu unreadable / %llu unstable / "
                      "%llu mounts / %llu raced, read %zu / %zu / %zu / %zu / %zu",
                      (unsigned long long)v[0], (unsigned long long)v[2],
                      (unsigned long long)v[3], (unsigned long long)v[4],
                      (unsigned long long)v[5], r->n_entries, r->n_unreadable,
                      r->n_unstable, r->n_mounts, r->n_raced);
        return -1;
    }
    if (!r->have_root) return lex_corrupt("no entry for the scope root \".\"");
    /* An unreadable root was not walked, so it is the only entry. Checked here
     * rather than per entry because names sorting before "." (such as "!x")
     * are read before the root itself. */
    if (r->root_unreadable && r->n_entries != 1)
        return lex_corrupt("entries recorded under an unreadable scope root");
    r->trailer.entries    = (size_t)v[0];
    r->trailer.vanished   = (size_t)v[1];
    r->trailer.unreadable = (size_t)v[2];
    r->trailer.unstable   = (size_t)v[3];
    r->trailer.mounts     = (size_t)v[4];
    r->trailer.raced    = (size_t)v[5];
    return 0;
}

int belay_manifest_next(struct belay_manifest_reader *r, struct belay_entry *e) {
    if (r == NULL || e == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_next: null argument");
        return -1;
    }
    if (r->state != 0) return r->state == 1 ? 0 : -1;

    const int got = lex_line(r->f, r->line, &r->len, &r->lineno);
    if (got == -1) { r->state = -1; return -1; }
    if (got == 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "manifest: no end marker after %zu entries (truncated?)", r->n_entries);
        r->state = -1;
        return -1;
    }

    struct obj o;
    if (r->len == 0) { lex_corrupt("blank line"); return fail(r); }
    if (lex_object(r->line, r->len, &o) == -1) return fail(r);

    if (lex_get(&o, "belay_manifest_end") != NULL) {
        if (parse_trailer(r, &o) == -1) return fail(r);
        const int more = lex_line(r->f, r->line, &r->len, &r->lineno);
        if (more != 0) {
            if (more == 1) lex_corrupt("data after the end marker");
            r->state = -1;
            return -1;
        }
        r->have_trailer = true;
        r->state = 1;
        return 0;
    }

    if (parse_entry(&o, e) == -1) return fail(r);
    if (entry_check_header(&r->header, e) == -1) return fail(r);

    /* Strictly increasing raw-path order: the comparator merges two
     * manifests and would mis-pair out-of-order or duplicated entries. */
    size_t common = 0;          /* length of the prefix shared with prev */
    if (r->have_prev) {
        const size_t n = r->prev_len < e->path_len ? r->prev_len : e->path_len;
        while (common < n && r->prev[common] == e->path[common]) common++;
        const bool greater = common < n
            ? (unsigned char)r->prev[common] < (unsigned char)e->path[common]
            : r->prev_len < e->path_len;
        if (!greater) {
            lex_corrupt(common == n && r->prev_len == e->path_len ? "duplicate path"
                                                               : "entries out of order");
            return fail(r);
        }
    }
    memcpy(r->prev, e->path, e->path_len);
    r->prev_len = e->path_len;
    r->have_prev = true;

    /* Nothing below a directory that was not descended -- the writer never
     * emits such an entry, and one appearing would contradict the flag that
     * tells the comparator "contents unknown". A sealed prefix longer than
     * the shared one is behind us for good. One of exactly the shared length
     * is a prefix of this path: the byte after it decides -- '/' is an entry
     * below it, above '/' is past its range, below '/' (as in "d!x") is
     * neither. Shorter ones are untouched: this path agrees with prev there. */
    while (r->n_sealed > 0 && r->sealed[r->n_sealed - 1] > common) r->n_sealed--;
    if (r->n_sealed > 0 && r->sealed[r->n_sealed - 1] == common) {
        const unsigned char next = (unsigned char)e->path[common];
        if (next == '/') {
            lex_corrupt("entry below an unreadable or mounted directory");
            return fail(r);
        }
        if (next > '/') r->n_sealed--;
    }
    /* "." is not a prefix of the paths below it; an unreadable root is
     * checked at the trailer instead (it must be the only entry). */
    if (e->type == BELAY_T_DIR && (e->unreadable || e->is_mount) &&
        !(e->path_len == 1 && e->path[0] == '.')) {
        if (r->n_sealed == SEALED_MAX) {        /* unreachable: see SEALED_MAX */
            lex_corrupt("too many nested sealed directories");
            return fail(r);
        }
        r->sealed[r->n_sealed++] = e->path_len;
    }

    if (e->path_len == 1 && e->path[0] == '.') {
        if (e->type != BELAY_T_DIR) { lex_corrupt("scope root is not a directory"); return fail(r); }
        if (e->is_mount) { lex_corrupt("scope root flagged as a mount"); return fail(r); }
        r->have_root = true;
        r->root_unreadable = e->unreadable;
    }
    r->n_entries++;
    if (e->unreadable) r->n_unreadable++;
    if (e->unstable)   r->n_unstable++;
    if (e->is_mount)   r->n_mounts++;
    if (e->raced)    r->n_raced++;
    return 1;
}

int belay_manifest_read(const char *path, belay_entry_fn fn, void *ctx) {
    if (path == NULL || fn == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_read: null argument");
        return -1;
    }
    struct belay_manifest_reader *r;
    if (belay_manifest_open(path, &r) == -1) return -1;

    struct belay_entry *e = malloc(sizeof *e);
    if (e == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        belay_manifest_close(r);
        return -1;
    }
    /* `got` is the iterator's status; `rc` is what this returns. Kept apart
     * so a callback stopping the walk with 1 is passed through. */
    int rc = 0, got;
    while ((got = belay_manifest_next(r, e)) == 1) {
        const int c = fn(e, ctx);
        if (c != 0) { rc = c; break; }
    }
    if (got == -1) rc = -1;
    free(e);
    belay_manifest_close(r);
    return rc;
}
