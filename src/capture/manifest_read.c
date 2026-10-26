/*
 *  Manifest reader.
 *
 *  A STRICT PARSER for exactly the language the writer emits -- not a JSON
 *  reader, and not a key-searcher. Every line is consumed byte by byte against
 *  the grammar below, and anything else is rejected:
 *
 *    line    := object                     (then end of line)
 *    object  := '{' pair (',' pair)* '}'
 *    pair    := key ':' value              (no whitespace anywhere)
 *    key     := '"' [a-z0-9_]+ '"'
 *    value   := string | integer | 'true' | '[' string (',' string)* ']'
 *    string  := '"' (byte >= 0x20 except '"' '\' | escape)* '"'
 *    escape  := '\"' | '\\' | '\b' | '\f' | '\n' | '\r' | '\t'
 *             | '\u00' hex hex   -- lowercase, only for control bytes that
 *                                   have no short form
 *    integer := '0' | '-'? [1-9][0-9]*     (canonical: no '+', no leading 0)
 *
 *  Why a parser: an earlier version searched each line for the keys it wanted.
 *  Everything it did not look at -- whitespace, junk between fields, junk after
 *  the closing brace, bytes after an embedded NUL -- was silently accepted, so
 *  a flag could be hidden where the search never reached. Independent review
 *  and the defect-class sweep found nineteen such instances between them. A
 *  grammar closes the class instead of the instances: the reader's accepted
 *  language is now exactly the writer's output language, plus unknown keys
 *  (whose values must still be well formed) so the format can grow.
 *
 *  Treat input as hostile: a manifest can be hand-edited, truncated by a full
 *  disk, or crafted. Strictness is the point -- a reader that repairs what it
 *  can lets two different files mean the same thing.
 */
#define _GNU_SOURCE

#include "belay/manifest.h"
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

/* The writer's longest possible line is under 50 KB (two 4095-byte fields at
 * six bytes per escaped byte, plus fixed fields). Anything longer is not a
 * manifest line, and refusing it bounds the reader's memory. */
#define LINE_MAX_BYTES (64u * 1024u)
#define MAX_PAIRS      32

/* st_mode type bits. The values are the same on Linux and macOS, so a
 * manifest written on one validates on the other. */
#define M_IFMT   0170000u
#define M_IFSOCK 0140000u
#define M_IFLNK  0120000u
#define M_IFREG  0100000u
#define M_IFBLK  0060000u
#define M_IFDIR  0040000u
#define M_IFCHR  0020000u
#define M_IFIFO  0010000u

/* ------------------------------------------------------------------------ */
/* Lexical layer                                                             */
/* ------------------------------------------------------------------------ */

enum vkind { V_STR, V_INT, V_TRUE, V_ARR };

struct pair {
    const char *key;  size_t klen;
    enum vkind kind;
    const char *val;  size_t vlen;     /* raw span: string body, digits, or array body */
    size_t nelem;                      /* V_ARR: number of strings */
};

struct obj {
    struct pair p[MAX_PAIRS];
    size_t n;
};

static int corrupt(const char *msg) {
    belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s", msg);
    return -1;
}

static bool is_lhex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
static int  hexv(char c)    { return c <= '9' ? c - '0' : c - 'a' + 10; }

/*
 *  Scans a string body starting just after the opening quote. On success
 *  *end points at the closing quote. Only the escapes the writer produces are
 *  accepted, in the form it produces them, so each byte string has exactly one
 *  encoding.
 */
static int scan_string(const char *s, const char *lim, const char **end) {
    while (s < lim && *s != '"') {
        const unsigned char c = (unsigned char)*s;
        if (c < 0x20) return corrupt("raw control byte in a string");
        if (c != '\\') { s++; continue; }
        if (s + 1 >= lim) return corrupt("unterminated escape");
        switch (s[1]) {
        case '"': case '\\': case 'b': case 'f': case 'n': case 'r': case 't':
            s += 2;
            break;
        case 'u': {
            if (lim - s < 6 || s[2] != '0' || s[3] != '0' || !is_lhex(s[4]) || !is_lhex(s[5]))
                return corrupt("non-canonical \\u escape");
            const int v = hexv(s[4]) * 16 + hexv(s[5]);
            /* \u00XX only for control bytes with no short form. */
            if (v >= 0x20 || v == '\b' || v == '\t' || v == '\n' || v == '\f' || v == '\r')
                return corrupt("non-canonical \\u escape");
            s += 6;
            break;
        }
        default:
            return corrupt("unknown escape in a string");
        }
    }
    if (s >= lim) return corrupt("unterminated string");
    *end = s;
    return 0;
}

/* Decodes a scanned string body into `out` (no NUL appended). */
static int decode_string(const char *s, size_t n, char *out, size_t cap, size_t *outlen) {
    size_t w = 0;
    for (size_t i = 0; i < n; ) {
        if (w >= cap) return corrupt("string value too long");
        if (s[i] != '\\') { out[w++] = s[i++]; continue; }
        switch (s[i + 1]) {
        case '"':  out[w++] = '"';  i += 2; break;
        case '\\': out[w++] = '\\'; i += 2; break;
        case 'b':  out[w++] = '\b'; i += 2; break;
        case 'f':  out[w++] = '\f'; i += 2; break;
        case 'n':  out[w++] = '\n'; i += 2; break;
        case 'r':  out[w++] = '\r'; i += 2; break;
        case 't':  out[w++] = '\t'; i += 2; break;
        default:   out[w++] = (char)(hexv(s[i + 4]) * 16 + hexv(s[i + 5])); i += 6; break;
        }
    }
    *outlen = w;
    return 0;
}

/* Canonical integer: '0' | '-'?[1-9][0-9]*. */
static int scan_int(const char *s, const char *lim, const char **end) {
    const char *p = s;
    if (p < lim && *p == '-') p++;
    if (p >= lim || *p < '0' || *p > '9') return corrupt("malformed number");
    if (*p == '0') {
        p++;
        if (p - s == 2) return corrupt("malformed number");          /* "-0" */
        if (p < lim && *p >= '0' && *p <= '9') return corrupt("number has a leading zero");
    } else {
        while (p < lim && *p >= '0' && *p <= '9') p++;
    }
    *end = p;
    return 0;
}

/* Parses one whole line into `o`. Duplicate keys are rejected. */
static int parse_object(const char *s, size_t len, struct obj *o) {
    const char *p = s, *lim = s + len;
    o->n = 0;
    if (p >= lim || *p != '{') return corrupt("line is not an object");
    p++;

    for (;;) {
        if (o->n == MAX_PAIRS) return corrupt("too many fields");
        struct pair *pr = &o->p[o->n];

        if (p >= lim || *p != '"') return corrupt("expected a key");
        const char *k = ++p;
        while (p < lim && ((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_')) p++;
        if (p == k || p >= lim || *p != '"') return corrupt("malformed key");
        pr->key = k;
        pr->klen = (size_t)(p - k);
        p++;
        if (p >= lim || *p != ':') return corrupt("expected ':' after a key");
        p++;

        if (p < lim && *p == '"') {
            const char *e = p + 1;
            if (scan_string(p + 1, lim, &e) == -1) return -1;
            pr->kind = V_STR;
            pr->val = p + 1;
            pr->vlen = (size_t)(e - (p + 1));
            p = e + 1;
        } else if (p < lim && (*p == '-' || (*p >= '0' && *p <= '9'))) {
            const char *e = p;
            if (scan_int(p, lim, &e) == -1) return -1;
            pr->kind = V_INT;
            pr->val = p;
            pr->vlen = (size_t)(e - p);
            p = e;
        } else if (lim - p >= 4 && memcmp(p, "true", 4) == 0) {
            pr->kind = V_TRUE;
            pr->val = p;
            pr->vlen = 4;
            p += 4;
        } else if (p < lim && *p == '[') {
            pr->kind = V_ARR;
            pr->val = p + 1;
            pr->nelem = 0;
            p++;
            for (;;) {
                if (p >= lim || *p != '"') return corrupt("array element is not a string");
                const char *e;
                if (scan_string(p + 1, lim, &e) == -1) return -1;
                pr->nelem++;
                p = e + 1;
                if (p < lim && *p == ',') { p++; continue; }
                if (p < lim && *p == ']') { p++; break; }
                return corrupt("malformed array");
            }
            pr->vlen = (size_t)(p - 1 - pr->val);
        } else {
            return corrupt("malformed value");
        }

        for (size_t i = 0; i < o->n; i++) {
            if (o->p[i].klen == pr->klen && memcmp(o->p[i].key, pr->key, pr->klen) == 0) {
                belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: duplicate key \"%.*s\"",
                              (int)pr->klen, pr->key);
                return -1;
            }
        }
        o->n++;

        if (p < lim && *p == ',') { p++; continue; }
        if (p < lim && *p == '}') { p++; break; }
        return corrupt("expected ',' or '}'");
    }
    if (p != lim) return corrupt("data after the closing brace");
    return 0;
}

/*
 *  Field order is part of the canonical form: the writer always emits known
 *  keys in the order of `order`, and the reader rejects any other order --
 *  otherwise one entry would have many spellings. Unknown keys (informational
 *  fields a newer writer may add) may only follow every known key.
 */
static int check_order(const struct obj *o, const char *const *order, size_t n) {
    size_t next = 0;               /* index into `order` the next known key must be at or after */
    bool seen_unknown = false;
    for (size_t i = 0; i < o->n; i++) {
        size_t k = n;
        for (size_t j = 0; j < n; j++) {
            if (strlen(order[j]) == o->p[i].klen && memcmp(order[j], o->p[i].key, o->p[i].klen) == 0) {
                k = j;
                break;
            }
        }
        if (k == n) { seen_unknown = true; continue; }
        if (seen_unknown) return corrupt("a known field follows an unknown one");
        if (k < next) return corrupt("fields out of canonical order");
        next = k + 1;
    }
    return 0;
}

static const char *const ENTRY_ORDER[] = {
    "path", "path_b64", "type", "mode", "uid", "gid", "size", "mtime_ns", "ctime_ns",
    "ino", "dev", "nlink", "sha256", "unverified", "unstable", "rdev", "link_target",
    "link_target_b64", "target_outside_scope", "stored", "mount", "unreadable", "raced"
};
static const char *const HEADER_ORDER[] = {
    "belay_manifest", "created_ns", "scopes", "scopes_b64", "hash", "hash_max_bytes",
    "store_max_bytes"
};
static const char *const TRAILER_ORDER[] = {
    "belay_manifest_end", "vanished", "unreadable", "unstable", "mounts", "raced"
};

static const struct pair *get(const struct obj *o, const char *key) {
    const size_t kl = strlen(key);
    for (size_t i = 0; i < o->n; i++)
        if (o->p[i].klen == kl && memcmp(o->p[i].key, key, kl) == 0) return &o->p[i];
    return NULL;
}

static int bad_kind(const char *key, const char *want) {
    belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: \"%s\" must be %s", key, want);
    return -1;
}

/* Field accessors. `required` decides whether absence is an error. */
static int get_u64(const struct obj *o, const char *key, bool required, uint64_t *out, bool *present) {
    const struct pair *p = get(o, key);
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
    const struct pair *p = get(o, key);
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
    const struct pair *p = get(o, key);
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
    const struct pair *pj = get(o, key);
    const struct pair *pb = get(o, key_b64);
    *present = false;
    if (pj != NULL && pb != NULL) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: both %s and %s", key, key_b64);
        return -1;
    }
    if (pj != NULL) {
        if (pj->kind != V_STR) return bad_kind(key, "a string");
        if (decode_string(pj->val, pj->vlen, out, cap - 1, outlen) == -1) return -1;
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
        if (pb->vlen >= sizeof b64) return corrupt("base64 value too long");
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
    const struct pair *p = get(o, key);
    *present = (p != NULL);
    if (p == NULL) return 0;
    if (p->kind != V_STR || p->vlen != BELAY_SHA256_HEX_LEN) return bad_kind(key, "64 lowercase hex");
    for (size_t i = 0; i < p->vlen; i++)
        if (!is_lhex(p->val[i])) return bad_kind(key, "64 lowercase hex");
    memcpy(out, p->val, 64);
    out[64] = '\0';
    return 0;
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
    if (path[0] == '/') return corrupt("entry path is absolute");
    size_t i = 0;
    while (i <= len) {
        size_t j = i;
        while (j < len && path[j] != '/') j++;
        const size_t n = j - i;
        if (n == 0) return corrupt("entry path has an empty component");
        if (n == 1 && path[i] == '.') return corrupt("entry path has a \".\" component");
        if (n == 2 && path[i] == '.' && path[i + 1] == '.')
            return corrupt("entry path contains a \"..\" component");
        i = j + 1;
    }
    return 0;
}

static int type_from(const struct pair *p, enum belay_entry_type *t, uint32_t *ifmt) {
    static const struct { const char *n; enum belay_entry_type t; uint32_t m; } tab[] = {
        { "reg", BELAY_T_REG, M_IFREG }, { "dir", BELAY_T_DIR, M_IFDIR },
        { "lnk", BELAY_T_LNK, M_IFLNK }, { "fifo", BELAY_T_FIFO, M_IFIFO },
        { "sock", BELAY_T_SOCK, M_IFSOCK }, { "blk", BELAY_T_BLK, M_IFBLK },
        { "chr", BELAY_T_CHR, M_IFCHR },
    };
    if (p->kind != V_STR) return bad_kind("type", "a string");
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++) {
        if (strlen(tab[i].n) == p->vlen && memcmp(tab[i].n, p->val, p->vlen) == 0) {
            *t = tab[i].t;
            *ifmt = tab[i].m;
            return 0;
        }
    }
    belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: unknown type \"%.*s\"", (int)p->vlen, p->val);
    return -1;
}

static int parse_entry(const struct obj *o, struct belay_entry *e) {
    memset(e, 0, sizeof *e);
    if (check_order(o, ENTRY_ORDER, sizeof ENTRY_ORDER / sizeof ENTRY_ORDER[0]) == -1) return -1;

    bool have_path;
    if (get_bytes(o, "path", "path_b64", e->path, sizeof e->path, &e->path_len, &have_path) == -1)
        return -1;
    if (!have_path) return corrupt("entry has no path");
    if (e->path_len == 0) return corrupt("empty path");
    if (check_canonical(e->path, e->path_len) == -1) return -1;

    const struct pair *tp = get(o, "type");
    if (tp == NULL) return corrupt("entry has no type");
    uint32_t ifmt = 0;
    if (type_from(tp, &e->type, &ifmt) == -1) return -1;

    if (get_u32(o, "mode", &e->mode) == -1 || get_u32(o, "uid", &e->uid) == -1 ||
        get_u32(o, "gid", &e->gid) == -1 ||
        get_u64(o, "size", true, &e->size, NULL) == -1 ||
        get_u64(o, "ino", true, &e->ino, NULL) == -1 ||
        get_u64(o, "dev", true, &e->dev, NULL) == -1 ||
        get_u64(o, "nlink", true, &e->nlink, NULL) == -1 ||
        get_i64(o, "mtime_ns", &e->mtime_ns) == -1 ||
        get_i64(o, "ctime_ns", &e->ctime_ns) == -1)
        return -1;

    /* The mode's type bits must agree with the declared type. */
    if ((e->mode & M_IFMT) != ifmt) return corrupt("mode's type bits disagree with type");

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

    if (get_bytes(o, "link_target", "link_target_b64", e->link_target, sizeof e->link_target,
                  &e->link_target_len, &have_target) == -1)
        return -1;
    e->has_link_target = have_target;

    /* Which fields and flags belong to which types -- exactly the
     * combinations the writer can produce, and no others. */
    switch (e->type) {
    case BELAY_T_REG:
        /* A hash or "unverified", never both and never neither. */
        if (e->has_hash == e->unverified)
            return corrupt(e->has_hash ? "both sha256 and unverified"
                                       : "regular file with neither sha256 nor unverified");
        if ((e->unstable || e->unreadable) && !e->unverified)
            return corrupt("unstable or unreadable file without unverified");
        if (e->unstable && e->unreadable) return corrupt("file both unstable and unreadable");
        if (e->is_mount && (e->unstable || e->unreadable)) return corrupt("mounted file with read flags");
        break;
    case BELAY_T_DIR:
        if (e->has_hash || e->unverified || e->has_stored)
            return corrupt("hash fields on a directory");
        /* A directory whose listing was recorded and then changed is flagged
         * unstable; raced is only for one recorded without its listing. */
        if (e->raced && !e->unreadable && !e->is_mount)
            return corrupt("raced on a listed directory");
        /* unreadable: contents absent. unstable: listing changed while read.
         * mount: not descended. At most one applies. */
        if ((int)e->unreadable + (int)e->unstable + (int)e->is_mount > 1)
            return corrupt("directory flags unreadable, unstable and mount are exclusive");
        break;
    case BELAY_T_LNK:
        if (e->has_hash || e->unverified || e->has_stored || e->unstable)
            return corrupt("file-only fields on a symlink");
        break;
    default:   /* fifo, socket, block and character devices: nothing is read */
        if (e->has_hash || e->unverified || e->has_stored || e->unstable || e->unreadable)
            return corrupt("read flags on a node that is never read");
        break;
    }
    if (e->has_stored && (!e->has_hash || strcmp(e->stored_hex, e->sha256_hex) != 0))
        return corrupt("stored key does not match sha256");

    const bool is_dev = (e->type == BELAY_T_BLK || e->type == BELAY_T_CHR);
    if (is_dev != e->has_rdev)
        return corrupt(is_dev ? "device without rdev" : "rdev on a non-device");

    if ((e->type == BELAY_T_LNK) != e->has_link_target)
        return corrupt(e->has_link_target ? "non-symlink with a link target"
                                          : "symlink without a target");
    if (e->target_outside_scope && e->type != BELAY_T_LNK)
        return corrupt("target_outside_scope on a non-symlink");
    /* A symlink's size is its target's length; the writer re-stats the link
     * after reading it to guarantee the two belong together. An unreadable
     * link is the exception: its target could not be read reliably, and an
     * empty target (which no real symlink has) means "unknown". */
    if (e->type == BELAY_T_LNK && !e->unreadable) {
        if (e->link_target_len == 0) return corrupt("symlink with an empty target");
        if (e->size != e->link_target_len)
            return corrupt("symlink size disagrees with its target's length");
    }
    if (e->target_outside_scope && e->link_target_len == 0)
        return corrupt("target_outside_scope on an unknown target");

    /* A mount point is recorded, never read: no hash on a mounted file. */
    if (e->is_mount && e->has_hash) return corrupt("hash on a mount point");
    return 0;
}

static int parse_header(const struct obj *o, struct belay_manifest_header *h) {
    memset(h, 0, sizeof *h);
    uint64_t ver;
    bool present;
    if (get_u64(o, "belay_manifest", false, &ver, &present) == -1) return -1;
    if (!present) return corrupt("missing header");
    if (ver != BELAY_MANIFEST_VERSION) {
        /* Refused rather than read: a newer writer may use fields whose
         * absence an older reader would read as "unchanged". */
        belay_err_set(BELAY_ERR_UNSUPPORTED, 0, "manifest: format version %llu, expected %d",
                      (unsigned long long)ver, BELAY_MANIFEST_VERSION);
        return -1;
    }
    h->version = ver;
    if (check_order(o, HEADER_ORDER, sizeof HEADER_ORDER / sizeof HEADER_ORDER[0]) == -1) return -1;

    if (get_i64(o, "created_ns", &h->created_ns) == -1 ||
        get_u64(o, "hash_max_bytes", true, &h->hash_max_bytes, NULL) == -1 ||
        get_u64(o, "store_max_bytes", true, &h->store_max_bytes, NULL) == -1)
        return -1;

    const struct pair *hp = get(o, "hash");
    if (hp == NULL || hp->kind != V_STR || hp->vlen != 6 || memcmp(hp->val, "sha256", 6) != 0)
        return corrupt("header hash is not sha256");

    /* The scope is what makes two manifests comparable at all. Exactly one in
     * this version, as JSON or (not UTF-8) base64. */
    const struct pair *sj = get(o, "scopes");
    const struct pair *sb = get(o, "scopes_b64");
    if ((sj == NULL) == (sb == NULL)) return corrupt("header needs exactly one of scopes, scopes_b64");
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
    if (slen == 0 || h->scope[0] != '/') return corrupt("scope is not an absolute path");
    /* The writer records realpath()'s output: absolute and canonical. "/" is
     * the only scope ending in a slash. */
    if (slen > 1 && check_canonical(h->scope + 1, slen - 1) == -1) {
        belay_err_clear();
        return corrupt("scope is not a canonical absolute path");
    }
    if (slen > 1 && h->scope[1] == '.' && slen == 2) return corrupt("scope is not canonical");
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

/*
 *  Rules that need the header. The writer hashes a regular file exactly when
 *  its size is within hash_max_bytes and nothing else prevents it, and it
 *  computes target_outside_scope from the scope with one shared function, so
 *  both are checked rather than taken on trust: otherwise one state would have
 *  two encodings (review round 3, F7).
 */
static int check_against_header(const struct belay_manifest_header *h,
                                 const struct belay_entry *e) {
    if (e->type == BELAY_T_REG) {
        if (e->has_hash && e->size > h->hash_max_bytes)
            return corrupt("hash on a file larger than hash_max_bytes");
        if (e->unverified && !e->unstable && !e->unreadable && !e->is_mount &&
            e->size <= h->hash_max_bytes)
            return corrupt("unverified file within hash_max_bytes, with no reason");
    }
    if (e->type == BELAY_T_LNK) {
        /* An unreadable link's target is unknown or stale: never annotated. */
        const bool want = !e->unreadable &&
            belay_link_target_outside(h->scope, e->path, e->path_len,
                                      e->link_target, e->link_target_len);
        if (e->target_outside_scope != want)
            return corrupt(want ? "target_outside_scope missing on a link leaving the scope"
                                : "target_outside_scope on a link that stays in the scope");
    }
    return 0;
}

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

/*
 *  Reads one line into r->line. 1 = line (newline stripped), 0 = EOF, -1 =
 *  error. Bounded, and NUL-intolerant: a NUL inside a line would end the
 *  parse early in any C-string consumer and hide what follows it -- verified
 *  with a flag placed after a NUL, which the old reader silently dropped.
 */
static int next_line(struct belay_manifest_reader *r) {
    size_t n = 0;
    int c;
    while ((c = getc(r->f)) != EOF) {
        if (c == '\n') {
            r->line[n] = '\0';
            r->len = n;
            r->lineno++;
            return 1;
        }
        if (c == '\0') {
            r->lineno++;
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: NUL byte in line %zu", r->lineno);
            return -1;
        }
        if (n == LINE_MAX_BYTES) {
            r->lineno++;
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: line %zu exceeds %u bytes",
                          r->lineno, LINE_MAX_BYTES);
            return -1;
        }
        r->line[n++] = (char)c;
    }
    if (ferror(r->f)) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: read error");
        return -1;
    }
    if (n > 0) {
        r->lineno++;
        /* A line without its newline is a truncated write. */
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "manifest: line %zu is truncated (no newline)", r->lineno);
        return -1;
    }
    return 0;
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

    const int got = next_line(r);
    if (got == -1) { belay_manifest_close(r); return -1; }
    if (got == 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: file is empty");
        belay_manifest_close(r);
        return -1;
    }
    struct obj o;
    if (parse_object(r->line, r->len, &o) == -1 || parse_header(&o, &r->header) == -1) {
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
    if (check_order(o, TRAILER_ORDER, sizeof TRAILER_ORDER / sizeof TRAILER_ORDER[0]) == -1) return -1;
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
    if (!r->have_root) return corrupt("no entry for the scope root \".\"");
    /* An unreadable root was not walked, so it is the only entry. Checked here
     * rather than per entry because names sorting before "." (such as "!x")
     * are read before the root itself. */
    if (r->root_unreadable && r->n_entries != 1)
        return corrupt("entries recorded under an unreadable scope root");
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

    const int got = next_line(r);
    if (got == -1) { r->state = -1; return -1; }
    if (got == 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "manifest: no end marker after %zu entries (truncated?)", r->n_entries);
        r->state = -1;
        return -1;
    }

    struct obj o;
    if (r->len == 0) { corrupt("blank line"); return fail(r); }
    if (parse_object(r->line, r->len, &o) == -1) return fail(r);

    if (get(&o, "belay_manifest_end") != NULL) {
        if (parse_trailer(r, &o) == -1) return fail(r);
        const int more = next_line(r);
        if (more != 0) {
            if (more == 1) corrupt("data after the end marker");
            r->state = -1;
            return -1;
        }
        r->have_trailer = true;
        r->state = 1;
        return 0;
    }

    if (parse_entry(&o, e) == -1) return fail(r);
    if (check_against_header(&r->header, e) == -1) return fail(r);

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
            corrupt(common == n && r->prev_len == e->path_len ? "duplicate path"
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
            corrupt("entry below an unreadable or mounted directory");
            return fail(r);
        }
        if (next > '/') r->n_sealed--;
    }
    /* "." is not a prefix of the paths below it; an unreadable root is
     * checked at the trailer instead (it must be the only entry). */
    if (e->type == BELAY_T_DIR && (e->unreadable || e->is_mount) &&
        !(e->path_len == 1 && e->path[0] == '.')) {
        if (r->n_sealed == SEALED_MAX) {        /* unreachable: see SEALED_MAX */
            corrupt("too many nested sealed directories");
            return fail(r);
        }
        r->sealed[r->n_sealed++] = e->path_len;
    }

    if (e->path_len == 1 && e->path[0] == '.') {
        if (e->type != BELAY_T_DIR) { corrupt("scope root is not a directory"); return fail(r); }
        if (e->is_mount) { corrupt("scope root flagged as a mount"); return fail(r); }
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
