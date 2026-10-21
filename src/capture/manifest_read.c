/*
 *  Manifest reader.
 *
 *  Parses only belay's own NDJSON (docs/spec/manifest-v1.md), not general
 *  JSON: a full parser would be a far larger attack surface than this needs.
 *  The input is nonetheless treated as untrusted -- a manifest can be
 *  hand-edited, truncated by a full disk, or corrupted -- so every field is
 *  bounds-checked and every malformed form is a hard error rather than a
 *  best-effort guess.
 *
 *  Strictness is the point. A reader that repairs what it can would let two
 *  different files mean the same thing, and `diff` would report a delta that
 *  never happened.
 */
#define _GNU_SOURCE

#include "belay/manifest.h"
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Finds "key": and returns a pointer just past the colon, or NULL. Matches
 * only at a key position (preceded by '{' or ','), so a value containing the
 * literal text of a key name cannot be mistaken for that key. */
static const char *find_key(const char *line, const char *key) {
    char pat[64];
    const int n = snprintf(pat, sizeof pat, "\"%s\":", key);
    if (n < 0 || (size_t)n >= sizeof pat) return NULL;

    const char *p = line;
    while ((p = strstr(p, pat)) != NULL) {
        if (p != line) {
            /* Walk back over whitespace to the structural character. */
            const char *q = p - 1;
            while (q > line && (*q == ' ' || *q == '\t')) q--;
            if (*q == '{' || *q == ',') return p + n;
        }
        p += n;
    }
    return NULL;
}

/*
 *  Reads a JSON string value into `out`, unescaping. `*out_len` receives the
 *  byte count; the result is also NUL-terminated for convenience, but
 *  `*out_len` is the authority because a path is a byte string.
 *
 *  Rejects: a missing opening quote, an unterminated string, an unknown escape,
 *  a malformed \u sequence, and -- per §5.1.1 -- a decoded NUL byte.
 */
static int read_str(const char *p, char *out, size_t outsz, size_t *out_len,
                    const char *what) {
    if (*p != '"') {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s is not a string", what);
        return -1;
    }
    p++;

    size_t w = 0;
    while (*p != '"') {
        if (*p == '\0' || *p == '\n') {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: unterminated %s", what);
            return -1;
        }
        if (w + 1 >= outsz) {
            belay_err_set(BELAY_ERR_RANGE, 0, "manifest: %s exceeds %zu bytes", what, outsz);
            return -1;
        }

        if (*p != '\\') {
            out[w++] = *p++;
            continue;
        }

        p++;   /* past the backslash */
        switch (*p) {
        case '"':  out[w++] = '"';  p++; break;
        case '\\': out[w++] = '\\'; p++; break;
        case '/':  out[w++] = '/';  p++; break;
        case 'b':  out[w++] = '\b'; p++; break;
        case 'f':  out[w++] = '\f'; p++; break;
        case 'n':  out[w++] = '\n'; p++; break;
        case 'r':  out[w++] = '\r'; p++; break;
        case 't':  out[w++] = '\t'; p++; break;
        case 'u': {
            p++;
            unsigned v = 0;
            for (int i = 0; i < 4; i++) {
                const char c = p[i];
                unsigned d;
                if (c >= '0' && c <= '9')      d = (unsigned)(c - '0');
                else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A' + 10);
                else {
                    belay_err_set(BELAY_ERR_CORRUPT, 0,
                                  "manifest: malformed \\u escape in %s", what);
                    return -1;
                }
                v = v * 16 + d;
            }
            p += 4;

            /* The writer only ever emits \u00XX for control bytes, so a value
             * above 0xFF did not come from belay. Rejecting rather than
             * transcoding keeps the reader's accepted language exactly equal
             * to the writer's output language. */
            if (v > 0xff) {
                belay_err_set(BELAY_ERR_CORRUPT, 0,
                              "manifest: \\u%04x out of range in %s", v, what);
                return -1;
            }
            out[w++] = (char)v;
            break;
        }
        default:
            belay_err_set(BELAY_ERR_CORRUPT, 0,
                          "manifest: unknown escape \\%c in %s", *p, what);
            return -1;
        }
    }

    out[w] = '\0';
    *out_len = w;
    return 0;
}

/* Reads an unsigned integer. Rejects a missing digit, a sign, and overflow:
 * strtoull would otherwise silently saturate at ULLONG_MAX. */
static int read_u64(const char *p, uint64_t *out, const char *what) {
    if (*p < '0' || *p > '9') {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s is not a number", what);
        return -1;
    }
    errno = 0;
    char *end = NULL;
    const unsigned long long v = strtoull(p, &end, 10);
    if (errno == ERANGE) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s out of range", what);
        return -1;
    }
    if (end == p) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s has no digits", what);
        return -1;
    }
    *out = (uint64_t)v;
    return 0;
}

static int read_i64(const char *p, int64_t *out, const char *what) {
    errno = 0;
    char *end = NULL;
    const long long v = strtoll(p, &end, 10);
    if (errno == ERANGE) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s out of range", what);
        return -1;
    }
    if (end == p) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s is not a number", what);
        return -1;
    }
    *out = (int64_t)v;
    return 0;
}

static int type_from_name(const char *s, enum belay_entry_type *out) {
    if (strcmp(s, "reg") == 0)  { *out = BELAY_T_REG;  return 0; }
    if (strcmp(s, "dir") == 0)  { *out = BELAY_T_DIR;  return 0; }
    if (strcmp(s, "lnk") == 0)  { *out = BELAY_T_LNK;  return 0; }
    if (strcmp(s, "fifo") == 0) { *out = BELAY_T_FIFO; return 0; }
    if (strcmp(s, "sock") == 0) { *out = BELAY_T_SOCK; return 0; }
    if (strcmp(s, "blk") == 0)  { *out = BELAY_T_BLK;  return 0; }
    if (strcmp(s, "chr") == 0)  { *out = BELAY_T_CHR;  return 0; }
    belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: unknown type \"%s\"", s);
    return -1;
}

/* A NUL anywhere in a decoded path is a hard error (§5.1.1). The lexical path
 * functions take NUL-terminated strings and cannot see an interior NUL, so a
 * truncation here would silently discard whatever followed -- including a
 * "..". This reader holds a length, so this is where the check belongs. */
static int reject_nul(const char *buf, size_t len, const char *what) {
    if (memchr(buf, '\0', len) != NULL) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s contains a NUL byte", what);
        return -1;
    }
    return 0;
}

/* Occurrences of "key": at a key position. */
static int count_key(const char *line, const char *key) {
    int n = 0;
    const char *p = line;
    char pat[64];
    const int plen = snprintf(pat, sizeof pat, "\"%s\":", key);
    while ((p = strstr(p, pat)) != NULL) {
        if (p != line && (p[-1] == '{' || p[-1] == ',')) n++;
        p += plen;
    }
    return n;
}

/*
 *  A duplicated key is rejected rather than resolved: "first wins" would let
 *  two different lines mean the same thing, and an appended second value
 *  would silently override nothing.
 */
static int reject_duplicate_keys(const char *line, const char *const *keys, size_t nkeys) {
    for (size_t i = 0; i < nkeys; i++) {
        if (count_key(line, keys[i]) > 1) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: duplicate key \"%s\"", keys[i]);
            return -1;
        }
    }
    return 0;
}

/*
 *  Boolean flags are spelled exactly `"key":true`. Anything else under that
 *  key -- `: true`, `false`, `1` -- is an error, NOT "flag absent". Before
 *  this, `"unreadable": true` with one space parsed as readable, so an
 *  unreadable directory whose subtree is absent read as an empty one.
 */
static int read_flag(const char *line, const char *key, bool *out) {
    const char *p = find_key(line, key);
    *out = false;
    if (p == NULL) return 0;
    if (strncmp(p, "true", 4) == 0 && (p[4] == ',' || p[4] == '}')) {
        *out = true;
        return 0;
    }
    belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: flag \"%s\" is not exactly true", key);
    return -1;
}

/*
 *  Entry paths must be in the one canonical form the writer produces:
 *  relative, no empty component ("a//b", trailing "/"), no "." or ".."
 *  component, except that the scope root itself is exactly ".". A
 *  non-canonical path is a second key for the same file -- "a//b" and "a/b"
 *  would compare as one removed and one added -- and ".." or an absolute path
 *  becomes an arbitrary write the moment anything restores from a manifest.
 */
static int check_canonical(const char *path, size_t len) {
    if (len == 1 && path[0] == '.') return 0;
    if (path[0] == '/') {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: entry path is absolute");
        return -1;
    }
    size_t i = 0;
    while (i <= len) {
        size_t j = i;
        while (j < len && path[j] != '/') j++;
        const size_t n = j - i;
        if (n == 0) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: entry path has an empty component");
            return -1;
        }
        if (n == 1 && path[i] == '.') {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: entry path has a \".\" component");
            return -1;
        }
        if (n == 2 && path[i] == '.' && path[i + 1] == '.') {
            belay_err_set(BELAY_ERR_CORRUPT, 0,
                          "manifest: entry path contains a \"..\" component");
            return -1;
        }
        i = j + 1;
    }
    return 0;
}

static int parse_header(const char *line, struct belay_manifest_header *h) {
    const char *p = find_key(line, "belay_manifest");
    if (p == NULL) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: missing header");
        return -1;
    }
    uint64_t ver = 0;
    if (read_u64(p, &ver, "belay_manifest") == -1) return -1;
    if (ver != BELAY_MANIFEST_VERSION) {
        /* Refusing an unknown version is deliberate: a newer writer may use
         * fields whose absence would be read as "unchanged". */
        belay_err_set(BELAY_ERR_UNSUPPORTED, 0,
                      "manifest: format version %llu, expected %d",
                      (unsigned long long)ver, BELAY_MANIFEST_VERSION);
        return -1;
    }

    static const char *const hkeys[] = {
        "belay_manifest", "created_ns", "scopes", "hash", "hash_max_bytes", "store_max_bytes"
    };
    if (reject_duplicate_keys(line, hkeys, sizeof hkeys / sizeof hkeys[0]) == -1) return -1;

    memset(h, 0, sizeof *h);
    h->version = ver;

    if ((p = find_key(line, "created_ns")) == NULL || read_i64(p, &h->created_ns, "created_ns") == -1 ||
        (p = find_key(line, "hash_max_bytes")) == NULL || read_u64(p, &h->hash_max_bytes, "hash_max_bytes") == -1 ||
        (p = find_key(line, "store_max_bytes")) == NULL || read_u64(p, &h->store_max_bytes, "store_max_bytes") == -1) {
        if (belay_err_code() == BELAY_OK)
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: header is missing a field");
        return -1;
    }

    /* The scope is what makes two manifests comparable at all. Exactly one in
     * this version; several scopes per manifest is not supported yet. */
    p = find_key(line, "scopes");
    if (p == NULL || *p != '[') {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: header has no scopes array");
        return -1;
    }
    size_t slen = 0;
    if (read_str(p + 1, h->scope, sizeof h->scope, &slen, "scope") == -1) return -1;
    if (slen == 0 || reject_nul(h->scope, slen, "scope") == -1 || h->scope[0] != '/') {
        if (belay_err_code() == BELAY_OK)
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: scope is not an absolute path");
        return -1;
    }
    /* Skip past the string to require the array closes after one element. */
    const char *q = p + 2;
    while (*q != '\0' && !(*q == '"' && q[-1] != '\\')) q++;
    if (*q != '"' || q[1] != ']') {
        belay_err_set(BELAY_ERR_UNSUPPORTED, 0, "manifest: more than one scope");
        return -1;
    }
    return 0;
}

static int parse_entry(const char *line, struct belay_entry *e) {
    memset(e, 0, sizeof *e);

    static const char *const ekeys[] = {
        "path", "path_b64", "type", "mode", "uid", "gid", "size", "mtime_ns",
        "ctime_ns", "ino", "dev", "nlink", "sha256", "unverified", "unstable",
        "rdev", "link_target", "link_target_b64", "target_outside_scope",
        "stored", "mount", "unreadable"
    };
    if (reject_duplicate_keys(line, ekeys, sizeof ekeys / sizeof ekeys[0]) == -1) return -1;

    const char *p_path = find_key(line, "path");
    const char *p_b64  = find_key(line, "path_b64");

    if (p_path != NULL && p_b64 != NULL) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: both path and path_b64");
        return -1;
    }

    if (p_path != NULL) {
        if (read_str(p_path, e->path, sizeof e->path, &e->path_len, "path") == -1) return -1;
    } else if (p_b64 != NULL) {
        char b64[8192];
        size_t b64len = 0;
        if (read_str(p_b64, b64, sizeof b64, &b64len, "path_b64") == -1) return -1;
        if (belay_base64_decode(e->path, sizeof e->path, &e->path_len, b64) == -1) return -1;
    } else {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: entry has no path");
        return -1;
    }

    if (e->path_len == 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: empty path");
        return -1;
    }
    if (reject_nul(e->path, e->path_len, "path") == -1) return -1;

    /* Canonical form only (see check_canonical). Found by independent review
     * (§0.4b) for ".." and absolute paths; widened by the defect-class sweep
     * to every non-canonical form. */
    if (check_canonical(e->path, e->path_len) == -1) return -1;

    const char *p = find_key(line, "type");
    if (p == NULL) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: entry has no type");
        return -1;
    }
    char tname[16];
    size_t tlen = 0;
    if (read_str(p, tname, sizeof tname, &tlen, "type") == -1) return -1;
    if (type_from_name(tname, &e->type) == -1) return -1;

    /* Required numeric fields. A missing one is corruption, not a default:
     * defaulting mode to 0 would make a chmod invisible. */
    struct { const char *key; uint64_t *dst; } req[] = {
        { "size",  &e->size  },
        { "ino",   &e->ino   },
        { "dev",   &e->dev   },
        { "nlink", &e->nlink },
    };
    for (size_t i = 0; i < sizeof req / sizeof req[0]; i++) {
        p = find_key(line, req[i].key);
        if (p == NULL) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: missing %s", req[i].key);
            return -1;
        }
        if (read_u64(p, req[i].dst, req[i].key) == -1) return -1;
    }

    struct { const char *key; uint32_t *dst; } req32[] = {
        { "mode", &e->mode },
        { "uid",  &e->uid  },
        { "gid",  &e->gid  },
    };
    for (size_t i = 0; i < sizeof req32 / sizeof req32[0]; i++) {
        p = find_key(line, req32[i].key);
        if (p == NULL) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: missing %s", req32[i].key);
            return -1;
        }
        uint64_t v = 0;
        if (read_u64(p, &v, req32[i].key) == -1) return -1;
        if (v > 0xffffffffu) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s out of range", req32[i].key);
            return -1;
        }
        *req32[i].dst = (uint32_t)v;
    }

    /* Timestamps are signed: a pre-1970 mtime is legal on disk. */
    struct { const char *key; int64_t *dst; } reqt[] = {
        { "mtime_ns", &e->mtime_ns },
        { "ctime_ns", &e->ctime_ns },
    };
    for (size_t i = 0; i < sizeof reqt / sizeof reqt[0]; i++) {
        p = find_key(line, reqt[i].key);
        if (p == NULL) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: missing %s", reqt[i].key);
            return -1;
        }
        if (read_i64(p, reqt[i].dst, reqt[i].key) == -1) return -1;
    }

    /* Optional fields. */
    p = find_key(line, "sha256");
    if (p != NULL) {
        size_t hlen = 0;
        if (read_str(p, e->sha256_hex, sizeof e->sha256_hex, &hlen, "sha256") == -1) return -1;
        if (hlen != BELAY_SHA256_HEX_LEN) {
            belay_err_set(BELAY_ERR_CORRUPT, 0,
                          "manifest: sha256 is %zu hex chars, expected %d",
                          hlen, BELAY_SHA256_HEX_LEN);
            return -1;
        }
        for (size_t i = 0; i < hlen; i++) {
            const char c = e->sha256_hex[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: sha256 is not lowercase hex");
                return -1;
            }
        }
        e->has_hash = true;
    }

    if (read_flag(line, "unverified", &e->unverified) == -1) return -1;
    if (read_flag(line, "unstable", &e->unstable) == -1) return -1;

    /* A hash and the unverified flag are mutually exclusive by construction;
     * both present means the file was edited or written by something else. */
    if (e->has_hash && e->unverified) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: both sha256 and unverified");
        return -1;
    }
    /* Unstable means "no trustworthy hash", so it implies unverified. */
    if (e->unstable && !e->unverified) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: unstable without unverified");
        return -1;
    }

    const char *p_lt  = find_key(line, "link_target");
    const char *p_ltb = find_key(line, "link_target_b64");
    if (p_lt != NULL && p_ltb != NULL) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: both link_target forms");
        return -1;
    }
    if (p_lt != NULL) {
        if (read_str(p_lt, e->link_target, sizeof e->link_target,
                     &e->link_target_len, "link_target") == -1) return -1;
        e->has_link_target = true;
    } else if (p_ltb != NULL) {
        char b64[8192];
        size_t b64len = 0;
        if (read_str(p_ltb, b64, sizeof b64, &b64len, "link_target_b64") == -1) return -1;
        if (belay_base64_decode(e->link_target, sizeof e->link_target,
                                &e->link_target_len, b64) == -1) return -1;
        e->has_link_target = true;
    }
    if (e->has_link_target &&
        reject_nul(e->link_target, e->link_target_len, "link_target") == -1) return -1;

    /* A symlink with no target, or a non-symlink with one, is corruption. */
    if (e->type == BELAY_T_LNK && !e->has_link_target) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: symlink without a target");
        return -1;
    }
    if (e->type != BELAY_T_LNK && e->has_link_target) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: non-symlink with a link target");
        return -1;
    }

    if (read_flag(line, "target_outside_scope", &e->target_outside_scope) == -1) return -1;
    if (read_flag(line, "mount", &e->is_mount) == -1) return -1;
    if (read_flag(line, "unreadable", &e->unreadable) == -1) return -1;

    /* Device numbers belong to device nodes, and device nodes must carry one:
     * without it a replaced device or an overlayfs whiteout (char 0,0) would
     * be indistinguishable from the original. */
    p = find_key(line, "rdev");
    const bool is_dev = (e->type == BELAY_T_BLK || e->type == BELAY_T_CHR);
    if (is_dev != (p != NULL)) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, is_dev ? "manifest: device without rdev"
                                                    : "manifest: rdev on a non-device");
        return -1;
    }
    if (p != NULL) {
        if (read_u64(p, &e->rdev, "rdev") == -1) return -1;
        e->has_rdev = true;
    }

    p = find_key(line, "stored");
    if (p != NULL) {
        size_t slen = 0;
        if (read_str(p, e->stored_hex, sizeof e->stored_hex, &slen, "stored") == -1) return -1;
        if (slen != BELAY_SHA256_HEX_LEN) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: stored key is not a sha256");
            return -1;
        }
        e->has_stored = true;
    }

    return 0;
}

/* ------------------------------------------------------------------------ */
/* Pull iterator                                                             */
/* ------------------------------------------------------------------------ */

/*
 *  A pull interface rather than callbacks only, because a diff must advance
 *  two manifests side by side. With callbacks alone one of them would have to
 *  be held in memory, which would throw away the constant-memory merge that
 *  sorted output exists to provide.
 */
struct belay_manifest_reader {
    FILE  *f;
    char  *line;
    size_t cap;
    size_t lineno;
    int    state;       /* 0 open, 1 ended cleanly, -1 failed (sticky) */

    struct belay_manifest_header header;
    struct belay_manifest_stats  trailer;
    bool   have_trailer;

    /* What was actually read, checked against the trailer. */
    size_t n_entries, n_unreadable, n_unstable;

    /* The previous path, for the strict-order check. */
    char   prev[4096];
    size_t prev_len;
    bool   have_prev;
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
 *  The trailer must be the last line and must agree with what was read.
 *  Without it a manifest cut off at a line boundary -- a crash, a full disk --
 *  is indistinguishable from a complete one with fewer entries, and the
 *  missing tail would read as deletions.
 */
static int parse_trailer(struct belay_manifest_reader *r, const char *line) {
    static const char *const tkeys[] = { "belay_manifest_end", "vanished", "unreadable", "unstable" };
    if (reject_duplicate_keys(line, tkeys, sizeof tkeys / sizeof tkeys[0]) == -1) return -1;

    uint64_t v[4];
    for (size_t i = 0; i < 4; i++) {
        const char *p = find_key(line, tkeys[i]);
        if (p == NULL) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: trailer is missing %s", tkeys[i]);
            return -1;
        }
        if (read_u64(p, &v[i], tkeys[i]) == -1) return -1;
    }
    if (v[0] != r->n_entries || v[2] != r->n_unreadable || v[3] != r->n_unstable) {
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "manifest: trailer says %llu entries / %llu unreadable / %llu unstable, "
                      "read %zu / %zu / %zu",
                      (unsigned long long)v[0], (unsigned long long)v[2],
                      (unsigned long long)v[3], r->n_entries, r->n_unreadable, r->n_unstable);
        return -1;
    }
    r->trailer.entries    = (size_t)v[0];
    r->trailer.vanished   = (size_t)v[1];
    r->trailer.unreadable = (size_t)v[2];
    r->trailer.unstable   = (size_t)v[3];
    return 0;
}

/* 1 = line in r->line with the newline stripped, 0 = EOF, -1 = error. */
static int next_line(struct belay_manifest_reader *r) {
    const ssize_t len = getline(&r->line, &r->cap, r->f);
    if (len < 0) {
        if (ferror(r->f)) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: read error");
            return -1;
        }
        return 0;
    }
    r->lineno++;
    /* A line without a terminating newline is a truncated write -- a full
     * disk or a killed process. Accepting it would mean trusting a partial
     * record. */
    if (len == 0 || r->line[len - 1] != '\n') {
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "manifest: line %zu is truncated (no newline)", r->lineno);
        return -1;
    }
    r->line[len - 1] = '\0';
    return 1;
}

/* Appends the line number to the current error, so a corrupt manifest can be
 * located by hand. */
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
    if (r == NULL) {
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
    if (parse_header(r->line, &r->header) == -1) {
        err_at_line(r->lineno);
        belay_manifest_close(r);
        return -1;
    }

    *out = r;
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

    /* The writer never emits a blank line; accepting one would widen the
     * reader's language beyond the writer's. */
    if (r->line[0] == '\0') {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: blank line");
        err_at_line(r->lineno);
        r->state = -1;
        return -1;
    }

    if (find_key(r->line, "belay_manifest_end") != NULL) {
        if (parse_trailer(r, r->line) == -1) {
            err_at_line(r->lineno);
            r->state = -1;
            return -1;
        }
        const int more = next_line(r);
        if (more != 0) {
            if (more == 1)
                belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: data after the end marker");
            r->state = -1;
            return -1;
        }
        r->have_trailer = true;
        r->state = 1;
        return 0;
    }

    if (parse_entry(r->line, e) == -1) {
        err_at_line(r->lineno);
        r->state = -1;
        return -1;
    }

    /*
     *  Strictly increasing raw-path order. The comparator advances two
     *  manifests as a merge; out of order or duplicated entries would be
     *  mis-paired silently. Verified before this check: a manifest listing
     *  "b" before "a", and one listing "a" twice, were both accepted.
     */
    if (r->have_prev) {
        const size_t n = r->prev_len < e->path_len ? r->prev_len : e->path_len;
        const int c = memcmp(r->prev, e->path, n);
        if (c > 0 || (c == 0 && r->prev_len >= e->path_len)) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, c == 0 && r->prev_len == e->path_len
                          ? "manifest: duplicate path" : "manifest: entries out of order");
            err_at_line(r->lineno);
            r->state = -1;
            return -1;
        }
    }
    memcpy(r->prev, e->path, e->path_len);
    r->prev_len = e->path_len;
    r->have_prev = true;

    r->n_entries++;
    if (e->unreadable) r->n_unreadable++;
    if (e->unstable)   r->n_unstable++;
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

    /* `got` is the iterator's status; `rc` is what this function returns.
     * Kept apart so a callback that stops the walk by returning 1 is passed
     * through rather than mistaken for "an entry was read". */
    int rc = 0;
    int got;
    while ((got = belay_manifest_next(r, e)) == 1) {
        const int c = fn(e, ctx);
        if (c != 0) { rc = c; break; }
    }
    if (got == -1) rc = -1;

    free(e);
    belay_manifest_close(r);
    return rc;
}
