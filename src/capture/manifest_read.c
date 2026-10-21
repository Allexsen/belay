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

static int parse_header(const char *line) {
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
    return 0;
}

static int parse_entry(const char *line, struct belay_entry *e) {
    memset(e, 0, sizeof *e);

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

    /*
     *  Entry paths are relative to the scope root and must stay inside it.
     *  Rejecting ".." and absolute paths here is defence in depth: M1 only
     *  reads, but the moment anything restores from a manifest, an accepted
     *  "../../etc/passwd" is an arbitrary write. Found by independent review
     *  (§0.4b) -- and the same hidden-".." risk the NUL rule exists to stop.
     */
    if (e->path[0] == '/') {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: entry path is absolute");
        return -1;
    }
    for (size_t i = 0; i < e->path_len; i++) {
        if (e->path[i] != '.') continue;
        const bool at_start = (i == 0) || (e->path[i - 1] == '/');
        if (!at_start) continue;
        if (i + 1 < e->path_len && e->path[i + 1] == '.' &&
            (i + 2 == e->path_len || e->path[i + 2] == '/')) {
            belay_err_set(BELAY_ERR_CORRUPT, 0,
                          "manifest: entry path contains a \"..\" component");
            return -1;
        }
    }

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

    e->unverified = (strstr(line, "\"unverified\":true") != NULL);

    /* A hash and the unverified flag are mutually exclusive by construction;
     * both present means the file was edited or written by something else. */
    if (e->has_hash && e->unverified) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: both sha256 and unverified");
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

    e->target_outside_scope = (strstr(line, "\"target_outside_scope\":true") != NULL);
    e->is_mount             = (strstr(line, "\"mount\":true") != NULL);
    e->unreadable           = (strstr(line, "\"unreadable\":true") != NULL);

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
};

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

    int got;
    while ((got = next_line(r)) == 1 && r->line[0] == '\0') { /* skip blank */ }
    if (got == -1) { belay_manifest_close(r); return -1; }
    if (got == 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: file is empty");
        belay_manifest_close(r);
        return -1;
    }
    if (parse_header(r->line) == -1) {
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

    for (;;) {
        const int got = next_line(r);
        if (got == -1) { r->state = -1; return -1; }
        if (got == 0)  { r->state = 1;  return 0; }
        if (r->line[0] == '\0') continue;   /* tolerate a blank line */

        if (parse_entry(r->line, e) == -1) {
            err_at_line(r->lineno);
            r->state = -1;
            return -1;
        }
        return 1;
    }
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
