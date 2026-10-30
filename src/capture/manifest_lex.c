/*
 *  The manifest's lexical layer (manifest_lex.h): the grammar, and nothing
 *  about fields.
 */
#define _GNU_SOURCE
#include "manifest_lex.h"

#include "belay/error.h"

#include <errno.h>
#include <string.h>

int lex_corrupt(const char *msg) {
    belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s", msg);
    return -1;
}

bool lex_is_lhex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
int  lex_hexv(char c)    { return c <= '9' ? c - '0' : c - 'a' + 10; }

/*
 *  Scans a string body starting just after the opening quote. On success
 *  *end points at the closing quote. Only the escapes the writer produces are
 *  accepted, in the form it produces them, so each byte string has exactly one
 *  encoding.
 */
static int scan_string(const char *s, const char *lim, const char **end) {
    while (s < lim && *s != '"') {
        const unsigned char c = (unsigned char)*s;
        if (c < 0x20) return lex_corrupt("raw control byte in a string");
        if (c != '\\') { s++; continue; }
        if (s + 1 >= lim) return lex_corrupt("unterminated escape");
        switch (s[1]) {
        case '"': case '\\': case 'b': case 'f': case 'n': case 'r': case 't':
            s += 2;
            break;
        case 'u': {
            if (lim - s < 6 || s[2] != '0' || s[3] != '0' || !lex_is_lhex(s[4]) || !lex_is_lhex(s[5]))
                return lex_corrupt("non-canonical \\u escape");
            const int v = lex_hexv(s[4]) * 16 + lex_hexv(s[5]);
            /* \u00XX only for control bytes with no short form. */
            if (v >= 0x20 || v == '\b' || v == '\t' || v == '\n' || v == '\f' || v == '\r')
                return lex_corrupt("non-canonical \\u escape");
            s += 6;
            break;
        }
        default:
            return lex_corrupt("unknown escape in a string");
        }
    }
    if (s >= lim) return lex_corrupt("unterminated string");
    *end = s;
    return 0;
}

/* Decodes a scanned string body into `out` (no NUL appended). */
int lex_decode_string(const char *s, size_t n, char *out, size_t cap, size_t *outlen) {
    size_t w = 0;
    for (size_t i = 0; i < n; ) {
        if (w >= cap) return lex_corrupt("string value too long");
        if (s[i] != '\\') { out[w++] = s[i++]; continue; }
        switch (s[i + 1]) {
        case '"':  out[w++] = '"';  i += 2; break;
        case '\\': out[w++] = '\\'; i += 2; break;
        case 'b':  out[w++] = '\b'; i += 2; break;
        case 'f':  out[w++] = '\f'; i += 2; break;
        case 'n':  out[w++] = '\n'; i += 2; break;
        case 'r':  out[w++] = '\r'; i += 2; break;
        case 't':  out[w++] = '\t'; i += 2; break;
        default:   out[w++] = (char)(lex_hexv(s[i + 4]) * 16 + lex_hexv(s[i + 5])); i += 6; break;
        }
    }
    *outlen = w;
    return 0;
}

/* Canonical integer: '0' | '-'?[1-9][0-9]*. */
static int scan_int(const char *s, const char *lim, const char **end) {
    const char *p = s;
    if (p < lim && *p == '-') p++;
    if (p >= lim || *p < '0' || *p > '9') return lex_corrupt("malformed number");
    if (*p == '0') {
        p++;
        if (p - s == 2) return lex_corrupt("malformed number");          /* "-0" */
        if (p < lim && *p >= '0' && *p <= '9') return lex_corrupt("number has a leading zero");
    } else {
        while (p < lim && *p >= '0' && *p <= '9') p++;
    }
    *end = p;
    return 0;
}

/* Parses one whole line into `o`. Duplicate keys are rejected. */
int lex_object(const char *s, size_t len, struct obj *o) {
    const char *p = s, *lim = s + len;
    o->n = 0;
    if (p >= lim || *p != '{') return lex_corrupt("line is not an object");
    p++;

    for (;;) {
        if (o->n == MAX_PAIRS) return lex_corrupt("too many fields");
        struct pair *pr = &o->p[o->n];

        if (p >= lim || *p != '"') return lex_corrupt("expected a key");
        const char *k = ++p;
        while (p < lim && ((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_')) p++;
        if (p == k || p >= lim || *p != '"') return lex_corrupt("malformed key");
        pr->key = k;
        pr->klen = (size_t)(p - k);
        p++;
        if (p >= lim || *p != ':') return lex_corrupt("expected ':' after a key");
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
                if (p >= lim || *p != '"') return lex_corrupt("array element is not a string");
                const char *e;
                if (scan_string(p + 1, lim, &e) == -1) return -1;
                pr->nelem++;
                p = e + 1;
                if (p < lim && *p == ',') { p++; continue; }
                if (p < lim && *p == ']') { p++; break; }
                return lex_corrupt("malformed array");
            }
            pr->vlen = (size_t)(p - 1 - pr->val);
        } else {
            return lex_corrupt("malformed value");
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
        return lex_corrupt("expected ',' or '}'");
    }
    if (p != lim) return lex_corrupt("data after the closing brace");
    return 0;
}

/*
 *  Field order is part of the canonical form: the writer always emits keys in
 *  the order of `order`, and the reader rejects any other order -- otherwise
 *  one entry would have many spellings. A key not in `order` is rejected
 *  (decided 2026-10-30): a reader that skipped it would read what it means as
 *  absent; the format grows only with a version bump.
 */
int lex_order(const struct obj *o, const char *const *order, size_t n) {
    size_t next = 0;               /* index into `order` the next key must be at or after */
    for (size_t i = 0; i < o->n; i++) {
        size_t k = n;
        for (size_t j = 0; j < n; j++) {
            if (strlen(order[j]) == o->p[i].klen && memcmp(order[j], o->p[i].key, o->p[i].klen) == 0) {
                k = j;
                break;
            }
        }
        if (k == n) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: unknown key \"%.*s\"",
                          (int)o->p[i].klen, o->p[i].key);
            return -1;
        }
        if (k < next) return lex_corrupt("fields out of canonical order");
        next = k + 1;
    }
    return 0;
}

const struct pair *lex_get(const struct obj *o, const char *key) {
    const size_t kl = strlen(key);
    for (size_t i = 0; i < o->n; i++)
        if (o->p[i].klen == kl && memcmp(o->p[i].key, key, kl) == 0) return &o->p[i];
    return NULL;
}


/*
 *  Reads one line into `line`. 1 = line (newline stripped), 0 = EOF, -1 =
 *  error. Bounded, and NUL-intolerant: a NUL inside a line would end the
 *  parse early in any C-string consumer and hide what follows it -- verified
 *  with a flag placed after a NUL, which the old reader silently dropped.
 */
int lex_line(FILE *f, char *line, size_t *len, size_t *lineno) {
    size_t n = 0;
    int c;
    while ((c = getc(f)) != EOF) {
        if (c == '\n') {
            line[n] = '\0';
            *len = n;
            (*lineno)++;
            return 1;
        }
        if (c == '\0') {
            (*lineno)++;
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: NUL byte in line %zu", *lineno);
            return -1;
        }
        if (n == LINE_MAX_BYTES) {
            (*lineno)++;
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: line %zu exceeds %u bytes",
                          *lineno, LINE_MAX_BYTES);
            return -1;
        }
        line[n++] = (char)c;
    }
    if (ferror(f)) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: read error");
        return -1;
    }
    if (n > 0) {
        (*lineno)++;
        /* A line without its newline is a truncated write. */
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "manifest: line %zu is truncated (no newline)", *lineno);
        return -1;
    }
    return 0;
}
