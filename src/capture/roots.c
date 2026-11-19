/*
 *  The roots of a version 5 capture (test/expect/manifest-v5.md): matching a
 *  path against the sorted list a caller gave.
 */
#define _GNU_SOURCE
#include <limits.h>

#include "capture_internal.h"

#include "belay/error.h"
#include "belay/json.h"

#include <string.h>

/* memcmp order of (a, al) against (b, bl) followed by `tail` (0: nothing). */
static int cmp_key(const char *a, size_t al, const char *b, size_t bl, char tail) {
    const size_t m = al < bl ? al : bl;
    const int c = memcmp(a, b, m);
    if (c != 0) return c;
    if (al <= bl) return al < bl || tail ? -1 : 0;
    if (!tail) return 1;
    return (unsigned char)a[bl] < (unsigned char)tail ? -1 : (unsigned char)a[bl] > (unsigned char)tail ? 1
           : al == bl + 1 ? 0 : 1;
}

/* The first root not below `key` + tail in byte order. */
static size_t lower(const struct belay_manifest_opts *o, const char *key, size_t len, char tail) {
    size_t lo = 0, hi = o->n_roots;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        const char *r = o->roots[mid].path;
        if (cmp_key(r, strlen(r), key, len, tail) < 0) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

int roots_match(const struct belay_manifest_opts *o, const char *rel, size_t len, size_t *idx, bool *below) {
    /* Every root below `rel` starts with rel + "/", and they sort together
     * from the first root at or after that key. */
    const size_t b = lower(o, rel, len, '/');
    *below = b < o->n_roots && strlen(o->roots[b].path) > len + 1 && memcmp(o->roots[b].path, rel, len) == 0 &&
             o->roots[b].path[len] == '/';
    const size_t i = lower(o, rel, len, 0);
    if (i < o->n_roots && strlen(o->roots[i].path) == len && memcmp(o->roots[i].path, rel, len) == 0) {
        *idx = i;
        return RM_EXACT;
    }
    return *below ? RM_ABOVE : RM_NONE;
}

bool roots_not_read(const struct belay_manifest_opts *o, const char *rel, size_t len) {
    for (size_t i = 0; i < o->n_not_read; i++)
        if (strlen(o->not_read[i]) == len && memcmp(o->not_read[i], rel, len) == 0) return true;
    return false;
}

static bool canonical(const char *p) {
    if (p == NULL || p[0] == '\0' || p[0] == '/') return false;
    for (const char *c = p; ; ) {
        const char *e = strchr(c, '/');
        const size_t n = e != NULL ? (size_t)(e - c) : strlen(c);
        if (n == 0 || (n == 1 && c[0] == '.') || (n == 2 && c[0] == '.' && c[1] == '.')) return false;
        if (e == NULL) return true;
        c = e + 1;
    }
}

int roots_check(const struct belay_manifest_opts *o) {
    for (size_t i = 0; i < o->n_roots; i++) {
        const char *p = o->roots[i].path;
        if (!canonical(p) || strlen(p) >= PATH_CAP || !belay_utf8_valid(p, strlen(p)) ||
            (i > 0 && strcmp(o->roots[i - 1].path, p) >= 0)) {
            belay_err_set(BELAY_ERR_INVALID, 0, "manifest: the roots are not canonical relative UTF-8 paths, "
                          "sorted, each once (at \"%s\")", p != NULL ? p : "");
            return -1;
        }
    }
    for (size_t i = 0; i < o->n_not_read; i++)
        if (!canonical(o->not_read[i])) {
            belay_err_set(BELAY_ERR_INVALID, 0, "manifest: a not-read path is not a canonical relative path");
            return -1;
        }
    return 0;
}
