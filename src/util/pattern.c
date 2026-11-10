#include "util/pattern.h"

#include <string.h>

struct comp { const char *s; size_t n; };

#define COMPS_MAX (PATTERN_MAX / 2 + 1)    /* a path of 4,096 bytes has no more */

/* The components of `p`, at most `max`; (size_t)-1 when there are more. */
static size_t split(const char *p, size_t n, struct comp *out, size_t max) {
    size_t k = 0, i = 0;
    while (i <= n) {
        const char *sl = i < n ? memchr(p + i, '/', n - i) : NULL;
        const size_t e = sl != NULL ? (size_t)(sl - p) : n;
        if (k == max) return (size_t)-1;
        out[k++] = (struct comp){ p + i, e - i };
        if (sl == NULL) break;
        i = e + 1;
    }
    return k;
}

bool pattern_valid(const char *p, size_t n) {
    if (n == 0 || n > PATTERN_MAX || memchr(p, '\0', n) != NULL) return false;
    if (p[0] == '/' || p[n - 1] == '/') return false;
    size_t i = 0;
    while (i < n) {
        const char *sl = memchr(p + i, '/', n - i);
        const size_t e = sl != NULL ? (size_t)(sl - p) : n;
        const size_t l = e - i;
        if (l == 0 || (l == 1 && p[i] == '.') || (l == 2 && p[i] == '.' && p[i + 1] == '.')) return false;
        i = e + 1;
    }
    return true;
}

static bool is_globstar(struct comp c) { return c.n == 2 && c.s[0] == '*' && c.s[1] == '*'; }

size_t pattern_globstars(const char *p, size_t n) {
    size_t k = 0, i = 0;
    while (i < n) {
        const char *sl = memchr(p + i, '/', n - i);
        const size_t e = sl != NULL ? (size_t)(sl - p) : n;
        if (is_globstar((struct comp){ p + i, e - i })) k++;
        i = e + 1;
    }
    return k;
}

static bool same(char a, char b, unsigned sw) {
    if (a == b) return true;
    if (!(sw & PATTERN_NOCASE)) return false;
    if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
    if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
    return a == b;
}

/* One component against one pattern component: `*` any run of bytes, the
 * rest themselves; without PATTERN_DOTS, a name starting with '.' only by
 * a pattern component that starts with '.' itself (PS-P4). */
static bool comp_match(struct comp pc, struct comp c, unsigned sw) {
    if (!(sw & PATTERN_DOTS) && c.n > 0 && c.s[0] == '.' && (pc.n == 0 || pc.s[0] != '.')) return false;
    size_t pi = 0, si = 0, star = (size_t)-1, mark = 0;
    while (si < c.n) {
        if (pi < pc.n && pc.s[pi] == '*') {
            star = pi++;
            mark = si;
        } else if (pi < pc.n && same(pc.s[pi], c.s[si], sw)) {
            pi++;
            si++;
        } else if (star != (size_t)-1) {
            pi = star + 1;
            si = ++mark;
        } else {
            return false;
        }
    }
    while (pi < pc.n && pc.s[pi] == '*') pi++;
    return pi == pc.n;
}

/* The pattern positions live once `path`'s components are consumed: a
 * `**` takes any number of whole components (PS-P2), none starting with
 * '.' unless PATTERN_DOTS (PS-P4). `live` has room for the pattern's
 * components + 1. *above: the pattern was matched whole by a proper prefix
 * of the path. false when either cannot be split. */
static bool run(const char *pat, size_t plen, const char *path, size_t n, unsigned sw, bool *live, size_t *np,
                bool *above) {
    static _Thread_local struct comp pc[COMPS_MAX], sc[COMPS_MAX];
    static _Thread_local bool next[COMPS_MAX + 1];
    const size_t P = split(pat, plen, pc, COMPS_MAX);
    const size_t S = n == 0 ? 0 : split(path, n, sc, COMPS_MAX);
    *above = false;
    if (P == (size_t)-1 || S == (size_t)-1) return false;
    memset(live, 0, P + 1);
    live[0] = true;
    for (size_t i = 0; i < P && live[i] && is_globstar(pc[i]); i++) live[i + 1] = true;
    for (size_t k = 0; k < S; k++) {
        if (live[P]) *above = true;
        memset(next, 0, P + 1);
        bool any = false;
        for (size_t i = 0; i < P; i++) {
            if (!live[i]) continue;
            if (is_globstar(pc[i])) {
                if ((sw & PATTERN_DOTS) || (sc[k].n > 0 && sc[k].s[0] != '.')) next[i] = any = true;
            } else if (comp_match(pc[i], sc[k], sw)) {
                next[i + 1] = any = true;
            }
        }
        for (size_t i = 0; i < P; i++)          /* a `**` also takes none */
            if (next[i] && is_globstar(pc[i])) next[i + 1] = true;
        memcpy(live, next, P + 1);
        if (!any) break;
    }
    *np = P;
    return true;
}

unsigned pattern_match(const char *pat, size_t plen, const char *path, size_t n, unsigned sw) {
    static _Thread_local bool live[COMPS_MAX + 1];
    size_t P;
    bool above;
    if (!run(pat, plen, path, n, sw, live, &P, &above)) return 0;
    return (live[P] ? PATTERN_SELF : 0u) | (above ? PATTERN_ABOVE : 0u);
}

bool pattern_covers(const char *pat, size_t plen, const char *dir, size_t n, unsigned sw) {
    static _Thread_local bool live[COMPS_MAX + 1];
    size_t P;
    bool above;
    if (!run(pat, plen, dir, n, sw, live, &P, &above)) return false;
    for (size_t i = 0; i <= P; i++)
        if (live[i]) return true;
    return false;
}
