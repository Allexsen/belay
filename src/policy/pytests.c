#include "policy/pytests.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "schema/policy_schema.h"

static const char *name_of(const char *p, size_t n, size_t *nl) {
    size_t i = n;
    while (i > 0 && p[i - 1] != '/') i--;
    *nl = n - i;
    return p + i;
}

static bool has(const char *s, size_t n, const char *sub) {
    const size_t l = strlen(sub);
    for (size_t i = 0; i + l <= n; i++)
        if (memcmp(s + i, sub, l) == 0) return true;
    return false;
}

bool test_file(const char *path, size_t n) {
    size_t i = 0;
    while (i < n) {
        const char *sl = memchr(path + i, '/', n - i);
        const size_t e = sl != NULL ? (size_t)(sl - path) : n, l = e - i;
        const char *c = path + i;
        if ((l == 4 && memcmp(c, "test", 4) == 0) || (l == 5 && memcmp(c, "tests", 5) == 0) ||
            (l == 4 && memcmp(c, "spec", 4) == 0) || (l == 9 && memcmp(c, "__tests__", 9) == 0))
            return true;
        i = e + 1;
    }
    size_t nl;
    const char *nm = name_of(path, n, &nl);
    return (nl >= 5 && memcmp(nm, "test_", 5) == 0) || has(nm, nl, "_test.") || has(nm, nl, ".test.") ||
           has(nm, nl, ".spec.");
}

bool py_test_file(const char *path, size_t n) {
    size_t nl;
    const char *nm = name_of(path, n, &nl);
    return test_file(path, n) && nl > 3 && memcmp(nm + nl - 3, ".py", 3) == 0 &&
           !(nl == 11 && memcmp(nm, "conftest.py", 11) == 0);
}

static bool ident(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

/* Occurrences of `pre` followed by identifier characters and '(' (or, with
 * `bare`, of `pre` followed directly by '('). */
static long calls(const char *s, size_t n, const char *pre, bool bare) {
    const size_t l = strlen(pre);
    long k = 0;
    for (size_t i = 0; i + l <= n; i++) {
        if (memcmp(s + i, pre, l) != 0 || (i > 0 && ident(s[i - 1]))) continue;
        size_t j = i + l;
        if (!bare)
            while (j < n && ident(s[j])) j++;
        if (j < n && s[j] == '(') k++;
    }
    return k;
}

static bool starts(const char *s, size_t n, const char *pre) {
    const size_t l = strlen(pre);
    return n >= l && memcmp(s, pre, l) == 0;
}

int pycount(const char *buf, size_t len, struct pycount *out) {
    memset(out, 0, sizeof *out);
    size_t i = 0, cap = 0;
    while (i < len) {
        const char *nlp = memchr(buf + i, '\n', len - i);
        const size_t e = nlp != NULL ? (size_t)(nlp - buf) : len;
        const char *l = buf + i;
        size_t ll = e - i;
        i = e + 1;
        while (ll > 0 && (*l == ' ' || *l == '\t')) l++, ll--;
        while (ll > 0 && (l[ll - 1] == ' ' || l[ll - 1] == '\t' || l[ll - 1] == '\r')) ll--;
        if (ll == 0 || *l == '#') continue;
        if (starts(l, ll, "assert") && (ll == 6 || l[6] == ' ' || l[6] == '(' || l[6] == '\t')) out->assertions++;
        out->assertions += calls(l, ll, "self.assert", false) + calls(l, ll, "pytest.raises", true) +
                           calls(l, ll, "pytest.approx", true) + calls(l, ll, "np.testing.assert_", false);
        if (starts(l, ll, "def test_") || starts(l, ll, "async def test_")) out->tests++;
        const bool marker = starts(l, ll, "@pytest.mark.skip") || starts(l, ll, "@pytest.mark.xfail") ||
                            starts(l, ll, "@unittest.skip") || calls(l, ll, "pytest.skip", true) > 0 ||
                            calls(l, ll, "pytest.xfail", true) > 0;
        if (!marker) continue;
        if (out->n_markers == cap) {
            cap = cap ? 2 * cap : 8;
            char **m = realloc(out->markers, cap * sizeof *m);
            if (m == NULL) {
                pycount_free(out);
                return -1;
            }
            out->markers = m;
        }
        size_t keep = ll < POLICY_STRING_MAX ? ll : POLICY_STRING_MAX;
        while (keep < ll && keep > 0 && ((unsigned char)l[keep] & 0xC0) == 0x80) keep--;   /* a whole character */
        char *c = malloc(keep + 1);
        if (c == NULL) {
            pycount_free(out);
            return -1;
        }
        memcpy(c, l, keep);
        c[keep] = '\0';
        out->markers[out->n_markers++] = c;
    }
    return 0;
}

void pycount_free(struct pycount *c) {
    for (size_t i = 0; i < c->n_markers; i++) free(c->markers[i]);
    free(c->markers);
    memset(c, 0, sizeof *c);
}

size_t pymarkers_added(const struct pycount *before, const struct pycount *after, const char **out, size_t max) {
    bool used[4096] = { false };
    size_t k = 0;
    for (size_t i = 0; i < after->n_markers && k < max; i++) {
        bool matched = false;
        for (size_t j = 0; j < before->n_markers && j < sizeof used / sizeof used[0] && !matched; j++)
            if (!used[j] && strcmp(before->markers[j], after->markers[i]) == 0) used[j] = matched = true;
        if (!matched) out[k++] = after->markers[i];
    }
    return k;
}

enum pyc_kind pyc_kind_of(const char *path, size_t n) {
    size_t nl;
    const char *nm = name_of(path, n, &nl);
    if (nl == 10 && memcmp(nm, "pytest.ini", 10) == 0) return PYC_PYTEST_INI;
    if (nl == 7 && memcmp(nm, "tox.ini", 7) == 0) return PYC_TOX_INI;
    if (nl == 9 && memcmp(nm, "setup.cfg", 9) == 0) return PYC_SETUP_CFG;
    if (nl == 14 && memcmp(nm, "pyproject.toml", 14) == 0) return PYC_PYPROJECT;
    return PYC_NONE;
}

/* A header line ("[name]", blanks around), its name (between the brackets,
 * "[[x]]" taken as "x"). */
static bool header(const char *l, size_t ll, const char **nm, size_t *nn) {
    while (ll > 0 && (*l == ' ' || *l == '\t')) l++, ll--;
    while (ll > 0 && (l[ll - 1] == ' ' || l[ll - 1] == '\t' || l[ll - 1] == '\r')) ll--;
    if (ll < 2 || l[0] != '[' || l[ll - 1] != ']') return false;
    size_t s = 1, e = ll - 1;
    if (ll >= 4 && l[1] == '[' && l[ll - 2] == ']') s = 2, e = ll - 2;
    *nm = l + s;
    *nn = e - s;
    return true;
}

static bool wanted(enum pyc_kind k, const char *nm, size_t nn) {
    if (k == PYC_TOX_INI) return nn == 6 && memcmp(nm, "pytest", 6) == 0;
    if (k == PYC_SETUP_CFG) return nn == 11 && memcmp(nm, "tool:pytest", 11) == 0;
    return k == PYC_PYPROJECT && nn >= 11 && memcmp(nm, "tool.pytest", 11) == 0;
}

/* The text of section `name` in buf: from its header line to the next
 * header (the first such section); NULL when absent. */
static const char *section(enum pyc_kind k, const char *buf, size_t len, const char *name, size_t nlen, size_t *sl) {
    const char *start = NULL;
    size_t i = 0;
    while (buf != NULL && i < len) {
        const char *nlp = memchr(buf + i, '\n', len - i);
        const size_t e = nlp != NULL ? (size_t)(nlp - buf) : len;
        const char *nm;
        size_t nn;
        if (header(buf + i, e - i, &nm, &nn)) {
            if (start != NULL) {
                *sl = (size_t)(buf + i - start);
                return start;
            }
            if (wanted(k, nm, nn) && nn == nlen && memcmp(nm, name, nn) == 0) start = buf + i;
        }
        i = e + 1;
    }
    if (start != NULL) *sl = (size_t)(buf + len - start);
    return start;
}

static bool first_diff(enum pyc_kind k, const char *x, size_t xl, const char *a, size_t al, const char *b, size_t bl,
                       char *out, size_t cap) {
    size_t i = 0;
    while (x != NULL && i < xl) {
        const char *nlp = memchr(x + i, '\n', xl - i);
        const size_t e = nlp != NULL ? (size_t)(nlp - x) : xl;
        const char *nm;
        size_t nn;
        if (header(x + i, e - i, &nm, &nn) && wanted(k, nm, nn)) {
            size_t sa = 0, sb = 0;
            const char *ta = section(k, a, al, nm, nn, &sa), *tb = section(k, b, bl, nm, nn, &sb);
            if ((ta == NULL) != (tb == NULL) || sa != sb || (ta != NULL && memcmp(ta, tb, sa) != 0)) {
                const bool dbl = (size_t)(nm - (x + i)) >= 2 && nm[-1] == '[' && nm[-2] == '[';
                snprintf(out, cap, dbl ? "[[%.*s]]" : "[%.*s]", (int)nn, nm);
                return true;
            }
        }
        i = e + 1;
    }
    return false;
}

bool pyc_differs(enum pyc_kind kind, const char *a, size_t al, const char *b, size_t bl, char *sec, size_t cap) {
    if (kind == PYC_PYTEST_INI) {
        if (a != NULL && b != NULL && al == bl && memcmp(a, b, al) == 0) return false;
        snprintf(sec, cap, "pytest.ini");
        return true;
    }
    /* each section before has its counterpart after, or none; then those only after */
    return first_diff(kind, a, al, a, al, b, bl, sec, cap) || first_diff(kind, b, bl, a, al, b, bl, sec, cap);
}
