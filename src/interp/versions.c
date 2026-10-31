#include "versions.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ---- Debian: epoch:upstream-revision, deb-version(7) ---- */

static bool is_digit(char c) { return c >= '0' && c <= '9'; }
static bool is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

/* The weight of a non-digit character: '~' before everything, even the end;
 * then the end; then letters; then everything else. */
static int order(const char *s, size_t i, size_t n) {
    if (i >= n) return 0;
    const char c = s[i];
    if (is_digit(c)) return 0;
    if (is_alpha(c)) return (unsigned char)c;
    if (c == '~') return -1;
    return (unsigned char)c + 256;
}

/* dpkg's verrevcmp over [a, a+al) and [b, b+bl). */
static int verrevcmp(const char *a, size_t al, const char *b, size_t bl) {
    size_t i = 0, j = 0;
    while (i < al || j < bl) {
        int first_diff = 0;
        while ((i < al && !is_digit(a[i])) || (j < bl && !is_digit(b[j]))) {
            const int ac = order(a, i, al), bc = order(b, j, bl);
            if (ac != bc) return ac - bc;
            i++;
            j++;
        }
        while (i < al && a[i] == '0') i++;
        while (j < bl && b[j] == '0') j++;
        while (i < al && is_digit(a[i]) && j < bl && is_digit(b[j])) {
            if (!first_diff) first_diff = a[i] - b[j];
            i++;
            j++;
        }
        if (i < al && is_digit(a[i])) return 1;
        if (j < bl && is_digit(b[j])) return -1;
        if (first_diff) return first_diff;
    }
    return 0;
}

struct debv { uint64_t epoch; const char *up; size_t upl; const char *rev; size_t revl; };

static void deb_split(const char *s, size_t n, struct debv *v) {
    const char *colon = memchr(s, ':', n);
    v->epoch = 0;
    if (colon != NULL) {
        for (const char *p = s; p < colon; p++)
            if (is_digit(*p) && v->epoch < UINT64_MAX / 10) v->epoch = v->epoch * 10 + (uint64_t)(*p - '0');
        n -= (size_t)(colon + 1 - s);
        s = colon + 1;
    }
    const char *dash = NULL;
    for (size_t i = n; i > 0; i--)
        if (s[i - 1] == '-') { dash = s + i - 1; break; }
    v->up = s;
    v->upl = dash != NULL ? (size_t)(dash - s) : n;
    v->rev = dash != NULL ? dash + 1 : s + n;
    v->revl = dash != NULL ? n - v->upl - 1 : 0;
}

int debver_cmp(const char *a, size_t al, const char *b, size_t bl) {
    struct debv va, vb;
    deb_split(a, al, &va);
    deb_split(b, bl, &vb);
    if (va.epoch != vb.epoch) return va.epoch < vb.epoch ? -1 : 1;
    const int r = verrevcmp(va.up, va.upl, vb.up, vb.upl);
    if (r != 0) return r;
    return verrevcmp(va.rev, va.revl, vb.rev, vb.revl);
}

/* ---- PEP 440 (packaging's ordering) ---- */

#define PEP_PARTS 32
#define PEP_MAX   255

/* A local part: numeric (sorts after any alphanumeric) or a lowercased string. */
struct lpart { bool num; uint64_t n; const char *s; size_t l; };

struct pepv {
    uint64_t epoch;
    uint64_t rel[PEP_PARTS];
    int nrel;
    int pre_kind;               /* 0 none, 1 a, 2 b, 3 rc */
    uint64_t pre;
    bool has_post, has_dev;
    uint64_t post, dev;
    struct lpart local[PEP_PARTS];
    int nlocal;                 /* -1: no local */
};

static char lower(char c) { return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c; }

static bool take_num(const char *s, size_t n, size_t *i, uint64_t *out) {
    if (*i >= n || !is_digit(s[*i])) return false;
    uint64_t v = 0;
    while (*i < n && is_digit(s[*i])) {
        if (v > (UINT64_MAX - 9) / 10) return false;
        v = v * 10 + (uint64_t)(s[(*i)++] - '0');
    }
    *out = v;
    return true;
}

/* A case-insensitive keyword at s[*i]. */
static bool take_word(const char *s, size_t n, size_t *i, const char *w) {
    const size_t l = strlen(w);
    if (*i + l > n) return false;
    for (size_t k = 0; k < l; k++)
        if (lower(s[*i + k]) != w[k]) return false;
    *i += l;
    return true;
}

static bool sep(const char *s, size_t n, size_t *i) {
    if (*i < n && (s[*i] == '.' || s[*i] == '-' || s[*i] == '_')) { (*i)++; return true; }
    return false;
}

static bool pep_parse(const char *s, size_t n, struct pepv *v) {
    memset(v, 0, sizeof *v);
    v->nlocal = -1;
    if (n == 0 || n > PEP_MAX) return false;
    size_t i = 0;
    if (s[0] == 'v' || s[0] == 'V') i++;
    uint64_t x;
    if (!take_num(s, n, &i, &x)) return false;
    if (i < n && s[i] == '!') {
        v->epoch = x;
        i++;
        if (!take_num(s, n, &i, &x)) return false;
    }
    v->rel[v->nrel++] = x;
    while (i + 1 < n && s[i] == '.' && is_digit(s[i + 1])) {
        if (v->nrel == PEP_PARTS) return false;
        i++;
        take_num(s, n, &i, &v->rel[v->nrel++]);
    }
    /* pre-release: [.-_]?(a|alpha|b|beta|rc|c|pre|preview)[.-_]?N? */
    {
        size_t k = i;
        sep(s, n, &k);
        int kind = 0;
        if (take_word(s, n, &k, "alpha")) kind = 1;
        else if (take_word(s, n, &k, "beta")) kind = 2;
        else if (take_word(s, n, &k, "preview") || take_word(s, n, &k, "pre") ||
                 take_word(s, n, &k, "rc") || take_word(s, n, &k, "c")) kind = 3;
        else if (take_word(s, n, &k, "a")) kind = 1;
        else if (take_word(s, n, &k, "b")) kind = 2;
        if (kind) {
            v->pre_kind = kind;
            size_t m = k;
            sep(s, n, &m);
            if (!take_num(s, n, &m, &v->pre)) v->pre = 0;     /* "2a." is 2a0 (Appendix B) */
            i = m;
        }
    }
    /* post-release: -N, or [.-_]?(post|rev|r)[.-_]?N? */
    {
        size_t k = i;
        if (k < n && s[k] == '-' && k + 1 < n && is_digit(s[k + 1])) {
            k++;
            take_num(s, n, &k, &v->post);
            v->has_post = true;
            i = k;
        } else {
            sep(s, n, &k);
            if (take_word(s, n, &k, "post") || take_word(s, n, &k, "rev") || take_word(s, n, &k, "r")) {
                size_t m = k;
                sep(s, n, &m);
                if (!take_num(s, n, &m, &v->post)) v->post = 0;
                v->has_post = true;
                i = m;
            }
        }
    }
    /* dev-release: [.-_]?dev[.-_]?N? */
    {
        size_t k = i;
        sep(s, n, &k);
        if (take_word(s, n, &k, "dev")) {
            size_t m = k;
            sep(s, n, &m);
            if (!take_num(s, n, &m, &v->dev)) v->dev = 0;
            v->has_dev = true;
            i = m;
        }
    }
    /* local: +[a-z0-9]+([.-_][a-z0-9]+)* */
    if (i < n && s[i] == '+') {
        i++;
        v->nlocal = 0;
        for (;;) {
            const size_t st = i;
            while (i < n && (is_digit(s[i]) || is_alpha(s[i]))) i++;
            if (i == st || v->nlocal == PEP_PARTS) return false;
            struct lpart *p = &v->local[v->nlocal++];
            p->s = s + st;
            p->l = i - st;
            p->num = true;
            for (size_t k = st; k < i; k++) p->num &= is_digit(s[k]);
            if (p->num) {
                size_t k = st;
                if (!take_num(s, n, &k, &p->n)) return false;
            }
            if (i == n) break;
            if (s[i] != '.' && s[i] != '-' && s[i] != '_') return false;
            i++;
        }
    }
    return i == n;
}

static int cmp_u(uint64_t a, uint64_t b) { return a < b ? -1 : a > b; }

/* packaging's _cmpkey, as ranks: pre (-1 = dev-only release, 4 = none),
 * post (-1 = none), dev (none sorts last), local (none sorts first). */
static int pep_order(const struct pepv *a, const struct pepv *b) {
    int r = cmp_u(a->epoch, b->epoch);
    if (r) return r;
    /* A missing release part is 0: 1.0 and 1.0.0 are one version. */
    const int na = a->nrel, nb = b->nrel;
    for (int k = 0; k < (na > nb ? na : nb); k++) {
        r = cmp_u(k < na ? a->rel[k] : 0, k < nb ? b->rel[k] : 0);
        if (r) return r;
    }
    const struct pepv *v[2] = { a, b };
    int prek[2];
    uint64_t pren[2];
    for (int t = 0; t < 2; t++) {
        if (v[t]->pre_kind == 0 && !v[t]->has_post && v[t]->has_dev) { prek[t] = -1; pren[t] = 0; }
        else if (v[t]->pre_kind == 0) { prek[t] = 4; pren[t] = 0; }
        else { prek[t] = v[t]->pre_kind; pren[t] = v[t]->pre; }
    }
    if (prek[0] != prek[1]) return prek[0] < prek[1] ? -1 : 1;
    if ((r = cmp_u(pren[0], pren[1]))) return r;
    if (a->has_post != b->has_post) return a->has_post ? 1 : -1;
    if ((r = cmp_u(a->post, b->post))) return r;
    if (a->has_dev != b->has_dev) return a->has_dev ? -1 : 1;
    if ((r = cmp_u(a->dev, b->dev))) return r;
    if (a->nlocal != b->nlocal && (a->nlocal < 0 || b->nlocal < 0)) return a->nlocal < 0 ? -1 : 1;
    for (int k = 0; k < a->nlocal && k < b->nlocal; k++) {
        const struct lpart *x = &a->local[k], *y = &b->local[k];
        if (x->num != y->num) return x->num ? 1 : -1;
        if (x->num) r = cmp_u(x->n, y->n);
        else {
            for (size_t m = 0; m < x->l && m < y->l && !r; m++)
                r = (unsigned char)lower(x->s[m]) - (unsigned char)lower(y->s[m]);
            if (!r) r = cmp_u(x->l, y->l);
        }
        if (r) return r < 0 ? -1 : 1;
    }
    return a->nlocal < b->nlocal ? -1 : a->nlocal > b->nlocal;
}

int pep440_cmp(const char *a, size_t al, const char *b, size_t bl, int *cmp) {
    struct pepv va, vb;
    if (!pep_parse(a, al, &va) || !pep_parse(b, bl, &vb)) return -1;
    *cmp = pep_order(&va, &vb);
    return 0;
}
