/*
 *  Ownership (system-interpreters.md SI-5): which package's file list names
 *  a path. The paths are asked first; then the manifest's entries are fed
 *  in its order, of which three kinds are looked at -- `var/lib/dpkg/
 *  diversions`, the directory `var/lib/dpkg/info`, and its `*.list` files,
 *  each read once from the store and matched line by line against what was
 *  asked. Memory is the paths asked, the diversions, and one list at a
 *  time: never the lists together.
 *
 *  A path is tried as recorded and with the top-level links (`bin`, `sbin`,
 *  `lib`, `lib32`, `lib64`, `libx32` into `usr`) rewritten each way: 22.04's
 *  lists say `/lib/systemd/system/nginx.service` where a merged-/usr
 *  machine's capture records `usr/lib/...` (measured: the pin's SI-5).
 *  dpkg-divert(1): a diversion is three lines -- the path, where the file of
 *  every package but the diverting one was moved, and that package (`:`
 *  for a local diversion).
 *
 *  Never assumed: with no database (no listed `var/lib/dpkg/info`) nothing
 *  is known; and when a list or the diversions could not be read, a path
 *  found in no other list is not "in no package" either.
 */
#include "lookup_internal.h"
#include "stored.h"

#include "belay/manifest.h"

#include <stdlib.h>
#include <string.h>

#define OWNER_LIST_MAX (64u * 1024u * 1024u)    /* bytes of one list read */
#define OWNER_DIV_MAX  (16u * 1024u * 1024u)    /* bytes of the diversions file */

#define DPKG_DIR  "var/lib/dpkg/info"
#define DPKG_DIVS "var/lib/dpkg/diversions"

struct ostr { char *s; size_t n; };

struct ask { struct ostr path, pkg; bool found; };

enum kmode { K_ANY, K_ONLY, K_NOT };
struct key { struct ostr s; size_t ask; enum kmode mode; struct ostr pkg; };   /* pkg: a diversion's, not owned */

struct divn { struct ostr from, to, pkg; };

struct owners {
    struct ask *a;
    size_t n, cap;
    bool sorted;
    struct key *k;
    size_t nk;
    bool built;
    struct divn *d;
    size_t nd;
    struct divn **by_to;        /* d, by `to` (d itself is sorted by `from`) */
    bool db;                    /* a listed var/lib/dpkg/info was seen */
    bool incomplete;            /* a list or the diversions could not be read */
    bool oom;
};

static int ostr_cmp(struct ostr a, struct ostr b) {
    const int c = memcmp(a.s, b.s, a.n < b.n ? a.n : b.n);
    return c ? c : (a.n > b.n) - (a.n < b.n);
}

static char *dup_n(const char *s, size_t n) {
    char *p = malloc(n + 1);
    if (p == NULL) return NULL;
    if (n) memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

struct owners *owners_new(void) { return calloc(1, sizeof(struct owners)); }

void owners_free(struct owners *o) {
    if (o == NULL) return;
    for (size_t i = 0; i < o->n; i++) { free(o->a[i].path.s); free(o->a[i].pkg.s); }
    for (size_t i = 0; i < o->nk; i++) free(o->k[i].s.s);
    for (size_t i = 0; i < o->nd; i++) { free(o->d[i].from.s); free(o->d[i].to.s); free(o->d[i].pkg.s); }
    free(o->a);
    free(o->k);
    free(o->d);
    free(o->by_to);
    free(o);
}

int owners_ask(struct owners *o, const char *path, size_t len) {
    if (o->built || len == 0 || len > 4096 || o->n >= BELAY_OWNER_ASKS) return 0;   /* not asked: "absent" */
    if (o->n == o->cap) {
        const size_t c = o->cap ? 2 * o->cap : 32;
        struct ask *q = realloc(o->a, c * sizeof *q);
        if (q == NULL) return -1;
        o->a = q;
        o->cap = c;
    }
    char *p = dup_n(path, len);
    if (p == NULL) return -1;
    o->a[o->n++] = (struct ask){ { p, len }, { NULL, 0 }, false };
    o->sorted = false;
    return 0;
}

static int ask_cmp(const void *a, const void *b) {
    return ostr_cmp(((const struct ask *)a)->path, ((const struct ask *)b)->path);
}

static void asks_sort(struct owners *o) {
    if (o->sorted) return;
    if (o->n > 1) qsort(o->a, o->n, sizeof *o->a, ask_cmp);
    size_t w = 0;
    for (size_t i = 0; i < o->n; i++) {
        if (w > 0 && ostr_cmp(o->a[w - 1].path, o->a[i].path) == 0) { free(o->a[i].path.s); continue; }
        o->a[w++] = o->a[i];
    }
    o->n = w;
    o->sorted = true;
}

/* ---- diversions ---- */

static int div_from_cmp(const void *a, const void *b) {
    return ostr_cmp(((const struct divn *)a)->from, ((const struct divn *)b)->from);
}
static int div_to_cmp(const void *a, const void *b) {
    return ostr_cmp((*(struct divn *const *)a)->to, (*(struct divn *const *)b)->to);
}

/* The diversions file: three lines a diversion. Anything else -- a count
 * that is not a multiple of three, an empty line -- and it is not relied on. */
static void diversions_read(struct owners *o, const char *buf, size_t len) {
    size_t lines = 0;
    for (size_t i = 0; i < len; i++) lines += buf[i] == '\n';
    if (len > 0 && buf[len - 1] != '\n') lines++;
    if (lines % 3 != 0) { o->incomplete = true; return; }
    if (lines == 0) return;
    o->d = calloc(lines / 3, sizeof *o->d);
    if (o->d == NULL) { o->oom = true; return; }
    const char *p = buf, *end = buf + len;
    for (size_t i = 0; i < lines / 3; i++) {
        struct ostr f[3];
        for (int k = 0; k < 3; k++) {
            const char *nl = memchr(p, '\n', (size_t)(end - p));
            const char *e = nl ? nl : end;
            f[k] = (struct ostr){ (char *)p, (size_t)(e - p) };
            p = nl ? nl + 1 : end;
        }
        if (f[0].n == 0 || f[1].n == 0 || f[2].n == 0) { o->incomplete = true; return; }
        struct divn *d = &o->d[o->nd];
        d->from = (struct ostr){ dup_n(f[0].s, f[0].n), f[0].n };
        d->to = (struct ostr){ dup_n(f[1].s, f[1].n), f[1].n };
        d->pkg = (struct ostr){ dup_n(f[2].s, f[2].n), f[2].n };
        o->nd++;
        if (d->from.s == NULL || d->to.s == NULL || d->pkg.s == NULL) { o->oom = true; return; }
    }
    qsort(o->d, o->nd, sizeof *o->d, div_from_cmp);
}

/* ---- the keys: what a list's line is compared with ---- */

static const char *const TOP[] = { "bin", "sbin", "lib", "lib32", "lib64", "libx32" };

/* `path` is "<top>/..." for one of the six names: the length of <top>, or 0. */
static size_t top_len(const char *path, size_t len) {
    for (size_t i = 0; i < sizeof TOP / sizeof TOP[0]; i++) {
        const size_t tl = strlen(TOP[i]);
        if (len > tl + 1 && path[tl] == '/' && memcmp(path, TOP[i], tl) == 0) return tl;
    }
    return 0;
}

static int key_cmp(const void *a, const void *b) {
    const struct key *x = a, *y = b;
    const int c = ostr_cmp(x->s, y->s);
    return c ? c : (x->ask > y->ask) - (x->ask < y->ask);
}

/* One spelling of an asked path as a list would write it (absolute): the
 * key it is found under, by the diversions. */
static void key_add(struct owners *o, size_t ask, char *abs, size_t n) {
    struct key *k = &o->k[o->nk];
    const struct divn probe = { { abs, n }, { abs, n }, { NULL, 0 } };
    const struct divn *pp = &probe;
    struct divn **t = o->nd ? bsearch(&pp, o->by_to, o->nd, sizeof *o->by_to, div_to_cmp) : NULL;
    const struct divn *f = o->nd ? bsearch(&probe, o->d, o->nd, sizeof *o->d, div_from_cmp) : NULL;
    if (t != NULL) {                    /* a file moved here: its package lists the diverted path */
        char *from = dup_n((*t)->from.s, (*t)->from.n);
        free(abs);
        if (from == NULL) { o->oom = true; return; }
        *k = (struct key){ { from, (*t)->from.n }, ask, K_NOT, (*t)->pkg };
    } else if (f != NULL) {             /* the diverted path itself: the diverting package's, if anyone's */
        if (f->pkg.n == 1 && f->pkg.s[0] == ':') { free(abs); return; }
        *k = (struct key){ { abs, n }, ask, K_ONLY, f->pkg };
    } else {
        *k = (struct key){ { abs, n }, ask, K_ANY, { NULL, 0 } };
    }
    o->nk++;
}

static void keys_build(struct owners *o) {
    if (o->built) return;
    o->built = true;
    asks_sort(o);
    if (o->n == 0) return;
    if (o->nd) {
        o->by_to = malloc(o->nd * sizeof *o->by_to);
        if (o->by_to == NULL) { o->oom = true; return; }
        for (size_t i = 0; i < o->nd; i++) o->by_to[i] = &o->d[i];
        qsort(o->by_to, o->nd, sizeof *o->by_to, div_to_cmp);
    }
    o->k = calloc(2 * o->n, sizeof *o->k);
    if (o->k == NULL) { o->oom = true; return; }
    for (size_t i = 0; i < o->n && !o->oom; i++) {
        const char *p = o->a[i].path.s;
        const size_t n = o->a[i].path.n;
        char *abs = malloc(n + 6);
        if (abs == NULL) { o->oom = true; return; }
        abs[0] = '/';
        memcpy(abs + 1, p, n);
        key_add(o, i, abs, n + 1);
        char *alt = NULL;
        size_t an = 0;
        if (n > 4 && memcmp(p, "usr/", 4) == 0 && top_len(p + 4, n - 4)) {      /* usr/bin/x: /bin/x */
            if ((alt = malloc(n)) == NULL) { o->oom = true; return; }
            alt[0] = '/';
            memcpy(alt + 1, p + 4, n - 4);
            an = n - 3;
        } else if (top_len(p, n)) {                                             /* bin/x: /usr/bin/x */
            if ((alt = malloc(n + 6)) == NULL) { o->oom = true; return; }
            memcpy(alt, "/usr/", 5);
            memcpy(alt + 5, p, n);
            an = n + 5;
        }
        if (alt != NULL) key_add(o, i, alt, an);
    }
    if (o->nk > 1) qsort(o->k, o->nk, sizeof *o->k, key_cmp);
}

/* ---- one list ---- */

static void list_match(struct owners *o, const char *name, size_t name_len, const char *buf, size_t len) {
    size_t base = 0;                            /* the package without its architecture */
    while (base < name_len && name[base] != ':') base++;
    const char *p = buf, *end = buf + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *e = nl ? nl : end;
        const struct ostr line = { (char *)p, (size_t)(e - p) };
        p = nl ? nl + 1 : end;
        size_t lo = 0, hi = o->nk;
        while (lo < hi) {
            const size_t mid = lo + (hi - lo) / 2;
            if (ostr_cmp(o->k[mid].s, line) < 0) lo = mid + 1;
            else hi = mid;
        }
        for (; lo < o->nk && ostr_cmp(o->k[lo].s, line) == 0; lo++) {
            const struct key *k = &o->k[lo];
            const bool same = k->pkg.n == base && (base == 0 || memcmp(k->pkg.s, name, base) == 0);
            if ((k->mode == K_ONLY && !same) || (k->mode == K_NOT && same)) continue;
            struct ask *a = &o->a[k->ask];
            if (a->found) continue;             /* the first list in byte order */
            a->pkg = (struct ostr){ dup_n(name, name_len), name_len };
            if (a->pkg.s == NULL) { o->oom = true; return; }
            a->found = true;
        }
    }
}

int owners_feed(struct owners *o, const struct belay_entry *e, const struct belay_content *c) {
    if (o->oom) return -1;
    static const size_t DL = sizeof DPKG_DIR - 1;
    if (e->path_len == sizeof DPKG_DIVS - 1 && memcmp(e->path, DPKG_DIVS, e->path_len) == 0) {
        if (o->built || o->n == 0) return 0;
        unsigned char *buf = NULL;
        size_t len = 0;
        if (e->type != BELAY_T_REG || stored_read_entry(c, e, OWNER_DIV_MAX, &buf, &len) != SW_OK) {
            o->incomplete = true;
            return 0;
        }
        diversions_read(o, (const char *)buf, len);
        free(buf);
        return o->oom ? -1 : 0;
    }
    if (e->path_len < DL || memcmp(e->path, DPKG_DIR, DL) != 0) return 0;
    if (e->path_len == DL) {
        o->db = e->type == BELAY_T_DIR && !e->unreadable && !e->not_read && !e->is_mount;
        return 0;
    }
    const char *name = e->path + DL + 1;
    const size_t nl = e->path_len - DL - 1;
    if (e->path[DL] != '/' || nl <= 5 || memcmp(name + nl - 5, ".list", 5) != 0 || memchr(name, '/', nl) != NULL)
        return 0;
    if (o->n == 0) return 0;                    /* nothing asked: no list is read */
    keys_build(o);
    if (o->oom) return -1;
    unsigned char *buf = NULL;
    size_t len = 0;
    if (e->type != BELAY_T_REG || stored_read_entry(c, e, OWNER_LIST_MAX, &buf, &len) != SW_OK) {
        o->incomplete = true;
        return 0;
    }
    list_match(o, name, nl - 5, (const char *)buf, len);
    free(buf);
    return o->oom ? -1 : 0;
}

void owners_done(struct owners *o) {
    o->built = true;                            /* nothing more is asked */
    asks_sort(o);
}

enum belay_owned owners_get(const struct owners *o, const char *path, size_t len,
                            const char **pkg, size_t *pkg_len) {
    if (o == NULL || !o->sorted || !o->db || o->oom) return BELAY_OWNER_ABSENT;
    const struct ask probe = { { (char *)path, len }, { NULL, 0 }, false };
    const struct ask *a = o->n ? bsearch(&probe, o->a, o->n, sizeof *o->a, ask_cmp) : NULL;
    if (a == NULL) return BELAY_OWNER_ABSENT;
    if (a->found) {
        if (pkg != NULL) *pkg = a->pkg.s;
        if (pkg_len != NULL) *pkg_len = a->pkg.n;
        return BELAY_OWNER_PACKAGE;
    }
    return o->incomplete ? BELAY_OWNER_ABSENT : BELAY_OWNER_NONE;
}
