/*
 *  The dpkg interpreter (finding-kinds.md, dpkg_*): which packages were
 *  installed, removed, upgraded, downgraded or changed state, from the
 *  status database before and after. A package is keyed by Package and
 *  Architecture (empty when absent; a key given twice keeps its first
 *  stanza) and is installed when its Status field's third word is
 *  `installed`. Each status file's changes are computed when its path is
 *  explained and emitted as events by the end hook, sorted (E4).
 *
 *  Never silent: a status whose copy cannot be read is content_unavailable
 *  on its path and in an event; one that cannot be parsed, or whose fields
 *  are not UTF-8, fails the end hook, so the events are one
 *  could_not_interpret (diff-events E6). The info/ files are claimed so a
 *  capture keeps them; they add nothing here.
 *
 *  `auto` (system-interpreters.md SD-1): every event but a removal says
 *  whether apt's record beside the status database -- the after-manifest's
 *  `var/lib/apt/extended_states`, which usually did not change and so is
 *  looked up (SI-4) -- has a stanza for the package and architecture with
 *  `Auto-Installed: 1`. No record there, or one that cannot be read or is
 *  not apt's: the field is absent, never assumed. The record's own change
 *  (`apt-mark auto`) is its path record and no event.
 */
#include "builtins.h"
#include "stanza.h"
#include "stored.h"
#include "versions.h"

#include "belay/interp.h"

#include "belay/error.h"
#include "belay/manifest.h"
#include "schema/finding_schema.h"

#include <stdlib.h>
#include <string.h>

#define DPKG_STATUS_MAX (256u * 1024u * 1024u)  /* bytes of one status read */
#define DPKG_STATE_MAX  (64u * 1024u * 1024u)   /* bytes of per-diff state (E5) */
#define DPKG_STATES_MAX (64u * 1024u * 1024u)   /* bytes of one extended_states read */
#define DPKG_TREES_MAX  64                      /* status databases of one diff whose record is asked */
#define DPKG_STATUS_TAIL "var/lib/dpkg/status"
#define DPKG_STATES_TAIL "var/lib/apt/extended_states"

struct str { const char *s; size_t n; };

struct dev {                    /* one pending event */
    int kind;
    struct str package, arch, a, b, path;   /* a, b: version, or from and to */
    bool prov;                              /* from a status whose outcome is unknown (E2) */
    signed char aut;                        /* auto: -1 absent, 0 false, 1 true */
    bool aut_set;                           /* a stanza of the record said: the first one counts */
};

struct dpkg;
/* One status database's tree: the record beside it, asked of the after-manifest. */
struct tree { struct dpkg *d; char *states; size_t states_len; const char *status; size_t status_len; };

/* A status that could not be read (why: a stored_why) or interpreted (why
 * SW_ERROR: E10). */
struct unavail { enum stored_why why; enum side side; struct str path; bool prov; };

struct dpkg {
    struct dev *e;
    size_t n, cap;
    struct unavail *u;
    size_t nu, ucap;
    size_t bytes;
    bool prov;                  /* the status being explained has the outcome unknown */
    bool failed;                /* state over its bound, or memory: E6 */
    struct belay_lookup *lk;
    bool asked;                 /* the records were asked for: once */
    struct tree tree[DPKG_TREES_MAX];
    size_t ntree;
};

static void *begin(void) { return calloc(1, sizeof(struct dpkg)); }

static int keep(struct dpkg *d, struct str *out, const char *s, size_t n) {
    if (d->bytes + n + 1 > DPKG_STATE_MAX) return -1;
    char *c = malloc(n + 1);
    if (c == NULL) return -1;
    if (n) memcpy(c, s, n);
    c[n] = '\0';
    d->bytes += n + 1;
    *out = (struct str){ c, n };
    return 0;
}

static int grow(void **v, size_t *cap, size_t n, size_t size, struct dpkg *d) {
    if (n < *cap) return 0;
    const size_t c = *cap ? 2 * *cap : 64;
    if (d->bytes + (c - *cap) * size > DPKG_STATE_MAX) return -1;
    void *q = realloc(*v, c * size);
    if (q == NULL) return -1;
    d->bytes += (c - *cap) * size;
    *v = q;
    *cap = c;
    return 0;
}

static int str_cmp(struct str a, struct str b) {
    const int c = a.n && b.n ? memcmp(a.s, b.s, a.n < b.n ? a.n : b.n) : 0;
    return c ? c : (a.n > b.n) - (a.n < b.n);
}

/* ---- one side's packages ---- */

struct pkg { struct str package, arch, version, status; size_t at; };
struct pkgs { struct pkg *v; size_t n, cap; };

static struct str field(const char *s, size_t n) { return (struct str){ s ? s : "", s ? n : 0 }; }

static int pkg_add(const struct stanza_pkg *p, void *ctx) {
    struct pkgs *ps = ctx;
    if (ps->n == ps->cap) {
        const size_t c = ps->cap ? 2 * ps->cap : 256;
        struct pkg *q = realloc(ps->v, c * sizeof *q);
        if (q == NULL) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "dpkg: out of memory");
            return -1;
        }
        ps->v = q;
        ps->cap = c;
    }
    ps->v[ps->n] = (struct pkg){ field(p->package, p->package_len), field(p->arch, p->arch_len),
                                 field(p->version, p->version_len), field(p->status, p->status_len),
                                 ps->n };
    ps->n++;
    return 0;
}

static int key_cmp(const struct pkg *x, const struct pkg *y) {
    const int c = str_cmp(x->package, y->package);
    return c ? c : str_cmp(x->arch, y->arch);
}
static int pkg_cmp(const void *a, const void *b) {
    const struct pkg *x = a, *y = b;
    const int c = key_cmp(x, y);
    return c ? c : (x->at > y->at) - (x->at < y->at);
}

static int pkgs_of(const unsigned char *buf, size_t len, struct pkgs *ps) {
    memset(ps, 0, sizeof *ps);
    if (buf == NULL) return 0;                  /* absent: no packages */
    if (stanza_each((const char *)buf, len, pkg_add, ps) != 0) return -1;
    if (ps->n > 1) qsort(ps->v, ps->n, sizeof *ps->v, pkg_cmp);
    size_t w = 0;
    for (size_t i = 0; i < ps->n; i++)
        if (w == 0 || key_cmp(&ps->v[w - 1], &ps->v[i]) != 0) ps->v[w++] = ps->v[i];
    ps->n = w;
    return 0;
}

/* The Status field's third word is "installed" (deb-control: want, error
 * flag, state). */
static bool installed(const struct pkg *p) {
    if (p == NULL) return false;
    const char *s = p->status.s, *e = s + p->status.n;
    for (int word = 0; word < 3; word++) {
        while (s < e && (*s == ' ' || *s == '\t')) s++;
        const char *w = s;
        while (s < e && *s != ' ' && *s != '\t') s++;
        if (word == 2) return (size_t)(s - w) == 9 && memcmp(w, "installed", 9) == 0;
    }
    return false;
}

/* ---- explaining the status file ---- */

static bool reg(const struct belay_interp_input *in, enum side s) {
    const struct belay_entry *e = side_entry(in, s);
    return e != NULL && e->type == BELAY_T_REG;
}

static bool ends_with(const char *s, size_t n, const char *t) {
    const size_t tl = strlen(t);
    return n >= tl && memcmp(s + n - tl, t, tl) == 0;
}

static int pend(struct dpkg *d, int kind, const struct pkg *k, struct str a, struct str b,
                const struct belay_interp_input *in) {
    /* Values are not checked here: an event the core refuses becomes one
     * invalid_finding event in its place, the others standing (E9). */
    if (grow((void **)&d->e, &d->cap, d->n, sizeof *d->e, d) == -1) return -1;
    struct dev *e = &d->e[d->n];
    memset(e, 0, sizeof *e);
    e->kind = kind;
    e->prov = d->prov;
    e->aut = -1;
    if (keep(d, &e->package, k->package.s, k->package.n) || keep(d, &e->arch, k->arch.s, k->arch.n) ||
        keep(d, &e->a, a.s, a.n) || keep(d, &e->b, b.s, b.n) ||
        keep(d, &e->path, in->path, in->path_len)) {
        free((char *)e->package.s); free((char *)e->arch.s); free((char *)e->a.s);
        free((char *)e->b.s); free((char *)e->path.s);
        return -1;
    }
    d->n++;
    return 0;
}

/* One package's events, before (x) and after (y); either may be NULL. */
static int changes(struct dpkg *d, const struct pkg *x, const struct pkg *y,
                   const struct belay_interp_input *in) {
    const struct pkg *k = y ? y : x;
    const struct str none = { "", 0 };
    const bool bi = installed(x), ai = installed(y);
    if (!bi && ai && pend(d, FK_DPKG_INSTALLED, k, y->version, none, in)) return -1;
    if (bi && !ai && pend(d, FK_DPKG_REMOVED, k, x->version, none, in)) return -1;
    if (bi && ai) {
        const int c = debver_cmp(x->version.s, x->version.n, y->version.s, y->version.n);
        if (c != 0 && pend(d, c < 0 ? FK_DPKG_UPGRADED : FK_DPKG_DOWNGRADED, k, x->version, y->version, in))
            return -1;
    }
    const struct str sx = x ? x->status : none, sy = y ? y->status : none;
    if (bi == ai && str_cmp(sx, sy) != 0 && pend(d, FK_DPKG_STATE_CHANGED, k, sx, sy, in)) return -1;
    return 0;
}

static int unavailable(struct dpkg *d, struct belay_findings *out, const struct belay_interp_input *in,
                       enum stored_why w, enum side s) {
    if (grow((void **)&d->u, &d->ucap, d->nu, sizeof *d->u, d) == -1) return -1;
    struct unavail *u = &d->u[d->nu];
    u->why = w;
    u->side = s;
    u->prov = d->prov;
    if (keep(d, &u->path, in->path, in->path_len) == -1) return -1;
    d->nu++;
    if (w == SW_ERROR || d->prov) return 0;     /* E10 has its own; unknown adds no finding (P8) */
    return stored_unavailable(out, w, s);
}

/* A status could not be interpreted: its record says so (unless its outcome
 * is unknown: P8), and one could_not_interpret event names it (E10). */
static enum belay_interp_result not_interpreted(struct dpkg *d, const struct belay_interp_input *in) {
    belay_err_clear();
    if (unavailable(d, NULL, in, SW_ERROR, SIDE_AFTER) == -1) d->failed = true;
    return d->prov ? BELAY_INTERP_DECLINE : BELAY_INTERP_ERROR;
}

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct dpkg *d = state;
    if (d == NULL) return BELAY_INTERP_ERROR;
    if (!ends_with(in->abs_path, in->abs_len, "/var/lib/dpkg/status")) return BELAY_INTERP_DECLINE;
    if (strcmp(in->outcome, "metadata_only") == 0) return BELAY_INTERP_DECLINE;    /* content equal */
    if (!reg(in, SIDE_BEFORE) && !reg(in, SIDE_AFTER)) return BELAY_INTERP_DECLINE;
    /* An unknown outcome is read too: its events are provisional (P7). */
    d->prov = strcmp(in->outcome, "unknown") == 0;
    unsigned char *buf[2] = { NULL, NULL };
    size_t len[2] = { 0, 0 };
    enum belay_interp_result r = BELAY_INTERP_DECLINE;
    bool ok = true, error = false;
    for (int k = SIDE_BEFORE; k <= SIDE_AFTER; k++) {
        if (!reg(in, (enum side)k)) continue;
        const enum stored_why w = stored_read(in, (enum side)k, DPKG_STATUS_MAX, &buf[k], &len[k]);
        if (w == SW_OK) continue;
        ok = false;
        if (w == SW_ERROR) error = true;
        else if (unavailable(d, out, in, w, (enum side)k) == -1) d->failed = true;
        else if (!d->prov) r = BELAY_INTERP_FINDINGS;
    }
    struct pkgs ps[2] = { { 0 }, { 0 } };
    if (error) {
        r = not_interpreted(d, in);
    } else if (ok) {
        if (pkgs_of(buf[0], len[0], &ps[0]) == -1 || pkgs_of(buf[1], len[1], &ps[1]) == -1) {
            r = not_interpreted(d, in);
        } else {
            size_t i = 0, j = 0;
            while ((i < ps[0].n || j < ps[1].n) && !d->failed) {
                const int c = i == ps[0].n ? 1 : j == ps[1].n ? -1 : key_cmp(&ps[0].v[i], &ps[1].v[j]);
                const struct pkg *x = c <= 0 ? &ps[0].v[i++] : NULL, *y = c >= 0 ? &ps[1].v[j++] : NULL;
                if (changes(d, x, y, in) == -1) d->failed = true;       /* state or memory: E6 */
            }
        }
    }
    free(ps[0].v);
    free(ps[1].v);
    free(buf[0]);
    free(buf[1]);
    return d->failed ? BELAY_INTERP_ERROR : r;
}

/* ---- the events ---- */

#define FV(x) { .s = (x).s, .len = (x).n }

/* E4: by Package, then Architecture, then kind; then the status path. */
static int dev_cmp(const void *a, const void *b) {
    const struct dev *x = a, *y = b;
    int c = str_cmp(x->package, y->package);
    if (c == 0) c = str_cmp(x->arch, y->arch);
    if (c == 0) c = x->kind - y->kind;
    if (c == 0) c = str_cmp(x->path, y->path);
    return c;
}

static unsigned flags(bool prov) { return prov ? BELAY_EVENT_PROVISIONAL : 0; }

/* 0, or -1 (memory). An event the core refuses -- a value with a NUL, text
 * over 1,024 bytes -- becomes invalid_finding in its place (E9). */
static int emit(struct belay_events *ev, const struct dev *e) {
    const char *path = e->path.s;
    const size_t pl = e->path.n;
    const bool two = e->kind == FK_DPKG_INSTALLED || e->kind == FK_DPKG_REMOVED;
    /* `auto`, last (SD-1), on every kind but dpkg_removed. */
    const struct belay_fv au = { .b = e->aut == 1, .absent = e->aut < 0 };
    const struct belay_fv v3[] = { FV(e->package), FV(e->arch), FV(e->a), au };
    const struct belay_fv v4[] = { FV(e->package), FV(e->arch), FV(e->a), FV(e->b), au };
    if (two) return belay_event(ev, e->kind, v3, e->kind == FK_DPKG_REMOVED ? 3 : 4, &path, &pl, 1, flags(e->prov));
    return belay_event(ev, e->kind, v4, 5, &path, &pl, 1, flags(e->prov));
}

static int upath_cmp(const void *a, const void *b) {
    return str_cmp(((const struct unavail *)a)->path, ((const struct unavail *)b)->path);
}

/* The events with no Package, before every package event (E4: no name sorts
 * first), in the Kinds table's order: one could_not_interpret per status not
 * interpreted (E10), by path; then, as pip's, one content_unavailable per
 * reason. */
static int unavailable_events(struct dpkg *d, struct belay_events *ev) {
    if (d->nu > 1) qsort(d->u, d->nu, sizeof *d->u, upath_cmp);
    for (size_t i = 0; i < d->nu; i++)
        if (d->u[i].why == SW_ERROR &&
            belay_event_not_interpreted(ev, &d->u[i].path.s, &d->u[i].path.n, 1, flags(d->u[i].prov)) == -1)
            return -1;
    for (int w = SW_NO_STORE; w < SW_ERROR; w++) {
        size_t n = 0;
        unsigned sides = 0;
        bool prov = false;
        for (size_t i = 0; i < d->nu; i++)
            if (d->u[i].why == (enum stored_why)w) { n++; sides |= 1u << d->u[i].side; prov |= d->u[i].prov; }
        if (n == 0) continue;
        const char **paths = malloc(n * sizeof *paths);
        size_t *lens = malloc(n * sizeof *lens);
        if (paths == NULL || lens == NULL) { free(paths); free(lens); return -1; }
        n = 0;
        for (size_t i = 0; i < d->nu; i++)
            if (d->u[i].why == (enum stored_why)w) { paths[n] = d->u[i].path.s; lens[n++] = d->u[i].path.n; }
        const char *why = stored_why_name((enum stored_why)w);
        const char *side = sides == 1u << SIDE_BEFORE ? "before" : sides == 1u << SIDE_AFTER ? "after" : "both";
        const struct belay_fv v[] = { { .s = why, .len = strlen(why) }, { .s = side, .len = strlen(side) } };
        const int r = belay_event(ev, FK_CONTENT_UNAVAILABLE, v, 2, paths, lens, n, flags(prov));
        free(paths);
        free(lens);
        if (r == -1) return -1;
    }
    return 0;
}

/* ---- auto: apt's record of the after-manifest (SD-1) ---- */

static bool sblank(char c) { return c == ' ' || c == '\t' || c == '\r'; }

static bool field_is(const char *n, size_t l, const char *want) {
    if (l != strlen(want)) return false;
    for (size_t i = 0; i < l; i++) {
        char c = n[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != want[i]) return false;
    }
    return true;
}

/* The events of (package, arch) from the status `t` names, in d->e sorted
 * by dev_cmp: each not yet told by an earlier stanza takes `value`. */
static void mark(struct dpkg *d, const struct tree *t, struct str package, struct str arch, int value) {
    size_t lo = 0, hi = d->n;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        int c = str_cmp(d->e[mid].package, package);
        if (c == 0) c = str_cmp(d->e[mid].arch, arch);
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    for (; lo < d->n && str_cmp(d->e[lo].package, package) == 0 && str_cmp(d->e[lo].arch, arch) == 0; lo++) {
        struct dev *e = &d->e[lo];
        if (e->kind == FK_DPKG_REMOVED || e->aut_set || e->path.n != t->status_len ||
            memcmp(e->path.s, t->status, t->status_len) != 0)
            continue;
        e->aut = (signed char)value;
        e->aut_set = true;
    }
}

/* apt's extended_states: deb822 stanzas, of each Package, Architecture and
 * Auto-Installed (0 or 1). One pass, no allocation. `apply` false only
 * checks that the whole file is such a record: nothing is said from one
 * that is not. */
static bool states_read(struct dpkg *d, const struct tree *t, const char *buf, size_t len, bool apply) {
    struct str package = { NULL, 0 }, arch = { "", 0 };
    int value = 0;
    bool open = false, have_arch = false;
    size_t i = 0;
    if (memchr(buf, '\0', len) != NULL) return false;
    for (;;) {
        const bool at_end = i >= len;
        const char *nl = at_end ? NULL : memchr(buf + i, '\n', len - i);
        const size_t end = nl != NULL ? (size_t)(nl - buf) : len;
        const char *l = buf + (at_end ? len : i);
        const size_t ll = at_end ? 0 : end - i;
        i = nl != NULL ? end + 1 : len;
        size_t k = 0;
        while (k < ll && sblank(l[k])) k++;
        if (k == ll) {                                  /* blank, or the end: the stanza ends */
            if (open) {
                if (package.s == NULL) return false;
                if (apply) mark(d, t, package, arch, value);
            }
            package = (struct str){ NULL, 0 };
            arch = (struct str){ "", 0 };
            value = 0;
            open = have_arch = false;
            if (at_end) return true;
            continue;
        }
        if (l[0] == ' ' || l[0] == '\t') {              /* a continuation: of some field of an open stanza */
            if (!open) return false;
            continue;
        }
        const char *colon = memchr(l, ':', ll);
        if (colon == NULL || colon == l) return false;
        open = true;
        const size_t nlen = (size_t)(colon - l);
        size_t vs = nlen + 1, ve = ll;
        while (vs < ve && sblank(l[vs])) vs++;
        while (ve > vs && sblank(l[ve - 1])) ve--;
        if (field_is(l, nlen, "package")) {
            if (package.s == NULL) package = (struct str){ l + vs, ve - vs };
        } else if (field_is(l, nlen, "architecture")) {
            if (!have_arch) arch = (struct str){ l + vs, ve - vs };
            have_arch = true;
        } else if (field_is(l, nlen, "auto-installed")) {
            if (ve - vs != 1 || (l[vs] != '0' && l[vs] != '1')) return false;
            value = l[vs] == '1';
        }
    }
}

/* The record of one tree, found in the after-manifest. */
static int states_seen(void *ctx, const struct belay_entry *e) {
    const struct tree *t = ctx;
    struct dpkg *d = t->d;
    unsigned char *buf = NULL;
    size_t len = 0;
    if (e->type != BELAY_T_REG ||
        stored_read_entry(belay_lookup_content(d->lk), e, DPKG_STATES_MAX, &buf, &len) != SW_OK)
        return 0;                                       /* cannot be read: auto stays absent */
    if (states_read(d, t, (const char *)buf, len, false)) {
        /* A record: every event of this tree is told -- false, unless a stanza says 1. */
        for (size_t i = 0; i < d->n; i++)
            if (d->e[i].kind != FK_DPKG_REMOVED && d->e[i].path.n == t->status_len &&
                memcmp(d->e[i].path.s, t->status, t->status_len) == 0)
                d->e[i].aut = 0;
        states_read(d, t, (const char *)buf, len, true);
    }
    free(buf);
    return 0;
}

/* Asks, once, for the record beside each status database that gave an
 * event carrying auto. Past DPKG_TREES_MAX trees, or a path too long: not
 * asked, and auto is absent there. */
static enum belay_interp_result prepare(void *state, struct belay_lookup *lk) {
    struct dpkg *d = state;
    if (d == NULL) return BELAY_INTERP_ERROR;
    if (d->failed || d->asked) return BELAY_INTERP_FINDINGS;
    d->asked = true;
    d->lk = lk;
    if (d->n > 1) qsort(d->e, d->n, sizeof *d->e, dev_cmp);       /* the order states_read searches */
    static const size_t TAIL = sizeof DPKG_STATUS_TAIL - 1, STL = sizeof DPKG_STATES_TAIL - 1;
    for (size_t i = 0; i < d->n; i++) {
        const struct dev *e = &d->e[i];
        if (e->kind == FK_DPKG_REMOVED || e->path.n < TAIL) continue;
        size_t k = 0;
        while (k < d->ntree && (d->tree[k].status_len != e->path.n || memcmp(d->tree[k].status, e->path.s, e->path.n) != 0)) k++;
        if (k < d->ntree || d->ntree == DPKG_TREES_MAX) continue;
        const size_t prefix = e->path.n - TAIL;
        if (prefix + STL > 4096) continue;
        struct tree *t = &d->tree[d->ntree];
        if ((t->states = malloc(prefix + STL + 1)) == NULL) return BELAY_INTERP_ERROR;
        memcpy(t->states, e->path.s, prefix);
        memcpy(t->states + prefix, DPKG_STATES_TAIL, STL + 1);
        t->states_len = prefix + STL;
        t->status = e->path.s;
        t->status_len = e->path.n;
        t->d = d;
        d->ntree++;
        if (belay_lookup_want(lk, t->states, t->states_len, false, states_seen, t) == -1) return BELAY_INTERP_ERROR;
    }
    return BELAY_INTERP_FINDINGS;
}

static enum belay_interp_result end(void *state, struct belay_events *ev) {
    struct dpkg *d = state;
    if (d == NULL) return BELAY_INTERP_ERROR;
    enum belay_interp_result r = d->failed ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    if (ev != NULL && r == BELAY_INTERP_FINDINGS) {
        if (d->n > 1) qsort(d->e, d->n, sizeof *d->e, dev_cmp);
        if (unavailable_events(d, ev) == -1) r = BELAY_INTERP_ERROR;
        for (size_t i = 0; i < d->n && r == BELAY_INTERP_FINDINGS; i++)
            if (emit(ev, &d->e[i]) == -1) r = BELAY_INTERP_ERROR;
    }
    for (size_t i = 0; i < d->n; i++) {
        free((char *)d->e[i].package.s); free((char *)d->e[i].arch.s); free((char *)d->e[i].a.s);
        free((char *)d->e[i].b.s); free((char *)d->e[i].path.s);
    }
    for (size_t i = 0; i < d->nu; i++) free((char *)d->u[i].path.s);
    for (size_t i = 0; i < d->ntree; i++) free(d->tree[i].states);
    free(d->e);
    free(d->u);
    free(d);
    return r;
}

const struct belay_interp INTERP_DPKG = { BELAY_INTERP_DPKG, begin, explain, end, prepare };
