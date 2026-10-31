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
 */
#include "builtins.h"
#include "stanza.h"
#include "stored.h"
#include "versions.h"

#include "belay/error.h"
#include "belay/manifest.h"
#include "schema/finding_schema.h"

#include <stdlib.h>
#include <string.h>

#define DPKG_STATUS_MAX (256u * 1024u * 1024u)  /* bytes of one status read */
#define DPKG_STATE_MAX  (64u * 1024u * 1024u)   /* bytes of per-diff state (E5) */

struct str { const char *s; size_t n; };

struct dev {                    /* one pending event */
    int kind;
    struct str package, arch, a, b, path;   /* a, b: version, or from and to */
};

struct unavail { enum stored_why why; enum side side; struct str path; };

struct dpkg {
    struct dev *e;
    size_t n, cap;
    struct unavail *u;
    size_t nu, ucap;
    size_t bytes;
    bool failed;
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
    if (!belay_finding_string_ok(k->package.s, k->package.n) || !belay_finding_string_ok(k->arch.s, k->arch.n) ||
        !belay_finding_string_ok(a.s, a.n) || !belay_finding_string_ok(b.s, b.n))
        return -1;
    if (grow((void **)&d->e, &d->cap, d->n, sizeof *d->e, d) == -1) return -1;
    struct dev *e = &d->e[d->n];
    memset(e, 0, sizeof *e);
    e->kind = kind;
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
    if (keep(d, &u->path, in->path, in->path_len) == -1) return -1;
    d->nu++;
    return stored_unavailable(out, w, s);
}

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct dpkg *d = state;
    if (d == NULL) return BELAY_INTERP_ERROR;
    if (!ends_with(in->abs_path, in->abs_len, "/var/lib/dpkg/status")) return BELAY_INTERP_DECLINE;
    if (strcmp(in->outcome, "unknown") == 0 || strcmp(in->outcome, "metadata_only") == 0)
        return BELAY_INTERP_DECLINE;            /* no proven change of content */
    if (!reg(in, SIDE_BEFORE) && !reg(in, SIDE_AFTER)) return BELAY_INTERP_DECLINE;
    unsigned char *buf[2] = { NULL, NULL };
    size_t len[2] = { 0, 0 };
    enum belay_interp_result r = BELAY_INTERP_DECLINE;
    bool ok = true;
    for (int k = SIDE_BEFORE; k <= SIDE_AFTER; k++) {
        if (!reg(in, (enum side)k)) continue;
        const enum stored_why w = stored_read(in, (enum side)k, DPKG_STATUS_MAX, &buf[k], &len[k]);
        if (w == SW_OK) continue;
        ok = false;
        r = BELAY_INTERP_FINDINGS;
        if (w == SW_ERROR || unavailable(d, out, in, w, (enum side)k) == -1) r = BELAY_INTERP_ERROR;
    }
    struct pkgs ps[2] = { { 0 }, { 0 } };
    if (ok) {
        if (pkgs_of(buf[0], len[0], &ps[0]) == -1 || pkgs_of(buf[1], len[1], &ps[1]) == -1) {
            belay_err_clear();
            r = BELAY_INTERP_ERROR;
        } else {
            size_t i = 0, j = 0;
            while ((i < ps[0].n || j < ps[1].n) && r != BELAY_INTERP_ERROR) {
                const int c = i == ps[0].n ? 1 : j == ps[1].n ? -1 : key_cmp(&ps[0].v[i], &ps[1].v[j]);
                const struct pkg *x = c <= 0 ? &ps[0].v[i++] : NULL, *y = c >= 0 ? &ps[1].v[j++] : NULL;
                if (changes(d, x, y, in) == -1) r = BELAY_INTERP_ERROR;
            }
        }
    }
    free(ps[0].v);
    free(ps[1].v);
    free(buf[0]);
    free(buf[1]);
    if (r == BELAY_INTERP_ERROR) d->failed = true;
    return r;
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

/* 0, or -1 when it cannot be added -- memory, or an event its kind's row
 * refuses (its text over 1,024 bytes: each value is checked already), which
 * fails the end hook (E6) rather than being added and dropped. */
static int emit(struct belay_events *ev, const struct dev *e) {
    const char *path = e->path.s;
    const size_t pl = e->path.n;
    const bool two = e->kind == FK_DPKG_INSTALLED || e->kind == FK_DPKG_REMOVED;
    const struct belay_fv v[] = { FV(e->package), FV(e->arch), FV(e->a), FV(e->b) };
    const size_t n = two ? 3 : 4;
    if (!belay_event_fits(ev, e->kind, v, n)) return -1;
    return belay_event(ev, e->kind, v, n, &path, &pl, 1);
}

/* As pip's: one per reason, before every package event (it has no Package). */
static int unavailable_events(struct dpkg *d, struct belay_events *ev) {
    for (int w = SW_NO_STORE; w < SW_ERROR; w++) {
        size_t n = 0;
        unsigned sides = 0;
        for (size_t i = 0; i < d->nu; i++)
            if (d->u[i].why == (enum stored_why)w) { n++; sides |= 1u << d->u[i].side; }
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
        const int r = belay_event(ev, FK_CONTENT_UNAVAILABLE, v, 2, paths, lens, n);
        free(paths);
        free(lens);
        if (r == -1) return -1;
    }
    return 0;
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
    free(d->e);
    free(d->u);
    free(d);
    return r;
}

const struct belay_interp INTERP_DPKG = { BELAY_INTERP_DPKG, begin, explain, end };
