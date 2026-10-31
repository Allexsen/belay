/*
 *  The pip interpreter (finding-kinds.md, pip_*): which distributions were
 *  installed, removed, upgraded, downgraded or reinstalled, from their
 *  dist-info RECORDs. A distribution is named by its directory,
 *  `{name}-{version}.dist-info` (split at the first '-'), and paired with
 *  another by the directory holding it and its name normalized as PEP 503
 *  does. Facts about distributions are events, emitted by the end hook once
 *  every RECORD has been seen; RECORD content is read only for a reinstall,
 *  whose files are counted.
 *
 *  Never silent: a RECORD whose copy cannot be read is content_unavailable on
 *  its path and in an event; a dist-info that cannot be named, a RECORD that
 *  cannot be parsed, or a pairing the finding kinds cannot express fails the
 *  end hook, so the events are one could_not_interpret (diff-events E6).
 */
#include "builtins.h"
#include "record_csv.h"
#include "stored.h"
#include "versions.h"

#include "belay/error.h"
#include "belay/manifest.h"
#include "schema/finding_schema.h"

#include <stdlib.h>
#include <string.h>

#define PIP_RECORD_MAX (64u * 1024u * 1024u)    /* bytes of one RECORD read */
#define PIP_STATE_MAX  (64u * 1024u * 1024u)    /* bytes of per-diff state (E5) */

enum change { C_ADDED, C_REMOVED, C_REINSTALLED };

struct dist {
    const char *key, *norm, *name, *version, *path;   /* into the state's arena */
    size_t key_len, norm_len, name_len, version_len, path_len;
    enum change change;
    size_t files_added, files_removed, files_changed;
};

struct unavail { enum stored_why why; enum side side; const char *path; size_t path_len; };

struct pip {
    struct dist *d;
    size_t n, cap;
    struct unavail *u;
    size_t nu, ucap;
    size_t bytes;                   /* of state, against PIP_STATE_MAX */
    bool failed;
};

static void *begin(void) { return calloc(1, sizeof(struct pip)); }

/* A copy of n bytes kept for the diff's length, or NULL (state full). */
static const char *keep(struct pip *p, const char *s, size_t n) {
    if (p->bytes + n + 1 > PIP_STATE_MAX) return NULL;
    char *c = malloc(n + 1);
    if (c == NULL) return NULL;
    memcpy(c, s, n);
    c[n] = '\0';
    p->bytes += n + 1;
    return c;
}

static int grow(void **v, size_t *cap, size_t n, size_t size, struct pip *p) {
    if (n < *cap) return 0;
    const size_t c = *cap ? 2 * *cap : 64;
    if (p->bytes + (c - *cap) * size > PIP_STATE_MAX) return -1;
    void *q = realloc(*v, c * size);
    if (q == NULL) return -1;
    p->bytes += (c - *cap) * size;
    *v = q;
    *cap = c;
    return 0;
}

/* PEP 503: lowercase, each run of '-', '_', '.' one '-'. */
static size_t normalize(const char *s, size_t n, char *out) {
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        const char c = s[i];
        if (c == '-' || c == '_' || c == '.') {
            if (w == 0 || out[w - 1] != '-') out[w++] = '-';
        } else {
            out[w++] = c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
        }
    }
    return w;
}

/* ---- RECORD rows, compared by path ---- */

struct row { const char *path, *hash, *size; size_t pl, hl, sl, at; };
struct rows { struct row *v; size_t n, cap; char *arena; size_t used, arena_cap; };

static const char *arena_put(struct rows *r, const char *s, size_t n) {
    char *w = r->arena + r->used;              /* sized so every field fits */
    memcpy(w, s, n);
    w[n] = '\0';
    r->used += n + 1;
    return w;
}

static int row_add(const struct record_row *x, void *ctx) {
    struct rows *r = ctx;
    if (r->n == r->cap) {
        const size_t c = r->cap ? 2 * r->cap : 256;
        struct row *q = realloc(r->v, c * sizeof *q);
        if (q == NULL) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "pip: out of memory");
            return -1;
        }
        r->v = q;
        r->cap = c;
    }
    if (r->used + x->path_len + x->hash_len + x->size_len + 3 > r->arena_cap) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "pip: RECORD fields exceed the file");   /* cannot happen */
        return -1;
    }
    struct row *w = &r->v[r->n];
    w->path = arena_put(r, x->path, x->path_len);
    w->hash = arena_put(r, x->hash, x->hash_len);
    w->size = arena_put(r, x->size, x->size_len);
    w->pl = x->path_len;
    w->hl = x->hash_len;
    w->sl = x->size_len;
    w->at = r->n++;
    return 0;
}

static int path_cmp(const struct row *x, const struct row *y) {
    const int c = memcmp(x->path, y->path, x->pl < y->pl ? x->pl : y->pl);
    return c ? c : (x->pl > y->pl) - (x->pl < y->pl);
}
static int row_cmp(const void *a, const void *b) {
    const struct row *x = a, *y = b;
    const int c = path_cmp(x, y);
    return c ? c : (x->at > y->at) - (x->at < y->at);
}

/* A RECORD's rows, sorted by path; a path given twice keeps its first row. */
static int rows_of(const unsigned char *buf, size_t len, struct rows *r) {
    memset(r, 0, sizeof *r);
    r->arena_cap = len + 3 * (len + 1) + 3;
    if ((r->arena = malloc(r->arena_cap)) == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "pip: out of memory");
        return -1;
    }
    if (record_each((const char *)buf, len, row_add, r) != 0) return -1;
    if (r->n > 1) qsort(r->v, r->n, sizeof *r->v, row_cmp);
    size_t w = 0;
    for (size_t i = 0; i < r->n; i++)
        if (w == 0 || path_cmp(&r->v[w - 1], &r->v[i]) != 0) r->v[w++] = r->v[i];
    r->n = w;
    return 0;
}

static void rows_free(struct rows *r) { free(r->v); free(r->arena); }

static void count_files(const struct rows *a, const struct rows *b, struct dist *d) {
    size_t i = 0, j = 0;
    while (i < a->n || j < b->n) {
        const int c = i == a->n ? 1 : j == b->n ? -1 : path_cmp(&a->v[i], &b->v[j]);
        if (c < 0) { d->files_removed++; i++; continue; }
        if (c > 0) { d->files_added++; j++; continue; }
        const struct row *x = &a->v[i++], *y = &b->v[j++];
        if (x->hl != y->hl || memcmp(x->hash, y->hash, x->hl) != 0 || x->sl != y->sl ||
            memcmp(x->size, y->size, x->sl) != 0)
            d->files_changed++;
    }
}

static void dist_free(struct dist *d) {
    free((char *)d->key); free((char *)d->norm); free((char *)d->name);
    free((char *)d->version); free((char *)d->path);
}

/* ---- explaining one path ---- */

static bool reg(const struct belay_interp_input *in, enum side s) {
    const struct belay_entry *e = side_entry(in, s);
    return e != NULL && e->type == BELAY_T_REG;
}

static bool ends_with(const char *s, size_t n, const char *t) {
    const size_t tl = strlen(t);
    return n >= tl && memcmp(s + n - tl, t, tl) == 0;
}

/* Names the dist-info holding `in`'s RECORD into d. -1: it cannot be named
 * (no '-', an empty name or version, not UTF-8, over a field's bound). */
static int name_dist(struct pip *p, const struct belay_interp_input *in, struct dist *d) {
    static const char SUFFIX[] = ".dist-info/RECORD";
    const size_t base_end = in->abs_len - (sizeof SUFFIX - 1);
    size_t start = base_end;
    while (start > 0 && in->abs_path[start - 1] != '/') start--;
    const char *base = in->abs_path + start;
    const size_t bl = base_end - start;
    const char *dash = memchr(base, '-', bl);
    if (dash == NULL || dash == base || dash == base + bl - 1) return -1;
    const size_t nl = (size_t)(dash - base), vl = bl - nl - 1;
    if (!belay_finding_string_ok(base, nl) || !belay_finding_string_ok(dash + 1, vl)) return -1;
    char norm[FINDING_STRING_MAX];
    const size_t ml = normalize(base, nl, norm);
    if ((d->key = keep(p, in->abs_path, start)) == NULL || (d->norm = keep(p, norm, ml)) == NULL ||
        (d->name = keep(p, base, nl)) == NULL || (d->version = keep(p, dash + 1, vl)) == NULL ||
        (d->path = keep(p, in->path, in->path_len)) == NULL)
        return -1;
    d->key_len = start;
    d->norm_len = ml;
    d->name_len = nl;
    d->version_len = vl;
    d->path_len = in->path_len;
    return 0;
}

static int unavailable(struct pip *p, struct belay_findings *out, const struct belay_interp_input *in,
                       enum stored_why w, enum side s) {
    if (grow((void **)&p->u, &p->ucap, p->nu, sizeof *p->u, p) == -1) return -1;
    const char *path = keep(p, in->path, in->path_len);
    if (path == NULL) return -1;
    p->u[p->nu++] = (struct unavail){ w, s, path, in->path_len };
    return stored_unavailable(out, w, s);
}

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct pip *p = state;
    if (p == NULL) return BELAY_INTERP_ERROR;
    if (!ends_with(in->abs_path, in->abs_len, ".dist-info/RECORD")) return BELAY_INTERP_DECLINE;
    if (strcmp(in->outcome, "unknown") == 0 || strcmp(in->outcome, "metadata_only") == 0)
        return BELAY_INTERP_DECLINE;            /* no proven change of content */
    const bool b = reg(in, SIDE_BEFORE), a = reg(in, SIDE_AFTER);
    if (!b && !a) return BELAY_INTERP_DECLINE;
    struct dist d = { 0 };
    d.change = b && a ? C_REINSTALLED : a ? C_ADDED : C_REMOVED;
    if (grow((void **)&p->d, &p->cap, p->n, sizeof *p->d, p) == -1 || name_dist(p, in, &d) == -1) {
        dist_free(&d);
        p->failed = true;
        return BELAY_INTERP_ERROR;
    }
    enum belay_interp_result r = BELAY_INTERP_FINDINGS;
    if (d.change == C_REINSTALLED) {
        unsigned char *buf[2] = { NULL, NULL };
        size_t len[2];
        bool ok = true;
        for (int k = SIDE_BEFORE; k <= SIDE_AFTER; k++) {
            const enum stored_why w = stored_read(in, (enum side)k, PIP_RECORD_MAX, &buf[k], &len[k]);
            if (w == SW_OK) continue;
            ok = false;
            if (w == SW_ERROR || unavailable(p, out, in, w, (enum side)k) == -1) r = BELAY_INTERP_ERROR;
        }
        struct rows ra = { 0 }, rb = { 0 };
        if (ok && (rows_of(buf[0], len[0], &ra) == -1 || rows_of(buf[1], len[1], &rb) == -1)) {
            belay_err_clear();
            r = BELAY_INTERP_ERROR;
            ok = false;
        }
        if (ok) count_files(&ra, &rb, &d);
        rows_free(&ra);
        rows_free(&rb);
        free(buf[0]);
        free(buf[1]);
        if (!ok) {                                  /* no event for it: said instead */
            dist_free(&d);
            if (r == BELAY_INTERP_ERROR) p->failed = true;
            return r;
        }
    }
    p->d[p->n++] = d;
    return BELAY_INTERP_DECLINE;                    /* its facts are events */
}

/* ---- the events ---- */

struct pev {
    const struct dist *x, *y;       /* y: the added one of a pair */
    int kind;
};

static int str_cmp(const char *a, size_t al, const char *b, size_t bl) {
    const int c = memcmp(a, b, al < bl ? al : bl);
    return c ? c : (al > bl) - (al < bl);
}

/* Distributions grouped by (normalized name, directory), then by change. */
static int dist_cmp(const void *a, const void *b) {
    const struct dist *x = a, *y = b;
    int c = str_cmp(x->norm, x->norm_len, y->norm, y->norm_len);
    if (c == 0) c = str_cmp(x->key, x->key_len, y->key, y->key_len);
    if (c == 0) c = (int)x->change - (int)y->change;
    if (c == 0) c = str_cmp(x->path, x->path_len, y->path, y->path_len);
    return c;
}

static bool same_group(const struct dist *x, const struct dist *y) {
    return str_cmp(x->norm, x->norm_len, y->norm, y->norm_len) == 0 &&
           str_cmp(x->key, x->key_len, y->key, y->key_len) == 0;
}

/* E4: by normalized name, then kind; then directory and path, so equal
 * keys still give the same bytes. */
static int pev_cmp(const void *a, const void *b) {
    const struct pev *x = a, *y = b;
    int c = str_cmp(x->x->norm, x->x->norm_len, y->x->norm, y->x->norm_len);
    if (c == 0) c = x->kind - y->kind;
    if (c == 0) c = str_cmp(x->x->key, x->x->key_len, y->x->key, y->x->key_len);
    if (c == 0) c = str_cmp(x->x->path, x->x->path_len, y->x->path, y->x->path_len);
    return c;
}

#define FV(p, n) { .s = (p), .len = (n) }

static int emit(struct belay_events *ev, const struct pev *e) {
    const struct dist *x = e->x, *y = e->y;
    const char *paths[2] = { x->path, y ? y->path : NULL };
    const size_t lens[2] = { x->path_len, y ? y->path_len : 0 };
    const size_t np = y ? 2 : 1;
    switch (e->kind) {
    case FK_PIP_INSTALLED:
    case FK_PIP_REMOVED: {
        const struct belay_fv v[] = { FV(x->name, x->name_len), FV(x->version, x->version_len) };
        return belay_event(ev, e->kind, v, 2, paths, lens, np);
    }
    case FK_PIP_REINSTALLED: {
        const struct belay_fv v[] = { FV(x->name, x->name_len), FV(x->version, x->version_len),
                                      { .i = x->files_added }, { .i = x->files_removed },
                                      { .i = x->files_changed } };
        return belay_event(ev, e->kind, v, 5, paths, lens, np);
    }
    default: {
        const struct belay_fv v[] = { FV(y->name, y->name_len), FV(x->version, x->version_len),
                                      FV(y->version, y->version_len) };
        return belay_event(ev, e->kind, v, 3, paths, lens, np);
    }
    }
}

/* One content_unavailable event per reason, naming its paths; the side is
 * theirs when they share one, else "both". Before every named event: it has
 * no name, and sorts first. */
static int unavailable_events(struct pip *p, struct belay_events *ev) {
    for (int w = SW_NO_STORE; w < SW_ERROR; w++) {
        size_t n = 0;
        unsigned sides = 0;
        for (size_t i = 0; i < p->nu; i++)
            if (p->u[i].why == (enum stored_why)w) { n++; sides |= 1u << p->u[i].side; }
        if (n == 0) continue;
        const char **paths = malloc(n * sizeof *paths);
        size_t *lens = malloc(n * sizeof *lens);
        if (paths == NULL || lens == NULL) { free(paths); free(lens); return -1; }
        n = 0;
        for (size_t i = 0; i < p->nu; i++)
            if (p->u[i].why == (enum stored_why)w) { paths[n] = p->u[i].path; lens[n++] = p->u[i].path_len; }
        const char *why = stored_why_name((enum stored_why)w);
        const char *side = sides == 1u << SIDE_BEFORE ? "before" : sides == 1u << SIDE_AFTER ? "after" : "both";
        const struct belay_fv v[] = { FV(why, strlen(why)), FV(side, strlen(side)) };
        const int r = belay_event(ev, FK_CONTENT_UNAVAILABLE, v, 2, paths, lens, n);
        free(paths);
        free(lens);
        if (r == -1) return -1;
    }
    return 0;
}

static void pip_free(struct pip *p) {
    for (size_t i = 0; i < p->n; i++) dist_free(&p->d[i]);
    for (size_t i = 0; i < p->nu; i++) free((char *)p->u[i].path);
    free(p->d);
    free(p->u);
    free(p);
}

static enum belay_interp_result end(void *state, struct belay_events *ev) {
    struct pip *p = state;
    if (p == NULL) return BELAY_INTERP_ERROR;
    enum belay_interp_result r = p->failed ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    struct pev *out = r == BELAY_INTERP_FINDINGS && p->n ? malloc(p->n * sizeof *out) : NULL;
    if (r == BELAY_INTERP_FINDINGS && p->n && out == NULL) r = BELAY_INTERP_ERROR;
    size_t no = 0;
    if (ev != NULL && r == BELAY_INTERP_FINDINGS) {
        if (p->n > 1) qsort(p->d, p->n, sizeof *p->d, dist_cmp);
        for (size_t i = 0; i < p->n && r == BELAY_INTERP_FINDINGS;) {
            size_t j = i, added = 0, removed = 0;
            while (j < p->n && same_group(&p->d[i], &p->d[j])) {
                added += p->d[j].change == C_ADDED;
                removed += p->d[j].change == C_REMOVED;
                j++;
            }
            const struct dist *rem = NULL, *add = NULL;
            for (size_t k = i; k < j; k++) {
                const struct dist *d = &p->d[k];
                if (d->change == C_REINSTALLED) out[no++] = (struct pev){ d, NULL, FK_PIP_REINSTALLED };
                else if (d->change == C_REMOVED) rem = d;
                else add = d;
            }
            if (added == 1 && removed == 1) {
                int cmp;
                const int kind = pep440_cmp(rem->version, rem->version_len, add->version,
                                            add->version_len, &cmp) == -1 || cmp == 0
                                     ? FK_PIP_VERSION_CHANGED
                                     : cmp < 0 ? FK_PIP_UPGRADED : FK_PIP_DOWNGRADED;
                out[no++] = (struct pev){ rem, add, kind };
            } else if (added && removed) {
                r = BELAY_INTERP_ERROR;     /* several of one name on a side: no kind says it */
            } else {
                for (size_t k = i; k < j; k++)
                    if (p->d[k].change != C_REINSTALLED)
                        out[no++] = (struct pev){ &p->d[k], NULL,
                                                  p->d[k].change == C_ADDED ? FK_PIP_INSTALLED : FK_PIP_REMOVED };
            }
            i = j;
        }
        if (r == BELAY_INTERP_FINDINGS) {
            if (no > 1) qsort(out, no, sizeof *out, pev_cmp);
            if (unavailable_events(p, ev) == -1) r = BELAY_INTERP_ERROR;
            for (size_t i = 0; i < no && r == BELAY_INTERP_FINDINGS; i++)
                if (emit(ev, &out[i]) == -1) r = BELAY_INTERP_ERROR;
        }
    }
    free(out);
    pip_free(p);
    return r;
}

const struct belay_interp INTERP_PIP = { BELAY_INTERP_PIP, begin, explain, end };
