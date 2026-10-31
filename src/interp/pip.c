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
#include "belay/json.h"
#include "belay/manifest.h"
#include "schema/finding_schema.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PIP_RECORD_MAX  (16u * 1024u * 1024u)   /* bytes of one RECORD read */
#define PIP_RECORD_ROWS 262144u                 /* rows of one RECORD: past it, too_large */
#define PIP_STATE_MAX  (64u * 1024u * 1024u)    /* bytes of per-diff state (E5) */

enum change { C_ADDED, C_REMOVED, C_REINSTALLED };

struct dist {
    const char *key, *norm, *name, *version, *path;   /* into the state's arena */
    size_t key_len, norm_len, name_len, version_len, path_len;
    enum change change;
    size_t files_added, files_removed, files_changed;
    bool uncounted;                 /* a reinstall whose rows were not compared */
    bool prov;                      /* its RECORD's outcome is unknown (P7) */
};

/* A RECORD that could not be read (why: a stored_why) or interpreted (why
 * SW_ERROR: E10). */
struct unavail { enum stored_why why; enum side side; const char *path; size_t path_len; bool prov; };

struct pip {
    struct dist *d;
    size_t n, cap;
    struct unavail *u;
    size_t nu, ucap;
    size_t bytes;                   /* of state, against PIP_STATE_MAX */
    bool prov;                      /* the RECORD being explained has the outcome unknown */
    bool failed;                    /* state over its bound, or memory: E6 */
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

struct row { const char *path, *hash, *size; uint32_t pl, hl, sl, at; };   /* fields <= 4096 */
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
    if (r->n == PIP_RECORD_ROWS) return 2;                  /* over the bound: stop */
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
    w->pl = (uint32_t)x->path_len;
    w->hl = (uint32_t)x->hash_len;
    w->sl = (uint32_t)x->size_len;
    w->at = (uint32_t)r->n++;
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

/* A RECORD's rows, sorted by path; a path given twice keeps its first row.
 * 0; -1 (could not parse, memory); -2 over PIP_RECORD_ROWS. The arena holds
 * every field unquoted and NUL-ended: a row's three fields and three NULs
 * fit in its own bytes (two commas and its line end), plus one for a last
 * row with no line end -- so len + 1 in all (review 2026-10-31, 4). */
static int rows_of(const unsigned char *buf, size_t len, struct rows *r) {
    memset(r, 0, sizeof *r);
    if (!belay_utf8_valid((const char *)buf, len)) {       /* RECORD is UTF-8 text (PEP 376) */
        belay_err_set(BELAY_ERR_CORRUPT, 0, "pip: RECORD is not UTF-8");
        return -1;
    }
    r->arena_cap = len + 4;
    if ((r->arena = malloc(r->arena_cap)) == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "pip: out of memory");
        return -1;
    }
    const int rc = record_each((const char *)buf, len, row_add, r);
    if (rc == 2) return -2;
    if (rc != 0) return -1;
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
 * (no '-', an empty name or version, not a string field's value); -2: the
 * state is full, or memory. */
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
        return -2;                                      /* state full, or memory */
    d->key_len = start;
    d->norm_len = ml;
    d->name_len = nl;
    d->version_len = vl;
    d->path_len = in->path_len;
    return 0;
}

/* Records a RECORD that could not be read (and says so on its record, unless
 * its outcome is unknown: P8), or interpreted (why SW_ERROR: E10). */
static int unavailable(struct pip *p, struct belay_findings *out, const struct belay_interp_input *in,
                       enum stored_why w, enum side s) {
    if (grow((void **)&p->u, &p->ucap, p->nu, sizeof *p->u, p) == -1) return -1;
    const char *path = keep(p, in->path, in->path_len);
    if (path == NULL) return -1;
    p->u[p->nu++] = (struct unavail){ w, s, path, in->path_len, p->prov };
    if (w == SW_ERROR || p->prov) return 0;
    return stored_unavailable(out, w, s);
}

/* A RECORD not interpreted: its record says so (unless unknown), and one
 * could_not_interpret event names it (E10); the other events stand. */
static enum belay_interp_result not_interpreted(struct pip *p, const struct belay_interp_input *in) {
    belay_err_clear();
    if (unavailable(p, NULL, in, SW_ERROR, SIDE_AFTER) == -1) p->failed = true;
    return p->failed ? BELAY_INTERP_ERROR : p->prov ? BELAY_INTERP_DECLINE : BELAY_INTERP_ERROR;
}

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct pip *p = state;
    if (p == NULL) return BELAY_INTERP_ERROR;
    if (!ends_with(in->abs_path, in->abs_len, ".dist-info/RECORD")) return BELAY_INTERP_DECLINE;
    if (strcmp(in->outcome, "metadata_only") == 0) return BELAY_INTERP_DECLINE;    /* content equal */
    const bool b = reg(in, SIDE_BEFORE), a = reg(in, SIDE_AFTER);
    if (!b && !a) return BELAY_INTERP_DECLINE;
    /* An unknown RECORD still pairs, by its directory's name (P7); one on both
     * sides is no proven reinstall, and its rows are not counted. */
    p->prov = strcmp(in->outcome, "unknown") == 0;
    struct dist d = { 0 };
    d.change = b && a ? C_REINSTALLED : a ? C_ADDED : C_REMOVED;
    d.prov = p->prov;
    if (grow((void **)&p->d, &p->cap, p->n, sizeof *p->d, p) == -1) {
        p->failed = true;
        return BELAY_INTERP_ERROR;
    }
    const int named = name_dist(p, in, &d);
    if (named != 0) {
        dist_free(&d);
        if (named == -2) {
            p->failed = true;
            return BELAY_INTERP_ERROR;
        }
        return not_interpreted(p, in);
    }
    enum belay_interp_result r = BELAY_INTERP_FINDINGS;
    if (d.change == C_REINSTALLED && p->prov) {
        /* Unknown on both sides: a provisional reinstall, its rows not
         * counted (decision 2026-10-31, c): graders read events. */
        d.uncounted = true;
    } else if (d.change == C_REINSTALLED) {
        unsigned char *buf[2] = { NULL, NULL };
        size_t len[2];
        bool ok = true, error = false;
        for (int k = SIDE_BEFORE; k <= SIDE_AFTER; k++) {
            const enum stored_why w = stored_read(in, (enum side)k, PIP_RECORD_MAX, &buf[k], &len[k]);
            if (w == SW_OK) continue;
            ok = false;
            if (w == SW_ERROR) error = true;
            else if (unavailable(p, out, in, w, (enum side)k) == -1) p->failed = true;
        }
        struct rows rs[2] = { { 0 }, { 0 } };
        for (int k = SIDE_BEFORE; k <= SIDE_AFTER && ok; k++) {
            const int rc = rows_of(buf[k], len[k], &rs[k]);
            if (rc == 0) continue;
            ok = false;
            belay_err_clear();
            if (rc == -1) error = true;
            else if (unavailable(p, out, in, SW_TOO_LARGE, (enum side)k) == -1) p->failed = true;
        }
        if (ok) count_files(&rs[0], &rs[1], &d);
        rows_free(&rs[0]);
        rows_free(&rs[1]);
        free(buf[0]);
        free(buf[1]);
        if (!ok) {                                  /* no event for it: said instead */
            dist_free(&d);
            if (error) return not_interpreted(p, in);
            return p->failed ? BELAY_INTERP_ERROR : r;
        }
    }
    p->d[p->n++] = d;
    return BELAY_INTERP_DECLINE;                    /* its facts are events */
}

/* ---- the events ---- */

struct pev {
    const struct dist *x, *y;       /* y: the added one of a pair */
    int kind;
    size_t first, count;            /* could_not_interpret (E10): the group in p->d */
    bool prov;
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

static unsigned flags(bool prov) { return prov ? BELAY_EVENT_PROVISIONAL : 0; }

/* 0, or -1 (memory). An event the core refuses is invalid_finding in its
 * place (E9). */
static int emit(struct pip *p, struct belay_events *ev, const struct pev *e) {
    const struct dist *x = e->x, *y = e->y;
    if (e->kind == FK_COULD_NOT_INTERPRET) {    /* a name no kind pairs: its RECORDs (E10) */
        const char **paths = malloc(e->count * sizeof *paths);
        size_t *lens = malloc(e->count * sizeof *lens), np = 0;
        if (paths == NULL || lens == NULL) { free(paths); free(lens); return -1; }
        for (size_t k = e->first; k < e->first + e->count; k++)
            if (p->d[k].change != C_REINSTALLED) { paths[np] = p->d[k].path; lens[np++] = p->d[k].path_len; }
        const int r = belay_event_not_interpreted(ev, paths, lens, np, flags(e->prov));
        free(paths);
        free(lens);
        return r;
    }
    const char *paths[2] = { x->path, y ? y->path : NULL };
    const size_t lens[2] = { x->path_len, y ? y->path_len : 0 };
    const size_t np = y ? 2 : 1;
    struct belay_fv v[5];
    size_t n;
    if (e->kind == FK_PIP_INSTALLED || e->kind == FK_PIP_REMOVED) {
        v[0] = (struct belay_fv)FV(x->name, x->name_len);
        v[1] = (struct belay_fv)FV(x->version, x->version_len);
        n = 2;
    } else if (e->kind == FK_PIP_REINSTALLED) {
        v[0] = (struct belay_fv)FV(x->name, x->name_len);
        v[1] = (struct belay_fv)FV(x->version, x->version_len);
        v[2] = (struct belay_fv){ .i = x->files_added, .absent = x->uncounted };
        v[3] = (struct belay_fv){ .i = x->files_removed, .absent = x->uncounted };
        v[4] = (struct belay_fv){ .i = x->files_changed, .absent = x->uncounted };
        n = 5;
    } else {
        v[0] = (struct belay_fv)FV(y->name, y->name_len);
        v[1] = (struct belay_fv)FV(x->version, x->version_len);
        v[2] = (struct belay_fv)FV(y->version, y->version_len);
        n = 3;
    }
    return belay_event(ev, e->kind, v, n, paths, lens, np, flags(e->prov));
}

static int upath_cmp(const void *a, const void *b) {
    const struct unavail *x = a, *y = b;
    return str_cmp(x->path, x->path_len, y->path, y->path_len);
}

/* The events with no name, before every named one (E4: no name sorts
 * first), in the Kinds table's order: one could_not_interpret per RECORD not
 * interpreted (E10), by path; then one content_unavailable per reason, naming
 * its paths, the side theirs when they share one, else "both". */
static int unavailable_events(struct pip *p, struct belay_events *ev) {
    if (p->nu > 1) qsort(p->u, p->nu, sizeof *p->u, upath_cmp);
    for (size_t i = 0; i < p->nu; i++)
        if (p->u[i].why == SW_ERROR &&
            belay_event_not_interpreted(ev, &p->u[i].path, &p->u[i].path_len, 1, flags(p->u[i].prov)) == -1)
            return -1;
    for (int w = SW_NO_STORE; w < SW_ERROR; w++) {
        size_t n = 0;
        unsigned sides = 0;
        bool prov = false;
        for (size_t i = 0; i < p->nu; i++)
            if (p->u[i].why == (enum stored_why)w) { n++; sides |= 1u << p->u[i].side; prov |= p->u[i].prov; }
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
        const int r = belay_event(ev, FK_CONTENT_UNAVAILABLE, v, 2, paths, lens, n, flags(prov));
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
            bool gprov = false;
            for (size_t k = i; k < j; k++) {
                const struct dist *d = &p->d[k];
                if (d->change == C_REINSTALLED) { out[no++] = (struct pev){ d, NULL, FK_PIP_REINSTALLED, 0, 0, d->prov }; continue; }
                gprov |= d->prov;
                if (d->change == C_REMOVED) rem = d;
                else add = d;
            }
            if (added == 1 && removed == 1) {
                int cmp;
                const int kind = pep440_cmp(rem->version, rem->version_len, add->version,
                                            add->version_len, &cmp) == -1 || cmp == 0
                                     ? FK_PIP_VERSION_CHANGED
                                     : cmp < 0 ? FK_PIP_UPGRADED : FK_PIP_DOWNGRADED;
                out[no++] = (struct pev){ rem, add, kind, 0, 0, gprov };
            } else if (added && removed) {          /* no kind says it: E10, the rest stand */
                out[no++] = (struct pev){ &p->d[i], NULL, FK_COULD_NOT_INTERPRET, i, j - i, gprov };
            } else {
                for (size_t k = i; k < j; k++)
                    if (p->d[k].change != C_REINSTALLED)
                        out[no++] = (struct pev){ &p->d[k], NULL,
                                                  p->d[k].change == C_ADDED ? FK_PIP_INSTALLED : FK_PIP_REMOVED,
                                                  0, 0, p->d[k].prov };
            }
            i = j;
        }
        if (r == BELAY_INTERP_FINDINGS) {
            if (no > 1) qsort(out, no, sizeof *out, pev_cmp);
            if (unavailable_events(p, ev) == -1) r = BELAY_INTERP_ERROR;
            for (size_t i = 0; i < no && r == BELAY_INTERP_FINDINGS; i++)
                if (emit(p, ev, &out[i]) == -1) r = BELAY_INTERP_ERROR;
        }
    }
    free(out);
    pip_free(p);
    return r;
}

const struct belay_interp INTERP_PIP = { BELAY_INTERP_PIP, begin, explain, end };
