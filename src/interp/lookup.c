/*
 *  Lookups (belay/interp.h, "Lookup"; system-interpreters.md SI-4): what the
 *  prepare hooks asked for in a round, and the delivery of the entries of
 *  the after-manifest to them as the diff reads it once more. Exact paths
 *  are found by binary search, so a pass costs the manifest's entries times
 *  the logarithm of what was asked; memory is what was asked.
 */
#include "lookup_internal.h"

#include "belay/error.h"
#include "belay/manifest.h"

#include <stdlib.h>
#include <string.h>

void lookup_init(struct belay_lookup *lk, const struct belay_content *content) {
    memset(lk, 0, sizeof *lk);
    lk->content = content;
}

void lookup_round_end(struct belay_lookup *lk) {
    for (size_t i = 0; i < lk->n; i++) free(lk->w[i].path);
    lk->n = 0;
    lk->sorted = false;
}

void lookup_free(struct belay_lookup *lk) {
    lookup_round_end(lk);
    free(lk->w);
    owners_free(lk->owners);
    memset(lk, 0, sizeof *lk);
}

size_t lookup_wanted(const struct belay_lookup *lk) { return lk->n; }

const struct belay_content *belay_lookup_content(const struct belay_lookup *lk) { return lk->content; }

int belay_lookup_want(struct belay_lookup *lk, const char *path, size_t len, bool below,
                      belay_lookup_fn fn, void *ctx) {
    if (lk == NULL || path == NULL || fn == NULL || len == 0 || len > 4096 || lk->n >= BELAY_LOOKUP_WANTS) return -1;
    if (lk->n == lk->cap) {
        const size_t c = lk->cap ? 2 * lk->cap : 16;
        struct lk_want *q = realloc(lk->w, c * sizeof *q);
        if (q == NULL) { lk->failed = true; return -1; }
        lk->w = q;
        lk->cap = c;
    }
    char *p = malloc(len + 1);
    if (p == NULL) { lk->failed = true; return -1; }
    memcpy(p, path, len);
    p[len] = '\0';
    lk->w[lk->n++] = (struct lk_want){ p, len, below, fn, ctx, lk->current };
    lk->sorted = false;
    return 0;
}

static int bytes_cmp(const char *a, size_t an, const char *b, size_t bn) {
    const int c = memcmp(a, b, an < bn ? an : bn);
    return c ? c : (an > bn) - (an < bn);
}

/* Exact wants first, by path; the directory wants after them (they are
 * few, and each is tried against every entry). */
static int want_cmp(const void *a, const void *b) {
    const struct lk_want *x = a, *y = b;
    if (x->below != y->below) return x->below ? 1 : -1;
    return bytes_cmp(x->path, x->len, y->path, y->len);
}

static void deliver(struct belay_lookup *lk, const struct lk_want *w, const struct belay_entry *e) {
    if (!lk->hook_failed[w->interp] && w->fn(w->ctx, e) != 0) lk->hook_failed[w->interp] = true;
}

void lookup_feed(struct belay_lookup *lk, const struct belay_entry *e) {
    if (lk->n == 0) return;
    if (!lk->sorted) {
        qsort(lk->w, lk->n, sizeof *lk->w, want_cmp);
        lk->sorted = true;
    }
    size_t exact = lk->n;
    while (exact > 0 && lk->w[exact - 1].below) exact--;
    size_t lo = 0, hi = exact;
    while (lo < hi) {                           /* the first exact want not before e's path */
        const size_t mid = lo + (hi - lo) / 2;
        if (bytes_cmp(lk->w[mid].path, lk->w[mid].len, e->path, e->path_len) < 0) lo = mid + 1;
        else hi = mid;
    }
    for (size_t i = lo; i < exact && lk->w[i].len == e->path_len && memcmp(lk->w[i].path, e->path, e->path_len) == 0; i++)
        deliver(lk, &lk->w[i], e);
    for (size_t i = exact; i < lk->n; i++) {
        const struct lk_want *w = &lk->w[i];
        if (e->path_len > w->len && e->path[w->len] == '/' && memcmp(e->path, w->path, w->len) == 0)
            deliver(lk, w, e);
    }
}

/* ---- ownership, for the interpreters of a diff ---- */

int belay_owner_ask(struct belay_lookup *lk, const char *path, size_t len) {
    if (lk == NULL || lk->owners_done) return 0;        /* too late: its answer is "absent" */
    if (lk->owners == NULL && (lk->owners = owners_new()) == NULL) { lk->failed = true; return -1; }
    if (owners_ask(lk->owners, path, len) == -1) { lk->failed = true; return -1; }
    return 0;
}

bool lookup_owner_pending(const struct belay_lookup *lk) { return lk->owners != NULL && !lk->owners_done; }

int lookup_owner_feed(struct belay_lookup *lk, const struct belay_entry *e) {
    return lk->owners != NULL ? owners_feed(lk->owners, e, lk->content) : 0;
}

void lookup_owner_done(struct belay_lookup *lk) {
    if (lk->owners != NULL) owners_done(lk->owners);
    lk->owners_done = true;
}

enum belay_owned belay_owner_of(const struct belay_lookup *lk, const char *path, size_t len,
                                const char **pkg, size_t *pkg_len) {
    if (lk == NULL || lk->owners == NULL || !lk->owners_done) return BELAY_OWNER_ABSENT;
    return owners_get(lk->owners, path, len, pkg, pkg_len);
}

/* ---- ownership by a manifest, outside a diff ---- */

int owners_of_manifest(const char *manifest, const char *store_dir, const char *const *paths,
                       const size_t *lens, size_t n, struct owners **out) {
    struct owners *o = owners_new();
    struct belay_manifest_reader *r = NULL;
    struct belay_content *c = NULL;
    struct belay_entry *e = malloc(sizeof *e);
    int rc = -1, got = 0;
    *out = NULL;
    if (o == NULL || e == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "owners: out of memory");
        goto done;
    }
    for (size_t i = 0; i < n; i++)
        if (owners_ask(o, paths[i], lens[i]) == -1) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "owners: out of memory");
            goto done;
        }
    if (store_dir != NULL && belay_content_open(store_dir, &c) == -1) goto done;
    if (belay_manifest_open(manifest, &r) == -1) goto done;
    while ((got = belay_manifest_next(r, e)) == 1)
        if (owners_feed(o, e, c) == -1) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "owners: out of memory");
            goto done;
        }
    if (got == -1) goto done;
    owners_done(o);
    *out = o;
    o = NULL;
    rc = 0;
done:
    owners_free(o);
    free(e);
    belay_manifest_close(r);
    belay_content_close(c);
    return rc;
}
