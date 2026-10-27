#include "runs.h"

#include "belay/error.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define FANIN  16
#define LEVELS 12                       /* 16^12 runs: unreachable in practice */

/* A record is [u32 key length][key][u32 value length][value]. */
struct cursor {
    FILE *f;
    uint32_t klen, vlen;
    unsigned char *buf;                 /* max_key bytes of key, then max_val of value */
    int live;
};

struct runs {
    size_t budget, used;
    uint32_t max_key, max_val;
    unsigned char *arena;
    size_t *offs, *scratch;
    size_t n, cap;
    size_t added;
    FILE *level[LEVELS][FANIN];
    size_t nlevel[LEVELS];
    runs_tmpfile_fn tmp;
    void *tmp_ctx;

    /* Iteration: over the arena (nothing spilled) or a merge of `final`. */
    FILE *final[LEVELS * FANIN];
    size_t nfinal;
    struct cursor cur[FANIN];
    struct cursor *last;                /* handed out last; advanced on the next call */
    size_t pos;
    unsigned char *prev;
    uint32_t prev_len;
    int have_prev, sealed, spilled;
};

static int rec_cmp(const unsigned char *a, const unsigned char *b) {
    uint32_t la, lb;
    memcpy(&la, a, 4);
    memcpy(&lb, b, 4);
    const int r = memcmp(a + 4, b + 4, la < lb ? la : lb);
    if (r != 0) return r;
    return (la > lb) - (la < lb);
}

static size_t rec_size(const unsigned char *r) {
    uint32_t kl, vl;
    memcpy(&kl, r, 4);
    memcpy(&vl, r + 4 + kl, 4);
    return 8 + (size_t)kl + vl;
}

/* Bottom-up merge sort of record offsets. Written out rather than qsort()
 * because the comparator needs the arena base and qsort_r differs between
 * glibc and macOS; a file-static context would make it non-reentrant. */
static void sort_offs(const unsigned char *base, size_t *a, size_t *tmp, size_t n) {
    for (size_t width = 1; width < n; width *= 2) {
        for (size_t lo = 0; lo < n; lo += 2 * width) {
            const size_t mid = lo + width < n ? lo + width : n;
            const size_t hi  = lo + 2 * width < n ? lo + 2 * width : n;
            size_t i = lo, j = mid, k = lo;
            while (i < mid && j < hi)
                tmp[k++] = rec_cmp(base + a[i], base + a[j]) <= 0 ? a[i++] : a[j++];
            while (i < mid) tmp[k++] = a[i++];
            while (j < hi)  tmp[k++] = a[j++];
        }
        memcpy(a, tmp, n * sizeof *a);
    }
}

static FILE *open_tmp(struct runs *r) {
    FILE *f = r->tmp(r->tmp_ctx);
    if (f == NULL) belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot create temporary file");
    return f;
}

static int cur_next(const struct runs *r, struct cursor *c) {
    uint32_t kl, vl;
    const size_t got = fread(&kl, 1, 4, c->f);
    if (got == 0 && feof(c->f)) { c->live = 0; return 0; }
    if (got != 4 || kl == 0 || kl > r->max_key) goto bad;
    if (fread(c->buf, 1, kl, c->f) != kl) goto bad;
    if (fread(&vl, 1, 4, c->f) != 4 || vl > r->max_val) goto bad;
    if (fread(c->buf + r->max_key, 1, vl, c->f) != vl) goto bad;
    c->klen = kl;
    c->vlen = vl;
    c->live = 1;
    return 0;
bad:
    belay_err_set(BELAY_ERR_IO, errno, "manifest: temporary run is unreadable");
    return -1;
}

static int cur_cmp(const struct cursor *a, const struct cursor *b) {
    const int r = memcmp(a->buf, b->buf, a->klen < b->klen ? a->klen : b->klen);
    if (r != 0) return r;
    return (a->klen > b->klen) - (a->klen < b->klen);
}

/* Strictly increasing keys, checked on every record handed on. */
static int in_order(struct runs *r, const unsigned char *key, uint32_t klen) {
    if (r->have_prev) {
        const int c = memcmp(r->prev, key, r->prev_len < klen ? r->prev_len : klen);
        if (c > 0 || (c == 0 && r->prev_len >= klen)) {
            belay_err_set(BELAY_ERR_CORRUPT, 0,
                          "manifest: the filesystem listed one name twice; refusing");
            return -1;
        }
    }
    memcpy(r->prev, key, klen);
    r->prev_len = klen;
    r->have_prev = 1;
    return 0;
}

static int cursors_open(struct runs *r, FILE **in, size_t k) {
    for (size_t i = 0; i < k; i++) {
        r->cur[i].f = in[i];
        r->cur[i].live = 0;
        if (fseek(in[i], 0, SEEK_SET) != 0 || cur_next(r, &r->cur[i]) == -1) return -1;
    }
    return 0;
}

static struct cursor *cursors_min(struct runs *r, size_t k) {
    struct cursor *m = NULL;
    for (size_t i = 0; i < k; i++)
        if (r->cur[i].live && (m == NULL || cur_cmp(&r->cur[i], m) < 0)) m = &r->cur[i];
    return m;
}

/* K-way merge of `k` runs into one run `out`. */
static int merge_into(struct runs *r, FILE **in, size_t k, FILE *out) {
    r->have_prev = 0;
    if (cursors_open(r, in, k) == -1) return -1;
    for (struct cursor *m; (m = cursors_min(r, k)) != NULL; ) {
        if (in_order(r, m->buf, m->klen) == -1) return -1;
        if (fwrite(&m->klen, 1, 4, out) != 4 || fwrite(m->buf, 1, m->klen, out) != m->klen ||
            fwrite(&m->vlen, 1, 4, out) != 4 ||
            fwrite(m->buf + r->max_key, 1, m->vlen, out) != m->vlen) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: write failed during merge");
            return -1;
        }
        if (cur_next(r, m) == -1) return -1;
    }
    return fflush(out) == 0 ? 0 : -1;
}

static int spill(struct runs *r) {
    if (r->n == 0) return 0;
    sort_offs(r->arena, r->offs, r->scratch, r->n);
    FILE *f = open_tmp(r);
    if (f == NULL) return -1;
    for (size_t i = 0; i < r->n; i++) {
        const unsigned char *rec = r->arena + r->offs[i];
        const size_t sz = rec_size(rec);
        if (fwrite(rec, 1, sz, f) != sz) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: temporary run write failed");
            fclose(f);
            return -1;
        }
    }
    if (fflush(f) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: temporary run write failed");
        fclose(f);
        return -1;
    }
    r->level[0][r->nlevel[0]++] = f;
    r->used = 0;
    r->n = 0;
    r->spilled = 1;

    /* Cascade: a full level becomes one run one level up. */
    for (size_t lv = 0; lv + 1 < LEVELS && r->nlevel[lv] == FANIN; lv++) {
        FILE *merged = open_tmp(r);
        if (merged == NULL) return -1;
        if (merge_into(r, r->level[lv], FANIN, merged) == -1) {
            fclose(merged);
            return -1;
        }
        for (size_t i = 0; i < FANIN; i++) fclose(r->level[lv][i]);
        r->nlevel[lv] = 0;
        r->level[lv + 1][r->nlevel[lv + 1]++] = merged;
    }
    if (r->nlevel[LEVELS - 1] == FANIN) {
        belay_err_set(BELAY_ERR_RANGE, 0, "manifest: too many entries to sort");
        return -1;
    }
    return 0;
}

struct runs *runs_new(size_t budget, uint32_t max_key, uint32_t max_val,
                      runs_tmpfile_fn tmp, void *tmp_ctx) {
    struct runs *r = calloc(1, sizeof *r);
    const size_t min = 8 + (size_t)max_key + max_val;
    if (r != NULL) {
        r->budget = budget < min ? min : budget;
        r->max_key = max_key;
        r->max_val = max_val;
        r->tmp = tmp;
        r->tmp_ctx = tmp_ctx;
        r->arena = malloc(r->budget);
        r->prev = malloc(max_key);
        for (size_t i = 0; i < FANIN; i++) r->cur[i].buf = malloc((size_t)max_key + max_val);
    }
    int ok = r != NULL && r->arena != NULL && r->prev != NULL;
    for (size_t i = 0; ok && i < FANIN; i++) ok = r->cur[i].buf != NULL;
    if (!ok) {
        runs_free(r);
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        return NULL;
    }
    return r;
}

void runs_free(struct runs *r) {
    if (r == NULL) return;
    for (size_t lv = 0; lv < LEVELS; lv++)
        for (size_t i = 0; i < r->nlevel[lv]; i++) fclose(r->level[lv][i]);
    for (size_t i = 0; i < r->nfinal; i++) fclose(r->final[i]);
    for (size_t i = 0; i < FANIN; i++) free(r->cur[i].buf);
    free(r->arena);
    free(r->offs);
    free(r->scratch);
    free(r->prev);
    free(r);
}

int runs_add(struct runs *r, const void *key, uint32_t klen, const void *val, uint32_t vlen) {
    const size_t sz = 8 + (size_t)klen + vlen;
    if (r->used + sz > r->budget && spill(r) == -1) return -1;
    if (r->n == r->cap) {
        const size_t ncap = r->cap ? r->cap * 2 : 4096;
        size_t *no = realloc(r->offs, ncap * sizeof *no);
        if (no == NULL) goto nomem;
        r->offs = no;
        size_t *ns = realloc(r->scratch, ncap * sizeof *ns);
        if (ns == NULL) goto nomem;
        r->scratch = ns;
        r->cap = ncap;
    }
    unsigned char *rec = r->arena + r->used;
    memcpy(rec, &klen, 4);
    memcpy(rec + 4, key, klen);
    memcpy(rec + 4 + klen, &vlen, 4);
    memcpy(rec + 8 + klen, val, vlen);
    r->offs[r->n++] = r->used;
    r->used += sz;
    r->added++;
    return 0;
nomem:
    belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
    return -1;
}

/* Everything in the arena: sort it. Otherwise spill the rest, then merge
 * the smallest runs (lowest level first, so the least data is rewritten)
 * until at most FANIN remain for the final, repeatable, merge. */
int runs_seal(struct runs *r) {
    r->sealed = 1;
    if (!r->spilled) {
        sort_offs(r->arena, r->offs, r->scratch, r->n);
        return 0;
    }
    if (spill(r) == -1) return -1;
    for (size_t lv = 0; lv < LEVELS; lv++) {
        for (size_t i = 0; i < r->nlevel[lv]; i++) r->final[r->nfinal++] = r->level[lv][i];
        r->nlevel[lv] = 0;
    }
    while (r->nfinal > FANIN) {
        FILE *merged = open_tmp(r);
        if (merged == NULL) return -1;
        if (merge_into(r, r->final, FANIN, merged) == -1) {
            fclose(merged);
            return -1;
        }
        for (size_t i = 0; i < FANIN; i++) fclose(r->final[i]);
        memmove(r->final, r->final + FANIN, (r->nfinal - FANIN) * sizeof *r->final);
        r->nfinal -= FANIN;
        r->final[r->nfinal++] = merged;
    }
    return 0;
}

int runs_rewind(struct runs *r) {
    r->pos = 0;
    r->have_prev = 0;
    r->last = NULL;
    return r->spilled ? cursors_open(r, r->final, r->nfinal) : 0;
}

int runs_next(struct runs *r, const unsigned char **key, uint32_t *klen,
              const unsigned char **val, uint32_t *vlen) {
    if (!r->spilled) {
        if (r->pos == r->n) return 0;
        const unsigned char *rec = r->arena + r->offs[r->pos++];
        memcpy(klen, rec, 4);
        *key = rec + 4;
        memcpy(vlen, rec + 4 + *klen, 4);
        *val = rec + 8 + *klen;
    } else {
        /* The record handed out last stays valid until now; only then is its
         * cursor advanced. */
        if (r->last != NULL && cur_next(r, r->last) == -1) return -1;
        struct cursor *m = cursors_min(r, r->nfinal);
        r->last = m;
        if (m == NULL) return 0;
        *key = m->buf;
        *klen = m->klen;
        *val = m->buf + r->max_key;
        *vlen = m->vlen;
    }
    return in_order(r, *key, *klen) == -1 ? -1 : 1;
}

size_t runs_count(const struct runs *r) { return r->added; }
