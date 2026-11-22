#include "sysev.h"
#include "stored.h"

#include "belay/manifest.h"

#include <stdlib.h>
#include <string.h>

/* ---- the two sides ---- */

bool sys_prov(const struct belay_interp_input *in) { return strcmp(in->outcome, "unknown") == 0; }

void sys_free(struct sysfile *f) {
    free(f->buf[0]);
    free(f->buf[1]);
    memset(f, 0, sizeof *f);
}

bool sys_read(const struct belay_interp_input *in, struct sysfile *f) {
    memset(f, 0, sizeof *f);
    for (int k = SIDE_BEFORE; k <= SIDE_AFTER; k++) {
        const struct belay_entry *e = side_entry(in, (enum side)k);
        if (e == NULL) continue;
        if (e->type != BELAY_T_REG || e->sealed || e->meta ||
            stored_read(in, (enum side)k, SYS_FILE_MAX, &f->buf[k], &f->len[k]) != SW_OK ||
            memchr(f->buf[k], '\0', f->len[k]) != NULL) {
            sys_free(f);
            return false;
        }
        f->have[k] = true;
    }
    return true;
}

/* ---- lines ---- */

struct sysline *sys_lines(const char *buf, size_t len, size_t *n, bool *oom) {
    size_t count = 0;
    *n = 0;
    *oom = false;
    for (size_t i = 0; i < len; i++) count += buf[i] == '\n';
    if (len > 0 && buf[len - 1] != '\n') count++;
    if (count == 0) return NULL;
    struct sysline *v = calloc(count, sizeof *v);
    if (v == NULL) { *oom = true; return NULL; }
    const char *p = buf, *end = buf + len;
    for (size_t i = 0; i < count; i++) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *e = nl ? nl : end;
        v[i] = (struct sysline){ .s = p, .n = (size_t)(e - p), .line = (uint32_t)(i + 1) };
        p = nl ? nl + 1 : end;
    }
    *n = count;
    return v;
}

static int line_cmp(const void *a, const void *b) {
    const struct sysline *x = *(struct sysline *const *)a, *y = *(struct sysline *const *)b;
    const int c = x->n && y->n ? memcmp(x->s, y->s, x->n < y->n ? x->n : y->n) : 0;
    if (c) return c;
    if (x->n != y->n) return x->n < y->n ? -1 : 1;
    return (x->line > y->line) - (x->line < y->line);
}
static int bytes_cmp(const struct sysline *x, const struct sysline *y) {
    const int c = x->n && y->n ? memcmp(x->s, y->s, x->n < y->n ? x->n : y->n) : 0;
    return c ? c : (x->n > y->n) - (x->n < y->n);
}

int sys_lines_diff(struct sysline *a, size_t na, struct sysline *b, size_t nb) {
    struct sysline **ia = malloc((na + 1) * sizeof *ia), **ib = malloc((nb + 1) * sizeof *ib);
    if (ia == NULL || ib == NULL) { free(ia); free(ib); return -1; }
    for (size_t i = 0; i < na; i++) { ia[i] = &a[i]; a[i].only = false; }
    for (size_t i = 0; i < nb; i++) { ib[i] = &b[i]; b[i].only = false; }
    if (na > 1) qsort(ia, na, sizeof *ia, line_cmp);
    if (nb > 1) qsort(ib, nb, sizeof *ib, line_cmp);
    size_t i = 0, j = 0;
    while (i < na || j < nb) {
        const int c = i == na ? 1 : j == nb ? -1 : bytes_cmp(ia[i], ib[j]);
        if (c < 0) ia[i++]->only = true;
        else if (c > 0) ib[j++]->only = true;
        else { i++; j++; }
    }
    free(ia);
    free(ib);
    return 0;
}

/* ---- small things ---- */

void sys_trim(const char **s, const char **e) {
    while (*s < *e && sys_blank(**s)) (*s)++;
    while (*e > *s && sys_blank((*e)[-1])) (*e)--;
}

bool sys_ends(const char *s, size_t n, const char *tail) {
    const size_t tl = strlen(tail);
    return n >= tl && memcmp(s + n - tl, tail, tl) == 0;
}

const char *sys_base(const char *path, size_t len, size_t *base_len, size_t *dir_len) {
    size_t i = len;
    while (i > 0 && path[i - 1] != '/') i--;
    if (base_len != NULL) *base_len = len - i;
    if (dir_len != NULL) *dir_len = i;
    return path + i;
}

bool sys_u32(const char *s, size_t n, uint32_t *out) {
    uint64_t v = 0;
    if (n == 0 || n > 10) return false;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    if (v > UINT32_MAX) return false;
    *out = (uint32_t)v;
    return true;
}

/* ---- the events ---- */

struct chunk { struct chunk *next; size_t used, cap; };

struct sysevs {
    struct chunk *chunks;
    size_t bytes;
    struct sysev **e;
    size_t n, cap, over;
    bool failed, asked;
};

struct sysevs *sysevs_new(void) { return calloc(1, sizeof(struct sysevs)); }

void sysevs_free(struct sysevs *s) {
    if (s == NULL) return;
    for (struct chunk *c = s->chunks; c != NULL; ) {
        struct chunk *next = c->next;
        free(c);
        c = next;
    }
    free(s->e);
    free(s);
}

bool sysevs_failed(const struct sysevs *s) { return s == NULL || s->failed; }

static void *arena(struct sysevs *s, size_t n) {
    n = (n + 15u) & ~(size_t)15u;
    if (s->failed) return NULL;
    if (s->chunks == NULL || s->chunks->cap - s->chunks->used < n) {
        const size_t cap = n > 65536u ? n : 65536u;
        if (s->bytes + cap > SYS_STATE_MAX) { s->failed = true; return NULL; }
        struct chunk *c = malloc(sizeof *c + cap);
        if (c == NULL) { s->failed = true; return NULL; }
        *c = (struct chunk){ s->chunks, 0, cap };
        s->chunks = c;
        s->bytes += cap;
    }
    void *p = (char *)(s->chunks + 1) + s->chunks->used;
    s->chunks->used += n;
    return p;
}

const char *sysevs_dup(struct sysevs *s, const char *p, size_t n) {
    char *q = arena(s, n + 1);
    if (q == NULL) return NULL;
    if (n) memcpy(q, p, n);
    q[n] = '\0';
    return q;
}

static struct sysev *slot(struct sysevs *s, const char *path, size_t path_len) {
    if (s->failed) return NULL;
    if (s->n >= EVENTS_PER_INTERP) { s->over++; return NULL; }
    if (s->n == s->cap) {
        const size_t c = s->cap ? 2 * s->cap : 64;
        struct sysev **q = realloc(s->e, c * sizeof *q);
        if (q == NULL) { s->failed = true; return NULL; }
        s->e = q;
        s->cap = c;
    }
    struct sysev *e = arena(s, sizeof *e);
    if (e == NULL) return NULL;
    memset(e, 0, sizeof *e);
    e->owner_field = -1;
    e->seq = s->n;
    e->path = sysevs_dup(s, path, path_len);
    e->path_len = path_len;
    if (e->path == NULL) return NULL;
    s->e[s->n++] = e;
    return e;
}

struct sysev *sysevs_add(struct sysevs *s, int kind, const char *path, size_t path_len, uint32_t line,
                         int rank, bool prov, const struct belay_fv *v, size_t n) {
    if (n > FINDING_FIELDS_MAX) { s->failed = true; return NULL; }
    struct sysev *e = slot(s, path, path_len);
    if (e == NULL) return NULL;
    e->kind = kind;
    e->line = line;
    e->rank = (uint8_t)rank;
    e->prov = prov;
    e->n = n;
    for (size_t k = 0; k < n; k++) {
        e->v[k] = v[k];
        if (v[k].s != NULL && (e->v[k].s = sysevs_dup(s, v[k].s, v[k].len)) == NULL) return NULL;
        if (v[k].nlist) {
            struct belay_fv *l = arena(s, v[k].nlist * sizeof *l);
            if (l == NULL) return NULL;
            for (size_t i = 0; i < v[k].nlist; i++) {
                l[i] = (struct belay_fv){ .len = v[k].list[i].len };
                if ((l[i].s = sysevs_dup(s, v[k].list[i].s ? v[k].list[i].s : "", v[k].list[i].len)) == NULL)
                    return NULL;
            }
            e->v[k].list = l;
        }
    }
    return e;
}

void sysevs_not_interpreted(struct sysevs *s, const char *path, size_t path_len, bool prov) {
    struct sysev *e = slot(s, path, path_len);
    if (e != NULL) e->prov = prov;
}

enum belay_interp_result sys_cannot(struct sysevs *s, const struct belay_interp_input *in) {
    const bool prov = sys_prov(in);
    sysevs_not_interpreted(s, in->path, in->path_len, prov);
    if (s->failed) return BELAY_INTERP_ERROR;
    return prov ? BELAY_INTERP_DECLINE : BELAY_INTERP_ERROR;
}

void sysevs_owner(struct sysevs *s, struct sysev *e, int field, const char *path, size_t len) {
    if (e == NULL) return;
    e->owner_path = sysevs_dup(s, path, len);
    e->owner_len = len;
    e->owner_field = e->owner_path != NULL ? field : -1;
    if (field >= 0 && (size_t)field < e->n) e->v[field] = (struct belay_fv){ .absent = true };
}

size_t sysevs_count(const struct sysevs *s) { return s->n; }
struct sysev *sysevs_at(struct sysevs *s, size_t i) { return s->e[i]; }

int sysevs_ask_owners(struct sysevs *s, struct belay_lookup *lk) {
    if (s->asked) return 0;
    s->asked = true;
    for (size_t i = 0; i < s->n; i++) {
        const struct sysev *e = s->e[i];
        if (!e->drop && e->owner_field >= 0 && belay_owner_ask(lk, e->owner_path, e->owner_len) == -1) return -1;
    }
    return 0;
}

/* E13: by path, then the line's place, removed before added, then kind (a
 * file that could not be interpreted first), then the order they were
 * found in. */
static int ev_cmp(const void *a, const void *b) {
    const struct sysev *x = *(struct sysev *const *)a, *y = *(struct sysev *const *)b;
    int c = memcmp(x->path, y->path, x->path_len < y->path_len ? x->path_len : y->path_len);
    if (c == 0) c = (x->path_len > y->path_len) - (x->path_len < y->path_len);
    if (c == 0) c = (x->line > y->line) - (x->line < y->line);
    if (c == 0) c = (int)x->rank - (int)y->rank;
    if (c == 0) c = x->kind - y->kind;
    if (c == 0) c = (x->seq > y->seq) - (x->seq < y->seq);
    return c;
}

enum belay_interp_result sysevs_emit(struct sysevs *s, struct belay_events *ev, const struct belay_lookup *lk) {
    if (s->failed) return BELAY_INTERP_ERROR;
    if (s->n > 1) qsort(s->e, s->n, sizeof *s->e, ev_cmp);
    size_t written = 0;
    for (size_t i = 0; i < s->n; i++) {
        struct sysev *e = s->e[i];
        if (e->drop) continue;
        const char *paths[2] = { e->path, e->path2 };
        const size_t lens[2] = { e->path_len, e->path2_len };
        const size_t np = e->path2 != NULL ? 2 : 1;
        const unsigned flags = e->prov ? BELAY_EVENT_PROVISIONAL : 0;
        written++;
        if (e->kind == 0) {
            if (belay_event_not_interpreted(ev, paths, lens, 1, flags) == -1) return BELAY_INTERP_ERROR;
            continue;
        }
        if (e->owner_field >= 0 && (size_t)e->owner_field < e->n) {
            const char *pkg = NULL;
            size_t pl = 0;
            const enum belay_owned o = lk != NULL ? belay_owner_of(lk, e->owner_path, e->owner_len, &pkg, &pl)
                                                  : BELAY_OWNER_ABSENT;
            e->v[e->owner_field] = o == BELAY_OWNER_PACKAGE ? (struct belay_fv){ .s = pkg, .len = pl }
                                 : o == BELAY_OWNER_NONE ? (struct belay_fv){ .null = true }
                                                         : (struct belay_fv){ .absent = true };
        }
        if (belay_event(ev, e->kind, e->v, e->n, paths, lens, np, flags) == -1) return BELAY_INTERP_ERROR;
    }
    if (s->over) {
        /* Past the bound the events were only counted: the core counts them
         * into and_more (E5), which it can only do from a full list. */
        if (written < EVENTS_PER_INTERP) return BELAY_INTERP_ERROR;
        const char *p = s->e[0]->path;
        const size_t pl = s->e[0]->path_len;
        for (size_t k = 0; k < s->over; k++)
            if (belay_event_not_interpreted(ev, &p, &pl, 1, 0) == -1) return BELAY_INTERP_ERROR;
    }
    return BELAY_INTERP_FINDINGS;
}
