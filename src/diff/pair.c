#include "pair.h"

#include "belay/error.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct side {
    struct belay_manifest_reader *r;
    struct belay_entry *e;      /* current entry */
    int state;                  /* 1 e is current, 0 ended, -1 not yet read */
    bool used;                  /* e was yielded: advance before comparing */
};

struct pair_state {
    struct side s[2];
    char last[4096];            /* the path yielded last, to re-assert order */
    size_t last_len;
    bool have_last;
};

static int path_cmp(const char *a, size_t al, const char *b, size_t bl) {
    const size_t n = al < bl ? al : bl;
    const int r = memcmp(a, b, n);
    if (r != 0) return r;
    return (al > bl) - (al < bl);
}

struct pair_state *pair_new(struct belay_manifest_reader *before,
                            struct belay_manifest_reader *after) {
    struct pair_state *p = calloc(1, sizeof *p);
    if (p == NULL) return NULL;
    for (int i = 0; i < 2; i++) {
        p->s[i].r = i ? after : before;
        p->s[i].state = -1;
        p->s[i].e = malloc(sizeof *p->s[i].e);
        if (p->s[i].e == NULL) {
            pair_free(p);
            return NULL;
        }
    }
    return p;
}

void pair_free(struct pair_state *p) {
    if (p == NULL) return;
    free(p->s[0].e);
    free(p->s[1].e);
    free(p);
}

static int advance(struct side *s) {
    if (s->state == 0) return 0;
    if (s->state == 1 && !s->used) return 1;
    s->state = belay_manifest_next(s->r, s->e);
    s->used = false;
    return s->state;
}

int pair_next(struct pair_state *p, const struct belay_entry **before,
              const struct belay_entry **after) {
    const int b = advance(&p->s[0]), a = advance(&p->s[1]);
    if (b == -1 || a == -1) return -1;
    if (b == 0 && a == 0) return 0;
    const struct belay_entry *eb = b == 1 ? p->s[0].e : NULL, *ea = a == 1 ? p->s[1].e : NULL;
    if (eb != NULL && ea != NULL) {
        const int c = path_cmp(eb->path, eb->path_len, ea->path, ea->path_len);
        if (c < 0) ea = NULL;
        else if (c > 0) eb = NULL;
    }
    const struct belay_entry *e = eb != NULL ? eb : ea;
    /* The reader guarantees each side strictly increasing; the merge of two
     * such sequences is too. Re-asserted, since every pairing rests on it. */
    if (p->have_last && path_cmp(p->last, p->last_len, e->path, e->path_len) >= 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "diff: paths out of order");
        return -1;
    }
    memcpy(p->last, e->path, e->path_len);
    p->last_len = e->path_len;
    p->have_last = true;
    if (eb != NULL) p->s[0].used = true;
    if (ea != NULL) p->s[1].used = true;
    *before = eb;
    *after = ea;
    return 1;
}
