/*
 *  The git interpreter (finding-kinds.md, git_*): refs, hooks, the index
 *  and the reflog, path by path, without object access. Stateless: every
 *  finding is about its own path. The reflog is written by the watched
 *  process, so what it says is evidence, not proof (diff-v1, Interpreters).
 */
#include "builtins.h"
#include "gitfmt.h"
#include "stored.h"

#include "belay/error.h"
#include "belay/manifest.h"
#include "schema/finding_schema.h"

#include <stdlib.h>
#include <string.h>

#define GIT_REF_MAX    (64u * 1024u)            /* HEAD or a loose ref */
#define GIT_PACKED_MAX (64u * 1024u * 1024u)    /* packed-refs */
#define GIT_LOG_MAX    (64u * 1024u * 1024u)    /* a reflog (stored within the store limit) */

enum git_file { G_NONE, G_INDEX, G_HEAD, G_PACKED, G_REF, G_HOOK, G_LOG };

/* What the path is within its .git directory, by dispatch's rules in
 * dispatch's order: for each, the last "/.git/" whose remainder it matches.
 * *name is the remainder (a ref, a hook) or, for a reflog, its ref. */
static enum git_file which(const char *p, size_t n, const char **name, size_t *name_len) {
    static const struct { const char *s; bool prefix; enum git_file f; } R[] = {
        { "index", false, G_INDEX }, { "HEAD", false, G_HEAD }, { "packed-refs", false, G_PACKED },
        { "refs/", true, G_REF }, { "hooks/", true, G_HOOK }, { "logs/HEAD", false, G_LOG },
        { "logs/refs/", true, G_LOG },
    };
    for (size_t r = 0; r < sizeof R / sizeof R[0]; r++) {
        const size_t rl = strlen(R[r].s);
        for (size_t i = n; i-- > 0;) {
            if (i + 6 > n || memcmp(p + i, "/.git/", 6) != 0) continue;
            const char *rest = p + i + 6;
            const size_t rn = n - i - 6;
            if (R[r].prefix ? rn < rl || memcmp(rest, R[r].s, rl) != 0
                            : rn != rl || memcmp(rest, R[r].s, rl) != 0)
                continue;
            *name = rest;
            *name_len = rn;
            if (R[r].f == G_HOOK) { *name += 6; *name_len -= 6; }
            if (R[r].f == G_LOG) { *name += 5; *name_len -= 5; }
            return R[r].f;
        }
    }
    return G_NONE;
}

static bool is(const struct belay_interp_input *in, const char *outcome) {
    return strcmp(in->outcome, outcome) == 0;
}

#define FV(p, n) { .s = (p), .len = (n) }

struct sides {
    unsigned char *buf[2];
    size_t len[2];
    bool ok, error;
};

/* Is the path a regular file on side k? A ref file that became a directory
 * (refs/heads/x to refs/heads/x/y) is absent as a file. */
static bool reg(const struct belay_interp_input *in, int k) {
    const struct belay_entry *e = side_entry(in, (enum side)k);
    return e != NULL && e->type == BELAY_T_REG;
}

/* Reads each side the path is a regular file on, saying content_unavailable
 * for each that cannot be read. */
static void read_sides(const struct belay_interp_input *in, size_t max, struct belay_findings *out,
                       struct sides *s) {
    memset(s, 0, sizeof *s);
    s->ok = true;
    for (int k = SIDE_BEFORE; k <= SIDE_AFTER; k++) {
        if (!reg(in, k)) continue;
        const enum stored_why w = stored_read(in, (enum side)k, max, &s->buf[k], &s->len[k]);
        if (w == SW_OK) continue;
        s->ok = false;
        if (w == SW_ERROR || stored_unavailable(out, w, (enum side)k) == -1) s->error = true;
    }
}

static void free_sides(struct sides *s) { free(s->buf[0]); free(s->buf[1]); }

/* HEAD or a loose ref: its value, "" where the path is absent. */
static int ref_value(const struct sides *s, int k, const char **v, size_t *vl) {
    *v = "";
    *vl = 0;
    if (s->buf[k] == NULL) return 0;
    bool sym;
    return git_ref_value((const char *)s->buf[k], s->len[k], &sym, v, vl);
}

static enum belay_interp_result ref_file(const struct belay_interp_input *in, enum git_file f,
                                         const char *name, size_t nl, struct belay_findings *out) {
    struct sides s;
    read_sides(in, GIT_REF_MAX, out, &s);
    enum belay_interp_result r = s.error ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    const char *from, *to;
    size_t fl, tl;
    if (s.ok && r == BELAY_INTERP_FINDINGS) {
        if (ref_value(&s, SIDE_BEFORE, &from, &fl) == -1 || ref_value(&s, SIDE_AFTER, &to, &tl) == -1) {
            belay_err_clear();
            r = BELAY_INTERP_ERROR;
        } else if ((!reg(in, SIDE_BEFORE) && !reg(in, SIDE_AFTER)) ||
                   (reg(in, SIDE_BEFORE) && reg(in, SIDE_AFTER) && fl == tl && memcmp(from, to, fl) == 0)) {
            r = BELAY_INTERP_DECLINE;           /* no file, or the same value: nothing moved */
        } else if (f == G_HEAD) {
            const struct belay_fv v[] = { FV(from, fl), FV(to, tl) };
            if (belay_finding(out, FK_GIT_HEAD_CHANGED, v, 2) == -1) r = BELAY_INTERP_ERROR;
        } else if (!reg(in, SIDE_BEFORE)) {
            const struct belay_fv v[] = { FV(name, nl), FV(to, tl) };
            if (belay_finding(out, FK_GIT_REF_CREATED, v, 2) == -1) r = BELAY_INTERP_ERROR;
        } else if (!reg(in, SIDE_AFTER)) {
            const struct belay_fv v[] = { FV(name, nl), FV(from, fl) };
            if (belay_finding(out, FK_GIT_REF_DELETED, v, 2) == -1) r = BELAY_INTERP_ERROR;
        } else {
            const struct belay_fv v[] = { FV(name, nl), FV(from, fl), FV(to, tl) };
            if (belay_finding(out, FK_GIT_REF_MOVED, v, 3) == -1) r = BELAY_INTERP_ERROR;
        }
    }
    free_sides(&s);
    return r;
}

/* ---- packed-refs: each side's (ref, oid) lines, sorted by ref ---- */

struct pref { const char *ref, *oid; size_t rl, ol, at; };
struct prefs { struct pref *v; size_t n, cap; };

static int pref_add(const char *ref, size_t rl, const char *oid, size_t ol, void *ctx) {
    struct prefs *p = ctx;
    if (p->n == p->cap) {
        const size_t c = p->cap ? 2 * p->cap : 64;
        struct pref *q = realloc(p->v, c * sizeof *q);
        if (q == NULL) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "git: out of memory");
            return -1;
        }
        p->v = q;
        p->cap = c;
    }
    p->v[p->n] = (struct pref){ ref, oid, rl, ol, p->n };
    p->n++;
    return 0;
}

static int ref_cmp(const struct pref *x, const struct pref *y) {
    const int c = memcmp(x->ref, y->ref, x->rl < y->rl ? x->rl : y->rl);
    return c ? c : (x->rl > y->rl) - (x->rl < y->rl);
}
static int pref_cmp(const void *a, const void *b) {
    const struct pref *x = a, *y = b;
    const int c = ref_cmp(x, y);
    return c ? c : (x->at > y->at) - (x->at < y->at);
}

/* Sorted by ref; a ref given twice keeps its first line. */
static void pref_sort(struct prefs *p) {
    if (p->n > 1) qsort(p->v, p->n, sizeof *p->v, pref_cmp);
    size_t w = 0;
    for (size_t i = 0; i < p->n; i++)
        if (w == 0 || ref_cmp(&p->v[w - 1], &p->v[i]) != 0) p->v[w++] = p->v[i];
    p->n = w;
}

static enum belay_interp_result packed(const struct belay_interp_input *in,
                                       struct belay_findings *out) {
    struct sides s;
    read_sides(in, GIT_PACKED_MAX, out, &s);
    enum belay_interp_result r = s.error ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    struct prefs p[2] = { { 0 }, { 0 } };
    for (int k = 0; k < 2 && s.ok && r == BELAY_INTERP_FINDINGS; k++)
        if (s.buf[k] != NULL &&
            git_packed_each((const char *)s.buf[k], s.len[k], pref_add, &p[k]) != 0) {
            belay_err_clear();
            r = BELAY_INTERP_ERROR;
        }
    if (s.ok && r == BELAY_INTERP_FINDINGS) {
        pref_sort(&p[0]);
        pref_sort(&p[1]);
        size_t i = 0, j = 0;
        while ((i < p[0].n || j < p[1].n) && r == BELAY_INTERP_FINDINGS) {
            const int c = i == p[0].n ? 1 : j == p[1].n ? -1 : ref_cmp(&p[0].v[i], &p[1].v[j]);
            int rc = 0;
            if (c < 0) {
                const struct belay_fv v[] = { FV(p[0].v[i].ref, p[0].v[i].rl), FV(p[0].v[i].oid, p[0].v[i].ol) };
                rc = belay_finding(out, FK_GIT_REF_DELETED, v, 2);
                i++;
            } else if (c > 0) {
                const struct belay_fv v[] = { FV(p[1].v[j].ref, p[1].v[j].rl), FV(p[1].v[j].oid, p[1].v[j].ol) };
                rc = belay_finding(out, FK_GIT_REF_CREATED, v, 2);
                j++;
            } else {
                const struct pref *a = &p[0].v[i], *b = &p[1].v[j];
                if (a->ol != b->ol || memcmp(a->oid, b->oid, a->ol) != 0) {
                    const struct belay_fv v[] = { FV(a->ref, a->rl), FV(a->oid, a->ol), FV(b->oid, b->ol) };
                    rc = belay_finding(out, FK_GIT_REF_MOVED, v, 3);
                }
                i++;
                j++;
            }
            if (rc == -1) r = BELAY_INTERP_ERROR;
        }
    }
    free(p[0].v);
    free(p[1].v);
    free_sides(&s);
    return r;
}

/* ---- hooks: from the manifest alone (hash and mode), never content ---- */

static bool executable(const struct belay_entry *e) { return (e->mode & 0100) != 0; }

static enum belay_interp_result hook(const struct belay_interp_input *in, const char *name,
                                     size_t nl, struct belay_findings *out) {
    int rc;
    const bool b = reg(in, SIDE_BEFORE), a = reg(in, SIDE_AFTER);
    if (!b && !a) return BELAY_INTERP_DECLINE;          /* a directory, a link: no hook file */
    if (!b) {
        const struct belay_fv v[] = { FV(name, nl), { .b = executable(in->after) } };
        rc = belay_finding(out, FK_GIT_HOOK_ADDED, v, 2);
    } else if (!a) {
        const struct belay_fv v[] = { FV(name, nl) };
        rc = belay_finding(out, FK_GIT_HOOK_REMOVED, v, 1);
    } else if (is(in, "modified")) {
        const struct belay_fv v[] = { FV(name, nl), { .b = executable(in->after) } };
        rc = belay_finding(out, FK_GIT_HOOK_CHANGED, v, 2);
    } else if (executable(in->before) != executable(in->after)) {      /* metadata_only */
        const struct belay_fv v[] = { FV(name, nl), { .b = executable(in->after) } };
        rc = belay_finding(out, FK_GIT_HOOK_EXECUTABLE_CHANGED, v, 2);
    } else {
        return BELAY_INTERP_DECLINE;
    }
    return rc == -1 ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
}

/* ---- the reflog ---- */

struct appended { struct belay_findings *out; const char *ref; size_t rl; size_t n; int rc; };

static bool plain(const struct git_reflog_entry *e) {
    static const char FF[] = "Fast-forward";
    if ((e->operation_len == 6 && memcmp(e->operation, "commit", 6) == 0) ||
        (e->operation_len == 16 && memcmp(e->operation, "commit (initial)", 16) == 0))
        return true;
    for (size_t i = 0; i + sizeof FF - 1 <= e->message_len; i++)
        if (memcmp(e->message + i, FF, sizeof FF - 1) == 0) return true;
    return false;
}

static int count_entries(const struct git_reflog_entry *e, void *ctx) {
    (void)e;
    ((struct appended *)ctx)->n++;
    return 0;
}

static int moves(const struct git_reflog_entry *e, void *ctx) {
    struct appended *a = ctx;
    if (plain(e)) return 0;
    const struct belay_fv v[] = { FV(a->ref, a->rl), FV(e->old_oid, e->oid_len),
                                  FV(e->new_oid, e->oid_len), FV(e->operation, e->operation_len) };
    return belay_finding(a->out, FK_GIT_REFLOG_MOVE, v, 4);
}

static enum belay_interp_result reflog(const struct belay_interp_input *in, const char *ref,
                                       size_t rl, struct belay_findings *out) {
    if (!reg(in, SIDE_BEFORE) && !reg(in, SIDE_AFTER)) return BELAY_INTERP_DECLINE;  /* a directory */
    if (!reg(in, SIDE_AFTER)) {                 /* every entry removed */
        const struct belay_fv v[] = { FV(ref, rl) };
        return belay_finding(out, FK_GIT_REFLOG_REWRITTEN, v, 1) == -1 ? BELAY_INTERP_ERROR
                                                                        : BELAY_INTERP_FINDINGS;
    }
    struct sides s;
    read_sides(in, GIT_LOG_MAX, out, &s);
    enum belay_interp_result r = s.error ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    if (s.ok && r == BELAY_INTERP_FINDINGS) {
        const char *a = (const char *)s.buf[1];
        const size_t bl = s.buf[0] ? s.len[0] : 0;
        /* Appended only when before is a prefix of after, ending a line. */
        if (bl > s.len[1] || (bl && memcmp(s.buf[0], a, bl) != 0) || (bl && a[bl - 1] != '\n')) {
            const struct belay_fv v[] = { FV(ref, rl) };
            if (belay_finding(out, FK_GIT_REFLOG_REWRITTEN, v, 1) == -1) r = BELAY_INTERP_ERROR;
        } else {
            struct appended ap = { out, ref, rl, 0, 0 };
            if (git_reflog_each(a + bl, s.len[1] - bl, count_entries, &ap) != 0) {
                belay_err_clear();
                r = BELAY_INTERP_ERROR;
            } else if (ap.n > 0) {
                const struct belay_fv v[] = { FV(ref, rl), { .i = ap.n } };
                if (belay_finding(out, FK_GIT_REFLOG_APPENDED, v, 2) == -1 ||
                    git_reflog_each(a + bl, s.len[1] - bl, moves, &ap) != 0)
                    r = BELAY_INTERP_ERROR;
            }
        }
    }
    free_sides(&s);
    return r;
}

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    (void)state;
    if (is(in, "unknown")) return BELAY_INTERP_DECLINE;      /* not a proven change */
    const char *name;
    size_t nl;
    const enum git_file f = which(in->abs_path, in->abs_len, &name, &nl);
    const bool content = !is(in, "metadata_only");
    switch (f) {
    case G_INDEX: {
        if (!content || (!reg(in, SIDE_BEFORE) && !reg(in, SIDE_AFTER))) return BELAY_INTERP_DECLINE;
        return belay_finding(out, FK_GIT_INDEX_CHANGED, NULL, 0) == -1 ? BELAY_INTERP_ERROR
                                                                       : BELAY_INTERP_FINDINGS;
    }
    case G_HEAD:
    case G_REF:    return content ? ref_file(in, f, name, nl, out) : BELAY_INTERP_DECLINE;
    case G_PACKED: return content ? packed(in, out) : BELAY_INTERP_DECLINE;
    case G_HOOK:   return hook(in, name, nl, out);
    case G_LOG:    return content ? reflog(in, name, nl, out) : BELAY_INTERP_DECLINE;
    case G_NONE:   break;
    }
    return BELAY_INTERP_ERROR;                  /* dispatch claimed what this cannot place */
}

const struct belay_interp INTERP_GIT = { BELAY_INTERP_GIT, NULL, explain, NULL };
