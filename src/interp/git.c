/*
 *  The git interpreter (finding-kinds.md, git_*): refs, hooks, the index
 *  and the reflog, path by path, without object access; every finding is
 *  about its own path. Its end hook derives repository-level events from
 *  what those paths held -- branches created, deleted, renamed, moved,
 *  commits added, history rewritten, HEAD switched (diff-events E12). The
 *  reflog is written by the watched process, so what it says is evidence,
 *  not proof (diff-v1, Interpreters).
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
#define GIT_LOG_MAX    BELAY_KEEP_BOUNDED_MAX   /* a reflog: kept up to 16 MiB, read in full within it */
#define GIT_STATE_MAX  (64u * 1024u * 1024u)    /* the per-diff state (diff-v1: 64 MiB; E6 past it) */

enum git_file { G_NONE, G_INDEX, G_HEAD, G_PACKED, G_REF, G_HOOK, G_LOG };

/* What the path is within its .git directory, by dispatch's rules in
 * dispatch's order: for each, the last "/.git/" whose remainder it matches.
 * *name is the remainder (a ref, a hook) or, for a reflog, its ref. */
static enum git_file which(const char *p, size_t n, const char **name, size_t *name_len,
                           const char **git_end) {
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
            *git_end = rest - 1;                /* just past ".git" */
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
/* Both sides' stored copies, at most `max` bytes each. With `kept_to_max`
 * (a claim kept up to `max`, BELAY_KEEP_STORE_BOUNDED), a side recorded
 * without a copy because it is larger is too_large, not missing (decision
 * 2026-11-01, 6). */
static void read_sides(const struct belay_interp_input *in, size_t max, bool kept_to_max,
                       struct belay_findings *out, struct sides *s) {
    memset(s, 0, sizeof *s);
    s->ok = true;
    for (int k = SIDE_BEFORE; k <= SIDE_AFTER; k++) {
        if (!reg(in, k)) continue;
        const struct belay_entry *e = side_entry(in, (enum side)k);
        const enum stored_why w = kept_to_max && !e->has_stored && e->size > max
                                      ? SW_TOO_LARGE
                                      : stored_read(in, (enum side)k, max, &s->buf[k], &s->len[k]);
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
    read_sides(in, GIT_REF_MAX, false, out, &s);
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
    read_sides(in, GIT_PACKED_MAX, false, out, &s);
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

/* A hook is a regular file or a symlink: git follows a symlinked hook, so
 * it is a working hook (decision P3). A directory is none. */
static bool is_hook(const struct belay_entry *e) {
    return e != NULL && (e->type == BELAY_T_REG || e->type == BELAY_T_LNK);
}

/* The owner's bit, for a file; absent for a symlink, whose own mode says
 * nothing about its target (decision 2026-10-31, a). */
static struct belay_fv executable(const struct belay_entry *e) {
    if (e->type == BELAY_T_LNK) return (struct belay_fv){ .absent = true };
    return (struct belay_fv){ .b = (e->mode & 0100) != 0 };
}

/* A link's target, empty for a file: bytes, written target_b64 when not
 * UTF-8 (decision 2026-10-31, b). */
static struct belay_fv target(const struct belay_entry *e) {
    if (e->type != BELAY_T_LNK || !e->has_link_target) return (struct belay_fv){ .s = "", .len = 0 };
    return (struct belay_fv){ .s = e->link_target, .len = e->link_target_len };
}

static enum belay_interp_result hook(const struct belay_interp_input *in, const char *name,
                                     size_t nl, struct belay_findings *out) {
    int rc;
    const bool b = is_hook(in->before), a = is_hook(in->after);
    if (!b && !a) return BELAY_INTERP_DECLINE;          /* a directory: no hook */
    if (!b) {
        const struct belay_fv v[] = { FV(name, nl), executable(in->after), target(in->after) };
        rc = belay_finding(out, FK_GIT_HOOK_ADDED, v, 3);
    } else if (!a) {
        const struct belay_fv v[] = { FV(name, nl), target(in->before) };
        rc = belay_finding(out, FK_GIT_HOOK_REMOVED, v, 2);
    } else if (is(in, "modified") || is(in, "type_changed")) {   /* content, target, file <-> link */
        const struct belay_fv v[] = { FV(name, nl), executable(in->after), target(in->after) };
        rc = belay_finding(out, FK_GIT_HOOK_CHANGED, v, 3);
    } else if (in->before->type == BELAY_T_REG && in->after->type == BELAY_T_REG &&
               executable(in->before).b != executable(in->after).b) {      /* metadata_only */
        const struct belay_fv v[] = { FV(name, nl), executable(in->after) };
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
    read_sides(in, GIT_LOG_MAX, true, out, &s);
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

/* ---- events: what each path held, kept for the end hook (E12) ---- */

struct gs { const char *s; size_t n; };         /* owned; freed with the state */

struct gentry { struct gs old, nw, op, msg; };  /* a reflog entry gained in this diff */

enum gkind { GK_HEAD, GK_LOOSE, GK_PACKED, GK_LOG };

/* What one path held: HEAD, a branch's loose ref, packed-refs (its
 * branches), or the reflog of HEAD or of a branch. */
struct gfact {
    enum gkind kind;
    struct gs repo, name, path;     /* name: the branch, or "HEAD" (HEAD, logs/HEAD) */
    bool prov;                      /* the path's outcome is unknown (E2) */
    bool present[2], known[2];      /* a file on that side; its content read */
    bool sym[2];                    /* HEAD: a symbolic ref */
    struct gs val[2];               /* HEAD, a loose ref: the ref's name or the object id */
    struct gs *pk[2];               /* packed-refs: branch, id, branch, id, ... */
    size_t npk[2];
    struct gentry *e;               /* a reflog: the entries gained, when log_ok */
    size_t ne;
    bool log_ok;                    /* before was a prefix of after, ending a line */
};

/* A path git could not read (why: a stored_why) or interpret (SW_ERROR). */
struct gunav { enum stored_why why; enum side side; struct gs path; bool prov; };

struct git {
    struct gfact *f;
    size_t nf, capf;
    struct gunav *u;
    size_t nu, capu;
    size_t bytes;
    bool failed;                    /* state over its bound, or memory: E6 */
};

static void *begin(void) { return calloc(1, sizeof(struct git)); }

static int keep(struct git *g, struct gs *out, const char *s, size_t n) {
    if (g->bytes + n + 1 > GIT_STATE_MAX) return -1;
    char *c = malloc(n + 1);
    if (c == NULL) return -1;
    if (n) memcpy(c, s, n);
    c[n] = '\0';
    g->bytes += n + 1;
    *out = (struct gs){ c, n };
    return 0;
}

static bool gs_eq(struct gs a, struct gs b) { return a.n == b.n && memcmp(a.s, b.s, a.n) == 0; }
static int gs_cmp(struct gs a, struct gs b) {
    const int c = memcmp(a.s, b.s, a.n < b.n ? a.n : b.n);
    return c ? c : (a.n > b.n) - (a.n < b.n);
}
static bool has(struct gs a, const char *w) {
    const size_t wl = strlen(w);
    for (size_t i = 0; i + wl <= a.n; i++) if (memcmp(a.s + i, w, wl) == 0) return true;
    return false;
}
static bool starts(struct gs a, const char *w) { return a.n >= strlen(w) && memcmp(a.s, w, strlen(w)) == 0; }
static bool is_op(struct gs a, const char *w) { return a.n == strlen(w) && memcmp(a.s, w, a.n) == 0; }
static bool zeros(struct gs a) {
    for (size_t i = 0; i < a.n; i++) if (a.s[i] != '0') return false;
    return a.n > 0;
}

static struct gfact *fact(struct git *g) {
    if (g->nf == g->capf) {
        const size_t c = g->capf ? 2 * g->capf : 16;
        struct gfact *q = realloc(g->f, c * sizeof *q);
        if (q == NULL) return NULL;
        g->f = q;
        g->capf = c;
    }
    struct gfact *x = &g->f[g->nf++];
    memset(x, 0, sizeof *x);
    return x;
}

static int unav(struct git *g, enum stored_why w, enum side side, const struct belay_interp_input *in, bool prov) {
    if (g->nu == g->capu) {
        const size_t c = g->capu ? 2 * g->capu : 8;
        struct gunav *q = realloc(g->u, c * sizeof *q);
        if (q == NULL) return -1;
        g->u = q;
        g->capu = c;
    }
    struct gunav *u = &g->u[g->nu];
    *u = (struct gunav){ w, side, { 0 }, prov };
    if (keep(g, &u->path, in->path, in->path_len) == -1) return -1;
    g->nu++;
    return 0;
}

/* A side's stored copy for the events: SW_OK with *buf, or why not. */
static enum stored_why copy_of(const struct belay_interp_input *in, int k, size_t max, bool kept_to_max,
                               unsigned char **buf, size_t *len) {
    const struct belay_entry *e = side_entry(in, (enum side)k);
    if (kept_to_max && !e->has_stored && e->size > max) return SW_TOO_LARGE;
    return stored_read(in, (enum side)k, max, buf, len);
}

struct pk_ctx { struct git *g; struct gs **v; size_t *n, cap; int rc; };

static int pk_add(const char *ref, size_t rl, const char *oid, size_t ol, void *ctx) {
    struct pk_ctx *c = ctx;
    if (rl <= 11 || memcmp(ref, "refs/heads/", 11) != 0) return 0;     /* branches only */
    for (size_t i = 0; i < *c->n; i += 2)                               /* a branch twice: its first line */
        if ((*c->v)[i].n == rl - 11 && memcmp((*c->v)[i].s, ref + 11, rl - 11) == 0) return 0;
    if (*c->n + 2 > c->cap) {
        const size_t cap = c->cap ? 2 * c->cap : 32;
        struct gs *q = realloc(*c->v, cap * sizeof *q);
        if (q == NULL) return 1;
        *c->v = q;
        c->cap = cap;
    }
    if (keep(c->g, &(*c->v)[*c->n], ref + 11, rl - 11) == -1 || keep(c->g, &(*c->v)[*c->n + 1], oid, ol) == -1)
        return 1;
    *c->n += 2;
    return 0;
}

struct log_ctx { struct git *g; struct gfact *x; size_t cap; };

static int log_add(const struct git_reflog_entry *e, void *ctx) {
    struct log_ctx *c = ctx;
    struct gfact *x = c->x;
    if (x->ne == c->cap) {
        const size_t cap = c->cap ? 2 * c->cap : 8;
        struct gentry *q = realloc(x->e, cap * sizeof *q);
        if (q == NULL) return 1;
        x->e = q;
        c->cap = cap;
    }
    struct gentry *n = &x->e[x->ne];
    memset(n, 0, sizeof *n);
    x->ne++;
    if (keep(c->g, &n->old, e->old_oid, e->oid_len) == -1 || keep(c->g, &n->nw, e->new_oid, e->oid_len) == -1 ||
        keep(c->g, &n->op, e->operation, e->operation_len) == -1 || keep(c->g, &n->msg, e->message, e->message_len) == -1)
        return 1;
    return 0;
}

/* (pk_add and log_add return 1, not -1, when the state runs out: -1 from
 * git_packed_each or git_reflog_each is then the file not being parsed.) */

/* Keeps what a HEAD, branch, packed-refs or reflog path held, for the end
 * hook. A side that cannot be read is said by a content_unavailable event;
 * one that cannot be parsed, by a could_not_interpret event (E10). -1 only
 * when the state is over its bound or memory runs out (E6). */
static int collect(struct git *g, const struct belay_interp_input *in, enum git_file f,
                   const char *name, size_t nl, const char *git_end, bool prov) {
    struct gs nm;
    enum gkind kind;
    if (f == G_HEAD) {
        kind = GK_HEAD; nm = (struct gs){ "HEAD", 4 };
    } else if (f == G_REF && nl > 11 && memcmp(name, "refs/heads/", 11) == 0) {
        kind = GK_LOOSE; nm = (struct gs){ name + 11, nl - 11 };
    } else if (f == G_PACKED) {
        kind = GK_PACKED; nm = (struct gs){ "", 0 };
    } else if (f == G_LOG && nl == 4 && memcmp(name, "HEAD", 4) == 0) {
        kind = GK_LOG; nm = (struct gs){ "HEAD", 4 };
    } else if (f == G_LOG && nl > 11 && memcmp(name, "refs/heads/", 11) == 0) {
        kind = GK_LOG; nm = (struct gs){ name + 11, nl - 11 };
    } else {
        return 0;                               /* tags, remote-tracking refs: no event (E12) */
    }
    const size_t off = in->abs_len - in->path_len;
    const size_t rl = (size_t)(git_end - in->abs_path) - off;
    struct gfact *x = fact(g);
    if (x == NULL) return -1;
    x->kind = kind;
    x->prov = prov;
    if (keep(g, &x->repo, in->path, rl) == -1 || keep(g, &x->name, nm.s, nm.n) == -1 ||
        keep(g, &x->path, in->path, in->path_len) == -1)
        return -1;
    const size_t max = kind == GK_PACKED ? GIT_PACKED_MAX : kind == GK_LOG ? GIT_LOG_MAX : GIT_REF_MAX;
    unsigned char *buf[2] = { NULL, NULL };
    size_t len[2] = { 0, 0 };
    int rc = 0;
    bool readable = true;
    const bool removed_log = kind == GK_LOG && !reg(in, SIDE_AFTER);   /* no copy needed (diff-v1, git) */
    for (int k = SIDE_BEFORE; k <= SIDE_AFTER && rc == 0; k++) {
        x->present[k] = reg(in, k);
        if (!x->present[k] || removed_log) { x->known[k] = true; continue; }
        const enum stored_why w = copy_of(in, k, max, kind == GK_LOG, &buf[k], &len[k]);
        if (w == SW_OK) { x->known[k] = true; continue; }
        readable = false;
        rc = unav(g, w, (enum side)k, in, prov);
    }
    struct pk_ctx pc[2] = { { g, &x->pk[0], &x->npk[0], 0, 0 }, { g, &x->pk[1], &x->npk[1], 0, 0 } };
    /* A side that cannot be parsed counts as one that cannot be read
     * (decision 141): no value there; the other side still gives one. */
    bool parsed = true;
    for (int k = SIDE_BEFORE; k <= SIDE_AFTER && rc == 0; k++) {
        if (buf[k] == NULL) continue;
        bool side_ok = true;
        if (kind == GK_HEAD || kind == GK_LOOSE) {
            const char *v;
            size_t vl;
            if (git_ref_value((const char *)buf[k], len[k], &x->sym[k], &v, &vl) == -1) side_ok = false;
            else rc = keep(g, &x->val[k], v, vl);
        } else if (kind == GK_PACKED) {
            const int r = git_packed_each((const char *)buf[k], len[k], pk_add, &pc[k]);
            if (r > 0) rc = -1;                 /* state over its bound, or memory */
            else if (r != 0) side_ok = false;
        }
        if (!side_ok) {
            parsed = false;
            x->known[k] = false;
            for (size_t m = 0; m < x->npk[k]; m++) free((char *)x->pk[k][m].s);
            x->npk[k] = 0;                      /* nothing of what was parsed before the fault */
        }
    }
    if (rc == 0 && kind == GK_LOG && readable && parsed && x->present[SIDE_AFTER]) {
        const char *a = (const char *)buf[SIDE_AFTER];
        const size_t bl = buf[SIDE_BEFORE] ? len[SIDE_BEFORE] : 0;
        x->log_ok = !(bl > len[SIDE_AFTER] || (bl && memcmp(buf[SIDE_BEFORE], a, bl) != 0) || (bl && a[bl - 1] != '\n'));
        struct log_ctx lc = { g, x, 0 };
        if (x->log_ok) {
            const int r = git_reflog_each(a + bl, len[SIDE_AFTER] - bl, log_add, &lc);
            if (r > 0) rc = -1;                 /* state over its bound, or memory */
            else if (r != 0) {
                parsed = false;
                x->known[0] = x->known[1] = false;  /* a reflog not parsed is no evidence */
            }
        }
    }
    if (!parsed) {                              /* said once for the path (E10) */
        belay_err_clear();
        if (rc == 0) rc = unav(g, SW_ERROR, SIDE_AFTER, in, prov);
    }
    free(buf[0]);
    free(buf[1]);
    return rc;
}

/* ---- the end hook: E12's events from the facts, by repository ---- */

enum vstate { V_NONE, V_ABSENT, V_UNKNOWN, V_VALUE };
struct val { enum vstate st; struct gs v; };

struct grepo {                  /* one repository's facts */
    struct gs repo;
    size_t lo, hi;              /* [lo, hi) of the sorted facts */
};

static const struct gfact *find(const struct git *g, const struct grepo *r, enum gkind k, struct gs name) {
    for (size_t i = r->lo; i < r->hi; i++)
        if (g->f[i].kind == k && (k == GK_PACKED || gs_eq(g->f[i].name, name))) return &g->f[i];
    return NULL;
}

static struct val packed_val(const struct gfact *p, int k, struct gs b) {
    if (!p->known[k]) return (struct val){ V_UNKNOWN, { 0 } };
    for (size_t i = 0; i < p->npk[k]; i += 2)
        if (gs_eq(p->pk[k][i], b)) return (struct val){ V_VALUE, p->pk[k][i + 1] };
    return (struct val){ V_ABSENT, { 0 } };
}

/* A branch's value on side k (E12): its loose ref there; else its line in
 * packed-refs when packed-refs is a path of this diff; else, before only,
 * the old id of the first entry its reflog gained in this diff (zeros:
 * absent); after, a loose ref removed with packed-refs not in this diff is
 * gone (git removes a branch from both). */
static struct val value(const struct git *g, const struct grepo *r, struct gs b, int k,
                        const struct gfact **src) {
    const struct gfact *lo = find(g, r, GK_LOOSE, b), *pk = find(g, r, GK_PACKED, b),
                       *lg = find(g, r, GK_LOG, b);
    *src = NULL;
    /* What cannot be read reduces what is claimed, never the fact the refs
     * give (decision 137): a side that cannot be read gives no value --
     * after, no event; before, what follows in this order still may. */
    bool existed = false;                       /* a loose ref there, unread */
    if (lo != NULL && lo->present[k]) {
        if (lo->known[k]) {
            *src = lo;
            return (struct val){ V_VALUE, lo->val[k] };
        }
        if (k == SIDE_AFTER) return (struct val){ V_UNKNOWN, { 0 } };
        existed = true;                         /* not packed-refs: a loose ref overrides it */
    } else if (pk != NULL) {
        if (pk->known[k]) {
            *src = pk;
            return packed_val(pk, k, b);
        }
        if (k == SIDE_AFTER) return (struct val){ V_UNKNOWN, { 0 } };
    } else if (k == SIDE_AFTER) {
        if (lo == NULL || !lo->present[SIDE_BEFORE]) return (struct val){ V_NONE, { 0 } };
        *src = lo;
        return (struct val){ V_ABSENT, { 0 } };
    }
    /* Before only, the reflog's evidence; one that cannot be read gives none. */
    if (k == SIDE_BEFORE && lg != NULL && lg->known[0] && lg->known[1] && lg->log_ok && lg->ne > 0) {
        if (zeros(lg->e[0].old)) {
            if (existed) return (struct val){ V_NONE, { 0 } };
            *src = lg;
            return (struct val){ V_ABSENT, { 0 } };
        }
        *src = lg;
        return (struct val){ V_VALUE, lg->e[0].old };
    }
    return (struct val){ V_NONE, { 0 } };
}

struct gev {                    /* one event, before it is written */
    int kind;
    struct gs repo, branch, a, b, c;    /* the kind's fields after repo, in order */
    long count;                 /* git_commits_added; -1: absent */
    bool from_absent;           /* git_branch_moved */
    int rank;                   /* E4: 0 HEAD switched, 1 the branch HEAD, 2 a branch */
    const char *paths[8];       /* each once: a rename merges two branches' */
    size_t pl[8], np;
    bool prov, dead;
    char *own;                  /* how, for git_history_rewritten: freed with the event */
};

static void add_path(struct gev *e, const struct gfact *x) {
    if (x == NULL) return;
    for (size_t i = 0; i < e->np; i++)
        if (e->paths[i] == x->path.s) { e->prov |= x->prov; return; }
    if (e->np == sizeof e->paths / sizeof e->paths[0]) return;
    e->paths[e->np] = x->path.s;
    e->pl[e->np++] = x->path.n;
    e->prov |= x->prov;
}

/* How the reflog says a branch moved from b to a, when its entries of this
 * diff lead from one to the other: rewritten, commits added, or not said. */
static void classify(struct git *g, struct gev *e, const struct gfact *lg, struct gs b, struct gs a) {
    e->kind = FK_GIT_BRANCH_MOVED;
    e->a = b; e->b = a;
    bool chain = lg != NULL && lg->known[0] && lg->known[1] && lg->log_ok && lg->ne > 0 &&
                 gs_eq(lg->e[0].old, b) && gs_eq(lg->e[lg->ne - 1].nw, a);
    for (size_t i = 1; chain && i < lg->ne; i++) chain = gs_eq(lg->e[i].old, lg->e[i - 1].nw);
    if (!chain) return;
    bool rewrite = false, adds = true, counted = true;
    for (size_t i = 0; i < lg->ne; i++) {
        const struct gentry *x = &lg->e[i];
        const bool rw = is_op(x->op, "reset") || is_op(x->op, "commit (amend)") || has(x->op, "rebase") ||
                        starts(x->msg, "branch: Reset to") || has(x->msg, "forced-update");
        const bool one = is_op(x->op, "commit") || is_op(x->op, "commit (merge)") || is_op(x->op, "cherry-pick") ||
                         is_op(x->op, "revert") || is_op(x->op, "am");
        const bool many = has(x->msg, "Fast-forward") || starts(x->op, "merge") || starts(x->op, "pull");
        rewrite |= rw;
        adds &= one || many;
        counted &= one;
    }
    if (rewrite) {
        /* how: the rewriting operations, each once, in order */
        char how[1025];
        size_t w = 0;
        for (size_t i = 0; i < lg->ne; i++) {
            const struct gentry *x = &lg->e[i];
            if (!(is_op(x->op, "reset") || is_op(x->op, "commit (amend)") || has(x->op, "rebase") ||
                  starts(x->msg, "branch: Reset to") || has(x->msg, "forced-update")))
                continue;
            bool seen = false;
            for (size_t j = 0; j < i && !seen; j++) {
                const struct gentry *y = &lg->e[j];
                seen = gs_eq(y->op, x->op) && (is_op(y->op, "reset") || is_op(y->op, "commit (amend)") ||
                       has(y->op, "rebase") || starts(y->msg, "branch: Reset to") || has(y->msg, "forced-update"));
            }
            if (seen) continue;
            if (w && w + 2 < sizeof how) { memcpy(how + w, ", ", 2); w += 2; }
            const size_t n = x->op.n < sizeof how - 1 - w ? x->op.n : sizeof how - 1 - w;
            memcpy(how + w, x->op.s, n);
            w += n;
        }
        if ((e->own = malloc(w + 1)) == NULL) { g->failed = true; return; }
        memcpy(e->own, how, w);
        e->own[w] = '\0';
        e->kind = FK_GIT_HISTORY_REWRITTEN;
        e->a = (struct gs){ e->own, w }; e->b = b; e->c = a;
        add_path(e, lg);                        /* it says how */
    } else if (adds) {
        add_path(e, lg);
        e->kind = FK_GIT_COMMITS_ADDED;
        e->count = counted ? (long)lg->ne : -1;
        e->a = a;
    }
}

static int gev_cmp(const void *x, const void *y) {
    const struct gev *a = x, *b = y;
    int c = gs_cmp(a->repo, b->repo);
    if (c == 0) c = (a->rank > b->rank) - (a->rank < b->rank);
    if (c == 0) c = gs_cmp(a->branch, b->branch);
    if (c == 0) c = (a->kind > b->kind) - (a->kind < b->kind);
    return c;
}

static int fact_cmp(const void *x, const void *y) {
    const struct gfact *a = x, *b = y;
    return gs_cmp(a->repo, b->repo);
}

/* A name without refs/heads/: what HEAD's symbolic ref names, for a reader. */
static struct gs short_ref(struct gs v) {
    return starts(v, "refs/heads/") ? (struct gs){ v.s + 11, v.n - 11 } : v;
}

static struct gev *more(struct gev **v, size_t *n, size_t *cap) {
    if (*n == *cap) {
        const size_t c = *cap ? 2 * *cap : 16;
        struct gev *q = realloc(*v, c * sizeof *q);
        if (q == NULL) return NULL;
        *v = q;
        *cap = c;
    }
    struct gev *e = &(*v)[(*n)++];
    memset(e, 0, sizeof *e);
    e->count = -1;
    return e;
}

/* One repository's events: HEAD, then each branch whose existence or commit
 * differs, a deletion and a creation at one commit said as a rename when the
 * new branch's reflog says so. */
static int repo_events(struct git *g, const struct grepo *r, struct gev **v, size_t *n, size_t *cap) {
    /* HEAD */
    const struct gfact *h = find(g, r, GK_HEAD, (struct gs){ "HEAD", 4 });
    if (h != NULL && h->present[0] && h->present[1] && h->known[0] && h->known[1] &&
        !(h->sym[0] == h->sym[1] && gs_eq(h->val[0], h->val[1]))) {
        struct gev *e = more(v, n, cap);
        if (e == NULL) return -1;
        e->repo = r->repo;
        add_path(e, h);
        if (!h->sym[0] && !h->sym[1]) {         /* detached on both sides: the branch HEAD moved */
            e->rank = 1;
            e->branch = (struct gs){ "HEAD", 4 };
            classify(g, e, find(g, r, GK_LOG, (struct gs){ "HEAD", 4 }), h->val[0], h->val[1]);
        } else {
            e->kind = FK_GIT_HEAD_SWITCHED;
            e->a = h->sym[0] ? short_ref(h->val[0]) : h->val[0];
            e->b = h->sym[1] ? short_ref(h->val[1]) : h->val[1];
        }
    }
    /* the branches named by any fact */
    const size_t first = *n;
    for (size_t i = r->lo; i < r->hi; i++) {
        const struct gfact *x = &g->f[i];
        for (size_t m = 0; m < (x->kind == GK_PACKED ? x->npk[0] + x->npk[1] : 1); m += (x->kind == GK_PACKED ? 2 : 1)) {
            struct gs b;
            if (x->kind == GK_PACKED) b = m < x->npk[0] ? x->pk[0][m] : x->pk[1][m - x->npk[0]];
            else if (x->kind == GK_HEAD || gs_eq(x->name, (struct gs){ "HEAD", 4 })) break;
            else b = x->name;
            bool done = false;
            for (size_t j = first; j < *n && !done; j++) done = gs_eq((*v)[j].branch, b);
            if (done) continue;
            const struct gfact *bs, *as;
            const struct val bv = value(g, r, b, SIDE_BEFORE, &bs), av = value(g, r, b, SIDE_AFTER, &as);
            if (bv.st == V_UNKNOWN || av.st == V_UNKNOWN) continue;     /* decides nothing */
            int kind = -1;
            if (av.st == V_VALUE && bv.st == V_ABSENT) kind = FK_GIT_BRANCH_CREATED;
            else if (av.st == V_VALUE && bv.st == V_NONE) kind = FK_GIT_BRANCH_MOVED;
            else if (bv.st == V_VALUE && av.st == V_ABSENT) kind = FK_GIT_BRANCH_DELETED;
            else if (bv.st == V_VALUE && av.st == V_VALUE && !gs_eq(bv.v, av.v)) kind = FK_GIT_BRANCH_MOVED;
            if (kind == -1) {
                struct gev *e = more(v, n, cap);    /* a marker: this branch is done */
                if (e == NULL) return -1;
                e->branch = b;
                e->dead = true;
                continue;
            }
            struct gev *e = more(v, n, cap);
            if (e == NULL) return -1;
            e->repo = r->repo;
            e->branch = b;
            e->rank = 2;
            e->kind = kind;
            /* the paths it is derived from: what decided each side's value
             * (a ref, packed-refs, or the reflog as evidence), and the
             * reflog when it says how the branch moved (E12, E3) */
            add_path(e, bs);
            add_path(e, as);
            if (kind == FK_GIT_BRANCH_CREATED) {
                e->a = av.v;
            } else if (kind == FK_GIT_BRANCH_DELETED) {
                e->a = bv.v;
            } else if (bv.st == V_NONE) {
                e->from_absent = true;
                e->b = av.v;
            } else {
                classify(g, e, find(g, r, GK_LOG, b), bv.v, av.v);
            }
        }
    }
    /* renames: a creation whose reflog of this diff says "Branch: renamed
     * refs/heads/<from> to refs/heads/<it>", with <from> deleted at that commit */
    for (size_t i = first; i < *n; i++) {
        struct gev *c = &(*v)[i];
        if (c->dead || c->kind != FK_GIT_BRANCH_CREATED) continue;
        const struct gfact *lg = find(g, r, GK_LOG, c->branch);
        for (size_t k = 0; lg != NULL && lg->log_ok && k < lg->ne; k++) {
            const struct gs m = lg->e[k].msg;
            static const char P[] = "Branch: renamed refs/heads/";
            if (!starts(m, P)) continue;
            const char *to = NULL;
            for (size_t q = sizeof P - 1; q + 16 <= m.n && to == NULL; q++)
                if (memcmp(m.s + q, " to refs/heads/", 15) == 0) to = m.s + q;
            if (to == NULL) continue;
            const struct gs from = { m.s + sizeof P - 1, (size_t)(to - m.s) - (sizeof P - 1) };
            const struct gs dest = { to + 15, (size_t)(m.s + m.n - to) - 15 };
            if (!gs_eq(dest, c->branch)) continue;
            for (size_t d = first; d < *n; d++) {
                struct gev *x = &(*v)[d];
                if (x->dead || x->kind != FK_GIT_BRANCH_DELETED || !gs_eq(x->branch, from) || !gs_eq(x->a, c->a))
                    continue;
                c->kind = FK_GIT_BRANCH_RENAMED;
                add_path(c, lg);                /* it says so */
                c->branch = from;               /* sorts by the old name */
                c->b = c->a;                    /* at */
                c->a = dest;                    /* to */
                for (size_t q = 0; q < x->np; q++) {
                    bool dup = false;
                    for (size_t w = 0; w < c->np; w++) dup |= c->paths[w] == x->paths[q];
                    if (!dup && c->np < sizeof c->paths / sizeof c->paths[0]) {
                        c->paths[c->np] = x->paths[q];
                        c->pl[c->np++] = x->pl[q];
                    }
                }
                c->prov |= x->prov;
                x->dead = true;
                break;
            }
            break;
        }
    }
    return 0;
}

static int emit(struct belay_events *ev, const struct gev *e) {
    const struct belay_fv repo = FV(e->repo.s, e->repo.n), br = FV(e->branch.s, e->branch.n);
    const struct belay_fv a = FV(e->a.s, e->a.n), b = FV(e->b.s, e->b.n), c = FV(e->c.s, e->c.n);
    const unsigned fl = e->prov ? BELAY_EVENT_PROVISIONAL : 0;
    switch (e->kind) {
    case FK_GIT_HEAD_SWITCHED: { const struct belay_fv v[] = { repo, a, b };
        return belay_event(ev, e->kind, v, 3, e->paths, e->pl, e->np, fl); }
    case FK_GIT_BRANCH_CREATED:
    case FK_GIT_BRANCH_DELETED: { const struct belay_fv v[] = { repo, br, a };
        return belay_event(ev, e->kind, v, 3, e->paths, e->pl, e->np, fl); }
    case FK_GIT_BRANCH_RENAMED: { const struct belay_fv v[] = { repo, br, a, b };
        return belay_event(ev, e->kind, v, 4, e->paths, e->pl, e->np, fl); }
    case FK_GIT_COMMITS_ADDED: {
        const struct belay_fv cnt = e->count < 0 ? (struct belay_fv){ .absent = true } : (struct belay_fv){ .i = e->count };
        const struct belay_fv v[] = { repo, br, cnt, a };
        return belay_event(ev, e->kind, v, 4, e->paths, e->pl, e->np, fl); }
    case FK_GIT_HISTORY_REWRITTEN: { const struct belay_fv v[] = { repo, br, a, b, c };
        return belay_event(ev, e->kind, v, 5, e->paths, e->pl, e->np, fl); }
    case FK_GIT_BRANCH_MOVED: {
        const struct belay_fv from = e->from_absent ? (struct belay_fv){ .absent = true } : a;
        const struct belay_fv v[] = { repo, br, from, b };
        return belay_event(ev, e->kind, v, 4, e->paths, e->pl, e->np, fl); }
    }
    return 0;
}

static int gunav_cmp(const void *a, const void *b) {
    return gs_cmp(((const struct gunav *)a)->path, ((const struct gunav *)b)->path);
}

/* The events with no repository first (E4): one could_not_interpret per
 * path not interpreted (E10), then, as pip's and dpkg's, one
 * content_unavailable per reason. */
static int unavailable_events(struct git *g, struct belay_events *ev) {
    if (g->nu > 1) qsort(g->u, g->nu, sizeof *g->u, gunav_cmp);
    for (size_t i = 0; i < g->nu; i++)
        if (g->u[i].why == SW_ERROR && (i == 0 || g->u[i - 1].why != SW_ERROR || !gs_eq(g->u[i - 1].path, g->u[i].path)) &&
            belay_event_not_interpreted(ev, &g->u[i].path.s, &g->u[i].path.n, 1,
                                        g->u[i].prov ? BELAY_EVENT_PROVISIONAL : 0) == -1)
            return -1;
    for (int w = SW_NO_STORE; w < SW_ERROR; w++) {
        size_t n = 0;
        unsigned sides = 0;
        bool prov = false;
        for (size_t i = 0; i < g->nu; i++)
            if (g->u[i].why == (enum stored_why)w) { n++; sides |= 1u << g->u[i].side; prov |= g->u[i].prov; }
        if (n == 0) continue;
        const char **paths = malloc(n * sizeof *paths);
        size_t *lens = malloc(n * sizeof *lens);
        if (paths == NULL || lens == NULL) { free(paths); free(lens); return -1; }
        n = 0;
        for (size_t i = 0; i < g->nu; i++)
            if (g->u[i].why == (enum stored_why)w) { paths[n] = g->u[i].path.s; lens[n++] = g->u[i].path.n; }
        const char *why = stored_why_name((enum stored_why)w);
        const char *side = sides == 1u << SIDE_BEFORE ? "before" : sides == 1u << SIDE_AFTER ? "after" : "both";
        const struct belay_fv v[] = { { .s = why, .len = strlen(why) }, { .s = side, .len = strlen(side) } };
        const int r = belay_event(ev, FK_CONTENT_UNAVAILABLE, v, 2, paths, lens, n,
                                  prov ? BELAY_EVENT_PROVISIONAL : 0);
        free(paths);
        free(lens);
        if (r == -1) return -1;
    }
    return 0;
}

static void free_state(struct git *g) {
    for (size_t i = 0; i < g->nf; i++) {
        struct gfact *x = &g->f[i];
        free((char *)x->repo.s); free((char *)x->name.s); free((char *)x->path.s);
        for (int k = 0; k < 2; k++) {
            free((char *)x->val[k].s);
            for (size_t m = 0; m < x->npk[k]; m++) free((char *)x->pk[k][m].s);
            free(x->pk[k]);
        }
        for (size_t m = 0; m < x->ne; m++) {
            free((char *)x->e[m].old.s); free((char *)x->e[m].nw.s);
            free((char *)x->e[m].op.s); free((char *)x->e[m].msg.s);
        }
        free(x->e);
    }
    for (size_t i = 0; i < g->nu; i++) free((char *)g->u[i].path.s);
    free(g->f);
    free(g->u);
    free(g);
}

static enum belay_interp_result end(void *state, struct belay_events *ev) {
    struct git *g = state;
    if (g == NULL) return BELAY_INTERP_ERROR;
    enum belay_interp_result r = g->failed ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    struct gev *v = NULL;
    size_t n = 0, cap = 0;
    if (ev != NULL && r == BELAY_INTERP_FINDINGS) {
        if (unavailable_events(g, ev) == -1) r = BELAY_INTERP_ERROR;
        if (g->nf > 1) qsort(g->f, g->nf, sizeof *g->f, fact_cmp);
        for (size_t i = 0; i < g->nf && r == BELAY_INTERP_FINDINGS;) {
            struct grepo rp = { g->f[i].repo, i, i };
            while (rp.hi < g->nf && gs_eq(g->f[rp.hi].repo, rp.repo)) rp.hi++;
            if (repo_events(g, &rp, &v, &n, &cap) == -1 || g->failed) r = BELAY_INTERP_ERROR;
            i = rp.hi;
        }
        if (r == BELAY_INTERP_FINDINGS) {
            size_t w = 0;
            for (size_t i = 0; i < n; i++) if (!v[i].dead) v[w++] = v[i]; else free(v[i].own);
            n = w;
            if (n > 1) qsort(v, n, sizeof *v, gev_cmp);
            for (size_t i = 0; i < n && r == BELAY_INTERP_FINDINGS; i++)
                if (emit(ev, &v[i]) == -1) r = BELAY_INTERP_ERROR;
        }
    }
    for (size_t i = 0; i < n; i++) free(v[i].own);
    free(v);
    free_state(g);
    return r;
}

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct git *g = state;
    const char *name = NULL, *git_end = NULL;
    size_t nl = 0;
    const enum git_file f = which(in->abs_path, in->abs_len, &name, &nl, &git_end);
    const bool content = !is(in, "metadata_only");
    /* What a HEAD, ref, packed-refs or reflog path held, for the events
     * (E12) -- an unknown one too, its events provisional, with no finding
     * on its record (P8). */
    if (g != NULL && !g->failed && (content || is(in, "unknown")) &&
        (f == G_HEAD || f == G_REF || f == G_PACKED || f == G_LOG) &&
        collect(g, in, f, name, nl, git_end, is(in, "unknown")) == -1)
        g->failed = true;
    if (is(in, "unknown")) return BELAY_INTERP_DECLINE;      /* not a proven change */
    switch (f) {
    case G_INDEX: {
        if (!content || (!reg(in, SIDE_BEFORE) && !reg(in, SIDE_AFTER))) return BELAY_INTERP_DECLINE;
        return belay_finding(out, FK_GIT_INDEX_CHANGED, NULL, 0) == -1 ? BELAY_INTERP_ERROR
                                                                       : BELAY_INTERP_FINDINGS;
    }
    case G_HEAD:
    case G_REF:
    case G_LOG: {
        const enum belay_interp_result r = !content ? BELAY_INTERP_DECLINE
                                         : f == G_LOG ? reflog(in, name, nl, out) : ref_file(in, f, name, nl, out);
        /* A tag's or a remote-tracking ref's file, or its reflog, derives
         * no event, but git claims it: one it cannot interpret is said by a
         * could_not_interpret event too (E10), as collect() says the rest. */
        const bool branch = f == G_HEAD || (nl == 4 && memcmp(name, "HEAD", 4) == 0) ||
                            (nl > 11 && memcmp(name, "refs/heads/", 11) == 0);
        if (r == BELAY_INTERP_ERROR && !branch && g != NULL && !g->failed && unav(g, SW_ERROR, SIDE_AFTER, in, false) == -1)
            g->failed = true;
        return r;
    }
    case G_PACKED: return content ? packed(in, out) : BELAY_INTERP_DECLINE;
    case G_HOOK:   return hook(in, name, nl, out);
    case G_NONE:   break;
    }
    return BELAY_INTERP_ERROR;                  /* dispatch claimed what this cannot place */
}

const struct belay_interp INTERP_GIT = { BELAY_INTERP_GIT, begin, explain, end };
