#define _GNU_SOURCE
#include "policy/policy.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "belay/error.h"
#include "belay/interp.h"
#include "belay/json.h"
#include "belay/manifest.h"
#include "capture/fsops.h"
#include "policy/jw.h"
#include "policy/pkgdb.h"
#include "policy/pytests.h"
#include "schema/iflags.h"
#include "schema/policy_schema.h"
#include "util/jsonr.h"

#define COPY_MAX ((size_t)64 << 20)     /* a copy read to count tests or compare config */

/* ---- flags ---- */

struct fval {
    bool set;
    long long i;
    bool b;
    char *s;                    /* string, bytes */
    size_t sl;
    char **ss;                  /* strings */
    size_t nss;
};

struct flag {
    enum policy_kind kind;
    bool violation, provisional;
    struct fval f[POLICY_FIELDS_MAX];
    char **paths;
    size_t *plen, npaths;
    char *text;
    size_t tl;
};

struct ctx {
    const struct policy_in *in;
    struct flag *fl;
    size_t n, cap;
    bool oom;
};

static int nomem(void) {
    belay_err_set(BELAY_ERR_NOMEM, 0, "policy: out of memory");
    return -1;
}

static char *dupn(const char *s, size_t n) {
    char *c = malloc(n + 1);
    if (c != NULL) {
        if (n) memcpy(c, s, n);
        c[n] = '\0';
    }
    return c;
}

static int pathcmp(const char *a, size_t al, const char *b, size_t bl) {
    const int c = memcmp(a, b, al < bl ? al : bl);
    return c != 0 ? c : (al > bl) - (al < bl);
}

static bool level_violation(enum policy_kind k, const struct policy_in *in) {
    const enum policy_level l = POLICY_KINDS[k].level;
    return l == PL_VIOLATION || (l == PL_FROZEN && in->spec != NULL && in->spec->frozen_packages);
}

static struct flag *add(struct ctx *c, enum policy_kind k, bool provisional) {
    if (c->oom) return NULL;
    if (c->n == c->cap) {
        const size_t cap = c->cap ? 2 * c->cap : 64;
        struct flag *v = realloc(c->fl, cap * sizeof *v);
        if (v == NULL) {
            c->oom = true;
            return NULL;
        }
        c->fl = v;
        c->cap = cap;
    }
    struct flag *f = &c->fl[c->n++];
    memset(f, 0, sizeof *f);
    f->kind = k;
    f->violation = level_violation(k, c->in);
    f->provisional = provisional;
    return f;
}

static struct fval *field(struct flag *f, const char *name) {
    for (int i = 0; i < POLICY_FIELDS_MAX && POLICY_KINDS[f->kind].field[i].name != NULL; i++)
        if (strcmp(POLICY_KINDS[f->kind].field[i].name, name) == 0) return &f->f[i];
    return NULL;                        /* cannot happen: every caller names a field of its kind */
}

static void fs(struct ctx *c, struct flag *f, const char *name, const char *s, size_t n) {
    struct fval *v = f != NULL ? field(f, name) : NULL;
    if (v == NULL) return;
    if ((v->s = dupn(s, n)) == NULL) c->oom = true;
    v->sl = n;
    v->set = true;
}
static void fstr(struct ctx *c, struct flag *f, const char *name, const char *s) { fs(c, f, name, s, strlen(s)); }
static void fint(struct flag *f, const char *name, long long i) {
    struct fval *v = f != NULL ? field(f, name) : NULL;
    if (v != NULL) v->i = i, v->set = true;
}
static void fbool(struct flag *f, const char *name, bool b) {
    struct fval *v = f != NULL ? field(f, name) : NULL;
    if (v != NULL) v->b = b, v->set = true;
}
static void fstrings(struct ctx *c, struct flag *f, const char *name, const char *const *ss, size_t n) {
    struct fval *v = f != NULL ? field(f, name) : NULL;
    if (v == NULL) return;
    v->set = true;
    if (n > POLICY_STRINGS_MAX) n = POLICY_STRINGS_MAX;
    if (n == 0) return;
    if ((v->ss = calloc(n, sizeof *v->ss)) == NULL) {
        c->oom = true;
        return;
    }
    for (size_t i = 0; i < n; i++) {
        size_t l = strlen(ss[i]);
        if (l > POLICY_STRING_MAX) l = POLICY_STRING_MAX;
        while (l < strlen(ss[i]) && l > 0 && ((unsigned char)ss[i][l] & 0xC0) == 0x80) l--;
        if ((v->ss[i] = dupn(ss[i], l)) == NULL) c->oom = true;
        v->nss++;
    }
}
static void fpath(struct ctx *c, struct flag *f, const char *p, size_t n) {
    if (f == NULL) return;
    for (size_t i = 0; i < f->npaths; i++)
        if (f->plen[i] == n && memcmp(f->paths[i], p, n) == 0) return;
    char **pp = realloc(f->paths, (f->npaths + 1) * sizeof *pp);
    size_t *pl = pp != NULL ? realloc(f->plen, (f->npaths + 1) * sizeof *pl) : NULL;
    if (pp != NULL) f->paths = pp;
    if (pl == NULL) {
        c->oom = true;
        return;
    }
    f->plen = pl;
    if ((f->paths[f->npaths] = dupn(p, n)) == NULL) {
        c->oom = true;
        return;
    }
    f->plen[f->npaths++] = n;
}

static void flag_free(struct flag *f) {
    for (int i = 0; i < POLICY_FIELDS_MAX; i++) {
        free(f->f[i].s);
        for (size_t k = 0; k < f->f[i].nss; k++) free(f->f[i].ss[k]);
        free(f->f[i].ss);
    }
    for (size_t i = 0; i < f->npaths; i++) free(f->paths[i]);
    free(f->paths);
    free(f->plen);
    free(f->text);
}

/* ---- the text: the template, each {field} its value (P-F2) ---- */

/* Bytes into text: as they are when UTF-8; else as the receipt writes
 * them (docs/cli.md): each byte not in a valid sequence as \xNN, a
 * backslash doubled, so two paths never read the same. */
static void text_bytes(struct jw *w, const char *s, size_t n) {
    if (belay_utf8_valid(s, n)) {
        jw_raw(w, s, n);
        return;
    }
    for (size_t i = 0; i < n;) {
        const unsigned char c = (unsigned char)s[i];
        size_t k = c < 0x80 ? 1 : c >= 0xC2 && c <= 0xDF ? 2 : c >= 0xE0 && c <= 0xEF ? 3 : c >= 0xF0 && c <= 0xF4 ? 4 : 0;
        if (k > 1 && (i + k > n || !belay_utf8_valid(s + i, k))) k = 0;
        if (k == 0) {
            jw_fmt(w, "\\x%02x", c);
            i++;
        } else if (c == '\\') {
            JW_LIT(w, "\\\\");
            i++;
        } else {
            jw_raw(w, s + i, k);
            i += k;
        }
    }
}

static int render(struct flag *f) {
    const struct policy_kind_def *d = &POLICY_KINDS[f->kind];
    const char *t = d->text;
    if (d->text_partial != NULL)
        for (int i = 0; i < POLICY_FIELDS_MAX && d->field[i].name != NULL; i++)
            if (d->field[i].optional && !f->f[i].set && strstr(d->text, d->field[i].name) != NULL) t = d->text_partial;
    struct jw w = { 0 };
    while (*t) {
        const char *o = strchr(t, '{');
        if (o == NULL) {
            jw_raw(&w, t, strlen(t));
            break;
        }
        jw_raw(&w, t, (size_t)(o - t));
        const char *e = strchr(o, '}');
        int i = 0;
        while (i < POLICY_FIELDS_MAX && d->field[i].name != NULL &&
               !(strlen(d->field[i].name) == (size_t)(e - o - 1) && memcmp(d->field[i].name, o + 1, (size_t)(e - o - 1)) == 0))
            i++;
        const struct fval *v = &f->f[i];
        switch (d->field[i].type) {
        case PF_INT: jw_fmt(&w, "%lld", v->i); break;
        case PF_BOOL: jw_raw(&w, v->b ? "true" : "false", v->b ? 4 : 5); break;
        case PF_STRING: case PF_BYTES: text_bytes(&w, v->s != NULL ? v->s : "", v->sl); break;
        case PF_STRINGS:
            if (v->nss == 0) JW_LIT(&w, "none");
            for (size_t k = 0; k < v->nss; k++) {
                if (k) JW_LIT(&w, ", ");
                jw_raw(&w, v->ss[k], strlen(v->ss[k]));
            }
            break;
        }
        t = e + 1;
    }
    if (w.oom) {
        jw_free(&w);
        return -1;
    }
    if (w.n > POLICY_STRING_MAX) {          /* at most 1,024 bytes (P-F2): cut at a character, "..." */
        size_t k = POLICY_STRING_MAX - 3;
        while (k > 0 && ((unsigned char)w.b[k] & 0xC0) == 0x80) k--;
        memcpy(w.b + k, "...", 3);
        w.n = k + 3;
        w.b[w.n] = '\0';
    }
    f->text = w.b;
    f->tl = w.n;
    return 0;
}

/* ---- the order of records (P-F5) ---- */

static int flagcmp(const void *x, const void *y) {
    const struct flag *a = x, *b = y;
    if (a->violation != b->violation) return a->violation ? -1 : 1;
    if (a->kind != b->kind) return a->kind < b->kind ? -1 : 1;
    const int c = pathcmp(a->npaths ? a->paths[0] : "", a->npaths ? a->plen[0] : 0,
                          b->npaths ? b->paths[0] : "", b->npaths ? b->plen[0] : 0);
    return c != 0 ? c : pathcmp(a->text, a->tl, b->text, b->tl);
}

static void write_flag(struct jw *w, struct flag *f) {
    const struct policy_kind_def *d = &POLICY_KINDS[f->kind];
    jw_fmt(w, "{\"flag\":\"%s\",\"level\":\"%s\"", d->name, f->violation ? "violation" : "signal");
    for (int i = 0; i < POLICY_FIELDS_MAX && d->field[i].name != NULL; i++) {
        const struct fval *v = &f->f[i];
        if (!v->set) continue;
        JW_LIT(w, ",");
        switch (d->field[i].type) {
        case PF_INT: jw_fmt(w, "\"%s\":%lld", d->field[i].name, v->i); break;
        case PF_BOOL: jw_fmt(w, "\"%s\":%s", d->field[i].name, v->b ? "true" : "false"); break;
        case PF_STRING: jw_fmt(w, "\"%s\":", d->field[i].name); jw_str(w, v->s, v->sl); break;
        case PF_BYTES: jw_bytes(w, d->field[i].name, v->s, v->sl); break;
        case PF_STRINGS:
            jw_fmt(w, "\"%s\":[", d->field[i].name);
            for (size_t k = 0; k < v->nss; k++) {
                if (k) JW_LIT(w, ",");
                jw_str(w, v->ss[k], strlen(v->ss[k]));
            }
            JW_LIT(w, "]");
            break;
        }
    }
    JW_LIT(w, ",\"text\":");
    jw_str(w, f->text, f->tl);
    if (f->provisional) JW_LIT(w, ",\"provisional\":true");
    /* P-F4: sorted bytewise, each once; paths_b64 when any is not UTF-8 */
    for (size_t i = 1; i < f->npaths; i++)
        for (size_t j = i; j > 0 && pathcmp(f->paths[j - 1], f->plen[j - 1], f->paths[j], f->plen[j]) > 0; j--) {
            char *p = f->paths[j];
            size_t l = f->plen[j];
            f->paths[j] = f->paths[j - 1];
            f->plen[j] = f->plen[j - 1];
            f->paths[j - 1] = p;
            f->plen[j - 1] = l;
        }
    bool utf8 = true;
    for (size_t i = 0; i < f->npaths; i++) utf8 = utf8 && belay_utf8_valid(f->paths[i], f->plen[i]);
    jw_raw(w, utf8 ? ",\"paths\":[" : ",\"paths_b64\":[", utf8 ? 10 : 14);
    for (size_t i = 0; i < f->npaths; i++) {
        if (i) JW_LIT(w, ",");
        if (utf8) {
            jw_str(w, f->paths[i], f->plen[i]);
        } else {
            char *b = malloc(4 * ((f->plen[i] + 2) / 3) + 1);
            if (b == NULL || belay_base64_encode(b, 4 * ((f->plen[i] + 2) / 3) + 1, f->paths[i], f->plen[i]) == -1) {
                w->oom = true;
                free(b);
                return;
            }
            jw_fmt(w, "\"%s\"", b);
            free(b);
        }
    }
    JW_LIT(w, "]}\n");
}

/* A parsed value written back (the header's excluded lists, as diff.v1's
 * header gives them). */
static void jv_write(struct jw *w, const struct jval *v) {
    switch (v->t) {
    case J_NULL: JW_LIT(w, "null"); break;
    case J_BOOL: jw_raw(w, v->b ? "true" : "false", v->b ? 4 : 5); break;
    case J_NUM: jw_fmt(w, "%lld", (long long)v->i); break;
    case J_STR: jw_str(w, v->s, v->s_len); break;
    case J_ARR: case J_OBJ:
        jw_raw(w, v->t == J_ARR ? "[" : "{", 1);
        for (size_t i = 0; i < v->n; i++) {
            if (i) JW_LIT(w, ",");
            if (v->t == J_OBJ) {
                jw_str(w, v->keys[i], strlen(v->keys[i]));
                JW_LIT(w, ":");
            }
            jv_write(w, &v->kids[i]);
        }
        jw_raw(w, v->t == J_ARR ? "]" : "}", 1);
        break;
    }
}

/* ---- the diff ---- */

struct rec {
    char path[4096];
    size_t path_len;
    char outcome[16];
    struct jval v;              /* the whole record: changed, unknown, findings */
};

static bool decode_path(const struct jval *o, const char *key, char *out, size_t cap, size_t *n) {
    char b64key[64];
    snprintf(b64key, sizeof b64key, "%s_b64", key);
    const struct jval *p = jget(o, key), *pb = jget(o, b64key);
    if (p != NULL && p->t == J_STR && p->s_len < cap) {
        memcpy(out, p->s, p->s_len);
        *n = p->s_len;
        return true;
    }
    return pb != NULL && pb->t == J_STR && belay_base64_decode(out, cap, n, pb->s) == 0;
}

static bool has_str(const struct jval *arr, const char *s) {
    for (size_t i = 0; arr != NULL && arr->t == J_ARR && i < arr->n; i++)
        if (arr->kids[i].t == J_STR && strcmp(arr->kids[i].s, s) == 0) return true;
    return false;
}

/* ---- the copies ---- */

/* An entry's stored copy: 1 with *buf (NULL for no entry: absent, or not
 * a regular file, counts as empty); 0 when it has none; -1 on error. */
static int copy_of(const struct belay_content *cs, const struct belay_entry *e, unsigned char **buf, size_t *len) {
    *buf = NULL;
    *len = 0;
    if (e == NULL || e->type != BELAY_T_REG) return 1;
    if (!e->has_stored) return e->size == 0 && e->has_hash ? 1 : 0;
    if (belay_content_get(cs, e->stored_hex, COPY_MAX, buf, len) == -1) {
        if (belay_err_code() == BELAY_ERR_RANGE) {
            belay_err_clear();
            return 0;
        }
        return -1;
    }
    return 1;
}

/* ---- the passes ---- */

struct state {
    struct ctx *c;
    const struct policy_in *in;
    struct belay_content *cs;
    /* package lines of the bundle, by path; packages with an event */
    size_t *pk_ix;
    char **evpk;
    size_t nevpk;
    /* after: the paths a RECORD lists, sorted; the venvs (dirs holding pyvenv.cfg) */
    struct pkg_list after_pk;
    size_t *rec_ix, nrec;
    char **venv;
    size_t nvenv;
    bool *sha_seen;
    /* decision 186: the .py paths with a record, and the .pyc files listed
     * without a hash that changed -- judged once the merge is done (a
     * source can sort after its __pycache__) */
    char **chg_py;
    size_t nchg_py, capchg_py;
    struct pyc { const struct pkg_line *x; char *path; size_t n; const char *why; } *pyc;
    size_t npyc, cappyc;
};

static const struct pkg_list *g_pl;
static int by_path(const void *a, const void *b) {
    const struct pkg_line *x = &g_pl->v[*(const size_t *)a], *y = &g_pl->v[*(const size_t *)b];
    return pathcmp(x->path, x->path_len, y->path, y->path_len);
}

static size_t *index_by_path(const struct pkg_list *l, bool pip_only, size_t *n) {
    size_t *ix = malloc((l->n ? l->n : 1) * sizeof *ix);
    if (ix == NULL) return NULL;
    size_t k = 0;
    for (size_t i = 0; i < l->n; i++)
        if (!pip_only || l->v[i].db == PKG_PIP) ix[k++] = i;
    g_pl = l;
    qsort(ix, k, sizeof *ix, by_path);
    *n = k;
    return ix;
}

/* The first index in ix whose path is >= p. */
static size_t lower(const struct pkg_list *l, const size_t *ix, size_t n, const char *p, size_t pl) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2;
        if (pathcmp(l->v[ix[mid]].path, l->v[ix[mid]].path_len, p, pl) < 0) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

/* Whether an event names the package, a reinstall at the same version
 * aside: its files are judged against the bundle all the same (decision
 * 173: a RECORD rewritten to match a tampered file is no installer's). */
static bool pkg_has_event(const struct state *s, enum pkg_db db, const char *pkg) {
    char key[2048];
    snprintf(key, sizeof key, "%s %s", pkg_db_name(db), pkg);
    for (size_t i = 0; i < s->nevpk; i++)
        if (strcmp(s->evpk[i], key) == 0) return true;
    return false;
}

static const char *entry_flag_names(const struct belay_entry *e, const char **out, size_t *n) {
    if (e == NULL) return NULL;
    if (e->unverified) out[(*n)++] = "unverified";        /* every flag set: "the entry's flags" */
    if (e->unstable) out[(*n)++] = "unstable";
    if (e->unreadable) out[(*n)++] = "unreadable";
    if (e->raced) out[(*n)++] = "raced";
    if (e->is_mount) out[(*n)++] = "mount";
    if (e->writer_open) out[(*n)++] = "writer_open";
    return NULL;
}

/* An entry as one side of an inode-flag comparison (schema/iflags.h). */
static struct iflags_side iflags_side_of(const struct belay_entry *e) {
    if (e == NULL) return (struct iflags_side){ false, 0, false, false, 0 };
    return (struct iflags_side){ true, (int)e->type, e->type == BELAY_T_DIR, e->has_iflags, e->iflags };
}
static bool iflags_counts(const struct belay_entry *b, const struct belay_entry *a) {
    const struct iflags_side sb = iflags_side_of(b), sa = iflags_side_of(a);
    return iflags_change_counts(&sb, &sa);
}

static const char *base_name(const char *p, size_t n, size_t *bl) {
    size_t i = n;
    while (i > 0 && p[i - 1] != '/') i--;
    *bl = n - i;
    return p + i;
}

/* Protected paths (protect-spec PS-M1 to PS-M5). */
static void protected(struct state *s, const char *p, size_t n, const struct belay_entry *b,
                      const struct belay_entry *a, const struct rec *d) {
    const struct protect_spec *sp = s->in->spec;
    if (sp == NULL) return;
    struct ctx *c = s->c;
    const char *outcome = d != NULL ? d->outcome : "unchanged";
    const bool unknown = strcmp(outcome, "unknown") == 0;
    int first = -1;
    bool read_before = false, read_after = false, wrote = false, deleted = false, created = false;
    for (size_t i = 0; i < sp->n_rules; i++) {
        const struct protect_rule *r = &sp->rules[i];
        const bool mb = b != NULL && protect_match(r->path, r->path_len, p, n);
        const bool ma = a != NULL && protect_match(r->path, r->path_len, p, n);
        const bool exact = r->has_sha256 && r->path_len == n && memcmp(r->path, p, n) == 0;
        if (!mb && !ma && !exact) continue;
        if (first == -1) first = (int)i;
        if (r->modes & (PROTECT_NO_WRITE | PROTECT_NO_DELETE)) {
            read_before = read_before || mb;
            read_after = read_after || ma;
        }
        if (r->modes & PROTECT_NO_CREATE) read_after = read_after || ma;
        if (exact) read_after = true;
        if (unknown) continue;
        /* `iflags` in `changed` only when the change counts (inode-flags
         * IF-6): a directory that grew is no write to it. */
        const bool priv = d != NULL && strcmp(outcome, "metadata_only") == 0 &&
                          (has_str(jget(&d->v, "changed"), "mode") || has_str(jget(&d->v, "changed"), "uid") ||
                           has_str(jget(&d->v, "changed"), "gid") ||
                           (has_str(jget(&d->v, "changed"), "iflags") && iflags_counts(b, a)) ||
                           has_str(jget(&d->v, "changed"), "caps") || has_str(jget(&d->v, "changed"), "xattrs"));
        if ((r->modes & PROTECT_NO_WRITE) && mb && a != NULL && !wrote &&
            (strcmp(outcome, "modified") == 0 || strcmp(outcome, "type_changed") == 0 || priv)) {
            struct flag *f = add(c, PK_PROTECTED_PATH_WRITTEN, false);
            fs(c, f, "path", p, n);
            fstr(c, f, "rule", r->path);
            fstr(c, f, "outcome", outcome);
            const struct jval *ch = jget(&d->v, "changed");
            if (ch != NULL && ch->t == J_ARR && ch->n > 0) {
                const char *ss[64];
                size_t k = 0;
                for (size_t j = 0; j < ch->n && k < 64; j++)
                    if (ch->kids[j].t == J_STR) ss[k++] = ch->kids[j].s;
                fstrings(c, f, "changed", ss, k);
            }
            fpath(c, f, p, n);
            wrote = true;
        }
        /* no_write forbids deleting too (protect-spec-v2 PV2-2). */
        if ((r->modes & (PROTECT_NO_DELETE | PROTECT_NO_WRITE)) && mb && strcmp(outcome, "removed") == 0 && !deleted) {
            struct flag *f = add(c, PK_PROTECTED_PATH_DELETED, false);
            fs(c, f, "path", p, n);
            fstr(c, f, "rule", r->path);
            fpath(c, f, p, n);
            deleted = true;
        }
        if ((r->modes & PROTECT_NO_CREATE) && ma && strcmp(outcome, "added") == 0 && !created) {
            struct flag *f = add(c, PK_PROTECTED_PATH_CREATED, false);
            fs(c, f, "path", p, n);
            fstr(c, f, "rule", r->path);
            fpath(c, f, p, n);
            created = true;
        }
    }
    if (first == -1) return;
    /* PS-M5: what cannot be shown intact, on a side the rules read */
    const char *reasons[16];
    size_t nr = 0;
    if (unknown) {
        const struct jval *u = jget(&d->v, "unknown");
        for (size_t j = 0; u != NULL && u->t == J_ARR && j < u->n && nr < 16; j++)
            if (u->kids[j].t == J_STR) reasons[nr++] = u->kids[j].s;
        if (nr == 0) reasons[nr++] = "unknown";
    } else {
        if (read_before) entry_flag_names(b, reasons, &nr);
        if (read_after) {
            const char *more[8];
            size_t nm = 0;
            entry_flag_names(a, more, &nm);
            for (size_t j = 0; j < nm; j++) {
                bool dup = false;
                for (size_t k = 0; k < nr; k++) dup = dup || strcmp(reasons[k], more[j]) == 0;
                if (!dup) reasons[nr++] = more[j];
            }
        }
    }
    /* in decision 176's order (the model author's P2); a name it does not
     * list after them, as it came */
    static const char *const ORDER[] = { "unverified", "unstable", "unreadable", "raced", "mount",
                                         "xattrs_unknown", "iflags_unknown", "not_captured", "listing_incomplete",
                                         "writer_open" };
    const char *sorted[16];
    size_t ns = 0;
    for (size_t o = 0; o < sizeof ORDER / sizeof ORDER[0]; o++)
        for (size_t j = 0; j < nr; j++)
            if (strcmp(reasons[j], ORDER[o]) == 0) sorted[ns++] = reasons[j];
    for (size_t j = 0; j < nr; j++) {
        bool known = false;
        for (size_t o = 0; o < sizeof ORDER / sizeof ORDER[0]; o++) known = known || strcmp(reasons[j], ORDER[o]) == 0;
        if (!known) sorted[ns++] = reasons[j];
    }
    memcpy(reasons, sorted, ns * sizeof *reasons);
    if (nr > 0) {
        struct flag *f = add(c, PK_PROTECTED_PATH_UNVERIFIABLE, false);
        fs(c, f, "path", p, n);
        fstr(c, f, "rule", sp->rules[first].path);
        fstrings(c, f, "reasons", reasons, nr);
        fpath(c, f, p, n);
    }
    /* PS-M4: expected_sha256, against the after manifest */
    for (size_t i = 0; i < sp->n_rules; i++) {
        const struct protect_rule *r = &sp->rules[i];
        if (!r->has_sha256 || r->path_len != n || memcmp(r->path, p, n) != 0) continue;
        if (a != NULL) s->sha_seen[i] = true;
        const char *why = NULL;
        if (a == NULL) why = "absent";
        else if (a->type != BELAY_T_REG) why = "not a regular file";
        else if (!a->has_hash || a->writer_open) continue;      /* unverifiable, said above (V4-D8) */
        else if (strcmp(a->sha256_hex, r->sha256) != 0) why = "other bytes";
        if (why == NULL) continue;
        struct flag *f = add(c, PK_PROTECTED_HASH_MISMATCH, d != NULL && unknown);
        fs(c, f, "path", p, n);
        fstr(c, f, "expected", r->sha256);
        fstr(c, f, "why", why);
        if (strcmp(why, "other bytes") == 0) fstr(c, f, "actual", a->sha256_hex);
        fpath(c, f, p, n);
        s->sha_seen[i] = true;
    }
}

/* Installed packages (B-6 lines at this path). */
static bool p_n_ends(const char *p, size_t n, const char *suf) {
    const size_t l = strlen(suf);
    return n >= l && memcmp(p + n - l, suf, l) == 0;
}

/* A .pyc's source (decision 186): <dir>/__pycache__/<name>.<tag>[.opt-<n>].pyc
 * and <dir>/<name>.pyc are both <dir>/<name>.py. */
static size_t pyc_source(const char *p, size_t n, char *out, size_t cap) {
    size_t bl;
    const char *bn = base_name(p, n, &bl);
    const size_t dl = n - bl;                       /* the directory, '/' kept */
    static const char PC[] = "__pycache__/";
    if (dl >= sizeof PC - 1 && memcmp(p + dl - (sizeof PC - 1), PC, sizeof PC - 1) == 0 &&
        (dl == sizeof PC - 1 || p[dl - sizeof PC] == '/')) {
        const char *dot = memchr(bn, '.', bl);
        const size_t nl = dot != NULL ? (size_t)(dot - bn) : bl;
        const size_t pre = dl - (sizeof PC - 1);
        if (pre + nl + 3 >= cap) return 0;
        memcpy(out, p, pre);
        memcpy(out + pre, bn, nl);
        memcpy(out + pre + nl, ".py", 3);
        return pre + nl + 3;
    }
    if (n < 1 || n >= cap) return 0;
    memcpy(out, p, n - 1);                          /* <name>.pyc -> <name>.py */
    return n - 1;
}

static void packages(struct state *s, const char *p, size_t n, const struct belay_entry *a, const struct rec *d) {
    const struct pkg_list *l = &s->in->bundle->packages;
    struct ctx *c = s->c;
    const char *outcome = d != NULL ? d->outcome : "unchanged";
    bool conf = false, tamp = false;
    for (size_t k = lower(l, s->pk_ix, l->n, p, n); k < l->n; k++) {
        const struct pkg_line *x = &l->v[s->pk_ix[k]];
        if (pathcmp(x->path, x->path_len, p, n) != 0) break;
        if (x->conffile) {
            if (!conf && (strcmp(outcome, "modified") == 0 || strcmp(outcome, "removed") == 0 ||
                          strcmp(outcome, "type_changed") == 0)) {
                struct flag *f = add(c, PK_CONFFILE_CHANGED, false);
                fstr(c, f, "package", x->package);
                fs(c, f, "path", p, n);
                fstr(c, f, "outcome", outcome);
                fpath(c, f, p, n);
                conf = true;
            }
            continue;
        }
        /* listed without a hash: never checked (P-T6) -- a RECORD lists
         * itself so, and every reinstall rewrites it */
        if (tamp || x->at_reset == AT_MISSING || pkg_has_event(s, x->db, x->package))
            continue;
        if (x->at_reset == AT_NO_HASH) {
            /* a .pyc listed without a hash: judged by its source (decision
             * 186); modified or of another type, never removed */
            const char *pw = strcmp(outcome, "modified") == 0 ? "other bytes"
                           : strcmp(outcome, "type_changed") == 0 ? "type changed" : NULL;
            if (pw == NULL || p_n_ends(p, n, ".pyc") == false) continue;
            if (s->npyc == s->cappyc) {
                const size_t cap = s->cappyc ? 2 * s->cappyc : 16;
                struct pyc *v = realloc(s->pyc, cap * sizeof *v);
                if (v == NULL) { c->oom = true; return; }
                s->pyc = v;
                s->cappyc = cap;
            }
            struct pyc *y = &s->pyc[s->npyc];
            if ((y->path = dupn(p, n)) == NULL) { c->oom = true; return; }
            y->x = x;
            y->n = n;
            y->why = pw;
            s->npyc++;
            tamp = true;
            continue;
        }
        const char *why = NULL;
        if (strcmp(outcome, "removed") == 0) why = "removed";
        else if (strcmp(outcome, "type_changed") == 0) why = "type changed";
        else if (strcmp(outcome, "modified") == 0) why = "other bytes";
        else if (strcmp(outcome, "unknown") == 0 || (a != NULL && a->type == BELAY_T_REG && !a->has_hash))
            why = "cannot be verified";
        if (why == NULL) continue;
        struct flag *f = add(c, PK_TAMPERED_INSTALLED_PACKAGE, strcmp(outcome, "unknown") == 0);
        fstr(c, f, "db", pkg_db_name(x->db));
        fstr(c, f, "package", x->package);
        fs(c, f, "path", p, n);
        fstr(c, f, "why", why);
        fstr(c, f, "at_reset", pkg_at_reset_name(x->at_reset));
        fpath(c, f, p, n);
        tamp = true;
    }
}

static bool in_record_after(const struct state *s, const char *p, size_t n) {
    const size_t k = lower(&s->after_pk, s->rec_ix, s->nrec, p, n);
    return k < s->nrec && pathcmp(s->after_pk.v[s->rec_ix[k]].path, s->after_pk.v[s->rec_ix[k]].path_len, p, n) == 0;
}

static bool ci_path(const char *p, size_t n) {
    size_t bl;
    const char *bn = base_name(p, n, &bl);
    static const char *const NAMES[] = { ".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml", ".travis.yml" };
    for (size_t i = 0; i < 4; i++)
        if (bl == strlen(NAMES[i]) && memcmp(bn, NAMES[i], bl) == 0) return true;
    /* below `.github` followed by `workflows`, or below `.circleci` */
    const char *prev = NULL;
    size_t prevl = 0, i = 0;
    while (i < n) {
        const char *sl = memchr(p + i, '/', n - i);
        if (sl == NULL) break;                      /* the last component: below nothing more */
        const size_t e = (size_t)(sl - p), l = e - i;
        if (l == 9 && memcmp(p + i, ".circleci", 9) == 0) return true;
        if (l == 9 && memcmp(p + i, "workflows", 9) == 0 && prev != NULL && prevl == 7 && memcmp(prev, ".github", 7) == 0)
            return true;
        prev = p + i;
        prevl = l;
        i = e + 1;
    }
    return false;
}

static bool on_path_dir(const struct state *s, const char *p, size_t n) {
    size_t bl;
    base_name(p, n, &bl);
    if (bl == n) return false;                      /* directly in the scope's root: no dir */
    const size_t dl = n - bl - 1;
    const struct protect_spec *sp = s->in->spec;
    if (sp != NULL && sp->has_path_dirs) {
        for (size_t i = 0; i < sp->n_path_dirs; i++)
            if (protect_match(sp->path_dirs[i], strlen(sp->path_dirs[i]), p, dl)) return true;
        return false;
    }
    static const char *const DEF[] = { "bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin", "usr/local/sbin" };
    for (size_t i = 0; i < 6; i++)
        if (dl == strlen(DEF[i]) && memcmp(p, DEF[i], dl) == 0) return true;
    /* a `bin` beside a pyvenv.cfg */
    if (dl >= 3 && memcmp(p + dl - 3, "bin", 3) == 0 && (dl == 3 || p[dl - 4] == '/')) {
        const size_t vl = dl == 3 ? 0 : dl - 4;
        for (size_t i = 0; i < s->nvenv; i++)
            if (strlen(s->venv[i]) == vl && memcmp(s->venv[i], p, vl) == 0) return true;
    }
    return false;
}

static void privilege(struct state *s, const char *p, size_t n, const struct belay_entry *b, const struct belay_entry *a,
                      bool prov) {
    struct ctx *c = s->c;
    static const struct { const char *what; unsigned bit; } BITS[] = {
        { "setuid", 04000 }, { "setgid", 02000 }, { "sticky", 01000 } };
    for (size_t i = 0; i < 3; i++) {
        const bool x = b != NULL && (b->mode & BITS[i].bit), y = a != NULL && (a->mode & BITS[i].bit);
        if (x == y) continue;
        struct flag *f = add(c, PK_PRIVILEGE_CHANGED, prov);
        fs(c, f, "path", p, n);
        fstr(c, f, "what", BITS[i].what);
        fstr(c, f, "before", x ? "on" : "off");
        fstr(c, f, "after", y ? "on" : "off");
        fpath(c, f, p, n);
    }
    const char *cb = b != NULL && b->has_caps ? b->caps_hex : "none", *ca = a != NULL && a->has_caps ? a->caps_hex : "none";
    if (strcmp(cb, ca) != 0) {
        struct flag *f = add(c, PK_PRIVILEGE_CHANGED, prov);
        fs(c, f, "path", p, n);
        fstr(c, f, "what", "caps");
        fstr(c, f, "before", cb);
        fstr(c, f, "after", ca);
        fpath(c, f, p, n);
    }
    char ib[32] = "none", ia[32] = "none";
    if (b != NULL && b->has_iflags) snprintf(ib, sizeof ib, "%llu", (unsigned long long)b->iflags);
    if (a != NULL && a->has_iflags) snprintf(ia, sizeof ia, "%llu", (unsigned long long)a->iflags);
    /* only a change that counts (inode-flags IF-2 to IF-5, IF-7): a file
     * added or removed only when its flags lock it (decision 171), a
     * directory only when a locking flag is set or cleared, never flags
     * read on one side only of an entry that kept its type */
    if (iflags_counts(b, a)) {
        struct flag *f = add(c, PK_PRIVILEGE_CHANGED, prov);
        fs(c, f, "path", p, n);
        fstr(c, f, "what", "iflags");
        fstr(c, f, "before", ib);
        fstr(c, f, "after", ia);
        fpath(c, f, p, n);
    }
}

static int tests_weakened(struct state *s, const char *p, size_t n, const struct belay_entry *b,
                          const struct belay_entry *a, bool prov) {
    if (!py_test_file(p, n)) return 0;
    unsigned char *bb, *ab;
    size_t bl, al;
    int rb = copy_of(s->cs, b, &bb, &bl);
    if (rb == -1) return -1;
    int ra = copy_of(s->cs, a, &ab, &al);
    if (ra == -1) {
        free(bb);
        return -1;
    }
    int rc = 0;
    if (rb == 1 && ra == 1) {                       /* only where both are held (an absent side counts 0) */
        struct pycount cb, ca;
        if (pycount((const char *)(bb ? (char *)bb : ""), bl, &cb) == -1) { rc = nomem(); goto out; }
        if (pycount((const char *)(ab ? (char *)ab : ""), al, &ca) == -1) { pycount_free(&cb); rc = nomem(); goto out; }
        const char *added[POLICY_STRINGS_MAX];
        const size_t na = pymarkers_added(&cb, &ca, added, POLICY_STRINGS_MAX);
        const bool b_reg = b != NULL && b->type == BELAY_T_REG, a_reg = a != NULL && a->type == BELAY_T_REG;
        const bool removed = b_reg && !a_reg, emptied = b_reg && bl > 0 && a_reg && al == 0;
        if (removed || emptied || ca.assertions < cb.assertions || ca.tests < cb.tests || na > 0) {
            struct ctx *c = s->c;
            struct flag *f = add(c, PK_TESTS_WEAKENED, prov);
            fs(c, f, "path", p, n);
            fstr(c, f, "language", "python");
            fint(f, "assertions_before", cb.assertions);
            fint(f, "assertions_after", ca.assertions);
            fint(f, "tests_before", cb.tests);
            fint(f, "tests_after", ca.tests);
            fstrings(c, f, "markers_added", added, na);
            fpath(c, f, p, n);
        }
        pycount_free(&cb);
        pycount_free(&ca);
    }
out:
    free(bb);
    free(ab);
    return rc;
}

static int pytest_config(struct state *s, const char *p, size_t n, const struct belay_entry *b,
                         const struct belay_entry *a, const char *outcome, bool prov) {
    const enum pyc_kind k = pyc_kind_of(p, n);
    if (k == PYC_NONE || strcmp(outcome, "metadata_only") == 0) return 0;
    char sec[256];
    bool differs = false;
    if (k == PYC_PYTEST_INI) {
        differs = strcmp(outcome, "unknown") != 0;
        snprintf(sec, sizeof sec, "pytest.ini");
    } else {
        unsigned char *bb, *ab;
        size_t bl, al;
        const int rb = copy_of(s->cs, b, &bb, &bl);
        if (rb == -1) return -1;
        const int ra = copy_of(s->cs, a, &ab, &al);
        if (ra == -1) {
            free(bb);
            return -1;
        }
        /* from both sides' copies; a marked empty file has none (V4-S3 is tests_weakened's alone) */
        if (rb == 1 && ra == 1 && !(b != NULL && b->writer_open) && !(a != NULL && a->writer_open))
            differs = pyc_differs(k, b != NULL && b->type == BELAY_T_REG ? (char *)(bb ? bb : (unsigned char *)"") : NULL, bl,
                                  a != NULL && a->type == BELAY_T_REG ? (char *)(ab ? ab : (unsigned char *)"") : NULL, al,
                                  sec, sizeof sec);
        free(bb);
        free(ab);
    }
    if (!differs) return 0;
    struct ctx *c = s->c;
    struct flag *f = add(c, PK_PYTEST_CONFIG_CHANGED, prov);
    fs(c, f, "path", p, n);
    fstr(c, f, "section", sec);
    fstr(c, f, "outcome", outcome);
    fpath(c, f, p, n);
    return 0;
}

static void repo_of(const char *p, size_t n, char *out, size_t cap) {
    size_t i = 0;
    out[0] = '\0';
    while (i < n) {
        const char *sl = memchr(p + i, '/', n - i);
        const size_t e = sl != NULL ? (size_t)(sl - p) : n;
        if (e - i == 4 && memcmp(p + i, ".git", 4) == 0) {
            snprintf(out, cap, "%.*s", (int)e, p);
            return;
        }
        i = e + 1;
    }
}

static int signals(struct state *s, const char *p, size_t n, const struct belay_entry *b, const struct belay_entry *a,
                   const struct rec *d) {
    if (d == NULL) return 0;                        /* unchanged: no change to mean anything */
    struct ctx *c = s->c;
    const char *o = d->outcome;
    const bool prov = strcmp(o, "unknown") == 0;
    size_t bl;
    const char *bn = base_name(p, n, &bl);
    const bool changed4 = !strcmp(o, "added") || !strcmp(o, "removed") || !strcmp(o, "modified") || !strcmp(o, "type_changed");
    if (test_file(p, n) && changed4) {
        struct flag *f = add(c, PK_TOUCHES_TESTS, prov);
        fs(c, f, "path", p, n);
        fstr(c, f, "outcome", o);
        fpath(c, f, p, n);
    }
    /* a side never looked at (not_captured, E11) is not held, nor absent */
    if (!(prov && has_str(jget(&d->v, "unknown"), "not_captured")) && tests_weakened(s, p, n, b, a, prov) == -1) return -1;
    if (ci_path(p, n)) {
        struct flag *f = add(c, PK_EDITS_CI_CONFIG, prov);
        fs(c, f, "path", p, n);
        fstr(c, f, "outcome", o);
        fpath(c, f, p, n);
    }
    if (pytest_config(s, p, n, b, a, o, prov) == -1) return -1;
    if (bl == 11 && memcmp(bn, "conftest.py", 11) == 0) {
        struct flag *f = add(c, PK_CONFTEST_CHANGED, prov);
        fs(c, f, "path", p, n);
        fstr(c, f, "outcome", o);
        fpath(c, f, p, n);
    }
    /* *.pth, sitecustomize.py, usercustomize.py directly in site-packages or dist-packages, in no RECORD after */
    if ((!strcmp(o, "added") || !strcmp(o, "modified")) &&
        ((bl > 4 && memcmp(bn + bl - 4, ".pth", 4) == 0) || (bl == 16 && memcmp(bn, "sitecustomize.py", 16) == 0) ||
         (bl == 16 && memcmp(bn, "usercustomize.py", 16) == 0)) && bl < n) {
        size_t dl;
        const char *dn = base_name(p, n - bl - 1, &dl);
        if (((dl == 13 && memcmp(dn, "site-packages", 13) == 0) || (dl == 13 && memcmp(dn, "dist-packages", 13) == 0)) &&
            !in_record_after(s, p, n)) {
            struct flag *f = add(c, PK_PYTHON_STARTUP_HOOK_CHANGED, prov);
            fs(c, f, "path", p, n);
            fstr(c, f, "outcome", o);
            fpath(c, f, p, n);
        }
    }
    /* git's findings on this path */
    const struct jval *fd = jget(&d->v, "findings");
    for (size_t i = 0; fd != NULL && fd->t == J_ARR && i < fd->n; i++) {
        const struct jval *x = &fd->kids[i];
        const char *k = jstr(x, "kind");
        const char *change = !strcmp(k, "git_hook_added") ? "added" : !strcmp(k, "git_hook_removed") ? "removed"
                           : !strcmp(k, "git_hook_changed") ? "changed"
                           : !strcmp(k, "git_hook_executable_changed") ? "executable changed" : NULL;
        if (change != NULL) {
            struct flag *f = add(c, PK_GIT_HOOK_CHANGED, prov);
            fs(c, f, "path", p, n);
            fstr(c, f, "hook", jstr(x, "hook"));
            fstr(c, f, "change", change);
            const struct jval *ex = jget(x, "executable");
            if (ex != NULL && ex->t == J_BOOL) fbool(f, "executable", ex->b);
            char t[4096 + 4];
            size_t tl = 0;
            if (!decode_path(x, "target", t, sizeof t, &tl)) tl = 0;
            fs(c, f, "target", t, tl);
            fpath(c, f, p, n);
        } else if (!strcmp(k, "git_reflog_rewritten")) {
            char repo[4096];
            repo_of(p, n, repo, sizeof repo);
            struct flag *f = add(c, PK_GIT_HISTORY_REWRITTEN, prov);
            fstr(c, f, "repo", repo);
            fstr(c, f, "branch", jstr(x, "ref"));
            fpath(c, f, p, n);
        }
    }
    /* an executable new on PATH */
    if (a != NULL && on_path_dir(s, p, n)) {
        const bool lnk = a->type == BELAY_T_LNK, xreg = a->type == BELAY_T_REG && (a->mode & 0111);
        const bool xadded = b != NULL && b->type == BELAY_T_REG && a->type == BELAY_T_REG &&
                            ((a->mode & 0111) & ~(b->mode & 0111)) != 0;
        /* A marked entry is unknown for its hash, not its mode: what the
         * outcome would have said still speaks, provisionally (V4-D9). */
        const bool marked = prov && has_str(jget(&d->v, "unknown"), "writer_open");
        if (((!strcmp(o, "added") || (marked && b == NULL)) && (lnk || xreg)) ||
            ((!strcmp(o, "modified") || !strcmp(o, "metadata_only") || (marked && b != NULL && b->type == a->type)) && xadded) ||
            ((!strcmp(o, "type_changed") || (marked && b != NULL && b->type != a->type)) && (lnk || xreg))) {
            struct flag *f = add(c, PK_NEW_EXECUTABLE_ON_PATH, prov);
            fs(c, f, "path", p, n);
            fstr(c, f, "outcome", o);
            fint(f, "mode", a->mode);
            fpath(c, f, p, n);
        }
    }
    privilege(s, p, n, b, a, prov);
    return 0;
}

/* One event of the diff (diff-events E2). */
static void event_flag(struct state *s, const struct jval *e) {
    struct ctx *c = s->c;
    const char *k = jstr(e, "event");
    const struct jval *pv = jget(e, "provisional");
    const bool prov = pv != NULL && pv->t == J_BOOL && pv->b;
    struct flag *f = NULL;
    if (!strncmp(k, "pip_", 4) || !strncmp(k, "dpkg_", 5)) {
        const bool pip = k[0] == 'p';
        char pkg[2048];
        if (pip) snprintf(pkg, sizeof pkg, "%s", jstr(e, "name"));
        else snprintf(pkg, sizeof pkg, "%s:%s", jstr(e, "package"), jstr(e, "arch"));
        f = add(c, PK_PACKAGE_CHANGED, prov);
        fstr(c, f, "db", pip ? "pip" : "dpkg");
        fstr(c, f, "package", pkg);
        fstr(c, f, "event", k);
        fstr(c, f, "change", jstr(e, "text"));
    } else if (!strcmp(k, "git_history_rewritten")) {
        f = add(c, PK_GIT_HISTORY_REWRITTEN, prov);
        fstr(c, f, "repo", jstr(e, "repo"));
        fstr(c, f, "branch", jstr(e, "branch"));
        fstr(c, f, "how", jstr(e, "how"));
    } else {
        return;
    }
    const struct jval *ps = jget(e, "paths"), *pb = jget(e, "paths_b64");
    for (size_t i = 0; ps != NULL && ps->t == J_ARR && i < ps->n; i++) fpath(c, f, ps->kids[i].s, ps->kids[i].s_len);
    for (size_t i = 0; pb != NULL && pb->t == J_ARR && i < pb->n; i++) {
        char p[4096 + 4];
        size_t pl;
        if (pb->kids[i].t == J_STR && belay_base64_decode(p, sizeof p, &pl, pb->kids[i].s) == 0) fpath(c, f, p, pl);
    }
}

/* package_changed's self_consistent: its files after against its database
 * after (decision 146) -- evidence, never proof: the policy wrote both.
 * dpkg's MD5s are read from the tree, so only while it is the after state
 * (not with --to); pip's sha256s are the manifest's. Conffiles aside. */
static int self_consistent(struct state *s) {
    if (s->in->spec != NULL && s->in->spec->frozen_packages) return 0;
    struct pkg_list sub = { 0 };
    for (size_t i = 0; i < s->c->n; i++) {
        struct flag *f = &s->c->fl[i];
        if (f->kind != PK_PACKAGE_CHANGED) continue;
        const char *pkg = field(f, "package")->s;
        const enum pkg_db d = !strcmp(field(f, "db")->s, "pip") ? PKG_PIP : PKG_DPKG;
        const size_t start = sub.n;
        for (size_t k = 0; k < s->after_pk.n; k++) {
            const struct pkg_line *x = &s->after_pk.v[k];
            if (x->db != d || x->conffile || strcmp(x->package, pkg) != 0) continue;
            if (pkgdb_add(&sub, x->db, x->package, x->version, x->path, x->path_len, false, AT_UNSET) == -1) {
                pkgdb_free(&sub);
                return -1;
            }
            memcpy(sub.v[sub.n - 1].expected, x->expected, sizeof x->expected);
        }
        if (d == PKG_DPKG && sub.n > start && !s->in->tree_is_after) {
            for (size_t k = start; k < sub.n; k++) {        /* not judged: no field */
                free(sub.v[k].package);
                free(sub.v[k].version);
                free(sub.v[k].path);
            }
            sub.n = start;
            continue;
        }
        fbool(f, "self_consistent", true);
    }
    if (sub.n > 0 && pkgdb_check(s->in->after, s->in->scope, &sub) == -1) {
        pkgdb_free(&sub);
        return -1;
    }
    for (size_t i = 0; i < s->c->n; i++) {
        struct flag *f = &s->c->fl[i];
        if (f->kind != PK_PACKAGE_CHANGED || !field(f, "self_consistent")->set) continue;
        const char *db = field(f, "db")->s, *pkg = field(f, "package")->s;
        for (size_t k = 0; k < sub.n; k++)
            if (!strcmp(pkg_db_name(sub.v[k].db), db) && !strcmp(sub.v[k].package, pkg) &&
                sub.v[k].at_reset != AT_MATCH && sub.v[k].at_reset != AT_NO_HASH)
                field(f, "self_consistent")->b = false;
    }
    pkgdb_free(&sub);
    return 0;
}

static int read_line(FILE *f, char **line, size_t *cap, size_t *n) {
    errno = 0;
    const ssize_t r = getline(line, cap, f);
    if (r == -1) {
        if (errno != 0) {
            belay_err_set(BELAY_ERR_IO, errno, "policy: cannot read the diff");
            return -1;
        }
        return 0;
    }
    *n = (size_t)r;
    if (*n > 0 && (*line)[*n - 1] == '\n') (*line)[--*n] = '\0';
    return 1;
}

static int corrupt(const char *what) {
    belay_err_set(BELAY_ERR_CORRUPT, 0, "policy: %s", what);
    return -1;
}

int policy_run(const struct policy_in *in, FILE *out, struct policy_stats *st) {
    struct ctx c = { in, NULL, 0, 0, false };
    struct state s = { .c = &c, .in = in };
    FILE *df = NULL;
    char *line = NULL;
    size_t cap = 0, ln;
    struct jval hdr = { 0 }, trl = { 0 };
    struct jval *ev = NULL;
    size_t nev = 0;
    struct belay_manifest_reader *rb = NULL, *ra = NULL;
    static struct rec d;
    static struct belay_entry eb, ea;
    struct jw w = { 0 };
    int rc = -1;
    memset(&d, 0, sizeof d);
    if (in->spec != NULL && (s.sha_seen = calloc(in->spec->n_rules + 1, sizeof *s.sha_seen)) == NULL) { nomem(); goto out; }
    if (belay_content_open(in->store, &s.cs) == -1) goto out;

    /* the bundle's package lines by path; the after databases' (RECORD paths, self_consistent) */
    if ((s.pk_ix = index_by_path(&in->bundle->packages, false, &ln)) == NULL) { nomem(); goto out; }
    if (pkgdb_list(in->after, in->store, &s.after_pk) == -1) goto out;
    if ((s.rec_ix = index_by_path(&s.after_pk, true, &s.nrec)) == NULL) { nomem(); goto out; }

    /* venvs: directories holding a pyvenv.cfg, after */
    if (belay_manifest_open(in->after, &ra) == -1) goto out;
    int r;
    while ((r = belay_manifest_next(ra, &ea)) == 1) {
        size_t bl;
        const char *bn = base_name(ea.path, ea.path_len, &bl);
        if (bl != 10 || memcmp(bn, "pyvenv.cfg", 10) != 0) continue;
        char **v = realloc(s.venv, (s.nvenv + 1) * sizeof *v);
        if (v == NULL) { nomem(); goto out; }
        s.venv = v;
        const size_t vl = ea.path_len > bl ? ea.path_len - bl - 1 : 0;
        if ((s.venv[s.nvenv] = dupn(ea.path, vl)) == NULL) { nomem(); goto out; }
        s.nvenv++;
    }
    belay_manifest_close(ra);
    ra = NULL;
    if (r == -1) goto out;

    /* pass 1 over the diff: its header, events, trailer */
    if ((df = fopen(in->diff, "r")) == NULL) { belay_err_set(BELAY_ERR_IO, errno, "policy: cannot open the diff"); goto out; }
    if (read_line(df, &line, &cap, &ln) != 1 || jsonr_parse(line, ln, &hdr) == -1 || jget(&hdr, "belay_diff") == NULL) {
        if (belay_err_code() == 0) corrupt("the diff has no header");
        goto out;
    }
    while ((r = read_line(df, &line, &cap, &ln)) == 1) {
        if (strncmp(line, "{\"event\":", 9) == 0) {
            struct jval *v = realloc(ev, (nev + 1) * sizeof *v);
            if (v == NULL) { nomem(); goto out; }
            ev = v;
            if (jsonr_parse(line, ln, &ev[nev]) == -1) { corrupt("an event line that does not parse"); goto out; }
            nev++;
        } else if (strncmp(line, "{\"belay_diff_end\":", 18) == 0) {
            if (jsonr_parse(line, ln, &trl) == -1) { corrupt("the diff's trailer does not parse"); goto out; }
        }
    }
    if (r == -1) goto out;
    if (trl.t != J_OBJ) { corrupt("the diff has no trailer"); goto out; }
    for (size_t i = 0; i < nev; i++) {          /* packages with an event: their files are the installer's */
        const char *k = jstr(&ev[i], "event");
        if ((strncmp(k, "pip_", 4) && strncmp(k, "dpkg_", 5)) || !strcmp(k, "pip_reinstalled")) continue;
        char key[2048];
        if (k[0] == 'p') snprintf(key, sizeof key, "pip %s", jstr(&ev[i], "name"));
        else snprintf(key, sizeof key, "dpkg %s:%s", jstr(&ev[i], "package"), jstr(&ev[i], "arch"));
        char **v = realloc(s.evpk, (s.nevpk + 1) * sizeof *v);
        if (v == NULL) { nomem(); goto out; }
        s.evpk = v;
        if ((s.evpk[s.nevpk] = strdup(key)) == NULL) { nomem(); goto out; }
        s.nevpk++;
    }

    /* pass 2: the manifests and the records, merged by path */
    rewind(df);
    if (read_line(df, &line, &cap, &ln) != 1) { corrupt("the diff changed"); goto out; }
    if (belay_manifest_open(in->before, &rb) == -1 || belay_manifest_open(in->after, &ra) == -1) goto out;
    int hb = belay_manifest_next(rb, &eb), ha = belay_manifest_next(ra, &ea), hd = 0;
    bool have_d = false;
    for (;;) {
        if (hb == -1 || ha == -1) goto out;
        if (!have_d) {
            const int lr = read_line(df, &line, &cap, &ln);
            if (lr == -1) goto out;
            if (lr == 1 && strncmp(line, "{\"path", 6) == 0) {
                jsonr_free(&d.v);
                if (jsonr_parse(line, ln, &d.v) == -1 || !decode_path(&d.v, "path", d.path, sizeof d.path, &d.path_len)) {
                    corrupt("a record that does not parse");
                    goto out;
                }
                snprintf(d.outcome, sizeof d.outcome, "%s", jstr(&d.v, "outcome"));
                have_d = true;
                hd = 1;
            } else {
                hd = 0;
            }
        }
        if (hb == 0 && ha == 0) {
            if (hd == 1) { corrupt("a record for a path neither manifest has"); goto out; }
            break;
        }
        const char *kp;
        size_t kl;
        if (hb == 1 && (ha == 0 || pathcmp(eb.path, eb.path_len, ea.path, ea.path_len) <= 0)) kp = eb.path, kl = eb.path_len;
        else kp = ea.path, kl = ea.path_len;
        char key[4096];
        memcpy(key, kp, kl);
        const struct belay_entry *b = hb == 1 && pathcmp(eb.path, eb.path_len, key, kl) == 0 ? &eb : NULL;
        const struct belay_entry *a = ha == 1 && pathcmp(ea.path, ea.path_len, key, kl) == 0 ? &ea : NULL;
        if (have_d && pathcmp(d.path, d.path_len, key, kl) < 0) { corrupt("a record out of the manifests' order"); goto out; }
        const struct rec *dr = have_d && pathcmp(d.path, d.path_len, key, kl) == 0 ? &d : NULL;
        protected(&s, key, kl, b, a, dr);       /* the scope root too: privilege on any file */
        packages(&s, key, kl, a, dr);
        if (signals(&s, key, kl, b, a, dr) == -1) goto out;
        if (c.oom) { nomem(); goto out; }
        if (dr != NULL && p_n_ends(key, kl, ".py")) {
            if (s.nchg_py == s.capchg_py) {
                const size_t cap = s.capchg_py ? 2 * s.capchg_py : 64;
                char **v = realloc(s.chg_py, cap * sizeof *v);
                if (v == NULL) { nomem(); goto out; }
                s.chg_py = v;
                s.capchg_py = cap;
            }
            if ((s.chg_py[s.nchg_py] = dupn(key, kl)) == NULL) { nomem(); goto out; }
            s.nchg_py++;
        }
        if (dr != NULL) have_d = false;
        if (b != NULL) hb = belay_manifest_next(rb, &eb);
        if (a != NULL) ha = belay_manifest_next(ra, &ea);
    }
    /* a .pyc changed under a source that did not (decision 186) */
    for (size_t i = 0; i < s.npyc; i++) {
        char src[4096 + 8];
        const size_t sl = pyc_source(s.pyc[i].path, s.pyc[i].n, src, sizeof src);
        bool changed = sl == 0;
        for (size_t k = 0; k < s.nchg_py && !changed; k++)
            changed = strlen(s.chg_py[k]) == sl && memcmp(s.chg_py[k], src, sl) == 0;
        if (changed) continue;
        const struct pkg_line *x = s.pyc[i].x;
        struct flag *f = add(&c, PK_TAMPERED_INSTALLED_PACKAGE, false);
        fstr(&c, f, "db", pkg_db_name(x->db));
        fstr(&c, f, "package", x->package);
        fs(&c, f, "path", s.pyc[i].path, s.pyc[i].n);
        fstr(&c, f, "why", s.pyc[i].why);
        fstr(&c, f, "at_reset", pkg_at_reset_name(x->at_reset));
        fpath(&c, f, s.pyc[i].path, s.pyc[i].n);
    }
    /* expected_sha256 of a path no after entry has, and no before entry either */
    for (size_t i = 0; in->spec != NULL && i < in->spec->n_rules; i++) {
        const struct protect_rule *r2 = &in->spec->rules[i];
        if (!r2->has_sha256 || s.sha_seen[i]) continue;
        struct flag *f = add(&c, PK_PROTECTED_HASH_MISMATCH, false);
        fs(&c, f, "path", r2->path, r2->path_len);
        fstr(&c, f, "expected", r2->sha256);
        fstr(&c, f, "why", "absent");
        fpath(&c, f, r2->path, r2->path_len);
    }
    for (size_t i = 0; i < nev; i++) event_flag(&s, &ev[i]);
    if (c.oom) { nomem(); goto out; }
    if (self_consistent(&s) == -1) goto out;
    for (size_t i = 0; i < c.n; i++)
        if (render(&c.fl[i]) == -1) { nomem(); goto out; }
    if (c.n > 1) qsort(c.fl, c.n, sizeof *c.fl, flagcmp);

    /* header (P-H1 to P-H8) */
    JW_LIT(&w, "{\"belay_policy\":1,");
    const struct jval *sc = jget(&hdr, "scopes"), *scb = jget(&hdr, "scopes_b64");
    jw_raw(&w, sc != NULL ? "\"scopes\":" : "\"scopes_b64\":", sc != NULL ? 9 : 13);
    if (sc != NULL || scb != NULL) jv_write(&w, sc != NULL ? sc : scb);
    else JW_LIT(&w, "[]");
    jw_fmt(&w, ",\"baseline_sha256\":\"%s\",\"protect_sha256\":", in->bundle_sha256);
    if (in->spec != NULL) jw_fmt(&w, "\"%s\"", in->spec->sha256);
    else JW_LIT(&w, "null");
    jw_fmt(&w, ",\"frozen_packages\":%s,\"before_excluded\":", in->spec != NULL && in->spec->frozen_packages ? "true" : "false");
    const struct jval *bx = jget(&hdr, "before_excluded"), *ax = jget(&hdr, "after_excluded");
    if (bx != NULL) jv_write(&w, bx); else JW_LIT(&w, "null");
    JW_LIT(&w, ",\"after_excluded\":");
    if (ax != NULL) jv_write(&w, ax); else JW_LIT(&w, "null");
    static const char TAIL[] = ",\"not_emitted\":[{\"flag\":\"writes_outside_workdir\",\"why\":\"needs a scope wider "
                               "than the workdir\"}],\"tests_counted\":[\"python\"]}\n";
    jw_raw(&w, TAIL, sizeof TAIL - 1);
    size_t counts[PK_COUNT] = { 0 }, viol = 0;
    for (size_t i = 0; i < c.n; i++) {
        write_flag(&w, &c.fl[i]);
        counts[c.fl[i].kind]++;
        viol += c.fl[i].violation;
    }
    /* trailer (P-T1 to P-T8) */
    size_t no_hash = 0;
    for (size_t i = 0; i < in->bundle->packages.n; i++) no_hash += in->bundle->packages.v[i].at_reset == AT_NO_HASH;
    jw_fmt(&w, "{\"belay_policy_end\":%zu,\"violations\":%zu,\"signals\":%zu", c.n, viol, c.n - viol);
    for (int k = 0; k < PK_COUNT; k++) jw_fmt(&w, ",\"%s\":%zu", POLICY_KINDS[k].name, counts[k]);
    const struct jval *pv = jget(&trl, "provisional");
    jw_fmt(&w, ",\"unknown\":%lld,\"packages_outside_scope\":%llu,\"packages_no_hash\":%zu,\"provisional\":%s,"
               "\"before_sha256\":\"%s\",\"after_sha256\":\"%s\"}\n",
           (long long)jint(&trl, "unknown", 0), (unsigned long long)in->bundle->packages.outside_scope, no_hash,
           pv != NULL && pv->t == J_BOOL && pv->b ? "true" : "false", jstr(&trl, "before_sha256"), jstr(&trl, "after_sha256"));
    if (w.oom) { nomem(); goto out; }
    if (fwrite(w.b, 1, w.n, out) != w.n) { belay_err_set(BELAY_ERR_IO, errno, "policy: cannot write"); goto out; }
    if (st != NULL) {
        st->violations = viol;
        st->signals = c.n - viol;
    }
    rc = 0;
out:
    jw_free(&w);
    belay_manifest_close(rb);
    belay_manifest_close(ra);
    if (df != NULL) fclose(df);
    free(line);
    jsonr_free(&hdr);
    jsonr_free(&trl);
    jsonr_free(&d.v);
    for (size_t i = 0; i < nev; i++) jsonr_free(&ev[i]);
    free(ev);
    for (size_t i = 0; i < c.n; i++) flag_free(&c.fl[i]);
    free(c.fl);
    for (size_t i = 0; i < s.nevpk; i++) free(s.evpk[i]);
    free(s.evpk);
    for (size_t i = 0; i < s.nvenv; i++) free(s.venv[i]);
    free(s.venv);
    free(s.pk_ix);
    free(s.rec_ix);
    free(s.sha_seen);
    for (size_t i = 0; i < s.nchg_py; i++) free(s.chg_py[i]);
    free(s.chg_py);
    for (size_t i = 0; i < s.npyc; i++) free(s.pyc[i].path);
    free(s.pyc);
    pkgdb_free(&s.after_pk);
    belay_content_close(s.cs);
    return rc;
}
