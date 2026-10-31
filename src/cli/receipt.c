#define _GNU_SOURCE
#include "receipt.h"

#include "jsonr.h"

#include "belay/error.h"
#include "belay/json.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* Rendered lines, kept until the trailer is read: the heading comes first. */
struct lines { char **v; size_t n, cap, more; };

static int keep(struct lines *l, char *s, bool fold, bool all) {
    if (fold && !all && l->n >= RECEIPT_FOLD) { free(s); l->more++; return 0; }
    if (l->n == l->cap) {
        const size_t c = l->cap ? l->cap * 2 : 32;
        char **q = realloc(l->v, c * sizeof *q);
        if (q == NULL) { free(s); belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
        l->v = q;
        l->cap = c;
    }
    l->v[l->n++] = s;
    return 0;
}

static void drop(struct lines *l) { for (size_t i = 0; i < l->n; i++) free(l->v[i]); free(l->v); }

/* A growable string. */
struct sb { char *p; size_t n, cap; bool bad; };
static void sbf(struct sb *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sbf(struct sb *b, const char *fmt, ...) {
    if (b->bad) return;
    va_list a;
    for (;;) {
        va_start(a, fmt);
        const int k = vsnprintf(b->p ? b->p + b->n : NULL, b->p ? b->cap - b->n : 0, fmt, a);
        va_end(a);
        if (k < 0) { b->bad = true; return; }
        if (b->p && (size_t)k < b->cap - b->n) { b->n += (size_t)k; return; }
        const size_t c = (b->cap + (size_t)k + 64) * 2;
        char *q = realloc(b->p, c);
        if (q == NULL) { b->bad = true; return; }
        b->p = q;
        b->cap = c;
    }
}

/* The record's path, printable: as is, or "(base64) ..." for path_b64. */
static const char *rpath(const struct jval *r, bool *b64) {
    const struct jval *p = jget(r, "path");
    *b64 = p == NULL;
    return p != NULL ? p->s : jstr(r, "path_b64");
}

static bool has(const struct jval *arr, const char *s) {
    if (arr == NULL || arr->t != J_ARR) return false;
    for (size_t i = 0; i < arr->n; i++)
        if (arr->kids[i].t == J_STR && strcmp(arr->kids[i].s, s) == 0) return true;
    return false;
}

static void list(struct sb *b, const struct jval *arr) {
    for (size_t i = 0; arr != NULL && arr->t == J_ARR && i < arr->n; i++)
        sbf(b, "%s%s", i ? ", " : "", arr->kids[i].t == J_STR ? arr->kids[i].s : "?");
}

static const char *sym(const char *outcome) {
    static const struct { const char *o, *s; } S[] = {
        { "added", "A" }, { "removed", "D" }, { "modified", "M" }, { "type_changed", "T" },
        { "metadata_only", "~" }, { "unknown", "?" },
    };
    for (size_t i = 0; i < sizeof S / sizeof S[0]; i++) if (strcmp(S[i].o, outcome) == 0) return S[i].s;
    return "?";
}

/* What makes a record a privilege change, said; "" when it is none. */
static void privilege(struct sb *b, const struct jval *r, const struct receipt_opts *o) {
    const struct jval *ch = jget(r, "changed");
    if (has(ch, "mode") && o->mode != NULL) {
        bool b64;
        const char *p = rpath(r, &b64);
        uint32_t m0, m1;
        if (!b64 && o->mode(o->mode_ctx, 0, p, strlen(p), &m0) == 0 &&
            o->mode(o->mode_ctx, 1, p, strlen(p), &m1) == 0 && ((m0 ^ m1) & 07000) != 0) {
            static const struct { uint32_t bit; const char *name; } B[] = {
                { 04000, "setuid" }, { 02000, "setgid" }, { 01000, "sticky" },
            };
            for (size_t i = 0; i < 3; i++)
                if ((m0 ^ m1) & B[i].bit)
                    sbf(b, "%s%s %s", b->n ? ", " : "", B[i].name, (m1 & B[i].bit) ? "added" : "removed");
            sbf(b, " (mode %04o -> %04o)", m0 & 07777, m1 & 07777);
        }
    }
    if (has(ch, "caps")) sbf(b, "%scapabilities changed", b->n ? ", " : "");
    if (has(ch, "iflags")) sbf(b, "%sinode flags changed", b->n ? ", " : "");
}

static int record(const struct jval *r, struct lines *priv, struct lines *other,
                  const struct receipt_opts *o) {
    struct sb why = { 0 };
    privilege(&why, r, o);
    if (why.bad) { free(why.p); return -1; }
    bool b64;
    const char *p = rpath(r, &b64);
    const char *outcome = jstr(r, "outcome");
    struct sb b = { 0 };
    sbf(&b, "  %s %s%s", sym(outcome), b64 ? "(base64) " : "", p);
    if (why.n) {
        sbf(&b, "   %s", why.p);
    } else if (strcmp(outcome, "unknown") == 0) {
        sbf(&b, "   unknown: ");
        list(&b, jget(r, "unknown"));
    } else if (strcmp(outcome, "type_changed") == 0) {
        sbf(&b, "   %s -> %s", jstr(r, "type_before"), jstr(r, "type"));
    } else if (strcmp(outcome, "metadata_only") == 0 || strcmp(outcome, "modified") == 0) {
        const struct jval *ch = jget(r, "changed");
        if (ch != NULL && ch->n && !jget(r, "findings")) { sbf(&b, "   "); list(&b, ch); }
    }
    free(why.p);
    const struct jval *f = jget(r, "findings");
    for (size_t i = 0; f != NULL && f->t == J_ARR && i < f->n && i < RECEIPT_FINDINGS; i++)
        sbf(&b, "\n      %s", jstr(&f->kids[i], "text"));
    if (f != NULL && f->t == J_ARR && f->n > RECEIPT_FINDINGS)
        sbf(&b, "\n      and %zu more", f->n - RECEIPT_FINDINGS);
    if (b.bad) { free(b.p); belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
    const bool is_priv = why.n != 0;
    return keep(is_priv ? priv : other, b.p, !is_priv, o->all);
}

static int event(const struct jval *e, struct lines *ev, const struct receipt_opts *o) {
    struct sb b = { 0 };
    sbf(&b, "  %-5s %s", jstr(e, "interp"), jstr(e, "text"));
    const struct jval *pv = jget(e, "provisional");
    if (pv != NULL && pv->t == J_BOOL && pv->b) sbf(&b, " (provisional: a path it came from is unknown)");
    const char *k = jstr(e, "event");
    if (strcmp(k, "could_not_interpret") == 0 || strcmp(k, "invalid_finding") == 0 ||
        strcmp(k, "content_unavailable") == 0) {
        const struct jval *ps = jget(e, "paths");
        if (ps == NULL) ps = jget(e, "paths_b64");
        if (ps != NULL && ps->t == J_ARR && ps->n)
            sbf(&b, ": %s%s", ps->kids[0].s, ps->n > 1 ? " and others" : "");
    }
    if (b.bad) { free(b.p); belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
    return keep(ev, b.p, true, o->all);
}

int receipt_render(FILE *diff, FILE *out, const struct receipt_opts *o) {
    struct lines ev = { 0 }, priv = { 0 }, other = { 0 };
    char *line = NULL, scope[4200] = "";
    size_t cap = 0, lineno = 0;
    ssize_t got;
    struct jval trailer = { 0 };
    bool have_trailer = false;
    int rc = -1;
    while ((got = getline(&line, &cap, diff)) > 0) {
        lineno++;
        struct jval v;
        if (jsonr_parse(line, (size_t)got, &v) == -1 || v.t != J_OBJ) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "receipt: line %zu is not diff.v1", lineno);
            goto out;
        }
        int r = 0;
        if (jget(&v, "belay_diff") != NULL) {
            const struct jval *s = jget(&v, "scopes");
            if (s != NULL && s->t == J_ARR && s->n) snprintf(scope, sizeof scope, "%s", s->kids[0].s);
        } else if (jget(&v, "belay_diff_end") != NULL) {
            trailer = v;
            have_trailer = true;
            continue;
        } else if (jget(&v, "event") != NULL) {
            r = event(&v, &ev, o);
        } else {
            r = record(&v, &priv, &other, o);
        }
        jsonr_free(&v);
        if (r == -1) goto out;
    }
    if (!have_trailer) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "receipt: the diff has no trailer (truncated)");
        goto out;
    }
    fprintf(out, "belay diff  %s  %s -> %s\n", scope, o->from ? o->from : "before", o->to ? o->to : "after");
    static const char *const OUT[] = { "modified", "added", "removed", "type_changed", "metadata_only", "unknown" };
    struct sb c = { 0 };
    for (size_t i = 0; i < sizeof OUT / sizeof OUT[0]; i++) {
        const int64_t k = jint(&trailer, OUT[i], 0);
        if (k) sbf(&c, "%s%lld %s", c.n ? " · " : "", (long long)k, OUT[i]);
    }
    const int64_t nev = jint(&trailer, "events", 0);
    if (c.n == 0 && nev == 0) fprintf(out, "  no changes\n");
    else fprintf(out, "  %s%sevents: %lld\n", c.n ? c.p : "", c.n ? "    " : "", (long long)nev);
    free(c.p);
    const int64_t vb = jint(&trailer, "before_vanished", 0), va = jint(&trailer, "after_vanished", 0);
    if (vb || va)
        fprintf(out, "  %lld entries vanished while the before walk ran, %lld while the after walk ran\n",
                (long long)vb, (long long)va);
    const struct { const char *title; struct lines *l; } SEC[] = {
        { "packages and files explained", &ev }, { "privilege", &priv }, { "changes", &other },
    };
    for (size_t s = 0; s < 3; s++) {
        if (SEC[s].l->n == 0) continue;
        fprintf(out, "\n%s\n", SEC[s].title);
        for (size_t i = 0; i < SEC[s].l->n; i++) fprintf(out, "%s\n", SEC[s].l->v[i]);
        if (SEC[s].l->more) fprintf(out, "  and %zu more (--all shows them)\n", SEC[s].l->more);
    }
    if (ferror(out)) {
        belay_err_set(BELAY_ERR_IO, 0, "receipt: write failed");
        goto out;
    }
    rc = 0;
out:
    if (have_trailer) jsonr_free(&trailer);
    free(line);
    drop(&ev);
    drop(&priv);
    drop(&other);
    return rc;
}
