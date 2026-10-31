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

/* A code point that changes how text around it is shown without being
 * seen: bidi controls and invisible format characters (second review
 * 2026-10-31, D6: "rlo\u202Eexe.txt" showed as "rlotxt.exe"). */
static bool invisible(uint32_t cp) {
    return cp == 0x00AD || cp == 0x061C || (cp >= 0x200B && cp <= 0x200F) || (cp >= 0x2028 && cp <= 0x202E) ||
           (cp >= 0x2060 && cp <= 0x2064) || (cp >= 0x2066 && cp <= 0x206F) || cp == 0xFEFF;
}

/* `len` bytes, printable on one line: valid UTF-8 as is, except C0 and C1
 * controls, DEL and invisible format characters; those and every byte that
 * is not UTF-8 as \xNN; a backslash doubled, so \xNN is never ambiguous. */
static void esc(struct sb *b, const char *s, size_t len) {
    for (size_t i = 0; i < len;) {
        const unsigned char c = (unsigned char)s[i];
        size_t k = c < 0x80 ? 1 : c >= 0xC2 && c <= 0xDF ? 2 : c >= 0xE0 && c <= 0xEF ? 3
                 : c >= 0xF0 && c <= 0xF4 ? 4 : 0;
        if (k > 1 && (i + k > len || !belay_utf8_valid(s + i, k))) k = 0;
        const bool c1 = k == 2 && c == 0xC2 && (unsigned char)s[i + 1] < 0xA0;
        uint32_t cp = 0;
        if (k == 2) cp = (uint32_t)(c & 0x1F) << 6 | ((unsigned char)s[i + 1] & 0x3F);
        if (k == 3)
            cp = (uint32_t)(c & 0x0F) << 12 | (uint32_t)((unsigned char)s[i + 1] & 0x3F) << 6 |
                 ((unsigned char)s[i + 2] & 0x3F);
        if (k == 0 || c1 || c < 0x20 || c == 0x7F || invisible(cp)) {
            const size_t n = k == 0 ? 1 : k;
            for (size_t j = 0; j < n; j++) sbf(b, "\\x%02x", (unsigned char)s[i + j]);
            i += n;
        } else if (c == '\\') {
            sbf(b, "\\\\");
            i++;
        } else {
            sbf(b, "%.*s", (int)k, s + i);
            i += k;
        }
    }
}

/* A string member, escaped; nothing when absent or not a string. */
static void escs(struct sb *b, const struct jval *v) {
    if (v != NULL && v->t == J_STR) esc(b, v->s, v->s_len);
}

/* The record's path as bytes into buf: "path", or "path_b64" decoded. 0, or
 * -1 when neither is there or the base64 is not. */
static int rpath(const struct jval *r, char *buf, size_t cap, size_t *len) {
    const struct jval *p = jget(r, "path");
    if (p != NULL && p->t == J_STR && p->s_len <= cap) {
        memcpy(buf, p->s, p->s_len);
        *len = p->s_len;
        return 0;
    }
    p = jget(r, "path_b64");
    if (p == NULL || p->t != J_STR) return -1;
    return belay_base64_decode(buf, cap, len, p->s) == 0 ? 0 : (belay_err_clear(), -1);
}

static bool has(const struct jval *arr, const char *s) {
    if (arr == NULL || arr->t != J_ARR) return false;
    for (size_t i = 0; i < arr->n; i++)
        if (arr->kids[i].t == J_STR && strcmp(arr->kids[i].s, s) == 0) return true;
    return false;
}

static void list(struct sb *b, const struct jval *arr) {
    for (size_t i = 0; arr != NULL && arr->t == J_ARR && i < arr->n; i++) {
        sbf(b, "%s", i ? ", " : "");
        if (arr->kids[i].t == J_STR) escs(b, &arr->kids[i]);
        else sbf(b, "?");
    }
}

static const char *sym(const char *outcome) {
    static const struct { const char *o, *s; } S[] = {
        { "added", "A" }, { "removed", "D" }, { "modified", "M" }, { "type_changed", "T" },
        { "metadata_only", "~" }, { "unknown", "?" },
    };
    for (size_t i = 0; i < sizeof S / sizeof S[0]; i++) if (strcmp(S[i].o, outcome) == 0) return S[i].s;
    return "?";
}

/* What makes a record a privilege change, said; nothing when it is none.
 * The special mode bits and file capabilities are compared across the two
 * sides whatever the outcome: a file added setuid, or removed with caps, is
 * a privilege change as much as a chmod is (review 2026-10-31, Phase 5, 7). */
static void privilege(struct sb *b, const struct jval *r, const char *path, size_t len,
                      const struct receipt_opts *o) {
    const struct jval *ch = jget(r, "changed");
    const char *outcome = jstr(r, "outcome");
    const bool sides = has(ch, "mode") || strcmp(outcome, "added") == 0 || strcmp(outcome, "removed") == 0 ||
                       strcmp(outcome, "type_changed") == 0;
    if (sides && o->mode != NULL && path != NULL) {
        struct receipt_meta m[2] = { { 0, false }, { 0, false } };
        bool on[2];
        for (int s = 0; s < 2; s++) on[s] = o->mode(o->mode_ctx, s, path, len, &m[s]) == 0;
        const uint32_t x0 = on[0] ? m[0].mode & 07000 : 0, x1 = on[1] ? m[1].mode & 07000 : 0;
        if (x0 != x1) {
            static const struct { uint32_t bit; const char *name; } B[] = {
                { 04000, "setuid" }, { 02000, "setgid" }, { 01000, "sticky" },
            };
            for (size_t i = 0; i < 3; i++)
                if ((x0 ^ x1) & B[i].bit)
                    sbf(b, "%s%s %s", b->n ? ", " : "", B[i].name, (x1 & B[i].bit) ? "added" : "removed");
            if (on[0] && on[1]) sbf(b, " (mode %04o -> %04o)", m[0].mode & 07777, m[1].mode & 07777);
            else if (on[1]) sbf(b, " (new, mode %04o)", m[1].mode & 07777);
            else sbf(b, " (removed, mode %04o)", m[0].mode & 07777);
        }
        if (!has(ch, "caps") && (on[0] && m[0].has_caps) != (on[1] && m[1].has_caps))
            sbf(b, "%scapabilities %s", b->n ? ", " : "", on[1] && m[1].has_caps ? "set" : "removed");
    }
    if (has(ch, "caps")) sbf(b, "%scapabilities changed", b->n ? ", " : "");
    if (has(ch, "iflags")) sbf(b, "%sinode flags changed", b->n ? ", " : "");
}

static int record(const struct jval *r, struct lines *priv, struct lines *other,
                  const struct receipt_opts *o) {
    static char path[4096];
    size_t plen = 0;
    const bool have_path = rpath(r, path, sizeof path, &plen) == 0;
    struct sb why = { 0 };
    privilege(&why, r, have_path ? path : NULL, plen, o);
    if (why.bad) { free(why.p); belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
    const char *outcome = jstr(r, "outcome");
    struct sb b = { 0 };
    sbf(&b, "  %s ", sym(outcome));
    if (have_path) esc(&b, path, plen);
    else sbf(&b, "(no path)");
    if (why.n) {
        sbf(&b, "   ");
        if (strcmp(outcome, "type_changed") == 0) {     /* the type change is said too (D8) */
            escs(&b, jget(r, "type_before"));
            sbf(&b, " -> ");
            escs(&b, jget(r, "type"));
            sbf(&b, ", ");
        }
        sbf(&b, "%s", why.p);
    } else if (strcmp(outcome, "unknown") == 0) {
        sbf(&b, "   unknown: ");
        list(&b, jget(r, "unknown"));
    } else if (strcmp(outcome, "type_changed") == 0) {
        sbf(&b, "   ");
        escs(&b, jget(r, "type_before"));
        sbf(&b, " -> ");
        escs(&b, jget(r, "type"));
    } else if (strcmp(outcome, "metadata_only") == 0 || strcmp(outcome, "modified") == 0) {
        const struct jval *ch = jget(r, "changed");
        if (ch != NULL && ch->n && !jget(r, "findings")) { sbf(&b, "   "); list(&b, ch); }
    }
    free(why.p);
    const struct jval *f = jget(r, "findings");
    for (size_t i = 0; f != NULL && f->t == J_ARR && i < f->n && i < RECEIPT_FINDINGS; i++) {
        sbf(&b, "\n      ");
        escs(&b, jget(&f->kids[i], "text"));
    }
    if (f != NULL && f->t == J_ARR && f->n > RECEIPT_FINDINGS)
        sbf(&b, "\n      and %zu more", f->n - RECEIPT_FINDINGS);
    if (b.bad) { free(b.p); belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
    /* Privilege never folds; nor does an entry belay could not capture
     * reliably: each is named on its own line (S7 2026-10-31, row 73). */
    const bool is_priv = why.n != 0;
    return keep(is_priv ? priv : other, b.p, !is_priv && strcmp(outcome, "unknown") != 0, o->all);
}

static int event(const struct jval *e, struct lines *ev, const struct receipt_opts *o) {
    struct sb b = { 0 };
    struct sb in = { 0 };
    escs(&in, jget(e, "interp"));
    sbf(&b, "  %-5s ", in.p != NULL ? in.p : "");
    free(in.p);
    escs(&b, jget(e, "text"));
    const struct jval *pv = jget(e, "provisional");
    if (pv != NULL && pv->t == J_BOOL && pv->b) sbf(&b, " (provisional: a path it came from is unknown)");
    const char *k = jstr(e, "event");
    if (strcmp(k, "could_not_interpret") == 0 || strcmp(k, "invalid_finding") == 0 ||
        strcmp(k, "content_unavailable") == 0) {
        const struct jval *ps = jget(e, "paths");
        bool b64 = false;
        if (ps == NULL) { ps = jget(e, "paths_b64"); b64 = true; }
        if (ps != NULL && ps->t == J_ARR && ps->n && ps->kids[0].t == J_STR) {
            static char raw[4096];
            size_t rl;
            sbf(&b, ": ");
            if (!b64) escs(&b, &ps->kids[0]);
            else if (belay_base64_decode(raw, sizeof raw, &rl, ps->kids[0].s) == 0) esc(&b, raw, rl);
            else { belay_err_clear(); sbf(&b, "?"); }
            sbf(&b, "%s", ps->n > 1 ? " and others" : "");
        }
    }
    if (b.bad) { free(b.p); belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
    return keep(ev, b.p, true, o->all);
}

int receipt_render(FILE *diff, FILE *out, const struct receipt_opts *o) {
    struct lines ev = { 0 }, priv = { 0 }, other = { 0 };
    char *line = NULL;
    struct sb scope = { 0 };
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
            if (lineno != 1 || jint(&v, "belay_diff", 0) != 1) {     /* a version not known: rejected (diff-v1) */
                jsonr_free(&v);
                belay_err_set(BELAY_ERR_CORRUPT, 0, "receipt: not diff.v1 (version %s)",
                              lineno != 1 ? "header not first" : "unknown");
                goto out;
            }
            const struct jval *s = jget(&v, "scopes");
            if (s != NULL && s->t == J_ARR && s->n && s->kids[0].t == J_STR) {
                esc(&scope, s->kids[0].s, s->kids[0].s_len);
            } else if ((s = jget(&v, "scopes_b64")) != NULL && s->t == J_ARR && s->n && s->kids[0].t == J_STR) {
                static char raw[4096];       /* a scope that is not UTF-8 (review 2026-10-31, Phase 5, 12) */
                size_t rl;
                if (belay_base64_decode(raw, sizeof raw, &rl, s->kids[0].s) == 0) esc(&scope, raw, rl);
                else belay_err_clear();
            }
        } else if (lineno == 1) {
            jsonr_free(&v);
            belay_err_set(BELAY_ERR_CORRUPT, 0, "receipt: the diff has no header");
            goto out;
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
    if (scope.bad) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory");
        goto out;
    }
    fprintf(out, "belay diff  %s  %s -> %s\n", scope.p != NULL ? scope.p : "", o->from ? o->from : "before",
            o->to ? o->to : "after");
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
    free(scope.p);
    drop(&ev);
    drop(&priv);
    drop(&other);
    return rc;
}

void receipt_fputs(FILE *f, const char *s) {
    struct sb b = { 0 };
    esc(&b, s, strlen(s));
    if (b.p != NULL && !b.bad) fputs(b.p, f);
    else if (b.bad) fputs("?", f);
    free(b.p);
}
