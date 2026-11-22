#define _GNU_SOURCE
#include "receipt.h"

#include "util/jsonr.h"
#include "cli/gitclass.h"
#include "schema/iflags.h"

#include "belay/error.h"
#include "belay/json.h"

size_t receipt_owner_asks = 262144;

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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

/* One side's value of `field` from the record's before/after object, as a
 * person reads it: a mode's permission bits in octal, a number, a string
 * escaped. 0 when shown; -1 when that side carries none. */
static int value(struct sb *b, const struct jval *side, const char *field) {
    const struct jval *v = jget(side, field);
    if (v == NULL) return -1;
    if (v->t == J_NUM && strcmp(field, "mode") == 0) sbf(b, "%04llo", (unsigned long long)v->i & 07777);
    else if (v->t == J_NUM) sbf(b, "%lld", (long long)v->i);
    else if (v->t == J_STR) escs(b, v);
    else return -1;
    return 0;
}

/* The changed fields, each with its values where a person reads them as
 * such -- "mode 0644 -> 0600", "uid 1000 -> 0" (decision 2026-11-01, 5:
 * receipts need them) -- the others by name: hashes and times say nothing
 * more than "changed". */
static void changed_values(struct sb *b, const struct jval *r, const struct jval *ch) {
    static const char *const SHOWN[] = { "mode", "uid", "gid", "size", "link_target", "nlink" };
    const struct jval *bf = jget(r, "before"), *af = jget(r, "after");
    for (size_t i = 0; i < ch->n; i++) {
        if (ch->kids[i].t != J_STR) continue;
        const char *f = ch->kids[i].s;
        sbf(b, "%s", i ? ", " : "");
        escs(b, &ch->kids[i]);
        bool shown = false;
        for (size_t k = 0; k < sizeof SHOWN / sizeof SHOWN[0]; k++) shown |= strcmp(f, SHOWN[k]) == 0;
        if (!shown || jget(bf, f) == NULL || jget(af, f) == NULL) continue;
        sbf(b, " ");
        value(b, bf, f);
        sbf(b, " -> ");
        value(b, af, f);
    }
}

/* What makes a record a privilege change, said; nothing when it is none.
 * The special mode bits and file capabilities are compared across the two
 * sides whatever the outcome: a file added setuid, or removed with caps, is
 * a privilege change as much as a chmod is (review 2026-10-31, Phase 5, 7). */
static void privilege(struct sb *b, const struct jval *r, const char *path, size_t len,
                      const struct receipt_opts *o) {
    const struct jval *ch = jget(r, "changed");
    const char *outcome = jstr(r, "outcome");
    const bool one_side = strcmp(outcome, "added") == 0 || strcmp(outcome, "removed") == 0;
    const bool sides = has(ch, "mode") || has(ch, "iflags") || one_side || strcmp(outcome, "type_changed") == 0;
    bool iflags_known = false, iflags_count = false;    /* by test/expect/inode-flags.md */
    if (sides && o->mode != NULL && path != NULL) {
        struct receipt_meta m[2] = { { 0, false, false, 0 }, { 0, false, false, 0 } };
        bool on[2];
        for (int s = 0; s < 2; s++) on[s] = o->mode(o->mode_ctx, s, path, len, &m[s]) == 0;
        /* Inode flags: a record that lists them has both sides' (a side
         * without them is `unknown`, never `changed`); an entry added or
         * removed has its own. Where the lookup gives none, the record is
         * believed, as before. */
        if (one_side ? (on[0] != on[1]) : (on[0] && on[1] && m[0].has_iflags && m[1].has_iflags)) {
            const struct iflags_side sb = { on[0], (int)(m[0].mode & S_IFMT), S_ISDIR(m[0].mode), m[0].has_iflags, m[0].iflags },
                                     sa = { on[1], (int)(m[1].mode & S_IFMT), S_ISDIR(m[1].mode), m[1].has_iflags, m[1].iflags };
            iflags_known = true;
            iflags_count = iflags_change_counts(&sb, &sa);
        }
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
    if (has(ch, "iflags") && (!iflags_known || iflags_count)) sbf(b, "%sinode flags changed", b->n ? ", " : "");
    /* an entry that came or went holding immutable or append-only (IF-3, IF-8) */
    if (one_side && iflags_known && iflags_count)
        sbf(b, "%sinode flags %s", b->n ? ", " : "", strcmp(outcome, "added") == 0 ? "set" : "removed");
    /* A flag change that is no privilege change, on a record that is one
     * for another reason: its line shows only these reasons, so the flags
     * are named here, as the other changes name them, or they would be
     * shown nowhere (IF-8; review of #129, 2). */
    if (has(ch, "iflags") && iflags_known && !iflags_count && b->n) sbf(b, ", iflags");
}

/* A count under a name -- an ignored top-level directory, or a repository's
 * .git -- with, for a .git, the moves that left a ref in place, by operation. */
struct op { char *name; size_t n; };
struct tally { char *key; size_t n; struct op *ops; size_t nops; };
struct tallies { struct tally *v; size_t n; };

static struct tally *tally(struct tallies *t, const char *key, size_t kl) {
    for (size_t i = 0; i < t->n; i++)
        if (strlen(t->v[i].key) == kl && memcmp(t->v[i].key, key, kl) == 0) return &t->v[i];
    struct tally *q = realloc(t->v, (t->n + 1) * sizeof *q);
    if (q == NULL) return NULL;
    t->v = q;
    struct tally *x = &t->v[t->n];
    memset(x, 0, sizeof *x);
    if ((x->key = strndup(key, kl)) == NULL) return NULL;
    t->n++;
    return x;
}

static int count_op(struct tally *x, const char *name) {
    for (size_t i = 0; i < x->nops; i++)
        if (strcmp(x->ops[i].name, name) == 0) { x->ops[i].n++; return 0; }
    struct op *q = realloc(x->ops, (x->nops + 1) * sizeof *q);
    if (q == NULL) return -1;
    x->ops = q;
    if ((x->ops[x->nops].name = strdup(name)) == NULL) return -1;
    x->ops[x->nops++].n = 1;
    return 0;
}

/* Most first; a tie by name. */
static int by_count(const void *a, const void *b) {
    const struct op *x = a, *y = b;
    return x->n != y->n ? (x->n < y->n ? 1 : -1) : strcmp(x->name, y->name);
}

static void tallies_free(struct tallies *t) {
    for (size_t i = 0; i < t->n; i++) {
        for (size_t k = 0; k < t->v[i].nops; k++) free(t->v[i].ops[k].name);
        free(t->v[i].ops);
        free(t->v[i].key);
    }
    free(t->v);
}

/* Where a path is a repository's bookkeeping, as the dogfood receipt reads
 * it (decision 105): the first ".git" followed by "/" or the end -- a .git
 * that is a file points elsewhere and is none. The offset of ".git", or -1. */
static long gitpos(const char *p, size_t len, const char *type) {
    for (size_t i = 0; i + 4 <= len; i++) {
        if (memcmp(p + i, ".git", 4) != 0 || (i + 4 < len && p[i + 4] != '/')) continue;
        if (i + 4 == len && (type == NULL || strcmp(type, "dir") != 0)) return -1;
        return (long)i;
    }
    return -1;
}

/* git's findings on a reflog that gained only moves leaving the ref where
 * it was: those fold, counted (2026-11-04). The index's "index changed"
 * folds wherever it is. */
static bool only_in_place(const struct jval *f) {
    size_t moves = 0;
    int64_t entries = 0;
    for (size_t i = 0; f != NULL && f->t == J_ARR && i < f->n; i++) {
        const char *k = jstr(&f->kids[i], "kind");
        if (strncmp(k, "git_", 4) != 0 || strcmp(k, "git_index_changed") == 0) continue;
        if (strcmp(k, "git_reflog_move") == 0) {
            const struct jval *a = jget(&f->kids[i], "from"), *b = jget(&f->kids[i], "to");
            if (a == NULL || b == NULL || a->t != J_STR || b->t != J_STR || strcmp(a->s, b->s) != 0) return false;
            moves++;
        } else if (strcmp(k, "git_reflog_appended") == 0) {
            entries += jint(&f->kids[i], "entries", 0);
        } else {
            return false;
        }
    }
    return moves > 0 && (entries == 0 || entries == (int64_t)moves);
}

/* A finding of git's that keeps a .git path on its own line: any but the
 * index's "index changed", which folds with the rest (2026-11-04). */
/* Whether a record's `unknown` names this reason. */
static bool has_reason(const struct jval *u, const char *why) {
    for (size_t i = 0; u != NULL && u->t == J_ARR && i < u->n; i++)
        if (u->kids[i].t == J_STR && strcmp(u->kids[i].s, why) == 0) return true;
    return false;
}

/* A text edit among a record's findings. */
static bool text_edit(const struct jval *f) {
    for (size_t i = 0; f != NULL && f->t == J_ARR && i < f->n; i++) {
        const char *k = jstr(&f->kids[i], "kind");
        if (strcmp(k, "text_changed") == 0 || strcmp(k, "text_rewritten") == 0) return true;
    }
    return false;
}

static bool any_git(const struct jval *f) {
    for (size_t i = 0; f != NULL && f->t == J_ARR && i < f->n; i++) {
        const char *k = jstr(&f->kids[i], "kind");
        if (strncmp(k, "git_", 4) == 0 && strcmp(k, "git_index_changed") != 0) return true;
    }
    return false;
}

/* A package of this diff's dpkg events (system-interpreters.md SD-3): the
 * records its file list owns are counted in its line. */
enum { PK_INSTALLED, PK_UPGRADED, PK_DOWNGRADED, PK_REMOVED };
struct pk {
    char *package, *arch, *version;     /* version: an installed one's, for the installed line */
    int kind;
    int aut;                            /* -1: the event has no `auto` */
    bool prov;
    size_t count;                       /* records folded into it */
};
/* A name dpkg's lists may give a package's owner: `package`, `package:arch`. */
struct pkkey { char *key; size_t pk; };

static int pkkey_cmp(const void *a, const void *b) {
    return strcmp(((const struct pkkey *)a)->key, ((const struct pkkey *)b)->key);
}

static int pk_kind(const char *event) {
    return strcmp(event, "dpkg_installed") == 0 ? PK_INSTALLED : strcmp(event, "dpkg_upgraded") == 0 ? PK_UPGRADED
         : strcmp(event, "dpkg_downgraded") == 0 ? PK_DOWNGRADED : strcmp(event, "dpkg_removed") == 0 ? PK_REMOVED : -1;
}

/* What the changes section is built from. */
struct ctx {
    struct lines priv, tracked, other, ignedit, ignored, gitvis;
    struct tallies ign, ignu, git;      /* ignored changes; ignored unknown rows, by reason; .git */
    const unsigned char *cls;   /* each classified path's class, in order; NULL: path order */
    size_t ci;
    bool git_events;            /* git's events say what its findings did (decision 126) */
    /* SD-3: the packages of the diff's dpkg events, in the events' order;
     * each asked path's owner by the after manifest (and by the before one,
     * when a package was removed), in the records' order; NULL: nothing folds. */
    struct pk *pk;
    size_t npk, pki, n_installed;
    bool collected;             /* pass 1 ran: pk is whole before the first event is rendered */
    bool installed_said;
    char **own[2];
    size_t nown, ri;
    struct pkkey *keys;
    size_t nkeys;
};

/* The package of the diff that owns record `ri`, or NULL. An installed
 * package's files are the after manifest's, a removed one's the before's,
 * an upgraded or downgraded one's either: a file the new version dropped is
 * in the old list alone. */
static struct pk *owner_pk(struct ctx *x, size_t ri) {
    if (x->keys == NULL || ri >= x->nown) return NULL;
    for (int side = 1; side >= 0; side--) {
        if (x->own[side] == NULL || x->own[side][ri] == NULL) continue;
        const struct pkkey probe = { x->own[side][ri], 0 };
        const struct pkkey *k = bsearch(&probe, x->keys, x->nkeys, sizeof *x->keys, pkkey_cmp);
        if (k == NULL) continue;
        /* several packages may share a key (libc6 of two architectures by a
         * list named without one): the first whose side this is */
        while (k > x->keys && strcmp(k[-1].key, probe.key) == 0) k--;
        for (; k < x->keys + x->nkeys && strcmp(k->key, probe.key) == 0; k++)
            if (x->pk[k->pk].kind != (side == 0 ? PK_INSTALLED : PK_REMOVED)) return &x->pk[k->pk];
    }
    return NULL;
}

static int record(const struct jval *r, struct ctx *x, const struct receipt_opts *o) {
    static char path[4096];
    size_t plen = 0;
    const bool have_path = rpath(r, path, sizeof path, &plen) == 0;
    struct sb why = { 0 };
    privilege(&why, r, have_path ? path : NULL, plen, o);
    if (why.bad) { free(why.p); belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
    const char *outcome = jstr(r, "outcome");
    const char *type = jstr(r, "type");
    const bool is_dir = type != NULL && strcmp(type, "dir") == 0;
    const long gp = have_path ? gitpos(path, plen, type) : -1;
    unsigned char c = GC_UNTRACKED;
    if (have_path && gp < 0 && x->cls != NULL) c = x->cls[x->ci++];
    const size_t ri = have_path && gp < 0 ? x->ri++ : (size_t)-1;      /* its place among the paths asked */
    /* An edit to a git-ignored file -- its text, or its type, not a
     * directory's -- is named, never folded: it is often .env or local
     * configuration (2026-11-04). A binary rewritten (build output) folds,
     * as added and removed entries do. */
    /* So is an entry marked writer_open, whatever else: a writer at an ignored
     * file is as much worth naming as an edit to one (2026-11-05). */
    const bool ign_edit = x->cls != NULL && c == GC_IGNORED &&
                          (has_reason(jget(r, "unknown"), "writer_open") ||
                           (!is_dir && (strcmp(outcome, "type_changed") == 0 ||
                                        (strcmp(outcome, "modified") == 0 && text_edit(jget(r, "findings"))))));
    struct sb b = { 0 };
    sbf(&b, "  %s ", sym(outcome));
    if (have_path) esc(&b, path, plen);
    else sbf(&b, "(no path)");
    if (ign_edit) sbf(&b, "   (git-ignored)");
    const size_t said = b.n;            /* the line up to its path */
    /* A directory belay could not list or did not enter is this one line,
     * whatever changed below it (checkpoint-v3, G3-1, G3-4, G3-5): unknown
     * for that, added so (O10), or what a path of another type became (O11). */
    const struct jval *cnr = jget(r, "content_not_read");
    const bool not_read = cnr != NULL && cnr->t == J_ARR && cnr->n > 0;
    const bool sealed = is_dir && (has(jget(r, "unknown"), "unreadable") || has(jget(r, "unknown"), "mount") ||
                                   has(jget(r, "unknown"), "not_read") ||     /* manifest v5: not entered, by rule */
                                   ((strcmp(outcome, "added") == 0 || strcmp(outcome, "type_changed") == 0) &&
                                    (has(cnr, "unreadable") || has(cnr, "mount"))));
    bool sealed_said = false;
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
        if (sealed) sbf(&b, ", nothing below it was seen");
        sealed_said = sealed;
    } else if (strcmp(outcome, "type_changed") == 0) {
        sbf(&b, "   ");
        escs(&b, jget(r, "type_before"));
        sbf(&b, " -> ");
        escs(&b, jget(r, "type"));
    } else if (strcmp(outcome, "metadata_only") == 0 || strcmp(outcome, "modified") == 0) {
        const struct jval *ch = jget(r, "changed");
        if (ch != NULL && ch->n && !jget(r, "findings")) { sbf(&b, "   "); changed_values(&b, r, ch); }
    }
    /* What was compared proves the change; the content was not read
     * (checkpoint-v3, G2-2). After whatever the line says so far. */
    if (sealed && !sealed_said) {       /* on a line that says something else, or nothing (G3-4) */
        sbf(&b, "%snothing below it was seen", b.n > said ? "; " : "   ");
    } else if (not_read && !is_dir) {
        sbf(&b, "%s", b.n > said ? "; " : "   ");
        sbf(&b, "content not read (");
        list(&b, cnr);
        sbf(&b, ")");
    }
    /* Neither is ever folded: each is named on its own line (G2-4, G3-4). */
    const bool named = not_read || sealed;
    free(why.p);
    /* A record past the 4,096-finding cap ends in an and_more finding
     * standing for n more: counted, not shown as one (review 2026-11-01,
     * D4: a 16 MiB reflog's "and 4081 more" was 114,096). */
    const struct jval *f = jget(r, "findings");
    size_t nf = f != NULL && f->t == J_ARR ? f->n : 0;
    uint64_t beyond = 0;
    if (nf > 0 && strcmp(jstr(&f->kids[nf - 1], "kind"), "and_more") == 0) {
        const int64_t k = jint(&f->kids[nf - 1], "n", 0);
        beyond = k > 0 ? (uint64_t)k : 0;
        nf--;
    }
    for (size_t i = 0; i < nf && i < RECEIPT_FINDINGS; i++) {
        sbf(&b, "\n      ");
        escs(&b, jget(&f->kids[i], "text"));
    }
    const uint64_t hidden = (nf > RECEIPT_FINDINGS ? nf - RECEIPT_FINDINGS : 0) + beyond;
    if (hidden > 0) sbf(&b, "\n      and %llu more", (unsigned long long)hidden);
    if (b.bad) { free(b.p); belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
    /* Privilege never folds; nor does an entry belay could not capture
     * reliably: each is named on its own line (S7 2026-10-31, row 73). */
    const bool is_priv = why.n != 0, unknown = strcmp(outcome, "unknown") == 0;
    if (is_priv) return keep(&x->priv, b.p, false, o->all);
    /* SD-3: counted in the line of the package that owns it, and listed
     * only by --all. Never what is named on a line of its own. */
    if (!o->all && !unknown && !named && ri != (size_t)-1) {
        struct pk *owner = owner_pk(x, ri);
        if (owner != NULL) {
            free(b.p);
            owner->count++;
            return 0;
        }
    }
    if (gp >= 0) {      /* a repository's bookkeeping: one line, but what git says stays (decision 105) */
        const char *rest = path + gp + 4;
        const size_t rl = plen - (size_t)gp - 4;
        const bool hooks = (rl >= 6 && memcmp(rest, "/hooks", 6) == 0 && (rl == 6 || rest[6] == '/'));
        const struct jval *f = jget(r, "findings");
        if (o->all || unknown || named || hooks || !(x->git_events || !any_git(f) || only_in_place(f)))
            return keep(&x->gitvis, b.p, false, o->all);
        free(b.p);
        struct tally *t = tally(&x->git, path, (size_t)gp);
        if (t == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
        t->n++;
        for (size_t i = 0; f != NULL && f->t == J_ARR && i < f->n; i++) {
            const struct jval *a = jget(&f->kids[i], "from"), *z = jget(&f->kids[i], "to");
            if (strcmp(jstr(&f->kids[i], "kind"), "git_reflog_move") == 0 && a != NULL && z != NULL &&
                a->t == J_STR && z->t == J_STR && strcmp(a->s, z->s) == 0 &&
                count_op(t, jstr(&f->kids[i], "operation")) == -1) {
                belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory");
                return -1;
            }
        }
        return 0;
    }
    if (ign_edit) return keep(&x->ignedit, b.p, false, o->all);
    if (x->cls != NULL && c == GC_IGNORED) {      /* what git ignores: by top-level directory */
        /* the key: "build/" for build and everything below it, "" at the top */
        const char *sl = memchr(path, '/', plen);
        const size_t kl = sl != NULL ? (size_t)(sl - path) : is_dir ? plen : 0;
        /* an unknown row folds under its directory, counted by reason; a
         * file at the top is under none, and stays named */
        if (o->all || (unknown && kl == 0) || named) return keep(&x->ignored, b.p, false, o->all);
        free(b.p);
        char *key = malloc(kl + 2);
        if (key == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
        memcpy(key, path, kl);
        if (kl) key[kl] = '/';
        struct tally *t = tally(unknown ? &x->ignu : &x->ign, key, kl ? kl + 1 : 0);
        free(key);
        if (t == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
        t->n++;
        if (unknown) {                  /* its first reason: the counts add up to the rows */
            const struct jval *u = jget(r, "unknown");
            if (count_op(t, u != NULL && u->t == J_ARR && u->n > 0 && u->kids[0].t == J_STR ? u->kids[0].s : "unknown") == -1) {
                belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory");
                return -1;
            }
        }
        return 0;
    }
    if (x->cls != NULL && c == GC_TRACKED) return keep(&x->tracked, b.p, false, o->all);
    return keep(&x->other, b.p, !unknown && !named, o->all);
}

static void changes_in(struct sb *b, size_t n, const char *whose) {
    if (n) sbf(b, "; %zu change%s in %s files", n, n == 1 ? "" : "s", whose);
}

static int most_cmp(const void *a, const void *b) {
    const struct pk *x = *(struct pk *const *)a, *y = *(struct pk *const *)b;
    if (x->count != y->count) return x->count > y->count ? -1 : 1;
    return strcmp(x->package, y->package);
}

#define INSTALLED_NAMES 10      /* packages the installed line names, then "and N more" */

/* SD-3's installed line: the packages apt does not mark automatic (or of
 * which it says nothing) by name, the rest counted, and the three with the
 * most records. */
static int installed_line(struct ctx *x, struct lines *ev, const struct receipt_opts *o) {
    struct sb b = { 0 };
    size_t named = 0, more = 0, autos = 0, total = 0, nm = 0;
    bool prov = false;
    struct pk **most = malloc((x->npk + 1) * sizeof *most);
    if (most == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
    sbf(&b, "  dpkg  installed");
    for (size_t i = 0; i < x->npk; i++) {
        const struct pk *p = &x->pk[i];
        if (p->kind != PK_INSTALLED) continue;
        prov |= p->prov;
        total += p->count;
        if (p->count) most[nm++] = &x->pk[i];
        if (p->aut == 1) { autos++; continue; }
        if (named == INSTALLED_NAMES) { more++; continue; }
        sbf(&b, "%s", named++ ? ", " : " ");
        esc(&b, p->package, strlen(p->package));
        sbf(&b, ":");
        esc(&b, p->arch, strlen(p->arch));
        sbf(&b, " ");
        esc(&b, p->version, strlen(p->version));
        if (p->aut == 0) sbf(&b, " (not marked automatic by apt)");
    }
    if (more) sbf(&b, " and %zu more not marked automatic", more);
    if (named == 0) sbf(&b, " %zu packages, marked automatic", autos);
    else if (autos) sbf(&b, "; %zu marked automatic", autos);
    changes_in(&b, total, "their");
    if (nm > 0) {
        qsort(most, nm, sizeof *most, most_cmp);
        for (size_t i = 0; i < nm && i < 3; i++) {
            sbf(&b, "%s", i ? ", " : " (most: ");
            esc(&b, most[i]->package, strlen(most[i]->package));
            sbf(&b, " %zu", most[i]->count);
        }
        sbf(&b, ")");
    }
    free(most);
    if (prov) sbf(&b, " (provisional: a path it came from is unknown)");
    if (b.bad) { free(b.p); belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory"); return -1; }
    return keep(ev, b.p, true, o->all);
}

static int event(const struct jval *e, struct ctx *x, struct lines *ev, const struct receipt_opts *o) {
    const char *k = jstr(e, "event");
    /* The package this event is of, as pass 1 listed it. */
    struct pk *pk = NULL;
    if (x->collected && strcmp(jstr(e, "interp"), "dpkg") == 0 && pk_kind(k) >= 0 && x->pki < x->npk)
        pk = &x->pk[x->pki++];
    if (pk != NULL && !o->all && pk->kind == PK_INSTALLED && x->n_installed > 1) {
        if (x->installed_said) return 0;
        x->installed_said = true;
        return installed_line(x, ev, o);
    }
    struct sb b = { 0 };
    struct sb in = { 0 };
    escs(&in, jget(e, "interp"));
    sbf(&b, "  %-5s ", in.p != NULL ? in.p : "");
    free(in.p);
    escs(&b, jget(e, "text"));
    /* What a field says, in the pins' words (system-interpreters.md):
     * apt's mark (SD-2), a uid below UID_MIN (SA-2), a schedule in words
     * (SI-6), an owner that is no package (SI-5). */
    const struct jval *au = jget(e, "auto");
    if (strncmp(k, "dpkg_", 5) == 0 && au != NULL && au->t == J_BOOL)
        sbf(&b, au->b ? " (marked automatic)" : " (not marked automatic by apt)");
    if (strcmp(k, "user_added") == 0) {
        const struct jval *um = jget(e, "uid_min"), *uid = jget(e, "uid");
        if (um != NULL && um->t == J_NUM && uid != NULL && uid->t == J_NUM && jint(e, "uid", 0) < jint(e, "uid_min", 0))
            sbf(&b, " (below UID_MIN %lld)", (long long)jint(e, "uid_min", 0));
    }
    if (strncmp(k, "cron_job_", 9) == 0 || strncmp(k, "timer_file_", 11) == 0) {
        const struct jval *w = jget(e, "in_words");
        if (w != NULL && w->t == J_STR) { sbf(&b, " -- "); escs(&b, w); }
    }
    const struct jval *ow = jget(e, "owner");
    const bool no_package = ow != NULL && ow->t == J_NULL;
    if (no_package) sbf(&b, " (in no package)");
    if (pk != NULL && !o->all) changes_in(&b, pk->count, "its");
    const struct jval *pv = jget(e, "provisional");
    if (pv != NULL && pv->t == J_BOOL && pv->b) sbf(&b, " (provisional: a path it came from is unknown)");
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
    /* An init script in no package has a line of its own, past the cut too
     * (system-interpreters.md, the `init script` row). */
    return keep(ev, b.p, !(no_package && strncmp(k, "init_script_", 12) == 0), o->all);
}

/* Pass 1 (when the diff can be read twice): each record's path outside a
 * .git, in order, for git to classify; and whether git's events are there
 * (they follow the records, E1). Lines that are not diff.v1 are left for
 * pass 2 to refuse. */
struct coll { char **p; size_t *len; bool *dir; size_t n, cap; bool git_events; struct pk *pk; size_t npk, pkcap; };

static int collect(FILE *diff, struct coll *c) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    static char path[4096];
    int rc = 0;
    while (rc == 0 && (got = getline(&line, &cap, diff)) > 0) {
        struct jval v;
        if (jsonr_parse(line, (size_t)got, &v) == -1) { belay_err_clear(); continue; }
        if (v.t == J_OBJ && jget(&v, "belay_diff") == NULL && jget(&v, "belay_diff_end") == NULL) {
            size_t len;
            if (jget(&v, "event") != NULL) {
                c->git_events |= strcmp(jstr(&v, "interp"), "git") == 0;
                const int kind = strcmp(jstr(&v, "interp"), "dpkg") == 0 ? pk_kind(jstr(&v, "event")) : -1;
                if (kind >= 0) {                /* a package records may fold into (SD-3) */
                    if (c->npk == c->pkcap) {
                        const size_t k = c->pkcap ? c->pkcap * 2 : 32;
                        struct pk *q = realloc(c->pk, k * sizeof *q);
                        if (q == NULL) rc = -1;
                        else { c->pk = q; c->pkcap = k; }
                    }
                    if (rc == 0) {
                        const struct jval *au = jget(&v, "auto"), *pv = jget(&v, "provisional");
                        struct pk *p = &c->pk[c->npk];
                        *p = (struct pk){ strdup(jstr(&v, "package")), strdup(jstr(&v, "arch")),
                                          strdup(jstr(&v, "version")), kind,
                                          au != NULL && au->t == J_BOOL ? (au->b ? 1 : 0) : -1,
                                          pv != NULL && pv->t == J_BOOL && pv->b, 0 };
                        c->npk++;
                        if (p->package == NULL || p->arch == NULL || p->version == NULL) rc = -1;
                    }
                }
            } else if (rpath(&v, path, sizeof path, &len) == 0 && gitpos(path, len, jstr(&v, "type")) < 0) {
                if (c->n == c->cap) {
                    const size_t k = c->cap ? c->cap * 2 : 256;
                    char **a = realloc(c->p, k * sizeof *a);
                    size_t *b = a != NULL ? realloc(c->len, k * sizeof *b) : NULL;
                    bool *d = b != NULL ? realloc(c->dir, k * sizeof *d) : NULL;
                    if (a != NULL) c->p = a;
                    if (b != NULL) c->len = b;
                    if (d != NULL) c->dir = d;
                    if (d == NULL) rc = -1;
                    else c->cap = k;
                }
                if (rc == 0 && (c->p[c->n] = malloc(len + 1)) == NULL) rc = -1;
                if (rc == 0) {
                    memcpy(c->p[c->n], path, len);
                    c->p[c->n][len] = '\0';
                    c->len[c->n] = len;
                    c->dir[c->n] = strcmp(jstr(&v, "type"), "dir") == 0 || strcmp(jstr(&v, "type_before"), "dir") == 0;
                    c->n++;
                }
            } else {
                belay_err_clear();
            }
        }
        jsonr_free(&v);
    }
    free(line);
    if (rc == -1) belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory");
    return rc;
}

/* SD-3: asks whose each record's path is -- the first receipt_owner_asks of
 * them, by the after manifest, and by the before one too when the diff
 * removed, upgraded or downgraded a package -- and lists the names a package of the diff may be
 * owner under. Without an answer nothing folds. 0, or -1 (memory). */
static int fold_owners(struct ctx *x, const struct coll *col, const struct receipt_opts *o) {
    if (o->owner == NULL || o->all || col->npk == 0 || col->n == 0) return 0;
    const size_t n = col->n < receipt_owner_asks ? col->n : receipt_owner_asks;
    bool removed = false;               /* a package whose files the before manifest lists */
    for (size_t i = 0; i < col->npk; i++) removed |= col->pk[i].kind != PK_INSTALLED;
    for (int side = 1; side >= 0; side--) {
        if (side == 0 && !removed) continue;
        if ((x->own[side] = calloc(n ? n : 1, sizeof *x->own[side])) == NULL) goto nomem;
        if (o->owner(o->owner_ctx, side, (const char *const *)col->p, col->len, n, x->own[side]) == -1) {
            belay_err_clear();              /* it cannot say: every record is listed */
            for (size_t i = 0; i < n; i++) free(x->own[side][i]);
            free(x->own[side]);
            x->own[side] = NULL;
            if (side == 1) return 0;
        }
    }
    x->nown = n;
    if ((x->keys = calloc(2 * col->npk, sizeof *x->keys)) == NULL) goto nomem;
    for (size_t i = 0; i < col->npk; i++) {
        const struct pk *p = &col->pk[i];
        const size_t pl = strlen(p->package), al = strlen(p->arch);
        char *plain = strdup(p->package), *arch = malloc(pl + al + 2);
        if (plain == NULL || arch == NULL) { free(plain); free(arch); goto nomem; }
        memcpy(arch, p->package, pl);
        arch[pl] = ':';
        memcpy(arch + pl + 1, p->arch, al + 1);
        x->keys[x->nkeys++] = (struct pkkey){ plain, i };
        x->keys[x->nkeys++] = (struct pkkey){ arch, i };
    }
    qsort(x->keys, x->nkeys, sizeof *x->keys, pkkey_cmp);
    return 0;
nomem:
    belay_err_set(BELAY_ERR_NOMEM, 0, "receipt: out of memory");
    return -1;
}

int receipt_render(FILE *diff, FILE *out, const struct receipt_opts *o) {
    struct lines ev = { 0 };
    struct ctx x = { 0 };
    struct coll col = { 0 };
    unsigned char *cls = NULL;
    char *line = NULL;
    struct sb scope = { 0 };
    size_t cap = 0, lineno = 0;
    ssize_t got;
    struct jval trailer = { 0 };
    bool have_trailer = false;
    int rc = -1;
    const long start = ftell(diff);
    if (start >= 0 && fseek(diff, start, SEEK_SET) == 0) {      /* it can be read twice */
        if (collect(diff, &col) == -1) goto out;
        if (fseek(diff, start, SEEK_SET) != 0) {
            belay_err_set(BELAY_ERR_IO, errno, "receipt: cannot read the diff again");
            goto out;
        }
        x.git_events = col.git_events;
        x.collected = true;
        x.pk = col.pk;
        x.npk = col.npk;
        for (size_t i = 0; i < col.npk; i++) x.n_installed += col.pk[i].kind == PK_INSTALLED;
        if (fold_owners(&x, &col, o) == -1) goto out;
        if (o->classify != NULL && col.n > 0 && (cls = malloc(col.n)) != NULL &&
            o->classify(o->class_ctx, (const char *const *)col.p, col.len, col.dir, col.n, cls) == 0)
            x.cls = cls;
    }
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
            r = event(&v, &x, &ev, o);
        } else {
            r = record(&v, &x, o);
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
    if (x.cls != NULL && o->class_note != NULL) fprintf(out, "  %s\n", o->class_note);
    /* No banner (decision 14.7); one actionable line counting what changed
     * while it was read -- vanished, unstable or raced -- per side, since
     * only the after side is settled by running belay again: an earlier
     * checkpoint's flags stay (decision 2026-11-01, 7; review 2026-11-01,
     * D2, D3: the counts are summed saturating, a hostile trailer's
     * included). */
    uint64_t moving[2] = { 0, 0 };
    static const char *const MOVING[2][3] = { { "before_vanished", "before_unstable", "before_raced" },
                                              { "after_vanished", "after_unstable", "after_raced" } };
    for (int sd = 0; sd < 2; sd++)
        for (int i = 0; i < 3; i++) {
            const int64_t k = jint(&trailer, MOVING[sd][i], 0);
            if (k > 0) moving[sd] = (uint64_t)k > UINT64_MAX - moving[sd] ? UINT64_MAX : moving[sd] + (uint64_t)k;
        }
    if (moving[0] || moving[1]) {
        fputs(" ", out);
        for (int sd = 1; sd >= 0; sd--) {
            if (!moving[sd]) continue;
            const bool one = moving[sd] == 1;
            fprintf(out, "%s %llu %s changed while %s read (%s); %s", sd == 0 && moving[1] ? ";" : "",
                    (unsigned long long)moving[sd], one ? "entry" : "entries", one ? "it was" : "they were",
                    sd ? (o->to ? o->to : "after") : (o->from ? o->from : "before"),
                    sd ? (one ? "running belay again settles it" : "running belay again settles them")
                       : (one ? "a diff from a later checkpoint avoids it" : "a diff from a later checkpoint avoids them"));
        }
        fputc('\n', out);
    }
    /* One line for what the writer probe could not ask (manifest v4). */
    const int64_t ug[2] = { jint(&trailer, "before_unguarded", 0), jint(&trailer, "after_unguarded", 0) };
    if (ug[0] > 0 || ug[1] > 0)
        fprintf(out, "  hashed with no check for a concurrent writer: %lld before, %lld after\n",
                (long long)(ug[0] > 0 ? ug[0] : 0), (long long)(ug[1] > 0 ? ug[1] : 0));
    /* One line for where the after side was not looked at (G3-2). */
    const int64_t sealing = jint(&trailer, "after_sealing", 0);
    if (sealing > 0)
        fprintf(out, "  nothing seen below %lld director%s\n", (long long)sealing, sealing == 1 ? "y" : "ies");
    /* One line when dpkg's lists were asked about only some of the changes (SD-3). */
    if (x.keys != NULL && x.nown < col.n)
        fprintf(out, "  dpkg's file lists were asked about the first %zu changes only; the others are listed whatever owns them\n",
                x.nown);
    const struct { const char *title; struct lines *l; } SEC[] = { { "events", &ev }, { "privilege", &x.priv } };
    for (size_t s = 0; s < 2; s++) {
        if (SEC[s].l->n == 0) continue;
        fprintf(out, "\n%s\n", SEC[s].title);
        for (size_t i = 0; i < SEC[s].l->n; i++) fprintf(out, "%s\n", SEC[s].l->v[i]);
        if (SEC[s].l->more) fprintf(out, "  and %zu more (--all shows them)\n", SEC[s].l->more);
    }
    /* Changes: tracked, untracked (the only ones cut), ignored edits by
     * name, the rest ignored, then .git (2026-11-04). */
    if (x.tracked.n || x.other.n || x.other.more || x.ignedit.n || x.ignored.n || x.ign.n || x.ignu.n || x.gitvis.n || x.git.n) {
        fputs("\nchanges\n", out);
        for (size_t i = 0; i < x.tracked.n; i++) fprintf(out, "%s\n", x.tracked.v[i]);
        for (size_t i = 0; i < x.other.n; i++) fprintf(out, "%s\n", x.other.v[i]);
        if (x.other.more) fprintf(out, "  and %zu more (--all shows them)\n", x.other.more);
        for (size_t i = 0; i < x.ignedit.n; i++) fprintf(out, "%s\n", x.ignedit.v[i]);
        for (size_t i = 0; i < x.ignored.n; i++) fprintf(out, "%s\n", x.ignored.v[i]);
        for (int top = 0; top < 2; top++)          /* directories, then files at the top */
            for (size_t i = 0; i < x.ign.n; i++) {
                const struct tally *t = &x.ign.v[i];
                if ((t->key[0] == '\0') != top) continue;
                fprintf(out, "  git-ignored: %zu change%s ", t->n, t->n == 1 ? "" : "s");
                if (top) fputs("in the top directory\n", out);
                else { fputs("under ", out); receipt_fputs(out, t->key); fputc('\n', out); }
            }
        for (size_t i = 0; i < x.ignu.n; i++) {
            struct tally *t = &x.ignu.v[i];
            qsort(t->ops, t->nops, sizeof *t->ops, by_count);
            fprintf(out, "  git-ignored: %zu unknown under ", t->n);
            receipt_fputs(out, t->key);
            for (size_t k = 0; k < t->nops; k++) {
                fputs(k ? ", " : " (", out);
                receipt_fputs(out, t->ops[k].name);
                fprintf(out, " %zu", t->ops[k].n);
            }
            fputs(")\n", out);
        }
        for (size_t i = 0; i < x.gitvis.n; i++) fprintf(out, "%s\n", x.gitvis.v[i]);
        for (size_t i = 0; i < x.git.n; i++) {
            const struct tally *t = &x.git.v[i];
            fprintf(out, "  git bookkeeping: %zu change%s under ", t->n, t->n == 1 ? "" : "s");
            receipt_fputs(out, t->key);
            fputs(".git/", out);
            for (size_t k = 0; k < t->nops; k++) {      /* a ref left in place may have lost work: said */
                const char *op = t->ops[k].name;
                fprintf(out, "%s%zu ", k ? ", " : " (", t->ops[k].n);
                receipt_fputs(out, op[0] ? op : "move");
                fprintf(out, "%s in place", t->ops[k].n != 1 && strchr(op, ' ') == NULL && op[0] ? "s" : "");
            }
            fputs(t->nops ? ")\n" : "\n", out);
        }
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
    drop(&x.priv);
    drop(&x.tracked);
    drop(&x.other);
    drop(&x.ignedit);
    drop(&x.ignored);
    drop(&x.gitvis);
    tallies_free(&x.ign);
    tallies_free(&x.ignu);
    tallies_free(&x.git);
    for (int side = 0; side < 2; side++) {
        for (size_t i = 0; x.own[side] != NULL && i < x.nown; i++) free(x.own[side][i]);
        free(x.own[side]);
    }
    for (size_t i = 0; i < x.nkeys; i++) free(x.keys[i].key);
    free(x.keys);
    for (size_t i = 0; i < col.npk; i++) { free(col.pk[i].package); free(col.pk[i].arch); free(col.pk[i].version); }
    free(col.pk);
    for (size_t i = 0; i < col.n; i++) free(col.p[i]);
    free(col.p);
    free(col.len);
    free(col.dir);
    free(cls);
    return rc;
}

char *receipt_escaped(const char *s, size_t len) {
    struct sb b = { 0 };
    sbf(&b, "%s", "");
    esc(&b, s, len);
    if (b.bad) { free(b.p); return NULL; }
    return b.p;
}

int receipt_record_path(const struct jval *r, char *buf, size_t cap, size_t *len) { return rpath(r, buf, cap, len); }

char *receipt_privilege_words(const struct jval *r, const char *path, size_t len, receipt_mode_fn mode, void *ctx) {
    const struct receipt_opts o = { .mode = mode, .mode_ctx = ctx };
    struct sb b = { 0 };
    privilege(&b, r, path, len, &o);
    if (b.bad || b.n == 0) { free(b.p); return NULL; }
    return b.p;
}

void receipt_fputs(FILE *f, const char *s) {
    struct sb b = { 0 };
    esc(&b, s, strlen(s));
    if (b.p != NULL && !b.bad) fputs(b.p, f);
    else if (b.bad) fputs("?", f);
    free(b.p);
}
