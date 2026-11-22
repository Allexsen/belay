/*
 *  The accounts interpreter (test/expect/system-interpreters.md, SA-1 to
 *  SA-6; finding-kinds.md, user_*, group_*, password_entry_*): what the
 *  text of `etc/passwd` and `etc/group` says was added, removed or changed,
 *  by name. It states lines, never an effect: not who may log in, not what
 *  a "system account" is (SA-2 gives UID_MIN and leaves the word alone).
 *
 *  A file is seven fields a line (`group`: four), split at `:`. One that
 *  is not -- another count (a blank line, a comment), a line beginning `+`
 *  or `-`, no name, a uid or gid that is not a decimal number of 32 bits --
 *  or that cannot be read on a side is could_not_interpret, on its record
 *  and as an event (SI-2, E10), and gives no other event. Two lines with
 *  one name: the first is the user, the events are given, and the file is
 *  could_not_interpret too (SA-1).
 *
 *  Lookups (SI-4), asked only when an event needs them: the `etc/login.defs`
 *  beside the passwd for uid_min; the presence of an `etc/shadow` beside it
 *  for an empty second field.
 *
 *  SA-6: `shadow` and `gshadow` are sealed, and no interpreter is given
 *  their bytes. What reaches this one is each capture's per-line digest
 *  file (belay_manifest_opts.shadow_lines_path): a first field and a keyed
 *  digest per line. Where both captures kept one under the same sealing
 *  key, an entry whose digest appeared, went or differs is named, for the
 *  files both digested. A digest file that is not what belay writes is
 *  could_not_interpret for the two files, never "no entries".
 */
#define _GNU_SOURCE                     /* getline */
#include "builtins.h"
#include "stored.h"
#include "sysev.h"

#include "belay/error.h"
#include "belay/json.h"
#include "belay/manifest.h"
#include "util/jsonr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define ROOTS_MAX 4096u         /* trees with a passwd whose lookups are made; past it: not asked */
#define AUX_EMPTY 0x80000000u   /* user_password_in_passwd for an empty field: dropped where a shadow is */
#define AUX_NONE  0x7fffffffu

struct root {
    struct accounts *st;
    const char *prefix;         /* the passwd's path without `etc/passwd` */
    size_t len;
    bool need_defs, need_shadow;
    bool has_uid_min, shadow;
    uint32_t uid_min;
};

struct accounts {
    struct sysevs *evs;
    struct root *roots;
    size_t nroots, cap;
    struct belay_lookup *lk;
    bool asked;
};

static void *begin(void) {
    struct accounts *st = calloc(1, sizeof *st);
    if (st != NULL && (st->evs = sysevs_new()) == NULL) { free(st); st = NULL; }
    return st;
}

/* ---- one side's lines ---- */

struct rec {
    const char *f[7];
    size_t n[7];
    uint32_t line, uid, gid;
};

static int name_cmp(const struct rec *x, const struct rec *y) {
    const int c = x->n[0] && y->n[0] ? memcmp(x->f[0], y->f[0], x->n[0] < y->n[0] ? x->n[0] : y->n[0]) : 0;
    return c ? c : (x->n[0] > y->n[0]) - (x->n[0] < y->n[0]);
}
static int rec_cmp(const void *a, const void *b) {
    const struct rec *x = a, *y = b;
    const int c = name_cmp(x, y);
    return c ? c : (x->line > y->line) - (x->line < y->line);
}

enum { P_OK, P_BAD, P_NOMEM };

/* The records of a side, by name, each name once (its first line); *dups
 * when a name had more. `nf` fields a line; the numbers at `iu` and `ig`
 * (iu -1: none). */
static int parse(const char *buf, size_t len, int nf, int iu, int ig, struct rec **out, size_t *n, bool *dups) {
    bool oom;
    size_t nl;
    *out = NULL;
    *n = 0;
    struct sysline *ls = sys_lines(buf, len, &nl, &oom);
    if (oom) return P_NOMEM;
    if (nl == 0) return P_OK;
    struct rec *r = calloc(nl, sizeof *r);
    if (r == NULL) { free(ls); return P_NOMEM; }
    int rc = P_OK;
    for (size_t i = 0; i < nl && rc == P_OK; i++) {
        const char *p = ls[i].s, *end = p + ls[i].n;
        int k = 0;
        if (p == end || *p == '+' || *p == '-') { rc = P_BAD; break; }
        for (;;) {
            const char *c = memchr(p, ':', (size_t)(end - p));
            if (k == nf) { rc = P_BAD; break; }            /* a field too many */
            r[i].f[k] = p;
            r[i].n[k] = (size_t)((c ? c : end) - p);
            k++;
            if (c == NULL) break;
            p = c + 1;
        }
        if (rc == P_OK && (k != nf || r[i].n[0] == 0)) rc = P_BAD;
        if (rc == P_OK && iu >= 0 && !sys_u32(r[i].f[iu], r[i].n[iu], &r[i].uid)) rc = P_BAD;
        if (rc == P_OK && !sys_u32(r[i].f[ig], r[i].n[ig], &r[i].gid)) rc = P_BAD;
        r[i].line = ls[i].line;
    }
    free(ls);
    if (rc != P_OK) { free(r); return rc; }
    qsort(r, nl, sizeof *r, rec_cmp);
    size_t w = 0;
    for (size_t i = 0; i < nl; i++) {
        if (w > 0 && name_cmp(&r[w - 1], &r[i]) == 0) { *dups = true; continue; }
        r[w++] = r[i];
    }
    *out = r;
    *n = w;
    return P_OK;
}

#define FS(r, k) { .s = (r)->f[k], .len = (r)->n[k] }

/* ---- passwd ---- */

static struct root *root_of(struct accounts *st, const char *path, size_t len) {
    const size_t pl = len - 10;                 /* without "etc/passwd" */
    for (size_t i = 0; i < st->nroots; i++)
        if (st->roots[i].len == pl && memcmp(st->roots[i].prefix, path, pl) == 0) return &st->roots[i];
    if (st->nroots >= ROOTS_MAX) return NULL;
    if (st->nroots == st->cap) {
        const size_t c = st->cap ? 2 * st->cap : 4;
        struct root *q = realloc(st->roots, c * sizeof *q);
        if (q == NULL) return NULL;
        st->roots = q;
        st->cap = c;
    }
    const char *p = sysevs_dup(st->evs, path, pl);
    if (p == NULL) return NULL;
    struct root *r = &st->roots[st->nroots++];
    memset(r, 0, sizeof *r);
    r->prefix = p;
    r->len = pl;
    return r;
}

static bool is(const struct rec *r, int k, const char *s) {
    return r->n[k] == strlen(s) && memcmp(r->f[k], s, r->n[k]) == 0;
}

/* The second field after says a password is in passwd itself (or, empty,
 * may: the lookup decides), and it is news: the name is new or the field
 * differs from before's. Its value goes nowhere. */
static void password(struct accounts *st, const struct belay_interp_input *in, const struct rec *b,
                     const struct rec *a, bool prov) {
    if (is(a, 1, "x") || is(a, 1, "*") || is(a, 1, "!")) return;
    if (b != NULL && b->n[1] == a->n[1] && (a->n[1] == 0 || memcmp(b->f[1], a->f[1], a->n[1]) == 0)) return;
    const struct belay_fv v[] = { FS(a, 0) };
    struct sysev *e = sysevs_add(st->evs, FK_USER_PASSWORD_IN_PASSWD, in->path, in->path_len, a->line, SYS_ADDED, prov, v, 1);
    if (e == NULL || a->n[1] != 0) return;
    struct root *r = root_of(st, in->path, in->path_len);
    e->aux = AUX_EMPTY | (r != NULL ? (uint32_t)(r - st->roots) : AUX_NONE);
    if (r != NULL) r->need_shadow = true;
}

static void passwd_pair(struct accounts *st, const struct belay_interp_input *in, const struct rec *b,
                        const struct rec *a, bool prov) {
    static const char *const FIELD[] = { "uid", "gid", "gecos", "home", "shell" };
    if (a == NULL) {
        const struct belay_fv v[] = { FS(b, 0), { .i = b->uid } };
        sysevs_add(st->evs, FK_USER_REMOVED, in->path, in->path_len, b->line, SYS_REMOVED, prov, v, 2);
        return;
    }
    if (b == NULL) {
        const struct belay_fv v[] = { FS(a, 0), { .i = a->uid }, { .i = a->gid }, FS(a, 5), FS(a, 6), { .null = true } };
        struct sysev *e = sysevs_add(st->evs, FK_USER_ADDED, in->path, in->path_len, a->line, SYS_ADDED, prov, v, 6);
        struct root *r = e != NULL ? root_of(st, in->path, in->path_len) : NULL;
        if (e != NULL) e->aux = r != NULL ? (uint32_t)(r - st->roots) : AUX_NONE;
        if (r != NULL) r->need_defs = true;
    } else {
        for (int k = 2; k < 7; k++) {
            if (b->n[k] == a->n[k] && (a->n[k] == 0 || memcmp(b->f[k], a->f[k], a->n[k]) == 0)) continue;
            const char *name = FIELD[k - 2];
            const struct belay_fv v[] = { FS(a, 0), { .s = name, .len = strlen(name) }, FS(b, k), FS(a, k) };
            sysevs_add(st->evs, FK_USER_CHANGED, in->path, in->path_len, a->line, SYS_ADDED, prov, v, 4);
        }
    }
    password(st, in, b, a, prov);
}

/* ---- group ---- */

struct mem { const char *s; size_t n; };
static int mem_cmp(const void *a, const void *b) {
    const struct mem *x = a, *y = b;
    const int c = memcmp(x->s, y->s, x->n < y->n ? x->n : y->n);
    return c ? c : (x->n > y->n) - (x->n < y->n);
}

/* The fourth field as a set: its names, sorted, each once; an empty name
 * (`a,,b`, a trailing comma) is none. NULL with *n 0 for none; *oom. */
static struct mem *members(const struct rec *r, size_t *n, bool *oom) {
    const char *p = r->f[3], *end = p + r->n[3];
    size_t count = 0;
    *n = 0;
    for (const char *q = p; q < end; ) {
        const char *c = memchr(q, ',', (size_t)(end - q));
        const char *e = c ? c : end;
        count += e > q;
        q = c ? c + 1 : end;
    }
    if (count == 0) return NULL;
    struct mem *m = malloc(count * sizeof *m);
    if (m == NULL) { *oom = true; return NULL; }
    size_t k = 0;
    for (const char *q = p; q < end; ) {
        const char *c = memchr(q, ',', (size_t)(end - q));
        const char *e = c ? c : end;
        if (e > q) m[k++] = (struct mem){ q, (size_t)(e - q) };
        q = c ? c + 1 : end;
    }
    qsort(m, k, sizeof *m, mem_cmp);
    size_t w = 0;
    for (size_t i = 0; i < k; i++)
        if (w == 0 || mem_cmp(&m[w - 1], &m[i]) != 0) m[w++] = m[i];
    *n = w;
    return m;
}

static bool group_pair(struct accounts *st, const struct belay_interp_input *in, const struct rec *b,
                       const struct rec *a, bool prov) {
    const bool same = b != NULL && a != NULL && b->gid == a->gid && b->n[1] == a->n[1] && b->n[2] == a->n[2] &&
                      (a->n[1] == 0 || memcmp(b->f[1], a->f[1], a->n[1]) == 0) &&
                      memcmp(b->f[2], a->f[2], a->n[2]) == 0;
    if (b != NULL && !same) {                   /* gone, or (SI-3) its line removed and another added */
        const struct belay_fv v[] = { FS(b, 0), { .i = b->gid } };
        sysevs_add(st->evs, FK_GROUP_REMOVED, in->path, in->path_len, b->line, SYS_REMOVED, prov, v, 2);
    }
    if (a != NULL && !same) {
        const struct belay_fv v[] = { FS(a, 0), { .i = a->gid } };
        sysevs_add(st->evs, FK_GROUP_ADDED, in->path, in->path_len, a->line, SYS_ADDED, prov, v, 2);
    }
    if (b == NULL || a == NULL) return true;
    bool oom = false;
    size_t nb, na, nadd = 0, nrem = 0;
    struct mem *mb = members(b, &nb, &oom), *ma = members(a, &na, &oom);
    struct belay_fv *add = malloc((na + 1) * sizeof *add), *rem = malloc((nb + 1) * sizeof *rem);
    if (oom || add == NULL || rem == NULL) { free(mb); free(ma); free(add); free(rem); return false; }
    for (size_t i = 0, j = 0; i < nb || j < na; ) {
        const int c = i == nb ? 1 : j == na ? -1 : mem_cmp(&mb[i], &ma[j]);
        if (c < 0) { rem[nrem++] = (struct belay_fv){ .s = mb[i].s, .len = mb[i].n }; i++; }
        else if (c > 0) { add[nadd++] = (struct belay_fv){ .s = ma[j].s, .len = ma[j].n }; j++; }
        else { i++; j++; }
    }
    if (nadd || nrem) {
        const struct belay_fv v[] = { FS(a, 0), { .list = add, .nlist = nadd }, { .list = rem, .nlist = nrem } };
        sysevs_add(st->evs, FK_GROUP_MEMBERS_CHANGED, in->path, in->path_len, a->line, SYS_ADDED, prov, v, 3);
    }
    free(mb);
    free(ma);
    free(add);
    free(rem);
    return true;
}

/* ---- explaining a path ---- */

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct accounts *st = state;
    (void)out;
    if (st == NULL) return BELAY_INTERP_ERROR;
    const bool pw = sys_ends(in->abs_path, in->abs_len, "/etc/passwd") && sys_ends(in->path, in->path_len, "etc/passwd");
    const bool gr = sys_ends(in->abs_path, in->abs_len, "/etc/group") && sys_ends(in->path, in->path_len, "etc/group");
    if (!pw && !gr) return BELAY_INTERP_DECLINE;
    if (strcmp(in->outcome, "metadata_only") == 0) return BELAY_INTERP_DECLINE;    /* the text is the same */
    const bool prov = sys_prov(in);
    struct sysfile f;
    if (!sys_read(in, &f)) return sys_cannot(st->evs, in);
    struct rec *r[2] = { NULL, NULL };
    size_t n[2] = { 0, 0 };
    bool dups = false, failed = false;
    int rc = P_OK;
    for (int k = 0; k < 2 && rc == P_OK; k++)
        if (f.have[k])
            rc = parse((const char *)f.buf[k], f.len[k], pw ? 7 : 4, pw ? 2 : -1, pw ? 3 : 2, &r[k], &n[k], &dups);
    enum belay_interp_result res = BELAY_INTERP_DECLINE;
    if (rc == P_NOMEM) {
        failed = true;
    } else if (rc == P_BAD) {
        res = sys_cannot(st->evs, in);
    } else {
        for (size_t i = 0, j = 0; (i < n[0] || j < n[1]) && !failed; ) {
            const int c = i == n[0] ? 1 : j == n[1] ? -1 : name_cmp(&r[0][i], &r[1][j]);
            const struct rec *b = c <= 0 ? &r[0][i++] : NULL, *a = c >= 0 ? &r[1][j++] : NULL;
            if (pw) passwd_pair(st, in, b, a, prov);
            else if (!group_pair(st, in, b, a, prov)) failed = true;
        }
        if (dups) res = sys_cannot(st->evs, in);
    }
    free(r[0]);
    free(r[1]);
    sys_free(&f);
    return failed || sysevs_failed(st->evs) ? BELAY_INTERP_ERROR : res;
}

/* ---- the lookups ---- */

/* login.defs (system-config.md CF-L): `NAME value`, whitespace separated,
 * `#` comments. UID_MIN is known when exactly one line gives it and its
 * value is one decimal number. */
static int defs_fn(void *ctx, const struct belay_entry *e) {
    struct root *r = ctx;
    unsigned char *buf = NULL;
    size_t len = 0, nl = 0, found = 0;
    bool oom = false, ok = false;
    uint32_t v = 0;
    if (e->type != BELAY_T_REG || e->sealed || e->meta ||
        stored_read_entry(belay_lookup_content(r->st->lk), e, SYS_FILE_MAX, &buf, &len) != SW_OK)
        return 0;
    struct sysline *ls = memchr(buf, '\0', len) == NULL ? sys_lines((const char *)buf, len, &nl, &oom) : NULL;
    for (size_t i = 0; i < nl; i++) {
        const char *s = ls[i].s, *end = s + ls[i].n;
        sys_trim(&s, &end);
        const char *w = s;
        while (w < end && !sys_blank(*w)) w++;
        if (w - s != 7 || memcmp(s, "UID_MIN", 7) != 0) continue;
        while (w < end && sys_blank(*w)) w++;
        found++;
        ok = sys_u32(w, (size_t)(end - w), &v);
    }
    free(ls);
    free(buf);
    if (oom) return -1;
    r->has_uid_min = found == 1 && ok;
    r->uid_min = v;
    return 0;
}

static int shadow_fn(void *ctx, const struct belay_entry *e) {
    (void)e;
    ((struct root *)ctx)->shadow = true;
    return 0;
}

/* ---- SA-6: the lines of shadow and gshadow ---- */

static const char *const PW_FILE[2] = { "etc/gshadow", "etc/shadow" };

struct pent { int file; char *name; size_t nlen; char hmac[65]; uint32_t place; };
struct plines { struct pent *v; size_t n, cap; char key[17]; bool has[2]; };

static void plines_free(struct plines *p) {
    for (size_t i = 0; i < p->n; i++) free(p->v[i].name);
    free(p->v);
    memset(p, 0, sizeof *p);
}

static bool hex_n(const char *s, size_t n) {
    if (strlen(s) != n) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

static int pw_file(const char *s) {
    for (int i = 0; i < 2; i++)
        if (strcmp(s, PW_FILE[i]) == 0) return i;
    return -1;
}

enum { L_OK, L_BAD, L_NOMEM };

/* One line of a digest file, parsed: the header (`first`) or an entry. */
static int pline(struct plines *p, const char *line, size_t len, bool first, uint32_t place[2]) {
    struct jval v;
    if (jsonr_parse(line, len, &v) == -1) { belay_err_clear(); return L_BAD; }
    int rc = L_BAD;
    if (v.t != J_OBJ) goto done;
    if (first) {
        const struct jval *ver = jget(&v, "belay_shadow_lines"), *files = jget(&v, "files");
        const char *key = jstr(&v, "sealed_key");
        if (ver == NULL || ver->t != J_NUM || ver->i != 1 || ver->num != 1.0 || !hex_n(key, 16) ||
            files == NULL || files->t != J_ARR)
            goto done;
        for (size_t i = 0; i < files->n; i++) {
            const int f = files->kids[i].t == J_STR ? pw_file(files->kids[i].s) : -1;
            if (f < 0 || p->has[f]) goto done;
            p->has[f] = true;
        }
        memcpy(p->key, key, 17);
        rc = L_OK;
        goto done;
    }
    const struct jval *file = jget(&v, "file"), *name = jget(&v, "name"), *b64 = jget(&v, "name_b64");
    const char *hmac = jstr(&v, "hmac");
    const int f = file != NULL && file->t == J_STR ? pw_file(file->s) : -1;
    if (f < 0 || !p->has[f] || !hex_n(hmac, 64) || (name == NULL) == (b64 == NULL) ||
        (name != NULL && name->t != J_STR) || (b64 != NULL && b64->t != J_STR))
        goto done;
    if (p->n == p->cap) {
        const size_t c = p->cap ? 2 * p->cap : 64;
        struct pent *q = realloc(p->v, c * sizeof *q);
        if (q == NULL) { rc = L_NOMEM; goto done; }
        p->v = q;
        p->cap = c;
    }
    struct pent *e = &p->v[p->n];
    memset(e, 0, sizeof *e);
    const char *src = name != NULL ? name->s : b64->s;
    const size_t sl = name != NULL ? name->s_len : strlen(src);
    if ((e->name = malloc(sl + 1)) == NULL) { rc = L_NOMEM; goto done; }
    if (name != NULL) {
        memcpy(e->name, src, sl + 1);
        e->nlen = sl;
    } else if (belay_base64_decode(e->name, sl + 1, &e->nlen, src) == -1) {
        belay_err_clear();
        free(e->name);
        goto done;
    }
    e->file = f;
    e->place = ++place[f];
    memcpy(e->hmac, hmac, 65);
    p->n++;
    rc = L_OK;
done:
    jsonr_free(&v);
    return rc;
}

static int plines_load(const char *path, struct plines *p) {
    memset(p, 0, sizeof *p);
    FILE *f = fopen(path, "rb");
    if (f == NULL) return L_BAD;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = L_OK;
    bool first = true;
    uint32_t place[2] = { 0, 0 };
    while (rc == L_OK && (n = getline(&line, &cap, f)) > 0) {
        if (line[n - 1] != '\n' || memchr(line, '\0', (size_t)n) != NULL) { rc = L_BAD; break; }   /* cut short */
        rc = pline(p, line, (size_t)n - 1, first, place);
        first = false;
    }
    if (rc == L_OK && (first || ferror(f))) rc = L_BAD;     /* no header at all */
    free(line);
    fclose(f);
    if (rc != L_OK) plines_free(p);
    return rc;
}

/* By file, then name, then place: equal names pair off in their order. */
static int pent_cmp(const void *a, const void *b) {
    const struct pent *x = a, *y = b;
    if (x->file != y->file) return x->file - y->file;
    const int c = memcmp(x->name, y->name, x->nlen < y->nlen ? x->nlen : y->nlen);
    if (c) return c;
    if (x->nlen != y->nlen) return x->nlen < y->nlen ? -1 : 1;
    return (x->place > y->place) - (x->place < y->place);
}
static int pent_key(const struct pent *x, const struct pent *y) {
    if (x->file != y->file) return x->file - y->file;
    const int c = memcmp(x->name, y->name, x->nlen < y->nlen ? x->nlen : y->nlen);
    return c ? c : (x->nlen > y->nlen) - (x->nlen < y->nlen);
}

static void pw_event(struct accounts *st, int kind, const struct pent *e, int rank) {
    const char *file = PW_FILE[e->file];
    const struct belay_fv v[] = { { .s = file, .len = strlen(file) }, { .s = e->name, .len = e->nlen } };
    sysevs_add(st->evs, kind, file, strlen(file), e->place, rank, false, v, 2);
}

/* 0, or -1 (memory). */
static int password_entries(struct accounts *st, struct belay_lookup *lk) {
    const char *pb = belay_lookup_shadow_lines(lk, 0), *pa = belay_lookup_shadow_lines(lk, 1);
    if (pb == NULL || pa == NULL) return 0;             /* a capture kept none: no names (SA-6) */
    struct plines b, a;
    const int rb = plines_load(pb, &b), ra = rb == L_OK ? plines_load(pa, &a) : L_OK;
    if (rb != L_OK || ra != L_OK) {
        if (rb == L_OK) plines_free(&b);
        if (rb == L_NOMEM || ra == L_NOMEM) return -1;
        for (int f = 0; f < 2; f++) sysevs_not_interpreted(st->evs, PW_FILE[f], strlen(PW_FILE[f]), false);
        return 0;
    }
    if (strcmp(b.key, a.key) == 0) {                    /* another key: the digests do not compare */
        if (b.n > 1) qsort(b.v, b.n, sizeof *b.v, pent_cmp);
        if (a.n > 1) qsort(a.v, a.n, sizeof *a.v, pent_cmp);
        for (size_t i = 0, j = 0; i < b.n || j < a.n; ) {
            const int c = i == b.n ? 1 : j == a.n ? -1 : pent_key(&b.v[i], &a.v[j]);
            const struct pent *x = c <= 0 ? &b.v[i++] : NULL, *y = c >= 0 ? &a.v[j++] : NULL;
            const int f = x != NULL ? x->file : y->file;
            if (!b.has[f] || !a.has[f]) continue;       /* a side did not digest this file */
            if (y == NULL) pw_event(st, FK_PASSWORD_ENTRY_REMOVED, x, SYS_REMOVED);
            else if (x == NULL) pw_event(st, FK_PASSWORD_ENTRY_ADDED, y, SYS_ADDED);
            else if (strcmp(x->hmac, y->hmac) != 0) pw_event(st, FK_PASSWORD_ENTRY_CHANGED, y, SYS_ADDED);
        }
    }
    plines_free(&b);
    plines_free(&a);
    return 0;
}

static enum belay_interp_result prepare(void *state, struct belay_lookup *lk) {
    struct accounts *st = state;
    if (st == NULL) return BELAY_INTERP_ERROR;
    if (st->asked) return BELAY_INTERP_FINDINGS;
    st->asked = true;
    st->lk = lk;
    if (password_entries(st, lk) == -1) return BELAY_INTERP_ERROR;
    char path[4096 + 16];
    for (size_t i = 0; i < st->nroots; i++) {
        struct root *r = &st->roots[i];
        r->st = st;
        if (r->len + 14 > 4096) continue;       /* no such path in a manifest: not there */
        memcpy(path, r->prefix, r->len);
        memcpy(path + r->len, "etc/login.defs", 14);
        if (r->need_defs && belay_lookup_want(lk, path, r->len + 14, false, defs_fn, r) == -1) return BELAY_INTERP_ERROR;
        memcpy(path + r->len, "etc/shadow", 10);
        if (r->need_shadow && belay_lookup_want(lk, path, r->len + 10, false, shadow_fn, r) == -1) return BELAY_INTERP_ERROR;
    }
    return BELAY_INTERP_FINDINGS;
}

static enum belay_interp_result end(void *state, struct belay_events *ev) {
    struct accounts *st = state;
    if (st == NULL) return BELAY_INTERP_ERROR;
    enum belay_interp_result r = BELAY_INTERP_FINDINGS;
    if (ev != NULL) {
        for (size_t i = 0; i < sysevs_count(st->evs); i++) {
            struct sysev *e = sysevs_at(st->evs, i);
            const uint32_t ri = e->aux & AUX_NONE;
            const struct root *root = ri < st->nroots ? &st->roots[ri] : NULL;
            if (e->kind == FK_USER_ADDED && root != NULL && st->asked && root->has_uid_min)
                e->v[5] = (struct belay_fv){ .i = root->uid_min };
            if (e->kind == FK_USER_PASSWORD_IN_PASSWD && (e->aux & AUX_EMPTY) && root != NULL && root->shadow)
                e->drop = true;
        }
        r = sysevs_emit(st->evs, ev, st->lk);
    }
    sysevs_free(st->evs);
    free(st->roots);
    free(st);
    return r;
}

const struct belay_interp INTERP_ACCOUNTS = { BELAY_INTERP_ACCOUNTS, begin, explain, end, prepare };
