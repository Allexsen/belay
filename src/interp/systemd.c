/*
 *  The systemd interpreter (test/expect/system-interpreters.md SY-1 to
 *  SY-4, SW-7; finding-kinds.md, unit_*, init_script_*, timer_file_*):
 *  what is linked into a target, masked, aliased, added, removed or changed
 *  in the directories systemd reads units from, and the scripts of init.d
 *  with rc.local. An event states the text of a file or of a link: never
 *  that a unit is enabled or will start (SY-3) -- units from /run,
 *  generators, presets and conditions are systemd's, and are not read.
 *
 *  A unit directory D is `etc/systemd/system`, `etc/systemd/user`,
 *  `usr/lib/systemd/system`, `usr/lib/systemd/user`, the same under `lib`
 *  where it is a directory, and a home's `.config/systemd/user`. Of what is
 *  claimed below one, by the entry's type and its place:
 *    D/<x>.wants/<unit>, D/<x>.requires/<unit>, a link   unit_linked, unit_unlinked
 *    D/<unit>, in etc or a home: a link to /dev/null,
 *              or an empty file                           unit_masked, unit_unmasked
 *    D/<name>, in etc or a home: another link             unit_alias_added, _removed
 *    D/<unit>, D/<unit>.d/<file>, a regular file          unit_file_added, _removed, _changed
 *    D/<x>.timer, a regular file                          timer_file_added, _removed too
 *  and everything else -- directories, deeper paths, other names -- is
 *  declined. Unit files are named, not parsed (their keys are config's);
 *  only a timer's `OnCalendar=` values are read, as written.
 */
#include "builtins.h"
#include "inwords.h"
#include "stored.h"
#include "sysev.h"

#include "belay/manifest.h"

#include <stdlib.h>
#include <string.h>

enum dkind { D_NONE, D_ETC, D_LIB, D_HOME };

struct systemd;
/* A unit file added in etc: is there a packaged one of its name (SY: unit_overrides_packaged)? */
struct ovr { struct systemd *sd; struct sysev *e; const char *usr, *lib; size_t usr_len, lib_len; bool in_usr, in_lib; };

struct systemd {
    struct sysevs *s;
    struct ovr **o;
    size_t no, cap;
    struct belay_lookup *lk;
    bool asked, failed;
};

static void *begin(void) {
    struct systemd *sd = calloc(1, sizeof *sd);
    if (sd != NULL && (sd->s = sysevs_new()) == NULL) { free(sd); sd = NULL; }
    return sd;
}

/* ---- where a path is ---- */

struct place {
    enum dkind kind;
    const char *d;              /* D, relative to the scope (in->path), d_len bytes; NULL when the scope is inside it */
    size_t d_len;
    size_t prefix_len;          /* of in->path: the tree before `etc/`, `usr/lib/` or `lib/`; SIZE_MAX: not known */
    bool user;                  /* a `user` directory */
    const char *sub, *name;     /* D/sub/name, or D/name with sub NULL */
    size_t sub_len, name_len;
};

/* The first unit directory in the absolute path, and what follows it: one
 * or two components. false: not below one, or deeper. */
static bool place_of(const struct belay_interp_input *in, struct place *p) {
    static const struct { const char *m; enum dkind k; bool user; } M[] = {
        { "/etc/systemd/system/", D_ETC, false }, { "/etc/systemd/user/", D_ETC, true },
        { "/lib/systemd/system/", D_LIB, false }, { "/lib/systemd/user/", D_LIB, true },
        { "/.config/systemd/user/", D_HOME, true },
    };
    const char *abs = in->abs_path;
    const size_t n = in->abs_len;
    size_t best = n, bm = 0;
    int which = -1;
    for (size_t k = 0; k < sizeof M / sizeof M[0]; k++) {
        const size_t ml = strlen(M[k].m);
        for (size_t i = 0; i + ml <= n && i < best; i++)
            if (abs[i] == '/' && memcmp(abs + i, M[k].m, ml) == 0) { best = i; bm = ml; which = (int)k; break; }
    }
    if (which < 0) return false;
    memset(p, 0, sizeof *p);
    p->kind = M[which].k;
    p->user = M[which].user;
    const char *rest = abs + best + bm;
    const size_t rl = n - best - bm;
    const char *slash = memchr(rest, '/', rl);
    if (rl == 0) return false;
    if (slash == NULL) {
        p->name = rest;
        p->name_len = rl;
    } else {
        p->sub = rest;
        p->sub_len = (size_t)(slash - rest);
        p->name = slash + 1;
        p->name_len = rl - p->sub_len - 1;
        if (p->sub_len == 0 || p->name_len == 0 || memchr(p->name, '/', p->name_len) != NULL) return false;
    }
    /* The same places in the path relative to the scope. */
    p->prefix_len = SIZE_MAX;
    if (in->path_len >= rl + 1) {
        const size_t dl = in->path_len - rl - 1;        /* D's length in in->path, when all of D is in it */
        size_t tail = bm - 2;                           /* the marker without its two slashes */
        if (p->kind == D_LIB && best >= 4 && memcmp(abs + best - 4, "/usr", 4) == 0) tail += 4;
        if (dl >= tail && (dl == tail || in->path[dl - tail - 1] == '/')) {
            p->d = in->path;
            p->d_len = dl;
            if (p->kind != D_HOME) p->prefix_len = dl - tail;
        }
    }
    return true;
}

static bool unit_name(const char *s, size_t n) {
    static const char *const SUF[] = { ".service", ".socket", ".device", ".mount", ".automount", ".swap",
                                       ".target", ".path", ".timer", ".slice", ".scope" };
    for (size_t i = 0; i < sizeof SUF / sizeof SUF[0]; i++) {
        const size_t sl = strlen(SUF[i]);
        if (n > sl && memcmp(s + n - sl, SUF[i], sl) == 0) return true;
    }
    return false;
}

static bool is_link(const struct belay_entry *e) { return e != NULL && e->type == BELAY_T_LNK; }
static bool is_reg(const struct belay_entry *e) { return e != NULL && e->type == BELAY_T_REG; }
/* A link whose text is not known cannot be said to be anything. */
static bool link_unknown(const struct belay_entry *e) { return is_link(e) && (e->unreadable || !e->has_link_target); }
static bool same_link(const struct belay_entry *a, const struct belay_entry *b) {
    return a->link_target_len == b->link_target_len && memcmp(a->link_target, b->link_target, a->link_target_len) == 0;
}

static enum belay_interp_result done(struct systemd *sd) {
    return sd->failed || sysevs_failed(sd->s) ? BELAY_INTERP_ERROR : BELAY_INTERP_DECLINE;
}

/* `name`, under a home prefixed by its directory's path (SY-3a). NULL: memory, or no path to prefix it with. */
static const char *unit_of(struct systemd *sd, const struct place *p, size_t *len) {
    if (p->kind != D_HOME) { *len = p->name_len; return p->name; }
    if (p->d == NULL) { *len = p->name_len; return p->name; }
    char *buf = malloc(p->d_len + 1 + p->name_len + 1);
    if (buf == NULL) { sd->failed = true; return NULL; }
    memcpy(buf, p->d, p->d_len);
    buf[p->d_len] = '/';
    memcpy(buf + p->d_len + 1, p->name, p->name_len);
    *len = p->d_len + 1 + p->name_len;
    const char *kept = sysevs_dup(sd->s, buf, *len);
    free(buf);
    return kept;
}

/* ---- links into a target ---- */

/* The path, relative to the scope, a link's text names: an absolute text
 * under the tree's prefix, a relative one from the link's directory, `.`
 * and `..` resolved by name alone. false: it leaves the scope, the tree is
 * not known, or it does not fit a path. */
static bool target_path(const struct belay_interp_input *in, const struct place *p, const struct belay_entry *l,
                        char *out, size_t cap, size_t *len) {
    const char *t = l->link_target;
    const size_t tl = l->link_target_len;
    size_t w = 0, floor = 0;
    if (tl == 0 || tl >= cap) return false;
    if (t[0] == '/') {
        const size_t pl = p->kind == D_HOME ? 0 : p->prefix_len;       /* a home's tree is the scope's (SY-3a) */
        if (pl == SIZE_MAX || pl >= cap) return false;
        memcpy(out, in->path, pl);
        w = floor = pl;
    } else {
        size_t dl;
        sys_base(in->path, in->path_len, NULL, &dl);
        if (dl >= cap) return false;
        memcpy(out, in->path, dl);
        w = dl;
    }
    for (size_t i = 0; i < tl; ) {
        size_t e = i;
        while (e < tl && t[e] != '/') e++;
        const size_t cl = e - i;
        if (cl == 2 && t[i] == '.' && t[i + 1] == '.') {
            if (w > 0 && out[w - 1] == '/') w--;
            if (w <= floor) return false;               /* above the tree, or the scope */
            while (w > floor && out[w - 1] != '/') w--;
        } else if (cl > 0 && !(cl == 1 && t[i] == '.')) {
            if (w > 0 && out[w - 1] != '/') { if (w + 1 >= cap) return false; out[w++] = '/'; }
            if (w + cl >= cap) return false;
            memcpy(out + w, t + i, cl);
            w += cl;
        }
        i = e + 1;
    }
    while (w > 0 && out[w - 1] == '/') w--;
    if (w == 0 || w > 4096) return false;
    *len = w;
    return true;
}

static void link_event(struct systemd *sd, const struct belay_interp_input *in, const struct place *p,
                       const struct belay_entry *l, size_t into_len, int kind) {
    size_t ul;
    const char *unit = unit_of(sd, p, &ul);
    if (unit == NULL) return;
    const struct belay_fv v[] = { { .s = unit, .len = ul }, { .s = p->sub, .len = into_len },
                                  { .s = l->link_target, .len = l->link_target_len }, { .absent = true } };
    struct sysev *e = sysevs_add(sd->s, kind, in->path, in->path_len, 0, kind == FK_UNIT_UNLINKED ? SYS_REMOVED : SYS_ADDED,
                                 sys_prov(in), v, 4);
    static char t[8192];
    size_t tl;
    if (e != NULL && target_path(in, p, l, t, sizeof t, &tl)) sysevs_owner(sd->s, e, 3, t, tl);
}

/* ---- a timer's OnCalendar= values ---- */

struct cal { struct belay_fv *v; size_t n, cap; char *text; bool other; };

static void cal_free(struct cal *c) { free(c->v); free(c->text); memset(c, 0, sizeof *c); }

/* systemd's whitespace, for a unit file's lines. */
static bool ws(char c) { return c == ' ' || c == '\t' || c == '\r'; }
static void strip(const char **s, const char **e) {
    while (*s < *e && ws(**s)) (*s)++;
    while (*e > *s && ws((*e)[-1])) (*e)--;
}

/* systemd.syntax(7): a line ending in a backslash is joined with the next,
 * the backslash read as a space; a line whose first non-blank is `#` or
 * `;` is a comment; `[Section]`; `Key=value`. Of the [Timer] section:
 * every OnCalendar= value, an empty one forgetting those above it, and
 * whether another trigger is set. 0, or -1 (memory). */
static int cal_parse(const char *buf, size_t len, struct cal *c) {
    static const char *const OTHER[] = { "OnActiveSec", "OnBootSec", "OnStartupSec", "OnUnitActiveSec", "OnUnitInactiveSec" };
    memset(c, 0, sizeof *c);
    if ((c->text = malloc(len + 1)) == NULL) return -1;
    size_t w = 0;
    bool timer = false;
    const char *p = buf, *end = buf + len;
    while (p < end) {
        const size_t start = w;                 /* one logical line into text[start, w) */
        for (;;) {
            const char *nl = memchr(p, '\n', (size_t)(end - p));
            const char *e = nl ? nl : end;
            const char *next = nl ? nl + 1 : end;
            const char *q = e;
            while (q > p && q[-1] == '\r') q--;
            const bool cont = q > p && q[-1] == '\\' && next < end;
            memcpy(c->text + w, p, (size_t)(q - p));
            w += (size_t)(q - p);
            p = next;
            if (!cont) break;
            c->text[w - 1] = ' ';
        }
        const char *s = c->text + start, *e = c->text + w;
        strip(&s, &e);
        if (s == e || *s == '#' || *s == ';') continue;
        if (*s == '[') {
            timer = (size_t)(e - s) == 7 && memcmp(s, "[Timer]", 7) == 0;
            continue;
        }
        const char *eq = memchr(s, '=', (size_t)(e - s));
        if (!timer || eq == NULL) continue;
        const char *ke = eq, *vs = eq + 1, *ve = e;
        strip(&s, &ke);
        strip(&vs, &ve);
        const size_t kl = (size_t)(ke - s);
        if (kl == 10 && memcmp(s, "OnCalendar", 10) == 0) {
            if (vs == ve) { c->n = 0; continue; }
            if (c->n == c->cap) {
                const size_t cap = c->cap ? 2 * c->cap : 8;
                struct belay_fv *q = realloc(c->v, cap * sizeof *q);
                if (q == NULL) return -1;
                c->v = q;
                c->cap = cap;
            }
            c->v[c->n++] = (struct belay_fv){ .s = vs, .len = (size_t)(ve - vs) };
            continue;
        }
        for (size_t i = 0; i < sizeof OTHER / sizeof OTHER[0]; i++)
            if (vs != ve && kl == strlen(OTHER[i]) && memcmp(s, OTHER[i], kl) == 0) c->other = true;
    }
    return 0;
}

static bool cal_same(const struct cal *a, const struct cal *b) {
    if (a->n != b->n) return false;
    for (size_t i = 0; i < a->n; i++)
        if (a->v[i].len != b->v[i].len || memcmp(a->v[i].s, b->v[i].s, a->v[i].len) != 0) return false;
    return true;
}

/* A side's copy of a unit file, for the timer's values. false: it cannot be read (SI-2). */
static bool side_read(const struct belay_interp_input *in, enum side k, unsigned char **buf, size_t *len) {
    const struct belay_entry *e = side_entry(in, k);
    *buf = NULL;
    if (e->sealed || e->meta || stored_read(in, k, SYS_FILE_MAX, buf, len) != SW_OK) return false;
    if (memchr(*buf, '\0', *len) != NULL) { free(*buf); *buf = NULL; return false; }
    return true;
}

static void timer_event(struct systemd *sd, const struct belay_interp_input *in, const struct cal *c, int kind) {
    char words[160];
    const bool has = c->n == 1 && !c->other && inwords_timer(c->v[0].s, c->v[0].len, words, sizeof words);
    const struct belay_fv v[] = { { .s = in->path, .len = in->path_len }, { .list = c->v, .nlist = c->n }, { .absent = true },
                                  has ? (struct belay_fv){ .s = words, .len = strlen(words) } : (struct belay_fv){ .absent = true } };
    struct sysev *e = sysevs_add(sd->s, kind, in->path, in->path_len, 0, kind == FK_TIMER_FILE_REMOVED ? SYS_REMOVED : SYS_ADDED,
                                 sys_prov(in), v, 4);
    sysevs_owner(sd->s, e, 2, in->path, in->path_len);
}

/* ---- files and links directly in D, and drop-ins ---- */

static void path_owner_event(struct systemd *sd, const struct belay_interp_input *in, int kind, int rank) {
    const struct belay_fv v[] = { { .s = in->path, .len = in->path_len }, { .absent = true } };
    struct sysev *e = sysevs_add(sd->s, kind, in->path, in->path_len, 0, rank, sys_prov(in), v, 2);
    sysevs_owner(sd->s, e, 1, in->path, in->path_len);
}

/* Whether the content of a file on both sides differs, as far as the diff says. */
static bool content_changed(const struct belay_interp_input *in) {
    if (strcmp(in->outcome, "metadata_only") == 0) return false;
    const struct belay_entry *b = in->before, *a = in->after;
    return !(b->has_hash && a->has_hash && !b->sealed && !a->sealed && strcmp(b->sha256_hex, a->sha256_hex) == 0);
}

static char *join(const char *a, size_t al, const char *b, const char *c, size_t cl, size_t *len) {
    const size_t bl = strlen(b);
    char *s = malloc(al + bl + cl + 1);
    if (s == NULL) return NULL;
    memcpy(s, a, al);
    memcpy(s + al, b, bl);
    memcpy(s + al + bl, c, cl);
    *len = al + bl + cl;
    return s;
}

/* A unit file added in etc: the event, kept back until the after-manifest
 * shows a packaged unit of its name. */
static void override_candidate(struct systemd *sd, const struct belay_interp_input *in, const struct place *p) {
    if (p->kind != D_ETC || p->prefix_len == SIZE_MAX) return;
    size_t ul, ll;
    char *usr = join(in->path, p->prefix_len, p->user ? "usr/lib/systemd/user/" : "usr/lib/systemd/system/", p->name, p->name_len, &ul);
    char *lib = join(in->path, p->prefix_len, p->user ? "lib/systemd/user/" : "lib/systemd/system/", p->name, p->name_len, &ll);
    if (usr == NULL || lib == NULL) { free(usr); free(lib); sd->failed = true; return; }
    if (ul <= 4096 && ll <= 4096) {
        const struct belay_fv v[] = { { .s = p->name, .len = p->name_len }, { .s = in->path, .len = in->path_len },
                                      { .s = usr, .len = ul } };
        struct sysev *e = sysevs_add(sd->s, FK_UNIT_OVERRIDES_PACKAGED, in->path, in->path_len, 0, SYS_ADDED, sys_prov(in), v, 3);
        if (e != NULL) {
            e->drop = true;
            struct ovr tmp = { sd, e, e->v[2].s, sysevs_dup(sd->s, lib, ll), ul, ll, false, false };
            struct ovr *o = (struct ovr *)(void *)sysevs_dup(sd->s, (const char *)&tmp, sizeof tmp);
            if (sd->no == sd->cap) {
                const size_t cap = sd->cap ? 2 * sd->cap : 16;
                struct ovr **q = realloc(sd->o, cap * sizeof *q);
                if (q == NULL) sd->failed = true;
                else { sd->o = q; sd->cap = cap; }
            }
            if (o != NULL && tmp.lib != NULL && sd->no < sd->cap) sd->o[sd->no++] = o;
        }
    }
    free(usr);
    free(lib);
}

static enum belay_interp_result in_dir(struct systemd *sd, const struct belay_interp_input *in, const struct place *p) {
    const struct belay_entry *b = in->before, *a = in->after;
    const bool etc = p->kind != D_LIB, unit = unit_name(p->name, p->name_len);
    if (etc && (link_unknown(b) || link_unknown(a))) return sys_cannot(sd->s, in);
#define MASKED(e) (etc && unit && ((is_link(e) && (e)->link_target_len == 9 && memcmp((e)->link_target, "/dev/null", 9) == 0) || \
                                   (is_reg(e) && (e)->size == 0)))
    const bool mb = MASKED(b), ma = MASKED(a);
#undef MASKED
    const bool lb = etc && is_link(b) && !mb && !(b->link_target_len == 9 && memcmp(b->link_target, "/dev/null", 9) == 0);
    const bool la = etc && is_link(a) && !ma && !(a->link_target_len == 9 && memcmp(a->link_target, "/dev/null", 9) == 0);
    const bool ub = unit && is_reg(b) && !mb, ua = unit && is_reg(a) && !ma;
    if (!mb && !ma && !lb && !la && !ub && !ua) return BELAY_INTERP_DECLINE;

    /* A timer's values are read first: a copy that cannot be read is said, and nothing else. */
    const bool timer = p->name_len > 6 && memcmp(p->name + p->name_len - 6, ".timer", 6) == 0;
    struct cal cb, ca;
    memset(&cb, 0, sizeof cb);
    memset(&ca, 0, sizeof ca);
    if (timer && (ub || ua) && !(ub && ua && !content_changed(in))) {
        unsigned char *buf = NULL;
        size_t len = 0;
        bool ok = true;
        int rc = 0;
        if (ub) { ok = side_read(in, SIDE_BEFORE, &buf, &len); if (ok) rc = cal_parse((const char *)buf, len, &cb); free(buf); }
        if (ok && rc == 0 && ua) { ok = side_read(in, SIDE_AFTER, &buf, &len); if (ok) rc = cal_parse((const char *)buf, len, &ca); free(buf); }
        if (!ok || rc == -1) {
            cal_free(&cb);
            cal_free(&ca);
            if (rc == -1) { sd->failed = true; return BELAY_INTERP_ERROR; }
            return sys_cannot(sd->s, in);
        }
    }

    size_t ul = 0;
    const char *uname = (mb != ma || lb || la) ? unit_of(sd, p, &ul) : NULL;
    if (mb != ma && uname != NULL) {
        const struct belay_fv v[] = { { .s = uname, .len = ul } };
        sysevs_add(sd->s, ma ? FK_UNIT_MASKED : FK_UNIT_UNMASKED, in->path, in->path_len, 0, ma ? SYS_ADDED : SYS_REMOVED,
                   sys_prov(in), v, 1);
    }
    if (uname != NULL && lb && !(la && same_link(b, a))) {
        const struct belay_fv v[] = { { .s = uname, .len = ul }, { .s = b->link_target, .len = b->link_target_len } };
        sysevs_add(sd->s, FK_UNIT_ALIAS_REMOVED, in->path, in->path_len, 0, SYS_REMOVED, sys_prov(in), v, 2);
    }
    if (uname != NULL && la && !(lb && same_link(b, a))) {
        const struct belay_fv v[] = { { .s = uname, .len = ul }, { .s = a->link_target, .len = a->link_target_len } };
        sysevs_add(sd->s, FK_UNIT_ALIAS_ADDED, in->path, in->path_len, 0, SYS_ADDED, sys_prov(in), v, 2);
    }
    if (ub && !ua) path_owner_event(sd, in, FK_UNIT_FILE_REMOVED, SYS_REMOVED);
    if (ua && !ub) {
        path_owner_event(sd, in, FK_UNIT_FILE_ADDED, SYS_ADDED);
        override_candidate(sd, in, p);
    }
    if (ua && ub && content_changed(in)) path_owner_event(sd, in, FK_UNIT_FILE_CHANGED, SYS_ADDED);
    if (timer && (ub || ua) && !(ub && ua && (!content_changed(in) || cal_same(&cb, &ca)))) {
        if (ub) timer_event(sd, in, &cb, FK_TIMER_FILE_REMOVED);
        if (ua) timer_event(sd, in, &ca, FK_TIMER_FILE_ADDED);
    }
    cal_free(&cb);
    cal_free(&ca);
    return done(sd);
}

/* ---- init scripts ---- */

static bool there(const struct belay_entry *e) { return e != NULL && e->type != BELAY_T_DIR; }

static bool init_path(const struct belay_interp_input *in) {
    size_t bl, dl;
    if (sys_ends(in->abs_path, in->abs_len, "/etc/rc.local")) return true;
    sys_base(in->abs_path, in->abs_len, &bl, &dl);
    return bl > 0 && dl > 0 && sys_ends(in->abs_path, dl - 1, "/etc/init.d");
}

static enum belay_interp_result init_script(struct systemd *sd, const struct belay_interp_input *in) {
    const struct belay_entry *b = in->before, *a = in->after;
    if (!there(b) && !there(a)) return BELAY_INTERP_DECLINE;
    if (there(b) && there(a) && strcmp(in->outcome, "metadata_only") == 0 && !((b->mode ^ a->mode) & 07777))
        return BELAY_INTERP_DECLINE;
    const int kind = !there(a) ? FK_INIT_SCRIPT_REMOVED : !there(b) ? FK_INIT_SCRIPT_ADDED : FK_INIT_SCRIPT_CHANGED;
    const struct belay_entry *e = there(a) ? a : b;
    const struct belay_fv v[] = { { .s = in->path, .len = in->path_len }, { .absent = true },
                                  { .b = e->type == BELAY_T_REG && (e->mode & 0111) != 0 } };
    struct sysev *ev = sysevs_add(sd->s, kind, in->path, in->path_len, 0, kind == FK_INIT_SCRIPT_REMOVED ? SYS_REMOVED : SYS_ADDED,
                                  sys_prov(in), v, 3);
    sysevs_owner(sd->s, ev, 1, in->path, in->path_len);
    return done(sd);
}

static bool tail_is(const char *s, size_t n, const char *t) {
    const size_t tl = strlen(t);
    return n > tl && memcmp(s + n - tl, t, tl) == 0;
}

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct systemd *sd = state;
    (void)out;                                  /* what systemd reports are events: the record stands as it is */
    if (sd == NULL) return BELAY_INTERP_ERROR;
    if (init_path(in)) return init_script(sd, in);
    struct place p;
    if (!place_of(in, &p)) return BELAY_INTERP_DECLINE;
    const struct belay_entry *b = in->before, *a = in->after;
    if (p.sub == NULL) return in_dir(sd, in, &p);

    const size_t suf = tail_is(p.sub, p.sub_len, ".wants") ? 6 : tail_is(p.sub, p.sub_len, ".requires") ? 9 : 0;
    if (suf) {                                  /* D/<x>.wants/<unit> */
        if (!is_link(b) && !is_link(a)) return BELAY_INTERP_DECLINE;
        if (link_unknown(b) || link_unknown(a)) return sys_cannot(sd->s, in);
        const bool same = is_link(b) && is_link(a) && same_link(b, a);
        if (is_link(b) && !same) link_event(sd, in, &p, b, p.sub_len - suf, FK_UNIT_UNLINKED);
        if (is_link(a) && !same) link_event(sd, in, &p, a, p.sub_len - suf, FK_UNIT_LINKED);
        return done(sd);
    }
    if (tail_is(p.sub, p.sub_len, ".d") && unit_name(p.sub, p.sub_len - 2)) {       /* D/<unit>.d/<file> */
        if (!is_reg(b) && !is_reg(a)) return BELAY_INTERP_DECLINE;
        if (is_reg(b) && !is_reg(a)) path_owner_event(sd, in, FK_UNIT_FILE_REMOVED, SYS_REMOVED);
        else if (!is_reg(b)) path_owner_event(sd, in, FK_UNIT_FILE_ADDED, SYS_ADDED);
        else if (content_changed(in)) path_owner_event(sd, in, FK_UNIT_FILE_CHANGED, SYS_ADDED);
        else return BELAY_INTERP_DECLINE;
        return done(sd);
    }
    return BELAY_INTERP_DECLINE;
}

/* ---- the lookups: a packaged unit of the name, and the owners ---- */

static int usr_seen(void *ctx, const struct belay_entry *e) {
    ((struct ovr *)ctx)->in_usr |= e->type == BELAY_T_REG || e->type == BELAY_T_LNK;
    return 0;
}
static int lib_seen(void *ctx, const struct belay_entry *e) {
    ((struct ovr *)ctx)->in_lib |= e->type == BELAY_T_REG || e->type == BELAY_T_LNK;
    return 0;
}

static enum belay_interp_result prepare(void *state, struct belay_lookup *lk) {
    struct systemd *sd = state;
    if (sd == NULL) return BELAY_INTERP_ERROR;
    sd->lk = lk;
    if (sd->asked) return BELAY_INTERP_FINDINGS;
    sd->asked = true;
    for (size_t i = 0; i < sd->no; i++) {
        struct ovr *o = sd->o[i];
        if (belay_lookup_want(lk, o->usr, o->usr_len, false, usr_seen, o) == -1 ||
            belay_lookup_want(lk, o->lib, o->lib_len, false, lib_seen, o) == -1)
            return BELAY_INTERP_ERROR;
    }
    return sysevs_ask_owners(sd->s, lk) == -1 ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
}

static enum belay_interp_result end(void *state, struct belay_events *ev) {
    struct systemd *sd = state;
    if (sd == NULL) return BELAY_INTERP_ERROR;
    enum belay_interp_result r = sd->failed ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    if (ev != NULL && r == BELAY_INTERP_FINDINGS) {
        for (size_t i = 0; i < sd->no; i++) {
            struct ovr *o = sd->o[i];
            if (!o->in_usr && !o->in_lib) continue;
            o->e->drop = false;
            if (!o->in_usr) o->e->v[2] = (struct belay_fv){ .s = o->lib, .len = o->lib_len };
        }
        r = sysevs_emit(sd->s, ev, sd->lk);
    }
    free(sd->o);
    sysevs_free(sd->s);
    free(sd);
    return r;
}

const struct belay_interp INTERP_SYSTEMD = { BELAY_INTERP_SYSTEMD, begin, explain, end, prepare };
