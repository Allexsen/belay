/*
 *  The cron interpreter (test/expect/system-interpreters.md SC-1 to SC-6;
 *  finding-kinds.md, cron_*): the job and `NAME=value` lines of
 *  `etc/crontab` and the files of `etc/cron.d` and `var/spool/cron/crontabs`, added and
 *  removed; the files of `etc/cron.hourly`, `cron.daily`, `cron.weekly` and
 *  `cron.monthly`, named and never read; and, only where the same capture's
 *  dpkg database has the package `cron` installed (SC-2), the files cron
 *  does not run (SC-3, SC-4). An event states a line of a file: never that
 *  a job will run, nor when the four directories do (SC-5).
 *
 *  A line (crontab(5)): blank, or a comment (`#` first); `NAME = value`;
 *  else a job -- five schedule fields or one `@word`, in `etc/crontab` and
 *  `cron.d` a user, then the command to the end of the line as written. A
 *  line that is none of these makes its file could_not_interpret (SI-2).
 *  Jobs are compared as multisets of (schedule, user, command), so a job
 *  moved in its file, or one whose environment lines changed, is no event;
 *  the lines changed are cron_env_changed, cron_env_added and cron_env_removed.
 */
#include "builtins.h"
#include "inwords.h"
#include "stanza.h"
#include "stored.h"
#include "sysev.h"

#include "belay/error.h"
#include "belay/manifest.h"

#include <stdlib.h>
#include <string.h>

#define CRON_STATUS_MAX (256u * 1024u * 1024u)  /* bytes of a dpkg status read, as dpkg.c's */
#define CRON_ROOTS 64u                          /* trees with cron files in one diff; more: validity not said */

enum ckind { C_NONE, C_CRONTAB, C_CROND, C_SPOOL, C_SCRIPT };

struct cron;
/* One tree cron's files were found in: the path, relative to the scope,
 * before `etc/` or `var/` (empty for a machine's root). */
struct root { struct cron *c; char *prefix; size_t n; bool cron; };

struct cron {
    struct sysevs *s;
    struct root *roots;
    size_t nroots;
    struct belay_lookup *lk;
    bool asked, failed;
};

static void *begin(void) {
    struct cron *c = calloc(1, sizeof *c);
    if (c != NULL && (c->s = sysevs_new()) == NULL) { free(c); c = NULL; }
    return c;
}

/* ---- which file ---- */

static bool dir_is(const char *abs, size_t dir_len, const char *dir) {
    return dir_len > 0 && sys_ends(abs, dir_len - 1, dir);
}

/* What the path is to cron, and the length of its tail from `etc/` or `var/`. */
static enum ckind classify(const struct belay_interp_input *in, size_t *tail) {
    static const char *const SCRIPTS[] = { "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly" };
    size_t bl, dl;
    sys_base(in->abs_path, in->abs_len, &bl, &dl);
    if (sys_ends(in->abs_path, in->abs_len, "/etc/crontab")) { *tail = 11; return C_CRONTAB; }
    if (bl == 0) return C_NONE;
    if (dir_is(in->abs_path, dl, "/etc/cron.d")) { *tail = 11 + bl; return C_CROND; }
    if (dir_is(in->abs_path, dl, "/var/spool/cron/crontabs")) { *tail = 24 + bl; return C_SPOOL; }
    for (size_t i = 0; i < sizeof SCRIPTS / sizeof SCRIPTS[0]; i++)
        if (dir_is(in->abs_path, dl, SCRIPTS[i])) { *tail = strlen(SCRIPTS[i]) + bl; return C_SCRIPT; }
    return C_NONE;
}

/* The tree of a path, as an index from 1; 0 when it cannot be told or
 * there are too many: then nothing is said of validity there (SC-2). */
static uint32_t root_of(struct cron *c, const struct belay_interp_input *in, size_t tail) {
    if (in->path_len < tail) return 0;
    const size_t n = in->path_len - tail;
    for (size_t i = 0; i < c->nroots; i++)
        if (c->roots[i].n == n && memcmp(c->roots[i].prefix, in->path, n) == 0) return (uint32_t)(i + 1);
    if (c->nroots == CRON_ROOTS) return 0;
    struct root *q = realloc(c->roots, (c->nroots + 1) * sizeof *q);
    if (q == NULL) { c->failed = true; return 0; }
    c->roots = q;
    char *p = malloc(n + 1);
    if (p == NULL) { c->failed = true; return 0; }
    if (n) memcpy(p, in->path, n);
    p[n] = '\0';
    c->roots[c->nroots] = (struct root){ c, p, n, false };
    return (uint32_t)++c->nroots;
}

/* ---- the files cron does not run (SC-3, SC-4): said at the end, where cron is installed ---- */

static bool name_ok(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        const char ch = s[i];
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-'))
            return false;
    }
    return true;
}

static void not_run(struct cron *c, const struct belay_interp_input *in, enum ckind kind, uint32_t root) {
    const struct belay_entry *a = in->after;
    if (a == NULL || a->type == BELAY_T_DIR) return;
    size_t bl;
    const char *base = sys_base(in->path, in->path_len, &bl, NULL);
    const char *why = NULL;
    if (!name_ok(base, bl)) why = "name";
    else if (a->type != BELAY_T_REG) return;
    else if (kind == C_CROND && (a->mode & 022)) why = "mode";
    else if (kind == C_SCRIPT && !(a->mode & 0111)) why = "not executable";
    if (why == NULL) return;
    const struct belay_fv v[] = { { .s = in->path, .len = in->path_len }, { .s = why, .len = strlen(why) } };
    struct sysev *e = sysevs_add(c->s, FK_CRON_FILE_NOT_RUN, in->path, in->path_len, 0, SYS_ADDED, sys_prov(in), v, 2);
    if (e != NULL) {
        e->drop = true;                         /* until the dpkg database says cron is installed */
        e->aux = root;
    }
}

/* ---- one side of a file of jobs ---- */

static const char *const ENV4[] = { "SHELL", "PATH", "MAILTO", "CRON_TZ" };

struct str { const char *s; size_t n; };
struct envl { struct str name, val, raw; uint32_t line; };
struct job { struct str sch, user, cmd; uint32_t line; long env[4]; };  /* env: an index of `e`, or -1 */

struct cside {
    struct sysline *lines;
    struct job *j;
    struct envl *e;
    struct sysline *jk, *ek;    /* the jobs' and env lines' keys, in their order */
    char *keys;
    size_t nj, ne;
    bool tz;                    /* the file sets CRON_TZ or TZ: no schedule of it is put in words (SW-8) */
};

static void side_free(struct cside *sd) {
    free(sd->lines); free(sd->j); free(sd->e); free(sd->jk); free(sd->ek); free(sd->keys);
    memset(sd, 0, sizeof *sd);
}

static bool is(struct str a, const char *b) { return a.n == strlen(b) && memcmp(a.s, b, a.n) == 0; }
static bool name_char(char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_';
}

/* The next field of [*p, e): to the next blank. Empty at the end. */
static struct str field(const char **p, const char *e) {
    while (*p < e && sys_blank(**p)) (*p)++;
    const char *s = *p;
    while (*p < e && !sys_blank(**p)) (*p)++;
    return (struct str){ s, (size_t)(*p - s) };
}

/* 0; 1: a line that is no line of a crontab; -1: memory. `user`: the user
 * of every job (a spool file's name), or NULL where the line gives it. */
static int parse(const char *buf, size_t len, const struct str *user, struct cside *sd) {
    size_t nl;
    bool oom;
    memset(sd, 0, sizeof *sd);
    sd->lines = sys_lines(buf, len, &nl, &oom);
    if (oom) return -1;
    if (nl == 0) return 0;
    /* A key is no longer than its line, two separators and, in a spool
     * file, the user its name gives every job. */
    sd->keys = malloc(len + (3 + (user != NULL ? user->n : 0)) * nl + 1);
    sd->j = calloc(nl, sizeof *sd->j);
    sd->e = calloc(nl, sizeof *sd->e);
    sd->jk = calloc(nl, sizeof *sd->jk);
    sd->ek = calloc(nl, sizeof *sd->ek);
    if (sd->keys == NULL || sd->j == NULL || sd->e == NULL || sd->jk == NULL || sd->ek == NULL) return -1;
    char *w = sd->keys;
    long cur[4] = { -1, -1, -1, -1 };
    for (size_t i = 0; i < nl; i++) {
        const char *s = sd->lines[i].s, *e = s + sd->lines[i].n;
        while (s < e && sys_blank(*s)) s++;
        if (s == e || *s == '#') continue;
        const char *q = s;
        while (q < e && name_char(*q)) q++;
        const char *eq = q;
        while (eq < e && sys_blank(*eq)) eq++;
        if (q > s && eq < e && *eq == '=') {                    /* NAME = value */
            struct envl *v = &sd->e[sd->ne];
            const char *vs = eq + 1, *ve = e, *rs = s, *re = e;
            sys_trim(&vs, &ve);
            sys_trim(&rs, &re);
            *v = (struct envl){ { s, (size_t)(q - s) }, { vs, (size_t)(ve - vs) }, { rs, (size_t)(re - rs) },
                                sd->lines[i].line };
            for (int k = 0; k < 4; k++)
                if (is(v->name, ENV4[k])) cur[k] = (long)sd->ne;
            if (is(v->name, "CRON_TZ") || is(v->name, "TZ")) sd->tz = true;
            char *key = w;                                      /* name=value */
            memcpy(w, v->name.s, v->name.n); w += v->name.n;
            *w++ = '=';
            if (v->val.n) memcpy(w, v->val.s, v->val.n);
            w += v->val.n;
            sd->ek[sd->ne] = (struct sysline){ .s = key, .n = (size_t)(w - key), .line = v->line, .aux = (uint32_t)sd->ne };
            sd->ne++;
            continue;
        }
        struct job *j = &sd->j[sd->nj];
        const char *p = s;
        char *key = w;
        const int nf = *s == '@' ? 1 : 5;
        for (int k = 0; k < nf; k++) {                          /* the schedule, one space between its fields */
            const struct str f = field(&p, e);
            if (f.n == 0) return 1;
            if (k) *w++ = ' ';
            memcpy(w, f.s, f.n);
            w += f.n;
        }
        j->sch = (struct str){ key, (size_t)(w - key) };
        *w++ = '\0';
        j->user = user != NULL ? *user : field(&p, e);
        if (j->user.n == 0) return 1;
        while (p < e && sys_blank(*p)) p++;
        j->cmd = (struct str){ p, (size_t)(e - p) };            /* to the end of the line, as written */
        if (j->cmd.n == 0) return 1;
        memcpy(w, j->user.s, j->user.n); w += j->user.n;
        *w++ = '\0';
        memcpy(w, j->cmd.s, j->cmd.n); w += j->cmd.n;
        j->line = sd->lines[i].line;
        memcpy(j->env, cur, sizeof cur);
        sd->jk[sd->nj] = (struct sysline){ .s = key, .n = (size_t)(w - key), .line = j->line, .aux = (uint32_t)sd->nj };
        sd->nj++;
    }
    return 0;
}

/* ---- the events of a file of jobs ---- */

static void job_event(struct cron *c, const struct belay_interp_input *in, const struct cside *sd, const struct job *j,
                      int rank) {
    struct belay_fv env[4];
    long at[4];
    size_t ne = 0;
    for (int k = 0; k < 4; k++) {                               /* those in force, in the file's order */
        if (j->env[k] < 0) continue;
        size_t i = ne++;
        for (; i > 0 && at[i - 1] > j->env[k]; i--) at[i] = at[i - 1];
        at[i] = j->env[k];
    }
    for (size_t i = 0; i < ne; i++) env[i] = (struct belay_fv){ .s = sd->e[at[i]].raw.s, .len = sd->e[at[i]].raw.n };
    char words[160];
    const bool has = !sd->tz && inwords_cron(j->sch.s, j->sch.n, words, sizeof words);
    const struct belay_fv v[] = {
        { .s = in->path, .len = in->path_len }, { .s = j->sch.s, .len = j->sch.n }, { .s = j->user.s, .len = j->user.n },
        { .s = j->cmd.s, .len = j->cmd.n }, { .list = env, .nlist = ne }, { .absent = true },
        has ? (struct belay_fv){ .s = words, .len = strlen(words) } : (struct belay_fv){ .absent = true },
    };
    struct sysev *e = sysevs_add(c->s, rank == SYS_ADDED ? FK_CRON_JOB_ADDED : FK_CRON_JOB_REMOVED, in->path,
                                 in->path_len, j->line, rank, sys_prov(in), v, 7);
    sysevs_owner(c->s, e, 5, in->path, in->path_len);
}

static void env_event(struct cron *c, const struct belay_interp_input *in, const struct envl *from,
                      const struct envl *to) {
    const struct envl *k = to != NULL ? to : from;
    if (from != NULL && to != NULL) {
        const struct belay_fv v[] = {
            { .s = in->path, .len = in->path_len }, { .s = k->name.s, .len = k->name.n },
            { .s = from->val.s, .len = from->val.n }, { .s = to->val.s, .len = to->val.n },
        };
        sysevs_add(c->s, FK_CRON_ENV_CHANGED, in->path, in->path_len, k->line, SYS_ADDED, sys_prov(in), v, 4);
        return;
    }
    const struct belay_fv v[] = {   /* one side: said as config says a key (cron_env_added, _removed) */
        { .s = in->path, .len = in->path_len }, { .s = k->name.s, .len = k->name.n }, { .s = k->val.s, .len = k->val.n },
    };
    sysevs_add(c->s, to != NULL ? FK_CRON_ENV_ADDED : FK_CRON_ENV_REMOVED, in->path, in->path_len, k->line,
               to != NULL ? SYS_ADDED : SYS_REMOVED, sys_prov(in), v, 3);
}

static int name_cmp(const struct envl *x, const struct envl *y) {
    const int c = memcmp(x->name.s, y->name.s, x->name.n < y->name.n ? x->name.n : y->name.n);
    return c ? c : (x->name.n > y->name.n) - (x->name.n < y->name.n);
}

static int envp_cmp(const void *a, const void *b) {
    const struct envl *x = *(const struct envl *const *)a, *y = *(const struct envl *const *)b;
    const int c = name_cmp(x, y);
    return c ? c : (x->line > y->line) - (x->line < y->line);
}

/* The env lines of one side, by name. NULL: none, or (with *oom) memory. */
static const struct envl **by_name(const struct cside *sd, bool *oom) {
    if (sd->ne == 0) return NULL;
    const struct envl **v = malloc(sd->ne * sizeof *v);
    if (v == NULL) { *oom = true; return NULL; }
    for (size_t i = 0; i < sd->ne; i++) v[i] = &sd->e[i];
    qsort(v, sd->ne, sizeof *v, envp_cmp);
    return v;
}

static bool same_name(const struct envl *x, const struct envl *y) { return name_cmp(x, y) == 0; }

/* cron_env_changed: a name with one line on each side whose values differ
 * is one event; otherwise each line added and each removed is its own. */
static int env_events(struct cron *c, const struct belay_interp_input *in, const struct cside sd[2]) {
    bool oom = false;
    if (sys_lines_diff(sd[0].ek, sd[0].ne, sd[1].ek, sd[1].ne) == -1) return -1;
    const struct envl **b = by_name(&sd[0], &oom), **a = by_name(&sd[1], &oom);
    size_t i = 0, j = 0;
    while (!oom && (i < sd[0].ne || j < sd[1].ne)) {
        const int cmp = i == sd[0].ne ? 1 : j == sd[1].ne ? -1 : name_cmp(b[i], a[j]);
        size_t ie = i, je = j;
        if (cmp <= 0) while (ie < sd[0].ne && same_name(b[ie], b[i])) ie++;
        if (cmp >= 0) while (je < sd[1].ne && same_name(a[je], a[j])) je++;
#define ONLY(sdk, p) ((sdk).ek[(p) - (sdk).e].only)
        if (ie - i == 1 && je - j == 1) {
            if (ONLY(sd[0], b[i])) env_event(c, in, b[i], a[j]);
        } else {
            for (size_t k = i; k < ie; k++) if (ONLY(sd[0], b[k])) env_event(c, in, b[k], NULL);
            for (size_t k = j; k < je; k++) if (ONLY(sd[1], a[k])) env_event(c, in, NULL, a[k]);
        }
#undef ONLY
        i = ie;
        j = je;
    }
    free(b);
    free(a);
    return oom ? -1 : 0;
}

static enum belay_interp_result done(struct cron *c) {
    return c->failed || sysevs_failed(c->s) ? BELAY_INTERP_ERROR : BELAY_INTERP_DECLINE;
}

static bool there(const struct belay_entry *e) { return e != NULL && e->type != BELAY_T_DIR; }

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct cron *c = state;
    (void)out;                                  /* what cron reports are events: the record stands as it is */
    if (c == NULL) return BELAY_INTERP_ERROR;
    size_t tail = 0;
    const enum ckind kind = classify(in, &tail);
    /* A directory in cron's place holds no job and is no script. */
    if (kind == C_NONE || (!there(in->before) && !there(in->after))) return BELAY_INTERP_DECLINE;
    const bool mode_changed = in->before != NULL && in->after != NULL && ((in->before->mode ^ in->after->mode) & 07777);
    if (strcmp(in->outcome, "metadata_only") == 0 && !mode_changed) return BELAY_INTERP_DECLINE;
    const uint32_t root = root_of(c, in, tail);

    if (kind == C_SCRIPT) {                     /* named, never read */
        const int k = !there(in->after) ? FK_CRON_SCRIPT_REMOVED : !there(in->before) ? FK_CRON_SCRIPT_ADDED
                                                                                      : FK_CRON_SCRIPT_CHANGED;
        const struct belay_fv v[] = { { .s = in->path, .len = in->path_len }, { .absent = true } };
        struct sysev *e = sysevs_add(c->s, k, in->path, in->path_len, 0, k == FK_CRON_SCRIPT_REMOVED ? SYS_REMOVED : SYS_ADDED,
                                     sys_prov(in), v, 2);
        sysevs_owner(c->s, e, 1, in->path, in->path_len);
        not_run(c, in, kind, root);
        return done(c);
    }

    if (kind == C_CROND) not_run(c, in, kind, root);
    if (strcmp(in->outcome, "metadata_only") == 0) return done(c);      /* the content is the same */
    struct sysfile f;
    if (!sys_read(in, &f)) return c->failed ? BELAY_INTERP_ERROR : sys_cannot(c->s, in);
    size_t bl;
    const char *base = sys_base(in->path, in->path_len, &bl, NULL);
    const struct str spool_user = { base, bl };
    struct cside sd[2];
    memset(sd, 0, sizeof sd);
    int rc = 0;
    for (int k = 0; k < 2 && rc == 0; k++)
        if (f.have[k]) rc = parse((const char *)f.buf[k], f.len[k], kind == C_SPOOL ? &spool_user : NULL, &sd[k]);
    enum belay_interp_result r = BELAY_INTERP_DECLINE;
    if (rc == 1) {
        r = sys_cannot(c->s, in);
    } else if (rc == -1 || sys_lines_diff(sd[0].jk, sd[0].nj, sd[1].jk, sd[1].nj) == -1 || env_events(c, in, sd) == -1) {
        c->failed = true;
    } else {
        for (int k = 0; k < 2; k++)
            for (size_t i = 0; i < sd[k].nj; i++)
                if (sd[k].jk[i].only) job_event(c, in, &sd[k], &sd[k].j[i], k == 0 ? SYS_REMOVED : SYS_ADDED);
    }
    side_free(&sd[0]);
    side_free(&sd[1]);
    sys_free(&f);
    return c->failed || sysevs_failed(c->s) ? BELAY_INTERP_ERROR : r;
}

/* ---- SC-2: is the package cron installed, by the same capture's dpkg database ---- */

struct found { bool seen, installed; };

static int cron_stanza(const struct stanza_pkg *p, void *ctx) {
    struct found *fd = ctx;
    if (fd->seen || p->package_len != 4 || memcmp(p->package, "cron", 4) != 0) return 0;
    fd->seen = true;                            /* a key given twice keeps its first stanza, as dpkg.c reads it */
    const char *s = p->status, *e = s != NULL ? s + p->status_len : NULL;
    for (int word = 0; s != NULL && word < 3; word++) {         /* want, error flag, state */
        while (s < e && sys_blank(*s)) s++;
        const char *w = s;
        while (s < e && !sys_blank(*s)) s++;
        if (word == 2) fd->installed = (size_t)(s - w) == 9 && memcmp(w, "installed", 9) == 0;
    }
    return 0;
}

/* Never assumed: a status that is not a file, has no copy that can be read,
 * or does not parse whole says nothing, and nothing is said of validity. */
static int status_seen(void *ctx, const struct belay_entry *e) {
    struct root *r = ctx;
    unsigned char *buf = NULL;
    size_t len = 0;
    if (e->type != BELAY_T_REG ||
        stored_read_entry(belay_lookup_content(r->c->lk), e, CRON_STATUS_MAX, &buf, &len) != SW_OK)
        return 0;
    struct found fd = { false, false };
    if (stanza_each((const char *)buf, len, cron_stanza, &fd) == 0) r->cron = fd.installed;
    else belay_err_clear();
    free(buf);
    return 0;
}

static enum belay_interp_result prepare(void *state, struct belay_lookup *lk) {
    struct cron *c = state;
    if (c == NULL) return BELAY_INTERP_ERROR;
    c->lk = lk;
    if (c->asked) return BELAY_INTERP_FINDINGS;
    c->asked = true;
    for (size_t i = 0; i < c->nroots; i++) {
        static const char STATUS[] = "var/lib/dpkg/status";
        char path[4096 + sizeof STATUS];
        struct root *r = &c->roots[i];
        if (r->n > 4096) continue;
        memcpy(path, r->prefix, r->n);
        memcpy(path + r->n, STATUS, sizeof STATUS);
        if (r->n + sizeof STATUS - 1 > 4096) continue;          /* no path of a manifest: nothing is said */
        if (belay_lookup_want(lk, path, r->n + sizeof STATUS - 1, false, status_seen, r) == -1)
            return BELAY_INTERP_ERROR;
    }
    return sysevs_ask_owners(c->s, lk) == -1 ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
}

static enum belay_interp_result end(void *state, struct belay_events *ev) {
    struct cron *c = state;
    if (c == NULL) return BELAY_INTERP_ERROR;
    enum belay_interp_result r = c->failed ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    if (ev != NULL && r == BELAY_INTERP_FINDINGS) {
        for (size_t i = 0; i < sysevs_count(c->s); i++) {
            struct sysev *e = sysevs_at(c->s, i);
            if (e->kind == FK_CRON_FILE_NOT_RUN)
                e->drop = !(e->aux >= 1 && e->aux <= c->nroots && c->roots[e->aux - 1].cron);
        }
        r = sysevs_emit(c->s, ev, c->lk);
    }
    for (size_t i = 0; i < c->nroots; i++) free(c->roots[i].prefix);
    free(c->roots);
    sysevs_free(c->s);
    free(c);
    return r;
}

const struct belay_interp INTERP_CRON = { BELAY_INTERP_CRON, begin, explain, end, prepare };
