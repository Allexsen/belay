/*
 *  The sudoers interpreter (test/expect/system-interpreters.md SS-1 to SS-5;
 *  finding-kinds.md, sudo_*): the logical lines `etc/sudoers` and the files
 *  directly in `etc/sudoers.d` gained and lost, as written. It states the
 *  text of the files and never what anyone may run (SS-5): host lists,
 *  later rules, `Defaults` and aliases decide that, in sudo.
 *
 *  A logical line (SS-1) is physical lines joined at a trailing backslash.
 *  A comment -- a physical line whose first non-blank is `#` not followed by
 *  `include`, `includedir` or a digit -- and a blank line are nothing; a
 *  comment ends at its line's end whatever its last byte, so the line after
 *  it is never hidden behind it. Lines are compared trimmed, as multisets
 *  (SI-3): a changed line is one removed and one added, a moved one nothing.
 *
 *  A user specification of the plain form (SS-2) is a rule with its parts
 *  as written; any other line is given whole. The form is read
 *  conservatively -- a line that is not surely of it is a line, never a
 *  rule split wrongly:
 *      WHO HOSTS = [(RUNAS)] [TAG: ...] COMMANDS
 *  with exactly one `=` outside double quotes and not escaped (so no second
 *  specification, and no option such as `CWD=`); WHO the first word, not
 *  `Defaults...`, an alias keyword or an include; HOSTS not empty; a runas
 *  list only right after the `=`, closed, and no other unescaped `(` after
 *  it; tags upper-case words (`A-Z`, `_`) each followed by `:`; COMMANDS not
 *  empty, and every unescaped `:` in them a later tag's (`, PASSWD: ...`).
 *
 *  The name rule of sudoers.d (SS-3) is said of a file that is there after
 *  and is a path of the diff; nothing is said from a mode (SS-4). Never
 *  silent (SI-2): a side that cannot be read is could_not_interpret, on the
 *  record and as an event.
 */
#include "builtins.h"
#include "sysev.h"

#include "belay/manifest.h"

#include <stdlib.h>
#include <string.h>

struct sudoers { struct sysevs *ev; };

static void *begin(void) {
    struct sudoers *s = calloc(1, sizeof *s);
    if (s != NULL && (s->ev = sysevs_new()) == NULL) { free(s); s = NULL; }
    return s;
}

/* ---- logical lines ---- */

static bool starts(const char *s, const char *e, const char *word) {
    const size_t n = strlen(word);
    return (size_t)(e - s) >= n && memcmp(s, word, n) == 0;
}

/* SS-1, of one physical line. */
static bool is_comment(const char *s, const char *e) {
    while (s < e && sys_blank(*s)) s++;
    if (s == e || *s != '#') return false;
    s++;
    return !(starts(s, e, "include") || (s < e && *s >= '0' && *s <= '9'));
}

/* One side's logical lines, trimmed, each at its first physical line:
 * malloc'd into *out (and *text, which they point into), *n of them.
 * 0, or -1 (memory). */
static int logical(const char *buf, size_t len, struct sysline **out, size_t *n, char **text) {
    *out = NULL;
    *n = 0;
    *text = NULL;
    bool oom;
    size_t np;
    struct sysline *phys = sys_lines(buf, len, &np, &oom);
    if (oom) return -1;
    if (np == 0) return 0;
    char *t = malloc(len + 1);
    struct sysline *v = malloc(np * sizeof *v);
    if (t == NULL || v == NULL) { free(t); free(v); free(phys); return -1; }
    size_t w = 0, count = 0;
    for (size_t i = 0; i < np; ) {
        const uint32_t first = phys[i].line;
        if (is_comment(phys[i].s, phys[i].s + phys[i].n)) { i++; continue; }
        const size_t start = w;
        for (;;) {                               /* joined at each trailing backslash */
            const struct sysline *p = &phys[i++];
            const bool more = p->n > 0 && p->s[p->n - 1] == '\\';
            const size_t take = more ? p->n - 1 : p->n;
            if (take) memcpy(t + w, p->s, take);
            w += take;
            if (!more || i == np) break;
        }
        const char *s = t + start, *e = t + w;
        sys_trim(&s, &e);
        if (s == e) continue;                    /* blank */
        v[count++] = (struct sysline){ .s = s, .n = (size_t)(e - s), .line = first };
    }
    free(phys);
    *out = v;
    *n = count;
    *text = t;
    return 0;
}

/* ---- the plain form (SS-2) ---- */

#define TAGS_KEPT (FINDING_LIST_MAX + 1)        /* one past what a list holds: the core refuses it (E9) */

struct rule {
    const char *who, *hosts, *runas, *commands;
    size_t who_len, hosts_len, runas_len, commands_len;
    struct belay_fv tags[TAGS_KEPT];
    size_t ntags;
};

static bool tag_char(char c) { return (c >= 'A' && c <= 'Z') || c == '_'; }

/* The length of the tag word at s (`NAME:`, the colon not counted), or 0. */
static size_t tag_at(const char *s, const char *e) {
    const char *p = s;
    while (p < e && tag_char(*p)) p++;
    return p > s && p < e && *p == ':' ? (size_t)(p - s) : 0;
}

static bool plain(const char *s, const char *e, struct rule *r) {
    static const char *const NOT_WHO[] = { "Defaults", "User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias",
                                           "Cmd_Alias", "@include", "#include" };
    for (size_t i = 0; i < sizeof NOT_WHO / sizeof NOT_WHO[0]; i++)
        if (starts(s, e, NOT_WHO[i])) return false;
    /* The one `=`: outside double quotes, not escaped. */
    const char *eq = NULL;
    bool quoted = false;
    for (const char *p = s; p < e; p++) {
        if (*p == '\\') { p++; continue; }
        if (*p == '"') quoted = !quoted;
        else if (*p == '=' && !quoted) {
            if (eq != NULL) return false;
            eq = p;
        }
    }
    if (eq == NULL || quoted) return false;
    const char *w = s;
    while (w < eq && !sys_blank(*w)) w++;
    r->who = s;
    r->who_len = (size_t)(w - s);
    const char *hs = w, *he = eq;
    sys_trim(&hs, &he);
    if (r->who_len == 0 || hs == he) return false;
    r->hosts = hs;
    r->hosts_len = (size_t)(he - hs);
    const char *p = eq + 1;
    while (p < e && sys_blank(*p)) p++;
    r->runas = "";
    r->runas_len = 0;
    if (p < e && *p == '(') {
        const char *close = memchr(p, ')', (size_t)(e - p));
        if (close == NULL) return false;
        const char *rs = p + 1, *re = close;
        sys_trim(&rs, &re);
        r->runas = rs;
        r->runas_len = (size_t)(re - rs);
        p = close + 1;
        while (p < e && sys_blank(*p)) p++;
    }
    r->ntags = 0;
    for (size_t tl; (tl = tag_at(p, e)) != 0; ) {
        if (r->ntags < TAGS_KEPT) r->tags[r->ntags++] = (struct belay_fv){ .s = p, .len = tl };
        p += tl + 1;
        while (p < e && sys_blank(*p)) p++;
    }
    if (p == e) return false;
    r->commands = p;
    r->commands_len = (size_t)(e - p);
    /* In the commands: no second runas list, and no colon but a later tag's. */
    for (const char *q = p; q < e; q++) {
        if (*q == '\\') { q++; continue; }
        if (*q == '(') return false;
        if (*q != ':') continue;
        const char *t = q;
        while (t > p && tag_char(t[-1])) t--;
        if (t == q || (t > p && !sys_blank(t[-1]) && t[-1] != ',' && t[-1] != ':')) return false;
    }
    return true;
}

/* ---- explaining one file ---- */

static void line_event(struct sudoers *st, const struct belay_interp_input *in, const struct sysline *l,
                       int rank, bool prov) {
    struct rule r;
    const struct belay_fv path = { .s = in->path, .len = in->path_len }, line = { .s = l->s, .len = l->n };
    if (plain(l->s, l->s + l->n, &r)) {
        const struct belay_fv v[] = { path, { .s = r.who, .len = r.who_len }, { .s = r.hosts, .len = r.hosts_len },
                                      { .s = r.runas, .len = r.runas_len }, { .list = r.tags, .nlist = r.ntags },
                                      { .s = r.commands, .len = r.commands_len }, line };
        sysevs_add(st->ev, rank == SYS_ADDED ? FK_SUDO_RULE_ADDED : FK_SUDO_RULE_REMOVED, in->path, in->path_len,
                   l->line, rank, prov, v, 7);
    } else {
        const struct belay_fv v[] = { path, line };
        sysevs_add(st->ev, rank == SYS_ADDED ? FK_SUDO_LINE_ADDED : FK_SUDO_LINE_REMOVED, in->path, in->path_len,
                   l->line, rank, prov, v, 2);
    }
}

static bool regular(const struct belay_entry *e) { return e != NULL && e->type == BELAY_T_REG; }

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct sudoers *st = state;
    (void)out;
    if (st == NULL) return BELAY_INTERP_ERROR;
    size_t base_len, dir_len;
    const char *base = sys_base(in->abs_path, in->abs_len, &base_len, &dir_len);
    const bool in_d = sys_ends(in->abs_path, dir_len, "/etc/sudoers.d/") && base_len > 0;
    if (!in_d && !sys_ends(in->abs_path, in->abs_len, "/etc/sudoers")) return BELAY_INTERP_DECLINE;
    if (strcmp(in->outcome, "metadata_only") == 0) return BELAY_INTERP_DECLINE;    /* SS-4 */
    if (!regular(in->before) && !regular(in->after)) return BELAY_INTERP_DECLINE;  /* a directory: not a file of sudo's */
    const bool prov = sys_prov(in);

    /* SS-3: the name, of a file that is there after. */
    if (in_d && regular(in->after)) {
        const char *why = memchr(base, '.', base_len) != NULL ? "a . in its name"
                        : base[base_len - 1] == '~' ? "its name ends ~" : NULL;
        if (why != NULL) {
            const struct belay_fv v[] = { { .s = in->path, .len = in->path_len }, { .s = why, .len = strlen(why) } };
            sysevs_add(st->ev, FK_SUDOERS_FILE_NOT_READ_BY_SUDO, in->path, in->path_len, 0, SYS_REMOVED, prov, v, 2);
        }
    }

    struct sysfile f;
    if (!sys_read(in, &f)) return sys_cannot(st->ev, in);
    struct sysline *l[2] = { NULL, NULL };
    size_t n[2] = { 0, 0 };
    char *text[2] = { NULL, NULL };
    bool ok = true;
    for (int k = 0; k < 2 && ok; k++)
        if (f.have[k] && logical((const char *)f.buf[k], f.len[k], &l[k], &n[k], &text[k]) == -1) ok = false;
    if (ok && sys_lines_diff(l[0], n[0], l[1], n[1]) == -1) ok = false;
    for (int k = 0; k < 2 && ok; k++)
        for (size_t i = 0; i < n[k]; i++)
            if (l[k][i].only) line_event(st, in, &l[k][i], k == 0 ? SYS_REMOVED : SYS_ADDED, prov);
    for (int k = 0; k < 2; k++) { free(l[k]); free(text[k]); }
    sys_free(&f);
    if (!ok) return sys_cannot(st->ev, in);      /* memory: this file's lines are not known, and that is said */
    if (sysevs_failed(st->ev)) return BELAY_INTERP_ERROR;
    return BELAY_INTERP_DECLINE;                 /* events only: the record carries nothing of ours */
}

static enum belay_interp_result end(void *state, struct belay_events *ev) {
    struct sudoers *st = state;
    if (st == NULL) return BELAY_INTERP_ERROR;
    const enum belay_interp_result r = ev != NULL ? sysevs_emit(st->ev, ev, NULL) : BELAY_INTERP_FINDINGS;
    sysevs_free(st->ev);
    free(st);
    return r;
}

const struct belay_interp INTERP_SUDOERS = { BELAY_INTERP_SUDOERS, begin, explain, end, NULL };
