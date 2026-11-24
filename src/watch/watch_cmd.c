/*
 *  The `belay watch` commands (docs/cli.md, "watch"; test/expect/watch-v1.md).
 *  step, close and mark run one event under the supervisor (run.c);
 *  summary, receipt and patterns only read, and take no lock.
 */
#define _GNU_SOURCE
#include "watch/watch_cmd.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "belay/error.h"
#include "belay/manifest.h"
#include "cli/cli.h"
#include "cli/cli_internal.h"
#include "cli/docker.h"
#include "cli/delta.h"
#include "util/pattern.h"
#include "watch/ledger.h"
#include "watch/run.h"
#include "watch/sysflag.h"

/* ---- the full receipt ---- */

struct steps { struct wstep *v; size_t n, cap; bool bad; };

static int step_line(void *ctx, const struct jval *line, const char *type) {
    struct steps *s = ctx;
    if (strcmp(type, "step") != 0) return 0;
    if (s->n == s->cap) {
        const size_t c = s->cap ? s->cap * 2 : 64;
        struct wstep *q = realloc(s->v, c * sizeof *q);
        if (q == NULL) { s->bad = true; return 1; }
        s->v = q;
        s->cap = c;
    }
    if (ledger_step(line, &s->v[s->n]) == 0) s->n++;
    return 0;
}

/* LN-14: the files put back and still as at their session's start in the
 * newest checkpoint, each once, by its newest put back */
struct putitem { char session[WATCH_ID_MAX + 1]; struct wput u; long num; };

static int pcmp(const char *a, size_t al, const char *b, size_t bl) {
    const int c = memcmp(a, b, al < bl ? al : bl);
    return c ? c : (al > bl) - (al < bl);
}

static int put_cmp(const void *a, const void *b) {
    const struct putitem *x = a, *y = b;
    return pcmp(x->u.path, x->u.len, y->u.path, y->u.len);
}

static int put_back_section(struct state *st, const struct ledger *l, char (*days)[11], size_t n_days, struct wsb *out) {
    struct putitem *v = NULL;
    size_t n = 0;
    struct wsb cut = { 0 };
    int rc = 0;
    for (size_t d = 0; d < n_days && rc == 0; d++) {         /* oldest first: the newest put back stays */
        struct steps s = { 0 };
        if (ledger_read(l, days[d], 0, step_line, &s) != 0 || s.bad) rc = -1;
        for (size_t i = 0; i < s.n && rc == 0; i++) {
            const struct wstep *w = &s.v[i];
            if (w->puts_cut > 0)
                wsb_f(&cut, "  and %llu more put back at step %ld\n", (unsigned long long)w->puts_cut, w->num);
            for (size_t j = 0; j < w->n_puts && rc == 0; j++) {
                size_t k = 0;
                while (k < n && !(strcmp(v[k].session, w->session) == 0 && v[k].u.len == w->puts[j].len &&
                                  memcmp(v[k].u.path, w->puts[j].path, w->puts[j].len) == 0))
                    k++;
                if (k == n) {
                    struct putitem *q = realloc(v, (n + 1) * sizeof *q);
                    if (q == NULL) { rc = -1; break; }
                    v = q;
                    n++;
                } else {
                    free(v[k].u.path);
                }
                snprintf(v[k].session, sizeof v[k].session, "%s", w->session);
                v[k].u = w->puts[j];
                v[k].num = w->num;
                if ((v[k].u.path = malloc(w->puts[j].len)) == NULL) { v[k].u.len = 0; rc = -1; break; }
                memcpy(v[k].u.path, w->puts[j].path, w->puts[j].len);
            }
        }
        for (size_t i = 0; i < s.n; i++) wstep_free(&s.v[i]);
        free(s.v);
    }
    if (rc == -1) belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
    /* the newest checkpoint, when it is still the one the record names; else nothing is said */
    struct checkpoint *list = NULL;
    size_t nl = 0;
    bool kept = false;
    if (rc == 0 && (n > 0 || cut.n > 0) && l->st.cursor > 0 && state_list(st, &list, &nl) == 0)
        for (size_t i = 0; i < nl; i++) kept |= list[i].id == l->st.cursor && list[i].created_ns == l->st.cursor_ns;
    free(list);
    struct manifest_file mf = { .temporary = false };
    struct belay_manifest_reader *r = NULL;
    if (kept && state_check_manifest(st, l->st.cursor) == 0 && manifest_acquire(st, l->st.cursor, &mf) == 0 &&
        belay_manifest_open(mf.path, &r) == 0) {
        bool many = false;
        for (size_t i = 1; i < n; i++) many |= strcmp(v[i].session, v[0].session) != 0;
        qsort(v, n, sizeof *v, put_cmp);
        struct wsb lines = { 0 };
        static struct belay_entry e;
        int got = belay_manifest_next(r, &e);
        for (size_t i = 0; i < n; i++) {
            const struct putitem *p = &v[i];
            while (got == 1 && pcmp(e.path, e.path_len, p->u.path, p->u.len) < 0) got = belay_manifest_next(r, &e);
            const bool same = got == 1 && e.path_len == p->u.len && memcmp(e.path, p->u.path, p->u.len) == 0 &&
                              e.type == BELAY_T_REG && e.has_hash && !e.unverified && !e.unstable && !e.writer_open &&
                              e.size == p->u.size && strcmp(e.sha256_hex, p->u.sha) == 0;
            if (!same) continue;                /* changed again: an ordinary change by the end */
            char *shown = receipt_escaped(p->u.path, p->u.len);
            if (p->u.k > 0) wsb_f(&lines, "  %s: changed at step %ld, as at the start again at step %ld", shown ? shown : "?", p->u.k, p->num);
            else wsb_f(&lines, "  %s: as at the start again at step %ld", shown ? shown : "?", p->num);
            if (many) wsb_f(&lines, " in session %s", p->session);
            wsb_f(&lines, "\n");
            free(shown);
        }
        if (lines.n > 0 || cut.n > 0) wsb_f(out, "\nput back\n%s%s", lines.p != NULL ? lines.p : "", cut.p != NULL ? cut.p : "");
        out->bad |= lines.bad || cut.bad;
        free(lines.p);
    }
    belay_err_clear();
    belay_manifest_close(r);
    manifest_release(&mf);
    for (size_t i = 0; i < n; i++) free(v[i].u.path);
    free(v);
    free(cut.p);
    return rc;
}

int watch_receipt(const char *scope, bool all, struct wsb *out, size_t *n_steps) {
    struct scope sc;
    struct state st;
    struct ledger l;
    st.dir_fd = st.cp_fd = st.lock_fd = -1;
    l.dfd = -1;
    *n_steps = 0;
    char (*days)[11] = NULL;
    size_t n_days = 0;
    int rc = -1;
    if (scope_resolve(scope, &sc) == -1 || state_open(&sc, false, &st, NULL) == -1 || ledger_open(&st, false, &l) == -1 ||
        ledger_days(&l, &days, &n_days) == -1)
        goto out;
    char *shown = receipt_escaped(sc.path, strlen(sc.path));
    wsb_f(out, "belay receipt  %s\n", shown != NULL ? shown : "");
    free(shown);
    const size_t head = out->n;
    rc = put_back_section(&st, &l, days, n_days, out);
    for (size_t d = n_days; d-- > 0 && rc == 0;) {
        struct steps s = { 0 };
        if (ledger_read(&l, days[d], 0, step_line, &s) != 0 || s.bad) {
            if (s.bad) belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
            rc = -1;
        }
        for (size_t i = s.n; i-- > 0 && rc == 0;) {             /* newest first */
            const struct wstep *w = &s.v[i];
            if (w->sec_len == 0 && w->n_trouble == 0) continue;
            (*n_steps)++;
            size_t len = 0;
            char *text = w->sec_len > 0 ? ledger_section_read(&l, w, &len) : NULL, *again = NULL;
            int r = 1;
            if (all && text != NULL && strstr(text, "\n  git bookkeeping: ") != NULL &&    /* LN-10a */
                (r = watch_section_all(&st, w, &again, &len)) == -1)
                rc = -1;
            if (again != NULL) {
                wsb_f(out, "\n%s", again);
            } else if (text != NULL) {
                wsb_f(out, "\n%s", text);
                if (r == 1 && all && strstr(text, "\n  git bookkeeping: ") != NULL)
                    wsb_f(out, "  .git/ as recorded: checkpoint %ld's diff from %ld is no longer kept\n", w->to, w->from);
            } else {
                char when[32];
                const time_t t = (time_t)(w->ns / 1000000000LL);
                struct tm tm;
                gmtime_r(&t, &tm);
                strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%SZ", &tm);
                wsb_f(out, "\n==== %s  session %s\n", when, w->session);
                if (w->sec_len > 0) wsb_f(out, "this step's section is missing\n");     /* TL-13 */
            }
            free(text);
            free(again);
            for (size_t k = 0; k < w->n_trouble; k++) wsb_f(out, "  %s\n", w->trouble[k]);
        }
        for (size_t i = 0; i < s.n; i++) wstep_free(&s.v[i]);
        free(s.v);
    }
    if (rc == 0 && out->n == head) wsb_f(out, "\nnothing recorded for this directory yet\n");
out:
    free(days);
    ledger_close(&l);
    state_close(&st);
    return rc;
}

int watch_receipt_file(const char *scope, const char *docker, const struct wsb *text, char *path, size_t cap) {
    struct scope sc;
    struct state st;
    struct ledger l;
    st.dir_fd = st.cp_fd = st.lock_fd = -1;
    l.dfd = -1;
    int rc = -1;
    if (scope_resolve_in(docker, scope, &sc) == 0 && state_open(&sc, false, &st, NULL) == 0 && ledger_open(&st, false, &l) == 0) {
        if (l.dfd == -1) {
            belay_err_set(BELAY_ERR_INVALID, 0, "nothing recorded for %s yet", sc.path);
        } else {
            /* the file's own path is its second line */
            snprintf(path, cap, "%s/receipt.txt", l.dir);
            const char *nl = text->p != NULL ? strchr(text->p, '\n') : NULL;
            struct wsb b = { 0 };
            if (nl != NULL) wsb_f(&b, "%.*s\n%s\n%s", (int)(nl - text->p), text->p, path, nl + 1);
            if (nl == NULL || b.bad) belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
            else rc = state_write_whole(l.dfd, "receipt.txt", b.p, b.n, path);
            free(b.p);
        }
    }
    ledger_close(&l);
    state_close(&st);
    return rc;
}

/* ---- patterns ---- */

static void limits_text(struct wsb *b, const struct brow *r) {
    static const struct { unsigned bit; const char *text; } L[] = {
        { BR_FILE, "not a directory" }, { BR_DEPS, "not in a dependency" }, { BR_NEWDIR, "not in a new directory" },
        { BR_NOTE_MOD, "noted when modified" }, { BR_NOTE, "noted" },
    };
    bool any = false;
    for (size_t i = 0; i < sizeof L / sizeof L[0]; i++)
        if (r->limits & L[i].bit) { wsb_f(b, "%s%s", any ? "; " : "", L[i].text); any = true; }
    if (r->except != NULL) { wsb_f(b, "%sexcept %s", any ? "; " : "", r->except); any = true; }
    if (r->except2 != NULL) { wsb_f(b, "%sexcept %s", any ? "; " : "", r->except2); any = true; }
    if (!any) wsb_f(b, "--");
}

static int cmd_patterns(const char *scope, bool entries, FILE *out, FILE *err) {
    struct scope sc;
    struct state st;
    struct ledger l;
    st.dir_fd = st.cp_fd = st.lock_fd = -1;
    l.dfd = -1;
    struct dtlist list = { 0 };
    bool have_list = false;
    size_t *user = NULL, *rows = calloc(flag_n_rows, sizeof *rows);
    struct manifest_file mf = { .temporary = false };
    struct belay_manifest_reader *r = NULL;
    struct checkpoint *cps = NULL;
    size_t n_cps = 0;
    int rc = 0;
    if (scope_resolve(scope, &sc) == -1) { cli_err_line(err); belay_err_clear(); rc = EXIT_REFUSED; goto out; }
    if (rows == NULL || state_open(&sc, false, &st, NULL) == -1 || ledger_open(&st, false, &l) == -1) {
        if (rows == NULL) belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        rc = cli_failed(err);
        goto out;
    }
    if (l.st.list[0] != '\0') {
        size_t n;
        char why[96], *b = ledger_list_read(&l, l.st.list, &n);
        have_list = b != NULL && dtlist_parse(b, n, &list, why, sizeof why) == 0;
        free(b);
    }
    if (have_list && (user = calloc(list.n + 1, sizeof *user)) == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        rc = cli_failed(err);
        goto out;
    }
    /* counted over the checkpoint the next step diffs against, else the newest */
    long id = l.st.cursor;
    if (st.cp_fd != -1 && (id == 0 || state_checkpoint_exists(&st, id) != 1)) {
        belay_err_clear();
        if (state_list(&st, &cps, &n_cps) == -1) { rc = cli_failed(err); goto out; }
        id = n_cps > 0 ? cps[n_cps - 1].id : 0;
    }
    struct flagctx fx = { .lists = { have_list ? &list : NULL, NULL } };
    if (id != 0) {
        if (manifest_acquire(&st, id, &mf) == -1 || belay_manifest_open(mf.path, &r) == -1) { rc = cli_failed(err); goto out; }
        static struct belay_entry e;
        int got;
        while ((got = belay_manifest_next(r, &e)) == 1) {
            const bool dir = e.type == BELAY_T_DIR;
            for (size_t i = 0; have_list && i < list.n; i++)
                if (flag_user_match(list.pat[i], list.len[i], e.path, e.path_len) != 0) user[i]++;
            for (size_t i = 0; i < flag_n_rows; i++)
                if (flag_row_applies(&flag_rows[i], e.path, e.path_len, dir)) rows[i]++;
            if (entries) {
                enum wkind kind;
                const char *reason;
                bool note;
                if (flag_path(&fx, e.path, e.path_len, dir, &kind, &reason, &note)) {
                    char *shown = receipt_escaped(e.path, e.path_len);
                    fprintf(out, "%s\t%s\t%s\t%s\n", wkind_name(kind), note ? "note" : "flag", reason, shown != NULL ? shown : "?");
                    free(shown);
                }
            }
        }
        if (got == -1) { rc = cli_failed(err); goto out; }
    }
    if (entries) goto out;
    if (!have_list) {
        fputs(l.st.list_trouble[0] != '\0' ? "no don't-touch list in force: " : "no don't-touch list in force", out);
        fputs(l.st.list_trouble, out);
        fputc('\n', out);
    } else {
        fprintf(out, "don't-touch list in force: %zu pattern%s (sha256 %.12s)\n", list.n, list.n == 1 ? "" : "s", l.st.list);
        for (size_t i = 0; i < list.n; i++) {
            fprintf(out, "  %zu\t", user[i]);
            receipt_fputs(out, list.pat[i]);
            fputs(id != 0 && user[i] == 0 ? "\tmatches nothing\n" : "\n", out);
        }
    }
    if (id == 0) fputs("no checkpoint of the directory yet: nothing to count\n", out);
    else fprintf(out, "counted over checkpoint %ld\n", id);
    fprintf(out, "built-in list: %zu rows\n", flag_n_rows);
    for (size_t i = 0; i < flag_n_rows; i++) {
        struct wsb b = { 0 };
        limits_text(&b, &flag_rows[i]);
        fprintf(out, "  %zu\t%s\t%s\t%s\n", rows[i], flag_rows[i].pattern, flag_rows[i].label, b.p != NULL ? b.p : "--");
        free(b.p);
    }
out:
    belay_manifest_close(r);
    manifest_release(&mf);
    free(cps);
    free(user);
    free(rows);
    if (have_list) dtlist_free(&list);
    ledger_close(&l);
    state_close(&st);
    return rc;
}

/* `watch patterns --system` (WS-8a, WS-9): the roots as the machine is now,
 * with their classes and how many entries of the newest checkpoint each
 * holds (a longer root wins), the directories not read, the homes left out
 * and why, then the flag list with the entries each path row matches. */
static int cmd_patterns_system(const char *scope, const char *docker, FILE *out, FILE *err) {
    struct scope sc;
    struct state st;
    st.dir_fd = st.cp_fd = st.lock_fd = -1;
    struct belay_system_roots sr = { 0 };
    struct manifest_file mf = { .temporary = false };
    struct belay_manifest_reader *r = NULL;
    struct checkpoint *cps = NULL;
    size_t n_cps = 0, *per = NULL, *rows = NULL;
    int rc = 0;
    if (scope_resolve_in(docker, scope, &sc) == -1) { cli_err_line(err); belay_err_clear(); return EXIT_REFUSED; }
    if ((docker != NULL ? docker_system_roots(docker, &sr) : belay_system_roots(sc.path, &sr)) == -1 ||
        state_open(&sc, false, &st, NULL) == -1 ||
        (per = calloc(sr.n_roots + 1, sizeof *per)) == NULL || (rows = calloc(sysflag_n_rows, sizeof *rows)) == NULL) {
        if (belay_err_code() == BELAY_OK) belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        rc = cli_failed(err);
        goto out;
    }
    long id = 0;
    if (st.cp_fd != -1) {
        if (state_list(&st, &cps, &n_cps) == -1) { rc = cli_failed(err); goto out; }
        id = n_cps > 0 ? cps[n_cps - 1].id : 0;
    }
    if (id != 0) {
        if (manifest_acquire(&st, id, &mf) == -1 || belay_manifest_open(mf.path, &r) == -1) { rc = cli_failed(err); goto out; }
        static struct belay_entry e;
        int got;
        while ((got = belay_manifest_next(r, &e)) == 1) {
            size_t best = sr.n_roots, bl = 0;
            for (size_t i = 0; i < sr.n_roots; i++) {
                const size_t n = strlen(sr.roots[i].path);
                if (n > bl && e.path_len >= n && memcmp(e.path, sr.roots[i].path, n) == 0 && (e.path_len == n || e.path[n] == '/')) {
                    best = i;
                    bl = n;
                }
            }
            per[best]++;
            for (size_t i = 0; i < sysflag_n_rows; i++) {
                const struct sysrow *w = &sysflag_rows[i];
                if (pattern_match(w->pattern, strlen(w->pattern), e.path, e.path_len, PATTERN_DOTS | PATTERN_NOCASE) != 0 &&
                    (w->except == NULL || pattern_match(w->except, strlen(w->except), e.path, e.path_len, PATTERN_DOTS) == 0))
                    rows[i]++;
            }
        }
        if (got == -1) { rc = cli_failed(err); goto out; }
    }
    if (id == 0) fputs("no checkpoint of the system yet: nothing to count\n", out);
    else fprintf(out, "counted over checkpoint %ld\n", id);
    fprintf(out, "roots: %zu\n", sr.n_roots);
    for (size_t i = 0; i < sr.n_roots; i++) {
        fprintf(out, "  %-8s  ", sr.roots[i].cls == BELAY_ROOT_CONTENT ? "content" : "metadata");
        receipt_fputs(out, sr.roots[i].path);
        if (id != 0) fprintf(out, "  %zu entr%s", per[i], per[i] == 1 ? "y" : "ies");
        fputc('\n', out);
    }
    fprintf(out, "not read: every other child of /, and %zu directories under the roots\n", sr.n_not_read);
    for (size_t i = 0; i < sr.n_not_read; i++) fprintf(out, "  %s\n", sr.not_read[i]);
    fprintf(out, "homes left out: %zu\n", sr.n_left_out);
    for (size_t i = 0; i < sr.n_left_out; i++) {
        fputs("  ", out);
        receipt_fputs(out, sr.left_out[i]);
        fputc('\n', out);
    }
    fprintf(out, "flag list (watch-system.md): %zu path rows\n", sysflag_n_rows);
    for (size_t i = 0; i < sysflag_n_rows; i++) {
        const struct sysrow *w = &sysflag_rows[i];
        fprintf(out, "  %zu\t%s\t%s\t%s%s%s\n", rows[i], w->pattern, w->label, w->id, w->except ? "; except " : "",
                w->except ? w->except : "");
    }
    fprintf(out, "and rows that read events, fields and runtime records: %zu\n", sysflag_n_event_rows);
    for (size_t i = 0; i < sysflag_n_event_rows; i++)
        fprintf(out, "  %s\t%s\n", sysflag_event_rows[i][0], sysflag_event_rows[i][1]);
out:
    belay_manifest_close(r);
    manifest_release(&mf);
    free(cps);
    free(per);
    free(rows);
    belay_system_roots_free(&sr);
    state_close(&st);
    return rc;
}

/* ---- the command line ---- */

static bool number(const char *s, long *v, long max) {
    const size_t n = s == NULL ? 0 : strlen(s);
    if (n == 0 || n > 6 || strspn(s, "0123456789") != n) return false;
    *v = strtol(s, NULL, 10);
    return *v <= max;
}

int cmd_watch(int argc, char **argv, FILE *out, FILE *err) {
    if (argc < 3) return cli_usage(err, "watch needs a command: start, step, close, mark, summary, receipt, stop or patterns");
    const char *sub = argv[2];
    const char *scope = NULL, *session = NULL, *begin = NULL, *finish = NULL, *agent = NULL, *name = NULL, *since = NULL;
    const char *system_root = NULL, *docker = NULL;
    bool first_ok = false, all = false, path = false, entries = false, system = false;
    long deadline = WATCH_DEADLINE_S, max_lines = 0;
    struct wsb ids = { 0 };
    char why[256];
    int rc = 0;
    for (int i = 3; i < argc; i++) {
        const char *a = argv[i];
        const char **val = NULL;
        if (!strcmp(a, "--first-ok")) { first_ok = true; continue; }
        if (!strcmp(a, "--all")) { all = true; continue; }
        if (!strcmp(a, "--path")) { path = true; continue; }
        if (!strcmp(a, "--entries")) { entries = true; continue; }
        if (!strcmp(a, "--system")) {                   /* watch-system WS-1 */
            if (system) { rc = cli_usage(err, "--system given twice"); goto done; }
            system = true;
            continue;
        }
        if (!strcmp(a, "--scope")) val = &scope;
        else if (!strcmp(a, "--session")) val = &session;
        else if (!strcmp(a, "--begin")) val = &begin;
        else if (!strcmp(a, "--finish")) val = &finish;
        else if (!strcmp(a, "--agent")) val = &agent;
        else if (!strcmp(a, "--name")) val = &name;
        else if (!strcmp(a, "--since")) val = &since;
        else if (!strcmp(a, "--system-root")) val = &system_root;      /* cli_system_scope */
        else if (!strcmp(a, "--docker")) val = &docker;                 /* WS-1: with --system */
        else if (strcmp(a, "--id") && strcmp(a, "--deadline") && strcmp(a, "--max-lines")) {
            snprintf(why, sizeof why, "unknown option %.200s", a);
            rc = cli_usage(err, why);
            goto done;
        }
        if (i + 1 >= argc) {
            snprintf(why, sizeof why, "%s needs a value", a);
            rc = cli_usage(err, why);
            goto done;
        }
        const char *v = argv[++i];
        if (val != NULL) {
            if (*val != NULL) {
                snprintf(why, sizeof why, "%s given twice", a);
                rc = cli_usage(err, why);
                goto done;
            }
            *val = v;
        } else if (!strcmp(a, "--id")) {
            if (!ledger_id_valid(v)) { rc = cli_usage(err, "--id needs a call's id: printable, no spaces, at most 96 bytes"); goto done; }
            wsb_f(&ids, "%s%s", ids.n ? " " : "", v);
        } else if (!strcmp(a, "--deadline") ? !number(v, &deadline, 3600) || deadline == 0 : !number(v, &max_lines, 999999)) {
            snprintf(why, sizeof why, "%s needs a number", a);
            rc = cli_usage(err, why);
            goto done;
        }
    }
    if (docker != NULL && !system) { rc = cli_usage(err, "--docker on watch is a system watch's: give --system"); goto done; }
    if (system || system_root != NULL) {
        if ((rc = cli_system_scope(system, system_root, &scope, docker, err)) != 0) goto done;
        system = true;
    }
    if (scope == NULL) { rc = cli_usage(err, "--scope DIR is required"); goto done; }
    const bool is_step = !strcmp(sub, "step"), is_close = !strcmp(sub, "close"), is_mark = !strcmp(sub, "mark"),
               is_summary = !strcmp(sub, "summary"), is_start = !strcmp(sub, "start"), is_stop = !strcmp(sub, "stop");
    if ((is_start || is_stop) && !system) { rc = cli_usage(err, "start and stop are a system watch's: give --system"); goto done; }
    if (!strcmp(sub, "patterns")) { rc = system ? cmd_patterns_system(scope, docker, out, err) : cmd_patterns(scope, entries, out, err); goto done; }
    if (system && (is_start || is_stop || !strcmp(sub, "receipt"))) {
        /* WS-2, WS-3, K12: a walk under the lock, no time limit, a line on standard error every 10 s */
        if (session != NULL && !ledger_id_valid(session)) { rc = cli_usage(err, "--session needs an id: printable, no spaces, at most 96 bytes"); goto done; }
        struct wreq q = { .scope = scope, .session = session != NULL ? session : "system", .agent = "", .first_ok = true,
                          .deadline_s = 0, .words = { "call", "", "" }, .system = true, .progress = err,
                          .docker = docker, .all = all };
        if (is_start) {
            fputs(CLI_SYSTEM_EXPERIMENTAL "\n", err);          /* WS-0: the first line printed */
            fflush(err);
            q.ops[q.n_ops++] = (struct wop){ WOP_START, NULL, 0 };
        }
        q.ops[q.n_ops++] = (struct wop){ WOP_STEP, NULL, WSTEP_PLAIN };
        if (!is_start) q.ops[q.n_ops++] = (struct wop){ WOP_RECEIPT, NULL, is_stop ? 1 : 0 };
        struct wsb text = { 0 };
        if (!is_start) wsb_f(&text, CLI_SYSTEM_EXPERIMENTAL "\n");      /* WS-0: the receipt's first line */
        const int wr = watch_run(&q, &text);
        char file[PATH_MAX + 120];
        if (text.bad) {
            fputs("belay: out of memory\n", err);
            rc = EXIT_FAILED;
        } else if (wr == 0 && path && !is_start) {
            if (watch_receipt_file(scope, docker, &text, file, sizeof file) == -1) rc = cli_failed(err);
            else fprintf(out, "%s\n", file);
        } else {
            long lines = 0;
            const char *p = text.p != NULL ? text.p : "";
            while (*p != '\0' && (max_lines == 0 || lines < max_lines)) {
                const char *nl = strchr(p, '\n');
                const size_t n = nl != NULL ? (size_t)(nl - p) + 1 : strlen(p);
                fwrite(p, 1, n, out);
                p += n;
                lines++;
            }
            if (*p != '\0') fputs("... the rest: belay watch receipt without --max-lines\n", out);
        }
        free(text.p);
        if (rc == 0) rc = wr == 0 ? EXIT_DONE : wr == 3 ? EXIT_REFUSED : EXIT_FAILED;
        goto done;
    }
    if (!strcmp(sub, "receipt")) {
        struct wsb text = { 0 };
        size_t n_steps;
        char file[PATH_MAX + 120];
        if (watch_receipt(scope, all, &text, &n_steps) == -1 || text.bad) {
            if (text.bad) belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
            rc = cli_failed(err);
        } else if (path) {
            if (watch_receipt_file(scope, docker, &text, file, sizeof file) == -1) rc = cli_failed(err);
            else fprintf(out, "%s\n", file);
        } else {
            long lines = 0;
            const char *p = text.p;
            while (*p != '\0' && (max_lines == 0 || lines < max_lines)) {
                const char *nl = strchr(p, '\n');
                const size_t n = nl != NULL ? (size_t)(nl - p) + 1 : strlen(p);
                fwrite(p, 1, n, out);
                p += n;
                lines++;
            }
            if (*p != '\0') fputs("... the rest: belay watch receipt without --max-lines\n", out);
        }
        free(text.p);
        goto done;
    }
    if (!is_step && !is_close && !is_mark && !is_summary) {
        snprintf(why, sizeof why, "unknown watch command %.200s", sub);
        rc = cli_usage(err, why);
        goto done;
    }
    if (!ledger_id_valid(session)) { rc = cli_usage(err, "--session needs an id: printable, no spaces, at most 96 bytes"); goto done; }
    if ((begin != NULL && !ledger_id_valid(begin)) || (finish != NULL && !ledger_id_valid(finish)) ||
        (agent != NULL && !ledger_id_valid(agent)) || (name != NULL && !ledger_id_valid(name)) ||
        (since != NULL && !ledger_id_valid(since))) {
        rc = cli_usage(err, "an id or a name is printable, without spaces, at most 96 bytes");
        goto done;
    }
    struct wreq q = { .scope = scope, .session = session, .agent = agent != NULL ? agent : "", .first_ok = first_ok,
                      .deadline_s = deadline, .words = { "call", "", "" }, .system = system, .docker = docker };
    char span[WATCH_ID_MAX + 16];
    if (is_step) {
        if (begin != NULL && finish != NULL) { rc = cli_usage(err, "--begin or --finish, not both"); goto done; }
        q.ops[q.n_ops++] = (struct wop){ WOP_STEP, begin != NULL ? begin : finish,
                                         begin != NULL ? WSTEP_BEGIN : finish != NULL ? WSTEP_FINISH : WSTEP_PLAIN };
    } else if (is_close) {
        if (all == (ids.n > 0)) { rc = cli_usage(err, "close needs --id ID (once or more) or --all"); goto done; }
        if (ids.bad) { rc = cli_usage(err, "out of memory"); goto done; }
        q.ops[q.n_ops++] = all ? (struct wop){ WOP_CLOSE_SESSION, NULL, 0 } : (struct wop){ WOP_CLOSE, ids.p, 0 };
    } else if (is_mark) {
        if (name == NULL) { rc = cli_usage(err, "mark needs --name NAME"); goto done; }
        q.ops[q.n_ops++] = (struct wop){ WOP_MARK, name, 0 };
    } else {
        if (since == NULL) { rc = cli_usage(err, "summary needs --since NAME, a marker"); goto done; }
        snprintf(span, sizeof span, "since %s", since);
        q.words.span = span;
        struct wsb lines = { 0 };
        if (watch_summary(&q, since, &lines) == -1 || lines.bad) {
            if (lines.bad) belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
            rc = cli_failed(err);
        } else {
            fputs(lines.p != NULL ? lines.p : "", out);
        }
        free(lines.p);
        goto done;
    }
    struct wsb lines = { 0 };
    const int wr = watch_run(&q, &lines);
    fputs(lines.p != NULL && !lines.bad ? lines.p : "", out);
    free(lines.p);
    rc = wr == 0 ? EXIT_DONE : wr == 3 ? EXIT_REFUSED : EXIT_FAILED;
done:
    free(ids.p);
    return rc;
}
