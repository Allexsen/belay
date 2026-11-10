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
#include "cli/delta.h"
#include "util/pattern.h"
#include "watch/ledger.h"
#include "watch/run.h"

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

int watch_receipt(const char *scope, struct wsb *out, size_t *n_steps) {
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
    rc = 0;
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
            char *text = w->sec_len > 0 ? ledger_section_read(&l, w, &len) : NULL;
            if (text != NULL) {
                wsb_f(out, "\n%s", text);
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

int watch_receipt_file(const char *scope, const struct wsb *text, char *path, size_t cap) {
    struct scope sc;
    struct state st;
    struct ledger l;
    st.dir_fd = st.cp_fd = st.lock_fd = -1;
    l.dfd = -1;
    int rc = -1;
    if (scope_resolve(scope, &sc) == 0 && state_open(&sc, false, &st, NULL) == 0 && ledger_open(&st, false, &l) == 0) {
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

/* ---- the command line ---- */

static bool number(const char *s, long *v, long max) {
    const size_t n = s == NULL ? 0 : strlen(s);
    if (n == 0 || n > 6 || strspn(s, "0123456789") != n) return false;
    *v = strtol(s, NULL, 10);
    return *v <= max;
}

int cmd_watch(int argc, char **argv, FILE *out, FILE *err) {
    if (argc < 3) return cli_usage(err, "watch needs a command: step, close, mark, summary, receipt or patterns");
    const char *sub = argv[2];
    const char *scope = NULL, *session = NULL, *begin = NULL, *finish = NULL, *agent = NULL, *name = NULL, *since = NULL;
    bool first_ok = false, all = false, path = false, entries = false;
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
        if (!strcmp(a, "--scope")) val = &scope;
        else if (!strcmp(a, "--session")) val = &session;
        else if (!strcmp(a, "--begin")) val = &begin;
        else if (!strcmp(a, "--finish")) val = &finish;
        else if (!strcmp(a, "--agent")) val = &agent;
        else if (!strcmp(a, "--name")) val = &name;
        else if (!strcmp(a, "--since")) val = &since;
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
    if (scope == NULL) { rc = cli_usage(err, "--scope DIR is required"); goto done; }
    const bool is_step = !strcmp(sub, "step"), is_close = !strcmp(sub, "close"), is_mark = !strcmp(sub, "mark"),
               is_summary = !strcmp(sub, "summary");
    if (!strcmp(sub, "patterns")) { rc = cmd_patterns(scope, entries, out, err); goto done; }
    if (!strcmp(sub, "receipt")) {
        struct wsb text = { 0 };
        size_t n_steps;
        char file[PATH_MAX + 120];
        if (watch_receipt(scope, &text, &n_steps) == -1 || text.bad) {
            if (text.bad) belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
            rc = cli_failed(err);
        } else if (path) {
            if (watch_receipt_file(scope, &text, file, sizeof file) == -1) rc = cli_failed(err);
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
                      .deadline_s = deadline, .words = { "call", "", "" } };
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
