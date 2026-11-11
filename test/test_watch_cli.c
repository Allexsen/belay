/*
 *  `belay watch` and `belay hook claude-code` end to end, through cli_main,
 *  on a real directory and a real state directory (test/expect/watch-v1.md;
 *  test/expect/state-retention-watch.md). What a line says is test_watch.c's;
 *  here: that a step is recorded once and only once, whatever kills it and
 *  wherever; that there is always a line; and that prune takes the record
 *  as the pin says.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "cli/cli.h"
#include "cli/cli_internal.h"
#include "cli/state.h"
#include "watch/ledger.h"
#include "watch/run.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RED "\xf0\x9f\x94\xb4"

static char g_dir[256], g_scope[400], g_state[400];
static char *g_out, *g_err;

static int belay_v(int argc, char **argv) {
    free(g_out);
    free(g_err);
    g_out = g_err = NULL;
    size_t on, en;
    FILE *out = open_memstream(&g_out, &on), *err = open_memstream(&g_err, &en);
    const int rc = cli_main(argc, argv, out, err);
    fclose(out);
    fclose(err);
    return rc;
}

/* Runs `belay <args...>` (NULL-terminated); the exit code, output in g_out, g_err. */
static int belay(const char *a0, ...) {
    char *argv[32] = { "belay", (char *)a0 };
    int argc = 2;
    va_list ap;
    va_start(ap, a0);
    const char *a;
    while (argc < 31 && (a = va_arg(ap, const char *)) != NULL) argv[argc++] = (char *)a;
    va_end(ap);
    return belay_v(argc, argv);
}

/* belay watch step --scope <scope> --session S [more...] */
static int step(const char *session, ...) {
    char *argv[32] = { "belay", "watch", "step", "--scope", g_scope, "--session", (char *)session };
    int argc = 7;
    va_list ap;
    va_start(ap, session);
    const char *a;
    while (argc < 31 && (a = va_arg(ap, const char *)) != NULL) argv[argc++] = (char *)a;
    va_end(ap);
    return belay_v(argc, argv);
}

static void sh(const char *fmt, ...) {
    char cmd[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    if (system(cmd) != 0) { /* the assertions say */ }
}

/* What a shell command prints, at most 1 MiB; freed by the next call. */
static const char *out_of(const char *fmt, ...) {
    static char *buf;
    char cmd[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    free(buf);
    buf = calloc(1, 1 << 20);
    FILE *p = popen(cmd, "r");
    if (p != NULL && buf != NULL) {
        const size_t n = fread(buf, 1, (1 << 20) - 1, p);
        buf[n] = '\0';
    }
    if (p != NULL) pclose(p);
    return buf != NULL ? buf : "";
}

static size_t count(const char *hay, const char *needle) {
    size_t n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

#define HAS(hay, needle) \
    do { const char *h_ = (hay); if (h_ == NULL || strstr(h_, (needle)) == NULL) BELAY_FAIL("wanted \"%s\" in:\n%s", (needle), h_ ? h_ : "(null)"); } while (0)
#define HAS_NOT(hay, needle) \
    do { const char *h_ = (hay); if (h_ != NULL && strstr(h_, (needle)) != NULL) BELAY_FAIL("did not want \"%s\" in:\n%s", (needle), h_); } while (0)

static void fresh(void) {
    sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s' '%s' && mkdir -p '%s/src' '%s' && chmod 700 '%s'",
       g_dir, g_scope, g_state, g_scope, g_state, g_state);
    sh("printf 'a\\nb\\n' > '%s/src/x.txt'", g_scope);
    watch_stage_hook = NULL;
    ledger_before_line = NULL;
    watch_clock = NULL;
    watch_second_ms = WATCH_SECOND_S * 1000;
    watch_withhold_go = false;
    prune_between_days = NULL;
    ledger_fail_at = 0;
    ledger_fail_sync_at = 0;
    ledger_fail_dirsync = false;
}

/* A fresh directory with a record: the session's first step made. */
static void started(const char *session) {
    fresh();
    step(session, "--first-ok", NULL);
}

static const char *ledger(void) { return out_of("cat '%s'/scopes/*/watch/ledger-*.ndjson 2>/dev/null", g_state); }
static const char *receipt(void) {
    belay("watch", "receipt", "--scope", g_scope, NULL);
    return g_out;
}

static int64_t g_now;
static int64_t fixed_clock(void) { return g_now; }
#define DAY1 1793534400LL       /* 2026-11-01T12:00:00Z */

/* ---- steps ---- */

TEST(a_first_step_says_so_unless_the_session_is_starting) {
    fresh();
    ASSERT_EQ_INT(0, step("s1", NULL));
    HAS(g_out, "belay: " RED " recording starts here: nothing before ");
    HAS(g_out, " is accounted for\n");
    ASSERT_EQ_INT(1, (int)count(g_out, "\n"));
    fresh();
    ASSERT_EQ_INT(0, step("s1", "--first-ok", NULL));
    ASSERT_EQ_STR("", g_out);
    /* LN-1: a step that changed nothing prints nothing; one that did, one line */
    ASSERT_EQ_INT(0, step("s1", NULL));
    ASSERT_EQ_STR("", g_out);
    sh("echo n > '%s/new.txt'", g_scope);
    ASSERT_EQ_INT(0, step("s1", NULL));
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: new.txt added\n", g_out);
    ASSERT_EQ_INT(0, step("s1", NULL));
    ASSERT_EQ_STR("", g_out);
    ASSERT_EQ_STR("", g_err);
}

TEST(a_steps_changes_belong_to_the_calls_open_during_it) {
    started("s1");
    ASSERT_EQ_INT(0, step("s1", "--begin", "c1", NULL));
    ASSERT_EQ_STR("", g_out);
    sh("echo 1 > '%s/f1'", g_scope);
    ASSERT_EQ_INT(0, step("s1", "--finish", "c1", NULL));
    ASSERT_EQ_STR("belay: 1 change: f1 added\n", g_out);
    sh("echo 2 > '%s/f2'", g_scope);
    ASSERT_EQ_INT(0, step("s1", NULL));                                 /* the call is closed */
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: f2 added\n", g_out);
    /* two calls at once: a change belongs to whichever is open */
    step("s1", "--begin", "c2", NULL);
    step("s1", "--begin", "c3", NULL);
    sh("echo 3 > '%s/f3'", g_scope);
    step("s1", "--finish", "c2", NULL);
    ASSERT_EQ_STR("belay: 1 change: f3 added\n", g_out);
    sh("echo 4 > '%s/f4'", g_scope);
    step("s1", "--finish", "c3", NULL);
    ASSERT_EQ_STR("belay: 1 change: f4 added\n", g_out);
    /* --finish of a call that is not open is a plain step */
    sh("echo 5 > '%s/f5'", g_scope);
    ASSERT_EQ_INT(0, step("s1", "--finish", "c3", NULL));
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: f5 added\n", g_out);
    /* a call that will never finish is closed without a capture */
    step("s1", "--begin", "c4", NULL);
    step("s1", "--begin", "c5", NULL);
    ASSERT_EQ_INT(0, belay("watch", "close", "--scope", g_scope, "--session", "s1", "--id", "c4", "--id", "never-opened", NULL));
    ASSERT_EQ_STR("", g_out);
    sh("echo 6 > '%s/f6'", g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: 1 change: f6 added\n", g_out);                /* c5 is still open */
    ASSERT_EQ_INT(0, belay("watch", "close", "--scope", g_scope, "--session", "s1", "--all", NULL));
    sh("echo 7 > '%s/f7'", g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: f7 added\n", g_out);
}

TEST(a_summary_sums_the_steps_since_the_marker) {
    started("s1");
    sh("echo 0 > '%s/before'", g_scope);
    step("s1", NULL);
    ASSERT_EQ_INT(0, belay("watch", "mark", "--scope", g_scope, "--session", "s1", "--name", "prompt", NULL));
    ASSERT_EQ_STR("", g_out);
    ASSERT_EQ_INT(0, belay("watch", "summary", "--scope", g_scope, "--session", "s1", "--since", "prompt", NULL));
    ASSERT_EQ_STR("belay: nothing changed since prompt\n", g_out);
    /* one file changed in two steps is two changes (SM-4) */
    step("s1", "--begin", "c1", NULL);
    sh("echo 1 >> '%s/src/x.txt'", g_scope);
    step("s1", "--finish", "c1", NULL);
    step("s1", "--begin", "c2", NULL);
    sh("echo 2 >> '%s/src/x.txt'", g_scope);
    step("s1", "--finish", "c2", NULL);
    sh("echo 3 > '%s/out'", g_scope);
    step("s1", NULL);
    belay("watch", "summary", "--scope", g_scope, "--session", "s1", "--since", "prompt", NULL);
    ASSERT_EQ_STR("belay: 3 changed since prompt: 2 in 2 calls, 1 outside calls\n", g_out);
    /* an event that changes nothing in the state writes no line (re-review of #132, 6) */
    {
        const size_t before = count(ledger(), "\n");
        ASSERT_EQ_INT(0, belay("watch", "close", "--scope", g_scope, "--session", "s1", "--id", "never-opened", NULL));
        ASSERT_EQ_INT((int)before, (int)count(ledger(), "\n"));
    }
    /* a summary reads: it is the same twice, and writes no line */
    const size_t lines = count(ledger(), "\n");
    belay("watch", "summary", "--scope", g_scope, "--session", "s1", "--since", "prompt", NULL);
    ASSERT_EQ_STR("belay: 3 changed since prompt: 2 in 2 calls, 1 outside calls\n", g_out);
    ASSERT_EQ_INT((int)lines, (int)count(ledger(), "\n"));
    /* the marker moves, and what came before it is no longer counted */
    belay("watch", "mark", "--scope", g_scope, "--session", "s1", "--name", "prompt", NULL);
    belay("watch", "summary", "--scope", g_scope, "--session", "s1", "--since", "prompt", NULL);
    ASSERT_EQ_STR("belay: nothing changed since prompt\n", g_out);
    /* another session's steps in the span are said (SM-5) */
    sh("echo 4 > '%s/theirs'", g_scope);
    step("s2", NULL);
    belay("watch", "summary", "--scope", g_scope, "--session", "s1", "--since", "prompt", NULL);
    ASSERT_EQ_STR("belay: 1 changed since prompt outside calls (with another session's steps)\n", g_out);
}

TEST(a_flag_leads_the_line_and_a_note_brings_no_red_circle) {
    started("s1");
    sh("cd '%s' && git init -q . && git config user.name t", g_scope);
    step("s1", NULL);                                                   /* a new repository's own files: no flag (BR-L3) */
    HAS_NOT(g_out, RED);
    HAS(g_out, "belay: outside tool calls: ");
    sh("cd '%s' && git config user.email t@example.invalid", g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: outside tool calls: .git/config modified (git config)\n", g_out);
    sh("printf '#!/bin/sh\\n' > '%s/.git/hooks/pre-push' && echo x > '%s/y.txt'", g_scope, g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: " RED " outside tool calls: .git/hooks/pre-push added (git hook) \xc2\xb7 1 more: 1 added\n", g_out);
    sh("chmod u+s '%s/y.txt'", g_scope);
    step("s1", NULL);
    HAS(g_out, "belay: " RED " outside tool calls: y.txt setuid added (mode 0");
    HAS(g_out, "(privilege)\n");
    /* a file replaced by a symlink; a new symlink is no flag */
    sh("echo z > '%s/z.txt'", g_scope);
    step("s1", NULL);
    sh("rm '%s/z.txt' && ln -s src/x.txt '%s/z.txt' && ln -s src/x.txt '%s/new-link'", g_scope, g_scope, g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: " RED " outside tool calls: z.txt replaced by a symlink \xc2\xb7 1 more: 1 added\n", g_out);
}

/* ---- .belay-donttouch ---- */

TEST(the_dont_touch_list_is_the_checkpoints_and_a_change_to_it_is_flagged) {
    fresh();
    sh("printf 'src\\n' > '%s/.belay-donttouch' && mkdir '%s/docs' && echo d > '%s/docs/a'", g_scope, g_scope, g_scope);
    step("s1", "--first-ok", NULL);
    ASSERT_EQ_STR("", g_out);
    sh("echo 1 >> '%s/src/x.txt' && echo 1 >> '%s/docs/a'", g_scope, g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: " RED " outside tool calls: src/x.txt modified (don't-touch) \xc2\xb7 1 more: 1 modified\n", g_out);
    /* DT-5: the change is flagged, and in that step the old list and the new both apply */
    sh("printf 'docs\\n' > '%s/.belay-donttouch' && echo 2 >> '%s/src/x.txt' && echo 2 >> '%s/docs/a'", g_scope, g_scope, g_scope);
    step("s1", NULL);
    HAS(g_out, ".belay-donttouch modified (don't-touch)");
    HAS(g_out, "docs/a modified (don't-touch)");
    HAS(g_out, "src/x.txt modified (don't-touch)");
    /* from the next step, the new one only */
    sh("echo 3 >> '%s/src/x.txt' && echo 3 >> '%s/docs/a'", g_scope, g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: " RED " outside tool calls: docs/a modified (don't-touch) \xc2\xb7 1 more: 1 modified\n", g_out);
    /* DT-6: an invalid file is said, and the previous list stays in force */
    sh("printf 'src\\n/abs\\n' > '%s/.belay-donttouch'", g_scope);
    step("s1", NULL);
    HAS(g_out, "belay: " RED " .belay-donttouch: line 2 is not a pattern; the previous list stays in force\n");
    HAS(g_out, ".belay-donttouch modified (don't-touch)");
    sh("echo 4 >> '%s/src/x.txt' && echo 4 >> '%s/docs/a'", g_scope, g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: " RED " outside tool calls: docs/a modified (don't-touch) \xc2\xb7 1 more: 1 modified\n", g_out);
    /* while it lasts, in every summary */
    belay("watch", "mark", "--scope", g_scope, "--session", "s1", "--name", "p", NULL);
    belay("watch", "summary", "--scope", g_scope, "--session", "s1", "--since", "p", NULL);
    ASSERT_EQ_STR("belay: " RED " .belay-donttouch: line 2 is not a pattern; the previous list stays in force\n", g_out);
    belay("watch", "patterns", "--scope", g_scope, NULL);
    HAS(g_out, "  2\tdocs\n");
    /* no file is an empty list: removing it is flagged, and then nothing is listed */
    sh("rm '%s/.belay-donttouch'", g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: " RED " outside tool calls: .belay-donttouch removed (don't-touch)\n", g_out);
    sh("echo 5 >> '%s/docs/a'", g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: docs/a modified\n", g_out);
    belay("watch", "summary", "--scope", g_scope, "--session", "s1", "--since", "p", NULL);
    HAS_NOT(g_out, "is not a pattern");
}

TEST(an_invalid_list_on_a_first_step_leaves_none_in_force) {
    fresh();
    sh("printf 'a\\r\\nb\\r\\n' > '%s/.belay-donttouch'", g_scope);
    step("s1", "--first-ok", NULL);
    ASSERT_EQ_STR("belay: " RED " .belay-donttouch: line 1 is not a pattern; no list is in force\n", g_out);
    step("s1", NULL);                                                   /* said where it arises, not at every step */
    ASSERT_EQ_STR("", g_out);
    /* a file belay holds no copy of cannot be read, and that is another line */
    fresh();
    sh("head -c 70000 /dev/zero | tr '\\0' 'a' > '%s/.belay-donttouch'", g_scope);
    step("s1", "--first-ok", NULL);
    ASSERT_EQ_STR("belay: " RED " .belay-donttouch: the file is over 65536 bytes; no list is in force\n", g_out);
    fresh();
    sh("mkdir '%s/.belay-donttouch'", g_scope);
    step("s1", "--first-ok", NULL);
    ASSERT_EQ_STR("belay: " RED " could not read .belay-donttouch: it is not a regular file; no list is in force\n", g_out);
}

/* ---- the record ---- */

TEST(every_step_writes_a_line_and_a_torn_tail_is_cut) {
    started("s1");
    step("s1", NULL);
    step("s1", NULL);
    ASSERT_EQ_INT(3, (int)count(ledger(), "\"t\":\"step\""));
    ASSERT_EQ_INT(3, (int)count(ledger(), "\"t\":\"attempt\""));
    /* a torn last line, then a line of NUL bytes */
    sh("for f in '%s'/scopes/*/watch/ledger-*.ndjson; do printf '{\"belay_watch\":1,\"t\":\"st' >> \"$f\"; done", g_state);
    HAS(ledger(), "\"t\":\"st");
    sh("echo n > '%s/n1'", g_scope);
    ASSERT_EQ_INT(0, step("s1", NULL));
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: n1 added\n", g_out);
    ASSERT_EQ_INT(0, (int)count(ledger(), "\"t\":\"st{"));
    ASSERT_EQ_STR("", out_of("grep -v '^{\"belay_watch\":1,.*}$' '%s'/scopes/*/watch/ledger-*.ndjson", g_state));
    sh("for f in '%s'/scopes/*/watch/ledger-*.ndjson; do printf '\\0\\0\\0\\0\\0\\0\\n' >> \"$f\"; done", g_state);
    ASSERT_EQ_STR("6", out_of("cat '%s'/scopes/*/watch/ledger-*.ndjson | tr -cd '\\000' | wc -c | tr -d ' \\n'", g_state));
    sh("echo n > '%s/n2'", g_scope);
    ASSERT_EQ_INT(0, step("s1", NULL));
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: n2 added\n", g_out);
    ASSERT_EQ_STR("0", out_of("cat '%s'/scopes/*/watch/ledger-*.ndjson | tr -cd '\\000' | wc -c | tr -d ' \\n'", g_state));
    /* every line of the record is one JSON object of this version */
    ASSERT_EQ_STR("", out_of("grep -v '^{\"belay_watch\":1,' '%s'/scopes/*/watch/ledger-*.ndjson", g_state));
}

TEST(a_record_that_cannot_be_read_is_said_not_passed_over) {
    /* TL-12: no line parses */
    started("s1");
    sh("echo x > '%s/x1'", g_scope);
    step("s1", NULL);
    sh("for f in '%s'/scopes/*/watch/ledger-*.ndjson; do echo garbage > \"$f\"; done", g_state);
    sh("echo x > '%s/x2'", g_scope);
    ASSERT_EQ_INT(0, step("s1", NULL));
    HAS(g_out, "belay: " RED " the record was interrupted: nothing before ");
    HAS_NOT(g_out, "x2");                                               /* not accounted for, and not invented */
    sh("echo x > '%s/x3'", g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: x3 added\n", g_out);
    /* TL-11: the cursor's checkpoint is gone, others survive */
    started("s1");
    step("s1", NULL);
    sh("cd '%s'/scopes/*/checkpoints && rm -rf \"$(ls | sort -n | tail -1)\"", g_state);
    sh("echo y > '%s/y1'", g_scope);
    ASSERT_EQ_INT(0, step("s1", NULL));
    HAS(g_out, "belay: " RED " the record was interrupted: resuming from checkpoint ");
    sh("echo y > '%s/y2'", g_scope);
    step("s1", NULL);
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: y2 added\n", g_out);    /* its id taken again by a checkpoint that is not it: still gone, never diffed against as if it were */
    sh("cd '%s'/scopes/*/checkpoints && rm -rf \"$(ls | sort -n | tail -1)\"", g_state);
    sh("echo y > '%s/y3'", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    sh("echo y > '%s/y4'", g_scope);
    ASSERT_EQ_INT(0, step("s1", NULL));
    HAS(g_out, "belay: " RED " the record was interrupted: resuming from checkpoint ");
    HAS_NOT(g_out, "y4");                                               /* y3 is not accounted for, so neither is claimed */
}

/* ---- kill points ---- */

static const char *g_die_at;
static void die_at(const char *stage) {
    if (strcmp(stage, g_die_at) == 0) _exit(9);
}
static void die_before_line(void) { _exit(9); }

TEST(a_worker_that_dies_at_any_stage_loses_nothing_and_repeats_nothing) {
    static const struct { const char *at, *said; } t[] = {
        { "capturing", "capturing" }, { "matching", "matching" }, { "rendering", "rendering" },
        { "committing", "rendering" },          /* before it asks: the last stage it reported */
        { "writing the record", "writing the record" },
        { NULL, "writing the record" },         /* after its section is synced, before its line */
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        started("s1");
        sh("echo k > '%s/k.txt'", g_scope);
        g_die_at = t[i].at != NULL ? t[i].at : "";
        watch_stage_hook = die_at;
        if (t[i].at == NULL) ledger_before_line = die_before_line;
        char want[200];
        snprintf(want, sizeof want, "belay: " RED " belay stopped unexpectedly while %s\n", t[i].said);
        ASSERT_EQ_INT(4, step("s1", NULL));
        ASSERT_EQ_STR(want, g_out);
        watch_stage_hook = NULL;
        ledger_before_line = NULL;
        /* the next step covers the same interval, and says the last one did not finish */
        ASSERT_EQ_INT(0, step("s1", NULL));
        ASSERT_EQ_STR("belay: " RED " the previous step did not finish\nbelay: outside tool calls: 1 change: k.txt added\n", g_out);
        /* in the receipt once: a section no step line names is never printed */
        ASSERT_EQ_INT(1, (int)count(receipt(), "A k.txt"));
        ASSERT_EQ_INT(0, step("s1", NULL));
        ASSERT_EQ_STR("", g_out);
    }
}

static void stall_capturing(const char *stage) {
    if (strcmp(stage, "capturing") == 0) sleep(4);
}

TEST(a_step_past_its_deadline_is_killed_said_and_backed_off_after_three) {
    started("s1");
    belay("watch", "mark", "--scope", g_scope, "--session", "s1", "--name", "p", NULL);
    sh("echo d > '%s/d.txt'", g_scope);
    watch_stage_hook = stall_capturing;
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ_INT(4, step("s1", "--deadline", "1", NULL));
        ASSERT_EQ_STR("belay: " RED " could not record in 1 s: capturing\n", g_out);
    }
    /* TM-3: the fourth does not capture, and writes nothing */
    const size_t lines = count(ledger(), "\n");
    const time_t t0 = time(NULL);
    ASSERT_EQ_INT(4, step("s1", "--deadline", "1", NULL));
    ASSERT_EQ_STR("belay: " RED " not recording: capturing this directory takes longer than 1 s\n", g_out);
    ASSERT_TRUE(time(NULL) - t0 <= 1);
    ASSERT_EQ_INT((int)lines, (int)count(ledger(), "\n"));
    watch_stage_hook = NULL;
    ASSERT_EQ_INT(4, step("s1", NULL));                                 /* nothing but a new session clears it */
    HAS(g_out, "not recording");
    /* the summary repeats what could not be kept, once */
    belay("watch", "summary", "--scope", g_scope, "--session", "s1", "--since", "p", NULL);
    ASSERT_EQ_STR("belay: " RED " could not record in 1 s: capturing\n", g_out);
    /* a new session starts afresh, and the change is still there to record */
    ASSERT_EQ_INT(0, step("s2", NULL));
    HAS(g_out, "belay: outside tool calls: 1 change: d.txt added\n");
    ASSERT_EQ_INT(1, (int)count(receipt(), "A d.txt"));
}

TEST(a_step_that_finishes_ends_the_run_of_kills) {
    started("s1");
    sh("echo d > '%s/d.txt'", g_scope);
    for (int round = 0; round < 2; round++) {
        watch_stage_hook = stall_capturing;
        for (int i = 0; i < 2; i++) {
            ASSERT_EQ_INT(4, step("s1", "--deadline", "1", NULL));
            ASSERT_EQ_STR("belay: " RED " could not record in 1 s: capturing\n", g_out);
        }
        watch_stage_hook = NULL;
        ASSERT_EQ_INT(0, step("s1", NULL));                             /* four kills in all, never three in a row */
        HAS_NOT(g_out, "not recording");
    }
    ASSERT_EQ_INT(1, (int)count(receipt(), "A d.txt"));
}

/* TM-2: "go" or a kill, never both. A worker that asked and was killed
 * instead of answered has written nothing. */
TEST(a_worker_killed_while_it_waits_for_the_answer_has_recorded_nothing) {
    started("s1");
    sh("echo w > '%s/w.txt'", g_scope);
    watch_withhold_go = true;
    const size_t steps = count(ledger(), "\"t\":\"step\"");
    ASSERT_EQ_INT(4, step("s1", "--deadline", "1", NULL));
    HAS(g_out, "belay: " RED " could not record in 1 s: ");
    watch_withhold_go = false;
    ASSERT_EQ_INT((int)steps, (int)count(ledger(), "\"t\":\"step\""));
    HAS_NOT(receipt(), "A w.txt");
    ASSERT_EQ_INT(0, step("s1", NULL));                                 /* said lost, and so still there to record */
    HAS(g_out, "belay: outside tool calls: 1 change: w.txt added\n");
    ASSERT_EQ_INT(1, (int)count(receipt(), "A w.txt"));
}

TEST(a_lock_that_is_not_free_by_the_deadline_is_a_line) {
    started("s1");
    sh("echo l > '%s/l.txt'", g_scope);
    const char *lock = out_of("ls '%s'/scopes/*/lock", g_state);
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%.*s", (int)strcspn(lock, "\n"), lock);
    const pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid == 0) {
        const int fd = open(path, O_RDWR);
        if (fd == -1 || flock(fd, LOCK_EX) == -1) _exit(1);
        sleep(3);
        _exit(0);
    }
    usleep(300 * 1000);
    ASSERT_EQ_INT(4, step("s1", "--deadline", "1", NULL));
    ASSERT_EQ_STR("belay: " RED " could not record: another belay holds this directory's lock\n", g_out);
    int status;
    waitpid(pid, &status, 0);
    ASSERT_EQ_INT(0, step("s1", NULL));
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: l.txt added\n", g_out);     /* no back-off for a lock */
}

static void stall_before_line(void) { sleep(3); }

TEST(no_word_after_go_is_said_and_the_step_is_not_killed) {
    started("s1");
    sh("echo g > '%s/g.txt'", g_scope);
    ledger_before_line = stall_before_line;
    watch_second_ms = 300;
    const time_t t0 = time(NULL);
    ASSERT_EQ_INT(4, step("s1", "--deadline", "1", NULL));
    ASSERT_EQ_STR("belay: " RED " could not confirm the record\n", g_out);
    ASSERT_TRUE(time(NULL) - t0 <= 2);
    ledger_before_line = NULL;
    sleep(3);                                                           /* the worker was told to go, and went on */
    ASSERT_EQ_INT(0, step("s1", NULL));
    ASSERT_EQ_STR("", g_out);                                           /* it was recorded: not lost, not said twice */
    ASSERT_EQ_INT(1, (int)count(receipt(), "A g.txt"));
}

/* Review of #125, finding 2: hooks of one directory running at the same
 * time each reported the same change. Here the changes are made first, and
 * then four processes step at once: one of them reports them, once. */
TEST(steps_at_the_same_time_count_each_change_once) {
    started("s0");
    for (int j = 0; j < 24; j++) sh("echo x > '%s/q%d'", g_scope, j);
    pid_t pids[4];
    for (int c = 0; c < 4; c++) {
        pids[c] = fork();
        REQUIRE(pids[c] != -1);
        if (pids[c] == 0) {
            char session[16];
            snprintf(session, sizeof session, "s%d", c + 1);
            for (int j = 0; j < 3; j++)
                if (step(session, NULL) != 0) _exit(1);
            _exit(0);
        }
    }
    for (int c = 0; c < 4; c++) {
        int status = -1;
        waitpid(pids[c], &status, 0);
        ASSERT_EQ_INT(0, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
    ASSERT_EQ_INT(13, (int)count(ledger(), "\"t\":\"step\""));         /* every one of the twelve wrote its line */
    ASSERT_EQ_STR("24\n", out_of("cat '%s'/scopes/*/watch/ledger-*.ndjson | grep '\"t\":\"step\"' | "
                                 "sed 's/.*\"changes\":\\([0-9]*\\).*/\\1/' | awk '{ s += $1 } END { print s }'", g_state));
    ASSERT_EQ_INT(24, (int)count(receipt(), "\n  A q"));
}

/* With files arriving while the steps run, a capture can meet one half made:
 * it may then be in two steps, as two states it was in. What must hold: every
 * file is in the record, and none is "added" twice. */
TEST(a_change_made_while_steps_run_is_in_the_record_and_added_at_most_once) {
    started("s0");
    pid_t pids[4];
    for (int c = 0; c < 4; c++) {
        pids[c] = fork();
        REQUIRE(pids[c] != -1);
        if (pids[c] == 0) {
            char session[16];
            snprintf(session, sizeof session, "s%d", c + 1);
            for (int j = 0; j < 6; j++) {
                sh("echo x > '%s/c%d_%d'", g_scope, c, j);
                if (step(session, NULL) != 0) _exit(1);
            }
            _exit(0);
        }
    }
    for (int c = 0; c < 4; c++) {
        int status = -1;
        waitpid(pids[c], &status, 0);
        ASSERT_EQ_INT(0, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
    step("s0", NULL);
    const char *r = receipt();
    for (int c = 0; c < 4; c++)
        for (int j = 0; j < 6; j++) {
            char added[32], name[32];
            snprintf(added, sizeof added, "\n  A c%d_%d\n", c, j);
            snprintf(name, sizeof name, " c%d_%d", c, j);
            ASSERT_TRUE(count(r, name) >= 1);
            ASSERT_TRUE(count(r, added) <= 1);
        }
}

/* ---- the Claude Code adapter ---- */

static const char *hook(const char *event, const char *fmt, ...) {
    static char *reply;
    char in[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(in, sizeof in, fmt, ap);
    va_end(ap);
    free(reply);
    reply = NULL;
    size_t n;
    FILE *fin = fmemopen(in, strlen(in), "r"), *fout = open_memstream(&reply, &n);
    hook_claude(event, g_scope, fin, fout);
    fclose(fin);
    fclose(fout);
    return reply;
}

#define S1 "\"session_id\":\"sess-1\",\"cwd\":\"/nowhere\""

/* Review of #132, finding 1: what fails after a step's line is written must
 * not undo it. The step was recorded: its line is shown, it is not said to
 * be lost, and the next step does not report it again. */
TEST(a_failure_after_a_step_is_recorded_neither_loses_it_nor_records_it_twice) {
    /* the line after the step's fails to be written: a prompt is a step, then a marker */
    fresh();
    unsetenv("CLAUDE_CODE_ENTRYPOINT");
    hook("start", "{" S1 ",\"source\":\"startup\"}");
    sh("mkdir -p '%s/.git/hooks' && printf '#!/bin/sh\\n' > '%s/.git/hooks/pre-commit' && echo 1 > '%s/f1'", g_scope, g_scope, g_scope);
    ledger_fail_at = 3;                                                 /* the attempt, the step, then the marker */
    const char *r = hook("prompt", "{" S1 ",\"prompt\":\"go\"}");
    ledger_fail_at = 0;
    HAS(r, "belay: " RED " outside tool calls: .git/hooks/pre-commit added (git hook)");
    HAS(r, "belay: " RED " this step is recorded; what came after it failed: ");
    HAS_NOT(r, "could not record");
    ASSERT_EQ_STR("", hook("pre", "{" S1 ",\"tool_use_id\":\"t1\"}"));       /* not again */
    ASSERT_EQ_INT(1, (int)count(receipt(), "A .git/hooks/pre-commit"));
    ASSERT_EQ_INT(3, (int)count(ledger(), "\"t\":\"step\""));                /* the start's, the prompt's, the pre's: no second go at it */

    /* the summary fails, after the Stop's step is written: an older day's file cannot be read */
    fresh();
    watch_clock = fixed_clock;
    g_now = DAY1 * 1000000000LL;
    hook("start", "{" S1 ",\"source\":\"startup\"}");
    hook("prompt", "{" S1 ",\"prompt\":\"go\"}");
    g_now += 86400LL * 1000000000LL;
    sh("echo 1 > '%s/f1'", g_scope);
    hook("pre", "{" S1 ",\"tool_use_id\":\"t1\"}");                          /* today's file now exists */
    sh("cd '%s'/scopes/*/watch && mv ledger-2026-11-01.ndjson aside && mkdir ledger-2026-11-01.ndjson", g_state);
    sh("mkdir -p '%s/.git/hooks' && printf '#!/bin/sh\\n' > '%s/.git/hooks/pre-commit' && echo 2 > '%s/f2'", g_scope, g_scope, g_scope);
    r = hook("stop", "{" S1 "}");
    HAS(r, ".git/hooks/pre-commit added (git hook)");
    HAS(r, "belay: " RED " this step is recorded; what came after it failed: ");
    HAS_NOT(r, "could not record");
    sh("cd '%s'/scopes/*/watch && rmdir ledger-2026-11-01.ndjson && mv aside ledger-2026-11-01.ndjson", g_state);
    ASSERT_EQ_STR("", hook("pre", "{" S1 ",\"tool_use_id\":\"t2\"}"));       /* the cursor did not go back */
    ASSERT_EQ_INT(1, (int)count(receipt(), "A .git/hooks/pre-commit"));
    r = hook("stop", "{" S1 "}");
    HAS(r, "belay: " RED " 1 flagged: .git/hooks/pre-commit added (git hook)\\n");     /* once, and counted once */
    HAS(r, "belay: " RED " this step is recorded; what came after it failed: ");       /* and the trouble is repeated */
    HAS(r, "belay: 5 changed this turn outside tool calls");                        /* f1, f2, .git, hooks, pre-commit: each once */
}

/* Re-review of #132: a line whose bytes were written and whose sync then
 * failed. It must not stay in the file while the event says "could not
 * record": the step would be in the record and recorded again. */
TEST(a_step_line_whose_sync_fails_is_taken_back_not_left_to_be_recorded_twice) {
    fresh();
    unsetenv("CLAUDE_CODE_ENTRYPOINT");
    hook("start", "{" S1 ",\"source\":\"startup\"}");
    hook("prompt", "{" S1 ",\"prompt\":\"go\"}");
    sh("mkdir -p '%s/.git/hooks' && printf '#!/bin/sh\\n' > '%s/.git/hooks/pre-commit' && echo 1 > '%s/a'", g_scope, g_scope, g_scope);
    const size_t steps = count(ledger(), "\"t\":\"step\"");
    ledger_fail_sync_at = 2;                                            /* the attempt's sync holds, the step's fails */
    const char *r = hook("post", "{" S1 ",\"tool_use_id\":\"t1\"}");
    ledger_fail_sync_at = 0;
    HAS(r, "belay: " RED " could not record: ");
    ASSERT_EQ_INT((int)steps, (int)count(ledger(), "\"t\":\"step\""));       /* said lost, and not in the record */
    ASSERT_EQ_STR("", out_of("grep -v '^{\"belay_watch\":1,.*}$' '%s'/scopes/*/watch/ledger-*.ndjson", g_state));
    r = hook("post", "{" S1 ",\"tool_use_id\":\"t2\"}");
    HAS(r, ".git/hooks/pre-commit added (git hook)");                   /* so the next step records it: once */
    ASSERT_EQ_INT(1, (int)count(receipt(), "A .git/hooks/pre-commit"));
    r = hook("stop", "{" S1 "}");
    HAS(r, "belay: " RED " 1 flagged: .git/hooks/pre-commit added (git hook)\\n");
    HAS(r, "belay: 4 changed this turn");
    /* the same on a day's first line, which is a new file: nothing of it stays */
    fresh();
    watch_clock = fixed_clock;
    g_now = DAY1 * 1000000000LL;
    hook("start", "{" S1 ",\"source\":\"startup\"}");
    g_now += 86400LL * 1000000000LL;
    sh("echo 1 > '%s/b'", g_scope);
    ledger_fail_sync_at = 1;                                            /* the new day's attempt line */
    r = hook("post", "{" S1 ",\"tool_use_id\":\"t1\"}");
    ledger_fail_sync_at = 0;
    HAS(r, "belay: " RED " could not record: ");
    /* the day's file holds the line that says so, and not the attempt that was taken back */
    ASSERT_EQ_STR("0 1\n", out_of("f=$(ls '%s'/scopes/*/watch/ledger-2026-11-02.ndjson); echo \"$(grep -c '\"t\":\"attempt\"' $f) $(grep -c '\"t\":\"trouble\"' $f)\"", g_state));
    ASSERT_EQ_STR("", out_of("ls -a '%s'/scopes/*/watch | grep tmp", g_state));
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: outside tool calls: 1 change: b added\"}\n", hook("post", "{" S1 ",\"tool_use_id\":\"t2\"}"));
    ASSERT_EQ_INT(1, (int)count(receipt(), "A b\n"));
    /* and when the new file was already renamed into place before its directory's sync failed */
    fresh();
    watch_clock = fixed_clock;
    g_now = DAY1 * 1000000000LL;
    hook("start", "{" S1 ",\"source\":\"startup\"}");
    g_now += 86400LL * 1000000000LL;
    sh("echo 1 > '%s/c'", g_scope);
    ledger_fail_dirsync = true;
    r = hook("post", "{" S1 ",\"tool_use_id\":\"t1\"}");
    HAS(r, "belay: " RED " could not record: ");
    ASSERT_EQ_STR("ledger-2026-11-01.ndjson\n", out_of("ls '%s'/scopes/*/watch | grep '^ledger-'", g_state));   /* the trouble line's file went the same way */
    ledger_fail_dirsync = false;
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: outside tool calls: 1 change: c added\"}\n", hook("post", "{" S1 ",\"tool_use_id\":\"t2\"}"));
    ASSERT_EQ_INT(1, (int)count(receipt(), "A c\n"));
    ASSERT_EQ_INT(0, (int)count(ledger(), "\"t\":\"attempt\"") - (int)count(ledger(), "\"t\":\"step\""));   /* no attempt left without its step */
}

/* Review of #132, finding 4: TM-4 drops the calls and markers of a session
 * that fires nothing for a day -- not of one that is still firing. A turn
 * longer than a day keeps its marker, and its summary its span. */
TEST(a_turn_longer_than_a_day_keeps_its_marker_and_its_open_call) {
    fresh();
    unsetenv("CLAUDE_CODE_ENTRYPOINT");
    watch_clock = fixed_clock;
    g_now = DAY1 * 1000000000LL;
    hook("start", "{" S1 ",\"source\":\"startup\"}");
    hook("prompt", "{" S1 ",\"prompt\":\"a long job\"}");
    hook("pre", "{" S1 ",\"tool_use_id\":\"t1\"}");
    sh("mkdir -p '%s/.git/hooks' && printf '#!/bin/sh\\n' > '%s/.git/hooks/pre-commit'", g_scope, g_scope);
    hook("post", "{" S1 ",\"tool_use_id\":\"t1\"}");
    hook("pre", "{" S1 ",\"tool_use_id\":\"t2\"}");
    hook("pre", "{\"session_id\":\"sess-dead\",\"cwd\":\"/nowhere\",\"tool_use_id\":\"d1\"}");    /* another session, which dies here */
    /* the session goes on firing, every twenty hours, for sixty */
    for (int i = 0; i < 3; i++) {
        g_now += 20 * 3600LL * 1000000000LL;
        hook("pre", "{" S1 ",\"tool_use_id\":\"keepalive\"}");
        hook("post", "{" S1 ",\"tool_use_id\":\"keepalive\"}");
    }
    sh("echo late > '%s/later.txt'", g_scope);
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: 1 change: later.txt added\"}\n", hook("post", "{" S1 ",\"tool_use_id\":\"t2\"}"));   /* t2 was still open */
    const char *r = hook("stop", "{" S1 "}");
    HAS(r, "belay: " RED " 1 flagged: .git/hooks/pre-commit added (git hook)\\n");     /* the first day's, in this turn's summary */
    HAS(r, "belay: 4 changed this turn in 2 tool calls");
    /* the session that died is the one whose call is dropped, and that is said */
    HAS(out_of("cat '%s'/scopes/*/watch/ledger-*.ndjson | grep -c 'call of a session that ended without saying so was closed'", g_state), "1\n");
    HAS_NOT(out_of("cat '%s'/scopes/*/watch/ledger-*.ndjson | tail -1", g_state), "sess-dead");
}

/* Second re-review of #132, new 1: a session whose events write no line (a
 * batch that closes nothing) has still fired. Another session must not drop
 * its marker inside the day. */
TEST(a_session_that_fired_without_writing_a_line_keeps_its_marker) {
    fresh();
    unsetenv("CLAUDE_CODE_ENTRYPOINT");
    watch_clock = fixed_clock;
    g_now = DAY1 * 1000000000LL;
    hook("start", "{" S1 ",\"source\":\"startup\"}");
    hook("prompt", "{" S1 ",\"prompt\":\"go\"}");
    sh("mkdir -p '%s/.git/hooks' && printf '#!/bin/sh\\n' > '%s/.git/hooks/pre-commit'", g_scope, g_scope);
    hook("post", "{" S1 ",\"tool_use_id\":\"t1\"}");
    g_now += 20 * 3600LL * 1000000000LL;
    hook("batch", "{" S1 ",\"tool_calls\":[{\"tool_use_id\":\"never-open\"}]}");      /* closes nothing */
    /* it costs a line only when the renewal is due, not at every such event */
    const size_t before = count(ledger(), "\n");
    hook("batch", "{" S1 ",\"tool_calls\":[{\"tool_use_id\":\"never-open\"}]}");
    hook("batch", "{" S1 ",\"tool_calls\":[{\"tool_use_id\":\"never-open\"}]}");
    ASSERT_EQ_INT((int)before, (int)count(ledger(), "\n"));
    g_now += 20 * 3600LL * 1000000000LL;
    hook("post", "{\"session_id\":\"sess-2\",\"cwd\":\"/nowhere\",\"tool_use_id\":\"x1\"}");
    HAS(hook("stop", "{" S1 "}"), "belay: " RED " 1 flagged: .git/hooks/pre-commit added (git hook)");
}

/* The other side: a step whose own line could not be written is not
 * recorded, is said so, and is recorded by the next. And an event that
 * fails before it writes anything leaves the state as it found it. */
TEST(a_step_whose_line_fails_is_said_lost_and_the_state_is_as_it_was) {
    fresh();
    unsetenv("CLAUDE_CODE_ENTRYPOINT");
    hook("start", "{" S1 ",\"source\":\"startup\"}");
    hook("prompt", "{" S1 ",\"prompt\":\"go\"}");
    ASSERT_EQ_STR("", hook("pre", "{" S1 ",\"tool_use_id\":\"t1\"}"));
    sh("echo 1 > '%s/f1'", g_scope);
    ledger_fail_at = 2;                                                 /* the Stop's attempt is written, its step is not */
    const char *r = hook("stop", "{" S1 "}");
    ledger_fail_at = 0;
    HAS(r, "belay: " RED " could not record: ");
    HAS_NOT(r, "f1 added");
    HAS_NOT(r, "this step is recorded");
    /* the Stop had closed t1 in memory before it failed: t1 is still open, so the change is its call's */
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: 1 change: f1 added\"}\n", hook("post", "{" S1 ",\"tool_use_id\":\"t1\"}"));
    ASSERT_EQ_INT(1, (int)count(receipt(), "A f1"));
}

/* ---- the receipt, and patterns ---- */

TEST(the_receipt_is_every_step_newest_first) {
    started("s1");
    step("s1", "--begin", "c1", NULL);
    sh("echo 1 > '%s/first.txt'", g_scope);
    step("s1", "--finish", "c1", NULL);
    sh("echo 2 > '%s/second.txt'", g_scope);
    step("s1", NULL);
    ASSERT_EQ_INT(0, belay("watch", "receipt", "--scope", g_scope, NULL));
    HAS(g_out, "belay receipt  ");
    const char *a = strstr(g_out, "A first.txt"), *b = strstr(g_out, "A second.txt");
    REQUIRE(a != NULL && b != NULL);
    ASSERT_TRUE(b < a);
    HAS(g_out, "  session s1  outside tool calls\n");
    HAS(g_out, "  session s1  call c1\n");
    /* --max-lines says there is more; --path is a file whose second line is its own path */
    ASSERT_EQ_INT(0, belay("watch", "receipt", "--scope", g_scope, "--max-lines", "3", NULL));
    ASSERT_EQ_INT(4, (int)count(g_out, "\n"));
    HAS(g_out, "... the rest: ");
    ASSERT_EQ_INT(0, belay("watch", "receipt", "--scope", g_scope, "--path", NULL));
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%.*s", (int)strcspn(g_out, "\n"), g_out);
    ASSERT_EQ_STR(path, out_of("sed -n 2p '%s' | tr -d '\\n'", path));
    HAS(out_of("cat '%s'", path), "A second.txt");
    /* TL-13: a section that is gone or fails its digest is said in its place */
    sh("for f in '%s'/scopes/*/watch/receipt-*.txt; do perl -pi -e 's/second.txt/SECOND.txt/' \"$f\"; done", g_state);
    ASSERT_EQ_INT(0, belay("watch", "receipt", "--scope", g_scope, NULL));
    HAS(g_out, "this step's section is missing\n");
    HAS(g_out, "A first.txt");
    HAS_NOT(g_out, "SECOND.txt");
    /* nothing recorded is said, not an empty page */
    fresh();
    ASSERT_EQ_INT(0, belay("watch", "receipt", "--scope", g_scope, NULL));
    HAS(g_out, "nothing recorded for this directory yet\n");
}

TEST(patterns_shows_the_lists_in_force_and_what_each_matches) {
    fresh();
    sh("printf 'src\\nnothing-here\\n' > '%s/.belay-donttouch' && echo k > '%s/.env'", g_scope, g_scope);
    ASSERT_EQ_INT(0, belay("watch", "patterns", "--scope", g_scope, NULL));        /* before any step */
    HAS(g_out, "no don't-touch list in force\n");
    HAS(g_out, "no checkpoint of the directory yet: nothing to count\n");
    step("s1", "--first-ok", NULL);
    ASSERT_EQ_INT(0, belay("watch", "patterns", "--scope", g_scope, NULL));
    HAS(g_out, "don't-touch list in force: 2 patterns (sha256 ");
    HAS(g_out, "  2\tsrc\n");
    HAS(g_out, "  0\tnothing-here\tmatches nothing\n");
    HAS(g_out, "  1\t**/.env\tcredentials\tnot a directory; not in a dependency\n");
    HAS(g_out, "  0\t**/.git/hooks/*\tgit hook\tnot a directory; except **/*.sample\n");
    ASSERT_EQ_INT(0, belay("watch", "patterns", "--scope", g_scope, "--entries", NULL));
    ASSERT_EQ_STR("don't-touch\tflag\tdon't-touch\t.belay-donttouch\ncredentials\tflag\tcredentials\t.env\n"
                  "don't-touch\tflag\tdon't-touch\tsrc\ndon't-touch\tflag\tdon't-touch\tsrc/x.txt\n", g_out);
}

/* ---- what is not read ---- */

TEST(a_change_of_what_is_read_is_flagged_and_what_is_not_read_is_said_once) {
    started("s1");
    belay("watch", "mark", "--scope", g_scope, "--session", "s1", "--name", "p", NULL);
    sh("mkdir '%s/big' && echo b > '%s/big/b'", g_scope, g_scope);
    step("s1", NULL);
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", "big", NULL));
    step("s1", NULL);                                                   /* CV-1 */
    HAS(g_out, "belay: " RED " outside tool calls: big is no longer read (coverage)");
    /* CV-2: once per session, in a line that is not flagged; CV-3: no alarm for an ordinary exclude */
    belay("watch", "summary", "--scope", g_scope, "--session", "s1", "--since", "p", NULL);
    HAS(g_out, "belay: not reading: big (excluded)\n");
    HAS_NOT(g_out, "where the list would flag");
    /* the command only reads: the hook's Stop is what remembers it was said (below) */
    sh("mkdir '%s/.claude' && echo '{}' > '%s/.claude/settings.json'", g_scope, g_scope);
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", ".claude", NULL));
    step("s1", NULL);
    belay("watch", "summary", "--scope", g_scope, "--session", "s1", "--since", "p", NULL);
    HAS(g_out, "belay: " RED " not reading .claude (excluded), where the list would flag a change\n");
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--remove", "big", NULL));
    step("s1", NULL);
    HAS(g_out, "big is read again (coverage)");
}

TEST(too_wide_a_directory_is_refused) {
    fresh();
    char home[500], *old = getenv("HOME") != NULL ? strdup(getenv("HOME")) : NULL;
    snprintf(home, sizeof home, "%s/src", g_scope);
    setenv("HOME", home, 1);                                            /* $HOME is inside the directory */
    ASSERT_EQ_INT(3, step("s1", NULL));
    HAS(g_out, "belay: " RED " not watching ");
    HAS(g_out, ": too wide\n");
    setenv("HOME", g_scope, 1);                                         /* it is $HOME */
    ASSERT_EQ_INT(3, step("s1", NULL));
    HAS(g_out, ": too wide\n");
    ASSERT_EQ_STR("", out_of("ls '%s'/scopes 2>/dev/null", g_state));   /* nothing is kept for it */
    setenv("HOME", g_dir, 1);                                           /* the directory is inside $HOME: fine */
    ASSERT_EQ_INT(0, step("s1", "--first-ok", NULL));
    ASSERT_EQ_STR("", g_out);
    if (old != NULL) setenv("HOME", old, 1); else unsetenv("HOME");
    free(old);
}

TEST(usage_errors_exit_2_and_say_why) {
    fresh();
    ASSERT_EQ_INT(2, belay("watch", NULL));
    ASSERT_EQ_INT(2, belay("watch", "frobnicate", "--scope", g_scope, NULL));
    HAS(g_err, "unknown watch command frobnicate");
    ASSERT_EQ_INT(2, belay("watch", "step", "--session", "s", NULL));
    HAS(g_err, "--scope DIR is required");
    ASSERT_EQ_INT(2, belay("watch", "step", "--scope", g_scope, NULL));
    HAS(g_err, "--session needs an id");
    ASSERT_EQ_INT(2, belay("watch", "step", "--scope", g_scope, "--session", "has space", NULL));
    ASSERT_EQ_INT(2, belay("watch", "step", "--scope", g_scope, "--session", "quote\"", NULL));
    ASSERT_EQ_INT(2, belay("watch", "step", "--scope", g_scope, "--session", "s", "--begin", "a", "--finish", "b", NULL));
    ASSERT_EQ_INT(2, belay("watch", "step", "--scope", g_scope, "--session", "s", "--deadline", "0", NULL));
    ASSERT_EQ_INT(2, belay("watch", "step", "--scope", g_scope, "--session", "s", "--deadline", "soon", NULL));
    ASSERT_EQ_INT(2, belay("watch", "step", "--scope", g_scope, "--session", "s", "--bogus", NULL));
    ASSERT_EQ_INT(2, belay("watch", "close", "--scope", g_scope, "--session", "s", NULL));
    ASSERT_EQ_INT(2, belay("watch", "close", "--scope", g_scope, "--session", "s", "--all", "--id", "x", NULL));
    ASSERT_EQ_INT(2, belay("watch", "mark", "--scope", g_scope, "--session", "s", NULL));
    ASSERT_EQ_INT(2, belay("watch", "summary", "--scope", g_scope, "--session", "s", NULL));
    ASSERT_EQ_STR("", g_out);
    ASSERT_EQ_STR("", out_of("ls '%s'/scopes 2>/dev/null", g_state));   /* and none of them made any state */
    ASSERT_EQ_INT(0, belay("help", "watch", NULL));
    HAS(g_out, "belay watch step");
}

/* ---- prune ---- */


static void two_days(void) {
    started("s1");                                                      /* today's first step, then into the past */
    sh("rm -rf '%s'", g_state);
    sh("mkdir -p '%s' && chmod 700 '%s'", g_state, g_state);
    watch_clock = fixed_clock;
    g_now = DAY1 * 1000000000LL;
    step("s1", "--first-ok", NULL);
    sh("echo 1 > '%s/day1'", g_scope);
    step("s1", NULL);
    g_now += 86400LL * 1000000000LL;
    sh("echo 2 > '%s/day2'", g_scope);
    step("s1", NULL);
}

TEST(a_checkpoint_of_a_watch_step_is_the_watchs) {
    started("s1");
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, NULL));
    HAS(g_out, "mark 1 ");
    ASSERT_EQ_INT(1, (int)count(g_out, ", watch\n"));                    /* the step's, not the user's mark */
    HAS_NOT(strstr(g_out, "mark 2 "), ", watch");
}

TEST(prune_takes_a_days_files_with_its_checkpoints_and_never_the_newest_days) {
    two_days();
    ASSERT_EQ_STR("ledger-2026-11-01.ndjson\nledger-2026-11-02.ndjson\nreceipt-2026-11-01.txt\nreceipt-2026-11-02.txt\n",
                  out_of("ls '%s'/scopes/*/watch | grep -v '^list-'", g_state));
    /* WR-6: --dry-run names the days, and removes nothing */
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", "--dry-run", NULL));
    HAS(g_out, "would remove 1 day of the watch record, ");
    HAS(g_out, " bytes: 2026-11-01\n");
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", "--dry-run", "--json", NULL));
    HAS(g_out, ",\"watch_days\":[\"2026-11-01\"],\"watch_bytes\":");
    HAS_NOT(g_out, "\"watch_bytes\":0}");
    HAS(out_of("ls '%s'/scopes/*/watch", g_state), "ledger-2026-11-01.ndjson");
    /* WR-4: a day stays while a checkpoint its lines name stays */
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "2", NULL));
    HAS(out_of("ls '%s'/scopes/*/watch", g_state), "ledger-2026-11-01.ndjson");
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    HAS(g_out, "removed 1 day of the watch record");
    ASSERT_EQ_STR("ledger-2026-11-02.ndjson\nreceipt-2026-11-02.txt\n", out_of("ls '%s'/scopes/*/watch | grep -v '^list-'", g_state));
    /* the record goes on, and what was removed is not in the receipt */
    sh("echo 3 > '%s/after'", g_scope);
    ASSERT_EQ_INT(0, step("s1", NULL));
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: after added\n", g_out);
    HAS_NOT(receipt(), "A day1");
    HAS(receipt(), "A day2");
    /* WR-5: the newest day's files stay even when its lines name no checkpoint: they hold the state */
    two_days();
    g_now += 86400LL * 1000000000LL;
    belay("watch", "mark", "--scope", g_scope, "--session", "s1", "--name", "p", NULL);
    ASSERT_EQ_STR("ledger-2026-11-03.ndjson\n", out_of("ls '%s'/scopes/*/watch | grep '^ledger-' | tail -1", g_state));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    ASSERT_EQ_STR("ledger-2026-11-02.ndjson\nledger-2026-11-03.ndjson\n", out_of("ls '%s'/scopes/*/watch | grep '^ledger-'", g_state));
    sh("echo 4 > '%s/later'", g_scope);
    ASSERT_EQ_INT(0, step("s1", NULL));
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: later added\n", g_out);
    /* a scope with no record is pruned as before, and says nothing of one */
    fresh();
    belay("mark", "--scope", g_scope, NULL);
    belay("mark", "--scope", g_scope, NULL);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    HAS_NOT(g_out, "watch");
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", "--json", NULL));
    HAS(g_out, ",\"watch_days\":[],\"watch_bytes\":0}");
}

TEST(prune_never_removes_the_checkpoint_the_next_step_reads) {
    started("s1");
    sh("echo 1 > '%s/one'", g_scope);
    step("s1", NULL);                                                   /* the cursor: checkpoint 2 */
    sh("echo 2 > '%s/two'", g_scope);
    belay("mark", "--scope", g_scope, NULL);                            /* 3 and 4: not the watch's, and newer */
    belay("mark", "--scope", g_scope, NULL);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    belay("log", "--scope", g_scope, NULL);
    HAS(g_out, "mark 2 ");                                              /* WR-3 */
    HAS_NOT(g_out, "mark 1 ");
    HAS_NOT(g_out, "mark 3 ");
    ASSERT_EQ_INT(0, step("s1", NULL));                                 /* and the change made since is still seen */
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: two added\n", g_out);
}

TEST(prune_watch_only_removes_nothing_the_watch_did_not_write) {
    fresh();
    belay("mark", "--scope", g_scope, NULL);                            /* 1, 2: the user's, old or not */
    belay("mark", "--scope", g_scope, NULL);
    step("s1", "--first-ok", NULL);                                     /* 3, 4, 5: the watch's */
    sh("echo 1 > '%s/one'", g_scope);
    step("s1", NULL);
    step("s1", NULL);
    belay("mark", "--scope", g_scope, NULL);                            /* 6: the user's */
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-days", "0", "--watch-only", "--dry-run", NULL));
    HAS(g_out, "would remove 2 of 6 checkpoints");
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-days", "0", "--watch-only", NULL));
    belay("log", "--scope", g_scope, NULL);
    HAS(g_out, "mark 1 ");
    HAS(g_out, "mark 2 ");
    HAS_NOT(g_out, "mark 3 ");
    HAS_NOT(g_out, "mark 4 ");
    HAS(g_out, "mark 5 ");                                              /* the cursor's */
    HAS(g_out, "mark 6 ");
    /* without the option, the same limits take the user's too: any prune's behaviour, unchanged */
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-days", "0", NULL));
    belay("log", "--scope", g_scope, NULL);
    HAS_NOT(g_out, "mark 1 ");
    HAS_NOT(g_out, "mark 2 ");
    HAS(g_out, "mark 5 ");
    HAS(g_out, "mark 6 ");
}

TEST(a_record_prune_cannot_read_is_left_whole_and_said) {
    two_days();
    sh("for f in '%s'/scopes/*/watch/ledger-*.ndjson; do echo garbage > \"$f\"; done", g_state);
    const char *before = strdup(out_of("ls -l '%s'/scopes/*/watch | grep -v '^total'", g_state));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));        /* WR-9: not exit 4 */
    HAS(g_out, "the watch record cannot be read: it is left whole\n");
    HAS(g_out, "removed 2 of 3 checkpoints");                           /* and the checkpoints go as if there were none */
    ASSERT_EQ_STR(before, out_of("ls -l '%s'/scopes/*/watch | grep -v '^total'", g_state));
    free((char *)before);
}

static void die_between_days(void) { _exit(9); }

TEST(prune_killed_between_a_days_two_files_leaves_valid_state_and_finishes_when_run_again) {
    two_days();
    const pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid == 0) {
        prune_between_days = die_between_days;
        belay("prune", "--scope", g_scope, "--keep-last", "1", NULL);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    ASSERT_EQ_INT(9, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    /* WR-7: the ledger file went first; its receipt file is read by nothing */
    ASSERT_EQ_STR("ledger-2026-11-02.ndjson\nreceipt-2026-11-01.txt\nreceipt-2026-11-02.txt\n",
                  out_of("ls '%s'/scopes/*/watch | grep -v '^list-'", g_state));
    HAS_NOT(receipt(), "A day1");
    HAS(receipt(), "A day2");
    sh("echo 3 > '%s/after'", g_scope);
    ASSERT_EQ_INT(0, step("s1", NULL));
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: after added\n", g_out);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    ASSERT_EQ_STR("ledger-2026-11-02.ndjson\nreceipt-2026-11-02.txt\n", out_of("ls '%s'/scopes/*/watch | grep -v '^list-'", g_state));
}

TEST(a_list_file_no_remaining_line_names_is_removed_and_the_one_in_force_never) {
    fresh();
    watch_clock = fixed_clock;
    g_now = DAY1 * 1000000000LL;
    sh("printf 'old\\n' > '%s/.belay-donttouch'", g_scope);
    step("s1", "--first-ok", NULL);
    g_now += 86400LL * 1000000000LL;
    sh("printf 'new\\n' > '%s/.belay-donttouch'", g_scope);
    step("s1", NULL);                                                   /* this day's lines name both */
    g_now += 86400LL * 1000000000LL;
    step("s1", NULL);
    step("s1", NULL);
    ASSERT_EQ_STR("2\n", out_of("ls '%s'/scopes/*/watch | grep -c '^list-'", g_state));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    ASSERT_EQ_STR("1\n", out_of("ls '%s'/scopes/*/watch | grep -c '^list-'", g_state));     /* WR-5 */
    sh("mkdir '%s/new' && echo n > '%s/new/n'", g_scope, g_scope);
    step("s1", NULL);
    HAS(g_out, "new added (don't-touch)");                              /* the list in force still is */
}

/* ---- the Claude Code adapter's events ---- */

TEST(the_claude_code_hook_maps_its_events_to_steps_calls_and_a_summary) {
    fresh();
    unsetenv("CLAUDE_CODE_ENTRYPOINT");
    ASSERT_EQ_STR("", hook("start", "{" S1 ",\"source\":\"startup\"}"));
    ASSERT_EQ_STR("", hook("prompt", "{" S1 ",\"prompt\":\"do it\"}"));
    ASSERT_EQ_STR("", hook("pre", "{" S1 ",\"tool_name\":\"Bash\",\"tool_input\":{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":"
                                  "{\"i\":[1,{\"x\":\"}]\\\\\\\"\"}]}}}}}}}}},\"tool_use_id\":\"toolu_1\"}"));
    sh("echo h > '%s/h.txt'", g_scope);
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: 1 change: h.txt added\"}\n", hook("post", "{" S1 ",\"tool_use_id\":\"toolu_1\",\"tool_response\":\"ok\"}"));
    /* a call the user denies fires only its PreToolUse: the Stop closes it */
    ASSERT_EQ_STR("", hook("pre", "{" S1 ",\"tool_use_id\":\"toolu_2\"}"));
    /* a subagent's call stays open across the main thread's Stop */
    ASSERT_EQ_STR("", hook("pre", "{" S1 ",\"tool_use_id\":\"toolu_3\",\"agent_id\":\"agent-a\"}"));
    sh("echo i > '%s/i.txt'", g_scope);
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: 1 change: i.txt added\\nbelay: 2 changed this turn in 2 tool calls \xc2\xb7 full receipt: /belay:receipt\"}\n",
                  hook("stop", "{" S1 "}"));
    sh("echo j > '%s/j.txt'", g_scope);
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: 1 change: j.txt added\"}\n", hook("post", "{" S1 ",\"tool_use_id\":\"toolu_3\",\"agent_id\":\"agent-a\"}"));
    sh("echo k > '%s/k.txt'", g_scope);
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: outside tool calls: 1 change: k.txt added\"}\n", hook("pre", "{" S1 ",\"tool_use_id\":\"toolu_4\"}"));
    /* a background command's end fires a prompt event: it does not move the marker */
    ASSERT_EQ_STR("", hook("prompt", "{" S1 ",\"prompt\":\"<task-notification>done</task-notification>\"}"));
    /* PostToolBatch closes the calls it lists that are still open: one the harness blocked */
    ASSERT_EQ_STR("", hook("batch", "{" S1 ",\"tool_calls\":[{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"x\"},\"tool_use_id\":\"toolu_4\"},"
                                    "{\"tool_use_id\":\"toolu_9\"}]}"));
    sh("echo l > '%s/l.txt'", g_scope);
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: outside tool calls: 1 change: l.txt added\\n"
                  "belay: 5 changed this turn: 3 in 2 tool calls, 2 outside tool calls \xc2\xb7 full receipt: /belay:receipt\"}\n",
                  hook("stop", "{" S1 "}"));
    /* the user's next message moves it */
    ASSERT_EQ_STR("", hook("prompt", "{" S1 ",\"prompt\":\"more\"}"));
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: nothing changed this turn\"}\n", hook("stop", "{" S1 "}"));
    /* SubagentStop closes that agent's calls and no one else's */
    hook("pre", "{" S1 ",\"tool_use_id\":\"toolu_5\",\"agent_id\":\"agent-b\"}");
    hook("pre", "{" S1 ",\"tool_use_id\":\"toolu_6\",\"agent_id\":\"agent-c\"}");
    ASSERT_EQ_STR("", hook("subagent-stop", "{" S1 ",\"agent_id\":\"agent-b\"}"));
    HAS_NOT(strrchr(ledger(), '{') - 400, "toolu_5");
    HAS(out_of("tail -1 '%s'/scopes/*/watch/ledger-*.ndjson", g_state), "[\"toolu_6\",\"sess-1\",\"agent-c\",");
    /* at a session's end nothing can be shown; its calls and marker go */
    sh("echo m > '%s/m.txt'", g_scope);
    ASSERT_EQ_STR("", hook("end", "{" S1 "}"));
    HAS(out_of("tail -1 '%s'/scopes/*/watch/ledger-*.ndjson", g_state), "\"open\":[],\"marks\":[],");
    ASSERT_EQ_INT(1, (int)count(receipt(), "A m.txt"));                 /* recorded all the same */
}

TEST(what_is_not_read_is_said_once_a_session_at_a_stop) {
    fresh();
    unsetenv("CLAUDE_CODE_ENTRYPOINT");
    sh("mkdir '%s/big' && echo b > '%s/big/b'", g_scope, g_scope);
    belay("exclude", "--scope", g_scope, "--add", "big", NULL);
    hook("start", "{" S1 ",\"source\":\"startup\"}");
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: not reading: big (excluded)\\nbelay: nothing changed this turn\"}\n", hook("stop", "{" S1 "}"));
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: nothing changed this turn\"}\n", hook("stop", "{" S1 "}"));
    /* another session is told too */
    HAS(hook("stop", "{\"session_id\":\"sess-2\",\"cwd\":\"/nowhere\"}"), "belay: not reading: big (excluded)");
}

TEST(the_hook_always_exits_0_and_never_stays_silent_about_a_failure) {
    fresh();
    unsetenv("CLAUDE_CODE_ENTRYPOINT");
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: " RED " could not record: the hook's input could not be read\"}\n", hook("pre", "not json"));
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: " RED " could not record: the hook's input could not be read\"}\n", hook("pre", "{\"a\":"));
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: " RED " could not record: the hook's input names no session or directory\"}\n", hook("pre", "{}"));
    ASSERT_EQ_STR("{\"systemMessage\":\"belay: " RED " could not record: the hook's input names no session or directory\"}\n",
                  hook("pre", "{\"session_id\":\"has space\"}"));
    ASSERT_EQ_STR("", hook("no-such-event", "{" S1 "}"));
    /* whatever the arguments, and whatever fails */
    ASSERT_EQ_INT(0, belay("hook", NULL));
    ASSERT_EQ_INT(0, belay("hook", "claude-code", NULL));
    ASSERT_EQ_INT(0, belay("hook", "some-other-agent", "start", NULL));
    ASSERT_EQ_INT(0, belay("hook", "claude-code", "bogus", "--scope", NULL));
    /* too wide is said at a session's start, and nowhere else (TL-14) */
    char *old = getenv("HOME") != NULL ? strdup(getenv("HOME")) : NULL;
    setenv("HOME", g_scope, 1);
    HAS(hook("start", "{" S1 ",\"source\":\"startup\"}"), "{\"systemMessage\":\"belay: " RED " not watching ");
    HAS(hook("start", "{" S1 ",\"source\":\"resume\"}"), ": too wide\"}\n");
    ASSERT_EQ_STR("", hook("pre", "{" S1 ",\"tool_use_id\":\"t\"}"));
    ASSERT_EQ_STR("", hook("stop", "{" S1 "}"));
    if (old != NULL) setenv("HOME", old, 1); else unsetenv("HOME");
    free(old);
    /* a session that is not starting begins with the flagged first-step line */
    HAS(hook("start", "{" S1 ",\"source\":\"resume\"}"), "belay: " RED " recording starts here: nothing before ");
}

TEST(the_receipt_command_is_answered_by_the_hook_and_no_other_command_is) {
    fresh();
    unsetenv("CLAUDE_CODE_ENTRYPOINT");
    ASSERT_EQ_STR("{\"decision\":\"block\",\"reason\":\"belay has no receipt for this directory yet: nothing has changed in it.\","
                  "\"hookSpecificOutput\":{\"hookEventName\":\"UserPromptExpansion\",\"suppressOriginalPrompt\":true}}\n",
                  hook("receipt", "{" S1 ",\"command_name\":\"belay:receipt\"}"));
    hook("start", "{" S1 ",\"source\":\"startup\"}");
    sh("echo r > '%s/r.txt'", g_scope);
    hook("stop", "{" S1 "}");
    const char *r = hook("receipt", "{" S1 ",\"command_name\":\"belay:receipt\"}");
    HAS(r, "{\"decision\":\"block\",\"reason\":\"belay receipt  ");
    HAS(r, "A r.txt");
    HAS(r, "\"suppressOriginalPrompt\":true}}\n");
    ASSERT_EQ_STR("", hook("receipt", "{" S1 ",\"command_name\":\"other:command\"}"));
    ASSERT_EQ_STR("", hook("receipt", "{" S1 "}"));
}

TEST(the_hook_prunes_once_a_day_and_only_the_watchs_own) {
    fresh();
    unsetenv("CLAUDE_CODE_ENTRYPOINT");
    belay("mark", "--scope", g_scope, NULL);                            /* the user's own, before the plugin */
    belay("mark", "--scope", g_scope, NULL);
    hook("start", "{" S1 ",\"source\":\"startup\"}");
    hook("stop", "{" S1 "}");
    for (int i = 0; i < 50 && strstr(out_of("ls '%s'/scopes/*/watch", g_state), "pruned") == NULL; i++) usleep(100 * 1000);
    HAS(out_of("ls '%s'/scopes/*/watch", g_state), "pruned\n");
    usleep(500 * 1000);                                                 /* the detached prune */
    belay("log", "--scope", g_scope, NULL);
    HAS(g_out, "mark 1 ");                                              /* WR-11: installing it removed nothing of the user's */
    HAS(g_out, "mark 2 ");
    ASSERT_EQ_STR("", out_of("cat '%s'/scopes/*/watch/prune.log 2>/dev/null", g_state));
    /* not again the same day */
    const char *stamp = strdup(out_of("perl -e 'print((stat($ARGV[0]))[9])' '%s'/scopes/*/watch/pruned", g_state));
    sleep(1);
    hook("stop", "{" S1 "}");
    ASSERT_EQ_STR(stamp, out_of("perl -e 'print((stat($ARGV[0]))[9])' '%s'/scopes/*/watch/pruned", g_state));
    free((char *)stamp);
    /* WR-12: a failed prune is a line at the next Stop, once */
    sh("echo 'belay: it broke' > \"$(ls -d '%s'/scopes/*/watch)/prune.log\"", g_state);
    HAS(hook("stop", "{" S1 "}"), "belay: " RED " the last prune failed: belay: it broke");
    HAS_NOT(hook("stop", "{" S1 "}"), "the last prune failed");
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_watch_%d", (int)getpid());
    mkdir(g_dir, 0700);
    char real[PATH_MAX];
    if (realpath(g_dir, real) != NULL) snprintf(g_dir, sizeof g_dir, "%.200s", real);
    snprintf(g_scope, sizeof g_scope, "%s/proj", g_dir);
    snprintf(g_state, sizeof g_state, "%s/state", g_dir);
    setenv("BELAY_STATE_DIR", g_state, 1);
    unsetenv("CLAUDE_PROJECT_DIR");
    RUN(a_first_step_says_so_unless_the_session_is_starting);
    RUN(a_steps_changes_belong_to_the_calls_open_during_it);
    RUN(a_summary_sums_the_steps_since_the_marker);
    RUN(a_flag_leads_the_line_and_a_note_brings_no_red_circle);
    RUN(the_dont_touch_list_is_the_checkpoints_and_a_change_to_it_is_flagged);
    RUN(an_invalid_list_on_a_first_step_leaves_none_in_force);
    RUN(every_step_writes_a_line_and_a_torn_tail_is_cut);
    RUN(a_record_that_cannot_be_read_is_said_not_passed_over);
    RUN(a_worker_that_dies_at_any_stage_loses_nothing_and_repeats_nothing);
    RUN(a_step_past_its_deadline_is_killed_said_and_backed_off_after_three);
    RUN(a_step_that_finishes_ends_the_run_of_kills);
    RUN(a_worker_killed_while_it_waits_for_the_answer_has_recorded_nothing);
    RUN(a_lock_that_is_not_free_by_the_deadline_is_a_line);
    RUN(no_word_after_go_is_said_and_the_step_is_not_killed);
    RUN(steps_at_the_same_time_count_each_change_once);
    RUN(a_change_made_while_steps_run_is_in_the_record_and_added_at_most_once);
    RUN(a_failure_after_a_step_is_recorded_neither_loses_it_nor_records_it_twice);
    RUN(a_step_line_whose_sync_fails_is_taken_back_not_left_to_be_recorded_twice);
    RUN(a_turn_longer_than_a_day_keeps_its_marker_and_its_open_call);
    RUN(a_session_that_fired_without_writing_a_line_keeps_its_marker);
    RUN(a_step_whose_line_fails_is_said_lost_and_the_state_is_as_it_was);
    RUN(the_receipt_is_every_step_newest_first);
    RUN(patterns_shows_the_lists_in_force_and_what_each_matches);
    RUN(a_change_of_what_is_read_is_flagged_and_what_is_not_read_is_said_once);
    RUN(too_wide_a_directory_is_refused);
    RUN(usage_errors_exit_2_and_say_why);
    RUN(a_checkpoint_of_a_watch_step_is_the_watchs);
    RUN(prune_takes_a_days_files_with_its_checkpoints_and_never_the_newest_days);
    RUN(prune_never_removes_the_checkpoint_the_next_step_reads);
    RUN(prune_watch_only_removes_nothing_the_watch_did_not_write);
    RUN(a_record_prune_cannot_read_is_left_whole_and_said);
    RUN(prune_killed_between_a_days_two_files_leaves_valid_state_and_finishes_when_run_again);
    RUN(a_list_file_no_remaining_line_names_is_removed_and_the_one_in_force_never);
    RUN(the_claude_code_hook_maps_its_events_to_steps_calls_and_a_summary);
    RUN(what_is_not_read_is_said_once_a_session_at_a_stop);
    RUN(the_hook_always_exits_0_and_never_stays_silent_about_a_failure);
    RUN(the_receipt_command_is_answered_by_the_hook_and_no_other_command_is);
    RUN(the_hook_prunes_once_a_day_and_only_the_watchs_own);
    sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    return belay_test_report();
}
