/*
 *  The command line (src/cli/; NOTES/phase5-structure.md §3, §6; decisions
 *  Q3, Q4, Q6, Q7, Q8, Q9), run in-process: every usage error, every exit
 *  code, the scope's resolution under attack (§5.1.1), the state directory
 *  inside a scope, mark's full-walk triggers, log, and diff --exit-code.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "cli/cli.h"
#include "cli/state.h"

#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char g_dir[256], g_scope[400], g_state[400];
static char *g_out, *g_err;

/* Runs `belay <args...>` (NULL-terminated); the exit code, output in g_out, g_err. */
static int belay(const char *a0, ...) {
    char *argv[32] = { "belay", (char *)a0 };
    int argc = a0 != NULL ? 2 : 1;
    va_list ap;
    va_start(ap, a0);
    const char *a;
    while (a0 != NULL && argc < 31 && (a = va_arg(ap, const char *)) != NULL) argv[argc++] = (char *)a;
    va_end(ap);
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

static void sh(const char *fmt, ...) {
    char cmd[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    if (system(cmd) != 0) { /* the assertions say */ }
}

static void fresh(void) {
    sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s' '%s' && mkdir -p '%s/src' '%s' && chmod 700 '%s'",
       g_dir, g_scope, g_state, g_scope, g_state, g_state);
    sh("printf 'a\\nb\\n' > '%s/src/x.txt' && printf 'tool\\n' > '%s/tool'", g_scope, g_scope);
}

TEST(usage_errors_exit_2) {
    ASSERT_EQ_INT(2, belay(NULL));
    ASSERT_EQ_INT(2, belay("frobnicate", NULL));
    ASSERT_TRUE(strstr(g_err, "unknown command frobnicate") != NULL);
    ASSERT_EQ_INT(2, belay("check", NULL));
    ASSERT_TRUE(strstr(g_err, "--scope DIR is required") != NULL);
    ASSERT_EQ_INT(2, belay("check", "--scope", g_scope, "--bogus", NULL));
    ASSERT_EQ_INT(2, belay("check", "--scope", NULL));
    ASSERT_EQ_INT(2, belay("diff", "--scope", g_scope, NULL));                     /* no --since */
    ASSERT_EQ_INT(2, belay("diff", "--scope", g_scope, "--since", "zero", NULL));
    ASSERT_EQ_INT(2, belay("diff", "--scope", g_scope, "--since", "-3", NULL));
    ASSERT_EQ_INT(2, belay("check", "--scope", g_scope, "--full", NULL));          /* mark's */
    ASSERT_EQ_INT(2, belay("check", "--scope", g_scope, "--since", "1", NULL));    /* diff's */
    ASSERT_EQ_INT(2, belay("mark", "--scope", g_scope, "--full-every", "x", NULL));
    ASSERT_EQ_STR("", g_out);                                   /* nothing on stdout for an error */
}

/* Review 2026-10-31, Phase 5, 10 and 15: an error is one line; ids are
 * digits without a leading zero; --full-every is a number (0: never), and
 * mark's and diff's only. */
TEST(a_usage_error_is_one_line_and_ids_are_strict) {
    ASSERT_EQ_INT(2, belay("check", "--scope", g_scope, "--bogus", NULL));
    size_t lines = 0;
    for (const char *c = g_err; *c; c++) lines += *c == '\n';
    ASSERT_EQ_INT(1, (int)lines);
    ASSERT_EQ_INT(2, belay(NULL));
    ASSERT_TRUE(strchr(g_err, '\n') == strrchr(g_err, '\n'));
    ASSERT_EQ_INT(2, belay("diff", "--scope", g_scope, "--since", "01", NULL));
    ASSERT_EQ_INT(2, belay("diff", "--scope", g_scope, "--since", "+1", NULL));
    ASSERT_EQ_INT(2, belay("diff", "--scope", g_scope, "--since", "99999999999999999999", NULL));
    ASSERT_EQ_INT(2, belay("mark", "--scope", g_scope, "--full-every", "", NULL));
    ASSERT_EQ_INT(2, belay("mark", "--scope", g_scope, "--full-every", "-1", NULL));
    ASSERT_EQ_INT(2, belay("check", "--scope", g_scope, "--full-every", "3", NULL));
    ASSERT_EQ_INT(2, belay("log", "--scope", g_scope, "--full-every", "3", NULL));
    ASSERT_EQ_INT(0, belay("help", "check", NULL));
    ASSERT_TRUE(strstr(g_out, "schema/checkpoint.v1.json") != NULL);
}

TEST(help_and_version_exit_0) {
    ASSERT_EQ_INT(0, belay("--version", NULL));
    ASSERT_TRUE(strncmp(g_out, "belay ", 6) == 0);
    ASSERT_EQ_INT(0, belay("help", NULL));
    ASSERT_TRUE(strstr(g_out, "exit codes") != NULL);
    static const char *const cmds[] = { "check", "mark", "diff", "log" };
    for (size_t i = 0; i < 4; i++) {
        if (belay(cmds[i], "--help", NULL) != 0 || strncmp(g_out, "usage: belay ", 13) != 0)
            BELAY_FAIL("%s --help", cmds[i]);
        if (belay("help", cmds[i], NULL) != 0) BELAY_FAIL("help %s", cmds[i]);
    }
    ASSERT_EQ_INT(2, belay("help", "nope", NULL));
}

/* Q7: the binary has no session command. */
TEST(the_session_engine_is_not_a_command) {
    ASSERT_EQ_INT(2, belay("run", NULL));
    ASSERT_TRUE(strstr(g_err, "unknown command run") != NULL);
    ASSERT_EQ_INT(2, belay("commit", NULL));
    ASSERT_EQ_INT(2, belay("discard", NULL));
}

/* §5.1.1, the scope's resolution: each refusal is exit 3 and one line. */
TEST(a_scope_that_cannot_be_resolved_is_refused_exit_3) {
    fresh();
    char p[600];
    snprintf(p, sizeof p, "%s/missing", g_dir);
    ASSERT_EQ_INT(3, belay("check", "--scope", p, NULL));
    snprintf(p, sizeof p, "%s/tool", g_scope);
    ASSERT_EQ_INT(3, belay("check", "--scope", p, NULL));              /* a file */
    ASSERT_TRUE(strstr(g_err, "not a directory") != NULL);
    sh("ln -sfn loop2 '%s/loop1' && ln -sfn loop1 '%s/loop2'", g_dir, g_dir);
    snprintf(p, sizeof p, "%s/loop1", g_dir);
    ASSERT_EQ_INT(3, belay("check", "--scope", p, NULL));              /* a symlink loop */
    ASSERT_EQ_INT(3, belay("check", "--scope", "", NULL));
    static char longp[8192];
    memset(longp, 'a', sizeof longp - 1);
    longp[0] = '/';
    ASSERT_EQ_INT(3, belay("check", "--scope", longp, NULL));          /* over PATH_MAX */
    if (geteuid() != 0) {                                                /* root reads anything */
        sh("mkdir -p '%s/locked/in' && chmod 000 '%s/locked'", g_dir, g_dir);
        snprintf(p, sizeof p, "%s/locked/in", g_dir);
        ASSERT_EQ_INT(3, belay("check", "--scope", p, NULL));
        sh("chmod 700 '%s/locked'", g_dir);
    }
    ASSERT_EQ_STR("", g_out);
}

/* A symlink, "..", ".", "//", a trailing "/" and a relative path are
 * resolved once, against the filesystem; the resolved path is recorded. */
TEST(a_scope_is_resolved_once_to_its_real_path) {
    fresh();
    char p[700];
    sh("ln -sfn '%s' '%s/link'", g_scope, g_dir);
    static const char *const forms[] = { "%s/link", "%s/proj/src/..", "%s/proj/./", "%s//proj//" };
    for (size_t i = 0; i < 4; i++) {
        snprintf(p, sizeof p, forms[i], g_dir);
        if (belay("check", "--scope", p, "--json", NULL) != 0) { BELAY_FAIL("%s: %s", p, g_err); continue; }
        char want[700];
        snprintf(want, sizeof want, "\"scope\":\"%s\"", g_scope);
        if (strstr(g_out, want) == NULL) BELAY_FAIL("%s recorded as: %s", p, g_out);
    }
    char cwd[600];
    REQUIRE(getcwd(cwd, sizeof cwd) != NULL);
    REQUIRE(chdir(g_dir) == 0);
    ASSERT_EQ_INT(0, belay("check", "--scope", "proj", NULL));           /* relative */
    REQUIRE(chdir(cwd) == 0);
}

/* §5.1.1: a component swapped for a symlink between realpath() and the open
 * is refused, never followed. */
static char g_victim[600];
static void swap_in_link(const char *resolved) {
    (void)resolved;
    char aside[700], cmd[4000];
    snprintf(aside, sizeof aside, "%s.aside", g_victim);
    snprintf(cmd, sizeof cmd, "mv '%s' '%s' && mkdir -p '%s/elsewhere' && ln -s '%s/elsewhere' '%s'",
             g_victim, aside, g_dir, g_dir, g_victim);
    if (system(cmd) != 0) { /* the assertions say */ }
}

TEST(a_component_swapped_after_resolution_is_refused) {
    fresh();
    snprintf(g_victim, sizeof g_victim, "%s/proj/src", g_dir);
    scope_resolve_hook = swap_in_link;
    char p[600];
    snprintf(p, sizeof p, "%s/proj/src", g_dir);
    const int rc = belay("check", "--scope", p, NULL);
    scope_resolve_hook = NULL;
    ASSERT_EQ_INT(3, rc);
    ASSERT_TRUE(strstr(g_err, "changed during resolution") != NULL);
    sh("rm -f '%s' && mv '%s.aside' '%s'", g_victim, g_victim, g_victim);
}

/* The scope swapped for another directory after it was resolved and before
 * the walk opened it: the walk's (dev, ino) check refuses it, exit 3. */
static void swap_scope(const char *scope) {
    char cmd[2000];
    snprintf(cmd, sizeof cmd, "mv '%s' '%s.aside' && mkdir '%s'", scope, scope, scope);
    if (system(cmd) != 0) { /* the assertions say */ }
}

TEST(a_scope_swapped_before_the_walk_is_refused) {
    fresh();
    state_capture_hook = swap_scope;
    const int rc = belay("check", "--scope", g_scope, NULL);
    state_capture_hook = NULL;
    ASSERT_EQ_INT(3, rc);
    ASSERT_TRUE(strstr(g_err, "changed during resolution") != NULL);
    sh("rm -rf '%s' && mv '%s.aside' '%s'", g_scope, g_scope, g_scope);
}

/* Q6: belay's own state directory inside a scope is not recorded, and the
 * output says so -- never silent. */
TEST(the_state_directory_inside_the_scope_is_excluded_and_said) {
    fresh();
    char inside[700];
    snprintf(inside, sizeof inside, "%s/.state", g_scope);
    setenv("BELAY_STATE_DIR", inside, 1);
    const int rc = belay("check", "--scope", g_scope, NULL);
    setenv("BELAY_STATE_DIR", g_state, 1);
    ASSERT_EQ_INT(0, rc);
    ASSERT_TRUE(strstr(g_out, "not recorded: belay's own state directory") != NULL);
    char man[2400];
    snprintf(man, sizeof man, "grep -c '\"path\":\".state' %s/scopes/*/checkpoints/1/manifest.ndjson > %s/count", inside, g_dir);
    sh("%s; true", man);
    char cnt[1200];
    snprintf(cnt, sizeof cnt, "%s/count", g_dir);
    FILE *f = fopen(cnt, "r");
    int n = -1;
    if (f) { if (fscanf(f, "%d", &n) != 1) n = -1; fclose(f); }
    ASSERT_EQ_INT(0, n);
}

/* Q3, Q4: diff --since keeps its capture; --exit-code is 1 on any record. */
TEST(diff_keeps_its_capture_and_exit_code_is_opt_in) {
    fresh();
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--exit-code", NULL));   /* nothing changed */
    ASSERT_TRUE(strstr(g_out, "no changes") != NULL);
    sh("printf 'a\\nB\\nc\\n' > '%s/src/x.txt'", g_scope);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", NULL));                  /* default: 0 */
    ASSERT_TRUE(strstr(g_out, "+2 -1 lines, first change at line 2") != NULL);
    ASSERT_EQ_INT(1, belay("diff", "--scope", g_scope, "--since", "1", "--exit-code", NULL));
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_out, "check 1") != NULL && strstr(g_out, "diff 4") != NULL);   /* kept */
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "2", "--json", NULL));
    ASSERT_TRUE(strncmp(g_out, "{\"belay_diff\":1,", 16) == 0);
    ASSERT_EQ_INT(2, belay("diff", "--scope", g_scope, "--since", "99", NULL));          /* no such */
}

/* Q8, and mark's other full-walk triggers, each said. */
TEST(mark_says_when_it_reads_every_file) {
    fresh();
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"full_reason\":\"no checkpoint before\"") != NULL);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"used\":true") != NULL);
    /* The state directory is on the scope's filesystem here: the previous
     * walk's start is the reference point (second review, D3). */
    ASSERT_TRUE(strstr(g_out, "\"reference\":\"walk_start\"") != NULL);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--full", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"full_reason\":\"asked for (--full)\"") != NULL);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--full-every", "2", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"used\":true") != NULL);              /* one since the full one */
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--full-every", "2", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"full_reason\":\"every 2 marks\"") != NULL);
    /* ctime going backwards: the latest manifest made to claim a newer ctime
     * than the tree holds. */
    sh("f=$(ls -d '%s'/scopes/*/checkpoints/5/manifest.ndjson) && "
       "sed -i.bak 's/\"ctime_ns\":[0-9]*/\"ctime_ns\":9000000000000000000/' \"$f\"", g_state);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "ctime went backwards") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"used\":false") != NULL);
}

TEST(log_lists_checkpoints_or_says_there_are_none) {
    fresh();
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_out, "no checkpoints") != NULL);
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, "--json", NULL));
    if (strncmp(g_out, "{\"id\":1,\"kind\":\"check\",", 23) != 0) BELAY_FAIL("log --json: %.200s", g_out);
}

/* The scope directory under the state root, into buf. */
static void scope_dir(char *buf, size_t cap) {
    char cmd[1200], f[700];
    snprintf(f, sizeof f, "%s/sdir", g_dir);
    snprintf(cmd, sizeof cmd, "ls -d '%s'/scopes/* | head -1 > '%s'", g_state, f);
    sh("%s", cmd);
    buf[0] = '\0';
    FILE *in = fopen(f, "r");
    if (in) { if (fgets(buf, (int)cap, in) == NULL) buf[0] = '\0'; fclose(in); }
    buf[strcspn(buf, "\n")] = '\0';
}

static bool empty_dir(const char *p) {
    char cmd[2600];
    snprintf(cmd, sizeof cmd, "[ -z \"$(ls -A '%s' 2>/dev/null)\" ]", p);
    return system(cmd) == 0;
}

/* Review 2026-10-31, Phase 5, 1: nothing in the state directory is written
 * through a symlink, and a root others could plant links in is refused. */
TEST(the_state_directory_never_writes_through_a_link) {
    fresh();
    char d[700], out[700];
    snprintf(out, sizeof out, "%s/outside", g_dir);
    sh("rm -rf '%s' && mkdir -p '%s/cp' && printf 'IMPORTANT\\n' > '%s/victim'", out, out, out);
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    scope_dir(d, sizeof d);
    REQUIRE(d[0] != '\0');
    /* checkpoints/ a symlink: refused, nothing written outside. */
    sh("mv '%s/checkpoints' '%s/cp.real' && ln -s '%s/cp' '%s/checkpoints'", d, d, out, d);
    ASSERT_EQ_INT(4, belay("check", "--scope", g_scope, NULL));
    char cp[2400];
    snprintf(cp, sizeof cp, "%s/cp", out);
    ASSERT_TRUE(empty_dir(cp));
    sh("rm '%s/checkpoints' && mv '%s/cp.real' '%s/checkpoints'", d, d, d);
    /* lock a dangling symlink: refused, nothing created. */
    sh("rm '%s/lock' && ln -s '%s/created-by-lock' '%s/lock'", d, out, d);
    ASSERT_EQ_INT(4, belay("check", "--scope", g_scope, NULL));
    snprintf(cp, sizeof cp, "%s/created-by-lock", out);
    ASSERT_TRUE(access(cp, F_OK) == -1);
    sh("rm '%s/lock'", d);
    /* scope.tmp planted before the scope file is written: unlinked, never followed. */
    sh("rm '%s/scope' && ln -s '%s/victim' '%s/scope.tmp'", d, out, d);
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    snprintf(cp, sizeof cp, "grep -qx IMPORTANT '%s/victim' && [ -f '%s/scope' ] && [ ! -L '%s/scope' ]", out, d, d);
    ASSERT_EQ_INT(0, system(cp));
    /* A root others can write: refused, exit 3. */
    sh("chmod 777 '%s'", g_state);
    ASSERT_EQ_INT(3, belay("check", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_err, "writable by others") != NULL);
    sh("chmod 700 '%s'", g_state);
}

/* Review 2026-10-31, Phase 5, 2: a FIFO where belay reads its own state is
 * corrupt state, exit 4 -- never a wait. */
static sigjmp_buf g_hang;
static void on_alarm(int sig) { (void)sig; siglongjmp(g_hang, 1); }

TEST(a_fifo_in_the_state_directory_is_corrupt_not_a_wait) {
    fresh();
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    char d[700];
    scope_dir(d, sizeof d);
    REQUIRE(d[0] != '\0');
    struct sigaction sa = { 0 }, old;
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, &old);
    static const char *const where[] = { "checkpoints/7/meta.json", "scope" };
    for (size_t i = 0; i < 2; i++) {
        if (i == 0) sh("mkdir -p '%s/checkpoints/7' && mkfifo '%s/%s'", d, d, where[i]);
        else sh("rm -rf '%s/checkpoints/7' && rm '%s/scope' && mkfifo '%s/scope'", d, d, d);
        volatile int rc = -1;
        if (sigsetjmp(g_hang, 1) == 0) {
            alarm(5);
            rc = belay(i == 0 ? "log" : "check", "--scope", g_scope, NULL);
            alarm(0);
            ASSERT_EQ_INT(4, rc);
        } else {
            BELAY_FAIL("a FIFO at %s: belay waited on it", where[i]);
        }
    }
    sigaction(SIGALRM, &old, NULL);
}

/* Review 2026-10-31, Phase 5, 3: captures racing on a scope's first use
 * all succeed, one after another, under the lock. */
TEST(concurrent_first_captures_all_succeed) {
  for (int round = 0; round < 20; round++) {     /* contention is timing: several rounds */
    fresh();
    enum { N = 6 };
    pid_t kids[N];
    for (int i = 0; i < N; i++) {
        kids[i] = fork();
        if (kids[i] == 0) {
            char ep[800];
            snprintf(ep, sizeof ep, "%s/kid%d.err", g_dir, i);
            FILE *o = fopen("/dev/null", "w"), *e = fopen(ep, "w");
            char *argv[] = { "belay", "check", "--scope", g_scope, NULL };
            const int rc = o && e ? cli_main(4, argv, o, e) : 9;
            if (o) fclose(o);
            if (e) fclose(e);               /* _exit does not flush stdio */
            _exit(rc);
        }
    }
    int ok = 0;
    for (int i = 0; i < N; i++) {
        int st = 0;
        if (kids[i] > 0 && waitpid(kids[i], &st, 0) == kids[i] && WIFEXITED(st) && WEXITSTATUS(st) == 0) ok++;
        else {                                       /* what it said, for the failure line */
            char ep[800], line[600] = "";
            snprintf(ep, sizeof ep, "%s/kid%d.err", g_dir, i);
            FILE *e = fopen(ep, "r");
            if (e != NULL) {
                char l[600];
                while (fgets(l, sizeof l, e) != NULL)
                    if (strstr(l, "waiting") == NULL) snprintf(line, sizeof line, "%s", l);
                fclose(e);
            }
            BELAY_FAIL("child %d: status %d: %s", i, st, line);
        }
    }
    ASSERT_EQ_INT(N, ok);
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, "--json", NULL));
    size_t lines = 0;
    for (const char *c = g_out; *c; c++) lines += *c == '\n';
    ASSERT_EQ_INT(N, (int)lines);
  }
}

/* Review 2026-10-31, Phase 5, 4: a change directly in the scope root is
 * not the clock going backwards, on any mark after it. */
TEST(a_change_in_the_scope_root_keeps_the_prefilter) {
    fresh();
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    sh("rm '%s/tool'", g_scope);
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--json", NULL));
        if (strstr(g_out, "ctime went backwards") != NULL || strstr(g_out, "\"used\":true") == NULL)
            BELAY_FAIL("mark %d after a root change: %.300s", i + 2, g_out);
    }
}

/* Review 2026-10-31, Phase 5, 8: diff's own capture says what any capture
 * says -- in the receipt, or on stderr under --json, never in the JSON. */
TEST(diff_says_what_its_capture_left_out) {
    fresh();
    char inside[700];
    snprintf(inside, sizeof inside, "%s/.state", g_scope);
    setenv("BELAY_STATE_DIR", inside, 1);
    int rc1 = belay("check", "--scope", g_scope, NULL);
    int rc2 = belay("diff", "--scope", g_scope, "--since", "1", NULL);
    const bool said = g_out != NULL && strstr(g_out, "not recorded: belay's own state directory") != NULL;
    int rc3 = belay("diff", "--scope", g_scope, "--since", "1", "--json", NULL);
    setenv("BELAY_STATE_DIR", g_state, 1);
    ASSERT_EQ_INT(0, rc1);
    ASSERT_EQ_INT(0, rc2);
    ASSERT_EQ_INT(0, rc3);
    ASSERT_TRUE(said);
    ASSERT_TRUE(strstr(g_err, "not recorded: belay's own state directory") != NULL);
    ASSERT_TRUE(strstr(g_out, "not recorded") == NULL);
}

/* Review 2026-10-31, Phase 5, 9: a scope that is the state directory, or
 * inside it, would record belay's own writes: refused, exit 3. */
TEST(a_scope_in_the_state_directory_is_refused) {
    fresh();
    ASSERT_EQ_INT(3, belay("check", "--scope", g_state, NULL));
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    char d[700];
    scope_dir(d, sizeof d);
    REQUIRE(d[0] != '\0');
    ASSERT_EQ_INT(3, belay("check", "--scope", d, NULL));
    ASSERT_TRUE(strstr(g_err, "state directory") != NULL);
}

/* Review 2026-10-31, Phase 5, 10 and 11: a directory whose name is not an
 * id is not a checkpoint and does not move the next id; a meta.json larger
 * than 8 KiB is read whole. */
TEST(odd_checkpoint_names_and_long_meta_are_handled) {
    fresh();
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    char d[700];
    scope_dir(d, sizeof d);
    REQUIRE(d[0] != '\0');
    sh("mkdir '%s/checkpoints/99999999999999999999' '%s/checkpoints/05' '%s/checkpoints/+7'", d, d, d);
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    ASSERT_TRUE(strncmp(g_out, "check 2 ", 8) == 0);
    /* A scope whose path escapes to more than 8 KiB of JSON: up to 6 levels
     * of 250 control bytes, as many as PATH_MAX allows (Linux: all 6; on
     * macOS, PATH_MAX 1024, no scope path can reach 8 KiB escaped, and the
     * test only checks such a scope is recorded and listed). */
    char deep[2400];
    int w = snprintf(deep, sizeof deep, "%s", g_scope);
    for (int lvl = 0; lvl < 6 && (size_t)w + 251 < PATH_MAX - 64; lvl++) {
        deep[w++] = '/';
        memset(deep + w, 1, 250);
        w += 250;
        deep[w] = '\0';
        REQUIRE(mkdir(deep, 0700) == 0 || errno == EEXIST);
    }
    ASSERT_EQ_INT(0, belay("check", "--scope", deep, NULL));
    ASSERT_EQ_INT(0, belay("log", "--scope", deep, NULL));
    ASSERT_TRUE(strstr(g_out, "check 1 ") != NULL);
    ASSERT_EQ_INT(0, belay("diff", "--scope", deep, "--since", "1", "--exit-code", NULL));
    sh("rm -rf '%s'/*", g_state);
}

/* Review 2026-10-31, Phase 5, 12: a scope that is not UTF-8 gives JSON
 * that is JSON: scope_b64 and manifest_b64. */
TEST(checkpoint_json_for_a_scope_that_is_not_utf8) {
    fresh();
    char bad[600];
    snprintf(bad, sizeof bad, "%s/bad\xff", g_scope);
    if (mkdir(bad, 0700) == -1) SKIP("this filesystem refuses a name that is not UTF-8");
    ASSERT_EQ_INT(0, belay("check", "--scope", bad, "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"scope_b64\":\"") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"manifest\":\"") != NULL);        /* under the state root: UTF-8 */
    ASSERT_TRUE(strstr(g_out, "\xff") == NULL);
}

/* Review 2026-10-31, Phase 5, 13: search permission on the scope's parents
 * is enough, as it is for the capture itself. */
TEST(a_parent_with_search_permission_only_is_enough) {
#if !defined(O_PATH) && !defined(O_SEARCH)
    SKIP("no O_PATH or O_SEARCH here: a parent must be readable");
#endif
    if (geteuid() == 0) SKIP("root reads anything");
    fresh();
    char p[700];
    snprintf(p, sizeof p, "%s/src", g_scope);
    sh("chmod 311 '%s'", g_scope);
    const int rc = belay("check", "--scope", p, NULL);
    sh("chmod 755 '%s'", g_scope);
    ASSERT_EQ_INT(0, rc);
}

/* Review 2026-10-31, Phase 5, 14: output that cannot be written is exit 4. */
TEST(output_that_cannot_be_written_is_exit_4) {
    FILE *full = fopen("/dev/full", "w");
    if (full == NULL) SKIP("no /dev/full here");
    fresh();
    char *argv[] = { "belay", "check", "--scope", g_scope, "--json", NULL };
    FILE *err = fopen("/dev/null", "w");
    const int rc = cli_main(5, argv, full, err);
    fclose(full);
    if (err) fclose(err);
    ASSERT_EQ_INT(4, rc);
}

/* Review 2026-10-31, Phase 5, 15: a scope directory that names another
 * scope is corrupt state: exit 4, as docs/cli.md says. */
TEST(state_of_another_scope_is_corrupt_exit_4) {
    fresh();
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    char d[700];
    scope_dir(d, sizeof d);
    REQUIRE(d[0] != '\0');
    sh("printf '/elsewhere\\n' > '%s/scope'", d);
    ASSERT_EQ_INT(4, belay("check", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_err, "belongs to the scope /elsewhere") != NULL);
}

/* Second review 2026-10-31, D1: a manifest is opened from the directory
 * fds before its path is handed on -- a link or FIFO planted in its place
 * is corrupt state (exit 4), not a manifest to trust or diff. */
TEST(a_planted_manifest_is_corrupt_state) {
    fresh();
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    char d[700], cmd[4000];
    scope_dir(d, sizeof d);
    REQUIRE(d[0] != '\0');
    for (int id = 1; id <= 2; id++) {     /* 1: diff --to reads it; 2, the latest: mark's previous */
        snprintf(cmd, sizeof cmd, "cp '%s/checkpoints/%d/manifest.ndjson' '%s/elsewhere%d.ndjson' && "
                 "rm '%s/checkpoints/%d/manifest.ndjson' && "
                 "ln -s '%s/elsewhere%d.ndjson' '%s/checkpoints/%d/manifest.ndjson'",
                 d, id, g_dir, id, d, id, g_dir, id, d, id);
        sh("%s", cmd);
        if (id == 1) ASSERT_EQ_INT(4, belay("diff", "--scope", g_scope, "--since", "1", "--to", "2", NULL));
    }
    ASSERT_EQ_INT(4, belay("mark", "--scope", g_scope, NULL));
    sh("rm '%s/checkpoints/2/manifest.ndjson' && mkfifo '%s/checkpoints/2/manifest.ndjson'", d, d);
    struct sigaction sa = { 0 }, old;
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, &old);
    volatile int rc = -1;
    if (sigsetjmp(g_hang, 1) == 0) {
        alarm(5);
        rc = belay("mark", "--scope", g_scope, NULL);
        alarm(0);
        ASSERT_EQ_INT(4, rc);
    } else {
        BELAY_FAIL("%s", "a FIFO for a manifest: belay waited on it");
    }
    sigaction(SIGALRM, &old, NULL);
}

/* Second review 2026-10-31, D2: a state root whose parent others can write
 * could be swapped after it was checked: refused, exit 3. A relative
 * BELAY_STATE_DIR is refused too (D8). */
TEST(a_state_root_others_could_swap_is_refused) {
    fresh();
    char shared[700];
    snprintf(shared, sizeof shared, "%s/shared", g_dir);
    sh("rm -rf '%s' && mkdir -p '%s/st' && chmod 0777 '%s' && chmod 0700 '%s/st'", shared, shared, shared, shared);
    char root[800];
    snprintf(root, sizeof root, "%s/st", shared);
    setenv("BELAY_STATE_DIR", root, 1);
    const int rc = belay("check", "--scope", g_scope, NULL);
    const bool said = strstr(g_err, "above the state directory") != NULL;
    sh("chmod 1777 '%s'", shared);                                   /* sticky, as /tmp: fine */
    const int sticky = belay("check", "--scope", g_scope, NULL);
    setenv("BELAY_STATE_DIR", "relative/state", 1);
    const int rel = belay("check", "--scope", g_scope, NULL);
    setenv("BELAY_STATE_DIR", g_state, 1);
    sh("chmod 0700 '%s'", shared);
    ASSERT_EQ_INT(3, rc);
    ASSERT_TRUE(said);
    ASSERT_EQ_INT(0, sticky);
    ASSERT_EQ_INT(3, rel);
}

/* Second review 2026-10-31, D5: what belay prints back from its state, and
 * errors naming a path, cannot carry a terminal sequence or a second line;
 * a meta.json that is not what belay wrote is corrupt. */
TEST(nothing_printed_back_forges_a_line) {
    fresh();
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    char d[700];
    scope_dir(d, sizeof d);
    REQUIRE(d[0] != '\0');
    sh("mkdir '%s/checkpoints/2' && cp '%s/checkpoints/1/manifest.ndjson' '%s/checkpoints/2/' && "
       "sed 's/\"id\":1,/\"id\":2,/; s/\"full_reason\":\"[^\"]*\"/\"full_reason\":\"\\\\u001b[31mRED\\\\nforged line\"/' "
       "'%s/checkpoints/1/meta.json' > '%s/checkpoints/2/meta.json'", d, d, d, d, d);
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, NULL));
    ASSERT_TRUE(strchr(g_out, '\x1b') == NULL);
    ASSERT_TRUE(strstr(g_out, "\nforged line") == NULL);
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, "--json", NULL));
    ASSERT_TRUE(strchr(g_out, '\x1b') == NULL);
    sh("sed -i.bak 's/\"kind\":\"check\"/\"kind\":\"a\\\\\"}\"/' '%s/checkpoints/2/meta.json'", d);
    ASSERT_EQ_INT(4, belay("log", "--scope", g_scope, "--json", NULL));
    sh("sed 's/\"id\":1,/\"id\":2.5,/' '%s/checkpoints/1/meta.json' > '%s/checkpoints/2/meta.json'", d, d);
    ASSERT_EQ_INT(4, belay("log", "--scope", g_scope, NULL));
    sh("rm -rf '%s/checkpoints/2'", d);
    /* An error naming a scope whose name holds ESC and a newline: one line. */
    char evil[700];
    snprintf(evil, sizeof evil, "%s/evil\x1b[2J\nforged: all clear", g_dir);
    ASSERT_EQ_INT(3, belay("check", "--scope", evil, NULL));
    ASSERT_TRUE(strchr(g_err, '\x1b') == NULL);
    ASSERT_TRUE(strchr(g_err, '\n') == g_err + strlen(g_err) - 1);
}

/* Second review 2026-10-31, D7 and D8: ids run out at 999,999,999 (exit 4,
 * documented); a diff of a scope never captured leaves no state behind. */
TEST(ids_run_out_and_a_failed_diff_leaves_nothing) {
    fresh();
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    char d[700];
    scope_dir(d, sizeof d);
    REQUIRE(d[0] != '\0');
    sh("mkdir '%s/checkpoints/999999999'", d);
    ASSERT_EQ_INT(4, belay("check", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_err, "no checkpoint ids left") != NULL);
    char other[700];
    snprintf(other, sizeof other, "%s/src", g_scope);
    sh("rm -rf '%s'/*", g_state);
    ASSERT_EQ_INT(2, belay("diff", "--scope", other, "--since", "1", NULL));
    ASSERT_TRUE(empty_dir(g_state));
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_cli_%d", (int)getpid());
    mkdir(g_dir, 0700);
    char real[PATH_MAX];
    if (realpath(g_dir, real) != NULL) snprintf(g_dir, sizeof g_dir, "%.200s", real);
    snprintf(g_scope, sizeof g_scope, "%s/proj", g_dir);
    snprintf(g_state, sizeof g_state, "%s/state", g_dir);
    setenv("BELAY_STATE_DIR", g_state, 1);
    RUN(usage_errors_exit_2);
    RUN(help_and_version_exit_0);
    RUN(the_session_engine_is_not_a_command);
    RUN(a_scope_that_cannot_be_resolved_is_refused_exit_3);
    RUN(a_scope_is_resolved_once_to_its_real_path);
    RUN(a_component_swapped_after_resolution_is_refused);
    RUN(a_scope_swapped_before_the_walk_is_refused);
    RUN(the_state_directory_inside_the_scope_is_excluded_and_said);
    RUN(diff_keeps_its_capture_and_exit_code_is_opt_in);
    RUN(mark_says_when_it_reads_every_file);
    RUN(log_lists_checkpoints_or_says_there_are_none);
    RUN(a_usage_error_is_one_line_and_ids_are_strict);
    RUN(the_state_directory_never_writes_through_a_link);
    RUN(a_fifo_in_the_state_directory_is_corrupt_not_a_wait);
    RUN(concurrent_first_captures_all_succeed);
    RUN(a_change_in_the_scope_root_keeps_the_prefilter);
    RUN(diff_says_what_its_capture_left_out);
    RUN(a_scope_in_the_state_directory_is_refused);
    RUN(odd_checkpoint_names_and_long_meta_are_handled);
    RUN(checkpoint_json_for_a_scope_that_is_not_utf8);
    RUN(a_parent_with_search_permission_only_is_enough);
    RUN(output_that_cannot_be_written_is_exit_4);
    RUN(state_of_another_scope_is_corrupt_exit_4);
    RUN(a_planted_manifest_is_corrupt_state);
    RUN(a_state_root_others_could_swap_is_refused);
    RUN(nothing_printed_back_forges_a_line);
    RUN(ids_run_out_and_a_failed_diff_leaves_nothing);
    free(g_out);
    free(g_err);
    char cmd[800];
    snprintf(cmd, sizeof cmd, "chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
