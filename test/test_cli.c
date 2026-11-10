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
#include "belay/manifest.h"

#include <sys/file.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <ftw.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/vfs.h>
#endif
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
    ASSERT_TRUE(strstr(g_out, "schema/checkpoint.v2.json") != NULL);
}

TEST(help_and_version_exit_0) {
    ASSERT_EQ_INT(0, belay("--version", NULL));
    ASSERT_TRUE(strncmp(g_out, "belay ", 6) == 0);
    ASSERT_TRUE(strstr(g_out, " (manifest v4, diff.v1)\n") != NULL);     /* what this build writes */
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
    ASSERT_TRUE(strstr(g_out, "not recorded: .state (belay's own state directory)") != NULL);
    char man[2400];
    snprintf(man, sizeof man, "tail -n +2 %s/scopes/*/checkpoints/1/manifest.ndjson | grep -c '\"path\":\".state' > %s/count; "
             "head -1 %s/scopes/*/checkpoints/1/manifest.ndjson | grep -c '\"excluded\":\\[{\"path\":\".state\",\"reason\":\"state_dir\"' >> %s/count",
             inside, g_dir, inside, g_dir);
    sh("%s; true", man);
    char cnt[1200];
    snprintf(cnt, sizeof cnt, "%s/count", g_dir);
    FILE *f = fopen(cnt, "r");
    int n = -1;
    int named = -1;
    if (f) { if (fscanf(f, "%d %d", &n, &named) != 2) n = -1; fclose(f); }
    ASSERT_EQ_INT(0, n);                        /* no entry */
    ASSERT_EQ_INT(1, named);                    /* and named in the v2 header, reason state_dir */
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
    /* checkpoint.v1 CK-16 (decision 210): the manifest's source, last; a walk here is null */
    const size_t ol = strlen(g_out);
    ASSERT_TRUE(ol > 46 && strcmp(g_out + ol - 46, ",\"source\":null,\"stored\":\"whole\",\"kept\":false}\n") == 0);
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
    const bool said = g_out != NULL && strstr(g_out, "\nnot compared\n  .state   belay's own state directory\n") != NULL;
    int rc3 = belay("diff", "--scope", g_scope, "--since", "1", "--json", NULL);
    setenv("BELAY_STATE_DIR", g_state, 1);
    ASSERT_EQ_INT(0, rc1);
    ASSERT_EQ_INT(0, rc2);
    ASSERT_EQ_INT(0, rc3);
    ASSERT_TRUE(said);
    ASSERT_TRUE(strstr(g_err, "belay: not compared: .state (belay's own state directory)") != NULL);
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

/* User excludes (decision 2026-11-01, 3): configured per scope, refused
 * when not a canonical relative path, at most 31. */
/* KP-1, KP-2: a kept checkpoint says so in meta.json and in the log, and
 * no other checkpoint's meta.json changes. */
TEST(mark_keep_is_recorded_and_shown) {
    fresh();
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--keep", NULL));
    ASSERT_TRUE(strstr(g_out, ", kept\n") != NULL);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_out, "kept") == NULL);
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, NULL));
    const char *first = strstr(g_out, "check 1"), *second = strstr(g_out, "mark 2"), *third = strstr(g_out, "mark 3");
    ASSERT_TRUE(first != NULL && second != NULL && third != NULL);
    ASSERT_TRUE(strstr(second, ", kept\n") != NULL && strstr(second, ", kept\n") < third);
    ASSERT_TRUE(strstr(third, "kept") == NULL);
    ASSERT_TRUE(strstr(first, ", kept\n") == strstr(second, ", kept\n"));
    char c[900];
    snprintf(c, sizeof c, "d=$(ls -d '%s'/scopes/*) && grep -q '\"kept\":true' \"$d/checkpoints/2/meta.json\" && "
             "! grep -q kept \"$d/checkpoints/1/meta.json\" && ! grep -q kept \"$d/checkpoints/3/meta.json\"", g_state);
    ASSERT_EQ_INT(0, system(c));
    ASSERT_EQ_INT(2, belay("check", "--scope", g_scope, "--keep", NULL));
    ASSERT_EQ_INT(2, belay("log", "--scope", g_scope, "--keep", NULL));
}

/* A shell check that counts, with $d the scope's state directory. */
static bool holds(const char *fmt, ...) {
    char body[1536], cmd[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof body, fmt, ap);
    va_end(ap);
    snprintf(cmd, sizeof cmd, "d=$(ls -d '%s'/scopes/*) && %s", g_state, body);
    return system(cmd) == 0;
}

/* A scope with checkpoints 1..n, a new text version in each: a.txt holds its
 * checkpoint's id, so each one stores a copy no other refers to. */
static void history(int n) {
    fresh();
    for (int i = 1; i <= n; i++) {
        sh("printf 'version %d\n' > '%s/a.txt'", i, g_scope);
        ASSERT_EQ_INT(0, i == 1 ? belay("check", "--scope", g_scope, NULL) : belay("mark", "--scope", g_scope, "--full", NULL));
    }
}

static bool has_checkpoint(int id) {
    char p[600];
    snprintf(p, sizeof p, "ls -d '%s'/scopes/*/checkpoints/%d >/dev/null 2>&1", g_state, id);
    return system(p) == 0;
}

static int store_objects(void) {
    char c[600];
    snprintf(c, sizeof c, "find '%s'/scopes/*/store -type f | wc -l", g_state);
    FILE *f = popen(c, "r");
    int n = -1;
    if (f != NULL) { if (fscanf(f, "%d", &n) != 1) n = -1; pclose(f); }
    return n;
}

TEST(prune_needs_a_limit_and_good_values) {
    history(2);
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(2, belay("prune", "--keep-last", "1", NULL));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--keep-last", "x", NULL));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--keep-days", "-1", NULL));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--keep-last", "1", "--keep-id", "0", NULL));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--keep-last", "1", "--keep-from", "x", NULL));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--keep-last", NULL));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--nope", NULL));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--keep-last", "1", "--keep-last", "2", NULL));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--keep-days", "1", "--keep-days", "2", NULL));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--scope", g_scope, "--keep-last", "1", NULL));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--keep-last", "1", "--keep-from", "1", "--keep-from", "2", NULL));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--keep-last", "0", "--keep-from", "99", NULL));
    static const char *const bad[] = { " 1", "\n1", "+1", "1234567890", "" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        if (belay("prune", "--scope", g_scope, "--keep-last", bad[i], NULL) != 2) BELAY_FAIL("accepted: \"%s\"", bad[i]);
    ASSERT_TRUE(has_checkpoint(1) && has_checkpoint(2));
}

/* PR-2, PR-10: outside the limit goes, and a command naming it is refused. */
TEST(prune_removes_what_is_outside_the_count) {
    history(5);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "2", NULL));
    ASSERT_TRUE(strstr(g_out, "removed 3 of 5 checkpoints") != NULL && strstr(g_out, ": 1-3\n") != NULL);
    ASSERT_TRUE(!has_checkpoint(1) && !has_checkpoint(3) && has_checkpoint(4) && has_checkpoint(5));
    ASSERT_EQ_INT(2, belay("diff", "--scope", g_scope, "--since", "2", "--to", "5", NULL));
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "4", "--to", "5", NULL));
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_TRUE(has_checkpoint(6));
}

/* PR-2: both limits given, a checkpoint within either stays. */
TEST(prune_keeps_what_is_within_either_limit) {
    history(4);
    ASSERT_TRUE(holds("for i in 1 2 3; do sed -i.bak 's/\"created_ns\":[0-9]*/\"created_ns\":1000/' \"$d/checkpoints/$i/meta.json\" && "
                      "rm \"$d/checkpoints/$i/meta.json.bak\"; done"));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-days", "1", "--keep-last", "2", NULL));
    ASSERT_TRUE(!has_checkpoint(1) && !has_checkpoint(2) && has_checkpoint(3) && has_checkpoint(4));
    history(3);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-days", "1", NULL));
    ASSERT_TRUE(has_checkpoint(1) && has_checkpoint(2) && has_checkpoint(3));
}

/* PR-3: the newest and a kept one survive any limit, and --keep-from too. */
TEST(prune_never_removes_the_newest_a_kept_one_or_a_pending_diff) {
    history(3);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--keep", NULL));
    sh("printf 'more\n' > '%s/a.txt'", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "0", "--keep-from", "3", NULL));
    ASSERT_TRUE(!has_checkpoint(1) && !has_checkpoint(2) && has_checkpoint(3) && has_checkpoint(4) && has_checkpoint(5));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "0", NULL));
    ASSERT_TRUE(!has_checkpoint(3) && has_checkpoint(4) && has_checkpoint(5));
}

/* KP-3: for good; refused for an id that isn't there, with nothing removed;
 * a dry run records nothing. */
TEST(prune_keep_id_lasts_and_is_checked) {
    history(4);
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--keep-last", "0", "--keep-id", "99", NULL));
    ASSERT_TRUE(has_checkpoint(1));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "0", "--keep-id", "2", "--dry-run", NULL));
    ASSERT_TRUE(strstr(g_out, "would remove 2 of 4 checkpoints") != NULL && strstr(g_out, "kept 1: 2\n") != NULL);
    ASSERT_TRUE(holds("! grep -q kept \"$d/checkpoints/2/meta.json\""));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "0", "--keep-id", "2", NULL));
    ASSERT_TRUE(!has_checkpoint(1) && has_checkpoint(2) && !has_checkpoint(3) && has_checkpoint(4));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "0", NULL));
    ASSERT_TRUE(has_checkpoint(2));
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_out, ", kept\n") != NULL);
}

/* PR-7: a dry run changes nothing, byte for byte, and says what a run does. */
TEST(prune_dry_run_changes_nothing_and_tells_the_truth) {
    history(4);
    char before[1024], said[1024];
    ASSERT_TRUE(holds("cd '%s' && find . -type f | sort | xargs cat | cksum > '%s/before'", g_state, g_dir));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", "--dry-run", "--json", NULL));
    snprintf(said, sizeof said, "%s", g_out);
    ASSERT_TRUE(holds("cd '%s' && find . -type f | sort | xargs cat | cksum > '%s/after' && cmp '%s/before' '%s/after'", g_state, g_dir, g_dir, g_dir));
    ASSERT_TRUE(strstr(said, "\"dry_run\":true,\"removed\":3,\"remaining\":1") != NULL);
    ASSERT_TRUE(strstr(said, "\"store_objects\":3") != NULL);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", "--json", NULL));
    snprintf(before, sizeof before, "%s", g_out);
    ASSERT_TRUE(strstr(before, "\"dry_run\":false,\"removed\":3,\"remaining\":1") != NULL);
    ASSERT_EQ_STR(strchr(said, ','), strchr(before, ','));
}

/* PR-6: an object only a removed checkpoint named goes; one that stays is
 * still read, by a diff that needs its content. */
TEST(prune_sweeps_the_store_and_what_stays_still_works) {
    history(4);
    const int all = store_objects();
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "2", NULL));
    ASSERT_EQ_INT(all - 2, store_objects());
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "3", "--to", "4", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "text_changed") != NULL || strstr(g_out, "text_rewritten") != NULL);
    ASSERT_TRUE(strstr(g_out, "content_unavailable") == NULL);
}

/* Keeps a copy of each manifest as it was written: the newest is always whole. */
static void history_copied(int n) {
    fresh();
    sh("mkdir -p '%s/copies'", g_dir);
    for (int i = 1; i <= n; i++) {
        sh("printf 'version %d\n' > '%s/a.txt'", i, g_scope);
        if (i % 7 == 0) sh("printf 'new\n' > '%s/f%d.txt'", g_scope, i);
        if (i % 11 == 0) sh("rm -f '%s/f%d.txt'", g_scope, i - 4);
        ASSERT_EQ_INT(0, i == 1 ? belay("check", "--scope", g_scope, NULL) : belay("mark", "--scope", g_scope, "--full", NULL));
        ASSERT_TRUE(holds("cp \"$d/checkpoints/%d/manifest.ndjson\" '%s/copies/%d'", i, g_dir, i));
    }
}

/* What `belay manifest` prints for `id` is what was written, byte for byte. */
static bool same_as_written(int id) {
    char n[16], p[600];
    snprintf(n, sizeof n, "%d", id);
    if (belay("manifest", "--scope", g_scope, "--id", n, NULL) != 0) return false;
    snprintf(p, sizeof p, "%s/copies/%d", g_dir, id);
    FILE *f = fopen(p, "r");
    if (f == NULL) return false;
    size_t len = strlen(g_out), got = 0;
    char *b = malloc(len + 2);
    if (b != NULL) got = fread(b, 1, len + 1, f);
    fclose(f);
    const bool same = b != NULL && got == len && memcmp(b, g_out, len) == 0;
    free(b);
    return same;
}

/* ST-1, ST-2, ST-3, ST-4: only the newest is whole, and every other rebuilds
 * byte for byte. */
TEST(delta_rebuilds_every_checkpoint_byte_for_byte) {
    history_copied(40);
    for (int i = 1; i <= 40; i++)
        if (!same_as_written(i)) BELAY_FAIL("checkpoint %d", i);
    ASSERT_TRUE(holds("[ -f \"$d/checkpoints/40/manifest.ndjson\" ] && [ ! -f \"$d/checkpoints/39/manifest.ndjson\" ] && "
                      "[ -f \"$d/checkpoints/39/manifest.delta\" ] && [ -f \"$d/checkpoints/1/manifest.ndjson\" ]"));
}

/* ST-2: a full copy after 255 deltas, and the chain starts again. */
TEST(delta_keeps_a_full_copy_every_256) {
    history_copied(262);
    ASSERT_TRUE(holds("[ -f \"$d/checkpoints/1/manifest.ndjson\" ] && [ -f \"$d/checkpoints/257/manifest.ndjson\" ] && "
                      "[ ! -f \"$d/checkpoints/256/manifest.ndjson\" ] && [ ! -f \"$d/checkpoints/258/manifest.ndjson\" ] && "
                      "[ ! -f \"$d/checkpoints/257/manifest.delta\" ]"));
    ASSERT_TRUE(holds("grep -q '\"chain\":255}' \"$d/checkpoints/256/manifest.delta\" && grep -q '\"chain\":1}' \"$d/checkpoints/258/manifest.delta\""));
    static const int ids[] = { 2, 128, 255, 256, 257, 258, 261, 262 };
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++)
        if (!same_as_written(ids[i])) BELAY_FAIL("checkpoint %d", ids[i]);
}

/* ST-4: a delta that doesn't hash is corrupt state, and nothing partial shows. */
TEST(delta_that_does_not_rebuild_is_corrupt) {
    history_copied(5);
    ASSERT_TRUE(holds("sed -i.bak 's/version 2/version 9/; s/=1$/=2/' \"$d/checkpoints/3/manifest.delta\" && rm \"$d/checkpoints/3/manifest.delta.bak\""));
    ASSERT_TRUE(holds("printf '+tampered\n' >> \"$d/checkpoints/3/manifest.delta\""));
    ASSERT_EQ_INT(4, belay("manifest", "--scope", g_scope, "--id", "3", NULL));
    ASSERT_EQ_STR("", g_out);
    ASSERT_EQ_INT(4, belay("manifest", "--scope", g_scope, "--id", "4", NULL));     /* what builds on it too */
    ASSERT_TRUE(belay("diff", "--scope", g_scope, "--since", "3", "--to", "5", NULL) != 0);
    ASSERT_EQ_INT(4, belay("prune", "--scope", g_scope, "--keep-last", "4", NULL));
    ASSERT_TRUE(has_checkpoint(1));
}

/* ST-4, the hash alone: a delta still well formed, its operations all valid,
 * that rebuilds to the wrong bytes. Only the check against the recorded sha256
 * can tell, and nothing of it reaches a reader. */
TEST(delta_that_rebuilds_wrong_bytes_is_refused_by_its_hash) {
    history_copied(5);
    ASSERT_TRUE(holds("sed -i.bak '/^+{\"path\":\"a.txt\"/s/\"uid\":[0-9]*/\"uid\":424242/' \"$d/checkpoints/3/manifest.delta\" && "
                      "rm \"$d/checkpoints/3/manifest.delta.bak\" && grep -q 424242 \"$d/checkpoints/3/manifest.delta\""));
    ASSERT_EQ_INT(4, belay("manifest", "--scope", g_scope, "--id", "3", NULL));
    ASSERT_EQ_STR("", g_out);
    ASSERT_TRUE(strstr(g_err, "does not match what was recorded") != NULL);
    ASSERT_TRUE(belay("diff", "--scope", g_scope, "--since", "1", "--to", "3", NULL) != 0);
    char bundle[500], sha[65];
    snprintf(bundle, sizeof bundle, "%s/bundle", g_dir);
    ASSERT_EQ_INT(0, belay("baseline", "export", "--scope", g_scope, "--out", bundle, "--json", NULL));
    const char *s = strstr(g_out, "\"sha256\":\"");
    ASSERT_TRUE(s != NULL);
    snprintf(sha, sizeof sha, "%.64s", s + 10);
    ASSERT_TRUE(belay("verify", "--scope", g_scope, "--baseline", bundle, "--baseline-sha256", sha, "--to", "3", NULL) != 0);
}

/* A delta made from another base: refused though its operations apply. */
TEST(delta_from_another_base_is_refused) {
    history_copied(5);
    ASSERT_TRUE(holds("sed -i.bak '1s/\"base_sha256\":\"[0-9a-f]*\"/\"base_sha256\":\"%064d\"/' \"$d/checkpoints/4/manifest.delta\" && "
                      "rm \"$d/checkpoints/4/manifest.delta.bak\"", 0));
    ASSERT_EQ_INT(4, belay("manifest", "--scope", g_scope, "--id", "4", NULL));
    ASSERT_TRUE(strstr(g_err, "not the one it was made from") != NULL);
}

/* ST-3: a lost base, and a link for a delta, are corrupt too. */
TEST(delta_with_no_base_or_a_link_is_corrupt) {
    history_copied(5);
    ASSERT_TRUE(holds("rm \"$d/checkpoints/2/manifest.delta\""));
    ASSERT_EQ_INT(4, belay("manifest", "--scope", g_scope, "--id", "3", NULL));
    history_copied(4);
    ASSERT_TRUE(holds("mv \"$d/checkpoints/2/manifest.delta\" \"$d/elsewhere\" && ln -s \"$d/elsewhere\" \"$d/checkpoints/2/manifest.delta\""));
    ASSERT_EQ_INT(4, belay("manifest", "--scope", g_scope, "--id", "2", NULL));
}

/* ST-5: a crash left both: the whole file is used, and nothing else changes. */
TEST(delta_beside_a_whole_file_uses_the_whole_file) {
    history_copied(4);
    ASSERT_TRUE(holds("cp '%s/copies/3' \"$d/checkpoints/3/manifest.ndjson\"", g_dir));
    ASSERT_TRUE(holds("printf 'garbage\n' > \"$d/checkpoints/3/manifest.delta\""));
    ASSERT_TRUE(same_as_written(3));
}

/* ST-6: checkpoints from before deltas stay whole, and chains start after them. */
TEST(delta_reads_checkpoints_stored_whole) {
    history_copied(4);
    ASSERT_TRUE(holds("for i in 2 3; do cp '%s/copies/'$i \"$d/checkpoints/$i/manifest.ndjson\"; rm \"$d/checkpoints/$i/manifest.delta\"; done; rm \"$d/checkpoints/4/manifest.delta\"", g_dir));
    for (int i = 1; i <= 4; i++) ASSERT_TRUE(same_as_written(i));
    sh("printf 'more\n' > '%s/a.txt'", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_TRUE(holds("[ -f \"$d/checkpoints/4/manifest.ndjson\" ] && [ -f \"$d/checkpoints/5/manifest.delta\" ]"));
    ASSERT_TRUE(same_as_written(4));
}

/* PR-4: pruning through a chain: what stays still rebuilds, the newest's delta
 * included, and the capture after it. */
TEST(prune_through_a_chain_leaves_what_stays_readable) {
    history_copied(12);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "5", NULL));
    for (int i = 8; i <= 12; i++) if (!same_as_written(i)) BELAY_FAIL("checkpoint %d", i);
    ASSERT_TRUE(holds("[ -f \"$d/checkpoints/8/manifest.ndjson\" ] && [ ! -f \"$d/checkpoints/8/manifest.delta\" ]"));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "0", NULL));
    ASSERT_TRUE(same_as_written(12));
    sh("printf 'after\n' > '%s/a.txt'", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_TRUE(same_as_written(12));
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "12", "--to", "13", NULL));
}

/* PR-7 with deltas: the whole files a prune must write count against it. */
TEST(prune_reports_exactly_what_it_frees_through_a_chain) {
    history_copied(9);
    ASSERT_TRUE(holds("find \"$d\" -type f -exec cat {} + | wc -c > '%s/size-before'", g_dir));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "3", "--dry-run", "--json", NULL));
    long long bytes = -1, store = -1;
    ASSERT_TRUE(sscanf(strstr(g_out, "\"bytes\":"), "\"bytes\":%lld", &bytes) == 1 &&
                sscanf(strstr(g_out, "\"store_bytes\":"), "\"store_bytes\":%lld", &store) == 1);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "3", NULL));
    ASSERT_TRUE(holds("find \"$d\" -type f -exec cat {} + | wc -c > '%s/size-after'", g_dir));
    char c[1000];
    snprintf(c, sizeof c, "[ $(( $(cat '%s/size-before') - $(cat '%s/size-after') )) -le %lld ]", g_dir, g_dir, bytes + store);
    ASSERT_EQ_INT(0, system(c));
}

/* C2-2..C2-4: what log and mark print. */
TEST(checkpoint_v2_says_how_it_is_stored) {
    history_copied(3);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--keep", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"stored\":\"whole\"") != NULL && strstr(g_out, "\"kept\":true") != NULL && strstr(g_out, "\"manifest\":\"") != NULL);
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, "--json", NULL));
    const char *two = strstr(g_out, "{\"id\":2,"), *three = strstr(g_out, "{\"id\":3,");
    ASSERT_TRUE(two != NULL && three != NULL);
    ASSERT_TRUE(strstr(two, "\"manifest\":null") != NULL && strstr(two, "\"manifest\":null") < three);
    ASSERT_TRUE(strstr(two, "\"stored\":\"delta\"") < three && strstr(two, "\"kept\":false") < three);
}

/* log reads a delta's header without a rebuild, and says the same. */
TEST(log_names_excludes_of_a_delta) {
    fresh();
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", "src", NULL));
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    sh("printf 'x\n' > '%s/a.txt'", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    sh("printf 'y\n' > '%s/a.txt'", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_TRUE(holds("[ ! -f \"$d/checkpoints/2/manifest.ndjson\" ]"));
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, "--json", NULL));
    const char *two = strstr(g_out, "{\"id\":2,"), *three = strstr(g_out, "{\"id\":3,");
    ASSERT_TRUE(two != NULL && three != NULL);
    const char *named = strstr(two, "\"excluded_paths\":[{\"path\":\"src\"");
    ASSERT_TRUE(named != NULL && named < three);
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_out, "cannot be read") == NULL);
}

/* ST-8 */
TEST(manifest_refuses_what_is_not_there) {
    history_copied(2);
    ASSERT_EQ_INT(2, belay("manifest", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(2, belay("manifest", "--scope", g_scope, "--id", "99", NULL));
    ASSERT_EQ_INT(2, belay("manifest", "--scope", g_scope, "--id", "x", NULL));
}

/* PR-9: the removing pass holds the lock. A child holds it for a moment, and
 * prune must wait for it, and say so. */
static void someone_holds_the_lock(void) {
    char path[600];
    snprintf(path, sizeof path, "%s/lockpath", g_dir);
    sh("ls -d '%s'/scopes/*/lock > '%s'", g_state, path);
    FILE *f = fopen(path, "r");
    if (f == NULL || fgets(path, sizeof path, f) == NULL) return;
    fclose(f);
    path[strcspn(path, "\n")] = '\0';
    const int fd = open(path, O_RDWR);
    if (fd == -1 || flock(fd, LOCK_EX) == -1) return;
    if (fork() == 0) {
        usleep(300000);
        _exit(0);           /* the lock goes with the last descriptor */
    }
    close(fd);
}

TEST(prune_takes_the_lock_to_remove) {
    history(3);
    prune_between_passes = someone_holds_the_lock;
    const int rc = belay("prune", "--scope", g_scope, "--keep-last", "1", NULL);
    prune_between_passes = NULL;
    ASSERT_EQ_INT(0, rc);
    ASSERT_TRUE(strstr(g_err, "waiting") != NULL);
    while (wait(NULL) > 0) { }
}

/* Asking to keep more must never keep less: a long limit keeps everything. */
TEST(prune_a_long_limit_keeps_everything) {
    history(4);
    static const char *const days[] = { "213504", "213505", "365000", "1000000", "999999999" };
    for (size_t i = 0; i < sizeof days / sizeof days[0]; i++) {
        ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-days", days[i], "--dry-run", NULL));
        if (strstr(g_out, "would remove 0 of 4") == NULL) BELAY_FAIL("--keep-days %s: %s", days[i], g_out);
    }
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-days", "365000", NULL));
    ASSERT_TRUE(has_checkpoint(1) && has_checkpoint(2) && has_checkpoint(3));
}

/* What stays still reads: a kept checkpoint's copies, and --keep-from's. */
TEST(prune_keeps_the_copies_of_what_it_keeps) {
    history(2);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--keep", NULL));     /* 3: version 2 */
    sh("printf 'pending\n' > '%s/a.txt'", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));               /* 4 */
    sh("printf 'newest\n' > '%s/a.txt'", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));               /* 5 */
    sh("printf 'last\n' > '%s/a.txt'", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));               /* 6 */
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "0", "--keep-from", "5", NULL));
    ASSERT_TRUE(holds("grep -rqx 'version 2' \"$d/store\" && grep -rqx 'newest' \"$d/store\" && grep -rqx 'last' \"$d/store\""));
    ASSERT_TRUE(holds("! grep -rqx 'version 1' \"$d/store\" && ! grep -rqx 'pending' \"$d/store\""));
}

/* PR-7: what it says is what goes, to the byte, unfinished directories and
 * orphaned diffs included. */
TEST(prune_reports_exactly_what_it_frees) {
    history(5);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "5", NULL));
    ASSERT_TRUE(holds("rm \"$d/checkpoints/2/meta.json\" && printf 'left\n' > \"$d/checkpoints/2/manifest.ndjson.tmp.aB3dE5\""));
    ASSERT_TRUE(holds("find \"$d\" -type f -exec cat {} + | wc -c > '%s/size-before'", g_dir));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "2", "--dry-run", "--json", NULL));
    long long bytes = -1, store = -1;
    const char *b = strstr(g_out, "\"bytes\":"), *o = strstr(g_out, "\"store_bytes\":");
    ASSERT_TRUE(b != NULL && o != NULL && sscanf(b, "\"bytes\":%lld", &bytes) == 1 && sscanf(o, "\"store_bytes\":%lld", &store) == 1);
    ASSERT_TRUE(bytes > 0 && store > 0);
    ASSERT_TRUE(strstr(g_out, "\"kept_ids\":[]") != NULL);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "2", NULL));
    ASSERT_TRUE(holds("find \"$d\" -type f -exec cat {} + | wc -c > '%s/size-after'", g_dir));
    char c[1000];
    snprintf(c, sizeof c, "[ $(( $(cat '%s/size-before') - $(cat '%s/size-after') )) -eq %lld ]", g_dir, g_dir, bytes + store);
    ASSERT_EQ_INT(0, system(c));
}

TEST(prune_json_names_what_it_keeps) {
    history(3);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "0", "--keep-id", "2", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"kept_ids\":[[2,2]]") != NULL && strstr(g_out, "\"ids\":[[1,1]]") != NULL);
}

/* Fails half way, on a directory that won't let go: the store is untouched,
 * since no checkpoint that went could have its copies swept first. */
TEST(prune_sweeps_only_after_the_checkpoints_are_gone) {
    if (geteuid() == 0) SKIP("root ignores a directory's mode");
    history(3);
    const int all = store_objects();
    ASSERT_TRUE(holds("chmod 500 \"$d/checkpoints/2\""));
    const int rc = belay("prune", "--scope", g_scope, "--keep-last", "1", NULL);
    ASSERT_TRUE(holds("chmod 700 \"$d/checkpoints/2\""));
    ASSERT_TRUE(rc != 0);
    ASSERT_EQ_INT(all, store_objects());
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    ASSERT_TRUE(store_objects() < all);
}

/* A link where a manifest should be, on a checkpoint that stays, is corrupt:
 * nothing goes. */
TEST(prune_refuses_a_link_for_a_manifest_that_stays) {
    history(3);
    ASSERT_TRUE(holds("mv \"$d/checkpoints/3/manifest.ndjson\" \"$d/elsewhere\" && ln -s \"$d/elsewhere\" \"$d/checkpoints/3/manifest.ndjson\""));
    ASSERT_EQ_INT(4, belay("prune", "--scope", g_scope, "--keep-last", "2", NULL));
    ASSERT_TRUE(has_checkpoint(1));
}

/* PR-11: a killed capture's temporaries go once old, counted; a recent one
 * may be a capture's, and stays. */
TEST(prune_clears_old_store_temporaries) {
    history(3);
    ASSERT_TRUE(holds("printf 'partial\n' > \"$d/store/.tmp-1-0\" && touch -t 202001010000 \"$d/store/.tmp-1-0\" && "
                      "printf 'running\n' > \"$d/store/.tmp-2-0\" && "
                      "printf 'mine\n' > \"$d/store/.other\" && touch -t 202001010000 \"$d/store/.other\""));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "9", "--dry-run", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"store_temps\":1,\"store_bytes\":8,") != NULL);
    ASSERT_TRUE(holds("[ -f \"$d/store/.tmp-1-0\" ]"));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "9", NULL));
    ASSERT_TRUE(strstr(g_out, "1 left by killed captures") != NULL);
    ASSERT_TRUE(holds("[ ! -f \"$d/store/.tmp-1-0\" ] && [ -f \"$d/store/.tmp-2-0\" ] && [ -f \"$d/store/.other\" ]"));
}

/* Only an object, and only a real cached diff: names belay never wrote stay. */
TEST(prune_touches_only_what_is_belays) {
    history(3);
    ASSERT_TRUE(holds("f=$(ls \"$d/store\" | head -1) && touch \"$d/store/$f/notanobject\" && "
                      "touch \"$d/checkpoints/3/diff-from-notes.txt\" \"$d/checkpoints/3/diff-from-\" && mkdir \"$d/checkpoints/99\""));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    ASSERT_TRUE(holds("ls \"$d\"/store/*/notanobject \"$d/checkpoints/3/diff-from-notes.txt\" \"$d/checkpoints/3/diff-from-\" >/dev/null"));
    ASSERT_TRUE(has_checkpoint(99));        /* above the newest: a capture may yet own it */
}

/* A diff cached from a checkpoint an earlier run removed goes too. */
TEST(prune_removes_a_cached_diff_whose_since_is_long_gone) {
    history(3);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "2", NULL));
    ASSERT_TRUE(holds("touch \"$d/checkpoints/3/diff-from-1.ndjson\""));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "2", NULL));
    ASSERT_TRUE(holds("! ls \"$d/checkpoints/3/diff-from-1.ndjson\" >/dev/null 2>&1"));
}

/* Pruning must not switch off the periodic full read. */
TEST(prune_does_not_reset_the_count_to_a_full_mark) {
    fresh();
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    bool full = false;
    for (int i = 0; i < 6 && !full; i++) {
        ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--full-every", "5", NULL));
        full = strstr(g_out, "every 5 marks") != NULL;
        ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    }
    ASSERT_TRUE(full);
}

/* PR-10, PR-8: a checkpoint a crash left without its meta.json is no
 * checkpoint, to verify too. */
TEST(verify_to_refuses_a_checkpoint_with_no_meta) {
    history(3);
    char bundle[500], sha[65];
    snprintf(bundle, sizeof bundle, "%s/bundle", g_dir);
    ASSERT_EQ_INT(0, belay("baseline", "export", "--scope", g_scope, "--out", bundle, "--json", NULL));
    const char *s = strstr(g_out, "\"sha256\":\"");
    ASSERT_TRUE(s != NULL);
    snprintf(sha, sizeof sha, "%.64s", s + 10);
    ASSERT_TRUE(holds("rm \"$d/checkpoints/2/meta.json\""));
    ASSERT_EQ_INT(2, belay("verify", "--scope", g_scope, "--baseline", bundle, "--baseline-sha256", sha, "--to", "2", NULL));
}

/* Nothing there: nothing made for it, and one JSON shape. */
TEST(prune_makes_no_state_for_a_scope_with_none) {
    fresh();
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"dry_run\":false") != NULL && strstr(g_out, "\"kept_ids\":[]") != NULL);
    char c[600];
    snprintf(c, sizeof c, "[ -z \"$(ls -A '%s')\" ]", g_state);
    ASSERT_EQ_INT(0, system(c));
    ASSERT_EQ_INT(2, belay("prune", "--scope", g_scope, "--keep-last", "1", "--keep-id", "7", NULL));
}

/* A capture during the long unlocked read names a copy only a checkpoint
 * going names: it must survive the sweep. */
static void an_old_version_comes_back(void) {
    sh("printf 'version 1\n' > '%s/a.txt'", g_scope);
    /* Inside belay(), whose buffers are in use: streams of its own. */
    char *argv[] = { "belay", "mark", "--scope", g_scope, "--full", NULL };
    char *o = NULL, *e = NULL;
    size_t on, en;
    FILE *out = open_memstream(&o, &on), *err = open_memstream(&e, &en);
    (void)cli_main(5, argv, out, err);
    fclose(out);
    fclose(err);
    free(o);
    free(e);
}

TEST(prune_keeps_what_a_capture_named_during_its_read) {
    history(3);
    prune_between_passes = an_old_version_comes_back;
    const int rc = belay("prune", "--scope", g_scope, "--keep-last", "1", NULL);
    prune_between_passes = NULL;
    ASSERT_EQ_INT(0, rc);
    ASSERT_TRUE(has_checkpoint(4) && !has_checkpoint(3));
    /* src/x.txt, tool, version 1, and version 3: the unlocked pass saw
     * checkpoint 3 as the newest, and a mark isn't taken back. The next run
     * sweeps it. One copy too many, never one too few. */
    ASSERT_EQ_INT(4, store_objects());
    ASSERT_TRUE(holds("grep -rqx 'version 1' \"$d/store\" && grep -rqx 'version 3' \"$d/store\""));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    ASSERT_EQ_INT(3, store_objects());
    ASSERT_TRUE(holds("grep -rqx 'version 1' \"$d/store\" && ! grep -rqx 'version 3' \"$d/store\""));
}

/* PR-5: a diff cached from a checkpoint that went goes too. */
TEST(prune_removes_cached_diffs_from_what_went) {
    history(3);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "3", NULL));
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "2", "--to", "3", NULL));
    ASSERT_TRUE(holds("ls \"$d\"/checkpoints/3/diff-from-1* \"$d\"/checkpoints/3/diff-from-2* >/dev/null"));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "2", NULL));
    ASSERT_TRUE(holds("! ls \"$d\"/checkpoints/3/diff-from-1* >/dev/null 2>&1"));
    ASSERT_TRUE(holds("ls \"$d\"/checkpoints/3/diff-from-2* >/dev/null"));
}

/* Everything that stays is read first: a bad manifest stops the run with
 * nothing removed. */
TEST(prune_with_a_corrupt_manifest_removes_nothing) {
    history(4);
    const int all = store_objects();
    ASSERT_TRUE(holds("sed -i.bak '3s/.*/not a manifest/' \"$d/checkpoints/4/manifest.ndjson\" && rm \"$d/checkpoints/4/manifest.ndjson.bak\""));
    ASSERT_EQ_INT(4, belay("prune", "--scope", g_scope, "--keep-last", "2", NULL));
    ASSERT_TRUE(has_checkpoint(1) && has_checkpoint(2));
    ASSERT_EQ_INT(all, store_objects());
}

/* PR-8: a removal a crash cut short, its meta.json gone: no checkpoint, and
 * the next run finishes it. */
TEST(prune_finishes_what_a_crash_left) {
    history(4);
    ASSERT_TRUE(holds("rm \"$d/checkpoints/2/meta.json\""));
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_out, "mark 2") == NULL);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "9", NULL));
    ASSERT_TRUE(!has_checkpoint(2) && has_checkpoint(1) && has_checkpoint(3));
}

/* What belay did not write stays, and is said before anything goes: by a dry
 * run too, and a run never stops half way for it. */
TEST(prune_leaves_what_belay_did_not_write) {
    history(3);
    ASSERT_TRUE(holds("touch \"$d/checkpoints/2/planted\""));
    ASSERT_EQ_INT(4, belay("prune", "--scope", g_scope, "--keep-last", "1", "--dry-run", NULL));
    ASSERT_EQ_INT(4, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    ASSERT_TRUE(has_checkpoint(1) && has_checkpoint(2) && has_checkpoint(3));
    ASSERT_TRUE(holds("ls \"$d/checkpoints/2/planted\" >/dev/null"));
    /* In an unfinished directory too: the run stops before checkpoint 1 goes. */
    ASSERT_TRUE(holds("rm \"$d/checkpoints/2/meta.json\""));
    ASSERT_EQ_INT(4, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
    ASSERT_TRUE(has_checkpoint(1) && has_checkpoint(2) && has_checkpoint(3));
}

/* A killed capture's leftovers are belay's, and go. */
TEST(prune_clears_what_a_killed_capture_left) {
    history(3);
    ASSERT_TRUE(holds("rm \"$d/checkpoints/2/meta.json\" && touch \"$d/checkpoints/2/manifest.ndjson.tmp.aB3dE5\" && "
                      "mkdir \"$d/checkpoints/2/manifest.ndjson.run.xY1zQ9\" && touch \"$d/checkpoints/2/manifest.ndjson.run.xY1zQ9/run0\" && "
                      "touch \"$d/checkpoints/2/manifest.ndjson.run.fILe01\""));
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "9", NULL));
    ASSERT_TRUE(!has_checkpoint(2) && has_checkpoint(1) && has_checkpoint(3));
}

TEST(prune_of_a_scope_with_no_checkpoints) {
    fresh();
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", "--dry-run", NULL));
    ASSERT_TRUE(strstr(g_out, "no checkpoints") != NULL);
    ASSERT_EQ_INT(0, belay("prune", "--scope", g_scope, "--keep-last", "1", NULL));
}

TEST(excludes_are_configured_per_scope) {
    fresh();
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_out, "no excludes") != NULL);
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", "node_modules", NULL));
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", "a/b", NULL));
    ASSERT_EQ_STR("node_modules\na/b\n", g_out);
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--remove", "node_modules", NULL));
    ASSERT_EQ_STR("a/b\n", g_out);
    static const char *const bad[] = { "/abs", "a/../b", "./a", "a/", "", "a//b", ".." };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        if (belay("exclude", "--scope", g_scope, "--add", bad[i], NULL) != 2) BELAY_FAIL("accepted: \"%s\"", bad[i]);
    ASSERT_EQ_INT(2, belay("check", "--scope", g_scope, "--add", "x", NULL));
    ASSERT_EQ_INT(2, belay("exclude", "--scope", g_scope, "--json", NULL));
    char p[32];
    for (int i = 0; i < 30; i++) {
        snprintf(p, sizeof p, "x%d", i);
        REQUIRE(belay("exclude", "--scope", g_scope, "--add", p, NULL) == 0);
    }
    ASSERT_EQ_INT(2, belay("exclude", "--scope", g_scope, "--add", "one-too-many", NULL));
    char d[700];
    scope_dir(d, sizeof d);
    sh("printf '/abs\\n' > '%s/excludes'", d);
    ASSERT_EQ_INT(4, belay("check", "--scope", g_scope, NULL));        /* corrupt: not what belay wrote */
}

/* An excluded path is not walked, named in the manifest and the output;
 * a diff across it reports it not compared -- never removed or added. */
TEST(an_exclude_is_named_and_never_reads_as_removed) {
    fresh();
    sh("mkdir -p '%s/node_modules/pkg' && printf 'x\\n' > '%s/node_modules/pkg/i.js'", g_scope, g_scope);
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", "node_modules", NULL));
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_out, "not recorded: node_modules (excluded for this scope)") != NULL);
    char d[700], cmd[4000];
    scope_dir(d, sizeof d);
    snprintf(cmd, sizeof cmd, "head -1 '%s/checkpoints/2/manifest.ndjson' | grep -q '\"excluded\":\\[{\"path\":\"node_modules\",\"reason\":\"user\"' "
             "&& [ \"$(tail -n +2 '%s/checkpoints/2/manifest.ndjson' | grep -c '\"path\":\"node_modules')\" = 0 ]", d, d);
    ASSERT_EQ_INT(0, system(cmd));
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "2", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"path\":\"node_modules\",\"outcome\":\"unknown\"") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"path\":\"node_modules/pkg/i.js\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"not_captured\"]") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"outcome\":\"removed\"") == NULL);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "2", NULL));
    ASSERT_TRUE(strstr(g_out, "\nnot compared\n  node_modules   excluded for this scope\n") != NULL);
    /* both sides excluding it: nothing about it at all */
    sh("printf 'y\\n' >> '%s/node_modules/pkg/i.js'", g_scope);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "2", "--json", "--exit-code", NULL));
    ASSERT_TRUE(strstr(g_out, "\"outcome\"") == NULL);                    /* in no record ... */
    ASSERT_TRUE(strstr(g_out, "\"before_excluded\":[{\"path\":\"node_modules\",\"reason\":\"user\"") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"after_excluded\":[{\"path\":\"node_modules\",\"reason\":\"user\"") != NULL);
}

/* diff-events E11 (review of #33, D1): a package under an exclude was not
 * looked at on that side, so no event is derived from it -- excluding a venv
 * or dpkg's database used to read as packages installed or removed. */
TEST(no_package_event_comes_from_an_excluded_path) {
    fresh();
    sh("d='%s/venv/lib/python3.12/site-packages' && mkdir -p \"$d/foo-1.0.dist-info\" \"$d/foo\" "
       "&& printf 'Name: foo\\nVersion: 1.0\\n' > \"$d/foo-1.0.dist-info/METADATA\" "
       "&& printf 'foo/__init__.py,,\\n' > \"$d/foo-1.0.dist-info/RECORD\" && : > \"$d/foo/__init__.py\" "
       "&& mkdir -p '%s/var/lib/dpkg' && printf 'Package: bash\\nStatus: install ok installed\\nVersion: 5.2\\n\\n' "
       "> '%s/var/lib/dpkg/status'", g_scope, g_scope, g_scope);
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", "venv", NULL));
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));              /* 1: venv excluded */
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--remove", "venv", NULL));
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", "var/lib/dpkg", NULL));
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));               /* 2: dpkg excluded */
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "2", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"path\":\"venv/lib/python3.12/site-packages/foo-1.0.dist-info/RECORD\","
                              "\"outcome\":\"unknown\"") != NULL);         /* the record stands */
    ASSERT_TRUE(strstr(g_out, "\"path\":\"var/lib/dpkg/status\",\"outcome\":\"unknown\"") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"event\"") == NULL);
    ASSERT_TRUE(strstr(g_out, "\"events\":0") != NULL);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "2", NULL));
    ASSERT_TRUE(strstr(g_out, "installed") == NULL && strstr(g_out, "removed bash") == NULL);
}

/* S1: the walk counts belay's state directory once, at its own path relative
 * to the scope -- only when that path is inside the scope, component-wise. */
TEST(the_state_directory_is_located_inside_the_scope_by_path) {
    static struct state st;
    const struct { const char *scope, *root, *want; } c[] = {
        { "/home/u/proj", "/home/u/proj/.belay", ".belay" },
        { "/home/u/proj", "/home/u/proj/a/b", "a/b" },
        { "/", "/var/belay", "var/belay" },
        { "/home/u/proj", "/home/u/projx/.belay", NULL },     /* a prefix, not a parent */
        { "/home/u/proj", "/home/u/.local/state/belay", NULL },
        { "/home/u/proj", "/home/u/proj", NULL },             /* refused before any walk */
    };
    for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
        snprintf(st.scope.path, sizeof st.scope.path, "%s", c[i].scope);
        snprintf(st.root, sizeof st.root, "%s", c[i].root);
        const char *got = state_rel(&st);
        if (c[i].want == NULL) ASSERT_TRUE(got == NULL);
        else ASSERT_TRUE(got != NULL && strcmp(got, c[i].want) == 0);
    }
}

/* Decision 112: a manifest's header line names every excluded path, and a
 * reader refuses a line over 65,536 bytes (A2). A list that could not fit
 * is refused by `exclude --add`; one edited in by hand makes the capture
 * fail, loudly, instead of writing a manifest nothing can read. */
TEST(an_exclude_list_whose_header_could_not_fit_is_refused) {
#if PATH_MAX < 4096
    /* macOS: an exclude is under 1,024 bytes, so 31 of them, base64 or
     * not, are far under the bound -- the overflow cannot happen there. */
    SKIP("PATH_MAX under 4096: no exclude list can outgrow a header line");
#else
    fresh();
    static char p[20][4000];
    static const char *ps[20];
    for (int i = 0; i < 20; i++) {
        int w = snprintf(p[i], sizeof p[i], "d%02d", i);
        for (int k = 0; k < 15; k++) {
            p[i][w++] = '/';
            memset(p[i] + w, 'c', 240);
            w += 240;
        }
        p[i][w] = '\0';
        ps[i] = p[i];
    }
    sh("cd '%s' && c=$(printf 'c%%.0s' $(seq 240)) && for i in $(seq -w 0 19); do p=d$i; "
       "for k in $(seq 15); do p=$p/$c; done; mkdir -p $p; done", g_scope);
    int accepted = 0;
    while (accepted < 20 && belay("exclude", "--scope", g_scope, "--add", p[accepted], NULL) == 0) accepted++;
    ASSERT_TRUE(accepted >= 15 && accepted < 20);
    ASSERT_TRUE(strstr(g_err, "a manifest's header could need") != NULL &&
                strstr(g_err, "over its 65536-byte line limit") != NULL);
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, NULL));
    size_t lines = 0;
    for (const char *c = g_out; *c; c++) lines += *c == '\n';
    ASSERT_EQ_INT(accepted, (int)lines);                                /* the refused one not kept */
    /* What was accepted is captured and read back; the bound held. */
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", NULL));
    char d[700], cmd[1600];
    scope_dir(d, sizeof d);
    REQUIRE(d[0] != '\0');
    snprintf(cmd, sizeof cmd, "head -1 '%s/checkpoints/1/manifest.ndjson' | wc -c", d);
    FILE *f = popen(cmd, "r");
    REQUIRE(f != NULL);
    long hl = 0;
    REQUIRE(fscanf(f, "%ld", &hl) == 1);
    pclose(f);
    char real[PATH_MAX];
    REQUIRE(realpath(g_scope, real) != NULL);
    const long bound = belay_manifest_header_bound(real, ps, (size_t)accepted, NULL);
    ASSERT_TRUE(hl - 1 > 60000 && hl - 1 <= bound && bound <= BELAY_MANIFEST_LINE_MAX);
    /* The bound is the widest line those names can make: every number at
     * its widest, the state directory counted where it is. */
    static const char *const one[] = { "a" };
    const char *widest = "{\"belay_manifest\":3,\"created_ns\":-9223372036854775808,\"scopes\":[\"/s\"],"
        "\"hash\":\"sha256\",\"hash_max_bytes\":18446744073709551615,\"store_max_bytes\":18446744073709551615,"
        "\"excluded\":[{\"path\":\".st\",\"reason\":\"state_dir\",\"dev\":18446744073709551615,"
        "\"ino\":18446744073709551615},{\"path\":\"a\",\"reason\":\"user\",\"dev\":18446744073709551615,"
        "\"ino\":18446744073709551615}],\"walk_start_ns\":-9223372036854775808,"
        "\"source\":{\"docker\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"image\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"}}";
    ASSERT_EQ_INT((int)strlen(widest), (int)belay_manifest_header_bound("/s", one, 1, ".st"));
    /* By hand, all twenty: the capture fails and says why. */
    sh("cd '%s' && find d* -mindepth 15 -maxdepth 15 -type d > '%s/excludes'", g_scope, d);
    ASSERT_EQ_INT(4, belay("check", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_err, "the header line would be") != NULL &&
                strstr(g_err, "over the 65536-byte line limit: 20 excluded paths") != NULL);
    snprintf(cmd, sizeof cmd, "[ ! -e '%s/checkpoints/3/manifest.ndjson' ] && [ ! -e '%s/checkpoints/3/meta.json' ]", d, d);
    ASSERT_EQ_INT(0, system(cmd));                                      /* no unreadable manifest */
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, NULL));
    /* The state directory inside the scope takes its place in that line: a
     * name that fits without it and not with it is refused. */
    fresh();
    char inside[700];
    snprintf(inside, sizeof inside, "%s/.state", g_scope);
    REQUIRE(realpath(g_scope, real) != NULL);
    size_t k = 0;
    while (k < 20 && belay_manifest_header_bound(real, ps, k + 1, ".state") <= BELAY_MANIFEST_LINE_MAX) k++;
    static char filler[4000];
    static const char *with[21];
    for (size_t i = 0; i < k; i++) with[i] = ps[i];
    with[k] = filler;
    size_t len = 0;
    for (len = 1; len < sizeof filler - 1; len++) {
        memset(filler, 'f', len);
        filler[len] = '\0';
        if (belay_manifest_header_bound(real, with, k + 1, ".state") > BELAY_MANIFEST_LINE_MAX) break;
    }
    REQUIRE(belay_manifest_header_bound(real, with, k + 1, NULL) <= BELAY_MANIFEST_LINE_MAX);
    setenv("BELAY_STATE_DIR", inside, 1);
    int added = 0;
    for (size_t i = 0; i < k; i++) added += belay("exclude", "--scope", g_scope, "--add", ps[i], NULL) == 0;
    const int rc = belay("exclude", "--scope", g_scope, "--add", filler, NULL);
    setenv("BELAY_STATE_DIR", g_state, 1);
    ASSERT_EQ_INT((int)k, added);
    ASSERT_EQ_INT(2, rc);
#endif
}

/* Review 2026-11-02 of #33, D3-D6: a hand-edited excludes file that is not
 * what belay writes is refused -- a NUL, a CR, a line twice -- and the
 * command never succeeds in silence. */
TEST(the_excludes_file_and_command_are_strict) {
    fresh();
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, NULL));
    char d[700];
    scope_dir(d, sizeof d);
    REQUIRE(d[0] != '\0');
    sh("printf 'node_modules\\n\\000src\\n' > '%s/excludes'", d);
    ASSERT_EQ_INT(4, belay("exclude", "--scope", g_scope, NULL));               /* D3 */
    sh("printf 'node_modules\\r\\n' > '%s/excludes'", d);
    ASSERT_EQ_INT(4, belay("exclude", "--scope", g_scope, NULL));               /* D4 */
    sh("printf 'node_modules\\nsrc\\nnode_modules\\n' > '%s/excludes'", d);
    ASSERT_EQ_INT(4, belay("exclude", "--scope", g_scope, NULL));               /* D5 */
    sh("rm '%s/excludes'", d);
    ASSERT_EQ_INT(2, belay("exclude", "--scope", g_scope, "--add", "a\rb", NULL));
    ASSERT_EQ_INT(2, belay("exclude", "--scope", g_scope, "--add", "x", "--add", "y", NULL));   /* D6 */
    ASSERT_TRUE(strstr(g_err, "--add given twice") != NULL);
    ASSERT_EQ_INT(2, belay("exclude", "--scope", g_scope, "--remove", "nothere", NULL));
    ASSERT_TRUE(strstr(g_err, "nothere is not excluded") != NULL);
}

/* D2: the machine interfaces name what was not walked -- diff --json in its
 * header (V2-R7) and on stderr, both sides, with --to too; checkpoint JSON by
 * path. S2: adding an
 * exclude over the newest files is not "ctime went backwards". */
TEST(json_output_names_every_excluded_path) {
    fresh();
    sh("mkdir -p '%s/node_modules/p' && printf 'x\\n' > '%s/node_modules/p/i.js'", g_scope, g_scope);
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", "node_modules", NULL));
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"excluded_paths\":[{\"path\":\"node_modules\",\"reason\":\"user\"}]") != NULL);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "2", "--json", NULL));
    ASSERT_TRUE(strstr(g_err, "belay: not compared: node_modules (excluded for this scope)\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"path\":\"node_modules\",\"outcome\"") == NULL);  /* in no record */
    /* ... and in the header, each side's (V2-R7): stderr is not the record */
    ASSERT_TRUE(strstr(g_out, "\"before_excluded\":[{\"path\":\"node_modules\",\"reason\":\"user\",\"dev\":") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"after_excluded\":[{\"path\":\"node_modules\",\"reason\":\"user\",\"dev\":") != NULL);
    /* S2: an exclude added over the newest file; the next mark prefilters */
    sh("printf 'y\\n' > '%s/src/newest.c'", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", "src", NULL));
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "ctime went backwards") == NULL);
    ASSERT_TRUE(strstr(g_out, "\"used\":true") != NULL);
}

/* Every entry under the state directory -- path, size, mtime, inode, links
 * -- as one string: two equal snapshots mean nothing was written, created,
 * replaced or removed there, whoever ran it (root ignores the read-only
 * modes below; this does not). */
static char *g_snap;
static size_t g_snap_n;
static FILE *g_snap_f;
static int snap_one(const char *p, const struct stat *sb, int type, struct FTW *f) {
    (void)type; (void)f;
#ifdef __APPLE__
    const struct timespec mt = sb->st_mtimespec;
#else
    const struct timespec mt = sb->st_mtim;
#endif
    fprintf(g_snap_f, "%s %lld %lld.%09ld %llu %llu\n", p, (long long)sb->st_size, (long long)mt.tv_sec,
            (long)mt.tv_nsec, (unsigned long long)sb->st_ino, (unsigned long long)sb->st_nlink);
    return 0;
}
static char *snapshot(void) {
    g_snap = NULL;
    g_snap_f = open_memstream(&g_snap, &g_snap_n);
    nftw(g_state, snap_one, 16, FTW_PHYS);
    fclose(g_snap_f);
    return g_snap;
}

/* Reads write nothing to the state directory (2026-11-04): log, exclude's
 * list, verify, and a diff between two kept checkpoints whose diff is
 * stored -- run against a read-only state directory, each succeeds and the
 * directory is as it was. A diff whose pair was never diffed stores it,
 * once. */
TEST(reads_leave_the_state_directory_as_it_was) {
    fresh();
    char bundle[600];
    snprintf(bundle, sizeof bundle, "%s/b.bundle", g_dir);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("baseline", "export", "--scope", g_scope, "--out", bundle, "--json", NULL));   /* checkpoint 2 */
    char sha[65] = "";
    const char *k = strstr(g_out, "\"sha256\":\"");
    ASSERT_TRUE(k != NULL);
    memcpy(sha, k + 10, 64);
    sh("printf 'c\\n' >> '%s/src/x.txt'", g_scope);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", NULL));     /* checkpoint 3, diff-from-1 */
    sh("printf 'd\\n' > '%s/src/y.txt'", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));                     /* checkpoint 4, no diff stored */

    sh("chmod -R a-w '%s'", g_state);
    char *before = snapshot();
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, NULL));
    ASSERT_TRUE(strstr(g_out, "diff 3") != NULL);
    ASSERT_EQ_INT(0, belay("log", "--scope", g_scope, "--json", NULL));
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "3", NULL));
    ASSERT_TRUE(strstr(g_out, "M src/x.txt") != NULL);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "3", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"path\":\"src/x.txt\"") != NULL);
    ASSERT_EQ_INT(EXIT_CHANGES, belay("diff", "--scope", g_scope, "--since", "1", "--to", "3", "--exit-code", NULL));
    const int vrc = belay("verify", "--scope", g_scope, "--baseline", bundle, "--baseline-sha256", sha, NULL);
    ASSERT_TRUE(vrc == 0);
    char *after = snapshot();
    ASSERT_EQ_STR(before, after);
    free(before);
    free(after);

    /* the pair 1 -> 4 never diffed: stored on the first diff, not again */
    sh("chmod -R u+w '%s'", g_state);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "4", NULL));
    before = snapshot();
    ASSERT_TRUE(strstr(before, "/checkpoints/4/diff-from-1.ndjson ") != NULL);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "4", NULL));
    after = snapshot();
    ASSERT_EQ_STR(before, after);
    free(before);
    free(after);
}

/* The receipt asks git (2026-11-04): a tracked change listed before an
 * untracked one that sorts first, what git ignores folded by directory, a
 * directory now a symlink not stopping git's answer for the rest; a diff to
 * an earlier checkpoint says the classification is the repository's now. */
TEST(the_receipt_orders_by_what_git_says) {
    fresh();
    sh("cd '%s' && git init -q && printf 'out/\\n' > .gitignore && mkdir -p d && printf 'f\\n' > d/f && "
       "git add -A && git -c user.name=t -c user.email=t@t -c commit.gpgSign=false commit -q -m one", g_scope);
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    sh("cd '%s' && printf 'more\\n' >> src/x.txt && printf 'n\\n' > a.txt && mkdir -p out/o && printf 'o\\n' > out/o/a.o && "
       "rm -r d && mkdir e && printf 'e\\n' > e/f && ln -s e d", g_scope);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", NULL));
    const char *x = strstr(g_out, "  M src/x.txt"), *a = strstr(g_out, "  A a.txt");
    ASSERT_TRUE(x != NULL && a != NULL && x < a);
    ASSERT_TRUE(strstr(g_out, "  git-ignored: 3 changes under out/\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "out/o") == NULL);
    ASSERT_TRUE(strstr(g_out, "as the repository is now") == NULL);       /* the latest checkpoint */
    ASSERT_EQ_INT(0, belay("mark", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "2", NULL));
    ASSERT_TRUE(strstr(g_out, "  tracked, untracked and ignored: as the repository is now, not at checkpoint 2\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "  git-ignored: 3 changes under out/\n") != NULL);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--to", "2", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"path\":\"out/o/a.o\"") != NULL);           /* NDJSON untouched */
}

/* Review gaps: an exclude names the symlink itself, never its target, and
 * siblings sharing a name's prefix are compared as usual. */
TEST(an_exclude_is_exact_on_links_and_prefixes) {
    fresh();
    sh("mkdir -p '%s/d/sub' '%s/a' '%s/a-' && printf 's\\n' > '%s/d/sub/s' && ln -s d '%s/ld' && "
       "printf 'q\\n' > '%s/a.b' && printf 'y\\n' > '%s/a-/y'", g_scope, g_scope, g_scope, g_scope, g_scope, g_scope, g_scope);
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", "ld", NULL));
    ASSERT_EQ_INT(0, belay("exclude", "--scope", g_scope, "--add", "a", NULL));
    ASSERT_EQ_INT(0, belay("check", "--scope", g_scope, "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "{\"path\":\"a\",\"reason\":\"user\"},{\"path\":\"ld\",\"reason\":\"user\"}") != NULL);
    char d[700], cmd[4000];
    scope_dir(d, sizeof d);
    snprintf(cmd, sizeof cmd, "m='%s/checkpoints/1/manifest.ndjson'; grep -q '\"path\":\"d/sub/s\"' \"$m\" && "
             "grep -q '\"path\":\"a.b\"' \"$m\" && grep -q '\"path\":\"a-/y\"' \"$m\" && "
             "[ \"$(tail -n +2 \"$m\" | grep -c '\"path\":\"ld\"')\" = 0 ]", d);
    ASSERT_EQ_INT(0, system(cmd));
    sh("printf 'Q\\n' >> '%s/a.b' && rm '%s/a-/y'", g_scope, g_scope);
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_scope, "--since", "1", "--json", NULL));
    ASSERT_TRUE(strstr(g_out, "\"path\":\"a.b\",\"outcome\":\"modified\"") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"path\":\"a-/y\",\"outcome\":\"removed\"") != NULL);
}

/* Manifest v4 (test/expect/manifest-v4.md). A real writer, a real lease
 * probe, the whole path to the diff. Where the kernel cannot show the writer
 * these say so: macOS has no leases; on overlayfs (the docker job's /tmp) a
 * mapping whose descriptor was closed is not seen. */
static const char *why_no_probe(const char *dir) {
#ifndef __linux__
    (void)dir;
    return "no lease facility here";
#else
    char p[700];
    snprintf(p, sizeof p, "%s/.leasable", dir);
    const int w = open(p, O_WRONLY | O_CREAT, 0600);
    if (w != -1) close(w);
    const int fd = open(p, O_RDONLY);
    const int ok = fd != -1 && fcntl(fd, F_SETLEASE, F_RDLCK) == 0;
    if (ok) fcntl(fd, F_SETLEASE, F_UNLCK);
    if (fd != -1) close(fd);
    unlink(p);
    if (!ok) return "this filesystem has no leases";
    struct statfs s;
    if (statfs(dir, &s) == 0 && s.f_type == 0x794c7630) return "overlayfs: a closed mapping is not seen";
    return NULL;
#endif
}

/* A number after `key` in the last line of the file `path`, or -1. */
static long trailer_num(const char *path, const char *key) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    static char line[1 << 16], last[1 << 16];
    while (fgets(line, sizeof line, f) != NULL) strcpy(last, line);
    fclose(f);
    const char *k = strstr(last, key);
    return k != NULL ? atol(k + strlen(key)) : -1;
}

/* The latest checkpoint's id and manifest, from `mark --json` in g_out. */
static long marked(char *manifest, size_t cap) {
    const char *m = strstr(g_out, "\"manifest\":\"");
    if (m == NULL) return -1;
    m += 12;
    const char *e = strchr(m, '"');
    snprintf(manifest, cap, "%.*s", (int)(e - m), m);
    return atol(g_out + 6);                                 /* {"id":N */
}

TEST(a_shared_mapping_writer_marks_every_pass_and_nothing_diffs_on_the_hash) {
    fresh();
    const char *no = why_no_probe(g_scope);
    if (no != NULL) SKIP(no);
    enum { SZ = 4 << 20 };
    char big[700], manifest[900];
    snprintf(big, sizeof big, "%s/big.dat", g_scope);
    sh("head -c %d /dev/zero | tr '\\0' A > '%s'", (int)SZ, big);
    REQUIRE(belay("mark", "--scope", g_scope, "--json", NULL) == 0);
    int ready[2];
    REQUIRE(pipe(ready) == 0);
    const pid_t w = fork();
    REQUIRE(w != -1);
    if (w == 0) {                       /* maps, closes the descriptor, stores for ever */
        const int fd = open(big, O_RDWR);
        char *m = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (m == MAP_FAILED) _exit(1);
        close(fd);
        for (long k = 0;; k++) {
            memset(m, (k & 1) ? 'B' : 'A', SZ);
            __asm__ volatile("" ::: "memory");      /* the stores stay: nothing else reads them */
            if (k == 0 && write(ready[1], "x", 1) != 1) _exit(1);
        }
    }
    char c;
    REQUIRE(read(ready[0], &c, 1) == 1);
    int marks = 0, ordinary = 0;
    char first[80] = "";
    bool moved = false;                 /* the writer really writes: the hashes differ */
    for (int i = 0; i < 30; i++) {
        REQUIRE(belay("mark", "--scope", g_scope, "--full", "--json", NULL) == 0);
        const long id = marked(manifest, sizeof manifest);
        marks += trailer_num(manifest, "\"writer_open\":") == 1;
        FILE *mf = fopen(manifest, "r");
        REQUIRE(mf != NULL);
        static char ml[4096];
        while (fgets(ml, sizeof ml, mf) != NULL) {
            const char *h = strstr(ml, "\"path\":\"big.dat\"") != NULL ? strstr(ml, "\"sha256\":\"") : NULL;
            if (h == NULL) continue;
            if (first[0] == '\0') snprintf(first, sizeof first, "%.74s", h);
            else if (strncmp(first, h, 74) != 0) moved = true;
        }
        fclose(mf);
        char since[24], to[24];
        snprintf(since, sizeof since, "%ld", id - 1);
        snprintf(to, sizeof to, "%ld", id);
        REQUIRE(belay("diff", "--scope", g_scope, "--since", since, "--to", to, "--json", NULL) == 0);
        const char *r = strstr(g_out, "\"path\":\"big.dat\"");
        const char *eol = r != NULL ? strchr(r, '\n') : NULL;
        char rec[1024] = "";
        if (eol != NULL) snprintf(rec, sizeof rec, "%.*s", (int)(eol - r), r);
        if (strstr(rec, "\"outcome\":\"unknown\"") == NULL || strstr(rec, "\"unknown\":[\"writer_open\"]") == NULL ||
            strstr(rec, "sha256") != NULL) {
            if (ordinary == 0) printf("      pass %d: %s\n", i, r != NULL ? rec : g_out);
            ordinary++;
        }
        if (strstr(g_out, "\"modified\":0,") == NULL || strstr(g_out, "\"provisional\":false") == NULL ||
            strstr(g_out, "\"after_writer_open\":1,") == NULL) ordinary++;
    }
    kill(w, SIGKILL);
    waitpid(w, NULL, 0);
    close(ready[0]);
    close(ready[1]);
    ASSERT_EQ_INT(30, marks);
    ASSERT_EQ_INT(0, ordinary);
    ASSERT_TRUE(moved);
    /* The writer gone, a plain mark reads the file again (V4-R6). */
    REQUIRE(belay("mark", "--scope", g_scope, "--json", NULL) == 0);
    marked(manifest, sizeof manifest);
    ASSERT_TRUE(trailer_num(manifest, "\"writer_open\":") == 0);
}

TEST(a_quiet_tree_has_no_marked_entry) {
    fresh();
    char manifest[900];
    sh("head -c 200000 /dev/zero | tr '\\0' A > '%s/big.dat'", g_scope);
    REQUIRE(belay("mark", "--scope", g_scope, "--json", NULL) == 0);
    for (int i = 0; i < 3; i++) {
        REQUIRE(belay("mark", "--scope", g_scope, "--full", "--json", NULL) == 0);
        const long id = marked(manifest, sizeof manifest);
        ASSERT_TRUE(trailer_num(manifest, "\"writer_open\":") == 0);
        char since[24], to[24];
        snprintf(since, sizeof since, "%ld", id - 1);
        snprintf(to, sizeof to, "%ld", id);
        REQUIRE(belay("diff", "--scope", g_scope, "--since", since, "--to", to, "--json", NULL) == 0);
        ASSERT_TRUE(strstr(g_out, "\"unknown\":0,") != NULL);
        ASSERT_TRUE(strstr(g_out, "\"before_writer_open\":0,\"after_writer_open\":0,\"before_unguarded\":") != NULL);
    }
}

TEST(a_held_open_writer_on_a_small_file_marks_it) {
    fresh();
    const char *no = why_no_probe(g_scope);
    if (no != NULL && strncmp(no, "overlayfs", 9) != 0) SKIP(no);    /* an open descriptor is seen there */
    char env[700], manifest[900];
    snprintf(env, sizeof env, "%s/.env", g_scope);
    sh("printf 'A=1\\n' > '%s'", env);
    REQUIRE(belay("mark", "--scope", g_scope, "--json", NULL) == 0);
    const int w = open(env, O_WRONLY | O_APPEND);
    REQUIRE(w != -1);
    REQUIRE(write(w, "B=2\n", 4) == 4);
    REQUIRE(belay("mark", "--scope", g_scope, "--full", "--json", NULL) == 0);
    const long id = marked(manifest, sizeof manifest);
    ASSERT_TRUE(trailer_num(manifest, "\"writer_open\":") == 1);
    sh("grep -q '\"path\":\".env\".*\"writer_open\":true' '%s'", manifest);
    sh("! grep '\"path\":\".env\"' '%s' | grep -q stored", manifest);       /* no copy */
    char since[24], to[24];
    snprintf(since, sizeof since, "%ld", id - 1);
    snprintf(to, sizeof to, "%ld", id);
    REQUIRE(belay("diff", "--scope", g_scope, "--since", since, "--to", to, "--json", NULL) == 0);
    const char *r = strstr(g_out, "\"path\":\".env\"");
    REQUIRE(r != NULL);                 /* the size moved too: still unknown (V4-D1) */
    ASSERT_TRUE(strstr(r, "\"outcome\":\"unknown\"") != NULL && strstr(r, "\"unknown\":[\"writer_open\"]") != NULL);
    close(w);
}

/* inode-flags IF-2 and IF-8 through `belay diff` itself, which gives the
 * receipt both manifests' inode flags (review of #129, 1): on ext4 a
 * directory that outgrows a block gains its hashed-index flag, and
 * v0.1.0-alpha.6's receipt called that a privilege change. Where a
 * filesystem sets no such flag the test says less. */
TEST(a_directory_that_grows_is_no_privilege_change_in_the_receipt) {
    fresh();
    sh("mkdir '%s/grows'", g_scope);
    ASSERT_EQ_INT(EXIT_DONE, belay("check", "--scope", g_scope, NULL));
    sh("i=0; while [ $i -lt 450 ]; do : > '%s'/grows/f$i; i=$((i+1)); done", g_scope);
    ASSERT_EQ_INT(EXIT_DONE, belay("diff", "--scope", g_scope, "--since", "1", "--all", NULL));
    ASSERT_TRUE(strstr(g_out, "inode flags") == NULL);
    ASSERT_TRUE(strstr(g_out, "\nprivilege\n") == NULL);
    ASSERT_TRUE(strstr(g_out, "  A grows/f449\n") != NULL);
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
    RUN(mark_keep_is_recorded_and_shown);
    RUN(prune_needs_a_limit_and_good_values);
    RUN(prune_removes_what_is_outside_the_count);
    RUN(prune_keeps_what_is_within_either_limit);
    RUN(prune_never_removes_the_newest_a_kept_one_or_a_pending_diff);
    RUN(prune_keep_id_lasts_and_is_checked);
    RUN(prune_dry_run_changes_nothing_and_tells_the_truth);
    RUN(prune_sweeps_the_store_and_what_stays_still_works);
    RUN(delta_rebuilds_every_checkpoint_byte_for_byte);
    RUN(delta_keeps_a_full_copy_every_256);
    RUN(delta_that_does_not_rebuild_is_corrupt);
    RUN(delta_that_rebuilds_wrong_bytes_is_refused_by_its_hash);
    RUN(delta_from_another_base_is_refused);
    RUN(delta_with_no_base_or_a_link_is_corrupt);
    RUN(delta_beside_a_whole_file_uses_the_whole_file);
    RUN(delta_reads_checkpoints_stored_whole);
    RUN(prune_through_a_chain_leaves_what_stays_readable);
    RUN(prune_reports_exactly_what_it_frees_through_a_chain);
    RUN(checkpoint_v2_says_how_it_is_stored);
    RUN(log_names_excludes_of_a_delta);
    RUN(manifest_refuses_what_is_not_there);
    RUN(prune_takes_the_lock_to_remove);
    RUN(prune_a_long_limit_keeps_everything);
    RUN(prune_keeps_the_copies_of_what_it_keeps);
    RUN(prune_reports_exactly_what_it_frees);
    RUN(prune_json_names_what_it_keeps);
    RUN(prune_sweeps_only_after_the_checkpoints_are_gone);
    RUN(prune_refuses_a_link_for_a_manifest_that_stays);
    RUN(prune_clears_old_store_temporaries);
    RUN(prune_touches_only_what_is_belays);
    RUN(prune_removes_a_cached_diff_whose_since_is_long_gone);
    RUN(prune_does_not_reset_the_count_to_a_full_mark);
    RUN(verify_to_refuses_a_checkpoint_with_no_meta);
    RUN(prune_makes_no_state_for_a_scope_with_none);
    RUN(prune_keeps_what_a_capture_named_during_its_read);
    RUN(prune_removes_cached_diffs_from_what_went);
    RUN(prune_with_a_corrupt_manifest_removes_nothing);
    RUN(prune_finishes_what_a_crash_left);
    RUN(prune_leaves_what_belay_did_not_write);
    RUN(prune_clears_what_a_killed_capture_left);
    RUN(prune_of_a_scope_with_no_checkpoints);
    RUN(excludes_are_configured_per_scope);
    RUN(an_exclude_is_named_and_never_reads_as_removed);
    RUN(no_package_event_comes_from_an_excluded_path);
    RUN(the_state_directory_is_located_inside_the_scope_by_path);
    RUN(an_exclude_list_whose_header_could_not_fit_is_refused);
    RUN(the_excludes_file_and_command_are_strict);
    RUN(json_output_names_every_excluded_path);
    RUN(an_exclude_is_exact_on_links_and_prefixes);
    RUN(reads_leave_the_state_directory_as_it_was);
    RUN(the_receipt_orders_by_what_git_says);
    RUN(a_shared_mapping_writer_marks_every_pass_and_nothing_diffs_on_the_hash);
    RUN(a_quiet_tree_has_no_marked_entry);
    RUN(a_held_open_writer_on_a_small_file_marks_it);
    RUN(a_directory_that_grows_is_no_privilege_change_in_the_receipt);
    free(g_out);
    free(g_err);
    char cmd[800];
    snprintf(cmd, sizeof cmd, "chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
