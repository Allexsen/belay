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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
    sh("rm -rf '%s' '%s' && mkdir -p '%s/src' '%s'", g_scope, g_state, g_scope, g_state);
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
    free(g_out);
    free(g_err);
    char cmd[800];
    snprintf(cmd, sizeof cmd, "chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
