/*
 *  belay verify against policy.v1's pin (test/expect/policy-v1.md), run
 *  in-process from export to verify: the header, records and trailer; every
 *  flag kind on a scenario that should raise it and, where the pin draws a
 *  line, on one beside it that should not; fail closed; packages frozen or
 *  not; verify's refusals and exit codes. Each scenario is exported, changed
 *  and verified in a fresh scope.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "cli/cli.h"

#include <dirent.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[256], g_scope[400], g_state[400], g_bundle[400], g_spec[400], g_tmp[400];
static char *g_out, *g_err, g_sha[65];

static int belay_v(char **argv, int argc) {
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

static int belay(const char *a0, ...) {
    char *argv[32] = { "belay", (char *)a0 };
    int argc = 2;
    va_list ap;
    va_start(ap, a0);
    const char *a;
    while (argc < 31 && (a = va_arg(ap, const char *)) != NULL) argv[argc++] = (char *)a;
    va_end(ap);
    return belay_v(argv, argc);
}

static void sh(const char *fmt, ...) {
    char cmd[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    static char full[8192 + 512];
    snprintf(full, sizeof full, "cd '%s' && %s", g_scope, cmd);
    if (system(full) != 0) { /* the assertions say */ }
}

/* A fresh scope, and a spec (NULL: none). */
static void fresh(const char *spec) {
    char cmd[4096];
    snprintf(cmd, sizeof cmd, "chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s' && mkdir -p '%s' '%s' '%s' && chmod 700 '%s'",
             g_dir, g_dir, g_scope, g_state, g_tmp, g_state);
    if (system(cmd) != 0) { /* the assertions say */ }
    setenv("BELAY_STATE_DIR", g_state, 1);
    setenv("TMPDIR", g_tmp, 1);
    if (spec != NULL) {
        FILE *f = fopen(g_spec, "w");
        fputs(spec, f);
        fclose(f);
    }
}

static int export_(bool spec) {
    const int rc = spec ? belay("baseline", "export", "--scope", g_scope, "--out", g_bundle, "--protect", g_spec, "--json", NULL)
                        : belay("baseline", "export", "--scope", g_scope, "--out", g_bundle, "--json", NULL);
    const char *s = g_out != NULL ? strstr(g_out, "\"sha256\":\"") : NULL;
    if (s != NULL) snprintf(g_sha, sizeof g_sha, "%.64s", s + 10);
    return rc;
}

static int verify_(bool spec) {
    return spec ? belay("verify", "--scope", g_scope, "--baseline", g_bundle, "--baseline-sha256", g_sha, "--protect", g_spec,
                        "--exit-code", NULL)
                : belay("verify", "--scope", g_scope, "--baseline", g_bundle, "--baseline-sha256", g_sha, "--exit-code", NULL);
}

/* The record line of `flag` naming `path` (its "path" field), or NULL. */
static const char *record(const char *flag, const char *path) {
    static char line[16384];
    char want[512], pw[512];
    snprintf(want, sizeof want, "{\"flag\":\"%s\",", flag);
    snprintf(pw, sizeof pw, "\"path\":\"%s\"", path);
    for (const char *p = g_out; p != NULL && *p; ) {
        const char *e = strchr(p, '\n');
        const size_t l = e != NULL ? (size_t)(e - p) : strlen(p);
        snprintf(line, sizeof line, "%.*s", (int)l, p);
        if (strncmp(line, want, strlen(want)) == 0 && (path == NULL || strstr(line, pw) != NULL)) return line;
        p = e != NULL ? e + 1 : NULL;
    }
    return NULL;
}

static int count(const char *flag) {
    char want[128];
    snprintf(want, sizeof want, "{\"flag\":\"%s\",", flag);
    int n = 0;
    for (const char *p = g_out; p != NULL && (p = strstr(p, want)) != NULL; p++) n++;
    return n;
}

/* Why a record is not as expected, or NULL. */
static const char *why_not(const char *flag, const char *path, const char *frag) {
    static char why[20000];
    const char *r = record(flag, path);
    if (r == NULL) snprintf(why, sizeof why, "no %s record for %s in:\n%s", flag, path ? path : "-", g_out ? g_out : "");
    else if (frag != NULL && strstr(r, frag) == NULL) snprintf(why, sizeof why, "%s for %s lacks %s: %s", flag, path ? path : "-", frag, r);
    else return NULL;
    return why;
}
#define HAS(flag, path, frag) do { const char *w_ = why_not(flag, path, frag); if (w_ != NULL) BELAY_FAIL("%s", w_); } while (0)
#define NONE(flag, path) do { const char *r_ = record(flag, path); \
    if (r_ != NULL) BELAY_FAIL("an unexpected record: %s", r_); } while (0)

/* ---- the format ---- */

TEST(header_records_and_trailer_are_the_pins) {
    fresh("{\"belay_protect\":1,\"protect\":[{\"path\":\"keep\",\"mode\":[\"no_delete\"]}]}");
    sh("printf 'k\\n' > keep && mkdir tests && printf 'def test_a():\\n    assert 1\\n' > tests/test_a.py");
    REQUIRE_MSG(export_(true) == EXIT_DONE, "%s", g_err);
    sh("rm keep && printf 'def test_a():\\n    pass\\n' > tests/test_a.py");
    ASSERT_EQ_INT(EXIT_CHANGES, verify_(true));                 /* --exit-code: a violation */
    /* P-H1 to P-H8, in order */
    char want[1024];
    snprintf(want, sizeof want, "{\"belay_policy\":1,\"scopes\":[\"%s\"],\"baseline_sha256\":\"%s\",\"protect_sha256\":\"", g_scope, g_sha);
    ASSERT_EQ_INT(0, strncmp(g_out, want, strlen(want)));
    ASSERT_TRUE(strstr(g_out, "\",\"frozen_packages\":false,\"before_excluded\":[],\"after_excluded\":[],\"not_emitted\":"
                              "[{\"flag\":\"writes_outside_workdir\",\"why\":\"needs a scope wider than the workdir\"}],"
                              "\"tests_counted\":[\"python\"]}\n") != NULL);
    /* P-F1 to P-F4 */
    HAS("protected_path_deleted", "keep", ",\"level\":\"violation\",\"path\":\"keep\",\"rule\":\"keep\","
        "\"text\":\"keep: protected by keep (no_delete), removed\",\"paths\":[\"keep\"]}");
    HAS("tests_weakened", "tests/test_a.py", ",\"level\":\"signal\",\"path\":\"tests/test_a.py\",\"language\":\"python\","
        "\"assertions_before\":1,\"assertions_after\":0,\"tests_before\":1,\"tests_after\":1,\"markers_added\":[],"
        "\"text\":\"tests/test_a.py: assertions 1 -> 0, tests 1 -> 1, markers added: none\"");
    /* P-F5: violations first */
    ASSERT_TRUE(strstr(g_out, "\"flag\":\"protected_path_deleted\"") < strstr(g_out, "\"flag\":\"touches_tests\""));
    /* P-T1 to P-T8 */
    const char *t = strstr(g_out, "{\"belay_policy_end\":");
    REQUIRE(t != NULL);
    ASSERT_TRUE(strstr(t, ",\"violations\":1,") != NULL);
    ASSERT_TRUE(strstr(t, ",\"protected_path_written\":0,\"protected_path_deleted\":1,") != NULL);
    ASSERT_TRUE(strstr(t, ",\"writes_outside_workdir\":0,\"unknown\":0,\"packages_outside_scope\":0,"
                          "\"packages_no_hash\":0,\"provisional\":false,\"before_sha256\":\"") != NULL);
    ASSERT_EQ_INT('\n', t[strlen(t) - 1]);
    /* signals never fail a run (Q8) */
    fresh(NULL);
    sh("mkdir tests && printf 'x\\n' > tests/test_a.py");
    REQUIRE(export_(false) == EXIT_DONE);
    sh("printf 'y\\n' > tests/test_a.py");
    ASSERT_EQ_INT(EXIT_DONE, verify_(false));
    HAS("touches_tests", "tests/test_a.py", ",\"outcome\":\"modified\",");
    ASSERT_TRUE(strstr(g_out, "\"protect_sha256\":null,\"frozen_packages\":false,") != NULL);
}

/* ---- protected paths (PS-M1 to PS-M5) ---- */

TEST(protected_paths_written_deleted_created) {
    fresh("{\"belay_protect\":1,\"protect\":["
          "{\"path\":\"tests/**\",\"mode\":[\"no_write\",\"no_delete\",\"no_create\"]},"
          "{\"path\":\".github/workflows/**\",\"mode\":[\"no_write\"]},"
          "{\"path\":\"tests/a.py\",\"mode\":[\"no_write\"]}]}");
    sh("mkdir -p tests/sub .github/workflows && printf 'a\\n' > tests/a.py && printf 'b\\n' > tests/b.py && "
       "printf 'c\\n' > tests/c.py && printf 'd\\n' > tests/d.py && printf 'w\\n' > .github/workflows/ci.yml && "
       "printf 'x\\n' > tests/sub/same.py");
    REQUIRE_MSG(export_(true) == EXIT_DONE, "%s", g_err);
    sh("printf 'A\\n' > tests/a.py && chmod 600 tests/b.py && rm tests/c.py && printf 'n\\n' > tests/new.py && "
       "touch -d '2001-01-01' tests/d.py && printf 'x\\n' > tests/sub/same.py.tmp && mv tests/sub/same.py.tmp tests/sub/same.py && "
       "printf 'W\\n' > .github/workflows/ci.yml && mkdir tests/.cache && printf 'z\\n' > tests/.cache/z");
    ASSERT_EQ_INT(EXIT_CHANGES, verify_(true));
    HAS("protected_path_written", "tests/a.py", ",\"rule\":\"tests/**\",\"outcome\":\"modified\",");
    ASSERT_EQ_INT(3, count("protected_path_written"));          /* a.py once, by the first rule: a, b, ci.yml */
    HAS("protected_path_written", "tests/b.py", ",\"outcome\":\"metadata_only\",\"changed\":[\"mode\"");   /* mode: a write */
    HAS("protected_path_deleted", "tests/c.py", NULL);
    HAS("protected_path_created", "tests/new.py", NULL);
    HAS("protected_path_written", ".github/workflows/ci.yml", ",\"rule\":\".github/workflows/**\",");   /* decision 157 */
    NONE("protected_path_written", "tests/d.py");               /* timestamps only */
    NONE("protected_path_written", "tests/sub/same.py");        /* the same bytes written back: a new inode, no write */
    NONE("protected_path_created", "tests/.cache/z");           /* `**` never takes a dot-name */
}

TEST(expected_sha256_holds_or_says_why_not) {
    /* sha256 of "ok\n", from sha256sum */
    fresh("{\"belay_protect\":1,\"protect\":["
          "{\"path\":\"g0\",\"expected_sha256\":\"dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22\"},"
          "{\"path\":\"g1\",\"expected_sha256\":\"dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22\"},"
          "{\"path\":\"g2\",\"expected_sha256\":\"dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22\"},"
          "{\"path\":\"g3\",\"expected_sha256\":\"dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22\"},"
          "{\"path\":\"never\",\"expected_sha256\":\"dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22\"}]}");
    sh("printf 'ok\\n' > g0 && printf 'other\\n' > g1 && printf 'x\\n' > g2 && mkdir g3");
    REQUIRE_MSG(export_(true) == EXIT_DONE, "%s", g_err);
    sh("rm g2");
    ASSERT_EQ_INT(EXIT_CHANGES, verify_(true));
    HAS("protected_hash_mismatch", "g1", ",\"why\":\"other bytes\",\"actual\":\"");   /* whatever the baseline held */
    HAS("protected_hash_mismatch", "g2", ",\"why\":\"absent\",\"text\"");
    HAS("protected_hash_mismatch", "g3", ",\"why\":\"not a regular file\",");
    HAS("protected_hash_mismatch", "never", ",\"why\":\"absent\",");                  /* on neither side */
    NONE("protected_hash_mismatch", "g0");                                             /* it holds */
}

/* PS-M5, decision 147: what cannot be shown intact is a violation. A
 * protected file past the 4 GiB bound is `unverified` (decision 159). */
TEST(a_protected_path_that_cannot_be_verified_is_a_violation) {
    fresh("{\"belay_protect\":1,\"protect\":[{\"path\":\"big\",\"mode\":[\"no_write\"]}]}");
    char big[600];
    snprintf(big, sizeof big, "%s/big", g_scope);
    const int fd = open(big, O_WRONLY | O_CREAT, 0644);
    REQUIRE(fd >= 0 && ftruncate(fd, (off_t)(4ull << 30) + 1) == 0);     /* sparse */
    close(fd);
    REQUIRE_MSG(export_(true) == EXIT_DONE, "%s", g_err);
    ASSERT_EQ_INT(EXIT_CHANGES, verify_(true));
    HAS("protected_path_unverifiable", "big", ",\"rule\":\"big\",\"reasons\":[\"unverified\"],");
    ASSERT_EQ_INT(0, count("protected_path_written"));
    /* hashed at reset, past the bound after: its size proves the write, its
     * after entry cannot be verified -- both said */
    fresh("{\"belay_protect\":1,\"protect\":[{\"path\":\"grow\",\"mode\":[\"no_write\"]}]}");
    sh("printf 'small\\n' > grow");
    REQUIRE_MSG(export_(true) == EXIT_DONE, "%s", g_err);
    snprintf(big, sizeof big, "%s/grow", g_scope);
    const int g = open(big, O_WRONLY);
    REQUIRE(g >= 0 && ftruncate(g, (off_t)(4ull << 30) + 1) == 0);
    close(g);
    ASSERT_EQ_INT(EXIT_CHANGES, verify_(true));
    HAS("protected_path_written", "grow", ",\"outcome\":\"modified\",");
    HAS("protected_path_unverifiable", "grow", ",\"reasons\":[\"unverified\"],");
}

/* ---- packages (decision 146) ---- */

static void dpkg_fixture(void) {
    sh("mkdir -p var/lib/dpkg/info usr/bin etc && printf 'bin\\n' > usr/bin/tool && printf 'two\\n' > usr/bin/other && "
       "printf 'c\\n' > etc/tool.conf && "
       "m=$(python3 -c \"import hashlib;print(hashlib.md5(b'bin\\\\n').hexdigest())\") && "
       "o=$(python3 -c \"import hashlib;print(hashlib.md5(b'two\\\\n').hexdigest())\") && "
       "c=$(python3 -c \"import hashlib;print(hashlib.md5(b'c\\\\n').hexdigest())\") && "
       "printf 'Package: tool\\nStatus: install ok installed\\nArchitecture: all\\nVersion: 1\\nConffiles:\\n /etc/tool.conf %%s\\n\\n"
       "Package: other\\nStatus: install ok installed\\nArchitecture: amd64\\nVersion: 1.0\\n\\n' $c > var/lib/dpkg/status && "
       "printf '%%s  usr/bin/tool\\n' $m > var/lib/dpkg/info/tool.md5sums && "
       "printf '%%s  usr/bin/other\\n' $o > var/lib/dpkg/info/other:amd64.md5sums");
}

TEST(packages_frozen_or_not) {
    for (int frozen = 0; frozen < 2; frozen++) {
        fresh(frozen ? "{\"belay_protect\":1,\"protect\":[],\"frozen_packages\":true}" : NULL);
        dpkg_fixture();
        REQUIRE_MSG(export_(frozen) == EXIT_DONE, "%s", g_err);
        /* tool tampered with; tool.conf edited; other upgraded (its file replaced by the installer) */
        sh("printf 'evil\\n' > usr/bin/tool && printf 'edited\\n' > etc/tool.conf && printf 'three\\n' > usr/bin/other && "
           "o=$(python3 -c \"import hashlib;print(hashlib.md5(b'three\\\\n').hexdigest())\") && "
           "sed -i 's/^Version: 1.0$/Version: 2.0/' var/lib/dpkg/status && "
           "printf '%%s  usr/bin/other\\n' $o > var/lib/dpkg/info/other:amd64.md5sums");
        ASSERT_EQ_INT(frozen ? EXIT_CHANGES : EXIT_DONE, verify_(frozen));
        HAS("tampered_installed_package", "usr/bin/tool", frozen ? ",\"level\":\"violation\",\"db\":\"dpkg\",\"package\":\"tool:all\","
                                                                   "\"path\":\"usr/bin/tool\",\"why\":\"other bytes\",\"at_reset\":\"match\""
                                                                 : ",\"level\":\"signal\",");
        HAS("conffile_changed", "etc/tool.conf", ",\"level\":\"signal\",\"package\":\"tool:all\",");
        NONE("tampered_installed_package", "etc/tool.conf");        /* a conffile: never tampered */
        NONE("tampered_installed_package", "usr/bin/other");        /* its package changed: the installer's */
        HAS("package_changed", NULL, frozen ? ",\"level\":\"violation\",\"db\":\"dpkg\",\"package\":\"other:amd64\",\"event\":\"dpkg_upgraded\","
                                            : ",\"self_consistent\":true,");
        if (frozen) ASSERT_TRUE(strstr(record("package_changed", NULL), "self_consistent") == NULL);
        ASSERT_TRUE(strstr(g_out, frozen ? ",\"frozen_packages\":true," : ",\"frozen_packages\":false,") != NULL);
    }
}

/* ---- the signals (decision 149) ---- */

TEST(test_files_touched_and_weakened) {
    fresh(NULL);
    sh("mkdir -p tests src && printf 'import pytest\\n\\ndef test_a():\\n    assert 1\\n    self.assertEqual(1, 1)\\n\\n"
       "async def test_b():\\n    with pytest.raises(ValueError):\\n        f()\\n' > tests/test_x.py && "
       "printf 'def test_c():\\n    assert 1\\n' > tests/test_gone.py && printf 'def test_d():\\n    assert 1\\n' > tests/test_empty.py && "
       "printf 'x\\n' > src/main.py && printf 'def test_k():\\n    assert 1\\n' > src/test_keep.py && "
       "printf 'x = 1\\n' > tests/test_e.py && printf 'x = 1\\n' > tests/test_r.py && printf 'm\\n' > tests/test_m.py && "
       "printf 'h\\n' > tests/helpers.txt");
    REQUIRE(export_(false) == EXIT_DONE);
    sh("printf 'import pytest\\n\\n@pytest.mark.skip(reason=\"later\")\\ndef test_a():\\n    assert 1\\n\\n' > tests/test_x.py && "
       "rm tests/test_gone.py && : > tests/test_empty.py && printf 'y\\n' > src/main.py && "
       "printf 'def test_k():\\n    assert 1\\n    assert 2\\n' > src/test_keep.py && "
       ": > tests/test_e.py && rm tests/test_r.py && chmod 600 tests/test_m.py && printf 'H\\n' > tests/helpers.txt");
    ASSERT_EQ_INT(EXIT_DONE, verify_(false));
    HAS("tests_weakened", "tests/test_e.py", ",\"assertions_before\":0,\"assertions_after\":0,\"tests_before\":0,");  /* emptied */
    HAS("tests_weakened", "tests/test_r.py", ",\"assertions_before\":0,\"assertions_after\":0,");                   /* removed */
    NONE("touches_tests", "tests/test_m.py");                   /* its mode only */
    HAS("touches_tests", "tests/helpers.txt", NULL);            /* below tests/ */
    HAS("tests_weakened", "tests/test_x.py", ",\"assertions_before\":3,\"assertions_after\":1,\"tests_before\":2,\"tests_after\":1,"
        "\"markers_added\":[\"@pytest.mark.skip(reason=\\\"later\\\")\"],");
    HAS("tests_weakened", "tests/test_gone.py", ",\"assertions_after\":0,\"tests_before\":1,\"tests_after\":0,");
    HAS("tests_weakened", "tests/test_empty.py", NULL);         /* emptied */
    HAS("touches_tests", "tests/test_gone.py", ",\"outcome\":\"removed\",");
    HAS("touches_tests", "src/test_keep.py", NULL);
    NONE("tests_weakened", "src/test_keep.py");                 /* more assertions: no weakening */
    NONE("touches_tests", "src/main.py");
}

TEST(ci_pytest_config_and_conftest) {
    fresh(NULL);
    sh("mkdir -p .github/workflows .circleci a other/workflows && printf 'o\\n' > other/workflows/x.yml && printf 'w\\n' > .github/workflows/ci.yml && printf 'c\\n' > .circleci/config.yml && "
       "printf '[tox]\\nenvlist = py3\\n[pytest]\\naddopts = -q\\n' > tox.ini && "
       "printf '[metadata]\\nname = x\\n[tool:pytest]\\naddopts = -q\\n' > setup.cfg && "
       "printf '[project]\\nname = \"x\"\\n[tool.pytest.ini_options]\\naddopts = \"-q\"\\n' > pyproject.toml && "
       "printf '[pytest]\\n' > pytest.ini && printf 'x\\n' > a/conftest.py && printf 'v\\n' > .github/README");
    REQUIRE(export_(false) == EXIT_DONE);
    sh("printf 'W\\n' > .github/workflows/ci.yml && rm .circleci/config.yml && printf 'y\\n' > .travis.yml && "
       "printf '[tox]\\nenvlist = py3,py4\\n[pytest]\\naddopts = -q\\n' > tox.ini && "
       "printf '[metadata]\\nname = x\\n[tool:pytest]\\naddopts = -x\\n' > setup.cfg && "
       "printf '[project]\\nname = \"x\"\\n[tool.pytest.ini_options]\\naddopts = \"-q -p no:x\"\\n' > pyproject.toml && "
       "printf '[pytest]\\nx = 1\\n' > pytest.ini && printf 'y\\n' > a/conftest.py && printf 'V\\n' > .github/README && "
       "printf 'O\\n' > other/workflows/x.yml");
    ASSERT_EQ_INT(EXIT_DONE, verify_(false));
    HAS("edits_ci_config", ".github/workflows/ci.yml", ",\"outcome\":\"modified\",");
    HAS("edits_ci_config", ".circleci/config.yml", ",\"outcome\":\"removed\",");
    HAS("edits_ci_config", ".travis.yml", ",\"outcome\":\"added\",");
    NONE("edits_ci_config", ".github/README");
    NONE("edits_ci_config", "other/workflows/x.yml");          /* `workflows` not below `.github` */
    NONE("pytest_config_changed", "tox.ini");                   /* only [tox] changed */
    HAS("pytest_config_changed", "setup.cfg", ",\"section\":\"[tool:pytest]\",\"outcome\":\"modified\",");
    HAS("pytest_config_changed", "pyproject.toml", ",\"section\":\"[tool.pytest.ini_options]\",");
    HAS("pytest_config_changed", "pytest.ini", ",\"section\":\"pytest.ini\",");
    HAS("conftest_changed", "a/conftest.py", ",\"text\":\"a/conftest.py: conftest.py modified, code pytest runs\",");
}

TEST(startup_hooks_git_hooks_and_history) {
    fresh(NULL);
    sh("mkdir -p lib/site-packages/pkg-1.0.dist-info .git/refs/heads .git/logs/refs/heads .git/hooks && "
       "printf 'x\\n' > lib/site-packages/listed.pth && "
       "h=$(python3 -c \"import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256(b'y\\\\n').digest()).rstrip(b'=').decode())\") && "
       "printf 'listed.pth,sha256=%%s,2\\n' $h > lib/site-packages/pkg-1.0.dist-info/RECORD && "
       "printf 'ref: refs/heads/main\\n' > .git/HEAD && printf '1111111111111111111111111111111111111111\\n' > .git/refs/heads/main && "
       "printf '0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 A <a@b> 1 +0000\\tcommit (initial): x\\n'"
       " > .git/logs/refs/heads/main");
    REQUIRE(export_(false) == EXIT_DONE);
    sh("printf 'import evil\\n' > lib/site-packages/zz.pth && printf 'import evil\\n' > lib/site-packages/sitecustomize.py && "
       "printf 'y\\n' > lib/site-packages/listed.pth && printf 'import x\\n' > lib/sitecustomize.py && "
       "printf '#!/bin/sh\\n' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit && "
       "printf '2222222222222222222222222222222222222222\\n' > .git/refs/heads/main && "
       "printf '0000000000000000000000000000000000000000 2222222222222222222222222222222222222222 A <a@b> 2 +0000\\tcommit (initial): y\\n'"
       " > .git/logs/refs/heads/main");
    ASSERT_EQ_INT(EXIT_DONE, verify_(false));
    HAS("python_startup_hook_changed", "lib/site-packages/zz.pth", ",\"outcome\":\"added\",");
    HAS("python_startup_hook_changed", "lib/site-packages/sitecustomize.py", NULL);
    NONE("python_startup_hook_changed", "lib/site-packages/listed.pth");   /* in a RECORD: a package's */
    NONE("python_startup_hook_changed", "lib/sitecustomize.py");          /* not in site-packages */
    HAS("git_hook_changed", ".git/hooks/pre-commit", ",\"hook\":\"pre-commit\",\"change\":\"added\",\"executable\":true,\"target\":\"\",");
    HAS("git_history_rewritten", NULL, ",\"repo\":\".git\",\"branch\":\"refs/heads/main\",\"text\":\"refs/heads/main in .git: reflog rewritten\"");
}

TEST(executables_on_path_and_privilege) {
    fresh(NULL);
    sh("mkdir -p bin opt/tools venv/bin data && printf 'x\\n' > bin/old && chmod 644 bin/old && printf 's\\n' > data/s && "
       "printf 'home = /usr\\n' > venv/pyvenv.cfg");
    REQUIRE(export_(false) == EXIT_DONE);
    sh("printf '#!/bin/sh\\n' > bin/new && chmod 755 bin/new && chmod 755 bin/old && ln -s /bin/sh bin/link && "
       "printf 'x\\n' > bin/plain && chmod 644 bin/plain && printf '#!/bin/sh\\n' > venv/bin/py && chmod 755 venv/bin/py && "
       "printf '#!/bin/sh\\n' > opt/tools/t && chmod 755 opt/tools/t && chmod u+s data/s");
    ASSERT_EQ_INT(EXIT_DONE, verify_(false));
    HAS("new_executable_on_path", "bin/new", ",\"outcome\":\"added\",\"mode\":33261,");
    HAS("new_executable_on_path", "bin/old", ",\"outcome\":\"metadata_only\",");      /* its execute bits added */
    HAS("new_executable_on_path", "bin/link", NULL);
    HAS("new_executable_on_path", "venv/bin/py", NULL);                                /* beside pyvenv.cfg */
    NONE("new_executable_on_path", "bin/plain");
    NONE("new_executable_on_path", "opt/tools/t");                                     /* not a PATH dir */
    HAS("privilege_changed", "data/s", ",\"what\":\"setuid\",\"before\":\"off\",\"after\":\"on\",");
    /* path_dirs replaces the default (PS-7) */
    fresh("{\"belay_protect\":1,\"protect\":[],\"path_dirs\":[\"opt/*\"]}");
    sh("mkdir -p bin opt/tools");
    REQUIRE(export_(true) == EXIT_DONE);
    sh("printf '#!/bin/sh\\n' > bin/new && chmod 755 bin/new && printf '#!/bin/sh\\n' > opt/tools/t && chmod 755 opt/tools/t");
    ASSERT_EQ_INT(EXIT_DONE, verify_(true));
    HAS("new_executable_on_path", "opt/tools/t", NULL);
    NONE("new_executable_on_path", "bin/new");
}

/* ---- refusals ---- */

TEST(verify_refuses_what_it_must_never_judge) {
    fresh("{\"belay_protect\":1,\"protect\":[{\"path\":\"keep\",\"mode\":[\"no_write\"]}]}");
    sh("printf 'k\\n' > keep");
    REQUIRE(export_(true) == EXIT_DONE);
    /* no digest; another digest (B-R2) */
    ASSERT_EQ_INT(EXIT_REFUSED, belay("verify", "--scope", g_scope, "--baseline", g_bundle, "--protect", g_spec, NULL));
    ASSERT_TRUE(strstr(g_err, "--baseline-sha256 HEX is required") != NULL);
    ASSERT_EQ_INT(EXIT_REFUSED, belay("verify", "--scope", g_scope, "--baseline", g_bundle, "--baseline-sha256",
                                      "0000000000000000000000000000000000000000000000000000000000000000", "--protect", g_spec, NULL));
    ASSERT_TRUE(strstr(g_err, "its bytes are not the bundle given") != NULL);
    ASSERT_EQ_INT(0, (int)strlen(g_out));
    /* the spec: none, another (PS-R3); refused (PS-R2, exit 2) */
    ASSERT_EQ_INT(EXIT_REFUSED, verify_(false));
    char other[600];
    snprintf(other, sizeof other, "%s/other.json", g_dir);
    FILE *f = fopen(other, "w");
    fputs("{\"belay_protect\":1,\"protect\":[{\"path\":\"keep\",\"mode\":[\"no_delete\"]}]}", f);
    fclose(f);
    ASSERT_EQ_INT(EXIT_REFUSED, belay("verify", "--scope", g_scope, "--baseline", g_bundle, "--baseline-sha256", g_sha,
                                      "--protect", other, NULL));
    f = fopen(other, "w");
    fputs("{\"belay_protect\":1,\"protect\":[],\"frozen\":true}", f);
    fclose(f);
    ASSERT_EQ_INT(EXIT_USAGE, belay("verify", "--scope", g_scope, "--baseline", g_bundle, "--baseline-sha256", g_sha,
                                    "--protect", other, NULL));
    /* a bundle of another scope */
    char elsewhere[600];
    snprintf(elsewhere, sizeof elsewhere, "%s/elsewhere", g_dir);
    sh("mkdir -p '%s'", elsewhere);
    ASSERT_EQ_INT(EXIT_REFUSED, belay("verify", "--scope", elsewhere, "--baseline", g_bundle, "--baseline-sha256", g_sha,
                                      "--protect", g_spec, NULL));
    ASSERT_TRUE(strstr(g_err, "another scope") != NULL);
    /* --to a checkpoint that trusted files, with a spec (PS-C1) */
    ASSERT_EQ_INT(EXIT_DONE, belay("check", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(EXIT_DONE, belay("mark", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(EXIT_REFUSED, belay("verify", "--scope", g_scope, "--baseline", g_bundle, "--baseline-sha256", g_sha,
                                      "--protect", g_spec, "--to", "3", NULL));
    ASSERT_TRUE(strstr(g_err, "trusted") != NULL);
    ASSERT_EQ_INT(EXIT_DONE, belay("verify", "--scope", g_scope, "--baseline", g_bundle, "--baseline-sha256", g_sha,
                                   "--protect", g_spec, "--to", "2", NULL));          /* a check: read every file */
    /* usage */
    ASSERT_EQ_INT(EXIT_USAGE, belay("verify", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(EXIT_USAGE, belay("verify", "--scope", g_scope, "--baseline", g_bundle, "--to", "x", NULL));
    /* the work directory is gone, whatever happened */
    DIR *d = opendir(g_tmp);
    REQUIRE(d != NULL);
    int left = 0;
    for (struct dirent *e; (e = readdir(d)) != NULL;) left += strncmp(e->d_name, "belay-verify.", 13) == 0;
    closedir(d);
    ASSERT_EQ_INT(0, left);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_policy_%d", (int)getpid());
    snprintf(g_scope, sizeof g_scope, "%s/scope", g_dir);
    snprintf(g_state, sizeof g_state, "%s/state", g_dir);
    snprintf(g_tmp, sizeof g_tmp, "%s/tmp", g_dir);
    snprintf(g_bundle, sizeof g_bundle, "%s/b.bundle", g_dir);
    snprintf(g_spec, sizeof g_spec, "%s/spec.json", g_dir);
    RUN(header_records_and_trailer_are_the_pins);
    RUN(protected_paths_written_deleted_created);
    RUN(expected_sha256_holds_or_says_why_not);
    RUN(a_protected_path_that_cannot_be_verified_is_a_violation);
    RUN(packages_frozen_or_not);
    RUN(test_files_touched_and_weakened);
    RUN(ci_pytest_config_and_conftest);
    RUN(startup_hooks_git_hooks_and_history);
    RUN(executables_on_path_and_privilege);
    RUN(verify_refuses_what_it_must_never_judge);
    char cmd[600];
    snprintf(cmd, sizeof cmd, "chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    if (system(cmd) != 0) { /* nothing to report */ }
    free(g_out);
    free(g_err);
    return belay_test_report();
}
