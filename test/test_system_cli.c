/*
 *  `--system` on check, mark, diff, log and manifest (test/expect/
 *  watch-system.md WS-1, WS-4, WS-5; manifest-v5.md V5-R3, V5-R4, V5-D6).
 *
 *  BLAST RADIUS: the machine's own `/` is never captured here. Every capture
 *  goes through `--system-root DIR`, the undocumented way to point the
 *  system scope at a directory, on a tree under the test's own temporary
 *  directory; belay's state is under it too (BELAY_STATE_DIR). `--system`
 *  itself appears only on commands that take no capture (log, manifest) or
 *  have no scope without it (baseline export, verify), and are refused: were
 *  a refusal to break, still nothing here would walk `/`.
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/error.h"
#include "belay/manifest.h"
#include "cli/cli.h"
#include "policy/bundle.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char g_dir[256], g_tree[400], g_state[400];
static char *g_out, *g_err;

static int belay(const char *a0, ...) {
    char *argv[32] = { "belay", (char *)a0 };
    int argc = 2;
    va_list ap;
    va_start(ap, a0);
    const char *a;
    while (argc < 31 && (a = va_arg(ap, const char *)) != NULL) argv[argc++] = (char *)a;
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
    char cmd[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    if (system(cmd) != 0) { /* the assertions say */ }
}

/* A machine in small, and an empty state. */
static void fresh(void) {
    sh("chmod -R u+rwx '%s' '%s' 2>/dev/null; rm -rf '%s' '%s'; mkdir -p '%s' '%s' && chmod 700 '%s' && chmod 755 '%s'",
       g_tree, g_state, g_tree, g_state, g_tree, g_state, g_state, g_tree);
    sh("cd '%s' && mkdir -p etc usr/bin usr/local/bin var/log var/lib root home/u/Documents proc && "
       "printf 'root:x:0:0:root:/root:/bin/sh\\nu:x:1000:1000::/home/u:/bin/sh\\n' > etc/passwd && "
       "printf 'root:*:1::::::\\n' > etc/shadow && chmod 640 etc/shadow && "
       "printf 'tool\\n' > usr/bin/tool && printf 'local\\n' > usr/local/bin/l && printf 'log\\n' > var/log/syslog && "
       "printf 'x\\n' > var/lib/x && printf 's\\n' > root/secret && chmod 700 root && "
       "printf 'export A=1\\n' > home/u/.bashrc && printf 'private\\n' > home/u/notes.txt && "
       "printf 'd\\n' > home/u/Documents/d.txt && printf 't\\n' > top.txt && ln -s usr/bin bin && chmod 755 . etc usr var home home/u",
       g_tree);
    struct timespec ts = { 0, 30 * 1000000L };
    nanosleep(&ts, NULL);
}

/* The line of the last `belay manifest` output whose path is `path`; the
 * header for "". */
static const char *mline(const char *path) {
    static char line[70000];
    char want[600];
    snprintf(want, sizeof want, "\n{\"path\":\"%s\",", path);       /* an entry's line, not a root in the header */
    const char *p = path[0] == '\0' ? g_out : strstr(g_out, want);
    if (p == NULL) return "";
    if (path[0] != '\0') p++;
    snprintf(line, sizeof line, "%.*s", (int)strcspn(p, "\n"), p);
    return line;
}

/* WS-1, WS-6 to WS-8: a check of the system scope reads the roots. */
TEST(check_captures_the_roots) {
    fresh();
    REQUIRE_MSG(belay("check", "--system-root", g_tree, "--json", NULL) == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "{\"id\":1,\"kind\":\"check\",") == g_out);
    ASSERT_TRUE(strstr(g_out, ",\"basis\":\"walk\",\"carried\":0,") != NULL);
    /* checkpoint-v3 C3-3: proc, var/log, home/u/Documents were not entered */
    ASSERT_TRUE(strstr(g_out, ",\"unreadable\":0,\"sealing\":3,") != NULL);
    REQUIRE(belay("manifest", "--system-root", g_tree, "--id", "1", NULL) == 0);
    ASSERT_TRUE(strstr(mline(""), "{\"belay_manifest\":5,") != NULL);
    ASSERT_TRUE(strstr(mline(""), ",\"roots\":[{\"path\":\"boot\",\"class\":\"metadata\",\"found\":false},") != NULL);
    ASSERT_TRUE(strstr(mline(""), "{\"path\":\"etc\",\"class\":\"content\",\"found\":true}") != NULL);
    ASSERT_TRUE(strstr(mline(""), "{\"path\":\"home/u/.ssh\",\"class\":\"content\",\"found\":false}") != NULL);
    ASSERT_TRUE(strstr(mline(""), "{\"path\":\"home/u/.bashrc\",\"class\":\"content\",\"found\":true}") != NULL);
    ASSERT_TRUE(strstr(mline(""), "{\"path\":\"root/.zshrc\",\"class\":\"content\",\"found\":false}") != NULL);
    ASSERT_TRUE(strstr(mline(""), "{\"path\":\"usr\",\"class\":\"metadata\",\"found\":true}") != NULL);
    ASSERT_TRUE(strstr(mline(""), "\"sealed_key\":\"") != NULL && strstr(mline(""), ",\"basis\":\"walk\"}") != NULL);
    ASSERT_TRUE(strstr(mline("."), ",\"partial\":true}") != NULL);
    ASSERT_TRUE(strstr(mline("home/u"), ",\"partial\":true}") != NULL);
    ASSERT_TRUE(strstr(mline("etc/passwd"), "\"sha256\":") != NULL && strstr(mline("etc/passwd"), "sealed") == NULL);
    ASSERT_TRUE(strstr(mline("etc/shadow"), ",\"sealed\":true}") != NULL && strstr(mline("etc/shadow"), "stored") == NULL);
    ASSERT_TRUE(strstr(mline("root/secret"), ",\"sealed\":true}") != NULL);
    ASSERT_TRUE(strstr(mline("usr/bin/tool"), ",\"meta\":true}") != NULL);
    ASSERT_TRUE(strstr(mline("usr/local/bin/l"), "\"sha256\":") != NULL);
    ASSERT_TRUE(strstr(mline("var/log"), ",\"not_read\":true}") != NULL && strstr(mline("proc"), ",\"not_read\":true}") != NULL);
    ASSERT_TRUE(strstr(mline("home/u/.bashrc"), "\"sha256\":") != NULL && strstr(mline("home/u/.bashrc"), "sealed") == NULL);
    ASSERT_TRUE(mline("bin")[0] != '\0');
    ASSERT_TRUE(mline("top.txt")[0] == '\0' && mline("home/u/notes.txt")[0] == '\0' && mline("var/log/syslog")[0] == '\0');
    /* V5-R3: the key is the state's, mode 600, 32 bytes */
    char cmd[900];
    snprintf(cmd, sizeof cmd, "f=$(find '%s' -name sealing.key) && [ \"$(wc -c < \"$f\" | tr -d ' ')\" = 32 ] && "
             "[ -z \"$(find \"$f\" -perm -004 -o -perm -040 -o -perm -100)\" ] && [ \"$(find '%s' -name sealing.key | wc -l | tr -d ' ')\" = 1 ]",
             g_state, g_state);
    ASSERT_EQ_INT(0, system(cmd));
    /* the text line (checkpoint-v3 G1-2) */
    REQUIRE(belay("check", "--system-root", g_tree, NULL) == 0);
    ASSERT_TRUE(strstr(g_out, "check 2  ") == g_out && strstr(g_out, " entries, nothing seen below 3 directories\n") != NULL);
    /* a scope captured without it is a whole scope, as before: no roots, no key use */
    REQUIRE(belay("check", "--scope", g_tree, NULL) == 0);
    REQUIRE(belay("manifest", "--scope", g_tree, "--id", "3", NULL) == 0);
    ASSERT_TRUE(strstr(mline(""), ",\"roots\":[],\"basis\":\"walk\"}") != NULL);
    ASSERT_TRUE(mline("top.txt")[0] != '\0' && strstr(mline("etc/shadow"), "sealed") == NULL);
}

/* WS-1: mark, diff and log take it too; V5-D6 / WS-10: the diff's header
 * says when the roots differ. */
TEST(mark_diff_and_log_take_it) {
    fresh();
    REQUIRE(belay("check", "--system-root", g_tree, NULL) == 0);
    REQUIRE_MSG(belay("mark", "--system-root", g_tree, "--json", NULL) == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "{\"id\":2,\"kind\":\"mark\",") == g_out);
    ASSERT_TRUE(strstr(g_out, "\"prefilter\":{\"used\":true,") != NULL);
    REQUIRE(belay("manifest", "--system-root", g_tree, "--id", "2", NULL) == 0);
    ASSERT_TRUE(strstr(mline("etc/shadow"), ",\"sealed\":true}") != NULL && strstr(mline("usr/bin/tool"), ",\"meta\":true}") != NULL);
    /* nothing changed: the same roots, no record */
    REQUIRE_MSG(belay("diff", "--system-root", g_tree, "--since", "1", "--json", NULL) == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "roots_differ") == NULL);
    ASSERT_TRUE(strstr(g_out, "\n{\"belay_diff_end\":0,") != NULL);
    /* changes: one in a content root, one in a metadata root, a first key, and two that are nobody's business */
    sh("cd '%s' && printf 'more\\n' >> etc/passwd && printf 'tool2\\n' > usr/bin/tool && mkdir home/u/.ssh && chmod 700 home/u/.ssh && "
       "printf 'ssh-ed25519 AAAA\\n' > home/u/.ssh/authorized_keys && printf 'more\\n' >> home/u/notes.txt && "
       "printf 'l\\n' >> var/log/syslog && printf 'r\\n' >> etc/shadow", g_tree);
    REQUIRE_MSG(belay("diff", "--system-root", g_tree, "--since", "1", "--json", NULL) == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, ",\"roots_differ\":true}\n") != NULL);                /* home/u/.ssh: found now */
    ASSERT_TRUE(strstr(g_out, "{\"path\":\"etc/passwd\",\"outcome\":\"modified\",") != NULL);
    ASSERT_TRUE(strstr(g_out, "{\"path\":\"usr/bin/tool\",\"outcome\":\"modified\",") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"content_not_read\":[\"not_read\"]") != NULL);
    ASSERT_TRUE(strstr(g_out, "{\"path\":\"home/u/.ssh\",\"outcome\":\"added\",\"type\":\"dir\"}") != NULL);
    ASSERT_TRUE(strstr(g_out, "{\"path\":\"home/u/.ssh/authorized_keys\",\"outcome\":\"added\",\"type\":\"reg\"") != NULL);
    ASSERT_TRUE(strstr(g_out, "{\"path\":\"etc/shadow\",\"outcome\":\"modified\",") != NULL);
    ASSERT_TRUE(strstr(g_out, "notes.txt") == NULL && strstr(g_out, "syslog") == NULL);
    /* the receipt names the directories nothing was seen below, as for any scope (G3-2) */
    REQUIRE(belay("diff", "--system-root", g_tree, "--since", "1", NULL) == 0);
    ASSERT_TRUE(strstr(g_out, "etc/passwd") != NULL);
    ASSERT_TRUE(strstr(g_out, "  nothing seen below 3 directories\n") != NULL);
    REQUIRE(belay("log", "--system-root", g_tree, NULL) == 0);
    ASSERT_TRUE(strstr(g_out, "check 1  ") != NULL && strstr(g_out, "mark 2  ") != NULL);
    ASSERT_TRUE(strstr(g_out, ", nothing seen below 3 directories") != NULL);
}

/* WS-1's forms, and what this version does not take it on. */
TEST(usage) {
    fresh();
    ASSERT_EQ_INT(2, belay("log", "--system", "--scope", g_tree, NULL));
    ASSERT_TRUE(strstr(g_err, "--system takes the place of --scope") != NULL);
    ASSERT_EQ_INT(2, belay("check", "--system-root", g_tree, "--scope", g_tree, NULL));
    ASSERT_EQ_INT(2, belay("manifest", "--system", "--scope", g_tree, "--id", "1", NULL));
    ASSERT_TRUE(strstr(g_err, "--system takes the place of --scope") != NULL);
    ASSERT_EQ_INT(2, belay("check", "--system-root", NULL));
    ASSERT_EQ_INT(2, belay("log", "--system", "--system", NULL));
    ASSERT_TRUE(strstr(g_err, "--system given twice") != NULL);
    ASSERT_EQ_INT(2, belay("exclude", "--system-root", g_tree, NULL));
    ASSERT_TRUE(strstr(g_err, "--system is check's, mark's, diff's, log's and manifest's") != NULL);
    /* a container's `/` (WS-1) is not read by roots yet: refused, loudly, before anything is read */
    ASSERT_EQ_INT(3, belay("log", "--system", "--docker", "no-such-container", NULL));
    ASSERT_TRUE(strstr(g_err, "--system with --docker") != NULL);
    ASSERT_EQ_INT(3, belay("manifest", "--system", "--docker", "no-such-container", "--id", "1", NULL));
    ASSERT_EQ_INT(3, belay("check", "--system-root", g_tree, "--docker", "no-such-container", NULL));
    /* nothing was captured or written by any of these */
    char cmd[600];
    snprintf(cmd, sizeof cmd, "[ -z \"$(ls -A '%s')\" ]", g_state);
    ASSERT_EQ_INT(0, system(cmd));
    /* a scope never captured: log says so, diff refuses, as for --scope */
    ASSERT_EQ_INT(0, belay("log", "--system-root", g_tree, NULL));
    ASSERT_TRUE(strstr(g_out, "no checkpoints of the scope") != NULL);
}

#define SHA64 "0000000000000000000000000000000000000000000000000000000000000000"

/* WS-5, V5-R4: baseline export, verify and a protect spec are refused for a
 * system watch, exit 3 -- by the flag, and by a scope whose manifest has
 * roots; for every other scope they work as before. */
TEST(baseline_verify_and_protect_are_refused) {
    fresh();
    char out[500], spec[500];
    snprintf(out, sizeof out, "%s/b.bundle", g_dir);
    snprintf(spec, sizeof spec, "%s/spec.json", g_dir);
    sh("printf '{\"belay_protect\":2,\"protect\":[{\"path\":\"etc/**\",\"mode\":[\"no_write\"]}]}' > '%s'; rm -f '%s'", spec, out);
    ASSERT_EQ_INT(3, belay("baseline", "export", "--system", "--out", out, NULL));
    ASSERT_TRUE(strstr(g_err, "not designed for a system watch") != NULL);
    ASSERT_EQ_INT(3, belay("baseline", "export", "--system-root", g_tree, "--out", out, NULL));
    ASSERT_TRUE(strstr(g_err, "not designed for a system watch") != NULL);
    ASSERT_EQ_INT(3, belay("baseline", "export", "--system", "--out", out, "--protect", spec, NULL));
    ASSERT_EQ_INT(3, belay("verify", "--system", "--baseline", out, "--baseline-sha256", SHA64, NULL));
    ASSERT_TRUE(strstr(g_err, "not designed for a system watch") != NULL);
    ASSERT_EQ_INT(3, belay("verify", "--system-root", g_tree, "--baseline", out, "--baseline-sha256", SHA64, "--protect", spec, NULL));
    ASSERT_TRUE(access(out, F_OK) != 0);
    char cmd[600];
    snprintf(cmd, sizeof cmd, "[ -z \"$(ls -A '%s')\" ]", g_state);
    ASSERT_EQ_INT(0, system(cmd));
    /* an ordinary scope: as before (V5-R4) */
    ASSERT_EQ_INT(0, belay("baseline", "export", "--scope", g_tree, "--out", out, NULL));
    ASSERT_TRUE(access(out, F_OK) == 0);
    unlink(out);
    /* the same scope once its latest manifest has roots: refused without the flag too */
    REQUIRE(belay("check", "--system-root", g_tree, NULL) == 0);
    ASSERT_EQ_INT(3, belay("baseline", "export", "--scope", g_tree, "--out", out, NULL));
    ASSERT_TRUE(strstr(g_err, "not designed for a system watch") != NULL);
    ASSERT_TRUE(access(out, F_OK) != 0);
    ASSERT_EQ_INT(3, belay("verify", "--scope", g_tree, "--baseline", out, "--baseline-sha256", SHA64, NULL));
    ASSERT_TRUE(strstr(g_err, "not designed for a system watch") != NULL);
    ASSERT_EQ_INT(3, belay("verify", "--scope", g_tree, "--baseline", out, "--baseline-sha256", SHA64, "--to", "2", NULL));
    ASSERT_TRUE(strstr(g_err, "not designed for a system watch") != NULL);
}

/* V5-R4: a bundle whose manifest has roots is rejected by every reader. */
TEST(a_bundle_whose_manifest_has_roots_is_rejected) {
    fresh();
    REQUIRE(belay("check", "--system-root", g_tree, "--json", NULL) == 0);
    char manifest[1200], store[1200], bundle[500], work[500], mout[600], sha[65], real[4096];
    const char *m = strstr(g_out, "\"manifest\":\"");
    REQUIRE(m != NULL);
    snprintf(manifest, sizeof manifest, "%.*s", (int)strcspn(m + 12, "\""), m + 12);
    snprintf(store, sizeof store, "%.*s", (int)(strstr(manifest, "/checkpoints/") - manifest), manifest);
    strncat(store, "/store", sizeof store - strlen(store) - 1);
    snprintf(bundle, sizeof bundle, "%s/roots.bundle", g_dir);
    snprintf(work, sizeof work, "%s/work", g_dir);
    snprintf(mout, sizeof mout, "%s/work/m.ndjson", g_dir);
    sh("rm -rf '%s'; mkdir -p '%s/store'", work, work);
    REQUIRE(realpath(g_tree, real) != NULL);
    struct bundle_meta meta = { .created_ns = 1, .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT };
    snprintf(meta.scope, sizeof meta.scope, "%s", real);
    snprintf(meta.belay_version, sizeof meta.belay_version, "test");
    const struct pkg_list none = { 0 };
    /* written by hand from a system manifest (belay itself refuses to export one) */
    REQUIRE_MSG(bundle_write(bundle, manifest, store, &none, &meta, sha) == 0, "%s", belay_err_msg());
    static struct bundle bd;
    char sdir[600];
    snprintf(sdir, sizeof sdir, "%s/store", work);
    ASSERT_EQ_INT(-1, bundle_read(bundle, sha, work, mout, sdir, &bd));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, (int)belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "roots") != NULL);
    bundle_free(&bd);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_sys_%d_%ld", (int)getpid(), (long)time(NULL));
    snprintf(g_tree, sizeof g_tree, "%s/tree", g_dir);
    snprintf(g_state, sizeof g_state, "%s/state", g_dir);
    mkdir(g_dir, 0700);
    setenv("BELAY_STATE_DIR", g_state, 1);
    RUN(check_captures_the_roots);
    RUN(mark_diff_and_log_take_it);
    RUN(usage);
    RUN(baseline_verify_and_protect_are_refused);
    RUN(a_bundle_whose_manifest_has_roots_is_rejected);
    sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    free(g_out);
    free(g_err);
    return belay_test_report();
}
