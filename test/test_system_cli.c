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
#include "cli/cli_internal.h"
#include "policy/bundle.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
       "printf 'root:SHADOWSECRET:1::::::\\n' > etc/shadow && chmod 640 etc/shadow && "
       "printf 'tool\\n' > usr/bin/tool && printf 'local\\n' > usr/local/bin/l && printf 'log\\n' > var/log/syslog && "
       "printf 'x\\n' > var/lib/x && printf 'ROOTNOTESECRET\\n' > root/secret && chmod 700 root && "
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
    /* V5-A1: a count in the header, one line per root after it */
    ASSERT_TRUE(strstr(mline(""), ",\"roots\":41,\"sealed_key\":\"") != NULL);     /* 13 fixed, 14 for each of two homes */
    ASSERT_TRUE(strstr(g_out, "\"}\n{\"root\":\"boot\",\"class\":\"metadata\",\"found\":false}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\n{\"root\":\"etc\",\"class\":\"content\",\"found\":true}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\n{\"root\":\"home/u/.ssh\",\"class\":\"content\",\"found\":false}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\n{\"root\":\"home/u/.bashrc\",\"class\":\"content\",\"found\":true}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\n{\"root\":\"root/.zshrc\",\"class\":\"content\",\"found\":false}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\n{\"root\":\"usr\",\"class\":\"metadata\",\"found\":true}\n") != NULL);
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
    sh("rm -rf '%s' && mkdir '%s' && chmod 700 '%s'", g_state, g_state, g_state);
    REQUIRE(belay("check", "--scope", g_tree, NULL) == 0);
    REQUIRE(belay("manifest", "--scope", g_tree, "--id", "1", NULL) == 0);
    ASSERT_TRUE(strstr(mline(""), ",\"roots\":0,\"basis\":\"walk\"}") != NULL);
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
    /* a checkpoint that is not there: the hint names the flag the command was given */
    ASSERT_TRUE(belay("diff", "--system-root", g_tree, "--since", "1", "--to", "99", NULL) != 0);
    ASSERT_TRUE(strstr(g_err, "(belay log --system lists them)") != NULL);
    REQUIRE(belay("log", "--system-root", g_tree, NULL) == 0);
    ASSERT_TRUE(strstr(g_out, "check 1  ") != NULL && strstr(g_out, "mark 2  ") != NULL);
    ASSERT_TRUE(strstr(g_out, ", nothing seen below 3 directories") != NULL);
}

/* The first line of a command's output, into a static buffer. */
static const char *sh_line(const char *fmt, ...) {
    static char line[600];
    char cmd[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    line[0] = '\0';
    FILE *f = popen(cmd, "r");
    if (f == NULL) return line;
    if (fgets(line, sizeof line, f) == NULL) line[0] = '\0';
    pclose(f);
    line[strcspn(line, "\n")] = '\0';
    return line;
}

/* system-interpreters.md SA-6, checkpoint-v3 C3-6b: a checkpoint of a
 * system watch keeps the per-line digests of shadow and gshadow as
 * `shadow.lines`, mode 600, and records its sha256; a diff of two names the
 * entries that changed; no part of a line but its first field is anywhere
 * in belay's state or output; and the file goes with its checkpoint. */
TEST(a_checkpoint_keeps_the_digests_of_shadow_lines) {
    fresh();
    sh("cd '%s' && printf 'root:SHADOWSECRET:1::::::\\ndaemon:*:1::::::\\n' > etc/shadow && "
       "printf 'root:GSHADOWSECRET::\\n' > etc/gshadow && chmod 640 etc/gshadow", g_tree);
    REQUIRE_MSG(belay("check", "--system-root", g_tree, "--json", NULL) == 0, "%s", g_err);
    char lines[600], sha[80];
    snprintf(lines, sizeof lines, "%s", sh_line("find '%s' -name shadow.lines", g_state));
    REQUIRE(strstr(lines, "/checkpoints/1/shadow.lines") != NULL);
    struct stat ls;
    REQUIRE(stat(lines, &ls) == 0);
    ASSERT_EQ_INT(0600, (int)(ls.st_mode & 07777));
    /* the record's last key is the sha256 of that file (sha256sum is coreutils'; shasum is everywhere else) */
    snprintf(sha, sizeof sha, "%.64s", sh_line("(sha256sum '%s' 2>/dev/null || shasum -a 256 '%s') | cut -c1-64", lines, lines));
    char want[200];
    snprintf(want, sizeof want, ",\"journal_seq\":null,\"shadow_lines_sha256\":\"%s\"}\n", sha);
    ASSERT_EQ_INT(64, (int)strlen(sha));
    ASSERT_TRUE(strstr(g_out, want) != NULL);
    ASSERT_EQ_STR("4", sh_line("wc -l < '%s' | tr -d ' '", lines));         /* a header, gshadow's line, shadow's two */
    ASSERT_EQ_STR("1", sh_line("grep -c '^{\"file\":\"etc/shadow\",\"name\":\"daemon\",\"hmac\":\"[0-9a-f]*\"}$' '%s'", lines));
    ASSERT_EQ_STR("1", sh_line("grep -c '^{\"file\":\"etc/gshadow\",\"name\":\"root\",\"hmac\":\"[0-9a-f]*\"}$' '%s'", lines));
    ASSERT_EQ_STR("", sh_line("grep -r -l 'SHADOWSECRET' '%s'", g_state));
    /* useradd's rewrite, in small: an entry changed, one added, one removed */
    sh("cd '%s' && printf 'root:SHADOWSECRET2:2::::::\\nsiteuser:!:3::::::\\n' > etc/shadow", g_tree);
    REQUIRE_MSG(belay("diff", "--system-root", g_tree, "--since", "1", "--json", NULL) == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "{\"event\":\"password_entry_changed\",\"interp\":\"accounts\",\"file\":\"etc/shadow\",\"name\":\"root\","
                              "\"text\":\"password database: entry changed for root\",\"paths\":[\"etc/shadow\"]}\n"
                              "{\"event\":\"password_entry_removed\",\"interp\":\"accounts\",\"file\":\"etc/shadow\",\"name\":\"daemon\","
                              "\"text\":\"password database: entry removed for daemon\",\"paths\":[\"etc/shadow\"]}\n"
                              "{\"event\":\"password_entry_added\",\"interp\":\"accounts\",\"file\":\"etc/shadow\",\"name\":\"siteuser\","
                              "\"text\":\"password database: entry added for siteuser\",\"paths\":[\"etc/shadow\"]}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "etc/gshadow\",\"name") == NULL);            /* gshadow did not change */
    ASSERT_TRUE(strstr(g_out, "SHADOWSECRET") == NULL);
    ASSERT_EQ_STR("", sh_line("grep -r -l 'SHADOWSECRET' '%s'", g_state));
    /* the receipt says them too, among the events */
    REQUIRE(belay("diff", "--system-root", g_tree, "--since", "1", "--to", "2", NULL) == 0);
    ASSERT_TRUE(strstr(g_out, "password database: entry added for siteuser") != NULL);
    ASSERT_TRUE(strstr(g_out, "SHADOWSECRET") == NULL);
    /* log prints each checkpoint's */
    REQUIRE(belay("log", "--system-root", g_tree, "--json", NULL) == 0);
    ASSERT_TRUE(strstr(g_out, want) != NULL);
    ASSERT_TRUE(strstr(g_out, "\"shadow_lines_sha256\":null") == NULL);
    /* a digest file that is not the one recorded is corrupt state, said: never compared, never skipped */
    sh("printf 'x' >> '%s'", lines);
    ASSERT_TRUE(belay("diff", "--system-root", g_tree, "--since", "1", "--to", "2", "--json", NULL) != 0);
    ASSERT_TRUE(strstr(g_err, "shadow.lines") != NULL);
    /* and it goes with its checkpoint */
    REQUIRE_MSG(belay("prune", "--scope", g_tree, "--keep-last", "1", NULL) == 0, "%s", g_err);
    ASSERT_EQ_INT(-1, access(lines, F_OK));
    lines[strlen(lines) - strlen("/shadow.lines")] = '\0';
    ASSERT_EQ_INT(-1, access(lines, F_OK));                                 /* the directory too */
    ASSERT_EQ_STR("", sh_line("grep -r -l 'SHADOWSECRET' '%s'", g_state));
}

/* A system watch of a machine whose shadow cannot be read (belay not root)
 * or that has none keeps no digest file, and says null. */
TEST(no_digest_file_where_shadow_is_not_read) {
    fresh();
    sh("rm -f '%s/etc/shadow'", g_tree);
    REQUIRE_MSG(belay("check", "--system-root", g_tree, "--json", NULL) == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, ",\"shadow_lines_sha256\":null}\n") != NULL);
    ASSERT_EQ_STR("", sh_line("find '%s' -name shadow.lines", g_state));
    /* against a checkpoint that has one: no entry is named, the record of shadow stands */
    sh("cd '%s' && printf 'root:SHADOWSECRET:1::::::\\n' > etc/shadow && chmod 640 etc/shadow", g_tree);
    REQUIRE_MSG(belay("diff", "--system-root", g_tree, "--since", "1", "--json", NULL) == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "password_entry") == NULL);
    ASSERT_TRUE(strstr(g_out, "{\"path\":\"etc/shadow\",\"outcome\":\"added\",") != NULL);
}

/* runtime-v1.md: a system watch's checkpoint keeps the runtime record its
 * proc gave -- under --system-root, that root's proc, a tree shaped like
 * /proc -- and records its sha256 (C3-6); a diff of two has the runtime
 * section; a record that is not the one recorded is corrupt state; it goes
 * with its checkpoint. A checkpoint with no proc to read has none. */
TEST(a_checkpoint_keeps_the_runtime_record_of_its_proc) {
    fresh();
    REQUIRE_MSG(belay("check", "--system-root", g_tree, "--json", NULL) == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, ",\"runtime_sha256\":null,") != NULL);          /* proc has no net/ */
    sh("cd '%s/proc' && mkdir -p net sys/net/ipv4 self/ns 1/fd && printf '32768 60999\\n' > sys/net/ipv4/ip_local_port_range && "
       "ln -s 'net:[4026531840]' self/ns/net && "
       "printf '  sl  local_address rem_address   st\\n   0: 00000000:0016 00000000:0000 0A 0:0 0:0 0 0 0 8760 1\\n' > net/tcp && "
       "printf '0::/init.scope\\n' > 1/cgroup && ln -s 'socket:[8760]' 1/fd/3", g_tree);
    REQUIRE_MSG(belay("check", "--system-root", g_tree, "--json", NULL) == 0, "%s", g_err);
    char rt[600], sha[80], want[200];
    snprintf(rt, sizeof rt, "%s", sh_line("find '%s' -name runtime.ndjson", g_state));
    REQUIRE(strstr(rt, "/checkpoints/2/runtime.ndjson") != NULL);
    struct stat rs;
    REQUIRE(stat(rt, &rs) == 0);
    ASSERT_EQ_INT(0600, (int)(rs.st_mode & 07777));
    snprintf(sha, sizeof sha, "%.64s", sh_line("(sha256sum '%s' 2>/dev/null || shasum -a 256 '%s') | cut -c1-64", rt, rt));
    snprintf(want, sizeof want, ",\"runtime_sha256\":\"%s\",\"journal_seq\":null,", sha);
    ASSERT_TRUE(strstr(g_out, want) != NULL);
    const bool root = geteuid() == 0;
    ASSERT_EQ_STR(root ? "{\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":22,\"holders\":[{\"exe\":null,\"cgroup\":\"/init.scope\"}]}"
                       : "{\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":22,\"holders\":null}",
                  sh_line("sed -n 2p '%s'", rt));
    /* the proc tree is not a root: nothing of it is in the manifest */
    REQUIRE(belay("manifest", "--system-root", g_tree, "--id", "2", NULL) == 0);
    ASSERT_TRUE(strstr(g_out, "\"path\":\"proc/") == NULL);
    /* against the checkpoint without one: the section says so, and nothing else */
    REQUIRE_MSG(belay("diff", "--system-root", g_tree, "--since", "1", "--to", "2", "--json", NULL) == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, root ? "{\"runtime\":\"incomplete\",\"why\":[\"no_record_before\"],"
                                     "\"text\":\"runtime incomplete: no runtime record before\"}\n"
                                   : "{\"runtime\":\"incomplete\",\"why\":[\"no_record_before\",\"holders_unknown_after\"],"
                                     "\"text\":\"runtime incomplete: no runtime record before; holders not read after\"}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, ",\"runtime\":1}\n") != NULL);
    /* port 22 closed, 80 opened: the receipt prints the records' texts */
    sh("cd '%s/proc' && printf '  sl  local_address rem_address   st\\n   0: 00000000:0050 00000000:0000 0A 0:0 0:0 0 0 0 9000 1\\n' > net/tcp",
       g_tree);
    REQUIRE_MSG(belay("diff", "--system-root", g_tree, "--since", "2", NULL) == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "\nruntime\n") != NULL);
    ASSERT_TRUE(strstr(g_out, root ? "  closed: tcp 0.0.0.0:22 held by systemd\n" : "  closed: tcp 0.0.0.0:22\n") != NULL);
    ASSERT_TRUE(strstr(g_out, root ? "  opened: tcp 0.0.0.0:80 (no process holds it)\n" : "  opened: tcp 0.0.0.0:80\n") != NULL);
    if (!root) ASSERT_TRUE(strstr(g_out, "  runtime incomplete: holders not read before; holders not read after\n") != NULL);
    /* a record that is not the one recorded is corrupt state, said */
    sh("printf 'x' >> '%s'", rt);
    ASSERT_TRUE(belay("diff", "--system-root", g_tree, "--since", "1", "--to", "2", "--json", NULL) != 0);
    ASSERT_TRUE(strstr(g_err, "runtime.ndjson") != NULL);
    /* and it goes with its checkpoint */
    REQUIRE_MSG(belay("prune", "--scope", g_tree, "--keep-last", "1", NULL) == 0, "%s", g_err);
    ASSERT_EQ_INT(-1, access(rt, F_OK));
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

static int count_checkpoints(void) {
    char cmd[700];
    snprintf(cmd, sizeof cmd, "exit $(find '%s' -path '*/checkpoints/*' -prune -type d | wc -l)", g_state);
    const int r = system(cmd);
    return WIFEXITED(r) ? WEXITSTATUS(r) : -1;
}
static int state_holds(const char *text) {
    char cmd[700];
    snprintf(cmd, sizeof cmd, "grep -rl '%s' '%s' >/dev/null 2>&1", text, g_state);
    return system(cmd) == 0;
}

/* "System" is the scope's state's, not one command line's: once a scope has
 * a checkpoint with roots, a capture without the flag is refused -- it would
 * read the whole scope and keep in the store what the system captures
 * sealed. And the reverse: a scope captured whole does not become a system
 * watch in silence. */
TEST(a_system_scope_is_captured_only_with_the_flag) {
    fresh();
    REQUIRE(belay("check", "--system-root", g_tree, NULL) == 0);
    REQUIRE(belay("mark", "--system-root", g_tree, NULL) == 0);
    ASSERT_TRUE(!state_holds("ROOTNOTESECRET") && !state_holds("SHADOWSECRET"));
    static const char *const CMD[] = { "check", "mark", "diff" };
    for (int i = 0; i < 3; i++) {
        const int rc = i == 2 ? belay("diff", "--scope", g_tree, "--since", "1", NULL) : belay(CMD[i], "--scope", g_tree, NULL);
        if (rc != 3) BELAY_FAIL("%s --scope on a system scope: exit %d, want 3", CMD[i], rc);
        if (strstr(g_err, "a system watch's") == NULL || strstr(g_err, "--system") == NULL)
            BELAY_FAIL("%s: %s", CMD[i], g_err);
        ASSERT_EQ_STR("", g_out);
    }
    ASSERT_EQ_INT(2, count_checkpoints());
    ASSERT_TRUE(!state_holds("ROOTNOTESECRET") && !state_holds("SHADOWSECRET"));
    /* what reads the state and captures nothing still works without it */
    ASSERT_EQ_INT(0, belay("log", "--scope", g_tree, NULL));
    ASSERT_EQ_INT(0, belay("diff", "--scope", g_tree, "--since", "1", "--to", "2", NULL));
    /* the reverse */
    sh("rm -rf '%s' && mkdir '%s' && chmod 700 '%s'", g_state, g_state, g_state);
    REQUIRE(belay("check", "--scope", g_tree, NULL) == 0);
    for (int i = 0; i < 3; i++) {
        const int rc = i == 2 ? belay("diff", "--system-root", g_tree, "--since", "1", NULL) : belay(CMD[i], "--system-root", g_tree, NULL);
        if (rc != 3) BELAY_FAIL("%s --system-root on a whole scope: exit %d, want 3", CMD[i], rc);
        if (strstr(g_err, "not a system watch's") == NULL) BELAY_FAIL("%s: %s", CMD[i], g_err);
    }
    ASSERT_EQ_INT(1, count_checkpoints());
    char cmd[700];
    snprintf(cmd, sizeof cmd, "[ -z \"$(find '%s' -name sealing.key)\" ]", g_state);
    ASSERT_EQ_INT(0, system(cmd));
}

/* WS-1: `--scope /` without --system is refused for check, mark and diff.
 * The refusing function is called here, never the commands: were it to
 * regress, a command on `/` would walk the machine. */
TEST(the_root_directory_is_refused_without_the_flag) {
    free(g_out);
    free(g_err);                        /* the last command's */
    g_out = g_err = NULL;
    size_t en = 0;
    FILE *err = open_memstream(&g_err, &en);
    ASSERT_EQ_INT(3, cli_refuse_root("/", false, NULL, err));
    fclose(err);
    ASSERT_TRUE(strstr(g_err, "--system") != NULL && strstr(g_err, "refused") != NULL);
    free(g_err);
    g_err = NULL;
    err = open_memstream(&g_err, &en);
    ASSERT_EQ_INT(0, cli_refuse_root("/", true, NULL, err));            /* with the flag: the system scope */
    ASSERT_EQ_INT(0, cli_refuse_root("/", false, "container", err));    /* a container's own / (host-reader.md) */
    ASSERT_EQ_INT(0, cli_refuse_root("/srv", false, NULL, err));
    ASSERT_EQ_INT(0, cli_refuse_root(g_tree, false, NULL, err));
    fclose(err);
    ASSERT_EQ_STR("", g_err);
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
    sh("rm -rf '%s' && mkdir '%s' && chmod 700 '%s'", g_state, g_state, g_state);
    /* the same scope once its latest manifest has roots: refused without the flag too */
    REQUIRE(belay("check", "--system-root", g_tree, NULL) == 0);
    ASSERT_EQ_INT(3, belay("baseline", "export", "--scope", g_tree, "--out", out, NULL));
    ASSERT_TRUE(strstr(g_err, "not designed for a system watch") != NULL);
    ASSERT_TRUE(access(out, F_OK) != 0);
    ASSERT_EQ_INT(3, belay("verify", "--scope", g_tree, "--baseline", out, "--baseline-sha256", SHA64, NULL));
    ASSERT_TRUE(strstr(g_err, "not designed for a system watch") != NULL);
    ASSERT_EQ_INT(3, belay("verify", "--scope", g_tree, "--baseline", out, "--baseline-sha256", SHA64, "--to", "1", NULL));
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
    sh("rm -rf '%s'; mkdir -p '%s/store' && chmod 700 '%s' '%s/store'", work, work, work, work);
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
    if (belay_err_code() != BELAY_ERR_CORRUPT) BELAY_FAIL("refused for another reason: %s", belay_err_msg());
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, (int)belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "roots") != NULL);
    bundle_free(&bd);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_sys_%d_%ld", (int)getpid(), (long)time(NULL));
    snprintf(g_tree, sizeof g_tree, "%s/tree", g_dir);
    snprintf(g_state, sizeof g_state, "%s/state", g_dir);
    /* The trees are made by the shell: which files others can read decides
     * what is sealed, and a store must not be group-writable. Neither may
     * depend on the umask the suite was started with (002 for a user with a
     * private group, as in CI's docker job; 077 elsewhere). */
    umask(022);
    mkdir(g_dir, 0700);
    setenv("BELAY_STATE_DIR", g_state, 1);
    RUN(check_captures_the_roots);
    RUN(mark_diff_and_log_take_it);
    RUN(a_checkpoint_keeps_the_digests_of_shadow_lines);
    RUN(no_digest_file_where_shadow_is_not_read);
    RUN(a_checkpoint_keeps_the_runtime_record_of_its_proc);
    RUN(usage);
    RUN(a_system_scope_is_captured_only_with_the_flag);
    RUN(the_root_directory_is_refused_without_the_flag);
    RUN(baseline_verify_and_protect_are_refused);
    RUN(a_bundle_whose_manifest_has_roots_is_rejected);
    sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    free(g_out);
    free(g_err);
    return belay_test_report();
}
