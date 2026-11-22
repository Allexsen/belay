/*
 *  The runtime record (test/expect/runtime-v1.md): read from a tree shaped
 *  like /proc, never the machine's own. The fixture's lines are the
 *  kernel's formats, its values those measured on Ubuntu 24.04 (an nginx on
 *  80, systemd holding 22, systemd-resolved on 53), with the sockets the
 *  pin's rows turn on added: a WireGuard-like 51820 no process holds, a
 *  socat on 40000 in the client port range, a connected client of each
 *  protocol, an abstract and an unconnected unix socket.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "belay/error.h"
#include "belay/runtime.h"
#include "belay/diff.h"
#include "cli/cli.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char g_dir[256], g_proc[400], g_out[400], g_tree[400];

static void sh(const char *fmt, ...) {
    char cmd[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    if (system(cmd) != 0) { /* the assertions say */ }
}

/* `content` at proc/<rel>, its directories made. */
static void put(const char *rel, const char *content) {
    char p[800];
    snprintf(p, sizeof p, "%s/%s", g_proc, rel);
    char *slash = strrchr(p, '/');
    *slash = '\0';
    sh("mkdir -p '%s'", p);
    *slash = '/';
    FILE *f = fopen(p, "w");
    if (f == NULL) return;
    fputs(content, f);
    fclose(f);
}

static void lnk(const char *target, const char *rel) {
    char p[800];
    snprintf(p, sizeof p, "%s/%s", g_proc, rel);
    char *slash = strrchr(p, '/');
    *slash = '\0';
    sh("mkdir -p '%s'", p);
    *slash = '/';
    if (symlink(target, p) != 0) { /* the assertions say */ }
}

/* A process: its cgroup file (v1 lines before the v2 one, as on a hybrid
 * system), stat with `start` in field 22, exe (none for NULL) and the
 * socket inodes it has descriptors of. */
static void process(int pid, const char *comm, const char *exe, const char *cgroup, unsigned start, const char *inodes) {
    char rel[80], body[600];
    snprintf(rel, sizeof rel, "%d/cgroup", pid);
    snprintf(body, sizeof body, "1:name=systemd:%s\n0::%s\n", cgroup, cgroup);
    put(rel, body);
    snprintf(rel, sizeof rel, "%d/stat", pid);
    snprintf(body, sizeof body, "%d (%s) S 1 %d %d 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 %u 1000 100 18446744073709551615\n",
             pid, comm, pid, pid, start);
    put(rel, body);
    snprintf(rel, sizeof rel, "%d/exe", pid);
    if (exe != NULL) lnk(exe, rel);
    snprintf(rel, sizeof rel, "%d/fd/0", pid);
    lnk("/dev/null", rel);
    int fd = 3;
    char list[200];
    snprintf(list, sizeof list, "%s", inodes);
    for (char *t = strtok(list, " "); t != NULL; t = strtok(NULL, " ")) {
        char target[64];
        snprintf(rel, sizeof rel, "%d/fd/%d", pid, fd++);
        snprintf(target, sizeof target, "socket:[%s]", t);
        lnk(target, rel);
    }
}

#define TCP_HEAD "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
#define UDP_HEAD "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
#define TAIL4 " 00000000:00000000 00:00000000 00000000     0        0 "

static void machine(void) {
    sh("rm -rf '%s' && mkdir -p '%s'", g_proc, g_proc);
    put("sys/net/ipv4/ip_local_port_range", "32768\t60999\n");
    lnk("net:[4026531840]", "self/ns/net");
    put("net/tcp", TCP_HEAD
        "   0: 3500007F:0035 00000000:0000 0A" TAIL4 "22790 1 0000000000000000 100 0 0 10 5\n"
        "   1: 00000000:0016 00000000:0000 0A" TAIL4 "8760 1 0000000000000000 100 0 0 10 0\n"
        "   2: 00000000:0050 00000000:0000 0A" TAIL4 "26691 1 0000000000000000 100 0 0 10 0\n"
        "   3: F88F000A:0016 0100000A:D2F0 01" TAIL4 "31000 4 0000000000000000 20 4 30 10 -1\n");
    put("net/tcp6", TCP_HEAD
        "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A" TAIL4 "8762 1 0000000000000000 100 0 0 10 0\n"
        "   1: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A" TAIL4 "26692 1 0000000000000000 100 0 0 10 0\n");
    put("net/udp", UDP_HEAD
        "  765: 3500007F:0035 00000000:0000 07" TAIL4 "22789 2 0000000000000000 0\n"
        " 1000: 00000000:CA6C 00000000:0000 07" TAIL4 "40100 2 0000000000000000 0\n"
        " 1001: 00000000:9C40 00000000:0000 07" TAIL4 "40200 2 0000000000000000 0\n"
        " 1002: F88F000A:8271 0101A8C0:0035 01" TAIL4 "40300 2 0000000000000000 0\n");
    put("net/udp6", UDP_HEAD
        "  323: 00000000000000000000000001000000:0143 00000000000000000000000000000000:0000 07" TAIL4 "22196 2 0000000000000000 0\n");
    put("net/unix", "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "0000000000000000: 00000002 00000000 00010000 0001 01 21567 /run/systemd/private\n"
        "0000000000000000: 00000002 00000000 00010000 0005 01 21600 /run/udev/control\n"
        "0000000000000000: 00000002 00000000 00010000 0001 01 21700 @/org/freedesktop/systemd1/notify\n"
        "0000000000000000: 00000003 00000000 00000000 0001 03 21800 /run/systemd/journal/stdout\n"
        "0000000000000000: 00000002 00000000 00010000 0001 01 21900 /run/a socket with spaces\n"
        "0000000000000000: 00000002 00000000 00010000 0001 01 21950\n");
    process(1, "systemd", "/usr/lib/systemd/systemd", "/init.scope", 2, "8760 8762 21567 21800");
    process(3466, "systemd-resolve", "/usr/lib/systemd/systemd-resolved", "/system.slice/systemd-resolved.service", 900,
            "22790 22789");
    process(3431, "(chr) d)", "/usr/sbin/chronyd", "/system.slice/chrony.service", 880, "22196");
    process(4148, "nginx", "/usr/sbin/nginx", "/system.slice/nginx.service", 98832, "26691 26692");
    process(4150, "nginx", "/usr/sbin/nginx", "/system.slice/nginx.service", 98900, "26691 26692");
    process(5000, "socat", "/usr/bin/socat", "/user.slice/user-1000.slice/session-3.scope", 99500, "40200");
    process(6000, "dbus-daemon", NULL, "/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service", 99000, "");
    process(7000, "old", "/usr/sbin/old (deleted)", "/system.slice/old.service", 1000, "");
}

static char *slurp(const char *p) {
    FILE *f = fopen(p, "r");
    if (f == NULL) return NULL;
    static char buf[65536];
    const size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

static int capture(int root, struct belay_runtime_stats *st) {
    const struct belay_runtime_opts o = { .proc_root = g_proc, .root = root };
    return belay_runtime_capture(&o, g_out, st);
}

#define NGINX "{\"exe\":\"/usr/sbin/nginx\",\"cgroup\":\"/system.slice/nginx.service\"}"
#define SYSTEMD "{\"exe\":\"/usr/lib/systemd/systemd\",\"cgroup\":\"/init.scope\"}"
#define RESOLVED "{\"exe\":\"/usr/lib/systemd/systemd-resolved\",\"cgroup\":\"/system.slice/systemd-resolved.service\"}"

/* RT-1 to RT-8, RT-10, RT-11: as root, every line in its order. */
TEST(as_root_the_record_lists_listeners_their_holders_and_services) {
    machine();
    struct belay_runtime_stats st;
    REQUIRE_MSG(capture(1, &st) == 1, "%s", belay_err_msg());
    ASSERT_EQ_STR(
        "{\"belay_runtime\":1,\"netns\":4026531840,\"root\":true,\"source\":null}\n"
        "{\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":22,\"holders\":[" SYSTEMD "]}\n"
        "{\"listener\":\"tcp\",\"proto\":6,\"addr\":\"::\",\"port\":22,\"holders\":[" SYSTEMD "]}\n"
        "{\"listener\":\"tcp\",\"proto\":4,\"addr\":\"127.0.0.53\",\"port\":53,\"holders\":[" RESOLVED "]}\n"
        "{\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":80,\"holders\":[" NGINX "]}\n"
        "{\"listener\":\"tcp\",\"proto\":6,\"addr\":\"::\",\"port\":80,\"holders\":[" NGINX "]}\n"
        "{\"listener\":\"udp\",\"proto\":4,\"addr\":\"127.0.0.53\",\"port\":53,\"holders\":[" RESOLVED "]}\n"
        "{\"listener\":\"udp\",\"proto\":6,\"addr\":\"::1\",\"port\":323,\"holders\":[{\"exe\":\"/usr/sbin/chronyd\","
        "\"cgroup\":\"/system.slice/chrony.service\"}]}\n"
        "{\"listener\":\"udp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":40000,\"client_range\":true,\"holders\":"
        "[{\"exe\":\"/usr/bin/socat\",\"cgroup\":\"/user.slice/user-1000.slice/session-3.scope\"}]}\n"
        "{\"listener\":\"udp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":51820,\"client_range\":true,\"holders\":[]}\n"
        "{\"listener\":\"unix\",\"proto\":null,\"addr\":\"/run/a socket with spaces\",\"port\":null,\"holders\":[]}\n"
        "{\"listener\":\"unix\",\"proto\":null,\"addr\":\"/run/systemd/private\",\"port\":null,\"holders\":[" SYSTEMD "]}\n"
        "{\"listener\":\"unix\",\"proto\":null,\"addr\":\"/run/udev/control\",\"port\":null,\"holders\":[]}\n"
        "{\"service\":\"/system.slice/chrony.service\",\"processes\":1,\"exe\":\"/usr/sbin/chronyd\",\"started_ns\":8800000000}\n"
        "{\"service\":\"/system.slice/nginx.service\",\"processes\":2,\"exe\":\"/usr/sbin/nginx\",\"started_ns\":988320000000}\n"
        "{\"service\":\"/system.slice/old.service\",\"processes\":1,\"exe\":\"/usr/sbin/old (deleted)\",\"started_ns\":10000000000}\n"
        "{\"service\":\"/system.slice/systemd-resolved.service\",\"processes\":1,\"exe\":\"/usr/lib/systemd/systemd-resolved\","
        "\"started_ns\":9000000000}\n"
        "{\"service\":\"/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service\",\"processes\":1,\"exe\":null,"
        "\"started_ns\":990000000000}\n"
        "{\"listeners\":12,\"services\":5,\"holders_unknown\":0}\n",
        slurp(g_out));
    ASSERT_EQ_INT(12, (int)st.listeners);
    ASSERT_EQ_INT(5, (int)st.services);
    ASSERT_EQ_INT(0, (int)st.holders_unknown);
    ASSERT_EQ_INT(64, (int)strlen(st.sha256));
    struct stat sb;
    REQUIRE(stat(g_out, &sb) == 0);
    ASSERT_EQ_INT(0600, (int)(sb.st_mode & 07777));
    char sha[80] = "";
    FILE *p = popen("(sha256sum 2>/dev/null || shasum -a 256) < \"$BELAY_RT_OUT\" | cut -c1-64", "r");
    if (p != NULL && fgets(sha, sizeof sha, p) != NULL) sha[strcspn(sha, "\n")] = '\0';
    if (p != NULL) pclose(p);
    ASSERT_EQ_STR(sha, st.sha256);
}

/* RT-9: not root, no holders are read -- each listener's are null and
 * counted -- and the ports themselves are. */
TEST(not_root_the_holders_are_null_and_counted) {
    machine();
    struct belay_runtime_stats st;
    REQUIRE_MSG(capture(0, &st) == 1, "%s", belay_err_msg());
    const char *r = slurp(g_out);
    ASSERT_TRUE(strncmp(r, "{\"belay_runtime\":1,\"netns\":4026531840,\"root\":false,\"source\":null}\n", 66) == 0);
    ASSERT_TRUE(strstr(r, "{\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":80,\"holders\":null}\n") != NULL);
    ASSERT_TRUE(strstr(r, "\"holders\":[") == NULL);
    ASSERT_TRUE(strstr(r, "{\"service\":\"/system.slice/nginx.service\",\"processes\":2,") != NULL);
    ASSERT_TRUE(strstr(r, "{\"listeners\":12,\"services\":5,\"holders_unknown\":12}\n") != NULL);
    ASSERT_EQ_INT(12, (int)st.holders_unknown);
    /* as root, a process there whose descriptors cannot be read makes every holder unknown */
    char fd[600];
    snprintf(fd, sizeof fd, "%s/4148/fd", g_proc);
    if (geteuid() != 0) {
        chmod(fd, 0);
        REQUIRE(capture(1, &st) == 1);
        chmod(fd, 0755);
        ASSERT_EQ_INT(12, (int)st.holders_unknown);
        ASSERT_TRUE(strstr(slurp(g_out), "\"holders\":[") == NULL);
    }
}

/* No proc file system (macOS; a root without one): nothing is written. A
 * tree whose lines are not the kernel's is an error and writes nothing. */
TEST(no_proc_writes_nothing_and_a_broken_line_is_an_error) {
    machine();
    unlink(g_out);
    sh("rm -rf '%s/net'", g_proc);
    struct belay_runtime_stats st;
    ASSERT_EQ_INT(0, capture(1, &st));
    ASSERT_EQ_INT(-1, access(g_out, F_OK));
    static const char *const BAD[] = {
        TCP_HEAD "   0: 3500007F:035 00000000:0000 0A" TAIL4 "22790 1\n",               /* a port of 3 digits */
        TCP_HEAD "   0: 3500007F00:0035 00000000:0000 0A" TAIL4 "22790 1\n",            /* an address of 10 */
        TCP_HEAD "   0: 3500007G:0035 00000000:0000 0A" TAIL4 "22790 1\n",              /* not hex */
        TCP_HEAD "   0: 3500007F:0035 00000000:0000 0A 00000000:00000000\n",            /* cut short */
        TCP_HEAD "   0: 3500007F:0035 00000000:0000 0A" TAIL4 "99999999999999999999999 1\n",  /* an inode past 64 bits */
    };
    for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        machine();
        put("net/tcp", BAD[i]);
        unlink(g_out);
        ASSERT_EQ_INT(-1, capture(1, &st));
        ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
        ASSERT_EQ_INT(-1, access(g_out, F_OK));
    }
    /* a line longer than any the kernel writes: tcp's is an error, unix's no listener */
    static char longl[9000];
    memset(longl, 'a', sizeof longl - 1);
    char *body = malloc(sizeof longl + 400);
    REQUIRE(body != NULL);
    machine();
    snprintf(body, sizeof longl + 400, TCP_HEAD "   0: 3500007F:0035 00000000:0000 0A" TAIL4 "22790 %s\n", longl);
    put("net/tcp", body);
    ASSERT_EQ_INT(-1, capture(1, &st));
    machine();
    snprintf(body, sizeof longl + 400, "Num       RefCount Protocol Flags    Type St Inode Path\n"
             "0000000000000000: 00000002 00000000 00010000 0001 01 21567 /run/%s\n"
             "0000000000000000: 00000002 00000000 00010000 0001 01 21600 /run/ok\n", longl);
    put("net/unix", body);
    free(body);
    REQUIRE(capture(1, &st) == 1);
    ASSERT_TRUE(strstr(slurp(g_out), "\"addr\":\"/run/ok\"") != NULL);
    ASSERT_TRUE(strstr(slurp(g_out), "aaaa") == NULL);
    /* the port range is read; without it nothing is guessed */
    machine();
    put("sys/net/ipv4/ip_local_port_range", "60999 32768\n");
    ASSERT_EQ_INT(-1, capture(1, &st));
}

/* RT-11: what readlink gives, as read -- one that is not UTF-8 in base64,
 * as a manifest's path_b64. RT-12's parameter: another process's net/. */
TEST(an_exe_as_read_and_another_process_net) {
    machine();
    process(8000, "x", "/opt/\xff", "/system.slice/bin.service", 5, "");
    char e[600];
    snprintf(e, sizeof e, "%s/8000/exe", g_proc);
    char got[64];
    const ssize_t n = readlink(e, got, sizeof got);
    if (n != 6) SKIP("this file system keeps no link target that is not UTF-8");
    struct belay_runtime_stats st;
    REQUIRE(capture(1, &st) == 1);
    ASSERT_TRUE(strstr(slurp(g_out), "{\"service\":\"/system.slice/bin.service\",\"processes\":1,\"exe_b64\":\"L29wdC//\","
                                     "\"started_ns\":50000000}\n") != NULL);
    /* the net/ of pid 4148, in its own namespace */
    put("4148/net/tcp", TCP_HEAD "   0: 00000000:1F90 00000000:0000 0A" TAIL4 "26691 1\n");
    put("4148/net/unix", "Num       RefCount Protocol Flags    Type St Inode Path\n");
    lnk("net:[4026532300]", "4148/ns/net");
    const struct belay_runtime_opts o = { .proc_root = g_proc, .root = 1, .net_pid = 4148,
                                          .source_json = "{\"docker\":\"x\"}" };
    REQUIRE(belay_runtime_capture(&o, g_out, &st) == 1);
    char *r = slurp(g_out), *svc = strstr(r, "{\"service\"");
    if (svc != NULL) *svc = '\0';
    ASSERT_EQ_STR("{\"belay_runtime\":1,\"netns\":4026532300,\"root\":true,\"source\":{\"docker\":\"x\"}}\n"
                  "{\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":8080,\"holders\":[" NGINX "]}\n", r);
}

/* ---- the diff's runtime section (RT-D1 to RT-D5) ---- */

static char g_text[200000];

static int belay(const char *a0, ...) {
    char *argv[16] = { "belay", (char *)a0 };
    int argc = 2;
    va_list ap;
    va_start(ap, a0);
    const char *a;
    while (argc < 15 && (a = va_arg(ap, const char *)) != NULL) argv[argc++] = (char *)a;
    va_end(ap);
    FILE *out = fopen("/dev/null", "w"), *err = fopen("/dev/null", "w");
    const int rc = cli_main(argc, argv, out, err);
    fclose(out);
    fclose(err);
    return rc;
}

static const char *find1(const char *what) {
    static char line[800];
    char cmd[1200];
    snprintf(cmd, sizeof cmd, "find '%s/state' %s | sort | head -1", g_dir, what);
    line[0] = '\0';
    FILE *f = popen(cmd, "r");
    if (f != NULL && fgets(line, sizeof line, f) != NULL) line[strcspn(line, "\n")] = '\0';
    if (f != NULL) pclose(f);
    return line;
}

/* Two checkpoints of a machine in small whose unit files are
 * usr/lib/systemd/system/ssh.socket and etc/systemd/system/foo.socket; the
 * diff of their manifests is given the runtime records at `before` and
 * `after`. 0 with the diff in g_text, or -1. */
static int diff_of(const char *before, const char *after) {
    static char m1[800], m2[800], store[800];
    if (m1[0] == '\0') {
        sh("rm -rf '%s' '%s/state' && mkdir -p '%s/usr/lib/systemd/system' '%s/etc/systemd/system' '%s/etc/systemd/system/sockets.target.wants' "
           "&& chmod 700 '%s'", g_tree, g_dir, g_tree, g_tree, g_tree, g_dir);
        sh("cd '%s' && printf 'root:x:0:0:root:/root:/bin/sh\\n' > etc/passwd && "
           "printf '[Socket]\\nListenStream=22\\n# ListenStream=2222\\nListenStream=12222\\nAccept=no\\n' > usr/lib/systemd/system/ssh.socket && "
           "printf '[Socket]\\n  ListenStream = 0.0.0.0:2222  \\nListenStream=/run/foo.sock\\nListenDatagram=41000\\n' > etc/systemd/system/foo.socket && "
           "ln -s /usr/lib/systemd/system/ssh.socket etc/systemd/system/sockets.target.wants/ssh.socket", g_tree);
        if (belay("check", "--system-root", g_tree, NULL) != 0 || belay("check", "--system-root", g_tree, NULL) != 0) return -1;
        snprintf(m1, sizeof m1, "%s", find1("-path '*/checkpoints/1/manifest.ndjson'"));
        snprintf(m2, sizeof m2, "%s", find1("-path '*/checkpoints/2/manifest.ndjson'"));
        snprintf(store, sizeof store, "%s", find1("-type d -name store"));
    }
    char out[600];
    snprintf(out, sizeof out, "%s/diff.ndjson", g_dir);
    const struct belay_diff_opts o = { .store_dir = store, .runtime_before = before, .runtime_after = after };
    struct belay_diff_stats st;
    if (belay_diff(m1, m2, out, &o, &st) == -1) return -1;
    FILE *f = fopen(out, "r");
    const size_t n = f != NULL ? fread(g_text, 1, sizeof g_text - 1, f) : 0;
    if (f != NULL) fclose(f);
    g_text[n] = '\0';
    return (int)st.runtime;
}

/* The section: the lines starting `{"runtime"`, in order. */
static const char *section(void) {
    static char sec[100000];
    size_t w = 0;
    for (const char *p = g_text; *p;) {
        const char *nl = strchr(p, '\n');
        const size_t n = nl != NULL ? (size_t)(nl - p) + 1 : strlen(p);
        if (strncmp(p, "{\"runtime\"", 10) == 0 && w + n < sizeof sec) {
            memcpy(sec + w, p, n);
            w += n;
        }
        p += n;
    }
    sec[w] = '\0';
    return sec;
}

/* The machine later: nginx stopped, socat gone and nc on 41000, resolved
 * restarted, sshd started, and systemd listening on 2222 and
 * /run/foo.sock (foo.socket). */
static void later(void) {
    put("net/tcp", TCP_HEAD
        "   0: 3500007F:0035 00000000:0000 0A" TAIL4 "22790 1 0000000000000000 100 0 0 10 5\n"
        "   1: 00000000:0016 00000000:0000 0A" TAIL4 "8760 1 0000000000000000 100 0 0 10 0\n"
        "   2: 00000000:08AE 00000000:0000 0A" TAIL4 "8800 1 0000000000000000 100 0 0 10 0\n");
    put("net/tcp6", TCP_HEAD
        "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A" TAIL4 "8762 1 0000000000000000 100 0 0 10 0\n");
    put("net/udp", UDP_HEAD
        "  765: 3500007F:0035 00000000:0000 07" TAIL4 "22789 2 0000000000000000 0\n"
        " 1000: 00000000:CA6C 00000000:0000 07" TAIL4 "40100 2 0000000000000000 0\n"
        " 1001: 00000000:A028 00000000:0000 07" TAIL4 "40400 2 0000000000000000 0\n");
    put("net/unix", "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "0000000000000000: 00000002 00000000 00010000 0001 01 21567 /run/systemd/private\n"
        "0000000000000000: 00000002 00000000 00010000 0005 01 21600 /run/udev/control\n"
        "0000000000000000: 00000002 00000000 00010000 0001 01 21900 /run/a socket with spaces\n"
        "0000000000000000: 00000002 00000000 00010000 0001 01 21990 /run/foo.sock\n");
    sh("rm -rf '%s/4148' '%s/4150' '%s/5000' '%s/3466' '%s/1'", g_proc, g_proc, g_proc, g_proc, g_proc);
    process(1, "systemd", "/usr/lib/systemd/systemd", "/init.scope", 2, "8760 8762 21567 8800 21990");
    process(3466, "systemd-resolve", "/usr/lib/systemd/systemd-resolved", "/system.slice/systemd-resolved.service", 120000,
            "22790 22789");
    process(5100, "nc", "/usr/bin/nc.openbsd", "/user.slice/user-1000.slice/session-3.scope", 120100, "40400");
    process(9000, "sshd", "/usr/sbin/sshd", "/system.slice/ssh.service", 120200, "");
}

/* RT-D1 to RT-D4: the records, their order, their texts; a systemd
 * listener's .socket units; the trailer's count. */
TEST(the_section_names_what_opened_closed_started_stopped_and_restarted) {
    char a[600], b[600];
    snprintf(a, sizeof a, "%s/a.ndjson", g_dir);
    snprintf(b, sizeof b, "%s/b.ndjson", g_dir);
    struct belay_runtime_stats st;
    machine();
    struct belay_runtime_opts o = { .proc_root = g_proc, .root = 1 };
    REQUIRE(belay_runtime_capture(&o, a, &st) == 1);
    later();
    REQUIRE(belay_runtime_capture(&o, b, &st) == 1);
    const int n = diff_of(a, b);
    REQUIRE_MSG(n == 9, "%d %s", n, belay_err_msg());
    ASSERT_EQ_STR(
        "{\"runtime\":\"listener_closed\",\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":80,\"holders\":[" NGINX "],"
        "\"text\":\"closed: tcp 0.0.0.0:80 held by nginx.service\"}\n"
        "{\"runtime\":\"listener_closed\",\"listener\":\"tcp\",\"proto\":6,\"addr\":\"::\",\"port\":80,\"holders\":[" NGINX "],"
        "\"text\":\"closed: tcp [::]:80 held by nginx.service\"}\n"
        "{\"runtime\":\"listener_opened\",\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":2222,\"holders\":[" SYSTEMD "],"
        "\"matches\":[\"foo.socket\"],\"text\":\"opened: tcp 0.0.0.0:2222 held by systemd\"}\n"
        "{\"runtime\":\"listener_closed\",\"listener\":\"udp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":40000,\"client_range\":true,"
        "\"holders\":[{\"exe\":\"/usr/bin/socat\",\"cgroup\":\"/user.slice/user-1000.slice/session-3.scope\"}],"
        "\"text\":\"closed: udp 0.0.0.0:40000 held by socat\"}\n"
        "{\"runtime\":\"listener_opened\",\"listener\":\"udp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":41000,\"client_range\":true,"
        "\"holders\":[{\"exe\":\"/usr/bin/nc.openbsd\",\"cgroup\":\"/user.slice/user-1000.slice/session-3.scope\"}],"
        "\"text\":\"opened: udp 0.0.0.0:41000 held by nc.openbsd\"}\n"
        "{\"runtime\":\"listener_opened\",\"listener\":\"unix\",\"proto\":null,\"addr\":\"/run/foo.sock\",\"port\":null,\"holders\":[" SYSTEMD "],"
        "\"matches\":[\"foo.socket\"],\"text\":\"opened: unix /run/foo.sock held by systemd\"}\n"
        "{\"runtime\":\"service_stopped\",\"service\":\"/system.slice/nginx.service\",\"processes\":2,\"exe\":\"/usr/sbin/nginx\","
        "\"text\":\"stopped: nginx.service\"}\n"
        "{\"runtime\":\"service_started\",\"service\":\"/system.slice/ssh.service\",\"processes\":1,\"exe\":\"/usr/sbin/sshd\","
        "\"text\":\"started: ssh.service\"}\n"
        "{\"runtime\":\"service_restarted\",\"service\":\"/system.slice/systemd-resolved.service\",\"processes\":1,"
        "\"exe\":\"/usr/lib/systemd/systemd-resolved\",\"text\":\"restarted: systemd-resolved.service\"}\n",
        section());
    /* after the events, before the trailer, which counts them last */
    const char *first = strstr(g_text, "{\"runtime\"");
    ASSERT_TRUE(first != NULL && strstr(first, "{\"event\"") == NULL && strstr(first, "{\"path\"") == NULL);
    ASSERT_TRUE(strstr(g_text, ",\"runtime\":9}\n") != NULL);
    /* systemd's port 22 held on both sides: nothing; a listener held by
     * systemd and another names both and is matched to no unit */
    process(9000, "sshd", "/usr/sbin/sshd", "/system.slice/ssh.service", 120200, "8800");
    REQUIRE(belay_runtime_capture(&o, b, &st) == 1);
    REQUIRE(diff_of(a, b) == 9);
    ASSERT_TRUE(strstr(section(), "\"port\":2222,\"holders\":[" SYSTEMD ",{\"exe\":\"/usr/sbin/sshd\",\"cgroup\":"
                                  "\"/system.slice/ssh.service\"}],\"text\":\"opened: tcp 0.0.0.0:2222 held by ssh.service, systemd\"}\n") != NULL);
    /* the same record twice: no section records */
    ASSERT_EQ_INT(0, diff_of(a, a));
    ASSERT_EQ_STR("", section());
    ASSERT_TRUE(strstr(g_text, ",\"runtime\":0}\n") != NULL);
}

/* RT-D5: a side without a record, or with holders not read: the section's
 * first record says so; without a record nothing is compared. RT-D1:
 * neither has one, no section. */
TEST(a_side_without_a_record_or_its_holders_is_incomplete) {
    char a[600], b[600];
    snprintf(a, sizeof a, "%s/a.ndjson", g_dir);
    snprintf(b, sizeof b, "%s/b.ndjson", g_dir);
    struct belay_runtime_stats st;
    machine();
    struct belay_runtime_opts o = { .proc_root = g_proc, .root = 1 };
    REQUIRE(belay_runtime_capture(&o, a, &st) == 1);
    REQUIRE(diff_of(NULL, a) == 1);
    ASSERT_EQ_STR("{\"runtime\":\"incomplete\",\"why\":[\"no_record_before\"],\"text\":\"runtime incomplete: no runtime record before\"}\n",
                  section());
    REQUIRE(diff_of(a, NULL) == 1);
    ASSERT_TRUE(strstr(section(), "\"why\":[\"no_record_after\"]") != NULL);
    ASSERT_EQ_INT(0, diff_of(NULL, NULL));
    ASSERT_TRUE(strstr(g_text, "{\"runtime\"") == NULL && strstr(g_text, ",\"runtime\":0}\n") != NULL);
    later();
    o.root = 0;
    REQUIRE(belay_runtime_capture(&o, b, &st) == 1);
    REQUIRE(diff_of(a, b) == 10);
    const char *s = section();
    ASSERT_TRUE(strncmp(s, "{\"runtime\":\"incomplete\",\"why\":[\"holders_unknown_after\"],"
                           "\"text\":\"runtime incomplete: holders not read after\"}\n", 106) == 0);
    ASSERT_TRUE(strstr(s, "{\"runtime\":\"listener_opened\",\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":2222,"
                          "\"holders\":null,\"text\":\"opened: tcp 0.0.0.0:2222\"}\n") != NULL);
    ASSERT_TRUE(strstr(s, "\"matches\"") == NULL);
    /* RT-10: none holds it */
    machine();
    put("net/udp", UDP_HEAD " 1000: 00000000:CA6C 00000000:0000 07" TAIL4 "40100 2 0000000000000000 0\n"
                            " 1003: 00000000:CA6D 00000000:0000 07" TAIL4 "40101 2 0000000000000000 0\n");
    o.root = 1;
    REQUIRE(belay_runtime_capture(&o, b, &st) == 1);
    REQUIRE(diff_of(a, b) > 0);
    ASSERT_TRUE(strstr(section(), ",\"port\":51821,\"client_range\":true,\"holders\":[],"
                                  "\"text\":\"opened: udp 0.0.0.0:51821 (no process holds it)\"}\n") != NULL);
    /* a record that is not one is corrupt input, never a section */
    sh("printf '{\"listener\":\"tcp\"}\\n' >> '%s'", a);
    ASSERT_EQ_INT(-1, diff_of(a, b));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_rt_%d_%ld", (int)getpid(), (long)time(NULL));
    snprintf(g_proc, sizeof g_proc, "%s/proc", g_dir);
    snprintf(g_out, sizeof g_out, "%s/runtime.ndjson", g_dir);
    snprintf(g_tree, sizeof g_tree, "%s/tree", g_dir);
    char state[600];
    snprintf(state, sizeof state, "%s/state", g_dir);
    setenv("BELAY_STATE_DIR", state, 1);
    umask(022);
    mkdir(g_dir, 0700);
    setenv("BELAY_RT_OUT", g_out, 1);
    RUN(as_root_the_record_lists_listeners_their_holders_and_services);
    RUN(not_root_the_holders_are_null_and_counted);
    RUN(no_proc_writes_nothing_and_a_broken_line_is_an_error);
    RUN(an_exe_as_read_and_another_process_net);
    RUN(the_section_names_what_opened_closed_started_stopped_and_restarted);
    RUN(a_side_without_a_record_or_its_holders_is_incomplete);
    sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    return belay_test_report();
}
