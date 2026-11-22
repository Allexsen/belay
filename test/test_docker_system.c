/*
 *  `--system --docker C` (test/expect/watch-system.md WS-1, WS-4, WS-5a,
 *  WS-R3; runtime-v1.md RT-1, RT-12; manifest-v5's roots resolved in the
 *  container's `/`, its homes from its own etc/passwd): a system watch of
 *  a container, read from the host, on check, mark, diff, log, manifest,
 *  prune and watch.
 *
 *  The container is the tests' (docker_test_open, src/cli/docker.h): two
 *  layer directories under the test's own temporary directory, opened as
 *  the host reader's union, and a tree shaped like /proc for its processes.
 *  So `docker inspect`, root and the first process's mount table are not
 *  what is tested here: scripts/host-reader-e2e.sh runs the same commands
 *  against a real container, as root, in CI's docker job.
 *
 *  BLAST RADIUS: no container is started, stopped or read, and no `docker`
 *  program is run (with the seam unset, the one command that would run it
 *  is refused before, not being root). The machine's own `/` is never
 *  captured: every `--system` here names the tests' container. belay's
 *  state is under the test's directory (BELAY_STATE_DIR).
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/error.h"
#include "cli/cli.h"
#include "cli/docker.h"
#include "capture/union.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ID "4f1c0e8a9b7d6c5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e"
#define IMAGE "sha256:91ef0af61f39ece4d6710e465df5ed6ca12112358344fd51ae6a3b886634148b"
#define CG "/system.slice/docker-" ID ".scope"

static char g_dir[256], g_lower[400], g_upper[400], g_proc[400], g_state[400], g_text[200000];
static char *g_out, *g_err;
static void sh(const char *fmt, ...) {
    char cmd[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    if (system(cmd) != 0) { /* the assertions say */ }
}

#ifdef __linux__
static long g_pid = 4242, g_pid_after;        /* g_pid_after: from the third look on (H-C5): resolve, capture, still */
static int g_opens;

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

/* What a shell command prints, into g_text. */
static const char *shout(const char *fmt, ...) {
    char cmd[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    g_text[0] = '\0';
    FILE *p = popen(cmd, "r");
    if (p == NULL) return g_text;
    const size_t n = fread(g_text, 1, sizeof g_text - 1, p);
    g_text[n] = '\0';
    pclose(p);
    return g_text;
}

static size_t count(const char *hay, const char *needle) {
    size_t n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

/* The container: its upper layer over its image's, as docker_open opens a
 * real one's (H-M3), without overlay xattrs (none is needed here). */
static int open_test_container(const char *name, struct docker_info *d, struct union_fs **u) {
    *u = NULL;
    if (strcmp(name, "c") != 0) {
        belay_err_set(BELAY_ERR_INVALID, 0, "--docker %s: docker inspect: No such container", name);
        return -1;
    }
    memset(d, 0, sizeof *d);
    snprintf(d->id, sizeof d->id, "%s", ID);
    snprintf(d->image, sizeof d->image, "%s", IMAGE);
    d->pid = g_pid_after != 0 && ++g_opens >= 3 ? g_pid_after : g_pid;
    int fd[2];
    if ((fd[0] = open(g_upper, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1) return -1;
    if ((fd[1] = open(g_lower, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1) { close(fd[0]); return -1; }
    *u = union_new(fsops_default(), fd, 2, "user.overlay.", NULL, 0);
    return *u == NULL ? -1 : 0;
}

/* A machine in small as the image's layer, an empty upper layer, the
 * container's processes, and an empty state. Its passwd names /srv/app,
 * which no host's does. */
static void fresh(void) {
    sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s/lower' '%s/upper' '%s/proc' '%s'; mkdir -p '%s' '%s' '%s' '%s' && chmod 700 '%s'",
       g_dir, g_dir, g_dir, g_dir, g_state, g_lower, g_upper, g_proc, g_state, g_state);
    sh("cd '%s' && mkdir -p etc usr/bin var/log root home/u srv/app/.ssh proc && "
       "printf 'root:x:0:0:root:/root:/bin/sh\\nu:x:1000:1000::/home/u:/bin/sh\\napp:x:1001:1001::/srv/app:/bin/sh\\n' > etc/passwd && "
       "printf 'root:x:0:\\nsudo:x:27:\\n' > etc/group && "
       "printf 'root:SHADOWSECRET:1::::::\\n' > etc/shadow && chmod 640 etc/shadow && "
       "printf 'tool\\n' > usr/bin/tool && printf 'log\\n' > var/log/syslog && printf 'k\\n' > srv/app/.ssh/authorized_keys && "
       "printf 'export A=1\\n' > home/u/.bashrc && chmod 700 root && chmod 755 . etc usr var home home/u srv srv/app",
       g_lower);
    sh("cd '%s' && mkdir -p sys/net/ipv4 self/ns 1 4242/net 4242/ns 4300/fd && "
       "printf '32768\\t60999\\n' > sys/net/ipv4/ip_local_port_range && ln -s 'net:[4026531840]' self/ns/net && "
       "printf '0::/init.scope\\n' > 1/cgroup && "
       "printf '0::%s\\n' > 4242/cgroup && ln -s 'net:[4026532999]' 4242/ns/net && "
       "printf '0::%s/system.slice/web.service\\n' > 4300/cgroup && ln -s /usr/sbin/nginx 4300/exe && "
       "ln -s 'socket:[555]' 4300/fd/3 && "
       "printf '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\\n"
       "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1\\n' > 4242/net/tcp && "
       "printf 'Num       RefCount Protocol Flags    Type St Inode Path\\n' > 4242/net/unix",
       g_proc, CG, CG);
    g_pid = 4242;
    g_pid_after = 0;
    g_opens = 0;
    docker_test_open = open_test_container;
    docker_proc = g_proc;
    struct timespec ts = { 0, 30 * 1000000L };
    nanosleep(&ts, NULL);
}

/* The runtime record of checkpoint `id`. */
static const char *runtime(int id) {
    return shout("cat \"$(find '%s' -path '*/checkpoints/%d/runtime.ndjson')\"", g_state, id);
}

/* WS-1, manifest-v5: the roots are read in the container's `/`, its homes
 * from its own passwd; sealing as on a machine; the manifest's source and
 * the runtime record's are the container (RT-1, RT-12). */
TEST(check_reads_the_container_s_roots_and_its_runtime) {
    fresh();
    REQUIRE_MSG(belay("check", "--system", "--docker", "c", "--json") == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "{\"id\":1,\"kind\":\"check\",") == g_out);
    ASSERT_TRUE(strstr(g_out, "\"source\":{\"docker\":\"" ID "\",\"image\":\"" IMAGE "\"}") != NULL);
    REQUIRE_MSG(belay("manifest", "--system", "--docker", "c", "--id", "1") == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "\n{\"root\":\"srv/app/.ssh\",\"class\":\"content\",\"found\":true}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\n{\"root\":\"home/u/.bashrc\",\"class\":\"content\",\"found\":true}\n") != NULL);
    ASSERT_EQ_INT(3, (int)count(g_out, "/.ssh\",\"class\""));           /* root's, u's, app's: none of the host's */
    ASSERT_TRUE(strstr(g_out, "\n{\"path\":\"srv/app/.ssh/authorized_keys\",") != NULL);
    ASSERT_TRUE(strstr(g_out, "\n{\"path\":\"etc/shadow\",") != NULL);
    const char *sh_line = strstr(g_out, "\n{\"path\":\"etc/shadow\",");
    ASSERT_TRUE(sh_line != NULL && strstr(sh_line, ",\"sealed\":true}") != NULL &&
                strstr(sh_line, ",\"sealed\":true}") < strchr(sh_line + 1, '\n'));
    ASSERT_TRUE(strstr(g_out, "\n{\"path\":\"var/log\",") != NULL && strstr(g_out, "\"path\":\"var/log/syslog\"") == NULL);
    const char *rt = runtime(1);
    ASSERT_TRUE(strstr(rt, "{\"belay_runtime\":1,\"netns\":4026532999,\"root\":") == rt);
    ASSERT_TRUE(strstr(rt, ",\"source\":{\"docker\":\"" ID "\",\"image\":\"" IMAGE "\"}}\n") != NULL);
    ASSERT_TRUE(strstr(rt, "{\"listener\":\"tcp\",\"proto\":4,\"addr\":\"0.0.0.0\",\"port\":80,") != NULL);
    ASSERT_TRUE(strstr(rt, "{\"service\":\"" CG "/system.slice/web.service\",\"processes\":1,") != NULL);
    ASSERT_TRUE(strstr(rt, "init.scope") == NULL);                      /* the host's processes are not the container's */
    REQUIRE(belay("log", "--system", "--docker", "c") == 0);
    ASSERT_TRUE(strstr(g_out, "1") != NULL);
}

/* RT-12: a container on the host's network has no listener lines, and its
 * record's `netns` says `host`. */
TEST(a_container_on_the_host_network_lists_no_listener) {
    fresh();
    sh("cd '%s' && rm 4242/ns/net && ln -s 'net:[4026531840]' 4242/ns/net", g_proc);
    REQUIRE_MSG(belay("check", "--system", "--docker", "c") == 0, "%s", g_err);
    const char *rt = runtime(1);
    ASSERT_TRUE(strstr(rt, "{\"belay_runtime\":1,\"netns\":\"host\",") == rt);
    ASSERT_TRUE(strstr(rt, "\"listener\"") == NULL && strstr(rt, "\n{\"listeners\":0,\"services\":1,") != NULL);
}

/* WS-1: mark and diff take it; the interpreters run as on a machine. */
TEST(mark_and_diff_say_what_changed_in_the_container) {
    fresh();
    REQUIRE_MSG(belay("check", "--system", "--docker", "c") == 0, "%s", g_err);
    sh("cd '%s' && mkdir etc && cp '%s/etc/passwd' etc/passwd && chmod 644 etc/passwd && "
       "printf 'v:x:1002:1002::/home/v:/bin/sh\\n' >> etc/passwd", g_upper, g_lower);
    REQUIRE_MSG(belay("mark", "--system", "--docker", "c") == 0, "%s", g_err);
    REQUIRE_MSG(belay("diff", "--system", "--docker", "c", "--since", "1", "--to", "2") == 0, "%s", g_err);
    REQUIRE_MSG(strstr(g_out, "user v added") != NULL, "%s", g_out);
    REQUIRE(belay("diff", "--system", "--docker", "c", "--since", "1", "--to", "2", "--json") == 0);
    ASSERT_TRUE(strstr(g_out, "\"etc/passwd\"") != NULL);
    REQUIRE_MSG(belay("prune", "--system", "--docker", "c", "--keep-last", "1", "--dry-run") == 0, "%s", g_err);
}

/* WS-5a: whether the container's `/` is a system watch is its state's. */
TEST(the_container_s_root_by_scope_after_a_system_capture_is_refused) {
    fresh();
    REQUIRE_MSG(belay("check", "--system", "--docker", "c") == 0, "%s", g_err);
    ASSERT_EQ_INT(3, belay("check", "--docker", "c", "--scope", "/"));
    REQUIRE_MSG(strstr(g_err, "--system") != NULL, "%s", g_err);
    ASSERT_EQ_INT(1, (int)count(shout("find '%s' -name runtime.ndjson", g_state), "\n"));
}

/* WS-1, WS-2, WS-R3: the watch of a container; the receipt names it; its
 * kernel record is off, for the reason this version gives. */
TEST(watch_start_step_stop_of_a_container) {
    fresh();
    REQUIRE_MSG(belay("watch", "start", "--system", "--docker", "c") == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(strstr(g_out, "could not read: nothing\n") == g_out);
    REQUIRE_MSG(strstr(g_out, "\nkernel record: off: no recorder for a container in this version: "
                                  "a change put back is not seen\n") != NULL, "%s", g_out);
    sh("cd '%s' && mkdir -p etc && cp '%s/etc/group' etc/group && printf 'docker:x:998:u\\n' >> etc/group", g_upper, g_lower);
    REQUIRE_MSG(belay("watch", "step", "--system", "--docker", "c", "--session", "s1") == 0, "%s%s", g_out, g_err);
    REQUIRE_MSG(strstr(g_out, "etc/group") != NULL || strstr(g_out, "docker") != NULL, "%s", g_out);
    REQUIRE_MSG(belay("watch", "mark", "--system", "--docker", "c", "--session", "s1", "--name", "m") == 0, "%s", g_out);
    REQUIRE_MSG(belay("watch", "summary", "--system", "--docker", "c", "--session", "s1", "--since", "m") == 0, "%s", g_err);
    REQUIRE_MSG(belay("watch", "receipt", "--system", "--docker", "c") == 0, "%s%s", g_out, g_err);
    REQUIRE_MSG(strstr(g_out, "belay receipt  / in the container c (4f1c0e8a9b7d)\n") == g_out, "%s", g_out);
    REQUIRE_MSG(belay("watch", "stop", "--system", "--docker", "c") == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(strstr(g_out, "belay receipt  / in the container c (4f1c0e8a9b7d)\n") == g_out);
    ASSERT_TRUE(strstr(g_out, "\nend state: by a walk at ") != NULL);
    REQUIRE_MSG(belay("watch", "patterns", "--system", "--docker", "c") == 0, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "srv/app/.ssh") != NULL);
}

/* The forms: --system-root is a directory's, --docker a container's; on
 * watch, --docker is a system watch's. A container that changed while it
 * was read keeps nothing (H-C5). */
TEST(the_forms_and_a_container_that_changed) {
    fresh();
    ASSERT_EQ_INT(2, belay("check", "--system-root", g_lower, "--docker", "c"));
    ASSERT_EQ_INT(2, belay("watch", "step", "--docker", "c", "--scope", g_lower, "--session", "s1"));
    ASSERT_EQ_INT(3, belay("check", "--system", "--docker", "nope"));
    ASSERT_EQ_INT(3, belay("baseline", "export", "--system", "--docker", "c", "--out", "/dev/null"));
    g_pid_after = 4243;
    g_opens = 0;
    ASSERT_EQ_INT(4, belay("check", "--system", "--docker", "c"));
    REQUIRE_MSG(strstr(g_err, "changed while it was read") != NULL, "%s", g_err);
    ASSERT_EQ_INT(0, (int)count(shout("find '%s' -type f \\( -name runtime.ndjson -o -name shadow.lines -o -name 'manifest*' \\)", g_state), "\n"));
}

/* WS-4: --docker needs root, as today: without the seam and without root,
 * refused before anything is run. */
TEST(not_root_a_container_is_refused) {
    if (geteuid() == 0) SKIP("run as root: the refusal is not root's");
    fresh();
    docker_test_open = NULL;
    ASSERT_EQ_INT(3, belay("check", "--system", "--docker", "c"));
    REQUIRE_MSG(strstr(g_err, "needs root") != NULL, "%s", g_err);
    ASSERT_EQ_INT(3, belay("watch", "start", "--system", "--docker", "c"));
}

#else

TEST(check_reads_the_container_s_roots_and_its_runtime) { SKIP("the host reader is Linux only"); }
TEST(a_container_on_the_host_network_lists_no_listener) { SKIP("the host reader is Linux only"); }
TEST(mark_and_diff_say_what_changed_in_the_container) { SKIP("the host reader is Linux only"); }
TEST(the_container_s_root_by_scope_after_a_system_capture_is_refused) { SKIP("the host reader is Linux only"); }
TEST(watch_start_step_stop_of_a_container) { SKIP("the host reader is Linux only"); }
TEST(the_forms_and_a_container_that_changed) { SKIP("the host reader is Linux only"); }
TEST(not_root_a_container_is_refused) { SKIP("the host reader is Linux only"); }

#endif

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_dsys_%d_%ld", (int)getpid(), (long)time(NULL));
    snprintf(g_lower, sizeof g_lower, "%s/lower", g_dir);
    snprintf(g_upper, sizeof g_upper, "%s/upper", g_dir);
    snprintf(g_proc, sizeof g_proc, "%s/proc", g_dir);
    snprintf(g_state, sizeof g_state, "%s/state", g_dir);
    umask(022);                         /* what is sealed must not depend on the suite's umask */
    mkdir(g_dir, 0700);
    setenv("BELAY_STATE_DIR", g_state, 1);
    RUN(check_reads_the_container_s_roots_and_its_runtime);
    RUN(a_container_on_the_host_network_lists_no_listener);
    RUN(mark_and_diff_say_what_changed_in_the_container);
    RUN(the_container_s_root_by_scope_after_a_system_capture_is_refused);
    RUN(watch_start_step_stop_of_a_container);
    RUN(the_forms_and_a_container_that_changed);
    RUN(not_root_a_container_is_refused);
    if (getenv("KEEP") == NULL) sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    free(g_out);
    free(g_err);
    return belay_test_report();
}
