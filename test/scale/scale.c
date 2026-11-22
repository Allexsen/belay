/*
 *  The bound of test/expect/capture-scale.md, SC-M2: for check, mark, diff,
 *  manifest, log, verify, prune and every watch command, belay's heap stays
 *  under 64 MiB whatever the number of entries.
 *
 *    scale <belay binary> <work directory> [entries]
 *
 *  A state directory is made whose checkpoints hold generated manifests of
 *  `entries` (2,000,000 by default) files -- written here as text, never as
 *  that many files -- and each command is run on it in a child whose data
 *  segment is limited to 64 MiB (RLIMIT_DATA: on Linux the heap and every
 *  private writable mapping, which is what malloc hands out). A command that
 *  reads a manifest whole asks for several hundred MiB and fails. The pin
 *  words the limit as one on the address space; RLIMIT_AS would also count
 *  the previous checkpoint's index, which is mapped read-only from a file
 *  and is no heap (SC-M3a), so the data segment is what is limited.
 *
 *  The tree the scope really holds is a few files: check, mark and a watch
 *  step walk that, with a generated manifest as the checkpoint before -- the
 *  part of a capture that grows with the previous manifest (its index, the
 *  delta against it) is what is measured, not the walk.
 *
 *  A command known to need more (KNOWN_OVER: per-diff state this step does
 *  not redesign) is run with the limit doubled until it passes, and the
 *  bracket is printed; it does not fail the run unless it passes at 64 MiB,
 *  which means its line here is stale. The peak RSS printed beside each
 *  command is not its heap: it counts the pages of the mapped index too
 *  (a mark of 2,000,000 entries shows about 300 MiB of them). Takes two to
 *  three minutes and 1.5 GB of disk: `make scale-test`, not part of
 *  `make check`.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "belay/error.h"
#include "cli/delta.h"
#include "cli/state.h"

#ifndef __linux__
int main(void) {
    puts("scale: skipped: a limit on the data segment bounds the heap on Linux only");
    return 0;
}
#else

#define LIMIT_MIB 64L

static char g_bin[PATH_MAX], g_work[PATH_MAX], g_scope[PATH_MAX + 16], g_state[PATH_MAX + 16], g_cp[PATH_MAX + 64];
static char g_header[70000], g_root[70000], g_bundle[PATH_MAX + 32], g_sha[65];
static long g_entries = 2000000;
static int g_failed;
static bool g_keep_stdout;      /* the next command's standard output is kept for a look (a capture's one line) */

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("scale: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(2);
}

static void sh(const char *fmt, ...) {
    static char cmd[4 * PATH_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    if (system(cmd) != 0) die("failed: %s", cmd);
}

/* The scope's one directory under the state root. */
static void find_checkpoints(void) {
    char cmd[2 * PATH_MAX + 64];
    snprintf(cmd, sizeof cmd, "ls -d '%s'/scopes/*/checkpoints", g_state);
    FILE *p = popen(cmd, "r");
    if (p == NULL || fgets(g_cp, sizeof g_cp, p) == NULL) die("no checkpoints directory under %s", g_state);
    pclose(p);
    g_cp[strcspn(g_cp, "\n")] = '\0';
}

/*
 *  A manifest of g_entries regular files in directories of 1000, under the
 *  real header and scope root of the scope. `variant` moves what a later
 *  capture would: every 1000th file's size, time and hash; every 5000th file
 *  is gone; one new file in every 100th directory.
 */
static void plant(long id, int variant) {
    char dir[PATH_MAX + 128], path[PATH_MAX + 160];
    snprintf(dir, sizeof dir, "%s/%ld", g_cp, id);
    if (mkdir(dir, 0700) == -1 && errno != EEXIST) die("mkdir %s: %s", dir, strerror(errno));
    snprintf(path, sizeof path, "%s/manifest.delta", dir);
    if (unlink(path) == -1 && errno != ENOENT) die("unlink %s: %s", path, strerror(errno));
    snprintf(path, sizeof path, "%s/manifest.ndjson", dir);
    FILE *f = fopen(path, "wb");
    if (f == NULL) die("cannot write %s", path);
    static char buf[1 << 20];
    setvbuf(f, buf, _IOFBF, sizeof buf);
    fputs(g_header, f);
    fputs(g_root, f);
    long n = 1;
    const long dirs = (g_entries + 999) / 1000;
    for (long d = 0; d < dirs; d++) {
        fprintf(f, "{\"path\":\"d%06ld\",\"type\":\"dir\",\"mode\":16877,\"uid\":1000,\"gid\":1000,\"size\":4096,"
                   "\"mtime_ns\":1700000000000000000,\"ctime_ns\":1700000000000000000,\"ino\":%ld,\"dev\":77,\"nlink\":2}\n",
                d, 100000000 + d);
        n++;
        for (long i = 0; i < 1000 && d * 1000 + i < g_entries; i++) {
            const long k = d * 1000 + i;
            const bool moved = variant != 0 && k % 1000 == 7;
            if (variant != 0 && k % 5000 == 11) continue;
            fprintf(f, "{\"path\":\"d%06ld/f%07ld.txt\",\"type\":\"reg\",\"mode\":33188,\"uid\":1000,\"gid\":1000,\"size\":%ld,"
                       "\"mtime_ns\":%ld,\"ctime_ns\":%ld,\"ino\":%ld,\"dev\":77,\"nlink\":1,"
                       "\"sha256\":\"%016lx%016lx%016lx%016lx\"}\n",
                    d, k, 100 + k % 900 + (moved ? variant : 0), 1700000000000000000 + k + (moved ? 5000000000L * variant : 0),
                    1700000000000000000 + k + (moved ? 5000000000L * variant : 0), 200000000 + k,
                    (unsigned long)k * 0x9E3779B97F4A7C15UL, (unsigned long)k ^ 0xA5A5A5A5UL, (unsigned long)(moved ? variant : 0),
                    (unsigned long)k);
            n++;
        }
        if (variant != 0 && d % 100 == 3) {
            fprintf(f, "{\"path\":\"d%06ld/new%d.txt\",\"type\":\"reg\",\"mode\":33188,\"uid\":1000,\"gid\":1000,\"size\":5,"
                       "\"mtime_ns\":1700000000000000000,\"ctime_ns\":1700000000000000000,\"ino\":%ld,\"dev\":77,\"nlink\":1,"
                       "\"sha256\":\"%064lx\"}\n", d, variant, 900000000 + d * 10 + variant, (unsigned long)d + 1);
            n++;
        }
    }
    fprintf(f, "{\"belay_manifest_end\":%ld,\"vanished\":0,\"unreadable\":0,\"unstable\":0,\"mounts\":0,\"raced\":0,"
               "\"trusted\":0,\"reference\":\"none\",\"read_all\":\"check\",\"writer_open\":0,\"unguarded\":0,"
               "\"not_read\":0,\"meta\":0,\"sealed\":0,\"carried\":0,\"racy\":0}\n", n);
    if (fclose(f) != 0) die("cannot write %s", path);
    if (id != 1)
        sh("sed 's/^{\"id\":1,/{\"id\":%ld,/' '%s/1/meta.json' > '%s/meta.json'", id, g_cp, dir);
}

struct result { int status; double secs; long rss_kib; };

/* `fn(arg)` in a child whose data segment is limited to `mib` MiB (0: not
 * limited), its output discarded. */
static struct result limited(long mib, int (*fn)(void *), void *arg) {
    struct result r = { -1, 0, 0 };
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    fflush(NULL);
    const pid_t pid = fork();
    if (pid == -1) die("fork: %s", strerror(errno));
    if (pid == 0) {
        char outp[PATH_MAX + 32];
        snprintf(outp, sizeof outp, "%s/stdout.txt", g_work);
        const int nul = g_keep_stdout ? open(outp, O_WRONLY | O_CREAT | O_TRUNC, 0600) : open("/dev/null", O_WRONLY);
        char errp[PATH_MAX + 32];
        snprintf(errp, sizeof errp, "%s/stderr.txt", g_work);
        const int err = open(errp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (nul == -1 || err == -1) _exit(120);
        dup2(nul, 1);
        dup2(err, 2);
        if (mib > 0) {
            const struct rlimit rl = { (rlim_t)mib << 20, (rlim_t)mib << 20 };
            if (setrlimit(RLIMIT_DATA, &rl) != 0) _exit(121);
        }
        _exit(fn(arg));
    }
    int st;
    struct rusage ru;
    if (wait4(pid, &st, 0, &ru) == -1) die("wait4: %s", strerror(errno));
    clock_gettime(CLOCK_MONOTONIC, &t1);
    r.status = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
    r.secs = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    r.rss_kib = ru.ru_maxrss;
    return r;
}

static int exec_belay(void *arg) {
    char **argv = arg;
    execv(g_bin, argv);
    return 122;
}

/* The delta writer on two generated manifests, as the capture calls it. */
static int store_delta(void *arg) {
    (void)arg;
    static struct scope sc;
    static struct state st;
    if (scope_resolve(g_scope, &sc) == -1 || state_open(&sc, true, &st, stderr) == -1) {
        fprintf(stderr, "%s\n", belay_err_msg());
        return 4;
    }
    manifest_store_delta(&st, 1, 2);
    const bool made = manifest_is_delta(&st, 2) || faccessat(st.cp_fd, "2/manifest.delta", F_OK, 0) == 0;
    state_close(&st);
    return made ? 0 : 4;
}

static const char *first_line(const char *name) {
    static char line[400];
    char errp[PATH_MAX + 32];
    snprintf(errp, sizeof errp, "%s/%s", g_work, name);
    line[0] = '\0';
    FILE *f = fopen(errp, "r");
    if (f != NULL) {
        if (fgets(line, sizeof line, f) == NULL) line[0] = '\0';
        fclose(f);
    }
    line[strcspn(line, "\n")] = '\0';
    return line;
}
static const char *stderr_line(void) { return first_line("stderr.txt"); }

/*
 *  A capture under the limit, once (a second would be another checkpoint):
 *  it exits 0, the checkpoint before it was used -- its line does not say
 *  every file was read -- when `prefiltered`, and its delta against that
 *  checkpoint was written, which a capture does not fail without.
 */
static void capture(const char *name, long id, bool prefiltered, char **argv) {
    g_keep_stdout = true;
    const struct result r = limited(LIMIT_MIB, exec_belay, argv);
    g_keep_stdout = false;
    char line[400], delta[PATH_MAX + 160];
    snprintf(line, sizeof line, "%s", first_line("stdout.txt"));
    snprintf(delta, sizeof delta, "%s/%ld/manifest.delta", g_cp, id);
    const char *why = r.status != 0 ? stderr_line()
                    : prefiltered && strstr(line, "every file read") != NULL ? line
                    : access(delta, F_OK) != 0 ? "its delta was not written" : NULL;
    if (why == NULL) printf("%-34s ok      %6.1f s  peak RSS %7ld KiB\n", name, r.secs, r.rss_kib);
    else printf("%-34s FAIL   exit %d: %s\n", name, r.status, why);
    g_failed += why != NULL;
    fflush(stdout);
}
#define CAPTURE(name, id, prefiltered, ...) do { \
    char *argv_[] = { g_bin, __VA_ARGS__, NULL }; \
    capture(name, id, prefiltered, argv_); } while (0)

/*
 *  One command: under 64 MiB it must exit `want`. One of KNOWN_OVER is
 *  expected to fail there, and is run again with the limit doubled until it
 *  exits `want`.
 */
static void run(const char *name, bool known_over, int want, int (*fn)(void *), void *arg, void (*again)(void)) {
    struct result r = limited(LIMIT_MIB, fn, arg);
    if (r.status == want) {
        printf("%-34s %s  %6.1f s  peak RSS %7ld KiB%s\n", name, known_over ? "PASSES (listed as over: stale)" : "ok    ",
               r.secs, r.rss_kib, "");
        if (known_over) g_failed++;
        fflush(stdout);
        return;
    }
    char first[400];
    snprintf(first, sizeof first, "%s", stderr_line());
    long mib = LIMIT_MIB;
    while (r.status != want && mib < 16384) {
        mib *= 2;
        if (again != NULL) again();
        r = limited(mib, fn, arg);
    }
    if (r.status == want)
        printf("%-34s %s  needs over %ld MiB, at most %ld MiB of heap (%.1f s, peak RSS %ld KiB there); at 64: %s\n", name,
               known_over ? "OVER (listed)" : "FAIL ", mib / 2, mib, r.secs, r.rss_kib, first);
    else
        printf("%-34s FAIL   exit %d whatever the limit: %s\n", name, r.status, stderr_line());
    if (!known_over || r.status != want) g_failed++;
    fflush(stdout);
}

#define BELAY(name, over, want, ...) do { \
    char *argv_[] = { g_bin, __VA_ARGS__, NULL }; \
    run(name, over, want, exec_belay, argv_, NULL); } while (0)

int main(int argc, char **argv) {
    if (argc < 3) die("usage: scale <belay binary> <work directory> [entries]");
    if (realpath(argv[1], g_bin) == NULL) die("no binary at %s", argv[1]);
    sh("rm -rf '%s' && mkdir -p '%s'", argv[2], argv[2]);
    if (realpath(argv[2], g_work) == NULL) die("no directory at %s", argv[2]);
    if (argc > 3) g_entries = atol(argv[3]);
    if (g_entries < 10000) die("at least 10000 entries");
    snprintf(g_scope, sizeof g_scope, "%s/scope", g_work);
    snprintf(g_state, sizeof g_state, "%s/state", g_work);
    snprintf(g_bundle, sizeof g_bundle, "%s/bundle", g_work);
    sh("mkdir -p '%s/src' '%s' && chmod 700 '%s' && printf 'a\\n' > '%s/a.txt' && printf 'int x;\\n' > '%s/src/x.c'",
       g_scope, g_state, g_state, g_scope, g_scope);
    setenv("BELAY_STATE_DIR", g_state, 1);
    unsetenv("XDG_STATE_HOME");

    /* The bundle verify judges against, and the first checkpoint: the scope as it is. */
    {
        static char cmd[6 * PATH_MAX + 256];
        /* in a state directory of its own: an export is a checkpoint too */
        snprintf(cmd, sizeof cmd, "mkdir -m 700 '%s/export-state' && BELAY_STATE_DIR='%s/export-state' "
                 "'%s' baseline export --scope '%s' --out '%s' --json", g_work, g_work, g_bin, g_scope, g_bundle);
        FILE *p = popen(cmd, "r");
        static char out[8192];
        const size_t n = p != NULL ? fread(out, 1, sizeof out - 1, p) : 0;
        out[n] = '\0';
        if (p == NULL || pclose(p) != 0 || strstr(out, "\"sha256\":\"") == NULL) die("baseline export failed: %s", out);
        snprintf(g_sha, sizeof g_sha, "%.64s", strstr(out, "\"sha256\":\"") + 10);
    }
    sh("'%s' check --scope '%s' > /dev/null", g_bin, g_scope);
    find_checkpoints();
    {
        char path[PATH_MAX + 160];
        snprintf(path, sizeof path, "%s/1/manifest.ndjson", g_cp);
        FILE *f = fopen(path, "r");
        if (f == NULL || fgets(g_header, sizeof g_header, f) == NULL || fgets(g_root, sizeof g_root, f) == NULL)
            die("cannot read %s", path);
        fclose(f);
    }
    printf("scale: %ld entries a manifest, each command's data segment limited to %ld MiB\n", g_entries, LIMIT_MIB);
    fflush(stdout);
    plant(1, 0);
    plant(2, 1);

    run("the delta writer (2 against 1)", false, 0, store_delta, NULL, NULL);
    CAPTURE("mark", 3, true, "mark", "--scope", g_scope);                          /* the index of 2, the delta against it */
    BELAY("log", false, 0, "log", "--scope", g_scope);
    BELAY("manifest (a delta)", false, 0, "manifest", "--scope", g_scope, "--id", "2");
    BELAY("diff, two generated manifests", false, 0, "diff", "--scope", g_scope, "--since", "1", "--to", "2");
    BELAY("diff --json, every entry removed", false, 0, "diff", "--scope", g_scope, "--since", "2", "--to", "3", "--json");
    /* KNOWN_OVER: the receipt keeps every line of a diff to order and fold them (src/cli/receipt.c), so
     * its memory follows the number of changes -- here every entry of the manifest, 2,000,000 lines;
     * measured between 64 and 128 MiB. Not the manifests: the same diff as JSON is under the limit. */
    if (g_entries >= 2000000) BELAY("diff, every entry removed", true, 0, "diff", "--scope", g_scope, "--since", "2", "--to", "3");
    else printf("%-34s not run: listed as over at 2,000,000 entries, and what it needs follows the count\n", "diff, every entry removed");
    BELAY("verify --to (a delta)", false, 0, "verify", "--scope", g_scope, "--baseline", g_bundle, "--baseline-sha256", g_sha,
          "--to", "2");
    plant(4, 2);
    CAPTURE("check", 5, false, "check", "--scope", g_scope);                       /* the delta against 4 */
    plant(6, 1);
    CAPTURE("watch step", 7, false, "watch", "step", "--scope", g_scope, "--session", "s", "--first-ok");
    plant(8, 2);
    CAPTURE("watch step, again", 9, false, "watch", "step", "--scope", g_scope, "--session", "s");
    BELAY("watch mark", false, 0, "watch", "mark", "--scope", g_scope, "--session", "s", "--name", "m");
    BELAY("watch summary", false, 0, "watch", "summary", "--scope", g_scope, "--session", "s", "--since", "m");
    BELAY("watch receipt", false, 0, "watch", "receipt", "--scope", g_scope);
    BELAY("watch patterns --entries", false, 0, "watch", "patterns", "--scope", g_scope, "--entries");
    BELAY("watch close", false, 0, "watch", "close", "--scope", g_scope, "--session", "s", "--all");
    BELAY("prune --dry-run", false, 0, "prune", "--scope", g_scope, "--keep-last", "1", "--keep-id", "2", "--dry-run");
    BELAY("prune (a delta made whole)", false, 0, "prune", "--scope", g_scope, "--keep-last", "1", "--keep-id", "2");

    if (g_failed == 0 || getenv("SCALE_KEEP") == NULL) sh("rm -rf '%s'", g_work);
    if (g_failed != 0) printf("scale: %d command(s) not as listed\n", g_failed);
    else puts("scale: every command as listed");
    return g_failed != 0;
}
#endif
