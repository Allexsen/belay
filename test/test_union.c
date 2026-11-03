/*
 *  The host reader's union (src/capture/union.c; test/expect/host-reader.md,
 *  "The union"): layers laid out as overlayfs lays them out, then captured
 *  through the union and read back. Whiteouts are character devices 0:0,
 *  which an unprivileged process may make only in a user namespace: each
 *  test runs in a child that enters one, and is skipped where the host
 *  forbids it. The overlay's xattrs are `user.overlay.*` here (a user
 *  namespace cannot set `trusted.*`); the union takes the prefix it is given.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "belay/error.h"
#include "belay/manifest.h"
#include "capture/capture.h"
#include "capture/union.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/fs.h>

static char g_root[256], g_m[300];
static struct belay_entry g_e[64];
static size_t g_n;

static int collect(const struct belay_entry *e, void *c) {
    (void)c;
    if (g_n < 64) g_e[g_n++] = *e;
    return 0;
}

static const struct belay_entry *find(const char *p) {
    for (size_t i = 0; i < g_n; i++)
        if (strcmp(g_e[i].path, p) == 0) return &g_e[i];
    return NULL;
}

static int enter_userns(void) {
    const uid_t uid = getuid();
    const gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER) != 0) return 77;
    char map[64];
    int fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) { if (write(fd, "deny", 4) != 4) { /* best effort */ } close(fd); }
    snprintf(map, sizeof map, "0 %u 1\n", (unsigned)uid);
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0 || write(fd, map, strlen(map)) < 0) return 77;
    close(fd);
    snprintf(map, sizeof map, "0 %u 1\n", (unsigned)gid);
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd < 0 || write(fd, map, strlen(map)) < 0) return 77;
    close(fd);
    return 0;
}

/* g_root/<layer>/<path>: a directory, a file with `text`, a whiteout, a link */
static int md(const char *l, const char *p) {
    char b[600];
    snprintf(b, sizeof b, "%s/%s/%s", g_root, l, p);
    return mkdir(b, 0755) == 0 || errno == EEXIST ? 0 : -1;
}
static int wf(const char *l, const char *p, const char *text) {
    char b[600];
    snprintf(b, sizeof b, "%s/%s/%s", g_root, l, p);
    FILE *f = fopen(b, "wb");
    if (f == NULL) return -1;
    fputs(text, f);
    return fclose(f);
}
static int wo(const char *l, const char *p) {
    char b[600];
    snprintf(b, sizeof b, "%s/%s/%s", g_root, l, p);
    return mknod(b, S_IFCHR | 0000, makedev(0, 0));
}
static int xa(const char *l, const char *p, const char *name, const char *v) {
    char b[600];
    snprintf(b, sizeof b, "%s/%s/%s", g_root, l, p);
    return lsetxattr(b, name, v, strlen(v), 0);
}
static ino_t ino_of(const char *l, const char *p) {
    char b[600];
    struct stat st;
    snprintf(b, sizeof b, "%s/%s/%s", g_root, l, p);
    return lstat(b, &st) == 0 ? st.st_ino : 0;
}

static int layers(int *fd) {
    static const char *const L[] = { "up", "mid", "low", "base" };
    for (int i = 0; i < 4; i++) {
        char b[400];
        snprintf(b, sizeof b, "%s/%s", g_root, L[i]);
        if ((fd[i] = open(b, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1) return -1;
    }
    return 0;
}

/* Capture through the union: 0, or the step that failed (> 0). */
static const struct fsops *base_ops(void);
static int capture_with(const char *scope, const char *const *mounts, size_t nm, char *refused, size_t rcap) {
    int fd[4];
    if (layers(fd) != 0) return 20;
    struct union_fs *u = union_new(base_ops(), fd, 4, "user.overlay.", mounts, nm);
    if (u == NULL) return 21;
    char canon[4096];
    const int root = union_open_scope(u, scope, canon, sizeof canon);
    if (root == -1) {
        snprintf(refused, rcap, "scope: %s", belay_err_msg());
        union_free(u);
        return 22;
    }
    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
        .source_docker = "4f1c0e8a9b7d6c5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e",
        .source_image = "sha256:91ef0af61f39ece4d6710e465df5ed6ca12112358344fd51ae6a3b886634148b",
    };
    const int w = capture_write_root(union_ops(u), g_m, canon, root, &o, NULL);
    snprintf(refused, rcap, "%s", union_refused(u));
    union_free(u);
    if (w != 0) {
        snprintf(refused, rcap, "capture: %s", belay_err_msg());
        return 23;
    }
    g_n = 0;
    return belay_manifest_read(g_m, collect, NULL) == 0 ? 0 : 24;
}

static const struct fsops *base_ops(void) { return fsops_default(); }

/* The layout of host-reader.md's union rows, four layers deep (the bottom
 * one empty but for what a case adds). */
static int build(void) {
    static const char *const L[] = { "up", "mid", "low", "base" };
    for (int i = 0; i < 4; i++) {
        char b[400];
        snprintf(b, sizeof b, "%s/%s", g_root, L[i]);
        if (mkdir(b, 0755) != 0) return -1;
        if (md(L[i], "w") != 0) return -1;
    }
    /* low: the image */
    if (md("low", "w/a") || wf("low", "w/a/f", "low\n") || wf("low", "w/a/g", "lowg\n") || md("low", "w/d") ||
        wf("low", "w/d/x", "x\n") || wf("low", "w/keep", "k\n") || md("low", "w/rn") || wf("low", "w/rn/y", "y\n") ||
        md("low", "w/op") || wf("low", "w/op/z", "z\n") || md("low", "w/sub") || md("low", "w/sub/deep") ||
        wf("low", "w/sub/deep/q", "q\n") || md("low", "w/vol") || wf("low", "w/vol/inner", "i\n"))
        return -1;
    char lk[600];
    snprintf(lk, sizeof lk, "%s/low/link", g_root);
    if (symlink("w", lk) != 0) return -1;
    /* mid: f rewritten, d deleted */
    if (md("mid", "w/a") || wf("mid", "w/a/f", "mid\n") || wo("mid", "w/d")) return -1;
    /* up: a file added; op deleted and made again (opaque); rn renamed in
     * place to rn2 (relative redirect); sub/deep moved to mv (absolute);
     * lock made immutable inside the container (protattr) */
    if (md("up", "w/a") || wf("up", "w/a/new", "new\n") || xa("up", "w/a/new", "user.test", "v") ||
        md("up", "w/op") || xa("up", "w/op", "user.overlay.opaque", "y") || wf("up", "w/op/w", "w\n") ||
        wo("up", "w/rn") || md("up", "w/rn2") || xa("up", "w/rn2", "user.overlay.redirect", "rn") ||
        md("up", "w/sub") || wo("up", "w/sub/deep") || md("up", "w/mv") ||
        xa("up", "w/mv", "user.overlay.redirect", "/w/sub/deep") || wf("up", "w/lock", "l\n") ||
        xa("up", "w/lock", "user.overlay.protattr", "i") || xa("up", "w/lock", "user.overlay.origin", ""))
        return -1;
    return 0;
}

static int union_child(void) {
    if (enter_userns() != 0) return 77;
    if (build() != 0) return errno == EPERM || errno == ENOTSUP || errno == EOPNOTSUPP ? 77 : 10;
    char why[600] = "";
    static const char *const mounts[] = { "/w/vol" };
    const int r = capture_with("/link", mounts, 1, why, sizeof why);   /* through a link in the container */
    if (r != 0) {
        fprintf(stderr, "capture step %d: %s\n", r, why);
        return r;
    }
    if (why[0] != '\0') {
        fprintf(stderr, "refused: %s\n", why);
        return 30;
    }
    /* the end-of-walk re-check agrees with the walk: nothing unstable or raced
     * (found in CI: lower contributors re-listed through a dup were empty) */
    for (size_t i = 0; i < g_n; i++)
        if (g_e[i].unstable || g_e[i].raced) { fprintf(stderr, "%s unstable or raced\n", g_e[i].path); return 41; }
    static const char *const present[] = { ".", "a", "a/f", "a/g", "a/new", "keep", "lock", "mv", "mv/q",
                                           "op", "op/w", "rn2", "rn2/y", "sub", "vol" };
    static const char *const absent[] = { "d", "d/x", "rn", "rn/y", "op/z", "sub/deep", "sub/deep/q", "vol/inner" };
    for (size_t i = 0; i < sizeof present / sizeof *present; i++)
        if (find(present[i]) == NULL) { fprintf(stderr, "missing %s\n", present[i]); return 31; }
    for (size_t i = 0; i < sizeof absent / sizeof *absent; i++)
        if (find(absent[i]) != NULL) { fprintf(stderr, "present %s\n", absent[i]); return 32; }
    /* H-U1, H-U7: the topmost layer supplies it, with its own identity */
    const struct belay_entry *f = find("a/f");
    if (f->size != 4 || f->ino != (uint64_t)ino_of("mid", "w/a/f")) return 33;
    /* H-U5: the content below a redirect, from where it lies */
    if (find("mv/q")->ino != (uint64_t)ino_of("low", "w/sub/deep/q")) return 34;
    if (find("rn2/y")->ino != (uint64_t)ino_of("low", "w/rn/y")) return 35;
    /* H-U8: protattr added to the iflags */
    const struct belay_entry *l = find("lock");
    if (!l->has_iflags || (l->iflags & FS_IMMUTABLE_FL) == 0) return 36;
    /* H-U6: the overlay's xattrs are not the file's; the file's are */
    const struct belay_entry *n = find("a/new");
    if (!n->has_xattrs || strstr(n->xattrs, "user.test") == NULL || strstr(n->xattrs, "overlay") != NULL) return 37;
    if (l->has_xattrs && strstr(l->xattrs, "overlay") != NULL) return 38;
    /* H-M5: a mount point is a boundary, nothing below it */
    if (!find("vol")->is_mount) return 39;
    /* the scope named as resolved in the container, with its source */
    return 0;
}

/* H-U3, H-U6: what the pin refuses is said, never read past. */
static int refusal_child(int which) {
    if (enter_userns() != 0) return 77;
    if (build() != 0) return errno == EPERM || errno == ENOTSUP || errno == EOPNOTSUPP ? 77 : 10;
    if (which == 0 && xa("up", "w/op", "user.overlay.opaque", "x") != 0) return 11;
    if (which == 1 && xa("low", "w/keep", "user.overlay.metacopy", "") != 0) return 11;
    /* H-U5: the absolute redirect's target whited out in the middle layer --
     * nothing below it merges (found by the union model: a whiteout there was
     * read as absent and the bottom layer's content used) */
    if (which == 2 && (md("up", "w/r2") != 0 || xa("up", "w/r2", "user.overlay.redirect", "/tgt") != 0 ||
                       wo("low", "tgt") != 0 || md("base", "tgt") != 0 || wf("base", "tgt/old", "o\n") != 0))
        return 11;
    char why[600] = "";
    const int r = capture_with("/w", NULL, 0, why, sizeof why);
    if (r != 0) return 40 + r;
    return strstr(why, which == 0 ? "H-U3" : which == 1 ? "H-U6" : "H-U5") != NULL ? 0 : 50;
}

/* H-C3: a scope that is a mount, below one, or not a directory is refused. */
static int scope_child(void) {
    if (enter_userns() != 0) return 77;
    if (build() != 0) return errno == EPERM || errno == ENOTSUP || errno == EOPNOTSUPP ? 77 : 10;
    static const char *const mounts[] = { "/w/vol" };
    static const char *const bad[] = { "/w/vol", "/w/vol/x", "/w/keep", "/w/d", "relative" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        char why[600] = "";
        if (capture_with(bad[i], mounts, 1, why, sizeof why) != 22) { fprintf(stderr, "accepted %s\n", bad[i]); return 60; }
        belay_err_clear();
    }
    return 0;
}

static int run_child(int (*fn)(int), int arg) {
    snprintf(g_root, sizeof g_root, "/tmp/belay_union_%d_%d", (int)getpid(), arg);
    snprintf(g_m, sizeof g_m, "%s.ndjson", g_root);
    if (mkdir(g_root, 0755) != 0) return -1;
    const pid_t pid = fork();
    if (pid == 0) _exit(fn(arg));
    int st = 0;
    waitpid(pid, &st, 0);
    char cmd[700];
    snprintf(cmd, sizeof cmd, "rm -rf '%s' '%s'", g_root, g_m);
    if (system(cmd) != 0) { /* best effort */ }
    return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
}

static int union_fn(int a) { (void)a; return union_child(); }
static int scope_fn(int a) { (void)a; return scope_child(); }

TEST(the_union_reads_the_layers_as_the_pin_says) {
    const int r = run_child(union_fn, 0);
    if (r == 77) SKIP("no user namespace here");
    ASSERT_EQ_INT(0, r);
}

TEST(what_the_pin_refuses_is_said) {
    for (int w = 0; w < 3; w++) {
        const int r = run_child(refusal_child, w);
        if (r == 77) SKIP("no user namespace here");
        ASSERT_EQ_INT(0, r);
    }
}

TEST(a_scope_the_layers_do_not_hold_is_refused) {
    const int r = run_child(scope_fn, 3);
    if (r == 77) SKIP("no user namespace here");
    ASSERT_EQ_INT(0, r);
}

#else
TEST(the_union_reads_the_layers_as_the_pin_says) { SKIP("the host reader is Linux only"); }
TEST(what_the_pin_refuses_is_said) { SKIP("the host reader is Linux only"); }
TEST(a_scope_the_layers_do_not_hold_is_refused) { SKIP("the host reader is Linux only"); }
#endif

int main(void) {
    RUN(the_union_reads_the_layers_as_the_pin_says);
    RUN(what_the_pin_refuses_is_said);
    RUN(a_scope_the_layers_do_not_hold_is_refused);
    return belay_test_report();
}
