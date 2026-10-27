/*
 *  Filesystem scenarios (gap b, 2026-10-26). Each race fires at an exact
 *  point through a decorated platform adapter, as in test/test_races.c.
 *
 *  The class that produced every HIGH review finding -- a change during the
 *  walk that the manifest does not show -- was fixed for NFS, SMB, FUSE and
 *  coarse-timestamp filesystems without ever running on one. CI mounts
 *  loopback btrfs and FAT images and a loopback NFS export and runs this
 *  driver on each:
 *
 *    fs_scenarios <dir-on-target-fs> [--coarse] [--subvol NAME]
 *
 *  --coarse: the filesystem's timestamps are coarser than the time between a
 *            fixture's creation and the change (FAT: 2 s). The "fresh"
 *            variants then hit known issue R4-F1 (equality cannot see a
 *            change in the same timestamp slot) and are expected to escape:
 *            XFAIL, not FAIL. An XFAIL that passes prints XPASS.
 *  --subvol: NAME is a btrfs subvolume created inside <dir> by the caller; it
 *            must be walked into, not recorded as a mount (review round 3, F4).
 *
 *  Exit status: 0 when every scenario met its expectation.
 */
#define _GNU_SOURCE
#include "belay/manifest.h"
#include "belay/error.h"
#include "capture/capture.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[512], g_scope[700], g_m[700];
static enum { NONE, MOVE_INTO_LISTED, CHANGE_AFTER_READ } g_arm;
static bool g_append, g_fired;
static int g_fail;

/* ---- interposition: a decorated platform adapter ---- */

static const struct fsops *g_real;
static struct fsops g_ops;

static void *g_root;
static char g_walked[8];
static const char *t_dir_next(void *ctx, void *d) {
    (void)ctx;
    const char *e = g_real->dir_next(g_real->ctx, d);
    if (g_root == NULL) g_root = d;
    /* When the root listing returns the second of A/B, move its file into the
     * first, which is fully walked by now. */
    if (g_arm == MOVE_INTO_LISTED && !g_fired && e != NULL && d == g_root &&
        (strcmp(e, "A") == 0 || strcmp(e, "B") == 0)) {
        if (g_walked[0] == '\0') {
            snprintf(g_walked, sizeof g_walked, "%.7s", e);
        } else {
            char from[1600], to[1600];
            snprintf(from, sizeof from, "%s/%s/m_%s", g_scope, e, e);
            snprintf(to, sizeof to, "%s/%s/m_%s", g_scope, g_walked, e);
            if (rename(from, to) == 0) g_fired = true;
        }
    }
    return e;
}

static char g_first[256];
static int t_openat(void *ctx, int fd, const char *name, int flags) {
    (void)ctx;
    /* On the second regular file opened, change the first one. */
    if (g_arm == CHANGE_AFTER_READ && !g_fired && !(flags & O_DIRECTORY) &&
        (flags & O_ACCMODE) == O_RDONLY) {
        if (g_first[0] == '\0') {
            snprintf(g_first, sizeof g_first, "%s", name);
        } else {
            char p[1600];
            snprintf(p, sizeof p, "%s/%s", g_scope, g_first);
            const int w = openat(AT_FDCWD, p, O_WRONLY | (g_append ? O_APPEND : 0), 0);
            if (w >= 0) {
                if (write(w, "Z", 1) == 1) g_fired = true;   /* same size unless appending */
                close(w);
            }
        }
    }
    return g_real->openat(g_real->ctx, fd, name, flags);
}

/* ---- helpers ---- */

static void fresh_scope(const char *name) {
    snprintf(g_scope, sizeof g_scope, "%s/%s", g_dir, name);
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_scope);
    if (system(cmd) != 0) { /* best effort */ }
    mkdir(g_scope, 0755);
}

static void put(const char *rel, const char *content) {
    char p[1600];
    snprintf(p, sizeof p, "%s/%s", g_scope, rel);
    FILE *f = fopen(p, "wb");
    if (f) { fputs(content, f); fclose(f); }
}

static void sub(const char *rel) {
    char p[1600];
    snprintf(p, sizeof p, "%s/%s", g_scope, rel);
    mkdir(p, 0755);
}

static struct belay_manifest_stats g_st;
static int noop(const struct belay_entry *e, void *c) { (void)e; (void)c; return 0; }
static bool check(void) {
    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
    };
    g_root = NULL;
    const int rc = capture_write(&g_ops, g_m, g_scope, &o, &g_st);
    g_arm = NONE;
    if (rc != 0) { printf("    write failed: %s\n", belay_err_msg()); belay_err_clear(); return false; }
    if (belay_manifest_read(g_m, noop, NULL) != 0) {           /* must read back */
        printf("    reader rejected the manifest: %s\n", belay_err_msg());
        belay_err_clear();
        return false;
    }
    return true;
}

static bool flagged(void) {
    return g_st.vanished || g_st.unreadable || g_st.unstable || g_st.raced;
}

/* PASS/FAIL/XFAIL/XPASS reporting. */
static void verdict(const char *name, bool ok, bool expect_escape) {
    const char *v = ok ? (expect_escape ? "XPASS" : "PASS ") : (expect_escape ? "XFAIL" : "FAIL ");
    printf("  %s %s  (unstable %zu, raced %zu, vanished %zu)%s\n", v, name, g_st.unstable,
           g_st.raced, g_st.vanished, !ok && expect_escape ? "  known issue R4-F1" : "");
    if (!ok && !expect_escape) g_fail++;
}

/* ---- scenarios ---- */

static void s_clean(void) {
    fresh_scope("clean");
    sub("A"); sub("B");
    put("A/x", "one"); put("B/y", "two");
    sleep(3);                       /* older than any coarse timestamp slot */
    const bool a = check() && !flagged();
    const bool b = check() && !flagged();
    verdict("clean tree, checked twice: no flags", a && b, false);
}

static void s_move(bool aged, bool coarse) {
    fresh_scope(aged ? "move_aged" : "move_fresh");
    sub("A"); sub("B");
    put("A/m_A", ""); put("B/m_B", "");
    if (aged) sleep(3);
    g_arm = MOVE_INTO_LISTED; g_fired = false; g_walked[0] = '\0';
    const bool ok = check() && g_fired && flagged();
    verdict(aged ? "move into a listed directory (aged fixture)"
                 : "move into a listed directory (fresh fixture)", ok, coarse && !aged);
}

static void s_change(bool append, bool aged, bool coarse) {
    fresh_scope(append ? (aged ? "append_aged" : "append_fresh")
                       : (aged ? "rewrite_aged" : "rewrite_fresh"));
    put("f1", "one"); put("f2", "two");
    if (aged) sleep(3);
    g_arm = CHANGE_AFTER_READ; g_append = append; g_fired = false; g_first[0] = '\0';
    const bool ok = check() && g_fired && g_st.raced >= 1;
    char name[128];
    snprintf(name, sizeof name, "file %s after it was read (%s fixture)",
             append ? "appended to" : "rewritten, same size", aged ? "aged" : "fresh");
    /* A size change is seen at any granularity; a same-size rewrite in the
     * same timestamp slot is not. */
    verdict(name, ok, coarse && !aged && !append);
}

static int g_sub_found, g_sub_child, g_sub_mount;
static int find_sub(const struct belay_entry *e, void *ctx) {
    const char *n = ctx;
    const size_t l = strlen(n);
    if (e->path_len == l && memcmp(e->path, n, l) == 0) { g_sub_found = 1; g_sub_mount = e->is_mount; }
    if (e->path_len > l && memcmp(e->path, n, l) == 0 && e->path[l] == '/') g_sub_child = 1;
    return 0;
}

static void s_subvol(const char *name) {
    snprintf(g_scope, sizeof g_scope, "%s", g_dir);
    char p[1600];
    snprintf(p, sizeof p, "%s/%s/inside", g_dir, name);
    FILE *f = fopen(p, "wb");
    if (f) { fputs("in a subvolume", f); fclose(f); }
    g_sub_found = g_sub_child = g_sub_mount = 0;
    bool ok = check() && belay_manifest_read(g_m, find_sub, (void *)name) == 0;
    ok = ok && g_sub_found && g_sub_child && !g_sub_mount;
    verdict("btrfs subvolume is walked, not a mount", ok, false);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: fs_scenarios <dir> [--coarse] [--subvol NAME]\n"); return 2; }
    snprintf(g_dir, sizeof g_dir, "%s", argv[1]);
    g_real = fsops_default();
    g_ops = *g_real;
    g_ops.dir_next = t_dir_next;
    g_ops.openat = t_openat;
    bool coarse = false;
    const char *subvol = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--coarse") == 0) coarse = true;
        else if (strcmp(argv[i], "--subvol") == 0 && i + 1 < argc) subvol = argv[++i];
    }
    snprintf(g_m, sizeof g_m, "/tmp/belay_fs_%d.ndjson", (int)getpid());
    printf("fs_scenarios on %s%s\n", g_dir, coarse ? " (coarse timestamps)" : "");

    s_clean();
    s_move(true, coarse);
    s_move(false, coarse);
    s_change(true, true, coarse);
    s_change(true, false, coarse);
    s_change(false, true, coarse);
    s_change(false, false, coarse);
    if (subvol != NULL) s_subvol(subvol);

    unlink(g_m);
    printf("%s: %d unexpected failure(s)\n", g_fail ? "FAILED" : "ok", g_fail);
    return g_fail ? 1 : 0;
}
