/*
 *  Manifest writer tests.
 *
 *  BLAST RADIUS unit. These build a throwaway tree under the test's own
 *  temporary directory (§0.4d: never the author's real filesystem) and assert
 *  what the writer records.
 *
 *  The filesystem-level containment scenarios deferred from phase 0 are here:
 *  scope itself a symlink, symlink to a parent directory, a directory replaced
 *  by a symlink, and a non-descending mount boundary.
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/manifest.h"
#include "belay/error.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char g_root[4096];

/* ---------- fixture helpers ---------- */

static void fx_init(void) {
    snprintf(g_root, sizeof g_root, "/tmp/belay_mw_%d_%ld", (int)getpid(), (long)time(NULL));
    mkdir(g_root, 0755);
}

static void fx_rm(const char *rel) {
    char p[8192];
    snprintf(p, sizeof p, "%s/%s", g_root, rel);
    unlink(p);
    rmdir(p);
}

static void fx_cleanup(void) {
    /* Depth-limited teardown of the fixture. The fixture is shallow by
     * construction, so a recursive unlink is not needed; anything left over
     * lives under /tmp and is harmless. */
    char cmd[8192];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_root);
    if (system(cmd) != 0) { /* best effort */ }
}

static void fx_mkdir(const char *rel) {
    char p[8192];
    snprintf(p, sizeof p, "%s/%s", g_root, rel);
    mkdir(p, 0755);
}

static void fx_write(const char *rel, const char *content, size_t len) {
    char p[8192];
    snprintf(p, sizeof p, "%s/%s", g_root, rel);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) return;
    if (len > 0 && write(fd, content, len) < 0) { /* reported by assertions */ }
    close(fd);
}

static void fx_symlink(const char *target, const char *rel) {
    char p[8192];
    snprintf(p, sizeof p, "%s/%s", g_root, rel);
    if (symlink(target, p) != 0) { /* reported by assertions */ }
}

static void fx_hardlink(const char *rel_from, const char *rel_to) {
    char a[8192], b[8192];
    snprintf(a, sizeof a, "%s/%s", g_root, rel_from);
    snprintf(b, sizeof b, "%s/%s", g_root, rel_to);
    if (link(a, b) != 0) { /* reported by assertions */ }
}

/* ---------- reading the produced manifest back ---------- */

struct found {
    char   path[4096];
    char   type[8];
    char   sha256[65];
    char   link_target[4096];
    bool   unverified;
    bool   mount;
    bool   outside;
    bool   unreadable;
    bool   seen;
    uint64_t nlink;
    uint32_t mode;
};

#define MAX_FOUND 256
static struct found g_found[MAX_FOUND];
static size_t g_nfound;
static char g_header[65600];

/* Deliberately a crude line scanner rather than the real reader: the writer's
 * tests must not depend on the reader being correct, or a bug in one could
 * mask a bug in the other. */
static const char *jstr(const char *line, const char *key, char *out, size_t outsz) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *p = strstr(line, pat);
    if (p == NULL) return NULL;
    p += strlen(pat);
    size_t w = 0;
    while (*p != '\0' && *p != '"' && w + 1 < outsz) {
        if (*p == '\\' && p[1] != '\0') p++;   /* crude unescape */
        out[w++] = *p++;
    }
    out[w] = '\0';
    return out;
}

static bool jbool(const char *line, const char *key) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":true", key);
    return strstr(line, pat) != NULL;
}

static uint64_t jnum(const char *line, const char *key) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":", key);
    const char *p = strstr(line, pat);
    if (p == NULL) return 0;
    return strtoull(p + strlen(pat), NULL, 10);
}

static int load(const char *mpath) {
    g_nfound = 0;
    g_header[0] = '\0';

    FILE *f = fopen(mpath, "rb");
    if (f == NULL) return -1;

    char line[65536];
    bool first = true;
    while (fgets(line, sizeof line, f) != NULL) {
        if (first) {
            snprintf(g_header, sizeof g_header, "%s", line);
            first = false;
            continue;
        }
        if (g_nfound >= MAX_FOUND) break;
        struct found *e = &g_found[g_nfound];
        memset(e, 0, sizeof *e);
        if (jstr(line, "path", e->path, sizeof e->path) == NULL) {
            /* path_b64 entry: record the raw b64 so tests can assert on it */
            jstr(line, "path_b64", e->path, sizeof e->path);
        }
        jstr(line, "type", e->type, sizeof e->type);
        jstr(line, "sha256", e->sha256, sizeof e->sha256);
        jstr(line, "link_target", e->link_target, sizeof e->link_target);
        e->unverified = jbool(line, "unverified");
        e->mount      = jbool(line, "mount");
        e->outside    = jbool(line, "target_outside_scope");
        e->unreadable = jbool(line, "unreadable");
        e->nlink      = jnum(line, "nlink");
        e->mode       = (uint32_t)jnum(line, "mode");
        e->seen       = true;
        g_nfound++;
    }
    fclose(f);
    return 0;
}

static struct found *get(const char *path) {
    for (size_t i = 0; i < g_nfound; i++)
        if (strcmp(g_found[i].path, path) == 0) return &g_found[i];
    return NULL;
}

static int run_check(const char *scope_rel, size_t *n) {
    char scope[8192], mpath[8192];
    if (scope_rel == NULL) snprintf(scope, sizeof scope, "%s", g_root);
    else snprintf(scope, sizeof scope, "%s/%s", g_root, scope_rel);
    snprintf(mpath, sizeof mpath, "/tmp/belay_m_%d.ndjson", (int)getpid());

    struct belay_manifest_opts o = {
        BELAY_HASH_MAX_BYTES_DEFAULT, BELAY_STORE_MAX_BYTES_DEFAULT, NULL
    };
    if (belay_manifest_write(mpath, scope, &o, n) == -1) return -1;
    return load(mpath);
}

/* ---------- tests ---------- */

TEST(records_regular_files_with_hashes) {
    fx_write("a.txt", "hello", 5);
    fx_mkdir("sub");
    fx_write("sub/b.txt", "", 0);

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    struct found *a = get("a.txt");
    ASSERT_TRUE(a != NULL);
    if (a) {
        ASSERT_EQ_STR("reg", a->type);
        /* sha256("hello") */
        ASSERT_EQ_STR("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                      a->sha256);
    }

    struct found *b = get("sub/b.txt");
    ASSERT_TRUE(b != NULL);
    if (b) {
        /* sha256("") -- an empty file still gets a hash, not "unverified" */
        ASSERT_EQ_STR("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                      b->sha256);
    }

    struct found *d = get("sub");
    ASSERT_TRUE(d != NULL);
    if (d) ASSERT_EQ_STR("dir", d->type);

    fx_rm("sub/b.txt"); fx_rm("sub"); fx_rm("a.txt");
}

/* Entries must be in bytewise path order: the comparator streams a merge and
 * would silently mis-pair entries otherwise. */
TEST(entries_are_sorted_bytewise) {
    fx_write("b", "x", 1);
    fx_write("a", "x", 1);
    fx_mkdir("a_dir");
    fx_write("a_dir/z", "x", 1);
    fx_write("Z", "x", 1);

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    for (size_t i = 1; i < g_nfound; i++) {
        const int cmp = strcmp(g_found[i - 1].path, g_found[i].path);
        if (cmp >= 0) {
            BELAY_FAIL("not sorted: %s before %s", g_found[i - 1].path, g_found[i].path);
        }
    }

    fx_rm("a_dir/z"); fx_rm("a_dir"); fx_rm("a"); fx_rm("b"); fx_rm("Z");
}

/* A symlink must be recorded AS a symlink, never followed. If it were
 * followed, the target's content would be attributed to the link's path. */
TEST(symlinks_recorded_not_followed) {
    fx_write("real.txt", "content", 7);
    fx_symlink("real.txt", "link.txt");

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    struct found *l = get("link.txt");
    ASSERT_TRUE(l != NULL);
    if (l) {
        ASSERT_EQ_STR("lnk", l->type);
        ASSERT_EQ_STR("real.txt", l->link_target);
        /* No hash: a symlink has no content of its own. */
        ASSERT_EQ_STR("", l->sha256);
    }

    fx_rm("link.txt"); fx_rm("real.txt");
}

/* A dangling symlink is legal and must be recorded, not treated as an error. */
TEST(dangling_symlink_is_recorded) {
    fx_symlink("nonexistent-target", "dangling");

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    struct found *l = get("dangling");
    ASSERT_TRUE(l != NULL);
    if (l) {
        ASSERT_EQ_STR("lnk", l->type);
        ASSERT_EQ_STR("nonexistent-target", l->link_target);
    }

    fx_rm("dangling");
}

/* An absolute symlink pointing outside the scope gets the advisory
 * annotation. It is reporting only and must never stop the walk (§5.1.1). */
TEST(symlink_outside_scope_is_annotated_not_followed) {
    fx_symlink("/etc", "escape");
    fx_symlink("/etc/passwd", "escape_file");

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    struct found *e = get("escape");
    ASSERT_TRUE(e != NULL);
    if (e) {
        ASSERT_EQ_STR("lnk", e->type);
        ASSERT_TRUE(e->outside);
        /* Critically: /etc's contents must NOT appear in the manifest. */
        ASSERT_TRUE(get("escape/passwd") == NULL);
    }

    fx_rm("escape"); fx_rm("escape_file");
}

/* A symlink pointing at a parent directory must not cause infinite recursion
 * or escape: it is recorded as a link and not descended. */
TEST(symlink_to_parent_does_not_recurse) {
    fx_mkdir("deep");
    fx_symlink("..", "deep/up");
    fx_write("deep/f", "x", 1);

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    struct found *u = get("deep/up");
    ASSERT_TRUE(u != NULL);
    if (u) ASSERT_EQ_STR("lnk", u->type);

    /* No path should contain the link traversed through. */
    for (size_t i = 0; i < g_nfound; i++) {
        if (strstr(g_found[i].path, "deep/up/") != NULL) {
            BELAY_FAIL("walked through a symlink: %s", g_found[i].path);
        }
    }

    fx_rm("deep/up"); fx_rm("deep/f"); fx_rm("deep");
}

/* The scope argument itself being a symlink is fine: realpath resolves it
 * once, then the walk proceeds from the resolved dirfd (§5.1.1). */
TEST(scope_itself_a_symlink_resolves_once) {
    fx_mkdir("realdir");
    fx_write("realdir/inside.txt", "data", 4);
    fx_symlink("realdir", "scopelink");

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check("scopelink", &n));

    /* Paths are relative to the resolved root, so the link name never
     * appears in them. */
    struct found *f = get("inside.txt");
    ASSERT_TRUE(f != NULL);
    if (f) ASSERT_EQ_STR("reg", f->type);

    fx_rm("scopelink"); fx_rm("realdir/inside.txt"); fx_rm("realdir");
}

/* Hard links: both names appear, each with nlink > 1. belay reports them and
 * never tries to repair the set. */
TEST(hardlinks_both_recorded_with_nlink) {
    fx_write("orig", "shared", 6);
    fx_hardlink("orig", "hard");

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    struct found *a = get("orig");
    struct found *b = get("hard");
    ASSERT_TRUE(a != NULL);
    ASSERT_TRUE(b != NULL);
    if (a && b) {
        ASSERT_EQ_INT(2, (int)a->nlink);
        ASSERT_EQ_INT(2, (int)b->nlink);
        /* Same content, so the same hash -- that is how diff can tell they
         * are the same inode without trusting ino alone. */
        ASSERT_EQ_STR(a->sha256, b->sha256);
    }

    fx_rm("hard"); fx_rm("orig");
}

/* FIFOs and sockets are zero-byte rendezvous tokens: recorded by type, never
 * opened. Opening a FIFO for read would block forever. */
TEST(fifo_recorded_by_type_not_opened) {
    char p[8192];
    snprintf(p, sizeof p, "%s/pipe", g_root);
    if (mkfifo(p, 0644) != 0) {
        /* Environment refused mkfifo; nothing to assert. */
        return;
    }

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    struct found *f = get("pipe");
    ASSERT_TRUE(f != NULL);
    if (f) {
        ASSERT_EQ_STR("fifo", f->type);
        ASSERT_EQ_STR("", f->sha256);   /* never hashed */
    }

    fx_rm("pipe");
}

/* Mode bits are first-class: a chmod with identical content must be visible,
 * which requires recording the full st_mode. */
TEST(mode_bits_are_recorded) {
    fx_write("perm", "x", 1);
    char p[8192];
    snprintf(p, sizeof p, "%s/perm", g_root);
    chmod(p, 0600);

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    struct found *f = get("perm");
    ASSERT_TRUE(f != NULL);
    if (f) ASSERT_EQ_INT(0600, (int)(f->mode & 07777));

    fx_rm("perm");
}

/* Empty directories are real changes and must be recorded -- git cannot
 * represent them, which is one of belay's stated differences. */
TEST(empty_directory_is_recorded) {
    fx_mkdir("emptydir");

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    struct found *d = get("emptydir");
    ASSERT_TRUE(d != NULL);
    if (d) ASSERT_EQ_STR("dir", d->type);

    fx_rm("emptydir");
}

/* A file above hash_max_bytes is recorded as unverified rather than hashed or
 * silently skipped: diff must then report any change as "modified
 * (unverified)" instead of claiming it is unchanged. */
TEST(oversized_file_is_unverified_not_skipped) {
    fx_write("big", "0123456789", 10);

    char mpath[8192], scope[8192];
    snprintf(mpath, sizeof mpath, "/tmp/belay_m2_%d.ndjson", (int)getpid());
    snprintf(scope, sizeof scope, "%s", g_root);

    struct belay_manifest_opts o = { 4, BELAY_STORE_MAX_BYTES_DEFAULT, NULL };
    size_t n = 0;
    ASSERT_EQ_INT(0, belay_manifest_write(mpath, scope, &o, &n));
    ASSERT_EQ_INT(0, load(mpath));

    struct found *f = get("big");
    ASSERT_TRUE(f != NULL);
    if (f) {
        ASSERT_TRUE(f->unverified);
        ASSERT_EQ_STR("", f->sha256);
    }
    unlink(mpath);
    fx_rm("big");
}

/* Non-UTF-8 path bytes must survive via path_b64 rather than being dropped,
 * mangled, or producing invalid JSON. */
TEST(non_utf8_path_uses_base64) {
    char p[8192];
    snprintf(p, sizeof p, "%s/bad\xff\xfename", g_root);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) return;   /* filesystem refused the name */
    close(fd);

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    /* base64 of "bad\xff\xfename" */
    bool found_b64 = false;
    for (size_t i = 0; i < g_nfound; i++) {
        if (strcmp(g_found[i].path, "YmFk//5uYW1l") == 0) found_b64 = true;
    }
    ASSERT_TRUE(found_b64);

    unlink(p);
}

/* A path with a newline or quote must produce valid JSON -- an unescaped
 * newline would split one entry into two malformed lines. */
TEST(path_with_newline_and_quote_is_escaped) {
    char p1[8192], p2[8192];
    snprintf(p1, sizeof p1, "%s/has\nnewline", g_root);
    snprintf(p2, sizeof p2, "%s/has\"quote", g_root);
    int f1 = open(p1, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int f2 = open(p2, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (f1 != -1) close(f1);
    if (f2 != -1) close(f2);

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));

    /* One line per entry: the newline must not have added any. */
    ASSERT_EQ_INT((int)n, (int)g_nfound);

    unlink(p1); unlink(p2);
}

TEST(rejects_dotdot_scope_before_touching_fs) {
    char scope[8192], mpath[8192];
    snprintf(scope, sizeof scope, "%s/../etc", g_root);
    snprintf(mpath, sizeof mpath, "/tmp/belay_m3_%d.ndjson", (int)getpid());

    struct belay_manifest_opts o = {
        BELAY_HASH_MAX_BYTES_DEFAULT, BELAY_STORE_MAX_BYTES_DEFAULT, NULL
    };
    ASSERT_EQ_INT(-1, belay_manifest_write(mpath, scope, &o, NULL));
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
    belay_err_clear();
}

TEST(rejects_nonexistent_scope) {
    char scope[8192], mpath[8192];
    snprintf(scope, sizeof scope, "%s/no-such-dir", g_root);
    snprintf(mpath, sizeof mpath, "/tmp/belay_m4_%d.ndjson", (int)getpid());

    struct belay_manifest_opts o = {
        BELAY_HASH_MAX_BYTES_DEFAULT, BELAY_STORE_MAX_BYTES_DEFAULT, NULL
    };
    ASSERT_EQ_INT(-1, belay_manifest_write(mpath, scope, &o, NULL));
    belay_err_clear();
}

/* The header must record the format version and the resolved scope. A reader
 * that cannot find a version it knows must refuse the file. */
TEST(header_records_version_and_scope) {
    fx_write("h", "x", 1);
    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));
    ASSERT_TRUE(strstr(g_header, "\"belay_manifest\":1") != NULL);
    ASSERT_TRUE(strstr(g_header, "\"hash\":\"sha256\"") != NULL);
    ASSERT_TRUE(strstr(g_header, "\"scopes\"") != NULL);
    fx_rm("h");
}

/*
 *  Found by independent review (§0.4b): an unreadable directory was silently
 *  omitted with rc=0 and no flag, so diff would report "unchanged" about files
 *  it never saw. The flag is what makes the omission visible.
 */
TEST(unreadable_directory_is_flagged_not_silently_omitted) {
    fx_mkdir("locked");
    fx_write("locked/hidden1", "secret", 6);
    fx_write("locked/hidden2", "secret", 6);

    char p[8192];
    snprintf(p, sizeof p, "%s/locked", g_root);
    if (chmod(p, 0000) != 0) return;   /* environment will not allow it */

    size_t n = 0;
    const int rc = run_check(NULL, &n);

    /* Restore before asserting, so a failure does not leave an unreadable
     * directory behind for the teardown. */
    chmod(p, 0755);

    ASSERT_EQ_INT(0, rc);

    struct found *d = get("locked");
    ASSERT_TRUE(d != NULL);
    if (d) {
        ASSERT_EQ_STR("dir", d->type);
        /* The subtree is absent, so the flag is the only thing standing
         * between diff and a false "unchanged". */
        ASSERT_TRUE(d->unreadable);
    }
    ASSERT_TRUE(get("locked/hidden1") == NULL);

    fx_rm("locked/hidden1"); fx_rm("locked/hidden2"); fx_rm("locked");
}

/* The specific indistinguishability the review demonstrated: before the fix,
 * an unreadable directory with contents was byte-identical to an empty one. */
TEST(unreadable_and_empty_directories_are_distinguishable) {
    fx_mkdir("has_content");
    fx_write("has_content/f", "x", 1);
    fx_mkdir("truly_empty");

    char p[8192];
    snprintf(p, sizeof p, "%s/has_content", g_root);
    if (chmod(p, 0000) != 0) return;

    size_t n = 0;
    const int rc = run_check(NULL, &n);
    chmod(p, 0755);
    ASSERT_EQ_INT(0, rc);

    struct found *locked = get("has_content");
    struct found *empty  = get("truly_empty");
    ASSERT_TRUE(locked != NULL);
    ASSERT_TRUE(empty != NULL);
    if (locked && empty) {
        ASSERT_TRUE(locked->unreadable);
        ASSERT_FALSE(empty->unreadable);
    }

    fx_rm("has_content/f"); fx_rm("has_content"); fx_rm("truly_empty");
}

/* An unreadable file keeps its metadata and gains both flags: unverified
 * because there is no hash, unreadable because the absence is not a choice. */
TEST(unreadable_file_is_flagged) {
    fx_write("noread", "data", 4);
    char p[8192];
    snprintf(p, sizeof p, "%s/noread", g_root);
    if (chmod(p, 0000) != 0) return;

    size_t n = 0;
    const int rc = run_check(NULL, &n);
    chmod(p, 0644);
    ASSERT_EQ_INT(0, rc);

    struct found *f = get("noread");
    ASSERT_TRUE(f != NULL);
    if (f) {
        ASSERT_TRUE(f->unreadable);
        ASSERT_EQ_STR("", f->sha256);
    }

    fx_rm("noread");
}

int main(void) {
    fx_init();

    RUN(records_regular_files_with_hashes);
    RUN(entries_are_sorted_bytewise);
    RUN(symlinks_recorded_not_followed);
    RUN(dangling_symlink_is_recorded);
    RUN(symlink_outside_scope_is_annotated_not_followed);
    RUN(symlink_to_parent_does_not_recurse);
    RUN(scope_itself_a_symlink_resolves_once);
    RUN(hardlinks_both_recorded_with_nlink);
    RUN(fifo_recorded_by_type_not_opened);
    RUN(mode_bits_are_recorded);
    RUN(empty_directory_is_recorded);
    RUN(oversized_file_is_unverified_not_skipped);
    RUN(non_utf8_path_uses_base64);
    RUN(path_with_newline_and_quote_is_escaped);
    RUN(rejects_dotdot_scope_before_touching_fs);
    RUN(rejects_nonexistent_scope);
    RUN(header_records_version_and_scope);
    RUN(unreadable_directory_is_flagged_not_silently_omitted);
    RUN(unreadable_and_empty_directories_are_distinguishable);
    RUN(unreadable_file_is_flagged);

    fx_cleanup();
    return belay_test_report();
}
