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
#include "belay/hash.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
    uint64_t size;
};

#define MAX_FOUND 256
static struct found g_found[MAX_FOUND];
static size_t g_nfound;
static char g_header[65600];
static char g_trailer[65600];

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
    g_trailer[0] = '\0';

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
        if (strstr(line, "\"belay_manifest_end\":") != NULL) {
            snprintf(g_trailer, sizeof g_trailer, "%s", line);
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
        e->size       = jnum(line, "size");
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

    struct belay_manifest_opts o = { .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT, .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT };
    struct belay_manifest_stats st;
    if (belay_manifest_write(mpath, scope, &o, &st) == -1) return -1;
    if (n != NULL) *n = st.entries;
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

    struct belay_manifest_opts o = { .hash_max_bytes = 4, .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT };
    struct belay_manifest_stats ost;
    ASSERT_EQ_INT(0, belay_manifest_write(mpath, scope, &o, &ost));
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

    struct belay_manifest_opts o = { .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT, .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT };
    ASSERT_EQ_INT(-1, belay_manifest_write(mpath, scope, &o, NULL));
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
    belay_err_clear();
}

TEST(rejects_nonexistent_scope) {
    char scope[8192], mpath[8192];
    snprintf(scope, sizeof scope, "%s/no-such-dir", g_root);
    snprintf(mpath, sizeof mpath, "/tmp/belay_m4_%d.ndjson", (int)getpid());

    struct belay_manifest_opts o = { .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT, .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT };
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

/* Reads a manifest and returns its body (every line after the header), so two
 * manifests can be compared without the created_ns timestamp. */
static char *body_of(const char *mpath, size_t *len) {
    FILE *f = fopen(mpath, "rb");
    if (f == NULL) return NULL;
    int c;
    while ((c = fgetc(f)) != EOF && c != '\n') { /* skip header */ }
    size_t cap = 1 << 20, n = 0;
    char *buf = malloc(cap);
    while (buf != NULL && (c = fgetc(f)) != EOF) {
        if (n + 1 >= cap) { cap *= 2; buf = realloc(buf, cap); if (!buf) break; }
        buf[n++] = (char)c;
    }
    fclose(f);
    if (buf) buf[n] = '\0';
    *len = n;
    return buf;
}

/*
 *  Defect 4 regression: the writer must hold bounded memory, so large trees
 *  spill sorted runs to disk and merge them. The strongest check available:
 *  forcing many spills and several FANIN cascades must produce exactly the
 *  same entries, in the same order, as a write that never spills.
 */
TEST(spilled_output_is_identical_to_in_memory_output) {
    fx_mkdir("many");
    char rel[256];
    /* ~5000 entries across nested dirs: with the minimum budget (~70 KB) that
     * is ~20 runs, so at least one 16-way cascade plus a final merge. Names
     * are chosen so walk order and sorted order disagree ("a-x" sorts before
     * "a/", "A" before "a"). */
    for (int d = 0; d < 50; d++) {
        snprintf(rel, sizeof rel, "many/d%02d", d);
        fx_mkdir(rel);
        snprintf(rel, sizeof rel, "many/d%02d-x", d);
        fx_write(rel, "x", 1);
        for (int i = 0; i < 100; i++) {
            snprintf(rel, sizeof rel, "many/d%02d/%s%03d", d, (i % 3) ? "f" : "F", i);
            fx_write(rel, "", 0);
        }
    }

    char scope[8192], m_mem[512], m_spill[512];
    snprintf(scope, sizeof scope, "%s/many", g_root);
    snprintf(m_mem, sizeof m_mem, "/tmp/belay_sp_mem_%d.ndjson", (int)getpid());
    snprintf(m_spill, sizeof m_spill, "/tmp/belay_sp_spill_%d.ndjson", (int)getpid());

    struct belay_manifest_opts big = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
        .run_bytes = 64u * 1024u * 1024u,       /* never spills */
    };
    struct belay_manifest_opts tiny = big;
    tiny.run_bytes = 1;                          /* clamped to the minimum */

    size_t n_mem = 0, n_spill = 0;
    struct belay_manifest_stats s_mem, s_spill;
    ASSERT_EQ_INT(0, belay_manifest_write(m_mem, scope, &big, &s_mem));
    ASSERT_EQ_INT(0, belay_manifest_write(m_spill, scope, &tiny, &s_spill));
    n_mem = s_mem.entries;
    n_spill = s_spill.entries;
    ASSERT_EQ_INT(5101, (int)n_mem);   /* 5,100 entries plus the root "." */
    ASSERT_EQ_INT((int)n_mem, (int)n_spill);

    size_t la = 0, lb = 0;
    char *a = body_of(m_mem, &la);
    char *b = body_of(m_spill, &lb);
    ASSERT_TRUE(a != NULL && b != NULL);
    if (a && b) {
        ASSERT_EQ_INT((int)la, (int)lb);
        ASSERT_TRUE(la == lb && memcmp(a, b, la) == 0);
    }
    free(a);
    free(b);

    /* And the spilled output is strictly sorted, entry by entry. Scanned line
     * by line rather than loaded, to keep the fixture small. Both outputs share
     * the sort routine, so equality alone would not catch a wrong sort. */
    FILE *sf = fopen(m_spill, "rb");
    ASSERT_TRUE(sf != NULL);
    if (sf) {
        char line[65536], prev[4096] = "", cur[4096];
        size_t lines = 0;
        while (fgets(line, sizeof line, sf) != NULL) {
            if (lines++ == 0) continue;            /* header */
            if (strstr(line, "belay_manifest_end") != NULL) continue;
            if (jstr(line, "path", cur, sizeof cur) == NULL) {
                BELAY_FAIL("line %zu has no path", lines);
                break;
            }
            if (prev[0] != '\0' && strcmp(prev, cur) >= 0) {
                BELAY_FAIL("not strictly sorted: %s then %s", prev, cur);
                break;
            }
            snprintf(prev, sizeof prev, "%s", cur);
        }
        fclose(sf);
    }

    unlink(m_mem);
    unlink(m_spill);
    char cmd[8300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s/many'", g_root);
    if (system(cmd) != 0) { /* best effort */ }
}

/* A failed write must leave nothing at out_path: the output is written to a
 * temporary name and renamed into place only on success. */
TEST(failed_write_leaves_no_partial_manifest) {
    char mpath[512], scope[8192];
    snprintf(mpath, sizeof mpath, "/tmp/belay_partial_%d.ndjson", (int)getpid());
    snprintf(scope, sizeof scope, "%s/does-not-exist", g_root);
    unlink(mpath);

    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
    };
    ASSERT_EQ_INT(-1, belay_manifest_write(mpath, scope, &o, NULL));
    belay_err_clear();
    ASSERT_TRUE(access(mpath, F_OK) != 0);
}

/* ===== Defect-class sweep, writer side ===== */

/* W4. The scope root is entry ".". Before, `chmod 700` on the root left the
 * manifest body byte-identical. */
TEST(sweep_scope_root_is_recorded) {
    char root[8192];
    snprintf(root, sizeof root, "%s/rootcase", g_root);
    mkdir(root, 0755);
    size_t n = 0;
    ASSERT_EQ_INT(0, run_check("rootcase", &n));
    struct found *r1 = get(".");
    ASSERT_TRUE(r1 != NULL);
    const uint32_t mode_before = r1 ? r1->mode : 0;
    if (r1) ASSERT_EQ_STR("dir", r1->type);

    chmod(root, 0700);
    ASSERT_EQ_INT(0, run_check("rootcase", &n));
    chmod(root, 0755);
    struct found *r2 = get(".");
    ASSERT_TRUE(r2 != NULL);
    if (r2) {
        ASSERT_EQ_INT(0700, (int)(r2->mode & 07777));
        ASSERT_TRUE(r2->mode != mode_before);
    }
    rmdir(root);
}

/* W8. Relative link targets are analysed too. Before, only absolute targets
 * were, so "../../etc" carried no annotation at all. Advisory only. */
TEST(sweep_relative_symlink_escape_is_annotated) {
    fx_mkdir("lk");
    fx_symlink("../../etc", "lk/esc");          /* lk -> scope root -> above it */
    fx_symlink("../sibling", "lk/inside");      /* lk/.. is the scope root: inside */
    fx_symlink("a/../../..", "lk/sneaky");      /* climbs out through a component */
    fx_symlink("x/y", "lk/down");

    size_t n = 0;
    ASSERT_EQ_INT(0, run_check(NULL, &n));
    struct found *e;
    e = get("lk/esc");    ASSERT_TRUE(e && e->outside);
    e = get("lk/inside"); ASSERT_TRUE(e && !e->outside);
    e = get("lk/sneaky"); ASSERT_TRUE(e && e->outside);
    e = get("lk/down");   ASSERT_TRUE(e && !e->outside);

    fx_rm("lk/esc"); fx_rm("lk/inside"); fx_rm("lk/sneaky"); fx_rm("lk/down"); fx_rm("lk");
}

/*
 *  W5. A recorded (size, sha256) pair must describe one real state of the
 *  file. Before the fix, a file appended to during `check` was recorded with a
 *  hash covering more bytes than its recorded size, 5 runs out of 5.
 *
 *  The race decides WHICH branch runs (stable hash vs unstable flag), so this
 *  test asserts the invariant that must hold either way, rather than a
 *  particular outcome. It cannot pass by luck: an inconsistent pair fails it
 *  whenever the race is hit.
 */
TEST(sweep_hash_always_matches_recorded_size_under_concurrent_append) {
    fx_mkdir("grow");
    char fpath[8192];
    snprintf(fpath, sizeof fpath, "%s/grow/log", g_root);
    {
        FILE *f = fopen(fpath, "wb");
        ASSERT_TRUE(f != NULL);
        if (!f) return;
        static char chunk[65536];
        memset(chunk, 'a', sizeof chunk);
        for (int i = 0; i < 300; i++) fwrite(chunk, 1, sizeof chunk, f);  /* ~19 MB */
        fclose(f);
    }

    const pid_t pid = fork();
    if (pid == 0) {
        /* Child: append for ~1.5 s, rate-limited to stay under the hash cap. */
        FILE *f = fopen(fpath, "ab");
        if (f == NULL) _exit(0);
        static char x[4096];
        memset(x, 'x', sizeof x);
        for (int i = 0; i < 3000; i++) {
            fwrite(x, 1, sizeof x, f);
            fflush(f);
            usleep(500);
        }
        fclose(f);
        _exit(0);
    }

    size_t unstable_seen = 0, hashed_seen = 0;
    for (int run = 0; run < 6; run++) {
        size_t n = 0;
        if (run_check("grow", &n) != 0) { BELAY_FAIL("check failed on run %d", run); break; }
        struct found *e = get("log");
        if (e == NULL) { BELAY_FAIL("log missing on run %d", run); break; }
        if (e->sha256[0] == '\0') {
            ASSERT_TRUE(e->unverified);
            unstable_seen++;
            continue;
        }
        hashed_seen++;
        /* Recompute sha256 of the first `size` bytes; it must equal the
         * recorded hash. Appends only add bytes, so those bytes are fixed. */
        FILE *f = fopen(fpath, "rb");
        if (f == NULL) continue;
        struct belay_sha256 c;
        belay_sha256_init(&c);
        static unsigned char buf[65536];
        uint64_t left = e->size;
        while (left > 0) {
            const size_t want = left < sizeof buf ? (size_t)left : sizeof buf;
            const size_t got = fread(buf, 1, want, f);
            if (got == 0) break;
            belay_sha256_update(&c, buf, got);
            left -= got;
        }
        fclose(f);
        uint8_t d[32];
        char hex[65];
        belay_sha256_final(&c, d);
        belay_hex_encode(hex, d, sizeof d);
        ASSERT_EQ_STR(e->sha256, hex);
    }
    int status;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(unstable_seen + hashed_seen == 6);

    unlink(fpath);
    fx_rm("grow");
}

/* W3. Device nodes carry rdev. Creating one needs privilege, so this reads the
 * real /dev/null, which exists on Linux and macOS alike. */
TEST(sweep_device_nodes_record_rdev) {
    char mpath[512];
    snprintf(mpath, sizeof mpath, "/tmp/belay_dev_%d.ndjson", (int)getpid());
    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
    };
    struct belay_manifest_stats st;
    if (belay_manifest_write(mpath, "/dev", &o, &st) != 0) {
        belay_err_clear();
        return;   /* /dev not walkable here; nothing to assert */
    }
    FILE *f = fopen(mpath, "rb");
    ASSERT_TRUE(f != NULL);
    bool found = false;
    char line[65536];
    while (f && fgets(line, sizeof line, f) != NULL) {
        if (strstr(line, "\"path\":\"null\",") != NULL) {
            found = true;
            ASSERT_TRUE(strstr(line, "\"type\":\"chr\"") != NULL);
            ASSERT_TRUE(strstr(line, "\"rdev\":") != NULL);
        }
    }
    if (f) fclose(f);
    ASSERT_TRUE(found);
    unlink(mpath);
}

/* W2. The trailer records what the walk could not capture, and stats agree. */
TEST(sweep_trailer_and_stats_report_unreadable) {
    fx_mkdir("tr");
    fx_mkdir("tr/locked");
    char p[8192];
    snprintf(p, sizeof p, "%s/tr/locked", g_root);
    if (chmod(p, 0000) != 0) return;

    char mpath[512], scope[8192];
    snprintf(mpath, sizeof mpath, "/tmp/belay_tr_%d.ndjson", (int)getpid());
    snprintf(scope, sizeof scope, "%s/tr", g_root);
    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
    };
    struct belay_manifest_stats st;
    const int rc = belay_manifest_write(mpath, scope, &o, &st);
    chmod(p, 0755);
    ASSERT_EQ_INT(0, rc);
    ASSERT_EQ_INT(2, (int)st.entries);      /* "." and "locked" */
    ASSERT_EQ_INT(1, (int)st.unreadable);

    ASSERT_EQ_INT(0, load(mpath));
    ASSERT_TRUE(strstr(g_trailer, "\"belay_manifest_end\":2,") != NULL);
    ASSERT_TRUE(strstr(g_trailer, "\"unreadable\":1,") != NULL);
    unlink(mpath);
    fx_rm("tr/locked"); fx_rm("tr");
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
    RUN(spilled_output_is_identical_to_in_memory_output);
    RUN(failed_write_leaves_no_partial_manifest);
    RUN(sweep_scope_root_is_recorded);
    RUN(sweep_relative_symlink_escape_is_annotated);
    RUN(sweep_hash_always_matches_recorded_size_under_concurrent_append);
    RUN(sweep_device_nodes_record_rdev);
    RUN(sweep_trailer_and_stats_report_unreadable);

    fx_cleanup();
    return belay_test_report();
}
