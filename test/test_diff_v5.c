/*
 *  The diff of version 5 manifests (test/expect/manifest-v5.md, V5-D1 to
 *  V5-D6 and V5-D4b with its two fixtures; diff-fields.md O9 and O10 for
 *  `not_read`; checkpoint-v3 C3-3 in the diff's trailer). Every manifest is
 *  written here by hand, so the diff is tested against the pin's words and
 *  not against what the walker happens to write.
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/diff.h"
#include "belay/error.h"
#include "belay/manifest.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char g_dir[512];
static char *g_out;

#define HA "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define HB "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define K1 "1111111111111111"
#define K2 "2222222222222222"

/* One manifest under construction: its header's v5 keys, its entries (given
 * in path order), the counts its trailer must carry. */
static struct { char roots[4096], key[64], body[65536]; size_t n, unstable, raced, wopen, nr, meta, sealed, mounts, unread; } M;

static void m_new(const char *roots, const char *sealed_key) {
    memset(&M, 0, sizeof M);
    snprintf(M.roots, sizeof M.roots, "%s", roots != NULL ? roots : "");
    if (sealed_key != NULL) snprintf(M.key, sizeof M.key, ",\"sealed_key\":\"%s\"", sealed_key);
}

/* A root for m_new's list: "path:c" content, "path:m" metadata, with "!" when not found. */
#define RT(p, cls, found) "{\"root\":\"" p "\",\"class\":\"" cls "\",\"found\":" found "}\n"

static void count(const char *flags) {
    M.n++;
    if (strstr(flags, "\"unstable\":true")) M.unstable++;
    if (strstr(flags, "\"raced\":true")) M.raced++;
    if (strstr(flags, "\"writer_open\":true")) M.wopen++;
    if (strstr(flags, "\"not_read\":true")) M.nr++;
    if (strstr(flags, "\"meta\":true")) M.meta++;
    if (strstr(flags, "\"sealed\":true")) M.sealed++;
    if (strstr(flags, "\"mount\":true")) M.mounts++;
    if (strstr(flags, "\"unreadable\":true")) M.unread++;
}

static void add(const char *line, const char *flags) {
    strncat(M.body, line, sizeof M.body - strlen(M.body) - 1);
    count(flags);
}

/* A directory; `flags` in canonical order, each with its leading comma. */
static void dir_m(const char *path, unsigned mode, const char *flags) {
    char l[1024];
    const bool nr = strstr(flags, "\"not_read\":true") != NULL;
    snprintf(l, sizeof l, "{\"path\":\"%s\",\"type\":\"dir\",\"mode\":%u,\"uid\":0,\"gid\":0,%s\"ino\":7,\"dev\":1%s%s}\n",
             path, 040000u | mode, nr ? "" : "\"size\":4096,\"mtime_ns\":5,\"ctime_ns\":5,", nr ? "" : ",\"nlink\":2", flags);
    add(l, flags);
}
static void dir(const char *path, const char *flags) { dir_m(path, 0755, flags); }

/* A regular file: `tail` is its hash fields and flags, in canonical order. */
static void reg_x(const char *path, unsigned mode, unsigned long size, long mtime, long ctime, const char *tail) {
    char l[1024];
    snprintf(l, sizeof l, "{\"path\":\"%s\",\"type\":\"reg\",\"mode\":%u,\"uid\":0,\"gid\":0,\"size\":%lu,\"mtime_ns\":%ld,"
             "\"ctime_ns\":%ld,\"ino\":9,\"dev\":1,\"nlink\":1%s}\n", path, 0100000u | mode, size, mtime, ctime, tail);
    add(l, tail);
}
static void reg(const char *path, const char *tail) { reg_x(path, 0644, 3, 5, 5, tail); }
#define SHA(h) ",\"sha256\":\"" h "\""
#define META ",\"meta\":true"
#define SEALED(h) ",\"sha256\":\"" h "\",\"sealed\":true"

static void lnk(const char *path) {
    char l[1024];
    snprintf(l, sizeof l, "{\"path\":\"%s\",\"type\":\"lnk\",\"mode\":41471,\"uid\":0,\"gid\":0,\"size\":1,\"mtime_ns\":5,"
             "\"ctime_ns\":5,\"ino\":8,\"dev\":1,\"nlink\":1,\"link_target\":\"t\"}\n", path);
    add(l, "");
}

static void m_write(const char *name) {
    char p[700];
    snprintf(p, sizeof p, "%s/%s", g_dir, name);
    FILE *f = fopen(p, "wb");
    if (f == NULL) return;
    /* A manifest given no roots whose entries carry a version 5 flag is made
     * the capture it must be for a reader to take it (V5-E3): each name
     * directly under the scope root is a root -- metadata when an entry at
     * or below it is meta, content otherwise -- and the scope root partial. */
    static char body[sizeof M.body + 64];
    snprintf(body, sizeof body, "%s", M.body);
    if (M.roots[0] == '\0' && (M.nr || M.meta || M.sealed || strstr(M.body, "\"partial\":true"))) {
        char seen[64][64];
        size_t ns = 0;
        for (const char *l = M.body; l != NULL && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL) {
            if (strncmp(l, "{\"path\":\"", 9) != 0) continue;
            char top[64];
            snprintf(top, sizeof top, "%.*s", (int)strcspn(l + 9, "\"/"), l + 9);
            if (strcmp(top, ".") == 0) continue;
            bool dup = false;
            for (size_t i = 0; i < ns; i++) dup |= strcmp(seen[i], top) == 0;
            if (dup || ns == 64) continue;
            snprintf(seen[ns++], sizeof seen[0], "%s", top);
            bool meta = false;              /* any entry at or below it */
            char at[80], below[80];
            snprintf(at, sizeof at, "{\"path\":\"%s\",", top);
            snprintf(below, sizeof below, "{\"path\":\"%s/", top);
            for (const char *k = M.body; k != NULL && *k; k = strchr(k, '\n') ? strchr(k, '\n') + 1 : NULL)
                if ((strncmp(k, at, strlen(at)) == 0 || strncmp(k, below, strlen(below)) == 0) &&
                    memmem(k, strcspn(k, "\n"), "\"meta\":true", 11) != NULL)
                    meta = true;
            char rl[200];
            snprintf(rl, sizeof rl, "{\"root\":\"%s\",\"class\":\"%s\",\"found\":true}\n", top, meta ? "metadata" : "content");
            strncat(M.roots, rl, sizeof M.roots - strlen(M.roots) - 1);
        }
        char *root = strstr(body, "{\"path\":\".\",");
        char *end = root != NULL ? strchr(root, '\n') : NULL;
        if (end != NULL && memmem(root, (size_t)(end - root), "\"partial\":true", 14) == NULL) {
            memmove(end - 1 + 15, end - 1, strlen(end - 1) + 1);
            memcpy(end - 1, ",\"partial\":true", 15);
        }
    }
    size_t nroots = 0;                  /* V5-A1: the count, then one line per root */
    for (const char *c = M.roots; *c; c++) nroots += *c == '\n';
    fprintf(f, "{\"belay_manifest\":5,\"created_ns\":0,\"scopes\":[\"/s\"],\"hash\":\"sha256\",\"hash_max_bytes\":67108864,"
               "\"store_max_bytes\":65536,\"excluded\":[],\"walk_start_ns\":0,\"source\":null,\"roots\":%zu%s,"
               "\"basis\":\"walk\"}\n%s%s", nroots, M.key, M.roots, body);
    fprintf(f, "{\"belay_manifest_end\":%zu,\"vanished\":0,\"unreadable\":%zu,\"unstable\":%zu,\"mounts\":%zu,\"raced\":%zu,"
               "\"trusted\":0,\"reference\":\"none\",\"read_all\":\"check\",\"writer_open\":%zu,\"unguarded\":0,"
               "\"not_read\":%zu,\"meta\":%zu,\"sealed\":%zu,\"carried\":0,\"racy\":0}\n",
            M.n, M.unread, M.unstable, M.mounts, M.raced, M.wopen, M.nr, M.meta, M.sealed);
    fclose(f);
}

static int run(void) {
    char b[700], a[700], o[700];
    snprintf(b, sizeof b, "%s/before", g_dir);
    snprintf(a, sizeof a, "%s/after", g_dir);
    snprintf(o, sizeof o, "%s/diff", g_dir);
    free(g_out);
    g_out = NULL;
    if (belay_diff(b, a, o, NULL, NULL) != 0) return -1;
    FILE *f = fopen(o, "rb");
    if (f == NULL) return -1;
    size_t cap = 0;
    const ssize_t n = getdelim(&g_out, &cap, '\0', f);
    fclose(f);
    return n < 0 ? -1 : 0;
}

/* The record of `path`, whole ("" when there is none). */
static const char *rec(const char *path) {
    static char line[8192];
    char want[600];
    snprintf(want, sizeof want, "\n{\"path\":\"%s\",", path);
    const char *p = g_out != NULL ? strstr(g_out, want) : NULL;
    if (p == NULL) return "";
    const char *e = strchr(p + 1, '\n');
    snprintf(line, sizeof line, "%.*s", (int)(e - p - 1), p + 1);
    return line;
}
static const char *first_line(void) {
    static char line[8192];
    snprintf(line, sizeof line, "%.*s", (int)strcspn(g_out, "\n"), g_out);
    return line;
}
static const char *last_line(void) {
    const size_t n = strlen(g_out);
    const char *p = g_out + n - 1;
    while (p > g_out && p[-1] != '\n') p--;
    return p;
}

/* Two manifests of one file `f`, differing as given, and their record. */
static const char *pair(unsigned long size_b, long mt_b, long ct_b, const char *tail_b, const char *key_b,
                        unsigned long size_a, long mt_a, long ct_a, const char *tail_a, const char *key_a) {
    m_new(NULL, key_b); dir(".", ""); reg_x("f", 0644, size_b, mt_b, ct_b, tail_b); m_write("before");
    m_new(NULL, key_a); dir(".", ""); reg_x("f", 0644, size_a, mt_a, ct_a, tail_a); m_write("after");
    if (run() != 0) return belay_err_msg();
    return rec("f");
}
#define IS(want, got) do { const char *g_ = (got); if (strcmp(want, g_) != 0) BELAY_FAIL("want %s\n      got  %s", want, g_); } while (0)

/* V5-D1: meta on both sides. */
TEST(meta_on_both_sides) {
    IS("", pair(3, 5, 5, META, NULL, 3, 5, 5, META, NULL));
    /* a different size proves it (diff-fields' size row; O9 says what was not read) */
    IS("{\"path\":\"f\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"size\",\"mtime_ns\"],"
       "\"before\":{\"size\":3,\"mtime_ns\":5},\"after\":{\"size\":4,\"mtime_ns\":6},\"content_not_read\":[\"not_read\"]}",
       pair(3, 5, 5, META, NULL, 4, 6, 6, META, NULL));
    /* any other difference: unknown, never metadata_only (a same-size rewrite moves these too) */
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"changed\":[\"mtime_ns\"],"
       "\"before\":{\"mtime_ns\":5},\"after\":{\"mtime_ns\":6},\"unknown\":[\"not_read\"]}",
       pair(3, 5, 5, META, NULL, 3, 6, 6, META, NULL));
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"changed\":[\"ctime_ns\"],"
       "\"before\":{\"ctime_ns\":5},\"after\":{\"ctime_ns\":6},\"unknown\":[\"not_read\"]}",
       pair(3, 5, 5, META, NULL, 3, 5, 6, META, NULL));
    m_new(NULL, NULL); dir(".", ""); reg_x("f", 0644, 3, 5, 5, META); m_write("before");
    m_new(NULL, NULL); dir(".", ""); reg_x("f", 0755, 3, 5, 5, META); m_write("after");
    REQUIRE(run() == 0);
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"changed\":[\"mode\"],"
       "\"before\":{\"mode\":33188},\"after\":{\"mode\":33261},\"unknown\":[\"not_read\"]}", rec("f"));
}

/* V5-D2: meta on one side, a hash on the other: as O1 for unverified. */
TEST(meta_on_one_side) {
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"not_read\"]}",
       pair(3, 5, 5, META, NULL, 3, 5, 5, SHA(HA), NULL));
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"not_read\"]}",
       pair(3, 5, 5, SHA(HA), NULL, 3, 5, 5, META, NULL));
    IS("{\"path\":\"f\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"size\"],"
       "\"before\":{\"size\":3},\"after\":{\"size\":4},\"content_not_read\":[\"not_read\"]}",
       pair(3, 5, 5, SHA(HA), NULL, 4, 5, 5, META, NULL));
    /* the type differs: type_changed (rule 2) */
    m_new(NULL, NULL); dir(".", ""); reg("f", META); m_write("before");
    m_new(NULL, NULL); dir(".", ""); lnk("f"); m_write("after");
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(rec("f"), "\"outcome\":\"type_changed\",\"type\":\"lnk\",\"type_before\":\"reg\"") != NULL);
    /* with a file over the hash limit on the other side: both reasons, in the table's order */
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"unverified\",\"not_read\"]}",
       pair(99999999, 5, 5, ",\"unverified\":true", NULL, 99999999, 5, 5, META, NULL));
}

/* V5-D3: sealed hashes compare only under one key; a record of a sealed
 * entry never carries the hash. */
TEST(sealed_entries_compare_under_one_key) {
    IS("", pair(3, 5, 5, SEALED(HA), K1, 3, 5, 5, SEALED(HA), K1));
    IS("{\"path\":\"f\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"sha256\"],\"before\":{},\"after\":{}}",
       pair(3, 5, 5, SEALED(HA), K1, 3, 5, 5, SEALED(HB), K1));
    /* different keys: nothing to compare, whatever the hashes */
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"sealed_key\"]}",
       pair(3, 5, 5, SEALED(HA), K1, 3, 5, 5, SEALED(HA), K2));
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"sealed_key\"]}",
       pair(3, 5, 5, SEALED(HA), K1, 3, 5, 5, SEALED(HB), K2));
    /* a metadata difference beside it is listed, the outcome still unknown */
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"changed\":[\"mtime_ns\"],"
       "\"before\":{\"mtime_ns\":5},\"after\":{\"mtime_ns\":6},\"unknown\":[\"sealed_key\"]}",
       pair(3, 5, 5, SEALED(HA), K1, 3, 6, 6, SEALED(HA), K2));
    /* under one key the other fields compare as for any file */
    IS("{\"path\":\"f\",\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"mtime_ns\"],"
       "\"before\":{\"mtime_ns\":5},\"after\":{\"mtime_ns\":6}}",
       pair(3, 5, 5, SEALED(HA), K1, 3, 6, 6, SEALED(HA), K1));
    /* across a type change the regular side's hash is carried (diff-values V6): not a sealed one */
    m_new(NULL, K1); dir(".", ""); reg("f", SEALED(HA)); m_write("before");
    m_new(NULL, NULL); dir(".", ""); lnk("f"); m_write("after");
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(rec("f"), "\"outcome\":\"type_changed\"") != NULL);
    ASSERT_TRUE(strstr(rec("f"), "\"before\":{\"mode\":33188,\"size\":3}") != NULL);
    ASSERT_TRUE(strstr(g_out, HA) == NULL);
}

/* V5-D4: a directory not entered on both sides is compared by type, mode
 * and owner alone; what lies below one is not captured. */
TEST(not_read_directories) {
    m_new(NULL, NULL); dir(".", ""); dir("d", ",\"not_read\":true"); m_write("before");
    m_new(NULL, NULL); dir(".", ""); dir("d", ",\"not_read\":true"); m_write("after");
    REQUIRE(run() == 0);
    IS("", rec("d"));
    ASSERT_TRUE(strstr(last_line(), "\"dir_timestamps_only\":0,") != NULL);
    /* checkpoint-v3 C3-3, G3-2: they seal */
    ASSERT_TRUE(strstr(last_line(), ",\"before_sealing\":1,\"after_sealing\":1}") != NULL);
    /* its mode differs */
    m_new(NULL, NULL); dir(".", ""); dir_m("d", 0700, ",\"not_read\":true"); m_write("after");
    REQUIRE(run() == 0);
    IS("{\"path\":\"d\",\"outcome\":\"unknown\",\"type\":\"dir\",\"changed\":[\"mode\"],"
       "\"before\":{\"mode\":16877},\"after\":{\"mode\":16832},\"unknown\":[\"not_read\"]}", rec("d"));
    /* not_read on one side only, nothing else differing */
    m_new(NULL, NULL); dir(".", ""); dir("d", ""); reg("d/f", SHA(HA)); m_write("after");
    REQUIRE(run() == 0);
    IS("{\"path\":\"d\",\"outcome\":\"unknown\",\"type\":\"dir\",\"unknown\":[\"not_read\"]}", rec("d"));
    /* and the path below it, on the side that looked: not captured on the other */
    IS("{\"path\":\"d/f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"not_captured\"]}", rec("d/f"));
    /* the other way round */
    m_new(NULL, NULL); dir(".", ""); dir("d", ""); dir("d/e", ""); reg("d/e/f", SHA(HA)); m_write("before");
    m_new(NULL, NULL); dir(".", ""); dir("d", ",\"not_read\":true"); m_write("after");
    REQUIRE(run() == 0);
    IS("{\"path\":\"d/e\",\"outcome\":\"unknown\",\"type\":\"dir\",\"unknown\":[\"not_captured\"]}", rec("d/e"));
    IS("{\"path\":\"d/e/f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"not_captured\"]}", rec("d/e/f"));
    /* a type change is a type change */
    m_new(NULL, NULL); dir(".", ""); reg("d", SHA(HA)); m_write("before");
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(rec("d"), "\"outcome\":\"type_changed\",\"type\":\"dir\",\"type_before\":\"reg\"") != NULL);
    /* raced beside it is rule 1's unknown, with both reasons in the table's order */
    m_new(NULL, NULL); dir(".", ""); dir("d", ",\"not_read\":true"); m_write("before");
    m_new(NULL, NULL); dir(".", ""); dir("d", ",\"raced\":true,\"not_read\":true"); m_write("after");
    REQUIRE(run() == 0);
    IS("{\"path\":\"d\",\"outcome\":\"unknown\",\"type\":\"dir\",\"unknown\":[\"raced\",\"not_read\"]}", rec("d"));
}

#define HOME_ROOTS RT("home/u/.bashrc", "content", "false") RT("home/u/.config/systemd/user", "content", "false") \
                   RT("home/u/.ssh", "content", "false")
#define P ",\"partial\":true"

/* The home of V5-D4b's fixtures before anything was added: partial, with a
 * .config that is partial in its turn (its systemd/user is looked for). */
static void home_before_as(const char *name) {
    m_new(HOME_ROOTS, NULL);
    dir(".", P); dir("home", P); dir("home/u", P); dir("home/u/.config", P);
    m_write(name);
}
static void home_before(void) { home_before_as("before"); }

/* V5-D4b, the first fixture: a first .ssh/authorized_keys in an existing
 * home is added. */
TEST(a_first_ssh_directory_in_a_home_is_added) {
    home_before();
    m_new(RT("home/u/.bashrc", "content", "false") RT("home/u/.config/systemd/user", "content", "false")
          RT("home/u/.ssh", "content", "true"), K1);
    dir(".", P); dir("home", P); dir("home/u", P); dir("home/u/.config", P); dir_m("home/u/.ssh", 0700, "");
    reg_x("home/u/.ssh/authorized_keys", 0600, 3, 5, 5, SEALED(HA));
    m_write("after");
    REQUIRE(run() == 0);
    IS("{\"path\":\"home/u/.ssh\",\"outcome\":\"added\",\"type\":\"dir\"}", rec("home/u/.ssh"));
    IS("{\"path\":\"home/u/.ssh/authorized_keys\",\"outcome\":\"added\",\"type\":\"reg\"}", rec("home/u/.ssh/authorized_keys"));
    /* V5-D6 */
    ASSERT_TRUE(strstr(first_line(), ",\"roots_differ\":true}") != NULL);
    ASSERT_TRUE(strstr(last_line(), "\"added\":2,") != NULL && strstr(last_line(), "\"unknown\":0,") != NULL);
}

/* V5-D4b, the second fixture: a first .config/systemd/user/x.service in a
 * home that had .config and no systemd below it is added. */
TEST(a_first_user_unit_in_a_home_is_added) {
    home_before();
    m_new(RT("home/u/.bashrc", "content", "false") RT("home/u/.config/systemd/user", "content", "true")
          RT("home/u/.ssh", "content", "false"), NULL);
    dir(".", P); dir("home", P); dir("home/u", P); dir("home/u/.config", P); dir("home/u/.config/systemd", P);
    dir("home/u/.config/systemd/user", ""); reg("home/u/.config/systemd/user/x.service", SHA(HA));
    m_write("after");
    REQUIRE(run() == 0);
    IS("{\"path\":\"home/u/.config/systemd\",\"outcome\":\"added\",\"type\":\"dir\"}", rec("home/u/.config/systemd"));
    IS("{\"path\":\"home/u/.config/systemd/user\",\"outcome\":\"added\",\"type\":\"dir\"}", rec("home/u/.config/systemd/user"));
    IS("{\"path\":\"home/u/.config/systemd/user/x.service\",\"outcome\":\"added\",\"type\":\"reg\"}",
       rec("home/u/.config/systemd/user/x.service"));
    /* and the other way: removed */
    char b[700], a[700], t[700];
    snprintf(b, sizeof b, "%s/before", g_dir);
    snprintf(a, sizeof a, "%s/after", g_dir);
    snprintf(t, sizeof t, "%s/swap", g_dir);
    REQUIRE(rename(b, t) == 0 && rename(a, b) == 0 && rename(t, a) == 0 && run() == 0);
    IS("{\"path\":\"home/u/.config/systemd\",\"outcome\":\"removed\",\"type\":\"dir\"}", rec("home/u/.config/systemd"));
    IS("{\"path\":\"home/u/.config/systemd/user/x.service\",\"outcome\":\"removed\",\"type\":\"reg\"}",
       rec("home/u/.config/systemd/user/x.service"));
}

/* V5-D4b, the rule: under a partial directory on the other side, a directory
 * (or a link directly under the scope root) is recorded whenever it is
 * there, so its absence is known; a file's is known only when the other
 * side's roots list it. `partial` itself is not compared. */
TEST(a_path_under_a_partial_directory_on_the_other_side) {
    /* the other side recorded everything: a capture of the whole scope (a
     * capture by roots never records such files, and a reader refuses one that does) */
    home_before();
    m_new(NULL, NULL);
    dir(".", ""); lnk("bin"); dir("home", ""); reg("home/stray", SHA(HA)); dir("home/u", "");
    reg("home/u/.bashrc", SHA(HA)); dir("home/u/.config", ""); dir("home/u/Music", ""); lnk("home/u/link");
    reg("home/u/notes.txt", SHA(HA)); reg("top.txt", SHA(HA));
    m_write("after");
    REQUIRE(run() == 0);
    /* a file the other side's roots list (found: false): its absence was known */
    IS("{\"path\":\"home/u/.bashrc\",\"outcome\":\"added\",\"type\":\"reg\"}", rec("home/u/.bashrc"));
    /* a file they do not list: that side did not record such a name */
    IS("{\"path\":\"home/u/notes.txt\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"not_captured\"]}", rec("home/u/notes.txt"));
    IS("{\"path\":\"home/stray\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"not_captured\"]}", rec("home/stray"));
    IS("{\"path\":\"top.txt\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"not_captured\"]}", rec("top.txt"));
    /* a directory: always recorded */
    IS("{\"path\":\"home/u/Music\",\"outcome\":\"added\",\"type\":\"dir\"}", rec("home/u/Music"));
    /* a link: directly under the scope root it is recorded, elsewhere not */
    IS("{\"path\":\"bin\",\"outcome\":\"added\",\"type\":\"lnk\"}", rec("bin"));
    IS("{\"path\":\"home/u/link\",\"outcome\":\"unknown\",\"type\":\"lnk\",\"unknown\":[\"not_captured\"]}", rec("home/u/link"));
    ASSERT_TRUE(strstr(first_line(), ",\"roots_differ\":true}") != NULL);
    /* partial on one side only, every compared field equal: no record */
    m_new(NULL, NULL); dir(".", ""); dir("home", ""); m_write("before");
    m_new(RT("home/u/.ssh", "content", "false"), NULL); dir(".", P); dir("home", P); m_write("after");
    REQUIRE(run() == 0);
    IS("", rec("home"));
    IS("", rec("."));
    ASSERT_TRUE(strstr(last_line(), "{\"belay_diff_end\":0,") != NULL);
    ASSERT_TRUE(strstr(first_line(), ",\"roots_differ\":true}") != NULL);
    /* a partial directory that is also unstable: its listing is incomplete first */
    m_new(HOME_ROOTS, NULL); dir(".", P); dir("home", ",\"unstable\":true,\"partial\":true"); m_write("before");
    m_new(HOME_ROOTS, NULL); dir(".", P); dir("home", P); dir("home/v", ",\"not_read\":true"); m_write("after");
    REQUIRE(run() == 0);
    IS("{\"path\":\"home/v\",\"outcome\":\"unknown\",\"type\":\"dir\",\"unknown\":[\"listing_incomplete\"]}", rec("home/v"));
}

/* manifest-v5-addendum V5-A4: a link where a directory on the way to a root
 * is looked for is recorded, so replacing ~/.config by a link is a type
 * change, and a link appearing there is added: its absence was known. */
TEST(a_link_on_the_way_to_a_root) {
    home_before();
    m_new(HOME_ROOTS, NULL);
    dir(".", P); dir("home", P); dir("home/u", P); lnk("home/u/.config");
    m_write("after");
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(rec("home/u/.config"), "\"outcome\":\"type_changed\",\"type\":\"lnk\",\"type_before\":\"dir\"") != NULL);
    /* (a link on the way to nothing is not such a name: home/u/link, in the test above) */
    m_new(HOME_ROOTS, NULL); dir(".", P); dir("home", P); dir("home/u", P); m_write("before");
    REQUIRE(run() == 0);
    IS("{\"path\":\"home/u/.config\",\"outcome\":\"added\",\"type\":\"lnk\"}", rec("home/u/.config"));
}

/* V5-A4, the root itself: a link where a root is looked for is recorded and
 * that root not found. On one side only, against a side that looked for the
 * root and found nothing, it is added or removed: its absence was known. In
 * place of the directory that was the root, it is a type change. */
TEST(a_link_where_a_root_is_looked_for) {
    home_before();
    m_new(HOME_ROOTS, NULL);
    dir(".", P); dir("home", P); dir("home/u", P); lnk("home/u/.bashrc"); dir("home/u/.config", P); lnk("home/u/.ssh");
    m_write("after");
    REQUIRE_MSG(run() == 0, "%s", belay_err_msg());
    IS("{\"path\":\"home/u/.ssh\",\"outcome\":\"added\",\"type\":\"lnk\"}", rec("home/u/.ssh"));
    IS("{\"path\":\"home/u/.bashrc\",\"outcome\":\"added\",\"type\":\"lnk\"}", rec("home/u/.bashrc"));
    /* the other way round: removed */
    m_new(HOME_ROOTS, NULL);
    dir(".", P); dir("home", P); dir("home/u", P); dir("home/u/.config", P); lnk("home/u/.ssh");
    m_write("before");
    home_before_as("after");
    REQUIRE_MSG(run() == 0, "%s", belay_err_msg());
    IS("{\"path\":\"home/u/.ssh\",\"outcome\":\"removed\",\"type\":\"lnk\"}", rec("home/u/.ssh"));
    /* a real ~/.ssh with a key, then a link in its place: a type change, and the key below it removed */
    m_new(RT("home/u/.bashrc", "content", "false") RT("home/u/.config/systemd/user", "content", "false")
          RT("home/u/.ssh", "content", "true"), NULL);
    dir(".", P); dir("home", P); dir("home/u", P); dir("home/u/.config", P); dir("home/u/.ssh", ""); reg("home/u/.ssh/authorized_keys", SHA(HA));
    m_write("before");
    m_new(HOME_ROOTS, NULL);
    dir(".", P); dir("home", P); dir("home/u", P); dir("home/u/.config", P); lnk("home/u/.ssh");
    m_write("after");
    REQUIRE_MSG(run() == 0, "%s", belay_err_msg());
    ASSERT_TRUE(strstr(rec("home/u/.ssh"), "\"outcome\":\"type_changed\",\"type\":\"lnk\",\"type_before\":\"dir\"") != NULL);
    ASSERT_TRUE(strstr(rec("home/u/.ssh/authorized_keys"), "\"outcome\":\"removed\"") != NULL);
}

/* V5-A6: sealed on one side only is the file's class changing, not a key's:
 * `class_changed`, whether the other manifest carries the same key (another
 * file there is sealed), another, or none. */
TEST(a_file_sealed_on_one_side_only_changed_class) {
    static const char CC[] = "{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"class_changed\"]}";
    IS(CC, pair(3, 5, 5, SEALED(HA), K1, 3, 5, 5, SHA(HA), NULL));
    IS(CC, pair(3, 5, 5, SHA(HB), NULL, 3, 5, 5, SEALED(HA), K1));
    for (int same_key = 0; same_key < 2; same_key++)
        for (int sealed_after = 0; sealed_after < 2; sealed_after++) {
            m_new(NULL, K1); dir(".", ""); reg("f", sealed_after ? SHA(HA) : SEALED(HA)); reg("g", SEALED(HB)); m_write("before");
            m_new(NULL, same_key ? K1 : K2); dir(".", ""); reg("f", sealed_after ? SEALED(HA) : SHA(HA)); reg("g", SEALED(HB));
            m_write("after");
            REQUIRE(run() == 0);
            IS(CC, rec("f"));
            /* the file sealed on both sides is the key's to say */
            IS(same_key ? "" : "{\"path\":\"g\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"sealed_key\"]}", rec("g"));
        }
    /* a different size proves it, as before; nothing of the sealed side's hash is carried */
    IS("{\"path\":\"f\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"size\"],"
       "\"before\":{\"size\":3},\"after\":{\"size\":4}}",
       pair(3, 5, 5, SHA(HA), NULL, 4, 5, 5, SEALED(HA), K1));
    /* a metadata difference beside it is listed, the outcome still unknown */
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"changed\":[\"mtime_ns\"],"
       "\"before\":{\"mtime_ns\":5},\"after\":{\"mtime_ns\":6},\"unknown\":[\"class_changed\"]}",
       pair(3, 5, 5, SHA(HA), NULL, 3, 6, 6, SEALED(HA), K1));
}

/* V5-D5: `not_read` after `writer_open`, `sealed_key` after it; V5-A6:
 * `class_changed` after that. */
TEST(the_new_reasons_come_last) {
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"writer_open\",\"not_read\"]}",
       pair(3, 5, 5, SHA(HA) ",\"writer_open\":true", NULL, 3, 5, 5, META, NULL));
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"writer_open\",\"sealed_key\"]}",
       pair(3, 5, 5, SHA(HA) ",\"writer_open\":true,\"sealed\":true", K1, 3, 5, 5, SEALED(HA), K2));
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"writer_open\",\"class_changed\"]}",
       pair(3, 5, 5, SHA(HA) ",\"writer_open\":true", NULL, 3, 5, 5, SEALED(HA), K1));
    IS("{\"path\":\"f\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"not_read\",\"class_changed\"]}",
       pair(3, 5, 5, META, NULL, 3, 5, 5, SEALED(HA), K1));
}

/* diff-fields O10 (and O9's v5 reason): an added file that was not read says
 * so. A removed one never does. */
TEST(an_added_meta_file_says_its_content_was_not_read) {
    m_new(NULL, NULL); dir(".", ""); m_write("before");
    m_new(NULL, NULL); dir(".", ""); reg("f", META); reg("g", SHA(HA)); m_write("after");
    REQUIRE(run() == 0);
    IS("{\"path\":\"f\",\"outcome\":\"added\",\"type\":\"reg\",\"content_not_read\":[\"not_read\"]}", rec("f"));
    IS("{\"path\":\"g\",\"outcome\":\"added\",\"type\":\"reg\"}", rec("g"));
    char b[700], a[700], t[700];
    snprintf(b, sizeof b, "%s/before", g_dir);
    snprintf(a, sizeof a, "%s/after", g_dir);
    snprintf(t, sizeof t, "%s/swap", g_dir);
    REQUIRE(rename(b, t) == 0 && rename(a, b) == 0 && rename(t, a) == 0 && run() == 0);
    IS("{\"path\":\"f\",\"outcome\":\"removed\",\"type\":\"reg\"}", rec("f"));
}

/* V5-D6: roots_differ, and nothing when the roots are equal. A found flag
 * that moved is a difference: the roots are compared whole. */
TEST(the_header_says_when_the_roots_differ) {
    m_new(RT("etc", "content", "true"), NULL); dir(".", P); m_write("before");
    m_new(RT("etc", "content", "true"), NULL); dir(".", P); m_write("after");
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(first_line(), "roots_differ") == NULL);
    ASSERT_TRUE(strstr(first_line(), ",\"after_excluded\":[]}") != NULL);
    m_new(RT("etc", "content", "false"), NULL); dir(".", P); m_write("after");
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(first_line(), ",\"after_excluded\":[],\"roots_differ\":true}") != NULL);
    m_new(RT("etc", "metadata", "true"), NULL); dir(".", P); m_write("after");
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(first_line(), ",\"roots_differ\":true}") != NULL);
    m_new(RT("etc", "content", "true") RT("usr", "metadata", "true"), NULL); dir(".", P); m_write("after");
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(first_line(), ",\"roots_differ\":true}") != NULL);
    m_new(NULL, NULL); dir(".", ""); m_write("after");
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(first_line(), ",\"roots_differ\":true}") != NULL);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_dv5_%d_%ld", (int)getpid(), (long)time(NULL));
    mkdir(g_dir, 0700);
    RUN(meta_on_both_sides);
    RUN(meta_on_one_side);
    RUN(sealed_entries_compare_under_one_key);
    RUN(a_file_sealed_on_one_side_only_changed_class);
    RUN(not_read_directories);
    RUN(a_first_ssh_directory_in_a_home_is_added);
    RUN(a_first_user_unit_in_a_home_is_added);
    RUN(a_path_under_a_partial_directory_on_the_other_side);
    RUN(a_link_on_the_way_to_a_root);
    RUN(a_link_where_a_root_is_looked_for);
    RUN(the_new_reasons_come_last);
    RUN(an_added_meta_file_says_its_content_was_not_read);
    RUN(the_header_says_when_the_roots_differ);
    char cmd[700];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    free(g_out);
    return belay_test_report();
}
