/*
 *  Manifest version 5 (test/expect/manifest-v5.md): the reader's key sets
 *  and entry rules, the writer's lines, and the walk over a listed set of
 *  roots -- partial and not_read directories, meta and sealed files, the
 *  sealing key, mounts by filesystem type, mark's trust by class -- and the
 *  roots of a system capture (test/expect/watch-system.md, WS-6 to WS-9).
 *
 *  BLAST RADIUS: every tree is the test's own, under its temporary
 *  directory; the system scope is never `/`.
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/manifest.h"
#include "belay/error.h"
#include "belay/hash.h"
#include "capture/capture.h"
#include "capture/fsops.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char g_dir[512], g_tree[600], g_m[600], g_m2[600], g_key[600];

/* ---------- text fixtures: the reader ---------- */

#define H_ "\"created_ns\":0,\"scopes\":[\"/s\"],\"hash\":\"sha256\",\"hash_max_bytes\":67108864," \
           "\"store_max_bytes\":65536,\"excluded\":[],\"walk_start_ns\":0,\"source\":null"
#define H4 "{\"belay_manifest\":4," H_ "}\n"
#define H5X(extra) "{\"belay_manifest\":5," H_ extra "}\n"
#define H5 H5X(",\"roots\":[],\"basis\":\"walk\"")
#define ROOTS1 ",\"roots\":[{\"path\":\"etc\",\"class\":\"content\",\"found\":true}," \
               "{\"path\":\"home/u/.ssh\",\"class\":\"content\",\"found\":false}," \
               "{\"path\":\"usr\",\"class\":\"metadata\",\"found\":true}]"
#define KEYID "0123456789abcdef"
#define HEX "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define ST_ "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,"
#define DIRX(p, stat, flags) "{\"path\":\"" p "\",\"type\":\"dir\",\"mode\":16877,\"uid\":0,\"gid\":0," stat \
    "\"ino\":2,\"dev\":1" flags "}\n"
#define NL_ ",\"nlink\":2"
#define DIR_(p, flags) DIRX(p, ST_, NL_ flags)
#define NR_(p, flags) DIRX(p, "", ",\"not_read\":true" flags)
#define ROOT_ DIR_(".", "")
#define REG_(p, tail) "{\"path\":\"" p "\",\"type\":\"reg\",\"mode\":33188,\"uid\":0,\"gid\":0,\"size\":0," \
    "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":3,\"dev\":1,\"nlink\":1" tail "}\n"
#define SHA_ ",\"sha256\":\"" HEX "\""
#define T4_(n) "{\"belay_manifest_end\":" #n ",\"vanished\":0,\"unreadable\":0,\"unstable\":0,\"mounts\":0," \
    "\"raced\":0,\"trusted\":0,\"reference\":\"none\",\"read_all\":\"check\",\"writer_open\":0,\"unguarded\":0"
#define T4(n) T4_(n) "}\n"
#define T5X(n, nr, meta, sealed, tail) T4_(n) ",\"not_read\":" #nr ",\"meta\":" #meta ",\"sealed\":" #sealed tail "}\n"
#define T5(n, nr, meta, sealed) T5X(n, nr, meta, sealed, ",\"carried\":0,\"racy\":[]")

static struct belay_entry g_e[64];
static size_t g_n;
static struct belay_manifest_header g_h;
static struct belay_root g_roots[64];
static char g_root_paths[64][256];
static struct belay_manifest_stats g_t;

/* Reads `text` as a manifest: 0 with the entries, header and trailer kept,
 * or -1 with belay_err. */
static int read_text(const char *text) {
    FILE *f = fopen(g_m, "wb");
    if (f == NULL) return -2;
    fputs(text, f);
    fclose(f);
    g_n = 0;
    struct belay_manifest_reader *r;
    if (belay_manifest_open(g_m, &r) == -1) return -1;
    g_h = *belay_manifest_header(r);
    for (size_t i = 0; i < g_h.n_roots && i < 64; i++) {
        g_roots[i] = g_h.roots[i];
        snprintf(g_root_paths[i], sizeof g_root_paths[i], "%s", g_h.roots[i].path);
        g_roots[i].path = g_root_paths[i];
    }
    g_h.roots = g_roots;                /* the reader's are gone with it */
    if (g_h.n_roots > 64) g_h.n_roots = 64;
    static struct belay_entry e;
    int got;
    while ((got = belay_manifest_next(r, &e)) == 1)
        if (g_n < 64) g_e[g_n++] = e;
    if (got == 0) g_t = *belay_manifest_trailer(r);
    belay_manifest_close(r);
    return got;
}

static const struct belay_entry *ent(const char *path) {
    for (size_t i = 0; i < g_n; i++)
        if (g_e[i].path_len == strlen(path) && memcmp(g_e[i].path, path, g_e[i].path_len) == 0) return &g_e[i];
    return NULL;
}

/* V5-1, V5-2, V5-10 to V5-12: a version 5 manifest of a whole scope. */
TEST(v5_of_a_whole_scope_reads) {
    REQUIRE(read_text(H5 ROOT_ REG_("f", SHA_) T5(2, 0, 0, 0)) == 0);
    ASSERT_EQ_INT(5, (int)g_h.version);
    ASSERT_EQ_INT(0, (int)g_h.n_roots);
    ASSERT_TRUE(!g_h.basis_events);
    ASSERT_EQ_STR("", g_h.sealed_key);
    ASSERT_EQ_INT(0, (int)g_t.carried);
    ASSERT_EQ_INT(0, (int)g_t.racy_listed);
}

/* V5-2: the roots, each with its class and whether it was found. */
TEST(v5_roots_are_read) {
    REQUIRE(read_text(H5X(ROOTS1 ",\"basis\":\"walk\"") DIR_(".", ",\"partial\":true") T5(1, 0, 0, 0)) == 0);
    REQUIRE(g_h.n_roots == 3);
    ASSERT_EQ_STR("etc", g_roots[0].path);
    ASSERT_TRUE(g_roots[0].cls == BELAY_ROOT_CONTENT && g_roots[0].found);
    ASSERT_EQ_STR("home/u/.ssh", g_roots[1].path);
    ASSERT_TRUE(!g_roots[1].found);
    ASSERT_TRUE(g_roots[2].cls == BELAY_ROOT_METADATA);
    ASSERT_TRUE(belay_manifest_lists_root(&g_h, "home/u/.ssh", 11));
    ASSERT_TRUE(!belay_manifest_lists_root(&g_h, "home/u", 6));
    ASSERT_TRUE(!belay_manifest_lists_root(&g_h, "home/u/.sshx", 12));
}

/* V5-R1, V5-R2: each version by its own key set, strictly; v1 to v4 read as
 * no roots, a walk, no entry flagged. */
TEST(each_version_is_read_by_its_own_keys) {
    REQUIRE(read_text(H4 ROOT_ REG_("f", SHA_) T4(2)) == 0);
    ASSERT_EQ_INT(4, (int)g_h.version);
    ASSERT_EQ_INT(0, (int)g_h.n_roots);
    ASSERT_TRUE(!g_h.basis_events);
    ASSERT_EQ_INT(0, (int)(g_t.not_read + g_t.meta + g_t.sealed + g_t.carried + g_t.racy_listed));
    ASSERT_TRUE(!ent("f")->meta && !ent("f")->sealed && !ent(".")->partial && !ent(".")->not_read);
    static const struct { const char *what, *text, *msg; } C[] = {
        { "v6", "{\"belay_manifest\":6," H_ ",\"roots\":[],\"basis\":\"walk\"}\n" ROOT_ T5(1, 0, 0, 0), "format version 6" },
        { "v5 header without roots", H5X(",\"basis\":\"walk\"") ROOT_ T5(1, 0, 0, 0), "missing roots" },
        { "v5 header without basis", H5X(",\"roots\":[]") ROOT_ T5(1, 0, 0, 0), "missing basis" },
        { "v5 header, basis first", H5X(",\"basis\":\"walk\",\"roots\":[]") ROOT_ T5(1, 0, 0, 0), "canonical order" },
        { "v4 header with roots", "{\"belay_manifest\":4," H_ ",\"roots\":[]}\n" ROOT_ T4(1), "unknown key \"roots\"" },
        { "v4 header with basis", "{\"belay_manifest\":4," H_ ",\"basis\":\"walk\"}\n" ROOT_ T4(1), "unknown key \"basis\"" },
        { "v5 with a v4 trailer", H5 ROOT_ T4(1), "missing not_read" },
        { "v5 trailer without racy", H5 ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0"), "racy" },
        { "v5 trailer without carried", H5 ROOT_ T5X(1, 0, 0, 0, ",\"racy\":[]"), "missing carried" },
        { "v4 with a v5 trailer", H4 ROOT_ T5(1, 0, 0, 0), "unknown key \"not_read\"" },
        { "v4 entry with meta", H4 ROOT_ REG_("f", ",\"meta\":true") T4(2), "unknown key \"meta\"" },
        { "v4 entry with sealed", H4 ROOT_ REG_("f", SHA_ ",\"sealed\":true") T4(2), "unknown key \"sealed\"" },
        { "v4 entry with not_read", H4 ROOT_ NR_("d", "") T4(2), "unknown key \"not_read\"" },
        { "v4 entry with partial", H4 DIR_(".", ",\"partial\":true") T4(1), "unknown key \"partial\"" },
        { "an unknown key in v5", H5 ROOT_ REG_("f", SHA_ ",\"later\":true") T5(2, 0, 0, 0), "unknown key \"later\"" },
        { "flags out of order", H5 ROOT_ REG_("f", SHA_ ",\"sealed\":true,\"writer_open\":true") T5(2, 0, 0, 1), "canonical order" },
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        const int r = read_text(C[i].text);
        if (r != -1) { BELAY_FAIL("%s: read, want refused", C[i].what); continue; }
        if (strstr(belay_err_msg(), C[i].msg) == NULL) BELAY_FAIL("%s: \"%s\", want \"%s\"", C[i].what, belay_err_msg(), C[i].msg);
    }
}

/* V5-2, V5-3, V5-10: the header's values. */
TEST(v5_header_values_are_checked) {
#define RT(p, c, f) "{\"path\":\"" p "\",\"class\":\"" c "\",\"found\":" f "}"
#define HR(roots) H5X(",\"roots\":[" roots "],\"basis\":\"walk\"") DIR_(".", ",\"partial\":true") T5(1, 0, 0, 0)
    static const struct { const char *what, *text, *msg; } C[] = {
        { "roots out of order", HR(RT("usr", "metadata", "true") "," RT("etc", "content", "true")), "roots out of order" },
        { "a root twice", HR(RT("etc", "content", "true") "," RT("etc", "content", "true")), "roots out of order" },
        { "a class unknown", HR(RT("etc", "contents", "true")), "class is not content or metadata" },
        { "found a string", HR("{\"path\":\"etc\",\"class\":\"content\",\"found\":\"true\"}"), "true or false" },
        { "found missing", HR("{\"path\":\"etc\",\"class\":\"content\"}"), "path, class and found" },
        { "a root's keys out of order", HR("{\"class\":\"content\",\"path\":\"etc\",\"found\":true}"), "canonical order" },
        { "a root with another key", HR("{\"path\":\"etc\",\"class\":\"content\",\"found\":true,\"n\":1}"), "unknown key" },
        { "the scope root as a root", HR(RT(".", "content", "true")), "canonical relative path" },
        { "an absolute root", HR(RT("/etc", "content", "true")), "canonical relative path" },
        { "a root with ..", HR(RT("etc/../x", "content", "true")), "canonical relative path" },
        { "roots not objects", H5X(",\"roots\":[\"etc\"],\"basis\":\"walk\"") ROOT_ T5(1, 0, 0, 0), "array of objects" },
        { "a basis unknown", H5X(",\"roots\":[],\"basis\":\"stat\"") ROOT_ T5(1, 0, 0, 0), "basis is not walk or events" },
        { "sealed_key too short", H5X(",\"roots\":[],\"sealed_key\":\"0123\",\"basis\":\"walk\"") ROOT_ T5(1, 0, 0, 0), "16 lowercase hex" },
        { "sealed_key upper case", H5X(",\"roots\":[],\"sealed_key\":\"0123456789ABCDEF\",\"basis\":\"walk\"") ROOT_ T5(1, 0, 0, 0), "16 lowercase hex" },
        { "sealed_key, nothing sealed", H5X(",\"roots\":[],\"sealed_key\":\"" KEYID "\",\"basis\":\"walk\"") ROOT_ T5(1, 0, 0, 0),
          "a sealed_key without sealed entries" },
        { "sealed, no sealed_key", H5 ROOT_ REG_("f", SHA_ ",\"sealed\":true") T5(2, 0, 0, 1), "sealed entries without a sealed_key" },
        { "false on a line of its own", H5 ROOT_ REG_("f", SHA_ ",\"sealed\":false") T5(2, 0, 0, 0), "malformed value" },
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        const int r = read_text(C[i].text);
        if (r != -1) { BELAY_FAIL("%s: read, want refused", C[i].what); continue; }
        if (strstr(belay_err_msg(), C[i].msg) == NULL) BELAY_FAIL("%s: \"%s\", want \"%s\"", C[i].what, belay_err_msg(), C[i].msg);
    }
    REQUIRE(read_text(H5X(",\"roots\":[],\"sealed_key\":\"" KEYID "\",\"basis\":\"walk\"") ROOT_
                      REG_("f", SHA_ ",\"sealed\":true") T5(2, 0, 0, 1)) == 0);
    ASSERT_EQ_STR(KEYID, g_h.sealed_key);
    ASSERT_TRUE(ent("f")->sealed);
}

/* V5-7 to V5-12: the trailer's counts are the entries', a walk carries
 * nothing and names no racy path, an event capture's racy paths are sorted. */
TEST(v5_trailer_values_are_checked) {
#define HE H5X(",\"roots\":[],\"basis\":\"events\"")
    static const struct { const char *what, *text, *msg; } C[] = {
        { "not_read miscounted", H5 ROOT_ NR_("d", "") T5(2, 0, 0, 0), "not_read" },
        { "meta miscounted", H5 ROOT_ REG_("f", ",\"meta\":true") T5(2, 0, 2, 0), "meta" },
        { "sealed miscounted", H5X(",\"roots\":[],\"sealed_key\":\"" KEYID "\",\"basis\":\"walk\"") ROOT_
          REG_("f", SHA_ ",\"sealed\":true") T5(2, 0, 0, 2), "sealed" },
        { "a walk that carries", H5 ROOT_ T5X(1, 0, 0, 0, ",\"carried\":1,\"racy\":[]"), "a walk carries no entry" },
        { "a walk with racy paths", H5 ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0,\"racy\":[\"f\"]"), "a walk names no racy path" },
        { "carried over the entries", HE ROOT_ T5X(1, 0, 0, 0, ",\"carried\":2,\"racy\":[]"), "carries more entries" },
        { "racy out of order", HE ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0,\"racy\":[\"b\",\"a\"]"), "racy paths out of order" },
        { "racy twice", HE ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0,\"racy\":[\"a\",\"a\"]"), "racy paths out of order" },
        { "a racy path absolute", HE ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0,\"racy\":[\"/a\"]"), "canonical relative path" },
        { "racy and racy_b64", HE ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0,\"racy\":[],\"racy_b64\":[\"/w==\"]"), "exactly one of racy" },
        { "racy_b64 all UTF-8", HE ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0,\"racy_b64\":[\"YQ==\"]"), "all UTF-8" },
        { "racy an integer", HE ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0,\"racy\":3"), "array of strings" },
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        const int r = read_text(C[i].text);
        if (r != -1) { BELAY_FAIL("%s: read, want refused", C[i].what); continue; }
        if (strstr(belay_err_msg(), C[i].msg) == NULL) BELAY_FAIL("%s: \"%s\", want \"%s\"", C[i].what, belay_err_msg(), C[i].msg);
    }
    REQUIRE(read_text(HE ROOT_ REG_("a", SHA_) REG_("b", SHA_) T5X(3, 0, 0, 0, ",\"carried\":1,\"racy\":[\"a\",\"b\"]")) == 0);
    ASSERT_TRUE(g_h.basis_events);
    ASSERT_EQ_INT(1, (int)g_t.carried);
    ASSERT_EQ_INT(2, (int)g_t.racy_listed);
    REQUIRE(read_text(HE ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0,\"racy_b64\":[\"YQ==\",\"/w==\"]")) == 0);
    ASSERT_EQ_INT(2, (int)g_t.racy_listed);
}

/* V5-4, V5-4b, V5-5, V5-6 and the entry rules V5-E1, V5-E2, V5-E8. */
TEST(v5_entry_rules) {
#define K5 H5X(",\"roots\":[],\"sealed_key\":\"" KEYID "\",\"basis\":\"walk\"")
    static const struct { const char *what, *text, *msg; } C[] = {
        /* V5-4, V5-E8 */
        { "not_read with size", H5 ROOT_ DIRX("d", "\"size\":1,", ",\"not_read\":true") T5(2, 1, 0, 0), "on a not_read directory" },
        { "not_read with nlink", H5 ROOT_ DIRX("d", "", NL_ ",\"not_read\":true") T5(2, 1, 0, 0), "on a not_read directory" },
        { "not_read with mtime_ns", H5 ROOT_ DIRX("d", "\"mtime_ns\":1,", ",\"not_read\":true") T5(2, 1, 0, 0), "on a not_read directory" },
        { "not_read with ctime_ns", H5 ROOT_ DIRX("d", "\"ctime_ns\":1,", ",\"not_read\":true") T5(2, 1, 0, 0), "on a not_read directory" },
        { "a directory without size", H5 ROOT_ DIRX("d", "\"mtime_ns\":1,\"ctime_ns\":1,", NL_) T5(2, 0, 0, 0), "missing size" },
        { "a directory without nlink", H5 ROOT_ DIRX("d", ST_, "") T5(2, 0, 0, 0), "missing nlink" },
        { "not_read on a file", H5 ROOT_ REG_("f", SHA_ ",\"not_read\":true") T5(2, 1, 0, 0), "on a non-directory" },
        { "not_read and unreadable", H5 ROOT_ DIRX("d", "", ",\"unreadable\":true,\"not_read\":true") T5X(2, 1, 0, 0, ",\"carried\":0,\"racy\":[]"),
          "exclusive" },
        { "not_read and mount", H5 ROOT_ DIRX("d", "", ",\"mount\":true,\"not_read\":true") T5(2, 1, 0, 0), "exclusive" },
        { "not_read and unstable", H5 ROOT_ DIRX("d", "", ",\"unstable\":true,\"not_read\":true") T5(2, 1, 0, 0), "exclusive" },
        /* V5-E2 */
        { "an entry below not_read", H5 ROOT_ NR_("d", "") REG_("d/f", SHA_) T5(3, 1, 0, 0), "entry below a not_read directory" },
        { "entries under a not_read root", H5 NR_(".", "") REG_("f", SHA_) T5(2, 1, 0, 0), "under an unreadable scope root" },
        /* V5-4b */
        { "partial on a file", H5 ROOT_ REG_("f", SHA_ ",\"partial\":true") T5(2, 0, 0, 0), "on a non-directory" },
        { "partial and not_read", H5 ROOT_ DIRX("d", "", ",\"not_read\":true,\"partial\":true") T5(2, 1, 0, 0), "partial with" },
        { "partial and unreadable", H5 ROOT_ DIR_("d", ",\"unreadable\":true,\"partial\":true") T5(2, 0, 0, 0), "partial with" },
        { "partial and mount", H5 ROOT_ DIRX("d", ST_, NL_ ",\"mount\":true,\"partial\":true") T5(2, 0, 0, 0), "partial with" },
        /* V5-5, V5-E1 */
        { "meta and sha256", H5 ROOT_ REG_("f", SHA_ ",\"meta\":true") T5(2, 0, 1, 0), "both sha256 and unverified" },
        { "meta and unverified", H5 ROOT_ REG_("f", ",\"unverified\":true,\"unreadable\":true,\"meta\":true") T5(2, 0, 1, 0),
          "both sha256 and unverified" },
        { "a file with none of the three", H5 ROOT_ REG_("f", "") T5(2, 0, 0, 0), "neither sha256 nor unverified" },
        { "meta on a directory", H5 ROOT_ DIR_("d", ",\"meta\":true") T5(2, 0, 1, 0), "on a non-regular file" },
        /* V5-6 */
        { "sealed without sha256", K5 ROOT_ REG_("f", ",\"meta\":true,\"sealed\":true") T5(2, 0, 1, 1), "sealed without sha256" },
        { "sealed with stored", K5 ROOT_ REG_("f", SHA_ ",\"stored\":\"" HEX "\",\"sealed\":true") T5(2, 0, 0, 1), "sealed with stored" },
        { "sealed on a directory", K5 ROOT_ DIR_("d", ",\"sealed\":true") T5(2, 0, 0, 1), "on a non-regular file" },
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        const int r = read_text(C[i].text);
        if (r != -1) { BELAY_FAIL("%s: read, want refused", C[i].what); continue; }
        if (strstr(belay_err_msg(), C[i].msg) == NULL) BELAY_FAIL("%s: \"%s\", want \"%s\"", C[i].what, belay_err_msg(), C[i].msg);
    }
    /* What the rules allow. */
    REQUIRE(read_text(K5 DIR_(".", ",\"partial\":true") NR_("a", "") DIRX("b", "", ",\"raced\":true,\"not_read\":true")
                      DIR_("c", ",\"unstable\":true,\"partial\":true") REG_("m", ",\"meta\":true")
                      REG_("s", SHA_ ",\"writer_open\":true,\"sealed\":true")
                      "{\"belay_manifest_end\":6,\"vanished\":0,\"unreadable\":0,\"unstable\":1,\"mounts\":0,\"raced\":1,"
                      "\"trusted\":0,\"reference\":\"none\",\"read_all\":\"check\",\"writer_open\":1,\"unguarded\":0,"
                      "\"not_read\":2,\"meta\":1,\"sealed\":1,\"carried\":0,\"racy\":[]}\n") == 0);
    ASSERT_TRUE(ent(".")->partial && ent("a")->not_read && ent("b")->raced && ent("c")->partial && ent("c")->unstable);
    ASSERT_TRUE(ent("m")->meta && !ent("m")->has_hash && ent("s")->sealed && ent("s")->writer_open);
    ASSERT_EQ_INT(2, (int)g_t.not_read);
    ASSERT_EQ_INT(1, (int)g_t.meta);
    ASSERT_EQ_INT(1, (int)g_t.sealed);
    ASSERT_EQ_INT(2, (int)g_t.sealing);             /* checkpoint-v3 C3-3: not_read directories seal */
}

/* ---------- real trees: the walk ---------- */

static void mk(const char *rel, mode_t mode) {
    char p[1200];
    snprintf(p, sizeof p, "%s/%s", g_tree, rel);
    if (mkdir(p, 0755) != 0 && errno != EEXIST) perror(p);
    if (chmod(p, mode) != 0) perror(p);
}

static void wr(const char *rel, const char *data, mode_t mode) {
    char p[1200];
    snprintf(p, sizeof p, "%s/%s", g_tree, rel);
    const int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) { perror(p); return; }
    if (write(fd, data, strlen(data)) < 0) perror(p);
    close(fd);
    /* setgid: an owner who is not root may set it only when the file's group
     * is one of theirs, and on BSD a new file takes its directory's group
     * (wheel under /tmp), where chmod then drops the bit in silence. So the
     * file is given the caller's own group first. */
    if ((mode & S_ISGID) && chown(p, (uid_t)-1, getegid()) != 0) perror(p);
    if (chmod(p, mode) != 0) perror(p);
}

/* Whether the setgid bit asked for usr/bin/wall is there: what the test may
 * expect of it is read back, never assumed. */
static bool wall_is_setgid(void) {
    char p[1200];
    struct stat st;
    snprintf(p, sizeof p, "%s/usr/bin/wall", g_tree);
    return stat(p, &st) == 0 && (st.st_mode & S_ISGID) != 0;
}

static void rm_rf(const char *path) {
    char cmd[1400];
    snprintf(cmd, sizeof cmd, "chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", path, path);
    if (system(cmd) != 0) { /* best effort */ }
}

static void pause_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* A machine in small: what the roots below read, read as metadata, and do
 * not read. */
static void tree(void) {
    rm_rf(g_tree);
    unlink(g_key);
    mkdir(g_tree, 0755);
    chmod(g_tree, 0755);
    mk("etc", 0755); mk("etc/sub", 0755);
    wr("etc/passwd", "root:x:0:0:root:/root:/bin/sh\nu:x:1000:1000::/home/u:/bin/sh\n", 0644);
    wr("etc/shadow", "root:*:1::::::\n", 0640);
    wr("etc/sub/x", "x\n", 0644);
    mk("usr", 0755); mk("usr/bin", 0755); mk("usr/local", 0755); mk("usr/local/bin", 0755);
    wr("usr/bin/tool", "tool\n", 0755);
    wr("usr/bin/su", "su\n", 04755);
    wr("usr/bin/wall", "wall\n", 02755);
    wr("usr/local/bin/l", "local\n", 0755);
    mk("var", 0755); mk("var/log", 0755); mk("var/lib", 0755);
    wr("var/log/syslog", "log\n", 0644);
    wr("var/lib/x", "x\n", 0644);
    mk("root", 0700);
    wr("root/secret", "s3cret\n", 0644);
    wr("root/.bashrc", "alias ll=ls\n", 0600);
    mk("home", 0755); mk("home/u", 0750); mk("home/u/.ssh", 0700); mk("home/u/Documents", 0755); mk("home/other", 0755);
    wr("home/u/.ssh/authorized_keys", "ssh-ed25519 AAAA u@h\n", 0600);
    wr("home/u/.bashrc", "export A=1\n", 0600);
    wr("home/u/notes.txt", "private\n", 0644);
    wr("home/u/Documents/d.txt", "d\n", 0644);
    wr("home/other/f", "f\n", 0644);
    wr("home/stray", "a file beside the homes\n", 0644);
    mk("proc", 0555);
    wr("top.txt", "a file under the scope root\n", 0644);
    char l[1200];
    snprintf(l, sizeof l, "%s/bin", g_tree);
    if (symlink("usr/bin", l) != 0) perror(l);
    snprintf(l, sizeof l, "%s/home/u/link", g_tree);
    if (symlink("notes.txt", l) != 0) perror(l);
    pause_ms(30);                   /* every ctime is before the first walk's start */
}

static const struct belay_root ROOTS[] = {
    { "etc", BELAY_ROOT_CONTENT, false, false },
    { "home/u/.bashrc", BELAY_ROOT_CONTENT, false, true },
    { "home/u/.config/systemd/user", BELAY_ROOT_CONTENT, false, false },
    { "home/u/.profile", BELAY_ROOT_CONTENT, false, true },
    { "home/u/.ssh", BELAY_ROOT_CONTENT, false, false },
    { "root", BELAY_ROOT_CONTENT, false, false },
    { "root/.bashrc", BELAY_ROOT_CONTENT, false, true },
    { "usr", BELAY_ROOT_METADATA, false, false },
    { "usr/local", BELAY_ROOT_CONTENT, false, false },
    { "var", BELAY_ROOT_METADATA, false, false },
};
static const char *const NOT_READ[] = { "var/log" };

static const struct fsops *g_real;
static struct fsops g_ops;

static struct belay_manifest_opts opts_roots(const char *previous) {
    const struct belay_manifest_opts o = {
        .hash_max_bytes = 1u << 20, .store_max_bytes = 4096, .previous = previous,
        .roots = ROOTS, .n_roots = sizeof ROOTS / sizeof ROOTS[0],
        .not_read = NOT_READ, .n_not_read = 1, .sealing_key_path = g_key,
    };
    return o;
}

/* Captures the tree by ROOTS into `out` and reads it back. 0, or -1. */
static int capture_roots(const char *out, const char *previous, struct belay_manifest_stats *st) {
    const struct belay_manifest_opts o = opts_roots(previous);
    if (capture_write(&g_ops, out, g_tree, &o, st) != 0) return -1;
    char *text = NULL;
    size_t cap = 0;
    FILE *f = fopen(out, "rb");
    if (f == NULL) return -1;
    const ssize_t n = getdelim(&text, &cap, '\0', f);
    fclose(f);
    if (n < 0) { free(text); return -1; }
    char keep[600];
    snprintf(keep, sizeof keep, "%s", g_m);
    snprintf(g_m, sizeof g_m, "%s/read.ndjson", g_dir);
    const int r = read_text(text);
    snprintf(g_m, sizeof g_m, "%s", keep);
    free(text);
    return r;
}

/* The line of `out` whose path is `path`, or the header ("") / trailer (NULL). */
static char g_line[70000];
static const char *line_of(const char *out, const char *path) {
    FILE *f = fopen(out, "rb");
    if (f == NULL) return "";
    char want[700];
    if (path != NULL) snprintf(want, sizeof want, "{\"path\":\"%s\",", path);
    char last[sizeof g_line] = "";
    bool first = true, hit = false;
    while (fgets(g_line, sizeof g_line, f) != NULL) {
        if (path != NULL && ((first && path[0] == '\0') || strncmp(g_line, want, strlen(want)) == 0)) { hit = true; break; }
        first = false;
        snprintf(last, sizeof last, "%s", g_line);
    }
    fclose(f);
    if (path == NULL) { snprintf(g_line, sizeof g_line, "%s", last); return g_line; }
    return hit ? g_line : "";
}

static void sha_hex(const void *data, size_t n, char hex[65]) {
    struct belay_sha256 h;
    uint8_t d[32];
    belay_sha256_init(&h);
    belay_sha256_update(&h, data, n);
    belay_sha256_final(&h, d);
    belay_hex_encode(hex, d, sizeof d);
}

/* HMAC-SHA256 (RFC 2104) of `msg` under a 32-byte key, written here from the
 * definition, not through the code under test. */
static void hmac_hex(const uint8_t key[32], const char *msg, char hex[65]) {
    uint8_t ipad[64], opad[64], inner[32], out[32];
    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);
    for (int i = 0; i < 32; i++) { ipad[i] ^= key[i]; opad[i] ^= key[i]; }
    struct belay_sha256 h;
    belay_sha256_init(&h);
    belay_sha256_update(&h, ipad, 64);
    belay_sha256_update(&h, msg, strlen(msg));
    belay_sha256_final(&h, inner);
    belay_sha256_init(&h);
    belay_sha256_update(&h, opad, 64);
    belay_sha256_update(&h, inner, 32);
    belay_sha256_final(&h, out);
    belay_hex_encode(hex, out, 32);
}

static bool read_key(uint8_t key[32]) {
    const int fd = open(g_key, O_RDONLY);
    if (fd == -1) return false;
    const bool ok = read(fd, key, 32) == 32;
    close(fd);
    return ok;
}

/* V5-R2, V5-10 to V5-12: belay writes version 5; a capture of a whole scope
 * has no roots, and is as version 4 in every other respect. */
TEST(a_whole_scope_is_written_as_v5_with_no_roots) {
    tree();
    const struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20, .store_max_bytes = 4096 };
    REQUIRE(capture_write(&g_ops, g_m2, g_tree, &o, NULL) == 0);
    ASSERT_TRUE(strncmp(line_of(g_m2, ""), "{\"belay_manifest\":5,", 20) == 0);
    ASSERT_TRUE(strstr(line_of(g_m2, ""), ",\"source\":null,\"roots\":[],\"basis\":\"walk\"}\n") != NULL);
    ASSERT_TRUE(strstr(line_of(g_m2, NULL), ",\"unguarded\":") != NULL);
    ASSERT_TRUE(strstr(line_of(g_m2, NULL), ",\"not_read\":0,\"meta\":0,\"sealed\":0,\"carried\":0,\"racy\":[]}\n") != NULL);
    /* nothing of version 5 on an entry: a mode-640 file is read and hashed plainly, a
     * directory is entered, a file under the root is recorded */
    ASSERT_TRUE(strstr(line_of(g_m2, "etc/shadow"), "\"sealed\"") == NULL);
    ASSERT_TRUE(strstr(line_of(g_m2, "etc/shadow"), "\"sha256\"") != NULL);
    ASSERT_TRUE(strstr(line_of(g_m2, "."), "\"partial\"") == NULL);
    ASSERT_TRUE(line_of(g_m2, "top.txt")[0] != '\0');
    ASSERT_TRUE(line_of(g_m2, "var/log/syslog")[0] != '\0');
    ASSERT_TRUE(strstr(line_of(g_m2, "usr/bin/tool"), "\"sha256\"") != NULL);
    ASSERT_TRUE(access(g_key, F_OK) != 0);          /* no key made: nothing needed one (V5-R3) */
}

/* V5-E3, V5-4, V5-4b: the directories on the way to a root are partial;
 * their other directories are not_read, their other files not recorded. */
TEST(roots_make_partial_and_not_read_directories) {
    tree();
    struct belay_manifest_stats st;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0);
    REQUIRE(ent(".") != NULL && ent("home") != NULL && ent("home/u") != NULL);
    ASSERT_TRUE(ent(".")->partial && ent("home")->partial && ent("home/u")->partial);
    ASSERT_TRUE(!ent("etc")->partial && !ent("usr")->partial && !ent("home/u/.ssh")->partial);
    /* a partial directory is recorded as any directory: its four stat keys are there */
    ASSERT_TRUE(strstr(line_of(g_m2, "home/u"), "\"size\":") != NULL && strstr(line_of(g_m2, "home/u"), "\"nlink\":") != NULL);
    ASSERT_TRUE(strstr(line_of(g_m2, "home/u"), "\"partial\":true}") != NULL);
    /* other directories: recorded, not entered, without what moves with their contents */
    static const char *const NR[] = { "proc", "home/other", "home/u/Documents", "var/log" };
    for (size_t i = 0; i < 4; i++) {
        REQUIRE_MSG(ent(NR[i]) != NULL, "%s is not recorded", NR[i]);
        ASSERT_TRUE(ent(NR[i])->not_read);
        const char *l = line_of(g_m2, NR[i]);
        if (strstr(l, "\"size\"") || strstr(l, "\"mtime_ns\"") || strstr(l, "\"ctime_ns\"") || strstr(l, "\"nlink\""))
            BELAY_FAIL("%s carries a key V5-4 leaves out: %s", NR[i], l);
        if (!strstr(l, "\"mode\":") || !strstr(l, "\"uid\":") || !strstr(l, "\"ino\":") || !strstr(l, ",\"not_read\":true}"))
            BELAY_FAIL("%s: %s", NR[i], l);
    }
    ASSERT_TRUE(ent("home/other/f") == NULL && ent("home/u/Documents/d.txt") == NULL && ent("var/log/syslog") == NULL);
    /* other files: not recorded at all; a link only directly under the scope root */
    ASSERT_TRUE(ent("top.txt") == NULL && ent("home/stray") == NULL && ent("home/u/notes.txt") == NULL);
    ASSERT_TRUE(ent("home/u/link") == NULL);
    REQUIRE(ent("bin") != NULL);
    ASSERT_TRUE(ent("bin")->type == BELAY_T_LNK);
    /* what the roots name is recorded */
    ASSERT_TRUE(ent("home/u/.ssh/authorized_keys") != NULL && ent("home/u/.bashrc") != NULL && ent("etc/sub/x") != NULL);
    ASSERT_EQ_INT(4, (int)st.not_read);
    ASSERT_EQ_INT(4, (int)st.sealing);
    ASSERT_EQ_INT(0, (int)(st.unstable + st.raced + st.unreadable));
    /* V5-2: every root looked for, found or not, sorted */
    REQUIRE(g_h.n_roots == sizeof ROOTS / sizeof ROOTS[0]);
    for (size_t i = 0; i < g_h.n_roots; i++) {
        ASSERT_EQ_STR(ROOTS[i].path, g_roots[i].path);
        ASSERT_TRUE(g_roots[i].cls == ROOTS[i].cls);
        const bool absent = strcmp(ROOTS[i].path, "home/u/.profile") == 0 || strcmp(ROOTS[i].path, "home/u/.config/systemd/user") == 0;
        if (g_roots[i].found == absent) BELAY_FAIL("%s: found %d", ROOTS[i].path, (int)g_roots[i].found);
    }
    ASSERT_TRUE(strstr(line_of(g_m2, ""), "{\"path\":\"home/u/.profile\",\"class\":\"content\",\"found\":false}") != NULL);
    ASSERT_TRUE(strstr(line_of(g_m2, ""), "{\"path\":\"usr\",\"class\":\"metadata\",\"found\":true}") != NULL);
}

/* V5-E4, V5-5: under a metadata root a file is not read, unless it is
 * setuid or setgid; a longer content root wins inside it (WS-9). */
TEST(a_metadata_root_reads_only_what_grants_privilege) {
    tree();
    struct belay_manifest_stats st;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0);
    REQUIRE(ent("usr/bin/tool") != NULL && ent("usr/bin/su") != NULL && ent("usr/bin/wall") != NULL && ent("var/lib/x") != NULL);
    ASSERT_TRUE(ent("usr/bin/tool")->meta && !ent("usr/bin/tool")->has_hash && !ent("usr/bin/tool")->unverified);
    ASSERT_TRUE(ent("var/lib/x")->meta);
    ASSERT_TRUE(strstr(line_of(g_m2, "usr/bin/tool"), ",\"meta\":true}") != NULL);
    char want[65];
    sha_hex("su\n", 3, want);
    ASSERT_TRUE(!ent("usr/bin/su")->meta && !ent("usr/bin/su")->sealed);
    ASSERT_EQ_STR(want, ent("usr/bin/su")->sha256_hex);
    /* setgid: read, where the filesystem let the bit be set (wr); a file without it is meta */
    const bool setgid = wall_is_setgid();
    sha_hex("wall\n", 5, want);
    if (setgid) ASSERT_EQ_STR(want, ent("usr/bin/wall")->sha256_hex);
    ASSERT_TRUE(ent("usr/bin/wall")->meta == !setgid);
    REQUIRE(ent("usr/local/bin/l") != NULL);
    sha_hex("local\n", 6, want);
    ASSERT_TRUE(!ent("usr/local/bin/l")->meta);
    ASSERT_EQ_STR(want, ent("usr/local/bin/l")->sha256_hex);
    ASSERT_EQ_INT(setgid ? 2 : 3, (int)st.meta);
}

/* V5-E5, V5-6, V5-3, V5-R3: under a content root a file others cannot read
 * -- by its mode, or by a directory above it -- carries a keyed hash. */
TEST(a_file_others_cannot_read_is_sealed) {
    tree();
    struct belay_manifest_stats st;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0);
    uint8_t key[32];
    struct stat ks;
    REQUIRE(read_key(key) && stat(g_key, &ks) == 0);
    ASSERT_EQ_INT(32, (int)ks.st_size);
    ASSERT_EQ_INT(0600, (int)(ks.st_mode & 07777));
    char want[65], id[65];
    sha_hex(key, 32, id);
    id[16] = '\0';
    ASSERT_EQ_STR(id, g_h.sealed_key);
    /* its own mode: 640 */
    REQUIRE(ent("etc/shadow") != NULL && ent("root/secret") != NULL && ent("home/u/.ssh/authorized_keys") != NULL);
    hmac_hex(key, "root:*:1::::::\n", want);
    ASSERT_TRUE(ent("etc/shadow")->sealed && !ent("etc/shadow")->has_stored);
    ASSERT_EQ_STR(want, ent("etc/shadow")->sha256_hex);
    ASSERT_TRUE(strstr(line_of(g_m2, "etc/shadow"), ",\"sealed\":true}") != NULL);
    /* a directory above it: root is 700, the file itself 644 */
    hmac_hex(key, "s3cret\n", want);
    ASSERT_TRUE(ent("root/secret")->sealed);
    ASSERT_EQ_STR(want, ent("root/secret")->sha256_hex);
    ASSERT_TRUE(ent("home/u/.ssh/authorized_keys")->sealed);
    /* readable by others, under directories they can search: plain */
    sha_hex("x\n", 2, want);
    ASSERT_TRUE(!ent("etc/sub/x")->sealed);
    ASSERT_EQ_STR(want, ent("etc/sub/x")->sha256_hex);
    /* the shell startup files are kept as ordinary content, wherever they are */
    sha_hex("alias ll=ls\n", 12, want);
    REQUIRE(ent("root/.bashrc") != NULL && ent("home/u/.bashrc") != NULL);
    ASSERT_TRUE(!ent("root/.bashrc")->sealed && !ent("home/u/.bashrc")->sealed);
    ASSERT_EQ_STR(want, ent("root/.bashrc")->sha256_hex);
    /* not under a metadata root: a setuid file there is hashed plainly whatever its mode */
    ASSERT_TRUE(!ent("usr/bin/su")->sealed);
    ASSERT_EQ_INT(3, (int)st.sealed);
    /* the key is never rewritten: a second capture seals to the same hashes */
    char first[65];
    snprintf(first, sizeof first, "%s", ent("etc/shadow")->sha256_hex);
    uint8_t again[32];
    REQUIRE(capture_roots(g_m2, NULL, NULL) == 0 && read_key(again));
    ASSERT_TRUE(memcmp(key, again, 32) == 0);
    ASSERT_EQ_STR(first, ent("etc/shadow")->sha256_hex);
}

/* V5-3, V5-R3: no sealed entry, no key and no sealed_key; and a capture that
 * must seal with no key to use fails, never writes a plain hash. */
TEST(the_key_is_made_only_when_needed) {
    tree();
    static const struct belay_root R[] = { { "usr", BELAY_ROOT_METADATA, false, false } };
    struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20, .roots = R, .n_roots = 1, .sealing_key_path = g_key };
    REQUIRE(capture_write(&g_ops, g_m2, g_tree, &o, NULL) == 0);
    ASSERT_TRUE(access(g_key, F_OK) != 0);
    ASSERT_TRUE(strstr(line_of(g_m2, ""), "sealed_key") == NULL);
    o = opts_roots(NULL);
    o.sealing_key_path = NULL;
    ASSERT_EQ_INT(-1, capture_write(&g_ops, g_m2, g_tree, &o, NULL));
    ASSERT_TRUE(strstr(belay_err_msg(), "no sealing key") != NULL);
    /* a key file that is not one is refused, not replaced */
    FILE *f = fopen(g_key, "wb");
    REQUIRE(f != NULL);
    fputs("short", f);
    fclose(f);
    chmod(g_key, 0600);
    o.sealing_key_path = g_key;
    ASSERT_EQ_INT(-1, capture_write(&g_ops, g_m2, g_tree, &o, NULL));
    ASSERT_TRUE(strstr(belay_err_msg(), "not a sealing key") != NULL);
    struct stat ks;
    REQUIRE(stat(g_key, &ks) == 0);
    ASSERT_EQ_INT(5, (int)ks.st_size);
    unlink(g_key);
}

/* The roots a caller gives are checked: sorted, canonical, each once. */
TEST(roots_that_are_not_a_sorted_list_are_refused) {
    tree();
    static const struct belay_root A[] = { { "usr", BELAY_ROOT_METADATA, false, false }, { "etc", BELAY_ROOT_CONTENT, false, false } };
    static const struct belay_root B[] = { { "etc", BELAY_ROOT_CONTENT, false, false }, { "etc", BELAY_ROOT_CONTENT, false, false } };
    static const struct belay_root C[] = { { "/etc", BELAY_ROOT_CONTENT, false, false } };
    static const struct belay_root D[] = { { "etc/../usr", BELAY_ROOT_CONTENT, false, false } };
    const struct { const struct belay_root *r; size_t n; } X[] = { { A, 2 }, { B, 2 }, { C, 1 }, { D, 1 } };
    for (size_t i = 0; i < 4; i++) {
        const struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20, .roots = X[i].r, .n_roots = X[i].n, .sealing_key_path = g_key };
        ASSERT_EQ_INT(-1, capture_write(&g_ops, g_m2, g_tree, &o, NULL));
        ASSERT_EQ_INT(BELAY_ERR_INVALID, (int)belay_err_code());
    }
}

/* V5-E7, V5-E9: mark trusts an entry only in the class it has now, and a
 * sealed one only under the key that made it. */
TEST(mark_trusts_by_class_and_by_key) {
    tree();
    char first[700];
    snprintf(first, sizeof first, "%s/first.ndjson", g_dir);
    struct belay_manifest_stats st;
    REQUIRE(capture_roots(first, NULL, &st) == 0);
    char sealed0[65];
    snprintf(sealed0, sizeof sealed0, "%s", ent("etc/shadow")->sha256_hex);
    /* nothing changed: every hashed file is trusted, the sealed ones too; meta files need none */
    REQUIRE(capture_roots(g_m2, first, &st) == 0);
    REQUIRE_MSG(st.prefilter, "the prefilter was not used: %s", st.prefilter_skipped ? st.prefilter_skipped : "?");
    const size_t all = st.trusted;
    ASSERT_TRUE(all >= 9);                          /* passwd, shadow, sub/x, su, (wall), l, secret, 2 x .bashrc, keys */
    ASSERT_TRUE(ent("etc/shadow")->sealed);
    ASSERT_EQ_STR(sealed0, ent("etc/shadow")->sha256_hex);
    ASSERT_TRUE(ent("usr/bin/tool")->meta);
    /* the class changed, the file did not move: a mode change moves ctime, so by a directory
     * above it -- root opens to others, and root/secret (644) is plain content now: read */
    char p[1200];
    snprintf(p, sizeof p, "%s/root", g_tree);
    REQUIRE(chmod(p, 0755) == 0);
    REQUIRE(capture_roots(g_m2, first, &st) == 0);
    char want[65];
    sha_hex("s3cret\n", 7, want);
    ASSERT_TRUE(!ent("root/secret")->sealed);
    ASSERT_EQ_STR(want, ent("root/secret")->sha256_hex);
    ASSERT_EQ_INT((int)all - 1, (int)st.trusted);
    REQUIRE(chmod(p, 0700) == 0);
    /* and back: sealed again, from a manifest where it was plain: read under the key */
    char plain[700];
    snprintf(plain, sizeof plain, "%s/plain.ndjson", g_dir);
    REQUIRE(chmod(p, 0755) == 0 && capture_roots(plain, NULL, NULL) == 0 && chmod(p, 0700) == 0);
    REQUIRE(capture_roots(g_m2, plain, &st) == 0);
    uint8_t key[32];
    REQUIRE(read_key(key));
    hmac_hex(key, "s3cret\n", want);
    ASSERT_TRUE(ent("root/secret")->sealed);
    ASSERT_EQ_STR(want, ent("root/secret")->sha256_hex);
    /* another key: no sealed entry of the previous manifest is trusted */
    unlink(g_key);
    REQUIRE(capture_roots(g_m2, first, &st) == 0);
    REQUIRE(st.prefilter);
    ASSERT_EQ_INT((int)all - 3, (int)st.trusted);   /* shadow, root/secret, authorized_keys were read */
    uint8_t key2[32];
    REQUIRE(read_key(key2));
    ASSERT_TRUE(memcmp(key, key2, 32) != 0);
    hmac_hex(key2, "root:*:1::::::\n", want);
    ASSERT_EQ_STR(want, ent("etc/shadow")->sha256_hex);
    ASSERT_TRUE(strcmp(sealed0, want) != 0);
}

/* V5-E7: an entry the previous trailer names racy is never trusted. This
 * build writes no such manifest; one that does is not used for trust at all. */
TEST(a_previous_manifest_naming_racy_entries_is_not_used) {
    tree();
    char first[700], edited[700];
    snprintf(first, sizeof first, "%s/first.ndjson", g_dir);
    snprintf(edited, sizeof edited, "%s/events.ndjson", g_dir);
    REQUIRE(capture_roots(first, NULL, NULL) == 0);
    FILE *in = fopen(first, "rb"), *out = fopen(edited, "wb");
    REQUIRE(in != NULL && out != NULL);
    static char line[70000];
    int edits = 0;
    while (fgets(line, sizeof line, in) != NULL) {
        char *b = strstr(line, ",\"basis\":\"walk\"}"), *r = strstr(line, ",\"racy\":[]}");
        if (b != NULL) { snprintf(b, 32, ",\"basis\":\"events\"}\n"); edits++; }
        if (r != NULL) { snprintf(r, 40, ",\"racy\":[\"etc/passwd\"]}\n"); edits++; }
        fputs(line, out);
    }
    fclose(in);
    fclose(out);
    REQUIRE(edits == 2);
    struct belay_manifest_stats st;
    REQUIRE(capture_roots(g_m2, edited, &st) == 0);
    ASSERT_TRUE(!st.prefilter);
    ASSERT_EQ_INT(0, (int)st.trusted);
    REQUIRE(st.prefilter_skipped != NULL);
    ASSERT_TRUE(strstr(st.prefilter_skipped, "racy") != NULL);
    ASSERT_TRUE(strstr(line_of(g_m2, NULL), "names racy entries") != NULL);      /* the trailer's read_all */
}

/* ---------- injected: mounts, a file that cannot be opened, changes during the walk ---------- */

static const char *g_mount_name;    /* reported as a mount root */
static bool g_enterable;
static const char *g_deny;          /* openat of this name fails EACCES (not O_PATH) */
static void (*g_action)(void);      /* runs once, when the walk is over and before the re-check */
static int g_tmpfiles;

static int t_stat_mount(void *ctx, int dfd, const char *name, struct stat *st, bool *mr, bool *mk) {
    const int r = g_real->stat_mount(ctx, dfd, name, st, mr, mk);
    if (r != 0) {                   /* no statx here: the same answer by lstat */
        if (g_real->fstatat(ctx, dfd, name[0] ? name : ".", st, AT_SYMLINK_NOFOLLOW) != 0) return -1;
        *mr = false;
    }
    *mk = true;
    if (g_mount_name != NULL && strcmp(name, g_mount_name) == 0) *mr = true;
    return 0;
}

static bool t_enterable(void *ctx, int dfd, const char *name) {
    (void)ctx; (void)dfd;
    return g_mount_name != NULL && strcmp(name, g_mount_name) == 0 && g_enterable;
}

static int t_openat(void *ctx, int dfd, const char *name, int flags) {
    if (g_deny != NULL && strcmp(name, g_deny) == 0) { errno = EACCES; return -1; }
    return g_real->openat(ctx, dfd, name, flags);
}

/* The capture's temporaries: the walk-start probe first, then (the tree is
 * too small for the sorter to spill) the re-check's verdicts, made when
 * every entry is recorded. */
static FILE *t_tmpfile_in(void *ctx, const char *dir, const char *tmpl) {
    if (++g_tmpfiles == 2 && g_action != NULL) {
        void (*a)(void) = g_action;
        g_action = NULL;
        a();
    }
    return g_real->tmpfile_in(ctx, dir, tmpl);
}

static void decorate(void) {
    g_real = fsops_default();
    g_ops = *g_real;
    g_ops.stat_mount = t_stat_mount;
    g_ops.mount_enterable = t_enterable;
    g_ops.openat = t_openat;
    g_ops.tmpfile_in = t_tmpfile_in;
}

/* V5-E6: a mount point under a root is entered when its filesystem is on
 * the list, and is a `mount` entry otherwise; without roots, always. */
TEST(a_mount_is_entered_by_its_filesystem_type) {
    tree();
    g_mount_name = "sub";
    g_enterable = true;
    struct belay_manifest_stats st;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0);
    REQUIRE(ent("etc/sub") != NULL);
    ASSERT_TRUE(!ent("etc/sub")->is_mount && ent("etc/sub/x") != NULL);
    ASSERT_EQ_INT(0, (int)(st.mounts + st.raced + st.unstable));    /* the re-check enters it too */
    g_enterable = false;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0);
    ASSERT_TRUE(ent("etc/sub")->is_mount && ent("etc/sub/x") == NULL);
    ASSERT_EQ_INT(1, (int)st.mounts);
    /* a capture of a whole scope enters no mount, whatever its type (as version 4) */
    g_enterable = true;
    const struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20 };
    REQUIRE(capture_write(&g_ops, g_m2, g_tree, &o, &st) == 0);
    ASSERT_EQ_INT(1, (int)st.mounts);
    ASSERT_TRUE(strstr(line_of(g_m2, "etc/sub"), "\"mount\":true") != NULL);
    g_mount_name = NULL;
}

/* V5-E7: a meta file that cannot be opened is still meta, never unreadable. */
TEST(a_meta_file_that_cannot_be_opened_is_still_meta) {
    tree();
    g_deny = "tool";
    struct belay_manifest_stats st;
    const int r = capture_roots(g_m2, NULL, &st);
    g_deny = NULL;
    REQUIRE(r == 0 && ent("usr/bin/tool") != NULL);
    ASSERT_TRUE(ent("usr/bin/tool")->meta && !ent("usr/bin/tool")->unreadable && !ent("usr/bin/tool")->unverified);
    ASSERT_EQ_INT(0, (int)st.unreadable);
    /* one that must be read (setuid) and cannot be is unreadable, as under a content root */
    g_deny = "su";
    const int r2 = capture_roots(g_m2, NULL, &st);
    g_deny = NULL;
    REQUIRE(r2 == 0 && ent("usr/bin/su") != NULL);
    ASSERT_TRUE(!ent("usr/bin/su")->meta && ent("usr/bin/su")->unreadable && ent("usr/bin/su")->unverified);
}

static void add_file_in_home(void) { wr("home/u/new-notes.txt", "n\n", 0644); wr("late.txt", "l\n", 0644); }
static void add_dir_in_home(void) { mk("home/u/Music", 0755); }
static void touch_not_read(void) { wr("home/other/g", "g\n", 0644); wr("var/log/more", "m\n", 0644); }
static void chmod_not_read(void) {
    char p[1200];
    snprintf(p, sizeof p, "%s/home/other", g_tree);
    if (chmod(p, 0700) != 0) perror(p);
}

/* The end-of-walk re-check of what version 5 records in part: a partial
 * directory's listing is the names recorded, a not_read directory's times
 * are not looked at; its mode is. */
TEST(the_recheck_looks_at_what_was_recorded) {
    struct belay_manifest_stats st;
    /* a file made in a partial directory during the walk: not recorded, nothing changed */
    tree();
    g_tmpfiles = 0; g_action = add_file_in_home;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0 && g_action == NULL);
    ASSERT_EQ_INT(0, (int)(st.unstable + st.raced));
    /* a directory made there would have been recorded: its listing changed */
    tree();
    g_tmpfiles = 0; g_action = add_dir_in_home;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0 && g_action == NULL);
    ASSERT_EQ_INT(1, (int)st.unstable);
    ASSERT_TRUE(ent("home/u")->unstable && ent("home/u")->partial);
    /* files made in a not_read directory: belay did not look inside */
    tree();
    g_tmpfiles = 0; g_action = touch_not_read;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0 && g_action == NULL);
    ASSERT_EQ_INT(0, (int)(st.unstable + st.raced));
    /* its mode is recorded, so a chmod during the walk is raced */
    tree();
    g_tmpfiles = 0; g_action = chmod_not_read;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0 && g_action == NULL);
    ASSERT_EQ_INT(1, (int)st.raced);
    ASSERT_TRUE(ent("home/other")->raced && ent("home/other")->not_read);
}

/* ---------- the roots of a system (watch-system.md WS-6 to WS-9) ---------- */

static struct belay_system_roots g_sr;
static const struct belay_root *sroot(const char *path) {
    for (size_t i = 0; i < g_sr.n_roots; i++)
        if (strcmp(g_sr.roots[i].path, path) == 0) return &g_sr.roots[i];
    return NULL;
}

TEST(system_roots_fixed) {
    tree();
    mk("lib", 0755);
    REQUIRE(belay_system_roots(g_tree, &g_sr) == 0);
    static const char *const CONTENT[] = { "etc", "usr/local", "root", "var/spool/cron", "var/lib/dpkg",
                                           "var/lib/apt/extended_states", "usr/lib/systemd", "lib/systemd",
                                           "boot/grub/grub.cfg" };
    static const char *const META[] = { "usr", "var", "opt", "srv", "boot", "lib" };
    for (size_t i = 0; i < sizeof CONTENT / sizeof CONTENT[0]; i++) {
        REQUIRE_MSG(sroot(CONTENT[i]) != NULL, "%s is not a root", CONTENT[i]);
        ASSERT_TRUE(sroot(CONTENT[i])->cls == BELAY_ROOT_CONTENT && !sroot(CONTENT[i])->plain);
    }
    for (size_t i = 0; i < sizeof META / sizeof META[0]; i++) {
        REQUIRE_MSG(sroot(META[i]) != NULL, "%s is not a root", META[i]);
        ASSERT_TRUE(sroot(META[i])->cls == BELAY_ROOT_METADATA);
    }
    /* bin is a link here, sbin, lib32, lib64, libx32 are not there: not roots (WS-7) */
    ASSERT_TRUE(sroot("bin") == NULL && sroot("sbin") == NULL && sroot("lib32") == NULL && sroot("lib64") == NULL &&
                sroot("libx32") == NULL);
    for (size_t i = 1; i < g_sr.n_roots; i++)
        if (strcmp(g_sr.roots[i - 1].path, g_sr.roots[i].path) >= 0) BELAY_FAIL("not sorted at %s", g_sr.roots[i].path);
    /* WS-8 */
    static const char *const NR[] = { "var/log", "var/cache", "var/tmp", "var/lib/docker", "var/lib/containerd",
                                      "var/lib/snapd", "var/snap" };
    ASSERT_EQ_INT(7, (int)g_sr.n_not_read);
    for (size_t i = 0; i < 7 && i < g_sr.n_not_read; i++) ASSERT_EQ_STR(NR[i], g_sr.not_read[i]);
    belay_system_roots_free(&g_sr);
    /* lib a link (merged /usr): neither lib nor lib/systemd */
    char l[1200];
    snprintf(l, sizeof l, "%s/lib", g_tree);
    REQUIRE(rmdir(l) == 0 && symlink("usr/lib", l) == 0);
    REQUIRE(belay_system_roots(g_tree, &g_sr) == 0);
    ASSERT_TRUE(sroot("lib") == NULL && sroot("lib/systemd") == NULL && sroot("usr/lib/systemd") != NULL);
    belay_system_roots_free(&g_sr);
}

/* WS-6, WS-8a: the homes of etc/passwd, as it is when the capture starts. */
TEST(system_roots_homes) {
    tree();
    mk("var/lib/postgresql", 0700); mk("var/log/svc", 0755); mk("srv", 0755); mk("srv/real", 0755);
    char l[1200];
    snprintf(l, sizeof l, "%s/srv/link", g_tree);
    REQUIRE(symlink("real", l) == 0);
    wr("etc/passwd",
       "root:x:0:0:root:/root:/bin/bash\n"
       "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"         /* not there */
       "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"                    /* a link */
       "sys:x:3:3:sys:/:/usr/sbin/nologin\n"                       /* the scope root */
       "u:x:1000:1000:U,,,:/home/u:/bin/bash\n"
       "u2:x:1001:1001::/home/u:/bin/bash\n"                       /* the same home again */
       "postgres:x:110:120::/var/lib/postgresql:/bin/bash\n"
       "svc:x:111:121::/var/log/svc:/bin/false\n"                  /* in a not-read directory */
       "svc2:x:112:122::/nonexistent:/bin/false\n"
       "rel:x:113:123::home/u:/bin/false\n"                        /* not absolute */
       "dots:x:114:124::/home/../root:/bin/false\n"                /* not canonical */
       "viaL:x:115:125::/srv/link:/bin/false\n"                    /* a link as its last component */
       "underL:x:116:126::/bin/x:/bin/false\n"                     /* a link on the way */
       "short:x:117\n"                                             /* no sixth field */
       "file:x:118:128::/etc/passwd:/bin/false\n"                  /* not a directory */
       "slash:x:119:129::/home/other/:/bin/false\n", 0644);        /* a trailing slash */
    REQUIRE(belay_system_roots(g_tree, &g_sr) == 0);
    static const char *const FILES[] = { ".profile", ".bash_profile", ".bash_login", ".bashrc", ".bash_logout",
                                         ".zshenv", ".zprofile", ".zshrc", ".zlogin", ".cshrc", ".login",
                                         ".config/fish/config.fish" };
    static const char *const HOMES[] = { "root", "home/u", "var/lib/postgresql", "home/other" };
    char p[300];
    size_t want = 0;
    for (size_t h = 0; h < 4; h++) {
        snprintf(p, sizeof p, "%s/.ssh", HOMES[h]);
        REQUIRE_MSG(sroot(p) != NULL, "%s is not a root", p);
        ASSERT_TRUE(sroot(p)->cls == BELAY_ROOT_CONTENT && !sroot(p)->plain);
        snprintf(p, sizeof p, "%s/.config/systemd/user", HOMES[h]);
        REQUIRE_MSG(sroot(p) != NULL, "%s is not a root", p);
        ASSERT_TRUE(!sroot(p)->plain);
        for (size_t i = 0; i < 12; i++) {
            snprintf(p, sizeof p, "%s/%s", HOMES[h], FILES[i]);
            REQUIRE_MSG(sroot(p) != NULL, "%s is not a root", p);
            ASSERT_TRUE(sroot(p)->cls == BELAY_ROOT_CONTENT && sroot(p)->plain);     /* V5-E5: never sealed */
        }
        want += 14;
    }
    size_t homes = 0;
    for (size_t i = 0; i < g_sr.n_roots; i++) {
        const char *q = g_sr.roots[i].path;
        const size_t n = strlen(q);
        if (n >= 5 && strcmp(q + n - 5, "/.ssh") == 0) homes++;
        if (strstr(q, "usr/sbin/.") || strncmp(q, "bin/", 4) == 0 || q[0] == '.' || strstr(q, "var/log/") ||
            strstr(q, "nonexistent") || strstr(q, "srv/link") || strstr(q, "etc/passwd/"))
            BELAY_FAIL("%s is a root", q);
    }
    ASSERT_EQ_INT(4, (int)homes);
    for (size_t i = 1; i < g_sr.n_roots; i++)
        if (strcmp(g_sr.roots[i - 1].path, g_sr.roots[i].path) >= 0) BELAY_FAIL("not sorted at %s", g_sr.roots[i].path);
    (void)want;
    belay_system_roots_free(&g_sr);
    /* no etc/passwd: the fixed roots alone */
    snprintf(l, sizeof l, "%s/etc/passwd", g_tree);
    REQUIRE(unlink(l) == 0 && belay_system_roots(g_tree, &g_sr) == 0);
    ASSERT_TRUE(sroot("etc") != NULL && sroot("root/.ssh") == NULL);
    belay_system_roots_free(&g_sr);
}

/* The resolved roots drive a capture: a home under a metadata root is
 * walked as metadata with its .ssh as content (WS-9), a home outside the
 * roots is partial (WS-8). */
TEST(system_roots_capture) {
    tree();
    mk("var/lib/postgresql", 0755); mk("var/lib/postgresql/.ssh", 0755);
    wr("var/lib/postgresql/.ssh/authorized_keys", "ssh-ed25519 BBBB pg\n", 0644);
    wr("var/lib/postgresql/data", "d\n", 0644);
    wr("etc/passwd", "u:x:1000:1000::/home/u:/bin/sh\npostgres:x:110:120::/var/lib/postgresql:/bin/sh\n", 0644);
    pause_ms(30);
    REQUIRE(belay_system_roots(g_tree, &g_sr) == 0);
    const struct belay_manifest_opts o = {
        .hash_max_bytes = 1u << 20, .roots = g_sr.roots, .n_roots = g_sr.n_roots,
        .not_read = g_sr.not_read, .n_not_read = g_sr.n_not_read, .sealing_key_path = g_key,
    };
    REQUIRE(capture_write(&g_ops, g_m2, g_tree, &o, NULL) == 0);
    belay_system_roots_free(&g_sr);
    char *text = NULL;
    size_t cap = 0;
    FILE *f = fopen(g_m2, "rb");
    REQUIRE(f != NULL);
    const ssize_t n = getdelim(&text, &cap, '\0', f);
    fclose(f);
    REQUIRE(n > 0);
    char keep[600];
    snprintf(keep, sizeof keep, "%s", g_m);
    snprintf(g_m, sizeof g_m, "%s/read.ndjson", g_dir);
    const int r = read_text(text);
    snprintf(g_m, sizeof g_m, "%s", keep);
    free(text);
    REQUIRE(r == 0);
    REQUIRE(ent("var/lib/postgresql") != NULL && ent("var/lib/postgresql/data") != NULL &&
            ent("var/lib/postgresql/.ssh/authorized_keys") != NULL && ent("home/u") != NULL);
    ASSERT_TRUE(!ent("var/lib/postgresql")->partial && ent("var/lib/postgresql/data")->meta);
    ASSERT_TRUE(ent("var/lib/postgresql/.ssh/authorized_keys")->has_hash);
    ASSERT_TRUE(ent("home/u")->partial && ent("home/u/.bashrc") != NULL && !ent("home/u/.bashrc")->sealed);
    ASSERT_TRUE(ent("var/log")->not_read && ent("home/u/notes.txt") == NULL);
    ASSERT_TRUE(ent("etc/shadow")->sealed);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_v5_%d_%ld", (int)getpid(), (long)time(NULL));
    umask(022);                         /* modes are set explicitly; nothing here follows the caller's umask */
    mkdir(g_dir, 0700);
    snprintf(g_tree, sizeof g_tree, "%s/tree", g_dir);
    snprintf(g_m, sizeof g_m, "%s/m.ndjson", g_dir);
    snprintf(g_m2, sizeof g_m2, "%s/out.ndjson", g_dir);
    snprintf(g_key, sizeof g_key, "%s/sealing.key", g_dir);
    decorate();
    RUN(v5_of_a_whole_scope_reads);
    RUN(v5_roots_are_read);
    RUN(each_version_is_read_by_its_own_keys);
    RUN(v5_header_values_are_checked);
    RUN(v5_trailer_values_are_checked);
    RUN(v5_entry_rules);
    RUN(a_whole_scope_is_written_as_v5_with_no_roots);
    RUN(roots_make_partial_and_not_read_directories);
    RUN(a_metadata_root_reads_only_what_grants_privilege);
    RUN(a_file_others_cannot_read_is_sealed);
    RUN(the_key_is_made_only_when_needed);
    RUN(roots_that_are_not_a_sorted_list_are_refused);
    RUN(mark_trusts_by_class_and_by_key);
    RUN(a_previous_manifest_naming_racy_entries_is_not_used);
    RUN(a_mount_is_entered_by_its_filesystem_type);
    RUN(a_meta_file_that_cannot_be_opened_is_still_meta);
    RUN(the_recheck_looks_at_what_was_recorded);
    RUN(system_roots_fixed);
    RUN(system_roots_homes);
    RUN(system_roots_capture);
    rm_rf(g_dir);
    return belay_test_report();
}
