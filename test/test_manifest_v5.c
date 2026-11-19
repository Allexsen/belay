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
#define H5 H5X(",\"roots\":0,\"basis\":\"walk\"")
/* V5-A1: the header's count, then one line per root. V5-A2: one line per racy path. */
#define H5R(n) H5X(",\"roots\":" #n ",\"basis\":\"walk\"")
#define RL(p, c, f) "{\"root\":\"" p "\",\"class\":\"" c "\",\"found\":" f "}\n"
#define RC(p) "{\"racy\":\"" p "\"}\n"
#define ROOTS1 RL("etc", "content", "true") RL("home/u/.ssh", "content", "false") RL("usr", "metadata", "true")
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
#define T5(n, nr, meta, sealed) T5X(n, nr, meta, sealed, ",\"carried\":0,\"racy\":0")

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
    REQUIRE(read_text(H5R(3) ROOTS1 DIR_(".", ",\"partial\":true") T5(1, 0, 0, 0)) == 0);
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
        { "v6", "{\"belay_manifest\":6," H_ ",\"roots\":0,\"basis\":\"walk\"}\n" ROOT_ T5(1, 0, 0, 0), "format version 6" },
        { "v5 header without roots", H5X(",\"basis\":\"walk\"") ROOT_ T5(1, 0, 0, 0), "missing roots" },
        { "v5 header without basis", H5X(",\"roots\":0") ROOT_ T5(1, 0, 0, 0), "missing basis" },
        { "v5 header, basis first", H5X(",\"basis\":\"walk\",\"roots\":0") ROOT_ T5(1, 0, 0, 0), "canonical order" },
        { "v4 header with roots", "{\"belay_manifest\":4," H_ ",\"roots\":0}\n" ROOT_ T4(1), "unknown key \"roots\"" },
        { "v4 header with basis", "{\"belay_manifest\":4," H_ ",\"basis\":\"walk\"}\n" ROOT_ T4(1), "unknown key \"basis\"" },
        { "v5 with a v4 trailer", H5 ROOT_ T4(1), "missing not_read" },
        { "v5 trailer without racy", H5 ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0"), "missing racy" },
        { "v5 trailer without carried", H5 ROOT_ T5X(1, 0, 0, 0, ",\"racy\":0"), "missing carried" },
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
#define PR_ DIR_(".", ",\"partial\":true")
    static const struct { const char *what, *text, *msg; } C[] = {
        /* V5-A1: the count is the number of root lines; they come before the first entry, sorted, each once */
        { "the old array of roots", H5X(",\"roots\":[],\"basis\":\"walk\"") ROOT_ T5(1, 0, 0, 0), "\"roots\" must be a non-negative integer" },
        { "fewer root lines than the count", H5R(3) RL("etc", "content", "true") RL("usr", "metadata", "true") PR_ T5(1, 0, 0, 0),
          "the header says 3 roots, read 2" },
        { "no root line at all", H5R(1) PR_ T5(1, 0, 0, 0), "the header says 1 roots, read 0" },
        { "more root lines than the count", H5R(1) RL("etc", "content", "true") RL("usr", "metadata", "true") PR_ T5(1, 0, 0, 0),
          "a root line past the header's count" },
        { "a root line with no count", H5 RL("etc", "content", "true") ROOT_ T5(1, 0, 0, 0), "a root line past the header's count" },
        { "a root line after an entry", H5R(1) RL("etc", "content", "true") PR_ RL("usr", "metadata", "true") T5(1, 0, 0, 0),
          "a root line past the header's count" },
        { "a root line not found, after an entry", H5R(1) RL("etc", "content", "true") PR_ RL("usr", "metadata", "false") T5(1, 0, 0, 0),
          "a root line past the header's count" },
        { "a root line in a v4 manifest", H4 RL("etc", "content", "true") ROOT_ T4(1), "unknown key \"root\"" },
        { "the file ends in the roots", H5R(2) RL("etc", "content", "true"), "the header says 2 roots, read 1" },
        { "roots out of order", H5R(2) RL("usr", "metadata", "true") RL("etc", "content", "true") PR_ T5(1, 0, 0, 0), "roots out of order" },
        { "a root twice", H5R(2) RL("etc", "content", "true") RL("etc", "content", "true") PR_ T5(1, 0, 0, 0), "roots out of order" },
        { "a class unknown", H5R(1) RL("etc", "contents", "true") PR_ T5(1, 0, 0, 0), "class is not content or metadata" },
        { "found a string", H5R(1) "{\"root\":\"etc\",\"class\":\"content\",\"found\":\"true\"}\n" PR_ T5(1, 0, 0, 0), "exactly true or false" },
        { "found null", H5R(1) "{\"root\":\"etc\",\"class\":\"content\",\"found\":null}\n" PR_ T5(1, 0, 0, 0), "exactly true or false" },
        { "found missing", H5R(1) "{\"root\":\"etc\",\"class\":\"content\"}\n" PR_ T5(1, 0, 0, 0), "root, class and found" },
        { "a root's keys out of order", H5R(1) "{\"root\":\"etc\",\"found\":true,\"class\":\"content\"}\n" PR_ T5(1, 0, 0, 0), "canonical order" },
        { "a root with another key", H5R(1) "{\"root\":\"etc\",\"class\":\"content\",\"found\":true,\"n\":1}\n" PR_ T5(1, 0, 0, 0), "unknown key" },
        { "the scope root as a root", H5R(1) RL(".", "content", "true") PR_ T5(1, 0, 0, 0), "canonical relative path" },
        { "an absolute root", H5R(1) RL("/etc", "content", "true") PR_ T5(1, 0, 0, 0), "canonical relative path" },
        { "a root with ..", H5R(1) RL("etc/../x", "content", "true") PR_ T5(1, 0, 0, 0), "canonical relative path" },
        { "root and root_b64", H5R(1) "{\"root\":\"etc\",\"root_b64\":\"/w==\",\"class\":\"content\",\"found\":true}\n" PR_ T5(1, 0, 0, 0), "both root and root_b64" },
        { "root_b64 of UTF-8", H5R(1) "{\"root_b64\":\"ZXRj\",\"class\":\"content\",\"found\":true}\n" PR_ T5(1, 0, 0, 0), "is valid UTF-8" },
        { "roots negative", H5X(",\"roots\":-1,\"basis\":\"walk\"") ROOT_ T5(1, 0, 0, 0), "non-negative integer" },
        { "a basis unknown", H5X(",\"roots\":0,\"basis\":\"stat\"") ROOT_ T5(1, 0, 0, 0), "basis is not walk or events" },
        { "sealed_key too short", H5X(",\"roots\":0,\"sealed_key\":\"0123\",\"basis\":\"walk\"") ROOT_ T5(1, 0, 0, 0), "16 lowercase hex" },
        { "sealed_key upper case", H5X(",\"roots\":0,\"sealed_key\":\"0123456789ABCDEF\",\"basis\":\"walk\"") ROOT_ T5(1, 0, 0, 0), "16 lowercase hex" },
        { "sealed_key, nothing sealed", H5X(",\"roots\":0,\"sealed_key\":\"" KEYID "\",\"basis\":\"walk\"") ROOT_ T5(1, 0, 0, 0),
          "a sealed_key without sealed entries" },
        { "sealed, no sealed_key", H5R(1) RL("f", "content", "true") PR_ REG_("f", SHA_ ",\"sealed\":true") T5(2, 0, 0, 1), "sealed entries without a sealed_key" },
        { "false on a line of its own", H5 ROOT_ REG_("f", SHA_ ",\"sealed\":false") T5(2, 0, 0, 0), "malformed value" },
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        const int r = read_text(C[i].text);
        if (r != -1) { BELAY_FAIL("%s: read, want refused", C[i].what); continue; }
        if (strstr(belay_err_msg(), C[i].msg) == NULL) BELAY_FAIL("%s: \"%s\", want \"%s\"", C[i].what, belay_err_msg(), C[i].msg);
    }
    REQUIRE(read_text(H5X(",\"roots\":1,\"sealed_key\":\"" KEYID "\",\"basis\":\"walk\"") RL("f", "content", "true") PR_
                      REG_("f", SHA_ ",\"sealed\":true") T5(2, 0, 0, 1)) == 0);
    ASSERT_EQ_STR(KEYID, g_h.sealed_key);
    ASSERT_TRUE(ent("f")->sealed);
    /* a path that is not UTF-8: root_b64, in byte order with the others */
    REQUIRE(read_text(H5R(2) RL("etc", "content", "true") "{\"root_b64\":\"/w==\",\"class\":\"metadata\",\"found\":false}\n"
                      PR_ T5(1, 0, 0, 0)) == 0);
    REQUIRE(g_h.n_roots == 2);
    ASSERT_TRUE(g_roots[1].path[0] == (char)0xff && g_roots[1].path[1] == '\0' && g_roots[1].cls == BELAY_ROOT_METADATA);
}

/* V5-7 to V5-12: the trailer's counts are the entries', a walk carries
 * nothing and names no racy path, an event capture's racy paths are sorted. */
TEST(v5_trailer_values_are_checked) {
#define HE H5X(",\"roots\":0,\"basis\":\"events\"")
    static const struct { const char *what, *text, *msg; } C[] = {
        { "not_read miscounted", H5R(1) RL("f", "content", "false") DIR_(".", ",\"partial\":true") NR_("d", "") T5(2, 0, 0, 0),
          "trailer says 0 not_read" },
        { "meta miscounted", H5R(1) RL("f", "metadata", "true") DIR_(".", ",\"partial\":true") REG_("f", ",\"meta\":true") T5(2, 0, 2, 0),
          "/ 2 meta" },
        { "sealed miscounted", H5X(",\"roots\":1,\"sealed_key\":\"" KEYID "\",\"basis\":\"walk\"") RL("f", "content", "true")
          DIR_(".", ",\"partial\":true") REG_("f", SHA_ ",\"sealed\":true") T5(2, 0, 0, 2), "/ 2 sealed" },
        { "a walk that carries", H5 ROOT_ T5X(1, 0, 0, 0, ",\"carried\":1,\"racy\":0"), "a walk carries no entry" },
        { "a walk with racy paths", H5 ROOT_ REG_("f", SHA_) RC("f") T5X(2, 0, 0, 0, ",\"carried\":0,\"racy\":1"), "a walk names no racy path" },
        /* V5-A2: the count is the number of racy lines; they come after the last entry, sorted, each naming an entry */
        { "the old array of racy paths", HE ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0,\"racy\":[]"), "\"racy\" must be a non-negative integer" },
        { "fewer racy lines than the count", HE ROOT_ REG_("a", SHA_) REG_("b", SHA_) RC("a") T5X(3, 0, 0, 0, ",\"carried\":0,\"racy\":2"),
          "trailer says 2 racy, read 1" },
        { "more racy lines than the count", HE ROOT_ REG_("a", SHA_) REG_("b", SHA_) RC("a") RC("b") T5X(3, 0, 0, 0, ",\"carried\":0,\"racy\":1"),
          "trailer says 1 racy, read 2" },
        { "racy lines and a count of 0", HE ROOT_ REG_("a", SHA_) RC("a") T5X(2, 0, 0, 0, ",\"carried\":0,\"racy\":0"), "trailer says 0 racy, read 1" },
        { "a racy line naming no entry", HE ROOT_ REG_("a", SHA_) REG_("c", SHA_) RC("b") T5X(3, 0, 0, 0, ",\"carried\":0,\"racy\":1"),
          "a racy line names no entry" },
        { "a racy line past the last entry", HE ROOT_ REG_("a", SHA_) RC("a") RC("z") T5X(2, 0, 0, 0, ",\"carried\":0,\"racy\":2"),
          "a racy line names no entry" },
        { "an entry after a racy line", HE ROOT_ REG_("a", SHA_) RC("a") REG_("b", SHA_) T5X(3, 0, 0, 0, ",\"carried\":0,\"racy\":1"),
          "an entry after a racy line" },
        { "a racy line in a v4 manifest", H4 ROOT_ REG_("a", SHA_) RC("a") T4(2), "unknown key \"racy\"" },
        { "a racy line with another key", HE ROOT_ REG_("a", SHA_) "{\"racy\":\"a\",\"type\":\"reg\"}\n" T5X(2, 0, 0, 0, ",\"carried\":0,\"racy\":1"),
          "unknown key" },
        { "carried over the entries", HE ROOT_ T5X(1, 0, 0, 0, ",\"carried\":2,\"racy\":0"), "carries more entries" },
        { "racy out of order", HE ROOT_ REG_("a", SHA_) REG_("b", SHA_) RC("b") RC("a") T5X(3, 0, 0, 0, ",\"carried\":0,\"racy\":2"), "racy paths out of order" },
        { "racy twice", HE ROOT_ REG_("a", SHA_) RC("a") RC("a") T5X(2, 0, 0, 0, ",\"carried\":0,\"racy\":2"), "racy paths out of order" },
        { "a racy path absolute", HE ROOT_ REG_("a", SHA_) "{\"racy\":\"/a\"}\n" T5X(2, 0, 0, 0, ",\"carried\":0,\"racy\":1"), "canonical relative path" },
        { "racy and racy_b64", HE ROOT_ REG_("a", SHA_) "{\"racy\":\"a\",\"racy_b64\":\"/w==\"}\n" T5X(2, 0, 0, 0, ",\"carried\":0,\"racy\":1"), "both racy and racy_b64" },
        { "racy_b64 of UTF-8", HE ROOT_ REG_("a", SHA_) "{\"racy_b64\":\"YQ==\"}\n" T5X(2, 0, 0, 0, ",\"carried\":0,\"racy\":1"), "is valid UTF-8" },
        { "racy_b64 in the trailer", HE ROOT_ T5X(1, 0, 0, 0, ",\"carried\":0,\"racy_b64\":0"), "unknown key \"racy_b64\"" },
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        const int r = read_text(C[i].text);
        if (r != -1) { BELAY_FAIL("%s: read, want refused", C[i].what); continue; }
        if (strstr(belay_err_msg(), C[i].msg) == NULL) BELAY_FAIL("%s: \"%s\", want \"%s\"", C[i].what, belay_err_msg(), C[i].msg);
    }
    REQUIRE_MSG(read_text(HE ROOT_ REG_("a", SHA_) REG_("b", SHA_) RC(".") RC("b") T5X(3, 0, 0, 0, ",\"carried\":1,\"racy\":2")) == 0,
                "%s", belay_err_msg());
    ASSERT_EQ_INT(3, (int)g_n);                     /* a racy line is no entry */
    ASSERT_TRUE(g_h.basis_events);
    ASSERT_EQ_INT(1, (int)g_t.carried);
    ASSERT_EQ_INT(2, (int)g_t.racy_listed);
    /* a path that is not UTF-8: racy_b64, on its own line */
    REQUIRE_MSG(read_text(HE ROOT_ REG_("a", SHA_) "{\"path_b64\":\"/w==\",\"type\":\"reg\",\"mode\":33188,\"uid\":0,\"gid\":0,"
                          "\"size\":0,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":3,\"dev\":1,\"nlink\":1" SHA_ "}\n"
                          RC("a") "{\"racy_b64\":\"/w==\"}\n" T5X(3, 0, 0, 0, ",\"carried\":0,\"racy\":2")) == 0, "%s", belay_err_msg());
    ASSERT_EQ_INT(2, (int)g_t.racy_listed);
}

/* V5-4, V5-4b, V5-5, V5-6 and the entry rules V5-E1, V5-E2, V5-E8. */
TEST(v5_entry_rules) {
#define K5 H5X(",\"roots\":0,\"sealed_key\":\"" KEYID "\",\"basis\":\"walk\"")
    static const struct { const char *what, *text, *msg; } C[] = {
        /* V5-4, V5-E8 */
        { "not_read with size", H5 ROOT_ DIRX("d", "\"size\":1,", ",\"not_read\":true") T5(2, 1, 0, 0), "on a not_read directory" },
        { "not_read with nlink", H5 ROOT_ DIRX("d", "", NL_ ",\"not_read\":true") T5(2, 1, 0, 0), "on a not_read directory" },
        { "not_read with mtime_ns", H5 ROOT_ DIRX("d", "\"mtime_ns\":1,", ",\"not_read\":true") T5(2, 1, 0, 0), "on a not_read directory" },
        { "not_read with ctime_ns", H5 ROOT_ DIRX("d", "\"ctime_ns\":1,", ",\"not_read\":true") T5(2, 1, 0, 0), "on a not_read directory" },
        { "a directory without size", H5 ROOT_ DIRX("d", "\"mtime_ns\":1,\"ctime_ns\":1,", NL_) T5(2, 0, 0, 0), "missing size" },
        { "a directory without nlink", H5 ROOT_ DIRX("d", ST_, "") T5(2, 0, 0, 0), "missing nlink" },
        { "not_read on a file", H5 ROOT_ REG_("f", SHA_ ",\"not_read\":true") T5(2, 1, 0, 0), "on a non-directory" },
        { "not_read and unreadable", H5 ROOT_ DIRX("d", "", ",\"unreadable\":true,\"not_read\":true") T5X(2, 1, 0, 0, ",\"carried\":0,\"racy\":0"),
          "exclusive" },
        { "not_read and mount", H5 ROOT_ DIRX("d", "", ",\"mount\":true,\"not_read\":true") T5(2, 1, 0, 0), "exclusive" },
        { "not_read and unstable", H5 ROOT_ DIRX("d", "", ",\"unstable\":true,\"not_read\":true") T5(2, 1, 0, 0), "exclusive" },
        /* V5-E2 */
        { "an entry below not_read", H5R(1) RL("f", "content", "false") DIR_(".", ",\"partial\":true") NR_("d", "") REG_("d/f", SHA_)
          T5(3, 1, 0, 0), "entry below a not_read directory" },
        { "entries under a not_read root", H5R(1) RL("f", "content", "true") NR_(".", "") REG_("f", SHA_) T5(2, 1, 0, 0),
          "under an unreadable scope root" },
        /* V5-4b */
        { "partial on a file", H5 ROOT_ REG_("f", SHA_ ",\"partial\":true") T5(2, 0, 0, 0), "on a non-directory" },
        { "partial and not_read", H5 ROOT_ DIRX("d", "", ",\"not_read\":true,\"partial\":true") T5(2, 1, 0, 0), "partial with" },
        { "partial and unreadable", H5 ROOT_ DIR_("d", ",\"unreadable\":true,\"partial\":true") T5(2, 0, 0, 0), "partial with" },
        { "partial and mount", H5 ROOT_ DIRX("d", ST_, NL_ ",\"mount\":true,\"partial\":true") T5(2, 0, 0, 0), "partial with" },
        /* V5-5, V5-E1 */
        { "meta and sha256", H5 ROOT_ REG_("f", SHA_ ",\"meta\":true") T5(2, 0, 1, 0), "meta with sha256 or unverified" },
        { "meta and unverified", H5 ROOT_ REG_("f", ",\"unverified\":true,\"unreadable\":true,\"meta\":true") T5(2, 0, 1, 0),
          "meta with sha256 or unverified" },
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
    REQUIRE(read_text(H5X(",\"roots\":2,\"sealed_key\":\"" KEYID "\",\"basis\":\"walk\"") RL("m", "metadata", "true")
                      RL("s", "content", "true") DIR_(".", ",\"partial\":true") NR_("a", "") DIRX("b", "", ",\"raced\":true,\"not_read\":true")
                      DIR_("c", ",\"unstable\":true,\"partial\":true") REG_("m", ",\"meta\":true")
                      REG_("s", SHA_ ",\"writer_open\":true,\"sealed\":true")
                      "{\"belay_manifest_end\":6,\"vanished\":0,\"unreadable\":0,\"unstable\":1,\"mounts\":0,\"raced\":1,"
                      "\"trusted\":0,\"reference\":\"none\",\"read_all\":\"check\",\"writer_open\":1,\"unguarded\":0,"
                      "\"not_read\":2,\"meta\":1,\"sealed\":1,\"carried\":0,\"racy\":0}\n") == 0);
    ASSERT_TRUE(ent(".")->partial && ent("a")->not_read && ent("b")->raced && ent("c")->partial && ent("c")->unstable);
    ASSERT_TRUE(ent("m")->meta && !ent("m")->has_hash && ent("s")->sealed && ent("s")->writer_open);
    ASSERT_EQ_INT(2, (int)g_t.not_read);
    ASSERT_EQ_INT(1, (int)g_t.meta);
    ASSERT_EQ_INT(1, (int)g_t.sealed);
    ASSERT_EQ_INT(2, (int)g_t.sealing);             /* checkpoint-v3 C3-3: not_read directories seal */
}

/* V5-E3 and "no roots: as v4 in every other respect", held by the reader:
 * where an entry may be, by the roots. */
TEST(v5_structure_by_the_roots) {
#define SR H5X(",\"roots\":4,\"sealed_key\":\"" KEYID "\",\"basis\":\"walk\"") \
           RL("etc", "content", "true") RL("home/u/.ssh", "content", "false") RL("opt", "metadata", "false") RL("usr", "metadata", "true")
#define PD(p) DIR_(p, ",\"partial\":true")
#define SEAL_ REG_("etc/shadow", SHA_ ",\"sealed\":true")
    /* as a capture writes it */
    REQUIRE_MSG(read_text(SR PD(".") "{\"path\":\"bin\",\"type\":\"lnk\",\"mode\":41471,\"uid\":0,\"gid\":0,\"size\":1,\"mtime_ns\":1,"
                          "\"ctime_ns\":1,\"ino\":4,\"dev\":1,\"nlink\":1,\"link_target\":\"u\"}\n"
                          DIR_("etc", "") SEAL_ PD("home") NR_("home/o", "") PD("home/u") NR_("proc", "")
                          DIR_("usr", "") REG_("usr/tool", ",\"meta\":true") T5(10, 2, 1, 1)) == 0, "%s", belay_err_msg());
    static const struct { const char *what, *text, *msg; } C[] = {
        /* no roots: as version 4 */
        { "partial without roots", H5 PD(".") T5(1, 0, 0, 0), "a capture of a whole scope" },
        { "not_read without roots", H5 ROOT_ NR_("d", "") T5(2, 1, 0, 0), "a capture of a whole scope" },
        { "meta without roots", H5 ROOT_ REG_("f", ",\"meta\":true") T5(2, 0, 1, 0), "a capture of a whole scope" },
        { "sealed without roots", K5 ROOT_ REG_("f", SHA_ ",\"sealed\":true") T5(2, 0, 0, 1), "a capture of a whole scope" },
        /* with roots */
        { "the scope root not partial", SR ROOT_ DIR_("etc", "") SEAL_ T5(3, 0, 0, 1), "scope root is not partial" },
        { "a file in a partial directory", SR PD(".") DIR_("etc", "") SEAL_ REG_("top.txt", SHA_) T5(4, 0, 0, 1), "outside every root" },
        { "a file in a partial home", SR PD(".") DIR_("etc", "") SEAL_ PD("home") PD("home/u") REG_("home/u/notes", SHA_) T5(6, 0, 0, 1),
          "outside every root" },
        { "a directory below a plain directory outside the roots", SR PD(".") DIR_("etc", "") SEAL_ DIR_("srv", "") NR_("srv/d", "") T5(5, 1, 0, 1),
          "outside every root" },
        { "meta under a content root", SR PD(".") DIR_("etc", "") REG_("etc/f", ",\"meta\":true") SEAL_ T5(4, 0, 1, 1), "meta under a content root" },
        { "sealed under a metadata root", SR PD(".") DIR_("etc", "") SEAL_ DIR_("usr", "") REG_("usr/f", SHA_ ",\"sealed\":true") T5(5, 0, 0, 2),
          "sealed under a metadata root" },
        { "partial under a root", SR PD(".") DIR_("etc", "") SEAL_ PD("etc/sub") T5(4, 0, 0, 1), "partial on a directory under a root" },
        { "a root itself partial", SR PD(".") PD("etc") SEAL_ T5(3, 0, 0, 1), "partial on a directory under a root" },
        { "entries under a root not found", SR PD(".") DIR_("etc", "") SEAL_ DIR_("opt", "") T5(4, 0, 0, 1), "a root that was not found" },
        { "an entry below a root not found", SR PD(".") DIR_("etc", "") SEAL_ PD("home") PD("home/u") DIR_("home/u/.ssh", "") T5(6, 0, 0, 1),
          "a root that was not found" },
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        const int r = read_text(C[i].text);
        if (r != -1) { BELAY_FAIL("%s: read, want refused", C[i].what); continue; }
        if (strstr(belay_err_msg(), C[i].msg) == NULL) BELAY_FAIL("%s: \"%s\", want \"%s\"", C[i].what, belay_err_msg(), C[i].msg);
    }
    /* F3's message: meta beside a hash is said as that */
    ASSERT_EQ_INT(-1, read_text(SR PD(".") DIR_("usr", "") REG_("usr/f", SHA_ ",\"meta\":true") T5(3, 0, 1, 0)));
    ASSERT_TRUE(strstr(belay_err_msg(), "meta with sha256 or unverified") != NULL);
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

static ino_t g_mount_ino[2];        /* the directories reported as mount roots (their fstat agrees) */
static int g_mount_inos;

/* A machine in small: what the roots below read, read as metadata, and do
 * not read. */
static void tree(void) {
    g_mount_inos = 0;
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
    mk("root/open", 0755);
    wr("root/open/deep", "deep\n", 0644);
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
static int g_dir_syncs;             /* fsyncs of a directory, counted by the decorated ops */
static ino_t g_gid_ino;             /* this inode is reported with another group ... */
static bool g_gid_on;               /* ... once this is set */

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

static char *slurp(const char *path) {
    char *text = NULL;
    size_t cap = 0;
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    const ssize_t n = getdelim(&text, &cap, '\0', f);
    fclose(f);
    if (n < 0) { free(text); return NULL; }
    return text;
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
    ASSERT_TRUE(strstr(line_of(g_m2, ""), ",\"source\":null,\"roots\":0,\"basis\":\"walk\"}\n") != NULL);
    ASSERT_TRUE(strstr(line_of(g_m2, NULL), ",\"unguarded\":") != NULL);
    ASSERT_TRUE(strstr(line_of(g_m2, NULL), ",\"not_read\":0,\"meta\":0,\"sealed\":0,\"carried\":0,\"racy\":0}\n") != NULL);
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
    /* V5-A1: the header's count, then one line per root, before the first entry */
    char count[64];
    snprintf(count, sizeof count, ",\"roots\":%zu,\"sealed_key\":\"", sizeof ROOTS / sizeof ROOTS[0]);
    ASSERT_TRUE(strstr(line_of(g_m2, ""), count) != NULL);
    char *all = slurp(g_m2);
    REQUIRE(all != NULL);
    const char *l2 = strchr(all, '\n') + 1;
    static const char FIRST[] = "{\"root\":\"etc\",\"class\":\"content\",\"found\":true}\n";
    ASSERT_TRUE(strncmp(l2, FIRST, sizeof FIRST - 1) == 0);
    ASSERT_TRUE(strstr(all, "\n{\"root\":\"home/u/.profile\",\"class\":\"content\",\"found\":false}\n") != NULL);
    const char *last_root = strstr(all, "\n{\"root\":\"var\",\"class\":\"metadata\",\"found\":true}\n{\"path\":");
    ASSERT_TRUE(last_root != NULL && strstr(last_root + 1, "\n{\"root\":") == NULL);
    ASSERT_TRUE(strstr(all, ",\"carried\":0,\"racy\":0}\n") != NULL && strstr(all, "{\"racy\":") == NULL);
    free(all);
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
    /* any directory above it: root/open is 755 and still inside root */
    REQUIRE(ent("root/open/deep") != NULL);
    ASSERT_TRUE(ent("root/open/deep")->sealed);
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
    ASSERT_EQ_INT(4, (int)st.sealed);
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
    /* and says what to do about it, and what that costs */
    ASSERT_TRUE(strstr(belay_err_msg(), "delete it") != NULL && strstr(belay_err_msg(), "unknown") != NULL);
    struct stat ks;
    REQUIRE(stat(g_key, &ks) == 0);
    ASSERT_EQ_INT(5, (int)ks.st_size);
    unlink(g_key);
    /* 32 bytes that others can read are not a key either */
    f = fopen(g_key, "wb");
    REQUIRE(f != NULL);
    fputs("0123456789abcdef0123456789abcdef", f);
    fclose(f);
    chmod(g_key, 0644);
    ASSERT_EQ_INT(-1, capture_write(&g_ops, g_m2, g_tree, &o, NULL));
    ASSERT_TRUE(strstr(belay_err_msg(), "not a sealing key") != NULL);
    unlink(g_key);
    /* a new key is in its directory for good: the directory is synced after the link */
    g_dir_syncs = 0;
    REQUIRE(capture_write(&g_ops, g_m2, g_tree, &o, NULL) == 0 && access(g_key, F_OK) == 0);
    const int with_key = g_dir_syncs;
    g_dir_syncs = 0;
    REQUIRE(capture_write(&g_ops, g_m2, g_tree, &o, NULL) == 0);
    ASSERT_EQ_INT(g_dir_syncs + 1, with_key);       /* one more than a capture that only reads the key */
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
    ASSERT_TRUE(all >= 10);                          /* passwd, shadow, sub/x, su, (wall), l, secret, 2 x .bashrc, keys */
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
    ASSERT_EQ_INT((int)all - 2, (int)st.trusted);   /* and root/open/deep with it */
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
    ASSERT_EQ_INT((int)all - 4, (int)st.trusted);   /* shadow, root/secret, root/open/deep, authorized_keys were read */
    uint8_t key2[32];
    REQUIRE(read_key(key2));
    ASSERT_TRUE(memcmp(key, key2, 32) != 0);
    hmac_hex(key2, "root:*:1::::::\n", want);
    ASSERT_EQ_STR(want, ent("etc/shadow")->sha256_hex);
    ASSERT_TRUE(strcmp(sealed0, want) != 0);
}

/* V5-E7, V5-A2: an entry the previous manifest names racy is never trusted;
 * the others are. This build writes no racy line, so the previous manifest
 * is a real capture's with its basis, one racy line and the count written in
 * by hand. */
TEST(mark_never_trusts_an_entry_the_previous_manifest_names_racy) {
    tree();
    char first[700], edited[700];
    snprintf(first, sizeof first, "%s/first.ndjson", g_dir);
    snprintf(edited, sizeof edited, "%s/events.ndjson", g_dir);
    struct belay_manifest_stats st;
    REQUIRE(capture_roots(first, NULL, NULL) == 0);
    REQUIRE(capture_roots(g_m2, first, &st) == 0 && st.prefilter);
    const size_t all = st.trusted;
    FILE *in = fopen(first, "rb"), *out = fopen(edited, "wb");
    REQUIRE(in != NULL && out != NULL);
    static char line[70000];
    int edits = 0;
    while (fgets(line, sizeof line, in) != NULL) {
        char *b = strstr(line, ",\"basis\":\"walk\"}"), *r = strstr(line, ",\"racy\":0}");
        if (b != NULL) { snprintf(b, 32, ",\"basis\":\"events\"}\n"); edits++; }
        if (r != NULL) {
            fputs("{\"racy\":\"etc/passwd\"}\n{\"racy\":\"usr/local/bin/l\"}\n", out);
            snprintf(r, 40, ",\"racy\":2}\n");
            edits++;
        }
        fputs(line, out);
    }
    fclose(in);
    fclose(out);
    REQUIRE(edits == 2);
    REQUIRE_MSG(capture_roots(g_m2, edited, &st) == 0, "%s", belay_err_msg());
    REQUIRE_MSG(st.prefilter, "the prefilter was not used: %s", st.prefilter_skipped ? st.prefilter_skipped : "?");
    ASSERT_EQ_INT((int)all - 2, (int)st.trusted);   /* the two named were read; every other file trusted */
    ASSERT_TRUE(strstr(line_of(g_m2, NULL), ",\"racy\":0}") != NULL);
}

/* ---------- injected: mounts, a file that cannot be opened, changes during the walk ---------- */

static const char *g_mount_name;    /* reported as a mount root */
static const char *g_mount_name2;   /* a second one, of the same filesystem */
static const char *g_mountinfo;     /* the mount table the capture is given; NULL: none */
static bool g_same_dev;             /* the mount is of the scope's own device */
static const char *g_deny;          /* openat of this name fails EACCES (not O_PATH) */
static void (*g_action)(void);      /* runs once, when the walk is over and before the re-check */
static int g_tmpfiles;

static bool g_no_statx;             /* the platform cannot stat with mount knowledge */
static int t_stat_mount(void *ctx, int dfd, const char *name, struct stat *st, bool *mr, bool *mk) {
    if (g_no_statx) { *mr = *mk = false; errno = ENOSYS; return -1; }
    const int r = g_real->stat_mount(ctx, dfd, name, st, mr, mk);
    if (r != 0) {                   /* no statx here: the same answer by lstat */
        if (g_real->fstatat(ctx, dfd, name[0] ? name : ".", st, AT_SYMLINK_NOFOLLOW) != 0) return -1;
        *mr = false;
    }
    *mk = true;
    if ((g_mount_name != NULL && strcmp(name, g_mount_name) == 0) || (g_mount_name2 != NULL && strcmp(name, g_mount_name2) == 0)) {
        *mr = true;
        if (!g_same_dev) st->st_dev += 1000;        /* a mounted filesystem has its own device */
        if (g_mount_inos < 2 && (g_mount_inos == 0 || g_mount_ino[0] != st->st_ino)) g_mount_ino[g_mount_inos++] = st->st_ino;
    }
    if (g_gid_on && st->st_ino == g_gid_ino) st->st_gid += 1;
    return 0;
}

static int t_mount_id(void *ctx, int dfd, const char *name, uint64_t *id) {
    (void)ctx; (void)dfd;
    if (g_mount_name != NULL && strcmp(name, g_mount_name) == 0) { *id = 77; return 0; }
    if (g_mount_name2 != NULL && strcmp(name, g_mount_name2) == 0) { *id = 77; return 0; }   /* the same mount source */
    return -1;
}

static char *t_mountinfo(void *ctx) {
    (void)ctx;
    return g_mountinfo != NULL ? strdup(g_mountinfo) : NULL;
}

static int t_fstat(void *ctx, int fd, struct stat *st) {
    const int r = g_real->fstat(ctx, fd, st);
    if (r == 0 && g_gid_on && st->st_ino == g_gid_ino) st->st_gid += 1;
    for (int i = 0; r == 0 && !g_same_dev && g_mount_name != NULL && i < g_mount_inos; i++)
        if (st->st_ino == g_mount_ino[i]) st->st_dev += 1000;
    return r;
}

static int t_fsync(void *ctx, int fd) {
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) g_dir_syncs++;
    return g_real->fsync(ctx, fd);
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
    g_ops.mount_id = t_mount_id;
    g_ops.mountinfo = t_mountinfo;
    g_ops.openat = t_openat;
    g_ops.tmpfile_in = t_tmpfile_in;
    g_ops.fstat = t_fstat;
    g_ops.fsync = t_fsync;
}

/* V5-E6 as manifest-v5-addendum V5-A5 has it: a mount point under a root is
 * entered only when its filesystem type is on the list, it is the mount of a
 * whole filesystem (its root in mountinfo is /), and that filesystem's device
 * is not one the capture already walks or has entered. Anything else -- a
 * bind mount of a directory included -- is a `mount` entry. The mount table
 * here is the test's (no mount is made). */
#define MI(id, root, type) #id " 30 8:" #id " " root " /mnt/" #id " rw,relatime shared:1 - " type " /dev/x rw\n"
TEST(a_mount_is_entered_by_its_filesystem_type) {
    struct belay_manifest_stats st;
    static const struct { const char *what, *table; bool entered; } C[] = {
        { "ext4, a whole filesystem", MI(77, "/", "ext4"), true },
        { "xfs", MI(77, "/", "xfs"), true },
        { "btrfs", MI(77, "/", "btrfs"), true },
        { "zfs", MI(77, "/", "zfs"), true },
        { "tmpfs", MI(77, "/", "tmpfs"), false },
        { "overlay", MI(77, "/", "overlay"), false },
        { "proc", MI(77, "/", "proc"), false },
        { "ext4, a directory of it bound", MI(77, "/srv/data", "ext4"), false },
        { "ext4, a file of it bound", MI(77, "/etc/hosts", "ext4"), false },
        { "a type that only starts like one", MI(77, "/", "ext4dev"), false },
        { "not in the table", MI(76, "/", "ext4") MI(771, "/", "ext4"), false },
        { "the table unreadable", NULL, false },
        { "a source that looks like a separator and a type", "77 30 8:1 / /mnt rw - tmpfs a - ext4 rw\n", false },
        { "optional fields that look like a type", "77 30 8:1 /srv/data /mnt rw - ext4 /dev/x rw\n78 30 8:2 / /ext4 rw - tmpfs none rw\n", false },
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        tree();
        g_mount_name = "sub";
        g_mountinfo = C[i].table;
        const int r = capture_roots(g_m2, NULL, &st);
        g_mount_name = NULL;
        if (r != 0 || ent("etc/sub") == NULL) { BELAY_FAIL("%s: no capture (%s)", C[i].what, belay_err_msg()); continue; }
        if (ent("etc/sub")->is_mount == C[i].entered || (ent("etc/sub/x") != NULL) != C[i].entered)
            BELAY_FAIL("%s: %s", C[i].what, C[i].entered ? "not entered" : "entered");
        if (C[i].entered && (st.mounts + st.raced + st.unstable) != 0) BELAY_FAIL("%s: the re-check did not enter it too", C[i].what);
        if (!C[i].entered && st.mounts != 1) BELAY_FAIL("%s: %zu mounts", C[i].what, st.mounts);
    }
    /* the same filesystem mounted a second time: the first met is entered, the second a mount entry */
    tree();
    mk("etc/sub2", 0755);
    wr("etc/sub2/y", "y\n", 0644);
    g_mount_name = "sub";
    g_mount_name2 = "sub2";
    g_mountinfo = MI(77, "/", "ext4");
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0);
    ASSERT_EQ_INT(1, (int)st.mounts);
    ASSERT_TRUE(ent("etc/sub")->is_mount != ent("etc/sub2")->is_mount);
    ASSERT_TRUE((ent("etc/sub/x") != NULL) != (ent("etc/sub2/y") != NULL));
    ASSERT_EQ_INT(0, (int)(st.raced + st.unstable));
    g_mount_name2 = NULL;
    /* a mount of the device the scope itself is on (a bind of the scope's own filesystem): never entered */
    tree();
    g_same_dev = true;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0);
    g_same_dev = false;
    ASSERT_TRUE(ent("etc/sub")->is_mount && ent("etc/sub/x") == NULL);
    /* a capture of a whole scope enters no mount, whatever it is (as version 4) */
    const struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20 };
    REQUIRE(capture_write(&g_ops, g_m2, g_tree, &o, &st) == 0);
    ASSERT_EQ_INT(1, (int)st.mounts);
    ASSERT_TRUE(strstr(line_of(g_m2, "etc/sub"), "\"mount\":true") != NULL);
    g_mount_name = NULL;
}

/* The platform's own answers, asked once for real: /proc is a mount, it has
 * an id, the mount table names it, and it is not a filesystem to enter. */
TEST(the_real_mount_table_is_read) {
#ifndef __linux__
    SKIP("the mount table and mount ids are Linux's; elsewhere no mount is entered");
#else
    const struct fsops *ops = fsops_default();
    const int root = open("/", O_RDONLY | O_DIRECTORY);
    REQUIRE(root != -1);
    uint64_t id = 0;
    char *table = ops->mountinfo(ops->ctx);
    const int have = ops->mount_id(ops->ctx, root, "proc", &id);
    close(root);
    REQUIRE(table != NULL && table[0] != '\0');
    REQUIRE_MSG(have == 0, "%s", "no mount id for /proc");
    char want[32];
    snprintf(want, sizeof want, "\n%llu ", (unsigned long long)id);
    ASSERT_TRUE(strstr(table, want) != NULL || strncmp(table, want + 1, strlen(want + 1)) == 0);
    ASSERT_TRUE(!fsops_mount_whole_listed(table, id));
    free(table);
#endif
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
static void regroup(void) { g_gid_on = true; }       /* as a chgrp would, without needing a second group */
static ino_t ino_of(const char *rel) {
    char p[1200];
    struct stat st;
    snprintf(p, sizeof p, "%s/%s", g_tree, rel);
    return stat(p, &st) == 0 ? st.st_ino : 0;
}
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
    /* so is its owner and group (V5-D4 compares them): a chgrp during the walk is raced */
    tree();
    g_gid_ino = ino_of("home/other");
    g_tmpfiles = 0; g_action = regroup;
    const int r1 = capture_roots(g_m2, NULL, &st);
    g_gid_on = false;
    REQUIRE(r1 == 0 && g_action == NULL);
    ASSERT_EQ_INT(1, (int)st.raced);
    ASSERT_TRUE(ent("home/other")->raced);
    /* a partial directory's too: its listing is what no longer holds as recorded */
    tree();
    g_gid_ino = ino_of("home/u");
    g_tmpfiles = 0; g_action = regroup;
    const int r2 = capture_roots(g_m2, NULL, &st);
    g_gid_on = false;
    REQUIRE(r2 == 0 && g_action == NULL);
    ASSERT_EQ_INT(1, (int)st.unstable);
    ASSERT_TRUE(ent("home/u")->unstable && ent("home/u")->partial);
}

/* A root the scope excludes was not looked at: it is not `found`. */
TEST(an_excluded_root_is_not_found) {
    tree();
    struct belay_manifest_opts o = opts_roots(NULL);
    static const char *const X[] = { "etc" };
    o.exclude_paths = X;
    o.n_exclude_paths = 1;
    REQUIRE(capture_write(&g_ops, g_m2, g_tree, &o, NULL) == 0);
    char *all = slurp(g_m2);
    REQUIRE(all != NULL);
    ASSERT_TRUE(strstr(all, "\n{\"root\":\"etc\",\"class\":\"content\",\"found\":false}\n") != NULL);
    ASSERT_TRUE(strstr(all, "{\"path\":\"etc\",\"reason\":\"user\",") != NULL && strstr(all, "\n{\"path\":\"etc/passwd\"") == NULL);
    free(all);
}

/* V5-E5: the scope root's own search bit counts, like any directory's above a file. */
TEST(a_scope_root_others_cannot_search_seals_everything_read) {
    tree();
    REQUIRE(chmod(g_tree, 0750) == 0);
    struct belay_manifest_stats st;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0);
    REQUIRE(ent("etc/sub/x") != NULL && ent("etc/passwd") != NULL);
    ASSERT_TRUE(ent("etc/sub/x")->sealed && ent("etc/passwd")->sealed);
    ASSERT_TRUE(!ent("home/u/.bashrc")->sealed && ent("usr/bin/tool")->meta);    /* the exceptions stand */
    chmod(g_tree, 0755);
}

/* V5-4: a not_read directory's ctime is not recorded, so it is no part of
 * the newest ctime a later mark measures the clock by. */
TEST(a_not_read_directory_s_ctime_is_not_the_newest) {
    tree();
    pause_ms(30);
    wr("var/log/later", "l\n", 0644);            /* var/log's own ctime is now the newest in the scope */
    char p[1200];
    struct stat ls;
    snprintf(p, sizeof p, "%s/var/log", g_tree);
    REQUIRE(stat(p, &ls) == 0);
#ifdef __APPLE__
    const int64_t dir_ct = (int64_t)ls.st_ctimespec.tv_sec * 1000000000LL + ls.st_ctimespec.tv_nsec;
#else
    const int64_t dir_ct = (int64_t)ls.st_ctim.tv_sec * 1000000000LL + ls.st_ctim.tv_nsec;
#endif
    struct belay_manifest_stats st;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0);
    ASSERT_TRUE(st.newest_ctime_ns < dir_ct);
}

/* manifest-v5-addendum V5-A4: a symbolic link standing where a directory on
 * the way to a root is looked for is recorded as a link, never followed; the
 * roots below it are not found. */
TEST(a_link_on_the_way_to_a_root_is_recorded) {
    tree();
    mk("home/u/.config", 0755); mk("home/u/.config/systemd", 0755); mk("home/u/.config/systemd/user", 0755);
    wr("home/u/.config/systemd/user/x.service", "[Unit]\n", 0644);
    REQUIRE(capture_roots(g_m2, NULL, NULL) == 0);
    REQUIRE(ent("home/u/.config") != NULL && ent("home/u/.config/systemd/user/x.service") != NULL);
    ASSERT_TRUE(ent("home/u/.config")->type == BELAY_T_DIR && ent("home/u/.config")->partial);
    /* .config replaced by a link to a directory elsewhere that holds the same names */
    char cmd[3000];
    snprintf(cmd, sizeof cmd, "cd '%s/home/u' && mv .config ../elsewhere && ln -s ../elsewhere .config", g_tree);
    REQUIRE(system(cmd) == 0);
    struct belay_manifest_stats st;
    REQUIRE(capture_roots(g_m2, NULL, &st) == 0);
    REQUIRE_MSG(ent("home/u/.config") != NULL, "%s", "the link is not recorded");
    ASSERT_TRUE(ent("home/u/.config")->type == BELAY_T_LNK);
    ASSERT_EQ_STR("../elsewhere", ent("home/u/.config")->link_target);
    ASSERT_TRUE(ent("home/u/.config/systemd") == NULL && ent("home/u/.config/systemd/user/x.service") == NULL);
    char *all = slurp(g_m2);
    REQUIRE(all != NULL);
    ASSERT_TRUE(strstr(all, "\n{\"root\":\"home/u/.config/systemd/user\",\"class\":\"content\",\"found\":false}\n") != NULL);
    free(all);
    ASSERT_EQ_INT(0, (int)(st.unstable + st.raced));     /* the re-check counts the link as the walk did */
    /* a link that is on the way to nothing is still nobody's business */
    ASSERT_TRUE(ent("home/u/link") == NULL);
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

/* V5-A1: with one line per root no number of homes is too many (in the
 * header's array, about 60 were: the line limit). */
TEST(five_hundred_homes_are_captured) {
    tree();
    char p[1200];
    snprintf(p, sizeof p, "%s/etc/passwd", g_tree);
    FILE *f = fopen(p, "wb");
    REQUIRE(f != NULL);
    mk("home/many", 0755);
    for (int i = 0; i < 500; i++) {
        char rel[64];
        snprintf(rel, sizeof rel, "home/many/user%03d", i);
        mk(rel, 0755);
        fprintf(f, "user%03d:x:%d:%d::/%s:/bin/sh\n", i, 2000 + i, 2000 + i, rel);
    }
    fclose(f);
    wr("home/many/user250/.bashrc", "export B=2\n", 0644);
    pause_ms(30);
    REQUIRE(belay_system_roots(g_tree, &g_sr) == 0);
    ASSERT_TRUE(g_sr.n_roots >= 500 * 14);
    const struct belay_manifest_opts o = {
        .hash_max_bytes = 1u << 20, .roots = g_sr.roots, .n_roots = g_sr.n_roots,
        .not_read = g_sr.not_read, .n_not_read = g_sr.n_not_read, .sealing_key_path = g_key,
    };
    struct belay_manifest_stats st;
    const size_t n = g_sr.n_roots;
    const int rc = capture_write(&g_ops, g_m2, g_tree, &o, &st);
    belay_system_roots_free(&g_sr);
    REQUIRE_MSG(rc == 0, "%s", belay_err_msg());
    /* and it reads back, every root there */
    struct belay_manifest_reader *r;
    REQUIRE_MSG(belay_manifest_open(g_m2, &r) == 0, "%s", belay_err_msg());
    const struct belay_manifest_header *h = belay_manifest_header(r);
    ASSERT_EQ_INT((int)n, (int)h->n_roots);
    ASSERT_TRUE(belay_manifest_lists_root(h, "home/many/user499/.ssh", 22));
    ASSERT_TRUE(belay_manifest_lists_root(h, "home/many/user250/.bashrc", 25));
    static struct belay_entry e;
    int got, homes = 0, found = 0;
    while ((got = belay_manifest_next(r, &e)) == 1) {
        if (e.path_len == 17 && memcmp(e.path, "home/many/user", 14) == 0 && e.partial) homes++;
        if (e.path_len == 25 && memcmp(e.path, "home/many/user250/.bashrc", 25) == 0) found++;
    }
    ASSERT_EQ_INT(0, got);
    ASSERT_EQ_INT(500, homes);
    ASSERT_EQ_INT(1, found);
    belay_manifest_close(r);
}

/* A reader of the header line alone (a delta holds no more of a manifest)
 * has the count of roots, and no root. */
TEST(a_header_alone_gives_the_count) {
    FILE *f = fopen(g_m, "wb");
    REQUIRE(f != NULL);
    fputs(H5R(3), f);
    fclose(f);
    struct belay_manifest_reader *r;
    ASSERT_EQ_INT(-1, belay_manifest_open(g_m, &r));        /* as a manifest it is cut short */
    REQUIRE_MSG(belay_manifest_open_header(g_m, &r) == 0, "%s", belay_err_msg());
    ASSERT_EQ_INT(3, (int)belay_manifest_header(r)->n_roots);
    ASSERT_TRUE(belay_manifest_header(r)->roots == NULL);
    static struct belay_entry e;
    ASSERT_EQ_INT(-1, belay_manifest_next(r, &e));          /* a header, not a manifest to read on */
    belay_manifest_close(r);
    /* nor when the file does hold the rest */
    f = fopen(g_m, "wb");
    REQUIRE(f != NULL);
    fputs(H5 ROOT_ T5(1, 0, 0, 0), f);
    fclose(f);
    REQUIRE(belay_manifest_open_header(g_m, &r) == 0);
    ASSERT_EQ_INT(-1, belay_manifest_next(r, &e));
    ASSERT_EQ_INT(-1, belay_manifest_rewind(r));
    belay_manifest_close(r);
}

/* etc/passwd is not ours: a line with a NUL byte or one too long to be a
 * line is dropped alone; a last line without a newline is used; a passwd
 * that is a link is not read at all. */
TEST(system_roots_from_a_hostile_passwd) {
    tree();
    mk("home/a", 0755); mk("home/b", 0755); mk("home/c", 0755); mk("home/d", 0755); mk("home/e", 0755);
    char p[1200];
    snprintf(p, sizeof p, "%s/etc/passwd", g_tree);
    FILE *f = fopen(p, "wb");
    REQUIRE(f != NULL);
    fwrite("x:x:1:1:ge\0cos:/home/a:/bin/sh\n", 1, 31, f);        /* a NUL inside the line */
    fputs("b:x:2:2::/home/b:/bin/sh\n", f);
    fputs("long:x:3:3::/home/d:", f);
    for (int i = 0; i < 20000; i++) fputc('s', f);               /* longer than any line is read: not cut and used */
    fputs("\n", f);
    fwrite("e:x:6:6::/home/e\0:/bin/sh\n", 1, 26, f);             /* a NUL after the home: the line is no line */
    fputs("c:x:4:4::/home/c:/bin/sh", f);                        /* no final newline */
    fclose(f);
    REQUIRE(belay_system_roots(g_tree, &g_sr) == 0);
    ASSERT_TRUE(sroot("home/a/.ssh") == NULL);      /* its home field cannot be told from what follows the NUL */
    ASSERT_TRUE(sroot("home/b/.ssh") != NULL);      /* the line after it is a line of its own */
    ASSERT_TRUE(sroot("home/d/.ssh") == NULL);
    ASSERT_TRUE(sroot("home/e/.ssh") == NULL);
    ASSERT_TRUE(sroot("home/c/.ssh") != NULL);
    belay_system_roots_free(&g_sr);
    /* the same home on many lines: once, and no more roots than one home's */
    f = fopen(p, "wb");
    REQUIRE(f != NULL);
    for (int i = 0; i < 2000; i++) fprintf(f, "u%d:x:%d:%d::/home/b:/bin/sh\n", i, i, i);
    fclose(f);
    REQUIRE(belay_system_roots(g_tree, &g_sr) == 0);
    size_t under = 0;
    for (size_t i = 0; i < g_sr.n_roots; i++) under += strncmp(g_sr.roots[i].path, "home/b/", 7) == 0;
    ASSERT_EQ_INT(14, (int)under);
    belay_system_roots_free(&g_sr);
    /* etc/passwd a link: not followed, no homes */
    char real[1300];
    snprintf(real, sizeof real, "%s/etc/passwd.real", g_tree);
    REQUIRE(rename(p, real) == 0 && symlink("passwd.real", p) == 0);
    REQUIRE(belay_system_roots(g_tree, &g_sr) == 0);
    ASSERT_TRUE(sroot("home/b/.ssh") == NULL && sroot("etc") != NULL);
    belay_system_roots_free(&g_sr);
}

/* WS-8a's two clauses a real tree cannot show without mounting: a home on a
 * filesystem the capture does not enter is not used; and where the platform
 * cannot say what is a mount (no statx), a link is still never followed. */
TEST(system_roots_homes_by_mount_and_without_statx) {
    tree();
    mk("srv", 0755); mk("srv/real", 0755);
    char l[1200];
    snprintf(l, sizeof l, "%s/srv/link", g_tree);
    REQUIRE(symlink("real", l) == 0);
    wr("etc/passwd", "u:x:1000:1000::/home/u:/bin/sh\nl:x:1001:1001::/srv/link:/bin/sh\nr:x:1002:1002::/srv/real:/bin/sh\n", 0644);
    g_mount_name = "home/u";            /* the resolver asks by the home's path */
    g_mountinfo = MI(77, "/", "tmpfs");
    REQUIRE(sysroots_resolve(&g_ops, g_tree, &g_sr) == 0);
    ASSERT_TRUE(sroot("home/u/.ssh") == NULL && sroot("srv/real/.ssh") != NULL);
    belay_system_roots_free(&g_sr);
    g_mountinfo = MI(77, "/", "ext4");
    REQUIRE(sysroots_resolve(&g_ops, g_tree, &g_sr) == 0);
    ASSERT_TRUE(sroot("home/u/.ssh") != NULL);
    belay_system_roots_free(&g_sr);
    g_mountinfo = MI(77, "/home", "ext4");          /* a directory of it, bound */
    REQUIRE(sysroots_resolve(&g_ops, g_tree, &g_sr) == 0);
    ASSERT_TRUE(sroot("home/u/.ssh") == NULL);
    belay_system_roots_free(&g_sr);
    g_mount_name = NULL;
    g_no_statx = true;
    const int r = sysroots_resolve(&g_ops, g_tree, &g_sr);
    g_no_statx = false;
    REQUIRE(r == 0);
    ASSERT_TRUE(sroot("home/u/.ssh") != NULL && sroot("srv/real/.ssh") != NULL && sroot("srv/link/.ssh") == NULL);
    belay_system_roots_free(&g_sr);
}

/* A home so deep that its roots would not fit a path is left out (it joins
 * the homes WS-8a leaves out); the capture does not fail. */
TEST(a_home_too_deep_for_its_roots_is_left_out) {
    tree();
    char comp[204], home[4200] = "home", cmd[9000];
    memset(comp, 'd', 203);
    comp[203] = '\0';
    for (int i = 0; i < 20; i++) { strcat(home, "/"); strcat(home, comp); }      /* 4084 bytes */
    snprintf(cmd, sizeof cmd, "cd '%s' && mkdir -p '%s'", g_tree, home);
    REQUIRE(system(cmd) == 0);
    char p[1200];
    snprintf(p, sizeof p, "%s/etc/passwd", g_tree);
    FILE *f = fopen(p, "wb");
    REQUIRE(f != NULL);
    fprintf(f, "deep:x:5:5::/%s:/bin/sh\nu:x:1000:1000::/home/u:/bin/sh\n", home);
    fclose(f);
    pause_ms(30);
    REQUIRE(belay_system_roots(g_tree, &g_sr) == 0);
    for (size_t i = 0; i < g_sr.n_roots; i++)
        if (strncmp(g_sr.roots[i].path, "home/ddd", 8) == 0) { BELAY_FAIL("a root of the deep home: %.40s...", g_sr.roots[i].path); break; }
    ASSERT_TRUE(sroot("home/u/.ssh") != NULL);
    const struct belay_manifest_opts o = {
        .hash_max_bytes = 1u << 20, .roots = g_sr.roots, .n_roots = g_sr.n_roots,
        .not_read = g_sr.not_read, .n_not_read = g_sr.n_not_read, .sealing_key_path = g_key,
    };
    const int rc = capture_write(&g_ops, g_m2, g_tree, &o, NULL);
    belay_system_roots_free(&g_sr);
    REQUIRE_MSG(rc == 0, "%s", belay_err_msg());
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
    RUN(v5_structure_by_the_roots);
    RUN(a_whole_scope_is_written_as_v5_with_no_roots);
    RUN(roots_make_partial_and_not_read_directories);
    RUN(a_metadata_root_reads_only_what_grants_privilege);
    RUN(a_file_others_cannot_read_is_sealed);
    RUN(the_key_is_made_only_when_needed);
    RUN(roots_that_are_not_a_sorted_list_are_refused);
    RUN(mark_trusts_by_class_and_by_key);
    RUN(mark_never_trusts_an_entry_the_previous_manifest_names_racy);
    RUN(five_hundred_homes_are_captured);
    RUN(a_header_alone_gives_the_count);
    RUN(a_mount_is_entered_by_its_filesystem_type);
    RUN(the_real_mount_table_is_read);
    RUN(a_meta_file_that_cannot_be_opened_is_still_meta);
    RUN(the_recheck_looks_at_what_was_recorded);
    RUN(an_excluded_root_is_not_found);
    RUN(a_scope_root_others_cannot_search_seals_everything_read);
    RUN(a_not_read_directory_s_ctime_is_not_the_newest);
    RUN(a_link_on_the_way_to_a_root_is_recorded);
    RUN(system_roots_from_a_hostile_passwd);
    RUN(system_roots_homes_by_mount_and_without_statx);
    RUN(a_home_too_deep_for_its_roots_is_left_out);
    RUN(system_roots_fixed);
    RUN(system_roots_homes);
    RUN(system_roots_capture);
    rm_rf(g_dir);
    return belay_test_report();
}
