/*
 *  Manifest reader tests.
 *
 *  The reader treats its input as untrusted: a manifest can be hand-edited,
 *  truncated by a full disk, or corrupted. Every malformed form must be a hard
 *  error rather than a repair, because a reader that guesses would let two
 *  different files mean the same thing and make `diff` report a delta that
 *  never happened.
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/manifest.h"
#include "belay/hash.h"
#include "belay/error.h"
#include "capture/manifest_decode.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HDR "{\"belay_manifest\":1,\"created_ns\":0,\"scopes\":[\"/s\"]," \
            "\"hash\":\"sha256\",\"hash_max_bytes\":67108864," \
            "\"store_max_bytes\":65536}\n"

#define EMPTY_SHA "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define ENTRY_REG(p) "{\"path\":\"" p "\",\"type\":\"reg\",\"mode\":33188," \
    "\"uid\":1000,\"gid\":1000,\"size\":5,\"mtime_ns\":1,\"ctime_ns\":2," \
    "\"ino\":10,\"dev\":20,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"
#define ROOT_E "{\"path\":\".\",\"type\":\"dir\",\"mode\":16877,\"uid\":1,\"gid\":1," \
    "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,\"nlink\":2}\n"

static char g_path[4096];

/* Writes `content` exactly as given -- for tests about truncation and other
 * framing errors, where an automatic trailer would mask the case. */
static void write_raw(const char *content) {
    snprintf(g_path, sizeof g_path, "/tmp/belay_mr_%d.ndjson", (int)getpid());
    FILE *f = fopen(g_path, "wb");
    if (f == NULL) return;
    fputs(content, f);
    fclose(f);
}

static size_t count_sub(const char *s, const char *sub) {
    size_t n = 0;
    for (const char *p = s; (p = strstr(p, sub)) != NULL; p += strlen(sub)) n++;
    return n;
}

/* Writes `content` followed by a trailer whose counts match it: one entry per
 * line after the header, and the unreadable/unstable flags it contains. Tests
 * about entry parsing then exercise the entry, not the trailer. */
static void write_manifest(const char *content) {
    size_t lines = 0;
    for (const char *p = content; *p; p++) if (*p == '\n') lines++;
    size_t entries = lines > 0 ? lines - 1 : 0;

    /* Every real manifest records the scope root "." -- add it right after
     * the header unless the test supplies its own. */
    const char *nl = strchr(content, '\n');
    const bool add_root = nl != NULL && strstr(content, "{\"path\":\".\",") == NULL;
    if (add_root) entries++;

    char *buf = malloc(strlen(content) + 512);
    if (buf == NULL) return;
    if (add_root) {
        const size_t hl = (size_t)(nl - content) + 1;
        memcpy(buf, content, hl);
        buf[hl] = '\0';
        strcat(buf, ROOT_E);
        strcat(buf, nl + 1);
    } else {
        strcpy(buf, content);
    }
    char trailer[256];
    snprintf(trailer, sizeof trailer,
             "{\"belay_manifest_end\":%zu,\"vanished\":0,\"unreadable\":%zu,\"unstable\":%zu,"
             "\"mounts\":%zu,\"raced\":%zu}\n",
             entries, count_sub(content, "\"unreadable\":true"),
             count_sub(content, "\"unstable\":true"), count_sub(content, "\"mount\":true"),
             count_sub(content, "\"raced\":true"));
    strcat(buf, trailer);
    write_raw(buf);
    free(buf);
}

/* ---------- collector ---------- */

#define MAX_E 64
static struct belay_entry g_e[MAX_E];
static size_t g_n;

/* Collects every entry except the scope root ".", which every valid manifest
 * now carries (write_manifest adds it); tests then see only their own. */
static int collect(const struct belay_entry *e, void *ctx) {
    (void)ctx;
    if (e->path_len == 1 && e->path[0] == '.') return 0;
    if (g_n < MAX_E) g_e[g_n++] = *e;
    return 0;
}

static int read_it(const char *content) {
    g_n = 0;
    write_manifest(content);
    return belay_manifest_read(g_path, collect, NULL);
}

/* A rejection counts only for its own reason (audit 2026-10): a fixture
 * rejected for anything else proves nothing about the rule it names, and
 * several here once were -- by canonical order or rule 5 -- while the rule
 * they named was never reached. Reasons are written by hand from each
 * test's intent. */
#define EXPECT_REJECT(what, rc, reason)                                                 \
    do {                                                                                \
        if ((rc) != -1) BELAY_FAIL("accepted: %s", what);                               \
        else if (strstr(belay_err_msg(), reason) == NULL)                               \
            BELAY_FAIL("%s: rejected for another reason: %s", what, belay_err_msg());   \
        belay_err_clear();                                                              \
    } while (0)

/* ---------- tests ---------- */
#define H64C "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

/* One witness per schema rule (audit 2026-10, R2): a manifest whose only fault
 * is that rule, which the reader must reject with that rule's own message.
 * Removing any one rule makes its witness fail; before, eight rules could be
 * removed with every check passing. Expectations are written here by hand. */
#define W_BASE(type, mode, size) "{\"path\":\"w\",\"type\":\"" type "\",\"mode\":" #mode \
    ",\"uid\":1,\"gid\":1,\"size\":" #size ",\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":3,\"dev\":1,\"nlink\":1"
#define WX "x:00"
static const struct { const char *rule, *line, *msg; } WITNESSES[] = {
    { "1",  W_BASE("reg", 16877, 5) ",\"sha256\":\"" EMPTY_SHA "\"}", "mode's type bits disagree with type" },
    { "2",  W_BASE("reg", 33188, 5) ",\"xattrs\":[\"user.a=" EMPTY_SHA "\"],\"xattrs_sha256\":\"" EMPTY_SHA "\",\"sha256\":\"" EMPTY_SHA "\"}", "both xattrs and xattrs_sha256" },
    { "3",  W_BASE("reg", 33188, 5) ",\"caps\":\"01\",\"xattrs_unknown\":true,\"sha256\":\"" EMPTY_SHA "\"}", "xattrs_unknown with recorded attributes" },
    { "4",  W_BASE("dir", 16877, 1) ",\"caps\":\"01\"}", "caps on a non-regular file" },
    { "5",  W_BASE("reg", 33188, 5) ",\"sha256\":\"" EMPTY_SHA "\",\"unverified\":true}", "both sha256 and unverified" },
    { "5b", W_BASE("reg", 33188, 5) "}", "regular file with neither sha256 nor unverified" },
    { "6",  W_BASE("reg", 33188, 5) ",\"sha256\":\"" EMPTY_SHA "\",\"unstable\":true}", "unstable or unreadable file without unverified" },
    { "7",  W_BASE("reg", 33188, 5) ",\"unverified\":true,\"unstable\":true,\"unreadable\":true}", "file both unstable and unreadable" },
    { "8",  W_BASE("reg", 33188, 5) ",\"unverified\":true,\"unstable\":true,\"mount\":true}", "mounted file with read flags" },
    { "9",  W_BASE("dir", 16877, 1) ",\"sha256\":\"" EMPTY_SHA "\"}", "hash fields on a directory" },
    { "10", W_BASE("dir", 16877, 1) ",\"raced\":true}", "raced on a listed directory" },
    { "11", W_BASE("dir", 16877, 1) ",\"unstable\":true,\"unreadable\":true}", "directory flags unreadable, unstable and mount are exclusive" },
    { "12", W_BASE("lnk", 41471, 1) ",\"unverified\":true,\"link_target\":\"t\"}", "file-only fields on a symlink" },
    { "13", W_BASE("fifo", 4516, 0) ",\"unreadable\":true}", "read flags on a node that is never read" },
    { "14", W_BASE("reg", 33188, 5) ",\"sha256\":\"" EMPTY_SHA "\",\"stored\":\"" H64C "\"}", "stored key does not match sha256" },
    { "15", W_BASE("chr", 8630, 0) "}", "device without rdev" },
    { "16", W_BASE("lnk", 41471, 0) "}", "symlink without a target" },
    { "17", W_BASE("reg", 33188, 5) ",\"sha256\":\"" EMPTY_SHA "\",\"target_outside_scope\":true}", "target_outside_scope on a non-symlink" },
    { "18", W_BASE("lnk", 41471, 0) ",\"link_target\":\"\"}", "symlink with an empty target" },
    { "19", W_BASE("lnk", 41471, 5) ",\"link_target\":\"t\"}", "symlink size disagrees with its target's length" },
    { "20", W_BASE("lnk", 41471, 0) ",\"link_target\":\"\",\"target_outside_scope\":true,\"unreadable\":true}", "target_outside_scope on an unknown target" },
    { "21", W_BASE("reg", 33188, 5) ",\"sha256\":\"" EMPTY_SHA "\",\"mount\":true}", "hash on a mount point" },
    { "22", W_BASE("dir", 16877, 1) ",\"iflags\":0,\"mount\":true}", "extended metadata on a mount point" },
    { "header 1", W_BASE("reg", 33188, 67108865) ",\"sha256\":\"" EMPTY_SHA "\"}", "hash on a file larger than hash_max_bytes" },
    { "header 1b", W_BASE("reg", 33188, 5) ",\"unverified\":true}", "unverified file within hash_max_bytes, with no reason" },
    { "header 2", W_BASE("lnk", 41471, 4) ",\"link_target\":\"/etc\"}", "target_outside_scope missing on a link leaving the scope" },
};

TEST(every_schema_rule_has_a_witness_rejected_for_that_rule) {
    for (size_t i = 0; i < sizeof WITNESSES / sizeof WITNESSES[0]; i++) {
        char buf[4096];
        snprintf(buf, sizeof buf, HDR "%s\n", WITNESSES[i].line);
        if (read_it(buf) != -1) {
            BELAY_FAIL("rule %s: its witness was accepted", WITNESSES[i].rule);
        } else if (strstr(belay_err_msg(), WITNESSES[i].msg) == NULL) {
            BELAY_FAIL("rule %s: rejected for another reason: %s", WITNESSES[i].rule, belay_err_msg());
        }
        belay_err_clear();
    }
}

/* Reader gaps the audit found (mutants RD-02/06/15/18/19/27 passed every
 * check). Each asserts the reason, not only the rejection. */
TEST(a_duplicate_key_is_rejected_as_a_duplicate) {
    ASSERT_EQ_INT(-1, read_it(HDR "{\"path\":\"a\",\"path\":\"b\",\"type\":\"reg\"}\n"));
    ASSERT_TRUE(strstr(belay_err_msg(), "duplicate key") != NULL);
    belay_err_clear();
}

TEST(a_json_string_must_be_valid_utf8) {
    ASSERT_EQ_INT(-1, read_it(HDR "{\"path\":\"a\xff\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,"
                                  "\"gid\":1,\"size\":5,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":3,\"dev\":1,"
                                  "\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"));
    ASSERT_TRUE(strstr(belay_err_msg(), "is not UTF-8") != NULL);
    belay_err_clear();
}

TEST(nothing_may_follow_the_trailer) {
    write_raw(HDR ROOT_E "{\"belay_manifest_end\":1,\"vanished\":0,\"unreadable\":0,\"unstable\":0,"
                         "\"mounts\":0,\"raced\":0}\n" ENTRY_REG("z"));
    ASSERT_EQ_INT(-1, belay_manifest_read(g_path, collect, NULL));
    ASSERT_TRUE(strstr(belay_err_msg(), "data after the end marker") != NULL);
    belay_err_clear();
}

TEST(a_number_beyond_64_bits_is_rejected) {
    ASSERT_EQ_INT(-1, read_it(HDR "{\"path\":\"a\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,"
                                  "\"gid\":1,\"size\":99999999999999999999,\"mtime_ns\":1,\"ctime_ns\":1,"
                                  "\"ino\":3,\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"));
    ASSERT_TRUE(strstr(belay_err_msg(), "size out of range") != NULL);
    belay_err_clear();
}

TEST(iflags_and_the_trailers_vanished_count_are_decoded) {
    ASSERT_EQ_INT(0, read_it(HDR W_BASE("reg", 33188, 5) ",\"iflags\":16,\"sha256\":\"" EMPTY_SHA "\"}\n"));
    ASSERT_EQ_INT(1, (int)g_n);
    ASSERT_TRUE(g_n == 1 && g_e[0].has_iflags && g_e[0].iflags == 16);
    write_raw(HDR ROOT_E "{\"belay_manifest_end\":1,\"vanished\":3,\"unreadable\":0,\"unstable\":0,"
                         "\"mounts\":0,\"raced\":0}\n");
    struct belay_manifest_reader *r;
    REQUIRE(belay_manifest_open(g_path, &r) == 0);
    static struct belay_entry e;
    while (belay_manifest_next(r, &e) == 1) {}
    const struct belay_manifest_stats *t = belay_manifest_trailer(r);
    ASSERT_TRUE(t != NULL && t->vanished == 3);
    belay_manifest_close(r);
}


TEST(reads_a_well_formed_entry) {
    ASSERT_EQ_INT(0, read_it(HDR ENTRY_REG("src/main.c")));
    ASSERT_EQ_INT(1, (int)g_n);
    ASSERT_EQ_STR("src/main.c", g_e[0].path);
    ASSERT_EQ_INT(10, (int)g_e[0].path_len);
    ASSERT_EQ_INT(BELAY_T_REG, g_e[0].type);
    ASSERT_EQ_INT(33188, (int)g_e[0].mode);
    ASSERT_EQ_INT(1000, (int)g_e[0].uid);
    ASSERT_EQ_INT(5, (int)g_e[0].size);
    ASSERT_EQ_INT(10, (int)g_e[0].ino);
    ASSERT_EQ_INT(1, (int)g_e[0].nlink);
    ASSERT_TRUE(g_e[0].has_hash);
}

TEST(rejects_unknown_format_version) {
    ASSERT_EQ_INT(-1, read_it("{\"belay_manifest\":999}\n"));
    ASSERT_EQ_INT(BELAY_ERR_UNSUPPORTED, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "format version 999") != NULL);
    belay_err_clear();
}

TEST(rejects_missing_header) {
    ASSERT_EQ_INT(-1, read_it(ENTRY_REG("a")));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "missing header") != NULL);
    belay_err_clear();
}

TEST(rejects_empty_file) {
    g_n = 0;
    write_raw("");
    ASSERT_EQ_INT(-1, belay_manifest_read(g_path, collect, NULL));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "file is empty") != NULL);
    belay_err_clear();
}

/* A line with no trailing newline is a truncated write -- a full disk or a
 * killed process. Trusting a partial record would mean trusting a field that
 * was never written. */
TEST(rejects_truncated_final_line) {
    g_n = 0;
    write_raw(HDR "{\"path\":\"a\",\"type\":\"reg\"");
    ASSERT_EQ_INT(-1, belay_manifest_read(g_path, collect, NULL));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "truncated") != NULL);
    belay_err_clear();
}

TEST(rejects_entry_without_path) {
    EXPECT_REJECT("no path", read_it(HDR "{\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
                                          "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,"
                                          "\"ino\":1,\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"),
                  "entry has no path");
}

TEST(rejects_both_path_forms) {
    EXPECT_REJECT("both path forms", read_it(HDR "{\"path\":\"a\",\"path_b64\":\"YQ==\","
                                  "\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
                                  "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,"
                                  "\"ino\":1,\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"),
                  "both path and path_b64");
}

/* Every required numeric field must be present. Defaulting a missing mode to
 * 0 would make a chmod invisible to diff. */
TEST(rejects_missing_required_numeric_fields) {
    const char *missing[] = { "mode", "uid", "gid", "size", "mtime_ns",
                              "ctime_ns", "ino", "dev", "nlink" };
    for (size_t i = 0; i < sizeof missing / sizeof missing[0]; i++) {
        char line[1024] = HDR "{\"path\":\"a\",\"type\":\"reg\"";
        for (size_t k = 0; k < sizeof missing / sizeof missing[0]; k++) {
            if (k == i) continue;
            char f[64];
            snprintf(f, sizeof f, ",\"%s\":%d", missing[k], k == 0 ? 33188 : 1);
            strcat(line, f);
        }
        strcat(line, ",\"sha256\":\"" EMPTY_SHA "\"}\n");
        char want[64];
        snprintf(want, sizeof want, "missing %s", missing[i]);
        EXPECT_REJECT(missing[i], read_it(line), want);
    }
}

TEST(rejects_unknown_type) {
    ASSERT_EQ_INT(-1, read_it(HDR "{\"path\":\"a\",\"type\":\"wat\",\"mode\":1,"
                                  "\"uid\":1,\"gid\":1,\"size\":1,\"mtime_ns\":1,"
                                  "\"ctime_ns\":1,\"ino\":1,\"dev\":1,\"nlink\":1}\n"));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "unknown type \"wat\"") != NULL);
    belay_err_clear();
}

/* THE NUL RULE (§5.1.1). A NUL in a decoded path is a hard error, never a
 * truncation: the lexical path functions cannot see past one, so truncating
 * would silently discard whatever followed -- including a "..". */
TEST(rejects_nul_in_json_path) {
    /* \u0000 decodes to a NUL byte. */
    ASSERT_EQ_INT(-1, read_it(HDR "{\"path\":\"a\\u0000/../etc/passwd\","
                                  "\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
                                  "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,"
                                  "\"ino\":1,\"dev\":1,\"nlink\":1}\n"));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "NUL") != NULL);
    belay_err_clear();
}

/* Same rule through the base64 path: "YQAvLi4vZXRj" is "a\0/../etc". */
TEST(rejects_nul_in_base64_path) {
    ASSERT_EQ_INT(-1, read_it(HDR "{\"path_b64\":\"YQAvLi4vZXRj\","
                                  "\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
                                  "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,"
                                  "\"ino\":1,\"dev\":1,\"nlink\":1}\n"));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "NUL") != NULL);
    belay_err_clear();
}

TEST(rejects_nul_in_link_target) {
    ASSERT_EQ_INT(-1, read_it(HDR "{\"path\":\"l\",\"type\":\"lnk\","
                                  "\"mode\":41471,\"uid\":1,\"gid\":1,"
                                  "\"size\":3,\"mtime_ns\":1,\"ctime_ns\":1,"
                                  "\"ino\":1,\"dev\":1,\"nlink\":1,"
                                  "\"link_target\":\"t\\u0000x\"}\n"));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "link_target contains a NUL byte") != NULL);
    belay_err_clear();
}

TEST(decodes_base64_path) {
    /* "YmFk//5uYW1l" is "bad\xff\xfe" "name" */
    ASSERT_EQ_INT(0, read_it(HDR "{\"path_b64\":\"YmFk//5uYW1l\","
                                 "\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
                                 "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,"
                                 "\"ino\":1,\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"));
    ASSERT_EQ_INT(1, (int)g_n);
    ASSERT_EQ_INT(9, (int)g_e[0].path_len);
    ASSERT_EQ_INT(0, memcmp(g_e[0].path, "bad\xff\xfe" "name", 9));
}

TEST(unescapes_json_strings) {
    ASSERT_EQ_INT(0, read_it(HDR "{\"path\":\"a\\nb\\tc\\\"d\\\\e\\u0001f\","
                                 "\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
                                 "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,"
                                 "\"ino\":1,\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"));
    ASSERT_EQ_INT(1, (int)g_n);
    ASSERT_EQ_STR("a\nb\tc\"d\\e\x01" "f", g_e[0].path);
}

TEST(rejects_malformed_escapes) {
    static const struct { const char *line, *reason; } bad[] = {
        { "{\"path\":\"a\\q\",\"type\":\"reg\"", "unknown escape" },
        { "{\"path\":\"a\\u00\",\"type\":\"reg\"", "non-canonical \\u escape" },     /* short */
        { "{\"path\":\"a\\uZZZZ\",\"type\":\"reg\"", "non-canonical \\u escape" },   /* non-hex */
        { "{\"path\":\"unterminated", "unterminated string" },             /* no closing quote */
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char line[1024];
        snprintf(line, sizeof line, "%s%s}\n", HDR, bad[i].line);
        EXPECT_REJECT(bad[i].line, read_it(line), bad[i].reason);
    }
}

/* \u above 0xFF never comes from belay's writer, which only emits \u00XX for
 * control bytes. Accepting it would make the reader's language wider than the
 * writer's. */
TEST(rejects_u_escape_above_ff) {
    EXPECT_REJECT("\\u0100", read_it(HDR "{\"path\":\"a\\u0100b\",\"type\":\"reg\","
                                  "\"mode\":33188,\"uid\":1,\"gid\":1,\"size\":1,"
                                  "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,"
                                  "\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"),
                  "non-canonical \\u escape");
}

TEST(validates_sha256_shape) {
    /* Too short. */
    EXPECT_REJECT("short sha256", read_it(HDR "{\"path\":\"a\",\"type\":\"reg\","
                                  "\"mode\":33188,\"uid\":1,\"gid\":1,\"size\":1,"
                                  "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,"
                                  "\"dev\":1,\"nlink\":1,\"sha256\":\"abcd\"}\n"),
                  "\"sha256\" must be 64 lowercase hex");

    /* Uppercase is not what the writer emits. */
    EXPECT_REJECT("uppercase sha256", read_it(HDR "{\"path\":\"a\",\"type\":\"reg\","
                                  "\"mode\":33188,\"uid\":1,\"gid\":1,\"size\":1,"
                                  "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,\"nlink\":1,"
                                  "\"sha256\":\"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\"}\n"),
                  "\"sha256\" must be 64 lowercase hex");

    /* Correct form is accepted. */
    ASSERT_EQ_INT(0, read_it(HDR "{\"path\":\"a\",\"type\":\"reg\","
                                 "\"mode\":33188,\"uid\":1,\"gid\":1,\"size\":1,"
                                 "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,"
                                 "\"dev\":1,\"nlink\":1,\"sha256\":"
                                 "\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}\n"));
    ASSERT_TRUE(g_e[0].has_hash);
}

/* A hash and the unverified flag are mutually exclusive by construction, so
 * both present means something edited the file. */
TEST(rejects_hash_and_unverified_together) {
    EXPECT_REJECT("hash and unverified", read_it(HDR "{\"path\":\"a\",\"type\":\"reg\","
                                  "\"mode\":33188,\"uid\":1,\"gid\":1,\"size\":1,"
                                  "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,\"nlink\":1,"
                                  "\"sha256\":\"" EMPTY_SHA "\",\"unverified\":true}\n"),
                  "both sha256 and unverified");
}

TEST(rejects_symlink_without_target_and_vice_versa) {
    /* lnk with no target */
    EXPECT_REJECT("lnk without a target", read_it(HDR "{\"path\":\"l\",\"type\":\"lnk\",\"mode\":41471,"
                                  "\"uid\":1,\"gid\":1,\"size\":1,\"mtime_ns\":1,"
                                  "\"ctime_ns\":1,\"ino\":1,\"dev\":1,\"nlink\":1}\n"),
                  "symlink without a target");

    /* reg with a target (once out of order with mode 1, so never reached) */
    EXPECT_REJECT("reg with a target", read_it(HDR "{\"path\":\"f\",\"type\":\"reg\",\"mode\":33188,"
                                  "\"uid\":1,\"gid\":1,\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,"
                                  "\"ino\":1,\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\","
                                  "\"link_target\":\"x\"}\n"),
                  "non-symlink with a link target");
}

TEST(reads_optional_flags) {
    ASSERT_EQ_INT(0, read_it(HDR "{\"path\":\"l\",\"type\":\"lnk\","
                                 "\"mode\":41471,\"uid\":1,\"gid\":1,\"size\":4,"
                                 "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,"
                                 "\"dev\":1,\"nlink\":1,"
                                 "\"link_target\":\"/etc\",\"target_outside_scope\":true}\n"
                                 "{\"path\":\"m\",\"type\":\"dir\","
                                 "\"mode\":16877,\"uid\":1,\"gid\":1,\"size\":1,"
                                 "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,"
                                 "\"dev\":99,\"nlink\":1,\"mount\":true}\n"));
    ASSERT_EQ_INT(2, (int)g_n);
    ASSERT_TRUE(g_e[0].has_link_target);
    ASSERT_EQ_STR("/etc", g_e[0].link_target);
    ASSERT_TRUE(g_e[0].target_outside_scope);
    ASSERT_TRUE(g_e[1].is_mount);
}

/* Unknown fields must be ignored so the format can grow (spec requirement). */
TEST(ignores_unknown_fields) {
    /* Unknown (informational) fields are allowed after every known field. */
    ASSERT_EQ_INT(0, read_it(HDR "{\"path\":\"a\",\"type\":\"reg\","
                                 "\"mode\":33188,\"uid\":1,\"gid\":1,\"size\":1,"
                                 "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,"
                                 "\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\","
                                 "\"future_field\":42,\"another\":\"x\"}\n"));
    ASSERT_EQ_INT(1, (int)g_n);
    ASSERT_EQ_STR("a", g_e[0].path);
}

TEST(rejects_out_of_range_numbers) {
    /* mode is 32-bit; this exceeds it. */
    EXPECT_REJECT("mode beyond 32 bits", read_it(HDR "{\"path\":\"a\",\"type\":\"reg\","
                                  "\"mode\":99999999999,\"uid\":1,\"gid\":1,\"size\":1,"
                                  "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,"
                                  "\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"),
                  "mode out of range");

    /* Non-numeric where a number belongs. */
    EXPECT_REJECT("mode as a string", read_it(HDR "{\"path\":\"a\",\"type\":\"reg\","
                                  "\"mode\":\"abc\",\"uid\":1,\"gid\":1,\"size\":1,"
                                  "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,"
                                  "\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"),
                  "\"mode\" must be a non-negative integer");
}

/* Negative timestamps are legal: a pre-1970 mtime exists on real disks. */
TEST(accepts_negative_timestamps) {
    ASSERT_EQ_INT(0, read_it(HDR "{\"path\":\"a\",\"type\":\"reg\",\"mode\":33188,"
                                 "\"uid\":1,\"gid\":1,\"size\":1,"
                                 "\"mtime_ns\":-1000000000,\"ctime_ns\":-5,"
                                 "\"ino\":1,\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"));
    ASSERT_EQ_INT(1, (int)g_n);
    ASSERT_TRUE(g_e[0].mtime_ns < 0);
}

/* A value containing the literal text of a key name must not be mistaken for
 * that key -- find_key matches only at a key position. */
TEST(key_text_inside_a_value_is_not_a_key) {
    ASSERT_EQ_INT(0, read_it(HDR "{\"path\":\"weird\\\"mode\\\":777\","
                                 "\"type\":\"reg\",\"mode\":33188,"
                                 "\"uid\":1,\"gid\":1,\"size\":1,"
                                 "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,"
                                 "\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"));
    ASSERT_EQ_INT(1, (int)g_n);
    ASSERT_EQ_INT(33188, (int)g_e[0].mode);
}

/* The callback stopping the walk must propagate, so diff can bail early. */
static int stop_after_first(const struct belay_entry *e, void *ctx) {
    (void)e;
    int *n = ctx;
    (*n)++;
    return 7;
}

TEST(callback_return_stops_and_propagates) {
    write_manifest(HDR ENTRY_REG("a") ENTRY_REG("b") ENTRY_REG("c"));
    int n = 0;
    ASSERT_EQ_INT(7, belay_manifest_read(g_path, stop_after_first, &n));
    ASSERT_EQ_INT(1, n);
}

/* A callback stopping the walk with 1 must surface as 1, not be confused with
 * the iterator's own "an entry was read" status, which is also 1. */
static int stop_with_one(const struct belay_entry *e, void *ctx) {
    (void)e; (void)ctx;
    return 1;
}

TEST(callback_returning_one_is_propagated) {
    write_manifest(HDR ENTRY_REG("a") ENTRY_REG("b"));
    ASSERT_EQ_INT(1, belay_manifest_read(g_path, stop_with_one, NULL));
}

/* The pull interface: entries in order, then a clean 0, and the end stays
 * sticky rather than restarting or erroring. */
TEST(pull_iterator_yields_entries_then_sticky_end) {
    write_manifest(HDR ENTRY_REG("a") ENTRY_REG("b"));
    struct belay_manifest_reader *r = NULL;
    ASSERT_EQ_INT(0, belay_manifest_open(g_path, &r));
    struct belay_entry e;
    ASSERT_EQ_INT(1, belay_manifest_next(r, &e));
    ASSERT_EQ_STR(".", e.path);                   /* the scope root comes first */
    ASSERT_EQ_INT(1, belay_manifest_next(r, &e));
    ASSERT_EQ_STR("a", e.path);
    ASSERT_EQ_INT(1, belay_manifest_next(r, &e));
    ASSERT_EQ_STR("b", e.path);
    ASSERT_EQ_INT(0, belay_manifest_next(r, &e));
    ASSERT_EQ_INT(0, belay_manifest_next(r, &e));
    belay_manifest_close(r);
    belay_manifest_close(NULL);   /* must be safe */
}

TEST(reports_missing_file) {
    ASSERT_EQ_INT(-1, belay_manifest_read("/tmp/belay-no-such-manifest", collect, NULL));
    ASSERT_EQ_INT(BELAY_ERR_IO, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "cannot open") != NULL);
    belay_err_clear();
}

/* ---------- round trip against the real writer ---------- */

/* The strongest test available: write a real tree, read it back, and confirm
 * the reader accepts every byte the writer produced. A disagreement between
 * the two is invisible to either one's own tests. */
TEST(round_trips_the_writers_output) {
    char root[4096], mpath[4096], p[8192];
    snprintf(root, sizeof root, "/tmp/belay_rt_%d", (int)getpid());
    mkdir(root, 0755);

    snprintf(p, sizeof p, "%s/plain.txt", root);
    FILE *f = fopen(p, "wb"); if (f) { fputs("content", f); fclose(f); }

    snprintf(p, sizeof p, "%s/sub", root);
    mkdir(p, 0755);

    snprintf(p, sizeof p, "%s/sub/nested", root);
    f = fopen(p, "wb"); if (f) { fputs("x", f); fclose(f); }

    /* Nasty names the writer must escape and the reader must decode. */
    snprintf(p, sizeof p, "%s/has\nnewline", root);
    f = fopen(p, "wb"); if (f) fclose(f);
    snprintf(p, sizeof p, "%s/has\"quote", root);
    f = fopen(p, "wb"); if (f) fclose(f);
    /* APFS on macOS rejects filenames that are not valid UTF-8, while Linux
     * filesystems accept any bytes but '/' and NUL. Record whether the
     * fixture could actually be created, so the assertion below tests the
     * writer rather than the host filesystem's naming rules. */
    bool have_non_utf8_name = false;
    snprintf(p, sizeof p, "%s/bad\xff\xfe" "bytes", root);
    f = fopen(p, "wb");
    if (f) { fclose(f); have_non_utf8_name = true; }

    snprintf(p, sizeof p, "%s/link", root);
    if (symlink("plain.txt", p) != 0) { /* fixture best-effort */ }

    snprintf(mpath, sizeof mpath, "/tmp/belay_rt_m_%d.ndjson", (int)getpid());
    struct belay_manifest_opts o = { .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT, .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT };
    struct belay_manifest_stats st;
    ASSERT_EQ_INT(0, belay_manifest_write(mpath, root, &o, &st));
    const size_t written = st.entries;

    g_n = 0;
    ASSERT_EQ_INT(0, belay_manifest_read(mpath, collect, NULL));
    ASSERT_EQ_INT((int)written - 1, (int)g_n);    /* every entry but the root "." */

    /* The non-UTF-8 name must survive byte-exactly through path_b64 -- but
     * only where the filesystem allowed such a name in the first place. */
    if (have_non_utf8_name) {
        bool found_bad = false;
        for (size_t i = 0; i < g_n; i++) {
            if (g_e[i].path_len == 10 &&
                memcmp(g_e[i].path, "bad\xff\xfe" "bytes", 10) == 0) found_bad = true;
        }
        ASSERT_TRUE(found_bad);
    }

    /* Entries arrive in bytewise order, which the comparator depends on. */
    for (size_t i = 1; i < g_n; i++) {
        const size_t n = g_e[i-1].path_len < g_e[i].path_len
                       ? g_e[i-1].path_len : g_e[i].path_len;
        const int c = memcmp(g_e[i-1].path, g_e[i].path, n);
        if (c > 0 || (c == 0 && g_e[i-1].path_len > g_e[i].path_len)) {
            BELAY_FAIL("round trip not sorted at index %zu", i);
        }
    }

    char cmd[8192];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
    if (system(cmd) != 0) { /* best effort */ }
    unlink(mpath);
}

/*
 *  Found by independent review (§0.4b). Inert in M1, which only reads, but an
 *  accepted "../../etc/passwd" becomes an arbitrary write the moment anything
 *  restores from a manifest -- the same hidden-traversal risk the NUL rule
 *  exists to prevent.
 */
TEST(rejects_traversal_and_absolute_entry_paths) {
    /* Each fixture is a valid entry except for its path, so the path check is
     * the only thing that can reject it (audit 2026-10: these lines once had
     * neither sha256 nor unverified, so rule 5 rejected them all first and the
     * test passed with ".." accepted). */
    static const struct { const char *path, *msg; } bad[] = {
        { "..", "\"..\" component" }, { "../x", "\"..\" component" },
        { "a/../../b", "\"..\" component" }, { "a/..", "\"..\" component" },
        { "/etc/shadow", "absolute" }, { "/", "absolute" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char line[2048];
        snprintf(line, sizeof line,
                 "%s{\"path\":\"%s\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,"
                 "\"gid\":1,\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,"
                 "\"ino\":1,\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n", HDR, bad[i].path);
        if (read_it(line) != -1) BELAY_FAIL("accepted traversal path: %s", bad[i].path);
        else if (strstr(belay_err_msg(), bad[i].msg) == NULL)
            BELAY_FAIL("%s rejected for another reason: %s", bad[i].path, belay_err_msg());
        belay_err_clear();
    }
}

/* "..." and "..a" are ordinary filenames, not traversal. Over-rejecting them
 * would make legitimate paths unreadable. */
TEST(allows_dotdot_lookalike_components) {
    ASSERT_EQ_INT(0, read_it(HDR "{\"path\":\"a/...b/..c\",\"type\":\"reg\","
                                 "\"mode\":33188,\"uid\":1,\"gid\":1,\"size\":1,"
                                 "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,"
                                 "\"dev\":1,\"nlink\":1,\"sha256\":\"" EMPTY_SHA "\"}\n"));
    ASSERT_EQ_INT(1, (int)g_n);
}

TEST(reads_unreadable_flag) {
    ASSERT_EQ_INT(0, read_it(HDR "{\"path\":\"d\",\"type\":\"dir\","
                                 "\"mode\":16877,\"uid\":1,\"gid\":1,\"size\":1,"
                                 "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,"
                                 "\"dev\":1,\"nlink\":1,\"unreadable\":true}\n"));
    ASSERT_EQ_INT(1, (int)g_n);
    ASSERT_TRUE(g_e[0].unreadable);
}

/* ===== Defect-class sweep: "a state the format can't express renders as
 * no-change". Each of these was accepted before the sweep; each is now an
 * error. ===== */

#define DIR_E(p, extra) "{\"path\":\"" p "\",\"type\":\"dir\",\"mode\":16877,\"uid\":1," \
    "\"gid\":1,\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,\"nlink\":1" extra "}\n"
#define TRL(n, u) "{\"belay_manifest_end\":" #n ",\"vanished\":0,\"unreadable\":" #u \
                  ",\"unstable\":0,\"mounts\":0,\"raced\":0}\n"

/* R1. Flags are exactly `"key":true`. `"unreadable": true` (one space) used to
 * parse as READABLE, so an absent subtree read as an empty directory. */
TEST(sweep_flag_with_other_spelling_is_rejected) {
    /* Only `true` is a literal the lexer knows; a number or string is a
     * value, refused where a flag is decoded. */
    static const struct { const char *flag, *reason; } bad[] = {
        { ",\"unreadable\": true", "malformed value" }, { ",\"unreadable\":false", "malformed value" },
        { ",\"unreadable\":1", "\"unreadable\" must be exactly true" },
        { ",\"mount\":\"true\"", "\"mount\" must be exactly true" },
        { ",\"unverified\":TRUE", "malformed value" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char m[1024];
        snprintf(m, sizeof m, "%s{\"path\":\"d\",\"type\":\"dir\",\"mode\":16877,\"uid\":1,"
                 "\"gid\":1,\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,"
                 "\"nlink\":1%s}\n", HDR, bad[i].flag);
        EXPECT_REJECT(bad[i].flag, read_it(m), bad[i].reason);
    }
    /* The exact spelling still works. */
    ASSERT_EQ_INT(0, read_it(HDR DIR_E("d", ",\"unreadable\":true")));
    ASSERT_TRUE(g_n == 1 && g_e[0].unreadable);
}

/* R2. A repeated key is an error, not "first wins". */
TEST(sweep_duplicate_key_is_rejected) {
    EXPECT_REJECT("mode twice", read_it(HDR DIR_E("d", ",\"mode\":2")), "duplicate key \"mode\"");
    EXPECT_REJECT("flag twice", read_it(HDR DIR_E("d", ",\"unreadable\":true,\"unreadable\":true")),
                  "duplicate key \"unreadable\"");
}

/* R3. Strict bytewise order. The comparator merges two manifests; out of order
 * or duplicate entries would be mis-paired without any error. */
TEST(sweep_out_of_order_and_duplicate_paths_are_rejected) {
    ASSERT_EQ_INT(-1, read_it(HDR DIR_E("b", "") DIR_E("a", "")));
    ASSERT_TRUE(strstr(belay_err_msg(), "order") != NULL);
    belay_err_clear();
    ASSERT_EQ_INT(-1, read_it(HDR DIR_E("a", "") DIR_E("a", "")));
    ASSERT_TRUE(strstr(belay_err_msg(), "duplicate") != NULL);
    belay_err_clear();
    /* Bytewise, not locale: "Z" (0x5a) < "a" (0x61), "a" < "a/b" < "a0". */
    ASSERT_EQ_INT(0, read_it(HDR DIR_E("Z", "") DIR_E("a", "") DIR_E("a/b", "") DIR_E("a0", "")));
}

/* R4. The trailer is required and must match what was read. Before, a
 * manifest cut off at a line boundary was accepted, so its missing tail would
 * read as deletions. */
TEST(sweep_missing_or_wrong_trailer_is_rejected) {
    /* Each manifest has its root entry, so the trailer is its only fault
     * (once none had one, and the last was rejected for that instead). */
    g_n = 0;
    write_raw(HDR ROOT_E DIR_E("a", ""));                 /* no trailer at all */
    EXPECT_REJECT("no trailer", belay_manifest_read(g_path, collect, NULL), "no end marker");

    write_raw(HDR ROOT_E DIR_E("a", "") DIR_E("b", "") TRL(2, 0));
    EXPECT_REJECT("count wrong", belay_manifest_read(g_path, collect, NULL), "trailer says 2 entries");

    /* A dropped flag shows up as a count mismatch: the trailer says one
     * entry was unreadable, the entries say none. */
    write_raw(HDR ROOT_E DIR_E("a", "") TRL(2, 1));
    EXPECT_REJECT("dropped flag", belay_manifest_read(g_path, collect, NULL), "1 unreadable");

    write_raw(HDR ROOT_E DIR_E("a", "") TRL(2, 0) DIR_E("b", ""));
    EXPECT_REJECT("data after end", belay_manifest_read(g_path, collect, NULL), "data after the end marker");
}

/* R5. One canonical spelling per path. "a//b" and "a/b" would otherwise be two
 * keys for one file. "." is legal only as the whole path (the scope root). */
TEST(sweep_non_canonical_paths_are_rejected) {
    static const struct { const char *path, *reason; } bad[] = {
        { "a//b", "empty component" }, { "a/./b", "\".\" component" }, { "a/", "empty component" },
        { "./a", "\".\" component" }, { "a/.", "\".\" component" }, { "/", "absolute" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char m[1024];
        snprintf(m, sizeof m, "%s{\"path\":\"%s\",\"type\":\"dir\",\"mode\":16877,\"uid\":1,"
                 "\"gid\":1,\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,"
                 "\"nlink\":1}\n", HDR, bad[i].path);
        EXPECT_REJECT(bad[i].path, read_it(m), bad[i].reason);
    }
    ASSERT_EQ_INT(0, read_it(HDR DIR_E(".", "") DIR_E("a", "")));
    ASSERT_EQ_INT(1, (int)g_n);                   /* "a"; the collector skips "." */
}

/* R7. The header is exposed, so a comparator can refuse to pair manifests of
 * different scopes. Before, two different projects with the same layout
 * compared as "same 2, changed 0". */
TEST(sweep_header_and_trailer_are_exposed) {
    write_manifest(HDR DIR_E("a", ""));
    struct belay_manifest_reader *r = NULL;
    ASSERT_EQ_INT(0, belay_manifest_open(g_path, &r));
    const struct belay_manifest_header *h = belay_manifest_header(r);
    ASSERT_TRUE(h != NULL);
    if (h) {
        ASSERT_EQ_STR("/s", h->scope);
        ASSERT_EQ_INT(1, (int)h->version);
    }
    ASSERT_TRUE(belay_manifest_trailer(r) == NULL);   /* not yet */
    struct belay_entry e;
    ASSERT_EQ_INT(1, belay_manifest_next(r, &e));   /* "." */
    ASSERT_EQ_INT(1, belay_manifest_next(r, &e));   /* "a" */
    ASSERT_EQ_INT(0, belay_manifest_next(r, &e));
    const struct belay_manifest_stats *t = belay_manifest_trailer(r);
    ASSERT_TRUE(t != NULL);
    if (t) ASSERT_EQ_INT(2, (int)t->entries);
    belay_manifest_close(r);

    /* A header without a usable scope is rejected outright -- by the lexer,
     * which refuses an empty array before the decoder can name it. */
    g_n = 0;
    write_raw("{\"belay_manifest\":1,\"created_ns\":0,\"scopes\":[],\"hash\":\"sha256\","
              "\"hash_max_bytes\":1,\"store_max_bytes\":1}\n");
    EXPECT_REJECT("no scope", belay_manifest_read(g_path, collect, NULL), "array element is not a string");
}

/* R8. Blank lines are not part of the format. */
TEST(sweep_blank_line_is_rejected) {
    EXPECT_REJECT("blank line", read_it(HDR DIR_E("a", "") "\n" DIR_E("b", "")), "blank line");
}

/* W3 on the reader side: device nodes must carry rdev, nothing else may. */
TEST(sweep_rdev_required_on_devices_only) {
    const char *dev_no_rdev = HDR "{\"path\":\"n\",\"type\":\"chr\",\"mode\":8630,\"uid\":0,"
        "\"gid\":0,\"size\":0,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,\"nlink\":1}\n";
    EXPECT_REJECT("device without rdev", read_it(dev_no_rdev), "device without rdev");
    EXPECT_REJECT("rdev on a directory", read_it(HDR DIR_E("d", ",\"rdev\":5")), "rdev on a non-device");
    ASSERT_EQ_INT(0, read_it(HDR "{\"path\":\"n\",\"type\":\"chr\",\"mode\":8630,\"uid\":0,"
        "\"gid\":0,\"size\":0,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,\"nlink\":1,"
        "\"rdev\":259}\n"));
    ASSERT_TRUE(g_n == 1 && g_e[0].has_rdev && g_e[0].rdev == 259);
}

/* W5 on the reader side: "unstable" means no trustworthy hash, so it must
 * come with "unverified". */
TEST(sweep_unstable_requires_unverified) {
    EXPECT_REJECT("unstable with a hash", read_it(HDR "{\"path\":\"f\",\"type\":\"reg\",\"mode\":33188,"
        "\"uid\":1,\"gid\":1,\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,\"nlink\":1,"
        "\"sha256\":\"" EMPTY_SHA "\",\"unstable\":true}\n"),
                  "unstable or unreadable file without unverified");
    ASSERT_EQ_INT(0, read_it(HDR "{\"path\":\"f\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,"
        "\"gid\":1,\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,\"nlink\":1,"
        "\"unverified\":true,\"unstable\":true}\n"));
}

/* ===== Independent review, D8 class: "the reader's accepted language is wider
 * than the writer's output". The earlier key-searching reader accepted every
 * case below; the strict grammar rejects them. Each manifest is complete and
 * valid apart from the single defect named. ===== */

#define REG_LINE(path, mid) "{\"path\":\"" path "\",\"type\":\"reg\",\"mode\":33188," \
    "\"uid\":1,\"gid\":1,\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1," \
    "\"nlink\":1" mid "}\n"
#define SHA_F ",\"sha256\":\"" EMPTY_SHA "\""

TEST(review_d8_reader_rejects_what_the_writer_never_emits) {
    static const struct { const char *name, *m, *reason; } cases[] = {
        { "reg with neither sha256 nor unverified", HDR ROOT_E REG_LINE("f", "") TRL(2, 0),
          "regular file with neither sha256 nor unverified" },
        { "duplicate key after whitespace",          /* the whitespace is refused first */
          HDR ROOT_E REG_LINE("f", SHA_F ", \"sha256\":\"" EMPTY_SHA "\"") TRL(2, 0), "expected a key" },
        { "non-canonical \\u escape",       HDR ROOT_E REG_LINE("\\u0066", SHA_F) TRL(2, 0),
          "non-canonical \\u escape" },
        { "escaped solidus",                HDR ROOT_E REG_LINE("a\\/b", SHA_F) TRL(2, 0),
          "unknown escape" },
        { "uppercase \\u hex",              HDR ROOT_E REG_LINE("a\\u001F", SHA_F) TRL(2, 0),
          "non-canonical \\u escape" },
        { "trailing junk after a number",
          HDR ROOT_E "{\"path\":\"f\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
          "\"size\":1abc,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1" SHA_F "}\n" TRL(2, 0),
          "expected ',' or '}'" },
        { "number with a plus sign",
          HDR ROOT_E "{\"path\":\"f\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
          "\"size\":1,\"mtime_ns\":+1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1" SHA_F "}\n" TRL(2, 0),
          "malformed value" },
        { "number with a leading zero",
          HDR ROOT_E "{\"path\":\"f\",\"type\":\"reg\",\"mode\":033188,\"uid\":1,\"gid\":1,"
          "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1" SHA_F "}\n" TRL(2, 0),
          "number has a leading zero" },
        { "no root entry",                  HDR REG_LINE("f", SHA_F) TRL(1, 0),
          "no entry for the scope root" },
        { "entry below an unreadable dir",
          HDR ROOT_E DIR_E("d", ",\"unreadable\":true") REG_LINE("d/x", SHA_F) TRL(3, 1),
          "entry below an unreadable or mounted directory" },
        { "entry below a mount point",
          HDR ROOT_E DIR_E("m", ",\"mount\":true") REG_LINE("m/x", SHA_F) TRL(3, 0),
          "entry below an unreadable or mounted directory" },
        { "sha256 on a directory",          HDR ROOT_E DIR_E("d", SHA_F) TRL(2, 0),
          "hash fields on a directory" },
        { "mode type bits say dir, type says reg",
          HDR ROOT_E "{\"path\":\"f\",\"type\":\"reg\",\"mode\":16877,\"uid\":1,\"gid\":1,"
          "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1" SHA_F "}\n" TRL(2, 0),
          "mode's type bits disagree with type" },
        { "junk between fields",
          HDR ROOT_E "{\"path\":\"f\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,junk,\"gid\":1,"
          "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1" SHA_F "}\n" TRL(2, 0),
          "expected a key" },
        { "junk after the closing brace",
          HDR ROOT_E "{\"path\":\"f\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
          "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1" SHA_F "}x\n" TRL(2, 0),
          "data after the closing brace" },
        { "flag false",                     HDR ROOT_E DIR_E("d", ",\"unreadable\":false") TRL(2, 0),
          "malformed value" },
        { "flag null",                      HDR ROOT_E DIR_E("d", ",\"mount\":null") TRL(2, 0),
          "malformed value" },
        { "path as base64 although it is valid UTF-8",
          HDR ROOT_E "{\"path_b64\":\"YQ==\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
          "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1" SHA_F "}\n" TRL(2, 0),
          "path_b64 is valid UTF-8" },
        { "symlink size disagrees with its target",
          HDR ROOT_E "{\"path\":\"l\",\"type\":\"lnk\",\"mode\":41471,\"uid\":1,\"gid\":1,"
          "\"size\":99,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1,"
          "\"link_target\":\"/etc\"}\n" TRL(2, 0), "symlink size disagrees with its target's length" },
        { "hash on a mount point",
          HDR ROOT_E "{\"path\":\"f\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
          "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1" SHA_F ",\"mount\":true}\n" TRL(2, 0),
          "hash on a mount point" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        write_raw(cases[i].m);
        g_n = 0;
        EXPECT_REJECT(cases[i].name, belay_manifest_read(g_path, collect, NULL), cases[i].reason);
    }
    /* And the control: the same skeleton with no defect is accepted. */
    write_raw(HDR ROOT_E REG_LINE("f", SHA_F) TRL(2, 0));
    ASSERT_EQ_INT(0, belay_manifest_read(g_path, collect, NULL));
}

/* A NUL byte inside a line would end any C-string parse early and hide what
 * follows -- here a flag. The old reader read this directory as readable. */
TEST(review_nul_byte_in_a_line_is_rejected) {
    static const char m[] = HDR ROOT_E
        "{\"path\":\"d\",\"type\":\"dir\",\"mode\":16877,\"uid\":1,\"gid\":1,\"size\":1,"
        "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1}\0,\"unreadable\":true}\n"
        TRL(2, 0);
    FILE *f = fopen(g_path, "wb");
    ASSERT_TRUE(f != NULL);
    if (f) { fwrite(m, 1, sizeof m - 1, f); fclose(f); }
    ASSERT_EQ_INT(-1, belay_manifest_read(g_path, collect, NULL));
    ASSERT_TRUE(strstr(belay_err_msg(), "NUL") != NULL);
    belay_err_clear();
}

/* D10: a line longer than any the writer can emit is refused before it can
 * cost memory; the old reader buffered a 300 MB line whole. */
TEST(review_overlong_line_is_rejected) {
    FILE *f = fopen(g_path, "wb");
    REQUIRE(f != NULL);
    fputs(HDR, f);
    for (int i = 0; i < 70000; i++) fputc('{', f);
    fputc('\n', f);
    fclose(f);
    ASSERT_EQ_INT(-1, belay_manifest_read(g_path, collect, NULL));
    ASSERT_TRUE(strstr(belay_err_msg(), "exceeds") != NULL);
    belay_err_clear();
}

/* D2 on the reader side: a scope ending in a backslash round-trips. */
TEST(review_scope_ending_in_backslash_is_read_back) {
    write_raw("{\"belay_manifest\":1,\"created_ns\":0,\"scopes\":[\"/tmp/sc\\\\\"],"
              "\"hash\":\"sha256\",\"hash_max_bytes\":1,\"store_max_bytes\":1}\n"
              ROOT_E TRL(1, 0));
    struct belay_manifest_reader *r = NULL;
    ASSERT_EQ_INT(0, belay_manifest_open(g_path, &r));
    if (r) ASSERT_EQ_STR("/tmp/sc\\", belay_manifest_header(r)->scope);
    belay_manifest_close(r);
}

/* ===== Independent review, round 2: more of the reader's language that the
 * writer never emits. ===== */
TEST(r2_reader_rejects_remaining_non_canonical_forms) {
    static const struct { const char *name, *m, *reason; } cases[] = {
        { "fields out of canonical order",
          HDR ROOT_E "{\"path\":\"f\",\"mode\":33188,\"type\":\"reg\",\"uid\":1,\"gid\":1,"
          "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1" SHA_F "}\n" TRL(2, 0),
          "fields out of canonical order" },
        { "known field after an unknown one",
          HDR ROOT_E "{\"path\":\"f\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
          "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1,\"x\":1" SHA_F "}\n" TRL(2, 0),
          "a known field follows an unknown one" },
        { "header fields out of order",
          "{\"created_ns\":0,\"belay_manifest\":1,\"scopes\":[\"/s\"],\"hash\":\"sha256\","
          "\"hash_max_bytes\":1,\"store_max_bytes\":1}\n" ROOT_E TRL(1, 0), "fields out of canonical order" },
        { "non-canonical base64 path (stray bits)",
          HDR ROOT_E "{\"path_b64\":\"/x==\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
          "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1" SHA_F "}\n" TRL(2, 0),
          "non-zero padding bits" },
        { "entry sorting before \".\" under an unreadable root",
          HDR "{\"path\":\"!x\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,"
          "\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1" SHA_F "}\n"
          "{\"path\":\".\",\"type\":\"dir\",\"mode\":16877,\"uid\":1,\"gid\":1,\"size\":1,"
          "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,\"nlink\":2,\"unreadable\":true}\n" TRL(2, 1),
          "entries recorded under an unreadable scope root" },
        { "regular file with a hash and unreadable",
          HDR ROOT_E REG_LINE("f", SHA_F ",\"unreadable\":true") TRL(2, 1),
          "unstable or unreadable file without unverified" },
        { "fifo flagged unreadable",
          HDR ROOT_E "{\"path\":\"p\",\"type\":\"fifo\",\"mode\":4516,\"uid\":1,\"gid\":1,"
          "\"size\":0,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1,\"unreadable\":true}\n" TRL(2, 1),
          "read flags on a node that is never read" },
        { "directory both unstable and unreadable",
          HDR ROOT_E DIR_E("d", ",\"unstable\":true,\"unreadable\":true") TRL(2, 1),
          "directory flags unreadable, unstable and mount are exclusive" },
        { "directory both mount and unreadable",
          HDR ROOT_E DIR_E("d", ",\"mount\":true,\"unreadable\":true") TRL(2, 1),
          "directory flags unreadable, unstable and mount are exclusive" },
        { "symlink with an empty target, not unreadable",
          HDR ROOT_E "{\"path\":\"l\",\"type\":\"lnk\",\"mode\":41471,\"uid\":1,\"gid\":1,"
          "\"size\":0,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1,"
          "\"link_target\":\"\"}\n" TRL(2, 0), "symlink with an empty target" },
        { "non-canonical scope",
          "{\"belay_manifest\":1,\"created_ns\":0,\"scopes\":[\"/s/./t/../u//\"],\"hash\":\"sha256\","
          "\"hash_max_bytes\":1,\"store_max_bytes\":1}\n" ROOT_E TRL(1, 0),
          "scope is not a canonical absolute path" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        write_raw(cases[i].m);
        g_n = 0;
        EXPECT_REJECT(cases[i].name, belay_manifest_read(g_path, collect, NULL), cases[i].reason);
    }
}

/* What the writer CAN now emit for a symlink it could not read reliably: an
 * unreadable link whose size need not match its target, and an unreadable
 * link with the empty "unknown" target. Both must read back. */
TEST(r2_reader_accepts_the_writers_unreadable_symlinks) {
    write_raw(HDR ROOT_E
              "{\"path\":\"a\",\"type\":\"lnk\",\"mode\":41471,\"uid\":1,\"gid\":1,"
              "\"size\":5,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":1,"
              "\"link_target\":\"a-much-longer-target\",\"unreadable\":true}\n"
              "{\"path\":\"b\",\"type\":\"lnk\",\"mode\":41471,\"uid\":1,\"gid\":1,"
              "\"size\":7,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":3,\"dev\":1,\"nlink\":1,"
              "\"link_target\":\"\",\"unreadable\":true}\n" TRL(3, 2));
    g_n = 0;
    ASSERT_EQ_INT(0, belay_manifest_read(g_path, collect, NULL));
    ASSERT_EQ_INT(2, (int)g_n);
}

/* Review round 2 found the sealed-directory check quadratic; the first fix
 * made it fast but still kept every sealed path, so memory grew with the
 * manifest. The reader now keeps only sealed prefixes of the previous path.
 * These orderings are what make that subtle: a sibling such as "d!x" sorts
 * BETWEEN "d" and "d/x", so "d" must stay sealed past its first
 * non-descendant, and an inner seal closing must not release an outer one. */
TEST(r3_sealed_directories_hold_across_interleaved_siblings) {
#define UNR ",\"unreadable\":true"
    static const struct { const char *name; const char *m; int want; } cases[] = {
        { "sibling sorting between a sealed dir and its child",
          HDR DIR_E("d", UNR) REG_LINE("d!x", SHA_F) REG_LINE("d/x", SHA_F), -1 },
        { "child of a sealed dir opened inside another seal's range",
          HDR DIR_E("d", UNR) DIR_E("d!", UNR) REG_LINE("d!/x", SHA_F), -1 },
        { "outer seal still holds after an inner one closes",
          HDR DIR_E("d", UNR) DIR_E("d!", UNR) REG_LINE("d!x", SHA_F) REG_LINE("d/x", SHA_F), -1 },
        { "mount point with siblings in between",
          HDR DIR_E("m", ",\"mount\":true") REG_LINE("m-1", SHA_F) REG_LINE("m.2", SHA_F)
          REG_LINE("m/z", SHA_F), -1 },
        { "a seal ends once its range is passed",
          HDR DIR_E("d", UNR) REG_LINE("d!x", SHA_F) REG_LINE("d.y", SHA_F)
          DIR_E("d0", "") REG_LINE("d0/x", SHA_F), 0 },
        { "an unsealed sibling's children are fine",
          HDR DIR_E("a", UNR) DIR_E("b", "") REG_LINE("b/c", SHA_F), 0 },
        { "nested seals closing innermost first",
          HDR DIR_E("d", UNR) DIR_E("d!", UNR) DIR_E("d!!", UNR) REG_LINE("d!!x", SHA_F)
          REG_LINE("d!x", SHA_F) REG_LINE("dx", SHA_F), 0 },
    };
#undef UNR
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        const int rc = read_it(cases[i].m);
        if (rc != cases[i].want)
            BELAY_FAIL("%s: got %d, want %d (%s)", cases[i].name, rc, cases[i].want,
                       belay_err_msg());
        else if (rc == -1 && strstr(belay_err_msg(), "entry below an unreadable or mounted directory") == NULL)
            BELAY_FAIL("%s: rejected for another reason: %s", cases[i].name, belay_err_msg());
        belay_err_clear();
    }
}

/* Many sealed siblings, then an entry below the last one: still caught, and
 * the same manifest without it is accepted. */
TEST(r3_many_sealed_directories) {
    enum { N = 3000 };
    const size_t per = 256;    /* longest line here is under 200 bytes */
    char *m = malloc(sizeof HDR + (N + 1) * per);
    ASSERT_TRUE(m != NULL);
    size_t w = (size_t)snprintf(m, sizeof HDR, "%s", HDR);
    for (int i = 0; i < N; i++)
        w += (size_t)snprintf(m + w, per,
            "{\"path\":\"s%04d\",\"type\":\"dir\",\"mode\":16877,\"uid\":1,"
            "\"gid\":1,\"size\":1,\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":1,\"dev\":1,"
            "\"nlink\":1,\"unreadable\":true}\n", i);
    const size_t base = w;
    ASSERT_EQ_INT(0, read_it(m));
    snprintf(m + base, per, REG_LINE("s%04d/x", SHA_F), N - 1);
    ASSERT_EQ_INT(-1, read_it(m));
    ASSERT_TRUE(strstr(belay_err_msg(), "below an unreadable") != NULL);
    belay_err_clear();
    free(m);
}

#define LNK_LINE(path, size, target, extra) "{\"path\":\"" path "\",\"type\":\"lnk\"," \
    "\"mode\":41471,\"uid\":1,\"gid\":1,\"size\":" #size ",\"mtime_ns\":1,\"ctime_ns\":1," \
    "\"ino\":3,\"dev\":1,\"nlink\":1,\"link_target\":\"" target "\"" extra "}\n"
#define REG_SIZED(path, size, mid) "{\"path\":\"" path "\",\"type\":\"reg\",\"mode\":33188," \
    "\"uid\":1,\"gid\":1,\"size\":" #size ",\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1," \
    "\"nlink\":1" mid "}\n"
#define OUT ",\"target_outside_scope\":true"

/* Review round 3, F7: the reader still accepted states the writer never
 * emits. target_outside_scope is now recomputed from the scope (with the
 * writer's own function), and the hash limit is checked both ways. The
 * header's scope is "/s"; hash_max_bytes is 67108864. */
TEST(r3_reader_checks_annotation_and_hash_limit_against_the_header) {
#define MISSING "target_outside_scope missing on a link leaving the scope"
#define STAYS "target_outside_scope on a link that stays in the scope"
    static const struct { const char *name; const char *m; int want; const char *reason; } cases[] = {
        { "absolute link outside, annotated",     HDR LNK_LINE("l", 4, "/etc", OUT), 0, NULL },
        { "absolute link outside, unannotated",   HDR LNK_LINE("l", 4, "/etc", ""), -1, MISSING },
        { "relative link inside, unannotated",    HDR LNK_LINE("l", 1, "x", ""), 0, NULL },
        { "relative link inside, annotated",      HDR LNK_LINE("l", 1, "x", OUT), -1, STAYS },
        { "relative escape, annotated",           HDR LNK_LINE("l", 4, "../x", OUT), 0, NULL },
        { "relative escape, unannotated",         HDR LNK_LINE("l", 4, "../x", ""), -1, MISSING },
        { "absolute link into the scope",         HDR LNK_LINE("l", 4, "/s/x", ""), 0, NULL },
        { "unreadable link with a stale target, annotated",      /* its target is unknown */
          HDR LNK_LINE("l", 9, "/etc", OUT ",\"unreadable\":true"), -1, STAYS },
        { "unreadable link with a stale target",  HDR LNK_LINE("l", 9, "/etc", ",\"unreadable\":true"), 0, NULL },
        { "unverified with no reason, within the limit",
          HDR REG_SIZED("f", 5, ",\"unverified\":true"), -1, "unverified file within hash_max_bytes, with no reason" },
        { "unverified over the limit",            HDR REG_SIZED("f", 67108865, ",\"unverified\":true"), 0, NULL },
        { "hash over the limit",                  HDR REG_SIZED("f", 67108865, SHA_F), -1,
          "hash on a file larger than hash_max_bytes" },
        { "hash at the limit",                    HDR REG_SIZED("f", 67108864, SHA_F), 0, NULL },
    };
#undef MISSING
#undef STAYS
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        const int rc = read_it(cases[i].m);
        if (cases[i].want == -1) {
            EXPECT_REJECT(cases[i].name, rc, cases[i].reason);
            continue;
        }
        if (rc != 0) BELAY_FAIL("%s: rejected: %s", cases[i].name, belay_err_msg());
        belay_err_clear();
    }
}

/* Round 3: entries that changed after being recorded carry "raced", and
 * the trailer counts raced entries and mount points, so a dropped flag
 * shows as a count mismatch. raced is never on a directory whose listing
 * was recorded: that is what "unstable" says. */
TEST(r3_raced_flag_and_mount_and_race_counts) {
    static const struct { const char *name; const char *m; int want; const char *reason; } cases[] = {
        { "raced file",                HDR REG_LINE("f", SHA_F ",\"raced\":true"), 0, NULL },
        { "raced unreadable directory", HDR DIR_E("d", ",\"unreadable\":true,\"raced\":true"), 0, NULL },
        { "raced mount point",         HDR DIR_E("m", ",\"mount\":true,\"raced\":true"), 0, NULL },
        { "raced listed directory",    HDR DIR_E("d", ",\"raced\":true"), -1, "raced on a listed directory" },
        { "raced out of order",        HDR DIR_E("d", ",\"raced\":true,\"unreadable\":true"), -1,
          "fields out of canonical order" },
        { "raced spelled false",       HDR REG_LINE("f", SHA_F ",\"raced\":false"), -1, "malformed value" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        const int rc = read_it(cases[i].m);
        if (cases[i].want == -1) {
            EXPECT_REJECT(cases[i].name, rc, cases[i].reason);
            continue;
        }
        if (rc != 0) BELAY_FAIL("%s: rejected: %s", cases[i].name, belay_err_msg());
        belay_err_clear();
    }
    /* Counts: one mount and one raced entry, against trailers that say 0. */
    g_n = 0;
    write_raw(HDR ROOT_E DIR_E("m", ",\"mount\":true") TRL(2, 0));
    ASSERT_EQ_INT(-1, belay_manifest_read(g_path, collect, NULL));
    ASSERT_TRUE(strstr(belay_err_msg(), "mounts") != NULL);
    belay_err_clear();
    write_raw(HDR ROOT_E REG_LINE("f", SHA_F ",\"raced\":true") TRL(2, 0));
    ASSERT_EQ_INT(-1, belay_manifest_read(g_path, collect, NULL));
    ASSERT_TRUE(strstr(belay_err_msg(), "raced") != NULL);
    belay_err_clear();
    /* A trailer without the new counts is a truncated or older format. */
    write_raw(HDR ROOT_E "{\"belay_manifest_end\":1,\"vanished\":0,\"unreadable\":0,\"unstable\":0}\n");
    EXPECT_REJECT("old trailer", belay_manifest_read(g_path, collect, NULL), "missing mounts");
}

/* W6 (decided 2026-10-26): extended metadata has one spelling per state.
 * Elements are "name=<sha256 of value>", sorted by name bytes; a name is
 * written as itself only when printable ASCII without '"', '\\' or '=' and
 * not starting "x:"; the file capability lives in "caps" alone. */
#define XH "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
TEST(w6_reader_accepts_exactly_the_canonical_extended_metadata) {
    static const struct { const char *name; const char *m; int want; const char *reason; } cases[] = {
        { "inode flags",                  HDR REG_LINE("f", ",\"iflags\":524288" SHA_F), 0, NULL },
        { "capability",                   HDR REG_LINE("f", ",\"caps\":\"0100000200200000\"" SHA_F), 0, NULL },
        { "two attributes, sorted",       HDR REG_LINE("f", ",\"xattrs\":[\"user.a=" XH "\",\"user.b=" XH "\"]" SHA_F), 0, NULL },
        { "hex-encoded non-ASCII name",   HDR REG_LINE("f", ",\"xattrs\":[\"x:757365722e77c3a9=" XH "\"]" SHA_F), 0, NULL },
        { "set recorded by digest",       HDR REG_LINE("f", ",\"xattrs_sha256\":\"" XH "\"" SHA_F), 0, NULL },
        { "attributes unknown",           HDR REG_LINE("f", ",\"xattrs_unknown\":true" SHA_F), 0, NULL },
        { "attributes on a directory",    HDR DIR_E("d", ",\"xattrs\":[\"user.a=" XH "\"]"), 0, NULL },
        { "unsorted",                     HDR REG_LINE("f", ",\"xattrs\":[\"user.b=" XH "\",\"user.a=" XH "\"]" SHA_F), -1,
          "xattrs not strictly sorted" },
        { "duplicate name",               HDR REG_LINE("f", ",\"xattrs\":[\"user.a=" XH "\",\"user.a=" XH "\"]" SHA_F), -1,
          "xattrs not strictly sorted" },
        { "capability inside xattrs",     HDR REG_LINE("f", ",\"xattrs\":[\"security.capability=" XH "\"]" SHA_F), -1,
          "security.capability belongs in caps" },
        { "printable name hex-encoded",   HDR REG_LINE("f", ",\"xattrs\":[\"x:612e62=" XH "\"]" SHA_F), -1,
          "hex-encoded but printable" },
        { "name containing '='",          HDR REG_LINE("f", ",\"xattrs\":[\"a=b=" XH "\"]" SHA_F), -1, "bad xattr name" },
        { "uppercase digest",             HDR REG_LINE("f", ",\"xattrs\":[\"user.a=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\"]" SHA_F), -1,
          "xattrs element is not name=sha256" },
        { "escape in an element",         HDR REG_LINE("f", ",\"xattrs\":[\"user.\\\"a=" XH "\"]" SHA_F), -1,
          "escape in an xattrs element" },
        { "non-canonical escape in an element",
          HDR REG_LINE("f", ",\"xattrs\":[\"user.\\u0061=" XH "\"]" SHA_F), -1, "non-canonical \\u escape" },
        { "empty array",                  HDR REG_LINE("f", ",\"xattrs\":[]" SHA_F), -1,
          "array element is not a string" },                    /* the lexer refuses [] */
        { "both inline and digest",       HDR REG_LINE("f", ",\"xattrs\":[\"user.a=" XH "\"],\"xattrs_sha256\":\"" XH "\"" SHA_F), -1,
          "both xattrs and xattrs_sha256" },
        { "unknown with attributes",      HDR REG_LINE("f", ",\"xattrs\":[\"user.a=" XH "\"],\"xattrs_unknown\":true" SHA_F), -1,
          "xattrs_unknown with recorded attributes" },
        { "capability on a directory",    HDR DIR_E("d", ",\"caps\":\"01000002\""), -1, "caps on a non-regular file" },
        { "capability of odd length",     HDR REG_LINE("f", ",\"caps\":\"010\"" SHA_F), -1, "\"caps\" must be lowercase hex" },
        { "extended metadata on a mount", HDR DIR_E("m", ",\"iflags\":1,\"mount\":true"), -1,
          "extended metadata on a mount point" },
        { "fields out of order",          HDR REG_LINE("f", ",\"xattrs\":[\"user.a=" XH "\"],\"iflags\":1" SHA_F), -1,
          "fields out of canonical order" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        const int rc = read_it(cases[i].m);
        if (cases[i].want == -1) {
            EXPECT_REJECT(cases[i].name, rc, cases[i].reason);
            continue;
        }
        if (rc != 0) BELAY_FAIL("%s: rejected: %s", cases[i].name, belay_err_msg());
        belay_err_clear();
    }
    /* The digest of an inline set is the digest of its array body, so a set
     * recorded inline in one manifest and by digest in another compares. */
    ASSERT_EQ_INT(0, read_it(HDR REG_LINE("f", ",\"xattrs\":[\"user.a=" XH "\"]" SHA_F)));
    ASSERT_TRUE(g_n == 1 && g_e[0].has_xattrs && g_e[0].xattrs_inline);
    if (g_n == 1) {
        struct belay_sha256 h;
        uint8_t d[BELAY_SHA256_DIGEST_LEN];
        char hex[65];
        const char body[] = "\"user.a=" XH "\"";
        belay_sha256_init(&h);
        belay_sha256_update(&h, body, strlen(body));
        belay_sha256_final(&h, d);
        belay_hex_encode(hex, d, sizeof d);
        ASSERT_EQ_STR(hex, g_e[0].xattrs_sha256_hex);
    }
}
#undef XH

/* The decoder reads fields in DECODE_ORDER (it fixes which error a line
 * with several bad fields reports): every schema field must be in it
 * exactly once, or a field added to entry.c would never be read. */
TEST(decoder_reads_every_schema_field_once) {
    int seen[F_COUNT] = { 0 };
    for (size_t i = 0; i < F_COUNT; i++) {
        ASSERT_TRUE(DECODE_ORDER[i] < F_COUNT);
        if (DECODE_ORDER[i] < F_COUNT) seen[DECODE_ORDER[i]]++;
    }
    for (size_t f = 0; f < F_COUNT; f++) ASSERT_EQ_INT(1, seen[f]);
}

int main(void) {
    RUN(reads_a_well_formed_entry);
    RUN(every_schema_rule_has_a_witness_rejected_for_that_rule);
    RUN(a_duplicate_key_is_rejected_as_a_duplicate);
    RUN(a_json_string_must_be_valid_utf8);
    RUN(nothing_may_follow_the_trailer);
    RUN(a_number_beyond_64_bits_is_rejected);
    RUN(iflags_and_the_trailers_vanished_count_are_decoded);
    RUN(rejects_traversal_and_absolute_entry_paths);
    RUN(allows_dotdot_lookalike_components);
    RUN(reads_unreadable_flag);
    RUN(rejects_unknown_format_version);
    RUN(rejects_missing_header);
    RUN(rejects_empty_file);
    RUN(rejects_truncated_final_line);
    RUN(rejects_entry_without_path);
    RUN(rejects_both_path_forms);
    RUN(rejects_missing_required_numeric_fields);
    RUN(rejects_unknown_type);
    RUN(rejects_nul_in_json_path);
    RUN(rejects_nul_in_base64_path);
    RUN(rejects_nul_in_link_target);
    RUN(decodes_base64_path);
    RUN(unescapes_json_strings);
    RUN(rejects_malformed_escapes);
    RUN(rejects_u_escape_above_ff);
    RUN(validates_sha256_shape);
    RUN(rejects_hash_and_unverified_together);
    RUN(rejects_symlink_without_target_and_vice_versa);
    RUN(reads_optional_flags);
    RUN(ignores_unknown_fields);
    RUN(rejects_out_of_range_numbers);
    RUN(accepts_negative_timestamps);
    RUN(key_text_inside_a_value_is_not_a_key);
    RUN(callback_return_stops_and_propagates);
    RUN(callback_returning_one_is_propagated);
    RUN(pull_iterator_yields_entries_then_sticky_end);
    RUN(reports_missing_file);
    RUN(sweep_flag_with_other_spelling_is_rejected);
    RUN(sweep_duplicate_key_is_rejected);
    RUN(sweep_out_of_order_and_duplicate_paths_are_rejected);
    RUN(sweep_missing_or_wrong_trailer_is_rejected);
    RUN(sweep_non_canonical_paths_are_rejected);
    RUN(sweep_header_and_trailer_are_exposed);
    RUN(sweep_blank_line_is_rejected);
    RUN(sweep_rdev_required_on_devices_only);
    RUN(sweep_unstable_requires_unverified);
    RUN(review_d8_reader_rejects_what_the_writer_never_emits);
    RUN(review_nul_byte_in_a_line_is_rejected);
    RUN(review_overlong_line_is_rejected);
    RUN(review_scope_ending_in_backslash_is_read_back);
    RUN(r2_reader_rejects_remaining_non_canonical_forms);
    RUN(r2_reader_accepts_the_writers_unreadable_symlinks);
    RUN(r3_sealed_directories_hold_across_interleaved_siblings);
    RUN(r3_many_sealed_directories);
    RUN(r3_reader_checks_annotation_and_hash_limit_against_the_header);
    RUN(r3_raced_flag_and_mount_and_race_counts);
    RUN(w6_reader_accepts_exactly_the_canonical_extended_metadata);
    RUN(round_trips_the_writers_output);
    RUN(decoder_reads_every_schema_field_once);

    unlink(g_path);
    return belay_test_report();
}
