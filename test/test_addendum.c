/*
 *  test/expect/manifest-v1-addendum.md: each row's fact, checked against the
 *  code, and every row has a check here and every check a row (the pin's
 *  both-ways rule). Reader facts are checked on hand-written manifests at
 *  each limit and one past it; writer facts by capturing a tree under /tmp.
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/manifest.h"
#include "belay/error.h"

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

static char g_dir[256], g_m[300];

#define H64 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

/* A manifest of the root and one entry line, `entry` (NULL: none), with
 * `raw_line` (NULL: none) written right after the header. */
static int none(const struct belay_entry *e, void *c) { (void)e; (void)c; return 0; }

static int read_with(const char *entry, const char *raw_line) {
    FILE *f = fopen(g_m, "wb");
    if (f == NULL) return -2;
    fputs("{\"belay_manifest\":1,\"created_ns\":1,\"scopes\":[\"/s\"],\"hash\":\"sha256\","
          "\"hash_max_bytes\":1000,\"store_max_bytes\":0}\n", f);
    if (raw_line != NULL) fprintf(f, "%s\n", raw_line);
    fputs("{\"path\":\".\",\"type\":\"dir\",\"mode\":16877,\"uid\":1,\"gid\":1,\"size\":0,"
          "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":2,\"dev\":1,\"nlink\":2}\n", f);
    if (entry != NULL) fprintf(f, "%s\n", entry);
    fprintf(f, "{\"belay_manifest_end\":%d,\"vanished\":0,\"unreadable\":0,\"unstable\":0,"
               "\"mounts\":0,\"raced\":0}\n", entry != NULL ? 2 : 1);
    fclose(f);
    return belay_manifest_read(g_m, none, NULL);
}

/* A regular file entry with `fields` spliced in before its hash. */
static char g_line[80000];
static const char *reg(const char *fields, const char *sha) {
    snprintf(g_line, sizeof g_line,
             "{\"path\":\"f\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,\"size\":3,"
             "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":7,\"dev\":1,\"nlink\":1%s,\"sha256\":\"%s\"}",
             fields, sha);
    return g_line;
}

/* Rejected, as CORRUPT. */
static bool rejected(int rc) {
    const bool r = rc == -1 && belay_err_code() == BELAY_ERR_CORRUPT;
    belay_err_clear();
    return r;
}

/* Rejected, as CORRUPT, for the reason `why` names. */
static bool rejected_for(int rc, const char *why) {
    const bool r = rc == -1 && belay_err_code() == BELAY_ERR_CORRUPT && strstr(belay_err_msg(), why);
    belay_err_clear();
    return r;
}

/* An xattrs array body of exactly n bytes: sorted elements, the last one's
 * name padded to make up the length. */
static char *xattrs_body(size_t n) {
    static char b[9000];
    size_t w = 0;
    for (int i = 0; i < 100; i++)
        w += (size_t)snprintf(b + w, sizeof b - w, "%s\"user.n%05d=" H64 "\"", i ? "," : "", i);
    const size_t last = n - w - 1;              /* the comma, then the last element */
    w += (size_t)snprintf(b + w, sizeof b - w, ",\"user.z");
    for (size_t k = 0; k < last - 73; k++) b[w++] = 'z';
    w += (size_t)snprintf(b + w, sizeof b - w, "=" H64 "\"");
    return b;
}

TEST(inline_xattrs_are_at_most_8192_bytes) {
    char fields[9100];
    snprintf(fields, sizeof fields, ",\"xattrs\":[%s]", xattrs_body(8192));
    ASSERT_EQ_INT(8192, (int)strlen(xattrs_body(8192)));
    ASSERT_EQ_INT(0, read_with(reg(fields, H64), NULL));
    snprintf(fields, sizeof fields, ",\"xattrs\":[%s]", xattrs_body(8193));
    ASSERT_TRUE(rejected_for(read_with(reg(fields, H64), NULL), "inline limit"));
}

TEST(a_line_is_at_most_65536_bytes) {
    static char line[65538];
    memset(line, 'x', sizeof line - 1);
    line[sizeof line - 1] = '\0';                       /* 65537 bytes */
    ASSERT_EQ_INT(-1, read_with(NULL, line));
    ASSERT_TRUE(strstr(belay_err_msg(), "exceeds 65536 bytes") != NULL);
    belay_err_clear();
    line[65536] = '\0';                                 /* 65536: not rejected for its length */
    ASSERT_EQ_INT(-1, read_with(NULL, line));
    ASSERT_TRUE(strstr(belay_err_msg(), "exceeds") == NULL);
    belay_err_clear();
}

static const char *named(size_t n) {
    static char name[5000];
    memset(name, 'p', n);
    name[n] = '\0';
    return name;
}

TEST(a_path_is_at_most_4095_bytes) {
    char line[5200];
    for (size_t n = 4095; n <= 4096; n++) {
        snprintf(line, sizeof line,
                 "{\"path\":\"%s\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,\"size\":3,"
                 "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":7,\"dev\":1,\"nlink\":1,\"sha256\":\"" H64 "\"}",
                 named(n));
        if (n == 4095) ASSERT_EQ_INT(0, read_with(line, NULL));
        else ASSERT_TRUE(rejected_for(read_with(line, NULL), "too long"));
    }
}

TEST(a_link_target_is_at_most_4095_bytes) {
    char line[5200];
    for (size_t n = 4095; n <= 4096; n++) {
        snprintf(line, sizeof line,
                 "{\"path\":\"l\",\"type\":\"lnk\",\"mode\":41471,\"uid\":1,\"gid\":1,\"size\":%zu,"
                 "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":7,\"dev\":1,\"nlink\":1,\"link_target\":\"%s\"}",
                 n, named(n));
        if (n == 4095) ASSERT_EQ_INT(0, read_with(line, NULL));
        else ASSERT_TRUE(rejected_for(read_with(line, NULL), "too long"));
    }
}

TEST(caps_is_at_most_128_hex_digits) {
    char fields[300], hex[200];
    memset(hex, 'a', 130);
    hex[128] = '\0';
    snprintf(fields, sizeof fields, ",\"caps\":\"%s\"", hex);
    ASSERT_EQ_INT(0, read_with(reg(fields, H64), NULL));
    hex[128] = 'a'; hex[130] = '\0';
    snprintf(fields, sizeof fields, ",\"caps\":\"%s\"", hex);
    ASSERT_TRUE(rejected(read_with(reg(fields, H64), NULL)));
    ASSERT_TRUE(rejected(read_with(reg(",\"caps\":\"abc\"", H64), NULL)));      /* odd */
    ASSERT_TRUE(rejected(read_with(reg(",\"caps\":\"\"", H64), NULL)));         /* empty */
}

TEST(hex_digits_are_lowercase) {
    const char *upper = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    ASSERT_EQ_INT(0, read_with(reg(",\"caps\":\"0a\"", H64), NULL));
    ASSERT_TRUE(rejected_for(read_with(reg("", upper), NULL), "lowercase hex"));   /* sha256 */
    char fields[400];
    snprintf(fields, sizeof fields, ",\"caps\":\"0A\"");
    ASSERT_TRUE(rejected_for(read_with(reg(fields, H64), NULL), "lowercase hex"));  /* caps */
    snprintf(fields, sizeof fields, ",\"xattrs_sha256\":\"%s\"", upper);
    ASSERT_TRUE(rejected_for(read_with(reg(fields, H64), NULL), "lowercase hex"));  /* xattrs_sha256 */
    snprintf(fields, sizeof fields, ",\"xattrs\":[\"user.a=%s\"]", upper);
    ASSERT_TRUE(rejected_for(read_with(reg(fields, H64), NULL), "name=sha256"));    /* in xattrs */
    snprintf(g_line, sizeof g_line,
             "{\"path\":\"f\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,\"size\":3,"
             "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":7,\"dev\":1,\"nlink\":1,\"sha256\":\"" H64 "\","
             "\"stored\":\"%s\"}", upper);
    ASSERT_TRUE(rejected_for(read_with(g_line, NULL), "lowercase hex"));            /* stored */
}

/* Writer facts: capture a tree under g_dir/tree. */
static int g_deepest_listed, g_first_unreadable;
static long long g_mtime;
static int depth_of(const struct belay_entry *e, void *c) {
    (void)c;
    if (strcmp(e->path, ".") == 0) return 0;
    int d = 1;
    for (const char *p = e->path; *p; p++) d += *p == '/';
    if (e->type == BELAY_T_DIR && !e->unreadable && d > g_deepest_listed) g_deepest_listed = d;
    if (e->unreadable && (g_first_unreadable == 0 || d < g_first_unreadable)) g_first_unreadable = d;
    if (strcmp(e->path, "t") == 0) g_mtime = (long long)e->mtime_ns;
    return 0;
}

static int capture(const char *tree) {
    struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20 };
    if (belay_manifest_write(g_m, tree, &o, NULL) != 0) return -1;
    return belay_manifest_read(g_m, depth_of, NULL);
}

static void fresh_tree(char *tree, size_t n) {
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s/tree'", g_dir);
    if (system(cmd) != 0) { /* the assertions say */ }
    snprintf(tree, n, "%s/tree", g_dir);
    mkdir(tree, 0700);
}

TEST(the_depth_limit_is_128) {
    char tree[300], p[1000];
    fresh_tree(tree, sizeof tree);
    snprintf(p, sizeof p, "%s", tree);
    for (int i = 0; i < 131; i++) {
        strcat(p, "/d");
        REQUIRE(mkdir(p, 0700) == 0);
    }
    g_deepest_listed = g_first_unreadable = 0;
    REQUIRE(capture(tree) == 0);
    ASSERT_EQ_INT(128, g_deepest_listed);
    ASSERT_EQ_INT(129, g_first_unreadable);
}

TEST(timestamps_saturate_at_the_int64_bounds) {
    char tree[300], t[400];
    fresh_tree(tree, sizeof tree);
    snprintf(t, sizeof t, "%s/t", tree);
    FILE *f = fopen(t, "w");
    REQUIRE(f != NULL);
    fclose(f);
    const struct timeval tv[2] = { { 10000000000LL, 0 }, { 10000000000LL, 0 } };   /* 2286 */
    REQUIRE(utimes(t, tv) == 0);
    g_mtime = 0;
    REQUIRE(capture(tree) == 0);
    ASSERT_TRUE(g_mtime == LLONG_MAX);
}

/* ---- the addendum's rows and these checks, both ways ---- */

static const char *const CHECKS[] = {
    "inline_xattrs_are_at_most_8192_bytes", "a_line_is_at_most_65536_bytes",
    "a_path_is_at_most_4095_bytes", "a_link_target_is_at_most_4095_bytes",
    "caps_is_at_most_128_hex_digits", "hex_digits_are_lowercase", "the_depth_limit_is_128",
    "timestamps_saturate_at_the_int64_bounds",
};

TEST(every_addendum_row_has_a_check_and_every_check_a_row) {
    FILE *f = fopen("test/expect/manifest-v1-addendum.md", "r");
    REQUIRE(f != NULL);
    char line[4096];
    size_t rows = 0;
    bool seen[sizeof CHECKS / sizeof CHECKS[0]] = { false };
    while (fgets(line, sizeof line, f) != NULL) {
        if (strncmp(line, "| A", 3) != 0) continue;
        rows++;
        char *last = strrchr(line, '`');
        char *first = last != NULL ? last - 1 : NULL;
        while (first != NULL && first > line && *first != '`') first--;
        if (first == NULL || first == last) { BELAY_FAIL("row without a check: %s", line); continue; }
        const size_t n = (size_t)(last - first - 1);
        bool found = false;
        for (size_t i = 0; i < sizeof CHECKS / sizeof CHECKS[0]; i++)
            if (strlen(CHECKS[i]) == n && strncmp(CHECKS[i], first + 1, n) == 0) found = seen[i] = true;
        if (!found) BELAY_FAIL("row names no check here: %.*s", (int)n, first + 1);
    }
    fclose(f);
    for (size_t i = 0; i < sizeof CHECKS / sizeof CHECKS[0]; i++)
        if (!seen[i]) BELAY_FAIL("check %s has no row", CHECKS[i]);
    ASSERT_EQ_INT((int)(sizeof CHECKS / sizeof CHECKS[0]), (int)rows);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_addendum_%d", (int)getpid());
    snprintf(g_m, sizeof g_m, "%s/m.ndjson", g_dir);
    mkdir(g_dir, 0700);
    RUN(inline_xattrs_are_at_most_8192_bytes);
    RUN(a_line_is_at_most_65536_bytes);
    RUN(a_path_is_at_most_4095_bytes);
    RUN(a_link_target_is_at_most_4095_bytes);
    RUN(caps_is_at_most_128_hex_digits);
    RUN(hex_digits_are_lowercase);
    RUN(the_depth_limit_is_128);
    RUN(timestamps_saturate_at_the_int64_bounds);
    RUN(every_addendum_row_has_a_check_and_every_check_a_row);
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
