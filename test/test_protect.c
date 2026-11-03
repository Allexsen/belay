/*
 *  The protect spec against its pin (test/expect/protect-spec.md): every
 *  key read, every row's refusals, the pattern language -- the explicit
 *  dot-segment rule of decision 157 included -- and what an exclusion
 *  covers (PS-C2). Each case is printed as "<case>: <result>", so a failure
 *  names it.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "belay/error.h"
#include "policy/protect.h"

static char g_line[8192];

static const char *parse(const char *json) {
    struct protect_spec s;
    if (protect_parse(json, strlen(json), &s) == -1) {
        snprintf(g_line, sizeof g_line, "%s: refused", json);
        return g_line;
    }
    protect_free(&s);
    snprintf(g_line, sizeof g_line, "%s: read", json);
    return g_line;
}

#define OK(json)      do { char w_[8192]; snprintf(w_, sizeof w_, "%s: read", json); ASSERT_EQ_STR(w_, parse(json)); } while (0)
#define REFUSED(json) do { char w_[8192]; snprintf(w_, sizeof w_, "%s: refused", json); ASSERT_EQ_STR(w_, parse(json)); } while (0)

TEST(a_spec_reads_every_key_of_its_rows) {
    const char *j = "{\"belay_protect\": 1,\n"
                    " \"protect\": [{\"path\": \"tests/**\", \"mode\": [\"no_write\", \"no_delete\", \"no_create\"]},\n"
                    "             {\"path\": \"grader/check.py\", \"mode\": [\"no_write\"],\n"
                    "              \"expected_sha256\": \"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"},\n"
                    "             {\"path\": \"answer.txt\", \"expected_sha256\": "
                    "\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}],\n"
                    " \"frozen_packages\": true, \"path_dirs\": [\"bin\", \"opt/*/bin\"]}\n";
    struct protect_spec s;
    REQUIRE_MSG(protect_parse(j, strlen(j), &s) == 0, "%s", belay_err_msg());
    ASSERT_EQ_INT(3, (int)s.n_rules);
    ASSERT_EQ_STR("tests/**", s.rules[0].path);
    ASSERT_EQ_INT(PROTECT_NO_WRITE | PROTECT_NO_DELETE | PROTECT_NO_CREATE, (int)s.rules[0].modes);
    ASSERT_FALSE(s.rules[0].has_sha256);
    ASSERT_EQ_INT(PROTECT_NO_WRITE, (int)s.rules[1].modes);
    ASSERT_TRUE(s.rules[1].has_sha256);
    ASSERT_EQ_STR("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", s.rules[1].sha256);
    ASSERT_EQ_INT(0, (int)s.rules[2].modes);        /* expected_sha256 alone (PS-4) */
    ASSERT_TRUE(s.frozen_packages);
    ASSERT_TRUE(s.has_path_dirs);
    ASSERT_EQ_INT(2, (int)s.n_path_dirs);
    ASSERT_EQ_STR("opt/*/bin", s.path_dirs[1]);
    ASSERT_EQ_INT(64, (int)strlen(s.sha256));
    protect_free(&s);
    /* the defaults: frozen_packages false, path_dirs not given */
    const char *m = "{\"belay_protect\":1,\"protect\":[]}";
    REQUIRE(protect_parse(m, strlen(m), &s) == 0);
    ASSERT_FALSE(s.frozen_packages);
    ASSERT_FALSE(s.has_path_dirs);
    ASSERT_EQ_INT(0, (int)s.n_rules);
    protect_free(&s);
}

/* PS-R2: whatever a row does not allow refuses the whole spec. */
TEST(a_spec_is_refused_for_anything_its_rows_do_not_allow) {
    OK("{\"belay_protect\":1,\"protect\":[{\"path\":\"a\",\"mode\":[\"no_write\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[],\"frozen_package\":true}");     /* a misspelt key */
    REFUSED("{\"belay_protect\":1,\"protect\":[],\"protect\":[]}");               /* given twice */
    REFUSED("{\"protect\":[]}");                                                  /* no version */
    REFUSED("{\"belay_protect\":2,\"protect\":[]}");
    REFUSED("{\"belay_protect\":1.0,\"protect\":[]}");
    REFUSED("{\"belay_protect\":\"1\",\"protect\":[]}");
    REFUSED("{\"belay_protect\":1}");                                             /* no protect */
    REFUSED("{\"belay_protect\":1,\"protect\":{}}");
    REFUSED("{\"belay_protect\":1,\"protect\":[],\"frozen_packages\":1}");
    REFUSED("{\"belay_protect\":1,\"protect\":[],\"path_dirs\":\"bin\"}");
    REFUSED("{\"belay_protect\":1,\"protect\":[],\"path_dirs\":[\"/bin\"]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a\"}]}");              /* neither mode nor sha */
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a\",\"mode\":[]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a\",\"mode\":[\"no_read\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a\",\"mode\":[\"no_write\",\"no_write\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a\",\"mode\":\"no_write\"}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a\",\"mode\":[\"no_write\"],\"why\":\"x\"}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a\",\"path\":\"b\",\"mode\":[\"no_write\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a*\",\"expected_sha256\":"
            "\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}");   /* sha with a '*' */
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a\",\"expected_sha256\":"
            "\"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\"}]}");   /* not lowercase */
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a\",\"expected_sha256\":\"e3b0\"}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"/a\",\"mode\":[\"no_write\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a/\",\"mode\":[\"no_write\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a//b\",\"mode\":[\"no_write\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a/./b\",\"mode\":[\"no_write\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"../a\",\"mode\":[\"no_write\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"\",\"mode\":[\"no_write\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"a\\u0000b\",\"mode\":[\"no_write\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\\u0000\":\"a\",\"mode\":[\"no_write\"]}]}");
    REFUSED("{\"belay_protect\":1,\"protect\":[]} x");                             /* after it */
    REFUSED("[{\"belay_protect\":1,\"protect\":[]}]");
    REFUSED("{\"belay_protect\":1,\"protect\":[{\"path\":\"\xff\",\"mode\":[\"no_write\"]}]}");   /* not UTF-8 */
}

TEST(a_spec_is_bounded_by_its_rows) {
    /* 4,096 rules read, 4,097 refused (PS-2) */
    const char *rule = "{\"path\":\"a\",\"mode\":[\"no_write\"]},";
    const size_t rl = strlen(rule);
    char *j = malloc(64 + (PROTECT_RULES_MAX + 1) * rl);
    REQUIRE(j != NULL);
    for (int extra = 0; extra < 2; extra++) {
        size_t n = (size_t)sprintf(j, "{\"belay_protect\":1,\"protect\":[");
        for (size_t i = 0; i < PROTECT_RULES_MAX + (size_t)extra; i++) n += (size_t)sprintf(j + n, "%s", rule);
        sprintf(j + n - 1, "]}");
        struct protect_spec s;
        const int rc = protect_parse(j, strlen(j), &s);
        ASSERT_EQ_INT(extra ? -1 : 0, rc);
        if (rc == 0) protect_free(&s);
    }
    free(j);
    /* a pattern of 4,096 bytes read, 4,097 refused (PS-P1) */
    char p[PROTECT_PATTERN_MAX + 2];
    memset(p, 'a', sizeof p - 1);
    p[PROTECT_PATTERN_MAX] = '\0';
    ASSERT_TRUE(protect_pattern_valid(p, PROTECT_PATTERN_MAX));
    ASSERT_FALSE(protect_pattern_valid(p, PROTECT_PATTERN_MAX + 1));
    /* larger than 1 MiB: refused before it is parsed (PS-R1) */
    char *big = malloc(PROTECT_SPEC_MAX + 2);
    REQUIRE(big != NULL);
    memset(big, ' ', PROTECT_SPEC_MAX + 1);
    const char *small = "{\"belay_protect\":1,\"protect\":[]}";
    memcpy(big, small, strlen(small));
    struct protect_spec s;
    ASSERT_EQ_INT(-1, protect_parse(big, PROTECT_SPEC_MAX + 1, &s));
    ASSERT_EQ_INT(0, protect_parse(big, PROTECT_SPEC_MAX, &s));
    protect_free(&s);
    free(big);
}

static const char *match(const char *pat, const char *path) {
    snprintf(g_line, sizeof g_line, "%s ~ %s: %s", pat, path,
             protect_match(pat, strlen(pat), path, strlen(path)) ? "matches" : "no");
    return g_line;
}

#define MATCHES(pat, path) do { char w_[8192]; snprintf(w_, sizeof w_, "%s ~ %s: matches", pat, path); ASSERT_EQ_STR(w_, match(pat, path)); } while (0)
#define NO(pat, path)      do { char w_[8192]; snprintf(w_, sizeof w_, "%s ~ %s: no", pat, path); ASSERT_EQ_STR(w_, match(pat, path)); } while (0)

TEST(patterns_match_as_ps_p2_to_p4) {
    MATCHES("grader/check.py", "grader/check.py");
    NO("grader/check.py", "grader/check.pyc");
    NO("grader/check.py", "grader");
    NO("grader", "grader/check.py");
    MATCHES("tests/**", "tests");                       /* PS-P2: none included */
    MATCHES("tests/**", "tests/a/b/test_x.py");
    NO("tests/**", "testsuite/x");
    MATCHES("**/conftest.py", "conftest.py");
    MATCHES("**/conftest.py", "a/b/conftest.py");
    MATCHES("a/**/b/**/c", "a/b/c");
    MATCHES("a/**/b/**/c", "a/x/b/y/z/c");
    MATCHES("a/**/b/**/c", "a/b/b/b/c");
    NO("a/**/b/**/c", "a/x/y/c");
    MATCHES("**", "a/b/c");
    MATCHES("test_*.py", "test_api.py");                /* PS-P3 */
    MATCHES("test_*.py", "test_.py");
    NO("test_*.py", "test_api.pyc");
    NO("test_*.py", "sub/test_api.py");
    MATCHES("a/*/c", "a/b/c");
    NO("a/*/c", "a/b/x/c");
    MATCHES("*_test.*", "x_test.go");
    MATCHES("a?[b]\\", "a?[b]\\");                      /* only '*' is special */
    NO("a?", "ab");
    /* PS-P4: a wildcard never matches a dot-name ... */
    NO("tests/**", "tests/.cache/x");
    NO("**", ".git/config");
    NO("**/x", ".a/x");
    NO("*", ".env");
    NO("*.yml", ".travis.yml");
    NO("a/*/c", "a/.b/c");
    /* ... and a component written with a leading '.' matches one (decision 157) */
    MATCHES(".github/workflows/**", ".github/workflows/ci.yml");
    MATCHES(".github/workflows/**", ".github/workflows");
    MATCHES(".github/**", ".github/workflows/ci.yml");
    MATCHES("**/.github/workflows/*.yml", "repo/.github/workflows/ci.yml");
    MATCHES("tests/.cache/**", "tests/.cache/x");
    MATCHES(".*", ".env");
    MATCHES(".travis.yml", ".travis.yml");
    NO(".*", "env");
    NO(".github/workflows/**", ".github/.hidden/ci.yml");
}

static const char *covers(const char *pat, const char *dir) {
    snprintf(g_line, sizeof g_line, "%s over %s: %s", pat, dir,
             protect_covers(pat, strlen(pat), dir, strlen(dir)) ? "covered" : "no");
    return g_line;
}

#define COVERED(pat, dir)   do { char w_[8192]; snprintf(w_, sizeof w_, "%s over %s: covered", pat, dir); ASSERT_EQ_STR(w_, covers(pat, dir)); } while (0)
#define UNCOVERED(pat, dir) do { char w_[8192]; snprintf(w_, sizeof w_, "%s over %s: no", pat, dir); ASSERT_EQ_STR(w_, covers(pat, dir)); } while (0)

/* PS-C2: an exclusion covers a pattern when some path at or below it could
 * match. */
TEST(an_exclusion_covers_a_pattern_when_a_path_below_it_could_match) {
    COVERED("grader/check.py", "grader");               /* above a protected file */
    COVERED("grader/check.py", "grader/check.py");      /* the file itself */
    UNCOVERED("grader/check.py", "data");
    UNCOVERED("tests", "tests/data");                   /* below it: `tests` itself still walked */
    COVERED("tests/**", "tests/data");
    COVERED("tests/**", "tests");
    COVERED("**/conftest.py", "vendor");
    UNCOVERED("**/conftest.py", ".belay-state");        /* `**` never takes a dot-name */
    COVERED(".github/workflows/**", ".github");
    UNCOVERED("src/*.py", "src/lib/deep");
    COVERED("src/*.py", "src");
}

TEST(a_spec_file_is_read_and_its_digest_is_its_bytes) {
    char path[] = "/tmp/belay-protect-XXXXXX";
    const int fd = mkstemp(path);
    REQUIRE(fd >= 0);
    const char *j = "{\"belay_protect\":1,\"protect\":[{\"path\":\"a\",\"mode\":[\"no_delete\"]}]}\n";
    REQUIRE(write(fd, j, strlen(j)) == (ssize_t)strlen(j));
    close(fd);
    struct protect_spec s;
    REQUIRE_MSG(protect_load(path, &s) == 0, "%s", belay_err_msg());
    /* sha256sum of those bytes, computed apart */
    ASSERT_EQ_STR("259f5493730e122ae2b41bd5a8d9ab1adda66cda27fdeb72d4cd7f230a16006c", s.sha256);
    protect_free(&s);
    unlink(path);
    ASSERT_EQ_INT(-1, protect_load("/nonexistent/belay-protect", &s));
    ASSERT_EQ_INT(BELAY_ERR_IO, belay_err_code());
}

int main(void) {
    RUN(a_spec_reads_every_key_of_its_rows);
    RUN(a_spec_is_refused_for_anything_its_rows_do_not_allow);
    RUN(a_spec_is_bounded_by_its_rows);
    RUN(patterns_match_as_ps_p2_to_p4);
    RUN(an_exclusion_covers_a_pattern_when_a_path_below_it_could_match);
    RUN(a_spec_file_is_read_and_its_digest_is_its_bytes);
    return belay_test_report();
}
