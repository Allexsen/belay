/*
 *  Adversarial tests for the lexical path utilities.
 *
 *  These functions are ARGUMENT VALIDATION ONLY (BELAY_DESIGN.md §5.1.1), so
 *  the filesystem-level scenarios -- scope itself a symlink, dir swapped for a
 *  symlink mid-walk, mount boundary inside scope -- are NOT testable here:
 *  containment is by construction in the walker, not by these calls. They are
 *  listed in the phase report as deferred to the walker's tests (phase 2.2),
 *  where a real filesystem fixture exists.
 */
#include "belay_test.h"
#include "belay/path.h"
#include "belay/error.h"

static const char *norm(const char *in) {
    static char out[4096];
    if (belay_path_normalize(out, sizeof out, in) == -1) return NULL;
    return out;
}

TEST(normalize_collapses_separators_and_dots) {
    ASSERT_EQ_STR("a/b",     norm("a//b"));
    ASSERT_EQ_STR("a/b",     norm("a/./b"));
    ASSERT_EQ_STR("a/b",     norm("a/b/"));
    ASSERT_EQ_STR("a/b",     norm("a/b///"));
    ASSERT_EQ_STR("/a/b",    norm("/a//./b/"));
    ASSERT_EQ_STR("/a/b",    norm("///a/b"));
    ASSERT_EQ_STR("a/b/c",   norm("./a/b/c"));
}

TEST(normalize_preserves_absoluteness) {
    ASSERT_EQ_STR("/a",  norm("/a"));
    ASSERT_EQ_STR("a",   norm("a"));
    ASSERT_EQ_STR("/",   norm("/"));
    ASSERT_EQ_STR("/",   norm("///"));
    ASSERT_EQ_STR("/",   norm("/./"));
}

/* Degenerate relative inputs that reduce to nothing. */
TEST(normalize_dot_only_inputs) {
    ASSERT_EQ_STR(".", norm("."));
    ASSERT_EQ_STR(".", norm("./"));
    ASSERT_EQ_STR(".", norm("././."));
}

/* ".." is rejected rather than resolved: lexical resolution is unsound under
 * symlinks. This is the single most important behaviour in this unit. */
TEST(normalize_rejects_dotdot_everywhere) {
    ASSERT_TRUE(norm("..") == NULL);
    ASSERT_TRUE(norm("../etc") == NULL);
    ASSERT_TRUE(norm("a/../../etc") == NULL);
    ASSERT_TRUE(norm("a/b/..") == NULL);
    ASSERT_TRUE(norm("/a/../etc/passwd") == NULL);
    ASSERT_TRUE(norm("/../..") == NULL);
    belay_err_clear();
}

/* "..." and "..a" are ordinary filenames, not traversal. Over-rejecting them
 * would make legitimate paths unusable. */
TEST(normalize_allows_lookalike_components) {
    ASSERT_EQ_STR("...",      norm("..."));
    ASSERT_EQ_STR("..a",      norm("..a"));
    ASSERT_EQ_STR("a/..b/c",  norm("a/..b/c"));
    ASSERT_EQ_STR(".hidden",  norm(".hidden"));
}

TEST(normalize_rejects_empty_and_null) {
    ASSERT_TRUE(norm("") == NULL);
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
    char buf[16];
    ASSERT_EQ_INT(-1, belay_path_normalize(buf, sizeof buf, NULL));
    ASSERT_EQ_INT(-1, belay_path_normalize(NULL, 16, "a"));
    ASSERT_EQ_INT(-1, belay_path_normalize(buf, 0, "a"));
    belay_err_clear();
}

/* Truncation must be an error, never a silently shortened path -- a shortened
 * path would name a different file. */
TEST(normalize_reports_truncation_not_truncates) {
    char small[4];
    ASSERT_EQ_INT(-1, belay_path_normalize(small, sizeof small, "aaaa/bbbb"));
    ASSERT_EQ_INT(BELAY_ERR_RANGE, belay_err_code());

    /* Exactly-fits boundary: "abc" needs 4 bytes with the NUL. */
    char exact[4];
    ASSERT_EQ_INT(0, belay_path_normalize(exact, sizeof exact, "abc"));
    ASSERT_EQ_STR("abc", exact);

    char tight[4];
    ASSERT_EQ_INT(-1, belay_path_normalize(tight, sizeof tight, "abcd"));
    belay_err_clear();
}

/* Paths are bytes. Non-UTF-8 and high-bit bytes must pass through unharmed. */
TEST(normalize_is_byte_transparent) {
    ASSERT_EQ_STR("\xff\xfe/b", norm("\xff\xfe//b"));
    ASSERT_EQ_STR("caf\xc3\xa9", norm("caf\xc3\xa9"));
    ASSERT_EQ_STR("a\x01\x02b", norm("a\x01\x02b"));
}

/* A path with a space or newline is legal on every POSIX filesystem. */
TEST(normalize_allows_whitespace_in_names) {
    ASSERT_EQ_STR("my dir/f",  norm("my dir//f"));
    ASSERT_EQ_STR("a\nb",      norm("a\nb"));
    ASSERT_EQ_STR("a\tb",      norm("a\tb"));
}

TEST(within_accepts_self_and_descendants) {
    ASSERT_EQ_INT(1, belay_path_within_lexical("/a", "/a"));
    ASSERT_EQ_INT(1, belay_path_within_lexical("/a", "/a/b"));
    ASSERT_EQ_INT(1, belay_path_within_lexical("/a", "/a/b/c/d"));
    ASSERT_EQ_INT(1, belay_path_within_lexical("/a/", "/a//b/"));
    ASSERT_EQ_INT(1, belay_path_within_lexical("rel", "rel/x"));
}

/* The classic string-prefix bug: "/ab" must not be inside "/a". */
TEST(within_is_component_wise_not_string_prefix) {
    ASSERT_EQ_INT(0, belay_path_within_lexical("/a", "/ab"));
    ASSERT_EQ_INT(0, belay_path_within_lexical("/a", "/abc/d"));
    ASSERT_EQ_INT(0, belay_path_within_lexical("/home/x", "/home/xy"));
}

TEST(within_rejects_outside_paths) {
    ASSERT_EQ_INT(0, belay_path_within_lexical("/a/b", "/a"));
    ASSERT_EQ_INT(0, belay_path_within_lexical("/a", "/b"));
    ASSERT_EQ_INT(0, belay_path_within_lexical("/a", "/"));
}

/* Root is the one case where the separator is already present. */
TEST(within_handles_root_as_scope) {
    ASSERT_EQ_INT(1, belay_path_within_lexical("/", "/"));
    ASSERT_EQ_INT(1, belay_path_within_lexical("/", "/anything/deep"));
}

/* A ".." anywhere in either argument is an error, not a false -- a caller
 * treating -1 as "not within" would silently accept a malformed scope. */
TEST(within_errors_on_dotdot_in_either_argument) {
    ASSERT_EQ_INT(-1, belay_path_within_lexical("/a", "/a/../b"));
    ASSERT_EQ_INT(-1, belay_path_within_lexical("/a/..", "/a/b"));
    belay_err_clear();
}

TEST(within_errors_on_mixed_absoluteness) {
    ASSERT_EQ_INT(-1, belay_path_within_lexical("/a", "a/b"));
    ASSERT_EQ_INT(-1, belay_path_within_lexical("a", "/a/b"));
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
    belay_err_clear();
}

TEST(within_errors_on_null_or_empty) {
    ASSERT_EQ_INT(-1, belay_path_within_lexical(NULL, "/a"));
    ASSERT_EQ_INT(-1, belay_path_within_lexical("/a", NULL));
    ASSERT_EQ_INT(-1, belay_path_within_lexical("", "/a"));
    belay_err_clear();
}

int main(void) {
    RUN(normalize_collapses_separators_and_dots);
    RUN(normalize_preserves_absoluteness);
    RUN(normalize_dot_only_inputs);
    RUN(normalize_rejects_dotdot_everywhere);
    RUN(normalize_allows_lookalike_components);
    RUN(normalize_rejects_empty_and_null);
    RUN(normalize_reports_truncation_not_truncates);
    RUN(normalize_is_byte_transparent);
    RUN(normalize_allows_whitespace_in_names);
    RUN(within_accepts_self_and_descendants);
    RUN(within_is_component_wise_not_string_prefix);
    RUN(within_rejects_outside_paths);
    RUN(within_handles_root_as_scope);
    RUN(within_errors_on_dotdot_in_either_argument);
    RUN(within_errors_on_mixed_absoluteness);
    RUN(within_errors_on_null_or_empty);
    return belay_test_report();
}
