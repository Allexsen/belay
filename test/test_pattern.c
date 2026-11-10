/*
 *  The one matcher (src/util/pattern.c) in the watch dialect
 *  (test/expect/watch-v1.md WD-1 to WD-4). The protect dialect, no switch
 *  on, is test_protect.c's and the independent policy model's: they run
 *  unchanged on this code. Each case is a table row; a failure names it.
 */
#include "belay_test.h"
#include <stdio.h>
#include <string.h>

#include "util/pattern.h"

static unsigned m(const char *pat, const char *path, unsigned sw) {
    return pattern_match(pat, strlen(pat), path, strlen(path), sw);
}

struct row { const char *pat, *path; unsigned sw, want; };

static void table(const struct row *t, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char want[512], got[512];
        snprintf(want, sizeof want, "%s ~ %s (switches %u): %u", t[i].pat, t[i].path, t[i].sw, t[i].want);
        snprintf(got, sizeof got, "%s ~ %s (switches %u): %u", t[i].pat, t[i].path, t[i].sw, m(t[i].pat, t[i].path, t[i].sw));
        ASSERT_EQ_STR(want, got);
    }
}

#define D PATTERN_DOTS
#define N PATTERN_NOCASE
#define S PATTERN_SELF
#define A PATTERN_ABOVE

TEST(wildcards_match_dot_names_only_with_the_switch) {
    static const struct row t[] = {
        { "*", ".env", 0, 0 },          { "*", ".env", D, S },
        { "**", ".a/.b", 0, A },        { "**", ".a/.b", D, S | A },   /* `**` takes none too: the top itself matches */
        { "tests/**", "tests/.cache/x", 0, A },     /* PS-P4: `tests` itself matches, the rest does not */
        { "tests/**", "tests/.cache/x", D, S | A },
        { "**/*.lock", ".hidden/a.lock", 0, 0 },    { "**/*.lock", ".hidden/a.lock", D, S },
        { "*.pth", ".x.pth", 0, 0 },    { "*.pth", ".x.pth", D, S },
        { ".*", ".env", 0, S },         { ".*", ".env", D, S },
    };
    table(t, sizeof t / sizeof t[0]);
}

TEST(a_match_on_an_ancestor_is_told_from_a_match_on_the_path) {
    static const struct row t[] = {
        { "migrations", "migrations", D, S },
        { "migrations", "migrations/0001.py", D, A },
        { "migrations", "migrations/a/b/c", D, A },
        { "migrations", "migrations2/x", D, 0 },
        { "migrations", "x/migrations/y", D, 0 },           /* a pattern starts at the top (WD-3) */
        { "**/migrations", "x/migrations/y", D, A },
        { ".claude", ".claude/skills/a/SKILL.md", D, A },
        { ".claude/*", ".claude", D, 0 },
        { ".claude/*", ".claude/settings.json", D, S },
        { ".claude/*", ".claude/skills/a/SKILL.md", D, A },
        { "**/.git/hooks/*", ".git/hooks/pre-push", D, S },
        { "**/.git/hooks/*", "sub/.git/hooks/pre-push", D, S },
        { "**/.git/hooks/*", ".git/hooks", D, 0 },
        { "**/.git/hooks", ".git/hooks/pre-push", D, A },
        { "**/node_modules", "a/node_modules/b/node_modules/c", D, A },
        { "**/node_modules", "node_modules", D, S },
        { "a/**", "a", D, S },          { "a/**", "a/b", D, S | A },
    };
    table(t, sizeof t / sizeof t[0]);
}

TEST(a_pattern_starts_at_the_top) {
    static const struct row t[] = {
        { "*.lock", "a.lock", D, S },   { "*.lock", "sub/a.lock", D, 0 },
        { "**/*.lock", "a.lock", D, S },    { "**/*.lock", "sub/deep/a.lock", D, S },
        { "CODEOWNERS", "docs/CODEOWNERS", D, 0 },
    };
    table(t, sizeof t / sizeof t[0]);
}

TEST(letters_fold_only_with_the_switch_and_only_ascii) {
    static const struct row t[] = {
        { "claude.md", "CLAUDE.md", D, 0 },         { "claude.md", "CLAUDE.md", D | N, S },
        { "**/CLAUDE.md", "docs/Claude.MD", D | N, S },
        { "**/.ENV", "a/.env", D | N, S },
        { "jenkinsfile", "Jenkinsfile", N, S },     /* the fold is its own switch */
        { "*.PEM", ".hidden.pem", N, 0 },           /* and does not bring dot-names with it */
        { "\xc3\xa9", "\xc3\x89", D | N, 0 },       /* e-acute and E-acute: bytes, not letters */
        { "a[b", "A[B", D | N, S },     { "a?b", "axb", D | N, 0 },     /* nothing else is special */
    };
    table(t, sizeof t / sizeof t[0]);
}

TEST(covers_says_whether_a_directory_could_hold_a_match) {
    ASSERT_TRUE(pattern_covers(".claude/worktrees", 17, ".claude", 7, D));
    ASSERT_TRUE(pattern_covers(".claude", 7, ".claude/worktrees", 17, D) == false);   /* past the pattern: a match's inside, not a prefix */
    ASSERT_FALSE(pattern_covers(".claude", 7, "node_modules", 12, D));
    ASSERT_FALSE(pattern_covers("CLAUDE.md", 9, "node_modules", 12, D | N));
    ASSERT_TRUE(pattern_covers("**/.env", 7, "node_modules", 12, D));
    ASSERT_FALSE(pattern_covers("**/x", 4, ".hidden", 7, 0));
    ASSERT_TRUE(pattern_covers("**/x", 4, ".hidden", 7, D));
    ASSERT_TRUE(pattern_covers("a/b", 3, "", 0, D));
}

TEST(globstars_are_counted_and_validity_is_the_protect_grammars) {
    ASSERT_EQ_INT(0, (int)pattern_globstars("a/b*", 4));
    ASSERT_EQ_INT(2, (int)pattern_globstars("**/a/**", 7));
    ASSERT_EQ_INT(1, (int)pattern_globstars("**/a**/b", 8));
    ASSERT_TRUE(pattern_valid("a/b", 3));
    ASSERT_FALSE(pattern_valid("", 0));
    ASSERT_FALSE(pattern_valid("/a", 2));
    ASSERT_FALSE(pattern_valid("a/", 2));
    ASSERT_FALSE(pattern_valid("a//b", 4));
    ASSERT_FALSE(pattern_valid("a/./b", 5));
    ASSERT_FALSE(pattern_valid("../b", 4));
    ASSERT_FALSE(pattern_valid("a\0b", 3));
}

int main(void) {
    RUN(wildcards_match_dot_names_only_with_the_switch);
    RUN(a_match_on_an_ancestor_is_told_from_a_match_on_the_path);
    RUN(a_pattern_starts_at_the_top);
    RUN(letters_fold_only_with_the_switch_and_only_ascii);
    RUN(covers_says_whether_a_directory_could_hold_a_match);
    RUN(globstars_are_counted_and_validity_is_the_protect_grammars);
    return belay_test_report();
}
