/*
 *  Minimal test harness for belay.
 *
 *  No dependencies, portable POSIX C: §9.1 requires the portable engine to build
 *  and pass tests on macOS in CI, so the harness must not use anything
 *  Linux-specific.
 *
 *  Usage: one test binary per unit under test.
 *
 *      #include "belay_test.h"
 *
 *      TEST(thing_does_what_it_says) {
 *          ASSERT_EQ_INT(2, 1 + 1);
 *      }
 *
 *      int main(void) {
 *          RUN(thing_does_what_it_says);
 *          return belay_test_report();
 *      }
 *
 *  A test ends early only through SKIP(reason), when something it needs is not
 *  there, or REQUIRE(expr), when an assertion it cannot go on without failed.
 *  A bare `return` in a TEST body is a lint error (scripts/lint-tests.py): it
 *  reports `ok` without having checked anything.
 *
 *  Exit status is 0 when every assertion passed and the accounting below
 *  holds, 1 otherwise, so `make test` and CI gate on it directly.
 *
 *  Accounting, when BELAY_ACCOUNTING names a directory (the Makefile sets it):
 *  the tests that ran must be exactly <dir>/tests/<binary>.txt, so a test
 *  cannot vanish by losing its RUN() line; and when BELAY_SKIP_PROFILE is set
 *  (CI sets it per job), the tests that skipped must be exactly the lines
 *  "<binary> <test>" of <dir>/skips/<profile>.txt. Without the profile, skips
 *  are printed but not judged (a developer's machine is not a CI job).
 */
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BELAY_TEST_MAX 512

static int belay_tests_run;
static int belay_tests_failed;
static int belay_tests_skipped;
static int belay_current_failed;
static int belay_current_skipped;
static char belay_current_skip_reason[256];
static const char *belay_h_names[BELAY_TEST_MAX];
static const char *belay_h_skips[BELAY_TEST_MAX];

#define TEST(name) static void belay_test_##name(void)

/*
 *  Runs one test and reports ok, FAIL or SKIP. A test fails if any assertion
 *  in it failed; assertions do not abort, so one run reports every broken
 *  assertion rather than only the first. A failure outranks a skip.
 */
#define RUN(name)                                                      \
    do {                                                               \
        belay_current_failed = 0;                                      \
        belay_current_skipped = 0;                                     \
        belay_current_skip_reason[0] = '\0';                           \
        if (belay_tests_run < BELAY_TEST_MAX)                          \
            belay_h_names[belay_tests_run] = #name;                 \
        belay_tests_run++;                                             \
        belay_test_##name();                                           \
        if (belay_current_failed) {                                    \
            belay_tests_failed++;                                      \
            printf("FAIL  %s\n", #name);                               \
        } else if (belay_current_skipped) {                            \
            if (belay_tests_skipped < BELAY_TEST_MAX)                  \
                belay_h_skips[belay_tests_skipped] = #name;         \
            belay_tests_skipped++;                                     \
            printf("SKIP  %s (%s)\n", #name, belay_current_skip_reason); \
        } else {                                                       \
            printf("ok    %s\n", #name);                               \
        }                                                              \
    } while (0)

#define BELAY_FAIL(fmt, ...)                                           \
    do {                                                               \
        printf("      %s:%d: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__); \
        belay_current_failed = 1;                                       \
    } while (0)

/* The test cannot run here: something it needs is missing. Ends the test. */
#define SKIP(reason)                                                   \
    do {                                                               \
        belay_current_skipped = 1;                                     \
        snprintf(belay_current_skip_reason, sizeof belay_current_skip_reason, "%s", (reason)); \
        return;                                                        \
    } while (0)

/* An assertion the rest of the test depends on: fails and ends the test. */
#define REQUIRE(expr)                                                  \
    do {                                                               \
        if (!(expr)) {                                                 \
            BELAY_FAIL("required: %s", #expr);                         \
            return;                                                    \
        }                                                              \
    } while (0)

#define REQUIRE_MSG(expr, fmt, ...)                                    \
    do {                                                               \
        if (!(expr)) {                                                 \
            BELAY_FAIL(fmt, __VA_ARGS__);                              \
            return;                                                    \
        }                                                              \
    } while (0)

#define ASSERT_TRUE(expr)                                              \
    do {                                                               \
        if (!(expr)) BELAY_FAIL("expected true: %s", #expr);           \
    } while (0)

#define ASSERT_FALSE(expr)                                             \
    do {                                                               \
        if (expr) BELAY_FAIL("expected false: %s", #expr);             \
    } while (0)

/* Signed integers; long long so every smaller integer type widens cleanly. */
#define ASSERT_EQ_INT(want, got)                                       \
    do {                                                               \
        long long _w = (long long)(want), _g = (long long)(got);       \
        if (_w != _g)                                                  \
            BELAY_FAIL("%s: want %lld, got %lld", #got, _w, _g);       \
    } while (0)

#define ASSERT_EQ_STR(want, got)                                       \
    do {                                                               \
        const char *_w = (want), *_g = (got);                          \
        if (_w == NULL || _g == NULL) {                                \
            if (_w != _g)                                              \
                BELAY_FAIL("%s: want %s, got %s", #got,                \
                           _w ? _w : "(null)", _g ? _g : "(null)");    \
        } else if (strcmp(_w, _g) != 0) {                              \
            BELAY_FAIL("%s: want \"%s\", got \"%s\"", #got, _w, _g);   \
        }                                                              \
    } while (0)

/* ---- accounting --------------------------------------------------------- */

/* Lines of `path` into `out` (malloc'd copies); -1 when it cannot be read. */
static int belay_h_lines(const char *path, char **out, int cap) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;
        if (n < cap) {
            const size_t l = strlen(line) + 1;
            out[n] = malloc(l);
            if (out[n] != NULL) memcpy(out[n++], line, l);
        }
    }
    fclose(f);
    return n;
}

static int belay_h_has(char **set, int n, const char *s) {
    for (int i = 0; i < n; i++) if (strcmp(set[i], s) == 0) return 1;
    return 0;
}

/* 0 when the accounting holds (or is not asked for), 1 otherwise. */
static inline int belay_h_accounting(void) {
#ifdef BELAY_TEST_BIN
    const char *dir = getenv("BELAY_ACCOUNTING");
    if (dir == NULL || dir[0] == '\0') return 0;
    int bad = 0;
    char path[1024], *want[BELAY_TEST_MAX];
    snprintf(path, sizeof path, "%s/tests/%s.txt", dir, BELAY_TEST_BIN);
    const int nw = belay_h_lines(path, want, BELAY_TEST_MAX);
    if (nw < 0) {
        printf("accounting: cannot read %s\n", path);
        return 1;
    }
    const int ran = belay_tests_run < BELAY_TEST_MAX ? belay_tests_run : BELAY_TEST_MAX;
    for (int i = 0; i < ran; i++)
        if (!belay_h_has(want, nw, belay_h_names[i])) {
            printf("accounting: %s ran but is not listed in %s\n", belay_h_names[i], path);
            bad = 1;
        }
    for (int i = 0; i < nw; i++) {
        int found = 0;
        for (int j = 0; j < ran; j++) if (strcmp(want[i], belay_h_names[j]) == 0) found = 1;
        if (!found) {
            printf("accounting: %s is listed in %s but did not run\n", want[i], path);
            bad = 1;
        }
    }
    const char *profile = getenv("BELAY_SKIP_PROFILE");
    if (profile != NULL && profile[0] != '\0') {
        char *decl[BELAY_TEST_MAX], key[600];
        snprintf(path, sizeof path, "%s/skips/%s.txt", dir, profile);
        const int nd = belay_h_lines(path, decl, BELAY_TEST_MAX);
        if (nd < 0) {
            printf("accounting: no skip list %s for profile %s\n", path, profile);
            return 1;
        }
        const int sk = belay_tests_skipped < BELAY_TEST_MAX ? belay_tests_skipped : BELAY_TEST_MAX;
        for (int i = 0; i < sk; i++) {
            snprintf(key, sizeof key, "%s %s", BELAY_TEST_BIN, belay_h_skips[i]);
            if (!belay_h_has(decl, nd, key)) {
                printf("accounting: %s skipped, not declared for %s\n", key, profile);
                bad = 1;
            }
        }
        const size_t bl = strlen(BELAY_TEST_BIN);
        for (int i = 0; i < nd; i++) {
            if (strncmp(decl[i], BELAY_TEST_BIN, bl) != 0 || decl[i][bl] != ' ') continue;
            int skipped = 0;
            for (int j = 0; j < sk; j++) if (strcmp(decl[i] + bl + 1, belay_h_skips[j]) == 0) skipped = 1;
            if (!skipped) {
                printf("accounting: %s is declared skipped for %s but did not skip\n", decl[i], profile);
                bad = 1;
            }
        }
    } else if (belay_tests_skipped > 0) {
        printf("accounting: %d skip(s) not judged (no BELAY_SKIP_PROFILE)\n", belay_tests_skipped);
    }
    return bad;
#else
    return 0;
#endif
}

/* Prints the summary; returns the process exit status. */
static inline int belay_test_report(void) {
    printf("\n%d run, %d failed, %d skipped\n", belay_tests_run, belay_tests_failed,
           belay_tests_skipped);
    const int acct = belay_h_accounting();
    return belay_tests_failed || acct ? 1 : 0;
}
