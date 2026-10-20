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
 *  Exit status is 0 when every assertion passed, 1 otherwise, so `make test`
 *  and CI gate on it directly.
 */
#pragma once

#include <stdio.h>
#include <string.h>

static int belay_tests_run;
static int belay_tests_failed;
static int belay_current_failed;

#define TEST(name) static void belay_test_##name(void)

/*
 *  Runs one test and reports pass/fail. A test fails if any assertion in it
 *  failed; assertions do not abort, so one run reports every broken assertion
 *  rather than only the first.
 */
#define RUN(name)                                                      \
    do {                                                               \
        belay_current_failed = 0;                                      \
        belay_tests_run++;                                             \
        belay_test_##name();                                           \
        if (belay_current_failed) {                                    \
            belay_tests_failed++;                                      \
            printf("FAIL  %s\n", #name);                               \
        } else {                                                       \
            printf("ok    %s\n", #name);                               \
        }                                                              \
    } while (0)

#define BELAY_FAIL(fmt, ...)                                           \
    do {                                                               \
        printf("      %s:%d: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__); \
        belay_current_failed = 1;                                       \
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

/* Prints the summary; returns the process exit status. */
static inline int belay_test_report(void) {
    printf("\n%d run, %d failed\n", belay_tests_run, belay_tests_failed);
    return belay_tests_failed ? 1 : 0;
}
