/*
 *  The harness's own failure path (audit 2026-10, A4). Every test here must be
 *  reported FAIL or SKIP, and the binary must exit 1; scripts/selftest.sh runs
 *  it before any real test and stops `make test` if a broken assertion macro,
 *  REQUIRE or SKIP lets one of these through as `ok`.
 */
#include "belay_test.h"

TEST(assert_true_fails)    { ASSERT_TRUE(0); }
TEST(assert_false_fails)   { ASSERT_FALSE(1); }
TEST(assert_eq_int_fails)  { ASSERT_EQ_INT(1, 2); }
TEST(assert_eq_str_fails)  { ASSERT_EQ_STR("a", "b"); }
TEST(require_fails)        { REQUIRE(0); ASSERT_TRUE(1); }
TEST(require_msg_fails)    { REQUIRE_MSG(0, "%s", "stops here"); }
TEST(skip_is_reported)     { SKIP("self-test"); }

int main(void) {
    RUN(assert_true_fails);
    RUN(assert_false_fails);
    RUN(assert_eq_int_fails);
    RUN(assert_eq_str_fails);
    RUN(require_fails);
    RUN(require_msg_fails);
    RUN(skip_is_reported);
    return belay_test_report();
}
