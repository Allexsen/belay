/*
 *  Smoke test for the harness itself.
 *
 *  Exists so `make test` and CI have something to go green on before any
 *  feature code lands (M0 infrastructure). Tests for real units replace its
 *  role as they arrive; this stays, because a harness that silently stops
 *  reporting failures is worse than no harness.
 */
#include "belay_test.h"

TEST(assertions_pass_on_equal_values) {
    ASSERT_TRUE(1);
    ASSERT_FALSE(0);
    ASSERT_EQ_INT(42, 42);
    ASSERT_EQ_STR("belay", "belay");
}

TEST(int_assertion_widens_types) {
    char c = 7;
    short s = 7;
    long l = 7;
    ASSERT_EQ_INT(7, c);
    ASSERT_EQ_INT(7, s);
    ASSERT_EQ_INT(7, l);
}

TEST(str_assertion_handles_null) {
    const char *null_str = NULL;
    ASSERT_EQ_STR(NULL, null_str);
}

int main(void) {
    RUN(assertions_pass_on_equal_values);
    RUN(int_assertion_widens_types);
    RUN(str_assertion_handles_null);
    return belay_test_report();
}
