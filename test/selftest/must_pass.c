/*
 *  The harness's accounting path (audit 2026-10, M3, L2): one passing test and
 *  one that skips. scripts/selftest.sh runs it against accounting lists that
 *  are right (must exit 0) and wrong in each way the accounting must catch
 *  (a test missing from the list, a listed test that did not run, an
 *  undeclared skip, a declared skip that ran) -- each must exit 1.
 */
#include "belay_test.h"

TEST(passes)  { ASSERT_EQ_INT(2, 1 + 1); }
TEST(skips)   { SKIP("self-test"); }

int main(void) {
    RUN(passes);
    RUN(skips);
    return belay_test_report();
}
