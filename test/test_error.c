#include "belay_test.h"
#include "belay/error.h"

#include <errno.h>

TEST(clear_resets_everything) {
    belay_err_set(BELAY_ERR_IO, EACCES, "boom");
    belay_err_clear();
    ASSERT_EQ_INT(BELAY_OK, belay_err_code());
    ASSERT_EQ_INT(0, belay_err_errno());
    ASSERT_EQ_STR("", belay_err_msg());
}

TEST(set_records_code_errno_and_message) {
    belay_err_clear();
    belay_err_set(BELAY_ERR_INVALID, 0, "bad path: %s", "/x/../y");
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
    ASSERT_EQ_INT(0, belay_err_errno());
    ASSERT_EQ_STR("bad path: /x/../y", belay_err_msg());
}

TEST(null_format_yields_empty_message) {
    belay_err_set(BELAY_ERR_NOMEM, 0, NULL);
    ASSERT_EQ_STR("", belay_err_msg());
    ASSERT_EQ_INT(BELAY_ERR_NOMEM, belay_err_code());
}

/* A diagnostic longer than the buffer must truncate, stay NUL-terminated, and
 * not be treated as a failure of its own. */
TEST(overlong_message_truncates_safely) {
    char big[4096];
    for (size_t i = 0; i < sizeof big - 1; i++) big[i] = 'A';
    big[sizeof big - 1] = '\0';

    belay_err_set(BELAY_ERR_RANGE, 0, "%s", big);
    const char *m = belay_err_msg();
    ASSERT_TRUE(m != NULL);
    ASSERT_TRUE(strlen(m) < 512);
    ASSERT_EQ_INT('A', m[0]);
}

TEST(errno_is_preserved_verbatim) {
    belay_err_set(BELAY_ERR_IO, ENOENT, "open failed");
    ASSERT_EQ_INT(ENOENT, belay_err_errno());
}

int main(void) {
    RUN(clear_resets_everything);
    RUN(set_records_code_errno_and_message);
    RUN(null_format_yields_empty_message);
    RUN(overlong_message_truncates_safely);
    RUN(errno_is_preserved_verbatim);
    return belay_test_report();
}
