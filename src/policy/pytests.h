/*
 *  What policy.v1 reads in Python test files and pytest's configuration
 *  (test/expect/policy-v1.md, `tests_weakened`, `pytest_config_changed`):
 *  counts and marker lines, never a verdict (decision 149).
 */
#ifndef BELAY_POLICY_PYTESTS_H
#define BELAY_POLICY_PYTESTS_H

#include <stdbool.h>
#include <stddef.h>

/* One test file's counts. Markers are kept as lines, stripped. */
struct pycount {
    long assertions, tests;
    char **markers;
    size_t n_markers;
};

/* Counts `assert` statements, self.assert*(, pytest.raises(,
 * pytest.approx(, np.testing.assert_*( (assertions); def test_* and async
 * def test_* (tests); and the skip and xfail marker lines. 0, or -1 (NOMEM). */
int pycount(const char *buf, size_t len, struct pycount *out);
void pycount_free(struct pycount *c);

/* The marker lines of `after` not in `before` (as many times as they are
 * more), at most `max`, into `out` (pointers into after's markers). */
size_t pymarkers_added(const struct pycount *before, const struct pycount *after, const char **out, size_t max);

/* Whether a path's last component names a counted Python test file:
 * a test file (policy-v1, "Test file") named *.py, conftest.py excepted. */
bool py_test_file(const char *path, size_t n);

/* Whether `path` is a test file (policy-v1, "Test file"). */
bool test_file(const char *path, size_t n);

/* pytest's configuration: which file kind `path` is, and the text of the
 * named section ("" when absent). PYC_NONE: not one. */
enum pyc_kind { PYC_NONE, PYC_PYTEST_INI, PYC_TOX_INI, PYC_SETUP_CFG, PYC_PYPROJECT };
enum pyc_kind pyc_kind_of(const char *path, size_t n);

/* The first section of a `kind` file whose text differs between `a` and
 * `b` (either may be NULL: absent), its name into `section`: true when one
 * does. pytest.ini differs as a whole (section "pytest.ini"). */
bool pyc_differs(enum pyc_kind kind, const char *a, size_t al, const char *b, size_t bl, char *section, size_t cap);

#endif
