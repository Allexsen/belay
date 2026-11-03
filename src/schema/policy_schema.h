/*
 *  policy.v1's flags, defined once (pin: test/expect/policy-v1.md, "The
 *  flags"): each kind's level, its fields and their types, the template its
 *  text is rendered from. The order is the pin's: records of one level are
 *  written in it (P-F5), and the trailer counts each kind in it (P-T3).
 */
#ifndef BELAY_SCHEMA_POLICY_SCHEMA_H
#define BELAY_SCHEMA_POLICY_SCHEMA_H

#include <stdbool.h>

enum policy_kind {
    PK_PROTECTED_PATH_WRITTEN, PK_PROTECTED_PATH_DELETED, PK_PROTECTED_PATH_CREATED,
    PK_PROTECTED_HASH_MISMATCH, PK_PROTECTED_PATH_UNVERIFIABLE,
    PK_PACKAGE_CHANGED, PK_TAMPERED_INSTALLED_PACKAGE, PK_CONFFILE_CHANGED,
    PK_TOUCHES_TESTS, PK_TESTS_WEAKENED, PK_EDITS_CI_CONFIG, PK_PYTEST_CONFIG_CHANGED, PK_CONFTEST_CHANGED,
    PK_PYTHON_STARTUP_HOOK_CHANGED, PK_GIT_HOOK_CHANGED, PK_GIT_HISTORY_REWRITTEN,
    PK_NEW_EXECUTABLE_ON_PATH, PK_PRIVILEGE_CHANGED, PK_WRITES_OUTSIDE_WORKDIR,
    PK_COUNT
};

/* PL_FROZEN: a violation when the spec says frozen_packages, else a signal. */
enum policy_level { PL_VIOLATION, PL_SIGNAL, PL_FROZEN };

/* P-F2: finding-kinds.md's types, and `strings`. */
enum pfield_type { PF_INT, PF_STRING, PF_BOOL, PF_BYTES, PF_STRINGS };

#define POLICY_FIELDS_MAX 8
#define POLICY_STRINGS_MAX 64          /* elements of a `strings` field */
#define POLICY_STRING_MAX 1024u        /* bytes of a string, of a `strings` element, of the text */

struct policy_field { const char *name; enum pfield_type type; bool optional; };

struct policy_kind_def {
    const char *name;
    enum policy_level level;
    struct policy_field field[POLICY_FIELDS_MAX];   /* in order; name NULL ends */
    const char *text;                               /* {field} is replaced */
    const char *text_partial;                       /* when an optional field it names is absent; NULL: none */
};

extern const struct policy_kind_def POLICY_KINDS[PK_COUNT];

#endif
