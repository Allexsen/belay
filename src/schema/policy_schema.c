#include "schema/policy_schema.h"

#define I(n)  { n, PF_INT, false }
#define S(n)  { n, PF_STRING, false }
#define SO(n) { n, PF_STRING, true }
#define BO(n) { n, PF_BOOL, true }
#define BY(n) { n, PF_BYTES, false }

#define SS(n) { n, PF_STRINGS, false }
#define SSO(n) { n, PF_STRINGS, true }

const struct policy_kind_def POLICY_KINDS[PK_COUNT] = {
    [PK_PROTECTED_PATH_WRITTEN] = { "protected_path_written", PL_VIOLATION,
        { BY("path"), S("rule"), S("outcome"), SSO("changed") }, "{path}: protected by {rule} (no_write), {outcome}", 0 },
    [PK_PROTECTED_PATH_DELETED] = { "protected_path_deleted", PL_VIOLATION,
        { BY("path"), S("rule") }, "{path}: protected by {rule}, removed", 0 },
    [PK_PROTECTED_PATH_CREATED] = { "protected_path_created", PL_VIOLATION,
        { BY("path"), S("rule") }, "{path}: created where {rule} forbids it (no_create)", 0 },
    [PK_PROTECTED_HASH_MISMATCH] = { "protected_hash_mismatch", PL_VIOLATION,
        { BY("path"), S("expected"), S("why"), SO("actual") }, "{path}: {why}, expected sha256 {expected}", 0 },
    [PK_PROTECTED_PATH_UNVERIFIABLE] = { "protected_path_unverifiable", PL_VIOLATION,
        { BY("path"), S("rule"), SS("reasons") }, "{path}: protected by {rule}, cannot be verified: {reasons}", 0 },
    [PK_PACKAGE_CHANGED] = { "package_changed", PL_FROZEN,
        { S("db"), S("package"), S("event"), S("change"), BO("self_consistent") }, "{db}: {change}", 0 },
    [PK_TAMPERED_INSTALLED_PACKAGE] = { "tampered_installed_package", PL_FROZEN,
        { S("db"), S("package"), BY("path"), S("why"), S("at_reset") }, "{package}: installed file {path} {why}", 0 },
    [PK_CONFFILE_CHANGED] = { "conffile_changed", PL_SIGNAL,
        { S("package"), BY("path"), S("outcome") }, "{package}: conffile {path} {outcome}", 0 },
    [PK_TOUCHES_TESTS] = { "touches_tests", PL_SIGNAL,
        { BY("path"), S("outcome") }, "{path}: test file {outcome}", 0 },
    [PK_TESTS_WEAKENED] = { "tests_weakened", PL_SIGNAL,
        { BY("path"), S("language"), I("assertions_before"), I("assertions_after"), I("tests_before"),
          I("tests_after"), SS("markers_added") },
        "{path}: assertions {assertions_before} -> {assertions_after}, tests {tests_before} -> {tests_after}, "
        "markers added: {markers_added}", 0 },
    [PK_EDITS_CI_CONFIG] = { "edits_ci_config", PL_SIGNAL,
        { BY("path"), S("outcome") }, "{path}: CI configuration {outcome}", 0 },
    [PK_PYTEST_CONFIG_CHANGED] = { "pytest_config_changed", PL_SIGNAL,
        { BY("path"), S("section"), S("outcome") }, "{path}: pytest configuration {section} {outcome}", 0 },
    [PK_CONFTEST_CHANGED] = { "conftest_changed", PL_SIGNAL,
        { BY("path"), S("outcome") }, "{path}: conftest.py {outcome}, code pytest runs", 0 },
    [PK_PYTHON_STARTUP_HOOK_CHANGED] = { "python_startup_hook_changed", PL_SIGNAL,
        { BY("path"), S("outcome") }, "{path}: runs at every Python start, {outcome}", 0 },
    [PK_GIT_HOOK_CHANGED] = { "git_hook_changed", PL_SIGNAL,
        { BY("path"), S("hook"), S("change"), BO("executable"), BY("target") }, "{path}: git hook {hook} {change}", 0 },
    [PK_GIT_HISTORY_REWRITTEN] = { "git_history_rewritten", PL_SIGNAL,
        { S("repo"), S("branch"), SO("how") }, "{branch} in {repo}: history rewritten by {how}",
        "{branch} in {repo}: reflog rewritten" },
    [PK_NEW_EXECUTABLE_ON_PATH] = { "new_executable_on_path", PL_SIGNAL,
        { BY("path"), S("outcome"), I("mode") }, "{path}: executable on PATH, {outcome}", 0 },
    [PK_PRIVILEGE_CHANGED] = { "privilege_changed", PL_SIGNAL,
        { BY("path"), S("what"), S("before"), S("after") }, "{path}: {what} {before} -> {after}", 0 },
    [PK_WRITES_OUTSIDE_WORKDIR] = { "writes_outside_workdir", PL_SIGNAL,
        { BY("path"), S("outcome") }, "{path}: outside the workdir, {outcome}", 0 },
};
