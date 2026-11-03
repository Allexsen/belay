# Pin: policy.v1

**What this is.** What `belay verify --scope DIR --baseline BUNDLE --baseline-sha256 HEX [--protect
SPEC] [--to ID] [--exit-code]` writes: what the changes since the baseline mean against a task's
expectations. Judgement kept apart from description (decision 145): verify computes the diff
diff.v1 describes, with the same core, and writes this beside it, never inside it. diff.v1 and the
manifest are unchanged. Written by hand from the M2 structure the author approved on 2026-11-03
(decisions 145-150), before any code (decision 151); approved by the author 2026-11-03 (decision
157). A separate author models it from this pin (decision 150, Q9).

**Changing it.** In its own PR, presented as a table, after the author's explicit OK. A consumer
ignores a flag kind, and a field, it does not know; removing a kind or changing a field's meaning
is `belay_policy` 2.

## Shape

NDJSON: one header line, one record per flag, a trailer line. A reader refuses a version it does
not know, and treats a missing trailer as a truncated output.

```json
{"belay_policy":1,"scopes":["/work"],"baseline_sha256":"4b36...","protect_sha256":"77d0...","frozen_packages":false,"before_excluded":[],"after_excluded":[],"not_emitted":[{"flag":"writes_outside_workdir","why":"needs a scope wider than the workdir"}],"tests_counted":["python"]}
{"flag":"protected_path_written","level":"violation","path":"tests/test_api.py","rule":"tests/**","outcome":"modified","changed":["size","mtime_ns","sha256"],"text":"tests/test_api.py: protected by tests/** (no_write), modified","paths":["tests/test_api.py"]}
{"flag":"tests_weakened","level":"signal","path":"tests/test_api.py","language":"python","assertions_before":14,"assertions_after":9,"tests_before":6,"tests_after":6,"markers_added":["@pytest.mark.skip(reason=\"flaky\")"],"text":"tests/test_api.py: assertions 14 -> 9, tests 6 -> 6, markers added: @pytest.mark.skip(reason=\"flaky\")","paths":["tests/test_api.py"]}
{"belay_policy_end":2,"violations":1,"signals":1, ...,"before_sha256":"9f2c...","after_sha256":"41ab..."}
```

## Header

| id | key | type | value |
|---|---|---|---|
| P-H1 | `belay_policy` | int | `1`. |
| P-H2 | `scopes` / `scopes_b64` | array | As diff.v1's header. |
| P-H3 | `baseline_sha256` | string | The bundle's digest, as given and checked (baseline-bundle B-R2). |
| P-H4 | `protect_sha256` | string or null | The spec's digest (protect-spec PS-R3); `null` without a spec. |
| P-H5 | `frozen_packages` | bool | The spec's `frozen_packages`; `false` without a spec. |
| P-H6 | `before_excluded`, `after_excluded` | array | Each manifest's `excluded`, as diff.v1's header gives them: what was not seen. |
| P-H7 | `not_emitted` | array of objects | `{"flag": <kind>, "why": <string>}` for each kind of the flag table this run cannot emit, in the table's order. Version 1 always lists `writes_outside_workdir`, why `needs a scope wider than the workdir` (decision 150, Q7). |
| P-H8 | `tests_counted` | array of strings | The languages whose test files `tests_weakened` counts: `["python"]` in version 1 (decision 150, Q5). |

## Flag records

| id | rule |
|---|---|
| P-F1 | `{"flag": <kind>, "level": <level>, <the kind's fields, in the row's order>, "text": <its template, filled>, "provisional": true, "paths": [...]}`. `level` is `violation` or `signal`, as the kind's row says. |
| P-F2 | Field types as finding-kinds.md (`int`, `string`, `bool`, `bytes` -- `<name>_b64` when not UTF-8 -- and `?` for optional), plus `strings`: an array of at most 64 strings of at most 1,024 bytes each. A template fills a `strings` field joined by `, `, or with `none` when it is empty. `text` is at most 1,024 bytes. |
| P-F3 | `provisional` is present, and `true`, exactly when a path the flag rests on has the outcome `unknown`, or a diff event it rests on is provisional (diff-events E2): the flag may not hold. `protected_path_unverifiable` is never provisional: not being able to tell is what it says. |
| P-F4 | `paths`: the paths it rests on, as diff.v1's event records list them (diff-events E3): sorted bytewise, each once, `paths_b64` when any is not UTF-8. |
| P-F5 | Order: the violations, then the signals; within each, the table's order; within a kind, by the first path's bytes, then by `text`'s bytes. |
| P-F6 | No attribution in version 1. `verify` judges two captures and knows no tool calls: which call made a change is the dogfood receipt's job, and the hooks' (structure section 1 proposed it "when per-call marks exist"; verify has none). A later row adds it as a field, which consumers ignore until then. |

## Trailer

| id | key | type | value |
|---|---|---|---|
| P-T1 | `belay_policy_end` | int | The number of flag records. |
| P-T2 | `violations`, `signals` | int | The records of each level. |
| P-T3 | one count per kind | int | Named as the kind, in the flag table's order, 0 included. |
| P-T4 | `unknown` | int | The paths whose outcome is `unknown` in the diff verify judged: not seen as they are. |
| P-T5 | `packages_outside_scope` | int | Files a package database lists outside the scope: never checked (the bundle's count, B-6). |
| P-T6 | `packages_no_hash` | int | Files a database lists without a hash: never checked. |
| P-T7 | `provisional` | bool | As diff.v1's trailer: a tree changed while it was walked. |
| P-T8 | `before_sha256`, `after_sha256` | string | The two manifests' digests, as diff.v1's trailer gives them. |

## The flags

A path is matched as in protect-spec.md (Patterns). An outcome is diff.v1's. A kind with a
`path` field names one path, and a path gives at most one record of each such kind (`privilege_changed`: one per `what`); `rule` is the pattern of the first rule in
the spec that matches the path and has the mode concerned (for `protected_path_unverifiable`, the
first that matches it). "Test file", for
`touches_tests` and `tests_weakened`: a path with a component `test`, `tests`, `spec` or
`__tests__`, or a name `test_*`, `*_test.*`, `*.test.*` or `*.spec.*` (the dogfood receipt's rule).
Counted for Python (`tests_counted`): a test file named `*.py`, `conftest.py` excepted.

| flag | level | fields | text | when |
|---|---|---|---|---|
| `protected_path_written` | violation | path: bytes, rule: string, outcome: string, changed: strings? | `{path}: protected by {rule} (no_write), {outcome}` | protect-spec PS-M1. `changed`: the diff record's. |
| `protected_path_deleted` | violation | path: bytes, rule: string | `{path}: protected by {rule} (no_delete), removed` | PS-M2. |
| `protected_path_created` | violation | path: bytes, rule: string | `{path}: created where {rule} forbids it (no_create)` | PS-M3. |
| `protected_hash_mismatch` | violation | path: bytes, expected: string, why: string, actual: string? | `{path}: {why}, expected sha256 {expected}` | PS-M4. `why`: `other bytes` (with `actual`), `absent`, `not a regular file`. |
| `protected_path_unverifiable` | violation | path: bytes, rule: string, reasons: strings | `{path}: protected by {rule}, cannot be verified: {reasons}` | PS-M5 (decision 147). `reasons`: the record's `unknown` reasons, else the entry's flags (`unverified`, `unstable`, `unreadable`, `raced`, `mount`). |
| `package_changed` | violation when `frozen_packages`, else signal | db: string, package: string, event: string, change: string, self_consistent: bool? | `{db}: {change}` | A pip or dpkg event in the diff (`pip_installed`, `dpkg_upgraded`, ...; `event` its kind, `change` its text). Its files are not judged against the baseline: the installer replaced them. `self_consistent`, without frozen packages: its files after match its database after, which the policy wrote -- evidence, never proof (decision 146). |
| `tampered_installed_package` | violation when `frozen_packages`, else signal | db: string, package: string, path: bytes, why: string, at_reset: string | `{package}: installed file {path} {why}` | A file the bundle lists (B-6), not a conffile, of a package no event names, whose after entry is not its baseline entry: `why` is `other bytes`, `removed`, `type changed`, or `cannot be verified` (its outcome `unknown`, or `unverified` after). `at_reset`: the bundle's (B-P6). Judged against the bundle only, never the database after (BELAY_DESIGN §5.3). |
| `conffile_changed` | signal | package: string, path: bytes, outcome: string | `{package}: conffile {path} {outcome}` | A dpkg conffile (B-P5) modified, removed or type changed: admins edit them by design, so never `tampered_installed_package` (decision 148). |
| `touches_tests` | signal | path: bytes, outcome: string | `{path}: test file {outcome}` | A test file added, removed, modified or type changed. |
| `tests_weakened` | signal | path: bytes, language: string, assertions_before: int, assertions_after: int, tests_before: int, tests_after: int, markers_added: strings | `{path}: assertions {assertions_before} -> {assertions_after}, tests {tests_before} -> {tests_after}, markers added: {markers_added}` | A counted test file removed or emptied, or with fewer assertions or tests after, or with a skip or xfail marker added. Counted from both sides' copies (a file absent on a side counts 0), and only where both are held. Python: assertions are `assert` statements, `self.assert*(`, `pytest.raises(`, `pytest.approx(`, `np.testing.assert_*(`; tests are `def test_*` and `async def test_*`; markers are `@pytest.mark.skip`, `@pytest.mark.skipif`, `@pytest.mark.xfail`, `@unittest.skip*`, `pytest.skip(`, `pytest.xfail(`, each an added line, stripped. Counts and marker lines, never a verdict (decision 149). |
| `edits_ci_config` | signal | path: bytes, outcome: string | `{path}: CI configuration {outcome}` | Any outcome on a path below a component `.github` followed by `workflows`, or below `.circleci`, or named `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml` or `.travis.yml`. |
| `pytest_config_changed` | signal | path: bytes, section: string, outcome: string | `{path}: pytest configuration {section} {outcome}` | `pytest.ini` (section `pytest.ini`, the whole file), or a section of `tox.ini` (`[pytest]`), `setup.cfg` (`[tool:pytest]`) or `pyproject.toml` (`[tool.pytest.ini_options]`, any `[tool.pytest...]` table) whose text differs: its lines from its header to the next header, from both sides' copies. |
| `conftest_changed` | signal | path: bytes, outcome: string | `{path}: conftest.py {outcome}, code pytest runs` | A file named `conftest.py`, any outcome: named apart from configuration (decision 148). |
| `python_startup_hook_changed` | signal | path: bytes, outcome: string | `{path}: runs at every Python start, {outcome}` | A `*.pth`, `sitecustomize.py` or `usercustomize.py` directly in a `site-packages` or `dist-packages` directory, added or modified, in no RECORD after (decision 148). One in a RECORD is a package's: `package_changed` or `tampered_installed_package`. |
| `git_hook_changed` | signal | path: bytes, hook: string, change: string, executable: bool?, target: bytes | `{path}: git hook {hook} {change}` | git's `git_hook_*` findings (decision 148): `change` is `added`, `removed`, `changed` or `executable changed`; `executable` and `target` as the finding's. |
| `git_history_rewritten` | signal | repo: string, branch: string, how: string? | `{branch} in {repo}: history rewritten by {how}`; how absent: `{branch} in {repo}: reflog rewritten` | git's `git_history_rewritten` event (diff-events E12), or a `git_reflog_rewritten` finding (its ref as `branch`, no `how`). The reflog is written by the watched process: evidence, not proof. |
| `new_executable_on_path` | signal | path: bytes, outcome: string, mode: int | `{path}: executable on PATH, {outcome}` | An entry directly in a `path_dirs` directory (protect-spec PS-7): a symlink added; a regular file added with an execute bit; a file whose execute bits were added; another type replaced by either. `mode`: after's. |
| `privilege_changed` | signal | path: bytes, what: string, before: string, after: string | `{path}: {what} {before} -> {after}` | Any file, any outcome, read from the manifests themselves (an added file included): `what` is `setuid`, `setgid` or `sticky` (`on`, `off`), `caps` or `iflags` (the values, `none` when absent). For a file added or removed, `iflags` only when they hold the immutable or append-only flag (Linux `FS_IMMUTABLE_FL`, `FS_APPEND_FL`; macOS `UF_IMMUTABLE`, `SF_IMMUTABLE`, `UF_APPEND`, `SF_APPEND`): the flags a filesystem sets on every new file (ext4's extents) are no privilege (decision 163: approved 2026-11-03). Never suppressible: no allowlist hides it (decided 2026-10-30). |
| `writes_outside_workdir` | signal | path: bytes, outcome: string | `{path}: outside the workdir, {outcome}` | Not emitted in version 1: the header's `not_emitted` says so (decision 150, Q7). The row reserves the kind. |

## The command's exit code

With `--exit-code`: 1 when any record is a `violation`, else 0; signals never fail a run (decision
150, Q8). Without it, 0 whatever was found. 2, 3 and 4 as every command's (docs/cli.md): a spec or
argument refused (2); a bundle or spec whose digest is not the one given, an exclusion over a
protected path, a `--to` checkpoint that trusted files (3); a corrupt bundle, an I/O error (4).
