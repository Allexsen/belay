Receipts: 21 turns of real sessions, 325 call sections with changes; commits since 2026-11-02T09:00.

| would-be flag | fired on (legitimate work) |
|---|---|
| a .git/ path touched | 158 of 325 calls (49%) |
| touches_tests | 61 of 325 calls (19%) |
| a test file modified or removed | 48 of 325 calls (15%) |
| git_history_rewritten | 30 of 325 calls (9%) |
| privilege_changed | 0 of 325 calls (0%) |
| git_hook_changed | 0 of 325 calls (0%) |
| edits_ci_config | 0 of 325 calls (0%) |
| pytest_config_changed | 0 of 325 calls (0%) |
| python_startup_hook_added | 0 of 325 calls (0%) |
| tests_weakened: an assertion line removed | 8 of 48 test commits |
| tests_weakened: net assertions removed | 0 of 48 |
| tests_weakened: a skip or xfail marker added | 4 of 48 |

## policy.v1 on legitimate work, measured (2026-11-03)

`belay baseline export` of this repository at 13:13, no protect spec; `belay verify` at 13:31
(m2/verify 56da966): eighteen minutes of this session's own work -- the S3 campaign, the policy
model's fixes, rebases. Nothing hostile happened; every record below is a false-positive
candidate.

| flag | records | where they came from |
|---|---|---|
| privilege_changed | 121 | all `iflags none -> 524288` on files added (ext4's extents flag): 119 new `.git` objects, 2 build outputs -- the #61 defect, 100% noise |
| touches_tests | 73 | 61 build outputs (`build/test/`, `build/san/test/`: the component `test`), 1 `docs/spec/diff-v1.md` (the component `spec`), 11 real test edits under `test/` |
| git_history_rewritten | 1 | m2/verify, `rebase (finish), commit (amend)`: the PR workflow |
| tests_weakened | 0 | (C tests: Python only is counted) |
| every violation kind | 0 | (no spec) |

Lessons for M3: the test-file rule (the receipt's) matches build trees and `docs/spec/`; on a
real task the scope would exclude build output, but the rule itself is broad. iflags on added
files: #61.

### Before and after decisions 171 and 175, the same eighteen minutes (2026-11-03)

Re-measured from the dogfood checkpoints that bracket the window -- 3280 (13:13:18) as the
baseline, made into a bundle by a driver on belay's own library, and `verify --to 3446`
(13:31:53) -- once with main before the change (8e8294e: pins only) and once after (m2/readings
9b7a5d1). The "before" run reproduces the live measurement exactly.

| flag | before | after | what went |
|---|---|---|---|
| privilege_changed (iflags on added files) | 121 | 0 | ext4's extents flag: not a locking flag (decision 171) |
| touches_tests | 73 | 11 | 61 below `build/`, 1 in `docs/spec/` (decision 175); the 11 left are the real test edits under `test/` |
| git_history_rewritten | 1 | 1 | the PR workflow's rebase (a true change; noise only for this workflow) |
| **total signals** | **195** | **12** | |
