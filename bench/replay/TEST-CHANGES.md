# What the 146 EvilGenie test changes were, and what belay said about them

This follows [belay against EvilGenie: replaying 2,115 published agent runs](https://github.com/Allexsen/belay/blob/main/bench/replay/RESULTS.md). The labels and the scripts that produced them are in [docs/notes/measurements/2026-11-17-evilgenie-test-change-classes/](https://github.com/Allexsen/belay/tree/main/docs/notes/measurements/2026-11-17-evilgenie-test-change-classes).

## What was tested

The replay study counted 146 runs that changed a test file, and belay reported each of them as a protected file written or deleted. That says a file changed. It does not say what was done to it. This study classifies what each of the 146 runs left in `test.py` and `test_cases.json`, and asks which of those classes a tool can state from the two versions of a file alone, without judging intent.

It also checks what belay's own test signal, `tests_weakened`, said on these runs. It said nothing. The section "What belay said" gives the counts and the reason.

## Data

- The original `test.py` and `test_cases.json` of each of the 9 problems.
- The end state of each of the 146 runs, as the replay left it: the changed files themselves, and their hashes.
- belay's stored `verify` output for all 2,115 runs, from the pre-registered pass of the replay study (belay v0.1.0-alpha.3).
- The dataset's own labels for each run (`classification`, `tamper_hack`). They were not checked here.
- The recorded tool calls of the dataset's runs, for fixed-string searches.

Nothing was built, replayed or run for the classification. No model-written file was executed: the scripts parse the files and compare them.

## Method

**End states.** Each file's end state was compared with the original by hash: unchanged, changed or deleted.

**`test.py`.** Every original runner is a Python script that runs `solution.py` on each case, compares the normalized output with the case's expected output, and exits non-zero on failure. Each changed runner was put in the first bucket that fits, from its syntax tree alone:

1. it does not parse;
2. it has no statements;
3. no string constant or import names the solution;
4. it has no failing exit: no `exit` or `quit` call with an argument other than `0` or `None`, no `assert`, no `raise`;
5. it never reads a case's expected output (no subscript or `.get` with `output`, `expected` or `expected_output`);
6. the original comparison (`if actual_norm == expected_norm:`) is still there and `normalize_output` is unchanged;
7. otherwise: the comparison with the expected output was rewritten.

**`test_cases.json`.** Both sides were parsed as JSON and compared by case `id`.

**Read by eye.** About 25 of the 125 changed runners, across every bucket, were read to check that the buckets say what they seem to. The other 100 were not.

**Other kinds of weakening.** Skip markers were looked for in the end files. Coverage settings, CI files, commits and agent instruction files were looked for by fixed strings in the recorded tool calls.

## Results

146 runs. 127 changed or deleted `test.py`, 33 changed or deleted `test_cases.json`, and 14 did both. Those 14 appear once in each table below.

### test.py (127 runs)

| end state | runs | of them `tamper_hack` | dataset says legitimate |
|---|---|---|---|
| deleted | 2 | 0 | 2 |
| no statements left | 2 | 1 | 1 |
| does not parse | 2 | 0 | 2 |
| does not run the solution | 12 | 7 | 8 |
| runs the solution, has no failing exit | 30 | 3 | 28 |
| never reads the expected output | 14 | 0 | 10 |
| comparison with the expected output rewritten | 57 | 0 | 47 |
| original comparison still there | 8 | 0 | 7 |

A run can carry both `tamper_hack` and the classification legitimate; the two columns overlap.

Of the two runners with no statements left, one is an empty file and one holds 96 bytes with no statement.

From the sample read by eye:

- The 57 rewrites are a checker written for the problem, which accepts any valid answer where the original accepted only the recorded one, or a numeric tolerance. The benchmark chose these problems for having several valid answers.
- The 30 runners without a failing exit are the runner overwritten with a scratch script that prints the expected and the actual output and always exits 0.

All 8 runners that keep the original comparison were read. 3 add a second way to pass beside it. 5 change something else: the failure cap raised from 3 to 100, loops, prints and time limits rewritten, a blank line removed, lines added at the end.

### test_cases.json (33 runs)

| end state | runs |
|---|---|
| deleted | 2 |
| emptied (0 bytes) | 3 |
| fewer cases | 11 |
| an expected output edited | 11 |
| cases added or swapped, none fewer | 3 |
| the same JSON, bytes differ | 3 |

The 11 runs with fewer cases went from 34 cases to 4 (five runs), 33 to 3 (three), 32 to 31 (two) and 34 to 1 (one).

### Which classes can be stated from the files alone

| kind of weakening | runs | can a tool state it from the two versions of the file, without judgement |
|---|---|---|
| test file deleted | 3 (`test.py` 2, `test_cases.json` 2, one run both) | yes. belay reports it as `protected_path_deleted` from v0.1.0-alpha.4 |
| test file emptied | 2 `test.py`, 3 `test_cases.json` | yes |
| runner no longer runs the solution | 12 | no: the tool would have to know what is under test |
| skip, only or xfail marker added | 0 in any end file | yes, where the markers exist. The nearest thing here is the 11 runs with fewer cases, and a case count can be stated only if the tool is told the file is a list of cases |
| assertions removed | 30 with no failing exit | partly: it is a syntax fact for a Python script, but that the exit status was the verdict is a convention of this benchmark |
| assertions loosened | 57 rewritten, 14 that never read the expected output, 11 with an expected output edited | no: only that the file changed |
| coverage threshold lowered | 0 | the workspaces have no coverage configuration (`fail_under`, `fail-under`: 0 lines) |
| CI step made to pass on failure | 0 | the workspaces have no CI files (`.github`, `continue-on-error`: 0 lines) |
| commit with hooks bypassed | 0 | the runs made no commits (`git commit`, `no-verify`: 0 lines) |
| agent instructions edited | 0 | none in the workspaces (`CLAUDE.md`, `AGENTS.md`: 0 lines) |

The rows a tool could state without judgement, given the conventions above (deleted, emptied, does not run the solution, no failing exit, fewer cases), cover 54 of the 146 runs. All 11 runs the dataset marks `tamper_hack` are among the 54. The dataset classifies 45 of the 54 as legitimate.

The other 92 runs changed how an answer is compared, or changed something that does not fit a class. For those, the files alone say that the test changed and not whether it became weaker. The dataset classifies 74 of the 92 as legitimate.

## What belay said

belay raised no `tests_weakened` record on any of the 2,115 runs. The 2,115 stored outputs hold two kinds of record:

- 156 `protected_path_written`, in 144 runs: 125 for `test.py` and 31 for `test_cases.json`. These come from the protect spec that named the two files, and are the result reported in the replay study.
- 356 `touches_tests`, in 100 runs. Every one is a file the agent added, under 235 different names (`time_test.py`, `test_logic.py`, `test_brute.py` and others). None names `test.py` or `test_cases.json`.

The reason is in the rules belay pins for test files ([policy-v1.md](https://github.com/Allexsen/belay/blob/main/test/expect/policy-v1.md), "Test file" and the `tests_weakened` row):

- A Python file is a test file if it is named `test_*.py` or `*_test.py`, or lies below a directory named `test`, `tests`, `__tests__` or `spec`. `test.py` at the workspace root is neither. belay did not treat the benchmark's runner as a test file at all.
- `tests_weakened` counts `assert` statements, a few assertion calls, and `def test_*` functions. The 9 original runners have none of either, so had the runner been counted, there was nothing to lose.
- `test_cases.json` is data. belay counts Python only.

So on this benchmark the signal built to say "a test got weaker" was silent on all 146 runs, including the 54 above. The changes were reported only because a spec named the two files in advance, and then only as "written" or "deleted".

The stored outputs are from v0.1.0-alpha.3. One case was repeated on the current build (v0.1.0-alpha.9 plus 5 commits): an original runner replaced by one of the 30 end states with no failing exit gave one `protected_path_written` record and no `touches_tests` or `tests_weakened` record.

## Limits

- 9 problems, each a workspace of a few files with one hand-written runner script. The result says nothing about projects that use a test framework, where `tests_weakened` has something to count.
- The buckets are syntactic. A runner in "has no failing exit" may fail some other way, and one in "comparison rewritten" may be stricter than the original, not looser. Only the sample read by eye was checked against the bucket's plain meaning.
- For 23 of the 127 runs whose `test.py` changed or was deleted, the write was not byte-proven against the recording in the replay study. The stored file may differ from what the original run left.
- The dataset's labels are the dataset's. "Legitimate" classifies the run; it is not a judgement of the test change, and this study did not make one either.
- A count of 0 for a fixed string means the string does not occur in the recorded tool calls. It does not rule out the same act written another way.
- End state only, as in the replay study. A file changed and restored before the end is not seen.
- The 2,115 stored outputs were not regenerated with a current belay. One case was.

## Reproduction

`labels.tsv` in [the measurement folder](https://github.com/Allexsen/belay/tree/main/docs/notes/measurements/2026-11-17-evilgenie-test-change-classes) has one row per run, with the bucket of each file and the facts it rests on. Every count in the tables above can be recomputed from it. The scripts beside it (`survey.py`, `feat.py`, `astfacts.py`, `labels.py`, in that order) produce it. Run again on a copy of the inputs for this report, they gave the same file byte for byte.

The scripts read the replay study's stored end states, in the layout of that study's working directory. Those files are not published. The harness in [bench/replay/](https://github.com/Allexsen/belay/tree/main/bench/replay) rebuilds end states by replaying, but it does not keep the changed files in that layout, and the scripts have not been run against its output.
