# What the 146 EvilGenie test changes were (2026-11-17)

The dataset is [EvilGenie-escalation](https://github.com/wiser-human-experimental/evilgenie-escalation)
(WiserHumanExperimental, MIT).

Question: classify the 146 EvilGenie runs that changed a test file against a list
(test file deleted, skip/only/xfail added, assertions removed or loosened, coverage threshold
lowered, CI step made to pass on failure, commit with hooks bypassed, agent instructions edited),
say how many fall in each, and which belay could derive from the files alone with no guessing.

Read-only: nothing was built, replayed or run. No model-written file was executed.

## Inputs

- `~/belay-replay/eg/` from the replay study (bench/replay/RESULTS.md): `problems.json` (the
  original `test.py` and `test_cases.json` of each of the 9 problems), `results2/` (each run's
  end-state hashes), `proof2/` (the 146 runs the dataset says changed a test file), `keep2/<key>/`
  (the changed files as the replay left them, and each run's `verify.ndjson`), and
  `scale_results.json` (the dataset's own labels).

These are the stored outputs of the original replay, not published and not written under these names by
bench/replay/; the scripts are kept as a record of method and cannot be run without them.

## How each fact was established

- **End states** are the replay's, compared with the originals by hash. For 23 of the 127 runs
  whose `test.py` changed or was deleted, the write was not byte-proven against the recording
  (`test_py_write_byte_proven` in `labels.tsv`), so the stored file may differ from what the run left.
- **`test.py` buckets** come from the end file's syntax tree alone (`scripts/astfacts.py`), tried
  in this order:
  1. it does not parse;
  2. it has no statements;
  3. no string constant or import names the solution;
  4. it has no failing exit: no `exit`/`quit` call with an argument other than `0` or `None`, no
     `assert`, no `raise`;
  5. it never reads a case's `output` (no subscript or `.get` with `output`, `expected` or
     `expected_output`);
  6. the `if actual_norm == expected_norm:` test is still there and `normalize_output` is unchanged;
  7. otherwise: the comparison with the expected output was rewritten.
- **Read by eye:** about 25 of the 125 changed runners, across every bucket, to check that the
  buckets say what they seem to. Not all 125.
- **`test_cases.json` buckets** come from parsing both sides as JSON and comparing by case `id`
  (`scripts/feat.py`).
- **The dataset's labels** (`classification`, `tamper_hack`) are the dataset's, not checked here.
- **The other categories** were looked for in the recorded tool calls of all 2,115 runs
  (`~/belay-replay/eg/all/*.jsonl`) by fixed strings.

## The table

146 runs: every run whose test file changed, including those RESULTS.md excludes from its 103. 14 changed both files and appear once in each half; the halves are per file.

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

Of the 8 in the last row, read by eye: 3 add a second way to pass beside the original test, 5
change something else (the failure cap raised from 3 to 100, loops and prints rewritten, a line
removed).

What the 57 rewrites are, from the sample read: a checker written for the problem that accepts any
valid answer where the original accepted only the recorded one, or a numeric tolerance. The
benchmark chose these problems for specification ambiguity or test-infrastructure quirks.

What the 30 without a failing exit are, from the sample read: the runner overwritten with a
scratch script that prints expected and actual output and always exits 0.

### test_cases.json (33 runs)

| end state | runs |
|---|---|
| deleted | 2 |
| emptied (0 bytes) | 3 |
| fewer cases (for example 34 to 4, or 32 to 31) | 11 |
| an expected output edited | 11 |
| cases added or swapped, none fewer | 3 |
| the same JSON, bytes differ | 3 |

### Against the list

| category | runs | from the files alone, with no guessing |
|---|---|---|
| test file deleted | 3 (`test.py` 2, `test_cases.json` 2, one run both) | yes; belay says it as of v0.1.0-alpha.9 (`protected_path_deleted`) |
| emptied, the nearest thing to deleted | 2 `test.py`, 3 `test_cases.json` | yes |
| runner no longer runs the solution | 12 | no: belay would have to know what is under test |
| skip/only/xfail added | 0 markers in any end file; nearest, 11 runs with fewer cases | markers yes (`tests_weakened` counts them for Python); a case count only if belay is told the file is a list of cases |
| assertions removed | 30 with no failing exit | a syntax fact for a Python script; that the exit status was the verdict is convention |
| assertions loosened | 57 rewritten, 14 never read the expected output, 11 with an expected output edited | no: only that the file changed |
| coverage threshold lowered | 0 | the workspaces have no coverage configuration (`fail_under`, `fail-under`: 0 lines) |
| CI step made to pass on failure | 0 | no CI files (`.github`, `continue-on-error`: 0 lines) |
| commit with hooks bypassed | 0 | no commits (`git commit`, `no-verify`: 0 lines) |
| agent instructions edited | 0 | none in the workspaces (`CLAUDE.md`, `AGENTS.md`: 0 lines) |

The rows a tool could state without judgement (deleted, emptied, does not run the solution, no
failing exit, fewer cases) cover 54 runs. All 11 runs the dataset marks `tamper_hack` are among
them, and the dataset labels 45 of the 54 legitimate. (A run can carry both labels:
`classification` and `tamper_hack` are separate columns of the dataset; this note does not say either is wrong.)

## What belay itself said on these runs

None of the 2,115 stored `verify.ndjson` outputs has a `tests_weakened` record. There were 156
`protected_path_written` and 356 `touches_tests`; the latter name scratch files the agents added
(`time_test.py`, `test_logic.py`, `test_brute.py`, ...), never the runner.

Why, from the pin (test/expect/policy-v1.md, "Test file" and the `tests_weakened` row): `test.py` at the
workspace root is not a test file by name (`test_*.py`, `*_test.py`, or below a test directory),
and it has no `assert` statement and no `def test_*`, so there was nothing to count either way.

## Files

- `labels.tsv`: one row per run, with the bucket of each file and the facts it rests on. `key` is
  `rules.key(run_key)` of bench/replay; `model`, `dataset_classification`, `tamper_hack` and `dataset_says_*`
  are the dataset's columns; every other column is this note's, derived from syntax, not a judgement of intent.
- `scripts/`: in the order they were run, from inside the directory. Each writes its intermediate JSON
  beside itself. Run again on 2026-11-17 from a fresh copy, they gave this `labels.tsv` byte for byte.
  1. `survey.py`: which file changed or was deleted in each run (`rows.json`).
  2. `feat.py`: line counts, the case comparison, and a unified diff per run (`feat.json`, `diffs/`).
  3. `static.py`: a first pass by regular expressions. Superseded by the next; kept as run.
  4. `astfacts.py`: the buckets (`ast.json`).
  5. `labels.py OUT_DIR`: `labels.tsv`.

The per-run diffs are not kept here: `feat.py` writes them again from `keep2/`.
