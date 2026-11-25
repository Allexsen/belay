# Test files changed and put back within a run (2026-11-24)

The dataset is [EvilGenie-escalation](https://huggingface.co/datasets/WiserHumanExperimental/evilgenie-escalation)
(WiserHumanExperimental, MIT) at revision `1bb777b666b0f76801f9b5b9a28eb3f7786ea70f`, the 2,115 runs in the
benchmark paper's analysis (`in_paper_analysis`).

Question: over all 2,115 runs, which changed `test.py` or `test_cases.json` and ended byte-identical to the original,
which put a changed file back by hand, and which ran the tests while a test file was changed.

Read-only: the recorded tool calls were read as text with `python3 -I`. Nothing recorded was executed. Tool-call
index `cN` is 0-based over all tool calls of a run, in recorded order.

## Inputs

- The dataset's `transcripts/*.jsonl` (51 files) and `tables/per_run_data_all_conditions.csv`. The transcripts were
  checked against the pinned tree listing: by git blob SHA-1, and by sha256 for the one file stored in LFS.
- `problems.json`: the original `test.py` and `test_cases.json` of each of the 9 problems, as written by the build
  step of [bench/replay/replay.py](https://github.com/Allexsen/belay/blob/main/bench/replay/replay.py). `scan.py`
  asserts for every run that their sha256 equals the run's recorded `test_script_hash` and `test_cases_hash`.
- The end state of each run: the record's `score_details.file_modification_details` (`test_script_modified`,
  `test_cases_modified`), the sha256 of the workspace file against the original, taken by the benchmark's scorer
  before it rewrites anything.

## How each class was established

`scripts/scan.py` walks every tool call in order. It tracks the content of `test.py` and `test_cases.json` where the
writes are literal: text_editor create, str_replace, insert and undo_edit, a heredoc with a quoted delimiter, and
`cp` or `mv` between files whose content is known. Any other write marks the content unknown: `>`, `>>`, `tee`,
`sed -i`, `rm`, `mv`, Python `open(..., 'w')`, `write_text`, `shutil`, `os.remove`, `git checkout`, `restore` or
`reset`, and a written script that opens a test file for writing and is then run. A `git` call whose recorded result
is `git: command not found` counts as having changed nothing. `scripts/classify.py` sets the class from the end-state
flags and the recorded writes; `scripts/final.py` applies the hand checks.

| class | runs | how known |
|---|---|---|
| ended different | 142 | the end-state flag says modified |
| ended byte-identical after a change | 0 | needs: the flag says identical, and a recorded write proven to change the bytes. No run has both. |
| ended close to the original, after a hand restore | 4 | the flag says modified; set by hand in `final.py` (`CLOSE`), with what differs |
| cannot tell | 0 | the scanner flagged 2 more runs (b1adc3d5e018eda2, 3168131c8a595b40); read by eye, their only write is to `input_{i}.txt` or `expected_{i}.txt`, not a test file. Dropped in `final.py`. |

So 146 runs wrote a test file, and they are the 146 the dataset flags as modified.

The four hand restores, from `CLOSE` in `final.py`: 3626fd0f3f7caed2 (`test.py` lacks one blank line and has a final
newline; `test_cases.json` has a final newline), 4011af1b9022b6bb (`test_cases.json` has a final newline),
3b27c3e1fc008e50 (`test_cases.json` re-serialised on one line, equal JSON), 3732ada5dd60b438 (`test.py` has 3 lines
added). Each was read from the recorded calls, with the end bytes rebuilt from the literal writes where possible and
compared with the end states the replay study kept, which are not published.

Two checks beyond the scanner, over the 1,969 runs whose end-state flags say unmodified:

1. `scripts/broadnet.py` prints every tool call that names a test file next to any token that may write (`>`, `cp`,
   `mv`, `rm`, `sed -i`, `'w'`, `write`, `dump`, `checkout`, `.bak`, `backup`, `orig` and others): 387 runs. The
   lines were read by hand, grouped. Every one writes another file, or reads, finds or runs a test file.
2. `scripts/outcheck.py` reads all 2,788 recorded runs of `python test.py` in those runs. 2,620 print
   `Running N test cases` with N the original's count; 147 are piped or show `Results: x/N`; the other 21 are a
   wrong directory, output sent to `/dev/null`, or a shell error. None shows another case count.

A write through a computed path that was then reversed exactly would escape the scanner and check 1. Check 2 would
catch it only if the case count changed.

## Runs of the tests while a test file was changed

`scripts/item3.py`. The state of a file at a test run is the end state when no later write to it follows, from the
end-state flag; otherwise the state rebuilt from the literal writes.

- Ran the tests at least once while a test file was changed: 138 of the 146. The other 8 did not run `test.py`
  after their write.
- Ran `test.py` while `test.py` itself was changed: 119; its output showed a pass at least once in 112.
- The last test run before the submit used a changed `test.py` and showed a pass: 111. By model:
  gemini-3.1-pro-preview 58, gemini-3.5-flash 39, grok-4.5 9, deepseek-v4-flash 3, claude-sonnet-5 1,
  qwen-3.7-max 1. Dataset result: `passed_all` 96, `passed_visible_only` 13, `failed_visible` 2. Audit outcome:
  `GENUINELY_CORRECT_MOD_JUSTIFIED` 77, `GENUINELY_CORRECT_VALIDATOR_BUG_FIXED` 10, `NO_INDEPENDENT_VALIDATOR` 10,
  `INCORRECT_BUT_RECORDED_PASS` 6, `GENUINELY_CORRECT_ROUND2` 3, `GENUINELY_CORRECT_MOD_UNNECESSARY` 3, other 2.
- A pass shown: `Results: N/N passed`, or an exit status of 0 with no `FAIL`, `Error` or `Traceback` in the output.
  An emptied runner counts as a pass.

## Files

- `runs-with-test-write.tsv`: the 146 runs, one row each: key (the first 16 hex digits of the sha256 of the run key),
  model, condition, problem, epoch, class, files written, first write call, restore call and what differs (hand
  restores only), restore attempts (git, undo, copy), ran while changed, the number of runs of a changed `test.py`,
  submitted after a passing run of a changed `test.py`, the dataset labels (`test_result`, `classification`,
  `final_verdict`, `tamper_hack`, `gt_outcome`) and the run key. The counts above are its columns `cls`,
  `ran_while_modified` and `submitted_after_passing_modified_testpy`.
- `runs.tsv`: the scanner's classes before the hand checks, 148 rows (the 146 and the 2 dropped).
- `scripts/`: `verify_transcripts.py`, `scan.py`, `classify.py`, `item3.py`, `final.py`, `broadnet.py`,
  `outcheck.py`.

Not published: `item3.tsv` (the per-run table `item3.py` writes and `final.py` reads; it also holds the last 300
characters of each run's final words), the output of `broadnet.py` (recorded tool-call lines) and excerpts of the
recorded calls. All but the excerpts are rebuilt by the commands below.

## Reproduce

`D` is a directory with `transcripts/*.jsonl` and `per_run_data_all_conditions.csv` from the pinned revision,
`tree-transcripts.json` (the revision's tree listing of `transcripts/`) and `problems.json`.

```
python3 -I scripts/verify_transcripts.py D/tree-transcripts.json D/transcripts
python3 -I scripts/scan.py D scan.json
python3 -I scripts/classify.py scan.json D/per_run_data_all_conditions.csv runs.tsv
python3 -I scripts/item3.py D scan.json item3.tsv
python3 -I scripts/final.py scan.json runs.tsv item3.tsv runs-with-test-write.tsv
python3 -I scripts/broadnet.py D scan.json > broadnet.txt
python3 -I scripts/outcheck.py D
```

Run again on 2026-11-25 from a fresh download of the pinned revision, `runs.tsv`, `item3.tsv` and the output of
`broadnet.py` came out byte-identical to the stored ones, and `runs-with-test-write.tsv` differed only in its
`end_differs` column for the 142 runs that ended different, whose text was changed in `final.py` that day.

`../2026-11-24-git-checkout-runs/` uses `scan.json` for the 18 runs that tried git.

Report: [bench/replay/TEST-CHANGES.md](https://github.com/Allexsen/belay/blob/main/bench/replay/TEST-CHANGES.md).
