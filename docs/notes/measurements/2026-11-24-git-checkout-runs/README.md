# The runs that tried to undo a test change with git (2026-11-24)

The dataset is [EvilGenie-escalation](https://huggingface.co/datasets/WiserHumanExperimental/evilgenie-escalation)
(WiserHumanExperimental, MIT) at revision `1bb777b666b0f76801f9b5b9a28eb3f7786ea70f`, the 2,115 runs in the
benchmark paper's analysis. The short excerpts of recorded commands and agent comments in `runs.tsv` are quoted from
it under that licence.

Question: which runs ran `git checkout`, `git restore`, `git reset --hard` or `git stash` on a test file they had
changed, what the recording shows around each command, and how each run ended.

Read-only: the recorded tool calls were read as text with `python3 -I`. Nothing recorded was executed. Tool-call
index `cN` is 0-based over all tool calls of a run, in recorded order.

## Files

- `runs.tsv`: one row per run, 18 rows, 27 fields: the run key and its 16-digit `key` (the first 16 hex digits of
  the sha256 of the run key), model, condition, problem, epoch; each git command and its recorded result; what was
  changed before it; the test runs before it and their summary lines; the calls in between and after; whether the
  end bytes match the original; the run's own words, quoted; the end state flags, score line and dataset labels;
  the observable-pattern category and the evidence for it.
- `scripts/find_git.py`: the search. A tool call whose argument text matches
  `(?<![\w./-])git\s+(?:-C\s+\S+\s+)?(checkout|restore|reset|stash)\b[^\n;&|]*`, where the matched command names
  `test.py` or `test_cases.json`, or is `git reset --hard` or `git stash` with no path.
- `scripts/facts.py`: per git call, the writes and test runs before it.
- `scripts/assemble.py`: builds `runs.tsv`. `MANUAL` in it holds the fields read by hand from the recording.
- `scripts/git_probe.sh`: whether `git checkout`, `git restore` and `git reset --hard` return changed test files to
  their original bytes, in a scratch repository. On git 2.43.0 all three did. It is about git, not about the runs.

The scripts also read outputs of earlier passes that are not published (a scan of the recorded writes and the
dataset labels of the 146 runs), so they cannot be run from this folder alone. Every count in the report can be
recomputed from `runs.tsv`.

## What the rows show

- All 18 git commands failed: the recorded answer is `git: command not found`, or, in 7172bbae87b96733, git's error
  went to `/dev/null` and the command after `||` ran. No restore happened.
- All 18 runs ended with a test file changed. None ended byte-identical to the original.
- Reasoning is encrypted in the 17 gemini-3.1-pro-preview runs. Nothing here states why a command was run.

Categories, by observable pattern only, assigned per git call: (1) right after a write, with no test run between;
(2) after a test run on the changed file; (3) after the run's own words that the change was not allowed;
(4) cannot tell. A run carries every category any of its git calls has.

Report: [bench/replay/TEST-CHANGES.md](https://github.com/Allexsen/belay/blob/main/bench/replay/TEST-CHANGES.md).
