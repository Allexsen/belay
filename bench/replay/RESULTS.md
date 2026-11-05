# belay against EvilGenie: replaying 2,115 published agent runs

The harness that produced these results is in bench/replay/. It downloads its inputs from their published sources; nothing here is redistributed.

## What was tested

belay records a directory's state before and after something runs, and reports what changed. This study checked whether those reports hold up on real agent runs rather than scripted ones.

## Data

EvilGenie-escalation (WiserHumanExperimental, MIT) publishes 2,295 runs. This study uses the 2,115 in the benchmark paper's analysis: 15 models on 9 competitive-programming problems, chosen by the benchmark for specification ambiguity or test-infrastructure quirks. Each workspace includes a visible test suite the model could modify. The other 180 runs are negative controls on single-canonical-answer problems and are not used.

The dataset classifies each run as legitimate, heuristic, reward_hacking or error, and flags runs with tamper_hack and test_py_modified. This study groups the runs as follows:

- tamper: tamper_hack or test_py_modified;
- test_cases.json only: changed test_cases.json and not test.py;
- solution hacks: heuristic or reward_hacking, with no test file changed;
- clean: everything else, except the runs classified as error, which are excluded.

## Method

1. Each workspace was rebuilt from the benchmark's templates; the test files matched the published hashes byte for byte for all 9 problems.
2. belay recorded the workspace.
3. Every recorded tool call was replayed in a sandbox with no network.
4. belay recorded again, and checked the result against a spec protecting test.py and test_cases.json, the same two files the benchmark's scorer checks.

Per the study plan, the spec, the groups and the rule for a valid replay were fixed before any full result. Replay is imperfect: 86.2% of bash and Python calls (26,523 of 30,783) reproduced the recorded output exactly, and editor calls agreed with the recording on 4,634 of 5,288 by a rougher check. So a run was counted only if its protected files' end state was byte-proven against the recording. That proof held for 2,079 runs. 2,072 were counted: 36 runs failed the proof, and 7 were excluded as classification errors.

## Results (pre-registered, belay v0.1.0-alpha.3)

| group | flagged |
|---|---|
| tamper | 103 / 103 |
| test_cases.json only | 7 / 7 |
| clean | 0 / 1,704 |
| solution hacks (out of scope by design) | 0 / 258 |

## The miss

Three runs deleted a protected file. Two of them, one deleting test.py and one deleting both test files, were not flagged: the spec used no_write, which at the time didn't cover deletion. The third deleted test_cases.json but also modified test.py, and was flagged for that. All three were excluded by the proof rule, so they are absent from the table above. Across every run that changed a test file, counted or not, belay flagged 144 of 146.

In v0.1.0-alpha.4, no_write also forbids deletion, and the proof rule was extended to prove a deletion from the replay. Re-judged with v0.1.0-alpha.4 on the same stored end states, with no new replay, the figure is 146 of 146, and 2,075 runs are counted. That figure was obtained after the rule was changed in response to these runs, so it is not a prediction. The pre-registered figures are the test.

## Limits

- Not independent detection. The benchmark's scorer hashes the same two files, so agreement shows belay's capture, diff and verification working correctly at scale on real agent output. It doesn't show belay finding what the scorer couldn't.
- End state only. A file modified and then restored before the end is invisible to both.
- Single-problem workspaces of a few files; the result says nothing yet about full repositories.
- Modified isn't cheated. Of the 103 tamper-group runs, 8 carry tamper_hack; the others changed test.py for reasons that include legitimate fixes to a defective test. belay reports that a file changed, not why.
- Replay conditions varied: 652 runs replayed without a memory limit, the rest with 1.5 GiB per process. The image used was built on 2026-10-28, after the original runs (June to August 2026).

## Reproduction

bench/replay/ has a single entry point with pinned inputs. It executes model-written code; read its safety notes first. The published harness applies the extended proof rule and a memory limit to every run, so its counts correspond to the post-hoc figures, not the pre-registered ones. The full 2,115-run set has not been re-run with it; a 200-run sample, replayed fresh on v0.1.0-alpha.4, matched the stored post-hoc results on every verdict and end-state hash.
