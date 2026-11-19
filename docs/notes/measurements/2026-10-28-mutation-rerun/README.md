# Refactor-era mutants, re-run clean (2026-10-28)

Why: the 2026-10-28 mutation harness restored files with old mtimes, so make reused mutant
objects and later results inherited earlier mutants. b2c15e0's claim ("5 mutants ... caught by
the same tests as under --wrap") is the evidence the refactor kept the tests' power, so it was
re-run where contamination is impossible.

The original run (transcript, 2026-10-27 07:31 UTC) was in fact clean -- it deleted the mutated
file's object before each build and restored with a fresh write -- but ran test_races only,
counted a mutant killed if ANY expected test failed, and the --wrap baseline it compared against
was not recorded.

Re-run: refactor_mutants.py, one fresh git worktree per commit, `make clean` + full `make test`
per mutant, mutants re-expressed where the code moved. Results (results.txt):

| mutant | e04186a (--wrap) | b2c15e0 (decorators) | fa319ff (end of refactor) | d03b606 (PR #5) |
|---|---|---|---|---|
| A no end-of-walk re-check | 3 tests | same 3 | same 3 | those 3 + 6 newer |
| B empty link target accepted | r3_empty_link_target_is_recorded_unreadable | same | same | same |
| C no directory identity check at open | directory_swapped_between_stat_and_open_is_flagged | same | same | same |
| D incomplete/changed listing not flagged | 2 tests | same 2 | same 2 | same 2 |
| E symlink re-stat ignored | 2 tests | same 2 | same 2 | same 2 |

Baselines: 185/185/185/192 run, 0 failing. No survivor. The original run's test lists match
exactly. (D at d03b606 only removes the W_INCOMPLETE flag: the per-directory timestamp check it
also disabled before no longer exists.)
