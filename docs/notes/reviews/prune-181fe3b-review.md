> **Note added at export.** A review made before the merge. Checked against commit 5f46e7c on 2026-11-15: findings 1, 2, 4 to 8, 10, 11, 13, 14, 15 and 18 are fixed, with tests; 3, 16 and 17 in part; 9, 12 and 19 stand. Of the twelve surviving mutants of finding 20, eleven are now killed by a test and one (meta.json removed last) still survives.

# Adversarial review of belay 0d6c23b (`mark --keep`) and 181fe3b (`belay prune`)

**Verdict: do not merge as is.** Findings 1 and 2 are real defects in the code that deletes. Finding 1 removes a user's history when they asked to keep it. Finding 2 stops prune from ever finishing after one killed capture. I found no bug that sweeps a store object a surviving manifest refers to.

Where I worked:
- Worktree, left in place: /tmp/scratchpad/rev-prune
- Harness (lib.sh, crash.c, stall.c, check.py, mutate.py): /tmp/scratchpad/x
- Mutant copy: /tmp/scratchpad/mut

Every belay run had `BELAY_STATE_DIR` under the scratchpad. The test binaries also ran with `HOME` and `XDG_STATE_HOME` redirected. I did not read or touch the real state directory, and I made no commits.

The `hook-prune` branch moved to 5402cc3 while I worked. This review covers 181fe3b only.

In the reproductions, `$S` is a throwaway scope with a few checkpoints and `$T` is that scratch run's directory.

## Findings

### 1. HIGH: `--keep-days` overflows, and a large "keep" value deletes everything but the newest
- **Established:** reproduced, and confirmed by UBSan.
- **Class:** integer overflow, no range check. Data loss.
- **Location:** src/cli/prune.c:296, `now - (int64_t)days * NS_PER_DAY`. `number()` accepts any `long`.
- **Reproduction:** `belay prune --scope $S --keep-days 365000` (1000 years) on 5 checkpoints from the same minute printed `removed 4 of 5 checkpoints: 1-4`, and only 5 remained.
- **UBSan:** `src/cli/prune.c:296:84: runtime error: signed integer overflow: 365000 * 86400000000000`.
- **Also ran, same bad result:** `--keep-days 1000000` and `--keep-days 9223372036854775807`, both dry runs. Each would remove every checkpoint but the newest.
- **By a model of the wrap only (not run):** 999999, 10000000, 999999999 and 213503 also keep nothing. 213504 means about 25 minutes, and 213505 about a day.
- `--dry-run` gives the same wrong answer, so it only helps someone who reads it closely.

### 2. HIGH: one killed capture stops prune for good, and the sweep never runs again (PR-8 fails, PR-7 is untrue)
- **Established:** reproduced with a real SIGKILL mid-walk.
- **Class:** incomplete list of the writer's temporary names, plus an ordering fault. Cleanup of one dead directory blocks all later work.
- **Location:** src/cli/prune.c:206 unlinks only `manifest.ndjson`, `meta.json.tmp` and `diff-from-*`. The rmdir at :210 then fails.
- **Cause:** the capture writes `manifest.ndjson.tmp.XXXXXX` (src/capture/manifest_write.c:130), and that file exists for the whole walk. By reading, belay's CLI installs no signal handlers, so SIGINT and SIGTERM leave it behind too. A hook timeout, Ctrl-C, OOM kill or reboot is enough.
- **Reproduction** (`killmid.py` in the harness directory): 20,000-file scope, kill a mark mid-walk, take two more marks.
  - `--dry-run --keep-last 2` said it would remove 4 checkpoints, 3 store objects and 1 unfinished directory, exit 0.
  - The real run exited 4 with `checkpoints/5 holds what belay did not write`. Checkpoints 1-4 were gone and the object count stayed at 20005.
  - Three more runs all exited 4. The dry run still says "would remove 3 store objects", which never happens.
- **Consequences:**
  - Orphan-diff cleanup and the sweep sit after the failing step (prune.c:325-338), so the store is never swept again. That is the store growth prune exists to stop.
  - The error blames corrupt state, but belay wrote the file itself.
  - A dead directory above the newest id is left alone at first. It becomes fatal once a later checkpoint exists.
- **By reading only:** `manifest.ndjson.run.XXXXXX` (manifest_write.c:114, the fallback where O_TMPFILE is missing, and the only path on macOS) would do the same in its short window.
- **Also by reading:** a real checkpoint directory never holds these names, so only unfinished directories are affected.

### 3. MEDIUM: a foreign file in a checkpoint that goes half-removes it, then wedges as in finding 2
- **Established:** reproduced.
- **Class:** the check happens after the deletion, though the file header says "Everything a run will do is decided first". PR-7 is untrue here.
- **Reproduction:** `touch $(sd)/checkpoints/2/.nfs0000000deadbeef`.
  - Dry run: exit 0, would remove 1-3.
  - Real run: exit 4 with `checkpoints/2 holds what belay did not write`.
  - Afterwards: 1 is gone, 2 has lost `meta.json` and its manifest, 3 is untouched, and no store object was swept.
  - Every rerun exits 4.
- The test `prune_leaves_what_belay_did_not_write` pins the exit code but not this partial result.

### 4. MEDIUM: options given twice: the last wins in silence
- **Established:** reproduced.
- **Class:** CLI strictness. This repeats a defect already fixed elsewhere, see the comment "(D6)" in `parse()` in src/cli/cli.c.
- `diff --scope S --scope S` and `diff --since 1 --since 2` exit 2, `--X given twice`. The same goes for `baseline export`.
- prune exits 0 in each of these:
  - `--keep-last 5 --keep-last 1`
  - `--keep-days 30 --keep-days 0`
  - `--keep-from 3 --keep-from 5`, which drops the protection of 3 and 4
  - `--scope /nonexistent --scope $S`, which acts on the second scope
- All were run with `--dry-run`. The real path parses identically.

### 5. MEDIUM: pruning silently switches off the periodic full mark (`--full-every`)
- **Established:** reproduced.
- **Class:** cross-feature invariant the pin does not cover.
- **Location:** src/cli/state.c:823 counts trailing non-full checkpoints in the current list, and prune shortens that list.
- **Reproduction:** 120 marks with default `--full-every 50`. Without prune, full reads came at marks 50 and 100. With `prune --keep-last 3` after each mark, there were none.
- Any scope that keeps fewer than 50 checkpoints after a prune never gets a full read again, and nothing says so. Under HK-1's `--keep-days 7`, that is any scope taking fewer than 50 marks a week. By the design's own rule, a change the prefilter cannot see then stays unseen.

### 6. MEDIUM: `verify --to` accepts a half-removed or unfinished checkpoint (PR-8, PR-10)
- **Established:** reproduced.
- **Class:** one command uses a different definition of "exists".
- **Location:** `checkpoint_after` in src/cli/verify.c calls `state_check_manifest`, never `state_list`.
- **Reproduction:** remove `checkpoints/2/meta.json`, which is what a crash between the two unlinks leaves.
  - `log` omits 2, and `diff --since 2` exits 2.
  - `verify --to 2` exits 0 and prints a full policy report on a checkpoint that does not exist.
  - It exits 2 only once the directory is gone.
- The code predates these commits. The pin rows are what make it a defect now.

### 7. MEDIUM-LOW: no sync between removing checkpoints and sweeping (PR-8, power loss)
- **Established:** measured with strace. The consequence is by reading only, I did not simulate power loss.
- **Class:** crash ordering without a barrier.
- A real run makes two fsyncs, both for the `--keep-id` meta write. There are none across the checkpoint unlinks, the sweep or the end of the run.
- If a filesystem reorders these, a `meta.json` could come back after its objects are gone. A single-journal filesystem keeps the order. src/capture/store.c says plainly it does not rely on fsync for ordering on macOS.
- Process kills are fine, see the checked list below.

### 8. MEDIUM-LOW: `--keep-from` accepts an id that does not exist
- **Established:** reproduced.
- **Class:** unchecked input on a safety option.
- `--keep-last 1 --keep-from 99` with 6 checkpoints exits 0 and protects nothing, while `--keep-id 99` is refused. An id below the newest that was already pruned may be legitimate. An id above the newest can only be a mistake.

### 9. MEDIUM-LOW: a scope whose directory is gone cannot be pruned
- **Established:** reproduced.
- **Class:** gap in the pin.
- After deleting the scope, `prune` exits 3 `cannot resolve the scope`, and `log` does too. Its checkpoints and store stay until someone removes them by hand.
- By reading, a removed container's `--docker` scope has the same problem.

### 10. LOW-MEDIUM: KP-2 is only half met
- **Established:** reproduced.
- **Class:** requirement met in the text output only.
- `belay log` prints `, kept`. `log --json` and `mark --keep --json` print nothing, because `json_checkpoint` has no such field.
- schema/checkpoint.v1.json has `additionalProperties: false`, so fixing this changes a pinned schema. That is your decision.

### 11. LOW-MEDIUM: prune under-reports what it frees (PR-7)
- **Established:** measured on identical copies.
- **Class:** incomplete accounting.
- Unfinished directories are counted but never sized. Orphan diffs are never mentioned.
- `--keep-last 2` reported 91,717 bytes and actually freed 129,858, so 29% went unreported.
- `--keep-days 1` reported 0 checkpoints and a 530-byte sweep, and actually freed 22,308.

### 12. LOW-MEDIUM: readers racing prune get "corrupt state" instead of a refusal (PR-10)
- **Established:** reproduced deterministically by stalling a process with LD_PRELOAD.
- **Class:** check-then-use race, wrong exit code.
- Stored-diff reader (`diff --since 1 --to 4`, lockless), `prune --keep-last 1` run in between:
  - Exit 4, `manifest: cannot open`.
  - With `--json`, stdout already holds a `content_unavailable` finding where a clean run has `text_changed`.
  - Exit 4 does flag it, so a caller that checks the code is safe. Stale output is printed first.
- Uncached diff: it lists under no lock, then waits on prune's lock. Exit 4, `checkpoints/1 is missing`, not exit 2.
- Dry run stalled, then a real prune: exit 4 `checkpoints/3 is missing`.
- Nothing is lost in any of these.

### 13. LOW: `orphan_diffs` deletes names belay never writes
- **Established:** reproduced.
- **Class:** contradicts the comment at prune.c:180, "Only what belay writes there is removed".
- `diff-from-notes.txt` and `diff-from-` in a checkpoint that stays were removed silently, and the dry run did not mention them. `strtol` gives 0, which is not in the list.

### 14. LOW: exit codes for a missing id disagree
- **Established:** reproduced.
- `--keep-id 99` exits 3. `diff --since 99` and `verify --to 77` exit 2. PR-10 says "as a checkpoint that never existed is today".

### 15. LOW: `number()` is looser than `--full-every`
- **Established:** reproduced.
- `--keep-last " 1"`, `$'\n1'`, `007` and 19-digit values are accepted. `--full-every` takes digits only, at most 9.

### 16. LOW: a real run on a never-captured scope behaves unlike a dry run, and `--json` output has no fixed shape
- **Established:** reproduced.
- A real run creates a state directory (`scopes/` count went 1 to 2), while the dry run does not. The principle in `cmd_diff`, comment D8, is that this leaves no state behind.
- `--keep-id 7` there exits 0 with no complaint.
- The `--json` output there has 3 keys against 11 normally. The format has no schema and is not described in docs/cli.md.

### 17. LOW: leftovers no prune removes
- **Established:** planted and observed. That a real kill leaves them is by reading.
- **Class:** gap in the pin. PR-6 is followed as written.
- `store/.tmp-*` from a killed capture stays for good, and so do empty fan-out directories. Each `.tmp-*` can be as large as the file being copied.

### 18. LOW: prune holds the lock for a long time on a big scope
- **Established:** measured, then extrapolated.
- 201 manifests of 1.7 MB took 2.82 s with a warm cache, about 123 MB/s. Applied to the measured 13.35 GiB scope, that is about 2 minutes under the lock, and captures block for all of it.

### 19. LOW: PR-9's "nothing else deletes" is not literally true
- **Established:** reading only.
- src/cli/docker.c:390 `unlink(manifest)` removes a failed capture's own manifest. It is harmless, but the pin and the header of prune.c overstate this.

### 20. MEDIUM: the tests do not protect the rows that matter most
- **Established:** 30 mutants of prune.c run against test_cli. Pristine code passes 53 of 53. M28 was badly built and is discarded, leaving 17 killed and 12 survived.
- **Survived, and each one is a real regression nothing would catch:**

| Mutant | What it breaks |
|---|---|
| M04 | `meta.json` removed last (PR-8) |
| M07 | real run takes no lock (PR-9) |
| M08 | sweep runs before checkpoint removal (PR-8) |
| M09 | a kept checkpoint's objects swept (KP-1 data loss) |
| M11 | `--keep-from` checkpoints' objects swept (PR-3 data loss) |
| M16 | checkpoint bytes not counted |
| M17 | store bytes not counted |
| M19 | manifest not checked from the fds |
| M21 | orphan left when its `since` id is already gone (crash rerun path) |
| M23 | non-object names in a fan-out swept (PR-6 "only such an object") |
| M24 | unfinished directories above the newest removed |
| M29 | `kept_ids` dropped from `--json` |

- **Killed:** M01-03, 05, 06, 10, 12-15, 18, 20, 22, 25-27, 30.
- The tests check that a checkpoint's directory exists, not that it still reads. `prune_finishes_what_a_crash_left` only simulates a crash with `rm meta.json`. No test kills a process, and no test covers locking.

## Checked and found fine

- **References (independent Python checker, hashes every object):** no surviving manifest lost an object in any run. That covers `--keep-id`, `--keep-from`, kept checkpoints, git repositories, cached diffs, and mixed v1, v2, v3 and v4 manifests. The older versions were converted from real ones and read correctly by diff. `diff` still gives `text_changed` across them after pruning.
- **Other references to the store:** by reading, nothing else does. Diffs are computed afresh, bundles carry their own copies, and verify copies into its own store.
- **Process kill at every step:** SIGKILL before each of the 18 unlinks, rmdirs and renames of a run with `--keep-id`, cached diffs and a kept checkpoint. All 18: state valid, `log` works, rerun exits 0, resulting tree byte-identical to a clean run. The only exceptions are findings 2 and 3.
- **`--dry-run`:**
  - 5 argument sets, text and JSON: output matches a real run on identical copies, and the tree hash (path, size, mode, mtime, content) is unchanged.
  - strace shows no mutating syscall and no flock.
  - A nonexistent state root is not created.
- **Stops with nothing removed:** corrupt line, truncated manifest, version 9, symlinked manifest on a checkpoint that stays, and a symlinked fan-out directory.
- **Left alone as they should be:** a foreign file in a checkpoint that stays, a junk name in a fan-out, a symlink at an object's name.
- **Locking:**
  - A capture waits, and says so.
  - 150 rounds of concurrent mark, prune, `log`, `log --json` and dry run: no failures, references valid.
  - `log` is safe against prune.
- **Sweep stopped by EACCES:** exit 4, state valid, rerun finishes.
- **`--keep-id` meta.json rewrite:** byte-identical apart from `,"kept":true`, including a non-UTF-8 scope path.
- **Ids are not reused,** because the newest is never removed.
- **Pin rows:**
  - PR-1, PR-2, PR-3, PR-5 and KP-1: behaviour matches. PR-3's protection is subject to findings 4 and 8.
  - KP-3 and DC-1: match; the DC-1 text was compared with the row.
  - PR-10 for `diff`: matches. PR-10 for `verify --to`: fails, finding 6.
  - PR-4 and PR-6's "rebuilt" do not apply yet.
  - PR-7 fails (findings 2, 3, 11). PR-8 fails (2, 3; see 7). PR-9 is met in code but untested.
- **Build and tests:** test_cli passes under ASan and UBSan, and `lint-tests` passes.

## Not covered

- Real power loss, macOS, NFS, a full disk, and real docker scopes (`--docker` was only refused for lack of root).
- `make check` in full and the e2e scripts. I ran only test_cli (plain and sanitized) and the lint.
- The real state directory, so I do not know how many killed-capture directories it already holds. If there are any, finding 2 will hit the first hook prune.
- ST-* and HK-* rows. `scripts/dogfood/receipt.py:324` opens manifests directly and I did not test it against a pruned checkpoint.
- `bsearch` with a NULL base (prune.c:117) when a store is empty but a manifest refers to it. By reading this is undefined behaviour with no practical effect. I meant to run it, but a safety check refused my `rm -rf` of a throwaway scope's store contents. I did not try another route, so this case was not run.
