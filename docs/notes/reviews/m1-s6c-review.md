# Independent review of the S6 completion commits (222fb07..358e8f0), 2026-10-30

Fresh agent, own worktree detached at 358e8f0. Verbatim below.

---

## Review of 222fb07..358e8f0 (worktree detached at 358e8f0d57f3b940ae455df6ef09ef6dec2c200a)

`make check` and `make check-san` both pass, and `make gen-check` is current. The required CI step `make oracle` fails, because the oracle's reference was not updated (F1). The diff changes in e1b7062, ed7aea5 and 358e8f0 match the pin and the spec on every input I tried. The durability commit (dcca6b3) syncs what this capture renamed, not everything the manifest it publishes depends on (F2–F4). It also claims more than it does (F5).

I built everything from `git archive` exports in the scratch directory and wrote nothing in the repository. The scratch files are listed at the end.

---

### F1 — HIGH — `make oracle` (a required CI check) fails at 358e8f0
**Where:**
- `scripts/oracle/reference.py:43-45` (`TRAILER_KEYS`), `:226-235` (`one_sided`), `:285-291` (`one_sided_unknown`), `:453-457` (trailer).
- `scripts/oracle/compare.py:258` compares the trailer's keys in order.
- `.github/workflows/ci.yml:39-40` runs the oracle on every pull request.

None of the five commits touches `scripts/oracle/`.

**Input and wrong output:** `scripts/oracle/run.sh 200 20261030` exits 1.
- **All 6,193 pairs fail on the trailer.** The reference has no `dir_timestamps_only` (from e1b7062).
- **55 pairs fail on records.** Example, pair-02934 "becomes a mount root with new timestamps: reg":
  - the reference expects `"unknown":["unverified","mount","iflags_unknown"]`;
  - the code gives `["unverified","mount"]`.
  - The code is right by the pin and by rule 4. The reference's one-sided `iflags` check ignores the `on mount roots` column.
- **The random seed (66910695):** 6,150 pairs fail the same way, 23 of them on records.
- **ed7aea5's rule is not checked by the oracle at all.** The reference does not have the rule, yet neither seed produced a disagreement. So the corpus never generates a path missing below a raced non-directory, and no coverage-gate scenario requires one.

**How established:** reproduced. `TMPDIR=<scratch>/tmp bash scripts/oracle/run.sh 200 20261030`, run in an export of 358e8f0.
- At 222fb07 the same command fails only on the then-uncoded F5 pin: 78 pairs, ctime on directories. e1b7062 fixes those, so both new failure classes come from this range.
- I added the three rules to a scratch copy of the reference, written from the prose (`patch_ref.py`). With it, 6,193/6,193 and 6,269/6,269 pairs agree, the gate passes, and the `dir_timestamps_only` counts agree on every pair. The code itself is right; the reference is stale.

**Class:** a rule change landed in spec, pin and code without the independent reference CI checks it against. 52a2621 set the convention for a trailer change: update the oracle in the same commit and report its result.
- No other instances. `test_pins` reads the pin at run time and followed on its own. The fuzz invariants come from the manifest pin, which is unchanged.

**Fix direction:**
- In `reference.py`:
  - add `dir_timestamps_only` to `TRAILER_KEYS`, with a naive count;
  - in `one_sided`, return `unknown`/`raced` when the ancestor is a non-directory carrying `raced`;
  - in `one_sided_unknown`, skip fields whose pin row says "not compared" on mount roots.
- In `gen_corpus.py`, add a scenario for a raced non-directory with names below it on the other side, including siblings like `d!x` and `d.x`, and require it in the coverage gate.

---

### F2 — MEDIUM — a published manifest can name copies whose directory entries no one has synced
**Where:**
- `src/capture/store.c:206-210`: the dedup branch sets no flag.
- `store.c:226-229`: flags are set only when this handle's own rename succeeds.
- `store.c:249-263`: `belay_store_sync`, called once, at `manifest_write.c:297`.
- `capture.c:451-456`: a dedup'd commit still sets `stored`.

**Input:**
1. Capture A commits copies, then fails before its batched sync. Any failure after the commits does this: killed, out of space, or EIO on the manifest's fsync.
2. Capture B of the same tree succeeds, and every copy deduplicates.

**Wrong output:** B's manifest names 2 copies. During B, the fan-out directory, the store directory and the store's parent are each synced 0 times; the manifest's directory once. The comment "The copies it names are durable before the manifest is" fails even for the names.

**How established:** reproduced: `storesync.c` scenario 1. The adapter is decorated to log every synced inode, and the failure is injected as EIO on the manifest's fsync.

**Exposure:** `fsync(2)` on Linux says an entry is durable only once its directory is fsynced.
- On ext4 and XFS, any fsync B makes commits the shared journal, which carries A's earlier changes. That masks the gap in practice.
- On btrfs (one of the CI `fs-scenarios` targets), fsync logs only the inodes it syncs. A's store entries wait for the next transaction commit (30 s by default) while B's manifest is already durable.
- This is inferred from documented filesystem behaviour, not from a power-loss test.

**Class:** durability bookkeeping keyed on what this handle changed, not on what the publication depends on.
- Other instances: F3 and F4.
- The same gap opens, by reading, when two concurrent captures share a store and the one that dedups publishes first.

**Fix direction:** set `published[prefix]` in the dedup branch too; fix F3 and F4 as below. Measured cost: none (see the verdict).
- Test gaps: the three new tests cover only a fresh store and one successful capture. `test_store.c` has no `belay_store_sync` test. Mutant M5 (flags never cleared after a sync) survives every test, so the "since the last call" contract is untested.

---

### F3 — LOW — `made` is lost when the commit that made the fan-out directory fails, contrary to `store.h`
**Where:**
- `store.c:161-167`: `open_prefix` sets `*created` when `mkdirat` succeeds.
- `store.c:226-229`: `made |= created` happens only in the rename-success branch.
- `store.h:57-61` promises a sync of the store directory "when a commit made a fan-out directory".

**Input:**
1. Commit 1 of object X makes fan-out `b6`, then fails. I used its staging file removed, so `renameat` returns ENOENT. Real causes: EMFILE on the open, EIO on `fstatat`, ENOSPC or EDQUOT on `renameat`.
2. The capture continues (`capture.c:451-453`).
3. Commit 2 of X lands in `b6`, with `created` now false.

**Wrong output:** after `belay_store_sync`, the fan-out directory is synced once and the store directory 0 times.

**How established:** reproduced: `storesync.c` scenario 2.

**Class:** as F2 — a side effect recorded only on the success path, though it is permanent from the first step.

**Fix direction:** set `s->made` in `open_prefix` when `mkdirat` succeeds, or sync the store directory on every `belay_store_sync` (one fsync of a clean directory).

---

### F4 — LOW — the store directory that `store_open` creates is never synced into its parent
**Where:** `store.c:59`. The `mkdir` result is used only to tolerate EEXIST, and nothing ever syncs the store directory's parent.

**Input:** the first capture into a store directory that does not exist yet — that is, the baseline capture.

**Wrong output:** the store directory is synced once, its parent 0 times, the manifest's directory once.

**How established:** reproduced: `storesync.c` scenario 3. The man page passage above applies here too.

**Class:** as F2. The fan-out level is handled; the level above it is not.
- Outside the range, `src/utils.c:41,50`, `src/session/rootfs.c:34` and `src/session/session.c:98` also create directories without syncing the parent. Whether those must survive power loss is a session-engine question I did not assess.

**Fix direction:** have `belay_store_sync` sync the parent through `openat(dfd, "..")`, either when `store_open` made the directory or on every call. Every call also covers a store directory made by a capture that later failed.

---

### F5 — LOW — "The copies it names are durable before the manifest is" overstates: the copies' bytes are never synced
**Where:** `manifest_write.c:296` and dcca6b3's commit message. Contrast `store.h:14-20`; no object is fsynced anywhere in `src/`.

**Input:** a capture with the store on, then a power loss before writeback.

**Outcome:** the manifest is durable. The copies' names are too, apart from F2–F4. Their bytes need not be: on ext4 with delayed allocation, a file renamed to a new name and never fsynced can come back empty. `belay_store_verify` then reports a mismatch. Nothing is silently corrupted, but the copy is lost.

**How established:** by reading (no fsync of an object). The ext4 consequence comes from its documented behaviour, not a crash test.

**Class:** a durability comment stronger than the mechanism. Also, `store.h:52-53` ("survives a crash only after belay_store_sync") states a necessary condition that F2–F4 show is not sufficient.

**Fix direction:** reword to what is true: names are synced before the manifest, bytes are verified on read. Syncing each object before its rename is a cost decision for you.

---

### F6 — LOW — on macOS, `fsync` does not reach stable storage
**Where:**
- `src/platform/fsops_macos.c:120` uses `.fsync = posix_fsync`; this table entry is new in dcca6b3.
- `src/diff/diff.c:82` and `:244` call `fsync` directly.

**Outcome:** Apple's `fsync(2)` page says the drive may hold and reorder the data, and points to `F_FULLFSYNC` for stronger guarantees. So on macOS, a published manifest can still vanish on power loss, which is the reason given for the decision.

**How established:** by reading, plus Apple's man page. No macOS host was available.

**Class:** the platform's durability primitive. Instances: every fsync site — `manifest_write.c:61` and `:286`, `store.c:258` and `:261`, `diff.c:82` and `:244`.

**Fix direction:** in the macOS adapter, use `fcntl(fd, F_FULLFSYNC)`, falling back to `fsync`. It costs a drive-cache flush per call, so it is your decision.

---

### F7 — LOW — the class fixed by the previous review's F6 has one more instance: a regular-file mount root carries `unverified`
**Where:**
- `entry.c:199-201` and `:240` force `unverified` on a mounted regular file.
- `classify.c:72-82` lists every flag's reason.
- The reason's meaning at `diff-v1.md:192`, and the new sentence at `diff-v1.md:153-156`.

**Input:** before, `m` is a regular file with `iflags`; after, `m` is a regular file, mount root, `dev` 2. Bind-mounted files are common: Docker does this for `/etc/hosts` and `/etc/resolv.conf`.

**Wrong output:** `{"path":"m","outcome":"unknown","type":"reg","changed":["dev"],"unknown":["unverified","mount"]}`. The `unverified` reason says "larger than its hash_max_bytes, or not readable", but a mount root is never read, by design.
- Related: the new sentence ("…with no reason that claims something could not be read") is stated universally. A directory that becomes a mount root against a side carrying `xattrs_unknown` gives `["mount","xattrs_unknown"]`. That output is correct by the flag rule; only the sentence is too broad.

**How established:** reproduced: `cases.py`, the cases "reg mount root against a reg with iflags" and "dir with iflags becomes mount root; other side xattrs_unknown".

**Class:** a "could not be read" reason on a mount root.
- For directories and regular files there are no other instances: rule 22 keeps `xattrs_unknown` off mount roots, and rules 8 and 11 keep `unstable` and `unreadable` off them.
- The rules do not exclude `unreadable` on a symlink mount root. I did not try to produce one.

**Fix direction:** either the `unverified` meaning names the mount case, or the classifier drops a content flag's reason when `mount` on the same side explains it. That is a pin-level choice. Narrow the sentence to "the unread attributes add no reason".

---

### F8 — LOW — misplaced comments in `test_races.c`
**Where:** `test/test_races.c:1455-1462`. The three new tests sit inside the "Audit 2026-10, the capture's surviving mutants" section. `a_file_gone_between_its_stat_and_open_is_counted`'s doc comment is now detached from its test and sits above the first new test.

**How established:** by reading.

**Fix direction:** move the three tests out of that section.

---

## Verdict on the batched store sync

Accept batching, but not as implemented.
- **What is right.** The guarantee the decision needs is an ordering: every directory a manifest depends on is synced before the manifest's rename. A batched sync delivers that. The cost of a sync per commit is real. On this machine (WSL2, ext4, 2,000 small distinct files):

  | Variant | First capture | Second capture (all dedup) |
  |---|---|---|
  | As is | 0.059–0.062 s | 0.041 s |
  | Sync inside each commit | 2.23–2.28 s (about 37×) | 0.040 s |

  Failure handling matches the diff output's sync.
- **What is wrong.** Durability moved out of the commit, a property of each object, which is what the decision named. It now lives in per-handle memory that is lost whenever a capture fails, and that memory records only this handle's own renames (F2–F4).
- **The fix costs nothing measurable.** A scratch variant marks the prefix on dedup, sets `made` at `mkdir`, and syncs the store directory and, when made, its parent. It takes 0.059–0.063 s and 0.039–0.041 s, closes scenarios 2 and 3, and closes scenario 1 except the store's parent (which needs a parent sync on every call). It passes `test_races` (42), `test_store` (10) and `test_manifest_write` (46).
- **One decision for you.** `belay_store_commit` alone no longer gives durability; callers must call `belay_store_sync`. `store.h` documents this, and today the manifest writer is the only production caller. Because the decision named the commit, this contract change should be approved explicitly.

## Checked and found correct
- **e1b7062.**
  - `dir_timestamps` is set only under rule 6 for a directory whose mtime or ctime differs. It is never set when the directory is unstable, has `xattrs_unknown`, has iflags on one side, changes type, has a mode change, or carries a flag.
  - It is counted for the scope root `.` and across a remounted scope.
  - The trailer order matches the schema and the spec, and `belay_diff_stats` agrees.
  - The ctime pin row, O4 and O5 agree with the spec and the generated tables. `manifest-v1.md` is consistent. The frozen manifest pin holds only the key table and is unaffected.
- **ed7aea5.**
  - These all give `raced`: raced regular-file, symlink and FIFO ancestors; two levels deep; siblings `d!x`, `d.x` and `d/e!z` sorting between a name and its children.
  - Below a `d!x` that did not race, absence stays known (added or removed).
  - The nearest raced file wins over an unstable directory above it.
  - A raced directory (rule 10) is sealed and gives `not_captured`.
  - The scope root can never yield `ANC_RACED` (`manifest_stream.c:70-72`, `entry.c:213-215`).
  - The reader rejects orphans and entries below a non-directory (`manifest_stream.c:45-55`), so a raced non-directory is always the nearest recorded ancestor on its side.
- **dcca6b3.**
  - Order: the manifest is fsynced, then the store is synced, then the rename, then the manifest's directory is synced.
  - Failures to sync or to open are ignored. With the store off, `belay_store_sync(NULL)` does nothing.
  - Every decorator copies the default table, so `fsync` is inherited. `measure.c`'s `openat` decorator skips `O_DIRECTORY` opens, and no race-test arm can fire on the sync's absolute-path open.
  - Each of these mutations fails a new test: no store sync, store sync after the rename, store directory never synced, manifest directory not synced.
- **7f6fa87 and 358e8f0.** The code follows the pin column. With `attrs_read` changed, caps and xattrs are still skipped on mount roots, and `differs()` is never called for them elsewhere. Ignoring the column now fails 23 `test_pins` cells and 3 `test_diff` tests; comparing iflags on mount roots fails the new test.

## Could not check
- **Power loss itself.** I have no crash harness. The missing syncs are reproduced through the fsync log; the losses they allow are inferred.
- **macOS, btrfs, XFS, NFS, FAT.** Only ext4 on WSL2 was available, so the timings are indicative only.
- **The GitHub workflow.** I ran its steps locally, not the workflow itself.
- **The session engine's directory creation** (F4's other instances).

## Scratch files
- Check logs: scratchpad/review-s6c/check.log, check-san.log
- Oracle logs: scratchpad/review-s6c/oracle.log, oracle-base.log, oracle-patched.log
- Reference patch: scratchpad/review-s6c/patch_ref.py
- Diff corner cases (F7 and the ed7aea5/e1b7062 checks): scratchpad/review-s6c/t/cases.py, t/difftool.c
- Store-sync reproduction (F2–F4): scratchpad/review-s6c/t/storesync.c
- Benchmark: scratchpad/review-s6c/t/bench_store.c
- Fixed variant: scratchpad/review-s6c/src-fix/src/capture/store.c
- Per-commit variant: scratchpad/review-s6c/src-percommit/src/capture/store.c
- Mutation drivers: scratchpad/review-s6c/t/mutate.py, t/mutate2.py
(scratchpad = /tmp/scratchpad)
