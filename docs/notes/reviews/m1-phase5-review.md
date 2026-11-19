# Phase 5 independent review (blast radius: scope resolution, state-directory writes; mark's prefilter), verbatim

Reviewer: a fresh agent with no implementation context (BELAY_DESIGN §0.4(b)), 2026-10-31.
Scope: `origin/main..m1/phase5-cli` at e3b2210. [n] tokens, 51 tool uses, 11.7 min.
Relayed verbatim (the reviewer's own message, unedited); dispositions appended after it.

---

Reviewed commit e3b2210, the head of m1/phase5-cli when I started (6d83d6e and e3b2210 on top of origin/main). By the end the branch in /home/user/workspace/belay had moved to 4063e67, which I did not review. Line numbers below are from e3b2210. I built in a detached worktree at /tmp/belay-review5, which I have since removed. Every run used a BELAY_STATE_DIR under the scratchpad. test_cli (10), test_mark (8) and test_receipt (4) all pass there.

ESTABLISHED DEFECTS

1. Medium. Writes in the state directory follow symlinks, so belay can write outside it and can overwrite a file.
   - Where: src/cli/state.c:137-138 (mkdir_p follows a symlinked scopes/<hex> or checkpoints/), :164 (fopen "w" on scope.tmp), :178 (lock opened O_CREAT without O_NOFOLLOW), :291 (meta.json.tmp).
   - Experiments:
     (a) Replaced checkpoints/ with a symlink to $T/outside/cp. `check` returned 0 and wrote checkpoint 2 (manifest and meta.json) into $T/outside/cp.
     (b) Before a scope's first use, created scopes/<hex>/scope.tmp as a symlink to $T/victim, which held "IMPORTANT DATA". After `check` (rc 0), victim holds the scope path and `scope` is a symlink to victim.
     (c) Replaced lock with a dangling symlink. `check` created the empty file $T/outside/created-by-lock.
   - What is safe: the manifest and diff outputs (mkstemp then rename) and the store (open O_NOFOLLOW; a symlinked store/ gave exit 4, "store: cannot open").
   - Who can exploit it: if the same user owns the state directory, nothing is gained. It matters when belay runs with more privilege than whoever can write the state root, for example sudo with an inherited XDG_STATE_HOME or BELAY_STATE_DIR, or a shared directory. Nothing checks the state root's owner or mode.
   - Fix: openat relative to a root dirfd with O_NOFOLLOW (and O_EXCL for the temporary files), and check the root's owner.

2. Medium. FIFOs planted in the state directory hang every command.
   - Where: state.c:199 (read_meta fopen "r"), :151 (the scope file), and the previous manifest opened by belay_manifest_open.
   - Experiment: `mkfifo checkpoints/7/meta.json`. Both `timeout 5 belay log` and `timeout 5 belay check` were killed (rc 124).

3. Medium. A race on first use makes concurrent captures fail.
   - The scope file is written at state.c:161-175 before the lock is taken at :176-183.
   - Experiment: 6 concurrent `mark` on a fresh scope. 1 succeeded; 5 exited 4 with "cannot write .../scope" (the losers' rename hits ENOENT).
   - Suspicion, not reproduced: one process's fopen "w" (O_TRUNC) could empty the inode another has just renamed into place. A reader would then see an empty scope and refuse with exit 3.
   - Once the scope file exists, captures serialize correctly on the flock.

4. Medium. A change directly in the scope root permanently disables mark's prefilter and blames the clock.
   - Cause: walk.c's visit() updates newest_ctime_ns for every entry except the root (the root is emitted in manifest_write.c:190-206 without going through visit). prev_load's newest_validated_ns does include the root (previous.c:196). So once the root holds the newest ctime, state.c:377 decides "ctime went backwards" and redoes the walk in full. The redone manifest again has the root as newest, so this repeats on every mark.
   - Experiment: check; rm sc/h; mark; mark; mark. Mark 2 trusted 2 files. Marks 3 and 4 both said "every file read (ctime went backwards: newest 1793465226625145274 below the previous 1793465226737828021)".
   - The test misses it because test_mark's mutate() only changes d0..d2, never the root.

5. Medium. A same-size rewrite during the previous capture, after the file was read and within its ctime tick, is trusted by every later mark.
   - Cause: R (previous.c:223-225) is the newest recorded ctime or the manifest's ctime. Neither is a time before each file's read, so it does not guard writes in the file's own tick after the read.
   - Experiment: a harness linking libbelay with test_mark's 1-s rounding adapter, which rewrites file a ("old!" to "NEW!") at the second file's open, then waits one tick. Capture 1 recorded f28d6cfd… ("old!"). The mark trusted it (trusted 2, racy 0) and recorded f28d6cfd…. A full capture recorded 77565307… ("NEW!").
   - Harness: /tmp/scratchpad/h/racy.c
   - Reach: needs coarse timestamps (1 s or 2 s filesystems, network filesystems, kernels without multigrain ctime).
   - Gap in the docs and tests: the docs' claim covers only writes after the checkpoint, and the coarse-timestamp tests only mutate between captures.
   - Suggested fix: R taken from the start of the previous walk, on the scope filesystem's clock.

6. Medium. The prefilter copies the previous entry's `stored` decision, so mark's manifest differs from check's (capture.c:373-392).
   - Only the hash is safe to reuse. Whether a copy is kept depends on path claims, writer_present and the store's contents, none of which the stat rule covers. Three experiments:
     (a) Writer present: held the file open for writing (exec 3>>f) during check, closed it, then ran mark and check. Mark 2 has no "stored"; check 3 has one.
     (b) Directory rename into a claimed path: a 169,893-byte staging/RECORD, then `mv staging foo-1.0.dist-info` (a directory rename leaves the files' ctime alone). The mark has no stored copy; the check stores it under the pip claim. The pip and dpkg interpreters then lose content. A KEEP_HASH claim (`.git/index`) would go the other way.
     (c) Store object missing: deleted the store objects after check. The mark recorded "stored":"2751…" with no object behind it. The next diff said "content unavailable (before): missing", where a full check would have stored the object again.

7. Medium. The receipt's privilege section misses setuid changes, and the rest of the receipt can be forged (receipt.c:86, :82, :110).
   - A setuid change on a file whose name is not valid UTF-8 is never classified as a privilege change (`!b64`), so it folds.
   - A newly added setuid file is not a privilege change either, because only "changed" containing "mode" is examined.
   - Paths, finding text and event text are printed raw.
   - Experiment: 60 modified files, `chmod u+s 'zzz\xff'`, a new 4755 file, and a file named "g\n\nprivilege\n  nothing here, all fine". By default the receipt shows only "changes / and 13 more", with no privilege section at all. With --all, a fake "privilege" heading appears, and both setuid files are under changes. ESC sequences would also reach the terminal unchanged.

8. Low-medium. diff never says that the state directory was excluded, or that its capture raced (cli.c:254-262).
   - docs/cli.md says the output of check, mark and diff says so "on every capture".
   - Experiment: state directory inside the scope. check printed "not recorded: belay's own state directory…". diff, in text and in --json, said nothing.

9. Low-medium. When the state directory is the scope itself, or the scope is inside the state directory, belay records its own writes and says nothing.
   - The exclusion compares children only (walk.c visit), never the root itself.
   - Experiment: BELAY_STATE_DIR equal to the scope gave "1 unstable", and entries grew from 9 to 16. A scope under st/scopes produced a diff full of its own store/manifest files marked unknown.
   - Suggestion: refuse both cases.

10. Low-medium. Checkpoint ids can overflow and leave the scope stuck (state.c:244 and :333).
    - Experiment: mkdir checkpoints/99999999999999999999 (strtol saturates at LONG_MAX, then +1 is undefined behaviour). `check` reported "check -9223372036854775808" with rc 0. log does not list it, because state_list skips ids <= 0. Every later capture then fails with exit 4 ("cannot create …/-9223372036854775808").
    - Also: highest_dir accepts names like "05" or "+5" that state_list resolves to a different directory.

11. Low. A meta.json larger than read_meta's 8 KiB buffer makes the checkpoint disappear (state.c:201).
    - Experiment: a scope path with 1,500 bytes of \x01 escapes to a 9,322-byte meta.json. check said "check 1"; log then said "no checkpoints"; `diff --since 1` exited 2 with "no checkpoint 1".

12. Low. Checkpoint JSON is not valid JSON for a scope path that is not UTF-8 (state.c:288, cli.c:137).
    - Experiment: `check --json` on a directory named "bad\xff". Python fails with UnicodeDecodeError at byte 171.
    - Manifest and diff.v1 use scopes_b64 for this case; checkpoint.v1 has no equivalent. The receipt's heading also shows an empty scope here, because receipt.c:168 reads only "scopes".

13. Low. scope_resolve opens each ancestor with O_RDONLY, which needs read permission, not just search permission (state.c:71).
    - Experiment: parent chmod 311 (owner has -wx). `cat` of the file works, but `check` gives exit 3, "cannot open the scope". capture's own open would have succeeded.
    - Fix: O_PATH (Linux) or O_SEARCH.

14. Low. Errors writing standard output are ignored and the exit code is 0.
    - Experiment: `check --json`, `diff --json`, the diff receipt and `log`, each redirected to /dev/full: all exited 0.
    - Cause: nothing flushes or checks stdout. The receipt's ferror check runs before the buffer is ever written.
    - docs/cli.md assigns exit 4 to I/O errors.

15. Low. Exit codes and messages differ from docs/cli.md.
    - A scope directory that belongs to another scope (corrupt state) exits 3 (cli.c:171); the docs give 4.
    - Usage errors print the whole usage text to stderr (13 lines measured); the docs say an error is one line.
    - `--full-every ''` is accepted as 0 ("never"), and 0 is undocumented.
    - --full-every is accepted and ignored by check and log, while --full is rejected for them.
    - The help texts point to schema/check.v1.json, mark.v1.json and log.v1.json (cli.c:40, 46, 55); only schema/checkpoint.v1.json exists.

16. Low. jsonr's string parser allocates the whole remaining line for every string, so memory is quadratic in the line (jsonr.c:29).
    - Experiment: one 64 KB line of 16,383 short strings reached a maxrss of 66 MB.
    - receipt.c:144 and :168 pass kids[0].s, which is NULL when the element is not a string, to %s. Only reachable through a diff file that belay did not write.

SUSPICIONS (not demonstrated)
- A hostile previous manifest in the state directory makes mark record its hashes for unchanged inodes. This needs write access to the state directory, the same precondition as finding 1.
- A corrupt latest manifest makes mark and `diff --since` fail with exit 4 until a check or `mark --full` is run (demonstrated). A fallback to a full walk might be preferable; this is a design question, not a defect.
- flock waits silently and forever behind a stopped belay. `diff --to`, which reads only, also takes the lock.

CHECKED AND SOUND
- Resolving the scope: realpath, then a component walk with O_NOFOLLOW, then capture's own realpath and open checked by (dev, ino). A swap to another directory between the resolve and the capture is refused, and the redone walk in state.c:385 checks again.
- The store (O_NOFOLLOW, O_EXCL). The manifest and diff outputs (mkstemp then rename, which replaces a planted symlink rather than following it).
- The O_DIRECTORY component walk does not block on a FIFO.
- prev_index: hard links and duplicate inodes are trusted on neither side. A file replaced by another with the same inode needs an equal ctime, so it is read unless the clock moves. The 64 MiB bound refuses with a reason, and the result is a full walk that says why.
- The mode cursor's memcmp order matches the manifest's bytewise sort.
- Exit codes: 2 for a missing checkpoint or bad usage, 3 for a missing scope or one that is a file, and --exit-code semantics, all as documented.

TESTS: GAPS AND CLAIMS NOT CHECKED
- test_mark's differential never writes during a capture or changes the root (findings 4 and 5). It has no claimed paths or directory renames, no writer present, and no missing store objects (finding 6).
- test_cli checks the exclusion note only on check (finding 8).
- No test plants symlinks or FIFOs in the state directory, runs captures concurrently, or exercises the real mode_of cursor beyond one file.
- No test uses paths with newlines, or paths that are not UTF-8, in the receipt or the JSON.
- e2e.sh's "an error wrote to stdout" checks only the last command.

---

## Dispositions (implementer, appended)

Every fix has a test that fails on the code before it: each was checked by reverting that fix
alone (a canary) and running the named test, which failed on an assertion (kill rule). Canary
runner: scratchpad/canary5/run.py (CLI, receipt) and canary46 (capture). Class and other
instances are named under each.

1. **Fixed.** The state root must be the user's and writable by no one else (exit 3); below it
   every directory is opened from a dirfd with O_NOFOLLOW (`dir_at`), the lock O_NOFOLLOW and
   checked regular, the scope file and meta.json written through `write_whole` (any stale or
   planted `.tmp` unlinked, never followed; O_CREAT|O_EXCL|O_NOFOLLOW; renameat; fsync), new
   checkpoint directories made with mkdirat. Test `the_state_directory_never_writes_through_a_link`
   (checkpoints/ a symlink -> 4, nothing outside; lock a dangling link -> 4, nothing created;
   scope.tmp planted -> victim intact; root 0777 -> 3). Canaries 1a-1d (no O_NOFOLLOW on dirs; on
   the lock; no unlink of the tmp; no mode check): each KILLED. Class: path-based writes in the
   state directory; other instances: the manifest and diff outputs and the store were already
   safe (mkstemp+rename, O_NOFOLLOW|O_EXCL), as the review found.
2. **Fixed.** Everything belay reads from its state is opened O_NONBLOCK|O_NOFOLLOW and must be a
   regular file (`read_small`; the manifest reader `belay_manifest_open` likewise, fstat S_ISREG
   after open). A FIFO is corrupt state, exit 4. Test
   `a_fifo_in_the_state_directory_is_corrupt_not_a_wait` (meta.json and scope as FIFOs, under a
   5-second alarm that fails the test). Canary 2 (no O_NONBLOCK): KILLED ("belay waited on it").
   Other instances: the previous manifest (manifest_read.c); a FIFO there now gives a full walk
   (R3).
3. **Fixed.** The lock is taken before the scope file is read or written; LOCK_NB first, and a
   one-line "waiting for another belay" note before blocking (the review's suspicion about a
   stopped belay: it is now said, not silent). Test `concurrent_first_captures_all_succeed`
   (6 forked first captures: all exit 0, log lists 6). Canary 3 (no flock): KILLED (1 of 6).
   The O_TRUNC suspicion is gone with the fixed `.tmp`+O_EXCL under the lock.
4. **Fixed.** The writer seeds newest_ctime_ns with the root's own ctime. Tests
   `a_change_in_the_root_is_the_newest_ctime` (test_mark), `a_change_in_the_scope_root_keeps_the_prefilter`
   (test_cli, three marks after removing a root file), and mutate() now changes the root (op 6).
   Canary C4: KILLED.
5. **Fixed, deviating from Q2 (decision-log R1, awaiting the author).** R is the previous walk's
   start: a probe file's ctime on the scope's device, stored as walk_start_ns in meta.json and
   passed back as previous_start_ns; otherwise the newest validated ctime. The manifest-ctime
   source is removed (it is after the walk, which is the defect). Test
   `a_rewrite_during_the_walk_after_its_read_is_read_by_every_mark` (1 s rounding; tree, walk and
   rewrite in one tick; asserts the rewrite happened). Canaries: R unbounded, and R = newest
   validated + 1: both KILLED (and by the 1 s and 2 s differentials). Reach that remains: a state
   directory on another device than the scope falls back to the newest validated ctime, which
   is NOT sound for this case when another file gets a newer ctime later in the same walk (A
   written, read and rewritten in tick T; B changed in T+1; N = T+1 > T, so A is trusted) --
   the original defect's hole, for that configuration only. Documented in docs/cli.md with the
   coarse-timestamp limit; a fix (a clock probe on the scope's device without writing into the
   scope) is an open question for the author.
   Test fixed on the way: `an_unchanged_file_is_trusted_and_a_racy_one_read` now waits 50 ms
   before its first capture: the kernel's coarse ctime clock put the last file written in the
   probe's tick, correctly racy.
6. **Fixed.** Only the hash is reused; `want` is computed first, and a trusted file whose copy is
   wanted is skipped only when the store holds that object at that size (`store_has`); else it is
   read. Test `a_mark_keeps_the_copies_a_full_capture_would` (a writer present at the first
   capture; store objects deleted; a 9,000-byte RECORD claimed by a directory rename): each
   mark equals a full capture byte for byte. Canary C6: KILLED.
   A regression of this fix, found by measuring (not by a test): an unclaimed small binary file
   has no copy, so every one was read whole on every mark (the Go tree: 756, trusted 15,419 of
   16,175). Fixed by reading only its first SNIFF_BYTES, which decide binary the same way.
   Test `a_small_binary_file_without_a_copy_is_trusted`; canary (no sniff): KILLED.
7. **Fixed.** Privilege is decided from both sides' modes and caps whatever the outcome
   (receipt_meta: mode, has_caps), on the decoded bytes of a path_b64 path. Every string from the
   diff is escaped (C0, C1, DEL, non-UTF-8 as \xNN; backslash doubled). Test
   `privilege_is_found_whatever_the_path_and_the_outcome` (the review's experiment: 60 modified, a
   setuid change on "bad\xffname", a new 4755 file, a removed file with caps, a path forging a
   "privilege" heading and an ESC sequence, a C1 CSI in a finding). Canaries 7a (no escaping),
   7b (mode changes only), 7c (path_b64 not decoded): each KILLED. Other instances of the class
   (untrusted text printed raw): event interp/text/paths, type names, unknown/changed lists, the
   heading's scope: all escaped. Not covered: caps or iflags *values* on a file that kept them
   (needs pin #24's values).
8. **Fixed.** diff prints its capture's notes (raced, excluded) after the receipt; with --json on
   stderr only. Test `diff_says_what_its_capture_left_out`. Canary 8: KILLED.
9. **Fixed.** A scope that is the state root or inside it is refused, exit 3 (realpath prefix,
   and (dev, ino) equality). Test `a_scope_in_the_state_directory_is_refused`. Canary 9: KILLED.
10. **Fixed.** `state_id_parse`: 1-9 digits, no leading zero, used for directory names and for
    --since/--to; at 999,999,999 a capture refuses ("no checkpoint ids left"). Tests
    `odd_checkpoint_names_and_long_meta_are_handled` (99999999999999999999, 05, +7 planted: the
    next check is 2) and `a_usage_error_is_one_line_and_ids_are_strict`. Canary 10: KILLED.
11. **Fixed.** meta.json read whole up to 64 KiB (a PATH_MAX scope escaped 6x fits); larger is
    corrupt, never silently a missing checkpoint. Same test (6 levels of 250 \x01 bytes). Canary
    11 (8 KiB): KILLED.
12. **Fixed.** `scope_b64` / `manifest_b64` in checkpoint JSON and meta.json (schema: oneOf each;
    the stdlib validator learned allOf/oneOf); the receipt's heading reads scopes_b64. Tests
    `checkpoint_json_for_a_scope_that_is_not_utf8`, `a_diff_of_another_version_is_rejected_and_b64_scopes_shown`,
    e2e (validated against the schema; skipped where the filesystem refuses the name). Canary 12:
    KILLED.
13. **Fixed.** O_PATH (Linux) or O_SEARCH for the component walk. Test
    `a_parent_with_search_permission_only_is_enough` (parent 0311). Canary 13 (O_RDONLY): KILLED.
14. **Fixed.** cli_main flushes and checks the output; failure is exit 4 unless already 4. Test
    `output_that_cannot_be_written_is_exit_4` (/dev/full; skipped on macOS, listed). Canary 14:
    KILLED.
15. **Fixed.** Corrupt state is 4 (another scope's directory included; cli.h and docs/cli.md
    agree); usage errors are one line; `--full-every ''` and negative values are usage errors, 0
    is documented as never, and --full-every is refused for check and log; help names
    schema/checkpoint.v1.json. Tests `state_of_another_scope_is_corrupt_exit_4`,
    `a_usage_error_is_one_line_and_ids_are_strict`. Canaries 15a-15d: each KILLED.
16. **Fixed.** jsonr sizes each string by its own raw length. NULL guards: every `kids[0].s` use
    checks J_STR first. Test `a_line_of_many_strings_is_read_in_linear_memory` (200,000 strings
    on one line under RLIMIT_AS = now + 1 GiB, Linux without ASan; elsewhere unlimited). Canary
    16: KILLED (render failed under the limit).

Suspicions:
- A hostile previous manifest: same precondition as 1, now refused at the root (R4).
- A corrupt latest manifest: now a full walk with a reason (R3), not exit 4.
- flock waits silently: now said (3). `diff --to` still takes the lock (it may write
  diff-from-N.ndjson).

Tests, gaps named: the differential still does not write during a capture except in the new
targeted test; e2e now checks stdout is empty after every error, not only the last.

