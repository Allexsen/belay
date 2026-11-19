# Phase 5 fixes, second independent review (blast radius: state-directory writes, scope resolution, mark prefilter, receipt), verbatim

Reviewer: a fresh agent with no implementation context, 2026-10-31.
Scope: `4063e67..a5bfa8e` (the fixes for NOTES/reviews/m1-phase5-review.md). [n] tokens, 65 tool uses, 13.7 min.
Relayed verbatim (the reviewer's own message, unedited); dispositions appended after it.

---

Review of git diff 4063e67..a5bfa8e (capture, cli, docs). I reviewed it in a detached worktree at a5bfa8e, which is now removed. The main checkout was not touched and `git status` is clean. Every experiment used a fresh 0700 BELAY_STATE_DIR under the scratchpad, and that scratch data is deleted.

`make -j8 check`: exit 0. 417 tests ran, 0 failed, 0 skipped, no compiler warnings.

## 1. Established defects (most severe first)

**D1. Medium: the state directory is reached again by path after the checks, so symlinks there are followed.**
- **Doc claim broken:** docs/cli.md says "Everything below it is opened without following symlinks … never followed".
- **Where:**
  - state.c:259-260 and 379-381 build path strings from the state root.
  - state.c:597/604 pass them to `belay_manifest_write`, which writes the manifest, store and temporaries by path and does `rename(outtmp, out_path)`.
  - cli.c:286-292 calls `belay_diff(a, b, d)` and `fopen(d)` by path.
  - manifest_read.c:124 does `open(path, O_RDONLY|O_NONBLOCK|O_CLOEXEC)` with no `O_NOFOLLOW`.
  - The fd-based checks in `state_open` only cover the moment they run.
- **Experiment A (planted symlink):** after `check`, I replaced checkpoints/1/manifest.ndjson with a symlink to a copy outside the state directory.
  - `belay mark --json` exited 0 with `"prefilter":{"used":true,"trusted":1}`, so the linked file was read and trusted.
  - `belay diff --since 1 --to 2` exited 0 with "no changes".
- **Experiment B (swap mid-capture):** an LD_PRELOAD shim on `realpath()` renamed scopes/<hex> away and put a symlink to another directory in its place at the writer's own `realpath` call (call #3, after `state_open`'s checks). `belay check` exited 0 with "check 3".
  - The manifest.ndjson and the store object landed in the other directory.
  - meta.json landed in the real one, because it is written through the held fd.
- **Same class:**
  - A FIFO at the latest manifest.ndjson does not give exit 4. `mark` exits 0 with full_reason "the previous checkpoint cannot be read". That contradicts "a FIFO … is corrupt state (exit 4)", though the mark section lists "unreadable".
  - `diff` refuses that FIFO with exit 4.
  - `store_open` uses `O_NOFOLLOW` on the last component only.
- **Who can exploit it:** anything that can write inside the state directory. That means the same uid, for example a recorded agent running as the user. With D2, it also means another user who can write an ancestor of the root.

**D2. Medium-low: only the root's owner and mode are checked, not its ancestors, and `mkdir_p` creates the root before the check.**
- **Where:** state.c:261-292.
- **Experiment:** I made `shared/` mode 0777 without the sticky bit, then `shared/st` mode 0700 owned by me. `BELAY_STATE_DIR=…/shared/st belay check` exited 0.
- **Why it matters:** because of D1, every later write re-resolves `shared/st`. Anyone who can write `shared/` can rename it and substitute their own directory after the check.
- **Not run:** the cross-user exploit itself (I have no second uid). The redirection mechanism is what Experiment B demonstrated.

**D3. Low-medium: mark falls back to the weak reference point silently, and the CLI's use of walk_start_ns has no test.**
- **Where:** manifest_write.c:157-166 records `walk_start_ns = 0` when the probe file is not on the scope's device; previous.c:165 then uses R = the newest validated ctime.
- **Experiment:** a harness built from test_mark.c's 1-second rounding adapter. f0 is rewritten at the same size during the walk, in the tick of its first write, and the walk then crosses into the next tick.
  - With the walk start known: trusted=0, racy=14, mark equals the full capture.
  - With previous_start_ns=0 (what the CLI passes when the state directory is on another device): trusted=12, mark keeps f0's old sha256, and mark differs from the full capture.
- **The limitation is documented, but nothing tells the user they are in it:** `walk_start_ns` is not in the `--json` output and no `full_reason` is given. It applies whenever the scope and state directory differ in st_dev: another mount, btrfs subvolumes, $HOME state with a scope elsewhere.
- **Mutation:** I changed state.c:588 to `previous_start = 0;`. test_cli (23), test_mark (13) and `make e2e` all still pass.

**D4. Low: mark records store copies that a full capture would not keep.**
- **Doc claim broken:** "Whether a copy is kept is decided anew for every file, as a full capture would."
- **Where:** capture.c:417 takes `copy = want && p->has_stored && store_has(...)` before two checks a full capture makes: `writer_present` (capture.c:458) and the binary test for unclaimed files.
- **Experiment (a), claim removed:** a small binary file at x/.git/hooks/bin is claimed KEEP_STORE and stored. After `mv x/.git x/notgit`:
  - The next `mark` records `"stored":"1bd95cf6…"`.
  - The following `check` records no stored copy.
  - The two manifests differ only on that line.
- **Experiment (b), writer present:** with `exec 7>>sc/held.txt` holding the file open:
  - `mark` (checkpoint 4) records `"stored":"b9e68e1b…"`.
  - `check` (checkpoint 5) records none.
- **Impact:** benign. The object is content-addressed and verified on read, and diff 2→3 says "no changes". But the doc claim and the mark-equals-check property do not hold.
- **Who:** any process writing in the scope.

**D5. Low: output outside the receipt is printed unescaped.**
- **Where:**
  - cli.c:148 prints `"kind":"%s"` raw into `--json`.
  - cli.c:170 and 172 print `kind` and `full_reason` raw in text mode.
  - Error lines print the resolved scope raw, for example cli.c:271-272 and state.c:86/301.
- **Experiment 1 (meta.json):** I planted a meta.json with kind `a"}\x1b]0` and full_reason `\x1b[31mRED\x1b[0m\nforged line`.
  - In `log --json`, the line fails `json.loads` ("Extra data"), and kind is outside the schema's enum.
  - In text `log`, raw ESC bytes and a forged second line appear.
- **Experiment 2 (scope path):** with `--scope proj`, where proj links to `evil\x1b[2J\nforged: all clear`, `diff --since 7` prints a two-line error containing raw ESC. That contradicts "An error is one line on standard error".
- **Same class:** `capture_notes` prints `st->root` raw.
- **Who:** kind/full_reason need write access to the state directory (same uid). The scope path needs only the ability to name a directory on the path the user passes.

**D6. Low: the receipt passes Unicode format and bidi characters through raw.**
- **Where:** receipt.c:54-72 escapes only C0, C1, DEL and invalid UTF-8.
- **Experiment:** files named `rlo‮exe.txt`, `ls sep` and `zw​j` appear in the receipt as raw bytes e2 80 ae, e2 80 a8 and e2 80 8b.
- **Effect:** the RLO character visually reverses the rest of the name ("rlotxt.exe").
- **Status against the docs:** docs/cli.md's literal wording holds. The claim in receipt.h ("a path cannot forge a line, a heading or a terminal sequence") is weakened.
- **Who:** anyone who can create a file in the scope.

**D7. Low: checkpoint ids can be used up by a planted directory, and the result is not documented.**
- **Experiment:** I made a directory named `999999998` (no meta.json). The next check was 999999999, then every capture failed with "no checkpoint ids left", exit 4. `diff --since 999999999` also exits 4, because it needs a new id.
- **Who:** the same uid.

**D8. Trivial items.**
- A type_changed record that is also a privilege change loses the type transition: "T tc_dir setuid added (mode 0755 -> 4755)" does not say a directory became a file.
- A too-long BELAY_STATE_DIR exits 4, while "no state directory can be named" is documented as 3.
- A relative BELAY_STATE_DIR is accepted, so `"manifest"` in the JSON is relative and depends on the working directory. A relative XDG_STATE_HOME is ignored.
- docs/cli.md says "about 85 bytes a file" for the prefilter index; manifest.h says "about 76 bytes a regular file".
- meta.json `"id":1.9` is accepted as 1.
- `diff` on a scope never captured creates its state directory and then exits 2.

## 2. Suspicions (not demonstrated)
- cli.c:301: the `fread` loop never checks `ferror(in)`. A read error would give truncated diff JSON with exit 0.
- cli.c:370: `strerror(errno)` can be stale when `ferror(out)` was set earlier and `fflush` then succeeded, so the message would be misleading.
- `store_has` checks only type and size. A store object corrupted at the same size would be recorded by mark, where a full capture rehashes the file. Readers verify on read, so this is bounded.

## 3. Same-class sweep
- **D1 (path re-resolution):** every path-based use of `st->dir` and `st->store` is affected: the manifest writer, store, temporaries and probe, `belay_diff` inputs and output, `fopen(d)`, and the previous-manifest read. The fd-based paths hold: dir_at, lock, scope, meta.json, write_whole, and checkpoint directories.
- **D5 (raw output):** `kind`, `full_reason` (text), the scope in error lines, the `scope` file's content in "belongs to the scope %s", and the root in capture notes. The receipt itself escapes correctly.

## 4. Checked and sound
- **Planted entries:** a symlink to a directory, a symlink to a file, or a FIFO at store, checkpoints, lock, scope, checkpoints/1 and checkpoints/1/meta.json all give exit 4 under check. Under log every one gives 4 except store and lock, which log never opens (exit 0). Nothing hung and no link target was modified. A symlink planted at checkpoints/2/diff-from-1.ndjson is replaced by rename and its target is untouched.
- **Root checks:**
  - mode 0770 gives 3 ("writable by others").
  - /var/tmp (owned by uid 0) gives 3.
  - A symlinked root is followed, as documented.
  - A scope at /a/state2 next to a root at /a/state is accepted.
  - A scope inside the root reached through a symlinked root gives 3; a scope equal to the root through a link gives 3.
  - A root inside the scope is excluded and the output says so.
- **Concurrency:** 5 trials of 12 parallel processes (4 check, 4 mark, 4 log) on a fresh scope. Each trial gave ids 1–8, unique, all exit 0, with the "waiting" notes on stderr.
- **Id parsing:** 999999999 is accepted. 1000000000, 0999, 0, -1, +1, 1x, "" and 01 all give 2. `--full-every 1000000000` gives 2.
- **meta.json bounds:** 65535 bytes is read; 65536 gives exit 4. Ids that are a string, 4294967297 or -1 give 4. Extreme created_ns values render.
- **Receipt escaping:** ESC, LF, CR, TAB, DEL, C1 (c2 9b), ff, overlong sequences (c0 af, e0 80 af), a surrogate (ed a0 80), f4 90 80 80 and a truncated e2 80 all come out as `\xNN`. A backslash comes out as `\\`.
- **Privilege section:** setuid, setgid and sticky added and removed; type_changed in both directions; chmod 6755; `chattr +d` (inode flags); non-UTF-8 names on added and removed records; correct order of "sub.x" against "sub/a.txt". Capabilities were not testable (no CAP_SETFCAP).
- **Output failures:** every command, plus help and --version, gives 4 when writing to /dev/full or to a closed stdout. `--exit-code` gives 1 when something changed and 0 when nothing did.
- **Prefilter end to end:** 15 rounds, each with 400 background same-size rewrites during a mark, then mark compared with check: 0 differences. The walk-start reference catches a rewrite inside the same tick (Experiment D3).
- **`--full-every` counting** across marks and diff captures matches the docs (N=3, 0 and 1).
- **Unverified files:** a file over 64 MiB shows as "? big unknown: unverified" and `--exit-code` gives 1.

## 5. Test gaps (doc claims no test holds)
- "Never followed" and "FIFO is exit 4" for checkpoints/<id>/manifest.ndjson. No test, and the behaviour does not match (D1).
- The CLI passing meta.json's walk_start_ns into the prefilter. A mutation survives every test (D3).
- Fallback mode when the state directory is on another device: no test, and no signal to the user.
- Ancestor writability of the state root: neither documented nor tested.
- A root owned by another uid: only mode 0777 is tested.
- "Whether a copy is kept is decided … as a full capture would": no test for a writer present at mark time, or for a binary file losing its claim (D4).
- The "waiting for another belay" stderr line: concurrent_first_captures sends stderr to /dev/null.
- The receipt's handling of overlong sequences, surrogates, DEL and code points above U+10FFFF works (I verified it) but is not in test_receipt.
- Running out of ids at 999999999, and its exit code.
- `log --json` schema conformance and escaping when meta.json holds unexpected values.

The scripts I wrote are in /tmp/scratchpad/scripts (plant.sh, swap.c, race.sh). The full test log is /tmp/scratchpad/rev6-check.log.

---

## Dispositions (implementer, appended)

Each fix has a test that fails with the fix reverted alone (canary runner
scratchpad/canary5/run2.py; D4 in canary46): 13 canaries, 13 KILLED.

- **D1 -- fixed in part; the rest relies on D2.** Every manifest is opened from the directory fds
  (O_NOFOLLOW|O_NONBLOCK, regular file) before its path is handed to the writer or to diff
  (`state_check_manifest`: mark's previous, diff's --since and --to): a planted link or FIFO is
  exit 4, as docs/cli.md says. Test `a_planted_manifest_is_corrupt_state`. Canaries (mark, diff):
  KILLED (the diff one only after the test used `--to`, since diff's own capture checked first).
  Not fixed: the swap *during* a capture (Experiment B) -- the writer and diff still take paths;
  moving them to dirfds is an API change of belay_manifest_write and belay_diff. With D2 fixed
  only a writer with the user's own uid can make that swap, and such a writer can already write
  the state directory directly; docs/cli.md now states the reliance instead of "never followed".
  Open question for the author. The paths are now built from the resolved root (a symlinked
  BELAY_STATE_DIR is followed once, checked, and not re-resolved).
- **D2 -- fixed.** Every ancestor of the resolved root: owned by the user or root, and not
  writable by others unless sticky (group write allowed for the user's own group); the root is
  re-stat'ed after realpath and must be the directory checked. Test
  `a_state_root_others_could_swap_is_refused` (0777 parent -> 3; 1777 -> 0). Canary: KILLED.
- **D3 -- fixed (signal), limit unchanged.** `prefilter.reference` ("none" / "walk_start" /
  "newest_ctime") in --json and meta.json (schema updated); text output says when the weaker
  point was used. Test: `mark_says_when_it_reads_every_file` asserts walk_start. The reviewer's
  mutation (previous_start = 0): KILLED. Fallback mode itself has no test (needs two
  filesystems in CI); the hole is documented.
- **D4 -- (b) fixed, (a) documented.** A trusted copy is recorded only when no writer is present
  (`writer_present` on the fd, as a full capture does). Test: `a_mark_keeps_the_copies_a_full_capture_would`
  (writer at the mark). Canary: KILLED. (a), a claim lost on a stored file: a full capture would
  sniff; doing so for every trusted stored file costs a read of each (the nm100k mark is mostly
  such files), so the copy is kept and docs/cli.md states the difference.
- **D5 -- fixed.** meta.json must hold an integral id, a known kind and a UTF-8 reason (else
  exit 4); kind/reason/root/scope/error lines printed through the receipt's escaping
  (`receipt_fputs`). Test `nothing_printed_back_forges_a_line`. Canaries (kind, id, reason, error
  line): each KILLED.
- **D6 -- fixed.** U+00AD, U+061C, U+200B-U+200F, U+2028-U+202E, U+2060-U+2064, U+2066-U+206F,
  U+FEFF escaped as bytes. Test `invisible_and_invalid_bytes_are_shown_and_a_type_change_is_said`
  (also overlong, surrogate, > U+10FFFF, DEL). Canary: KILLED.
- **D7 -- documented** (ids end at 999,999,999, exit 4); test in
  `ids_run_out_and_a_failed_diff_leaves_nothing`. A planted directory needs the user's uid.
- **D8 -- fixed:** type change said with privilege (canary KILLED); a too-long state root is 3; a
  relative BELAY_STATE_DIR is refused, 3 (canary KILLED); docs say 76 bytes; id 1.9 is corrupt;
  diff of a scope never captured creates nothing (canary KILLED).
- Suspicions: `ferror(in)` now checked after the copy (exit 4); the write-failure message names
  errno only when fflush set it. store_has's same-size corruption: left (readers verify on read).
- Test gaps left: the "waiting" line (stderr of forked children not captured); a root owned by
  another uid (needs a second uid); fallback mode (needs two filesystems).

Also found in CI after these fixes, not by the review: on macos-portable,
`concurrent_first_captures_all_succeed` failed once (5 of 6) and
`odd_checkpoint_names_and_long_meta_are_handled` could not make its 1,566-byte path (PATH_MAX
1,024). Fixed in the commits that introduced them (history of this PR rewritten, trees verified
equal to the fixed heads): the lock file now made O_EXCL, else the existing one opened -- the
failing children said "cannot open .../lock" once their stderr was flushed (decision-log R27; a
first guess, clearing O_NONBLOCK before flock, did not fix it); the test runs 20 rounds; 4 macOS
runs after the fix, 0 failures in 80 rounds. The path sized by PATH_MAX.
