> **Note added at export.** Checked against commit 5f46e7c on 2026-11-15: findings 2 and 3 were fixed in 520be72; finding 4 was left as it is.

# Review of PR #129 (inode flags as a privilege change), head 0fea1ea

## Verdict

Safe to release as far as behaviour goes: I found no input where `verify`, `privilege_changed` or the receipt contradicts a pin row in the direction that hides a change the pin says counts, and no path outside IF-2/IF-5 that stopped being a violation or a `privilege_changed` record. diff.v1 records are byte-identical between alpha.6 and this build on the same directory. What is wrong is smaller: one real test gap (the line that feeds the receipt its inode flags can be deleted and every test still passes, while the real `belay diff` then prints the false report the pin removes), one receipt case that contradicts IF-8's letter (a directory that is a privilege change for another reason no longer shows its flag change anywhere), a bisect-skip entry naming a commit that passes, and a cross-platform narrowing. None needs root to matter; none is a regression that hides a locking flag. Everything involving immutable/append-only on a real filesystem I could check only by reading and through the unit tests (no root here).

Head confirmed: 0fea1ea, on top of ff5c576: e636dbe (code), 63aa1d4 (model, touches only scripts/policy-model/), 0fea1ea (bisect-skip). Clean build: `make check` rc 0, `make policy-model` rc 0 (446 scenarios, 389 end to end, 0 disagreements; the 30 `if-` scenarios all ran end to end), `selftest.py` passes, `make check-san` (ASan/UBSan, in a copy) rc 0. Worktree's tracked files untouched (`git status --short` empty); it now holds build/ and bin/.

## Findings

### 1. MEDIUM. Test gap: the receipt's real metadata lookup is untested
Class: a wiring line no test holds.
Mutant m4: delete `m->has_iflags = c->e.has_iflags;` in src/cli/cli.c:496 (the receipt then never learns the flags and falls back to "believe the record"). Result: `make test` rc 0, `make e2e` rc 0, policy-model 0 disagreements. The mutant's `belay diff` on a directory that gained 450 files prints
```
privilege
  ~ tests   inode flags changed
```
which is exactly what the pin removes. Reproduced: scratchpad/review-scripts/mut.sh m4, then check + 450 files + `diff --since 1` with scratchpad/review-mut/m4/bin/belay.
Cause: test/test_receipt.c feeds the receipt from its own table (`table_mode`), and nothing runs the real `belay diff` over a grown directory. The same holds for cli.c:497 (`m->iflags`). The receipt half of the pin's own example ("With it: neither") has no end-to-end test.
Other instances of the class (mutants, same script):
- m1 (PS-M1 gate removed, src/policy/policy.c:502) and m2 (`privilege_changed` back to the old condition, policy.c:778): `make test` passes; only `make policy-model` catches them (11 and 54 disagreements). policy-model is in CI (.github/workflows/ci.yml:48) but not in `make check`. test_policy.c's new test calls `iflags_change_counts` directly and never goes through `protected()` or `privilege()`.
- m3, m5, m6, m7 (receipt gate, type-change rule, added/removed line, IF-5) are caught by the C tests.
- By reading: a directory whose immutable flag is swapped for append-only (16 -> 32, the model's P55) is tested in the model's selftest only, i.e. against the model itself. The C tests use one LOCK bit; a rule written as "holds a lock before != holds a lock after" instead of the XOR at src/schema/iflags.c:16 would pass all of them, and the harness cannot set locking flags.

### 2. LOW. Receipt: a non-counting flag change disappears when the record is a privilege change for another reason (IF-8, IF-9 "nothing is hidden")
Class: a field dropped from display.
Reproduced (ext4, unprivileged): `mkdir sgdir; belay check; chmod g+s sgdir; chattr +d sgdir; belay diff --since 1 --all`.
- alpha.6: `~ sgdir   setgid added (mode 0755 -> 2755), inode flags changed`
- this build: `~ sgdir   setgid added (mode 0755 -> 2755)`
- diff.v1 (both): `"changed":["mode","iflags"]`
The record is in the privilege section, whose line prints only the privilege reasons (src/cli/receipt.c:338-349: when `why.n` is non-zero, `changed_values` is not called), so the `iflags` change is shown nowhere in the receipt, folded or `--all`. IF-8 says a change that does not count "is still shown"; docs/cli.md's new sentence ("a flag change that does not count stays among the other changes") is false for this case. By reading, the same happens with `caps` beside `iflags` on a directory (needs root to produce). A plain `chmod 700` beside the flag change is shown correctly (`~ growmode   mode 0755 -> 0700, iflags`).

### 3. LOW. scripts/bisect-skip.txt names a commit that passes
Class: wrong entry in a list.
The two added lines resolve (`scripts/bisect-skip.sh HEAD`) to e636dbe and 63aa1d4. e636dbe does fail policy-model (reproduced: the model as of e636dbe against this binary disagrees, first on `unverif-unreadable-episode`). 63aa1d4 is the commit that fixes it: its tree is the head's minus this file, and passes. The comment "its first commit until the second" was carried over from the protect-spec-2 entry, where there were two failing commits. A bisect would skip a good commit. Also the file's header says it lists commits that fail `make check`; e636dbe fails `make policy-model`, not `make check` (as the earlier entry does too).

### 4. LOW. A manifest judged on another platform: directories are now judged by the judging platform's mask
Class: platform constant applied to foreign data. By reading; not run (no macOS).
`belay_iflags_locking` is the build's (src/platform/fsops_linux.c:98: 0x10|0x20; fsops_macos.c:67: 0x2|0x4|0x20000|0x40000) and the manifest does not record its platform. Before this PR only added/removed entries went through the mask (decision 171); an entry at both ends counted on any difference, whatever the platform. Now a directory at both ends goes through the mask too (src/schema/iflags.c:15-16): a macOS manifest pair in which a directory gained `UF_IMMUTABLE` (0x2), judged by a Linux build, gives no `privilege_changed` and no PS-M1 violation, where alpha.6 gave both; a Linux pair with immutable (0x10) judged on macOS likewise. Reachable only by moving a state directory or bundle between platforms. Regular files at both ends are unaffected.

### 5. Readings and pin consequences for the author (not code defects)
- IF-4 against IF-5 (a type change with flags on one side). The code follows the model's P56/P57 reading in the two places where it can matter: src/schema/iflags.c:11-12 and so `privilege_changed` (policy.c:778); PS-M1 never asks (a type change is a violation by itself and `changed` is `["type"]`). The receipt says nothing about inode flags on a type change, before or now (`changed` never lists them, O7). Reproduced, a file replaced by a symlink: alpha.6 and this build both give `f2link: iflags 524288 -> none` and the receipt line `T f2link   reg -> lnk`. So all three places are as alpha.6. Consequence of this reading: every regular file replaced by a symlink on Linux still gets an `iflags ... -> none` signal, a report of the same false kind the pin removes; IF-5's last sentence read alone would drop it. The pin's words allow both; the author should say which.
- IF-5 (the model's P58): an entry of one type whose flags were unread on one side and hold a locking flag on the other gives no `privilege_changed`; with no protect rule on the path, verify reports nothing about it. Reproduced for the non-locking case (`chmod 000` on a file: alpha.6 `f_chmod0: iflags 524288 -> none`, now none; `protected_path_unverifiable` unchanged when protected).
- IF-2 covers every non-locking flag an owner can set on a directory, not only the hashed index. Reproduced: `chattr +d` on a directory under a `no_write` rule was `protected_path_written` + `privilege_changed` in alpha.6 and is neither now. By the same row noatime, sync, dirsync, topdir, project-inherit and casefold (which changes how names in the directory are looked up) are silent on a directory. The pin says so in words; I name it because it is the one place where a deliberate change by the watched process stops being a violation.
- The receipt has two new phrases, `inode flags set` and `inode flags removed`, for an added or removed entry holding a locking flag (src/cli/receipt.c:213-214). No pin fixes the wording; IF-3/IF-8 ask for the entry to be named.
- scripts/dogfood/receipt.py:639, 662, 1016, 1057 still treats any `iflags` in `changed` as a privilege change. Not in this PR, by reading only; I did not check what uses it.

## Checked and found fine

- IF-2, hashed index: 450 files in a protected `tests/` gives no `protected_path_written`, no `privilege_changed`, receipt line `~ tests   iflags` under changes (reproduced; alpha.6 gave all three false reports).
- IF-3, non-locking: added directory with hashed index, added file with nodump, removed file: no record, receipt `A`/`D` under changes (reproduced, same as alpha.6).
- IF-4, regular file: `chattr +d` alone and beside `chmod`: violation, `privilege_changed`, receipt `inode flags changed`, as alpha.6 (reproduced).
- IF-4, type change file <-> directory with equal flags: nothing; with differing flags: `privilege_changed` as before (model scenarios `if-4-type-*`, end to end).
- IF-5: `chmod 000` file: outcome `unknown`, reasons unchanged, `protected_path_unverifiable` unchanged, no `iflags` record (reproduced).
- IF-6: directory with `mode` and `iflags` changed: violation, `changed` is `["mode","iflags"]`, no `iflags` signal (reproduced). PS-M1's gate can only see `iflags` in `changed` when both sides have flags and one type, so it cannot drop a violation IF-2 does not name (by reading policy.c:499-503 with O6/O7).
- IF-7: no `iflags` record for the non-counting cases above.
- IF-9: the diff.v1 records of alpha.6 and this build are identical line for line on the same directory (only the end record's manifest digests differ, separate captures).
- Non-UTF-8 path: a grown directory `bad\xff` is looked up correctly and printed escaped (`~ bad\xff   iflags`), no signal (reproduced).
- `--all` and the folded form agree: a non-counting record folds like any other change (`and N more`, `git-ignored: 451 changes under node_modules/`) and `--all` shows it (reproduced, in a git repository too).
- Receipt fallback: with no flags from the lookup the record is believed, so the failure direction is to over-report (by reading receipt.c:189, 211; and m4).
- Receipt added/removed gate `on[0] != on[1]`, struct initialisers, zeroed `m[]` when the lookup fails, `(int)(mode & S_IFMT)` (at most 0170000), `(int)e->type`, `~x + 1` on `uint64_t`: no undefined behaviour by reading; UBSan/ASan clean.
- Manifest `mode` is `st_mode` with type bits (src/capture/capture.c:89), so `S_ISDIR` in the receipt is sound.
- macOS constants: the tests' 0x1000 (unused bit) and 0x80000 (`SF_RESTRICTED`) are outside the macOS mask 0x60006; LOCK there is 0x2. The `REQUIRE` holds on both platforms and fails, not skips, if it does not.
- Accounting: both new test names are in test/accounting/tests/test_policy.txt and test_receipt.txt; nothing under test/accounting/skips changed.
- Model commit: only scripts/policy-model/; selftest passes; P55, P56, P58, P59 match the pin's words; P57 is the stated ambiguity. Its expectations in selftest are hand-written values, not computed from belay.
- The unit tests' expectations follow the pin rows; each new test fails under at least one mutant (m3, m5, m6, m7).

## Could not check

- Immutable and append-only on a real filesystem (no root, no CAP_LINUX_IMMUTABLE): IF-1, IF-2's counting half, IF-3's locking half, the receipt's `inode flags set` / `removed` lines through the real binary, `chattr +i tests` from the pin's example. Read, and covered by the unit tests on `iflags_change_counts` and the fake-table receipt test only.
- macOS: not built or run. Symlinks and devices with flags at both ends (IF-4 on macOS) by reading only.
- `caps` beside `iflags` in the receipt (needs setcap), devices, `--docker`.
- Whether anything consumes scripts/dogfood/receipt.py's privilege count.

Scratch material: scripts in scratchpad/review-scripts/ (s1.sh, mut.sh), scenario outputs in scratchpad/rv.ItEyEW/out, mutants in scratchpad/review-mut/.
