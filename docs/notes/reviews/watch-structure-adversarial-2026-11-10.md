# Adversarial review of NOTES/watch-structure.md (`belay watch`)

## Verdict

Not ready to approve as written. The move into the binary is right, and it does close F2, F3, F5, F8, F10, F13 and F14. The central claim of section 4 does not hold in five cases, three of which I ran against the current binary:

- Removing belay's state (the review's own F4 reproduction) removes the ledger with it, so the next step is a silent first step.
- The agent can consume lines with belay's own `watch step` and `watch end`.
- A step that cannot finish (lock held, timeout, corrupt state) says nothing, indefinitely.
- An exclude the agent adds makes later changes produce no diff record at all.
- The receipt and the ledger are two files with no stated way to detect disagreement.

Separately, Q1 (protect spec version 3) costs far more than the proposal says, and its proposed evidence cannot show anything.

How I worked: read-only on the repository and the 690e902 worktree. Runs used a copy in a `mktemp -d` directory, built after `make clean`, on Linux x86_64 (WSL2, ext4); the copy is deleted. During the review another process moved the repository from `ci/inspect-acp-bound` (786f371) to `main` (9c6c7b3); `git diff 786f371 9c6c7b3` is empty, so every citation holds for both.

## A. Must change before approval

### A1. Removing the state is a silent restart; F4 is not closed
- **What is wrong:** Q7 puts the ledger in the scope's state directory. The review's F4 reproduction is `rm -rf $T/state` in the same call as planting a hook. After it there is no ledger, and section 3 says "The first `step` in a directory begins the record", so the step cannot tell "state removed" from "never watched". Section 4's "belay's state was removed ... prints a flagged line" has nothing to implement it. PR #125 at least kept its cursor outside the state directory.
- **How established:** by reading the proposal (sections 3, 4, Q7) against review F4.
- **Should say instead:** the first step of a record always prints a line ("recording started HH:MM; earlier changes are not accounted for"). The adapter flags that line whenever it is not the answer to a SessionStart. State plainly that a same-user process that also wipes the adapter's own memory cannot be detected.

### A2. The agent can consume lines with belay's own commands
- **What is wrong:** `watch step` and `watch end` are public and carry no caller identity. An agent that runs `belay watch step --scope .` in its Bash call gets the line on its own stdout; the hook's step then finds nothing. If it also runs `belay watch end`, the turn is closed and the real Stop reports an empty turn. Appending a ledger line whose "to" is a checkpoint the agent made with `belay mark` does the same. "The cursor is the ledger's last line" detects a missing checkpoint, not a valid forged one. "1 earlier line was not shown" has no stated mechanism: the ledger is "one line per step" and nothing records that a line was shown.
- **How established:** by reading (sections 3 and 4). State files are 0600/0700 for the same uid (state.c:143, 219).
- **Should say instead:** scope the claim: "unless a process running as the user writes belay's state or runs `watch` itself". Record "shown" as a ledger record written only by the adapter. The next hook line must repeat the flags of unshown steps, not only count them. `end` must print every step of the turn that was not shown.

### A3. A step that cannot finish says nothing, for as long as the cause lasts
The proposal covers "killed once, next step covers the interval". It does not cover causes that persist. All of these ran on the current binary:

| Cause | Command | Result |
|---|---|---|
| Lock held by any same-user process | `( flock -x 9; sleep 6 ) 9<>$SD/lock &` then `timeout 3 belay mark` | `belay: waiting for another belay working on ...`, rc=124. state.c:424 blocks with no timeout. |
| Checkpoint ids exhausted | `mkdir $SD/checkpoints/999999999; belay mark` | `no checkpoint ids left`, rc=4 (state.c:568-570, 812) |
| One bad meta.json | `mkdir checkpoints/7; echo garbage > checkpoints/7/meta.json` | `mark` and `log` both rc=4 |
| Scope file edited | `echo /elsewhere > $SD/scope` | rc=4 |

- **Legitimate holders of the lock:** a `belay prune` second pass, a user's `belay check` on a large tree, the dogfood hooks.
- **Capture slower than the hook timeout:** by reading, every step is then killed before the append, the cursor never moves, and no line is ever printed. Section 7's F1 row turns a lost interval into an indefinite silent deferral.
- **Should say instead:**
  - The step takes a deadline from the adapter and prints "could not record (why)" before it expires.
  - The lock wait is bounded.
  - Every failure of capture or diff is a flagged line, as decision 156 requires of a Stop.
  - An attempt marker lets the next step say "the previous step did not finish".
  - Section 4's list of interruptions includes "capture failed".

### A4. An exclude makes changes vanish from every flag
- **What is wrong:** section 5 flags diff records. A path excluded on both sides has no record (diff-v1.md:140-144); only the header names it. `belay exclude` is one command for the agent, or one line in `$SD/excludes`.
- **How established:** by running, in a fresh `git init` directory:

      belay mark; belay exclude --scope P --add .git/hooks     (rc=0)
      belay mark; diff --json   -> 15 records, all "unknown" ["not_captured"]: .git/hooks (dir) and 14 *.sample
      (write .git/hooks/pre-push, chmod +x); belay mark; diff --json
                                -> {"belay_diff_end":0,...}   stderr: not compared: .git/hooks (excluded for this scope)

  Under the proposal's rules the first step flags nothing: `.git/hooks/*` does not match the directory, and Q4 exempts `*.sample`. The second step has no record to flag.
- **Should say instead:** a step is flagged when the excluded set differs between its two manifests, and on every step while an exclusion covers a built-in or don't-touch pattern (`protect_covers`, as PS-C2 does for verify). The same "covers" test is needed for a directory whose outcome is `unknown` (unreadable, mount) and for a non-directory sitting at a pattern's prefix. `.git/hooks` replaced by a symlink to a directory inside the scope is otherwise still unflagged (review F11).

### A5. Q1/Q1a: version 3 of the protect spec is disproportionate, and the proposed evidence is empty
- **It changes PS-C2, which the proposal does not mention.** With the dot rule gone, a rule starting `**` is covered by every dot-named exclusion. Ran with the two dot conditions removed (protect.c:55, :94) in the temp copy, spec `**/conftest.py` + `tests/**`:

      state dir inside the scope: refused: .belay-state is belay's state directory ... covers the protected **/conftest.py (PS-C2)
      belay exclude --add .venv:  refused: .venv is excluded ... covers the protected **/conftest.py (PS-C2)

  Both are accepted by the binary as built. test_protect.c:226 and the model's P26 (model.py:149) pin today's behaviour.
- **The replay re-run cannot show a changed verdict.** The replay's spec is `no_write` on `test.py` and `test_cases.json`, two literal paths with no wildcard (bench/replay/rules.py:19, bench/replay/README.md:47).
- **Who pays:**
  - Every pybelay user with a version 2 spec gets `Refused`, which `reward` turns into reward × 0 by default (reward.md RW-5).
  - Every bundle must be exported again.
  - bench/replay/replay.py:209 probes the version by error text.
  - The policy model is a required CI job.
  - `tests/**` starts matching `tests/.pytest_cache/...`, the noise decision 157 was added to avoid.
- **Should say instead:** keep one matcher implementation with the dot rule as a parameter. The protect spec stays version 2; the watch lists use the no-dot dialect. No verify pin changes. If the author still wants one dialect, the pin must state the PS-C2 consequence and the evidence must come from specs that contain wildcards.

### A6. Two files, no stated way to detect disagreement, and a torn line is treated as loss
- **Killed between the receipt section and the ledger append:** an orphan section is in the receipt and the next step writes the interval again, so the receipt holds the change twice. By reading the stated order (write receipt section, then append and sync the ledger).
- **Power loss:** only the ledger is synced, so a line can survive whose receipt section did not.
- **Partial append (ENOSPC, SIGKILL):** leaves a line with no newline. The proposal's rule for an unreadable ledger is "start again from now", which discards an interval that the previous complete line still covers.
- **Should say instead:**
  - Each ledger line carries the offset, length and digest of its receipt section.
  - The receipt is synced first.
  - `receipt` prints only sections a ledger line names.
  - An incomplete last line is truncated under the lock and the previous line is the cursor.
  - On a lost cursor, diff from the newest surviving checkpoint and say so, rather than dropping everything.

### A7. The symlink flag fires on every virtualenv, and drops coverage PR #125 had
- **False positive, by running:** `python3 -m venv .venv` gives `.venv/bin/python3 -> /usr/bin/python3` with `"target_outside_scope":true`. Every venv creation would lead with a red circle, the same class as F6. Other tools that link outside the project are an unverified concern.
- **The design forbids this use.** `target_outside_scope` is lexical (path.c:175-183), and BELAY_DESIGN §5.1.1 says it "must never drive a decision". Using it for a flag needs the author's explicit reading of that sentence.
- **Coverage lost:** PR #125 flagged any file replaced by a symlink (belay-receipt.awk:159). The proposal flags only those pointing outside, so `tests/test_x.py -> ../always_pass.py` is no longer flagged.
- **Should say instead:** which of these is intended, and an exception rule for the venv case.

### A8. `.belay-donttouch` "as it was before" is not always available
- **What is wrong:** a checkpoint keeps a copy only of a text file of at most 64 KiB with no writer present (manifest.h:40, capture.c:403-405, :422, :428). No copy exists for a file that is larger, contains a NUL, is held open for writing, or is a symlink or FIFO. Reading the live file instead would follow a symlink or block on a FIFO, and races the capture.
- **How established:** by reading; the proposal is silent on all of these.
- **"Invalid file means every line says so" is safe only with a second rule.** Otherwise the agent invalidates the file in step k (one generic red line) and touches a listed file in step k+1, when both "before" and "after" are invalid and no pattern applies.
- **Should say instead:**
  - The list in force is kept in the ledger and stays in force until a valid one replaces it.
  - The list is read only from the checkpoint's hash-checked copy.
  - Anything not a regular stored file is "invalid".
  - There is a cap on bytes and lines.

### A9. "No pattern can take long" is false in aggregate
- **What is wrong:** the matcher is O(pattern components × path components) with bounded backtracking inside a component (protect.c:56-72, 88-103). It is not linear.
- **How established:** by running a harness linked against protect.o. A 4,093-byte pattern of 1,364 `**` components takes 3.5 ms per match against a 2,048-component path, and 26 µs against a 12-component path.
- **Consequence, by arithmetic (not run through a hook):** the proposal sets no limit on lines. 256 such patterns (1 MiB) against 70 deep files is about 63 s, and against a 50,000-record install about 330 s. Both exceed PR #125's 60 s timeout.
- **Should say instead:** limits on the list (lines, bytes, `**` per pattern), and A3's deadline.

### A10. The turn and session model ignores decisions already made on the dogfood hooks
- **Decision 197:** a Stop is not the user's unit. Turns woken by background tasks each end in a Stop, and the line must cover everything since the user's message. `watch end` at every Stop reintroduces "nothing changed this turn" after the work.
- **Decision 185:** attribution needs to know which calls are open. `--outside` is a boolean decided by which hook fired, so with parallel calls or subagents a `pre` hook labels another call's in-flight writes "outside tool calls".
- **"The session's full receipt" (section 3) is undefined.** There is no start and no session id in the ledger. Two sessions in one directory close each other's turns and split each other's totals.
- **Should say instead:** `step` records open and close of a call (agent-neutral), a session or owner field is in the ledger, and it is stated what `end` covers. The adapter owns the turn boundary.

### A11. Q7 needs a fourth pin change, and nothing prunes
- **What is wrong:** state-retention PR-3 protects the newest checkpoint, kept ones and `--keep-from` (prune.c:421). The cursor's checkpoint is not the newest whenever anything else captured since: the dogfood hooks, a user's `belay mark`, or a `diff` without `--to`. "`prune` never removes the cursor's checkpoint" is therefore a change to state-retention.md (PR-3, and PR-9 and DC-1 if the ledger or receipts are ever trimmed). Section 9 lists three pins.
- **Dropped from PR #125:** its daily prune and one-week receipt retention (belay-hook:193-200). The ledger and stored receipts then grow without bound; one large install is megabytes of receipt text.
- **How established:** by reading.
- **Should say instead:** who prunes, what bounds the ledger and receipts, and the state-retention pin PR.

### A12. Q5 conflicts with the design, not only with the policy pin
- **What is wrong:** BELAY_DESIGN §5.3 says of iflags that "no receipt-noise filter may suppress them" and that the policy layer "flags every one of them". Decision 171 narrowed only added and removed files (policy.c:760-765, policy-v1.md:99).
- **The fallback is worse:** "apply the rule in `watch` only" gives a full receipt whose privilege section lists a change the line did not flag.
- **Too narrow, as an unverified concern:** a rule for directories alone may miss the same class on regular files (ext4 inline-data).
- **Should say instead:** one rule for all three (watch, receipt, policy.v1), presented as a change to §5.3 and the pin, with the fp-table measurement that decision 171 had.

### A13. Process
- **Pins that would change:** protect-spec, watch-v1, policy-v1, and also state-retention (A11) and two design sentences (§5.1.1 in A7, §5.3 in A12).
- **Decision 184 applies to Q4.** Every list addition is a claim about an external tool, and the review says they are "from general knowledge, not probed". The same holds for the Claude Code behaviour Q6 rests on, which the review marks "from memory". Probe before the pin.
- **Sequencing:** the policy model is a required CI job (ci.yml:47-48). Step 2 cannot merge until the separate author's model change exists, so section 9 must place that between steps 1 and 2.

## B. Can be settled in the pin or during implementation

- **Q3 is still gameable.** One decoy in each of the first three kinds (a don't-touch entry the agent adds itself, `.git/config`, `CLAUDE.md`) pushes privilege, CI, credentials and symlinks out. Within a kind, the bytewise-first path wins. Give counts per kind after the three names; ten kinds cannot be pushed out.
- **Q1b, hand-written file.** `protect_pattern_valid` (protect.c:35-47) accepts control bytes, so a CRLF file matches nothing, silently. state.c:719-722 fixed this class for excludes. `/LICENSE` and `docs/` are invalid, so the whole file goes red. `*.lock` is valid but root-only, a silent under-match for anyone with gitignore habits. `?`, `[ab]` and `!x` stay silently literal (F12, third bullet). Make those invalid, with the line number.
- **Q4.** The per-row "except" is sound if it exempts only its own row. A `.git` that is a file (a gitdir pointer) is not in the list.
- **Q10.** macOS arm64 is a shipped target, and its default volume folds case. Matching the built-in list ASCII-case-insensitively over-flags only.
- **F15.** belay's usage exit code is 2 (cli.c:55, :126), which is the code that blocks a PreToolUse. `belay hook ...` must return 0 for any argv, before generic parsing.
- **Q8.** The receipt already runs `git` by PATH (gitclass.c:85), and `code` would be the same. If a hook's PATH holds a directory inside the scope (an activated venv), the agent chooses that program. Refuse a resolved path inside the scope. Whether hooks run outside the tool sandbox is unverified.
- **Q2.** Say whether "every command" means `watch` only. Refusing `$HOME` for `verify` or `mark` would be a behaviour change. Say what a dotfiles repository at `$HOME` gets, and how often the refusal is printed.
- **Dropped from PR #125 without a word:**
  - the first-run download ("find the pinned binary" does not fetch);
  - "said once" for repeated problems;
  - the 400-line cap;
  - the "N under dir/" summary;
  - the PostToolUseFailure mapping;
  - what the `start` event does now.
- **`--json` output.** `step --json` prints the ledger record, so the on-disk format becomes the public one.
- **"Agent-neutral".** "turn", "tool call" and "outside tool calls" are in the core commands and in the pinned line text.
- **Latency.** Measured as capture plus `diff --json`:

  | Tree | Entries | Per step |
  |---|---|---|
  | this repository | 2,178 | 0.05 s |
  | synthetic `node_modules` | 60,602 | 1.2 s |

  That is two steps per call, serialized under the lock for parallel calls. R47's 0.1 s target is not mentioned.
- **Ledger line size.** "What it flagged" needs a bound.

## C. Checked and found sound

- **F2:** the lock is taken before anything is read when opened with create (state.c:388-429) and held to close. Read-only commands (`log`, `prune --dry-run`) do not take it (ran: both returned while the lock was held).
- **F14:** the receipt's escaping covers U+200B, U+FEFF, U+2028 and C1 (ran: `a\xe2\x80\x8bb\xef\xbb\xbfc\xe2\x80\xa8d\xc2\x9be`).
- **Manifest fields:** the manifests carry mode, caps, iflags, link target and `target_outside_scope` (manifest.h:59-166). diff.v1 has the `git_history_rewritten` event and the `unknown` outcome.
- **Stored copies** are hash-checked on read (diff-v1.md:303-306).
- **State growth with deltas:** 60 marks of the 60,602-entry tree added 1 MB.
- **F3, F5, F8, F10, F13:** closed by the structure, by reading.
- **Platforms:** belay builds for Linux and macOS only (release.yml:30-32). There is no Windows target to behave the same on.

## D. Could not check

- Anything about Claude Code: whether `systemMessage` is shown for each event, hook concurrency, timeouts, what Stop does on interrupt, sandboxing of hooks.
- macOS.
- File capabilities and `chattr` (need root).
- The ext4 inline-data concern in A12.
- Any behaviour of `watch` itself: no code exists, so A1, A2, A6, A8 and A10 are from the proposal's text.
