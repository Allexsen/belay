# Adversarial review of NOTES/watch-structure.md, second version

## Verdict

Not ready to approve as written, but close. The second version answers most of the first report in its text. The scoped claim and the seven-stage order are sound for a single kill at any stage. What remains falls into four groups:

- **Q5 does not give verify one rule.** A directory's index flag still raises a `protected_path_written` violation (exit 1). I ran it.
- **The watch dialect cannot express the PR #125 list or its README examples.** The fix the list needs (`**/` in front of most rows) makes the "coverage lost" flag fire for any exclude at all. I ran the covers test.
- **The call model is missing what the dogfood hooks already had to learn.** Denied and interrupted calls never get a `--finish`, and background commands are not modelled.
- **Four mechanisms are named but not designed:** the deadline, trimming the record, the "shown" note, and what an absent `.belay-donttouch` means. Each has a case where the text as written gives a wrong or endless line.

How I worked: read-only on the repository (main, 9c6c7b3) and the 690e902 worktree. Runs used `git archive HEAD` unpacked into a `mktemp -d` directory under the scratchpad, built after `make clean`, on Linux x86_64 (WSL2, ext4). The copy is deleted. No network.

## A1-A13 and B of the first report

| Item | Status | Where, and what is left |
|---|---|---|
| A1 state removed | answered | Section 5: "A first step always says so ... flagged." Residue in N9 (plugin enabled in mid-session). |
| A2 lines consumed | answered in scope | Section 1 scopes it out; section 5 "Only the adapter writes a 'shown' note". The mechanism has problems: N6. |
| A3 a step that cannot finish | answered | Section 5's table. The deadline behind three of its rows is not designed: N4. |
| A4 excludes | partly | "A step is flagged when the two manifests' excluded sets differ" answers the first half. The covers half is not well defined and over-fires: N2. "A non-directory sitting at a pattern's prefix" has no sentence. |
| A5 protect spec v3 | answered | Q1, the author's decision 1. |
| A6 two files | answered | Section 4, stages 5 and 6 and the three bullets. Trimming reopens it: N5. |
| A7 symlink flag | answered | Section 6, the author's decision 2. A retargeted symlink is dropped without a word: P3. |
| A8 list not always available | partly | Section 6, "Read only from the checkpoint's stored, hash-checked copy". An absent file is undefined and one sentence overclaims: N7. |
| A9 pattern cost | answered | Section 6 limits, measurement promised. |
| A10 turns and sessions | partly | Decision 197: answered by `mark` and `summary`, subject to a probe that is not listed (N3). Decision 185: cited, but background commands and unfinished calls are not handled (N3). Session field: answered. |
| A11 prune | partly | Q7 and the state-retention row. What trimming must keep, and PR-6, are missing: N5. |
| A12 Q5 | partly | One rule, §5.3 and a measurement are there. The rule covers one of verify's two uses of `iflags`: N1. |
| A13 process | partly | Pins listed; decision 184 applied to Q4; probes listed. The model change Q5 needs is not in section 12: N1. |
| B Q3 decoys | answered | Q3, counts for every kind. |
| B hand-written file | partly | Section 6 makes CRLF, `/x`, `x/`, `?`, `[`, `\`, `!` invalid. `*.lock` stays a silent under-match, and a bare directory name is worse: N2. |
| B Q4 except, `.git` file | answered | Q4. |
| B Q10 case | answered | Q4. One sentence is wrong for except patterns: P8. |
| B F15 | answered for the binary | Section 2. The shell wrapper can still exit non-zero: P9. |
| B Q8 PATH | answered | Q8. It conflicts with §5.1.1 as written: N11. |
| B Q2 | answered | Section 5 and Q2. |
| B dropped: first-run download | answered | Sections 2 and 12, step 8. |
| B dropped: "said once" | answered | Replaced by "repeated at every Stop" (decision 114); `$HOME` once per session. |
| B dropped: 400-line cap | answered | `--max-lines`. |
| B dropped: "N under dir/" | not answered | No sentence. |
| B dropped: PostToolUseFailure | not answered | The event list is `start|pre|post|prompt|stop|receipt`; nothing says failure maps to `post`. |
| B dropped: what `start` does | partly | Implied by `--first-ok` and Q7's prune; never stated as a list. |
| B `--json` | answered | Section 3, "on purpose". I object to the choice: N11. |
| B agent-neutral | answered | "call", Q9, markers. |
| B latency | acknowledged, not solved | Section 9. |
| B ledger line size | answered | Q7, 64 flagged paths. |

## New objections: must change before approval

### N1. Q5 gives `privilege_changed` one rule and leaves verify's violation as it is

- **What is wrong.** The author's decision 3 is one rule for watch, the receipt and verify. The proposal changes `privilege_changed` only, and says "No change to the protect spec". PS-M1 makes `metadata_only` with `iflags` in `changed` a `no_write` violation (protect-spec.md:49, policy.c:486-491). A protected directory that grows therefore fails a run.
- **How established: by running.** Spec `{"path":"tests/**","mode":["no_write"]}` (no `no_create`), `baseline export`, then 450 empty files created in `tests/`, then `verify --exit-code`:

      lsattr -d proj/tests   before: --------------e-------   after: -----------I--e-------
      verify rc=1
      {"flag":"protected_path_written","level":"violation","path":"tests","rule":"tests/**","outcome":"metadata_only","changed":["iflags"],...}
      {"flag":"privilege_changed","level":"signal","path":"tests","what":"iflags","before":"524288","after":"528384",...}

  After Q5 as worded the signal goes and the violation stays. pybelay's `reward` multiplies by 0 on a violation by default (reward.md RW-5, as the first report cited).
- **Also inconsistent, by reading.**
  - The receipt names inode flags only for a record that has `changed` (receipt.c:198). A file added with the immutable flag is not in the privilege section, while policy.c:763-765 reports it. docs/cli.md:295-296 says "inode flags ... on a file changed, added or removed". Q5 is silent on added and removed entries, so the three places still differ after it.
  - docs/cli.md's receipt paragraph changes with Q5. Section 8's docs row lists only the new commands and Q8.
  - The independent model implements `privilege_changed` for entries on both sides (model.py P3, P4) and is a required CI job (ci.yml:48). The Q5 code cannot merge before the separate author changes the model. Section 12 lists a model change for the watch dialect only.
- **Should say instead.** Q5's rule is stated once and applied in four places: PS-M1 (a protect-spec pin change, or a row in policy-v1 that overrides it for directories), `privilege_changed`, the receipt's privilege section, and watch. It states what each does for an added or removed entry. Section 8 gains the protect-spec row and the docs/cli.md receipt sentence. Section 12 gains "the model's Q5 change, by its separate author" before the Q5 code.

### N2. The watch dialect cannot hold the list it is meant to carry, and the covers rule fires for any exclude

- **What is wrong, part 1: two semantics of PR #125 are dropped without a word.** PR #125's patterns matched at any depth when they had no slash, and "a match on a directory covers everything below it" (sensitive.txt:5-9, README.md:62-64). Its list depends on both: `.env`, `*.pem`, `.claude`, `.husky`, `.ssh`, `CLAUDE.md`. Q1 defines the watch dialect as the protect grammar with dot-names matched. In that grammar `.claude` matches one entry, the directory itself, and `CLAUDE.md` matches at the top level only (protect.c:79-112). "The PR #125 list plus the review's gaps" (Q4) is therefore a rewrite of every row, not a copy.
- **The same holds for the user's file.** `migrations` and `tests/fixtures` are the README's own examples. In the watch dialect `migrations` is valid and flags the directory entry and nothing below it. Section 6 makes `docs/` and `/LICENSE` loud errors and leaves this one silent. A user lists `migrations`, the agent edits `migrations/0001.py`, and no flag is raised: a careless change the claim says is caught.
- **What is wrong, part 2: the rewritten list makes "coverage lost" permanent.** Any-depth rows must start with `**/`. A pattern that starts with `**` is covered by every directory (protect.c:86-87, 93-94, 114-120).
- **How established: by running**, today's matcher, spec with `**/.env`:

      belay exclude --scope P --add node_modules      rc=0
      belay baseline export --scope P --out B --protect spec.json
      belay: refused: node_modules is excluded, and protects nothing from being seen: it covers the protected **/.env (protect-spec PS-C2)   rc=3

  In the watch dialect the dot rule is off, so `.venv`, `.cache` and a state directory inside the scope cover it too (the first report ran that, A5). Under section 5, the first step of every span is then flagged for anyone with any exclude, any unreadable directory or any mount. Excluding `node_modules` is also the only remedy for section 5's "this directory is too large" line.
- **Not defined, by reading.** "The same covers test" has no meaning yet for a row with an except-pattern (is `.claude/worktrees` excluded a loss of coverage for `.claude/**` except `.claude/worktrees/**`? That needs "every path below it is excepted", which `protect_covers` does not compute), for a file-only row, or for case-insensitive rows.
- **Should say instead.**
  - Whether the watch dialect has "a match on a directory covers everything below it". If yes, that is a second switch beside the dot rule and belongs in Q1. If no, a pattern that names a directory needs `/**`, and section 6 says how the user learns that (for example: a pattern that matches only directories in the current checkpoint is reported as a problem).
  - That the built-in list is rewritten, with the rewritten rows in the pin.
  - A coverage rule that does not fire for every exclude. For example: flagged in the step where the excluded set changes (already there), then said once per session, unflagged, with the excluded paths named; flagged again only for an exclusion whose own path matches a row or lies below a root-anchored row.
  - The covers test for except, file-only and case-insensitive rows, or a statement that it ignores them.

### N3. The call model has no answer for calls that never finish, or for background commands

- **What is wrong.** The dogfood hooks record, checked against Claude Code 2.1.318 (receipt.py:17-24, belay-dogfood:8-22):
  - a call that was denied or blocked by a hook gets no PostToolUse; it is listed in PostToolBatch and "closes where it opened";
  - a call the user interrupted gets no post and no batch; the next prompt or Stop closes it;
  - a background command's end is seen through /proc, on Linux only.
- **By reading the proposal.** The adapter's events are `start|pre|post|prompt|stop|receipt`. There is no batch event and no rule that closes a call. A denied call stays open, and "a step's changes are attributed to the calls open during its interval" then credits it with every later change of the session. The core has `--finish ID`, which steps now; it has nothing that closes a call at the point it opened.
- **Decision 185 is cited as answered and is not.** Decision 185 is about a background command and a foreground call open together. A Bash call with `run_in_background` gets its post at once and the process keeps writing. Under the proposal its later writes go to whichever call is open, or to none, with no "(a background command was also running)". That is the turn-3803 defect in reverse.
- **The 197 answer rests on an unprobed fact.** The adapter marks at each `prompt` event. Decision 197 found the user's message in the transcript ("origin.kind human; task notifications are not"), not from an event (receipt.py:1120-1137). If UserPromptSubmit fires when a background task wakes the agent, the marker moves and "nothing changed" returns. Section 9 does not list this probe.
- **Other probes section 9 lacks:** that pre and post carry one matching call id; what closes a denied call; whether `systemMessage` is shown for each of the six events (the "shown" note's meaning depends on it); what SessionStart's `source` is on resume, clear and compaction (listed), and whether the plugin gets a SessionStart when it is enabled in a running session.
- **Should say instead.** How a call is closed without a post (a batch event, and close-at-prompt and close-at-Stop for the session's open calls); a core operation that closes a call where it opened; whether background commands are modelled, and if not, that decision 185 is not carried over and what the line says; the missing probes added to section 9.

### N4. The deadline is named, not designed

- **What is wrong.** Three rows of section 5's table and section 6's "the deadline bounds it regardless" depend on a timer that stops a capture. By reading:
  - Capture is one synchronous call with no cancellation (state.c:888, manifest.h options; `grep` finds no signal handler, alarm or timer in src/ outside fsops_linux.c's SIGIO probe).
  - The lock wait loops on EINTR (state.c:424-425), so a timer signal does not end it. `state_open` is shared by every command.
  - Section 1 says "not in this proposal: any change to capture". So the timer must end the process from a signal handler, or a parent must kill a child. A handler can only `write` a prepared buffer and `_exit`: the line, and for the adapter the hook's JSON reply, must be built before the capture starts. Neither is stated.
  - A timer that fires during stage 6 produces the torn line itself. A timer that fires after stage 6 and before the print reports "could not record" for a step that was recorded.
- **What a killed capture leaves, by running** (60,301-entry tree, `timeout -s KILL 0.15 belay check`, three times): three `checkpoints/N` directories with no `meta.json` and a `store/.tmp-*` file; the next `mark` took id 5 and worked; `prune --dry-run` said "would remove 3 unfinished directories". So a deadline kill is safe for state. With `timeout -s ALRM` belay died with no output (rc 124): the default action prints nothing.
- **The cost of a cause that lasts is not bounded.** On a tree that cannot be captured in time, every hook waits the full deadline and then fails: two deadlines per tool call, and one more at every prompt and Stop, for as long as the plugin is installed. The deadline's value is not given. PR #125's timeouts were 60 s.
- **Should say instead.** The mechanism (handler with a prepared reply, or parent and child, and who holds the lock); that the timer is disarmed before stage 5 or 6; the deadline's value against the hook's timeout; a back-off (after K steps that hit the deadline, stop capturing until the next session and say so at every Stop); and that `state_open` gains a bounded wait, listed as a change to existing code.

### N5. Trimming the record is not designed, and it can undo sections 4, 5 and 6

- **What is wrong, by reading Q7** ("it trims ledger lines and receipt sections older than its limits"):
  - **Offsets.** Step lines hold their section's offset. Cutting sections from the front of the receipt file moves every later offset, so the ledger must be rewritten too. Two files cannot be replaced in one atomic step. A prune killed between them leaves step lines whose offsets point at other bytes; their digests fail and `receipt` omits them. Section 11's kill points cover the step only.
  - **What must never be trimmed** is not stated: the last step line (it is the cursor), the list in force, the lines of calls still open, a marker an open span uses, and steps not yet shown. A project left for more than the limit loses its last step line, and the next step is then a "first step": flagged "recording starts here" for a project that was recorded all along, or plain if it is a session start, with a week of changes in no line.
  - **The list in force against PR-6.** Section 6 says the list "is recorded in the ledger". If the ledger holds its digest, the store object is swept once no remaining manifest names it (state-retention PR-6: "an object none refers to is removed"), which is the case as soon as the file is deleted or made invalid and a week passes. If the ledger holds its bytes, a ledger line is up to 64 KiB and `--json` prints it. The proposal does not say which.
  - **"Append-only"** (section 4) and "trimmed" (Q7) cannot both describe one file.
- **Reading cost.** A step must find the cursor, the list in force, the open calls, the unshown steps and the last attempt. Only the first is at the end of the file. Nothing bounds the rest short of reading a week of lines at every hook.
- **Should say instead.** A layout in which trimming is deleting whole files (for example one receipt file and one ledger segment per day, a step line naming its segment); the list of what is never trimmed; where the list in force's bytes live; that every step line carries the running state a later step needs, so a step reads only the tail; a kill-point test for prune; PR-6 and PR-7 added to the state-retention row. The ledger and receipt trimming is on the blast-radius list (§0.4: "cleanup of state dirs") and should be named as such.

### N6. The "shown" note

- **No command writes it.** Section 3 lists `step|mark|summary|receipt|patterns`. "Only the adapter writes a 'shown' note" means `hook_claude.c` reaches past the agent-neutral commands. A second harness that uses `watch step --json` can never mark anything shown, so every line it gets repeats every earlier flagged step, growing until prune trims them.
- **It is at least once, not exactly once.** The note is written after the reply, so after the lock is released in stage 7. That is a second wait for the lock in every hook that printed something. If that wait fails or the hook is killed between the reply and the note, the flags are printed again. Section 1's "a change is in exactly one line" should read "at least one".
- **"Written" is not "seen".** Whether Claude Code shows `systemMessage` for each event is not probed (N3).
- **The cases it serves are mostly outside the scope.** Section 5 says it covers "a killed hook and a person running `belay watch step` by hand". Section 1 puts running `watch` oneself outside the claim. That leaves a hook killed after stage 6, which the Stop summary already covers if the summary names the span's flags.
- **Should say instead.** Either drop the note and state that the Stop summary names every flag of its span (smaller, no second lock, no repeats), or keep it and add the command, the at-least-once wording, and the rule for a step with changes and no flags.

### N7. The don't-touch list: an absent file, an overclaim, and a missing row

- **An absent file is undefined.** By section 6's own text, "no stored copy ... means the file is invalid", and a deleted file has no stored copy. Then deleting `.belay-donttouch` gives a flagged line at every Stop for ever, with the old list in force for ever, and "naming the line number" has nothing to name. If instead absence is a valid empty list, deleting the file removes every pattern from the next step on.
- **One sentence is false as written.** "So an agent cannot unflag a change by editing, emptying or breaking the list, in that step or a later one." A valid edit that removes a pattern replaces the list. From the next step the removed pattern does not apply. Only breaking the file keeps the old list.
- **The file itself is not said to be flagged.** PR #125's README: "A change to the list itself is flagged." Section 6 and Q4 have no such row. The claim for the case above rests on it: the step that removes a pattern must say so.
- **"No stored copy" has causes that are not the user's.** A store failure records the entry without a copy and the capture goes on (capture.c:469-476, 482-486, 521-523). An editor holding the file open does the same (capture.c:466-467). Calling the file "invalid" then blames the wrong thing. The NUL rule is only for the first sniffed bytes (capture.c:31-36, 68-71), so the reader needs its own NUL check.
- **Should say instead.** Absent means an empty list, and the step that deletes or changes the file flags the file itself, kind don't-touch, with both lists applied in that step. The overclaiming sentence is cut to what holds. "Could not read the list (why)" is a different line from "line N is invalid". Whether `#` comments and blank lines are allowed.

### N8. Whether a step with no changes writes a step line

- **What is wrong.** Section 3: `step` "prints one line if anything changed". Section 4 does not say whether stage 6 happens when nothing changed. If it does not, the attempt line of stage 3 is followed by no step line, and the next step says "the previous step did not finish" after every quiet step. If it does, the ledger gains two lines and the stages' syncs for every hook of every read-only call.
- **How established:** by reading sections 3, 4 and 5.
- **Should say instead.** Every step ends in a step line (or a "done" record), empty or not, and the cursor moves. Then state the cost. On this machine an append and fsync took 1.2 ms at p50 (200 runs, ext4 on WSL2), so three or four per hook is small beside the capture.

### N9. "Not noticed" is incomplete

By reading, each of these is a careless change that is in no line and in no "could not record" line, and section 5's list has none of them:

- **Under a path excluded on both sides.** No record exists (diff-v1.md:140-144). An install into an excluded `node_modules` is the plain case.
- **What `mark`'s prefilter is documented to miss** (docs/cli.md:272-281): with the state directory on another filesystem than the project, a same-size rewrite within a timestamp tick during the previous walk; coarse timestamps. The default state directory is under `$HOME`, which is often another filesystem than the project. The proposal does not say whether a step captures as `mark` or as `check`.
- **After the last hook of a session.** A background process that writes after the final Stop is seen only by a later session's first step, if there is one. The adapter has no SessionEnd event; the dogfood hook has (`end`).
- **A session start, any session's, after the state was removed.** Section 5 says "the session restarted". A second session opening in the directory, or a SessionStart on resume or compaction if the adapter passes `--first-ok` for those, does the same.
- **The reverse misfire.** A plugin enabled in a running session has had no session-start event, so its first line is the flagged "recording starts here" on a brand-new, untouched record. Unverified whether Claude Code fires SessionStart then; it should be probed and the line's wording chosen for it.

### N10. What a summary counts is not defined

- **What is wrong.** "`summary` totals every step since a marker." A file edited in five steps is five changes or one. Decision 197's line is "N paths changed since your message", one diff over the span. A step line names at most 64 flagged paths and counts the rest (Q7), so the distinct paths of a span cannot be computed from step lines. Q7 also says prune keeps "a marker's [checkpoint] that an open span needs", which implies a diff from the marker, which in turn hides a change made and undone inside the span.
- **How established:** by reading section 3, Q7 and decision 197.
- **Should say instead.** Which of the two the number is, what a marker records, and what the summary prints when nothing changed (decision 156 requires a line).

### N11. Proportion: two things the scoped claim does not need

- **The ledger line as a pinned public format.** Section 3 makes it public "on purpose". Section 1 puts other agents' adapters outside the proposal, so the format has no second reader. Sections N3, N5 and N6 each change the record. The precedent in this repository is the opposite: ST-3, "its format belongs to the state directory: no one outside belay reads it". §0.7 asks for "no speculative abstraction for features that do not exist yet". Smaller: `watch-v1.md` pins the lines' text, the lists and the file's rules; the ledger stays internal and versioned; `--json` waits for a second consumer.
- **Q8's "resolved path inside the scope is not run".** It defends against an agent that puts a `git` on PATH, which section 1 puts outside the claim. It changes `belay diff`. And it is a resolve-then-use containment check, which §5.1.1 says the project deliberately does not provide ("racy by construction"). It needs the author's reading of §5.1.1, as A7 did, or it can be left out of this proposal.
- **The smallest set that delivers the claim, as I read it:** the step under the lock with the cursor in the ledger, the attempt line and torn-line repair; flags from manifest fields; the two lists; section 5's failure lines with a designed deadline; the adapter with call closing; prune keeping the cursor. Not needed for it: the "shown" note (N6), offsets and digests of receipt sections if sections are files (N5), `patterns`, `--json`, Q8. The proposal's section 13 says the size is large and gives one reason (the shell hook was rejected). It should say which parts serve the claim and which serve a second adapter.

### N12. Sequencing

- **Step 5 before step 6 builds the A12 state.** `flag.c` (step 5) applies the Q5 rule; the receipt and policy get it in step 6. Between them the line and its own full receipt disagree about a directory's inode flags. If the Q5 measurement changes the rule, `flag.c` has been written against a rule with no pin. Put the Q5 pin, the model change and the receipt and policy code before `flag.c`, and the policy-v1 pin before watch-v1.
- **The model step is larger than "the watch dialect added".** The model's harness is black-box over `baseline export` and `verify` (run.py:2). A watch dialect has no surface there until `belay watch` exists, so step 3 can be written and cannot be run before step 5. Say what it is run against.
- **§0.7 asks for "the interfaces between them".** Section 2 gives each module's job and no interface.

## New objections: can be settled in the pins or during implementation

- **P1. No measurement of list noise.** Section 9 measures inode flags only. Any-depth `*.pem`, `*.key` and `.env.*` rows match files inside installed packages, and decision 2 flags every directory or file a tool replaces by a symlink. Unverified how often; run the recorded `npm install` and `pip install`, and a `pnpm install` over an npm tree, through the list and put the table in the pin, as for Q5.
- **P2. Dropped from PR #125 and still unsaid:** "N under dir/"; the PostToolUseFailure mapping; "three changes or fewer are named"; whether a receipt section is `diff --all` (nothing folded); `#` comments in the list.
- **P3. A retargeted symlink.** PR #125 flagged one retargeted to an absolute path or through `..`. Decision 2 speaks of replacements and new links. Section 6 drops retargeting without saying so.
- **P4. A cursor checkpoint that is there but unreadable.** Section 5 has a row for "gone". A corrupt one makes every diff fail (exit 4), so "could not record" repeats with no recovery. Treat it as gone.
- **P5. A step line whose section fails its digest.** "`receipt` prints only sections ... whose digest matches" omits it silently. Print that the section is missing. On macOS belay's fsync does not reach the disk (fsops_macos.c:100-109, 134), so stage 5 before stage 6 gives no ordering there after a power loss.
- **P6. Repair.** A line of NUL bytes after a power loss is complete by the newline rule and unparseable. Cut back to the last line that parses instead of "nothing before HH:MM". Every writer of the ledger (`mark`, the note) must repair before it appends.
- **P7. Prune at session start holds the lock** (PR-9) while the first hooks run. On a large state that is a flagged "could not record" every day. HK-1 runs it at a Stop. It also removes the user's own unkept checkpoints of that directory older than a week; the README should say so.
- **P8. "Can only over-flag"** (Q4) is false for an except-pattern matched case-insensitively: it exempts more. Match excepts case-sensitively.
- **P9. F15.** The wrapper is still shell. PR #125's exit 2 came from `set -u` in sh (F15). "Impossible" in section 10 holds for the binary only.
- **P10. Lines whose reason is wrong.** A deadline that fires while patterns are matched prints "this directory is too large". Parallel calls queue on the lock, so a step can print "another belay holds this directory's lock" when the holder is its own sibling. Both are flagged.
- **P11. `receipt --session S`.** Steps are shared between sessions, so a session's receipt holds the other session's changes and lacks its own that the other's hook recorded. Say so or drop the option.
- **P12. The checkpoint's kind.** `meta.json` accepts `check`, `mark`, `diff` (state.c:510). A new kind makes every older belay (the dogfood hooks pin one) refuse the state as corrupt. Use `mark`.
- **P13. Limits.** 256 patterns of 4,096 bytes are 1 MiB; the 64 KiB store limit is the one that binds. No limit on `*` within a component; bounded by NAME_MAX in practice. Measure as promised.

## Checked and found sound

- **The seven-stage order for a single kill** (by reading section 4 against state.c): the cursor moves only at stage 6; a kill at 3, 4 or 5 leaves an attempt line and the same interval for the next step; an orphan section is never printed; a torn attempt line is cut by repair and costs nothing.
- **A killed capture leaves valid state** (by running, N4): unfinished directories are not checkpoints (state.c:575), ids are not reused, prune removes them (prune.c:227-246).
- **"Read only from the stored copy" is implementable** (by reading capture.c:400-447): a small text file with no writer gets a copy on a full read, and on `mark`'s shortcut the copy is recorded when the store holds it, else the file is read.
- **Manifests and `meta.json` are synced** when published (state.c:231-243, fsops.h:94).
- **Q1** keeps PS-P1 to PS-P4 and PS-C2 as they are; protect.c's two dot conditions (lines 55, 94) are the only places the switch touches.
- **Q3**: twelve kinds, three names, a count per kind; no decoy removes a kind.
- **Section 8 lists state-retention** PR-3, PR-9 and DC-1, which A11 asked for.
- **Cost of the syncs**: 1.2 ms each here (N8).
- **PR #125 does not touch src/** by its review's file list, so moving `protect.c`'s matcher does not collide with it.

## Could not check

- Anything about Claude Code itself: the events on resume, clear and compaction; whether UserPromptSubmit fires on a background wake; whether `systemMessage` is shown per event; hook concurrency; what a timed-out hook's children do. The dogfood comments cited in N3 are the repository's own record, dated 2026-11-04 against 2.1.318; I did not re-run them.
- macOS, and a filesystem other than ext4 (the index flag in N1 is ext4's).
- Other open pull requests that might touch `src/policy/protect.c` (no network).
- Any behaviour of `watch`: no code exists, so N3 to N10 are from the proposal's text against the code it builds on.
- How often the noise in P1 and P10 occurs.
