# Check of NOTES/watch-structure.md, third version, against the second adversarial report

## Verdict

Not ready for pins as written, but no redesign is needed: one more short revision of the text. The third version answers N1-N12 in its text, except N4 (the deadline), which is now designed only halfway, and parts of N2 and N5. Three things block, each a few sentences:

1. **The deadline** still has a case that prints a wrong reply, a case that prints nothing at all, and a back-off with nowhere stated to keep its count (problems 1-3).
2. **Per-session state never ends**: a session that dies leaves its calls open for ever, and every step line carries every session that ever ran (problem 4).
3. **The day files**: "a step reads only the tail of the newest file" loses the cursor when that file is empty or damaged, which a kill at the day boundary produces (problem 5).

The rest (problems 6-12) can be settled in the pins, but two of them change what a pin must contain: Q5 leaves two cases open, and pin 3 omits PR-7 and what prune's limits mean for a day file.

How I worked: reading only, on main at 9c6c7b3. Nothing was run and nothing was built. Every statement about Claude Code is unverified; I cite the dogfood hooks where they record a fact.

## N1-N12 and P1-P13

| Item | Status | Where, and what is left |
|---|---|---|
| N1 | answered | Q5: "One rule, in four places ... PS-M1 (`no_write`), policy.v1's `privilege_changed`, the receipt's privilege section, and watch"; pin 1; section 8's docs line; section 12 steps 3 and 4. Two cases left open: problem 6. |
| N2 | partly | Section 6: "a pattern that matches a directory covers everything below it"; "The built-in list is rewritten in this dialect, row by row, in the pin"; section 5's coverage rule; "The covers test ignores a row's exceptions and its file-only limit". "Anchored at the top" and "unrelated" are not defined: problem 7. |
| N3 | answered | `close`; the PostToolBatch and PostToolUseFailure rows; Q6; decision 6 with section 5's last "not noticed" bullet; the probes in section 9. Left: a session that dies, and `--finish` of a closed id: problem 4. |
| N4 | partly | Supervisor and worker, 45 s against 60 s, back-off, "`state_open` gains a bounded wait". Not answered: N4's own "a timer that fires after stage 6 and before the print reports 'could not record' for a step that was recorded": problems 1-3. |
| N5 | partly | Day files, the list in force as a file, running state on every step line, prune's kill point in section 11, the blast-radius sentence in Q7. Left: PR-7 and the limits (problem 8); the newest file damaged (problem 5); the marker of an open span is not in "except the newest and the list in force". |
| N6 | answered | Cut (decision 5). Section 3: the summary names what was flagged. |
| N7 | answered | Section 6: "No file is an empty list"; "A change to the file is itself flagged"; two different lines; `#` and blank lines; its own NUL check. One wording gap: problem 10. |
| N8 | answered | Section 4: "Every step writes a step line", with the cost. |
| N9 | answered | Section 5, "Not noticed": all five are there; SessionEnd is mapped; the mid-session plugin is in the first-step bullet and the probes. |
| N10 | answered | Section 3: "the sum of the steps' counts. A file changed in five steps is five changes"; "With no change it says so". |
| N11 | answered | Decision 5; Q8 reduced; section 13 says what serves the claim. |
| N12 | answered | Section 12 steps 2-4 before 5-6; step 7 says what the model is run against; section 2's "what it offers" column. One circular step: problem 9. |
| P1 | answered | Section 9, "List noise". See problem 9. |
| P2 | partly | PostToolUseFailure, `diff --all`, `#` comments are said. "N under dir/" and "three changes or fewer are named" are not; they belong to pin 4's "the lines' text". |
| P3 | answered | Section 5, "Not noticed": "a symlink retargeted". |
| P4 | answered | Section 5 table: "gone or unreadable, others survive". |
| P5 | answered | Stage 5's barrier; "this step's section is missing". `barrier` exists (fsops.h:97-101, fsops_macos.c:106-109). |
| P6 | answered | Stage 2; section 2: "open under the lock with repair". |
| P7 | answered | Stop, once a day; README. |
| P8 | answered | Q4: exceptions matched case-sensitively. |
| P9 | answered | Section 2 (no `set -u`, exit 0); section 10's F15 row. |
| P10 | partly | The stage is now the reason. The sibling case keeps "another belay holds this directory's lock"; at 45 s it is rare. |
| P11 | answered | `receipt` has no `--session`. The same question now applies to `summary`: problem 4. |
| P12 | answered | Section 3: "recorded as kind `mark`". |
| P13 | answered | Section 6 limits; measurement in the pin. See problem 9. |

## Problems, most serious first

### 1. The deadline can still report "could not record" for a recorded step, and can still hang the hook

- **The race.** "At the deadline the supervisor kills the worker" unless it has reported "committing". The worker's report and the supervisor's kill are not ordered: the supervisor reads the pipe, sees "matching", and kills, while the worker has just entered stage 5 or finished stage 6. That is N4's last bullet, unchanged. By reading section 5.
- **The hang.** "Once the worker reports 'committing' ... the supervisor does not kill it; it waits for the result." Nothing bounds that wait. Stages 5 and 6 are two syncs with a barrier; on a full or stalled disk, or a network home, they do not return. Claude Code then kills the hook at 60 s and no line is printed, which is the silence section 5 forbids.
- **"Milliseconds" is unproven for stage 5.** The section is "`belay diff --all`, nothing folded" and the receipt asks `git` (Q8). If the section is rendered inside stage 5, committing takes as long as rendering. No stage is named for rendering.
- **The worker dying on its own** (a crash, the OOM killer) has no row. "Capture or diff failed: (belay's message)" has no message to print.
- **Should say.** (a) The worker asks before committing and waits for one byte back; the supervisor answers or kills, never both. (b) The section is rendered before that request; committing is two writes and two syncs of prepared bytes. (c) After "committing", the supervisor waits to a second limit below the hook's timeout, then prints "could not confirm the record" without killing. (d) A row: "belay stopped unexpectedly while (stage)". (e) What the pipe carries: the stage, the request, and the final line and status.

### 2. The deadline covers `step` only; a hook event makes two or three lock-taking calls

- **By reading section 3's table.** UserPromptSubmit is `close --all`, `step`, `mark`; Stop is `close --all`, `step`, `summary`, and starts a detached prune that holds the lock (PR-9). `close` and `mark` append to the ledger, so they take the lock. Section 5 gives the bounded wait to the step. If `close --all` waits 40 s on a sibling's capture and the step then takes its 45 s, the hook is killed at 60 s with no line.
- **`watch step` without the adapter.** `--deadline` is optional and no default is given, so whether a bare `watch step` runs under the supervisor, and with what limit, is unstated.
- **Should say.** One deadline for the whole hook event. Simplest: the adapter's calls for one event run in one worker under one hold of the lock (close, step, mark or summary), with the supervisor around all of it. State the default when `--deadline` is absent.

### 3. The back-off's count has nowhere stated to live

- **By reading.** The worker that hit the deadline was killed, so it wrote nothing. The supervisor does not hold the lock, and the ledger is written "under the scope's lock". An attempt line does not say which session made it or why it has no step line.
- **"Until its next start"** has no core meaning: the core has `--session` and markers, no start. If SessionStart with source `compact` or `resume` counts, a long session pays three more deadlines after each compaction.
- **A step in back-off** must write neither an attempt line nor a step line, or section 4's "an attempt line with none after it always means a step that did not finish" and "every step writes a step line" both break. Not said.
- **Should say.** Either the attempt line carries the session, and after a kill the supervisor (the lock is free then: flock on an O_CLOEXEC descriptor, state.c:397, 413) appends "killed at the deadline while capturing"; or the count is a small per-session file the supervisor replaces by rename. Which event clears it, as a core operation. What a step in back-off writes.

### 4. Per-session state has no end, and not every call is eventually closed

- **A session that dies** (terminal closed, crash) fires no Stop and no prompt. SessionEnd maps to `step` only. Its open calls stay in the running state for ever, and every later change in the directory, from any session, is attributed to them.
- **Every step line carries "each session's last marker".** Nothing removes a session. After some hundreds of sessions each step line carries all of them, twice per tool call. The same holds for "once per session" notes (excludes), which also need per-session state.
- **`close --all` at Stop can close a call that is still running.** It is per session, which is right for two sessions in one directory. But a subagent's calls carry the parent's session id (the dogfood hook reads `agent_type` from the same event, belay-dogfood:115; unverified beyond that), and a background subagent outlives the Stop. Its `--finish ID` then arrives for a closed id. The same happens if the batch event's `close --id` runs before a queued post hook: PostToolBatch lists every call of the batch, not only denied ones (belay-dogfood:115, `tool_calls[].tool_use_id`), and the adapter cannot know which are "still open" without the ledger.
- **The summary** is "every step since that marker" in a record shared between sessions. Session B's count includes steps session A's hooks recorded and showed in A's terminal. Section 3 says this of the receipt (P11) and not of the summary.
- **"Too wide a directory ... said once per session"** has no state directory to record that it was said, since the directory is refused.
- **Should say.** SessionEnd is `close --all` then `step`, and drops the session's marker. Open calls and markers older than a stated age are dropped, with a line. `--finish` or `close` of an id that is not open is a plain step or a no-op. The summary covers the directory since S's marker and says when another session's steps are in it. The `$HOME` line is said at SessionStart only. Add to the probes: which session id a subagent's hooks carry, and whether UserPromptSubmit can fire while a call is open.

### 5. Day files: the tail-only read, the day boundary, and "never rewritten"

- **Empty or damaged newest file.** The first step of a day creates the file and writes the carry line. Killed between the two, the newest file is empty, or repair cuts it to nothing. By "a step reads only the tail of the newest file" that is "no ledger line parses: nothing before HH:MM is accounted for", flagged, and the cursor is lost, although yesterday's file holds it.
- **"Never rewritten"** (section 4, layout) against stage 2's repair, which cuts the file. And `summary`, `receipt` and `patterns` are readers: whether they take the lock and repair, or read without it and tolerate a torn tail, is not said.
- **"Older files are needed only to print them"** is not true of `summary` when the span crosses midnight, or when prune has deleted the file holding the session's marker (Q7 excepts only the newest and the list in force).
- **Which day.** Local dates go backwards with a time zone or clock change; then the newest file by name is not today's.
- **Line size.** A typical step line is a few hundred bytes plus the open calls and markers. The bound is not: 64 flagged paths of up to 4,096 bytes each, before escaping, is over 256 KiB, plus problem 4's sessions. A reader of "the tail" needs a stated maximum line length.
- **Should say.** The running state is read from the newest file that has a parsable step or carry line. A day file is created under a unique temporary name with its carry line and renamed. "Append-only, except that repair cuts a torn tail." UTC dates, and append to the newest file unless today is later. A maximum line length, with flagged paths cut to fit and counted. A summary whose marker's file is gone says the record before that day was trimmed.

### 6. Q5 leaves two cases where the four places still differ

- **One side has no inode flags.** The diff makes that outcome `unknown` (classify.c:39-40, 108), so PS-M1 does not fire and PS-M5 does. `privilege` in policy.c reports it as a change, "none" to a number (policy.c:757-765). Q5 says "set or cleared" and does not say what an unread side is.
- **`type_changed` with a directory on one side.** "On a directory" does not say whether a file that became a directory is under the directory rule. policy.c compares the two values whatever the types.
- **Consistent otherwise, by reading.** PS-M1 has the entries of both sides (policy.c:463-464), so it can apply the rule instead of reading `changed` (policy.c:486-491). The receipt cannot today: `receipt_meta` holds the mode and `has_caps` only (receipt.h:33-36) and the receipt reads `changed` (receipt.c:198). It needs the inode flags of both sides through the same callback. That is implementable and should be named in step 4. PS-M1 has no added or removed case (it needs both sides, policy.c:490), so pin 1's "for added and removed entries" applies to `privilege_changed`, the receipt and watch only.
- **Should say.** Both cases, one sentence each, in Q5 and pin 1.

### 7. The coverage rule is computable, but two of its words are not defined

- **Computable, by reading protect.c:79-120.** "Matches a row" and "lies below a row's match" are the matcher with decision 4's switch. "An ancestor of a row" is `protect_covers`. For an exclude of `node_modules` against `.claude`, `CLAUDE.md` or `.envrc`: only position 0 is live, the first component does not match, nothing stays live, so it is no ancestor. The ordinary exclude is not an alarm.
- **"Anchored at the top"** is only contrasted with "rows that begin `**/`". A row `*/.env` or `*/secrets/**` is neither, and with dot-names matched every top-level directory is its ancestor.
- **"An unrelated directory"** implies a related one counts for a `**/` row; no rule says which.
- **Permanent flag.** Exceptions are ignored, so a user who excludes `.claude/worktrees` (below the row `.claude`, and the example exception in N2) gets a flagged summary at every Stop until the exclude is removed. True by the rule; say it.
- **Should say.** "A row whose first component is `**` counts only when the path matches it or lies below a match. Any other row also counts when `covers(row, path)` holds." Pin 4 states, as a checked property, that no built-in row has a wildcard first component followed by more components. Rows are compared case-insensitively in the covers test too.

### 8. Section 8's list is incomplete for prune

- **PR-7** (`--dry-run` says what a real run would remove) must name day files. N5 asked for it; pin 3 lists PR-3, PR-9 and DC-1.
- **PR-1 and PR-2.** Prune's limits are `--keep-days` and `--keep-last`, a count of checkpoints. "Deletes day files older than its limits" has no meaning under `--keep-last` alone. One definition that fits: a day file goes when every checkpoint its step lines name is removed in this run.
- **PR-8** gives the order of removal and the crash guarantee; day files need their place in it, since section 11 tests prune killed while deleting them.
- **`state_open`'s bounded wait** is named in section 5 as a change to existing code and is in no step of section 12. No pin governs it (PR-9's "a capture waits for it" still holds), so it needs only a line in step 6.
- **Consistent, by reading:** there is no receipt pin in test/expect, so "docs/cli.md with the code" is right for the receipt sentence (docs/cli.md:295-296); checkpoint kinds are unchanged; the list in force is a file under `watch/`, so PR-6 is not touched.

### 9. Step 1 needs code that step 5 writes

- "List noise" runs installs "through the built-in rows and decision 2's symlink flag", and section 6's limit is "measured and stated in the pin". Both need the watch dialect's matcher, which exists only after pin 4 is approved (steps 5 and 6).
- **Should say.** These measurements use a throwaway harness outside the tree (the first report did the same on a copy of protect.c), not merged.

### 10. Smaller wording, each one sentence

- **Section 6:** "the previous list stays in force until a valid file replaces it". Deleting an invalid file must also end it (no file is an empty list); say "a valid file, or none".
- **Section 6:** the very first step with an invalid or unreadable file: the list in force is empty, with the flagged line. Not said.
- **Section 6:** `.belay-donttouch` under a user's exclude is absent from the manifest, so it reads as "no file" with no line, while a list exists. Make it the "could not read" line.
- **Section 1:** "what was flagged is named again in the summary" against section 3's "three named, then a count".
- **Section 11:** "a call open across a Stop" cannot occur within a session once Stop is `close --all`; say "still open when the Stop arrives".
- **Pin 4's contents** omit the summary's counting rule, the deadline's value and the back-off's threshold.

## Checked and found consistent

- **The lock.** The worker holds it; a kill releases it (state.c:397, 413: flock on an O_CLOEXEC descriptor); the supervisor never opens the state. The bounded wait replaces one loop (state.c:424-425).
- **Calls, walked through section 3's table:** denied (closed at the batch), interrupted (closed at the next prompt or Stop, and still attributed, because the rule is "open at any time during its interval"), two parallel calls (steps are serial under the lock; both are named), two sessions in one directory (`--all` is per session and that is enough between sessions), a Stop followed by a background wake (the summary runs from the user's prompt, as decision 197, if the probe lets the adapter tell the wake apart).
- **Don't-touch:** absent, changed, a pattern removed, invalid and unreadable each give a line, and none leaves a stale list in force without one. The user can clear each by fixing or deleting the file, subject to problem 10.
- **Q3 and section 6** agree on twelve kinds.
- **Q5 against decision 171 and policy-v1.md:99:** the added and removed rule is today's, extended to the receipt.
- **Section 12** has no code before its pin, apart from problem 9; the model's change (step 3) comes before the code it checks (step 4).
- **Decisions 1-7** are followed; I found no sentence that contradicts one.

## Not checked

- Anything about Claude Code: which events fire, their order, session ids of subagents, concurrency of hooks. All of problem 4's adapter cases rest on the dogfood hooks' comments and the probes still to run.
- macOS, and any behaviour of `watch`: no code exists.
