# `belay watch`: the plugin's logic in the binary (structure proposal, fourth version)

Status: **APPROVED by the author 2026-11-10 (fourth version).** No implementation code exists for it.
Pins: 1 (#127) and 2 merged; 3 merged (#128) with the author's change, below; 4 is PR #131, awaiting OK.

Changed by the author with the approval: **the plugin prunes only the watch's own checkpoints**
(`belay prune --watch-only`; a watch step's checkpoint is marked in meta.json; state-retention-watch.md
WR-10, WR-11, WR-14, WR-15). Where Q7 and section 3 below say the plugin's prune removes the user's
own checkpoints, that is superseded.

- Two adversarial passes: NOTES/reviews/watch-structure-adversarial-2026-11-10.md ("A3" is its
  objection A3) and NOTES/reviews/watch-structure-adversarial-2-2026-11-10.md ("N4", "P7").
- A narrow check of the third version: NOTES/reviews/watch-structure-check-3-2026-11-10.md ("C4" is
  its problem 4). Its ten problems are answered in this version; it asked for no redesign.
- Measurements and probes made so far: NOTES/measurements/2026-11-10-watch/README.md.
- The author's decisions, all 2026-11-10, which this version follows:
  1. One matcher implementation with switches. Protect specs stay version 2 with today's dot rule.
  2. A file replaced by a symlink is flagged. New symlinks are not flagged by where they point.
  3. A directory's inode flags: one rule for watch, the receipt and verify, **the protect rule
     included**, as a pin change with a measurement and no spec version bump.
  4. In the watch dialect, a match on a directory covers everything below it.
  5. Cut: the ledger as a public format and `--json`; the "shown" note; the rule against running a
     program found inside the directory. Keep `belay watch patterns`.
  6. Background commands are not modelled in the first version.
  7. The claim's scope is careless changes (section 1).
- PR #125 (the shell and awk plugin) is a draft and would be closed, not amended. Its review is
  NOTES/reviews/pr125-plugin-690e902-review.md ("F3").

## 1. What it is for, and what it is not

`belay watch` keeps a running record of one directory while an agent works in it: one line after
each step saying what changed, with anything in a sensitive or declared place first; totals when
the agent stops; every change in full on request.

**The claim, and its scope.** It catches careless changes: what an agent, a tool it ran or an
install did to the directory without saying. Such a change is in the step's line and in the full
receipt, and the summary names or counts everything flagged in its span; or a line says the record was
interrupted and why.

It does **not** hold against a process running as the user that attacks belay itself: one that
deletes or rewrites belay's state, adds an exclude, runs `belay watch` or the hook command itself,
or holds the lock. Section 5 lists what is still noticed and what is not.

Not in this proposal: any change to capture, manifests, diff.v1 or the protect spec's version;
other agents' adapters; a machine-readable output; background commands; the dogfood hooks.

## 2. The shape

```
 plugin (shell, about 60 lines, no `set -u`): on session start, fetch the pinned binary if absent
        and check its sha256; on every event, exec it, and exit 0 whatever happens (P9).
        │
        ▼
 belay hook claude-code EVENT          src/cli/hook_claude.c   the only Claude Code knowledge
        │  reads the hook's JSON with the real parser, maps the event to core calls, closes calls
        │  that never finish, owns the span a Stop reports, writes the hook's JSON reply.
        │  Exit status 0 for any arguments, before any other parsing (F15).
        ▼
 belay watch step|close|mark|summary|receipt|patterns   src/cli/watch_cmd.c   agent-neutral
        ▼
 src/watch/ledger.c    the record, under the scope's lock
 src/watch/flag.c      what is flagged, and why
 src/watch/lines.c     ledger records -> short lines (a pure function)
 src/util/pattern.c    the one matcher, moved from src/policy/protect.c, with two switches
 existing: state.c, capture, belay_diff, receipt.c
```

| module | its one job | what it offers | what it must not know |
|---|---|---|---|
| `pattern.c` | Matching. | valid(text, dialect); match(pattern, path, dialect); covers(pattern, directory, dialect). | Who is asking. |
| `flag.c` | One diff record to a flag. | flag(record, entry before, entry after, lists) -> kind and reason, or none. | Lines, calls, agents. |
| `ledger.c` | The record. | open under the lock with repair; tail state; append attempt, step, close, marker; segments. | What a flag is. |
| `lines.c` | Text. | step line(step); summary lines(steps); given the caller's word for a call. | Files, locks, JSON. |
| `watch_cmd.c` | The commands and the supervisor. | Each command of section 3. | Claude Code. |
| `hook_claude.c` | The adapter. | One function per event. | Patterns, the ledger's layout. |

Moving the matcher is behaviour-preserving for verify: the protect dialect's answers must be
identical, proven by the existing policy tests and the independent model running unchanged.

## 3. The commands

```
belay watch step     --scope DIR --session S [--begin ID | --finish ID] [--first-ok]
                     [--deadline SECONDS]
belay watch close    --scope DIR --session S (--id ID... | --all)
belay watch mark     --scope DIR --session S --name NAME
belay watch summary  --scope DIR --session S --since NAME
belay watch receipt  --scope DIR [--max-lines N] [--path]
belay watch patterns --scope DIR
belay hook claude-code start|pre|post|batch|prompt|stop|end|receipt
```

- **`step`** captures (as `mark` does, with its prefilter, and recorded as kind `mark`, P12), diffs
  against the cursor and prints one line if anything changed. `--begin ID` opens a *call* and
  `--finish ID` closes one. A step's changes are attributed to the calls open at any time during
  its interval; with none open the line says "outside tool calls".
- **`close`** closes calls without a capture, for calls that will never finish (N3).
- **`mark`** writes a named marker. **`summary`** prints, for every step since that marker: what
  was flagged (three named, then a count for every kind) and the number of changes, which is the
  sum of the steps' counts. A file changed in five steps is five changes; nothing is recomputed
  from a diff, so nothing made and undone across steps is hidden (N10). With no change it says so
  (decision 156).
- **`receipt`** prints the full receipt, newest first; each section is `belay diff --all`, nothing
  folded. Steps are shared between sessions, so there is one receipt per directory (P11).
- **`patterns`** prints the list in force and how many current entries each pattern matches, and
  marks a pattern that matches nothing.

**The adapter's mapping** (each fact about Claude Code below is probed first, section 9):

| Claude Code event | Core calls |
|---|---|
| SessionStart, source `startup` | fetch (wrapper); `step --first-ok` |
| SessionStart, other sources | `step` |
| UserPromptSubmit from the user | `step`; `mark --name prompt`. It closes nothing: a message typed while a call runs fires this event with the call still open (probed) |
| PreToolUse | `step --begin ID` |
| PostToolUse, PostToolUseFailure | `step --finish ID` |
| PostToolBatch | `close --id` for each listed call still open (a denied call) |
| Stop | `close` the main thread's open calls (an interrupted or denied call fires nothing else, probed); `step`; `summary --since prompt`; once a day, `belay prune` detached (P7) |
| SubagentStop | `close` that agent's open calls; `step` |
| SessionEnd | `close --all`; `step` (recorded; nothing can be shown); the session's marker is dropped (C4) |
| `/belay:receipt` | `receipt` |

**One event, one hold of the lock** (C2): the core calls of one event run in one worker, under one
supervisor and one deadline, not as separate commands.

Probed on Claude Code 2.1.322: a background command's end fires UserPromptSubmit with a prompt that
begins `<task-notification>`. So the adapter must tell that from the user's message, as the
dogfood receipt does from the transcript (decision 197), and only the user's message moves the
marker.

**Calls and sessions that never end** (C4):

- A call is owned by its session and, in a subagent, its agent id: a subagent's hooks carry the
  parent's session id, and its calls can still be running when the main thread stops (probed). So
  a Stop closes only the main thread's calls.
- `--finish` or `close` of an id that is not open is a plain step, or nothing. PostToolBatch lists
  every call of its batch, and one the harness blocked gets no PreToolUse at all (probed).
- A session that dies fires nothing. Open calls and markers older than a day are dropped, and the
  next line says how many.
- A summary covers the directory since the session's marker, and says when another session's steps
  are among them.

## 4. The record

**Layout.** In the scope's state directory, `watch/`: one ledger file and one receipt file per
UTC day, append-only except that repair cuts a torn tail, plus the don't-touch list in force as a
file named by its sha256. Trimming is deleting whole day files (N5). A step appends to the newest
file unless today is later, so a clock that goes backwards starts no older file (C5). The ledger is belay's own format, versioned, read by nothing
outside belay (as ST-3 says of the state directory).

**Every step line carries the running state:** the cursor, the open calls, the list in force's
digest, each session's last marker. A new day's file is created under a temporary name with a
line carrying the same, then renamed, so it never exists empty. The running state is read from the
newest file that has a line that parses (C5). A line is at most 64 KiB: flagged paths are cut to
fit and counted. Older files are needed to print the receipt, and for a summary whose span began
before today; one whose marker's file has been trimmed says the record before that day is gone.

`summary`, `receipt` and `patterns` only read: they take no lock and ignore a torn last line.

**Order within a step.** The command runs as a supervisor and a worker (section 5, deadline).

1. Take the lock, waiting at most until the deadline.
2. Repair: cut the ledger back to its last line that parses (N8, P6).
3. Append an attempt line.
4. Capture; diff against the cursor; flag.
5. If anything changed, write the step's section to the receipt file and sync it, with the
   platform's barrier so it reaches the disk before the next stage on macOS too (P5).
6. Append the step line, whether or not anything changed, with the section's file, offset, length
   and sha256, and sync it.
7. Release the lock. Print.

- **The cursor is the "to" checkpoint of the last step line.**
- **Killed before stage 6:** the cursor has not moved; the next step covers the same interval and
  says "the previous step did not finish". A receipt section no step line names is never printed.
- **Killed after stage 6:** the change is in the receipt and in the summary, which names its flags.
- **Every step writes a step line**, so an attempt line with none after it always means a step
  that did not finish. Cost: two or three syncs a step, about 1.2 ms each as measured on this
  machine, beside a capture of 50 ms or more.
- **One step at a time** (F2). No temporary file has a fixed name.
- **A step line whose section is missing or fails its digest** is printed in the receipt as
  "this step's section is missing", never left out (P5).

## 5. What is noticed, and what is not

**The deadline** (N4, C1-C3). Every `watch` command that captures, and every hook event, runs as
a supervisor and one worker. The supervisor builds the "could not record" reply first and never
opens belay's state. The worker holds the lock and reports down a pipe: its stage (waiting for the
lock, capturing, matching, rendering), then a request to commit, then its lines and status.

- The deadline is 45 s where the hook's timeout is 60 s, and the default without `--deadline`.
- **Commit is asked for, not announced.** The worker renders the receipt section first, then asks
  and waits for one byte. The supervisor answers "go" or kills, never both, so a step is never
  reported as lost after it was recorded. Committing is then two writes and two syncs of bytes
  already prepared.
- After "go" the supervisor waits to a second limit, 55 s, and then prints "could not confirm the
  record" without killing. A stalled disk cannot turn into silence.
- A worker that dies by itself is a line: "belay stopped unexpectedly while (stage)".
- A killed capture leaves valid state: unfinished checkpoint directories that `prune` removes (run
  by the second reviewer).
- **Back-off.** After a kill the lock is free, and the supervisor appends "killed at the deadline
  while capturing" with the session. Three in a row for a session and it stops capturing: a step
  in back-off writes nothing to the ledger and prints the back-off line. A new session id starts
  afresh; nothing else clears it.
- `state_open` gains a bounded wait for the lock, used only here: a change to existing code.

**Always a line, never silence** (A3, decision 156), flagged and repeated at every Stop while the
cause lasts:

| Cause | Line |
|---|---|
| The lock is not free by the deadline | could not record: another belay holds this directory's lock |
| Capture or diff failed | could not record: (belay's message) |
| The worker died by itself | belay stopped unexpectedly while (the stage) |
| No answer after "go" by the second limit | could not confirm the record |
| Still capturing, or matching, at the deadline | could not record in N s: (the stage) |
| Back-off | not recording: capturing this directory takes longer than N s |
| An attempt with no step line after it | the previous step did not finish |
| The cursor's checkpoint is gone or unreadable, others survive (P4) | the record was interrupted: resuming from checkpoint K (HH:MM) |
| No ledger line parses | the record was interrupted: nothing before HH:MM is accounted for |
| `.belay-donttouch` cannot be read, or has an invalid line | section 6 |

- **A first step always says so** (A1): "recording starts here: nothing before HH:MM is accounted
  for", flagged, unless `--first-ok`, which the adapter passes only for a session's `startup`. A
  plugin enabled in a running session therefore begins with that flagged line; it is true, and it
  appears once.
- **Excludes, mounts, unreadable directories** (A4, N2):
  - a step is flagged when the two manifests' excluded sets differ;
  - once per session, a plain line names what is not being read;
  - a summary is flagged when such a path matches a list row or lies below a row's match; and,
    for a row whose first component is not `**`, also when the path is an ancestor of something
    the row could match (the matcher's "covers"). So excluding `node_modules` is not an alarm:
    it is an ancestor of no such row (checked by the third reviewer against the matcher).
  - The covers test ignores a row's exceptions and its file-only limit, and compares built-in rows
    case-insensitively; each can only over-flag. So a user who excludes `.claude/worktrees` gets
    a flagged summary at every Stop until the exclude goes.
  - Pin 4 states, as a checked property, that no built-in row has a wildcard first component
    followed by more components (C7).
- **Too wide a directory** (F3): `/`, `$HOME`, or any directory `$HOME` is inside, refused by
  `watch` and `hook` in one function, and said at a session's start only: nothing is kept for a
  refused directory (C4).

**Not noticed**, and said in the README (N9):

- anything a same-user process does to belay's state, the lock or the commands themselves;
- state removed, followed by a session `startup` before the next hook;
- a change made and undone between two steps;
- a change under a path excluded at both ends of a step: named once per session, never listed;
- what `mark`'s prefilter is documented to miss (docs/cli.md, "mark: which files are read"),
  until the next full capture;
- a write after the last hook of a session, until a later session's first step;
- a file removed in one step and a symlink put there in a later one; a symlink retargeted (P3);
- what a background command writes after its call has finished is recorded and counted, but
  attributed to whichever call is open, or to none.

## 6. Flags and lists

Flags come from the manifests' fields (F8); paths are matched as bytes (F9).

| Kind | When |
|---|---|
| don't-touch | The path matches the list in force, or is `.belay-donttouch` itself. |
| the built-in kinds | The path matches a built-in row (Q4). |
| privilege | setuid, setgid, sticky, capabilities, inode flags, under the one rule of Q5. |
| replaced by a symlink | An entry that was not a symlink and is one now. |
| history | The diff's `git_history_rewritten` event. |
| could not be read | Outcome `unknown` on a listed path. |
| coverage | As section 5. |

**The watch dialect** is the protect grammar (PS-P1 to PS-P3) with two switches on: `*` and `**`
match dot-names, and a pattern that matches a directory covers everything below it. So
`migrations` covers `migrations/0001.py`, and `.claude` covers what is in it. A pattern still
starts at the top of the directory: `*.lock` is the top level only, `**/*.lock` any depth.
`belay watch patterns` shows what each pattern matches. The built-in list is rewritten in this
dialect, row by row, in the pin.

**The don't-touch list in force** (A8, N7):

- Read only from the checkpoint's stored, hash-checked copy of `.belay-donttouch`, with its own
  check for NUL bytes.
- **No file is an empty list.** `#` at the start of a line is a comment; blank lines are allowed.
- Limits: the store's 64 KiB, 256 patterns, four `**` a pattern (A9, P13); the worst case is
  measured and stated in the pin.
- **A change to the file is itself flagged**, kind don't-touch, and in that step the old list and
  the new both apply. From the next step the new list applies: removing a pattern is allowed, and
  it has been seen.
- **An invalid line** ("line N is not a pattern") or **a file that cannot be read** ("could not
  read .belay-donttouch: no stored copy, a writer has it open", and the like) are different
  flagged lines. In both cases the previous list stays in force until a valid file, or no file,
  replaces it. On the very first step there is no previous list: the list in force is empty, and
  the line says so.
- A `.belay-donttouch` under an exclude is the "could not read" line, not "no file".
- Invalid, with the line number: control bytes (so CRLF), a leading or trailing `/`, an empty, `.`
  or `..` component, and `?`, `[`, `\` or a leading `!`.

## 7. Design questions, settled

| # | Question | Settled as |
|---|---|---|
| Q1 | One matcher | One implementation, two switches (dot-names; a directory covers below). Protect dialect: both off, exactly today's PS-P1 to PS-P4. Watch dialect: both on. |
| Q2 | `$HOME` and `/` | Section 5. |
| Q3 | More than three flags | Three named, one from each kind before a second of any, in this order: don't-touch, git hooks and config, agent rules, privilege, loads on its own, package source, CI, credentials, replaced by a symlink, history, could not be read, coverage. Then a count for every kind. |
| Q4 | The built-in list | The PR #125 list and the review's gaps, rewritten in the watch dialect. **A row enters the pin only after it is probed against the tool that honours it** (decision 184); the rest are listed as not yet probed and left out. A row may carry an exception for that row only, matched case-sensitively (P8), and may be limited to files. Rows are matched ASCII-case-insensitively. User patterns are case-sensitive and have no exceptions. |
| Q5 | Inode flags | **One rule, in four places.** On a directory, a change to inode flags counts only when immutable or append-only is set or cleared. On an entry added or removed, inode flags count only when immutable or append-only is set (today's decision 171, extended to the receipt). The directory rule applies only to an entry that is a directory at both ends; a type change is judged by its own rules. Inode flags read on one side only stay what they are today, `unknown` with the reason `iflags_unknown`, and are a privilege change in none of the places (C6). The places: PS-M1 (`no_write`, which has no added or removed case), policy.v1's `privilege_changed`, the receipt's privilege section, and watch. A pin change with no spec version bump, an amendment to BELAY_DESIGN §5.3, and a measurement first. |
| Q6 | Calls that never finish | Closed by the adapter: one the harness blocked at the batch event; one the user denied or interrupted at the next Stop, since neither fires anything of its own. Until then it is named beside the calls that really made a change. |
| Q7 | Size and pruning | `belay prune` never removes the cursor's checkpoint, and deletes day files older than its limits, except the newest and the list in force. It runs from the adapter at a Stop, once a day, keeping a week. It also removes the user's own unkept checkpoints of that directory older than a week; the README says so. Deleting day files is cleanup of belay's state and is on the blast-radius list (§0.4). |
| Q8 | Programs on PATH | `code` on request, and the `git` the receipt already asks, found as today. |
| Q9 | The words in a line | The caller gives the word for a call; the Claude Code adapter says "tool call". |

## 8. Pins and design text: each its own PR, a table, the author's OK before code

| # | Pin or text | Change |
|---|---|---|
| 1 | `test/expect/` : inode flags (new file amending protect-spec PS-M1 and policy-v1) | The Q5 rule, in PS-M1 and `privilege_changed`, for directories and for added and removed entries. With the measurement. |
| 2 | BELAY_DESIGN §5.3 | The "never suppress" sentence gains the Q5 rule. |
| 3 | `test/expect/state-retention.md` (amendment) | PR-3: the cursor's checkpoint. PR-1 and PR-2: a day file goes when every checkpoint its step lines name is removed in the same run and it is not the newest. PR-7: `--dry-run` names the day files. PR-8: their place in the order of removal. PR-9, DC-1: the wording (C8). |
| 4 | `test/expect/watch-v1.md` (new) | The lines' text; the kinds and their order; the built-in rows with their probes; the watch dialect; the don't-touch file's rules and limits; the failure lines of section 5; how a summary counts; "N under dir/" and when changes are named; the deadline, the second limit and the back-off's threshold. |

With the code, not as pins: docs/cli.md (the commands; the receipt's privilege sentence).

## 9. Before the pins: measurements and probes

Results so far are in NOTES/measurements/2026-11-10-watch/README.md.

- **Inode flags** (pin 1): **done.** Over 2,789 stored checkpoints of this repository (10,990,360
  entry comparisons): no inode-flag change on any entry present at both ends. An `npm install`
  into an existing `node_modules`: one, the directory's hashed-index flag. A `pip install` into a
  virtualenv: none. No change on a regular file anywhere, so nothing argues for widening the rule.
- **The built-in rows** (pin 4): **partly done**, and the probes already change rows. On this
  machine `sitecustomize.py` in a virtualenv is not run (Ubuntu ships its own, found first), nor
  is one in the working directory; `*.pth` runs only from site-packages; `pip.conf` is honoured at
  a virtualenv's root and not in the working directory; `.gitattributes` alone runs nothing. Not
  probed, for want of the tool here: direnv, yarn, cargo, pre-commit, lefthook, twine, husky, and
  every editor and CI row.
- **List noise and the pattern limits** (pin 4, C9): with a throwaway harness outside the tree
  (the watch matcher does not exist yet), not merged: how many flags a clean install raises and
  from which rows; the worst case the limits allow.
- **Claude Code** (pin 4), with a throwaway plugin on 2.1.322. **Done:** `startup` as a source;
  hooks of parallel calls run at the same time; pre and post carry one id; the batch lists every
  call; a blocked call gets only the batch; a background command's end fires UserPromptSubmit;
  `systemMessage` is shown for start, prompt, pre, post, batch and Stop in the terminal.
  Also done, in a second session: a denied and an interrupted call fire only their PreToolUse; a
  message typed during a call fires a prompt event at once; a subagent's hooks carry the parent's
  session id and an agent id, and can run after the main Stop; `/clear` starts a new session id,
  while compaction and resume keep it; a hook past its timeout is killed with its children.
  **Not probed:** a plugin enabled in a running session.
- **Latency.** The second reviewer measured a step at 0.05 s here (2,178 entries) and 1.2 s on a
  synthetic 60,602-entry tree; a tool call costs two. That misses R47's 0.1 s on large trees. I
  will measure a real large project for the README. One capture per call is a separate decision.

## 10. What the structure makes impossible, and what it only decides

| Finding | Status |
|---|---|
| F1 lost interval | Impossible to lose: the cursor moves only with the step line. A timeout that repeats is a line and then a back-off. |
| F2 double counting | Impossible: one lock around the step. |
| F3 `$HOME` | Impossible: one check. |
| F4 silent loss of state | Narrowed: a flagged first-step line at the next hook; not noticed across a `startup`. |
| F5 a start in mid-turn | Impossible: nothing resets. |
| F8, F9, F13, F14, F10 | Impossible in the binary: no text parsed, belay's escaping and JSON writer. |
| F15 exit status | Impossible in the binary; the wrapper is written to exit 0 and tested for it. |
| F6, F7, F11, F12 | Decided: Q5, Q3, Q4, section 6. |

## 11. Proof

- Unit tests per module; the lines as a table of ledger records and expected text.
- **Concurrency:** N processes stepping one directory while files change; each change counted once.
- **Kill points:** the worker killed after each stage of section 4, a torn last line, a line of
  NUL bytes; and `prune` killed while deleting day files. Afterwards nothing is missing from both
  layers and nothing is in the receipt twice.
- **Every row of section 5's table** produced for real, and its line checked; the back-off.
- **Calls:** denied, interrupted, parallel, one still open when a Stop arrives, a session that
  dies with calls open, and `--finish` of an id already closed.
- **The matcher:** the protect dialect proven unchanged. The watch dialect is added to the
  independent model by its separate author from pin 4 alone, and run against
  `belay watch patterns` once that exists.
- Fuzz targets for the don't-touch reader, the ledger reader and the hook's stdin.
- Every new test mutation-checked; an independent review of each diff; a real Claude Code session
  in the terminal, and the author's look in the extension.

## 12. Order of work

1. The measurements and probes of section 9.
2. Pins 1 and 2 (inode flags), then 3 (retention), then 4 (watch-v1), each waiting for the OK.
3. The independent model's inode-flag change, by its separate author, from pin 1.
4. The inode-flag rule in policy, the protect rule and the receipt (N12); the receipt is given
   both sides' inode flags through its existing callback (C6). This also fixes the false
   `protected_path_written` on a directory that grows, which alpha.6 has today.
5. `pattern.c` moved, behaviour-preserving, proven before anything lands on it.
6. `state_open`'s bounded wait; `ledger`, `flag`, `lines`, `watch_cmd` with the supervisor, then
   `hook_claude`; prune's changes.
7. The watch dialect in the independent model, run against `belay watch patterns`.
8. A release (alpha.7) when the author says so.
9. A new plugin PR replacing #125.

## 13. Size, and what serves the claim

- **Needed for the scoped claim:** the step under the lock with the cursor in the ledger; the
  attempt line and repair; flags from manifest fields; the two lists; the failure lines with the
  supervisor; call closing in the adapter; prune keeping the cursor.
- **Kept beyond that, and why:** day files with digests (so that trimming and a kill cannot make
  the receipt lie); `patterns` (so a list that protects nothing is visible).
- **Cut** (decision 5): a public record format, the "shown" note, the PATH rule.
- **Risks:** Claude Code's hook protocol changes often, confined to one file and one pinned binary;
  hook latency on large trees; two dialects of one grammar until the grading redesign, said in the
  README and by `patterns`.
