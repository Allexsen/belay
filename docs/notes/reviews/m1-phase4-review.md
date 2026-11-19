# Phase 4 independent review (blast radius + hostile input), verbatim

Reviewer: a fresh agent with no implementation context (BELAY_DESIGN §0.4(b)), 2026-10-31.
Scope: `origin/main..m1/phase4-interpreters` (reviewed at 75ae2ce; tip moved to c3fffd8, tests and
spec reflow only). [n] tokens, 62 tool uses, 12.8 min. Relayed verbatim below; the dispositions
follow after the report.

---

I reviewed 75ae2ce, the branch tip when I started. While I was reviewing, m1/phase4-interpreters moved to c3fffd8. The three new commits change only tests and reflow the spec text; nothing under src/ changed, so every finding below also holds at c3fffd8. I built and tested in a detached worktree under /tmp, which I have since removed. `make all` and `make test` passed there. I wrote the experiment programs in the scratchpad and linked them against that build's build/libbelay.a.

FINDINGS

1. HIGH: a FIFO planted in the store hangs the whole diff.
   Where: src/interp/content.c:61. The object is opened with `openat(pfd, hex+2, O_RDONLY|O_NOFOLLOW|O_CLOEXEC)` and has no O_NONBLOCK. The S_ISREG check (line 72) only runs after open() returns, and open() on a FIFO with no writer never returns.
   Spec: diff-v1 says a copy "that is not a regular file (a symlink included) is corrupt". Every interpreter that reads content (text, pip, dpkg, git) goes through this call.
   Trigger: `mkfifo <store>/ab/<rest>` where ab<rest> is a name a manifest entry records as `stored`.
   How I established it: experiment. An end-to-end belay_diff with a text file whose before-copy is a FIFO. The child process ran under alarm(5). Output: "child killed by signal 14 (SIGALRM=14): diff hung on the FIFO".
   Fix direction: open with O_NONBLOCK (then fstat, then read), or fstatat with AT_SYMLINK_NOFOLLOW first. Also see finding 6.

2. MEDIUM: directories under .git/logs/refs/ get a false `git_reflog_rewritten`.
   Where: dispatch claims every path matching "*/.git/logs/refs/*", whatever its type. In src/interp/git.c:269, `if (!reg(in, SIDE_AFTER))` emits git_reflog_rewritten. A directory that is added therefore reads as a rewritten reflog.
   Trigger: any branch created in a new namespace (`git branch feature/x`), or the first commit in a fresh repo (which creates .git/logs/refs/heads).
   How I established it: experiment. End-to-end belay_diff where the after side adds r/.git/logs/refs/heads/feature (dir) and feature/x (reg, stored). Output record:
   {"path":"r/.git/logs/refs/heads/feature","outcome":"added","type":"dir","findings":[{"kind":"git_reflog_rewritten","ref":"refs/heads/feature","text":"refs/heads/feature: reflog rewritten"}]}
   Why it matters: "reflog rewritten" is the history-tampering signal, and this fires it on routine operations. The spec says "a side on which the path is not a regular file counts as absent", so absent on both sides means nothing should be reported.

3. MEDIUM: hostile dpkg status values that are each valid still wipe out every dpkg event (E6). This also breaks the fuzz target's own invariant.
   Where: src/interp/findings.c:120 and :136. `valid()` rejects a finding whose rendered text exceeds 1,024 bytes. In belay_event (findings.c:287) that marks the interpreter broken, and end_all then replaces all of its events with one could_not_interpret. src/interp/dpkg.c:155 (pend) checks each value with belay_finding_string_ok but never checks the rendered length. The stanza parser allows values up to 1,024 bytes each, so "upgraded {package}:{arch} {from} -> {to}" can reach about 4 KiB.
   Spec: the dpkg section lists the E6 triggers as "a status cannot be parsed or a value an event would carry is not a string field's value". This case is neither. Pip is not reachable this way in practice, because the name and version come from one path component (NAME_MAX 255).
   Trigger: one package whose before and after Version fields are 600 bytes each (installed, upgraded), next to an ordinary bash 5.1 -> 5.2 upgrade.
   How I established it: two experiments.
   - End-to-end belay_diff. The bash upgrade disappears; the only event is {"event":"could_not_interpret","interp":"dpkg",...,"paths":["var/lib/dpkg/status"]}.
   - test/fuzz/fuzz_interpreters.c built with gcc and ASan/UBSan and a file-reading main (no clang here), fed byte 0 = 2 (dpkg, modified) plus the same two statuses. Output: "fuzz_interpreters: an event broke its row (line 87)", then abort. The header's claim "no built-in ever adds an event that breaks its kind's row" is false.
   Decision for the author: the spec does not say what an over-long event text becomes.

4. MEDIUM: one hostile RECORD at the 64 MiB bound costs about 1.6 GB per side.
   Where: src/interp/pip.c:103-155 (row_add, rows_of). Each row costs a 56-byte struct row, plus an arena of 4*len+6 bytes. The row array grows by realloc doubling, up to 2^25 entries (about 1.9 GB reserved). record_csv accepts ",,\n" (3 bytes) as a row, so 64 MiB holds about 22M rows.
   Trigger: a dist-info RECORD modified in place, with after = 64 MiB of ",,\n". RECORD is KEEP_STORE, so it is stored whatever its size under default settings.
   How I established it: experiment, end-to-end belay_diff with one side hostile. Result: "rc=0 2.72s maxrss=1644 MB". Both sides hostile would be about 3.3 GB.
   On allocation failure, NOMEM degrades to could_not_interpret, which is fine. On a typical Linux the OOM killer may act first.

5. LOW-MEDIUM: git hooks ignore "a side that is not a regular file counts as absent".
   Where: src/interp/git.c:218-237, which looks only at before/after being NULL and the outcome.
   How I established it: experiment, end-to-end. Records produced:
   - hook post-merge, reg -> lnk (type_changed): git_hook_changed, executable:true (the symlink's 0777 mode).
   - hook pre-commit added as a symlink: git_hook_added, executable:true.
   - directory hooks/pre-push.d added: {"kind":"git_hook_added","hook":"pre-push.d","executable":true,...}
   The directory case is plainly wrong. Reporting symlink hooks is arguably more useful than the spec's rule (under which they would report nothing). Either the code or the spec should change; that is the author's call.

6. LOW: a socket (and some other non-regular objects) in the store gives could_not_interpret, not "corrupt"; for pip and dpkg that means E6.
   Where: src/interp/content.c:64-69. open() on a socket fails with ENXIO, which is mapped to BELAY_ERR_IO, then SW_ERROR in stored.c:197.
   How I established it: experiment. belay_content_get on a bound unix socket returns "rc=-1 code=1 (CORRUPT=5 IO=1) msg=content: cannot open object ...". The spec says a non-regular copy is corrupt.
   Minor, from reading the code: a prefix that is a regular file (ENOTDIR) is reported as corrupt, but its message says "is missing".

7. LOW: the core keeps the E6 claim list for the whole diff, with no bound, and the E6 event is one line of unbounded size.
   Where: src/diff/diff.c:125 calls events_claim (src/interp/findings.c:227) for every non-unchanged path dispatched to an interpreter with an end hook (pip, dpkg). Each path is copied into ev->per[i].claimed and kept until the end. events_failed then writes all of them into a single NDJSON line.
   Spec: diff-v1 "Shape" says bounded memory however many entries the manifests hold, and E5 says per-diff state is "bounded to match". Pip and dpkg bound their own state at 64 MiB; this list has no bound.
   Trigger: a process that creates or changes very many *.dist-info/METADATA files or dpkg info/*.list files.
   How I established it: reading the code; not measured.

8. LOW: filling the 64 MiB per-diff state limit causes E6, which the spec does not list as an E6 trigger.
   Where: src/interp/pip.c:55 and :67 (keep, grow); src/interp/dpkg.c:52 and :65.
   What happens: when the state is full, name_dist/pend fail, so a correctly named RECORD gets a path-level could_not_interpret and the whole interpreter goes to E6.
   Trigger: with 1,024-byte dpkg values, each pending event keeps about 4 KB, so roughly 16K events fill the state. That is well short of the 65,536 events E5 allows before and_more.
   How I established it: reading the code.

9. LOW: git_ref_moved and git_head_changed can say from == to.
   Where: src/interp/git.c:110-121. The parsed values are never compared. packed() does compare them (line 198), so loose refs and packed refs behave differently.
   How I established it: experiment, calling the git explain hook directly.
   - Loose ref "OA\n" -> "OA  \n": {"kind":"git_ref_moved",...,"from":"1111...","to":"1111..."}
   - HEAD "ref: refs/heads/main\n" -> "ref:  refs/heads/main\nextra\n": "HEAD refs/heads/main -> refs/heads/main".
   Spec: git_ref_moved means "a ref names another commit".

10. LOW: if memory runs out partway through end_all, the remaining interpreters' state leaks.
    Where: src/diff/diff.c:142 sets x->ended = true before the loop. If events_oom fires for interpreter i, it returns -1 at once, and the cleanup at diff.c:289 skips every end hook because ended is set. Interpreters after i never get end(state, NULL), so their state leaks. This only happens on a diff that is already failing from out-of-memory.
    How I established it: reading the code.

11. LOW (documentation): the pins disagree with each other and with the code.
    (a) E2 says an event's kind is "an event-level kind ... or and_more". E6 emits could_not_interpret as an event, but the Kinds table gives could_not_interpret level "path" only.
    (b) and_more's meaning (pin: "The findings past the 4,096th of this record"; schema: "...or the events past the 65,536th") does not match the code. The code replaces the 4,096th (or 65,536th) item and sets n = extra + 1, so n includes that item. The diff-v1 prose ("the last place is one and_more counting the rest") matches the code; the meaning column is off by one.
    (c) IN_ANY|LV_PATH means an interpreter may itself add and_more (with any n), could_not_interpret or invalid_finding to a path. The built-ins don't, but the core can't tell those from its own. At event level these are rejected, and test_findings checks that.

12. LOW: the text interpreter's memory at its 16 MiB bound is about 830 MB.
    Where: src/interp/linediff.c:110. split() allocates 24 bytes per line for both sides.
    Who can reach it: only with a store_max_bytes raised far above the 64 KiB default.
    How I established it: experiment. 16 MiB of "\n" on each side gave "rc=0 0.63s maxrss=834 MB". I also tried block-structured near-worst cases for Myers with D up to 1,998: 0.1-0.27 s. I found no time DoS.

TESTS
- test/fuzz/fuzz_interpreters.c header claims "one JSON line per event" and "each finding within its bounds". Neither is checked: the code checks UTF-8, count <= 4,096, determinism and broken events only. Its "no built-in breaks its row" invariant is falsified by finding 3.
- No test covers:
  - non-regular store objects other than a symlink (FIFO, socket, directory);
  - non-regular paths claimed by git (directories under logs/refs and hooks, symlink hooks, type_changed hooks or refs);
  - dpkg or pip events whose text would exceed 1,024 bytes;
  - E6 caused by the per-diff state limit;
  - pip/dpkg too_large or corrupt as an event;
  - E5 and_more end to end through belay_diff (only test_findings at unit level);
  - a git ref rewritten with the same value.
- test_interpreters.c r_path/r_end copy diff.c's handling by hand instead of calling it, so differences between them would go unnoticed (none seen today). The end-to-end coverage in test_diff.c is limited to text, a no-store dpkg status, and stub interpreters.

CHECKED AND SOUND (by reading the code unless noted)
- content.c:
  - object names checked as exactly 64 lowercase hex digits, so no `..` or path injection;
  - store opened O_DIRECTORY|O_NOFOLLOW, prefix directory and object O_NOFOLLOW;
  - a symlinked object is corrupt (existing test);
  - size checked against max before malloc;
  - growth while reading detected;
  - the hash is computed over exactly the bytes returned, so a TOCTOU swap can only produce corrupt;
  - nothing in the store is created, written or deleted.
- diff.c output: unchanged mkstemp + rename + unlink of the temporary file on failure; nothing else in the diff creates or deletes files.
- findings.c:
  - each kind is checked against its interpreter and level, field count and string rule (UTF-8, no NUL, at most 1,024 bytes);
  - text is rendered only from the template;
  - escape buffers are big enough for 6x expansion;
  - and_more placement and counting match the diff-v1 prose for both findings and events;
  - paths sorted bytewise, deduplicated, base64 when any is not UTF-8, at least one, at most 4,096 bytes (manifest paths are at most 4,095);
  - interpreter output order text, pip, dpkg, git (E4);
  - E6 drops every other event and lists the claimed paths;
  - the trailer's `events` comes after dir_timestamps_only and belay_diff_end counts path records only (E7).
- Interpreters cannot change an outcome or a record: they get const entries and the verdict as a string; findings are reset for every path and checked against the interpreter's id; a DECLINE drops anything added.
- Parsers (record_csv, stanza, gitfmt, versions): no recursion; every field bounded; linear time; no size arithmetic that can overflow at the read bounds (RECORD arena 4*len+6, sb_put doubling).
- E4 ordering: pip by normalized name, kind, directory, path; dpkg by Package, Architecture, kind, path; content_unavailable events first; all comparators are total, so output is deterministic.
- content_unavailable: reasons and sides; per-reason events with side before, after or both; missing for an entry with no `stored` and for an absent object (ENOENT); no_store; too_large; never silent for text, pip reinstall, dpkg and git refs, packed-refs and reflogs (spot-checked).
- Pip rules: split at the first '-'; PEP 503 normalization; pairing by directory and normalized name; added's spelling for a pair; E6 on more than one added and removed in a group.
- Dpkg rules: first stanza of a key kept; third word of Status; installed/removed/upgraded/downgraded; state_changed only when no installed or removed event covers the package.
- TEXT dispatch matches the "stored on every side it exists on" rule.

Scratchpad files: experiment sources are /tmp/scratchpad/exp/exp.c, /tmp/scratchpad/exp/gitsame.c, /tmp/scratchpad/exp/sock.c and /tmp/scratchpad/exp/driver.c. The fuzz input that reproduces finding 3 is /tmp/scratchpad/exp/dpkg_long.in.

---

## Dispositions (implementer, appended)

Every "fixed" has a test that fails on the code before the fix (run and seen); commits 30124dd
(code, tests) and 38d6d5f (spec).

| # | disposition | class, and other instances (checked by running or reading, as said) |
|---|---|---|
| 1 | FIXED. fstatat(AT_SYMLINK_NOFOLLOW) first, never open a non-regular object; open O_NONBLOCK; fstat again. Test `an_object_that_is_not_a_regular_file_is_corrupt_at_once` (child under alarm: old code killed by SIGALRM). | Opening an untrusted path without O_NONBLOCK. Other instances: capture's two opens already use O_NONBLOCK (src/capture/store.c:322, capture.c:338). The O_DIRECTORY opens (store dir, prefix) fail at once on a FIFO with ENOTDIR (experiment). The manifests given to belay_diff are the caller's own paths: not hostile input, not changed. |
| 2 | FIXED. reflog with no regular side declines. Test `git_paths_that_are_not_files_are_absent`. | "A non-regular side is absent" applied per file. Other instances: hooks (5, fixed), the index (a directory named index gave index_changed: fixed, same test), loose refs and HEAD (already declined), packed-refs (empty), pip and dpkg (already checked type). |
| 3 | FIXED as E6 (the interpreter fails its end hook), stated in the spec; flagged to the author as a decision (open question). Test `dpkg_an_event_whose_text_would_not_fit_fails_the_end_hook`. | An interpreter handing the core what the core will refuse. Other instances: pip's events (now checked the same way; not reachable with 255-byte path components); git's path findings degrade to invalid_finding by design (path level, no E6). |
| 4 | FIXED. RECORD bound 16 MiB and 262,144 rows (too_large); arena len+4 (proof in the code comment); 40-byte rows. Measured at the bound, both sides: 92 MB peak, 0.19 s. Test `pip_a_record_past_its_row_bound_is_too_large`. | Per-element memory multiplied by a hostile element count. Other instances: text (12, fixed with a line bound); dpkg (stanzas bounded at 262,144, measured 105 MB at the bound); packed-refs (64 MiB bound, ~40 B a ref: measured 24 MB for 100k refs, not measured at the bound -- known gap). |
| 5 | FIXED to the spec's rule (a symlink hook is no hook). Whether symlink hooks should be reported is put to the author. | Same class as 2. |
| 6 | FIXED with 1 (every non-regular object is corrupt; I/O errors stay errors). The ENOTDIR message now says "not a regular file". | -- |
| 7 | OPEN: not changed. The E6 claim list grows with the paths pip/dpkg claim that changed (~path length each). Bounding it needs the E6 shape (pin #19) to say what happens past the bound: a question for the author. | -- |
| 8 | FIXED in the spec: state over 64 MiB is listed as an E6 trigger. | -- |
| 9 | FIXED. Test `git_a_ref_rewritten_to_the_same_value_says_nothing`. | Comparing parsed values before reporting a move: packed-refs already did. |
| 10 | FIXED. Each end hook marked ended when called; the cleanup ends the rest with no sink. Not tested (needs an allocation failure inside end_all). | -- |
| 11a | OPEN (pin): could_not_interpret is emitted as an event by E6 while the Kinds table gives it level `path`; a pin wording change, for the author. | -- |
| 11b | Schema meaning (generated) fixed to say what the code and prose do. The pin's meaning column still says "past the 4,096th": a pin change, for the author. | -- |
| 11c | OPEN (pin): an interpreter may add and_more / could_not_interpret / invalid_finding itself at path level (interpreter `any` in the pin). Restricting them to the core is a pin change, for the author. | -- |
| 12 | FIXED. Text too_large past 1,048,576 lines. Test `text_past_its_line_bound_is_too_large`. | See 4. |
| tests | Fuzz header claims made true (event-line shape now checked; the bounds claim narrowed to what is checked); the review's dpkg input is a seed. Not added: E6 by the state limit (needs 64 MiB of state), E5 end to end, pip/dpkg corrupt as an event (dpkg corrupt event is tested; pip too_large is). | -- |
