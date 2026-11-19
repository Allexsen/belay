> **Note added at export.** Checked against commit 5f46e7c on 2026-11-15: of the findings this review left open, F3 and F8 are fixed, F9 no longer applies (nothing is truncated any more), and F7's claim was narrowed in the code's own comment.

# Independent review of 79b73d4 (S1-S6 on m1/phase3-diff), 2026-10-30

Fresh agent, no implementation context, own detached worktree at 79b73d4. Report verbatim below.

---

Review of 79b73d4 (main...79b73d4, src + include and their tests). I worked in a detached worktree at /tmp/scratchpad/review-s6/wt and confirmed HEAD was 79b73d4. `make -j8 check`, `make check-san` and `make oracle` all pass, with no compiler warnings and no skips. The main working tree was not touched.

I found no HIGH defects. There are 2 MEDIUM and 7 LOW. Only F1 is a case of "a state read as no change".

FINDINGS

F1. MEDIUM. The two specs disagree: a change that moves only ctime on a FIFO, socket or device node is reported as unchanged.
- Where:
  - src/schema/diff_schema.c:62 limits F_CTIME to reg|lnk|dir.
  - src/diff/classify.c:121-125 applies rule 5 only where the field's class is ctime.
  - docs/spec/manifest-v1.md:260 says a ctime change with every recorded field equal is "never 'unchanged'".
  - docs/spec/manifest-v1.md:384-387 lists "inode flags of symlinks, FIFOs, sockets and devices on Linux" and says "A change to any of these still moves ctime_ns, and the ctime rule above keeps it from rendering as 'unchanged'".
  - diff-v1.md carves these types out (decision (c)); manifest-v1.md was not updated in this diff.
- Concrete input: two manifests identical except ctime_ns 1→5 on `c` (chr), `p` (fifo) and `s` (sock). The diff gives records=0, unchanged=4. A real case on Linux: root adds a trusted.* xattr to a device node or FIFO. A non-root belay cannot list it, so only ctime moves, and the diff says unchanged.
- How established: reproduced with my driver (inputs in /tmp/scratchpad/review-s6/e1/before and /tmp/scratchpad/review-s6/e1/after). test_diff.c:226 pins this behaviour (`record("p") == NULL`).
- Class: spec text left stale by a decision. F4 and F6 are other instances.
- Options: either amend manifest-v1's consumer obligation and the "deliberately not recorded" paragraph, or restore rule 5 for these types.

F2. MEDIUM. `belay_findings_add` writes out of bounds when `n > BELAY_FINDINGS_MAX`.
- Where: src/interp/explain.c:24 checks `f->n == BELAY_FINDINGS_MAX`, then writes `item[f->n]` at :30-31.
- Concrete input: an explain() that sets `out->n = 17` and then calls `belay_findings_add(out, "x")`. ASan reports a heap-buffer-overflow WRITE at explain.c:30, called from diff.c:122. The write runs past `item[]` into the rest of `struct run` (interp, state[], begun) and past the calloc'd block.
- How established: reproduced with /tmp/scratchpad/review-s6/drv_hook.c in "nterp" mode, linked against the sanitizer objects.
- Why it matters: diff.c:129 and :135 already treat n > MAX as an interpreter failure to survive (they bound and clamp it). The helper interpreters are meant to use turns that same failure into memory corruption, against interp.h's "its failures degrade to its own output". Today every built-in declines; Phase 4 adds four interpreters.
- Class: a capacity check by `==` instead of `>=`. I found no other instance: the pair, ancestry and stream stacks are bounded by path length.

F3. LOW. `belay_diff` can return -1 when a complete output is already in place.
- Where: src/diff/diff.c:244-249 renames into place, clears tmp_live, then a failing `sync_dir_of` jumps to `done` with rc = -1. include/belay/diff.h:27 promises "0, or -1 with belay_err set and no output file".
- Concrete input: an output directory with mode 0300 (writable and searchable but not readable, like a drop directory). mkstemp and rename succeed, `open(dir, O_RDONLY|O_DIRECTORY)` fails with EACCES, and belay_diff returns -1 ("cannot sync"). Yet <dir>/out.diff holds a complete diff, and any earlier file at that path has been replaced.
- How established: reproduced (/tmp/scratchpad/review-s6/e1/wo).
- Class: a step after the publish is reported as failure of the whole operation.
- Related instances (no sync at all, rather than a wrong error): manifest_write.c:279 renames the manifest into place with no directory fsync, and store.c's commit renameat has none either. The diff output is now the only artifact synced after its rename.

F4. LOW. Scopes are compared only after entries have been read.
- Where: diff.c:207 runs find_root on both manifests, which reads and validates every entry up to ".". The scope comparison comes later, at diff.c:141. docs/spec/diff-v1.md:101 and include/belay/diff.h:26 say "Manifests of different scopes are refused before any entry is read."
- Concrete input: before has scope /s and an orphan "!a/b" that sorts before "."; after has scope /other. The error is "manifest: orphan ... (line 2)" (CORRUPT) instead of the scope refusal (INVALID).
- How established: reproduced (/tmp/scratchpad/review-s6/e1/b2 and /tmp/scratchpad/review-s6/e1/a2).
- Impact: no entries are ever compared across scopes, so the safety property holds. The spec statement and the error precedence do not. Comparing headers right after the two opens would fix it.

F5. LOW. Spec gap (code, spec and oracle all agree): a path missing below a raced non-directory gets a definite added/removed.
- Where: diff-v1.md:103-109 makes an absence unknown only when the nearest ancestor is a directory carrying unreadable, mount or unstable. ancestry.c:6 returns ANC_NONE for any non-directory, raced or not (classify.c:131-139).
- Concrete input: before = {".", "d" reg raced}; after = {".", "d" dir, "d/x" reg}. The diff gives "d" unknown [raced], which is right, but "d/x" added. Raced means "d" changed after it was recorded, for example into a directory holding x, so x may have existed at the end of the before walk. Swapping the sides gives "removed".
- The spec already applies this reasoning to the side that has the path (diff-v1.md:108: "it may not have existed at the end of that walk"), but not to the absent side's ancestor. This never produces "unchanged", and the trailer says provisional.
- How established: reproduced (/tmp/scratchpad/review-s6/e4). Directories cannot hit this, because rule 10 allows raced on a directory only with unreadable or mount, which seal it.

F6. LOW. The "on mount roots" column says "compared" for iflags, caps and xattrs, but manifest rule 22 means a mount root never carries any of them.
- Where:
  - diff_schema.c:74/77/80 set MR_COMPARED, and the generated diff-v1.md table repeats it.
  - The pin test/expect/diff-fields.md:47-49 also says "compared", while its own rule O2 (:68) says caps/xattrs are not compared on a mount root.
  - classify.c:21/41/44 implements O2, so for caps/xattrs the column misstates behaviour. test_pins.c:280 skips exactly those two cells.
  - For iflags the column is followed. Since a mount side never has iflags, every directory↔mount-root change gains reason iflags_unknown, and that reason's text ("absent means they could not be read") is wrong there.
- Concrete input: before "m" dir with iflags and xattrs; after "m" mount root. Output: {"path":"m","outcome":"unknown","type":"dir","unknown":["mount","iflags_unknown"]}. xattrs differ but are not in `changed`, though the table says they are compared on mount roots. The outcome is unknown either way.
- How established: reproduced (/tmp/scratchpad/review-s6/e5).
- Class: a schema column contradicted by a special case in differs(), with a test skipping the cells that disagree. Fixing it needs a pin change (its own PR).

F7. LOW. The mid-copy store-failure test passes only because of a signal setting belay itself never uses.
- Where: test/test_races.c:1372 sets SIGXFSZ to SIG_IGN in the child before applying RLIMIT_FSIZE. belay never ignores SIGXFSZ, so the R11 claim (capture.c:30-35, :399-416) does not hold for the fault the test injects.
- Concrete input: `ulimit -f 64`, a store dir, store_max 1 MiB, and a 256 KiB text file. The capture is killed by SIGXFSZ (exit 153), no manifest is written, and a 65,536-byte staged .tmp-<pid>-0 is left in the store.
- How established: reproduced (/tmp/scratchpad/review-s6/t3).
- The degrade path itself is correct for errors that write(2) returns (ENOSPC, EDQUOT, EIO). The manifest temp file and run files are subject to the same limit.

F8. LOW. Findings left by one path can appear on the next.
- Where: diff.c:111 resets only `x->findings.n`, but interp.h:94 promises "`out` cleared first".
- Concrete input: an interpreter adds two findings for path f, then for path g sets out->n = 2 without writing anything. g's record carries f's findings. Since all interpreters share this one buffer, one interpreter's text can be attributed to another interpreter's path.
- How established: reproduced (drv_hook.c in "stale" mode).
- Class: a reused output buffer that is not cleared; same family as F2.

F9. LOW. Truncation can turn invalid UTF-8 into a valid finding.
- Where: explain.c:26-28 backs up over any number of continuation bytes (not at most 3).
- Concrete input: a 300-byte finding made only of 0x80 bytes is emitted as "findings":[""], not "invalid finding". "abc" followed by 300 bytes of 0x80 becomes "abc".
- How established: reproduced (drv_hook.c in "cont" mode).
- Class: sanitising after truncation instead of before.

CHECKED AND CORRECT
- classify.c:
  - What I checked: rules 1-6, the dev relation, ino within one device and across a scope-root remount, node and mount-root timestamps, one-sided iflags, attrs_read, and the order of the reasons.
  - How: read against diff-v1.md and diff-fields.md; the oracle passed on 10 seeds (about 74,000 pairs, including names like a!b, a-b, a., !x, -y and #h). I also captured a real throwaway tree, changed it and captured again; the outcomes were as expected (chmod fifo → [mode], user xattr → [xattrs], same-size rewrite → modified [sha256], rename-over with the same bytes → [mtime, ino], new file under d!x → added).
- ancestry.c: the stack is always a chain of proper byte prefixes, and popping during a query is safe because every popped T has all of T/… sorting before the query. Lengths stay at most 4095. Checked by reading and by the oracle.
- manifest_stream.c orphan and sealed stacks: I fuzzed them against a brute-force reference on 19,000 generated manifests with names such as `a!`, `a-`, `a.`, `!`, `-`, space, `.a`, `\x01`, `\x7f`, plus unreadable dirs. 0 mismatches in either direction (/tmp/scratchpad/review-s6/fuzz_orphan.py).
- Unknown keys are rejected in header, entry and trailer; a second header line, or a trailer key inside an entry, is rejected (by reading).
- The digest equals sha256 of the file for any manifest the reader accepts. Rewind resets digest, stream and trailer, and the header comparison is deterministic because the struct is memset first.
- The whole-struct memcmp of the root (diff.c:154) is deterministic because decode_entry memsets (manifest_decode.c:394). I verified the check fires: an interpreter begin() hook rewrote the root line in place, with the root placed beyond the first stdio buffer, and the diff failed with "changed while it was read" and left no output. For small files the whole manifest is already buffered at rewind, so the check only covers the instant between the prescan and the rewind.
- Refusing an output that is an input works for ./, symlink and hard-link spellings. ASan/LSan report nothing on the error paths I ran (orphan, different scopes, missing input, output equal to input, failed sync).
- EMIT_LINE_CAP (64 KiB) is enough for the worst record: about 50 KB for a 4,095-byte path of control bytes plus 16 findings of 255 control bytes.
- Capture side:
  - `seen` now holds only recorded names, and `dname` stays valid across the recursion because each DIR* has its own readdir buffer.
  - A name that vanishes and comes back flags its directory.
  - Store transactions: abort after a failed write is safe, commit ends the transaction on every path, and the staged file is unlinked on every in-process failure.
  - store_failed is counted once per file.
- The re-check verdict key hash is effective: in a scratch copy I dropped one verdict, and the capture failed with "re-check verdict for "b" misaligned" and wrote no manifest. No test in the suite exercises that branch.
- Minor note: cap_walk now ignores a visit() return value it does not recognise (neither recorded nor incomplete), where the old code failed on it. That is unreachable today.

NOT CHECKED
- The libFuzzer target (no clang on this host).
- macOS behaviour.
- Real mounts, remounts, overlayfs, btrfs, NFS or FAT: I created no mounts, so the dev/ino/remount logic was only exercised with hand-built manifests.
- Crash durability of the directory fsync.
- CI scripts, the oracle generator and reference internals, and gen_schema beyond `gen-check`.
- /tmp/belay_diff_1709577 contains an orphaned empty diff.ndjson.J2i4b6. It predates my build (created 17:20:34, my test_diff was linked at 17:22:06), so it most likely came from someone else's run that was killed mid-diff. I left it untouched.
- My worktree is still registered in the main repo; remove it with `git -C /home/user/workspace/belay worktree remove /tmp/scratchpad/review-s6/wt`. The review driver is /tmp/scratchpad/review-s6/drv.c.
