# PR #28 (decisions 2026-11-01), independent review, verbatim

Reviewer: a fresh agent with no implementation context, 2026-11-01.
Scope: `origin/main...origin/m1/decisions-2026-11-01` (src/ and test/).
Relayed verbatim (the reviewer's own message, unedited); dispositions appended after it.

---

Review of origin/main...origin/m1/decisions-2026-11-01 (src/ and test/; head 2857279)

I worked in a detached worktree and removed it afterwards. The main checkout was not modified (git status is clean). Every belay run used a fresh 0700 BELAY_STATE_DIR in the scratchpad, plus one under /dev/shm for the state-on-another-filesystem case, which I deleted afterwards.

SUITES
- make -j8 check: passed. 425 tests ran, 0 failed, 0 skipped; the selftest and the accounting check passed too.
- make oracle ORACLE_BASES=60: "=== oracle: PASS". All coverage cells were met, including "interpreters, with no store 107/107".
- make reference REFERENCE_N=100: 268 cases, 389 pairs, 0 failing, 4.9 s.

ESTABLISHED DEFECTS (most severe first)

D1 (MEDIUM, soundness, and the docs promise more than the code does). The coarse-timestamp guard only catches whole-second timestamps. Timestamps that are coarse at a kernel tick or at 10 ms still have a non-zero nanosecond part, so they pass the test, and the newest-ctime fallback then misses the very rewrite the decision was meant to catch.
- Where:
  - src/capture/previous.c:142 sets `fine` when `e->ctime_ns % 1000000000 != 0`.
  - previous.c:171-175 refuses the prefilter only when no ctime has a nanosecond part.
  - The comment at previous.c:165-170 says "On fine-grained timestamps the fallback is sound".
  - docs/cli.md (the mark section) says: "That is sound on fine-grained timestamps. On coarse ones (1 or 2 seconds, or a kernel tick) it could miss ..., so when every ctime ... has a zero nanosecond part, mark reads every file instead". Kernel-tick timestamps are named there as coarse, but the test cannot detect them.
- Experiment: a probe built from test/test_mark.c's harness, using the same g_round_ns stat-rounding fsops. Each run did this:
  1. Write d0/f0 just past a tick boundary.
  2. During the previous walk, after f0 is opened, rewrite f0 at the same size within its tick.
  3. Three ticks later, change d2/f11, which the walk lists afterwards. This moves the newest validated ctime past f0's.
  4. Run mark with g_last_start = 0 (previous_start_ns unknown), then a full capture, and compare the two bodies.
- Output:
  - Tick 1 s, 3 of 3 runs: "prefilter 0 (the previous walk's start is unknown and the scope's timestamps are coarse) ... mark AGREES WITH check".
  - Tick 10 ms, 3 of 3 runs, and tick 4 ms, 3 of 3 runs: "prefilter 1, trusted 11, racy 1 ... mark DIFFERS FROM check". For d0/f0 the mark recorded sha256 170fc778a250… (the content read during the walk); the check recorded 26a156022044… (the content on disk).
  - Control (KNOWN=1, walk start kept): all runs "AGREES WITH check".
- When it bites on a real system: ext4, xfs, btrfs or tmpfs on kernels without multigrain timestamps (before 6.13, which is most LTS distributions), exFAT (10 ms), any scope with belay's state on another filesystem.
- On this host (6.18) multigrain closes the hole for real files. I measured it: 300 files written with no stat in between all share one ctime, .067125959, coarse but with a non-zero nanosecond part. A write after a stat gets a fresh fine-grained ctime. So the probe needs the simulated rounding to show the miss.
- Same class, second instance (established by reading the code, not run): `fine` is computed over every entry, including `mount` entries. manifest-v1.md:268-270 says a mount root's times belong to the mounted filesystem. So a coarse scope (for example a vfat or ext3 tree) with any fine-grained filesystem mounted inside it passes the guard and uses the fallback. Related and pre-existing: walk.c:73-75 and previous.c:144 also let a mount root's ctime become R.
- No zero-nanosecond test can detect tick-granular timestamps: a coarse clock reading carries an arbitrary nanosecond part. Fixing it means either treating the fallback as unsound everywhere (read in full) or recording "read within its own tick" per entry. That is the author's call. At minimum the docs and the code comment should stop calling the fallback sound and stop listing "a kernel tick" among the cases that are handled.

D2 (LOW; undefined behaviour). Signed int64 overflow when the receipt sums the trailer counts.
- Where: src/cli/receipt.c:317, `moving += jint(...)`. jint saturates values of 2^63 and above to INT64_MAX (strtoll). The manifest reader accepts any uint64 `vanished` (that count is not checked against entries), and emit.c prints it with %zu.
- Experiment: I set the trailer of checkpoint 1's manifest to "vanished":9223372036854775807 and checkpoint 3's to 1 (and in a second run to 18446744073709551615). Then `belay diff --since 1 --to 3`.
  - Release binary: the JSON trailer has `"provisional":true`, but the receipt prints no "changed while read" line at all (the sum wrapped negative).
  - ASan+UBSan build of the same CLI: "src/cli/receipt.c:317:74: runtime error: signed integer overflow: 9223372036854775807 + 9223372036854775807 cannot be represented in type 'long int'".
- The old code printed the two values separately and had no sum. The diff introduced this. I found no other place that sums trailer counts. Fix: saturating add, or sum as uint64 with a cap, and treat any non-zero count as worth the line.

D3 (LOW; wording, now in user-facing text). "running belay again settles them" is false for before-side counts, and the count is per side, not per entry.
- Experiment: with "vanished":1 in checkpoint 1's trailer:
  - `diff --since 1 --to 3`, run twice: "1 entry changed while it was read; running belay again settles it" both times.
  - `diff --since 1` (to now): the same line again, because the before side is a fixed historical checkpoint.
- Also, by reading receipt.c:315-317: the six per-side counts are added together, so one path raced on both sides prints "2 entries".
- The old line's before/after split, which told the user which checkpoint was unsettled, is gone.
- The same wording appears in docs/cli.md:117-119 and manifest-v1.md:244-246.

D4 (LOW; pre-existing, but this diff makes it easy to hit). The receipt's "and N more" undercounts when a record hit the 4,096-finding cap.
- Where: receipt.c:204-205 prints `f->n - 15` and ignores the n of the trailing `and_more` finding.
- Experiment: a 16 MiB logs/HEAD of 114,110 checkout entries added after the check, then `diff --since 1 --to 2`.
  - Receipt: "HEAD: 114110 reflog entries", 15 lines, then "and 4081 more".
  - JSON: 4,096 findings, the last being {"kind":"and_more","n":110016}.
  - The true remainder is 114,096.
- Before this diff a reflog was read only up to 64 KiB (a few hundred entries), so a reflog could not reach the cap.

SUSPICIONS (labelled; not defects against the decisions)
- S1, store growth: every changed reflog now costs a full copy of up to 16 MiB per checkpoint, and belay never deletes anything. Measured: three versions of a roughly 16 MiB HEAD reflog left a 49 MiB store. A busy repository with logs/HEAD plus a branch log of several MiB each, under frequent marks, grows the store without bound. Worth a sentence in docs/cli.md.
- S2, library users only: if hash_max_bytes is below 16 MiB, a reflog between hash_max_bytes and 16 MiB is OUT_TOO_LARGE with no hash and no copy, and git.c reports it as "missing" rather than too_large, because size ≤ 16 MiB. The CLI is not affected (hash limit 64 MiB).
- S3: when hash_max_bytes and store_max_bytes are both above 16 MiB, a 20 MiB unclaimed text file is kept but a 20 MiB reflog is not. This is consistent with "whatever store_max_bytes says", but odd.

CHECKED AND SOUND (how)
- Reflog through the real binary, with the default store_max of 64 KiB and the state on the same filesystem:
  - 1 MiB logs/HEAD: check stores it (manifest has "stored"). mark trusts it and records the stored copy (trusted 1). Appending a checkout line and a reset line, then diffing, gives "HEAD: 2 reflog entries" plus both moves.
  - Growing it to 18,049,057 bytes: mark hashes it without storing. `diff 3→4` gives "content unavailable (after): too_large", in JSON too.
  - Boundary: exactly 16,777,216 bytes is stored (checkpoints 3 and 5), and an append that lands exactly on 16 MiB is interpreted ("1 reflog entries" plus the move). At 16,777,239 bytes both sides are too_large.
- mark's trusted-copy logic matches a full check:
  - I stripped "stored" from the previous manifest, as a checkpoint taken by the old binary would have it. The next mark re-read the reflog and stored it (trusted 0, "stored":"dca03ea5…"), and the mark after that trusted it with its copy.
  - A reflog over 16 MiB has want=false, so it is trusted with no copy, as a check would leave it.
  - capture.c:400-403 and the prefilter path use the same `want`.
- Interpreting a 16 MiB reflog is cheap: 114,110 appended entries took 0.06-0.07 s with 19.8 MB max RSS. One 16 MiB line ("Fast-forwar" repeated, so plain()'s scan never matches) took 0.07 s with 26 MB.
- too_large comes before no_store and missing as the spec says: stored.c:19-20 gives missing before no_store, and the new branch in git.c read_sides replaces only missing. The oracle's no-store cells pass.
- Prefilter refusal through the CLI, with state on /dev/shm (tmpfs) and the scope on ext4:
  - With fine timestamps, mark uses the fallback: "reference point: the newest ctime recorded …", JSON "reference":"newest_ctime".
  - After I rounded every ctime_ns in the previous manifest to whole seconds, the next mark printed "every file read (the previous walk's start is unknown and the scope's timestamps are coarse)". meta.json and log keep that reason, used:false, so it counts as a full capture for --full-every and resets the counter. The following mark prefiltered again.
  - The 74-character reason fits full_reason[160].
  - The Q8 "ctime went backwards" redo runs only when s.prefilter is true (state.c:731), so it cannot interact with a refusal.
  - With the walk start known, coarse timestamps still prefilter: the existing 2 s test asserts trusted+racy == 12, and my KNOWN=1 control agreed with the check.
- False "coarse" on a fine-grained filesystem (every ctime a whole second by chance) only costs a full read and is about 1e-9 per entry. Raced, unstable and unreadable entries counting toward `fine` is correct: their ctimes still come from the same filesystem's clock.
- Receipt arithmetic for honest input: the counts are size_t from the manifests, printed with %zu, never negative. Singular and plural forms are right (unit test plus my runs).
- The doc changes in diff-v1.md and manifest-v1.md (the unverified/unknown rule, the size-proves-modified rule, provisional) agree with diff-v1.md:148-149, 206, 219, 252 and 99.

TEST GAPS
- Nothing covers tick-granular timestamps under the fallback. The probe above (rounding 4 ms or 10 ms, g_last_start = 0, rewrite in f0's tick, later change to d2/f11, compare mark with check) fails today and would guard whatever fix is chosen.
- Nothing covers a mount entry with a fine ctime inside a coarse previous manifest.
- No receipt test with saturated or huge counts (UBSan would catch D2), with before-side-only counts, or with one path raced on both sides.
- No capture-level test that a reflog over 16 MiB has no "stored" and a reflog of exactly 16 MiB does. test_mark's new test covers only 100,000 bytes, and test_interpreters uses synthetic sizes.
- No CLI test (test_cli or equivalent) that the coarse refusal reason reaches meta.json and log and resets the --full-every count.
- No receipt test for "and N more" when the findings carry an and_more element (D4).

All my scratch files and the worktree were removed.

---

## Dispositions (implementer, appended)

Each fix has a test that fails with the fix reverted alone (scratchpad/canary/c3.json): 4 of 4
KILLED.

- **D1 -- not fixed: the decision's own limit; for the author.** The zero-nanosecond test is the
  author's decision (2026-11-01, 2). It cannot recognise tick-granular timestamps (4 ms, 10 ms),
  which carry a nanosecond part, and the reviewer reproduced the miss there (3/3 at 10 ms and at
  4 ms). Fixed what was claimed beyond it: the code comment and docs/cli.md no longer call the
  fallback sound or list "a kernel tick" as handled; they name the gap and the remedy (state on
  the scope's filesystem, or check). Fixed the second instance: a mount root's ctime no longer
  counts toward "fine" or toward R (`a_mount_root_does_not_make_a_coarse_scope_fine`; canary
  KILLED). Options for the author: a full walk whenever the walk's start is unknown, or keep the
  heuristic and the documented gap.
- **D2 -- fixed.** Per-side counts summed as uint64, saturating; negative values ignored. Test
  (three INT64_MAX counts -> 18446744073709551615); canary (plain add) KILLED.
- **D3 -- fixed.** The line counts each side: the newer side's entries "running belay again
  settles"; an earlier checkpoint's "a diff from a later checkpoint avoids". docs/cli.md and
  manifest-v1.md reworded. Canary KILLED.
- **D4 -- fixed.** "and N more" adds an and_more finding's n. Test; canary KILLED.
- **S1 -- documented** (docs/cli.md: the store keeps every version, reflogs up to 16 MiB each).
- **S2 -- recorded, not fixed.** Only a library caller with hash_max_bytes below 16 MiB; the CLI
  hashes to 64 MiB. My own new boundary test met it (test_mark's helper hashes to 1 MiB) and now
  uses the CLI's limits.
- **S3 -- as decided** ("whatever store_max_bytes says").
- Test gaps closed: the 16 MiB boundary at capture (exactly kept, one byte more not); a mount root
  in a coarse manifest; saturated counts; before-side-only counts; and_more. Left: tick-granular
  timestamps under the fallback (D1, the author's), the coarse refusal through the CLI's
  meta.json and --full-every count (verified by the reviewer by hand).

