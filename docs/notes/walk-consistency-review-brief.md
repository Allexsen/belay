# Request: design-level review of walk consistency

Raised 2026-10-27 under decision 1's stop condition: review round 4 found regressions caused
by round-3 fixes (R4-F4a: the end-of-walk re-check enters mounts that appeared after the walk;
R4-F6: activity through a FIFO or inside a mount raises "raced"), plus a HIGH (R4-F1). Rounds
found 10, 8, 10, 7 defects; three of four HIGHs were in this one area. Patching is not
converging. This asks for a review of the DESIGN, not a fifth defect hunt.

## The question

What can a manifest of a live, unquiesced tree honestly promise, and what mechanism delivers
exactly that? Candidates to weigh, not presupposed:
- The current layered design: per-entry identity checks, ctime window rule, per-directory
  post-subtree check, end-of-walk equality re-check, trailer counts.
- Snapshot capture where available (btrfs/LVM/ZFS snapshots; overlay upper-layer freeze in the
  M4 session engine; a frozen container) and "provisional" everywhere else.
- Re-reading suspect content (git racy rule) vs. marking it unverified.
- Scoping the promise by tier: RL mode (policy killed before the scan; host-reader reads from
  outside) needs no live-tree consistency at all; dev-tier/live checks are best-effort and say so.

## Evidence (all in NOTES/ and the repo)

- Verbatim reviews: NOTES/reviews/m1-phase2-round{1,2,3,4}.md
- Open issues by class: NOTES/known-issues.md
- TORN: see "Torn reads" below.
- Coarse timestamps defeat equality (R4-F1), confirmed on real FAT in CI
  (test/fs/fs_scenarios.c, job "filesystems"); btrfs and NFS pass every scenario.
- Racy-rule cost on quiet trees: negligible (bench/spike_racy.c).
- Stress test (test/test_stress.c): no clean-but-false manifest in thousands of checks with
  atomic mutations, on ext4, btrfs and NFS.

## Torn reads (added 2026-10-27)

**Mechanism.** On Linux, `write(2)` updates mtime/ctime first (file_update_time) and copies the
data into the page cache afterwards. belay's check on a regular file is: stat, open, fstat,
read everything, fstat again, and compare size/mtime/ctime with the recorded stat. A write that
was already in flight when the read began has already moved the timestamps, so they do not
move again during the read: the before and after stats agree, the check passes, and the read
returns part old and part new bytes. The recorded `sha256`, and the stored copy when there is
one, are then of bytes the file never held.

**Measured** (bench/spike_torn.c, Linux 6.18, one writer rewriting a 4 MiB file in place while a
reader runs belay's check, 2,000 reads each): **56 of 2,000 reads torn and passing the check on
ext4, 11 of 2,000 on tmpfs.**

**Why fine-grained timestamps don't close it.** Linux 6.13+ gives a file a new ctime for each
write that is observed (multigrain timestamps), which closes the "two writes in one tick look
like one" hole. It does nothing for this one: the problem is not that two writes share a stamp,
but that a single write stamps *before* its data lands. Every kernel version has that order.
Kernels before 6.13 (Ubuntu 22.04/24.04) and coarse-timestamp filesystems (FAT: 2 s) widen the
window further.

**The racy rule narrows it but does not close it.** The decided racy rule (git's, made
clock-free): when a file's ctime is the newest seen so far in the walk, treat it as suspect and
re-read it. That catches the file currently being written when it is the latest change in the
tree. It misses a write still copying into a file that is *not* the newest-changed -- for
example, a large write into one file while a later, smaller write lands on another. That file's
ctime is not the newest, so it is not re-read, and the torn read stands.

**Candidate mechanisms named so far (not decided, not exhaustive):**
- *Time margin*: treat content as suspect when its mtime/ctime is within some margin of the
  read (git's racy-git uses the index's own mtime). NOTE: this depends on a clock, which
  conflicts with the author's "no clock dependency in walk consistency" constraint below -- the
  review has to resolve that, either by a clock-free formulation or by arguing for an exception.
- *Read twice and compare*: hash the content, re-read, compare; a mismatch means it was moving.
  Cost: double the read I/O on hashed files (hash throughput is ~330 MB/s), or a cheaper partial
  re-read with a weaker guarantee. Note that two reads can both be torn identically only if the
  writer is stalled between them, which is not impossible.

**Where exposure is highest: the dev tier, not RL.** In RL mode the policy's processes are
killed before the scan, and host-reader mode reads from outside the sandbox, so nothing writes
during the check. But M1.5 fires marks around every Claude Code tool call, while that agent is
actively writing to the same tree. Torn reads will therefore happen during our own dogfooding,
not just in theory: a mark taken while the agent's write is still landing records a hash, and
possibly a stored copy, of bytes the file never held. A restore from that copy writes a file
that never existed, and a content diff against it shows changes nobody made. (The entry is
still reported as changed, which is true, so the risk is wrong content, not a missed change.)

## Where the code is now (after the capture refactor, merged with PR #4)

Every consistency judgment is in `src/capture/consistency.c`. Around it: `walk.c` (traversal),
`capture.c` (reading one entry), `outcome.c` (the only place results become flags and counts),
`ident.c` (the only identity comparison), `entry.c` (the format: fields, types, rules; the spec's
field rules and Entries table are generated from it). The format is frozen until this review
concludes.

## What the review must deliver

1. **One decision on what `consistency.c` guarantees**, stated as a property a user can rely
   on -- a sentence of the form "if a manifest says X about an entry, then Y was true of it at
   some instant between T1 and T2", including what it does NOT promise and where (tier,
   filesystem, kernel).
2. **Its cost**: wall-time and I/O on a quiet tree and on a tree under write load, and any
   format change it needs (format is frozen until this decision; a change is allowed but must
   be named).
3. How each open item in NOTES/known-issues.md that touches walk consistency is resolved by
   that decision, or explicitly left out of it.

It does not implement anything.

## Constraints from the author

No clock dependency in walk consistency. Don't touch src/session/. No format change after
diff.v1 publishes without a version bump.
