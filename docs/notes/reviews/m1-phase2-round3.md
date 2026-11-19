# M1 Phase 2 -- independent review, round 3

Reviewed: the round-2 fix commit, at 7daa6a6 (diff 1f058b8..7daa6a6). Fresh agent, no implementation
context (§0.4b). Its worktree started on main by mistake; it was corrected mid-review and re-ran
everything against 7daa6a6 (see Provenance). Text below is the reviewer's report, verbatim.

---

Review of 7daa6a6 (diff 1f058b8..7daa6a6), round 3

Provenance: everything ran against 7daa6a6. I first built from a `git archive 7daa6a6` export in /tmp/belay-r3. After the coordinator's correction I ran `git checkout --detach 7daa6a6` in the worktree, and `diff -r` showed the export identical to it. `make clean && make check` and `make clean && make check-san` both pass 165/165, in the export and again in the worktree. The worktree is left at 7daa6a6, detached and clean. Only the 1f058b8 comparisons used a second export, /tmp/belay-r2.

Reproduction drivers are in /tmp/belay-r3-exp: exp.c, fb.c, rd.c, rdf.c, gen.py. They link the real objects and interpose libc with GNU ld --wrap, the same technique as test/test_races_linux.c. "Simulated" below means the interposition stands in for a filesystem or clock property this machine cannot produce.

=== 1. FINDINGS ===

F1. HIGH. src/capture/manifest_write.c:992-999 (rule), 1217-1226 (walk start), 1258 (step threshold)
Defect: claim 1's fix only works if file ctimes come from the local clock with sub-walk precision. Without that, a file moved mid-walk is again recorded nowhere and the trailer is all zeros.
- Scenario: the test suite's own MOVE_ON_ROOT_READDIR case (m_A moves from not-yet-walked A into already-walked B).
- Results (simulated, ./exp move):
  - Control (local fs, sane clock): A flagged unstable, trailer unstable=1. The fix works here.
  - File timestamps 5 s behind the local clock: trailer 0/0/0, m_A recorded 0 times.
  - File timestamps 5 s ahead: trailer 0/0/0, recorded 0 times. The new upper bound causes this one.
  - File timestamps 1 s behind: trailer 0/0/0, recorded 0 times.
  - Clock stepped back 0.4 s at walk start: trailer 0/0/0, recorded 0 times. A 0.6 s step does flag the root.
  - 1 s timestamp granularity: trailer 0/0/0, recorded 0 times.
- Where this happens in practice:
  - Timestamps from another clock: NFS, SMB, WSL /mnt/c (drvfs/9p, stamped by Windows; the WSL clock drift is exactly this), Docker Desktop bind mounts (virtiofs/gRPC-FUSE, stamped by the host), other FUSE filesystems.
  - 1–2 s granularity: HFS+, FAT, ext3, some NFS servers.
  - For a small scope the walk takes under 1 s, so a 1 s skew blinds the rule for the whole walk.
- Fix: make it clock-free. At the end of the walk, re-stat every directory by its recorded path and compare ino, mtime and ctime by equality; flag any mismatch, or flag the root. That catches the already-walked destination, which is the directory whose listing is actually stale, with no clock involved. Keep the window rule only as an extra signal.

F2. MEDIUM. manifest_write.c:992 (`cfd != -1`, directories only) and read_file (721-835)
Defect: walk consistency is checked for directory listings only. Files changed during the walk give a manifest that matches no single instant, with a clean trailer.
- Scenario (./exp files, 2 of 2 runs, reproduced): file y is rewritten after belay hashed it, then file x is rewritten before belay stats it.
- Result: y recorded with OLD content, x with NEW content, trailer unstable=0 vanished=0 unreadable=0, root not flagged. The state (y old, x new) never existed.
- A diff against the baseline calls y unchanged. The commit's own claim-1 wording treats a clean trailer as "a clean walk".
- Fix: apply the same check to every entry. Either use the end-of-walk re-stat from F1, or, when a non-directory's ctime falls in the window, flag the root unstable. The root's `unstable` already means "not a single instant", so no format change is needed and the file keeps its hash.

F3. MEDIUM, new in this diff. manifest_write.c:617 and 638-641 (`static int statx_blocked`)
Defect: one EPERM from statx on one entry switches the whole process to fstatat permanently. That silently turns off STATX_ATTR_MOUNT_ROOT detection.
- Before this diff, a non-ENOSYS statx error was fatal, i.e. loud.
- Scenario (./exp eperm, reproduced, in a user+mount namespace with a same-device bind mount at scope/bm and EPERM injected once for one file):
  - Run 1: bm recorded as a mount.
  - Run 2: bm walked, and the outside file bm/secret.txt recorded with a sha256.
  - Run 3: a fresh belay_manifest_write call with no injection; still walked and hashed.
  - All three trailers clean.
- Real triggers: FUSE or network filesystems that return EPERM for one entry. The flag is also process-global, so it affects every later check in a long-lived session process, and it is a data race across threads.
- Consequences: §5.1.1 containment is broken; with a store, outside files are copied (by reading); and F4 follows.
- Fix: probe statx once per walk on the root fd (statx(root_fd, "", AT_EMPTY_PATH)) and keep the result in walk_ctx. Treat a per-entry EPERM like EACCES (W_INCOMPLETE).

F4. MEDIUM, by reading. manifest_write.c:938-939 (st_dev rule kept for directories)
Defect: a btrfs subvolume inside the scope (also bcachefs) is a directory with its own st_dev but not a mount root. It is recorded as `mount` and never descended.
- Where statx works, the directory st_dev test adds only false mounts like these.
- Changes inside the subvolume never appear. `mount` is not counted in the trailer, and the spec's consumer obligations say nothing about it, so the manifest reads clean and complete.
- The general "a mount's contents are invisible and the trailer stays clean" behaviour is by design for real mounts; I did not reproduce it separately. No btrfs here, so the subvolume case is by reading only.
- Fix: on Linux, when STATX_ATTR_MOUNT_ROOT is in stx_attributes_mask, use it alone. Add a trailer count for mount entries and a consumer obligation ("contents not recorded", never "unchanged").

F5. LOW, regression from claim 4. manifest_write.c:938-939
Defect: where statx cannot report mount roots, a FILE bind-mounted from another filesystem is now hashed (and stored) as a local file.
- That covers kernels 4.11–5.7 (e.g. RHEL 8's 4.18, Ubuntu 20.04 GA 5.4), statx blocked as ENOSYS, or after F3's latch.
- Reproduced on both commits (fb_r2 / fb_r3, tmpfs file bind-mounted into the scope):

  | statx mode | 1f058b8 | 7daa6a6 |
  |---|---|---|
  | statx → ENOSYS | MOUNT | hashed, no mount flag |
  | statx without MOUNT_ROOT in the mask (<5.8) | MOUNT | hashed, no mount flag |
  | working statx | MOUNT | MOUNT |

- Example: files a container runtime or Kubernetes subPath mounts into a project directory.
- Fix: when MOUNT_ROOT is unavailable, compare mount IDs (name_to_handle_at mnt_id, or /proc/self/mountinfo) instead of st_dev. Keep st_dev only on macOS.

F6. LOW. manifest_write.c:668-706 (read_link accepts n == 0) vs manifest_read.c:561-562
Defect: the writer emits a manifest its own reader rejects when the filesystem presents an empty symlink.
- Scenario (./exp emptylink, simulated via readlinkat returning 0 and size 0):
  - Writer returns 0 and writes `{"path":"E","type":"lnk",...,"size":0,...,"link_target":""}` with no unreadable flag.
  - Reader: "symlink with an empty target (line 3)".
- Linux refuses empty targets at symlink(2), but FUSE and NFS can present one. BSD-derived systems reportedly allow creating them; I did not verify macOS. If macOS does, any agent can make every manifest unreadable (it fails closed, but the check is lost).
- Fix: in the writer, treat n == 0 as V_UNREADABLE, or have the reader accept a readable empty link with size 0.

F7. LOW. manifest_read.c:518-539 and 555-567 (claim 7 incomplete)
Defect: the reader still accepts states the writer never emits (crafted manifests via rd and rdf3, reproduced). All of these are ACCEPTED:
- the same link to /etc both with and without `target_outside_scope` (two encodings of one state);
- `target_outside_scope` on an inside target ("x");
- an `unreadable` link with a stale target plus `target_outside_scope`;
- a plain `unverified` on a 10-byte file when `hash_max_bytes` is 64 MiB;
- a `sha256` on a 100 MiB file over the 64 MiB limit.
Fix: check both hash cases against the header's `hash_max_bytes`. Either recompute `target_outside_scope` (the reader has the scope and path) or exclude it from the canonical-form claim.

F8. LOW. manifest_write.c:1166 and 201-218 (spill files beside out_path)
Defect: when out_path or store_dir is inside the scope (e.g. scope = $HOME with the default state directory), belay sees its own writes.
- ./exp self, 3 of 3 runs, reproduced: with nothing else changing, the output directory is flagged unstable every run because of belay's spill files, so the trailer is never clean. The previous run's manifest is also recorded in the next one.
- include/belay/manifest.h:9 says "nothing here writes into a scope", which is false in this setup.
- Fix: exclude or refuse out_path's directory and store_dir when they lie inside the scope, or document it.

F9. LOW, pre-existing, by reading. manifest_write.c:810-813 (stability check)
Defect: read_file proves a stable read only by timestamp equality. On kernels before 6.13, timestamps tick every jiffy (4 ms at HZ=250); some filesystems tick every 1–2 s. Two same-size writes inside one tick around belay's stat and read give a torn sha256, which is recorded as valid and committed to the store, so a restore would write corrupt content.
- Not reproducible here: on 6.18, ext4, tmpfs and ramfs give a fine-grained ctime after a stat (multigrain).
- Fix: treat as racy any file whose ctime is not older than walk start (the git "racy" rule), or use the F1/F2 re-stat.

F10. LOW. Spec and comments disagree with the code:
- docs/spec/manifest-v1.md:91-92: the `sha256` / `unverified` rows still say only "size ≤ / > hash_max_bytes".
- Spec line 87: lnk `size` is "the target length", which is untrue for unreadable links.
- Spec line 96: the directory `unstable` row omits two triggers, fdopendir failure and a child name that does not fit (walk() rel_join).
- The obligations section has no rule for `unstable` directories, for the root's overloaded `unstable` (incomplete listing vs clock step), for trailer `vanished`/`unstable`, or for `mount`.
- manifest.h:93-97 says an unreadable link's target "is then empty"; after retries run out it keeps a stale non-empty target.
- manifest_write.c:456 says "minus a margin"; there is no margin on Linux.
- manifest_write.c:15-16 says st_dev is compared for every type; it is now directories only.

=== 2. CLAIMS IN 7daa6a6 ===
1. Fix incomplete. It is correct on a local filesystem with a sane clock (control row reproduced). It fails under clock skew, coarse timestamps or small steps (F1), and covers directory listings only (F2). The upper bound trades WSL false positives for false negatives when the filesystem's clock is ahead.
2. Fix correct. The reader accepts an unreadable link whose size does not match its target. The header comment is stale (F10).
3. Fix correct. A link that is briefly absent (ENOENT during a non-atomic replace) is still dropped and counted vanished, but its parent's post-walk check flags the parent, so it is not silent.
4. Fix incomplete. Correct for overlayfs on kernels that report MOUNT_ROOT. It regresses file-mount detection elsewhere (F5, reproduced) and keeps dev-based false mounts for btrfs subvolumes (F4).
5. Fix correct for the listed errors. It introduced the EPERM latch (F3).
6. Fix correct. Measured: 200k sealed directories (400,001 entries) read in 0.41 s with 7daa6a6 against 13.9 s with 1f058b8.
7. Fix incomplete. All listed forms are now rejected, but the reader still accepts states the writer never emits (F7) and rejects one the writer can emit (F6).
8. Fix correct. The bounds arithmetic is right, and the reader accepts the saturated values.
"Also" items: NUL-byte cleanup verified (no tracked file contains NUL); fuzz invariants match the reader; the variable initializations are harmless.

=== 3. DISMISSED ===
- base64 canonical checks: right for every padding case ("/w==" ok; "/x==", "Zm9=", "AB=C" rejected); the encoder always writes zero pad bits.
- Reader hash set: probing always ends (load ≤ 1/2); every ancestor prefix is checked; sealing "." is a no-op, but the trailer check covers an unreadable root; close frees every slot.
- Integer overflow: ns_of and d_rt/d_mono can only overflow if the clock jumps from before 1970 to after 2262 mid-walk.
- unstable/unreadable counters: incremented once per entry on every path (retries loop only on V_RACED, before any counter), and they match the reader's counts.
- W_INCOMPLETE: confined to one level, and the root handles it.
- Writer field order matches ENTRY_ORDER, the header and trailer orders, and the spec.
- Worst-case line is under 50 KB, below the reader's 64 KiB limit.
- Suspend mid-walk flags the root: a false positive only.
- Multigrain timestamps: the false positives stay within one tick, as the code comment says.
- An entry carrying belay_manifest_end is rejected; an unknown "belay_manifest" key is ignored harmlessly.
- Error paths in the new code: every fd and allocation is released.
- A per-entry ENOMEM stays fatal: loud, not silent.
- Platforms where rename does not update the moved directory's ctime: the parent's post-walk check catches the swap.
- Unverifiable `vanished`: by design, and on fine-timestamp filesystems the parent is flagged anyway.

=== 4. CLASSES ===
- F1, F9: consistency proven by a clock or timestamp property that isn't guaranteed (cross-clock, granularity, step threshold). Other instances: the per-directory and root post-walk equality checks share the granularity limit.
- F2: a consistency guarantee implemented for one entry type only. No other instance found.
- F3: process-global state set by a per-entry error. Only other global state is base64's static table (a benign race).
- F4, F5: mount boundary detected through a proxy (st_dev, or one statx attribute). Two instances, plus the pre-existing macOS limitation (same-device bind mounts undetected).
- F6, F7: writer and reader languages differ. I swept the type × flag table; no others.
- F8: belay observing its own writes. Instances: out_path, store_dir, and the previous manifest.
- F10: documentation not updated with the semantics. All instances listed above.
