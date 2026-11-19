# M1 Phase 2 -- independent review, round 4

Reviewed: c178be1 and 39a84c0 (diff 7daa6a6..39a84c0), checked out at 39a84c0 before any
build. Fresh agent, no implementation context (§0.4b). Text below is the reviewer's report,
verbatim.

---

REVIEW ROUND 4: belay `git diff 7daa6a6 39a84c0` (c178be1, 39a84c0)

Every result below comes from commit 39a84c0 (detached HEAD, confirmed with `git log -1`). Builds: `make clean && make check` passed all tests, and `make clean && make check-san` passed all tests with no ASan/UBSan reports. My drivers link against the 39a84c0 release objects. They live in /tmp/scratchpad/r4/ (drv.c, spill.c, deep.c, sealdiff.c, wslclk.c, mnt.c, coarse.c, coarse2.c, limits.c). I edited no tracked files.

== 1. FINDINGS ==

F-1 HIGH: coarse file timestamps defeat the equality re-check. F1 and F2 still give a clean trailer.
- Where: src/capture/manifest_write.c:1245-1249 (ident_matches) and 1050-1057 (window rule). Code comments 1189-1191 and 1477-1479. Spec docs/spec/manifest-v1.md:174-175.
- Defect: on a filesystem whose timestamps are coarser than the kernel tick, a change in the same tick as an entry's previous change leaves (size, mtime, ctime) equal. The window rule misses it too, because the truncated ctime is below walk_start.
- Affected filesystems: legacy ext3/ext4 with 128-byte inodes (s_time_gran = 1 s), HFS+, FAT (2 s), exFAT (10 ms), sshfs/SFTP (1 s), and NFS/SMB exports of these.
- Scenario, directory: the agent writes A/m_A and B/m_B. In the same second belay lists A, and the agent then moves B/m_B into A. Result: A is unchanged, B is not flagged, the trailer is all zeros, and m_B is recorded nowhere.
- Scenario, file: f2 is hashed, then rewritten in place (same size) within the same second. Result: clean trailer and a stale sha256.
- Reproduced by simulation, not on a real coarse filesystem. coarse.c and coarse2.c wrap statx, fstat and fstatat with --wrap to set tv_nsec to 0, which is what timestamp_truncate does on a 1 s filesystem. Output: "unstable=0 drifted=0", with A/m_A absent and the f2 hash stale.
  - Controls (same drivers, real timestamps): A and B are flagged unstable, and f2 is flagged drifted.
- Status: the code comment acknowledges this gap. The spec promises "complete record of one instant" without condition, and the F1 claim lists "or are coarse" as fixed. It overlaps F9 (still open).
- Suggested fix:
  - Handle "racily clean" entries the way git does. Detect coarse granularity (for example, every observed tv_nsec is 0, or a known statfs f_type).
  - Any entry whose ctime lies within one granularity tick of the filesystem's own "now" (the max ctime seen) at re-check time: re-hash it if a file, re-list it and compare names if a directory, or flag it.
  - At minimum, state the limit in the spec and flag the root when granularity is 1 s or more.

F-2 MEDIUM: a directory whose own attributes change after it is recorded gets only "unstable", which the spec defines as "listing incomplete".
- Where: manifest_write.c:648-651 (an unstable directory is RC_NONE, never re-checked) and 1286 (a changed listing gets MARK_UNSTABLE). manifest_read.c:535-536 rejects drifted on a listed directory. Spec :101 and :192-196.
- Scenario: `chmod 0777 d1` (or chown) after d1 is recorded but before the walk ends.
  - The manifest records d1 with mode 0755 and "unstable".
  - A comparator following the spec reports d1's mode as unchanged, plus "children possibly incomplete" and a global "provisional".
  - The same chmod on a file produces "drifted", which the spec says to report as "changed during capture".
- The same happens for the root ".", and for directories flagged unstable during the walk (open_dir mismatch, window rule, post-walk check). Their own attributes are never re-checked at all.
- Reproduced: drv.c modes chmod_dir and chmod_root, in-memory and with run_bytes=1. Output: "d1 mode=755 unstable" and ". mode=755 unstable", with drifted=0.
- Suggested fix: re-check every directory's own attributes, RC_NONE ones included, and emit drifted alongside unstable when they changed. Allow unstable+drifted on directories in the reader and spec. Alternatively, extend the consumer rule: an unstable directory's own fields may be stale and must be reported as "changed during capture".

F-3 LOW: the window rule still flags unchanged directories on WSL's back-and-forth clock.
- Where: manifest_write.c:1050-1057. The comment at 1484-1486 ("A clock STEP can blind this rule but never make it flag") is false.
- Measured on this machine: the wall clock jumps +107.6 s for about 70 ms every 5.4 s.
- Scenario:
  - A directory is changed during a jump, within 108 s before the walk.
  - The walk starts while the clock is normal.
  - The walk reaches that directory during a later jump, so walk_start <= ctime <= now.
  - The directory is flagged unstable and the result becomes provisional.
- The existing tests shift the clock only in one direction (r3_clock_step shifts only `now`; r3_clock_behind shifts both), so this pattern is never exercised.
- Reproduced on the real clock: wslclk.c wraps only openat, to hold the visit until a jump. Output: "X unstable", unstable=1, although nothing changed during the walk. Tests that assert exact unstable counts can flake this way, very rarely.
- Suggested fix: store (realtime − monotonic) at walk start, and skip the rule when the offset at `now` differs by more than one tick. A clock step then only blinds the rule, as the comment intends.

F-4 LOW: the re-check ignores mount topology (two instances).
- (a) Where: manifest_write.c:1227. rs_to's openat crosses mounts that appeared after the walk, then stats and opens inside a filesystem the walk never entered. This breaks the §5.1.1 rule that mounts are not descended. The verdict is still "changed", but the re-check can hang on a dead network mount or trigger an automount deeper down.
- (b) Where: manifest_write.c:1260. The root is checked only through the held root_fd, and the scope path is never resolved again. Mounting something over the scope root during a check gives a clean manifest (unstable=0, drifted=0) while the scope path now shows a different, empty tree.
- Reproduced under `unshare -Urm` with mnt.c:
  - mode "over" logged "re-check statx(x) in dev 0:84 <-- NOT the scope's filesystem";
  - mode "over_root" gave a clean trailer while `ls` of the scope showed an empty tmpfs.
- Renaming the scope away is caught already: the moved directory's ctime changes, so the root is flagged.
- Suggested fix:
  - use openat2 with RESOLVE_NO_XDEV|RESOLVE_NO_SYMLINKS (Linux 5.6+);
  - otherwise statx each component with AT_NO_AUTOMOUNT and stop at STATX_ATTR_MOUNT_ROOT or a dev change;
  - at the end, statx the scope path and compare ino, dev and mount-root with the initial stat (`rst`), flagging the root if they differ.

F-5 LOW: the reader accepts listed directories beyond the writer's own walk limits.
- Where: manifest_read.c parse_entry and the checks at 903-928, against manifest_write.c:906.
- The writer marks unreadable any directory at 129 components (MAX_DEPTH) or with a path longer than 3839 bytes. The reader accepts both as listed, with children, so a hand-edited or corrupt manifest can present a never-listed subtree as a complete listing.
- Reproduced with crafted manifests (limits.c): the reader ACCEPTS a listed directory at 129 components with a child at 130, and a listed 4019-byte directory with a child.
- Status: older than this diff, but the same class F7 says it closes.
- Suggested fix: reject entries with more than 129 components. Reject a directory that is neither unreadable nor mount when it has 129 or more components or a path longer than 3839 bytes.

F-6 LOW: "drifted" is raised by activity that does not change any recorded state.
- Where: manifest_write.c:648-651 and 1245-1249.
- Writes through a FIFO update the FIFO's mtime and ctime. Activity inside a mount that is not captured updates the mount root's mtime.
- Effect: with a busy FIFO in the scope, or a tmpfs such as /tmp or /run under scope "/", every manifest is provisional. Users then learn to ignore the provisional signal.
- Reproduced: drv.c mode fifo gave "fifo drifted"; mnt.c mode inside gave "m drifted mount".
- Suggested fix: for fifo, sock and chr entries and for mount roots, compare identity fields (ino, dev, mode, uid/gid, rdev) rather than timestamps.

F-7 LOW: spec and comments disagree with the code (by reading only).
- spec:89 says a directory whose dev differs from the root's is a mount boundary. This contradicts F4 (a btrfs subvolume is descended).
- manifest.h:72-74: the is_mount comment ("for directories also a dev differing") is stale.
- manifest_write.c:163-167: the old record-layout comment, without the ident, still sits above the new one.
- manifest_write.c:1477-1479: "a change made after this instant can never carry an earlier ctime" is false on coarse filesystems (F-1).
- manifest_write.c:1484-1486: "never make it flag" is false (F-3).
- spec:155-157: the version-1 exemption lists unreadable, unstable and rdev, but not drifted or the mounts count. An older reader would read a missing drifted as no change.
- manifest.h:112-114: the drifted comment says "type"; the code compares dev, not type (minor).

== 2. CLAIMS ==

c178be1:
- Reader prefix-length stack for sealed directories: fix correct. A 20,000-case differential test against a naive checker (sealdiff.c) gave 0 mismatches (7,069 accepted, 12,931 rejected).
- Clock-step tests:
  - root-on-step rule: superseded, since 39a84c0 removed it;
  - ctime upper bound: fix incomplete. It holds for one step, but the back-and-forth pattern still flags (F-3), and no test covers it.

39a84c0:
- F1: fix correct with fine timestamps. My move_in mode is flagged in both paths, and the suite's ±5 s skew test passes. Fix incomplete:
  - coarse timestamps (F-1);
  - by reading: NFS (acdirmin 30 s), FUSE (attr_timeout) and CIFS cache attributes, so the re-check can see stale values for changes made by another host. statx with AT_STATX_FORCE_SYNC in the re-check would help.
- F2: fix correct with fine timestamps. N=10,300 and N=40,000 with spilled, cascaded runs gave exactly the expected drifted set in both paths, and the reader agreed. Fix incomplete:
  - coarse timestamps (F-1);
  - by reading, pre-existing: stores through an already-dirty shared mmap page update no timestamp.
- F3: fix correct (by reading; the suite's test passes).
- F4: fix correct (by reading; no btrfs available here). spec:89 was left stale.
- F5: fix correct. The userns bind-mount test passes with and without statx.
- F6: fix correct.
- F7: fix correct for both named states. Writer and reader call one function on the same inputs, and the writer's only bare-unverified path is size > hash_max. The class is not closed (F-5).
- F8: fix correct where O_TMPFILE works (local Linux filesystems). Not on macOS (acknowledged), nor NFS, 9p or older FUSE, which fall back to mkstemp. An in-scope store still changes during the walk (acknowledged as phase 5).
- F10: fix incomplete (F-7).
- Format additions (drifted, the mounts and drifted counts, struct fields): correct. Flags are inserted in canonical position, counts match, and the reader accepted every manifest the writer produced in my tests.
- Removal of the realtime/monotonic rule: correct. The re-check covers what it did.
- "The re-check runs before the output exists": correct.

== 3. DISMISSED ==
- Stale cached fds in rs_to: harmless. Every re-check open happens after the last recording, so any instant between the end of the walk and the start of the re-check is a consistent snapshot, and every listing and entry is verified after the walk.
- statx versus fstat st_dev encoding: identical, since kernel majors are below 4096. No spurious mismatch (deep.c and drv.c "none" mode were clean).
- rs_to logic at 129-component depth, 4095-byte paths, and siblings such as "s!" sorting between a directory and its children: clean on both paths (deep.c).
- In-place mark rewrite in run files, plus the cascade and spill_finish merges: correct (spill.c).
- Placement of the inserted flags: canonical. The +16 bytes fit easily under the 64 KiB line limit.
- target_outside_scope on unreadable links: never set, because the scratch entry is cleared on each retry.
- Unstable files: always drifted too, since the recorded stat predates the read, so they get a per-entry "changed" signal.
- Renaming the scope root during a check: caught (ctime changes, root unstable).
- Automounts through rs_to: a listed directory cannot be an automount trigger, because the walk's identity check would have marked it unreadable.
- Overlay copy-up during a check: correctly flagged drifted (dev/ino change).
- New code: name, path and fd arrays are bounded, and error paths close the stack fds. ASan was clean.
- macOS build guards (statx, sys/vfs.h, O_TMPFILE, the coarse clock): look right, by reading only.
- write_line with llen < 2 would drop a counted flag, but it is unreachable.

== 4. CLASSES ==
- F-1 (timestamp equality as the only change detector): other instances are F9 (open), attribute caching (by reading) and mmap stores (by reading).
- F-2 (unstable conflates "listing" with "own attributes"): every source of unstable on a directory (open_dir mismatch, window rule, post-walk check, re-check, root). Files are not affected, because unstable implies drifted.
- F-3 (clock dependence): only the window rule and its two comments remain.
- F-4 (mount topology not re-verified at re-check): two instances, rs_to traversal and the scope path. The walk itself is safe through its identity checks.
- F-5 (reader accepts states the writer never produces): the depth and length limits. None found among the new flags.
- F-6 (activity counted as drift): FIFOs and mount roots; by reading, probably tty character devices too.
- F-7 (documentation drift): the six items listed.
