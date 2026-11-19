# M1 Phase 2 -- independent review, round 2

Reviewed: the round-1 fix commit, at 1f058b8. Fresh agent, no implementation context (§0.4b).
Findings fixed in 7daa6a6. Text below is the reviewer's report, verbatim.

---

Review of 1f058b8. Everything below marked VERIFIED was reproduced by running code (ASan+UBSan build, harnesses in /tmp/rv2/). I did not modify the repository.

## Verified defects

**1. HIGH: a file moved between two sibling directories is silently lost. The D7 "unstable directory" fix only covers part of the race window.**
- Setup: /tmp/rv2/races.c, mode `move`, linked with --wrap=readdir. The tree is `A/m_A` and `B/m_B`, and readdir returns B before A. The hook fires when the root's readdir returns "A": it moves `A/m_A` to `B/m_A`. At that moment B has been fully walked and post-checked, and A has not been stat'ed yet.
- Observed: m_A appears in no entry. A and B are both unflagged, and the trailer reads `vanished 0, unreadable 0, unstable 0`. The reader accepts the manifest.
- Expected (per the commit's claim): a flag or a non-clean trailer.
- Why: the check in visit() only covers the time between a directory's own stat and the end of its own listing. A directory that has already been emitted is never checked again. The repo's MOVE_BETWEEN_DIRS test only fires when the second directory is opened, which is after its stat, so it passes.
- Class: "directory consistency checked only inside that directory's own walk window". Other instances:
  - **The scope root has no post-listing check at all.** It is emitted before walk() and never re-checked. Verified with /tmp/rv2/races_big.c, mode `rootmove`: a root with 3000 files plus A/. Once A is done, the not-yet-listed root entry f599 is moved into A. Result: f599 is recorded nowhere, `.` is not flagged unstable, and vanished=0.
  - With a small root (8 entries) the same race gave vanished=1, but only because getdents had already buffered the name.

**2. MEDIUM: the writer emits a manifest its own reader rejects when a symlink keeps changing.**
- Setup: races mode `lnklen`. On each readlinkat("L"), L is replaced by a link with a different target length. This exhausts the 3 retries.
- Observed: the writer returns rc=0 and emits `"size":5,...,"link_target":"a-much-longer-target-xxxxxxxx","unreadable":true`. The reader then fails with "symlink size disagrees with its target's length (line 3)". The whole manifest is unusable.
- Why: visit() keeps the last attempt's stat (size) together with the target from a different link.
- The same outcome applies to any filesystem whose symlink st_size never equals the readlink length. That variant is unverified.
- Class: a retry-exhausted fallback emits a state that breaks the reader's invariants. No other instance found: unstable regular files clear has_hash, and crossed regular files carry unverified.

**3. MEDIUM: a symlink that never disappeared is dropped and counted only as "vanished".**
- Setup: races mode `lnkinval`. During each readlinkat, L is briefly a regular file (EINVAL), then a symlink again.
- Observed: after 3 attempts L has no entry and the trailer says vanished=1. A diff would report L as deleted.
- Expected (claim 3): the entry is flagged, not dropped.
- Code: manifest_write.c:921 drops the entry when `!e->has_link_target`. memset at the top of each attempt guarantees that is false after an EINVAL attempt.

**4. MEDIUM (regression from D4): every file on an overlayfs scope without uniform st_dev is now flagged "mount" and never hashed.**
- Setup: /tmp/rv2/ovl.sh under `unshare -rm`. Overlay with lower on ext4, upper on tmpfs, xino off. The merged root has dev=80, while files have dev=84 (lower) and dev=83 (upper).
- Observed: every reg and lnk entry is `"mount":true`, every regular file is unverified, and none is hashed or stored. This includes upper-layer files and `sub/b.txt` under a normally descended directory.
- Cause: `crossed = mount_root || st.st_dev != root_dev` now applies to all types. Before this commit the st_dev test was used only for directories, so regular files were still hashed.
- On Linux, statx's STATX_ATTR_MOUNT_ROOT already answers "is this a mount", and st_dev is a wrong signal for non-directories on overlayfs. This matters because belay's own per-directory overlays are this setup.
- Class: st_dev used as a mount signal for non-directories. That is the only instance; the st_dev comparisons in read_file and open_dir are same-object identity checks and are fine.

**5. LOW–MEDIUM: per-entry I/O errors still abort the whole check.**
- The commit says only EMFILE/ENFILE/ENOMEM stay fatal. Verified otherwise:
  - mode `readdireio`: readdir in a subdirectory returns EIO, and the whole write fails with "manifest: readdir".
  - mode `lnkeio`: readlinkat returns EIO, and the whole write fails with "manifest: readlinkat L".
- This fails closed, but it contradicts D5.
- Other instances, from code inspection: stat_entry errors other than ENOENT (e.g. EIO, or EACCES from an LSM), fstat failures in read_file, open_dir and the post-walk check, and a readlink returning ≥4096 bytes (`n >= sizeof` is fatal).

**6. LOW–MEDIUM: the reader's time is quadratic in the number of sealed directories, and that memory is unbounded.**
- under_sealed() scans every sealed path for every entry.
- Measured: 10k unreadable dirs took 0.15 s, 20k took 0.52 s, 40k took 1.9 s. Extrapolating, a hostile 1M-line manifest would hang the reader for many minutes.
- Entries are sorted, so a stack of only the current ancestors would make this O(depth).

**7. LOW: the reader accepts input the writer never emits. Claim 1 and the spec's "exactly one byte representation" are false.** Verified with /tmp/rv2/rd.c:
- Permuted field order is accepted, in entries and in the header.
- Non-canonical base64 is accepted. Two cases:
  - `/x==` and `/w==` both decode to 0xff.
  - `//=A` has a misplaced pad that json.c lets through when it is at k=2 with a non-pad after it.
- Entry `!x`, which sorts before `.`, is accepted under an unreadable root `.`. "Nothing below an unreadable dir" is not enforced for entries that sort before the root; the control case `x` after `.` is rejected.
- Flag combinations the writer never produces are accepted: reg with sha256 and unreadable, fifo with unreadable, dir with unreadable and unstable, dir with mount and unreadable.
- A non-canonical scope such as `/s/./t/../u//` is accepted. This fails safe, because the comparator refuses to compare different scopes.
- Class: "semantic or encoding rules enforced only partly". The base64 part lives in json.c, which this commit did not change, but get_bytes depends on it.

**8. LOW: signed overflow (UB) in ts_ns.**
- `touch -d 2300-01-01` gives UBSan "manifest_write.c:511 signed integer overflow: 10413792000 * 1000000000".
- The value is recorded as `mtime_ns:-8032952073709551616`, i.e. year 1715.
- The header's `created` field has the same pattern.
- An ext4 mtime collision is out of reach and ctime still changes, so the impact is low.

## Unverified suspicions
- statx() is called without AT_NO_AUTOMOUNT, so walking a scope may trigger autofs mounts. fstatat implies that flag since Linux 4.14; statx does not, as far as I know.
- The fallback to fstatat happens only on ENOSYS. A seccomp profile that returns EPERM for statx (old Docker) would make every stat fatal.
- Store: only the top directory is checked. Prefix subdirectories (`ab/`) and existing objects are not checked for owner or mode. This is only reachable by someone holding an fd from before a chmod, so it is not a practical bypass.
- Store false refusal on filesystems without real permissions (vfat, or drvfs without metadata).

## What held up
- **Parser bounds:** every `lim - p` check in scan_string, scan_int and parse_object; decode_string's capacity checks; truncated escapes, keys, `tru`, `-`, `[` at end of line.
- **Integers:** INT64_MIN is accepted; INT64_MIN-1, INT64_MAX+1 and UINT64_MAX+1 are rejected; UINT64_MAX is accepted.
- **Mutation fuzz:** 20,000 rounds on a 380 KB manifest under ASan, no crash and no broken invariant.
- **Writer/reader agreement on hostile names** (/tmp/rv2/agree.c): every byte 0x01–0xff in names and targets; invalid UTF-8 (overlong, surrogate, >U+10FFFF, truncated); 0x7f; a path of 15×255 control bytes; 4095-byte targets of control bytes and of 0xff (longest line 48,098 bytes); fifo, socket, 07777 mode, and unsearchable or unreadable dirs and files. All accepted, 539/539 entries.
- **Scope round-trip:** non-UTF-8, a trailing backslash, `"`, \x01 and 0x7f, and é all round-trip.
- **statx encoding:** makedev from statx matches fstat's st_dev.
- **Mount detection:** a bind-mounted dir, a bind-mounted file and a tmpfs mount are all flagged and not read (verified in a user namespace).
- **Cascade** (/tmp/rv2/cascade.c): about 7.8 KB records at the minimum run size, 5 to 4300 files, 576 temp files including multi-level and n>FANIN final merges. Output is byte-identical to the in-memory write, no fds or temp files are left behind, and peak fds were about 68.
- **Heap and fd cleanup:** the per-directory copy and cfd are freed or closed on every error path I traced.
- **Store** owner and mode check: no bypass found.
