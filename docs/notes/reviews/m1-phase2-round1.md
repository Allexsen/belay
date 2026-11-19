# M1 Phase 2 -- independent review, round 1

Reviewed: writer, reader and store (branch m1/phase2b-streaming), at 895ef8c. Fresh agent, no implementation context (§0.4b).
Findings fixed in 1f058b8. Text below is the reviewer's report, verbatim.

---

## Independent review of belay capture (branch m1/phase2b-streaming, 895ef8c)

Every defect below was reproduced by running code. All harnesses and fixtures are in `/tmp/rv/`. No repository files were changed. The fault-injection harness is `/tmp/rv/inject.c`. It links with `-Wl,--wrap=openat,--wrap=readlinkat,--wrap=readdir` so a race can be forced at an exact point. Mount tests ran inside `unshare -Urm`.

### Verified defects

**D1. A directory's metadata and its contents can come from two different directories, with no flag. Severity: medium-high.**
- **Defect class:** an identity check made on one object type but not its siblings (metadata from `fstatat`, content from a later `openat`).
- **Setup:** `s/A` (mode 0700, holds `x_marker`) and `s/B` (mode 0755, holds `y_marker`). `renameat2(RENAME_EXCHANGE)` swaps A and B between the `fstatat` and the `openat` of A (`/tmp/rv/inject 1 /tmp/rv/i1/s /tmp/rv/i1/m A B`).
- **What happens:**
  - The write returns 0.
  - Entry `A` carries ino and mode 0700 of the original A, but its listed child is `A/y_marker`.
  - `y_marker` appears twice (same ino, under A and under B).
  - `x_marker` is missing from the manifest.
  - vanished, unreadable and unstable are all 0. The manifest claims to be a clean instant.
  - In reality the directory named A now has mode 0755, but the manifest says A's mode and ino are unchanged. That is a false "unchanged" on A, and a silent loss of `x_marker`.
- **Expected:** `visit()` checks `fstat(cfd)` against `st` (ino and dev), as the regular-file path does at lines 619-621, and flags `unstable`/`unreadable` on a mismatch.
- **Reachability:** 3000 natural race iterations on ext4 never hit the window; it is narrow but real.
- **Other instances:**
  - Symlinks: `readlinkat` after `fstatat` has no identity check either. A symlink swapped for another symlink records size and target from different links. A symlink swapped for a file aborts the whole write (D5).
  - Regular files: covered by D7.

**D2. `"scopes"` parsing breaks when the scope path ends in a backslash. Severity: medium (writer emits a manifest the reader rejects).**
- **Defect class:** hand-rolled scanning of a JSON string that is not escape-aware.
- **Setup:** `mkdir 't1/sc\'`, then write and read.
- **What happens:** the writer succeeds and the header holds `"scopes":["/tmp/rv/t1/sc\\"]`. The reader fails with `manifest: more than one scope`. The cause is in `parse_header`: the skip loop `!(*q=='"' && q[-1] != '\\')` treats the closing quote after an escaped `\\` as escaped.
- **Other instances:** none found. I checked `find_key`/`count_key`. They are not escape-aware either, but they are safe for writer output, because every `"` inside a written string is preceded by `\`, so `,"key":` can never appear inside a value.

**D3. A duplicate name from `readdir` produces a "successful" manifest the reader rejects (in-memory path only). Severity: medium (a real trigger is unverified).**
- **Defect class:** an invariant checked on one code path but not on its sibling.
- **Setup:** `readdir` returns directory `a` twice in the same directory (injected: `/tmp/rv/inject 3 ...`).
- **What happens:**
  - With the default buffer (no spill), the write returns 0 and the manifest holds `a` and `a/k` twice. The subtree was walked twice. The trailer count matches. The reader then fails with "duplicate path (line 4)".
  - With a spilled run the write correctly fails ("merge out of order").
- **Expected:** the `sp.nruns == 0` branch (around line 917) should run the same strict-order check `merge()` does.
- **Real trigger:** I tried to make tmpfs return a duplicate with a concurrent rename on kernel 6.18 and could not. Filesystems with index-ordered `readdir` may still do it. Unverified.
- **Other instances:** none. The `written != n_entries` check covers both paths.

**D4. Same-device bind mounts are not detected as mount boundaries, and regular files never get the boundary check. Severity: medium (claim 1 is incomplete).**
- **Defect class:** mount-boundary detection by `st_dev` only, applied to directories only.
- **Setup:** in a user namespace, `mount --bind outside/secretdir s/x` (same fs), `mount --bind outside/secret.txt s/file`, and a tmpfs file from another device bind-mounted onto `s/file` in a second test.
- **What happens:**
  - `x/inner.txt` is walked, hashed and stored with no `mount` flag.
  - `file` gets the hash and stored copy of the outside file. A file on another device (dev 77 against root dev 2096) is hashed with no `mount` flag, because `crossed` is only consulted for `BELAY_T_DIR`.
  - The tmpfs directory mount was correctly flagged `mount:true`.
- **Expected:** detect mounts with `statx` `STATX_MNT_ID` / `STATX_ATTR_MOUNT_ROOT` where available, and apply the check to every entry type.
- **Other instances:** none beyond the two shown.

**D5. One unexpected per-entry condition aborts the whole manifest. Severity: medium (availability).** Any user, or any process writing in the scope, can make `check` fail permanently.
- **Defect class:** a per-entry problem treated as a fatal error instead of being flagged on that entry.
- **Instances, all verified:**
  - A directory with r but no x (`chmod 0444`) aborts with `fstatat d/f` (EACCES). An x-only directory is handled correctly, as unreadable.
  - A symlink swapped for a file between `fstatat` and `readlinkat` aborts with `readlinkat l` (EINVAL).
  - A 4095-byte symlink target aborts with "link target too long". This is off by one: the code reads at most 4095 bytes and then rejects 4095. The reader accepts 4095. 4094 works.
  - Directory depth over 128 aborts.
  - A relative path over 4095 bytes aborts.
- **Unverified, by reading the code:** EAGAIN from `openat(O_NONBLOCK)` on a file holding a write lease, and EIO from `read` in `hash_fd`, also abort the whole run.

**D6. The fan-in "cascade" re-merges one ever-growing run, so temp-file I/O grows quadratically. Severity: medium (performance and disk).**
- **Defect class:** an unbalanced merge cascade.
- **Measured** with the minimum run size (wchar from `/proc/self/io`):

| Entries | Bytes written / manifest size |
|---|---|
| 5k | 3.0× |
| 20k | 5.3× |
| 80k | 13.1× |

- **Why:** each cascade rewrites the whole accumulated run. Peak temp disk is also about twice the run data during a cascade.
- **Scale estimate:** at the 4 MiB default, a tree of about 10M entries should see roughly 20× amplification. I extrapolated that; I did not measure it.
- Memory itself held; see "What held up".

**D7. A regular-file entry can mix ctime/mtime from one state with the hash of another. Severity: low.**
- **Defect class:** a partial stability comparison. Only `before` vs `after` are compared; `st` (`fstatat`) vs `before` is compared on ino, dev and size only.
- **Setup:** rewrite the file in place, same size, between `fstatat` and `openat` (`inject 5`).
- **What happens:** the entry has the old ctime with the sha256 of the new content, and no `unstable` flag. The spec says `unstable` applies when "size, mtime or ctime moved".
- **Expected:** compare `st` mtime and ctime to `before` too.
- **Impact:** I could not build a false "unchanged" from this, only a spurious "unrecorded attribute" change later.

**D8. The reader accepts states the writer never emits, including one that loses the "content unknown" signal. Severity: medium for (a), low for the rest.**
- **Defect class:** the reader's accepted language is wider than the writer's output.
- **Verified** with mutated manifests in `/tmp/rv/rd/`. All of these are accepted with rc=0:
  - (a) `reg` with neither `sha256` nor `unverified`. A comparator would treat it as unhashed, with no flag forcing "unverified".
  - (b) A duplicate key preceded by whitespace (`..., "sha256":"000..."`). `count_key` checks `p[-1]` directly while `find_key` skips whitespace, so the duplicate goes undetected and the first value wins.
  - (c) `"path":"f"`, a non-canonical escape. `\u0080`–`ÿ`, uppercase hex and `\/` are accepted too. The source comment says the accepted language equals the writer's; it does not.
  - (d) `"size":3abc` (trailing junk after a number) and `"mtime_ns": +N` (strtoll whitespace and sign).
  - (e) No `.` root entry.
  - (f) An entry under an `unreadable` directory.
  - (g) `sha256` on a `dir`.
  - (h) A `reg` type whose `mode` has directory type bits.
- **Other instance of the duplicate-key gap:** the header and trailer key checks share the same `count_key`.

**D9. The header writes the scope as raw bytes even when it is not valid UTF-8. Severity: low.**
- **Defect class:** bytes reaching JSON output without the UTF-8 gate.
- **Setup:** a scope directory named `s\xff`.
- **What happens:** the header line is not valid UTF-8, and Python's `json` rejects it. Belay's own reader accepts it.
- **Other instances:** none. Grep shows `belay_json_escape` is called only from `ap_bytes` (gated) and `write_header` (ungated).

**D10. The reader's line buffer is unbounded. Severity: low.** A 300 MB single line costs about 295 MB RSS (`getline`) before the 4096-byte path limit rejects it.

### Store observations
- **Store directory inside the scope:**
  - Nothing escapes and nothing breaks.
  - But objects created later in the walk are missing from that walk's view of the store. Two back-to-back checks of an unchanged tree therefore differ: 16 entries, then 22.
  - The store also stores copies of its own objects.
  - It deserves a guard or an exclusion. This produces false "changed" reports, not missed changes.
- **No permission check on an existing store directory:** `belay_store_open` accepts one with any mode (for example 0777). Another user could plant objects there; dedup keeps them, and only verify-on-read catches them. I did not exploit this.

### Unverified suspicions
- A regular file swapped for a device node between `fstatat` and `openat` gets `open(O_RDONLY|O_NONBLOCK)`. Opening some devices has side effects. Not testable without `mknod` privilege.
- Concurrent renames that move an entry from a not-yet-walked directory into an already-walked one lose it with `vanished=0`. This is inherent to a non-snapshot walk, but the "vanished" count suggests a completeness it cannot deliver.
- At every depth level a directory's fd is held twice (`cfd` plus the `dup` given to `fdopendir`): about 256 fds at depth 128. Fine with the default limit, but EMFILE is a hard failure.

### What held up
- **Store path containment and naming:**
  - A planted fan-out directory symlink (`store/58 -> /tmp/rv/outside`) is refused, and nothing is written outside.
  - Object names are gated by `valid_hex`.
  - Every error path after `store_begin` aborts or commits the staging file; no staging files were left behind.
  - Stored bytes are exactly the hashed bytes.
  - Copies of unstable files are discarded.
- **Spill, merge and cascade correctness:** spilled output matched in-memory output byte for byte at 163 entry counts from 0 to 6000. That spans fewer than one run, exactly 16, and more than 16 runs. No fd leaks (6 before, 6 after) and no temp files left. ASan and UBSan stayed clean.
- **Memory:** peak RSS stayed 2–6 MB from 0 to 80k entries and at depth 127. The bounded-memory claim holds apart from the I/O issue in D6.
- **Writer/reader agreement:** both sort the same way, and the trailer counts agreed in every normal run. The 4094-byte link target, non-UTF-8 paths and a separate-device directory mount (tmpfs, correctly flagged `mount`) all round-trip.
- **Symlinks:** recorded and never followed.
- **No escape from the `"` quoting:** `find_key` cannot match a key inside a writer-escaped value.
