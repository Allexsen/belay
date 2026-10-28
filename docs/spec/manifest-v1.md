# belay manifest format, version 1

Status: draft. Stable once M1 ships; `diff.v1` (the public diff schema) is a separate document.

A manifest is the record of what a scope looked like at one instant. `belay check` writes one;
`belay diff --since <id>` compares two.

## Location

```
$XDG_STATE_HOME/belay/checkpoints/<id>/
  manifest.ndjson     the manifest (this document)
  store/              content-addressed copies of stored files
```

`$XDG_STATE_HOME` defaults to `$HOME/.local/state`.

## Encoding

Newline-delimited JSON: one JSON object per line, no array wrapper, LF line endings.

**The encoding is canonical: every manifest state has exactly one byte representation**, and a
reader MUST reject anything else. Concretely, each line is exactly

```
line    := '{' pair (',' pair)* '}'      -- then LF; no whitespace anywhere
pair    := '"' [a-z0-9_]+ '"' ':' value
value   := string | integer | 'true' | '[' string (',' string)* ']'
string  := '"' ( byte >= 0x20 other than '"' and '\' | escape )* '"'
escape  := \" | \\ | \b | \f | \n | \r | \t | \u00XX
           (\u00XX only for a control byte with no short form, lowercase hex)
integer := '0' | '-'? [1-9][0-9]*
```

No line may exceed 64 KiB or contain a NUL byte. `false` and `null` never appear: a flag is absent
or exactly `true`.

Why canonical: a reader that tolerates a second spelling -- whitespace, a duplicated key, `"x":
true` with a space, bytes after an embedded NUL -- has a place where a flag can be hidden from it.
Independent review found such places in a reader that searched lines for keys; this grammar removes
them as a class.

Chosen over a binary format because it is streamable (a 100k-file manifest never needs a whole-file
parse), greppable while developing, and because the JSON writer is needed anyway for `--json` output
(§4.2 contract 2), so it is shared code rather than a second format.

**Line 1 is the header. The last line is the trailer. Every line between is an entry.** Blank lines
are not permitted anywhere.

## Header

```json
{"belay_manifest":1,"created_ns":1761000000000000000,"scopes":["/home/u/proj"],"hash":"sha256","hash_max_bytes":67108864,"store_max_bytes":65536}
```

| field | type | meaning |
|---|---|---|
| `belay_manifest` | int | format version. A reader MUST reject a version it does not know. |
| `created_ns` | int | wall clock at creation, nanoseconds since the epoch. Informational only — never used for comparison, per §6.3. |
| `scopes` | array | the resolved scope root, exactly one in this version. A scope that is not valid UTF-8 is written as `scopes_b64` (base64 elements) instead, never both. |
| `hash` | string | digest algorithm for the `sha256` field |
| `hash_max_bytes` | int | regular files larger than this are recorded without a hash (see `unverified`) |
| `store_max_bytes` | int | size threshold for copying content into `store/` |

## Entries

Sorted by **`path` bytewise ascending** (`memcmp` order, not locale collation), **strictly**: no
path appears twice. This lets `diff` stream two manifests as a merge rather than building a hash
map, so memory stays constant regardless of tree size. A reader MUST reject an entry that is not
strictly greater than the one before it; out-of-order or duplicated entries would otherwise be
mis-paired without any error.

**The scope root itself is an entry, with path `.`.** Without it, a change to the root's own mode or
owner is invisible.

```json
{"path":"src/main.c","type":"reg","mode":33188,"uid":1000,"gid":1000,"size":1234,"mtime_ns":1760...,"ctime_ns":1760...,"ino":8612,"dev":2096,"nlink":1,"sha256":"e3b0...","stored":"e3b0..."}
```

<!-- BEGIN GENERATED: entries -->
<!-- From src/capture/entry.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| field | kind | carried by | meaning |
|---|---|---|---|
| `path` / `path_b64` | string | every entry | Path relative to its scope root, `/`-separated; `.` is the root itself. Written as `path_b64`, base64 of the raw bytes, when they are not valid UTF-8. |
| `type` | string | every entry | The entry's type. The spellings, and the `mode` bits that go with each, are listed under the field rules. |
| `mode` | int | every entry | `st_mode`, full value including type bits. |
| `uid` | int | every entry | Owner. |
| `gid` | int | every entry | Group. |
| `size` | int | every entry | `st_size`. For `lnk`, the target length -- except on an `unreadable` link, whose target is unknown or stale. |
| `mtime_ns` | int | every entry | Modification time, nanoseconds. Times outside the int64 range (before 1678, after 2262) saturate at its bounds. |
| `ctime_ns` | int | every entry | Change time, nanoseconds, saturating like `mtime_ns`. **`ctime_ns` is the change prefilter**: an unprivileged process can set mtime but not ctime (§6.3). Never the sole evidence for a protected path — hash those. |
| `ino` | int | every entry | Inode number; with `dev`, the entry's identity. |
| `dev` | int | every entry | Device. On a directory, `dev` differing from the scope root's means a mount boundary; on other types it need not (see `mount`). |
| `nlink` | int | every entry | Link count. `> 1` on a regular file means hard links exist. |
| `iflags` | int | any type | Inode flags, where the filesystem has them. Linux: `FS_IOC_GETFLAGS` (`chattr`: immutable, append-only, nodump...), on regular files and directories. macOS: `st_flags` (`chflags`), on every type. |
| `caps` | string | `reg` | The file capability: the raw `security.capability` value, lowercase hex. `setcap` on an interpreter is a privilege change; this is where it shows. |
| `xattrs` | array | any type | One string per extended attribute other than `security.capability`, `"<name>=<sha256 of value>"`, sorted strictly by name bytes; absent when there are none. POSIX ACLs appear here as `system.posix_acl_access` / `system.posix_acl_default`. A name is written as itself when it is printable ASCII without `"`, `\` or `=` and does not start `x:`; otherwise as `x:` followed by its bytes in hex. At most 8192 bytes of array body; a larger set is recorded as `xattrs_sha256` instead. |
| `xattrs_sha256` | string | any type | For a set too large for `xattrs`: the sha256 of the array body `xattrs` would have held, so a set recorded inline in one manifest and by digest in another still compares. |
| `xattrs_unknown` | bool | any type | `true`: the attributes could not be read. An absent `xattrs` means "none", so failing to read must say so. `diff` reports the entry's metadata as `unknown`, never unchanged. |
| `sha256` | string | `reg` | Lowercase hex content digest, of a file within `hash_max_bytes` read in one stable pass (see "What a hash, and a stored copy, prove"). |
| `unverified` | bool | `reg` | `true`: no hash is recorded. The file is larger than `hash_max_bytes`, or it is also flagged `unstable`, `unreadable` or `mount`, which say why. `diff` must report any change to it as **modified (unverified)**, never as unchanged. |
| `unstable` | bool | `reg`, `dir` | `true`. On a regular file: it changed while being read (size, mtime or ctime moved, or the inode opened was not the one stat'ed); no hash is recorded, because the bytes read describe no state the file ever had. On a directory: **its listing is not its listing at the end of the walk** -- the end-of-walk validator found it changed since it was recorded (its inode, device, mode, mtime or ctime differ, it is now a mount, or it can no longer be reached), or the listing failed part way (it could not be read as a directory stream, a `readdir` error, a child that could not be stat'ed at all, or a child name too long to fit the path limit). Entries may be missing from it or recorded under another directory; the comparator MUST NOT read its children as a complete listing. |
| `rdev` | int | every `blk`, `chr` | The device number. Without it a replaced device node, or an overlayfs whiteout (char 0,0), is indistinguishable from the original. |
| `link_target` / `link_target_b64` | string | every `lnk` | The link's bytes, verbatim and unresolved; `link_target_b64`, base64, when they are not valid UTF-8. Empty only on an `unreadable` link, meaning the target is unknown. |
| `target_outside_scope` | bool | `lnk` | `true` when the target resolves lexically outside the scope. **Advisory only** — never drives a decision (§5.1.1). |
| `stored` | string | `reg` | Present when content was copied: the `store/` key, which is the content's sha256. On Linux no copy is kept of a file another process had open for writing while belay read it (see "What a hash, and a stored copy, prove"). |
| `mount` | bool | any type | `true`. The entry is the root of another mount. Where statx can say so (`STATX_ATTR_MOUNT_ROOT`, Linux 5.8+), its answer is used alone: it catches bind mounts from the same filesystem, and it does not mistake a btrfs subvolume (a directory with its own `dev`, not a mount) for one. Without it, an entry whose `dev` differs from the scope root's is a mount -- except a non-directory in an overlayfs scope, where every file carries its layer's device. A mount is recorded and **never read or descended** (§5.1.1): a mounted regular file carries `unverified` and no hash, and **for a directory the subtree below it is ABSENT**: `diff` MUST report it as *not captured*, never as *unchanged*. |
| `unreadable` | bool | `reg`, `dir`, `lnk` | `true`. belay could not capture this entry's contents: a directory it could not open or search (permission, or readable-but-not-searchable), a directory swapped for another between its stat and its open, a directory beyond the depth limit (128) or whose path leaves no room for a child name, a file it could not open or read, or a symlink whose target could not be read or kept changing while being read. **For a directory, the entire subtree below it is ABSENT.** `diff` MUST report such a subtree as *contents unknown* and never as *unchanged*. Without this field an unreadable directory is byte-identical to an empty one. |
| `raced` | bool | any type | `true`. The entry changed after it was recorded, before the walk ended: re-stat'ed at the end of the walk, its inode, device, mode, size, mtime or ctime differed, or it could not be reached without entering a mount. What is recorded held when belay read it, but not at the end. (A listed directory that changed is flagged `unstable` instead, since its listing is what no longer holds.) |
<!-- END GENERATED: entries -->

### Field rules a reader MUST enforce

In addition to the grammar above:

- **Fields appear in one fixed order**, optional ones omitted, never reordered; unknown fields
  may appear only after every known one. The entry order is generated below. Header:
  `belay_manifest`, `created_ns`, `scopes`|`scopes_b64`, `hash`, `hash_max_bytes`,
  `store_max_bytes`. Trailer: `belay_manifest_end`, `vanished`, `unreadable`, `unstable`, `mounts`,
  `raced`.
- **No key appears twice** in one line. "First wins" would let two different lines mean the same
  thing.
- **Boolean flags are spelled exactly `"key":true`**, and are absent otherwise. Any other value
  under a flag's key (`: true`, `false`, `1`, `"true"`) is an error, never "flag absent". A flag
  that silently reads as absent is the failure this format exists to prevent: an unreadable
  directory would read as an empty one.
- **`path` is used only for valid UTF-8 and `path_b64` only for anything else** (likewise
  `link_target`/`link_target_b64`, `scopes`/`scopes_b64`), and base64 is canonical (padding bits
  zero, padding only at the end), so every byte string has exactly one encoding.
- **The scope is a canonical absolute path** (as `realpath` produces: no empty, `.` or `..`
  component, no trailing slash except `/` itself).
- **The scope root `.` is present**, exactly once, is a directory and is never a mount. If it is
  `unreadable`, it is the only entry.
- **Nothing appears below a directory marked `unreadable` or `mount`.**

The rest is generated from the schema the writer and reader both execute, so it cannot drift from
them. An unreadable symlink with an **empty** target means "target unknown": no real symlink has
an empty target, so it cannot be confused with one.

<!-- BEGIN GENERATED: schema -->
<!-- From src/capture/entry.c by tools/gen_schema.c. Edit there, then `make gen`. -->

- **Entry fields appear in one fixed order**, optional ones omitted, never reordered (`a`|`b`: one
  spelling or the other, never both):
  `path`|`path_b64`, `type`, `mode`, `uid`, `gid`, `size`, `mtime_ns`, `ctime_ns`, `ino`, `dev`,
  `nlink`, `iflags`, `caps`, `xattrs`, `xattrs_sha256`, `xattrs_unknown`, `sha256`, `unverified`,
  `unstable`, `rdev`, `link_target`|`link_target_b64`, `target_outside_scope`, `stored`, `mount`,
  `unreadable`, `raced`.
- **`type` is one of these, and `mode`'s type bits (`S_IFMT`, octal) match it:**
  `reg` 100000, `dir` 040000, `lnk` 120000, `fifo` 010000, `sock` 140000, `blk` 060000, `chr`
  020000.
- **Types, fields and flags agree** -- exactly the combinations the writer produces.
  A reader applies these rules in this order and reports the first one violated:

  1. `mode`'s type bits match `type` (`S_IFMT`; the same values on Linux and macOS).
  2. `xattrs` and `xattrs_sha256` are never both present.
  3. `xattrs_unknown` excludes `xattrs`, `xattrs_sha256` and `caps`.
  4. `caps` appears only on `reg`.
  5. A `reg` carries exactly one of `sha256` and `unverified`.
  6. On a `reg`, `unstable` and `unreadable` each require `unverified`.
  7. On a `reg`, `unstable` and `unreadable` are never both present.
  8. A mounted `reg` carries neither `unstable` nor `unreadable`.
  9. A `dir` carries no `sha256`, `unverified` or `stored`.
  10. A `dir` carries `raced` only with `unreadable` or `mount` (a listed one that changed is
      `unstable`).
  11. A `dir` carries at most one of `unreadable`, `unstable` and `mount`.
  12. A `lnk` carries no `sha256`, `unverified`, `stored` or `unstable`.
  13. A `fifo`, `sock`, `blk` or `chr` carries no hash fields, `unstable` or `unreadable`.
  14. `stored` appears only with `sha256`, and equals it.
  15. `rdev` appears exactly on `blk` and `chr`.
  16. `link_target` (or `link_target_b64`) appears exactly on `lnk`.
  17. `target_outside_scope` appears only on `lnk`.
  18. A `lnk`'s target is empty only when the link is `unreadable` (empty means unknown).
  19. A `lnk`'s `size` equals its target's length, unless the link is `unreadable`.
  20. `target_outside_scope` never accompanies an empty (unknown) target.
  21. A `mount` carries no `sha256`.
  22. A `mount` carries no extended metadata (`iflags`, `caps`, `xattrs`, `xattrs_sha256`,
      `xattrs_unknown`).
- **What the header determines, holds**, checked after the rules above:

  1. A `reg` carries `sha256` only if its `size` is within `hash_max_bytes`, and a bare `unverified`
     (no `unstable`, `unreadable` or `mount` giving another reason) only if it is larger.
  2. A `lnk` carries `target_outside_scope` exactly when the lexical rule says its target leaves the
     scope (an absolute target outside it; a relative one whose `..` climbs above the scope root,
     resolved from the link's own directory; a target the rule cannot judge), and never when it is
     `unreadable`. Writer and reader share one implementation of that rule, so the annotation has
     one value per state.
<!-- END GENERATED: schema -->

### Growing the format

Unknown fields are ignored by a reader, so the format can grow -- **but only by informational
fields.** Any new field whose absence an older reader would misread as "nothing changed" (as
`unreadable`, `unstable` and `rdev` would have been) MUST come with a version bump, which older
readers refuse. `unreadable`, `unstable`, `rdev`, `raced` and the trailer counts `mounts` and
`raced` are part of version 1 because version 1 has not shipped. Once Phase 3 publishes the diff
schema (diff.v1), every format change needs an explicit version bump.

## Trailer

```json
{"belay_manifest_end":12345,"vanished":0,"unreadable":2,"unstable":0,"mounts":1,"raced":0}
```

| field | meaning |
|---|---|
| `belay_manifest_end` | number of entries, including `.` |
| `vanished` | entries that disappeared between being listed and being read. Non-zero means the tree was changing during the walk, so the manifest is not a single instant. |
| `unreadable` | entries carrying `unreadable` |
| `unstable` | entries carrying `unstable` (files and directories). Non-zero means the manifest is not a consistent single-instant snapshot. |
| `mounts` | entries carrying `mount`: boundaries whose contents were not captured |
| `raced` | entries carrying `raced`. Non-zero means the tree was changing during the walk, so the manifest is not a single instant. |

A manifest is a complete record of one instant only when `vanished`, `unreadable`, `unstable` and
`raced` are all zero, and it covers everything in the scope only when `mounts` is zero too.

The trailer is **required** and must be the **last line**. A reader MUST reject a manifest with no
trailer, a trailer whose counts disagree with the entries read, or anything after the trailer.
Without it, a manifest cut off at a line boundary by a crash or a full disk is indistinguishable
from a complete one with fewer entries, and its missing tail would read as deletions. The writer
also writes to a temporary name and renames into place.

## Obligations on a consumer (the comparator, step 3.1)

Each rule below closes a way for a state the format records to be rendered as "no change":

- **Refuse to compare manifests of different scopes.** Relative paths from different roots line up
  by name: two unrelated projects with the same layout would otherwise compare as unchanged
  (measured).
- **`unreadable` means "contents unknown"**, never "empty" and never "unchanged". **`mount` means
  "not captured"**: the same, by design rather than by failure.
- **An `unstable` directory's children are not a complete listing.** An entry absent below it is
  "possibly present", never "deleted"; an entry present below it may also exist elsewhere.
- **`raced` means the recorded state held during the walk but not at its end.** Report the entry
  as changed during capture, not as unchanged.
- **Non-zero `vanished`, `unstable` or `raced` in the trailer makes the whole result provisional**:
  the tree was changing while it was read. Say so, and recommend a re-check.
- **`unstable`, `raced` and `unverified` map to the outcome `unknown`, never to "unchanged".** In the
  diff schema (diff.v1), `unknown` is a first-class outcome beside added, removed, modified,
  type-changed and metadata-only.
- **Do not assume an entry's parent is present.** The reader does not reject an orphan (`a/b`
  without `a`): that would cost memory in proportion to the number of directories, and flat memory
  at a million entries is worth more. A comparator must handle an orphan without crashing or
  misreporting it.
- **`unverified` (including `unstable`) never reports "unchanged" on content alone.** With identical
  metadata the honest label is "unchanged (unverified)"; on a protected path it is a failure to
  verify, not a pass.
- **A change in `iflags`, `caps` or the xattr set is a metadata change**, reported as such
  (diff.v1: metadata-only), naming the attributes where `xattrs` is inline.
- **A `ctime_ns` change with every recorded field equal means "changed: unrecorded attribute"**,
  never "unchanged". The extended metadata belay cannot see (see below) still changes ctime. This
  turns its absence into a visible, if unspecific, change.
- **Compare under the same `hash_max_bytes`**, or report entries hashed on one side and unverified
  on the other as unverified rather than changed.

## What a manifest of a live tree promises

A walk takes time, and the tree may change while it runs. When the walk is over, every recorded
entry is stat'ed again and compared, by equality, with what was recorded; the manifest describes
that instant, the end of the walk. An entry carrying none of `raced`, `unstable` and `unreadable`
was found unchanged, so what is recorded for it held at the end of the walk. A directory carrying
none of `unstable`, `unreadable` and `mount` lists exactly the entries it held then. No clock is
read: every judgment compares two observations of the same entry, so a stepped or skewed clock
changes nothing.

Equality compares timestamps, which bounds what it can see:

- A change within one timestamp tick of the recorded stat can go unseen where timestamps are
  coarser than the change: FAT (2 s), HFS+ and some network or FUSE filesystems (1 s), and Linux
  before 6.13 (one timer tick, a few ms). From 6.13, filesystems with multigrain timestamps give
  a file whose timestamps were read a new one on its next change (measured on ext4 and tmpfs).
- A change made through another machine (NFS, SMB, a FUSE backend) is seen only once this
  machine's attribute cache shows it.
- Content has its own limits, below.

## What a hash, and a stored copy, prove

A recorded `sha256` is the hash of one read pass during which the file's size, mtime and ctime
did not change (checked on the open file before and after the read, and against the stat that
was recorded). **That alone does not prove the bytes are a state the file really had.** It
catches a write that starts during the read, but not one already in flight when the read began:
`write(2)` updates the timestamps first and copies the data afterwards, so a read that overlaps
the copy can see part old and part new bytes while the timestamps no longer move. Measured on
Linux 6.18 with a 4 MiB in-place rewrite racing the read: 56 of 2,000 reads were torn and passed
the check on ext4, 11 of 2,000 on tmpfs (`bench/spike_torn.c`). Against a writer storing through
a shared mapping, which moves no timestamp at all, an independent review measured 634 of 1,000
on ext4.

**A stored copy is held to a stricter rule**, because a restore from a torn copy would write a
file that never existed. On Linux, belay keeps a copy only if no process had the file open for
writing, or mapped shared-writable, when the read began and when it ended. It asks the kernel
with a lease probe: a read lease taken and released at once, so nothing is held and a writer is
never delayed by more than those two calls. A `write(2)` in flight holds its file open, so the
case above is always seen. The hash is still recorded, without a copy: at worst a wrong line in
a diff, never corrupted data.

What the store rule does not cover:

- On kernels before 6.13 and on coarse-timestamp filesystems, a writer that opens the file,
  writes in place and closes it entirely within one read, inside one timestamp tick, is seen by
  neither probe nor the stability check. (This follows from the kernel's rules; it was not
  observed.)
- Where the probe cannot tell, the copy is kept unguarded: on macOS, which has no lease API; on
  filesystems without lease support; and for files belay's user does not own, unless it runs
  with `CAP_LEASE` (root does).
- On overlayfs (a container's root, Docker's `/tmp`), a shared writable mapping whose file
  descriptor was closed holds the upper layer's file, not the overlay's, so the probe does not
  see it (measured). A writer holding the file open is seen. Reading the upper layer directly,
  as host-reader mode does, sees both.
- On Linux, if SIGIO still has its default action, belay sets it to ignored: a writer opening
  the file during the probe makes the kernel send SIGIO, whose default action would end the
  process.

The hash itself carries no such guarantee. On real workloads (a build-and-test loop, and large
npm installs, measured with `bench/measure`) no torn hash was found among about 1.5 million
checked against the files' final content; the files read while a writer held them open showed
real, partly written states. **That means none of those workloads had an in-place overwriter or
a shared-mapping writer, not that torn reads do not happen**: both tear reads, as measured above.

All of this applies only while something writes to the tree during the check. In RL mode the
policy's processes are killed before the scan, and host-reader mode reads from outside the
sandbox, so these are limits of dev-tier and live checks, not of the trust model.

(Two earlier statements were wrong. The commit that introduced the store said "the store never
holds bytes that match no state of the file"; its first correction said that holds on Linux
6.13+ with fine-grained timestamps. Neither holds while a write is in flight.)

## Path encoding

POSIX paths are **bytes**, not text. They may contain anything except `/` and NUL.

- Valid UTF-8 → `path`, as a JSON string.
- Not valid UTF-8 → `path_b64`, base64 of the raw bytes. An entry has exactly one of the two.
- **A path containing a NUL byte is a hard error** (`BELAY_ERR_CORRUPT`) on read, never a truncation
  (§5.1.1). The lexical path functions take NUL-terminated strings and cannot detect an interior
  NUL; the reader holds a length, so the check belongs there.

Sorting is on the **raw path bytes** either way, so an entry's encoding does not affect its position.

**Entry paths are relative to the scope root and must stay inside it.** A reader MUST reject an
absolute path and any path containing a `..` component. M1 only reads, but the moment anything
restores from a manifest an accepted `../../etc/passwd` is an arbitrary write. This is the same
hidden-traversal risk the NUL rule above exists to prevent.

## What is deliberately not recorded

- **Extended metadata belay cannot see or does not reach** (recorded since 2026-10-26 otherwise):
  `trusted.*` attributes, which only root can list; macOS ACLs, which are not extended attributes;
  inode flags of symlinks, FIFOs, sockets and devices on Linux (no safe fd to ask through); and on
  macOS the attributes of FIFOs, sockets and devices, which are recorded as `xattrs_unknown`
  because opening them has side effects. A change to any of these still moves `ctime_ns`, and the
  ctime rule above keeps it from rendering as "unchanged".
- **File content**, except copies under `store/` for files within `store_max_bytes` or claimed by an
  interpreter.
- **Anything below a mount boundary** inside a scope.
