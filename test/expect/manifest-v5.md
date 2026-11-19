# Pin: manifest version 5

**Status.** Approved by the author, 2026-11-19, after two independent reviews. The code follows in later
PRs: until a row's code has merged, nothing in it is implemented, and `docs/cli.md` says only what is.
Rows marked **owed** state what a run must show before the code resting on them merges.

**Evidence.** "Measured" means run on GitHub-hosted Ubuntu 24.04 (kernel 7.0) and 22.04 (kernel 6.8)
runners, 2026-11-18 and 19. The file names and section labels given (`events.txt` E1, `facts.txt` P4,
`owed.txt` U1, `round-3`, ...) are those runs' outputs, kept in the project's notes, not in this repository.

**What this is.** Version 5 of the manifest: a capture that reads a listed set of roots of one
scope, and says on every entry how it was looked at. A v5 manifest is a v4 manifest
(`manifest-v4.md` and through it v3, v2, v1 and the addendum) with exactly the changes below.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK. Later rules
go in `manifest-v5-addendum.md`, append-only.

## Lines

| id | line | key | type | value | when |
|---|---|---|---|---|---|
| V5-1 | header | `belay_manifest` | int | `5` | always |
| V5-2 | header | `roots` | array | `{"path": <relative to the scope>, "class": "content" \| "metadata", "found": true \| false}` for every root this capture looked for, sorted bytewise by path, each once. `found: false`: looked for and not there (a home with no `.ssh`). Empty for a capture of a whole scope, which is then as v4 in every other respect. | always |
| V5-3 | header | `sealed_key` | string | The first 16 hex digits of the sha256 of the state's sealing key: two manifests compare `sealed` hashes only when this is equal. Absent when no entry is `sealed`. | see value |
| V5-4 | entry | `not_read` | bool | `true`: a directory the capture did not enter, by rule. No listing was taken. Its `size`, `mtime_ns`, `ctime_ns` and `nlink` are not recorded: they move with every file made inside, and belay did not look inside. | a directory; excludes `unreadable`, `unstable`, `mount`; absent otherwise, never `false` |
| V5-4b | entry | `partial` | bool | `true`: a directory on the way to a root that is not itself under one. Only the children the roots name were looked at; its other children are not recorded, except directories, which are recorded with `not_read`. | a directory; excludes `not_read`, `unreadable`, `mount`; absent otherwise |
| V5-5 | entry | `meta` | bool | `true`: a regular file whose content was not read, by its root's class. Every other key as for a file that is read: `caps`, `xattrs`, `iflags` included (it is opened, never read). | a regular file with none of `sha256`, `unverified`, `stored`; absent otherwise |
| V5-6 | entry | `sealed` | bool | `true`: the `sha256` value is HMAC-SHA256 of the content under the state's sealing key, not a plain hash. The content was not kept. | a regular file with `sha256`, no `stored`; absent otherwise |
| V5-7 | trailer | `not_read` | int | entries carrying `not_read` | always |
| V5-8 | trailer | `meta` | int | entries carrying `meta` | always |
| V5-9 | trailer | `sealed` | int | entries carrying `sealed` | always |
| V5-10 | header | `basis` | string | `walk` or `events` | always |
| V5-11 | trailer | `carried` | int | entries taken from the previous manifest without a stat (`events` only; `0` for a walk) | always |
| V5-12 | trailer | `racy` | array | paths (relative, sorted, each once; `racy_b64` when any is not UTF-8) of entries looked at in this capture whose `ctime_ns` was not older than its barrier. At most 65,536; past that the capture is a walk. Empty for a walk. | always |

Key order: an entry's as v4's, with `not_read`, `partial`, `meta`, `sealed` after `writer_open`. The header:
v4's keys, then `roots`, `sealed_key`, `basis`. The trailer: v4's, then V5-7, V5-8, V5-9, V5-11, V5-12.

## Entry rules (manifest-v1's, amended)

| id | rule |
|---|---|
| V5-E1 | Rule 5 becomes: a regular file has exactly one of `sha256`, `unverified`, `meta`. |
| V5-E2 | Rule 10 and rule 11 read `unreadable`, `mount` **or `not_read`** wherever they read `unreadable` or `mount`: at most one of them on a directory, and no entry below a directory carrying any. A reader rejects an entry below one (`manifest_stream.c`'s check). |
| V5-E3 | With `roots` not empty, the scope root `.` and every directory on the way to a root looked for, as far as the path exists, are entries, recorded as any directory and carrying `partial` (a home's `.config` is `partial` when `.config/systemd/user` is looked for, found or not). Of the other children of such a directory: a directory is recorded with `not_read`; a symbolic link directly under the scope root is recorded (`bin`, `lib`, `lib64` on a merged-`/usr` machine); anything else is not recorded: a file's name in a home directory is nobody's business. A root may be a single file. |
| V5-E4 | A regular file under a `metadata` root carries `meta`, unless its mode has setuid or setgid or it has `caps`: then it is read, and carries `sha256` (or `unverified`) like a file under a `content` root. |
| V5-E5 | A regular file under a `content` root that others cannot read carries `sealed`: its own mode has no read bit for others, **or** some directory from the scope root down to it has no search bit for others (`/root` is 0700: everything in it is sealed). Exceptions, kept as ordinary content: a file an interpreter claims with `BELAY_KEEP_STORE` (sudoers, crontabs, `authorized_keys`, units), and the shell startup files watch-system.md names. `stored` is never written for a sealed file and its bytes are given to no interpreter. The rule does not apply under a `metadata` root: a setuid file there is read and hashed plainly (V5-E4), whatever its mode. |
| V5-E6 | A mount point under a root is entered when its filesystem type is one of `ext2`, `ext3`, `ext4`, `xfs`, `btrfs`, `vfat`, `f2fs`, `zfs`; its root entry is then an ordinary directory whose `dev` differs from its parent's. Any other type gives a `mount` entry, as v1. A ZFS child dataset is such a mount: its own `dev`, its own inode numbers. Entering a filesystem says nothing about the kernel record: which types are marked is kernel-record.md K2a, a shorter list. |
| V5-E7 | The trust rule of `mark` is unchanged for files that are read, with two additions: an entry named in the previous trailer's `racy` is never trusted, and a `sealed` entry is never trusted or carried when the previous manifest's `sealed_key` is not this state's. A `meta` entry needs no trust: it is statted and opened for its inode flags, never read. A `meta` file that cannot be opened is still `meta`, without `iflags` (never `unreadable`, which would make it a record in every diff). |
| V5-E8 | manifest-v1's keys `size`, `mtime_ns`, `ctime_ns` and `nlink` are required on every entry except one carrying `not_read`, where they are absent. The schema says so, and pybelay gives `None` for them, never `0`. The diff compares none of them on a directory, so no diff changes. |
| V5-E9 | Trust and carrying need the same class: an entry is trusted by `mark`, or carried by an event capture, only when the flags the rules give it now (`sealed`, `meta`, or neither) are the ones it carries in the previous manifest. Otherwise it is read. A directory whose search bit for others differs from its previous entry's has every entry below it looked at again. |

## Readers and writers

| id | rule |
|---|---|
| V5-R1 | A reader that knows only v1 to v4 rejects a v5 manifest. A reader that knows v5 accepts `1` to `5`, each by its own key set, strictly. |
| V5-R2 | belay writes v5 from the release that adds it. A manifest of an earlier version reads as `roots` empty, no entry flagged, `basis` `walk`. |
| V5-R3 | The sealing key is 32 random bytes in `<state>/sealing.key`, mode 600, made at the first capture that needs it and never rewritten. A state without it cannot compare `sealed` entries of older manifests: they are `unknown`, reason `sealed_key`. |
| V5-R4 | `baseline export`, `verify`, and a protect spec are refused for a scope whose manifest has a non-empty `roots`: exit 3, `not designed for a system watch`. For every other scope they work as before: baseline-bundle's B-4 reads manifest v5 where it says v4 (V4-R7's rule: a bundle carries the manifest belay writes), and a bundle whose manifest has `roots` is rejected by every reader. |

## The diff (diff.v1)

| id | rule |
|---|---|
| V5-D1 | `meta` on both sides: `sha256` is not compared; every other field is. All equal: no record (`unchanged`). `size` differs: `modified`, with `content_not_read: ["not_read"]` (diff-fields' `size` row stands: a different size proves it). Otherwise any difference: `unknown`, reason `not_read`, `changed` listing the fields; never `metadata_only`. diff-fields gains the row `meta \| flag: content unknown when any other field differs \| reg \| compared \| flag \| this pin`. |
| V5-D2 | `meta` on one side and a hash on the other: `unknown`, reason `not_read`, unless `size` differs (`modified`, with `content_not_read: ["not_read"]`) or the type differs (`type_changed`). As O1 for `unverified`. |
| V5-D3 | `sealed` on both sides with equal `sealed_key`: the hashes are compared like any. On one side only, or with different keys: `unknown`, reason `sealed_key`. A record for a `sealed` entry never carries `sha256` in `before` or `after`. |
| V5-D4 | A directory with `not_read` on both sides and equal type, mode, owner: no record. `not_read` on one side only, or those fields differ: `unknown`, reason `not_read`. A path on one side only that lies below a `not_read` directory on the other: `unknown`, `not_captured` (the existing one-sided rule, which names `unreadable` and `mount`, gains `not_read`). E11 then applies: no event is derived from it. |
| V5-D4b | A path P on one side only whose nearest ancestor with an entry on the other side, A, carries `partial` there. Let C be A's child on the way to P (or P). If C is a directory or a link directly under the scope root on P's side: the ordinary rules (`added`, `removed`), because every such child of a `partial` directory is recorded, so its absence is known. Otherwise C is P, a file: `added` or `removed` when the other side's `roots` lists P (`found: false`: looked for, not there), and `unknown`, `not_captured` when it does not. `partial` itself is not compared. Fixtures: a first `.ssh/authorized_keys` in an existing home is `added`, and `ssh_key_added` is derived; a first `.config/systemd/user/x.service` in a home that had `.config` and no `systemd` below it is `added`. |
| V5-D5 | The reason `not_read` comes after `writer_open` in policy-v1's order; `sealed_key` after it. |
| V5-D6 | The diff header gains `roots_differ`: `true` when the two manifests' `roots` are not equal, absent otherwise. |
| V5-D7 | (struck after the second pass: a write moves `ctime_ns`, so a `meta` entry with a modify event already differs and is V5-D1's `unknown`.) |

## How each was established

| rows | how |
|---|---|
| V5-E2, V5-E3 | read: the diff refuses a manifest without `.` (`src/diff/diff.c`), ancestry seals below `unreadable` and `mount` (`src/diff/ancestry.c`), the `excluded` header holds at most 32 exact paths (`include/belay/manifest.h`) |
| V5-D1 | the adversarial review, F28: under v4's rules a same-size rewrite reads `metadata_only`, which PS-M1 takes as content intact |
| V5-E5 | measured: `shadow`, `shadow-`, `gshadow` are mode 640 (`facts.txt`, P4; `gshadow-` was not listed); `security/opasswd` and others unreadable to an ordinary user (`round-2/unprivileged/diff-etc.txt`) |
| V5-E6 | measured: belay reads ext4, btrfs and ZFS trees alike, and fanotify marks each (a ZFS pool and its child dataset each take a mark; the pool's file reported a write, a chmod and a rename, the child's a write, whose object did not resolve to the file: `owed-*/owed.txt`, Z1). Today a child dataset is a `mount` entry (`? child unknown: mount`). xfs, vfat and f2fs are on the list by kind, not by a run |
