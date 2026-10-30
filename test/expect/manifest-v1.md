# Pin: the frozen manifest format, version 1

**What this is.** The v1 format as published and frozen: the keys a v1 writer emits, their order,
spellings and kinds, the entry types, and the combinations of types, fields and flags a v1 writer
can produce. Unlike `diff-fields.md` this is a freeze, not a design: it must equal the format as
published, so it restates the published spec (`docs/spec/manifest-v1.md`, whose key order and
rules are a generated block). A test fails when the code's schema differs from it in either
direction, which is what makes "the format is frozen" enforced rather than stated (audit
2026-10, R12); the fuzz target's invariants are written from it (M4).

**Decided changes to what a reader accepts** (2026-10-30; what a writer emits is unchanged): a
key not listed here is rejected (future fields come with a version bump), and an entry whose
parent directory is not recorded (an orphan) is rejected.

**Changing it.** Only with a version bump, in its own PR, with the author's explicit OK.

## Keys

`a|b`: one spelling or the other, never both (`b` is base64 of bytes that are not valid UTF-8).

| line | position | key | kind | presence |
|---|---|---|---|---|
| header | 1 | belay_manifest | int | required: 1 |
| header | 2 | created_ns | int | required |
| header | 3 | scopes\|scopes_b64 | array | required, exactly one element |
| header | 4 | hash | string | required: `sha256` |
| header | 5 | hash_max_bytes | int | required |
| header | 6 | store_max_bytes | int | required |
| entry | 1 | path\|path_b64 | string | required |
| entry | 2 | type | string | required |
| entry | 3 | mode | int | required |
| entry | 4 | uid | int | required |
| entry | 5 | gid | int | required |
| entry | 6 | size | int | required |
| entry | 7 | mtime_ns | int | required |
| entry | 8 | ctime_ns | int | required |
| entry | 9 | ino | int | required |
| entry | 10 | dev | int | required |
| entry | 11 | nlink | int | required |
| entry | 12 | iflags | int | optional |
| entry | 13 | caps | string | optional |
| entry | 14 | xattrs | array | optional |
| entry | 15 | xattrs_sha256 | string | optional |
| entry | 16 | xattrs_unknown | bool | optional (flag) |
| entry | 17 | sha256 | string | optional |
| entry | 18 | unverified | bool | optional (flag) |
| entry | 19 | unstable | bool | optional (flag) |
| entry | 20 | rdev | int | optional |
| entry | 21 | link_target\|link_target_b64 | string | optional |
| entry | 22 | target_outside_scope | bool | optional (flag) |
| entry | 23 | stored | string | optional |
| entry | 24 | mount | bool | optional (flag) |
| entry | 25 | unreadable | bool | optional (flag) |
| entry | 26 | raced | bool | optional (flag) |
| trailer | 1 | belay_manifest_end | int | required |
| trailer | 2 | vanished | int | required |
| trailer | 3 | unreadable | int | required |
| trailer | 4 | unstable | int | required |
| trailer | 5 | mounts | int | required |
| trailer | 6 | raced | int | required |

## Entry types

| type | mode type bits (octal) |
|---|---|
| reg | 100000 |
| dir | 040000 |
| lnk | 120000 |
| fifo | 010000 |
| sock | 140000 |
| blk | 060000 |
| chr | 020000 |

## Combinations a v1 writer produces

A reader rejects an entry that breaks any of these, in this order, and reports the first one.

| rule | applies to | statement |
|---|---|---|
| 1 | all | `mode`'s type bits match `type` |
| 2 | all | `xattrs` and `xattrs_sha256` are never both present |
| 3 | all | `xattrs_unknown` excludes `xattrs`, `xattrs_sha256` and `caps` |
| 4 | all but reg | no `caps` |
| 5 | reg | exactly one of `sha256` and `unverified` |
| 6 | reg | `unstable` or `unreadable` requires `unverified` |
| 7 | reg | never both `unstable` and `unreadable` |
| 8 | reg | `mount` excludes `unstable` and `unreadable` |
| 9 | dir | no `sha256`, `unverified` or `stored` |
| 10 | dir | `raced` only together with `unreadable` or `mount` |
| 11 | dir | at most one of `unreadable`, `unstable` and `mount` |
| 12 | lnk | no `sha256`, `unverified`, `stored` or `unstable` |
| 13 | fifo, sock, blk, chr | no `sha256`, `unverified`, `stored`, `unstable` or `unreadable` |
| 14 | all | `stored` only with `sha256`, and equal to it |
| 15 | all | `rdev` present exactly on `blk` and `chr` |
| 16 | all | `link_target` present exactly on `lnk` |
| 17 | all but lnk | no `target_outside_scope` |
| 18 | lnk | an empty target only when `unreadable` |
| 19 | lnk | `size` equals the target's length, unless `unreadable` |
| 20 | all | `target_outside_scope` never with an empty target |
| 21 | all | `mount` excludes `sha256` |
| 22 | all | `mount` excludes `iflags`, `caps`, `xattrs`, `xattrs_sha256` and `xattrs_unknown` |
| header 1 | reg | `sha256` only when `size` is within `hash_max_bytes`; a bare `unverified` (no `unstable`, `unreadable` or `mount`) only when larger |
| header 2 | lnk | `target_outside_scope` exactly when the lexical rule says the target leaves the scope, and never when `unreadable` |
