# Pin: how the diff compares each manifest field

**What this is.** The diff's expected behaviour, field by field, written by hand from the spec's
prose (`docs/spec/diff-v1.md` "How an outcome is decided", `docs/spec/manifest-v1.md`
"Obligations on a consumer") and from the author's decisions -- never from the generated tables,
never from the code. Tests compare the code's tables with this file in both directions, and the
oracle reads it instead of the spec (audit 2026-10, R2). A row whose `source` says *proposed* has
no prose behind it: the author approved it with this table (2026-10-30).

**Changing it.** A change to this file lands in its own PR, never together with a change to
`src/schema/` or `src/diff/classify.c`, and waits for the author's explicit OK.

**Columns.**
- `compared as`:
  - `key`: pairs entries.
  - `type`: a difference is `type_changed`.
  - `content`: a difference proves `modified`.
  - `metadata`, `identity`: a difference is `metadata_only`.
  - `identity: device relation`: whether the entry is on the scope root's device, per side.
  - `identity: within one device`: rule O3.
  - `ctime`: compared only when nothing else differs, then `metadata_only`.
  - `flag: X unknown`: not compared; on either side it makes X unknown, with the flag's name as
    the reason.
  - `not compared`.
- `for types`: the entry types the comparison applies to; on other types the field is not
  compared.
- `on mount roots`: whether it is compared on an entry carrying `mount`.
- `absent means`, for an optional field:
  - `none`: compared as absent.
  - `none if read`: rule O2.
  - `unknown`: present on one side only makes the outcome `unknown`, except across a type change (O6).
  - Otherwise why absence cannot occur.

| field | compared as | for types | on mount roots | absent means | source |
|---|---|---|---|---|---|
| path | key | all | compared | required | diff-v1, "How an outcome is decided" |
| type | type | all | compared | required | diff-v1, rule 2 |
| mode | metadata | all | compared | required | proposed; decision 2026-10-30 (c): compared on fifo, sock, blk, chr and mount roots |
| uid | metadata | all | compared | required | proposed; decision (c) |
| gid | metadata | all | compared | required | proposed; decision (c) |
| size | content | reg, lnk | compared | required | diff-v1, rule 3: "`size` for a regular file or symlink" |
| mtime_ns | metadata | reg, lnk | not compared | required | decision (c): fifo, sock, blk, chr and mount roots update timestamps on use; a directory's follows its listing |
| ctime_ns | ctime | reg, lnk | not compared | required | diff-v1, rule 5; decision (c); decision F5: a directory's own timestamps are not compared (O5) |
| ino | identity: within one device | all | compared | required | decision Q3 (same content, new inode is `metadata_only` naming `ino`); decision (b): rule O3 |
| dev | identity: device relation | all | compared | required | decision (b): the raw number is not compared (overlay, tmpfs and btrfs renumber devices at mount); a change in the relation is a real mount change |
| nlink | identity | reg, lnk, fifo, sock, blk, chr | compared | required | proposed: a directory's link count counts its subdirectories |
| iflags | metadata | all | not compared | unknown | manifest-v1 obligations: "A change in `iflags` ... is a metadata change"; decision F7: one-sided fields are unknown; not on mount roots: manifest-v1 rule 22, never read there |
| caps | metadata | all | not compared | none if read | manifest-v1 obligations; diff-v1: compared "when neither side carries `xattrs_unknown`"; decision (a) |
| xattrs | metadata | all | not compared | none if read | manifest-v1 obligations ("the xattr set"); decision (a); each element is `name=sha256(value)`, so the set and its digest cover values, not only names (verified 2026-10-30) |
| xattrs_sha256 | not compared | all | not compared | none if read | proposed: the digest-only spelling of `xattrs`, compared as `xattrs` |
| xattrs_unknown | flag: metadata unknown | all | compared | flag | diff-v1, rule 4 |
| sha256 | content | reg | compared | with unverified | diff-v1, rule 3: "the hash when both sides have one"; rule O1 |
| unverified | flag: content unknown | all | compared | flag | diff-v1, rule 3 |
| unstable | flag: content unknown | all | compared | flag | diff-v1, rule 3 |
| rdev | content | blk, chr | compared | only on its types | diff-v1, rule 3: "the device number"; decision (c) |
| link_target | content | lnk | compared | only on its types | diff-v1, rule 3: "the link target when neither side is `unreadable`" |
| target_outside_scope | not compared | all | not compared | n/a | design doc §5.1.1: "reporting only and must never drive a decision" |
| stored | not compared | all | not compared | none | proposed: bookkeeping, equal to `sha256` |
| mount | flag: content unknown | all | compared | flag | diff-v1, rule 3 |
| unreadable | flag: content unknown | all | compared | flag | diff-v1, rule 3 |
| raced | flag: everything unknown | all | compared | flag | diff-v1, rule 1 |

## Outcome rules

| rule | statement | source |
|---|---|---|
| O1 | A hash on one side and `unverified` on the other: `unknown` (reason `unverified`), unless `size` differs, which gives `modified`, or the type differs, which gives `type_changed` (rule 2). | decision 2026-10-30 (d) |
| O2 | `none if read`: an absent `caps` or `xattrs` means none only where the attributes were read. With `xattrs_unknown` on either side, or on a mount root (never read), they are not compared and the metadata is `unknown` unless another metadata field proves a change. | decision 2026-10-30 (a) |
| O3 | `ino` is compared only when the entry's `dev` is the same on both sides: inode numbers are meaningful within one device. When the scope root's `dev` differs between the two manifests (a remount), the diff header reports it once and states that identity was not compared; `ino` is then compared for no entry, and content still compares by hash. | decision 2026-10-30 (b) |
| O4 | An absent record means `unchanged`, or a directory whose only difference is its own timestamps, which the trailer counts (O5). That holds only because every other path that is not provably unchanged is emitted -- `unknown` always included. | decision 2026-10-30 (f); decision F5 |
| O5 | A directory whose `ctime_ns` or `mtime_ns` differs while every compared field is equal and no flag makes anything unknown is not emitted: its listing is recorded through its children, and its timestamps move with every change below it. The diff trailer counts such directories. | decision F5 (review m1-phase3 round 1, F5: every parent of every added or removed file got a ctime-only record) |
| O6 | A field whose absence means `unknown` (`iflags`), present on one side only: `unknown` (reason `iflags_unknown`), unless the type differs, which gives `type_changed` (rule 2) -- or, with `raced`, `unknown` for the flags' reasons alone (O7). | independent re-check of the oracle edits, 2026-10-30, edit 1; rule 2; O1's form |
| O7 | Across a type change no field is compared: `changed` is `["type"]`, and when `raced` makes the outcome `unknown` (rule 1) its reasons are those of the flags on either side, never a field's (no `iflags_unknown`). | diff-v1: "when the types are the same, of every field unknown under rule 4 (across a type change no field is compared)" |
| O8 | `unverified` on a side that also carries `mount` adds no reason: a mounted regular file carries it because it is never read (manifest-v1 rules 5 and 21), and `mount` is that reason. `unverified` on the other side still gives its own. | independent review of the S6 completion, F7 (2026-10-30) |
| O9 | A `modified` or `metadata_only` record of a regular file (`reg` on both sides) whose content was not read on a side carries `content_not_read`: an array of the reasons, in the order of the `unknown` array, from the flags of either side: `unstable`, `unverified`, `unreadable`, `mount`, and from v5 `not_read`. As O8 does for `mount`: `unverified` adds no reason on a side that also carries `unreadable`, `unstable` or `mount` (it is there because of them); alone it means the file was over the hash limit. So an unreadable file gives `["unreadable"]`. Absent when both sides were hashed. It stands where `unknown` would, after the values and before `findings`; no record has both. The `unknown` key and the outcome are unchanged: a different size still proves `modified`. | checkpoint-v3, "The lines", G2-1; measured as an unprivileged user on a mode-600 file, 2026-11-18: its record after a rewrite was `modified` by `size` with no sign that its content was not read; read: `src/diff/classify.c` sets reasons only for outcome `unknown` |
| O10 | An `added` record carries `content_not_read` too, from its one entry. A regular file: by O9's rule for a side -- `unstable`, `unreadable`, `mount`, or `unverified` when it carries none of those (over the hash limit). A directory carrying `unreadable` or `mount`: that reason, since its listing was not read and nothing below it has a record. No other type, and never a `removed` record. It stands where O9 puts it: after `type`, before `findings`. The outcome is unchanged: the entry is there, and `added` says so. | checkpoint-v3, "The lines", G2-5; approved by the author, 2026-11-19; run as an unprivileged user on the branch before this row: a new mode-000 file gave `{"path":"newfile","outcome":"added","type":"reg"}` and a new mode-000 directory with a file in it `{"path":"newdir","outcome":"added","type":"dir"}`, neither with any sign of what was not read |
| O11 | A `type_changed` record whose entry after is a directory carrying `unreadable` or `mount` carries `content_not_read` with that reason, placed as O10 places it. No other `type_changed` record carries it: across a type change no content is compared (O7), so nothing else there was left unread. | checkpoint-v3, "The lines", G3-5 |

## The trailer

The trailer's keys are diff-v1's ("Trailer") and manifest-v4's (V4-D5). This table holds the keys
added after those, each with its rule.

| id | key | type | rule | source |
|---|---|---|---|---|
| G3-2 | `before_sealing`, `after_sealing` | int | Each manifest's entries nothing below which was looked at: its directories carrying `unreadable` or `mount` (checkpoint-v3 C3-3), counted from its entries. In that order, after every key the trailer has. | checkpoint-v3, "The lines", G3-2; measured as an unprivileged user on a mode-700 directory, 2026-11-18: a file added in it changes nothing in the diff but the directory's own line |
| RT-T1 | `runtime` | int | The count of the diff's `runtime` records (runtime-v1 RT-D1). Always present; 0 when the diff has no `runtime` section. After every key the trailer has, `after_sealing` included. | runtime-v1 RT-D1; every earlier key is always present |
| ID-1 | `before_sha256`, `after_sha256` | string | For a manifest stored as a delta of version 2 (state-retention ST-3; an event capture's, kernel-record K9) the key carries the manifest's identity, not a digest of its bytes: the same 64 hex digits whoever makes the diff, a watch step from the dirty entries or `belay diff` from the rebuilt manifests. Nothing else of the trailer changes, and no key is added. For every other manifest it is the sha256 of the bytes, as before. policy-v1 P-T8 passes on what it is given. | state-retention ST-3 (option A, 2026-11-23); a reading taken in the build, listed for the author |
