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
  - `unknown`: present on one side only makes the outcome `unknown`.
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
| ctime_ns | ctime | reg, lnk, dir | not compared | required | diff-v1, rule 5; decision (c) |
| ino | identity: within one device | all | compared | required | decision Q3 (same content, new inode is `metadata_only` naming `ino`); decision (b): rule O3 |
| dev | identity: device relation | all | compared | required | decision (b): the raw number is not compared (overlay, tmpfs and btrfs renumber devices at mount); a change in the relation is a real mount change |
| nlink | identity | reg, lnk, fifo, sock, blk, chr | compared | required | proposed: a directory's link count counts its subdirectories |
| iflags | metadata | all | compared | unknown | manifest-v1 obligations: "A change in `iflags` ... is a metadata change"; decision F7: one-sided fields are unknown |
| caps | metadata | all | compared | none if read | manifest-v1 obligations; diff-v1: compared "when neither side carries `xattrs_unknown`"; decision (a) |
| xattrs | metadata | all | compared | none if read | manifest-v1 obligations ("the xattr set"); decision (a); each element is `name=sha256(value)`, so the set and its digest cover values, not only names (verified 2026-10-30) |
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
| O4 | An absent record means `unchanged`. That holds only because every path that is not provably unchanged is emitted -- `unknown` always included. | decision 2026-10-30 (f) |
