# Pin: how the diff compares each manifest field

**What this is.** The diff's expected behaviour, field by field, written by hand from the spec's
prose (`docs/spec/diff-v1.md` "How an outcome is decided", `docs/spec/manifest-v1.md`
"Obligations on a consumer") and from the author's decisions -- never from the generated tables,
never from the code. Tests compare the code's tables with this file in both directions, and the
oracle reads it instead of the spec (audit 2026-10, R2). A row whose `source` says *proposed* has
no prose behind it: it is what the author approved when approving this table.

**Changing it.** A change to this file lands in its own PR, never together with a change to
`src/schema/` or `src/diff/classify.c`, and waits for the author's explicit OK.

Columns: `compared as` -- `key` pairs entries; `type` (a difference is `type_changed`);
`content` (a difference proves `modified`); `metadata` and `identity` (a difference is
`metadata_only`); `ctime` (compared only when nothing else differs: `metadata_only`); `flag: X
unknown` (not compared; on either side it makes X unknown, with the flag's name as the reason);
`not compared`. `for types`: the entry types the comparison applies to; on other types the field
is not compared. `absent means`: for an optional field, what its absence on one side means --
`none` (compared as absent), `unknown` (one side only makes the outcome `unknown`), or `n/a`.

| field | compared as | for types | absent means | source |
|---|---|---|---|---|
| path | key | all | n/a (required) | diff-v1, "How an outcome is decided" |
| type | type | all | n/a (required) | diff-v1, rule 2 |
| mode | metadata | all | n/a (required) | proposed: the prose lists no metadata fields; the permission bits (the type bits are `type`) |
| uid | metadata | all | n/a (required) | proposed |
| gid | metadata | all | n/a (required) | proposed |
| size | content | reg, lnk | n/a (required) | diff-v1, rule 3: "`size` for a regular file or symlink" |
| mtime_ns | metadata | reg, lnk, fifo, sock, blk, chr | n/a (required) | proposed: a directory's mtime follows its listing, which its children report |
| ctime_ns | ctime | all | n/a (required) | diff-v1, rule 5; manifest-v1 obligations: "changed: unrecorded attribute" |
| ino | identity | all | n/a (required) | decision 2026-10-30 (Q3): same content, new inode is `metadata_only` naming `ino` |
| dev | identity | all | n/a (required) | proposed |
| nlink | identity | reg, lnk, fifo, sock, blk, chr | n/a (required) | proposed: a directory's link count counts its subdirectories |
| iflags | metadata | all | unknown | manifest-v1 obligations: "A change in `iflags` ... is a metadata change"; decision 2026-10-30 (F7): one-sided fields are unknown |
| caps | metadata | all | none | manifest-v1 obligations ("caps"); diff-v1: compared "when neither side carries `xattrs_unknown`" |
| xattrs | metadata | all | none | manifest-v1 obligations ("the xattr set"); diff-v1: compared "when neither side carries `xattrs_unknown`"; compared by the set's digest, so an inline set and a digest-only set compare |
| xattrs_sha256 | not compared | all | none | proposed: the digest-only spelling of `xattrs`, compared as `xattrs` |
| xattrs_unknown | flag: metadata unknown | all | n/a (flag) | diff-v1, rule 4 |
| sha256 | content | reg | n/a (a `reg` without it carries `unverified`) | diff-v1, rule 3: "the hash when both sides have one" |
| unverified | flag: content unknown | all | n/a (flag) | diff-v1, rule 3 |
| unstable | flag: content unknown | all | n/a (flag) | diff-v1, rule 3 |
| rdev | content | blk, chr | n/a (present exactly on `blk`, `chr`) | diff-v1, rule 3: "the device number" |
| link_target | content | lnk | n/a (present exactly on `lnk`) | diff-v1, rule 3: "the link target when neither side is `unreadable`" |
| target_outside_scope | not compared | all | n/a | design doc §5.1.1: "reporting only and must never drive a decision" |
| stored | not compared | all | none | proposed: bookkeeping, equal to `sha256` |
| mount | flag: content unknown | all | n/a (flag) | diff-v1, rule 3 |
| unreadable | flag: content unknown | all | n/a (flag) | diff-v1, rule 3 |
| raced | flag: everything unknown | all | n/a (flag) | diff-v1, rule 1 |
