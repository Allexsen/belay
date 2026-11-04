# Pin: manifest version 4

**What this is.** Version 4 of the manifest format: a hash a concurrent writer may have torn says
so. A v4 manifest is a v3 manifest -- `manifest-v3.md`, and through it `manifest-v2.md`,
`manifest-v1.md` and its addendum, which stay as they are -- with exactly the changes below.
Everything not listed here is as v3 says, byte for byte. A new entry key and new trailer keys are a
new version, not an addendum row: every reader so far rejects an unknown key (V3-R2).

Until now a file hashed while a process held it open for writing, or mapped shared-writable, was
recorded like any other, and a diff compared that hash: measured with a shared-mapping writer, 30
of 30 captures recorded a hash of bytes the file never held, with no flag, and the diff said
`modified`. From v4, `writer_open` marks such an entry and the diff does not compare its hash.

The diff's rows are here, as V2-R4 and V2-R7 are in `manifest-v2.md`; `diff-fields.md` is unchanged
and states the fields of a manifest before v4. `checkpoint-v1.md` is unchanged too: `provisional`
keeps its meaning, in `checkpoint.v1` and in the diff trailer.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK. Rules added
to v4 later go in `manifest-v4-addendum.md`, append-only, as v1's do.

## Lines

| id | line | key | type | value | when |
|---|---|---|---|---|---|
| V4-1 | header | `belay_manifest` | int | `4` | always |
| V4-2 | entry | `writer_open` | bool | `true`: when the file was read to hash it, some process had it open for writing or mapped shared-writable, at the start of the read, at its end, or both, by the platform's probe. The `sha256` is of what one read returned and is kept for debugging; it may be bytes the file never held. | a regular file with `sha256`, no `stored`, and none of `unverified`, `unstable`, `unreadable`, `mount`; absent otherwise, never `false` |
| V4-3 | trailer | `writer_open` | int | entries carrying `writer_open` | always |
| V4-4 | trailer | `unguarded` | int | regular files read and hashed in this walk with no answer from the probe: at the start or end of the read it could not tell (no lease facility on the platform or filesystem, or a file belay's user does not own, without `CAP_LEASE`), or the scope is on overlayfs, where a shared mapping whose file descriptor was closed is not seen. Carrying `writer_open` excludes an entry from this count. A file not read (`trusted`) is not counted. | always |

Key order: an entry's as v1's, with `writer_open` after `raced`. The trailer: v3's keys in v3's
order, then V4-3, then V4-4. A trailer key is never optional.

## Readers and writers

| id | rule |
|---|---|
| V4-R1 | A reader that knows only v1 to v3 rejects a v4 manifest, loudly (an unknown `belay_manifest` value is rejected). |
| V4-R2 | A reader that knows v4 accepts `1` to `4`, each by its own key set, strictly: a v4 trailer missing a v4 key, or a line of v1, v2 or v3 carrying one, or an entry of v1, v2 or v3 carrying `writer_open`, is rejected, as is any unknown key. |
| V4-R3 | An entry breaking V4-2's "when" is rejected. A trailer's `writer_open` that is not the number of entries carrying it is rejected, as for `raced`, and so is an `unguarded` larger than the trailer's entries. |
| V4-R4 | belay writes v4 only, from the release that adds it. A manifest of an earlier version stays valid and readable, and reads as `writer_open` absent on every entry and both trailer counts `0`: those versions did not ask. |
| V4-R5 | Wherever the probe can tell, it is asked at the start and at the end of the read of every regular file that is hashed, not only of a file whose copy is wanted. A `1` at either point marks the entry; its copy is not kept, as before. The hash is not dropped. A file that fails the stability check is `unstable` and has no hash, so no `writer_open`. |
| V4-R6 | mark's prefilter never trusts an entry carrying `writer_open`, nor another name of its inode: the file is read again, whatever its stat says. Its stat does not move when the write is through a mapping already dirty (A9), so a hash kept this way would outlive the writer. |
| V4-R7 | baseline-bundle's B-4 reads manifest v4 where it says v3: a bundle carries the manifest belay writes. |

## The diff (diff.v1, no version change: a consumer ignores a field it does not know)

| id | rule |
|---|---|
| V4-D1 | The field's row, in `diff-fields.md`'s columns: `writer_open` \| flag: everything unknown \| all \| compared \| flag \| this pin. As with `raced` (diff-v1's rule 1), on either side the outcome is `unknown`, whatever else differs: `size`, `mode`, the type. |
| V4-D2 | On an entry with `writer_open` on either side, `sha256` is not compared: it is never in `changed`, and no before or after value carries it, across a type change included, where diff-values V6 otherwise carries a regular file's hash (the marked side's only). Every other field is compared and listed as for `raced`. |
| V4-D3 | A path on one side only whose entry carries `writer_open`: `unknown`, never `added` or `removed`. diff-v1's one-sided rules decide first: an earlier rule that applies (`not_captured`, `listing_incomplete`, a raced ancestor) gives its one reason, as it would without the flag. Otherwise the reasons are the entry's own: `writer_open`, after `raced` when it carries both. |
| V4-D4 | The reason is `writer_open`, last in `unknown` when others are present, and last in policy-v1's order, after `listing_incomplete` and every other reason. It means a concurrent writer: the hash may be of bytes the file never held. |
| V4-D5 | The diff trailer gains `before_writer_open`, `after_writer_open`, `before_unguarded`, `after_unguarded`, ints, each that manifest's trailer count (`0` for a manifest before v4), in that order, after every key it has. |
| V4-D6 | `provisional` is unchanged: it stays any of the six counts `vanished`, `unstable`, `raced`, per side. A marked entry is said by its own record. |
| V4-D7 | protect-spec's PS-M5 entry flags gain `writer_open`, last: a protected path that carries it, on either side, is `protected_path_unverifiable`. |
| V4-D8 | Outside the diff too, a marked entry has no hash: no consumer compares or reports it. An `expected_sha256` (PS-M4) stops at `protected_path_unverifiable`, with no `protected_hash_mismatch` of `other bytes`; `absent` and `not a regular file` compare no hash and stand. A package row with a database hash to compare has `at_reset` (B-P6) `unverified`, and `self_consistent` follows from it; a row without one stays `no_hash`. |
| V4-D9 | policy-v1's `new_executable_on_path` reads the mode, not the hash: on a path whose `unknown` reasons include `writer_open`, it fires as it would for the entry's added, changed or swapped mode and type, read from the two entries, provisional, its `outcome` field `unknown`. The mark decides: any other reason beside it, on either side, changes nothing. A one-sided entry whose reason is an earlier rule's (V4-D3) has no `writer_open` among its reasons, so does not fire. A path whose reasons do not include `writer_open` stays as it is. |

## Settled alongside v4

True before v4, and silent or read two ways in their pins, until a model's coverage reached them. They state what belay does.

| id | rule |
|---|---|
| V4-S1 | A package database file, these by name (`RECORD`, dpkg's `status`, `info/*.md5sums`), with no stored copy because a writer held it: `baseline export` and `verify` refuse, exit 4, `no stored copy (a writer held it open?): capture again`. |
| V4-S2 | protect-spec's PS-M5: a path on one side only whose outcome is `unknown`, under any rule that matches it, is `protected_path_unverifiable`, whichever side the rule's modes read. |
| V4-S3 | `tests_weakened` alone: a file of size 0 with a `sha256` in its entry, a marked entry's included (V4-D8 is about what a hash says; an empty file's says nothing), counts as held, and empty, with or without a copy: it needs none, and an empty file cannot be torn. A file belay could not read has no hash and is not held. In that row a file "removed" is one that was a regular file before and is not after, whatever the diff's outcome, so a held empty file gone from one side is reported, at 0 -> 0. |

## Example

```
{"path":"data.bin","type":"reg","mode":33188,"uid":1000,"gid":1000,"size":4194304,"mtime_ns":1793823520041427976,"ctime_ns":1793823520041427976,"ino":92219,"dev":2096,"nlink":1,"iflags":524288,"sha256":"e3fff6c24125127992ace439f2b750153d8123100eb524239af540b2034a339e","writer_open":true}
...
{"belay_manifest_end":1840,"vanished":0,"unreadable":0,"unstable":0,"mounts":1,"raced":0,"trusted":0,"reference":"none","read_all":"check","writer_open":1,"unguarded":0}
```

Its diff record, the file's mtime having moved:

```
{"path":"data.bin","outcome":"unknown","type":"reg","changed":["mtime_ns"],"before":{"mtime_ns":1793823520009543603},"after":{"mtime_ns":1793823520041427976},"unknown":["writer_open"]}
```
