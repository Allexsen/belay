# diff.v1

Status: draft (Phase 3). Defined in `src/schema/diff_schema.c`; the tables below are generated from
it (`make gen`, checked in CI by `make gen-check`).

A diff compares two manifests of the **same scope** (`manifest-v1.md`) and gives every path one
outcome. It is produced as a stream, in bounded memory however many entries the manifests hold:
the two sorted manifests are merged, one path at a time, and each record is written as soon as it
is decided.

## Shape

NDJSON, like the manifest: one header line, one record per path whose outcome is not `unchanged`,
in the manifests' path order (bytewise), and a trailer line. Readers MUST reject a version they do
not know, and treat a missing trailer as a truncated diff.

```json
{"belay_diff":1,"scopes":["/home/u/proj"],"before_created_ns":1761000000000000000,"after_created_ns":1761000600000000000,"before_hash_max_bytes":67108864,"after_hash_max_bytes":67108864,"scope_remounted":false,"identity_compared":true}
{"path":"src/main.c","outcome":"modified","type":"reg","changed":["size","mtime_ns","sha256"]}
{"path":"build","outcome":"unknown","type":"dir","unknown":["unstable"]}
{"belay_diff_end":2,"unchanged":1840,"added":0,"removed":0,"modified":1,"type_changed":0,"metadata_only":0,"unknown":1,"before_vanished":0,"before_unstable":0,"before_raced":0,"after_vanished":0,"after_unstable":1,"after_raced":0,"provisional":true,"before_sha256":"9f2c...","after_sha256":"41ab..."}
```

### Header

<!-- BEGIN GENERATED: diff-header -->
<!-- From src/schema/diff_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| field | kind | meaning |
|---|---|---|
| `belay_diff` | int | Format version. A reader MUST reject a version it does not know. |
| `scopes` / `scopes_b64` | array | The scope both manifests record; manifests of different scopes are never compared. Not valid UTF-8: `scopes_b64`. |
| `before_created_ns` | int | The earlier manifest's `created_ns`. |
| `after_created_ns` | int | The later manifest's `created_ns`. |
| `before_hash_max_bytes` | int | The earlier manifest's hash limit. When the two differ, a file hashed on one side and not the other is `unknown` unless its size proves a change. |
| `after_hash_max_bytes` | int | The later manifest's hash limit. |
| `scope_remounted` | bool | The scope root's `dev` differs between the manifests: it was remounted, and devices were numbered anew. |
| `identity_compared` | bool | Whether `ino` was compared: never across a remount of the scope root, since an inode number means something only within one device. Content still compares by hash. |
<!-- END GENERATED: diff-header -->

### Records

<!-- BEGIN GENERATED: diff-record -->
<!-- From src/schema/diff_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| field | kind | meaning |
|---|---|---|
| `path` / `path_b64` | string | As in the manifest: relative to the scope, base64 when not valid UTF-8. |
| `outcome` | string | One of the outcomes below, never `unchanged`. |
| `type` | string | The entry's type after (before, for `removed`). |
| `type_before` | string | For `type_changed` only: the type before. |
| `changed` | array | The compared fields that differ, in the manifest's field order; absent when none. |
| `unknown` | array | For `unknown` only: the reasons, in the order of the reasons table. |
| `findings` | array | What an interpreter explained about the change, one string each; absent when none. Annotations only: an interpreter never sets or changes the outcome. |
<!-- END GENERATED: diff-record -->

### Trailer

<!-- BEGIN GENERATED: diff-trailer -->
<!-- From src/schema/diff_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| field | kind | meaning |
|---|---|---|
| `belay_diff_end` | int | Number of records emitted. Then one count per outcome, named as the outcome, unchanged included. |
| `unchanged` | int | Paths whose outcome is `unchanged`. |
| `added` | int | Paths whose outcome is `added`. |
| `removed` | int | Paths whose outcome is `removed`. |
| `modified` | int | Paths whose outcome is `modified`. |
| `type_changed` | int | Paths whose outcome is `type_changed`. |
| `metadata_only` | int | Paths whose outcome is `metadata_only`. |
| `unknown` | int | Paths whose outcome is `unknown`. |
| `before_vanished` | int | The earlier manifest's `vanished`: entries gone while its tree was walked. |
| `before_unstable` | int | The earlier manifest's `unstable`. |
| `before_raced` | int | The earlier manifest's `raced`. |
| `after_vanished` | int | The later manifest's `vanished`. |
| `after_unstable` | int | The later manifest's `unstable`. |
| `after_raced` | int | The later manifest's `raced`. |
| `provisional` | bool | Any of the six counts above is not 0: a tree changed while it was walked, so the result is provisional (manifest-v1, obligations on a consumer). The records name each flagged path; `vanished` paths have none. |
| `before_sha256` | string | The sha256 of the earlier manifest's bytes as this diff read them. |
| `after_sha256` | string | The sha256 of the later manifest's bytes as this diff read them. |
<!-- END GENERATED: diff-trailer -->

## Outcomes

<!-- BEGIN GENERATED: diff-outcomes -->
<!-- From src/schema/diff_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| name | meaning |
|---|---|
| `unchanged` | Every compared field equal and nothing unknown. Counted in the trailer, never emitted. |
| `added` | Present after, absent before, and the absence is known. |
| `removed` | Present before, absent after, and the absence is known. |
| `modified` | Content changed: a content field differs (hash, size, link target, device number). |
| `type_changed` | The entry's type differs. |
| `metadata_only` | Content unchanged; metadata or identity differs (`changed` names the fields). A `ctime_ns` change alone is listed too: an attribute the manifest does not record changed. |
| `unknown` | Neither side proves a change, and something prevents proving there was none (`unknown` names why). Never read as unchanged. |
<!-- END GENERATED: diff-outcomes -->

## How an outcome is decided

Manifests of different scopes are refused before any entry is read. Then, for each path:

**Present on one side only.** Look at the side that lacks it: its nearest recorded ancestor (the
deepest entry whose path, followed by `/`, begins this path; the scope root `.` when there is none).

- That ancestor is a directory carrying `unreadable` or `mount`: `unknown`, reason `not_captured`.
- It is a directory carrying `unstable`: `unknown`, reason `listing_incomplete`.
- Otherwise the absence is known. If the side that has the path carries `raced` on it, `unknown`
  (reason `raced`): it may not have existed at the end of that walk. Else `added` or `removed`.

An entry whose parent directory is missing from its own manifest (an orphan) never reaches the
diff: the reader rejects that manifest, and the diff writes nothing.

**Present on both sides.** Each field takes part in the comparison by its class, for the entry
types, and on the entries (mount roots or not) that `test/expect/diff-fields.md` pins and the
table below generates. Flags on **either** side make part of the comparison unknown: their reasons
are collected.

1. `raced` on either side: `unknown`. Its recorded fields may not be the state at the end of its
   walk, so not even a difference proves a change.
2. Types differ: `type_changed`.
3. **Content**: a content field that differs is proof (`size` for a regular file or symlink, the
   hash when both sides have one, the link target when neither side is `unreadable`, the device
   number). Proof gives `modified`. Without proof, content is unknown if a content-scoped flag
   (`unverified`, `unstable`, `unreadable`, `mount`) is on either side: `unknown`. In particular,
   a hash on one side and `unverified` on the other -- the two manifests' hash limits differ, or
   the file could not be hashed -- is `unknown`, unless `size` differs, which proves `modified`.
4. **Metadata and identity**: content unchanged and a metadata or identity field differs:
   `metadata_only`. Without such a difference, metadata is unknown, and the outcome `unknown`, if
   either side carries `xattrs_unknown` (reason `xattrs_unknown`) or `iflags` is present on one
   side only (reason `iflags_unknown`: an absent `iflags` means it could not be read).
5. Only `ctime_ns` differs, on a regular file, symlink or directory that is not a mount root:
   `metadata_only`, `changed` names `ctime_ns` -- an attribute the manifest does not record
   changed.
6. Otherwise `unchanged`.

**Devices and identity.** `dev` is not compared as a number: overlay, tmpfs and btrfs number their
devices when they are mounted, so a remount would make every entry differ and bury a real change.
Each side says instead whether the entry is on the same device as its scope root; a change in that
is a real mount change (`metadata_only`, `changed` names `dev`). `ino` is compared only when the
entry's `dev` is the same on both sides: an inode number means something only within one device.
When the scope root's own `dev` differs between the two manifests -- a remount -- the header says
so once (`scope_remounted`, `identity_compared`) and `ino` is compared for no entry; content still
compares by hash.

**Timestamps that move on use.** On a FIFO, socket or device node, and on a mount root,
`mtime_ns` and `ctime_ns` are not compared: ttys and pipes stamp themselves when used, and a mount
root's times belong to the mounted filesystem. Their mode, owner, group, inode, device relation
and device number still compare, so a real `chmod` is still seen.

`changed`, for a path present on both sides: when the types differ, `["type"]`; otherwise every
compared field that differs (by its class for that type), whatever the outcome, and `ctime_ns` only
under rule 5. A field is compared only where both sides know it: the hash when both have one, the
link target when neither is `unreadable`, `iflags` when both have it, `caps` and `xattrs` where the
attributes were read on both sides (neither carries `xattrs_unknown`, neither is a mount root --
an absent `caps` or `xattrs` means none only where they were read). `unknown`, for an `unknown`
outcome: the reasons of every flag on either side and, when the types are the same, of every field
unknown under rule 4 (across a type change no field is compared), in the order of the reasons
table; for the one-sided case, its one reason.

**An absent record means `unchanged`.** That holds only because every path that is not provably
unchanged is emitted -- `unknown` included. Nothing above can produce `unchanged` for a path on
which either side carries `raced`, `unstable`, `unverified`, `unreadable`, `mount` or
`xattrs_unknown`, or `iflags` on one side only, nor for a path present on one side only.

## Reasons

<!-- BEGIN GENERATED: diff-reasons -->
<!-- From src/schema/diff_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| name | meaning |
|---|---|
| `raced` | An entry changed after it was recorded: its recorded fields may not be the state at the end of its walk, so not even a difference proves a change. |
| `unstable` | A file changed while read (no hash), or a directory's listing is incomplete. |
| `unverified` | No hash on one side (larger than its `hash_max_bytes`, or not readable). |
| `unreadable` | The entry's contents could not be captured. |
| `mount` | A mount root: contents not captured, by design. |
| `xattrs_unknown` | Extended attributes could not be read. |
| `iflags_unknown` | Inode flags recorded on one side only: absent means they could not be read. |
| `listing_incomplete` | Absent on a side whose nearest recorded ancestor directory is `unstable`: possibly present. |
| `not_captured` | Absent on a side whose nearest recorded ancestor directory is `unreadable` or a `mount`: nothing below it was captured. |
<!-- END GENERATED: diff-reasons -->

## How each manifest field is compared

<!-- BEGIN GENERATED: diff-fields -->
<!-- From src/schema/diff_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| field | class | for types | on mount roots | absent means | makes unknown | why |
|---|---|---|---|---|---|---|
| `path` | key |  | compared | required |  | Pairs the entries. |
| `type` | type | all | compared | required |  | A different type is `type_changed`. |
| `mode` | metadata | all | compared | required |  | Permission bits (the type bits are `type`). |
| `uid` | metadata | all | compared | required |  | Owner. |
| `gid` | metadata | all | compared | required |  | Group. |
| `size` | content | reg, lnk | compared | required |  | Proof of a content change without a hash. A directory's follows its listing. |
| `mtime_ns` | metadata | reg, lnk | not compared | required |  | Settable by any writer. Not compared on a directory (it follows the listing), on a FIFO, socket or device node, or on a mount root: those stamp themselves when used. |
| `ctime_ns` | ctime | reg, dir, lnk | not compared | required |  | Moves with every change; reported only when nothing else differs. Not compared on a FIFO, socket or device node, or on a mount root. |
| `ino` | identity: within one device | all | compared | required |  | Same bytes, new inode: replaced (rename-over, as dpkg installs). Compared only when the entry's `dev` is the same on both sides, never across a remount of the scope root. |
| `dev` | identity: device relation | all | compared | required |  | Whether the entry is on its scope root's device, per side: a change is a real mount change. The raw number is not compared (assigned at mount time). |
| `nlink` | identity | reg, lnk, fifo, sock, blk, chr | compared | required |  | Hard links added or removed elsewhere. A directory's counts its subdirectories. |
| `iflags` | metadata | all | compared | unknown |  | On one side only it is `unknown` (reason `iflags_unknown`): absent means it could not be read. |
| `caps` | metadata | all | compared | none if read |  | A file capability, added or removed: a privilege change. Compared only where the attributes were read (no `xattrs_unknown`, not a mount root). |
| `xattrs` | metadata | all | compared | none if read |  | Compared by the set's digest (each element is `name=sha256(value)`), so an inline set and a digest-only set compare. Only where the attributes were read. |
| `xattrs_sha256` | not compared |  | not compared | none if read |  | Compared as `xattrs`. |
| `xattrs_unknown` | flag |  | compared | flag | metadata | Metadata unknown unless another metadata field proves a change. |
| `sha256` | content | reg | compared | with unverified |  | Content digest. |
| `unverified` | flag |  | compared | flag | content | Content unknown unless size proves a change (different hash limits included). |
| `unstable` | flag |  | compared | flag | content | Content (a directory's listing) unknown unless another content field proves a change. |
| `rdev` | content | blk, chr | compared | only on its types |  | Which device the node refers to. |
| `link_target` | content | lnk | compared | only on its types |  | Compared only when neither side is `unreadable` (empty means unknown). |
| `target_outside_scope` | not compared |  | not compared | n/a |  | Derived from the target; advisory. |
| `stored` | not compared |  | not compared | none |  | Bookkeeping: equal to `sha256`. |
| `mount` | flag |  | compared | flag | content | Contents not captured. |
| `unreadable` | flag |  | compared | flag | content | Contents unknown unless another content field proves a change. |
| `raced` | flag |  | compared | flag | everything | Everything unknown: the recorded fields may not be the state at the end of the walk, so no difference is proof. |
<!-- END GENERATED: diff-fields -->

## Interpreters

An interpreter receives `{path, before, after}` for a path that is not `unchanged`, and returns
findings (strings, emitted in `findings`) or declines. It cannot set or change the outcome. In
this version every interpreter declines; Phase 4 adds pip, dpkg, git and text.
