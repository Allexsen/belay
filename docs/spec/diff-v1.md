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
{"belay_diff":1,"scopes":["/home/u/proj"],"before_created_ns":1761000000000000000,"after_created_ns":1761000600000000000,"before_hash_max_bytes":67108864,"after_hash_max_bytes":67108864}
{"path":"src/main.c","outcome":"modified","type":"reg","changed":["size","mtime_ns","sha256"]}
{"path":"build/","outcome":"unknown","type":"dir","unknown":["unstable"]}
{"belay_diff_end":2,"unchanged":1840,"added":0,"removed":0,"modified":1,"type_changed":0,"metadata_only":0,"unknown":1}
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

An entry whose parent is missing from its own manifest (an orphan) is handled the same way; nothing
looks a parent up.

**Present on both sides.** Each field takes part in the comparison by its class (table below).
Flags on **either** side make part of the comparison unknown: their reasons are collected.

1. `raced` on either side: `unknown`. Its recorded fields may not be the state at the end of its
   walk, so not even a difference proves a change.
2. Types differ: `type_changed`.
3. **Content**: a content field that differs is proof (`size` for a regular file or symlink, the
   hash when both sides have one, the link target when neither side is `unreadable`, the device
   number). Proof gives `modified`. Without proof, content is unknown if a content-scoped flag
   (`unverified`, `unstable`, `unreadable`, `mount`) is on either side, or one side has a hash and
   the other does not: `unknown`.
4. **Metadata and identity**: content unchanged and a metadata or identity field differs:
   `metadata_only`. Without such a difference, `xattrs_unknown` on either side: `unknown`.
5. Only `ctime_ns` differs: `metadata_only`, `changed` names `ctime_ns` -- an attribute the
   manifest does not record changed.
6. Otherwise `unchanged`.

`changed`, for a path present on both sides: when the types differ, `["type"]`; otherwise every
compared field that differs (content, metadata or identity, by its class for that type), whatever
the outcome, and `ctime_ns` only under rule 5. A field is compared only where both sides know it:
the hash when both have one, the link target when neither is `unreadable`, `iflags` when both
have it (absent means not available), `caps` and `xattrs` when neither side carries
`xattrs_unknown`. `unknown`, for an `unknown` outcome: the reason of every flag on either side, in
the order of the reasons table; for the one-sided case, its one reason.

Nothing above can produce `unchanged` for a path on which either side carries `raced`, `unstable`,
`unverified`, `unreadable`, `mount` or `xattrs_unknown`, nor for a path present on one side only.

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
| `listing_incomplete` | Absent on a side whose nearest recorded ancestor directory is `unstable`: possibly present. |
| `not_captured` | Absent on a side whose nearest recorded ancestor directory is `unreadable` or a `mount`: nothing below it was captured. |
<!-- END GENERATED: diff-reasons -->

## How each manifest field is compared

<!-- BEGIN GENERATED: diff-fields -->
<!-- From src/schema/diff_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| field | class | for types | makes unknown | why |
|---|---|---|---|---|
| `path` | key |  |  | Pairs the entries. |
| `type` | type | all |  | A different type is `type_changed`. |
| `mode` | metadata | all |  | Permission bits (the type bits are `type`). |
| `uid` | metadata | all |  | Owner. |
| `gid` | metadata | all |  | Group. |
| `size` | content | reg, lnk |  | Proof of a content change without a hash. A directory's follows its listing. |
| `mtime_ns` | metadata | reg, lnk, fifo, sock, blk, chr |  | Settable by any writer. A directory's follows its listing. |
| `ctime_ns` | ctime | all |  | Moves with every change; reported only when nothing else differs. |
| `ino` | identity | all |  | Same bytes, new inode: replaced (rename-over, as dpkg installs). Hard links break and open descriptors keep the old file. |
| `dev` | identity | all |  | Which filesystem holds it. |
| `nlink` | identity | reg, lnk, fifo, sock, blk, chr |  | Hard links added or removed elsewhere. A directory's counts its subdirectories. |
| `iflags` | metadata | all |  | Compared when both sides have it: absent means not available (known issue). |
| `caps` | metadata | all |  | A file capability, added or removed: a privilege change. Not compared under `xattrs_unknown`. |
| `xattrs` | metadata | all |  | Compared by the set's digest, so an inline set and a digest-only set compare. Not compared under `xattrs_unknown`. |
| `xattrs_sha256` | not compared |  |  | Compared as `xattrs`. |
| `xattrs_unknown` | flag |  | metadata | Metadata unknown unless another metadata field proves a change. |
| `sha256` | content | reg |  | Content digest. |
| `unverified` | flag |  | content | Content unknown unless size proves a change (different hash limits included). |
| `unstable` | flag |  | content | Content (a directory's listing) unknown unless another content field proves a change. |
| `rdev` | content | blk, chr |  | Which device the node refers to. |
| `link_target` | content | lnk |  | Compared only when neither side is `unreadable` (empty means unknown). |
| `target_outside_scope` | not compared |  |  | Derived from the target; advisory. |
| `stored` | not compared |  |  | Bookkeeping: equal to `sha256`. |
| `mount` | flag |  | content | Contents not captured. |
| `unreadable` | flag |  | content | Contents unknown unless another content field proves a change. |
| `raced` | flag |  | everything | Everything unknown: the recorded fields may not be the state at the end of the walk, so no difference is proof. |
<!-- END GENERATED: diff-fields -->

## Interpreters

An interpreter receives `{path, before, after}` for a path that is not `unchanged`, and returns
findings (strings, emitted in `findings`) or declines. It cannot set or change the outcome. In
this version every interpreter declines; Phase 4 adds pip, dpkg, git and text.
