# diff.v1

Status: draft. Defined in `src/schema/diff_schema.c` and `src/schema/finding_schema.c`; the tables
below are generated from them (`make gen`, checked in CI by `make gen-check`).

A diff compares two manifests of the **same scope** (`manifest-v1.md`) and gives every path one
outcome. It is produced as a stream, in bounded memory however many entries the manifests hold:
the two sorted manifests are merged, one path at a time, and each record is written as soon as it
is decided.

## Shape

NDJSON, like the manifest: one header line, one record per path whose outcome is not `unchanged`,
in the manifests' path order (bytewise), then the event records (see "Interpreters"), and a
trailer line. Readers MUST reject a version they do not know, and treat a missing trailer as a
truncated diff. No line has a fixed length bound (a record's findings alone make it unbounded):
consumers MUST handle lines of any length.

```json
{"belay_diff":1,"scopes":["/home/u/proj"],"before_created_ns":1761000000000000000,"after_created_ns":1761000600000000000,"before_hash_max_bytes":67108864,"after_hash_max_bytes":67108864,"scope_remounted":false,"identity_compared":true,"before_manifest_version":2,"after_manifest_version":2,"before_excluded":[{"path":"node_modules","reason":"user","dev":2049,"ino":131990}],"after_excluded":[{"path":"node_modules","reason":"user","dev":2049,"ino":131990}]}
{"path":"src/main.c","outcome":"modified","type":"reg","changed":["size","mtime_ns","sha256"]}
{"path":"build","outcome":"unknown","type":"dir","unknown":["unstable"]}
{"belay_diff_end":2,"unchanged":1840,"added":0,"removed":0,"modified":1,"type_changed":0,"metadata_only":0,"unknown":1,"dir_timestamps_only":0,"events":0,"before_vanished":0,"before_unstable":0,"before_raced":0,"after_vanished":0,"after_unstable":1,"after_raced":0,"provisional":true,"before_sha256":"9f2c...","after_sha256":"41ab...","before_writer_open":0,"after_writer_open":0,"before_unguarded":0,"after_unguarded":0,"before_sealing":0,"after_sealing":0}
```

`before` is the first manifest given and `after` the second, whatever their `created_ns` say.

### Header

<!-- BEGIN GENERATED: diff-header -->
<!-- From src/schema/diff_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| field | kind | meaning |
|---|---|---|
| `belay_diff` | int | Format version. A reader MUST reject a version it does not know. |
| `scopes` / `scopes_b64` | array | The scope both manifests record; manifests of different scopes are never compared. Not valid UTF-8: `scopes_b64`. |
| `before_created_ns` | int | The first manifest's `created_ns`. |
| `after_created_ns` | int | The second manifest's `created_ns`. |
| `before_hash_max_bytes` | int | The first manifest's hash limit. When the two differ, a file hashed on one side and not the other is `unknown` unless its size proves a change. |
| `after_hash_max_bytes` | int | The second manifest's hash limit. |
| `scope_remounted` | bool | The scope root's `dev` differs between the manifests: it was remounted, and devices were numbered anew. |
| `identity_compared` | bool | Whether `ino` was compared: never across a remount of the scope root, since an inode number means something only within one device. Content still compares by hash. |
| `before_manifest_version` | int | The before manifest's format version (`belay_manifest`): provenance only; the outcomes do not depend on it (test/expect/manifest-v2.md, V2-R4). |
| `after_manifest_version` | int | The after manifest's format version, likewise. |
| `before_excluded` | array | What the before manifest did not walk: its `excluded`, as its header writes it (manifest-v2.md); `null` for a v1 manifest, which does not say. It decides nothing: a record says `not_captured` where an exclusion matters, and a path both sides excluded is named only here (test/expect/manifest-v2.md, V2-R7). |
| `after_excluded` | array | What the after manifest did not walk, likewise. |
| `roots_differ` | bool | `true` when the two manifests' `roots` (manifest v5) are not equal -- another list, another class, or a root found on one side only; absent otherwise. |
<!-- END GENERATED: diff-header -->

### Records

<!-- BEGIN GENERATED: diff-record -->
<!-- From src/schema/diff_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| field | kind | meaning |
|---|---|---|
| `path` / `path_b64` | string | As in the manifest: relative to the scope, base64 when not valid UTF-8. |
| `outcome` | string | One of the outcomes below, never `unchanged`. |
| `type` | string | The entry's type after (before, for `removed`). |
| `type_before` | string | When the path is on both sides and its types differ: the type before. That is every `type_changed`, and an `unknown` whose type also changed (`raced`). |
| `changed` | array | The compared fields that differ, in the manifest's field order; absent when none. |
| `before` | object | With `changed`: each field it names, the before side's value under the manifest's key and encoding (`link_target_b64`, `xattrs_sha256` where the manifest spells it so); a field that side does not record is left out. Where the type differs (`type_changed`, or `unknown` with `type_before`): that side's `mode` and its type's content fields (`size`, `sha256` for `reg`; `link_target` for `lnk`; `rdev` for `chr`, `blk`). Carried, never compared: the outcome does not depend on it (`test/expect/diff-values.md`). |
| `after` | object | As `before`, for the after side. |
| `unknown` | array | For `unknown` only: the reasons, in the order of the reasons table. |
| `content_not_read` | array | For `modified` and `metadata_only` only, on a regular file whose content was not read on a side: the reasons, in the order of the reasons table, from the flags of either side -- `unstable`, `unverified`, `unreadable`, `mount`. `unverified` is listed only for a side that carries none of the other three: the file was over the hash limit. Absent when both sides were hashed. What was compared proves the change; the content itself was not compared (`test/expect/diff-fields.md`, O9). For `added` too, from the one entry: a regular file by the same rule, and a directory carrying `unreadable` or `mount`, whose listing was not read (O10). For `type_changed` only when the entry after is such a directory (O11). Never on `removed`. |
| `findings` | array | What an interpreter explained about the change, one object each (Findings, below); absent when none. Annotations only: an interpreter never sets or changes the outcome. |
<!-- END GENERATED: diff-record -->

### Trailer

The trailer is written once both manifests have been read to their ends. `belay_diff_end` is the
number of records written. Then come one count per outcome, named as the outcome, in the order of
the outcomes table, `unchanged` included: every path present in either manifest is counted once,
so the counts add up to the number of distinct paths. `dir_timestamps_only` counts the directories
among `unchanged` whose own timestamps differ (see "A directory's own timestamps"), and `events`
the event records (`belay_diff_end` counts path records only). Then what each
manifest's own trailer said about its walk: `before_vanished`, `before_unstable` and `before_raced`
are the first manifest's `vanished`, `unstable` and `raced` counts, and `after_vanished`,
`after_unstable` and `after_raced` the second's. `provisional` is `true` exactly when any of those
six is not 0: a tree changed while it was walked, so the whole result is provisional (manifest-v1,
obligations on a consumer), and a `vanished` path has no record that could say so. Then
`before_sha256` and `after_sha256` are the sha256 of each manifest file's bytes, all of them, as
this diff read them; a reader accepts nothing after a manifest's trailer, so that is the whole
file. Last, `before_writer_open`, `after_writer_open`, `before_unguarded` and `after_unguarded` are
each manifest's own trailer counts (manifest v4; `0` for a manifest before it). None of the four
is in `provisional`. After those, `before_sealing` and `after_sealing` are each manifest's
directories carrying `unreadable` or `mount`, counted from its entries: nothing below them was
looked at, so a change there is that directory's one `unknown` record at most. Neither is in
`provisional`. Last, `runtime` counts the records of the runtime section (below); `0` when there
is none.

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
| `dir_timestamps_only` | int | Directories counted in `unchanged` whose `mtime_ns` or `ctime_ns` differs: a directory's own timestamps move with every name added, removed or renamed in it, which the records of its children report. |
| `events` | int | The number of event records (diff-events E7); `belay_diff_end` counts path records only. |
| `before_vanished` | int | The first manifest's `vanished`: entries gone while its tree was walked. |
| `before_unstable` | int | The first manifest's `unstable`. |
| `before_raced` | int | The first manifest's `raced`. |
| `after_vanished` | int | The second manifest's `vanished`. |
| `after_unstable` | int | The second manifest's `unstable`. |
| `after_raced` | int | The second manifest's `raced`. |
| `provisional` | bool | Any of the six counts above is not 0: a tree changed while it was walked, so the result is provisional (manifest-v1, obligations on a consumer). The records name each flagged path; `vanished` paths have none. |
| `before_sha256` | string | The sha256 of the first manifest's bytes as this diff read them: the whole file. |
| `after_sha256` | string | The sha256 of the second manifest's bytes, likewise. |
| `before_writer_open` | int | The first manifest's `writer_open`: entries a concurrent writer may have torn. `0` before manifest v4. |
| `after_writer_open` | int | The second manifest's `writer_open`. |
| `before_unguarded` | int | The first manifest's `unguarded`: files hashed with no answer from the writer probe. `0` before manifest v4. |
| `after_unguarded` | int | The second manifest's `unguarded`. |
| `before_sealing` | int | The first manifest's directories carrying `unreadable`, `mount` or (manifest v5) `not_read`, counted from its entries: nothing below them was looked at (test/expect/diff-fields.md, "The trailer"). |
| `after_sealing` | int | The second manifest's, likewise. |
| `runtime` | int | The number of `runtime` records, after the events (test/expect/runtime-v1.md, RT-D1); `0` when neither capture has a runtime record. Last. |
<!-- END GENERATED: diff-trailer -->

## Outcomes

<!-- BEGIN GENERATED: diff-outcomes -->
<!-- From src/schema/diff_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| name | meaning |
|---|---|
| `unchanged` | Every compared field equal and nothing unknown. Counted in the trailer, never emitted. A directory whose timestamps differ while every compared field is equal is `unchanged` (its timestamps are not compared), and counted again in `dir_timestamps_only`. |
| `added` | Present after, absent before, and the absence is known. |
| `removed` | Present before, absent after, and the absence is known. |
| `modified` | Content changed: a content field differs (hash, size, link target, device number). |
| `type_changed` | The entry's type differs. |
| `metadata_only` | Content unchanged; metadata or identity differs (`changed` names the fields). A `ctime_ns` change alone on a regular file or symlink is listed too: an attribute the manifest does not record changed. |
| `unknown` | Neither side proves a change, and something prevents proving there was none (`unknown` names why). Never read as unchanged. |
<!-- END GENERATED: diff-outcomes -->

## How an outcome is decided

Manifests of different scopes are refused before any entry is read. Then, for each path:

**Present on one side only.** Look at the side that lacks it: its nearest recorded ancestor (the
deepest entry whose path, followed by `/`, begins this path; the scope root `.` when there is none).
The first of these that applies decides:

- The side that lacks it excluded the path, or a path above it (manifest v2's `excluded`,
  `manifest-v2.md`): `unknown`, reason `not_captured`. That manifest did not look there, so its
  absence says nothing -- never `added` or `removed`. A path both manifests excluded is in neither,
  and in no record: the header's `before_excluded` and `after_excluded` name it (`manifest-v2.md`,
  V2-R7).
- That ancestor is a directory carrying `unreadable` or `mount`: `unknown`, reason `not_captured`.
- It is a directory carrying `unstable`: `unknown`, reason `listing_incomplete`.
- It is not a directory and carries `raced`: `unknown`, reason `raced`. It changed after it was
  recorded, and may have become a directory holding this path before that walk ended.
- Otherwise the absence is known. If the side that has the path carries `raced` on it, `unknown`
  (reason `raced`): it may not have existed at the end of that walk. Else `added` or `removed`.

An entry whose parent directory is missing from its own manifest (an orphan) never reaches the
diff: the reader rejects that manifest, and the diff writes nothing.

**Present on both sides.** Each field takes part in the comparison by its class, for the entry
types, and on the entries (mount roots or not) that `test/expect/diff-fields.md` pins and the
table below generates. Flags on **either** side make part of the comparison unknown: their reasons
are collected.

1. `raced` on either side: `unknown`. Its recorded fields may not be the state at the end of its
   walk, so not even a difference proves a change. `writer_open` (manifest v4) is treated the same
   way, with its own reason, and the entry's hash is not compared at all: a writer had the file
   when it was read, so the hash may be of bytes the file never held. A path on one side only that
   carries it is `unknown`, never `added` or `removed` (`test/expect/manifest-v4.md`, V4-D1 to D3).
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
   side only (reason `iflags_unknown`: an absent `iflags` means it could not be read), on an entry
   that is not a mount root.
5. Only `ctime_ns` differs, on a regular file or symlink that is not a mount root:
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
and device number still compare, so a real `chmod` is still seen. A mount root's own `iflags`,
`caps` and `xattrs` are never read (manifest-v1, rule 22), so on an entry that is a mount root on
either side they are not compared and add no reason: a directory that became a mount root, or
stopped being one, is `unknown` with the reason `mount`, plus those of any flags either side
carries.

**A directory's own timestamps.** A directory's `mtime_ns` and `ctime_ns` are not compared either:
they move whenever a name is added, removed or renamed in it, and the records of its children
report those changes. A directory whose timestamps differ while every compared field is equal
(its `size` and `nlink` are not compared either: they follow its listing too) is therefore
`unchanged` and gets no record; the trailer counts it in `dir_timestamps_only`, which is part of
`unchanged`. What this hides: an attribute the manifest does not record (a `trusted.*` extended
attribute when belay does not run as root) that changes on a directory is seen only in that
count.

`type_before`, for a path present on both sides whose types differ: the type before, whatever the
outcome -- `type_changed`, or `unknown` when `raced` or `writer_open` is on either side.

`changed`, for a path present on both sides: when the types differ, `["type"]`; otherwise every
compared field that differs (by its class for that type), whatever the outcome, and `ctime_ns` only
under rule 5. A field is compared only where both sides know it: the hash when both have one, the
link target when neither is `unreadable`, `iflags` when both have it, `caps` and `xattrs` where the
attributes were read on both sides (neither carries `xattrs_unknown` -- an absent `caps` or
`xattrs` means none only where they were read), and none of the three on a mount root.
`unknown`, for an `unknown` outcome: the reasons of every flag on either side -- except
`unverified` on a side that also carries `mount`, since a mounted regular file is never read and
`mount` is that reason -- and, when the types are the same, of every field unknown under rule 4
(across a type change no field is compared), in the order of the reasons table; for the
one-sided case, the reason of the rule that decided it, or, where no earlier rule applies to an
entry carrying `writer_open`, the entry's own: `writer_open`, after `raced` when it carries both.

**An absent record means `unchanged`** -- for a directory, possibly with its own timestamps
changed, which the trailer counts in `dir_timestamps_only`. That holds only because every other
path that is not provably unchanged is emitted -- `unknown` included. Nothing above can produce
`unchanged` for a path on which either side carries `raced`, `unstable`, `unverified`,
`unreadable`, `mount` or `xattrs_unknown`, or `iflags` on one side only, nor for a path present on
one side only.

## Reasons

<!-- BEGIN GENERATED: diff-reasons -->
<!-- From src/schema/diff_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| name | meaning |
|---|---|
| `raced` | An entry changed after it was recorded: its recorded fields may not be the state at the end of its walk, so not even a difference proves a change. For a path on one side only, that entry is the path's own, or its nearest recorded ancestor on the side that lacks it, a non-directory that may have become a directory holding it. |
| `unstable` | A file changed while read (no hash), or a directory's listing is incomplete. |
| `unverified` | No hash on one side (larger than its `hash_max_bytes`, or not readable). Not given for a side that is a mount root, which is never read: `mount` is its reason. |
| `unreadable` | The entry's contents could not be captured. |
| `mount` | A mount root: contents not captured, by design. |
| `xattrs_unknown` | Extended attributes could not be read. |
| `iflags_unknown` | Inode flags recorded on one side only: absent means they could not be read. |
| `listing_incomplete` | Absent on a side whose nearest recorded ancestor directory is `unstable`: possibly present. |
| `not_captured` | Absent on a side whose nearest recorded ancestor directory is `unreadable`, a `mount` or (manifest v5) `not_read`, or that excluded the path or a directory above it (manifest v2's `excluded`), or whose nearest recorded ancestor is `partial` and records neither such a name nor, in its `roots`, this path: nothing there was captured. |
| `writer_open` | A concurrent writer: some process had the file open for writing, or mapped shared-writable, when it was read, so its hash may be of bytes it never held. Never compared. |
| `not_read` | Manifest v5. A regular file whose content was not read, by its root's class (`meta`), with something else differing or a hash on the other side; or a directory not entered (`not_read`) on one side only, or whose type, mode or owner differs. |
| `sealed_key` | Manifest v5. A `sealed` hash on both sides under different sealing keys (the manifests' `sealed_key`): the hashes do not compare. |
| `class_changed` | Manifest v5. A `sealed` hash on one side only: the file moved between the class whose content is kept and the class that is sealed, and a keyed hash does not compare with a plain one, whatever the keys. |
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
| `ctime_ns` | ctime | reg, lnk | not compared | required |  | Moves with every change; reported only when nothing else differs. Not compared on a directory (it moves with the listing, which its children report: the trailer counts such directories), on a FIFO, socket or device node, or on a mount root. |
| `ino` | identity: within one device | all | compared | required |  | Same bytes, new inode: replaced (rename-over, as dpkg installs). Compared only when the entry's `dev` is the same on both sides, never across a remount of the scope root. |
| `dev` | identity: device relation | all | compared | required |  | Whether the entry is on its scope root's device, per side: a change is a real mount change. The raw number is not compared (assigned at mount time). |
| `nlink` | identity | reg, lnk, fifo, sock, blk, chr | compared | required |  | Hard links added or removed elsewhere. A directory's counts its subdirectories. |
| `iflags` | metadata | all | not compared | unknown |  | On one side only it is `unknown` (reason `iflags_unknown`): absent means it could not be read. Never read on a mount root, so not compared there. |
| `caps` | metadata | all | not compared | none if read |  | A file capability, added or removed: a privilege change. Compared only where the attributes were read (no `xattrs_unknown`, not a mount root). |
| `xattrs` | metadata | all | not compared | none if read |  | Compared by the set's digest (each element is `name=sha256(value)`), so an inline set and a digest-only set compare. Only where the attributes were read. |
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
| `writer_open` | flag |  | compared | flag | everything | Everything unknown: the hash may be torn and is not compared, and a writer was at the file, so no difference is proof (manifest-v4 V4-D1, V4-D2). |
| `not_read` | flag: by its rule (manifest v5) | dir | compared | flag |  | A directory not entered. On both sides, with equal type, mode and owner: no record, and nothing else of it is compared. On one side only, or those differ: `unknown` (reason `not_read`). A path below it on the other side is `not_captured`. |
| `partial` | not compared |  | compared | flag |  | Not compared. For a path the other side lacks directly under it: a directory, or a link under the scope root, is `added` or `removed` as anywhere; anything else only when that side's `roots` list it, and is `not_captured` otherwise. |
| `meta` | flag: by its rule (manifest v5) | reg | compared | flag |  | Content not read. On both sides: unchanged when every other field is equal, `modified` when `size` differs, `unknown` (reason `not_read`) for any other difference, never `metadata_only`. Against a hash on the other side: `unknown` unless `size` differs. |
| `sealed` | flag: by its rule (manifest v5) | reg | compared | flag |  | A keyed hash. On both sides under one `sealed_key`, `sha256` compares as any; under different keys it does not: `unknown` (reason `sealed_key`) unless `size` differs. On one side only: `unknown` (reason `class_changed`) unless `size` differs. No record carries a sealed entry's hash. |
<!-- END GENERATED: diff-fields -->

## Interpreters

For a path that is not `unchanged`, the interpreter that claims it adds **findings** to its record:
what the change means (a package upgraded, a ref moved, lines changed). Findings are annotations
only. An interpreter receives the core's verdict read-only and has no way to set or change an
outcome, so whatever an interpreter says or fails to say, every record's outcome is the one the
rules above decide.

**Which interpreter.** A path is claimed by its absolute path (scope + path): dpkg claims
`*/var/lib/dpkg/status` and the per-package `*/var/lib/dpkg/info/*.list` and `*.md5sums`; pip claims
`*.dist-info/RECORD` and `*.dist-info/METADATA`; git claims `*/.git/HEAD`, `*/.git/packed-refs`,
`*/.git/refs/*`, `*/.git/hooks/*`, `*/.git/index` and the reflogs `*/.git/logs/HEAD` and
`*/.git/logs/refs/*`. An unclaimed path is **text** when its entry is `stored` on every side it
exists on (a capture stores small text files by default); any other is **binary**, which adds
nothing: its size and hash are already in the record.

**Content.** Interpreters read the stored copies through the store given to the diff (`belay_diff`'s
options): the directory a capture keeps copies in, each at `<store>/<the first two hex digits of its
sha256>/<the other 62>`, named by the manifest entry's `stored`. Every copy read is hashed and must
match its name, so a stale, planted or truncated copy is never read as content; one that is not a
regular file (a symlink included) is `corrupt`. When an interpreter needs a copy it cannot read, on
a side where the path exists, it says so: the finding `content_unavailable`, with `reason`
`no_store` (the diff was given no store), `missing`, `too_large` (over the interpreter's bound) or
`corrupt` (does not hash to its name), and `side`. It never declines silently there: pip, dpkg and
git, whose package and repository facts come from that content, also emit a `content_unavailable`
event naming the paths, so a consumer never reads "no packages changed" or "no branch moved" where
the change could not be read. git names only the paths it derives events from (HEAD, branches,
`packed-refs`, their reflogs), and a reflog removed needs no copy.

**Findings.** Each finding is an object: `{"kind": ..., <its fields, in order>, "text": ...}`. `int`
fields are non-negative integers, `string` fields UTF-8 of at most 1,024 bytes, `bool` fields `true`
or `false`, `bytes` fields up to 4,095 bytes written as `<name>` when UTF-8 and `<name>_b64`
(base64) otherwise; an optional field (`?`) is absent where its kind says, and then the kind's
second template is used; `text` is the kind's template with each `{field}` replaced by its value, at
most 1,024 bytes. The core checks every finding against its kind's row below and renders its text,
so an interpreter supplies values, never text: a finding that breaks the row (an unknown kind, a
kind of another interpreter or level, a field missing, extra or over its bound) is replaced by
`invalid_finding`. `could_not_interpret`, `invalid_finding` and `and_more` are the core's alone: one
an interpreter adds is itself replaced by `invalid_finding`, so no interpreter can write "could not
interpret" over its own findings. An interpreter that fails on a path has its findings there
replaced by `could_not_interpret`; the diff does not fail. A record carries at most 4,096 findings:
past that, the 4,096th place is one `and_more` counting the findings from that place on, itself
included.

**Event records.** A fact about a package rather than a path -- installed, removed, upgraded,
reinstalled -- is an event record, emitted once every path has been seen, listing the paths it was
derived from. Every path an event lists has its own record, or is unchanged. An event derived from a
path whose outcome is `unknown` says `"provisional": true`: it may not hold. A path whose only
reason is `not_captured` derives no event at all: that side was not looked at, so nothing was
installed or removed there (diff-events E11). An event that breaks
its kind's row becomes, in its place, one `invalid_finding` event naming its paths, and a file an
interpreter cannot interpret one `could_not_interpret` event naming it: either way the interpreter's
other events stand. Only when its end hook fails as a whole -- its per-diff state over its bound,
memory, an event naming no path -- are its events one `could_not_interpret` naming at most 1,024 of
the paths it was given, with `paths_truncated` counting the rest. At most 65,536 event records per
interpreter: past that, the 65,536th is one `and_more` counting the events from that place on,
itself included.

<!-- BEGIN GENERATED: diff-events -->
<!-- From src/schema/finding_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| rule | statement |
|---|---|
| E1 placement | Event records come after the last path record and before the trailer. A diff with none has none. |
| E2 shape | `{"event": "<kind>", "interp": "<interpreter>", <the kind's fields, in finding-kinds.md's order>, "text": "<its template>", "provisional": true, "paths": [...]}`. The kind is an `event`-level kind of finding-kinds.md. `provisional` is present, and `true`, exactly when a path the event was derived from has the outcome `unknown` (decision P7): the event may not hold. |
| E3 paths | The paths it was derived from, relative to the scope as in path records, sorted bytewise, each once, at least one (except `and_more`). `paths_b64` instead -- every element base64 -- when any is not valid UTF-8. |
| E4 order | By interpreter, in the order text, pip, dpkg, git; within one, as the interpreter defines it in finding-kinds.md's terms: pip by normalized name, then kind; dpkg by Package, then Architecture, then kind; git by repository, then `HEAD` before every branch, then branch, then kind (decision 126). The same inputs give the same bytes. |
| E5 bound | At most 65,536 event records per interpreter per diff: past that, the 65,536th is `{"event": "and_more", "interp": ..., "n": <that one and the rest>, "text": "and {n} more", "paths": []}`. An interpreter's per-diff state is bounded to match. |
| E6 failure | An interpreter whose end hook fails emits `{"event": "could_not_interpret", "interp": ..., "text": "could not interpret", "paths": [...], "paths_truncated": <n>}` and no other event: `paths` the first 1,024 of the paths it had claimed (bytewise; never a path E11 withholds), `paths_truncated` the number of the rest, present only when not 0 (decision P4). The diff does not fail. |
| E7 trailer | The trailer gains `events`: the number of event records. `belay_diff_end` still counts path records only. |
| E8 forward | A consumer ignores an event kind it does not know, as it ignores an unknown finding kind or field. |
| E9 invalid | An event an interpreter adds that breaks its kind's row -- a kind not its own, not event-level, or the core's; a field missing, extra, or not a string field's value; text over 1,024 bytes -- is replaced, in its place, by `{"event": "invalid_finding", "interp": ..., "text": "invalid finding", "paths": [<its paths>]}`; the interpreter's other events stand (decisions P1, P5). |
| E10 a file not interpreted | A file an interpreter claims and cannot interpret gives one `{"event": "could_not_interpret", "interp": ..., "text": "could not interpret", "paths": [<the files>]}`; the interpreter's other events stand (the class of decision P1). pip: a dist-info that cannot be named, or a RECORD it must read that cannot be parsed -- that RECORD's path record carries `could_not_interpret` too, unless its outcome is `unknown`, and nothing more is read from it; a name with RECORDs added and removed other than one of each -- one event naming them, their path records carrying nothing (the pairing is known only once every path record is written). dpkg: a status that cannot be parsed -- its path record carries `could_not_interpret` too, unless its outcome is `unknown`. |
| E11 not captured | A path whose outcome is `unknown` with `not_captured` as its only reason -- the side that lacks it excluded it, or it lies below an `unreadable` directory or a mount there (diff-v1, "Present on one side only") -- derives no event: that side was not looked at, so nothing was installed or removed there. Its path record stands. Any other `unknown` path still derives provisional events (E2). No interpreter is given it, so no event of the core's names it either: no `could_not_interpret` (E10) nor `content_unavailable` for it, and a failed end hook's event (E6) never lists it. (Decision 2026-11-02: approved, from the review of #33, D1; the core's events spelled out, decision 118.) |
| E12 git events | git's end hook derives repository-level events from the paths of this diff it explained -- loose refs, `packed-refs`, `HEAD`, reflogs -- per repository (a directory named `.git`; `repo` its path in the scope). A branch is a ref `refs/heads/<branch>`, named without `refs/heads/`. Its value on a side: its loose ref there; else its line in `packed-refs` when `packed-refs` is a path of this diff; else, before only, the old id of the first entry its reflog gained in this diff (all zeros: absent). One event per branch whose existence or commit differs: absent before by that evidence and present after, `git_branch_created`; present after with no evidence of before, `git_branch_moved` with no `from`; its loose ref removed and `packed-refs` without it (a path of this diff, or not -- git removes a branch from both), `git_branch_deleted`; a deletion and a creation at the same commit whose new reflog says `Branch: renamed`, one `git_branch_renamed`. A branch on both sides at different commits is decided by the entries its reflog gained in this diff, when they lead from its value before to its value after (each entry's old id the previous one's new, the first's old the value before, the last's new the value after): any `reset`, `commit (amend)`, operation containing `rebase`, message starting `branch: Reset to`, or message containing `forced-update` -- `git_history_rewritten`; else only commits (`commit`, `commit (merge)`, `cherry-pick`, `revert`, `am`) and fast-forwards or merges (a message containing `Fast-forward`; an operation starting with `merge` or `pull`) -- `git_commits_added`; else, or with no such entries, `git_branch_moved`. `HEAD` naming another branch, or detaching or attaching: `git_head_switched`; `HEAD` detached on both sides at different commits is the branch `HEAD`, decided by `logs/HEAD` as above. Remote-tracking refs and tags derive no event (their path findings stand). A path whose outcome is `unknown` adds no finding to its record (P8) but is read like any other where its copy can be read, as dpkg reads a status (a `raced` file's bytes were true when read, and may be no longer): every event derived from it is provisional (E2), so a branch whose ref raced is never silent. What git cannot read reduces what is claimed, never the fact the refs give: a reflog it cannot read is no evidence -- the move still comes from the refs, as `git_branch_moved`, without a how; a ref or `packed-refs` that cannot be read on a side gives no value there -- before, the reflog's evidence may still give one, and without one the event is `git_branch_moved` with no `from` (a branch only in `packed-refs` too); after, the branch derives no event. A side git cannot parse counts as one it cannot read (and is a `could_not_interpret` event, E10); parsing a reflog is parsing only the entries it gained in this diff -- those after before's bytes when they are a prefix of after's ending at a line's end, and none otherwise (diff-v1, git: `git_reflog_rewritten`) -- never its older entries. A reflog's line is an entry when git reads it as one: `<old> <new> <identity>> <time> <zone>` and the message -- the ids 40 or 64 hex digits of either case, the identity up to the first `>` with a space after it, the time a number other than 0 as `strtoumax` reads it, the zone `+` or `-` and four digits, the message after one tab when there is one; every other line, a blank one included, git skips, and so does belay, counting the lines the reflog gained in this diff that git skips in `git_reflog_lines_ignored` (decision 202). A reflog's last line without its newline is no entry, and not counted: git does not read it as one. A loose ref's or `HEAD`'s value is read as git reads it: `ref:`, any spaces or tabs, then the name to the line's end, trailing whitespace cut; or an object id of either case at the start, followed by the end or by whitespace, whatever follows ignored -- a value git calls a broken ref is one git cannot parse (E10). An id read in either case is written lowercased, as git prints it (decision 213). A branch whose loose ref is symbolic (`ref: refs/heads/<other>`) on a side is an alias of its target there, as git lists it (`alias -> main`), not a branch of its own: it derives no event, its path finding stands, and the target's events are the target's own (decision 213). A last line without its newline is read, as git reads it; a `packed-refs` that ends without a newline is one git refuses, so a side git cannot parse (E10). A branch removed whose value before cannot be told derives no event (`git_branch_deleted` needs `was`), and `HEAD` that cannot be read on a side derives none. The record of a path git cannot read whose outcome is not `unknown` carries `content_unavailable`, and one `content_unavailable` event per reason names those paths (provisional when one of them is `unknown`). `paths`: every ref, `packed-refs` and `HEAD` path whose value the event uses, and a reflog only when its entries were used -- giving the value before or evidence of absence before, a rename, or how the branch moved (entries that lead from before to after but say not how are not used). The reflog is written by the watched process (diff-v1, git): the kinds that rest on it say so. (Decisions 126, 132: approved 2026-11-02, events from an `unknown` path provisional rather than dropped; 137: what cannot be read, and `paths`, worded -- refs are proof, the reflog is evidence; 141: a side not parsed, a removal not dated, HEAD not read; 144: a reflog parsed by the entries it gained; 160, 183: a reflog's unterminated last line no entry; 183: a ref's and HEAD's read, an unterminated packed-refs refused -- as git does; 202: the reflog lines git skips skipped and counted, refs read as git reads them; 213: ids lowercased, a symbolic loose branch an alias.) |
| E13 order, amended | By interpreter, in the order text, pip, dpkg, accounts, sudoers, cron, systemd, sshkeys, trust, config, git: this list supersedes E4's (system-interpreters.md SI-1). Within pip, dpkg and git, as E4 says. Within each of accounts, sudoers, cron, systemd, sshkeys, trust and config: by path (the first of the event's `paths`), then by the line's place in the file (a removed line's place before, an added line's after; an event of the file as a whole before every line's), removed before added, then by kind in finding-kinds.md's order. The same inputs give the same bytes. |
<!-- END GENERATED: diff-events -->

### Runtime

When either checkpoint has a runtime record (test/expect/runtime-v1.md: what is listening and
which services have processes), the diff has a `runtime` section after the event records and
before the trailer: `{"runtime": <kind>, <fields>, "text": ...}`, one a line. Runtime changes are
not events: they list no path.

| kind | fields | when |
|---|---|---|
| `incomplete` | `why`: any of `no_record_before`, `no_record_after`, `holders_unknown_before`, `holders_unknown_after` | First, when a side has no record (then nothing is compared) or did not read its listeners' holders (RT-D5). |
| `listener_opened`, `listener_closed` | the listener's line: `listener`, `proto`, `addr`, `port`, `client_range` (UDP, when true), `holders`; `matches` for one held by systemd alone | A listener on one side only, by `(listener, proto, addr, port)`; two sockets of one key are two (RT-D2). `matches`: the names of the after-manifest's `.socket` unit files whose `ListenStream=` (UDP: `ListenDatagram=`) is that port, alone or after a `:`, or a unix listener's path (RT-D4). |
| `service_started`, `service_stopped`, `service_restarted` | `service` (the cgroup's path), `processes`, `exe` | A service on one side only; on both with another start time (RT-D3). |

Listeners first, by key, a closed one before an opened one; then services, by `service`. The
text: `opened: tcp 0.0.0.0:80 held by nginx.service` -- `[::]:80` for IPv6, `unix <path>` for a
unix socket; each holder named by the last `.service` component of its cgroup, else its
executable's last component, `systemd` for `/init.scope`, sorted, each once; `(no process holds
it)` for `[]`; nothing when `holders` is `null` -- and `started: nginx.service`, `stopped: ...`,
`restarted: ...`. A consumer ignores a kind it does not know.

**Reading findings.** A consumer ignores a finding kind, an event kind or a field it does not
know. Removing a kind or changing a field's meaning is a new diff version.

### Kinds

<!-- BEGIN GENERATED: diff-findings -->
<!-- From src/schema/finding_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| kind | interpreter | level | fields | text | meaning |
|---|---|---|---|---|---|
| `could_not_interpret` | core | path, event | -- | `could not interpret` | The interpreter failed on this path (R11), nothing else from it here; or, as an event, on the paths it names (E6, E10). |
| `invalid_finding` | core | path, event | -- | `invalid finding` | A finding that broke the rules, replaced; or, as an event, an event that did (E9). |
| `and_more` | core | path, event | n: int | `and {n} more` | In the last place of a record past 4,096 findings, or of an interpreter's events past 65,536: the findings or events from that place on, counted. |
| `content_unavailable` | text, pip, dpkg, git | path, event | reason: string, side: string | `content unavailable ({side}): {reason}` | The stored copy of a claimed path, on a side where it exists, cannot be read: reason `no_store`, `missing`, `too_large` or `corrupt`; side `before`, `after` (or, for an event, `both`). Never a silent decline. |
| `text_changed` | text | path | lines_added: int, lines_deleted: int, first_changed_line: int | `+{lines_added} -{lines_deleted} lines, first change at line {first_changed_line}` | Stored on both sides: lines by the longest common subsequence of lines; the first line past the common prefix, 1-based, in before. |
| `text_rewritten` | text | path | lines_before: int, lines_after: int, first_changed_line: int | `rewritten: {lines_before} lines before, {lines_after} after, first change at line {first_changed_line}` | As text_changed, past 2,000 lines of edit distance: not counted. |
| `text_added` | text | path | lines: int | `{lines} lines` | Added, stored. |
| `text_removed` | text | path | lines: int | `{lines} lines` | Removed, stored before. |
| `pip_installed` | pip | event | name: string, version: string | `installed {name} {version}` | A dist-info whose RECORD is added, none removed of that name. |
| `pip_removed` | pip | event | name: string, version: string | `removed {name} {version}` | A dist-info whose RECORD is removed, none added of that name. |
| `pip_upgraded` | pip | event | name: string, from: string, to: string | `upgraded {name} {from} -> {to}` | One removed and one added of a name; to higher (PEP 440). |
| `pip_downgraded` | pip | event | name: string, from: string, to: string | `downgraded {name} {from} -> {to}` | The same; to lower. |
| `pip_version_changed` | pip | event | name: string, from: string, to: string | `{name} {from} -> {to}` | The same; equal by PEP 440, or not a PEP 440 version. |
| `pip_reinstalled` | pip | event | name: string, version: string, files_added: int?, files_removed: int?, files_changed: int? | `reinstalled {name} {version}: +{files_added} -{files_removed} ~{files_changed} files`; counts absent: `reinstalled {name} {version} (files not counted)` | The same dist-info on both sides, its RECORD changed; unknown on both sides, provisional and not counted. |
| `dpkg_installed` | dpkg | event | package: string, arch: string, version: string, auto: bool? | `installed {package}:{arch} {version}` | `installed` after and not before. auto: `true` when the after-manifest's `var/lib/apt/extended_states` has a stanza for this Package and Architecture with `Auto-Installed: 1`; `false` when it has none or it says `0`; absent when that file is not in the scope or cannot be read (SD-1). |
| `dpkg_removed` | dpkg | event | package: string, arch: string, version: string | `removed {package}:{arch} {version}` | `installed` before and not after. |
| `dpkg_upgraded` | dpkg | event | package: string, arch: string, from: string, to: string, auto: bool? | `upgraded {package}:{arch} {from} -> {to}` | `installed` on both sides; to higher (Debian version comparison). auto: `true` when the after-manifest's `var/lib/apt/extended_states` has a stanza for this Package and Architecture with `Auto-Installed: 1`; `false` when it has none or it says `0`; absent when that file is not in the scope or cannot be read (SD-1). |
| `dpkg_downgraded` | dpkg | event | package: string, arch: string, from: string, to: string, auto: bool? | `downgraded {package}:{arch} {from} -> {to}` | The same; to lower. auto: `true` when the after-manifest's `var/lib/apt/extended_states` has a stanza for this Package and Architecture with `Auto-Installed: 1`; `false` when it has none or it says `0`; absent when that file is not in the scope or cannot be read (SD-1). |
| `dpkg_state_changed` | dpkg | event | package: string, arch: string, from: string, to: string, auto: bool? | `{package}:{arch} {from} -> {to}` | The Status field differs, no installed or removed event covering it. auto: `true` when the after-manifest's `var/lib/apt/extended_states` has a stanza for this Package and Architecture with `Auto-Installed: 1`; `false` when it has none or it says `0`; absent when that file is not in the scope or cannot be read (SD-1). |
| `git_head_changed` | git | path | from: string, to: string | `HEAD {from} -> {to}` | `.git/HEAD`: the symbolic ref, or the commit it names. |
| `git_ref_created` | git | path | ref: string, to: string | `created {ref} at {to}` | A ref appeared. |
| `git_ref_deleted` | git | path | ref: string, from: string | `deleted {ref} (was {from})` | A ref went away. |
| `git_ref_moved` | git | path | ref: string, from: string, to: string | `{ref} {from} -> {to}` | A ref names another commit. |
| `git_hook_added` | git | path | hook: string, executable: bool?, target: bytes | `hook {hook} added` |  |
| `git_hook_removed` | git | path | hook: string, target: bytes | `hook {hook} removed` |  |
| `git_hook_changed` | git | path | hook: string, executable: bool?, target: bytes | `hook {hook} changed` | Its content changed. |
| `git_hook_executable_changed` | git | path | hook: string, executable: bool | `hook {hook} executable: {executable}` | Only its executable bit changed. |
| `git_index_changed` | git | path | -- | `index changed` | `.git/index` (hashed, never stored). |
| `git_reflog_appended` | git | path | ref: string, entries: int | `{ref}: {entries} reflog entries` | Entries appended to the ref's reflog. |
| `git_reflog_move` | git | path | ref: string, from: string, to: string, operation: string | `{ref} {from} -> {to} by {operation}` | An appended entry that is not a plain commit or a fast-forward. The reflog is written by the watched process: evidence, not proof. |
| `git_reflog_rewritten` | git | path | ref: string | `{ref}: reflog rewritten` | The reflog before is not a prefix of the reflog after. |
| `git_reflog_lines_ignored` | git | path | ref: string, lines: int | `{ref}: {lines} lines git ignores` | Lines the reflog gained in this diff that git does not read as entries: blank, or not in the form of one (diff-events E12). git skips them silently; the count is evidence worth showing. |
| `git_head_switched` | git | event | repo: string, from: string, to: string | `HEAD {from} -> {to}` | `HEAD` names another branch, or became or stopped being detached: from and to are the branch or, detached, the commit (diff-events E12). |
| `git_branch_created` | git | event | repo: string, branch: string, at: string | `branch {branch} created at {at}` | A branch absent before, by evidence (E12), exists after. |
| `git_branch_deleted` | git | event | repo: string, branch: string, was: string | `branch {branch} deleted (was {was})` | A branch that existed before exists no more (E12). |
| `git_branch_renamed` | git | event | repo: string, from: string, to: string, at: string | `branch {from} renamed to {to}` | In place of a deletion and a creation at the same commit, by the new branch's reflog. From the reflog: evidence, not proof. |
| `git_commits_added` | git | event | repo: string, branch: string, count: int?, to: string | `commits added to {branch}: {count}, now at {to}`; counts absent: `commits added to {branch}, now at {to}` | The branch moved forward by commits, fast-forwards or merges alone (E12); count, when every entry is one commit. From the reflog: evidence, not proof. |
| `git_history_rewritten` | git | event | repo: string, branch: string, how: string, from: string, to: string | `{branch} rewritten by {how}: {from} -> {to}` | A reset, an amend, a rebase or a forced update (E12). From the reflog: evidence, not proof. |
| `git_branch_moved` | git | event | repo: string, branch: string, from: string?, to: string | `{branch} {from} -> {to}`; counts absent: `{branch} now at {to}` | The branch names another commit, its reflog not saying how; from absent when its value before cannot be told (E12). |
| `user_added` | accounts | event | name: string, uid: int, gid: int, home: string, shell: string, uid_min: int/null | `user {name} added: uid {uid}, home {home}, shell {shell}` | A name in `passwd` after and not before (SA-1). uid_min: the `UID_MIN` of the `etc/login.defs` beside that `passwd` in the after-manifest, when it has exactly one `UID_MIN` line and its value is a decimal number; null otherwise -- not there, not kept, or not one number (SA-2, SI-4). |
| `user_removed` | accounts | event | name: string, uid: int | `user {name} removed (uid {uid})` | A name in `passwd` before and not after. |
| `user_changed` | accounts | event | name: string, field: string, from: string, to: string | `user {name}: {field} {from} -> {to}` | A name on both sides: one event per differing field of `uid`, `gid`, `gecos`, `home`, `shell`, in that order, the values as written. A second name with uid 0 is no kind of its own (SA-4). |
| `user_password_in_passwd` | accounts | event | name: string | `user {name}: a password is set in passwd itself` | The second field after is none of `x`, `*`, `!`, and not empty where the after-manifest has an `etc/shadow` beside that `passwd`; and the name is new, or its second field before was one of those or another value. The value is never copied. |
| `group_added` | accounts | event | name: string, gid: int | `group {name} added (gid {gid})` | A name in `group` after and not before; or (SI-3) a name on both sides whose second or third field differs: its line was removed and another added. |
| `group_removed` | accounts | event | name: string, gid: int | `group {name} removed (gid {gid})` | The reverse. |
| `group_members_changed` | accounts | event | name: string, added: list, removed: list | `group {name}: added {added}; removed {removed}` | A name on both sides whose fourth field differs as a set of names: those only after, those only before, each sorted bytewise. |
| `password_entry_added` | accounts | event | file: string, name: string | `password database: entry added for {name}` | A line of `shadow` or `gshadow` (`file`: its path), by its first field, whose keyed digest is in the after capture's per-line digests and not in the before's (SA-6). Only when both captures kept digests under one sealing key. |
| `password_entry_removed` | accounts | event | file: string, name: string | `password database: entry removed for {name}` | The reverse. |
| `password_entry_changed` | accounts | event | file: string, name: string | `password database: entry changed for {name}` | A first field on both sides whose line's keyed digest differs. No other part of the line is known to belay. |
| `sudo_rule_added` | sudoers | event | path: string, who: string, hosts: string, runas: string, tags: list, commands: string, line: string | `sudo rule added in {path}: {line}` | A logical line (SS-1) after and not before that is a user specification of the plain form (SS-2): `who`, `hosts`, `commands` the text between its marks, trimmed; `runas` the text inside `(...)`, empty when none is written; `tags` the `NAME:` words before the first command, without the colon; `line` the logical line, its physical lines joined, trimmed. Nothing is expanded, and nothing is said of what anyone may run (SS-5). |
| `sudo_rule_removed` | sudoers | event | path: string, who: string, hosts: string, runas: string, tags: list, commands: string, line: string | `sudo rule removed in {path}: {line}` | The reverse. |
| `sudo_line_added` | sudoers | event | path: string, line: string | `sudoers line added in {path}: {line}` | Any other logical line that is not a comment or blank: an alias, `Defaults`, `@include`, `@includedir`, `#include`, `#includedir`, and a user specification SS-2 does not cover. |
| `sudo_line_removed` | sudoers | event | path: string, line: string | `sudoers line removed in {path}: {line}` | The reverse. |
| `sudoers_file_not_read_by_sudo` | sudoers | event | path: string, why: string | `{path}: sudo does not read a file named like this ({why})` | A file directly in `etc/sudoers.d`, added or changed in this diff, whose name contains `.` (why: `a . in its name`) or ends `~` (why: `its name ends ~`) (SS-3). Its lines are events all the same. No rule from the mode (SS-4). |
| `cron_job_added` | cron | event | path: string, schedule: string, user: string, command: string, env: list, owner: string/null?, in_words: string? | `cron job added in {path}: {schedule} {user} {command}` | A job line (SC-1) after and not before: `schedule` its five fields joined by one space, or its `@word`; `user` the sixth field in `etc/crontab` and `etc/cron.d/*`, the file's name in `crontabs/*`; `command` the rest of the line as written; `env` the `SHELL`, `PATH`, `MAILTO`, `CRON_TZ` lines in force above it in its file, as written. in_words: only for the forms of SW-1 to SW-6, absent otherwise (SW-8). owner: the package that owns the file (SI-5); null: in no package; absent: no dpkg database in the after-manifest, or one that could not be read whole. |
| `cron_job_removed` | cron | event | path: string, schedule: string, user: string, command: string, env: list, owner: string/null?, in_words: string? | `cron job removed in {path}: {schedule} {user} {command}` | The reverse; `owner` by the after-manifest all the same. |
| `cron_env_changed` | cron | event | path: string, name: string, from: string, to: string | `{path}: {name} {from} -> {to}` | A `NAME=value` line added, removed or changed: a name with one such line on each side whose values differ is one event; otherwise one event per line added (from empty) and per line removed (to empty). |
| `cron_script_added` | cron | event | path: string, owner: string/null? | `{path} added` | A file directly in `etc/cron.hourly`, `cron.daily`, `cron.weekly` or `cron.monthly`; never read for meaning, and no schedule is claimed for it (SC-5). owner: the package that owns it (SI-5); null: in no package; absent: no dpkg database in the after-manifest, or one that could not be read whole. |
| `cron_script_removed` | cron | event | path: string, owner: string/null? | `{path} removed` | The same, removed. |
| `cron_script_changed` | cron | event | path: string, owner: string/null? | `{path} changed` | The same: its content, or its mode. |
| `cron_file_not_run` | cron | event | path: string, why: string | `{path}: cron does not run a file like this ({why})` | Only where the after-manifest's dpkg database has the package `cron` installed (SC-2). A file of `etc/cron.d` added or changed in this diff whose name has a character outside `A-Za-z0-9_-` (why: `name`) or that group or others may write (why: `mode`) (SC-3); a file of the four directories whose name has such a character (why: `name`) or that has no execute bit (why: `not executable`) (SC-4). |
| `unit_linked` | systemd | event | unit: string, into: string, target: string, owner: string/null? | `{unit} linked into {into}` | A symbolic link added in a directory named `<x>.wants` or `<x>.requires` under a directory systemd reads units from: `unit` the link's name, `into` `<x>`, `target` the link's text. Under a home's `.config/systemd/user`, `unit` is prefixed by that directory's path (SY-3a). Never `enabled` (SY-3). owner: the package that owns the file the link's text names, read from the link's directory (SI-5); null: in no package; absent: no dpkg database in the after-manifest, or one that could not be read whole. |
| `unit_unlinked` | systemd | event | unit: string, into: string, target: string, owner: string/null? | `{unit} unlinked from {into}` | The same, removed. |
| `unit_masked` | systemd | event | unit: string | `{unit} masked` | A unit name directly in `etc/systemd/system` or `etc/systemd/user` (or a home's `.config/systemd/user`) that became a symbolic link to `/dev/null` or an empty file. |
| `unit_unmasked` | systemd | event | unit: string | `{unit} unmasked` | One that stopped being that. |
| `unit_file_added` | systemd | event | path: string, owner: string/null? | `unit file {path} added` | A regular file with a unit suffix (`.service`, `.socket`, `.device`, `.mount`, `.automount`, `.swap`, `.target`, `.path`, `.timer`, `.slice`, `.scope`), or a file under a `<unit>.d` directory. An empty one in `etc/systemd` is `unit_masked` instead. owner: the package that owns it (SI-5); null: in no package; absent: no dpkg database in the after-manifest, or one that could not be read whole. |
| `unit_file_removed` | systemd | event | path: string, owner: string/null? | `unit file {path} removed` | The same, removed. |
| `unit_file_changed` | systemd | event | path: string, owner: string/null? | `unit file {path} changed` | The same, its content changed. |
| `unit_overrides_packaged` | systemd | event | unit: string, path: string, over: string | `{path} takes the place of {over}` | A unit file added under `etc/systemd/system` (or `etc/systemd/user`) while the after-manifest has one of that name under `usr/lib/systemd/system` (`.../user`), or under `lib/systemd/...`: `over` is that path. |
| `unit_alias_added` | systemd | event | alias: string, target: string | `{alias} is a link to {target}` | A symbolic link added directly in `etc/systemd/system` or `etc/systemd/user` (or a home's `.config/systemd/user`), not to `/dev/null`: `target` its text. |
| `unit_alias_removed` | systemd | event | alias: string, target: string | `{alias} is no longer a link to {target}` | The same, removed. |
| `init_script_added` | systemd | event | path: string, owner: string/null?, executable: bool | `init script {path} added` | `etc/rc.local` or a file directly in `etc/init.d`; never read for meaning. executable: whether any execute bit is set (SY-3b). owner: the package that owns it (SI-5); null: in no package; absent: no dpkg database in the after-manifest, or one that could not be read whole. |
| `init_script_removed` | systemd | event | path: string, owner: string/null?, executable: bool | `init script {path} removed` | The same, removed; executable: as it was. |
| `init_script_changed` | systemd | event | path: string, owner: string/null?, executable: bool | `init script {path} changed` | The same: its content, or its mode; executable: as it is after. |
| `timer_file_added` | systemd | event | path: string, on_calendar: list, owner: string/null?, in_words: string? | `timer {path} added: {on_calendar}` | A `.timer` unit file added (it is a `unit_file_added` too): `on_calendar` its `OnCalendar=` values as written, in order, or empty. in_words: SW-7, absent otherwise. A changed timer whose `OnCalendar=` values differ is one removed and one added (SI-3). owner: the package that owns it (SI-5); null: in no package; absent: no dpkg database in the after-manifest, or one that could not be read whole. |
| `timer_file_removed` | systemd | event | path: string, on_calendar: list, owner: string/null?, in_words: string? | `timer {path} removed: {on_calendar}` | The same, removed. |
| `ssh_key_added` | sshkeys | event | path: string, type: string, fingerprint: string, comment: string, options: list | `key added in {path}: {type} {fingerprint} {comment}` | A key line (SK-1) of an `authorized_keys` or `authorized_keys2` whose `(type, fingerprint)` is in the file after and not before, or whose options or comment differ (SI-3: one removed, one added). fingerprint: `SHA256:` and the unpadded base64 of the sha256 of the decoded key. options: as written, split at commas outside double quotes. The event names the file, not whose login it opens (SK-2). |
| `ssh_key_removed` | sshkeys | event | path: string, type: string, fingerprint: string, comment: string, options: list | `key removed in {path}: {type} {fingerprint} {comment}` | The reverse. |
| `ssh_ca_added` | sshkeys | event | path: string, type: string, fingerprint: string, comment: string, options: list | `certificate authority added in {path}: {type} {fingerprint} {comment}` | The same, for a key line whose options include `cert-authority`. |
| `ssh_ca_removed` | sshkeys | event | path: string, type: string, fingerprint: string, comment: string, options: list | `certificate authority removed in {path}: {type} {fingerprint} {comment}` | The reverse. |
| `trust_anchor_added` | trust | event | path: string, target: string, subject: string?, fingerprint: string?, owner: string/null? | `certificate added to the trust store: {subject} ({path})`; counts absent: `certificate added to the trust store: {path}` | A symbolic link or regular file added directly under `etc/ssl/certs` whose name ends `.pem` or `.crt`, the bundle `ca-certificates.crt` aside (TS-1). target: the path, relative to the scope, where the chain of links ends by the after-manifest (the path itself for a regular file; where the chain leaves what the manifest records, the last path it names). subject, fingerprint: from the PEM when the target's content is kept and holds exactly one certificate; `subject` as `openssl x509 -noout -subject` prints it after `subject=`, `fingerprint` the sha256 of the DER in uppercase hex pairs joined by `:`; else both absent (TS-2). Not validated. owner: the package that owns the target (SI-5); null: in no package; absent: no dpkg database in the after-manifest, or one that could not be read whole. |
| `trust_anchor_removed` | trust | event | path: string, target: string, subject: string?, fingerprint: string?, owner: string/null? | `certificate removed from the trust store: {subject} ({path})`; counts absent: `certificate removed from the trust store: {path}` | The same, removed: target, subject and fingerprint by the entries the diff was given and the after-manifest; absent where they cannot be told. |
| `config_key_added` | config | event | path: string, grammar: string, context: list, key: string, value: string | `{path}: {context} › {key} added: {value}` | A value of `key` in `context` that the file has after and not before, unless the key has one value there on each side (CF-2). grammar: `nginx`, `sshd`, `ini`, `keyvalue` or `namevalue`, by the file's path (system-config.md CF-N to CF-L). context: the enclosing block headers, outermost first, or the section name, as written; empty at the top level. key: as written; `sshd` keywords are compared without regard to ASCII case. value: the rest of the directive as written, each run of whitespace made one space (CF-1); of an opaque `nginx` block, whose key is its header, the sha256 of the text between its braces. The values of a key in a context are a set. A symbolic link is no file of its path: its target's file is keyed where it is. The text of one file, never the setting in force. |
| `config_key_removed` | config | event | path: string, grammar: string, context: list, key: string, value: string | `{path}: {context} › {key} removed: {value}` | The reverse. |
| `config_key_changed` | config | event | path: string, grammar: string, context: list, key: string, from: string, to: string | `{path}: {context} › {key} {from} -> {to}` | The key has exactly one value in that context on each side and they differ (CF-2); key as written after. A repeated key is never reported as changed. |
| `config_not_keyed` | config | event | path: string, grammar: string, why: string | `{path}: shown as lines ({why})` | The file's keys are not compared, on a side or both; the text interpreter's line findings stand (CF-6). why: `too large` (a side over 1 MiB or of more than 65,536 triples: CF-4), else `does not parse` (CF-4), else `a block header is not unique` (two blocks at one level, or two sections, with the same header text on a side: CF-3). |
<!-- END GENERATED: diff-findings -->

### What each interpreter reports

An interpreter adds findings only to a path whose content is proven changed (added, removed,
modified, type_changed): to a path whose outcome is `unknown` or `metadata_only` it adds none (a git
hook's executable bit excepted, which is metadata). pip, dpkg and git still derive events from an
`unknown` path, each marked provisional -- but none from a path `unknown` only as `not_captured`,
which no interpreter is given (E11). A side on which the path is not a regular file counts as
absent (git hooks excepted: a symlink is a hook). Where an interpreter keeps the first of two equal
keys (a package, a RECORD path, a packed ref), "first" is in file order. The limits: each
interpreter reads at most a bound of each stored copy, and a larger one is `content_unavailable`,
reason `too_large`; pip's, dpkg's and git's per-diff state is at most 64 MiB; a record carries at most
4,096 findings and an interpreter at most 65,536 events (and_more past either); a failed end hook
names at most 1,024 paths:

| interpreter | file | bound |
|---|---|---|
| text | the file | 16 MiB, and 1,048,576 lines |
| pip | RECORD | 16 MiB, and 262,144 rows |
| dpkg | `status` | 256 MiB |
| git | `HEAD`, a loose ref | 64 KiB |
| git | `packed-refs` | 64 MiB |
| git | a reflog | 16 MiB: a capture keeps a reflog up to this whatever `store_max_bytes` says, and a side recorded without a copy because it is larger is `content_unavailable`, reason `too_large` |
| pip, dpkg | per-diff state | 64 MiB (past it, the end hook fails) |

`missing` covers a path whose entry records no `stored` copy (a reflog over its 16 MiB bound
excepted: `too_large`) as well as a copy the store lacks, and
is given before `no_store` when both apply. A record's `content_unavailable` findings come before
side, then after; an interpreter's `content_unavailable` events come one per reason, in the order
`no_store`, `missing`, `too_large`, `corrupt`. A `bool` field renders in `text` as `true` or
`false`.

Three rules for a reflog over its bound, stated because independent authors had to infer them
(decided 2026-11-01): the reflog's `too_large` stands where `missing` would, so it too is given
before `no_store` when both apply; "over its 16 MiB bound" means a `size` strictly larger than
16,777,216 bytes (a reflog of exactly 16 MiB is kept and read); and a reflog entry that carries no
hash because it is larger than the capture's `hash_max_bytes` (`unverified`) is `too_large` by the
same `size` rule, like one recorded without a copy.

Where an interpreter fails on a path (a file it claims cannot be parsed, a dist-info cannot be
named), that path's record carries `could_not_interpret` (R11) unless its outcome is `unknown`,
nothing more is read from it (git: nothing more from the side that failed; the other side still
gives its value, E12), and pip, dpkg and git emit one `could_not_interpret` event naming it (E10);
their other events stand. An event a value of which is not a string field's value, or whose text
would exceed 1,024 bytes, is one `invalid_finding` event naming its paths (E9). Events with no name
-- `could_not_interpret` for a file, `content_unavailable` -- come before every named event, in the
Kinds table's order, then by path (`content_unavailable`, one per reason, in the reasons' order).
The end hook fails (E6) only when the interpreter's per-diff state would exceed 64 MiB, memory
runs out, or it adds an event naming no path: its events are then one `could_not_interpret` naming the first 1,024 paths given to it
(every path it claims whose outcome is not `unchanged`; none `unknown` only as `not_captured`, which
it is never given: E11) and counting the rest.

**text.** Stored on both sides: `text_changed`, counted from the longest common subsequence of
lines; when the two differ in more than 2,000 lines, `text_rewritten` gives the line counts only.
A line is the bytes up to and including a newline, or the bytes after the last newline. Added or
removed and stored on its one side: `text_added` / `text_removed`, its line count. Content that is
not text is still counted in lines.

**pip.** Only RECORD carries facts; METADATA is claimed so captures keep it. A dist-info directory's
name gives the distribution and its version, `{name}-{version}.dist-info`, split at its first `-`;
distributions are paired by the directory holding the dist-info and by their name normalized as PEP
503 does (ASCII lowercase, each run of `-`, `_`, `.` one `-`). For one such pair key: a RECORD added
with none removed is `pip_installed`; removed with none added, `pip_removed`; exactly one removed
and one added, `pip_upgraded` or `pip_downgraded` by PEP 440 ordering, or `pip_version_changed` when
the two are equal by it or either is not a PEP 440 version (as PEP 440's Appendix B expression
parses one: a separator may follow `a`, `post`, `dev` and the like with no number, `2a.` being
`2a0`). `name` is as the dist-info directory spells it; for a pair, the added one's. A RECORD
modified in place is `pip_reinstalled`: its rows (path, hash, size; UTF-8 text in Python's csv
dialect, so a RECORD that is not UTF-8, or a row of other than three fields, cannot be parsed)
compared by path, a path listed twice keeping its first row; `files_changed` counts the paths whose
hash or size differs. Only a reinstall reads content (both RECORDs); the others come from the paths
alone. A RECORD whose outcome is `unknown` pairs like any other, by its directory's name, and every
event it takes part in is provisional; one present on both sides is a provisional `pip_reinstalled`
whose rows are not compared: its three counts are absent, under the kind's second template. An event
lists the RECORD paths it was derived from. Event order: by normalized name (none first), then kind
(in the Kinds table's order), then directory, then the paths it lists. A dist-info that cannot be
named (no `-`, an empty name or version, or one that is not a string field's value), or a RECORD it
must read that cannot be parsed, is one `could_not_interpret` event naming that RECORD; one pair key
with RECORDs both added and removed other than exactly one of each (no kind says that) is one
`could_not_interpret` event naming them, in that name's place; their records carry nothing, as the
pairing is known only once every path record is written. Several added with none removed are each
`pip_installed`; several removed with none added, each `pip_removed`.

**dpkg.** From the `status` file before and after (an absent side lists no packages): a package is
keyed by `Package` and `Architecture` (empty when absent), the first stanza of a key kept, and is
installed when its `Status` field's third blank-separated word is `installed` (a stanza with no
`Version` has the empty version). A status in which `Package`, `Architecture`, `Version` or `Status`
is folded onto a continuation line cannot be parsed: Debian Policy 5.1 never folds those. Installed
after and not before: `dpkg_installed`, with the version after; the reverse, `dpkg_removed`, with
the version before; installed on both sides at versions that differ by Debian ordering (as `dpkg
--compare-versions`), `dpkg_upgraded` or `dpkg_downgraded`; and whenever `Status` differs and no
installed or removed event covers the package, `dpkg_state_changed` (an upgrade whose `Status` also
changed has both). A status whose outcome is `unknown` is read too, and every event from it is
provisional. An event lists the status path. Event order: by Package, then Architecture, then kind
(in the Kinds table's order), then path; the events with no name first. A status that cannot be
parsed is one `could_not_interpret` event naming it; an event a value of which is not a string
field's value (a NUL in a field, or one over 1,024 bytes: a field read may be any length) is one
`invalid_finding` event in its place, and a value no event carries changes nothing. The `info/`
files are claimed so captures keep them (the baseline M2's integrity check needs); they add no
findings.

**git.** No objects are read: refs, hooks, the index and the reflog only. A path is placed by the
part after its `.git/` (the last one that fits). `HEAD`: `git_head_changed`, from and to being the
symbolic ref's name or the object id (empty on a side where it is absent); nothing when the two are
equal. A loose ref or a line of `packed-refs` (in ref order): `git_ref_created`, `git_ref_deleted`,
`git_ref_moved` (only when the value differs), the ref being its full name (`refs/heads/main`).
`HEAD` and a loose ref are read as git reads them: without their last newline, and an object id of
either case followed by whitespace and anything at all is that id, written lowercased (decisions 202,
213); a loose branch that is symbolic is an alias of its target, as git lists it, and derives no
branch event of its own (decision 213); a `packed-refs` that
ends without a newline is refused, as git refuses it: `could_not_interpret` (decision 183). A
hook, from the manifest alone, is a regular file or a symlink -- git follows a symlinked hook, so it
is a working hook; a directory is none: added, removed, changed (its content, a link's target, or a
file becoming a link or back), or -- a file's content unchanged -- its executable bit (the owner's),
whatever else changed. `executable` is after's owner bit, for a file; it is absent for a symlink,
whose own mode says nothing about its target. `target` is the link's target, empty for a file, up to
4,095 bytes, and `target_b64` instead when it is not UTF-8: a planted hook is always reported. The
index: `git_index_changed` when it is added, removed or its content changed (hashed, never stored).
A reflog (`logs/HEAD` is ref `HEAD`, `logs/refs/...` is `refs/...`): when before's bytes are a
prefix of after's ending at a line's end (an absent before is empty), `git_reflog_appended` counts
the entries after it (a last line without its newline is none: git does not read it as an entry; nor is a blank line, which git skips) -- and says nothing when it gained none (decision 183) -- and
`git_reflog_lines_ignored` counts the lines after it that git skips as no entry, blank ones included,
and says nothing when there are none (decision 202: git skips them silently, and they are evidence
worth showing) -- and each of those that is not a plain commit (operation `commit` or `commit
(initial)`) or a fast-forward (its message contains `Fast-forward`) is a `git_reflog_move`, its
operation being the message before its first `:`; otherwise, or when the reflog was removed (no copy
needed), `git_reflog_rewritten`. **The reflog is written by the process being watched: it is
evidence, not proof.** A reflog's record gives `git_reflog_appended`, then its `git_reflog_move`s in
file order, then `git_reflog_lines_ignored`: the order of the kinds table. A process can write any reflog it likes; a capture taken from outside the
process (a host-reader mode, not built yet) would be the answer when that matters.

From its end hook git also derives repository-level events (diff-events E12), so that a reader
sees "branch x created", not the file git keeps it in. Per repository -- a directory named `.git`,
`repo` being its path in the scope -- and per branch (a ref `refs/heads/<branch>`, named without
`refs/heads/`): `git_branch_created`, `git_branch_deleted`, `git_branch_renamed`,
`git_commits_added`, `git_history_rewritten` or `git_branch_moved`, one for each branch whose
existence or commit differs, and `git_head_switched` when `HEAD` names another branch or detaches
or attaches. A branch's value on a side is its loose ref there; else its line in `packed-refs`
when `packed-refs` is a path of this diff; else, before only, the old id of the first entry its
reflog gained in this diff (all zeros: absent). git sees only the paths that changed, so an
unchanged `packed-refs` is never read: a branch is created only by evidence that it was absent
before, and a ref that appeared without that evidence is moved, with no `from`. The values are the
refs' own; the reflog only says how a branch moved (a reset, an amend, a rebase or a forced update
rewrites; commits, fast-forwards and merges add), and only when its entries of this diff lead from
the value before to the value after -- the kinds that rest on it say evidence, not proof. A path
whose outcome is `unknown` is read where its copy can be read, and every event from it is
provisional. Tags and remote-tracking refs derive no event.
