# diff.v1

Status: draft (Phase 3). Defined in `src/schema/diff_schema.c`; the tables below are generated from
it (`make gen`, checked in CI by `make gen-check`).

A diff compares two manifests of the **same scope** (`manifest-v1.md`) and gives every path one
outcome. It is produced as a stream, in bounded memory however many entries the manifests hold:
the two sorted manifests are merged, one path at a time, and each record is written as soon as it
is decided.

## Shape

NDJSON, like the manifest: one header line, one record per path whose outcome is not `unchanged`,
in the manifests' path order (bytewise), then the event records (see "Interpreters"), and a
trailer line. Readers MUST reject a version they do not know, and treat a missing trailer as a
truncated diff.

```json
{"belay_diff":1,"scopes":["/home/u/proj"],"before_created_ns":1761000000000000000,"after_created_ns":1761000600000000000,"before_hash_max_bytes":67108864,"after_hash_max_bytes":67108864,"scope_remounted":false,"identity_compared":true}
{"path":"src/main.c","outcome":"modified","type":"reg","changed":["size","mtime_ns","sha256"]}
{"path":"build","outcome":"unknown","type":"dir","unknown":["unstable"]}
{"belay_diff_end":2,"unchanged":1840,"added":0,"removed":0,"modified":1,"type_changed":0,"metadata_only":0,"unknown":1,"dir_timestamps_only":0,"events":0,"before_vanished":0,"before_unstable":0,"before_raced":0,"after_vanished":0,"after_unstable":1,"after_raced":0,"provisional":true,"before_sha256":"9f2c...","after_sha256":"41ab..."}
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
| `unknown` | array | For `unknown` only: the reasons, in the order of the reasons table. |
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
obligations on a consumer), and a `vanished` path has no record that could say so. Last,
`before_sha256` and `after_sha256` are the sha256 of each manifest file's bytes, all of them, as
this diff read them; a reader accepts nothing after a manifest's trailer, so that is the whole
file.

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
outcome -- `type_changed`, or `unknown` when `raced` is on either side.

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
one-sided case, its one reason.

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
<!-- END GENERATED: diff-fields -->

## Interpreters

For a path that is not `unchanged`, the interpreter that claims it adds **findings** to its record:
what the change means (a package upgraded, a ref moved, lines changed). Findings are annotations
only. An interpreter receives the core's verdict read-only and has no way to set or change an
outcome, so whatever an interpreter says or fails to say, every record's outcome is the one the
rules above decide.

**Which interpreter.** A path is claimed by its absolute path (scope + path): dpkg claims
`*/var/lib/dpkg/status` and the per-package `info/*.list` and `info/*.md5sums`; pip claims
`*.dist-info/RECORD` and `*.dist-info/METADATA`; git claims `*/.git/HEAD`, `*/.git/packed-refs`,
`*/.git/refs/*`, `*/.git/hooks/*`, `*/.git/index` and the reflogs `*/.git/logs/HEAD` and
`*/.git/logs/refs/*`. An unclaimed path is **text** when its entry is `stored` on every side it
exists on (a capture stores small text files by default); any other is **binary**, which adds
nothing: its size and hash are already in the record.

**Content.** Interpreters read the stored copies through the store given to the diff (`belay_diff`'s
options). Every copy read is hashed and must match its name, so a stale, planted or truncated copy
is never read as content. When an interpreter needs a copy it cannot read, on a side where the path
exists, it says so: the finding `content_unavailable`, with `reason` `no_store` (the diff was given
no store), `missing`, `too_large` (over the interpreter's bound) or `corrupt` (does not hash to its
name), and `side`. It never declines silently there: pip and dpkg, whose package facts come from
that content, also emit a `content_unavailable` event naming the paths, so a consumer never reads
"no packages changed" where the change could not be read.

**Findings.** Each finding is an object: `{"kind": ..., <its fields, in order>, "text": ...}`.
`int` fields are non-negative integers, `string` fields UTF-8 of at most 1,024 bytes, `bool` fields
`true` or `false`; `text` is the kind's template with each `{field}` replaced by its value, at most
1,024 bytes. The core checks every finding against its kind's row below and renders its text, so
an interpreter supplies values, never text: a finding that breaks the row (an unknown kind, a kind
of another interpreter or level, a field missing, extra or over its bound) is replaced by
`invalid_finding`. An interpreter that fails on a path has its findings there replaced by
`could_not_interpret`; the diff does not fail. A record carries at most 4,096 findings: past that,
the last place is one `and_more` counting the rest.

**Event records.** A fact about a package rather than a path -- installed, removed, upgraded,
reinstalled -- is an event record, emitted once every path has been seen, listing the paths it was
derived from. Every path an event lists has its own record, or is unchanged. At most 65,536 event
records per interpreter: past that, the last place is one `and_more` counting the rest.

<!-- BEGIN GENERATED: diff-events -->
<!-- From src/schema/finding_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| rule | statement |
|---|---|
| E1 placement | Event records come after the last path record and before the trailer. A diff with none has none. |
| E2 shape | `{"event": "<kind>", "interp": "<interpreter>", <the kind's fields, in finding-kinds.md's order>, "text": "<its template>", "paths": [...]}`. The kind is an `event`-level kind of finding-kinds.md, or `and_more`. |
| E3 paths | The paths it was derived from, relative to the scope as in path records, sorted bytewise, each once, at least one (except `and_more`). `paths_b64` instead -- every element base64 -- when any is not valid UTF-8. |
| E4 order | By interpreter, in the order text, pip, dpkg, git; within one, as the interpreter defines it in finding-kinds.md's terms: pip by normalized name, then kind; dpkg by Package, then Architecture, then kind. The same inputs give the same bytes. |
| E5 bound | At most 65,536 event records per interpreter per diff; past that, one final `{"event": "and_more", "interp": ..., "n": <the rest>, "text": "and {n} more", "paths": []}`. An interpreter's per-diff state is bounded to match. |
| E6 failure | An interpreter that fails in its end hook emits `{"event": "could_not_interpret", "interp": ..., "text": "could not interpret", "paths": [...]}` with the paths it had claimed, and no other event. The diff does not fail. |
| E7 trailer | The trailer gains `events`: the number of event records. `belay_diff_end` still counts path records only. |
| E8 forward | A consumer ignores an event kind it does not know, as it ignores an unknown finding kind or field. |
<!-- END GENERATED: diff-events -->

**Reading findings.** A consumer ignores a finding kind, an event kind or a field it does not
know. Removing a kind or changing a field's meaning is a new diff version.

### Kinds

<!-- BEGIN GENERATED: diff-findings -->
<!-- From src/schema/finding_schema.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| kind | interpreter | level | fields | text | meaning |
|---|---|---|---|---|---|
| `could_not_interpret` | any | path | -- | `could not interpret` | The interpreter failed on this path (R11); nothing else from it here. |
| `invalid_finding` | any | path | -- | `invalid finding` | A finding that broke the rules, replaced. |
| `and_more` | any | path | n: int | `and {n} more` | The findings past the 4,096th of a record, or the events past the 65,536th of an interpreter, counted. |
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
| `pip_reinstalled` | pip | event | name: string, version: string, files_added: int, files_removed: int, files_changed: int | `reinstalled {name} {version}: +{files_added} -{files_removed} ~{files_changed} files` | The same dist-info on both sides, its RECORD changed. |
| `dpkg_installed` | dpkg | event | package: string, arch: string, version: string | `installed {package}:{arch} {version}` | `installed` after and not before. |
| `dpkg_removed` | dpkg | event | package: string, arch: string, version: string | `removed {package}:{arch} {version}` | `installed` before and not after. |
| `dpkg_upgraded` | dpkg | event | package: string, arch: string, from: string, to: string | `upgraded {package}:{arch} {from} -> {to}` | `installed` on both sides; to higher (Debian version comparison). |
| `dpkg_downgraded` | dpkg | event | package: string, arch: string, from: string, to: string | `downgraded {package}:{arch} {from} -> {to}` | The same; to lower. |
| `dpkg_state_changed` | dpkg | event | package: string, arch: string, from: string, to: string | `{package}:{arch} {from} -> {to}` | The Status field differs, no installed or removed event covering it. |
| `git_head_changed` | git | path | from: string, to: string | `HEAD {from} -> {to}` | `.git/HEAD`: the symbolic ref, or the commit it names. |
| `git_ref_created` | git | path | ref: string, to: string | `created {ref} at {to}` | A ref appeared. |
| `git_ref_deleted` | git | path | ref: string, from: string | `deleted {ref} (was {from})` | A ref went away. |
| `git_ref_moved` | git | path | ref: string, from: string, to: string | `{ref} {from} -> {to}` | A ref names another commit. |
| `git_hook_added` | git | path | hook: string, executable: bool | `hook {hook} added` |  |
| `git_hook_removed` | git | path | hook: string | `hook {hook} removed` |  |
| `git_hook_changed` | git | path | hook: string, executable: bool | `hook {hook} changed` | Its content changed. |
| `git_hook_executable_changed` | git | path | hook: string, executable: bool | `hook {hook} executable: {executable}` | Only its executable bit changed. |
| `git_index_changed` | git | path | -- | `index changed` | `.git/index` (hashed, never stored). |
| `git_reflog_appended` | git | path | ref: string, entries: int | `{ref}: {entries} reflog entries` | Entries appended to the ref's reflog. |
| `git_reflog_move` | git | path | ref: string, from: string, to: string, operation: string | `{ref} {from} -> {to} by {operation}` | An appended entry that is not a plain commit or a fast-forward. The reflog is written by the watched process: evidence, not proof. |
| `git_reflog_rewritten` | git | path | ref: string | `{ref}: reflog rewritten` | The reflog before is not a prefix of the reflog after. |
<!-- END GENERATED: diff-findings -->

### What each interpreter reports

**text.** Stored on both sides: `text_changed`, counted from the longest common subsequence of
lines; when the two differ in more than 2,000 lines, `text_rewritten` gives the line counts only.
A line is the bytes up to and including a newline, or the bytes after the last newline. Added or
removed and stored on its one side: `text_added` / `text_removed`, its line count. Content that is
not text is still counted in lines.

**pip.** A dist-info directory's name gives the distribution and its version
(`{name}-{version}.dist-info`); distributions are paired by their directory (the site-packages they
are in) and their name normalized as PEP 503 does (lowercase, runs of `-`, `_`, `.` as one `-`). A
RECORD added with none removed of the same name is `pip_installed`; removed with none added,
`pip_removed`; one removed and one added, `pip_upgraded`, `pip_downgraded` (PEP 440 ordering) or
`pip_version_changed` (equal by PEP 440, or not PEP 440 versions). The same dist-info on both sides
with its RECORD changed is `pip_reinstalled`, with RECORD's rows compared by path (that one needs
both RECORDs' content). Event order: by normalized name, then kind.

**dpkg.** From the `status` file before and after: a package is keyed by `Package` and
`Architecture`, and is installed when its `Status` field's third word is `installed`. Installed
after and not before: `dpkg_installed`; the reverse, `dpkg_removed`; installed on both sides at
another version, `dpkg_upgraded` or `dpkg_downgraded` (Debian version ordering, as
`dpkg --compare-versions`); any other change to `Status`, `dpkg_state_changed`. Event order: by
Package, then Architecture, then kind. The `info/` files are claimed so captures keep them (the
baseline M2's integrity check needs); they add no findings.

**git.** No objects are read: refs, hooks, the index and the reflog only. `HEAD`: `git_head_changed`.
A loose ref or a line of `packed-refs`: `git_ref_created`, `git_ref_deleted`, `git_ref_moved`. A
hook: added, removed, changed (its hash), or only its executable bit. The index: changed (hashed,
never stored). A reflog (`logs/HEAD`, `logs/refs/...`): the entries appended, and each appended
entry that is not a plain commit or a fast-forward as `git_reflog_move`, with git's own operation
(reset, commit (amend), rebase, checkout, ...); a reflog whose earlier entries were removed or
altered is `git_reflog_rewritten`. **The reflog is written by the process being watched: it is
evidence, not proof.** A process can write any reflog it likes; a capture taken from outside the
process (host-reader mode) is the answer when that matters.
