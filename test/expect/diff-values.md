# Pin: before and after values of changed fields (diff.v1)

**What this is.** A diff.v1 record names the compared fields that differ (`changed`); from this pin
it also carries their values on each side (decision 2026-10-31, Q5: "receipts and graders need
'mode 644 -> 4755', and diff.v1 is unpublished"). Written by hand; approved by the author
2026-11-01 with V5 and V6 as they stand. The emitter does not carry the values yet: its
implementation follows, with the oracle's update by its own author.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## The rule

| id | rule |
|---|---|
| V1 shape | A record with `changed` also carries `"before": {...}` and `"after": {...}`, after `changed` and before `unknown`. Each holds, for every field `changed` names, in `changed`'s order, that side's value, under the key and in the encoding the manifest uses for it (manifest-v1, "Entries"). A record without `changed` carries neither. A record that carries `type_before` carries V6's values instead (V6). |
| V2 absent | A field that side's entry does not record (iflags not read, no caps, no xattrs, a symlink's target that could not be read) is absent from that side's object; the other side's value stands alone. A side's object is therefore `{}` when the only changed field is absent on that side (caps or an xattr set added or removed); the two are never both empty, since a field in `changed` is recorded on at least one side. (Corrected 2026-11-01: "neither object is ever empty" was false; an unreadable target is left out, not written as `""`, which reads as a genuinely empty target.) |
| V3 alternates | A value the manifest writes under an alternate key keeps it: `link_target_b64` for a target that is not UTF-8; `xattrs_sha256` for an xattr set recorded as its digest only. Each side chooses its own spelling. |
| V4 decides nothing | The values are carried, never compared again: the outcome and `changed` are decided as before (diff-fields.md). |
| V5 bounds | No line of diff.v1 has a fixed length bound -- a record's findings already make lines unbounded, and two link targets (4,095 bytes each, A4) and two inline xattr sets (8,192 bytes each, A1), escaped, exceed 64 KiB. Consumers MUST handle lines of any length (stated in diff-v1, "Shape"). (Decision 2026-11-01: no bound.) |
| V6 type change | A record that carries `type_before` -- every `type_changed` record, and an `unknown` one whose type also changed, as a raced swap does (decision 2026-11-01: "a file swapped for a symlink during the walk is exactly the race a tamperer creates, and the unknown outcome already says the values are unreliable") -- carries `"before"` and `"after"` (after `changed`, which is `["type"]` on every type change), each holding that side's `mode` and its type's content fields: `size` and `sha256` for `reg`, `link_target` (or `link_target_b64`) for `lnk`, `rdev` for `chr` and `blk`; `mode` alone for `dir`, `fifo` and `sock`. A field the side's entry does not record (a `sha256` not computed) is absent (V2). The values decide nothing (V4). (Decision 2026-11-01: a test file replaced by a symlink to a sensitive path is a tampering route, and the target is the fact that matters.) |

## The fields

| field | as the manifest writes it | note |
|---|---|---|
| mode | int, the whole `st_mode` | type bits included; a receipt shows the permission bits in octal (`0644 -> 4755`) |
| uid | int | |
| gid | int | |
| size | int | |
| mtime_ns | int | |
| ctime_ns | int | |
| ino | int | |
| dev | int, the raw number | `dev` is compared as a relation (diff-fields.md); the raw numbers are carried for the reader, not as the reason |
| nlink | int | |
| iflags | int | absent on a side that did not read them (V2) |
| caps | string, lowercase hex | absent on a side with none (V2) |
| xattrs | array of `name=sha256` strings | or `xattrs_sha256` on a side recorded as a digest (V3); absent on a side with none (V2) |
| sha256 | string, lowercase hex | |
| rdev | int | |
| link_target | string | or `link_target_b64` (V3) |

Examples:

`{"path":"bin/tool","outcome":"metadata_only","type":"reg","changed":["mode","ctime_ns"],"before":{"mode":33188,"ctime_ns":1761000000000000000},"after":{"mode":35309,"ctime_ns":1761000600000000000}}`

`{"path":"tests/test_auth.py","outcome":"type_changed","type":"lnk","type_before":"reg","changed":["type"],"before":{"mode":33188,"size":812,"sha256":"5d1c..."},"after":{"mode":41471,"link_target":"/etc/shadow"}}`
