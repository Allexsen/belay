# Pin: before and after values of changed fields (diff.v1)

**What this is.** A diff.v1 record names the compared fields that differ (`changed`); from this pin
it also carries their values on each side (decision 2026-10-31, Q5: "receipts and graders need
'mode 644 -> 4755', and diff.v1 is unpublished"). Written by hand for the author's approval.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## The rule

| id | rule |
|---|---|
| V1 shape | A record with `changed` also carries `"before": {...}` and `"after": {...}`, after `changed` and before `unknown`. Each holds, for every field `changed` names, in `changed`'s order, that side's value, under the key and in the encoding the manifest uses for it (manifest-v1, "Entries"). A record without `changed` carries neither. |
| V2 absent | A field that side's entry does not record (iflags not read, no caps, no xattrs) is absent from that side's object; the other side's value stands alone. Neither object is ever empty: a field in `changed` is recorded on at least one side. |
| V3 alternates | A value the manifest writes under an alternate key keeps it: `link_target_b64` for a target that is not UTF-8; `xattrs_sha256` for an xattr set recorded as its digest only. Each side chooses its own spelling. |
| V4 decides nothing | The values are carried, never compared again: the outcome and `changed` are decided as before (diff-fields.md). |
| V5 bounds | A record's line has no fixed bound: two link targets (4,095 bytes each, A4) and two inline xattr sets (8,192 bytes each, A1), escaped, can exceed 64 KiB. A consumer reads lines of any length. |

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

Example: `{"path":"bin/tool","outcome":"metadata_only","type":"reg","changed":["mode","ctime_ns"],"before":{"mode":33188,"ctime_ns":1761000000000000000},"after":{"mode":35309,"ctime_ns":1761000600000000000}}`
