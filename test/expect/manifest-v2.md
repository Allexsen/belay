# Pin: manifest version 2

**What this is.** Version 2 of the manifest format (decision 2026-11-01, #25: "a manifest v2, not a
relaxed v1 ... the strict reader is the founding principle, and exercising the version bump now,
before any user exists, is cheap"). A v2 manifest is a v1 manifest -- `manifest-v1.md` and its
addendum (A1-A8), which stay immutable -- with exactly the changes below. Everything not listed
here is as v1 says, byte for byte: the canonical encoding, the entries, their keys and rules.
v2 carries in the manifest what decisions Q6 and Q8 (2026-10-31) require belay to say, which v1
cannot hold, and what a later capture needs from an earlier one. Written by hand for the
author's approval.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK. Rules added
to v2 later go in `manifest-v2-addendum.md`, append-only, as v1's do.

## Lines

| id | line | key | type | value | when |
|---|---|---|---|---|---|
| V2-1 | header | `belay_manifest` | int | `2` | always |
| V2-2 | header | `excluded` | array of objects | each `{"path": string, "dev": int, "ino": int}` (`path_b64` in place of `path` when not UTF-8, as for entries), sorted by path bytes: a directory inside the scope that was not walked because it is belay's own state directory (Q6). It has no entry; its name still counts in its parent's listing. `[]` when none | always (empty included: never silent) |
| V2-3 | header | `walk_start_ns` | int | when the walk began, on the scope filesystem's clock (the ctime of a file the writer creates on the scope's device as the walk starts); `0` when that clock could not be read (the output is on another filesystem) | always |
| V2-4 | trailer | `trusted` | int | regular files whose hash and copy decision came from a previous manifest, not from reading them (mark's prefilter); `0` for a full walk | always |
| V2-5 | trailer | `reference` | string | what a trusted file's ctime was compared with: `walk_start` (the previous manifest's `walk_start_ns`), `newest_ctime` (its newest validated ctime, when the start was unknown), `none` (no previous manifest used) | always |
| V2-6 | trailer | `read_all` | string | why every file was read: `check`, `no checkpoint before`, `asked for (--full)`, `every N marks`, `ctime went backwards: newest N below the previous M`, `the previous walk's start is unknown and the scope's timestamps are coarse`, or why the previous manifest could not be used; `""` when the prefilter was used (Q8: said in the trailer) | always |

Key order within each line: v1's keys in v1's order, then the new keys in the order of this
table. No key is optional: a reader can tell "not said" from "nothing to say".

## Readers and writers

| id | rule |
|---|---|
| V2-R1 | A reader that knows only v1 rejects a v2 manifest, loudly (v1: an unknown `belay_manifest` value is rejected). |
| V2-R2 | A reader that knows v2 accepts `1` and `2`, each by its own key set, strictly: a v2 line missing a v2 key, or a v1 line carrying one, is rejected, as is any unknown key. |
| V2-R3 | belay writes v2 only, from the first release on. A v1 manifest already written stays valid and readable. |
| V2-R4 | Two manifests of different versions compare: diff.v1 records and outcomes do not depend on the version (the entries are v1's). The diff header does not name the versions. |
| V2-R5 | A v1 manifest used as mark's previous: its `walk_start_ns` is taken as `0` (unknown), so the newest-ctime reference applies, with its coarse-timestamp rule. |
| V2-R6 | The values of V2-4..6 decide nothing in a diff; they are the capture's statements about itself. |

## Example

```
{"belay_manifest":2,"created_ns":1762000000000000000,"scopes":["/home/u/proj"],"hash":"sha256","hash_max_bytes":67108864,"store_max_bytes":65536,"excluded":[{"path":".belay-state","dev":2049,"ino":131077}],"walk_start_ns":1761999999990000000}
...entries, as v1...
{"belay_manifest_end":1840,"vanished":0,"unreadable":0,"unstable":0,"mounts":0,"raced":0,"trusted":1802,"reference":"walk_start","read_all":""}
```
