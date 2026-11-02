# belay manifest format, version 2

Status: the format belay writes from v0.1.0-alpha on. Pinned in `test/expect/manifest-v2.md`.

A version 2 manifest is a [version 1 manifest](manifest-v1.md) -- every rule of that document and
of its addendum (`test/expect/manifest-v1-addendum.md`), byte for byte: the canonical encoding,
the entries, their keys and checks -- with exactly the additions below. They carry in the
manifest what belay must say about how a capture walked (what it left out, how it read) and what
a later capture needs from an earlier one (when its walk began).

## The header

`"belay_manifest":2`, then version 1's header keys in their order, then these, always present:

<!-- BEGIN GENERATED: header-v2 -->
<!-- From src/schema/entry.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| field | kind | meaning |
|---|---|---|
| `excluded` | array | What inside the scope was not walked, one object each (below), sorted by path bytes; `[]` when nothing was. It has no entry, nor anything below it; its name still counts in its parent's listing. Nothing is ever excluded silently. |
| `walk_start_ns` | int | When the walk began, on the scope filesystem's clock (the ctime of a file the writer creates on the scope's device as the walk starts); `0` when that clock could not be read. A later capture's prefilter compares with it. |
<!-- END GENERATED: header-v2 -->

Each element of `excluded` is a flat object with these keys, in this order:

<!-- BEGIN GENERATED: excluded -->
<!-- From src/schema/entry.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| field | kind | meaning |
|---|---|---|
| `path` / `path_b64` | string | Relative to the scope, as entry paths are. |
| `reason` | string | `state_dir`: belay's own state directory; `user`: an exclude configured for the scope. |
| `dev` | int | The device of what was there. |
| `ino` | int | Its inode. |
<!-- END GENERATED: excluded -->

An excluded path is relative to the scope and canonical, as entry paths are (base64 as
`path_b64` when not UTF-8); the elements are sorted by path bytes, each path once. Nothing below
an excluded path is recorded. A path configured for exclusion that was not there is not listed:
nothing was hidden. A reader rejects a manifest that records an entry at or below one of its
excluded paths.

## The trailer

Version 1's trailer keys in their order, then these, always present:

<!-- BEGIN GENERATED: trailer-v2 -->
<!-- From src/schema/entry.c by tools/gen_schema.c. Edit there, then `make gen`. -->

| field | kind | meaning |
|---|---|---|
| `trusted` | int | Regular files whose hash and copy decision came from a previous manifest instead of a read (mark's prefilter); `0` for a full walk. |
| `reference` | string | What a trusted file's ctime was compared with: `walk_start` (the previous manifest's `walk_start_ns`), `newest_ctime` (its newest validated ctime, the start unknown), `none` (no previous manifest used). |
| `read_all` | string | Why every file was read: `check` for a full check, or the reason a capture with a previous manifest read everything; `""` when the prefilter was used. |
<!-- END GENERATED: trailer-v2 -->

The three agree, and a reader checks it: the prefilter was used exactly when `read_all` is `""`;
then `reference` is `walk_start` or `newest_ctime`; otherwise it is `none` and `trusted` is `0`.
`trusted` is at most the number of entries.

## Grammar

Version 2 adds two value forms to version 1's (manifest-v1.md, "Encoding"):

```
value  := ... | '[' ']' | '[' flat (',' flat)* ']'
flat   := '{' key ':' (string | integer) (',' key ':' (string | integer))* '}'
```

`[]` is an empty `excluded`; an array of flat objects is a non-empty one. Every version 1 field
that holds an array still requires a non-empty array of strings.

## Readers

- A reader that knows only version 1 rejects a version 2 manifest (version 1: a reader MUST
  reject a version it does not know).
- A reader that knows version 2 reads `1` and `2`, each by its own key set, strictly: a v2 line
  missing a v2 key, a v1 line carrying one, or any unknown key is rejected.
- How a diff treats a path one manifest excluded is diff-v1's first rule for a path present on
  one side only (diff-v1.md, "Present on one side only").
- Two manifests of different versions compare: diff.v1's records and outcomes do not depend on
  the version. The diff header names both (`before_manifest_version`, `after_manifest_version`),
  as provenance only.
- A version 1 manifest used as `mark`'s previous one has no `walk_start_ns`: the walk's start is
  unknown, and `mark` compares with the newest recorded ctime (docs/cli.md).
