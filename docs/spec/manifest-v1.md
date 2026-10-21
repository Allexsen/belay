# belay manifest format, version 1

Status: draft. Stable once M1 ships; `diff.v1` (the public diff schema) is a separate document.

A manifest is the record of what a scope looked like at one instant. `belay check` writes one;
`belay diff --since <id>` compares two.

## Location

```
$XDG_STATE_HOME/belay/checkpoints/<id>/
  manifest.ndjson     the manifest (this document)
  store/              content-addressed copies of stored files
```

`$XDG_STATE_HOME` defaults to `$HOME/.local/state`.

## Encoding

Newline-delimited JSON: one JSON object per line, no array wrapper, LF line endings.

**The encoding is canonical: every manifest state has exactly one byte representation**, and a
reader MUST reject anything else. Concretely, each line is exactly

```
line    := '{' pair (',' pair)* '}'      -- then LF; no whitespace anywhere
pair    := '"' [a-z0-9_]+ '"' ':' value
value   := string | integer | 'true' | '[' string (',' string)* ']'
string  := '"' ( byte >= 0x20 other than '"' and '\' | escape )* '"'
escape  := \" | \\ | \b | \f | \n | \r | \t | \u00XX
           (\u00XX only for a control byte with no short form, lowercase hex)
integer := '0' | '-'? [1-9][0-9]*
```

No line may exceed 64 KiB or contain a NUL byte. `false` and `null` never appear: a flag is absent
or exactly `true`.

Why canonical: a reader that tolerates a second spelling -- whitespace, a duplicated key, `"x":
true` with a space, bytes after an embedded NUL -- has a place where a flag can be hidden from it.
Independent review found such places in a reader that searched lines for keys; this grammar removes
them as a class.

Chosen over a binary format because it is streamable (a 100k-file manifest never needs a whole-file
parse), greppable while developing, and because the JSON writer is needed anyway for `--json` output
(§4.2 contract 2), so it is shared code rather than a second format.

**Line 1 is the header. The last line is the trailer. Every line between is an entry.** Blank lines
are not permitted anywhere.

## Header

```json
{"belay_manifest":1,"created_ns":1761000000000000000,"scopes":["/home/u/proj"],"hash":"sha256","hash_max_bytes":67108864,"store_max_bytes":65536}
```

| field | type | meaning |
|---|---|---|
| `belay_manifest` | int | format version. A reader MUST reject a version it does not know. |
| `created_ns` | int | wall clock at creation, nanoseconds since the epoch. Informational only — never used for comparison, per §6.3. |
| `scopes` | array | the resolved scope root, exactly one in this version. A scope that is not valid UTF-8 is written as `scopes_b64` (base64 elements) instead, never both. |
| `hash` | string | digest algorithm for the `sha256` field |
| `hash_max_bytes` | int | regular files larger than this are recorded without a hash (see `unverified`) |
| `store_max_bytes` | int | size threshold for copying content into `store/` |

## Entries

Sorted by **`path` bytewise ascending** (`memcmp` order, not locale collation), **strictly**: no
path appears twice. This lets `diff` stream two manifests as a merge rather than building a hash
map, so memory stays constant regardless of tree size. A reader MUST reject an entry that is not
strictly greater than the one before it; out-of-order or duplicated entries would otherwise be
mis-paired without any error.

**The scope root itself is an entry, with path `.`.** Without it, a change to the root's own mode or
owner is invisible.

```json
{"path":"src/main.c","type":"reg","mode":33188,"uid":1000,"gid":1000,"size":1234,"mtime_ns":1760...,"ctime_ns":1760...,"ino":8612,"dev":2096,"nlink":1,"sha256":"e3b0...","stored":"e3b0..."}
```

| field | type | present when | meaning |
|---|---|---|---|
| `path` | string | always, unless `path_b64` | path relative to its scope root, `/`-separated |
| `path_b64` | string | instead of `path` | base64 of the raw path bytes, when they are not valid UTF-8 |
| `type` | string | always | `reg` `dir` `lnk` `fifo` `sock` `blk` `chr` |
| `mode` | int | always | `st_mode`, full value including type bits |
| `uid`, `gid` | int | always | owner |
| `size` | int | always | `st_size`. For `lnk`, the target length. |
| `mtime_ns`, `ctime_ns` | int | always | nanosecond timestamps. **`ctime_ns` is the change prefilter**: an unprivileged process can set mtime but not ctime (§6.3). Never the sole evidence for a protected path — hash those. |
| `ino`, `dev` | int | always | identity. `dev` differing from the scope root's means a mount boundary. |
| `nlink` | int | always | link count. `> 1` on a regular file means hard links exist. |
| `sha256` | string | `reg`, size ≤ `hash_max_bytes` | lowercase hex content digest |
| `unverified` | bool | `reg`, size > `hash_max_bytes` | `true`. The file was too large to hash; `diff` must report any change to it as **modified (unverified)**, never as unchanged. |
| `link_target` | string | `lnk` | the link's bytes, verbatim and unresolved |
| `link_target_b64` | string | `lnk`, non-UTF-8 | base64 of the target bytes |
| `target_outside_scope` | bool | `lnk`, advisory | `true` when the target resolves lexically outside the scope. **Advisory only** — never drives a decision (§5.1.1). |
| `unstable` | bool | `reg` (with `unverified`) or `dir` | `true`. On a regular file: it changed while being read (size, mtime or ctime moved, or the inode opened was not the one stat'ed); no hash is recorded, because the bytes read describe no state the file ever had. On a directory: its listing changed between its stat and the end of its listing, so entries may be missing from it or recorded under another directory; the comparator MUST NOT read its children as a complete listing. |
| `rdev` | int | `blk` and `chr` only, required | the device number. Without it a replaced device node, or an overlayfs whiteout (char 0,0), is indistinguishable from the original. A reader MUST reject a device without `rdev` and `rdev` on anything else. |
| `stored` | string | when content was copied | the `store/` key, which is the content's sha256 |
| `mount` | bool | any type, at a boundary | `true`. The entry is the root of another mount: its `dev` differs from the scope root's, or (Linux) statx reports it as a mount root, which also catches bind mounts from the same filesystem. It is recorded and **never read or descended** (§5.1.1): a mounted regular file carries `unverified` and no hash. |
| `unreadable` | bool | when capture failed for this entry | `true`. belay could not capture this entry's contents: a directory it could not open or search (permission, or readable-but-not-searchable), a directory swapped for another between its stat and its open, a directory beyond the depth limit (128) or whose path leaves no room for a child name, a file it could not open or read, or a symlink that kept changing while being read. **For a directory, the entire subtree below it is ABSENT.** `diff` MUST report such a subtree as *contents unknown* and never as *unchanged*. Without this field an unreadable directory is byte-identical to an empty one. |

### Field rules a reader MUST enforce

In addition to the grammar above:

- **Types and fields agree.** A `reg` entry carries exactly one of `sha256` and `unverified`.
  No other type carries `sha256`, `unverified`, `unstable` or `stored`. `rdev` appears exactly on
  `blk` and `chr`; `link_target` (or `link_target_b64`) exactly on `lnk`; `target_outside_scope`
  only on `lnk`. A `mount` entry carries no `sha256`.
- **`mode`'s type bits match `type`** (`S_IFMT`; the values are the same on Linux and macOS).
- **A symlink's `size` equals its target's length.** The writer re-stats the link after reading it
  to guarantee they belong together.
- **`path` is used only for valid UTF-8 and `path_b64` only for anything else** (likewise
  `link_target`/`link_target_b64`), so a path has one encoding.
- **The scope root `.` is present**, exactly once, and is a directory.
- **Nothing appears below a directory marked `unreadable` or `mount`.**

- **No key appears twice** in one line. "First wins" would let two different lines mean the same
  thing.
- **Boolean flags are spelled exactly `"key":true`.** Any other value under a flag's key (`: true`,
  `false`, `1`, `"true"`) is an error, never "flag absent". A flag that silently reads as absent is
  the failure this format exists to prevent: an unreadable directory would read as an empty one.
- **`unstable` implies `unverified`**, and `sha256` excludes both.

### Growing the format

Unknown fields are ignored by a reader, so the format can grow -- **but only by informational
fields.** Any new field whose absence an older reader would misread as "nothing changed" (as
`unreadable`, `unstable` and `rdev` would have been) MUST come with a version bump, which older
readers refuse. `unreadable`, `unstable` and `rdev` are part of version 1 because version 1 has not
shipped.

## Trailer

```json
{"belay_manifest_end":12345,"vanished":0,"unreadable":2,"unstable":0}
```

| field | meaning |
|---|---|
| `belay_manifest_end` | number of entries, including `.` |
| `vanished` | entries that disappeared between being listed and being read. Non-zero means the tree was changing during the walk, so the manifest is not a single instant. |
| `unreadable` | entries carrying `unreadable` |
| `unstable` | entries carrying `unstable` (files and directories) |

The trailer is **required** and must be the **last line**. A reader MUST reject a manifest with no
trailer, a trailer whose counts disagree with the entries read, or anything after the trailer.
Without it, a manifest cut off at a line boundary by a crash or a full disk is indistinguishable
from a complete one with fewer entries, and its missing tail would read as deletions. The writer
also writes to a temporary name and renames into place.

## Obligations on a consumer (the comparator, step 3.1)

Each rule below closes a way for a state the format records to be rendered as "no change":

- **Refuse to compare manifests of different scopes.** Relative paths from different roots line up
  by name: two unrelated projects with the same layout would otherwise compare as unchanged
  (measured).
- **`unreadable` means "contents unknown"**, never "empty" and never "unchanged".
- **`unverified` (including `unstable`) never reports "unchanged" on content alone.** With identical
  metadata the honest label is "unchanged (unverified)"; on a protected path it is a failure to
  verify, not a pass.
- **A `ctime_ns` change with every recorded field equal means "changed: unrecorded attribute"**,
  never "unchanged". Extended attributes, ACLs, file capabilities and inode flags are not recorded
  (see below) but do change ctime. This turns their absence into a visible, if unspecific, change.
- **Compare under the same `hash_max_bytes`**, or report entries hashed on one side and unverified
  on the other as unverified rather than changed.

## Path encoding

POSIX paths are **bytes**, not text. They may contain anything except `/` and NUL.

- Valid UTF-8 → `path`, as a JSON string.
- Not valid UTF-8 → `path_b64`, base64 of the raw bytes. An entry has exactly one of the two.
- **A path containing a NUL byte is a hard error** (`BELAY_ERR_CORRUPT`) on read, never a truncation
  (§5.1.1). The lexical path functions take NUL-terminated strings and cannot detect an interior
  NUL; the reader holds a length, so the check belongs there.

Sorting is on the **raw path bytes** either way, so an entry's encoding does not affect its position.

**Entry paths are relative to the scope root and must stay inside it.** A reader MUST reject an
absolute path and any path containing a `..` component. M1 only reads, but the moment anything
restores from a manifest an accepted `../../etc/passwd` is an arbitrary write. This is the same
hidden-traversal risk the NUL rule above exists to prevent.

## What is deliberately not recorded

- **Extended attributes, ACLs, file capabilities (`security.capability`) and inode flags**
  (`chattr +i`, BSD `chflags`). A change to any of them alters only `ctime_ns` -- measured with a
  `user.*` xattr. This is a known gap and is open for decision; until it closes, the ctime rule above
  is what keeps such a change from rendering as "unchanged". `security.capability` matters most for
  the RL use case, since `setcap` on an interpreter is a privilege change.
- **File content**, except copies under `store/` for files within `store_max_bytes` or claimed by an
  interpreter.
- **Anything below a mount boundary** inside a scope.
