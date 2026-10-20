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

Chosen over a binary format because it is streamable (a 100k-file manifest never needs a whole-file
parse), greppable while developing, and because the JSON writer is needed anyway for `--json` output
(§4.2 contract 2), so it is shared code rather than a second format.

**Line 1 is the header.** Every subsequent line is an entry.

## Header

```json
{"belay_manifest":1,"created_ns":1761000000000000000,"scopes":["/home/u/proj"],"hash":"sha256","hash_max_bytes":67108864,"store_max_bytes":65536}
```

| field | type | meaning |
|---|---|---|
| `belay_manifest` | int | format version. A reader MUST reject a version it does not know. |
| `created_ns` | int | wall clock at creation, nanoseconds since the epoch. Informational only — never used for comparison, per §6.3. |
| `scopes` | array | the normalized scope roots this manifest covers |
| `hash` | string | digest algorithm for the `sha256` field |
| `hash_max_bytes` | int | regular files larger than this are recorded without a hash (see `unverified`) |
| `store_max_bytes` | int | size threshold for copying content into `store/` |

## Entries

Sorted by **`path` bytewise ascending** (`memcmp` order, not locale collation). This lets `diff`
stream two manifests as a merge rather than building a hash map, so memory stays constant regardless
of tree size.

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
| `stored` | string | when content was copied | the `store/` key, which is the content's sha256 |
| `mount` | bool | `dir`, at a boundary | `true`. `dev` differs from the scope root's; belay recorded the mount point and did **not** descend (§5.1.1). |
| `unreadable` | bool | when enumeration or reading failed | `true`. belay could not read this entry: an unreadable directory, or a file it could not open. **For a directory, the entire subtree below it is ABSENT from the manifest.** `diff` MUST report such a subtree as *contents unknown* and never as *unchanged*. Without this field an unreadable directory is byte-identical to an empty one. |

Unknown fields MUST be ignored by a reader, so the format can grow.

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

- **xattrs and ACLs.** Noted as a gap; needed before belay can claim metadata completeness.
- **File content**, except copies under `store/` for files within `store_max_bytes` or claimed by an
  interpreter.
- **Anything below a mount boundary** inside a scope.
