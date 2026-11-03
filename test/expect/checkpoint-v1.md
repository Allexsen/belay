# Pin: checkpoint.v1, the checkpoints `check`, `mark`, `diff` and `log` print

**What this is.** The JSON object `belay check --json`, `belay mark --json` and `belay log --json` print for a
checkpoint, one per line; `diff` keeps its capture to now as a checkpoint of kind `diff`, which `log` lists.
Published since v0.1.0-alpha as `schema/checkpoint.v1.json` and in `docs/cli.md`, but never pinned; pybelay's
`Checkpoint` makes it public API, so it is pinned before pybelay ships (decision 200). Every row below is what
the binary prints today (main at the time of this PR, run on Linux), except CK-16, which is proposed with it.
Written by hand; *proposed 2026-11-03, awaiting the author's OK*.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK. A key added, removed or
changed in meaning is a `checkpoint.v2`.

## Keys, in this order

| id | key | type | value |
|---|---|---|---|
| CK-1 | `id` | int, at least 1 | The checkpoint's number in its scope's state, as `--since` and `--to` take it. |
| CK-2 | `kind` | string | `check` (every file read), `mark` (a checkpoint after the latest, reading what may have changed), or `diff` (the capture `diff` made to now). |
| CK-3 | `created_ns` | int | When the checkpoint was made, nanoseconds since the epoch (the manifest's `created_ns`). |
| CK-4 | `scope` / `scope_b64` | string | The scope, as its manifest's `scopes` names it; `scope_b64` (base64) in its place when it is not UTF-8, never both. |
| CK-5 | `manifest` / `manifest_b64` | string | The manifest's path in belay's state directory; `manifest_b64` in its place when it is not UTF-8, never both. |
| CK-6 | `entries` | int, at least 1 | The manifest's entries (its trailer's `belay_manifest_end`): the scope root at least. |
| CK-7 | `raced` | int | Entries recorded `raced`: changed after they were recorded, before the walk ended. |
| CK-8 | `unstable` | int | Entries recorded `unstable`: changed while they were read. |
| CK-9 | `vanished` | int | Entries listed in their directory and gone when read. |
| CK-10 | `provisional` | bool | `true` exactly when any of `raced`, `unstable`, `vanished` is not 0: the tree changed while it was walked. |
| CK-11 | `excluded` | int | The paths the capture did not walk (the manifest's `excluded`). |
| CK-12 | `excluded_paths` | array of objects | Each `{"path" or "path_b64", "reason"}` of the manifest's `excluded`, in its order; `reason` `state_dir` or `user`. `[]` when none. |
| CK-13 | `prefilter` | object | How the walk read, keys in this order: `used` (bool: mark's shortcut was used), `reference` (`none`, `walk_start` or `newest_ctime`: the manifest trailer's `reference`), `trusted` (int: files whose hash came from the previous manifest), `racy` (int: files unchanged but at or past the reference point, read), `full_reason` (string: why every file was read, the trailer's `read_all`; `""` when the shortcut was used). |
| CK-14 | (none other) | -- | No other key, at any level. A reader that knows checkpoint.v1 rejects an unknown key. |
| CK-15 | (lines) | -- | `check` and `mark` print one line, `log` one per checkpoint, oldest first. Each line is one JSON object, keys in the order of this table, ending in `\n`. |
| CK-16 | `source` | null or object | **Proposed with this pin (M3):** the manifest's `source` (manifest-v3 V3-2) -- `null`, or `{"docker": ..., "image": ...}` for a container capture -- after `prefilter`. A v1 or v2 manifest's checkpoint gives `null`. Without it, a checkpoint of a container would not say which container it is. |

## Example

```
{"id":2,"kind":"mark","created_ns":1793706136308733845,"scope":"/home/u/proj","manifest":"/home/u/.local/state/belay/scopes/365c91f19b4085ae/checkpoints/2/manifest.ndjson","entries":3,"raced":0,"unstable":0,"vanished":0,"provisional":false,"excluded":0,"excluded_paths":[],"prefilter":{"used":true,"reference":"walk_start","trusted":1,"racy":0,"full_reason":""},"source":null}
```
