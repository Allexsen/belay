# Pin: checkpoint.v3, the checkpoints `check`, `mark`, `diff` and `log` print

**What this is.** checkpoint.v2 (`checkpoint-v2.md`) with the changes below, and the lines that say what a
capture could not read. Before it the binary (v0.1.0-alpha.9) was true but silent about content it never
read: measured as an unprivileged user on a mode-600 file and a mode-700 directory, 2026-11-18. A key added
is a new version (CK-14 rejects an unknown key). One bump carries what these lines need and what the system
watch will need, so there is not a second one. Written by hand; approved by the author as drafted.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

| id | key | type | rule |
|---|---|---|---|
| C3-1 | every key of checkpoint.v2 | as v2 | As `checkpoint-v2.md` says, except as below. |
| C3-2 | `unreadable` | int | The manifest trailer's `unreadable`: entries whose content or listing could not be read. After `vanished`. |
| C3-3 | `sealing` | int | Entries nothing below which was looked at: directories carrying `unreadable`, `mount` or (v5) `not_read`. After `unreadable`. |
| C3-4 | `basis` | string | `walk` or `events` (kernel-record.md K7). Always `walk` until the recorder exists. After `prefilter`. |
| C3-5 | `carried` | int | Entries taken from the previous manifest without a stat; `0` for a walk. After `basis`. |
| C3-6 | `runtime_sha256` | string or null | The sha256 of the checkpoint's runtime record (runtime-v1.md), or null when it has none. After `kept`. |
| C3-6a | `journal_seq` | int or null | The kernel record's journal sequence number of this checkpoint's barrier; null when the checkpoint was not taken under a kernel record. After `runtime_sha256`. |
| C3-6b | `shadow_lines_sha256` | string or null | The sha256 of the checkpoint's per-line digest file for shadow/gshadow; null when it has none. Last. |
| C3-7 | | | `schema/checkpoint.v3.json` replaces v2's. pybelay follows in the same release: `Checkpoint` gains the seven fields; a v2 record read from an older state has `unreadable`, `sealing` as `None`, never `0`. |
| C3-8 | | | A checkpoint made before v3 stays as stored. `log` prints for it what it printed before: not recorded is not zero. belay does not read old manifests to fill the count in. |

## The lines

What `check`, `mark` and `log` print without `--json`, and the receipt `diff` prints (docs/cli.md).

| id | before | pinned |
|---|---|---|
| G1-1 | `check 1  <time>  5 entries` | `check 1  <time>  5 entries, 2 could not be read` when `unreadable` is not 0; nothing added when it is 0. The same on `mark` and in `log`. Exit status unchanged. |
| G1-2 | | When `sealing` is not 0 the line continues `, nothing seen below 1 directory` (plural: `directories`). |
| G3-1 | `? secret   unknown: unreadable` | `? secret   unknown: unreadable, nothing below it was seen`. The same suffix for a mount root and for a directory at the depth limit (addendum A7). |
| G3-2 | | The diff trailer gains `before_sealing`, `after_sealing`, ints, after every key it has (`diff-fields.md`, "The trailer"). The receipt's summary line says `nothing seen below N directories` when the after count is not 0. |
| G3-3 | | `belay watch`'s `not read:` line is unchanged: it already names unreadable directories and mounts (`watch-v1.md`, no change). |

## How each was established

| row | how |
|---|---|
| G1-1 | measured as an unprivileged user on a mode-600 file and a mode-700 directory, 2026-11-18: `check` prints `5 entries`, exit 0, with both in the scope; the manifest's trailer has `"unreadable":2` |
| G3-1 | measured, the same run: a file added in the mode-700 directory changes nothing in the diff but the directory's own line |
| C3-8 | read: `log` prints from the stored checkpoint record (`src/cli/cli.c`), which has no such count before v3 |
