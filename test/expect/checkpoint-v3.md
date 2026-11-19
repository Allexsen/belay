# Pin: checkpoint.v3, the checkpoints `check`, `mark`, `diff` and `log` print

**What this is.** checkpoint.v2 (`checkpoint-v2.md`) with the changes below, and the lines that say what a
capture could not read. Before it the binary (v0.1.0-alpha.9) was true but silent about content it never
read: measured as an unprivileged user on a mode-600 file and a mode-700 directory, 2026-11-18. A key added
is a new version (CK-14 rejects an unknown key). One bump carries what these lines need and what the system
watch will need, so there is not a second one. Written by hand; approved by the author, 2026-11-19.

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
| G2-1 | a `modified` or `metadata_only` record for a regular file whose content was not read on a side has no sign of it | The record gains `content_not_read` (`diff-fields.md`, O9): the reasons, in the order of the diff's own `unknown` array, from the flags of either side; `unverified` adds no reason on a side that also carries `unreadable`, `unstable` or `mount`. An unreadable file gives `["unreadable"]`. |
| G2-2 | `M shadow   size 530 -> 542, mtime_ns` | `M shadow   size 530 -> 542, mtime_ns; content not read (unreadable)` |
| G2-3 | | policy-v1 and the protect spec read `content_not_read` as they read an `unknown` reason: a protected path with it is `protected_path_unverifiable` (PS-M5), as well as whatever its fields prove (`policy-v1.md`, "Rows added"; `protect-spec-v2.md`, PV2-7). |
| G3-1 | `? secret   unknown: unreadable` | `? secret   unknown: unreadable, nothing below it was seen`. The same suffix for a mount root and for a directory at the depth limit (addendum A7). |
| G3-2 | | The diff trailer gains `before_sealing`, `after_sealing`, ints, after every key it has (`diff-fields.md`, "The trailer"). The receipt says so on a line of its own under its counts line, `  nothing seen below N directories` (`1 directory`), when the after count is not 0; the counts line itself is unchanged. |
| G3-3 | | `belay watch`'s `not read:` line is unchanged: it already names unreadable directories and mounts (`watch-v1.md`, no change). |
| G2-4 | a row whose record carries `content_not_read` folds as any change does | Such a row is never folded: not into the `git-ignored:` lines, not into `git bookkeeping:`, not past the 50-row cut. It is named on its own line, as `unknown` rows already are. Approved by the author, 2026-11-19. |
| G2-5 | `A newfile` | An `added` record of a regular file not read, or of a directory nothing was seen below, carries `content_not_read` (`diff-fields.md`, O10). The file's line: `A newfile   content not read (unreadable)`, the note placed as in G2-2 (after `; ` when the line says something else first). The directory's line is G3-4's. Neither folds (G2-4). Approved by the author, 2026-11-19. |
| G3-4 | the suffix is only on the `unknown: ...` line | Every receipt line that names a directory nothing was seen below says so. After `unknown: ...` it is G3-1's, with `, `. On a line that says something else first, after `; `: a privilege row is `? d   setgid added (mode 0755 -> 2000); nothing below it was seen`. On a line that says nothing else, after the path: an added directory is `A newdir   nothing below it was seen`. A git-ignored directory nothing was seen below is named on its own line, `? build/sealed   unknown: unreadable, nothing below it was seen`, and not counted into `git-ignored: N unknown under build/`. Approved by the author, 2026-11-19. |
| G3-5 | `T tofile   reg -> dir` for a path that became a directory nothing was seen below | Such a `type_changed` record carries `content_not_read` (`diff-fields.md`, O11), its line says so, `T tofile   reg -> dir; nothing below it was seen`, and it is never folded (G2-4). With it, every directory the trailer's `after_sealing` counts has a line that names it. Approved by the author, 2026-11-19. |

## How each was established

| row | how |
|---|---|
| G1-1 | measured as an unprivileged user on a mode-600 file and a mode-700 directory, 2026-11-18: `check` prints `5 entries`, exit 0, with both in the scope; the manifest's trailer has `"unreadable":2` |
| G2-1, G2-2 | measured, the same run: after the mode-600 file was rewritten the receipt had `M shadow   size 530 -> 542, mtime_ns`; read: `src/diff/classify.c` sets reasons only for outcome `unknown` |
| G2-3 | read and run: `src/policy/policy.c` takes PS-M5's reasons from the entry's flags whenever the outcome is not `unknown`, so a protected file rewritten and unreadable is `protected_path_written` and `protected_path_unverifiable` already |
| G3-1 | measured, the same run: a file added in the mode-700 directory changes nothing in the diff but the directory's own line |
| G2-4 | run on the branch before this row, as an unprivileged user in a git repository: four mode-000 files rewritten longer -- a git-ignored `.env`, a file under an ignored `build/`, an untracked file past the 50-row cut and a file under `.git/` -- each had `content_not_read` in `--json` and none was named in the receipt |
| G2-5 | run, the same way: a new mode-000 file gave `A newfile`, a new mode-000 directory `A newdir` |
| G3-4 | run, the same way: `chmod 2000` on a directory gave `? d   setgid added (mode 0755 -> 2000)`; a mode-000 `build/sealed` under an ignored `build/` gave `git-ignored: 1 unknown under build/ (unreadable 1)` |
| G3-5 | run on the branch before this row: a file replaced by a mode-000 directory gave `T tofile   reg -> dir` under `--all` and was folded without it, while the summary counted it (`nothing seen below 7 directories`, 5 rows carrying the suffix) |
| C3-8 | read: `log` prints from the stored checkpoint record (`src/cli/cli.c`), which has no such count before v3 |
