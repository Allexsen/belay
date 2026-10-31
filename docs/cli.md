# The belay command line

```
belay check --scope DIR [--json]
belay mark  --scope DIR [--full] [--full-every N] [--json]
belay diff  --scope DIR --since ID [--to ID] [--full-every N] [--json] [--exit-code] [--all]
belay log   --scope DIR [--json]
belay help [command]  |  belay <command> --help  |  belay --version
```

- **check** records `DIR` as a new checkpoint, reading every file (no prefilter) up to the hash
  limit: a file over 64 MiB is recorded `unverified`, without its hash.
- **mark** records a new checkpoint after the scope's latest one, reading only the files that may
  have changed (below).
- **diff** shows what changed from checkpoint `--since` to checkpoint `--to`, or to the directory as
  it is now -- that capture is kept as a new checkpoint, prefiltered as a mark is. Without `--json`
  it prints a receipt; with `--json`, the diff in [diff.v1](spec/diff-v1.md).
- **log** lists the scope's checkpoints: id, kind, time, number of entries.

belay only reads `DIR`. It writes only under its state directory: `$BELAY_STATE_DIR`, else
`$XDG_STATE_HOME/belay`, else `$HOME/.local/state/belay`.

A checkpoint id is a decimal number without a leading zero, at most 9 digits.

## Exit codes

| code | meaning |
|---|---|
| 0 | done -- for `diff`, whatever it found, unless `--exit-code` |
| 1 | `diff --exit-code`: some path is not unchanged (`unknown` counts) |
| 2 | usage: an unknown option or command, a missing or malformed argument, a checkpoint that does not exist |
| 3 | refused: the scope cannot be resolved, is not a directory, changed while it was resolved, or is the state directory or inside it; no state directory can be named; the state directory belongs to another user or others can write it |
| 4 | failed: an I/O error (writing the output included), corrupt state, out of memory |

An error is one line on standard error; `--json` output never carries one.

## The scope

`--scope` is resolved against the filesystem (`..`, `.` and symlinks included), and the result is
opened one component at a time without following symlinks (search permission on its parents is
enough). A component swapped for a symlink in between is refused (exit 3), never followed. The
capture resolves the path again and refuses it unless it is the same directory (device and inode)
-- exit 3. The resolved path is what the checkpoint records.

If belay's own state directory is inside the scope, it is not recorded, and every capture says so:
`check` and `mark` in their output (`"excluded"` in `--json`), `diff` after its receipt, or on
standard error with `--json`. A scope that is the state directory, or inside it, is refused.

## The state directory

```
<state>/scopes/<16 hex digits of the scope's sha256>/
    scope                       the scope's resolved path
    store/                      copies of small text files and of files an interpreter needs,
                                shared by every checkpoint of the scope
    checkpoints/<id>/manifest.ndjson
    checkpoints/<id>/diff-from-<since>.ndjson   what diff --since computed for this checkpoint
    checkpoints/<id>/meta.json  written last: a checkpoint exists once it does
    lock                        one writer at a time
```

The state directory must belong to the user belay runs as, and no one else may write it (exit 3
otherwise). Everything below it is opened without following symlinks; a symlink, FIFO or anything
else belay did not write there is corrupt state (exit 4), never followed or waited on. A capture
that finds another belay working on the same scope says so on standard error and waits for it.

Nothing in it is deleted by belay.

## mark: which files are read

A regular file is not read again, and keeps the previous checkpoint's hash, when its inode, mode,
size, modification time and change time (ctime) are all what the previous checkpoint recorded,
and its ctime is before a reference point: the time the previous checkpoint's walk began, on the
scope filesystem's clock (the ctime of a file belay creates in the state directory as the walk
starts). A file written after that point -- during that walk included -- gets a ctime at or past
it and is read. Whether a copy is kept is decided anew for every file, as a full capture would.

When the state directory is on another filesystem than the scope, that clock cannot be read; the
reference point is then the newest ctime the previous checkpoint recorded. On a filesystem with
coarse timestamps (1 or 2 seconds, or a kernel tick), a same-size rewrite made during the previous
walk, after the file was read and within the tick of its previous write, can then be missed if
another file changed later in that walk; keep the state directory on the scope's filesystem, or
use `check`, where that matters.

`mark` reads every file, and says why (`full_reason` under `prefilter` in `--json`), when there is
no checkpoint before; with `--full`; every `N` prefiltered captures -- marks, and `diff`'s captures
to now -- since the last full one (`--full-every N`, default 50; 0: never); when the newest ctime it
sees is older than the newest the previous checkpoint recorded (the clock went backwards: the walk
is done again in full); or when the previous checkpoint cannot be used -- unreadable, of another
scope, taken with other limits, or too large to index (64 MiB, about 85 bytes a file).

## The receipt

Events first (packages installed, upgraded, removed), then every privilege change -- capabilities,
inode flags, setuid, setgid or sticky bits, on a file changed, added or removed -- then the other
changes by path. A record shows at most 15 of its findings, then "and N more". An entry belay could
not capture reliably is named on its own line with the reason (`raced`, `unstable`, `unverified`,
...); entries that vanished while a walk ran are counted. Sections of more than 50 entries fold to
"and N more" (`--all` shows everything); privilege changes and unknown entries never fold.

Every path and text is printed escaped: control characters, bytes that are not UTF-8 and C1
controls as `\xNN`, a backslash as `\\`.

## --json

`check`, `mark` and `log` print checkpoints as JSON objects, one a line, described by
[schema/checkpoint.v1.json](../schema/checkpoint.v1.json). A path that is not UTF-8 is given in
base64 as `scope_b64` or `manifest_b64` in place of `scope` or `manifest`.
