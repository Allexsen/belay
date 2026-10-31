# The belay command line

```
belay check --scope DIR [--json]
belay mark  --scope DIR [--full] [--full-every N] [--json]
belay diff  --scope DIR --since ID [--to ID] [--json] [--exit-code] [--all]
belay log   --scope DIR [--json]
belay help [command]  |  belay <command> --help  |  belay --version
```

- **check** records `DIR` as a new checkpoint, reading every file.
- **mark** records a new checkpoint after the scope's latest one, reading only the files that may
  have changed (below).
- **diff** shows what changed from checkpoint `--since` to checkpoint `--to`, or to the directory as
  it is now -- that capture is kept as a new checkpoint. Without `--json` it prints a receipt;
  with `--json`, the diff in [diff.v1](spec/diff-v1.md).
- **log** lists the scope's checkpoints: id, kind, time, number of entries.

belay only reads `DIR`. It writes only under its state directory: `$BELAY_STATE_DIR`, else
`$XDG_STATE_HOME/belay`, else `$HOME/.local/state/belay`.

## Exit codes

| code | meaning |
|---|---|
| 0 | done -- for `diff`, whatever it found, unless `--exit-code` |
| 1 | `diff --exit-code`: some path is not unchanged (`unknown` counts) |
| 2 | usage: an unknown option or command, a missing argument, a checkpoint that does not exist |
| 3 | refused: the scope cannot be resolved, is not a directory, or changed while it was resolved |
| 4 | failed: an I/O error, corrupt state, out of memory |

An error is one line on standard error; `--json` output never carries one.

## The scope

`--scope` is resolved once, against the filesystem (`..`, `.` and symlinks included), and the
result is opened one component at a time without following symlinks. A component swapped for a
symlink in between is refused (exit 3), never followed. The resolved path is what the checkpoint
records.

If belay's own state directory is inside the scope, it is not recorded: the output of `check`,
`mark` and `diff` says so on every capture.

## The state directory

```
<state>/scopes/<16 hex digits of the scope's sha256>/
    scope                       the scope's resolved path
    store/                      copies of small text files and of files an interpreter needs,
                                shared by every checkpoint of the scope
    checkpoints/<id>/manifest.ndjson
    checkpoints/<id>/meta.json  written last: a checkpoint exists once it does
    lock                        one capture at a time
```

Nothing in it is deleted by belay.

## mark: which files are read

A regular file is not read again, and keeps the previous checkpoint's hash, when its inode, mode,
size, modification time and change time (ctime) are all what the previous checkpoint recorded,
and its ctime is before a reference point: the newest ctime the previous checkpoint recorded, or
the previous manifest file's own ctime when it is on the scope's filesystem, whichever is later
(git uses its index file's timestamp the same way). A file written after the previous checkpoint
gets a ctime at or past that point and is read.

`mark` reads every file when there is no checkpoint before, with `--full`, every `N` marks
(`--full-every N`, default 50), or when the newest ctime it sees is older than the newest the
previous checkpoint recorded (the clock went backwards). The output says which, under
`prefilter` in `--json`.

## The receipt

Events first (packages installed, upgraded, removed), then every privilege change -- capabilities,
inode flags, setuid, setgid or sticky bits -- then the other changes by path. A record shows at
most 15 of its findings, then "and N more". An entry belay could not capture reliably is named on
its own line with the reason (`raced`, `unstable`, `unverified`, ...). Sections longer than 50
lines fold to "and N more" (`--all` shows everything); the privilege section never folds.

## --json

`check`, `mark` and `log` print checkpoints as JSON objects, one a line, described by
[schema/checkpoint.v1.json](../schema/checkpoint.v1.json).
