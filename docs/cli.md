# The belay command line

```
belay check --scope DIR [--json]
belay mark  --scope DIR [--full] [--full-every N] [--json]
belay diff  --scope DIR --since ID [--to ID] [--full-every N] [--json] [--exit-code] [--all]
belay log   --scope DIR [--json]
belay exclude --scope DIR [--add PATH | --remove PATH]
belay baseline export --scope DIR --out FILE [--protect SPEC] [--json]
belay verify --scope DIR --baseline FILE --baseline-sha256 HEX [--protect SPEC] [--to ID] [--exit-code]
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

belay only reads `DIR`. It writes only under its state directory: `$BELAY_STATE_DIR` (an absolute
path), else `$XDG_STATE_HOME/belay`, else `$HOME/.local/state/belay`.

A checkpoint id is a decimal number without a leading zero, at most 9 digits. Ids end at
999,999,999: past it every capture fails (exit 4).

## Exit codes

| code | meaning |
|---|---|
| 0 | done -- for `diff`, whatever it found, unless `--exit-code` |
| 1 | `diff --exit-code`: some path is not unchanged (`unknown` counts) |
| 2 | usage: an unknown option or command, a missing or malformed argument, a checkpoint that does not exist |
| 3 | refused: the scope cannot be resolved, is not a directory, changed while it was resolved, or is the state directory or inside it; no state directory can be named; the state directory, or a directory above it, belongs to another user or others can write it |
| 4 | failed: an I/O error (writing the output included), corrupt state, out of memory |

An error is one line on standard error; `--json` output never carries one.

## The scope

`--scope` is resolved against the filesystem (`..`, `.` and symlinks included), and the result is
opened one component at a time without following symlinks (search permission on its parents is
enough). A component swapped for a symlink in between is refused (exit 3), never followed. The
capture resolves the path again and refuses it unless it is the same directory (device and inode)
-- exit 3. The resolved path is what the checkpoint records.

If belay's own state directory is inside the scope, it is not recorded, and every capture says so:
in the manifest's header (`excluded`, reason `state_dir`; [manifest v2](spec/manifest-v2.md)),
`check` and `mark` in their output (`"excluded"` in `--json`), `diff` after its receipt, or on
standard error with `--json`. It is counted once, at its own path: reached again through a bind
mount inside the scope, it is a mount point like any other -- recorded, never entered. A scope that
is the state directory, or inside it, is refused.

## Excludes

`belay exclude --scope DIR --add PATH` makes this scope's captures skip `PATH`, relative to `DIR`
and matched exactly (`--remove PATH` undoes it; without either, the list). They are for speed --
a `node_modules` that a package manager owns -- not for noise: each one is a blind spot. Every
manifest names what it did not walk in its header (`excluded`, with the reason `user` or, for
belay's own state directory, `state_dir`), `check` and `mark` say so, and a receipt lists them
under "not compared" (with `--json`, on standard error: `belay: not compared: PATH (...)`, both
sides), checkpoint JSON lists them as `excluded_paths`, and diff.v1's header as each side's
`before_excluded` and `after_excluded`. A diff across an exclude reports what one side holds there
as `unknown`, `not_captured`, never as removed or added, and derives no package event from it. An exclude has no
control character; at most 31 per scope, each once, and no more than a manifest's header line can
name (64 KiB, every number at its widest): `--add` refuses one past that, and a capture refuses to
write a header it could not read back (exit 4); an `excludes` file that is not what belay
writes is corrupt state (exit 4). Protected paths (a later milestone) will never be excludable.

## The state directory

```
<state>/scopes/<16 hex digits of the scope's sha256>/
    scope                       the scope's resolved path
    store/                      copies of small text files and of files an interpreter needs,
                                shared by every checkpoint of the scope
    checkpoints/<id>/manifest.ndjson
    checkpoints/<id>/diff-from-<since>.ndjson   what diff --since computed for this checkpoint
    checkpoints/<id>/meta.json  written last: a checkpoint exists once it does
    excludes                    the scope's excludes, one a line (belay exclude)
    lock                        one writer at a time
```

The state directory must belong to the user belay runs as and be writable by no one else; every
directory above it must belong to that user or to root and be writable by no one else, unless it
is sticky (as `/tmp` is) or only the user's own group may write it. Otherwise belay refuses (exit
3). Every directory and file belay keeps there is opened from the state directory without
following symlinks: a symlink, FIFO or anything else belay did not write is corrupt state (exit
4), never followed or waited on. A manifest is checked that way before it is read or compared;
the capture and the comparison then reach it by its path, which is why no one else may be able to
write the state directory or anything above it. A capture that finds another belay working on
the same scope says so on standard error and waits for it.

**A known limit.** A process running as your own user while a capture runs can replace a
directory under the state directory between belay's check and its use, and send that capture's
writes elsewhere. That is outside belay's threat model: such a process can already write
anything you can, belay's state included (where belay scans for others -- inside a sandbox after
the watched processes are stopped, or as a host reader running as root -- no such process is
there).

Nothing in it is deleted by belay. The store keeps one copy of every version of every file it
copies -- small text files, and up to 16 MiB for each git reflog -- so a busy repository's
reflogs, changing between marks, grow it by up to their size each time.

## baseline export: the bundle a later verify judges against

At reset, before the policy being judged runs, `belay baseline export` records `DIR` reading every
file (a `check`) and writes the baseline bundle to `FILE`
([test/expect/baseline-bundle.md](../test/expect/baseline-bundle.md)): the manifest, every copy it
names, and what each package database says of each file it lists -- dpkg's `md5sums` and
`Conffiles` (MD5, checked in the same read that hashes the file, whose sha256 must be the
manifest's: a file changed meanwhile fails the export), pip's `RECORD` (sha256, compared with the
manifest's own). It prints the bundle's sha256 -- keep it outside the sandbox: verify reads a
bundle only when its bytes hash to it -- and every file not as its database says: already so at
reset, a baseline-integrity finding, never an episode's. Files a database lists outside the scope
are counted, never checked.

`--out` inside the scope is refused (exit 3): the bundle must leave what it describes. With
`--protect SPEC` (the task's protect spec, [test/expect/protect-spec.md](../test/expect/protect-spec.md)):
every file within 4 GiB is hashed, protected or not, since a manifest holds a hash only within its
limit; an exclude, or belay's state directory, covering a protected pattern is refused (exit 3);
a spec it refuses is a usage error (exit 2).

## verify: what the changes mean

After the episode -- every process of the policy stopped first -- `belay verify` records `DIR`
reading every file, in a state directory of its own it creates fresh (in `$TMPDIR`, removed when it
is done: no state a policy prepared is ever read), diffs it against the bundle, and writes
[policy.v1](../test/expect/policy-v1.md) to standard output: one record per flag, each a
`violation` (a declared expectation broken: protected paths, frozen packages) or a `signal`
(informational: tests touched or weakened, CI and pytest configuration, startup and git hooks,
history rewritten, new executables on PATH, privilege changes). diff.v1 and the manifest are
unchanged: judgement is apart from description.

The bundle is read only when its bytes hash to `--baseline-sha256` (exit 3 otherwise, or without
it), and only for the scope it describes. `--protect` must be the spec the bundle was exported
with, or none when it had none (exit 3). Installed files are judged against the bundle, never
against the databases as the episode left them. With `--exit-code`, verify exits 1 when any
record is a violation; signals never fail a run.

`--to ID` judges checkpoint `ID` of the scope's own state instead of capturing now; with a spec,
only a checkpoint that read every file (a `check`, or `mark --full`: its trailer's `trusted` is 0).

## mark: which files are read

A regular file is not read again, and keeps the previous checkpoint's hash, when its inode, mode,
size, modification time and change time (ctime) are all what the previous checkpoint recorded,
and its ctime is before a reference point: the time the previous checkpoint's walk began, on the
scope filesystem's clock (the ctime of a file belay creates in the state directory as the walk
starts), which the previous manifest's header records (`walk_start_ns`). Each manifest's trailer
says how its walk read: `trusted`, `reference`, and `read_all` (why every file was read, or `""`). A file written after that point -- during that walk included -- gets a ctime at or past
it and is read. Whether a copy is kept is decided anew, as a full capture would decide it -- in
the store, no writer holding the file open, a binary file without one -- with one difference: a
file stored under an interpreter's claim keeps its copy after losing the claim (its content is
the same).

When the state directory is on another filesystem than the scope, that clock cannot be read; the
reference point is then the newest ctime the previous checkpoint recorded, and the output says so
(`"reference":"newest_ctime"` under `prefilter` in `--json`, `walk_start` otherwise). That point
can miss a same-size rewrite made during the previous walk within its file's own timestamp tick
when another file changed later in that walk. On fine-grained timestamps there is no such tick.
On whole-second ones (FAT, HFS+, some network filesystems) the miss is possible, so when every
ctime the previous checkpoint recorded (mount roots aside) has a zero nanosecond part, `mark` reads
every file instead and says why. Timestamps coarse at a kernel tick or 10 ms (Linux before 6.13,
exFAT) carry a nanosecond part, are not recognised, and keep that risk: keep belay's state
directory on the scope's filesystem, or use `check`, where it matters.

`mark` reads every file, and says why (`full_reason` under `prefilter` in `--json`), when there is
no checkpoint before; with `--full`; every `N` prefiltered captures -- marks, and `diff`'s captures
to now -- since the last full one (`--full-every N`, default 50; 0: never); when the newest ctime it
sees is older than the newest the previous checkpoint recorded (the clock went backwards: the walk
is done again in full); when the previous walk's start is unknown on coarse timestamps (above);
or when the previous checkpoint cannot be used -- unreadable, of another scope, taken with other
limits, or too large to index (64 MiB, about 76 bytes a file). A
previous manifest that is a symlink or a FIFO is corrupt state (exit 4).

## The receipt

Events first, under `events` (packages installed, upgraded, removed; branches created, deleted,
renamed or moved, commits added, history rewritten, HEAD switched), then every privilege change -- capabilities,
inode flags, setuid, setgid or sticky bits, on a file changed, added or removed -- then the other
changes by path. A record shows at most 15 of its findings, then "and N more". An entry belay could
not capture reliably is named on its own line with the reason (`raced`, `unstable`, `unverified`,
...). There is no "provisional" banner; when entries changed while they were read (raced, unstable
or vanished), one line counts them for each side: those of the newer side are settled by running
belay again; those of an earlier checkpoint stay in any diff from it. Sections of more than 50 entries fold to
"and N more" (`--all` shows everything); privilege changes and unknown entries never fold.

Every path and text is printed escaped -- in the receipt, in error lines, and whatever belay
reads back from its state: control characters, C1 controls, DEL, invisible format and bidi
characters (U+200B-U+200F, U+2028-U+202E, U+2060-U+206F, U+FEFF, ...) and bytes that are not UTF-8
as `\xNN`, a backslash as `\\`. A type change that is also a privilege change says both.

## --json

`check`, `mark` and `log` print checkpoints as JSON objects, one a line, described by
[schema/checkpoint.v1.json](../schema/checkpoint.v1.json). A path that is not UTF-8 is given in
base64 as `scope_b64` or `manifest_b64` in place of `scope` or `manifest`.
