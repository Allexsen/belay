# Pin: captures that do not grow with the machine

**Status.** Approved by the author, 2026-11-19, after two independent reviews. The code follows in later
PRs: until a row's code has merged, nothing in it is implemented, and `docs/cli.md` says only what is.
Rows marked **owed** state what a run must show before the code resting on them merges.

**Evidence.** "Measured" means run on GitHub-hosted Ubuntu 24.04 (kernel 7.0) and 22.04 (kernel 6.8)
runners, 2026-11-18 and 19. The file names and section labels given (`events.txt` E1, `facts.txt` P4,
`owed.txt` U1, `round-3`, ...) are those runs' outputs, kept in the project's notes, not in this repository.

| id | rule | how established |
|---|---|---|
| SC-M1 | `mark` uses the previous checkpoint whatever its size. The reason `the previous checkpoint is too large to index` no longer occurs. | measured: at 1,133,426 entries every mark read 43 GB again (`2026-11-18-system-scope-probe/round-3/README.md`); read: `PREV_BYTES_MAX`, 64 MiB, `src/capture/previous.h` |
| SC-M2 | For `check`, `mark`, `diff`, `manifest`, `log`, `verify`, `prune` and every `watch` command, belay's heap stays under 64 MiB whatever the number of entries. The test: a generated 2,000,000-entry scope's manifests, each command run under an address-space limit that a whole-manifest read would break. | read: the delta writer and `rebuild` hold manifests whole (`src/cli/delta.c`), and `verify` and `prune` go through `rebuild`; measured: 906 MB peak at 1.13 M entries with the cap raised (`round-4/out-bigindex/times.txt`) |
| SC-M3 | The index of a checkpoint and every rebuilt manifest are files in belay's state directory, never under `TMPDIR` or `/tmp`. The index of a scope's latest checkpoint is kept beside it as a cache (it can always be rebuilt from the manifest, and is when missing or older than it), so a step does not build it again; every other temporary is removed when the command ends, and a leftover from a killed run by the next. | read: `src/cli/delta.c:317` writes to `TMPDIR`; the first review's F24, the second pass's M3 |
| SC-M3a | The index holds every entry of the manifest, of every type, and every name of an inode: fixed records sorted by `(dev, ino, sequence)`, each with the offset of its path in a second file; and the paths in order, so a path is found by bisection too. Each record carries the entry's own fields (what the manifest line has), so an old entry is read from the index and no whole manifest need be on disk. An index names the sha256 of the manifest it stands for and is used only when that is the manifest wanted; otherwise it is rebuilt. An event capture writes the index of its result as the previous index and an overlay of the records it changed, looked up first; a walk writes a whole one. | read: today's index keeps regular files with a hash, one record an inode, no path (`src/capture/previous.c`); the kernel record needs every name (kernel-record K9) |
| SC-M4 | The trust rule is unchanged: same `dev`, `ino`, `mode`, `size`, `mtime_ns`, `ctime_ns`, and `ctime_ns` before the reference. An inode with two names is still trusted by neither. | read: `src/capture/previous.c` |
| SC-M5 | Owed, in the build: a mark of the 1.13 M-entry runner image with the new index, against 47 s warm and 168 s cold with the cap merely raised. A result worse than that by more than 10 s is brought to the author before merge. | |
