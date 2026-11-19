# Phase 5 (the CLI, mark, receipts; M1 completion): structure proposal

Status: **PROPOSED 2026-10-31, awaiting the author's approval** (standing rule, BELAY_DESIGN.md §0.7).
No implementation code exists for it. One measurement spike was run for `mark`
(NOTES/measurements/2026-10-31-mark/); it is scratch code, not product code.

## 1. What Phase 5 must do (known requirements only)

- **The CLI**: `belay check`, `belay diff`, `belay mark`, each with `--json`, `--help`, and exit
  codes with one meaning each (§4.2: `--json` output validated against `schema/*.json`). Today
  `src/main.c` runs the session engine's fork and nothing else.
- **check's path resolution** per §5.1.1: `realpath()` exactly once per `--scope`, opened at once
  as the root dirfd; adversarial tests (symlinks, `..`, mount boundaries, races).
- **`mark`**: the delta since the previous mark (§5.4), with a prefilter on an aging reference
  point -- the newest ctime seen through validation, as git uses its index timestamp -- and the full
  walk as the fallback (decided-open item, §13a). Measured below.
- **Receipts** (§8.2, §14.7, Q4): the human rendering of a diff. Names flagged entries (`raced`,
  `unstable`, `unverified`), no global "provisional" banner; 15 findings a record, then "and N
  more"; events grouped before path records; never suppresses `caps`, setuid/setgid or `iflags`
  changes (§5.3, never-suppressible metadata).
- **M1's done criteria** (§9): `check`/`diff`/`mark` work unprivileged in a plain directory and in
  a Docker container; the portable engine builds and passes tests on macOS in CI; interpreters
  pip, dpkg, git, text, binary (done); diff.v1 drafted (done).
- **S7 claims ledger at M1 completion** (§13a), scoped to the spec, the public headers, the README
  and docs/.

Not in Phase 5: `log`, `doctor`, `run`/`commit`/`discard` and the session engine (M4; src/session/
untouched), integrity and flags (M2), host readers (M3), hooks and shims (M1.5, M5).

## 2. Modules, one job each

```
 src/main.c ──> src/cli/cli.c (dispatch: check|diff|mark|help|version)
                   ├── args.c       options, usage errors, --help text (one table per command)
                   ├── state.c      the state directory: checkpoints, ids, the latest, a lock
                   ├── cmd_check.c  scope resolution (§5.1.1) -> belay_manifest_write
                   ├── cmd_mark.c   previous checkpoint -> capture with the prefilter
                   ├── cmd_diff.c   belay_diff -> diff.v1 (--json) or receipt.c
                   ├── receipt.c    diff.v1 -> the human receipt (no decisions of its own)
                   └── jsonout.c    --json results of check and mark (schema/check.v1.json, ...)
 src/capture/previous.c   the previous manifest as a compact index for the prefilter
```

| module | its one job | what it must not know |
|---|---|---|
| `cli.c`, `args.c` | Parse, dispatch, map every failure to one exit code and one stderr line. | Formats, the walk. |
| `state.c` | `$XDG_STATE_HOME/belay/` (manifest-v1 "Location"): create checkpoint directories, choose ids, find a scope's latest checkpoint, one advisory lock per scope so two marks never interleave. | What a manifest holds. |
| `cmd_check.c` | Resolve each `--scope` once (§5.1.1), hand the root to capture, print the id. | Diff. |
| `cmd_mark.c` | Find the previous checkpoint, decide prefilter or full walk (§4), capture. | Rendering. |
| `cmd_diff.c` | Choose the two manifests and the store, run `belay_diff`, print diff.v1 or a receipt. | Capture internals. |
| `receipt.c` | Render diff.v1 for a human, by the rules in §5. Reads diff.v1 (and the two manifests' `mode` values, Q5); decides nothing the diff did not. | Capture, interpreters. |
| `previous.c` | The previous manifest as an index: path -> (stat fields, sha256, stored), bounded memory. | The CLI. |

Estimated size: cli+args ~250 lines, state ~200, cmd_* ~350, receipt ~350, jsonout ~120,
previous ~250; capture gains one reuse hook (~60).

## 3. Interfaces

```
belay check --scope <dir> [--scope <dir>]... [--json]        -> prints the checkpoint id
belay mark  --scope <dir> [--full] [--json]                  -> a checkpoint after the scope's latest
belay diff  --scope <dir> --since <id> [--to <id>] [--json]  -> diff.v1 (--json) or a receipt
belay help [command] | belay <command> --help | belay --version
```

- **Exit codes** (one meaning each, Q4): 0 success; 1 `diff` found a change (as `diff(1)` and
  `git diff --exit-code`; `check`/`mark` never return 1); 2 usage (unknown option, a missing
  argument, a bad id); 3 refused (the scope cannot be resolved, is not a directory, changed during
  resolution; manifests of different scopes); 4 failed (I/O, corrupt state, out of memory). A
  provisional result is not a failure: it is in the output, never in the exit code.
- **`--json`**: `check`/`mark` print one object `{"id", "scope", "manifest", "entries", "raced",
  "unstable", "vanished", "provisional", "prefilter": {"used", "trusted", "hashed", "racy"} (mark)}`
  validated in tests against `schema/check.v1.json`, `schema/mark.v1.json`; `diff --json` prints the
  diff.v1 stream itself (its schema is the spec). Errors under `--json` are still one stderr line
  and an exit code, never JSON on stdout.
- **Capture's reuse hook** (internal): before reading a regular file, capture asks
  `previous_lookup(index, path, stat) -> {sha256, stored} | none`; on a hit it records the previous
  hash and `stored` without opening the file. The end-of-walk validation is unchanged, so a file
  that changes during the walk is `raced` exactly as today.

## 4. mark: the prefilter on an aging reference point

**Rule.** A regular file is trusted unchanged, and not read, when its `(dev, ino, type, mode,
size, mtime_ns, ctime_ns)` equal the previous entry's, the previous entry has a `sha256`, and its
`ctime_ns < R`. Then its `sha256` and `stored` are the previous entry's. Anything else is read.

**R** (Q2) = the larger of
1. the newest `ctime_ns` among the previous manifest's entries that validation passed (not
   `raced`, `unstable`, `unreadable`) -- derivable from the frozen format, no new field; and
2. the previous manifest file's own ctime, when it is on the scope's device (git's index rule):
   it was written after every stat the walk made, so any later write to a file gives that file a
   ctime at or past it.

Why both: (1) alone never ages on an idle tree -- R moves only when a newer ctime is seen, so the
files that share the newest tick are re-read on every mark, which on coarse timestamps is most of
a freshly written tree (measured: 15,013 of 16,175 Go files at 1 s granularity). (2) moves forward
with every mark; measured, it leaves 0 racy files on both trees at every granularity. (2) needs
the state directory on the scope's device; (1) is the fallback where it is not.

**Full walk (the fallback)** when: no previous checkpoint for the scope; `--full`; the previous
manifest is unreadable, from another scope, or has a different `hash_max_bytes` or
`store_max_bytes`; its index would exceed its memory bound (§5 of the measurement: 32 B an entry,
bounded at 64 MiB, about 2M entries); or (Q8) the filesystem's ctime cannot be trusted to move
forward -- WSL showed ctime moving backwards (2026-10-27), so a periodic full mark is proposed.

**Measured** (NOTES/measurements/2026-10-31-mark/, warm cache, fine-grained ctime):

| | Go (18,027 entries) | 100k tree (109,757) |
|---|---|---|
| full `check` | 0.600 s | 1.251 s |
| the pipeline without reading content | 0.100 s | 0.574 s |
| prefilter spike, nothing changed (load + stat walk + hash) | 0.080 s; 1 file read | 0.408 s; 1 file read |
| prefilter spike, 1% changed | -- | 0.401 s; 1,001 read |
| **estimated mark** (pipeline + index + reads) | **~0.16 s** | **~0.87 s** (~0.68 s with a lexer-only index) |

The prefilter's gain is the hashing it skips: 3.7x on the Go tree, 1.4-1.8x on the 100k tree,
where the walk, xattr/iflags reads and the manifest write dominate. Memory: the spike's naive
table took 20/33 MiB; the proposed index (path hash -> manifest offset, 16 B, half full) is
~3.5 MiB at 110k.

**Proof** (§6): a differential test -- random mutation sequences on a tree, after each `mark`
and a full `check`; their manifests must agree on every recorded field -- run also under a
decorated fsops that rounds ctime/mtime to 1 s and 2 s (coarse timestamps) and one that writes
a file within the same tick right after its stat (the racy case). Canaries for the rule's every
clause.

## 5. Receipts

`belay diff` without `--json`, rendered from diff.v1 only (plus the manifests' modes, Q5):

```
belay diff  /home/u/proj  since 3 (12:04:11) -> now
  2 modified · 1 added · 1 metadata_only · 0 unknown        events: 2

packages
  pip   upgraded numpy 1.26.4 -> 2.1.0
  dpkg  installed git:amd64 1:2.39.2-1.1 (provisional: status raced)

privilege                                         <- never folded, never filtered
  bin/tool     setuid added (mode 0755 -> 4755)

changes
  M src/main.c        +12 -3 lines, first change at line 40
  A tests/new_test.py 48 lines
  M .git/refs/heads/main   refs/heads/main 1a2b.. -> 3c4d..
  ? build/out.log     raced                           <- flagged entries named, no banner
```

Rules: events first (by interpreter, as E4), then privilege changes (any record whose `changed`
holds `caps` or `iflags`, or whose `mode` change adds or drops setuid/setgid/sticky), then the
rest by outcome. Each record shows at most 15 findings, then "and N more". Provisional events
and `unknown` records say why, per entry. Sections longer than a screen fold to "and N more"
except privilege, which never folds. Output is deterministic; colour only on a tty.

## 6. check's path resolution (§5.1.1) and its adversarial tests

`realpath()` once per `--scope`; the result opened at once with `O_DIRECTORY | O_NOFOLLOW` and,
where available, `openat2(RESOLVE_NO_SYMLINKS)` from `/` (else per-component `O_NOFOLLOW` opens
from `/`): a component swapped for a symlink between `realpath` and the open is refused (exit 3),
never followed. The walk is unchanged (it already never re-resolves a string). Tests, each through
the CLI and, for the races, a decorated fsops: a symlink as the scope (resolved once, the
resolved path recorded); a symlinked parent; `..`, `.`, `//`, trailing `/`, a relative scope; a
file, a missing path, an unreadable directory, a symlink loop (ELOOP); a component swapped
between `realpath` and the open; the scope a mount point and one containing mounts; a non-UTF-8
scope; a path over PATH_MAX; the scope containing belay's own state directory (Q6); two scopes
that overlap. Docker (non-root, existing job) and macOS run them as part of `make check`.

## 7. M1 completion

- **Unprivileged, plain dir, Docker, macOS**: CLI end-to-end tests (check -> change -> mark ->
  diff, with pip/dpkg/git/text fixtures) in `make check`, which the docker job already runs as a
  non-root user and macos-portable runs natively. The non-Linux `main.c` gains the portable
  commands.
- **S7 claims ledger**: every claim in docs/spec/, include/belay/*.h comments, README.md and
  docs/ -- each sentence that states a number, a bound, a guarantee or a "never/always" -- listed
  with its evidence (a test, a pin, a measurement) or rewritten/removed. Proposed author: a fresh
  agent (Q10), as the review protocol uses for independence.

## 8. Defect classes the structure makes impossible

| class | how |
|---|---|
| A path re-resolved from a string (TOCTOU) | one realpath, one open, everything after relative to the root fd; a swap is refused |
| A trusted file that changed | the prefilter's equality includes ctime and R; the differential test against full `check`, under coarse-timestamp decorators |
| Exit 0 on a failure | one table maps every error to its code; a test per row |
| A receipt that hides privilege changes | the privilege section is unfoldable and unfiltered; a test per kind (caps, iflags, setuid, setgid) |
| --json drift | outputs validated against schema/*.json in tests |
| Two marks interleaving | one advisory lock per scope in state.c |

## 9. Proof standard

Contract tests for the CLI (every option, every exit code, --help for each command); golden
receipts written by hand from diff.v1 fixtures, never from a run; the path-resolution tests above;
the mark differential test; schema validation of --json; S3 canaries at the phase end; an
independent blast-radius review (the CLI resolves user-supplied paths). Measured: check, mark,
diff on the Go and 100k trees, in Docker and on the macOS runner.

## 10. Open questions for the author

1. **The store across checkpoints.** manifest-v1's Location gives each checkpoint its own `store/`,
   but a mark reuses the previous copies and `belay_diff` takes one store. Proposal: one store per
   scope (`$XDG_STATE_HOME/belay/scopes/<id>/store/`), each checkpoint's `store` pointing at it --
   a documented deviation from the Location section (the encoding is untouched). Alternative: hard
   links between per-checkpoint stores, and `belay_diff` taking two.
2. **R's second source.** The previous manifest file's own ctime (git's index rule) when on the
   scope's device. "Recorded in the manifest" would need a new manifest field: a format change.
   Approve deriving it instead?
3. **`diff --since <id>` without `--to`.** Proposal: it captures the live tree now (as a mark,
   kept as a checkpoint so a receipt can be re-rendered) and diffs against `<id>`. Alternative: a
   temporary capture, discarded.
4. **Exit codes.** `diff` returning 1 on a change (diff/git convention), or 0 always?
5. **Privilege changes need mode values**, which diff.v1 does not carry (only that `mode`
   changed). Proposal for M1: the receipt reads the two manifests' modes for records whose
   `changed` holds `mode`; for M2's policy, add the before/after modes to diff.v1 (a pin change).
6. **Self-observation.** A scope containing `$XDG_STATE_HOME/belay` would record belay's own
   writes. Proposal: the walk skips that directory by (dev, ino), recorded as excluded in the
   receipt (no manifest change: it is simply not walked). Or refuse such a scope.
7. **main.c's session fork.** Today `belay` with no arguments runs the session engine. Proposal:
   it becomes `belay help`; the session fork is reachable only from its tests until M4
   (src/session/ untouched).
8. **Untrustworthy ctime.** WSL's ctime went backwards once (2026-10-27). Proposal: `mark` does a
   full walk every Nth mark (N = 20) or when the previous checkpoint is older than an hour, and
   always with `--full`. Or trust ctime everywhere and document it.
9. **`belay log`** (list checkpoints) is in §5's command list but not in M1's done criteria. Include
   a minimal one (ids, times, scope) in Phase 5?
10. **S7's author.** A fresh agent with no implementation context, as the blast-radius review is?
