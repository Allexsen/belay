# Pin: pybelay, the Python package

**What this is.** The public behaviour of `pybelay` (decision 187: "PyPI name: pybelay"): how it is
distributed, the functions it offers, what they return and raise. It is a thin layer over the CLI:
every function runs the release's binary once and parses its JSON by the pinned formats, which stay
the interface (BELAY_DESIGN §5); nothing here adds a format. Written by hand; approved by the author
2026-11-03 (decision 200), with checkpoint.v1 pinned in its own PR before pybelay ships.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## Distribution

| id | rule |
|---|---|
| PY-D1 | The distribution is `pybelay` on PyPI, and the import name is `pybelay` too. `belay` on PyPI is another project (BrianPugh/belay, a MicroPython library, 0.30.1 on 2026-11-03), which imports as `belay`. |
| PY-D2 | Its version is the belay binary's (`belay --version`), in PEP 440. A release's: `v0.1.0-alpha.3` is `0.1.0a3`. A development build's carries git's description as a local version: `0.1.0-alpha.2+95-ga2054b3` is `0.1.0a2+95.ga2054b3`, `-dirty` becomes `.dirty`, and `+unknown` (no git) stays `+unknown`; such a wheel is never published (PEP 440: local versions are not for public indexes). One release, one binary, one wheel set. |
| PY-D3 | Wheels only, one per release target, each tagged `py3-none-<platform>` (no extension: any Python 3.9 or later): Linux x86_64 and aarch64, tagged for both manylinux and musllinux since the binary is static; macOS arm64. No sdist: one could not carry a checked binary. |
| PY-D4 | Each wheel vendors its target's binary from the same release, taken from the release's assets after their `SHA256SUMS` and provenance attestation are checked, and records its sha256 in the package. Each wheel also carries whichever of the release's Linux x86_64 and arm64 static binaries it does not vendor, taken and recorded the same way, for sandboxes only (PY-I5): never run on the host. |
| PY-D5 | Before its first call in a process, the package hashes the vendored binary and compares it with the recorded digest: on a mismatch it raises `BinaryMismatch` and runs nothing. No environment variable or argument selects another binary to run on the host. `belay_record`'s `binary=` (PY-I1) is the one exception to the rule's wording: it names a binary that is only copied into a sandbox, and never run on the host. `pybelay.binary_path()` returns the vendored binary's path (for an orchestrator to copy into a sandbox: in-sandbox mode). |
| PY-D6 | An extra, `inspect`, needs `inspect-ai>=0.3.213` and so Python 3.10 or later, and adds an `inspect_ai` entry point. The package itself still needs neither. |

## Inspect

`pybelay.inspect`, with the extra (PY-D6): belay in an [Inspect](https://inspect.aisi.org.uk/) eval.

| id | rule |
|---|---|
| PY-I1 | `belay_record(protect, *, scope, sandbox, user, binary, timeout, where)` is a solver for `Task(setup=...)`. `protect` is a protect spec, a dict or a path. `where` is `"sandbox"` (the default) or `"host"` (PY-I7); anything else is a `ValueError`. |
| PY-I2 | `belay_verify(*, on_error, after_scorers)` is a scorer. Its value and answer are `C` and `pass`, `I` and `violation`, or `I` and `error` for a run it could not judge. |
| PY-I3 | `belay_verify` refuses to run after another scorer unless `after_scorers=True`. |
| PY-I4 | Nothing of belay's is in the sandbox while the agent runs, and the bundle stays on the host. |
| PY-I5 | Without `binary=`, the binary is the one that suits the sandbox: the wheel's own, else the carried Linux binary of the sandbox's architecture (PY-D4). `belay_verify` uses the binary `belay_record` used. |
| PY-I7 | With `where="host"` nothing of belay's enters the sandbox. `belay_record` and `belay_verify` run belay on the machine the eval runs on, with `--docker` and the name of the sample's container as Inspect's `sandbox().connection()` gives it, and with the container paused (`docker pause`) for each reading and running again after it, whatever the reading's outcome. belay runs as root: directly when the eval is root, else through `sudo -n`; a refused `sudo` is a `UsageError` that says so. A sandbox whose connection is not a Docker container, a machine that is not Linux, and a binary not built for this machine are each a `UsageError`. `belay_verify` refuses a sandbox whose container is not the one `belay_record` read. The score's metadata gains `where`, `"sandbox"` or `"host"`, in every case. What the host reader refuses (host-reader.md) is refused here with its reason, as any run belay could not judge (PY-I2). |

## Calls

Each function runs the binary once, with an argument list (never a shell) and `--json` where the
command takes it, never `--exit-code`, and parses its standard output strictly: each line by its
pinned format, an unknown key or a missing one is a `FormatError`. Paths are given as `str` or
`os.PathLike` and returned as `str`, decoded as `os.fsdecode` does (a name that is not UTF-8 keeps
its bytes as surrogate escapes and round-trips to the file system); a `*_b64` key is decoded into
its plain counterpart, so a result never has both.

| id | function | runs | returns |
|---|---|---|---|
| PY-F1 | `check(scope, *, docker=None)` | `belay check --scope S [--docker C] --json` | `Checkpoint` |
| PY-F2 | `mark(scope, *, docker=None, full=False, full_every=None)` | `belay mark ...` | `Checkpoint` |
| PY-F3 | `log(scope, *, docker=None)` | `belay log ...` | `list[Checkpoint]`, oldest first, as the CLI prints them |
| PY-F4 | `diff(scope, since, to=None, *, docker=None, all=False, full_every=None)` | `belay diff ...` | `Diff` |
| PY-F5 | `baseline_export(scope, out, *, protect=None, docker=None)` | `belay baseline export ...` | `Baseline` |
| PY-F6 | `verify(scope, baseline, sha256, *, protect=None, to=None, docker=None)` | `belay verify ...` | `Policy` |

`docker=` is the container's name or id (host-reader.md). `exclude` has no function: it changes
the scope's configuration and prints nothing to parse; the CLI does it.

## Results

All are frozen dataclasses: equal when their contents are, safe to keep and share.

| id | type | fields |
|---|---|---|
| PY-R1 | `Checkpoint` | One attribute per key of checkpoint.v1 (`schema/checkpoint.v1.json`), named as the key; `prefilter` a frozen dataclass of its keys. |
| PY-R2 | `Diff` | `header` and `trailer`: one attribute per key of diff.v1's header and trailer; `records`: a tuple of `DiffRecord`, each with diff.v1's record keys as attributes and `findings` a tuple of dicts, each finding's JSON object as diff.v1 writes it (paths decoded as above). Event records likewise, as `DiffEvent`. |
| PY-R3 | `Baseline` | `bundle` (str), `sha256` (str), `baseline_integrity`: a tuple of dicts, as baseline-bundle B-R4 gives them. |
| PY-R4 | `Policy` | `header` and `trailer` (policy.v1's keys as attributes), `flags`: a tuple of `Flag`, each with `flag`, `level`, `text`, `provisional` (bool, `False` when absent), `paths` (tuple of str) and `fields` (a dict of the kind's own fields, policy-v1 P-F1). `violations` and `signals`: the trailer's counts. |

## Errors

Every error is a `pybelay.BelayError` (an `Exception`), with `exit_code` (int or `None`) and
`stderr` (the binary's, as text). A violation is never an error: it is in the result.

| id | when | raises |
|---|---|---|
| PY-E1 | exit 2 (usage) | `UsageError` |
| PY-E2 | exit 3 (refused: a digest that does not match, a source that differs, an unsupported container, ...) | `Refused` |
| PY-E3 | exit 4 (failed) | `Failed` |
| PY-E4 | output a strict parse rejects, or an exit code the CLI does not document | `FormatError` |
| PY-E5 | the vendored binary does not hash to its recorded digest (PY-D5) | `BinaryMismatch` |
