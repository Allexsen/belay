# belay

**Intent:** record what changed on a system, explain it in semantic terms rather than as a path
list, and make it reversible.

**Status: pre-alpha.** The checkpoint and diff engine runs (below); the formats it writes are drafts
that may still change, and the latest pre-release is v0.1.0-alpha.6. Nothing that changes your files
exists yet.

Tested against 2,115 published agent runs: [results](bench/replay/RESULTS.md).

> **Pre-alpha. The most useful contribution right now is real-world
> use.** Run belay around something you actually do (an agent session,
> a build, an install) and compare its report with what really
> happened. If it missed a change, invented one, or buried the real
> change in noise, open an issue with the receipt. That's the data
> I need the most.

## What exists today

- `belay check`, `mark`, `diff` and `log` (see [docs/cli.md](docs/cli.md)): record a directory as a
  checkpoint, record what changed since the last one, show the difference, list checkpoints. They
  need no privileges and only read the directory they are given; belay writes only under its own
  state directory.
- Interpreters that explain changes to pip installs, dpkg's package database, git refs, hooks,
  reflogs (kept and read in full up to 16 MiB each) and small text files
  ([docs/spec/diff-v1.md](docs/spec/diff-v1.md)).
- `belay baseline export` and `belay verify`: a checkpoint kept as a bundle, and a directory compared
  with it and judged against a protect spec.
- `--docker`: a container's layers read from the host.
- pybelay, Python bindings around the binary, with a reward helper and an
  [Inspect integration](python/README.md#using-belay-with-inspect).
- The manifest format, version 4 ([test/expect/manifest-v4.md](test/expect/manifest-v4.md), built on
  [version 2](docs/spec/manifest-v2.md) and [version 1](docs/spec/manifest-v1.md), all of which belay
  still reads) and the diff format (diff.v1, a draft).
- Tests on Linux (x86_64, arm64), on macOS, and inside a Docker container as an unprivileged user,
  in CI on every change.

## What does not exist

No `commit`, `discard`, restore or undo: belay records and explains, and changes nothing. The
session engine under `src/session/` (namespaces and overlays) is not part of the `belay` binary.
No stable release.

## Deliberate limits

Today belay only records and reports; it contains nothing. The session engine, when it ships, is
meant as a **safety** boundary, not a **security** boundary — built for accidents, not for hostile
code; it will not contain a process that is actively trying to escape. See [SECURITY.md](SECURITY.md).

What a checkpoint does not see: anything outside the scope, anything below a mount point inside it,
belay's own state directory and the paths you exclude (left out, and named in every manifest), and
network effects (pushes, API calls, emails).
On filesystems with coarse timestamps some same-size rewrites can be missed; the limits are in
[docs/spec/manifest-v1.md](docs/spec/manifest-v1.md). A file being written while it is read is
marked and reported unknown where the kernel can say so, and counted where it can't
([docs/cli.md](docs/cli.md#a-file-being-written-while-it-is-read)).

## Build

```sh
make check
```

`make` needs a C11 compiler and GNU make, on Linux or macOS; `make check` also needs python3. The
binary is `bin/belay`.

## Contributing

Sign-off required (`git commit -s`), no CLA. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. **The core stays Apache-2.0, permanently.** If paid offerings ever exist they will be
separate products — never features removed from or withheld by this repository.
