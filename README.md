# belay

**Intent:** record what changed on a system, explain it in semantic terms rather than as a path
list, and make it reversible.

**Status: pre-alpha.** The checkpoint and diff engine runs (below); the formats it writes are drafts
that may still change, and there are no releases. Nothing that changes your files exists yet.

## What exists today

- `belay check`, `mark`, `diff` and `log` (see [docs/cli.md](docs/cli.md)): record a directory as a
  checkpoint, record what changed since the last one, show the difference, list checkpoints. They
  need no privileges and only read the directory they are given; belay writes only under its own
  state directory.
- Interpreters that explain changes to pip installs, dpkg's package database, git refs, hooks,
  reflogs (up to the store limit, 64 KiB by default) and small text files
  ([docs/spec/diff-v1.md](docs/spec/diff-v1.md)).
- The manifest format ([docs/spec/manifest-v1.md](docs/spec/manifest-v1.md)) and the diff format
  (diff.v1, a draft).
- Tests on Linux (x86_64, arm64), on macOS, and inside a Docker container as an unprivileged user,
  in CI on every change.

## What does not exist

No `commit`, `discard`, restore or undo: belay records and explains, and changes nothing. The
session engine under `src/session/` (namespaces and overlays) is not part of the `belay` binary.
No integrity checking against a baseline, no policy layer, no Python package, no releases.

## Deliberate limits

Today belay only records and reports; it contains nothing. The session engine, when it ships, is
meant as a **safety** boundary, not a **security** boundary — built for accidents, not for hostile
code; it will not contain a process that is actively trying to escape. See [SECURITY.md](SECURITY.md).

What a checkpoint does not see: anything outside the scope, anything below a mount point inside it,
belay's own state directory (left out, and said), and network effects (pushes, API calls, emails).
On filesystems with coarse timestamps some same-size rewrites can be missed; the limits are in
[docs/spec/manifest-v1.md](docs/spec/manifest-v1.md).

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
