# belay

**Intent:** record what changed on a system, explain it in semantic terms rather than as a path
list, and make it reversible.

**Status: pre-alpha, work in progress. Nothing here is usable yet.** `HEAD` does not run: the
session engine fails on directories that contain nested mounts, and the parts the project is being
rebuilt around — the checkpoint engine, the diff core, the interpreters — are not written.

This repository is published early because the design is settled enough to work in the open, not
because there is anything to install.

## What exists today

- A Linux session engine that creates a user and mount namespace, overlays each top-level directory
  of `/` separately, and `pivot_root`s into the result. Verified by `strace` on one machine
  (WSL2, kernel 6.18); it fails on directories containing nested mounts.
- A child-to-parent failure protocol that reports which setup stage failed, and why.
- Session directory layout and path resolution under `$XDG_STATE_HOME`.
- Build and test plumbing: `make check`, a dependency-free test harness, CI on Linux x86_64 and
  arm64 plus macOS, DCO enforcement.

## What does not exist

No CLI beyond "fork a shell". No `commit`, `discard`, `diff`, `check`, or `doctor`. No diff engine,
no interpreters, no integrity verification, no policy layer, no Python package, no releases.

## Deliberate limits

belay is a **safety** boundary, not a **security** boundary — it is built for accidents, not for
hostile code. It will not contain a process that is actively trying to escape. See
[SECURITY.md](SECURITY.md).

Some things are outside any belay session and can never be captured or undone: anything done through
a daemon started outside it, network effects (pushes, API calls, emails), and any path deliberately
passed through. These will be listed explicitly rather than glossed over.

## Build

```sh
make check
```

Requires a C11 compiler and GNU make. Linux for the session engine; the portable parts are intended
to build on macOS as they land.

## Contributing

Sign-off required (`git commit -s`), no CLA. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. **The core stays Apache-2.0, permanently.** If paid offerings ever exist they will be
separate products — never features removed from or withheld by this repository.
