# Contributing

belay is pre-alpha and changing shape quickly. Open an issue before starting anything substantial.

## Sign-off is required

Every commit needs a Developer Certificate of Origin sign-off:

```sh
git commit -s
```

That adds a `Signed-off-by:` line certifying you wrote the change or have the right to submit it
(see [developercertificate.org](https://developercertificate.org/)). The name and email must match
the commit author. CI rejects commits without it.

To add sign-off to commits you already made:

```sh
git rebase --signoff <base>
```

There is no CLA. The project is Apache-2.0 and stays Apache-2.0.

## Build and test

```sh
make            # build bin/belay
make test       # build and run the test binaries
make check      # both — this is what CI gates on
make clean
```

Tests live in `test/`, one binary per `test/test_*.c`, using the header-only harness in
`test/belay_test.h`. No external dependencies: the portable parts must build on macOS too.

## Blast-radius review

Some code can damage a contributor's or user's real filesystem. Changes to any of the following get
reviewed line by line, and need tests covering the adversarial cases — symlinks, hard links, `..`
traversal, mount boundaries, whiteouts, and races:

- `commit` and `discard`, or anything else that writes to or deletes from the real filesystem
- bind mounts, passthrough mounts, and masks
- anything that resolves a user-supplied path

Everything else gets a normal review. If you are unsure which side your change falls on, say so in
the PR and assume it's blast-radius.

Never run `commit` or `discard` against your own home directory while developing. Use throwaway
directories or a VM.
