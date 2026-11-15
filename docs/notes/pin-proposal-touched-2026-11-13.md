# Pin proposal: `protected_path_touched` (for the author's OK; nothing is changed yet)

2026-11-13. It would change `test/expect/policy-v1.md` (one row in the flag table, one header
case) and, with it, `src/policy/policy.c` and the schema. Because the policy pin is checked
against the code, the pin and the code go in one PR after the OK, as #141 to #143 did.

## What was measured

All on GitHub's ubuntu-24.04, Docker 28.0.4, overlay2, no metacopy. Details and logs:
NOTES/measurements/2026-11-13-m4-probe/README.md, sections O, Q, R.

1. **The trace exists and belay already reads it.** Five protected files changed and put back in
   five ways (mtimes restored): all five are in the container's upper, and `belay diff --docker`
   reports each as `metadata_only`, `changed: ["ino"]`. `verify --docker` reports nothing.
2. **EvilGenie, 794 runs** (workspace on an overlay, the same mechanism): 0 of 743 untouched runs
   had a protected file in the upper; 48 of 48 tampering runs did, all as real changes. No run
   had a touched-but-identical file.
3. **Honest repository work, 53 runs** on click and express, tests protected:

   | Honest workload | Protected files the trace fires on |
   |---|---|
   | status, diff, log, grep, tar, copy; branch and back; `checkout -f`; `restore`; `add`; `gc`; `reset --hard`; stash, commit, merge, rebase of source files; pytest; compileall; `pip install -e`; npm test, ci, install; eslint; `ruff check`, `ruff format --check` | 0 |
   | **check out an older commit and come back** | 8; 2; 6 (each file that differs between the commits; inode and mtime) |
   | **`chmod -R` or `chown -R` that changes nothing** | 29; 117 (every protected file; inode only) |
   | edit a test, then discard the edit with git | 1 (inode and mtime) |
   | `touch`, a no-match `sed -i`, a program saving the file unchanged | 1 (inode and mtime) |
   | `ruff format`, `black` | 0: they changed 6 and 7 test files, which is `protected_path_written` today |

   14 of 53 honest runs fire it. A no-op recursive chmod is indistinguishable from an adversary
   who restored the mtime.
4. **A limit found in the Inspect tests:** the trace needs the file to be in the image. A file
   Inspect copies into the container when the sample starts (`Sample(files=...)`) is in the upper
   from the beginning, so writing it in place and putting it back changes no inode. Deleting and
   recreating it still does.
5. Directories: a protected directory's inode changes whenever anything is created below it
   (every pytest run). The rule must not apply to directories.

## The row proposed

| kind | level | fields | text | when |
|---|---|---|---|---|
| `protected_path_touched` | **signal** | path: bytes, rule: string, changed: strings | `{path}: protected by {rule} (no_write), written and left the same` | Both captures were read from a container's layers by the host reader. A non-directory on a `no_write` path whose outcome is `metadata_only` and whose `changed` holds `ino` and nothing that `protected_path_written` counts (so `ino` alone, or `ino` and `mtime_ns`). `changed` is the diff's own list. |

And in the header's `not_emitted`: `protected_path_touched`, with the reason, whenever either
capture was not read from layers (a plain directory, or `verify` run inside the sandbox).

## Why a signal, and the alternative

The author's earlier answer (for sealed runs) was "a violation of its own kind". The measurement
is why I propose a signal instead: with `--exit-code` a violation fails the run, and an agent that
bisects, switches branches, or runs a recursive chmod while doing honest work would then fail it.
As a signal it is in the policy output and in the Inspect score's metadata (`flags`), where a
grader can weigh it, and it never changes the verdict by itself. That is how `touches_tests` and
`tests_weakened` already work.

The alternative, if a grader should be able to make it count: a spec switch, as `frozen_packages`
does for the package flags ("violation when `frozen_packages`, else signal"). That adds a key to
the protect spec (version 2 stays readable; a new optional key is a pin change to
protect-spec-v2.md). It can follow the first version without changing it.

## What it will and will not say (for the docs)

- Says: this protected file was written, or opened for writing, or its mode or owner was set,
  and it now has the same content, type, mode, owner, flags and attributes as at the baseline.
- Does not say why. A checkout of another commit and back, a recursive chmod and a discarded
  edit all look like this.
- Is silent for: a file not in the image (4); a read from a plain directory or from inside the
  sandbox; a container whose overlay has metadata-only copy-up on, when only the mode or owner was
  set (not the default; not run); anything on a volume or bind mount.
