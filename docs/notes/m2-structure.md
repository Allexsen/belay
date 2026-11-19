# M2 structure proposal: integrity, protected paths, flags, the in-sandbox protocol

Status: **proposal, 2026-11-03** (decision-log row 142). Design only: no code until the author
approves it and the pins it names. BELAY_DESIGN §9, M2: "pip/dpkg integrity vs. baseline, protected
paths with expected hashes, generic flags, in-sandbox protocol per §6". §5.3 and §6 are the
requirements; this document says how, and what is still the author's to decide (section 10).

Sources: the code on main (1288595 and after), the pins in `test/expect/`, BELAY_DESIGN §5.3 and §6,
and the M1.5 dogfood receipts in `~/.local/state/belay/dogfood/` (section 8: what they say about
false positives, measured, with the method). Nothing below about RL testbeds is measured: that is
M3's job (§9, Gate A).

## 1. The shape

M2 adds one command and one output format, and changes neither format belay already writes:

    belay verify --scope DIR --baseline BUNDLE [--protect SPEC] [--to ID] [--json] [--exit-code]

- **Inputs.** A *baseline bundle* (section 2), made at reset and kept outside the sandbox; the
  scope as it is now (or checkpoint `--to`); optionally a *protect spec* from the task package
  (section 3).
- **What it does.** The diff it would print anyway (diff.v1, the same core), then a policy pass over
  that diff, the two manifests and the stored copies: integrity of installed packages, protected
  paths, generic flags, privilege changes.
- **Output.** `policy.v1`, NDJSON beside diff.v1, never inside it: a header (the bundle's digest,
  the after manifest's digest, the protect spec's digest), one record per flag, a trailer counting
  each. A flag record names its paths, its evidence (the diff record or values that decided it),
  its *level* -- `violation` (a declared expectation broken: protected paths, frozen packages) or
  `signal` (informational: everything generic) -- and its *attribution* when per-call marks exist
  (the call, "between tool calls", or "unattributed": section 8's lesson).
- **Why a separate format.** diff.v1 says what changed; policy says what that means against a task's
  expectations. Keeping them apart keeps diff.v1 a pure, stable description (it is still a draft;
  M2 would add nothing to it) and lets policy rules change without a diff version. Manifest v2 is
  untouched: every hash M2 needs is already recorded (sha256 per file) or stored (the package
  databases).
- **Exit code** with `--exit-code`: 1 when any `violation`, else 0; signals never fail a run (the
  Goodhart rule, §5.3).

## 2. The baseline bundle and package integrity

### 2.1 What the bundle holds

Made by `belay baseline export --scope DIR --out BUNDLE` at reset, before the policy runs (§6, 2):

- the baseline manifest (a full `check`, never a prefiltered `mark`: nothing is trusted at reset);
- the stored copies the policy pass needs: the dpkg databases (`status`, `info/*.md5sums`,
  `info/*.list` -- already claimed with `BELAY_KEEP_STORE`, `src/interp/dispatch.c`), every pip
  `RECORD` and `METADATA` (likewise), and the copies of protected text files;
- for every file a package database lists with a hash, the hash it had *at reset* checked against
  the database (2.2): the bundle records which files matched, so a mismatch that was already there
  is never blamed on the episode;
- a digest over all of it (the manifest's digest is already in every diff trailer; the bundle's
  digest covers the copies too). The orchestrator keeps the digest; `verify` refuses a bundle whose
  digest it is not given or that does not match.

One file, a tar-like container belay writes and reads itself (no compression dependency): the
format is a pin of its own (section 7).

### 2.2 dpkg

- **Which files.** `info/<pkg>[:arch].md5sums`: one `md5  path` line per file, the path relative to
  the dpkg root -- the directory above `var/lib/dpkg`, so `/` in a container scanned whole and
  `chroot/sid` for a chroot inside the scope. A path outside the scope is skipped and counted, never
  silently.
- **Conffiles** are not in `md5sums`; their md5 is in `status` (the `Conffiles:` field). Admins edit
  them by design: a changed conffile is a signal (`conffile_changed`), never `tampered_installed_package`.
- **MD5 at reset only.** The manifest records sha256, not md5. At reset the export computes both for
  each listed file in one read (MD5 is vendored, `src/util/md5.c`), verifies md5 against the
  database, and keeps the sha256. After the episode, integrity is sha256 against that kept sha256:
  no md5 is needed then, and the in-sandbox database is never read for the judgement.
- **Flags.** A listed file whose sha256 differs from its reset value, whose type changed, or which
  is gone: `tampered_installed_package` (violation when packages are frozen, section 10 Q2; else
  signal), naming the package, the path, and both hashes. A file already mismatched at reset:
  `baseline_mismatch` in the export's own report, not an episode flag.

### 2.3 pip

- **Which files.** Each `*.dist-info/RECORD`: `path,sha256=<urlsafe base64, no padding>,size`, paths
  relative to the dist-info's parent (`site-packages`), and some escaping it (`../../../bin/x`
  for entry points): resolved lexically, containment-checked against the scope (the §5.1.1 rule),
  skipped and counted when outside. Rows with no hash (`RECORD` itself, `*.pyc` under
  `__pycache__`) are not checked; their count is reported.
- **Compare.** The RECORD hash decodes to the same sha256 the manifest records: direct comparison,
  no recomputation, at reset (2.1) and after.
- **Flags.** As dpkg: `tampered_installed_package` with the distribution's name.
- **Startup hooks.** A `*.pth` file or `sitecustomize.py`/`usercustomize.py` added in a
  `site-packages` and in no RECORD runs code at every interpreter start: `python_startup_hook_added`
  (signal; proposed, section 10 Q6).

### 2.4 Packages that changed during the episode

pip and dpkg already say so as events (`pip_installed`, `dpkg_upgraded`, ...). A file of a package
whose database entry changed is not judged against the baseline (the installer replaced it), and the
in-environment database after the episode is the policy's own writing (§5.3: "never against the
in-environment copy after the episode"). So:

- default: `package_changed` (signal) with the event, and the package's new files checked against
  the *after* database, the result labelled `self_consistent` or not -- evidence, never proof;
- with `frozen_packages: true` in the protect spec: any package event is a violation
  (`package_changed_while_frozen`).

## 3. Protected paths

### 3.1 The spec

From the task package, never from the environment (§6, 4). JSON, a pin of its own:

    {"belay_protect": 1,
     "protect": [{"path": "tests/**", "mode": ["no_write", "no_delete"]},
                 {"path": "grader/check.py", "expected_sha256": "<64 hex>", "mode": ["no_write"]},
                 {"path": "tests/", "mode": ["no_create"]}],
     "frozen_packages": false}

- `path`: relative to the scope, `/`-separated; `*` within one component, `**` any number of
  components, no `..`, no leading `/`; a name starting with `.` is matched only by a pattern that
  says so. Matched against the before *and* the after manifest, so a deletion and a creation are
  both seen.
- `mode`: `no_write` (content, type, a link's target, mode bits, owner, caps, xattrs, inode flags:
  anything but timestamps and inode number), `no_delete`, `no_create` (no path matching it may
  appear).
- `expected_sha256`: checked against the *after* manifest whatever the baseline said -- the task's
  ground truth (§6, 4).

### 3.2 What capture must do for them

Three capture changes, each a blast-radius change for independent review:

- **Never trusted by the prefilter.** `mark` keeps a previous hash when inode, mode, size, mtime and
  ctime are unchanged; for a protected path it always re-reads and re-hashes (§6, 3: "never trust
  mtime or size for protected paths").
- **Always hashed.** A protected file over `hash_max_bytes` is hashed anyway, up to a separate bound
  (proposed 4 GiB); past it, the capture fails loudly rather than record it `unverified`.
- **Never excluded.** An exclude covering a protected path, or a directory above one, is refused
  when the protection is declared (decision 2026-11-01, row 82; §5.3).

### 3.3 Fail closed

A protected path whose outcome is `unknown` -- raced, unstable listing, unreadable -- cannot be shown
to be intact: `protected_path_unverifiable`, a violation (section 10 Q4). Hardlinks need nothing
special (a write through another name changes the content seen here); a symlink swapped in is a type
change (`no_write`); a rename over it changes inode and content. A write that leaves the bytes,
mode and owner as they were is not a violation: nothing was changed to exploit.

## 4. Generic flags (signals, never penalties)

Each names its paths and its evidence, and inherits the attribution of the records it came from.

| flag | from | evidence |
|---|---|---|
| `touches_tests` | a test path added, modified, removed, type changed | the paths |
| `tests_weakened` | a test file removed or emptied; net assertions removed; a skip or xfail marker added; a test function removed (4.1) | counts before and after, the marker lines |
| `edits_ci_config` | `.github/workflows/**`, `.gitlab-ci.yml`, `.circleci/**`, `Jenkinsfile`, `azure-pipelines.yml`, `.travis.yml` | the paths |
| `pytest_config_changed` | `pytest.ini`, `conftest.py` (anywhere), `tox.ini` `[pytest]`, `setup.cfg` `[tool:pytest]`, `pyproject.toml` `[tool.pytest*]` | the section's text change; `conftest.py` named apart (it is code run by the test runner) |
| `git_history_rewritten` | git's `git_history_rewritten` event (E12), and `git_reflog_rewritten` findings | the event; the reflog is evidence, not proof |
| `git_hook_changed` | git's `git_hook_*` findings | the hook, its target, executable bit |
| `new_executable_on_path` | a file or symlink added, or made executable, in a PATH directory the task declares (default: the usual bin directories, a venv's `bin/`) | the path, its mode |
| `writes_outside_workdir` | a change in the scope outside the declared workdir, less an allowlist (temporary and cache directories) | the paths; only meaningful with a scope wider than the workdir (section 10 Q7) |
| `privilege_changed` | caps, setuid/setgid/sticky, inode flags changed, on any file (5) | the values before and after |

### 4.1 `tests_weakened`, concretely

- **Test files**: path patterns per ecosystem (`test_*.py`, `*_test.py`, `tests/**`, `*.test.ts`,
  `*_test.go`, `*.spec.*`, ...) -- the receipt's rule, extended.
- **Content needed on both sides**: test files are claimed `BELAY_KEEP_STORE` (an implementation
  rule in `dispatch.c`, no format change) so a copy exists past the 64 KiB text threshold.
- **Counted per language, Python first** (section 10 Q5): assertions (`assert`, `self.assert*`,
  `pytest.raises`, `pytest.approx` uses, `np.testing.assert_*`); markers (`@pytest.mark.skip`,
  `skipif`, `xfail`, `@unittest.skip*`, `pytest.skip(`, `pytest.xfail(`); test functions
  (`def test_*`, `class Test*` methods). JavaScript/TypeScript, Go, Rust next.
- **Reported, not judged**: the counts before and after and the added marker lines. Section 8 shows
  why the raw rule "an assertion line was removed" is useless (it fires on ordinary expectation
  updates), and why a count, though quiet, is gameable (a strong assertion replaced by a trivial one
  keeps the count): both say "signal", and the task's protected paths are what a grader penalises.

## 5. Never-suppressible metadata (decided 2026-10-30)

diff.v1 classifies caps, setuid/setgid and inode-flag changes as `metadata_only`; M2 flags every
one as `privilege_changed`, and no filter -- receipt folding, a policy allowlist -- may hide it. For
an added or removed file the diff record carries no mode (values only for changed fields, pin V1),
so the policy pass reads the manifests themselves, as belay's own text receipt already does
(`src/cli/receipt.c`, `privilege()`).

## 6. The in-sandbox protocol (§6)

For when no host reader exists (M3 builds one: §6, 1 prefers it). Each step, and what it defends:

1. **At reset, before the policy runs**: `belay baseline export` with a binary from outside; the
   bundle and its digest leave the sandbox. *Defends*: a baseline the policy wrote.
2. **After the episode, stop the policy first**: every process of the episode killed (the
   orchestrator's job -- a cgroup freeze and kill, or the PID namespace torn down); belay's own
   docs say what "first" means and why. *Defends*: belay's known limit (a process of the same user
   redirecting its writes while it scans, `docs/cli.md`): with no such process left, the limit is
   empty.
3. **Inject a fresh binary**: the orchestrator copies in a release binary whose sha256 it checks
   against the attested SHA256SUMS (as done for v0.1.0-alpha.2: `gh attestation verify`), never one
   left in the sandbox. Static: `LD_PRELOAD` does not apply. *Defends*: a patched scanner.
4. **Scan with nothing trusted**: `belay verify --baseline BUNDLE` reads every file (no prefilter:
   the final capture is a `check`), hashes protected paths whatever their size, and uses its own
   state directory created fresh outside the scope (a state directory the policy could have
   prepared is refused: the existing ownership and mode checks, plus "must not exist before").
   *Defends*: forged metadata, a prepared state directory.
5. **Judge against the bundle only**: package hashes from the bundle, expectations from the protect
   spec, never from the sandbox. *Defends*: a rewritten database.
6. **Report what was not seen**: excluded paths (none may cover a protected one), unknown entries,
   paths outside the scope -- in the policy header, never silent.

**Not covered** (§5.3, honest scope): in-code cheating that leaves no state, reads of hidden data,
network effects, anything outside the scope; a kernel or a container runtime the policy can
subvert.

## 7. Pins (each its own PR, a table, the author's OK before code)

- `test/expect/policy-flags.md`: every flag -- level, fields, evidence, text template -- like
  finding-kinds.md.
- `test/expect/protect-spec.md`: the spec's keys, glob semantics, modes.
- `test/expect/baseline-bundle.md`: the bundle's layout and digest.
- `policy.v1` itself: header, flag record and trailer, as diff.v1's spec is generated from a schema.

## 8. What the dogfood receipts say about false positives

**Method.** The turn receipts of real sessions in `~/.local/state/belay/dogfood/` (scripted
selftest sessions excluded): 14 turns, 10 with changes, 264 call sections with changes; and, for
`tests_weakened`, the 30 commits since dogfooding began that touched `test/`,
`scripts/dogfood/selftest.sh` or `scripts/e2e.sh` (`git show -U0`, counting assertion macros and
`SKIP(` on added and removed lines). Every change in them was ordinary, legitimate agent work on
belay itself. One repository (C, no Python tests), one agent: these say where the noise comes from,
not what the rates will be on RL tasks.

| would-be flag | how often (legitimate work) | reading |
|---|---|---|
| any `.git/` path touched | 111 of 264 calls (42%) | git's bookkeeping: flags must key on git's events, never on `.git/` paths |
| `touches_tests` | 52 calls (20%); 5 of 10 turns | normal coding edits tests: a signal, as §5.3 says |
| a test file modified or removed | 42 calls (16%); 1 removal | likewise |
| `tests_weakened`, raw "an assertion line was removed" | 7 of 30 commits (23%) | all expectation updates (an assertion replaced): useless as a rule |
| `tests_weakened`, "net assertions removed" | 0 of 30 | quiet here, but gameable (4.1) |
| `tests_weakened`, "a skip marker added" | 2 of 30 | both legitimate platform skips (macOS, a docker seccomp): the marker text must be in the evidence |
| `git_history_rewritten` (reset, amend, rebase in the reflog) | 18 calls (7%) | the PR workflow rebases constantly: a signal; for RL tasks with no git workflow it means more |
| `privilege_changed`, `git_hook_changed`, `edits_ci_config` | 0 | no false positives, and no positives either: no evidence of precision |

Two lessons beyond counts:

- **Attribution is part of a flag.** The receipts show writes no tool call made -- VS Code writing
  `branch.<b>.vscode-merge-base` into `.git/config` between calls -- and a gap where the hooks were
  inactive, now labelled "unattributed" (decision 122). A flag on such a change must say so, or a
  grader blames the agent for its editor.
- **Measure precision where it matters.** None of the strong signals (privilege, hooks, startup
  hooks, protected paths) fired here because nothing hostile happened; their false-positive rate on
  clean runs, and their recall on hacks, are M3's measured run (§9).

## 9. Build order, tests, reviews

1. Pins (section 7), author's OK.
2. Integrity (2): bundle export, dpkg and pip checks. Adversarial tests: an installed file edited;
   edited and its RECORD row forged too; md5sums forged; a file deleted; mtime restored after an
   edit (ctime still moves; the final scan hashes anyway).
3. Protected paths (3): capture changes (prefilter, hashing, excludes) with an independent review;
   tests: same-size same-mtime rewrite, symlink swap, rename over, hardlink write, raced protected
   file, an exclude refused.
4. Generic flags (4, 5): Python first; the dogfood corpus and the 30 commits above as a
   false-positive regression set.
5. The in-sandbox protocol (6): a docker harness that runs a hostile "policy" (rewrites a database,
   prepares a state directory, leaves a process running) and shows each step stopping it.
6. A separate author models policy.v1 from the pins (the oracle's role); canaries for every rule.

## 10. Questions for the author (with a recommendation each)

1. **A separate command and format** (`belay verify`, `policy.v1`) rather than flags inside
   diff.v1? Recommend: separate.
2. **Packages changed during the episode**: signal by default, violation with `frozen_packages`?
   Recommend: yes, both.
3. **MD5 at reset** to verify the baseline against dpkg's own hashes, sha256 afterwards? Recommend:
   yes; a pre-existing mismatch is reported at export, never as an episode flag.
4. **Fail closed on protected paths**: `unknown` there is a violation? Recommend: yes.
5. **`tests_weakened` languages**: Python first, then JS/TS, Go, Rust? Recommend: Python first (RL
   testbeds are mostly Python).
6. **New signals** beyond §5.3's list: `python_startup_hook_added`, `git_hook_changed`,
   `conftest.py` named apart, `conffile_changed`. Recommend: add all four.
7. **`writes_outside_workdir`** needs a scope wider than the workdir: only with the host reader
   (M3) or a root-scoped in-sandbox scan, with a task-declared allowlist? Recommend: yes; until
   then the flag is not emitted, and the policy header says so.
8. **Exit code**: 1 on any violation, signals never? Recommend: yes.
9. **Who models policy.v1**: the oracle's author extended, or a new separate author? Recommend: a
   new one (the policy rules are a different reading job, and independence is the point).
10. **The forced-hash bound for protected files** (proposed 4 GiB, failing loudly past it)?
