# Phase 4 (interpreters): structure proposal

Status: **APPROVED 2026-10-31 with the author's changes (section 7 supersedes where they differ)** (standing rule, BELAY_DESIGN.md §0.7). No
implementation code exists for it. 2026-10-30. Builds on the hook as S6 left it (commit 5963b9e:
`struct belay_interp` with begin/explain/end and per-diff state, the verdict and `content` in the
input, errors and invalid findings degraded per R11).

## 1. What Phase 4 must do (known requirements only)

- **Explain changes for M1's interpreters**: pip (`*.dist-info`), dpkg/apt (status deltas), git
  (refs, hooks, index), text (small stored files), binary (the fallback: declines -- size and hash
  are already in the record). npm, config and sqlite are M7. (§5.2, §9 M1.)
- **Findings never decide anything.** The outcome stays the core's (no field for it); an error is
  "could not interpret"; findings are bounded (16 per record, 255 bytes each) and valid UTF-8.
- **Content is attacker-controlled.** RECORD, dpkg `status` and git refs are written by the
  process being watched. Every parser must be bounded in memory and time, must not recurse on input,
  and must fail into "could not interpret", never a crash (fuzzed).
- **Both sides' content.** An interpreter compares before and after content, so the diff needs the
  stored copies (capture keeps them: dispatch.c claims dpkg status, pip RECORD and git refs/hooks
  as KEEP_STORE; small text files are kept by default). `belay_diff` takes only manifest paths
  today -- the store must reach it (open question 1).
- **Cross-path pairs.** A pip upgrade is a `name-OLD.dist-info` removal plus a `name-NEW.dist-info`
  addition: two paths. Per-diff state (S6) lets the second record of a pair carry the finding.
- **Determinism**: same inputs, same findings, byte for byte (no locale, no hash-order iteration).
- **Feeds M2**: integrity (`tampered_installed_package`) and the generic flags (`tests_weakened`,
  `git_history_rewritten`, ...) will consume interpreter output, and the never-suppressible metadata
  rule (caps, setuid/setgid, iflags) holds whatever an interpreter says.

Not in Phase 4: integrity against the baseline database and the flags themselves (M2), external
`.belayattributes` interpreters (M7), `mark` (Phase 5), the CLI's rendering of findings.

## 2. Modules (src/interp/), one job each

```
 diff.c ──> dispatch.c (path -> interpreter) ──> one of:
                                                  pip.c   dpkg.c   git.c   text.c   (binary: declines)
                 content.c (stored copies by hash, verified, bounded)  <── each interpreter
                 stanza.c / record_csv.c (bounded parsers, fuzzed)     <── dpkg.c / pip.c
```

| module | its one job | what it must not know |
|---|---|---|
| `dispatch.c` (exists) | Path -> interpreter id and what capture keeps. Adds the TEXT rule: unclaimed, and stored on both sides (question 6). | Content, outcomes. |
| `content.c` (new) | `belay_content_get(c, sha256_hex, max, &buf, &len)`: one stored object, read whole up to `max`, its sha256 checked against the name (verify-on-read); absent, too large or corrupt is an error the interpreter turns into a decline or "could not interpret". | What the bytes mean. |
| `stanza.c` (new) | dpkg control format (`Key: value`, continuation lines, blank-line stanzas): a streaming tokenizer over a buffer, fixed limits on field and stanza count. | Packages. |
| `record_csv.c` (new) | pip RECORD (CSV: path, hash, size): a streaming tokenizer, fixed limits. | Packages. |
| `pip.c` | From the dist-info path's name and version, and RECORD: installed, removed, upgraded/downgraded (paired through per-diff state), reinstalled with changed files ("RECORD changed: N files"). | dpkg, git. |
| `dpkg.c` | From the status file before and after: installed, removed, upgraded, held/half-installed state changes; over 15, the 16th finding is "and N more". | pip, git. |
| `git.c` | refs/heads, refs/tags, HEAD: created, deleted, moved (old..new hash); hooks: added, removed, changed, executable bit; index: changed. No object access (question 3). | Content of the worktree. |
| `text.c` | For a small stored text file: "+A -D lines" and the first changed hunk's header (question 2). | Formats. |
| `explain.c` (exists) | The table of built-ins (`belay_interp_builtin`). | -- |

Estimated size: content ~120 lines, stanza ~150, record_csv ~120, pip ~200, dpkg ~220, git ~180,
text ~200 (a bounded line diff: Myers on line hashes with a cap, else a count-only summary).

## 3. Interfaces

```c
/* content.c -- reaches the diff through belay_diff's options (question 1). */
struct belay_content;                              /* opaque: a store opened read-only */
int belay_content_get(const struct belay_content *c, const char *sha256_hex, size_t max,
                      unsigned char **buf, size_t *len);   /* 0, or -1: absent, too large,
                                                              not matching its name */

/* diff.h -- the store is optional; without one, content is NULL and every
 * content-reading interpreter declines. */
struct belay_diff_opts { const char *store_dir; };
int belay_diff_with(const char *before, const char *after, const char *out_path,
                    const struct belay_diff_opts *opts, struct belay_diff_stats *stats);

/* interp.h -- unchanged from S6: belay_interp {id, begin, explain(state, in, out), end};
 * belay_interp_input {path, before, after, outcome, changed, content}. */
```

Each interpreter is a `static const struct belay_interp` in its own file; `explain.c` lists them.
State is a struct private to the interpreter's file, allocated in `begin`, freed in `end`.

## 4. Defect classes the structure makes impossible

| class | how this structure closes it |
|---|---|
| **An interpreter hides or invents a change** | No outcome field (Phase 3); the verdict is read-only input. Unchanged paths never reach an interpreter. |
| **Hostile content crashes or stalls the diff** | Parsers are separate modules with fixed limits and no recursion, each with a fuzz target; content is read whole only up to `max`; every failure is "could not interpret" (R11, S6). |
| **A stale or swapped stored copy is explained as the file** | `content.c` checks every object's sha256 against the hash the manifest recorded; a mismatch is an error, never content. |
| **Invalid or unbounded output** | Findings are bounded and validated at emission (S6); "and N more" is the only way past 16. |
| **Non-deterministic findings** | Interpreters emit in input order (paths are sorted; stanzas in file order); no hash-table iteration reaches output; a test runs each fixture twice and compares bytes. |
| **Interface drift (Phase 3's B5)** | The interfaces above go into R9 contract tests (S7) before the interpreters are written. |

## 5. Proof standard

- Per interpreter: hand-written fixtures (RECORD files, status files, refs) and expected findings
  written from the format documentation, never from a run.
- Fuzz targets: `fuzz_stanza`, `fuzz_record_csv`, and one per interpreter over (before, after)
  content pairs, with invariants: no crash, findings within bounds, valid UTF-8, deterministic.
- A Python reference for dpkg and pip findings (separate author, from the format docs), compared on
  a generated corpus of status/RECORD pairs, with a coverage gate (as the diff oracle).
- The S3 generated-breakage campaign at the end of Phase 4 (decided): every finding kind has a
  canary killed by its named test.
- Bounded resources measured: the largest real `status` (~3 MB on a full Debian) and a 10k-line
  RECORD, time and peak memory.

## 6. Open questions for the author

1. **The store in the diff.** Proposal: `struct belay_diff_opts { store_dir }` and
   `belay_diff_with()`; `belay_diff()` stays as the no-store form. The alternative, changing
   `belay_diff`'s signature, is free pre-1.0 but touches every caller.
2. **Where a text change goes.** Findings are short strings, so a unified diff does not fit.
   Proposal: the finding is a summary ("+3 -1 lines; first change at line 42"); full patches are a
   later, separate output, opt-in.
3. **git without objects.** Commits, trees and packs are not captured, so "worktree vs HEAD" and
   commit counts are out of reach. Proposal for M1: refs created/deleted/moved with both hashes,
   HEAD changed, hooks added/removed/changed (and their executable bit), index changed.
   `git_history_rewritten` (M2) can be judged from a ref moving to a non-descendant only with
   object access: defer.
4. **The 16-finding cap.** A dpkg upgrade can change hundreds of packages. Proposal: 15 findings
   in package order, then "and N more"; the full list is a later, opt-in output.
5. **Pairs across paths.** Proposal: the second record of a pair carries the finding (the
   removal of `numpy-2.1.3.dist-info` sorts before the addition of `numpy-2.2.0.dist-info`, so the
   addition says "upgraded numpy 2.1.3 -> 2.2.0"; a downgrade is said on the removal). The
   alternative -- findings in the trailer, emitted by `end` -- changes diff.v1's shape.
6. **TEXT dispatch.** Proposal: an unclaimed path whose entry is stored on both sides is TEXT
   (capture stores only small text files by default); otherwise BINARY, which declines.
7. **Structured findings, before diff.v1 is published.** Findings are free text today. M2's flags
   and an RL reward helper (M3) want fields, not prose ("pkg_upgraded", name, from, to). diff.v1 is
   not published yet (§13a: forward compatibility undecided). Proposal: findings become objects
   `{"kind": "...", ...fields, "text": "..."}` with the kinds pinned per interpreter in
   test/expect/ -- decided now, before any interpreter emits one, and in the same decision as the
   forward-compatibility rule.
   *Recorded 2026-10-30 (BELAY_DESIGN.md §13a) as decided, pending the author's confirmation before
   diff.v1 is published: structured findings, and "consumers ignore unknown fields and unknown
   finding kinds; any change to an outcome's meaning requires a version bump". The proposal itself
   is not approved yet; no Phase 4 code.*

## 7. Approved 2026-10-31, with the author's answers and changes

- **Q1** `belay_diff(before, after, out, opts, stats)`: opts NULL means no store. One entry point.
- **Q2** text: kind `text_changed` {lines_added, lines_deleted, first_changed_line}; full patches later,
  opt-in. A file added or removed and stored on its one side: its line count.
- **Q3** git without objects, plus the reflog: `.git/logs/HEAD`, `.git/logs/refs/**` claimed
  KEEP_STORE (bounded by the store limit; declined above it). From the reflog delta, ref moves with
  git's own operation -- reset, commit (amend), rebase, anything but a plain commit or a
  fast-forward. Spec: the reflog is written by the watched process: evidence, not proof;
  host-reader mode is the trust answer.
- **Q4** diff.v1 carries every finding, up to 4,096 per record, then one final "and N more". The
  15-plus-"and N more" display is the CLI receipt's (Phase 5). Each finding's own size bounded.
- **Q5** path records carry path-level findings only. Package-level facts (installed, removed,
  upgraded, downgraded, reinstalled) are event records, emitted by each interpreter's end hook
  after all path records and before the trailer, each listing the paths it was derived from; dpkg
  likewise. Per-diff interpreter state bounded and measured on the largest real dpkg status.
- **Q6** TEXT: unclaimed and stored on both sides; otherwise BINARY (declines). Reconciled with Q2
  (implementer's reading, reported): unclaimed and stored on every side the path is present on.
- **Q7** confirmed (structured findings, forward-compat rule).
- Event records and the finding-kind pins are diff.v1 schema: defined in src/schema/, generated
  into the spec, gen-check. Interfaces into contract tests before the interpreters. Proof standard
  as proposed (fixtures from format docs, fuzz per parser and interpreter, separate-author Python
  reference for dpkg and pip with a coverage gate, S3 campaign at phase end, measured on a ~3 MB
  status and a 10k-line RECORD).
