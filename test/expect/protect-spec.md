# Pin: the protect spec

**What this is.** What a task declares about its scope for `belay verify` and `belay baseline
export`: which paths must stay as they were, which file must hold which bytes, whether installed
packages are frozen, where its executables live. Read from the task package, never from the
environment being judged (BELAY_DESIGN §6, 4). Written by hand from the M2 structure the author
approved on 2026-11-03 (decisions 145-150), before any code (decision 151); approved by the author
2026-11-03 with the dot-segment rule added to PS-P4 (decision 157) and the hashing bound (Q10,
decision 159).

**Changing it.** In its own PR, presented as a table, after the author's explicit OK. A key added
later is one every earlier reader refuses (PS-R2), so a spec is never half-understood; changing a
key's meaning is `belay_protect` 2.

## The file

| id | key | type | value | when |
|---|---|---|---|---|
| PS-1 | `belay_protect` | int | `1`. A reader refuses any other value. | required |
| PS-2 | `protect` | array of rule objects (PS-3 to PS-5) | At most 4,096 rules, in any order; an empty array protects nothing. | required |
| PS-3 | rule: `path` | string | A pattern (Patterns, below). | required |
| PS-4 | rule: `mode` | array of strings | Each of `no_write`, `no_delete`, `no_create` at most once, in any order (Modes, below). | optional, default `[]`; a rule with neither a mode nor `expected_sha256` is refused |
| PS-5 | rule: `expected_sha256` | string | 64 lowercase hex digits: the bytes the file must hold after the episode (PS-M4). | optional; only in a rule whose pattern has no `*` |
| PS-6 | `frozen_packages` | bool | `true`: the task declares installed packages frozen, and a package changed or an installed file tampered with is a violation; `false`: those are signals (decision 146). | optional, default `false` |
| PS-7 | `path_dirs` | array of strings | Patterns naming the directories whose new executables `new_executable_on_path` reports (policy-v1.md). Given, it replaces the default: `bin`, `sbin`, `usr/bin`, `usr/sbin`, `usr/local/bin`, `usr/local/sbin`, and every directory `bin` beside a file `pyvenv.cfg` (a venv's). At most 256. | optional |

## Reading it

| id | rule |
|---|---|
| PS-R1 | One JSON object (RFC 8259), UTF-8, at most 1 MiB; nothing after it but whitespace. |
| PS-R2 | A key not in the table above, a key given twice, a value of another type, or one its row does not allow: the spec is refused, nothing is judged (exit 2). A misspelt key never silently drops a protection. |
| PS-R3 | Its digest is the sha256 of its bytes as read. policy.v1's header carries it; a bundle exported with a spec records its digest, and `verify` refuses a spec whose digest is not that one (exit 3): the protections are the same at both ends. |

## Patterns

| id | rule |
|---|---|
| PS-P1 | Relative to the scope, components separated by `/`; no leading or trailing `/`, no empty component, no `.` or `..` component; at most 4,096 bytes. Matched against a path's bytes, case-sensitively. |
| PS-P2 | A component `**` matches any number of whole components, none included: `tests/**` matches `tests` and every path below it. |
| PS-P3 | In any other component, `*` matches any run of bytes within that component, none included (`test_*.py`). No other character is special: `?`, `[` and `\` match themselves. |
| PS-P4 | A wildcard never matches a component starting with `.`: `tests/**` does not match `tests/.cache/x`. A component that itself starts with `.` matches one: `.github/workflows/**` matches `.github/workflows/ci.yml`, `tests/.cache/**` matches `tests/.cache/x`, and `.*` matches `.env`. Only `*` and `**` skip dot-names (decision 157; a test proves it). |
| PS-P5 | Matched against the paths of both manifests: the bundle's (before) and `verify`'s capture (after). Each mode says which side it reads. |

## Modes

| id | mode | a violation when (the flags: policy-v1.md) |
|---|---|---|
| PS-M1 | `no_write` | A path matched before, on both sides, whose outcome is `modified` or `type_changed`, or `metadata_only` with any of `mode`, `uid`, `gid`, `iflags`, `caps`, `xattrs` in `changed`: anything but timestamps (`mtime_ns`, `ctime_ns`) and identity (`ino`, `nlink`, `dev`). Bytes rewritten in place, through a rename over it or through a hard link elsewhere all show here; the same bytes, mode and owner written back are no change. `protected_path_written`. |
| PS-M2 | `no_delete` | A path matched before whose outcome is `removed`. `protected_path_deleted`. |
| PS-M3 | `no_create` | A path matched after whose outcome is `added`. `protected_path_created`. |
| PS-M4 | `expected_sha256` | The after manifest's entry at the path is not a regular file with that `sha256` (it is absent, of another type, or other bytes), whatever the baseline held: the task's ground truth (BELAY_DESIGN §6, 4). `protected_hash_mismatch`. |
| PS-M5 | fail closed | A path a rule matches, on a side its modes read, whose outcome is `unknown`, or whose entry there is `unverified`, `unstable`, `unreadable`, `raced` or a `mount`: it cannot be shown intact. `protected_path_unverifiable`, a violation, whatever the rule's modes (decision 147). |

## What a capture does for a protected path

| id | rule |
|---|---|
| PS-C1 | **Never trusted by mark's shortcut** (decision 147). Both captures `verify` judges read every file: the bundle's manifest is a full `check` (baseline-bundle.md, B-4), and so is `verify`'s own capture. Given `--to ID` and a spec, `verify` takes only a checkpoint that trusted nothing (its trailer's `trusted` is 0, manifest-v2 V2-4) and refuses any other (exit 3). The manifest does not say which files were trusted, and it stays as it is, so a checkpoint that trusted any file is not used. |
| PS-C2 | **Never excludable** (decision 147). An excluded path (a manifest header's `excluded`, any reason: an exclude, belay's state directory) covers a pattern when some path at or below it could match: its components, in order, matched by a leading part of the pattern (`**` taking any number). `baseline export` and `verify`, given a spec, refuse an exclusion that covers one of its patterns (exit 3), naming both. |
| PS-C3 | **Always hashed** (decision 147), up to 4 GiB (decision 159). A manifest holds a `sha256` only within its `hash_max_bytes` (manifest-v1, header rule 1), and the manifest stays as it is, so both captures made with a spec raise `hash_max_bytes` for the whole capture to the bound: every file within it is hashed, protected or not. A protected regular file larger than the bound is `unverified`, so `protected_path_unverifiable` (PS-M5); the capture is otherwise complete. The bound is 4 GiB (4,294,967,296 bytes). |

## Example

```json
{"belay_protect": 1,
 "protect": [{"path": "tests/**", "mode": ["no_write", "no_delete", "no_create"]},
             {"path": "grader/check.py", "mode": ["no_write"],
              "expected_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}],
 "frozen_packages": false}
```
