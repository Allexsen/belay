# Pin: which inode-flag changes are a privilege change

**What this is.** One rule for when a change to an entry's inode flags (`iflags`) counts as a
privilege change, applied wherever belay says so: the protect spec's `no_write` (PS-M1 in
`protect-spec.md`), policy.v1's `privilege_changed` (`policy-v1.md`) and the receipt's privilege
section (docs/cli.md, "The receipt"). It amends those texts with exactly the rows below; everything
not listed here is as they say. The protect spec stays version 2 and `belay_policy` stays 1
(author, 2026-11-10): the change only removes reports that were false.

**Why.** ext4 sets a directory's hashed-index flag by itself when the directory outgrows one
block. belay recorded that as an inode-flag change and called it a privilege change. Under a spec
with `tests/**` as `no_write`, creating 450 files in `tests/` made `verify` report
`protected_path_written` on `tests` and exit 1 (reproduced on v0.1.0-alpha.6).

**Measured** (2026-11-10, ext4, v0.1.0-alpha.6; inode-flag changes on entries present at both ends
of a pair of checkpoints):

| Workload | Entries compared | Changes | Which |
|---|---|---|---|
| 2,789 stored checkpoints of belay's own repository, each against the next | 10,990,360 | 0 | |
| `npm install eslint typescript jest` into a `node_modules` holding one package | 8,402 | 1 | directory `node_modules`: hashed index set |
| `pip install` of nine packages into a fresh virtualenv | 4,341 | 0 | |

No change to a regular file's inode flags was seen. Entries added in the same workloads carried
ext4's extents flag (15,276 regular files, 1,698 directories) and, on six new directories, the
hashed-index flag: what decision 171 already leaves out for added files.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

| id | rule |
|---|---|
| IF-1 | The **locking flags** are immutable and append-only: Linux `FS_IMMUTABLE_FL`, `FS_APPEND_FL`; macOS `UF_IMMUTABLE`, `SF_IMMUTABLE`, `UF_APPEND`, `SF_APPEND` (policy-v1's list). |
| IF-2 | **A directory at both ends:** a change to its `iflags` counts only when a locking flag is set or cleared. Any other change to a directory's flags does not count. |
| IF-3 | **An entry added or removed**, of any type: its `iflags` count only when they hold a locking flag. policy-v1 says this of `privilege_changed` today (decision 171); this row makes it the rule in the receipt too. |
| IF-4 | **Any other entry at both ends** (a regular file, a symlink, a device): every change to its `iflags` counts, as today. An entry whose type changed is not under IF-2: it is `type_changed`, judged as today. |
| IF-5 | **Flags read on one side only** are not a change that counts. The diff's outcome stays `unknown`, reason `iflags_unknown`, and PS-M5 reports a protected path as unverifiable, as today. `privilege_changed` no longer reports `none` against a value for such an entry. |
| IF-6 | **PS-M1.** `metadata_only` with `iflags` in `changed` is a `no_write` violation only when the change counts by IF-2 or IF-4. When another of `mode`, `uid`, `gid`, `caps`, `xattrs` is also in `changed`, it is a violation as today, and the flag's `changed` field lists what the diff lists. |
| IF-7 | **`privilege_changed`** has no record with `what` `iflags` for a change that does not count. |
| IF-8 | **The receipt** names inode flags in its privilege section only for a change that counts, an added or removed entry included (IF-3). A change that does not count is still shown: the record stays among the other changes, as `metadata_only`. |
| IF-9 | **Nothing is hidden and no format changes.** The manifest records `iflags` as before; diff.v1 lists `iflags` in `changed` and the outcome is `metadata_only` as before. Only what is called a privilege change, and so a violation, changes. A bundle is unaffected. |

## Example

A spec `{"path": "tests/**", "mode": ["no_write"]}`; 450 files are created in `tests/`; ext4 sets
the directory's hashed-index flag.

- diff.v1, unchanged: `{"path":"tests","outcome":"metadata_only","changed":["iflags"],...}`.
- Before this pin: `protected_path_written` (violation) and `privilege_changed` (signal) on `tests`.
- With it: neither. `chattr +i tests` still gives both.
