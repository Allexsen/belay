# Pin: `belay watch`, version 1

**What this is.** What `belay watch` says and when: the lines it prints, what it flags and in what
order, the built-in list, the pattern dialect of that list and of `.belay-donttouch`, the lines for
a record that could not be kept, how a summary counts, and its time limits. It is written before
`belay watch` exists, from the structure the author approved on 2026-11-10. Nothing here takes
effect until that code does. The record's files and their pruning are `state-retention-watch.md`;
inode flags are `inode-flags.md`.

**Its claim.** It catches careless changes: what an agent, a tool it ran or an install did to a
directory without saying. It does not hold against a process running as the user that attacks
belay's state, its lock or its commands.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## Measured

2026-11-10, ext4, belay v0.1.0-alpha.7, git 2.43.0, npm 9.2.0, pnpm 10.34.7, Python 3.12.3. A
throwaway harness outside the tree ran 20 workloads in fresh directories, one command a step, as
one tool call would be: a checkpoint before, `belay mark` after each command, `belay diff` between
the two. 47 steps, 76,967 changed entries. Three candidate lists were applied to the same recorded
diffs with a model of the dialect below:

- **A**: the list of the draft plugin (PR #125) under its rule, a name with no slash matching at any depth.
- **B**: the rows below without BR-L2 and BR-L3.
- **C**: the rows below as pinned, with their limits and the quiet level (FL-2).

A step is "flagged" when its line would carry the red circle.

| Steps | Count | Changed entries | Flagged under A | under B | under C | Noted only, under C |
|---|---|---|---|---|---|---|
| Installs, scaffolds, builds, test runs (npm, pnpm, pip, create-vite, create-next-app, django, pytest, make) | 27 | 75,479 | 9 steps, 68 entries | 6 steps, 11 entries | **2 steps, 2 entries** | 0 |
| Git operations (init, clone, branch, commit, amend, fetch, stash, rebase, gc, remote add, config, submodule add) | 14 | 647 | 8 steps, 33 entries | 8 steps, 20 entries | **4 steps, 11 entries** | 3 steps |
| Installing a hook manager (husky, pre-commit, lefthook): flags are the point | 6 | 841 | 3 steps, 24 entries | 3 steps, 24 entries | 3 steps, 23 entries | 0 |

What is still flagged under C, in the 41 steps where no flag was the aim:

| Step | Flagged | Why it is left |
|---|---|---|
| `pip install -U pip setuptools wheel` | `site-packages/distutils-precedence.pth` added | It does run at every Python start. |
| `pip install -e .` | `site-packages/__editable__.demo-0.1.pth` added | The same. |
| `git clone` of a repository | its `.devcontainer` (3 entries) and `.pre-commit-config.yaml` | What the cloned repository carries. |
| `git submodule add` | `.gitmodules`, and the same 4 entries of the submodule | The same. The parent's `.git/config`, modified, is noted. |
| `git commit --amend`; `git rebase` | history rewritten | They do rewrite it. 2 of 14 git steps. |

Noted, without the red circle: `.git/config` modified by `git checkout -b x origin/main`,
`git remote add` and `git config user.name` (3 of 14 git steps), and beside the flags of
`git submodule add` and `husky init`. Without the quiet level each of the three was a flagged
step (author, 2026-11-10: it fires on routine work).

**What Claude Code writes under `.claude/` itself** (2.1.322, a scratch project): a `claude -p`
session that wrote, ran and edited files wrote nothing there. An interactive session in manual
mode with three permission prompts, a subagent and an edit wrote one file,
`.claude/settings.local.json`, when a prompt was answered "Yes, and don't ask again"; the other
two answers and the subagent wrote nothing. So that file is its own row, noted (BR-17).

What A and B flagged and C does not:

- **CI files below the top** (A only; BR-P2): 26 `.travis.yml` and 37 entries of `.github/workflows`, inside `node_modules` packages and cloned repositories.
- **In dependencies** (A and B; BR-L2): `cacert.pem` in every virtualenv (certifi, and pip's own copy), 4 entries; `tornado/test/test.key`; two `.yarnrc.yml` inside jupyterlab.
- **A new repository's own files** (A and B; BR-L3): `.git/config` and `.git/info/exclude` added by `git init`, `git clone`, `git submodule add` and `create-next-app`: 7 entries in 4 steps.
- **`.gitattributes`** (A only; 6 entries), which runs nothing by itself (left out, below).

No step in any workload changed a privilege bit, set a locking inode flag, or replaced a file with
a symlink. `belay mark` after a step took 0.036 s at the median (2,167 entries) and 0.88 s at most
(18,975 entries, after `create-next-app`).

**Matching time**, with the matcher of `src/policy/protect.c` copied and both switches on:

| Case | Time |
|---|---|
| The rows below (65 when measured) against the 67,144 distinct paths the workloads changed | 0.26 s, 0.004 ms a changed path |
| The same paths against 256 ordinary user patterns (`**/dir/**/*.ext`) | 1.3 s, 0.02 ms a path |
| The worst the limits of DT-4 allow, on ordinary paths: 256 patterns of four `**`, each before a component that scans every name to its end | 0.05 ms a path |
| The same patterns on paths of 3,839 bytes in 15 components of 255 bytes | 26 ms a path |
| 256 patterns of four `**` on paths of 2,000 one-byte components | 8.4 ms a path |

So a list written to be slow, in a directory holding paths near the system's limit, reaches the
45 s deadline at about 1,750 changed entries in one step. That is TL-5's line, not silence.

## The dialect

| id | rule |
|---|---|
| WD-1 | A pattern is the protect spec's (PS-P1 to PS-P3 of `protect-spec.md`): relative, components separated by `/`, `**` any number of whole components, `*` any run of bytes within one. PS-P4 does not apply: `*` and `**` match names that start with a dot. |
| WD-2 | A pattern that matches a directory covers everything below it: `migrations` covers `migrations/0001.py`, `.claude` covers all that is in it. |
| WD-3 | A pattern starts at the top of the watched directory: `*.lock` is the top level only, `**/*.lock` any depth. |
| WD-4 | Paths are matched as bytes. A user's pattern is case-sensitive. A built-in row is matched ASCII-case-insensitively; its exceptions are case-sensitive. |
| WD-5 | The protect spec is untouched: version 2, with PS-P4, by the same matcher with both switches off. |
| WD-6 | `belay watch patterns` prints the list in force and how many current entries each pattern matches, and marks one that matches nothing. |

## What is flagged, and the order

| id | rule |
|---|---|
| FL-1 | **Flagged**: the line carries the red circle and names the entry first. Every kind below is flagged unless FL-2 says otherwise. |
| FL-2 | **Noted**, the quiet level: the entry is named at the front of the line, after anything flagged, with its reason, and brings no red circle. Only a built-in row can note, and only where its limit says so (BR-L5, BR-L6). Reading a file's keys to flag the dangerous ones is not in this version. |
| FL-3 | A user's pattern always flags. Every line of "The record could not be kept", below, is flagged. |

A flag or a note has a kind and a reason. They are named in this order of kind, one of each kind
before a second of any (LN-4).

| id | kind | when | the reason shown |
|---|---|---|---|
| FK-1 | don't-touch | The path matches the list in force (DT-1), or is `.belay-donttouch` at the top. | `don't-touch` |
| FK-2 | git hooks and config | A built-in row of that kind matches. | the row's label |
| FK-3 | agent rules | likewise | the row's label |
| FK-4 | privilege | setuid, setgid, sticky, capabilities; inode flags as `inode-flags.md` counts them. | `privilege` |
| FK-5 | loads on its own | A built-in row of that kind matches. | the row's label |
| FK-6 | package source | likewise | the row's label |
| FK-7 | CI | likewise | the row's label |
| FK-8 | credentials | likewise | the row's label |
| FK-9 | replaced by a symlink | The entry was not a symlink and is one now. A new symlink is not flagged by where it points, and a retargeted one is not flagged. | `replaced by a symlink` |
| FK-10 | history | The diff's `git_history_rewritten` event. | `history` |
| FK-11 | could not be read | Outcome `unknown` on a path FK-1 to FK-8 would flag. | `could not be read` and the first reason |
| FK-12 | coverage | CV-1 to CV-3. | CV's text |

An entry is flagged once, by the first kind in this order that applies, and within the built-in
list by the first row. Flags come from the manifests' fields, never from parsing the receipt's
text.

## The built-in list

A row is here because a change to a match is rarely the task itself, and either runs code nobody
asked to run, decides where code comes from, or holds a credential. Each row says what was run to
check that its tool honours it. A row marked **not verified** is included by name, as the author
decided (2026-11-10): its tool could not be run here, and its behaviour is from the tool's
documentation.

Limits a row may carry:

| id | limit | meaning |
|---|---|---|
| BR-L1 | not a directory | The row flags only an entry that matches it and is not a directory. A directory that matches covers nothing below it (so a virtualenv named `.env` is not "credentials"). |
| BR-L2 | not in a dependency | The row does not apply at or below a directory named `node_modules` or `site-packages`, at any depth. What a package ships inside itself is the package's content: npm does not read a dependency's `.npmrc` (probed), and an install would otherwise be flagged for every package that ships its own CI or test keys. |
| BR-L3 | not in a new directory | The row does not flag an entry that is added when the directory it is in is added in the same step: a new repository's `config` and `info/exclude` are git's own. A change to one that was there, or one added to a directory that was there, is flagged. |
| BR-L4 | except PATTERN | The row does not apply to a path the exception matches or that lies below its match. |
| BR-L5 | noted when modified | A match whose outcome is `modified` is noted (FL-2), not flagged. Added, removed, type changed or metadata changed, it is flagged. So `git config core.hooksPath` on an existing repository is noted, like `git config user.name`: the file's keys are not read. |
| BR-L6 | noted | Every match is noted, not flagged. |

| id | kind | label | pattern | limits | probed |
|---|---|---|---|---|---|
| BR-1 | git hooks and config | git hook | `**/.git/hooks` | not a directory | `.git/hooks` replaced by a symlink to a directory holding `pre-commit`; `git commit`: ran |
| BR-2 | git hooks and config | git hook | `**/.git/hooks/*` | not a directory; except `**/*.sample` | an executable `pre-commit`; `git commit`: ran |
| BR-3 | git hooks and config | git hook | `**/.git/modules/**/hooks/*` | not a directory; except `**/*.sample` | `pre-commit` there; a commit inside the submodule: ran |
| BR-4 | git hooks and config | git config | `**/.git/config` | not a directory; not in a new directory; noted when modified | `core.hooksPath`; `git commit`: the hook there ran |
| BR-5 | git hooks and config | git config | `**/.git/config.worktree` | not a directory; not in a new directory; noted when modified | `core.hooksPath`: honoured with `extensions.worktreeConfig`, not without |
| BR-6 | git hooks and config | git config | `**/.git/worktrees/*/config.worktree` | not a directory; not in a new directory; noted when modified | `core.hooksPath`; a commit in that worktree: the hook ran (with `extensions.worktreeConfig`) |
| BR-7 | git hooks and config | git config | `**/.git/modules/**/config` | not a directory; not in a new directory; noted when modified | `core.hooksPath`; a commit inside the submodule: the hook ran |
| BR-8 | git hooks and config | git exclude list | `**/.git/info/exclude` | not a directory; not in a new directory | a file listed there is no longer shown by `git status` |
| BR-9 | git hooks and config | git attributes | `**/.git/info/attributes` | not a directory; not in a new directory | `* filter=x` with the filter defined in `.git/config`; `git add`: the filter's command ran |
| BR-10 | git hooks and config | git submodules | `**/.gitmodules` | not a directory | the `url` changed; `git submodule sync` and `update --remote`: fetched from the new place |
| BR-11 | git hooks and config | git hook manager | `**/.husky` | not in a dependency | husky 9.1.7: `.husky/pre-commit`; `git commit`: ran |
| BR-12 | git hooks and config | git hook manager | `**/.pre-commit-config.yaml` | not a directory; not in a dependency | pre-commit 4.7.0, after `pre-commit install`; `git commit`: its command ran |
| BR-13 | git hooks and config | git hook manager | `**/lefthook.yml` | not a directory; not in a dependency | lefthook 2.2.2, after `lefthook install`; `git commit`: its command ran |
| BR-14 | git hooks and config | git hook manager | `**/lefthook.yaml` | not a directory; not in a dependency | as `lefthook.yml`: ran |
| BR-15 | git hooks and config | git hook manager | `**/.lefthook.yml` | not a directory; not in a dependency | as `lefthook.yml`: ran |
| BR-16 | git hooks and config | git hook manager | `**/.lefthook.yaml` | not a directory; not in a dependency | as `lefthook.yml`: ran |
| BR-17 | agent rules | agent permissions | `.claude/settings.local.json` | not a directory; noted | Claude Code 2.1.322 wrote it itself when a permission prompt was answered "Yes, and don't ask again" |
| BR-18 | agent rules | agent rules | `.claude/*` | except `.claude/worktrees` | Claude Code 2.1.322: a `SessionStart` hook in `.claude/settings.json` ran under `claude -p` |
| BR-19 | agent rules | agent rules | `**/CLAUDE.md` | not a directory; not in a dependency | Claude Code 2.1.322: read at the top of the directory. Below the top: **not verified** |
| BR-20 | agent rules | agent rules | `**/CLAUDE.local.md` | not a directory; not in a dependency | Claude Code 2.1.322: read at the top of the directory. Below the top: **not verified** |
| BR-21 | agent rules | agent rules | `**/AGENTS.md` | not a directory; not in a dependency | **not verified** (no tool that reads it is installed here) |
| BR-22 | agent rules | agent rules | `.mcp.json` | not a directory | Claude Code 2.1.322: the server's command ran under `claude -p`; `claude mcp list` shows it as pending approval |
| BR-23 | agent rules | agent rules | `.cursor` | -- | **not verified** (Cursor is not installed here) |
| BR-24 | agent rules | agent rules | `.cursorrules` | not a directory | **not verified** (Cursor is not installed here) |
| BR-25 | agent rules | agent rules | `.github/copilot-instructions.md` | not a directory | **not verified** (Copilot is not installed here) |
| BR-26 | loads on its own | runs on entering the directory | `**/.envrc` | not a directory; not in a dependency | **not verified** (direnv is not installed here) |
| BR-27 | loads on its own | editor runs it | `**/.vscode/tasks.json` | not a directory; not in a dependency | **not verified** (no way to run it here) |
| BR-28 | loads on its own | editor settings | `**/.vscode/settings.json` | not a directory; not in a dependency | **not verified** (no way to run it here) |
| BR-29 | loads on its own | editor runs it | `**/.vscode/launch.json` | not a directory; not in a dependency | **not verified** (no way to run it here) |
| BR-30 | loads on its own | container setup | `**/.devcontainer` | not in a dependency | **not verified** (no way to run it here) |
| BR-31 | loads on its own | container setup | `**/.devcontainer.json` | not a directory; not in a dependency | **not verified** (no way to run it here) |
| BR-32 | loads on its own | runs at every Python start | `**/site-packages/*.pth` | not a directory | a line starting `import`, in a virtualenv; `python -c pass`: ran. Not run from the working directory |
| BR-33 | loads on its own | runs at every Python start | `**/site-packages/sitecustomize.py` | not a directory | **not verified**: not run on this machine, where Ubuntu's own `sitecustomize.py` is found first |
| BR-34 | loads on its own | runs at every install | `**/.pnpmfile.cjs` | not a directory; not in a dependency | pnpm 10.34.7; `pnpm add`: ran |
| BR-35 | package source | package source | `**/.npmrc` | not a directory; not in a dependency | `registry=`: honoured by npm 9.2.0 and pnpm 10.34.7, also in a subdirectory with its own `package.json`; not read from a dependency's directory |
| BR-36 | package source | package source | `**/.yarnrc` | not a directory; not in a dependency | yarn 1.22.22: `registry` honoured |
| BR-37 | package source | package source | `**/.yarnrc.yml` | not a directory; not in a dependency | **not verified** (yarn 2 or later is not installed here) |
| BR-38 | package source | package source | `**/pip.conf` | not a directory; not in a dependency | honoured at a virtualenv's root; not in the working directory |
| BR-39 | package source | package source | `**/.cargo/config.toml` | not a directory; not in a dependency | **not verified** (cargo is not installed here) |
| BR-40 | package source | package source | `**/.cargo/config` | not a directory; not in a dependency | **not verified** (cargo is not installed here) |
| BR-41 | CI | CI | `.github/workflows` | -- | **not verified** (no way to run it here) |
| BR-42 | CI | CI | `.github/actions` | -- | **not verified** (no way to run it here) |
| BR-43 | CI | CI | `.github/CODEOWNERS` | not a directory | **not verified** (no way to run it here) |
| BR-44 | CI | CI | `CODEOWNERS` | not a directory | **not verified** (no way to run it here) |
| BR-45 | CI | CI | `docs/CODEOWNERS` | not a directory | **not verified** (no way to run it here) |
| BR-46 | CI | CI | `.github/dependabot.yml` | not a directory | **not verified** (no way to run it here) |
| BR-47 | CI | CI | `.github/dependabot.yaml` | not a directory | **not verified** (no way to run it here) |
| BR-48 | CI | CI | `.gitlab-ci.yml` | not a directory | **not verified** (no way to run it here) |
| BR-49 | CI | CI | `.circleci` | -- | **not verified** (no way to run it here) |
| BR-50 | CI | CI | `Jenkinsfile` | not a directory | **not verified** (no way to run it here) |
| BR-51 | CI | CI | `azure-pipelines.yml` | not a directory | **not verified** (no way to run it here) |
| BR-52 | CI | CI | `.travis.yml` | not a directory | **not verified** (no way to run it here) |
| BR-53 | credentials | credentials | `**/.env` | not a directory; not in a dependency | by name; nothing to run |
| BR-54 | credentials | credentials | `**/.env.*` | not a directory; not in a dependency | by name; nothing to run |
| BR-55 | credentials | credentials | `**/*.pem` | not a directory; not in a dependency | by name; nothing to run |
| BR-56 | credentials | credentials | `**/*.key` | not a directory; not in a dependency | by name; nothing to run |
| BR-57 | credentials | credentials | `**/*.p12` | not a directory; not in a dependency | by name; nothing to run |
| BR-58 | credentials | credentials | `**/*.pfx` | not a directory; not in a dependency | by name; nothing to run |
| BR-59 | credentials | credentials | `**/id_rsa*` | not a directory; not in a dependency | by name; nothing to run |
| BR-60 | credentials | credentials | `**/id_ed25519*` | not a directory; not in a dependency | by name; nothing to run |
| BR-61 | credentials | credentials | `**/id_ecdsa*` | not a directory; not in a dependency | by name; nothing to run |
| BR-62 | credentials | credentials | `**/.ssh` | not in a dependency | by name; nothing to run |
| BR-63 | credentials | credentials | `**/.aws` | not in a dependency | by name; nothing to run |
| BR-64 | credentials | credentials | `**/.netrc` | not a directory; not in a dependency | by name; nothing to run |
| BR-65 | credentials | credentials | `**/.git-credentials` | not a directory; not in a dependency | by name; nothing to run |
| BR-66 | credentials | credentials | `**/.kube/config` | not a directory; not in a dependency | by name; nothing to run |

| id | rule |
|---|---|
| BR-P1 | No row's first component holds a `*` unless it is exactly `**`, when more components follow it. Checked by a test over the list. This is what makes CV-3 computable. |
| BR-P3 | `.claude` itself, added as a directory, matches no row; what is in it does. Replaced by a symlink it is FK-9. |
| BR-P2 | CI rows and the agent's directories are at the top only: a host runs the workflows of the repository's root. A repository below the watched directory is not covered by them, and its `.git` is, by the `**/.git` rows. |

Left out, and why:

| Path | Why |
|---|---|
| `.gitattributes` | Probed: alone it runs nothing. It takes effect only with a filter defined in a git config, and that file is a row. It changes in ordinary work (line endings, LFS). |
| `.pypirc` in the directory | Probed with twine 7.0.0: only `~/.pypirc` is read. |
| `sitecustomize.py`, `usercustomize.py`, `*.pth` outside `site-packages` | Probed: not run from the working directory. `usercustomize.py` is not run in a virtualenv. |
| `.vscode/extensions.json` | It recommends extensions and runs nothing. |

## `.belay-donttouch`

| id | rule |
|---|---|
| DT-1 | The list in force is read only from the checkpoint's stored, hash-checked copy of `.belay-donttouch` at the top of the directory. No file is an empty list. |
| DT-2 | One pattern a line, in the dialect above. A line starting `#` is a comment; blank lines are allowed. No exceptions and no limits: a pattern flags whatever it matches, whatever happens to it. |
| DT-3 | Invalid, said with its line number: a control byte other than NUL (so a CRLF line ending), a leading or trailing `/`, an empty, `.` or `..` component, and `?`, `[`, `\` or a leading `!`. A file that holds a NUL byte anywhere, a comment included, is not text: belay keeps no stored copy of it, so it cannot be read (TL-10: `no stored copy`), and no line number is given. |
| DT-4 | Limits: the file at most 64 KiB, 256 patterns, a pattern at most 4,096 bytes with at most four `**`. Past any of them the file is invalid. |
| DT-5 | A change to the file is itself flagged, kind don't-touch. In that step the old list and the new both apply; from the next step the new one. |
| DT-6 | An invalid file (`line N is not a pattern`, or the limit passed) and a file that cannot be read (no stored copy, which is also what a NUL byte in it gives; a writer has it open; it is under an exclude; it is not a regular file) are two different flagged lines (TL-9, TL-10). In both, the previous list stays in force until a valid file, or no file, replaces it. On a first step there is no previous list: the list in force is empty, and the line says so. |

## Coverage

| id | rule |
|---|---|
| CV-1 | A step is flagged when the two manifests' excluded sets differ. |
| CV-2 | Once per session, a line that is not flagged names what is not being read: excludes, mounts, unreadable directories. |
| CV-3 | A summary is flagged when such a path matches a row or a user's pattern, or lies below a match; and, for a row or pattern whose first component is not `**`, also when the path is an ancestor of something it could match. Limits BR-L1 to BR-L6 are ignored in this test, which can only flag more. So excluding `node_modules` is no alarm, and excluding `.claude/worktrees` is one at every Stop until the exclude goes. |

## The lines

Every line starts `belay: `. When anything in it is flagged, `🔴 ` follows at once, always in that
place. A line with notes only has none. Examples are in the last section.

| id | rule |
|---|---|
| LN-1 | **A step that changed nothing prints nothing.** A step that changed something prints one line. |
| LN-2 | A step with no call open at any time in its interval says `outside tool calls: ` after the prefix. |
| LN-3 | **A flagged or noted entry is named** as `PATH WORD (REASON)`. WORD is the outcome: `added`, `removed`, `modified`, `type changed`, `metadata changed`, `not compared`. FK-4: the receipt's privilege words stand in place of WORD. FK-9: `PATH replaced by a symlink`, with no parentheses. FK-10: the event's text in place of `PATH WORD`, its commit ids cut to seven characters. |
| LN-4 | **At most three entries are named**, joined by `; `: the flagged before the noted; within each, in FK's order, one of each kind before a second of any, and within a kind in path order. The rest are counted by kind: `; and N more flagged: 17 git hooks and config, 1 credentials`, then `; and N more noted: ...`. |
| LN-5 | **The entries neither flagged nor noted** follow ` · `. With flags or notes before them: `N more: ` and the counts. Alone: `N change(s): ` and, when N is three or fewer, each named as `PATH WORD` joined by `; `; otherwise the counts. |
| LN-6 | **The counts** are by outcome, in LN-3's order, zero left out: `7 added, 1 modified`. When more than three are counted and more than half lie under one top-level directory, ` (N under DIR/)` follows. |
| LN-7 | A path is shown as the receipt shows one (belay's escaping, so no control or bidirectional character reaches the line), cut in its middle with `…` past 80 characters. |
| LN-8 | A line is at most 64 KiB in the record; a flagged path is cut to fit and the cut ones are counted. |
| LN-9 | Every changed entry of a step is counted in exactly one place of its line. |

**A summary** (the Claude Code adapter prints it at a Stop, for the steps since the user's last message):

| id | rule |
|---|---|
| SM-1 | With nothing changed: `belay: nothing changed this turn`. |
| SM-2 | If anything was flagged in the span, first: `belay: 🔴 N flagged: ` and the flags as LN-3 and LN-4, over every step of the span. |
| SM-7 | If anything was noted in the span, next: `belay: N noted: ` and the notes likewise, with no red circle. |
| SM-3 | Then the totals: `belay: N changed this turn in K tool call(s)`, or `N changed this turn: A in K tool call(s), B outside tool calls`, then ` · full receipt: /belay:receipt`. |
| SM-4 | **N is the sum of the steps' counts.** A file changed in five steps is five. Nothing is recomputed from a diff across the span, so nothing made and undone across steps is hidden. |
| SM-5 | When another session's steps are among them, the totals line says ` (with another session's steps)`. A summary whose span began in a day file that has been pruned says ` (the record before DATE is gone)`. |
| SM-6 | The words `tool call`, `this turn` and the receipt command are the Claude Code adapter's. The agent-neutral commands take the word for a call from their caller. |

## The record could not be kept

Always a line, never silence. Each is flagged, and is repeated in every summary while its cause
lasts.

| id | cause | line, after `belay: 🔴 ` |
|---|---|---|
| TL-1 | A first step, unless the adapter says the session is starting | `recording starts here: nothing before HH:MM is accounted for` |
| TL-2 | The lock is not free by the deadline | `could not record: another belay holds this directory's lock` |
| TL-3 | Capture or diff failed | `could not record: ` and belay's message |
| TL-4 | The worker died by itself | `belay stopped unexpectedly while ` and the stage |
| TL-5 | Still capturing, or matching, at the deadline | `could not record in N s: ` and the stage |
| TL-6 | No answer after "go" by the second limit | `could not confirm the record` |
| TL-7 | Back-off (TM-3) | `not recording: capturing this directory takes longer than N s` |
| TL-8 | An attempt with no step line after it | `the previous step did not finish` |
| TL-9 | `.belay-donttouch` is invalid | `.belay-donttouch: line N is not a pattern` (or the limit passed), then `; the previous list stays in force` or `; no list is in force` |
| TL-10 | `.belay-donttouch` cannot be read | `could not read .belay-donttouch: ` and why, then as TL-9 |
| TL-11 | The cursor's checkpoint is gone or unreadable, others survive | `the record was interrupted: resuming from checkpoint K (HH:MM)` |
| TL-12 | No ledger line parses | `the record was interrupted: nothing before HH:MM is accounted for` |
| TL-13 | A step's section of the receipt is missing or fails its digest | in the receipt, in that step's place: `this step's section is missing` |
| TL-14 | The directory is `/`, `$HOME`, or one `$HOME` is inside | at a session's start only: `not watching DIR: too wide` |
| TL-15 | Calls or markers older than a day were dropped | `N calls of a session that ended without saying so were closed` |

The stages are `waiting for the lock`, `capturing`, `matching`, `rendering`.

## Time limits

| id | rule |
|---|---|
| TM-1 | **The deadline is 45 s**: the default of every `watch` command that captures, and the adapter's under Claude Code's 60 s hook timeout. Past it the worker is killed and TL-2 or TL-5 is printed. |
| TM-2 | **The second limit is 55 s.** The worker asks before it commits and waits for the answer; the answer is "go" or a kill, never both. After "go" nothing is killed: by 55 s without the worker's word, TL-6 is printed. |
| TM-3 | **Back-off after three.** Three steps of one session killed at the deadline in a row, and that session stops capturing: its steps print TL-7 and write nothing. A new session id starts afresh; nothing else clears it. |
| TM-4 | Calls and markers of a session that fires nothing for a day are dropped (TL-15). |

## Examples

```
belay: 1 change: a.txt modified
belay: outside tool calls: 2 changes: b.txt added; c.txt removed
belay: 714 changes: 714 added (713 under node_modules/)
belay: 🔴 .git/hooks/pre-push added (git hook) · 7 more: 7 added (5 under node_modules/)
belay: .git/config modified (git config) · 7 more: 3 added, 4 modified
belay: 🔴 .gitmodules added (git submodules); .git/config modified (git config) · 258 more: 258 added (254 under vendor/)
belay: 🔴 migrations/0001.py modified (don't-touch); .husky/pre-commit added (git hook manager); .env added (credentials); and 19 more flagged: 19 git hooks and config · 1 more: 1 modified
belay: 🔴 bin/tool setuid added (mode 0755 -> 4755) (privilege)
belay: 🔴 feature rewritten by commit (amend): c38c0d4 -> e487650 (history) · 6 more: 2 added, 4 modified
belay: 🔴 could not record in 45 s: capturing

belay: 🔴 1 flagged: .git/hooks/pre-push added (git hook)
belay: 1 noted: .git/config modified (git config)
belay: 8 changed this turn in 1 tool call · full receipt: /belay:receipt
belay: 42 changed this turn: 40 in 15 tool calls, 2 outside tool calls · full receipt: /belay:receipt
belay: nothing changed this turn
```
