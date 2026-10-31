# Pin: finding kinds (diff.v1)

**What this is.** Every kind of finding an interpreter may emit, written by hand for the author's
approval before any interpreter emits one (decision 2026-10-31, Q7). A finding is an object; a
consumer ignores a kind it does not know, and a field it does not know (the forward-compatibility
rule). Findings never decide an outcome.

**Changing it.** A change lands in its own PR, presented as a table, and waits for the author's
explicit OK. Removing a kind or changing a field's meaning is a diff.v1 version bump.

## The object

`{"kind": "<kind>", <fields, in the order listed>, "text": "<the template, filled>"}`

- `int` fields are non-negative integers; `string` fields are UTF-8, at most 1,024 bytes each;
  `bool` fields are `true` or `false`. A field absent from a kind's row never appears.
- A type ending in `?` is optional: absent exactly when the kind's meaning says. A kind whose
  optional fields may be absent gives a second template, used when any of them is (decision
  2026-10-31, c); no template names a field that may be absent from it.
- A `bytes` field is a byte string of at most 4,095 bytes (the manifest's link-target limit,
  addendum A4; an exception to the 1,024-byte limit): `"<name>": "..."` when it is valid UTF-8,
  else `"<name>_b64": "..."`, base64, as the manifest writes bytes (decision 2026-10-31, b).
- `text` is the row's template with each `{field}` replaced by its value, at most 1,024 bytes.
- A finding that breaks any of this -- an unknown kind, a missing or extra field, a value of the
  wrong type or over its bound, text that is not the template's -- is replaced by `invalid_finding`.
- `and_more`, `could_not_interpret` and `invalid_finding` are the core's (interpreter `core`): an
  interpreter that adds one has it replaced by `invalid_finding` (decision P5).
- A record carries at most 4,096 findings: past that, its 4,096th place is one `and_more` counting
  the findings from that place on, itself included (decisions Q4, P5). An event record
  (`diff-events.md`) is one finding.

## Kinds

`level`: `path` -- in a path record's `findings`; `event` -- an event record; `path, event` -- both.

| kind | interpreter | level | fields | text | meaning |
|---|---|---|---|---|---|
| could_not_interpret | core | path, event | -- | `could not interpret` | The interpreter failed on this path (R11), nothing else from it here; or, as an event, on the paths it names (diff-events E6, E10). |
| invalid_finding | core | path, event | -- | `invalid finding` | A finding that broke the rules above, replaced; or, as an event, an event that did (diff-events E9). |
| and_more | core | path, event | n: int | `and {n} more` | In the 4,096th place of a record past 4,096 findings, or the 65,536th of an interpreter's events past 65,536: the findings or events from that place on, itself included, counted. |
| content_unavailable | text, pip, dpkg, git | path, event | reason: string, side: string | `content unavailable ({side}): {reason}` | The interpreter needs the stored copy of a path it claims, on a side where the path exists, and cannot read it. reason: `no_store` (the diff was given no store), `missing`, `too_large` (over the interpreter's bound), `corrupt` (does not hash to its name). side: `before` or `after`, one finding per side. Never a silent decline (decision 2026-10-31). pip and dpkg, which emit events from that content, also emit one `content_unavailable` event per reason, with side `before` or `after` when all its paths share it, else `both`, naming the paths: a consumer never reads "no packages changed" where the change could not be read. |
| text_changed | text | path | lines_added: int, lines_deleted: int, first_changed_line: int | `+{lines_added} -{lines_deleted} lines, first change at line {first_changed_line}` | Stored on both sides. lines_deleted = before's lines minus the longest common subsequence of lines, lines_added = after's minus it; first_changed_line: 1-based, in before, the first line past the common prefix. |
| text_rewritten | text | path | lines_before: int, lines_after: int, first_changed_line: int | `rewritten: {lines_before} lines before, {lines_after} after, first change at line {first_changed_line}` | As text_changed, when the two differ in more than 2,000 lines (edit distance): the counts are not computed. |
| text_added | text | path | lines: int | `{lines} lines` | Added, stored. |
| text_removed | text | path | lines: int | `{lines} lines` | Removed, stored before. |
| pip_installed | pip | event | name: string, version: string | `installed {name} {version}` | A dist-info whose RECORD is added, no removed one of the same name. |
| pip_removed | pip | event | name: string, version: string | `removed {name} {version}` | A dist-info whose RECORD is removed, no added one of the same name. |
| pip_upgraded | pip | event | name: string, from: string, to: string | `upgraded {name} {from} -> {to}` | One removed and one added of the same name; to is higher by PEP 440 ordering. |
| pip_downgraded | pip | event | name: string, from: string, to: string | `downgraded {name} {from} -> {to}` | The same; to is lower. |
| pip_version_changed | pip | event | name: string, from: string, to: string | `{name} {from} -> {to}` | The same; the versions are equal by PEP 440, or one is not a PEP 440 version. |
| pip_reinstalled | pip | event | name: string, version: string, files_added: int?, files_removed: int?, files_changed: int? | `reinstalled {name} {version}: +{files_added} -{files_removed} ~{files_changed} files`; counts absent: `reinstalled {name} {version} (files not counted)` | The same dist-info on both sides, its RECORD changed: RECORD rows by path, changed = same path, different hash or size. When the RECORD's outcome is `unknown` (on both sides), the event is provisional and the three counts are absent (decision 2026-10-31, c). |
| dpkg_installed | dpkg | event | package: string, arch: string, version: string | `installed {package}:{arch} {version}` | `installed` after (the Status field's third word) and not before (no stanza, or another state). |
| dpkg_removed | dpkg | event | package: string, arch: string, version: string | `removed {package}:{arch} {version}` | `installed` before and not after. |
| dpkg_upgraded | dpkg | event | package: string, arch: string, from: string, to: string | `upgraded {package}:{arch} {from} -> {to}` | `installed` on both sides; to higher by Debian version comparison (`dpkg --compare-versions`). |
| dpkg_downgraded | dpkg | event | package: string, arch: string, from: string, to: string | `downgraded {package}:{arch} {from} -> {to}` | The same; to lower. |
| dpkg_state_changed | dpkg | event | package: string, arch: string, from: string, to: string | `{package}:{arch} {from} -> {to}` | The Status field differs and no installed or removed event covers the package (a hold, half-installed, config-files, ...); from or to empty where it has no stanza. Packages are keyed by Package and Architecture (empty when absent). |
| git_head_changed | git | path | from: string, to: string | `HEAD {from} -> {to}` | `.git/HEAD`: the symbolic ref or the commit it names. |
| git_ref_created | git | path | ref: string, to: string | `created {ref} at {to}` | A ref appeared (a loose ref, or a line of packed-refs). |
| git_ref_deleted | git | path | ref: string, from: string | `deleted {ref} (was {from})` | A ref went away. |
| git_ref_moved | git | path | ref: string, from: string, to: string | `{ref} {from} -> {to}` | A ref names another commit. |
| git_hook_added | git | path | hook: string, executable: bool?, target: bytes | `hook {hook} added` | A regular file or a symlink appeared (decision P3: git follows a symlinked hook). target: the link's target, empty for a file. executable: the owner's bit, for a file; absent for a symlink, whose own mode says nothing about its target (decision 2026-10-31, a). |
| git_hook_removed | git | path | hook: string, target: bytes | `hook {hook} removed` | target: the removed link's target, empty for a file. |
| git_hook_changed | git | path | hook: string, executable: bool?, target: bytes | `hook {hook} changed` | Its content changed, a link's target changed, or it changed between a file and a symlink. target and executable as in git_hook_added, after. |
| git_hook_executable_changed | git | path | hook: string, executable: bool | `hook {hook} executable: {executable}` | Only its executable bit changed. |
| git_index_changed | git | path | -- | `index changed` | `.git/index` (hashed, never stored). |
| git_reflog_appended | git | path | ref: string, entries: int | `{ref}: {entries} reflog entries` | Entries appended to the ref's reflog. |
| git_reflog_move | git | path | ref: string, from: string, to: string, operation: string | `{ref} {from} -> {to} by {operation}` | An appended entry that is not a plain commit (`commit`, `commit (initial)`) or a fast-forward: reset, commit (amend), rebase, checkout, ... operation is the message before its first `:`. The reflog is written by the watched process: evidence, not proof. |
| git_reflog_rewritten | git | path | ref: string | `{ref}: reflog rewritten` | The reflog before is not a prefix of the reflog after: entries removed or altered. |

binary claims nothing it explains: it declines.
