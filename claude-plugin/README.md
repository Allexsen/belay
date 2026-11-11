# belay for Claude Code

One line after every tool call that changed something, leading with anything unexpected. A line or
two when the agent stops, with the turn's totals. And a full receipt, with nothing left out, that
`/belay:receipt` opens.

```
● Bash(npm install 2>&1 | tail -15 && npm test 2>&1 | tail -40)
  ⎿  added 1 package, and audited 2 packages in 330ms
  ⎿  PostToolUse:Bash says: belay: 🔴 .git/hooks/pre-push added (git hook) · 7 more: 7 added (5 under node_modules/)

● Dependencies installed (npm install added 1 package, tiny-slug, with no vulnerabilities). All tests pass.
  ⎿  Stop says: belay: 🔴 1 flagged: .git/hooks/pre-push added (git hook)
     belay: 8 changed this turn in 1 tool call · full receipt: /belay:receipt
```

The plugin is a thin wrapper: everything it says and records is done by the belay binary
(`belay hook claude-code`, `belay watch`), which behaves the same in a terminal, in the VS Code
extension and by hand. What a line says, and when, is pinned in
[test/expect/watch-v1.md](../test/expect/watch-v1.md).

**It catches careless changes**: what the agent, a tool it ran or an install did to your project
directory without saying. It does not hold against a process running as you that sets out to fool
belay: one that rewrites belay's state, or runs its commands itself.

## Install

    claude plugin marketplace add Allexsen/belay
    claude plugin install belay@belay

Then start Claude Code in a project directory. To remove it: `claude plugin uninstall belay@belay`.

Claude Code tries the repository over SSH first and falls back to HTTPS, so no GitHub SSH key is
needed. On a network that blocks SSH the first command waits two minutes before falling back; the
full URL goes straight to HTTPS:

    claude plugin marketplace add https://github.com/Allexsen/belay.git
    claude plugin install belay@belay

## The lines

Every line starts `belay:`. When something is flagged, a 🔴 comes right after it, always in the
same place.

- **After a tool call that changed something, one line.** What is flagged comes first, with why;
  the rest is counted, and named when there are three or fewer.
- **`belay: outside tool calls:`** the same line, for what changed between calls: a background
  process, another program, or you.
- **When the agent stops:** a line for what the turn flagged, a line for what it noted, then how
  many entries changed in how many calls, ending in `full receipt: /belay:receipt`. A turn that
  changed nothing says `belay: nothing changed this turn`.
- **When belay could not record,** a line says so and why (`belay: 🔴 could not record in 45 s:
  capturing`), and the turn's end repeats it. It is never silent about a step it lost.

Every changed entry is counted in exactly one line. The lines go to you, as Claude Code's
`systemMessage`; the hook adds nothing to the model's context. Claude Code puts its own label
before every line of a hook's message (`PostToolUse:Bash says:`), and a hook cannot change it.

### What is flagged

- **Your don't-touch list**, `.belay-donttouch` at the project's top, one pattern a line:

      # anything here is flagged, whatever happens to it
      migrations
      tests/fixtures
      **/*.lock
      LICENSE

  `*` is any run of characters within a name and `**` any number of whole names; both match names
  that start with a dot. A pattern starts at the project's top: `*.lock` is the top level only,
  `**/*.lock` any depth. A match on a directory covers everything below it. `#` starts a comment.
  A change to the list itself is flagged. `belay watch patterns --scope .` shows what each pattern
  matches now, and marks one that matches nothing.
- **The built-in list**: places where a change is rarely the task itself and either runs code
  nobody asked to run, decides where code comes from, or holds a credential. Git hooks and hook
  managers, the agent's own rules (`.claude/`, `CLAUDE.md`, `.mcp.json`), files that load on
  their own (`.envrc`, `.vscode/tasks.json`, a `.pth` in `site-packages`), package sources
  (`.npmrc`), CI at the project's top, credentials (`.env`, keys). The rows, what each was checked
  against, and the ones that could not be checked are in the pin.
- **Privilege changes:** setuid, setgid, sticky, file capabilities, a locking inode flag.
- **A file replaced by a symlink**, and **git history rewritten**.

**Noted, with no 🔴:** a modified `.git/config` (it changes when a branch starts tracking; belay
does not yet read which key changed, so `core.hooksPath` is noted like `user.name`), and
`.claude/settings.local.json`, which Claude Code writes itself when you answer a permission prompt
"don't ask again".

Not flagged, on purpose: what a package ships inside `node_modules` or `site-packages` (its own
CI files, test keys), and a brand-new repository's own `.git/config`.

Flagging decides only what leads a line. Nothing is hidden by not being flagged.

## The full receipt

`/belay:receipt` shows every change of every step, newest first, each step as `belay diff --all`
prints it: nothing folded, nothing filtered, git-ignored files and `.git` included. Nothing is sent
to the model.

- **In the VS Code extension** it opens as an editor tab. The first time in a workspace, VS Code
  asks "Do you want to allow untrusted files in this workspace?", because the file is outside it.
  A plugin cannot answer that for you.
- **In a terminal**, its first 400 lines are shown in the conversation, under Claude Code's heading
  "UserPromptExpansion operation blocked by hook": blocking the command is how the hook answers it
  without a model call. The whole of it: `belay watch receipt --scope .`.

## What it downloads

The first session fetches one file: the belay binary for your platform, of the release named in
[hooks/pin](hooks/pin), from this repository's GitHub releases. The wrapper runs it only if its
sha256 is the one in that file. Nothing else is fetched, then or later, and belay itself makes no
network calls. Linux x86_64 and arm64, and macOS on Apple silicon only. The wrapper needs `sh`,
`curl` and `sha256sum` or `shasum`.

## What it keeps, and removes

belay keeps its checkpoints and the record under `~/.local/state/belay`. Once a day the plugin
prunes **only the checkpoints it made itself** that are more than a week old. A checkpoint you
made with `belay mark` or `belay check` is never removed by the plugin, whatever its age.

## Limits

- **Pre-alpha.** A line that missed a change, invented one, or led with the wrong thing is the most
  useful thing you can report: [open an issue](https://github.com/Allexsen/belay/issues) with it.
- It watches the project directory only. `~/.ssh`, `~/.gitconfig`, your shell's startup files and
  everything else outside it are not seen, and neither are network effects. `$HOME` and `/` are
  refused.
- A change made and undone between two lines is not seen.
- Tool calls that run in parallel share lines: the first to finish shows what all of them had done
  by then. What a background command writes after its call has finished is counted, but not under
  that call.
- A new symlink is counted and listed, but not flagged for where it points, and neither is one
  that is retargeted.
- Each tool call captures the directory twice. On a tree of 19,000 entries a capture took 0.9 s
  here; a very large tree slows every call. Past 45 s a step is given up and said, and after three
  in a row the session stops recording and says so.
- A plugin enabled in a session that is already running records from its next start. Until then a
  turn's end says it is not recording.
- On macOS, Apple silicon only: there is no binary for an Intel Mac.
- It is a record, not a sandbox. See [SECURITY.md](../SECURITY.md).

## Develop

    BELAY_BIN=$PWD/bin/belay claude --plugin-dir ./claude-plugin    # run a binary you built
    make plugin-test                                                # the wrapper, against bin/belay
