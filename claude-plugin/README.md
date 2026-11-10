# belay for Claude Code

One line after every tool call that changed something, leading with anything unexpected. One or
two when the agent stops, with the turn's totals. And a full receipt on file, with nothing left
out, that `/belay:receipt` opens.

```
● Bash(npm install 2>&1 | tail -15 && npm test 2>&1 | tail -40)
  ⎿  added 1 package, and audited 2 packages in 330ms
  ⎿  PostToolUse:Bash says: belay: 🔴 .git/hooks/pre-push added (git hook) · 7 more: 7 added (5 under node_modules/)

● Dependencies installed (npm install added 1 package, tiny-slug, with no vulnerabilities). All tests pass.
  ⎿  Stop says: belay: 🔴 1 flagged: .git/hooks/pre-push added (git hook)
     belay: 8 changed this turn in 1 tool call · full receipt: /belay:receipt
```

## Install

    claude plugin install belay --marketplace Allexsen/belay

Then start Claude Code in a project directory. In a session that is already open, run
`/plugin install belay --marketplace Allexsen/belay`, then `/reload-plugins` if it asks. Both
need Claude Code 2.1.292 or later; `/belay:receipt` was tested on 2.1.322.

To remove it: `claude plugin uninstall belay@belay`.

## The short layer

Every line starts `belay:`. When something is flagged, a 🔴 comes right after it, always in the
same place.

- **After a tool call that changed something, one line:** what it changed. Anything flagged comes
  first, with why; the rest is counted. Three changes or fewer are named.
- **`belay: outside tool calls:`** the same line, for what changed between calls: a background
  process, another program, or you.
- **When the agent stops:** a line for what the turn flagged, if it flagged anything, then a line
  with how many entries changed in how many calls, ending in `full receipt: /belay:receipt`. A
  turn that changed nothing says `belay: nothing changed this turn`.

Every changed entry is counted in exactly one line. The lines go to you, as Claude Code's
`systemMessage`; the hook adds nothing to the model's context.

Claude Code puts its own label before every line of a hook's message (`PostToolUse:Bash says:`,
`Stop says:`), and a hook cannot change it.

### What is flagged

- **The built-in list**, [hooks/sensitive.txt](hooks/sensitive.txt): places where a change is rarely
  the task itself and either runs code nobody asked to run, holds a credential, or changes what
  later automation does. Git hooks and config, files that load on their own (`.envrc`,
  `.vscode/tasks.json`, `*.pth`), credentials (`.env`, keys), package sources (`.npmrc`), CI, and
  the agent's own rules (`.claude/`, `CLAUDE.md`, `.mcp.json`).
- **Your don't-touch list**, `.belay-donttouch` at the project root, one pattern a line:

      # anything here is flagged, whatever happens to it
      migrations
      tests/fixtures/**
      *.lock
      /LICENSE

  `*` is any run of characters within a name, `**` any run across names, and both match names
  that start with a dot. A pattern with no slash matches at any depth; one with a slash, or
  starting with one, is taken from the project root. A match on a directory covers everything
  below it. `#` starts a comment. A change to the list itself is flagged.
- **Privilege changes:** setuid, setgid, file capabilities, inode flags.
- **Symlinks:** a file replaced by one, and one retargeted to an absolute path or through `..`.
- **Git history rewritten.**

Flagging decides only what leads a line. Nothing is hidden by not being flagged.

## The long layer: the full receipt

One file per project; its own path is on its second line. It holds every change of the turn, call by
call, as `belay diff --all` prints it: nothing folded, nothing filtered, git-ignored files and
`.git` included. The newest turn is first and the session's earlier turns follow; each turn is also
kept on its own for a week, in the `turns` directory beside it.

Type `/belay:receipt` to open it. Nothing is sent to the model:

- **In the VS Code extension**, where no path in a hook's line can be clicked, it opens as an
  editor tab. The first time in a workspace, VS Code asks "Do you want to allow untrusted files
  in this workspace?", because the file is outside it. **Open** settles it for that workspace;
  ticking "Remember my decision for all workspaces" settles it everywhere. A plugin cannot answer
  that for you: VS Code skips the question only for files inside a folder you have trusted.
- **In a terminal**, its text is shown in the conversation, under Claude Code's heading
  "UserPromptExpansion operation blocked by hook": blocking the command is how the hook answers
  it without a model call.

Nothing opens unless you ask.

## What it downloads

The first session fetches one file: the belay v0.1.0-alpha.6 binary for your platform, from this
repository's GitHub release. The hook runs it only if its sha256 is the one written in
[hooks/belay-hook](hooks/belay-hook). Nothing else is fetched, then or later, and belay itself
makes no network calls.

Linux x86_64 and arm64, and macOS arm64. It needs `sh`, `awk`, `curl` and `sha256sum` or `shasum`.

## Limits

- **Pre-alpha.** A line that missed a change, invented one, or led with the wrong thing is the most
  useful thing you can report: [open an issue](https://github.com/Allexsen/belay/issues) with it.
- It watches the project directory only. `~/.ssh`, `~/.gitconfig`, your shell's startup files and
  everything else outside it are not seen, and neither are network effects.
- A change made and undone between two lines is not seen.
- Tool calls that run in parallel share lines: the first to finish shows what all of them had done
  by then.
- A symlink that is new is counted and listed, but not flagged for where it points: belay's diff
  does not give a new link's target yet.
- A name that is not UTF-8 is counted and listed, but no pattern is matched against it.
- Each hook walks the directory, twice per tool call, so a very large tree slows every call. This
  has not been measured. `$HOME` and `/` are refused.
- macOS has not been tested.
- belay keeps its checkpoints under `~/.local/state/belay` and prunes them to a week.
- It is a record, not a sandbox. See [SECURITY.md](../SECURITY.md).

## Develop

    claude --plugin-dir ./claude-plugin        # load it for one session
    make plugin-test                           # the hook, against bin/belay
