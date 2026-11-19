# Pin: configuration keys by name

**Status.** Approved by the author, 2026-11-19, after two independent reviews. The code follows in later
PRs: until a row's code has merged, nothing in it is implemented, and `docs/cli.md` says only what is.
Rows marked **owed** state what a run must show before the code resting on them merges. Every grammar row here is owed: no fixture has been run against its tool yet, and a rule a
tool contradicts is changed, with the author's OK, before its code merges.

**Evidence.** "Measured" means run on GitHub-hosted Ubuntu 24.04 (kernel 7.0) and 22.04 (kernel 6.8)
runners, 2026-11-18 and 19. The file names and section labels given (`events.txt` E1, `facts.txt` P4,
`owed.txt` U1, `round-3`, ...) are those runs' outputs, kept in the project's notes, not in this repository.

**What this is.** For a few file formats whose grammar is fixed, belay names the key that changed
instead of counting lines. **It states the text of one file.** It never states the setting in
force: includes, drop-in order, first-match rules and built-in defaults are the tool's.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## Events

| kind | fields | text |
|---|---|---|
| `config_key_added`, `config_key_removed` | path, grammar, context, key, value | `{path}: {context} › {key} {added}: {value}` |
| `config_key_changed` | path, grammar, context, key, from, to | `{path}: {context} › {key} {from} -> {to}` |
| `config_not_keyed` | path, grammar, why | `{path}: shown as lines ({why})` |

## Rules for every grammar

| id | rule |
|---|---|
| CF-1 | A file is tokenized on both sides into `(context, key, value)` triples. `context` is the list of enclosing block headers or the section name, as written; top level is `[]`. `value` is the rest of the directive as written, inner whitespace runs made one space. Comments and blank lines are not triples. |
| CF-2 | Per `(context, key)`: one value on each side and they differ: `config_key_changed`. Otherwise the two sides are sets of values: each value on one side only is `config_key_added` or `config_key_removed`. A repeated key is never reported as changed. |
| CF-3 | If two blocks at one level have the same header text on either side (two `server {` blocks), the file is not keyed: one `config_not_keyed`, `why: a block header is not unique`, and its line diff stands. |
| CF-4 | A file that does not tokenize: `config_not_keyed`, `why: does not parse`. A file over 1 MiB or with more than 65,536 triples: `why: too large`. |
| CF-5 | Order: by path, then context, then key, removed before added. |
| CF-6 | The text interpreter's line findings for the same path stand beside these. |

## Grammars

| id | grammar | files claimed | tokens | checked against (owed) |
|---|---|---|---|---|
| CF-N | `nginx` | `etc/nginx/nginx.conf`, `etc/nginx/conf.d/*.conf`, `sites-available/*`, `sites-enabled/*` (a link is its target's file, once), `modules-enabled/*`, `snippets/*` | a directive is words to `;`; a block is words then `{ ... }`; `#` to end of line outside quotes; single and double quotes with backslash. A block whose first word ends `_by_lua_block`, or is `map`, `types`, `geo`, `split_clients`, `charset_map`, is opaque: it is one triple whose value is the sha256 of its text. | each fixture accepted by `nginx -t`; a fixture that breaks the tokenizer's assumption rejected by it |
| CF-S | `sshd` | `etc/ssh/sshd_config`, `etc/ssh/sshd_config.d/*.conf` | a line is a keyword and arguments, separated by whitespace or one `=`; keywords compared ASCII-case-insensitively and shown as written; `Match ...` opens a context that runs to the next `Match` or the end. | `sshd -t -f FIXTURE`; for single-file fixtures without `Match`, `sshd -T -f` shows the same keyword and value |
| CF-I | `ini` | every unit file and drop-in systemd claims (system-interpreters.md), `etc/systemd/*.conf`, `etc/systemd/*.conf.d/*.conf` | `[Section]` sets the context; `Key=Value`; a trailing `\` joins lines; `#` and `;` begin comments; an empty assignment (`Key=`) is a value, the empty one. | `systemd-analyze verify FIXTURE` |
| CF-K | `keyvalue` | `etc/sysctl.conf`, `etc/sysctl.d/*.conf` | `key = value`; `#` and `;` comments; a leading `-` on the key is part of the key as written. | `sysctl -p FIXTURE` in a container made for it, never on a watched machine |
| CF-L | `namevalue` | `etc/login.defs` | `NAME value`, whitespace separated; `#` comments. | measured so far: `UID_MIN 1000` is read by `useradd` (accounts SA-2). Owed: one changed value seen to change `useradd`'s choice |

## Not keyed, by design

| id | what | why |
|---|---|---|
| CF-X1 | `etc/default/*`, `etc/profile*`, `etc/environment`, anything sourced by a shell | shell syntax is not a fixed grammar: line diffs only |
| CF-X2 | Apache, PAM, fstab, netplan, YAML and JSON files | not designed here; line diffs. Each would be its own grammar row and probe. |
| CF-X3 | the effective value of anything | section "What this is" |
