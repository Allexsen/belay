#!/bin/sh
#
# The plugin's hook, run as Claude Code runs it, against a real belay:
#
#   sh claude-plugin/test.sh BELAY_BINARY
#
# Works in a temporary directory and removes it. Needs python3 (to check
# that what the hook prints is JSON) and git. The download of the pinned
# binary is not tested here (it needs the network): BELAY_HOOK_BINARY
# stands in, and a stand-in `code` for VS Code's.

set -u
BELAY=$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")
HOOK=$(cd "$(dirname "$0")" && pwd -P)/hooks/belay-hook
T=$(mktemp -d) || exit 1
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/proj" "$T/home" "$T/fakebin"
P=$T/proj
fails=0
n=0
ENTRY=
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/code.log"\n' "$T" > "$T/fakebin/code"
chmod +x "$T/fakebin/code"

INPUT='{"session_id":"s","tool_name":"Bash","tool_input":{"command":"x"}}'
RECEIPT='{"hook_event_name":"UserPromptExpansion","expansion_type":"slash_command","command_name":"belay:receipt","command_args":"","prompt":"/belay:receipt"}'
hook() {
    printf '%s' "${IN:-$INPUT}" |
        env -u CLAUDE_CODE_ENTRYPOINT ${ENTRY:+CLAUDE_CODE_ENTRYPOINT=$ENTRY} PATH="$T/fakebin:$PATH" \
            HOME="$T/home" CLAUDE_PROJECT_DIR="${DIR:-$P}" CLAUDE_PLUGIN_DATA="$T/data" BELAY_STATE_DIR="$T/state" \
            BELAY_HOOK_BINARY="${BIN:-$BELAY}" sh "$HOOK" "$1"
}
# The message a hook's output carries: "" for no output; fails when the
# output is anything but one JSON object with only systemMessage, every
# line of it starting "belay: " -- or, for /belay:receipt, one that blocks
# the command, whose reason it is -- or when it has another number of
# lines than $LINES_WANT (when set).
message() {
    python3 -I -c '
import json, os, sys
s = sys.stdin.read()
if s:
    o = json.loads(s)
    if "decision" in o:
        assert o["decision"] == "block" and o["hookSpecificOutput"]["hookEventName"] == "UserPromptExpansion", o
        m = o["reason"]
    else:
        assert list(o) == ["systemMessage"], o
        m = o["systemMessage"]
        assert all(l.startswith("belay: ") for l in m.split("\n")), "a row that does not start with belay:"
    want = os.environ.get("LINES_WANT")
    assert not want or len(m.split("\n")) == int(want), "%d lines" % len(m.split("\n"))
    print(m)'
}
bad() { fails=$((fails + 1)); printf 'FAIL %s\n  wanted: %s\n  got: %s\n' "$1" "$2" "$3"; }
lines() {       # lines NAME COUNT OUTPUT: the message has that many lines
    n=$((n + 1))
    printf '%s' "$3" | LINES_WANT=$2 message >/dev/null 2>&1 || bad "$1" "$2 line(s)" "$3"
}
starts() {      # starts NAME PREFIX OUTPUT
    n=$((n + 1))
    msg=$(printf '%s' "$3" | message 2>/dev/null) || { bad "$1" "$2" "not JSON: $3"; return; }
    case $msg in "$2"*) ;; *) bad "$1" "starting: $2" "$msg" ;; esac
}
has() {         # has NAME SUBSTRING OUTPUT
    n=$((n + 1))
    msg=$(printf '%s' "$3" | message 2>/dev/null) || { bad "$1" "$2" "not one line of JSON: $3"; return; }
    case $msg in *"$2"*) ;; *) bad "$1" "$2" "$msg" ;; esac
}
hasnt() {       # hasnt NAME SUBSTRING OUTPUT
    n=$((n + 1))
    msg=$(printf '%s' "$3" | message 2>/dev/null) || { bad "$1" "no $2" "not one line of JSON: $3"; return; }
    case $msg in *"$2"*) bad "$1" "no $2" "$msg" ;; esac
}
none() {        # none NAME OUTPUT
    n=$((n + 1))
    [ -z "$2" ] || bad "$1" "(nothing)" "$2"
}
ok() {          # ok NAME COMMAND...
    n=$((n + 1)); name=$1; shift
    "$@" >/dev/null 2>&1 || bad "$name" "$*" "failed"
}
FIXED() { ls "$T"/data/receipts/*/belay-receipt-proj.txt 2>/dev/null; }

( cd "$P" && git init -q . && printf 'node_modules/\n' > .gitignore ) || exit 1
echo one > "$P/a.txt"
none "start says nothing" "$(hook start)"
none "nothing changed: prompt says nothing" "$(hook prompt)"
none "nothing changed: pre says nothing" "$(hook pre)"
none "nothing changed: post says nothing" "$(hook post)"

# ---- the line after a call ----
RED=$(printf '\360\237\224\264')
echo two >> "$P/a.txt"
out=$(hook post)
starts "a change after a call, named, from belay" "belay: 1 change: a.txt modified" "$out"
lines "on one line" 1 "$out"
none "a change is in one line only" "$(hook post)"
echo x > "$P/b.txt"
starts "a change no call made says so" "belay: outside tool calls: 1 change: b.txt added" "$(hook pre)"

# ---- sensitive places lead ----
mkdir -p "$P/node_modules/x" "$P/.git/hooks"
i=0; while [ $i -lt 6 ]; do echo $i > "$P/node_modules/x/f$i.js"; i=$((i + 1)); done
printf '#!/bin/sh\n' > "$P/.git/hooks/pre-push"
printf '#!/bin/sh\n' > "$P/.git/hooks/pre-commit.sample"
out=$(hook post)
starts "a git hook leads the line, behind belay and a red circle" "belay: $RED .git/hooks/pre-push added (git hook) · " "$out"
lines "on one line" 1 "$out"
has "the rest is counted, with where most of it is" "added (7 under node_modules/)" "$out"
hasnt "a .sample hook is not flagged" "pre-commit.sample" "$out"

mkdir -p "$P/svc/.github/workflows" "$P/.claude"
echo k > "$P/svc/.env"; echo y > "$P/svc/.github/workflows/ci.yml"; echo '{}' > "$P/.claude/settings.json"
echo p > "$P/evil.pth"; echo r > "$P/.npmrc"
out=$(hook post)
has "the first three flagged are named" "belay: $RED .claude/settings.json added (agent rules); .npmrc added (package source); evil.pth added (runs at every Python start)" "$out"
has "more than three flagged are counted" "and 2 more flagged" "$out"
hasnt "a directory made is not flagged twice over" ".claude added" "$out"
ok "every flagged path is kept for the turn: a nested .env" grep -q "^svc/.env added	credentials$" "$T"/data/scopes/*/turn/flagged
ok "and a nested workflow" grep -q "^svc/.github/workflows/ci.yml added	CI$" "$T"/data/scopes/*/turn/flagged

# ---- .belay-donttouch ----
mkdir -p "$P/fixtures/deep" "$P/sub"
printf '# comment\nfixtures\n*.lock\n/only-root.txt\n' > "$P/.belay-donttouch"
has "the don't-touch list is itself flagged" ".belay-donttouch added (don't-touch list)" "$(hook post)"
echo h > "$P/fixtures/deep/.hidden"
has "a dot-name below a declared directory" "fixtures/deep/.hidden added (don't-touch)" "$(hook post)"
echo l > "$P/sub/yarn.lock"; echo r > "$P/only-root.txt"; echo r > "$P/sub/only-root.txt"
out=$(hook post)
has "a pattern with no slash matches at any depth" "sub/yarn.lock added (don't-touch)" "$out"
has "a pattern starting with a slash matches at the root" "belay: $RED only-root.txt added (don't-touch)" "$out"
hasnt "and only there" "sub/only-root.txt added (don't-touch)" "$out"
printf 'conf/**\n*.gen\n' >> "$P/.belay-donttouch"
has "a change to the list is flagged too" ".belay-donttouch modified (don't-touch list)" "$(hook post)"
mkdir -p "$P/conf/.secret"; echo s > "$P/conf/.secret/x"; echo g > "$P/.x.gen"
out=$(hook post)
has "** matches names that start with a dot" "conf/.secret/x added (don't-touch)" "$out"
has "and so does *" ".x.gen added (don't-touch)" "$out"

# ---- privilege and symlinks ----
chmod u+s "$P/a.txt"
has "setuid is flagged" "(privilege)" "$(hook post)"
rm "$P/b.txt" && ln -s /etc/hostname "$P/b.txt"
has "a file replaced by a symlink" "b.txt type changed (replaced by a symlink)" "$(hook post)"
ln -s a.txt "$P/inside"
out=$(hook post)
has "a symlink added is counted" "1 change: inside added" "$out"
ln -sfn ../../outside "$P/inside"
has "a symlink retargeted through .." "symlink now points to ../../outside" "$(hook post)"

# ---- names ----
printf 'q\n' > "$P/we\"ird \\ name.txt"
has "a quote and a backslash in a name are valid JSON" 'we"ird \ name.txt added' "$(hook post)"
printf 'q\n' > "$P/$(printf 'a\342\200\256b.txt')"
out=$(hook post)
has "a bidi control in a name is not passed on" "a?b.txt added" "$out"
printf 'q\n' > "$P/$(printf 'bad\377name')"
has "a name that is not UTF-8 is counted" "1 change: (a name that is not UTF-8) added" "$(hook post)"

# ---- the turn's rows and the long layer ----
echo late > "$P/late.txt"
out=$(hook stop)
lines "stop gives two rows" 2 "$out"
starts "what was flagged first, the red circle after belay as everywhere" "belay: $RED 16 flagged: .git/hooks/pre-push added (git hook); " "$out"
has "then the totals, calls and outside apart, and the command" "
belay: 42 changed this turn: 40 in 15 tool calls, 2 outside tool calls · full receipt: /belay:receipt" "$out"
hasnt "and no path" "receipts/" "$out"
F=$(FIXED)
ok "the path is at the top of the receipt" sh -c "sed -n 2p '$F' | grep -q '^This file: $F\$'"
ok "the long layer names what the line only counted" grep -q 'A node_modules/x/f3.js' "$F"
ok "and what was flagged" grep -q 'hook pre-push added' "$F"
ok "and what changed outside calls" grep -q -- '-- outside tool calls' "$F"
ok "and the last change, seen at stop" grep -q 'A late.txt' "$F"
ok "call by call, with the tool's name" grep -q -- '-- after Bash' "$F"
ok "the turn is kept apart" sh -c "grep -l 'A late.txt' '$T'/data/receipts/*/turns/*.txt"

out=$(hook stop)
starts "a turn with no change says so" "belay: nothing changed this turn" "$out"
lines "in one row" 1 "$out"
hasnt "with no receipt to open" "/belay:receipt" "$out"
none "the next prompt says nothing" "$(hook prompt)"
echo z > "$P/z.txt"
hook post >/dev/null
out=$(hook stop)
starts "the next turn counts only its own" "belay: 1 changed this turn in 1 tool call · full receipt: /belay:receipt" "$out"
lines "with nothing flagged, one row" 1 "$out"
hasnt "and no red circle" "$RED" "$out"
ok "the fixed file has the newest turn first" sh -c "[ \$(grep -n 'A z.txt' '$F' | cut -d: -f1) -lt \$(grep -n 'A late.txt' '$F' | cut -d: -f1) ]"

# ---- /belay:receipt ----
out=$(IN=$RECEIPT hook receipt)
has "in a terminal the command's answer is the receipt itself" "A late.txt" "$out"
has "newest turn first" "== turn ended" "$out"
none "another command is left alone" "$(IN='{"hook_event_name":"UserPromptExpansion","command_name":"deploy","prompt":"/deploy"}' hook receipt)"
ok "nothing was opened" sh -c "[ ! -e '$T/code.log' ]"
ENTRY=claude-vscode
out=$(IN=$RECEIPT hook receipt)
has "in the extension it is opened as a tab" "open in an editor tab: $F" "$out"
hasnt "and not repeated in the conversation" "A late.txt" "$out"
ok "by VS Code's own command" grep -q -- "--reuse-window $F" "$T/code.log"
printf '#!/bin/sh\nexit 1\n' > "$T/fakebin/code"
has "where it cannot be opened, it is shown" "A late.txt" "$(IN=$RECEIPT hook receipt)"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/code.log"\n' "$T" > "$T/fakebin/code"
# nothing opens unasked
: > "$T/code.log"
hook start >/dev/null
has "a new session has no receipt yet, and says so" "no receipt for this directory yet" "$(IN=$RECEIPT hook receipt)"
echo t1 > "$P/t1.txt"; hook post >/dev/null; hook stop >/dev/null
echo t2 > "$P/t2.txt"; hook post >/dev/null; hook stop >/dev/null; sleep 1
ok "in the extension, no turn opens anything by itself" sh -c "[ ! -s '$T/code.log' ]"
ENTRY=

# ---- when things go wrong ----
rm -rf "$T/state"
echo again > "$P/e.txt"
none "state removed: starts again without a word" "$(hook post)"
echo more > "$P/f.txt"
has "and the next change is seen" "f.txt added" "$(hook post)"

starts "a failing belay is said" "belay: no receipt: " "$(BIN=/bin/false hook post)"
none "once" "$(BIN=/bin/false hook post)"
hook start >/dev/null
none "a working belay clears it" "$(hook post)"

has "the home directory is refused, and said" "too wide" "$(DIR=$T/home hook start)"
none "and nothing is recorded there" "$(DIR=$T/home hook post)"

for ev in start pre post prompt stop nonsense; do
    n=$((n + 1))
    hook $ev >/dev/null 2>&1 || bad "$ev exits 0" "0" "non-zero"
done
n=$((n + 1))
[ -z "$(printf '{}' | env -u CLAUDE_PROJECT_DIR CLAUDE_PLUGIN_DATA="$T/data" sh "$HOOK" post)" ] ||
    bad "no project directory" "(nothing)" "printed something"

echo "claude-plugin: $((n - fails)) of $n passed"
[ "$fails" = 0 ]
