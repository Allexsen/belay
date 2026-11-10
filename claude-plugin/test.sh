#!/bin/sh
# The Claude Code plugin's wrapper, run as Claude Code runs it: an event as
# its argument, the hook's JSON on standard input. What the lines say is the
# binary's and is tested there (test/test_watch_cli.c); here: that the
# wrapper always exits 0, passes the event and the input through, fetches
# only the pinned binary and runs it only when its sha256 is the pinned one.
#
#   claude-plugin/test.sh BELAY_BINARY
BIN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
HERE=$(cd "$(dirname "$0")" && pwd)
HOOK=$HERE/hooks/belay-hook
T=$(mktemp -d "${TMPDIR:-/tmp}/belay-plugin.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
fails=0
n=0
ok() { n=$((n + 1)); printf 'ok    %s\n' "$1"; }
bad() { n=$((n + 1)); fails=$((fails + 1)); printf 'FAIL  %s\n      want: %s\n      got:  %s\n' "$1" "$2" "$3"; }
is() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }
has() { case $3 in *"$2"*) ok "$1" ;; *) bad "$1" "...$2..." "$3" ;; esac; }
RED=$(printf '\360\237\224\264')

mkdir -p "$T/proj" "$T/state" "$T/home" "$T/data" && chmod 700 "$T/state"
export BELAY_STATE_DIR="$T/state" CLAUDE_PROJECT_DIR="$T/proj" HOME="$T/home" CLAUDE_PLUGIN_DATA="$T/data"
unset CLAUDE_CODE_ENTRYPOINT BELAY_PIN BELAY_RELEASE_URL
S='"session_id":"plug-1","cwd":"/nowhere"'
hook() { printf '%s' "$2" | BELAY_BIN=$BIN sh "$HOOK" "$1"; }

# ---- with a binary given: the event and the input go through ----
is "a session's start prints nothing" "" "$(hook start "{$S,\"source\":\"startup\"}")"
hook prompt "{$S,\"prompt\":\"go\"}" >/dev/null
hook pre "{$S,\"tool_use_id\":\"toolu_1\"}" >/dev/null
echo x > "$T/proj/a.txt"
is "a call's change is one line, in the hook's JSON" '{"systemMessage":"belay: 1 change: a.txt added"}' \
   "$(hook post "{$S,\"tool_use_id\":\"toolu_1\"}")"
mkdir -p "$T/proj/.git/hooks" && printf '#!/bin/sh\n' > "$T/proj/.git/hooks/pre-push"
out=$(hook stop "{$S}")
has "what is flagged leads the Stop's lines" "belay: $RED outside tool calls: .git/hooks/pre-push added (git hook)" "$out"
has "and the totals end them, with the receipt's command" 'changed this turn: 1 in 1 tool call, ' "$out"
has "the receipt command is answered by the hook" '{"decision":"block","reason":"belay receipt  ' \
    "$(hook receipt "{$S,\"command_name\":\"belay:receipt\"}")"

# ---- exit status 0, whatever happens ----
for case in "no argument|" "an unknown event|bogus" "input that is not JSON|pre"; do
    name=${case%%|*}; arg=${case#*|}
    printf 'not json' | BELAY_BIN=$BIN sh "$HOOK" $arg >/dev/null 2>&1
    is "exit 0: $name" 0 $?
done
printf '{}' | BELAY_BIN=/bin/false sh "$HOOK" pre >/dev/null 2>&1; is "exit 0: a binary that fails" 0 $?
printf '{}' | BELAY_BIN="$T/no-such-binary" sh "$HOOK" pre >/dev/null 2>&1; is "exit 0: a binary that is not there" 0 $?
printf '{}' | BELAY_BIN=$BIN CLAUDE_PROJECT_DIR=/nonexistent sh "$HOOK" stop >/dev/null 2>&1; is "exit 0: a directory that is not there" 0 $?
has "and a directory that is not there is a line, not silence" "belay: $RED could not record: " \
    "$(printf '{%s}' "$S" | BELAY_BIN=$BIN CLAUDE_PROJECT_DIR=/nonexistent sh "$HOOK" stop)"
case $(grep -c -E '^[[:space:]]*set +-[a-z]*[eu]' "$HOOK") in 0) ok "the wrapper sets neither -e nor -u" ;; *) bad "the wrapper sets neither -e nor -u" 0 "it does" ;; esac

# ---- the pinned binary: fetched once, run only when its sha256 is the pinned one ----
case $(uname -s)-$(uname -m) in
    Linux-x86_64) target=linux-x86_64 ;; Linux-aarch64|Linux-arm64) target=linux-arm64 ;; Darwin-arm64) target=macos-arm64 ;; *) target= ;;
esac
if [ -n "$target" ]; then
    sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
    mkdir -p "$T/rel/vtest" && cp "$BIN" "$T/rel/vtest/belay-vtest-$target"
    pinned() { printf '%s' "$2" | BELAY_PIN="$T/pin" BELAY_RELEASE_URL="file://$T/rel" sh "$HOOK" "$1"; }

    printf 'version unreleased\n' > "$T/pin"
    is "an unreleased pin says so at a session's start" "{\"systemMessage\":\"belay: $RED not recording: this plugin names no released belay yet\"}" \
       "$(pinned start "{$S,\"source\":\"startup\"}")"
    is "without a binary a tool call says nothing" "" "$(pinned pre "{$S,\"tool_use_id\":\"t\"}")"
    has "and a turn's end says nothing is recorded" "belay: $RED not recording: belay's binary is not here yet" "$(pinned stop "{$S}")"

    printf 'version vtest\n%s %s\n' "$target" 0000000000000000000000000000000000000000000000000000000000000000 > "$T/pin"
    has "a download whose sha256 is not the pinned one is not run" "not the pinned one: not run" "$(pinned start "{$S,\"source\":\"startup\"}")"
    is "and is not kept" "" "$(ls "$T/data/bin" 2>/dev/null)"

    printf 'version vtest\nother-target abc\n' > "$T/pin"
    has "a platform the pin has no binary for is said" "not recording: belay vtest has no binary for " "$(pinned start "{$S,\"source\":\"startup\"}")"

    printf '# a comment\nversion vtest\n%s %s\n' "$target" "$(sum "$BIN")" > "$T/pin"
    is "the pinned binary is fetched at a session's start, and run" "" "$(pinned start "{$S,\"source\":\"resume\"}")"
    is "kept under its version" "belay-vtest" "$(ls "$T/data/bin")"
    echo y > "$T/proj/b.txt"
    rm -rf "$T/rel"
    is "and not fetched again" '{"systemMessage":"belay: outside tool calls: 1 change: b.txt added"}' "$(pinned pre "{$S,\"tool_use_id\":\"toolu_2\"}")"
    pinned start "{$S,\"source\":\"startup\"}" >/dev/null 2>&1; is "exit 0: with the release gone and the binary here" 0 $?
    rm -rf "$T/data"
    has "a fetch that fails is a line" "not recording: could not fetch belay vtest" "$(pinned start "{$S,\"source\":\"startup\"}")"
    pinned start "{$S}" >/dev/null 2>&1; is "exit 0: a fetch that fails" 0 $?
else
    ok "the fetch is not tested on $(uname -s) $(uname -m): the plugin has no binary for it"
fi

# ---- the manifests name what exists ----
for arg in $(sed -n 's/.*belay-hook\\" \([a-z-]*\)".*/\1/p' "$HERE/hooks/hooks.json"); do
    printf '{}' | "$BIN" hook claude-code "$arg" >/dev/null 2>&1; rc=$?
    has "hooks.json's event '$arg' is one the binary's help names" "$arg" "$("$BIN" help hook)"
    is "and exits $rc" 0 $rc
done
is "hooks.json registers ten events" 10 "$(grep -c 'belay-hook' "$HERE/hooks/hooks.json")"
has "the receipt command's file is there" "disable-model-invocation: true" "$(cat "$HERE/commands/receipt.md")"

printf '\n%d run, %d failed\n' "$n" "$fails"
[ "$fails" -eq 0 ]
