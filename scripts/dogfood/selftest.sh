#!/bin/sh
#
# The M1.5 hooks, on scripted sessions (NOTES design m1.5-structure, section
# 9): sequential calls, two concurrent ones, a background write between
# calls, a cancelled call, another project ignored. Checks where each change
# lands in the receipt, that concurrent hooks lose no log line, and that the
# turn line is said only when something changed. Needs jq and python3.
#
#   scripts/dogfood/selftest.sh [path/to/belay]

set -eu
BELAY=${1:-bin/belay}
case $BELAY in /*) ;; *) BELAY=$PWD/$BELAY ;; esac
HOOK=$PWD/scripts/dogfood/belay-dogfood
T=$(mktemp -d "${TMPDIR:-/tmp}/belay-dogfood.XXXXXX")
trap 'chmod -R u+rwx "${T:?}" 2>/dev/null; rm -rf "${T:?}"' EXIT
S=$T/repo
mkdir -p "$S/src" "$S/tests" "$T/state" && chmod 700 "$T/state"
printf 'a\n' > "$S/src/a.c"
printf 'def test_x(): assert 1\n' > "$S/tests/test_x.py"
export BELAY BELAY_DOGFOOD_SCOPE="$S" BELAY_STATE_DIR="$T/state" CLAUDE_PROJECT_DIR="$S" \
       BELAY_DOGFOOD_NOTES="$T/notes"
fail() { echo "dogfood selftest: FAIL: $*" >&2; exit 1; }
hook() {  # hook EVENT [tool_use_id tool summary]
    jq -cn --arg tid "${2:-}" --arg tool "${3:-}" --arg s "${4:-}" \
        '{session_id:"s1", tool_use_id:$tid, tool_name:$tool, tool_input:{command:$s}}' | "$HOOK" "$1"
}
LOG=$T/state/dogfood/s1.jsonl

mkdir "$S/locked" && chmod 000 "$S/locked"         # unreadable before the session: unknown throughout
hook start
# one call, writing src/a.c
hook pre t1 Bash "edit a"; printf 'b\n' >> "$S/src/a.c"; hook post t1 Bash
# a background writer between calls
printf 'x\n' > "$S/watcher.log"
# two concurrent calls
( hook pre t2 Bash "write b" ) & ( hook pre t3 Bash "write c" ) & wait
printf 'b\n' > "$S/src/b.c"; printf 'c\n' > "$S/src/c.c"
( hook post t2 Bash ) & ( hook post t3 Bash ) & wait
# a cancelled call: no post; closed by the stop
hook pre t4 Bash "weaken a test"; printf 'def test_x(): pass\n' > "$S/tests/test_x.py"
out=$(hook stop)
[ "$(wc -l < "$LOG")" = 9 ] || fail "the log has $(wc -l < "$LOG") lines, expected 9 (concurrent hooks lost one)"
printf '%s' "$out" | jq -e '.systemMessage | test("changes this turn")' >/dev/null || fail "no turn line: $out"
R=$(ls "$T/state/dogfood"/s1.turn-*.txt)
grep -q '^Bash: edit a$' "$R" && grep -q '  M src/a.c' "$R" || fail "src/a.c not under its call: $(cat "$R")"
grep -A2 '^between tool calls$' "$R" | grep -q '  A watcher.log' || fail "the background write not between calls"
grep -q '^during these concurrent calls: Bash: write b; Bash: write c$' "$R" || fail "the concurrent calls not together"
grep -q '^Bash: weaken a test   (cancelled)$' "$R" || fail "the cancelled call not named"
grep -q 'background writers were active (1 change outside any tool call)' "$R" || fail "background not said: $(cat "$R")"

# an entry unknown in every interval (an unreadable directory) is said once,
# and is no change: a turn with nothing else says nothing
hook pre t5 Bash "touch d"; printf 'd\n' > "$S/src/d.c"; hook post t5 Bash
hook pre t6 Bash "touch e"; printf 'e\n' > "$S/src/e.c"; hook post t6 Bash
out=$(hook stop)
R2=$(ls -t "$T/state/dogfood"/s1.turn-*.txt | head -1)
[ "$(grep -c 'locked' "$R2")" = 1 ] || fail "the unreadable directory not said once: $(cat "$R2")"
grep -q '^unknown throughout the session' "$R2" || fail "no 'unknown throughout' section: $(cat "$R2")"
printf '%s' "$out" | jq -e '.systemMessage | test("^belay: 2 changes")' >/dev/null || fail "counted the unreadable directory: $out"
# a turn that changes nothing says nothing
out=$(hook stop)
[ -z "$out" ] || fail "a turn without changes said: $out"
# another project: ignored, nothing logged
n=$(wc -l < "$LOG")
CLAUDE_PROJECT_DIR=$T/elsewhere hook pre t9 Bash x
[ "$(wc -l < "$LOG")" = "$n" ] || fail "another project's hook was logged"

hook end
[ -f "$T/state/dogfood/s1.receipt.txt" ] || fail "no session receipt"
ls "$T/notes"/*-s1.md >/dev/null 2>&1 || fail "a test file changed, but the receipt was not kept"
grep -q 'Kept because: a test file changed' "$T"/notes/*-s1.md || fail "kept for the wrong reason"
echo "dogfood selftest: sequential, concurrent, background, cancelled, silent turn, other project: ok"
