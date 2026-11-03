#!/bin/sh
#
# The M1.5 hooks, on scripted sessions (NOTES design m1.5-structure, section
# 9): sequential calls, two concurrent ones, a background write between
# calls, a cancelled call, another project ignored. Checks where each change
# lands in the receipt, that concurrent hooks lose no log line, and that the
# turn line is said at every Stop. Needs jq and python3.
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
# The session receipt is made detached (decision 143): wait for its mark to go.
done_receipt() {
    i=0
    while [ -e "$T/state/dogfood/$1.receipt-running.session" ] && [ $i -lt 150 ]; do sleep 0.1; i=$((i + 1)); done
    [ ! -e "$T/state/dogfood/$1.receipt-running.session" ]
}

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
printf '%s' "$out" | jq -e '.systemMessage | test("paths changed this turn")' >/dev/null || fail "no turn line: $out"
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
[ "$(grep -c '^  ? locked' "$R2")" = 1 ] || fail "the unreadable directory not said once: $(cat "$R2")"
grep -q '^unknown throughout the session' "$R2" || fail "no 'unknown throughout' section: $(cat "$R2")"
printf '%s' "$out" | jq -e '.systemMessage | test("^belay: 2 paths changed")' >/dev/null || fail "counted the unreadable directory: $out"
# a turn that changes nothing says so: a Stop always says its line, or why
# it could not (decision 156) -- no line is never a quiet turn
out=$(hook stop)
printf '%s' "$out" | jq -e '.systemMessage | test("^belay: nothing changed this turn -- .*/s1[.]turn-[0-9]+[.]txt$")' \
    >/dev/null || fail "a turn without changes said nothing, or not that: $out"
# what each Stop said is kept, so a missing line can be told from one never made
tail -1 "$T/state/dogfood/s1.said" | grep -q 'nothing changed this turn' || fail "the Stop's line was not kept"
# another project: ignored, nothing logged
n=$(wc -l < "$LOG")
CLAUDE_PROJECT_DIR=$T/elsewhere hook pre t9 Bash x
[ "$(wc -l < "$LOG")" = "$n" ] || fail "another project's hook was logged"
# this project by another name (a symlink): the same project, logged
ln -s "$S" "$T/link"
CLAUDE_PROJECT_DIR=$T/link hook pre t9b Bash x; CLAUDE_PROJECT_DIR=$T/link hook post t9b Bash
[ "$(wc -l < "$LOG")" = "$((n + 2))" ] || fail "the project through a symlink was ignored"

# git's bookkeeping folds; what git reports stays (decision 105): a ref
# moved, HEAD, a hook added, the index's content -- and a real edit beside
# them. A nested repository folds on its own line; a .git file is not one.
H=0123456789abcdef0123456789abcdef01234567; H2=89abcdef0123456789abcdef0123456789abcdef
mkdir -p "$S/.git/refs/heads" "$S/.git/objects/01" "$S/.git/hooks" "$S/vendor/lib/.git/objects" "$S/wt"
printf 'ref: refs/heads/main\n' > "$S/.git/HEAD"; printf '%s\n' "$H" > "$S/.git/refs/heads/main"
printf 'gitdir: /elsewhere\n' > "$S/wt/.git"
printf '#!/bin/sh\n' > "$S/.git/hooks/post-merge"; chmod +x "$S/.git/hooks/post-merge"
hook pre t10 Bash "git fetch"
out=$(hook stop)                     # the .git above, before this turn's calls
hook pre t11 Bash "git commit"
printf 'x' > "$S/.git/objects/01/a"; printf 'y' > "$S/.git/objects/01/b"; printf 'f\n' > "$S/.git/FETCH_HEAD"
printf '%s\n' "$H2" > "$S/.git/refs/heads/main"; printf 'ref: refs/heads/dev\n' > "$S/.git/HEAD"
printf '#!/bin/sh\n' > "$S/.git/hooks/pre-commit"; chmod +x "$S/.git/hooks/pre-commit"
printf 'z' > "$S/vendor/lib/.git/objects/o"; printf 'gitdir: /moved\n' > "$S/wt/.git"
touch -m -d '2001-01-01' "$S/.git/hooks/post-merge"           # metadata only: no finding of git's
printf 'c\n' >> "$S/src/a.c"
hook post t11 Bash
out=$(hook stop)
R3=$(ls -t "$T/state/dogfood"/s1.turn-*.txt | head -1)
grep -q '^  git bookkeeping: 5 changes under \.git/$' "$R3" || fail "git's bookkeeping not folded: $(cat "$R3")"
grep -q '^  git bookkeeping: [0-9]* changes\{0,1\} under vendor/lib/\.git/$' "$R3" || fail "the nested repository not folded apart"
! grep -q 'objects/01\|FETCH_HEAD' "$R3" || fail "a raw .git path listed: $(cat "$R3")"
# git's events say what its findings did (decision 126): the events listed,
# the ref and HEAD paths folded with the bookkeeping, their findings in the JSON
grep -q '^  git HEAD main -> dev$' "$R3" && grep -q "^  git main ${H%????????????????????????????} -> ${H2%????????????????????????????}\$" "$R3" \
    || fail "git's events not shown, ids cut to 12 for reading: $(cat "$R3")"
! grep -q '  M \.git/refs/heads/main \|  M \.git/HEAD ' "$R3" || fail "a ref path listed beside its event: $(cat "$R3")"
grep -q '  A \.git/hooks/pre-commit' "$R3" && grep -q '  ~ \.git/hooks/post-merge' "$R3" || fail "a hook was folded"
grep -q '  M wt/\.git ' "$R3" && grep -q '  M src/a\.c' "$R3" || fail "a .git file or a real edit was folded"
J=${R3%.txt}.json
jq -e '[.sections[].records[].path] | index(".git/objects/01/a") != null' "$J" >/dev/null || fail "the JSON lost a folded path"
jq -e 'any(.sections[].records[]; .path == ".git/refs/heads/main" and any(.findings[]?; .kind == "git_ref_moved"))' "$J" >/dev/null \
    || fail "the JSON lost git's finding on the ref"
# A belay that emits no git events (the pinned release, before E12): git's
# findings stay listed, as decision 105 had them.
python3 -I -B -c '
import importlib.util, sys
spec = importlib.util.spec_from_file_location("r", sys.argv[1]); R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
ref = {"path": ".git/refs/heads/x", "outcome": "modified", "findings": [{"kind": "git_ref_moved"}]}
sys.exit(0 if R.folded_git(ref) is None and R.folded_git(ref, True) == "" else 1)' scripts/dogfood/receipt.py \
    || fail "without git events, git's findings were folded"

# A label is cut for one glance; the call's whole command is in the detail
# (turn-267: a command cut at 200 characters hid the git fetch that wrote).
long="cat README; gh pr view 36 --json state $(printf '%0220d' 0); git fetch -q origin
echo second line"
hook pre t12 Bash "$long"; printf 'd\n' >> "$S/src/a.c"; hook post t12 Bash
hook pre t13 Bash "python3 - <<'EOF'
open('src/e.c', 'w')
EOF"; printf 'e\n' > "$S/src/e.c"; hook post t13 Bash
out=$(hook stop)
R4=$(ls -t "$T/state/dogfood"/s1.turn-*.txt | head -1)
head=$(grep '^Bash: cat README' "$R4") || fail "no heading for the long call: $(cat "$R4")"
case $head in "Bash: cat README; gh pr view 36 --json state 00000000000000…   [1]") ;;
    *) fail "the heading is not cut to 60 with an ellipsis: $head" ;; esac
grep -q "^Bash: python3 - <<'EOF'…   \\[2\\]\$" "$R4" || fail "a short first line hides the other lines: $(cat "$R4")"
grep -q '^  \[1\] Bash: cat README.*; git fetch -q origin$' "$R4" && grep -q '^      echo second line$' "$R4" \
    || fail "the whole command is not in the detail: $(cat "$R4")"
printf '%s' "$out" | jq -e '.systemMessage | (test("git fetch") | not) and test("state 0+…")' >/dev/null \
    || fail "the Stop line does not carry the cut label: $out"
jq -e 'any(.sections[].calls[]; test("git fetch -q origin\necho second line"))' "${R4%.txt}.json" >/dev/null \
    || fail "the JSON lost the whole command"

# A command left running in the background (decision 111): what lands while
# it runs may be its writing -- said so, never put on the open call alone.
# Its end is seen at the next hook (its output file no longer open). One
# moved to the background at its timeout, whose output file cannot be
# found, runs until the stop.
export BELAY_DOGFOOD_TASKS="$T/tasks"; mkdir -p "$T/tasks"
raw() { printf '%s' "$2" | "$HOOK" "$1"; }
bgcall='"session_id":"s1","tool_use_id":"t20","tool_name":"Bash","tool_input":{"command":"make watch","run_in_background":true}'
raw pre "{$bgcall}"
sleep 60 > "$T/tasks/bgt20.output" & held=$!
raw post "{$bgcall,\"tool_response\":{\"backgroundTaskId\":\"bgt20\"}}"
hook pre t21 Bash "cat README"; printf 'w\n' > "$S/watch.out"; hook post t21 Bash
printf 'v\n' >> "$S/watch.out"
kill $held; wait $held 2>/dev/null || :        # its status is the kill's
hook pre t22 Bash "edit f"; printf 'f\n' > "$S/src/f.c"; hook post t22 Bash
tocall='"session_id":"s1","tool_use_id":"t23","tool_name":"Bash","tool_input":{"command":"long build"}'
raw pre "{$tocall}"; raw post "{$tocall,\"tool_response\":{\"backgroundTaskId\":\"gone1\",\"timedOutAfterMs\":120000}}"
printf 'g\n' > "$S/late.txt"
out=$(hook stop)
R5=$(ls -t "$T/state/dogfood"/s1.turn-*.txt | head -1)
grep -A2 '^a background command may have written these: Bash: make watch   (open at the time: Bash: cat README)$' "$R5" \
    | grep -q '  A watch.out' || fail "the open call was blamed for the background command's time: $(cat "$R5")"
! grep -q '^Bash: cat README' "$R5" || fail "a read-only call got changes while a background command ran: $(cat "$R5")"
grep -A2 '^a background command may have written these: Bash: make watch$' "$R5" | grep -q '  M watch.out' \
    || fail "a write between calls while it ran is not said to be maybe its"
grep -A2 '^Bash: edit f$' "$R5" | grep -q '  A src/f.c' || fail "after its end, a call is not credited: $(cat "$R5")"
grep -A2 '^a background command may have written these: Bash: long build$' "$R5" | grep -q '  A late.txt' \
    || fail "a command moved to the background at its timeout is not seen: $(cat "$R5")"
hook pre t24 Bash "after"; printf 'h\n' > "$S/src/h.c"; hook post t24 Bash
out=$(hook stop)
R6=$(ls -t "$T/state/dogfood"/s1.turn-*.txt | head -1)
grep -A2 '^Bash: after$' "$R6" | grep -q '  A src/h.c' && ! grep -q 'background command' "$R6" \
    || fail "a background command whose output cannot be found outlived the stop: $(cat "$R6")"

hook end
done_receipt s1 || fail "the session receipt did not finish"
[ -f "$T/state/dogfood/s1.receipt.txt" ] || fail "no session receipt"
ls "$T/notes"/*-s1.md >/dev/null 2>&1 || fail "a test file changed, but the receipt was not kept"
grep -q 'Kept because: a test file changed' "$T"/notes/*-s1.md || fail "kept for the wrong reason"
# A whole directory added folds to one line; a setuid file, a test file
# and a finding git made below it stay listed (decision 116). The headline
# counts paths, and changes across calls when they differ (decision 117).
hook start
hook pre t30 Bash "unpack"
mkdir -p "$S/pkg/lib/deep" "$S/pkg/tests" "$S/pkg/.git/refs/heads"
for i in 1 2 3 4 5; do printf '%s\n' "$i" > "$S/pkg/lib/deep/f$i.txt"; done
printf 'x\n' > "$S/pkg/tool"; chmod 4755 "$S/pkg/tool"
printf 'def test_y(): assert 1\n' > "$S/pkg/tests/test_y.py"
printf '%s\n' "$H" > "$S/pkg/.git/refs/heads/main"
hook post t30 Bash
hook pre t31 Bash "touch"; printf 'again\n' > "$S/pkg/lib/deep/f1.txt"; hook post t31 Bash
out=$(hook stop)
R7=$(ls -t "$T/state/dogfood"/s1.turn-*.txt | head -1)
grep -q '^  A pkg/ and [0-9][0-9,]* entries below it$' "$R7" || fail "a whole added directory not folded: $(cat "$R7")"
grep -q '  A pkg/tool' "$R7" || fail "a setuid file under it was folded: $(cat "$R7")"
grep -q '  A pkg/tests/test_y.py' "$R7" || fail "a test file under it was folded"
grep -q "^  git main now at ${H%????????????????????????????}\$" "$R7" || fail "a git finding under it was folded"   # its event: no evidence it was absent (E12)
! grep -q 'pkg/lib/deep/f2' "$R7" || fail "a plain file under it was listed: $(cat "$R7")"
n=$(jq '[.sections[] | select(.section | startswith("unknown throughout") | not) | .records[] | select(.event == null) | .path] | unique | length' "${R7%.txt}.json")
grep -q "^  $n paths changed ([0-9]* changes across calls)" "$R7" || fail "the headline does not count paths: $(head -2 "$R7")"
printf '%s' "$out" | jq -e --arg n "$n" '.systemMessage | test("^belay: " + $n + " paths changed this turn \\([0-9]+ changes across calls\\)")' >/dev/null \
    || fail "the Stop line does not count paths: $out"

# Never silent (decision 114): a hook that fails is said at the next Stop,
# every Stop while it keeps failing, and no more once it works again.
hook pre t40 Bash "x" </dev/null >/dev/null
BELAY=/nonexistent/belay hook pre t41 Bash "y"
out=$(hook stop)
printf '%s' "$out" | jq -e '.systemMessage | test("^belay: hooks failing: pre: belay mark failed")' >/dev/null \
    || fail "a failed mark was not said at the Stop: $out"
out=$(hook stop)
printf '%s' "$out" | jq -e '.systemMessage | test("hooks failing") | not' >/dev/null \
    || fail "a failure said again after it stopped: $out"
for k in 1 2; do
    out=$(BELAY=/nonexistent/belay hook stop)
    printf '%s' "$out" | jq -e '.systemMessage | test("^belay: hooks failing: stop: belay mark failed")' >/dev/null \
        || fail "a lasting failure was not said at Stop $k: $out"
done
mkdir -p "$T/broken" && cp "$HOOK" "$T/broken/" && echo 'raise SystemExit(3)' > "$T/broken/receipt.py"
out=$(jq -cn '{session_id:"s1"}' | "$T/broken/belay-dogfood" stop)
printf '%s' "$out" | jq -e '.systemMessage | test("hooks failing: stop: the turn.s receipt failed")' >/dev/null \
    || fail "a failed receipt was not said: $out"
mkdir -p "$T/nojq" && for c in date cat mkdir chmod tr sed head wc mv rm dirname cut; do ln -sf "$(command -v $c)" "$T/nojq/$c"; done
out=$(printf '{}' | PATH="$T/nojq" "$HOOK" stop)
printf '%s' "$out" | grep -q '"systemMessage":"belay: hooks failing: stop: jq not found' || fail "a missing jq was not said: $out"

# A hook that failed (decision 122): the calls around it were never seen,
# so what changed then is unattributed -- never "between tool calls", never
# background writing.
hook pre t60 Bash "seen"; printf 'a\n' > "$S/seen.txt"; hook post t60 Bash
BELAY=/nonexistent/belay hook pre t61 Bash "unseen"
printf 'b\n' > "$S/unseen.txt"
hook post t61 Bash
out=$(hook stop)
R8=$(ls -t "$T/state/dogfood"/s1.turn-*.txt | head -1)
grep -A3 "^hooks were inactive; these changes are unattributed$" "$R8" | grep -q '  A unseen.txt' \
    || fail "changes around a failed hook were not unattributed: $(cat "$R8")"
grep -A2 '^Bash: seen$' "$R8" | grep -q '  A seen.txt' || fail "the call before the failure lost its change: $(cat "$R8")"
! grep -q 'background writers\|^between tool calls' "$R8" || fail "a failed hook's gap read as background writing: $(cat "$R8")"
printf '%s' "$out" | jq -e '.systemMessage | test("^belay: hooks failing: pre: belay mark failed")' >/dev/null \
    || fail "the failure was not said with the receipt: $out"

# The turn at a glance (decisions 125, 127, 128): a summary before any
# section -- edited with line counts, files added and removed, git,
# packages, privilege, build output, unknown; a file touched with its
# content unchanged folds, a mode change never does; a long command shows
# ten lines and counts the rest, the whole of it in the JSON.
hook pre t80 Bash "glance"
printf 'x\ny\nz\n' >> "$S/src/a.c"
mkdir -p "$S/newpkg" "$S/build" "$S/venv/lib/python3.12/site-packages/foo-1.0.dist-info"
printf '1\n' > "$S/newpkg/one.txt"; printf '2\n' > "$S/newpkg/two.txt"; printf 'n\n' > "$S/src/new1.c"
for i in 1 2 3 4 5; do printf '%s\n' "$i" > "$S/src/m$i.c"; done
mkdir -p "$S/src/__pycache__"; printf 'p' > "$S/src/__pycache__/a.cpython-312.pyc"; printf 'q' > "$S/stray.pyc"
rm "$S/src/b.c"
chmod 4755 "$S/src/c.c"
printf 'o' > "$S/build/out.o"
touch -m -d '2002-02-02' "$S/src/d.c"
printf '%s\n' "$H" > "$S/.git/refs/heads/feature"
printf 'Name: foo\nVersion: 1.0\n' > "$S/venv/lib/python3.12/site-packages/foo-1.0.dist-info/METADATA"
printf 'foo-1.0.dist-info/METADATA,,\n' > "$S/venv/lib/python3.12/site-packages/foo-1.0.dist-info/RECORD"
hook post t80 Bash
fifteen=$(seq 1 15 | sed 's/^/echo line /')
hook pre t81 Bash "$fifteen"; printf 'q\n' > "$S/src/q.c"; hook post t81 Bash
out=$(hook stop)
R10=$(ls -t "$T/state/dogfood"/s1.turn-*.txt | head -1)
[ "$(sed -n 4p "$R10")" = "summary" ] || fail "no summary before the sections: $(head -6 "$R10")"
sum=$(sed -n '/^summary$/,/^$/p' "$R10")
n=$(printf '%s\n' "$sum" | grep -c '^  ')
[ "$n" -ge 3 ] && [ "$n" -le 8 ] || fail "a summary of $n lines: $sum"
printf '%s\n' "$sum" | grep -q '^  edited     .*src/a\.c +3 -0' || fail "the edit's line counts not summarised: $sum"
printf '%s\n' "$sum" | grep -q '^  files      added [0-9]*: .*newpkg/ (+2).*; removed 1: src/b\.c' || fail "added and removed not summarised: $sum"
printf '%s\n' "$sum" | grep -q '^  files      added [0-9]*: [^;]* (and [0-9]* more);' || fail "a long list not cut with a count: $sum"
printf '%s\n' "$sum" | grep -q "^  git        .*feature now at ${H%????????????????????????????}\$" || fail "git not summarised: $sum"   # git's event (E12)
printf '%s\n' "$sum" | grep -q '^  packages   pip installed foo 1\.0' || fail "the package not summarised: $sum"
printf '%s\n' "$sum" | grep -q '^  privilege  .*src/c\.c' || fail "the setuid bit not summarised: $sum"
printf '%s\n' "$sum" | grep -q '^  build      2 changes under build/, bin/; 3 compiled Python$' || fail "build output not counted: $sum"
! printf '%s\n' "$sum" | grep -q 'build/ (+' || fail "build/ listed as an added directory: $sum"
! printf '%s\n' "$sum" | grep -q 'pyc\|__pycache__' || fail "compiled Python listed as edits: $sum"
grep -A30 '^Bash: glance$' "$R10" | grep -q '^  compiled Python: 3 changes (__pycache__/, \*\.pyc)$' || fail "compiled Python not folded: $(cat "$R10")"
printf '%s\n' "$sum" | grep -q '^  unknown    .*locked' || fail "the unknown not summarised: $sum"
grep -A20 '^Bash: glance$' "$R10" | grep -q '^  ~ 1 file touched, content unchanged   \[t1\]$' || fail "an mtime-only change not folded: $(cat "$R10")"
grep -A1 '^the files touched, content unchanged$' "$R10" | grep -q '^  \[t1\] src/d\.c$' || fail "the touched file not in the detail"
grep -q '^  ~ src/c\.c   mode' "$R10" || fail "a mode change was folded with the touched files: $(cat "$R10")"
grep -q '^      echo line 10$' "$R10" && ! grep -q '^      echo line 11$' "$R10" && grep -q '^      … 5 more lines$' "$R10" \
    || fail "a long command not shown as ten lines and a count: $(cat "$R10")"
jq -e 'any(.sections[].calls[]; test("echo line 15$"))' "${R10%.txt}.json" >/dev/null || fail "the JSON lost the whole command"

# Lost receipts are loud (decision 143). The session receipt is made
# detached: the end hook returns at once, however long the receipt takes,
# and the receipt still arrives. A mark whose maker is gone -- a session's or
# a turn's receipt killed by a hook's timeout -- is said at the next Stop, by
# any session's hook, once; a "starting" mark only after a minute.
mkdir -p "$T/slow" && cp "$HOOK" "$T/slow/"
printf 'import runpy, sys, time\ntime.sleep(3)\nsys.argv[0] = "%s"\nrunpy.run_path("%s", run_name="__main__")\n' \
    "$PWD/scripts/dogfood/receipt.py" "$PWD/scripts/dogfood/receipt.py" > "$T/slow/receipt.py"
slow() { jq -cn --arg t "${2:-}" '{session_id:"s5", tool_use_id:$t, tool_name:"Bash", tool_input:{command:"x"}}' | "$T/slow/belay-dogfood" "$1"; }
slow start; slow pre t90; printf 's\n' > "$S/slow.txt"; slow post t90
t0=$(date +%s); slow end; t1=$(date +%s)
[ $((t1 - t0)) -lt 2 ] || fail "the end hook waited for its receipt ($((t1 - t0)) s)"
[ -e "$T/state/dogfood/s5.receipt-running.session" ] || fail "no mark while the session receipt is made"
sleep 1; hook pre t89 Bash "while it is made"; hook post t89 Bash      # its maker alive: not lost
done_receipt s5 && [ -f "$T/state/dogfood/s5.receipt.txt" ] || fail "the detached session receipt never arrived"
sh -c 'exit 0' & dead=$!; wait $dead
printf '%s %s session\n' "$dead" "$(date +%s%N)" > "$T/state/dogfood/ghost.receipt-running.session"
printf '%s %s turn\n' "$dead" "$(date +%s%N)" > "$T/state/dogfood/ghost2.receipt-running.turn"
printf 'starting %s session\n' "$(date +%s%N)" > "$T/state/dogfood/young.receipt-running.session"
printf 'starting %s session\n' "$(( $(date +%s) - 120 ))000000000" > "$T/state/dogfood/old.receipt-running.session"
hook pre t91 Bash "after"
out=$(hook stop)
printf '%s' "$out" | jq -e '.systemMessage | test("^belay: hooks failing: pre: the (session|turn) receipt of session [a-z0-9]+ was lost: begun [0-9:]+ UTC and never finished") and test("and 2 more since the last stop")' >/dev/null \
    || fail "the lost receipts not said at the Stop: $out"
for w in "session receipt of session ghost was lost" "turn receipt of session ghost2 was lost" "session receipt of session old was lost"; do
    grep -qF "$w" "$T/state/dogfood/failures.log" || fail "a lost receipt not kept ($w)"
done
! printf '%s' "$out" | grep -q 'young' || fail "a receipt still starting was called lost: $out"
! grep -q 'session s5 was lost' "$T/state/dogfood/failures.log" || fail "a receipt still being made was called lost"
[ -e "$T/state/dogfood/young.receipt-running.session" ] || fail "a receipt still starting lost its mark"
out=$(hook stop)
! printf '%s' "$out" | grep -q 'was lost' || fail "a lost receipt said twice: $out"
! ls "$T/state/dogfood"/s1.receipt-running.* >/dev/null 2>&1 || fail "a finished turn receipt left its mark"
rm -f "$T/state/dogfood/young.receipt-running.session"

# A receipt that succeeds and says nothing is a failure said at this Stop,
# never a Stop without a line (decision 156).
mkdir -p "$T/mute" && cp "$HOOK" "$T/mute/" && printf 'pass\n' > "$T/mute/receipt.py"
out=$(jq -cn '{session_id:"s6"}' | "$T/mute/belay-dogfood" stop)
printf '%s' "$out" | jq -e '.systemMessage | test("^belay: hooks failing: stop: the turn.s receipt gave no line")' >/dev/null \
    || fail "a receipt with no line made a silent Stop: $out"
# a log with no checkpoint at all (every mark failed) still gives a line
printf '{"event":"error","during":"stop","message":"x"}\n' > "$T/nocp.jsonl"
out=$(python3 -I scripts/dogfood/receipt.py turn "$T/nocp.jsonl" "$BELAY" "$S" "$T/state/dogfood")
[ "$out" = "belay: no checkpoint recorded in this session, so no receipt this turn" ] \
    || fail "a turn with no checkpoint said: $out"

# install.sh (decision 115): the settings in a file, one line printed that
# merges them into settings.json after a backup of its own -- other hooks
# and keys kept, an earlier belay hook replaced, twice the same as once. A
# script that no longer matches its checksum is said at every Stop (114).
FH=$T/home; mkdir -p "$FH/.claude"
printf '%s' '{"theme":"dark","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other-hook"}]},{"hooks":[{"type":"command","command":"cd / && /old/belay-dogfood pre"}]}]}}' > "$FH/.claude/settings.json"
m=$(HOME=$FH sh scripts/dogfood/install.sh "$BELAY" "$S" 2>/dev/null)
[ "$(printf '%s\n' "$m" | wc -l)" = 1 ] || fail "install.sh printed more than the merge command: $m"
SH=$FH/.local/share/belay/dogfood/settings-hooks.json
jq -e '.hooks | keys == ["PostToolUse","PostToolUseFailure","PreToolUse","SessionEnd","SessionStart","Stop"]' "$SH" >/dev/null || fail "no settings file"
sh -c "$m" >/dev/null && sh -c "$m" >/dev/null || fail "the merge command failed"
jq -e '.theme == "dark" and ([.hooks.PreToolUse[].hooks[].command] | (index("other-hook") != null)
        and (map(select(test("belay-dogfood"))) | length == 1) and (map(select(test("/old/"))) | length == 0))' \
    "$FH/.claude/settings.json" >/dev/null || fail "the merge lost or doubled a hook: $(cat "$FH/.claude/settings.json")"
[ "$(ls "$FH/.claude"/settings.json.bak-* | wc -l)" = 2 ] || fail "each merge does not keep a backup of its own"
grep -q 'other-hook' "$(ls "$FH/.claude"/settings.json.bak-* | head -1)" && ! grep -q 'belay-dogfood pre"' "$(ls "$FH/.claude"/settings.json.bak-* | head -1)" \
    || ! grep -q "$FH/.local" "$(ls "$FH/.claude"/settings.json.bak-* | head -1)" || fail "the first backup is not the settings as they were"
stop=$(jq -r '.hooks.Stop[0].hooks[0].command' "$SH")
out=$(jq -cn '{session_id:"s1"}' | sh -c "$stop")
! printf '%s' "$out" | grep -q 'inactive' || fail "the installed Stop hook is inactive: $out"
echo '#' >> "$FH/.local/share/belay/dogfood/receipt.py"
for k in 1 2; do
    out=$(jq -cn '{session_id:"s1"}' | sh -c "$stop")
    printf '%s' "$out" | jq -e '.systemMessage | test("^belay: hooks inactive: checksum mismatch: .*/receipt.py -- run scripts/dogfood/install.sh$")' >/dev/null \
        || fail "a checksum mismatch was not said at Stop $k: $out"
done
# Inactive hooks are recorded at every event, and once installed again the
# receipt says what changed meanwhile is unattributed (decision 122).
run_cmd() {  # run_cmd EVENT tool_use_id summary -- the installed command for EVENT
    c=$(jq -r --arg e "$1" '.hooks[$e][0].hooks[0].command' "$SH")
    jq -cn --arg t "$2" --arg s "$3" '{session_id:"s3", tool_use_id:$t, tool_name:"Bash", tool_input:{command:$s}}' | sh -c "$c"
}
run_cmd PreToolUse t71 "while inactive" >/dev/null
printf 'd\n' > "$S/while-inactive.txt"
run_cmd PostToolUse t71 "while inactive" >/dev/null
grep -q 'pre: checksum mismatch (hooks inactive)' "$T/state/dogfood/failing" || fail "an inactive pre hook left no record"
HOME=$FH sh scripts/dogfood/install.sh "$BELAY" "$S" >/dev/null 2>&1
SH=$FH/.local/share/belay/dogfood/settings-hooks.json
run_cmd SessionStart "" "" >/dev/null
run_cmd PreToolUse t72 "before" >/dev/null; printf 'c\n' > "$S/before-gap.txt"; run_cmd PostToolUse t72 "before" >/dev/null
echo '#' >> "$FH/.local/share/belay/dogfood/receipt.py"
run_cmd PreToolUse t73 "while inactive" >/dev/null
printf 'e\n' > "$S/gap.txt"
run_cmd PostToolUse t73 "while inactive" >/dev/null
HOME=$FH sh scripts/dogfood/install.sh "$BELAY" "$S" >/dev/null 2>&1
run_cmd PreToolUse t74 "after" >/dev/null; printf 'f\n' > "$S/after-gap.txt"; run_cmd PostToolUse t74 "after" >/dev/null
out=$(run_cmd Stop "" "")
R9=$(ls -t "$T/state/dogfood"/s3.turn-*.txt | head -1)
grep -A3 "^hooks were inactive; these changes are unattributed$" "$R9" | grep -q '  A gap.txt' \
    || fail "changes made while the hooks were inactive were not unattributed: $(cat "$R9")"
grep -A2 '^Bash: before$' "$R9" | grep -q '  A before-gap.txt' && grep -A2 '^Bash: after$' "$R9" | grep -q '  A after-gap.txt' \
    || fail "the calls around the gap lost their changes: $(cat "$R9")"
! grep -q 'background writers\|^between tool calls' "$R9" || fail "an inactive gap read as background writing: $(cat "$R9")"
printf '%s' "$out" | jq -e '.systemMessage | test("^belay: hooks failing: [a-z]+: checksum mismatch \\(hooks inactive\\)")' >/dev/null \
    || fail "the first good Stop did not say the hooks had been inactive: $out"
echo "dogfood selftest: sequential, concurrent, background, cancelled, quiet turn said, other project, symlinked project, git folded, labels cut, background commands, directories folded, paths counted, failures said, inactive gaps unattributed, summary, touched folded, long commands, git events, compiled Python, lost receipts, install: ok"
