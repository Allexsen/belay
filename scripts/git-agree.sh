#!/bin/sh
#
# belay's git interpreter against real git (decision 183: belay describes
# git's state, so what git ignores or refuses is not state). Each case is
# made with git, and the test first asserts what git itself does with the
# file -- so a git that reads it otherwise fails here, loudly, and the pin is
# looked at again -- then what belay's diff says:
#
#   a reflog whose last line has no newline   git: not an entry    belay: no entry gained
#   a blank line in a reflog                  git: skipped         belay: skipped
#   a packed-refs that ends without a newline git: refused         belay: could_not_interpret
#   a loose ref, HEAD, without the newline    git: read            belay: read
#
# Each beside its control, the same file with its newline. Run by e2e.sh.
#
#   scripts/git-agree.sh [path/to/belay]

set -eu
BELAY=${1:-bin/belay}
case $BELAY in /*) ;; *) BELAY=$PWD/$BELAY ;; esac
command -v git >/dev/null || { echo "git-agree: FAIL: git is needed (CI installs it)" >&2; exit 1; }
T=$(mktemp -d "${TMPDIR:-/tmp}/belay-git-agree.XXXXXX")
trap 'rm -rf "${T:?}"' EXIT
fail() { echo "git-agree: FAIL: $*" >&2; exit 1; }
G() { git -C "$R" -c user.name=a -c user.email=a@b -c core.hooksPath=/dev/null "$@"; }

# A repository with two commits on main, captured; then `change`; then the
# diff since the capture, as diff.v1.
run() {   # run NAME CHANGE...
    R=$T/$1; shift
    git init -q -b main "$R"
    G commit -q --allow-empty -m one
    G commit -q --allow-empty -m two
    BELAY_STATE_DIR=$T/state-${R##*/} "$BELAY" check --scope "$R" >/dev/null
    "$@"
    BELAY_STATE_DIR=$T/state-${R##*/} "$BELAY" diff --scope "$R" --since 1 --json > "$R.diff"
}
has() { grep -qF -- "$2" "$1" || { cat "$1" >&2; fail "$3"; }; }
hasnt() { ! grep -qF -- "$2" "$1" || { cat "$1" >&2; fail "$3"; }; }
strip_last_newline() { python3 -c 'import sys; p = sys.argv[1]; b = open(p, "rb").read(); open(p, "wb").write(b[:-1])' "$1"; }

# ---- a reflog whose last line has no newline ----
third_cut() { G commit -q --allow-empty -m three; strip_last_newline "$R/.git/logs/refs/heads/main"; }
run reflog-cut third_cut
[ "$(G reflog show main | wc -l | tr -d " ")" = 2 ] || fail "git reads a reflog's unterminated last line as an entry: the pin no longer holds"
has "$R.diff" '"event":"git_branch_moved","interp":"git","repo":".git","branch":"main"' "the moved branch not said"
hasnt "$R.diff" '"git_commits_added"' "an unterminated reflog line used as an entry"
grep '"path":".git/logs/refs/heads/main"' "$R.diff" > "$R.main"
hasnt "$R.main" '"kind":"git_reflog_appended"' "an unterminated reflog line counted"
third() { G commit -q --allow-empty -m three; }
run reflog-control third
[ "$(G reflog show main | wc -l | tr -d " ")" = 3 ] || fail "the control's reflog is not three entries"
has "$R.diff" '"event":"git_commits_added","interp":"git","repo":".git","branch":"main","count":1' "the control's commit not counted"

# ---- a blank line in a reflog: git skips it ----
blank_then_third() { printf '\n' >> "$R/.git/logs/refs/heads/main"; G commit -q --allow-empty -m three; }
run reflog-blank blank_then_third
[ "$(G reflog show main | wc -l | tr -d " ")" = 3 ] || fail "git does not skip a blank reflog line: the words no longer hold"
has "$R.diff" '"event":"git_commits_added","interp":"git","repo":".git","branch":"main","count":1' "a blank reflog line read as an entry"
hasnt "$R.diff" 'could_not_interpret' "a blank reflog line not skipped"

# ---- a packed-refs that ends without a newline ----
packed_cut() {
    G branch x; G pack-refs --all             # x only in packed-refs
    G commit -q --allow-empty -m three        # main moves (its loose ref)
    strip_last_newline "$R/.git/packed-refs"
}
run packed-cut packed_cut
if G rev-parse -q --verify x >/dev/null 2>&1; then fail "git reads a packed-refs that ends without a newline: the pin no longer holds"; fi
has "$R.diff" '{"event":"could_not_interpret","interp":"git","text":"could not interpret","paths":[".git/packed-refs"]}' \
    "a packed-refs git refuses not said could_not_interpret"
packed() { G branch x; G pack-refs --all; G commit -q --allow-empty -m three; }
run packed-control packed
G rev-parse -q --verify x >/dev/null || fail "the control's packed-refs is not read by git"
hasnt "$R.diff" '{"event":"could_not_interpret","interp":"git","text":"could not interpret","paths":[".git/packed-refs"]}' \
    "the control's packed-refs said could_not_interpret"
has "$R.diff" '"event":"git_branch_created","interp":"git","repo":".git","branch":"x"' "the control's packed branch not read"

# ---- a loose ref and HEAD without their newline ----
loose_cut() {
    G commit -q --allow-empty -m three
    printf '%s' "$(G rev-parse main)" > "$R/.git/refs/heads/main"
    printf 'ref: refs/heads/main' > "$R/.git/HEAD"
}
run loose-cut loose_cut
G rev-parse -q --verify main >/dev/null && [ "$(G symbolic-ref HEAD)" = refs/heads/main ] \
    || fail "git does not read a loose ref or HEAD without its newline: the pin no longer holds"
has "$R.diff" '"event":"git_commits_added","interp":"git","repo":".git","branch":"main","count":1' "a loose ref without its newline not read"
hasnt "$R.diff" 'could_not_interpret' "a loose ref or HEAD without its newline refused"

echo "git-agree: belay reads the reflog, packed-refs, loose refs and HEAD as $(git --version | cut -d' ' -f3) does: ok"
