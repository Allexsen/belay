#!/bin/sh
#
# M1's done criterion, end to end: check, mark, diff and log through the
# real binary, unprivileged, in a plain directory -- run by `make check`, so
# by every CI job that runs it: linux (x86_64, arm64), docker (a non-root
# user in ubuntu:24.04) and macos-portable. Fixtures for the text, pip, dpkg
# and git interpreters; --json validated against schema/checkpoint.v1.json;
# exit codes checked. Fails on the first broken expectation, naming it.
#
#   scripts/e2e.sh [path/to/belay]

set -eu

BELAY=${1:-bin/belay}
case $BELAY in /*) ;; *) BELAY=$PWD/$BELAY ;; esac
VALIDATE="python3 $PWD/scripts/check-json-schema.py $PWD/schema/checkpoint.v1.json"
T=$(mktemp -d "${TMPDIR:-/tmp}/belay-e2e.XXXXXX")
trap 'chmod -R u+rwx "${T:?}" 2>/dev/null; rm -rf "${T:?}"' EXIT
S=$T/scope
export BELAY_STATE_DIR="$T/state"
fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
want() {   # want <file> <fixed string>: the output holds it
    grep -F -- "$2" "$1" >/dev/null || { echo "--- $1:" >&2; cat "$1" >&2; fail "expected: $2"; }
}
code() {   # code <expected exit> <command...>
    exp=$1; shift
    set +e; "$@" >"$T/out" 2>"$T/err"; got=$?; set -e
    [ "$got" = "$exp" ] || { cat "$T/err" >&2; fail "exit $got, expected $exp: $*"; }
}

# ---- the scope, before ----
mkdir -p "$S/lib/site-packages/six-1.16.0.dist-info" "$S/var/lib/dpkg" "$S/repo/.git/refs/heads" \
         "$S/repo/.git/hooks" "$S/bin"
printf 'one\ntwo\nthree\n' > "$S/notes.txt"
printf 'six.py,sha256=AAAA,100\nsix-1.16.0.dist-info/RECORD,,\n' > "$S/lib/site-packages/six-1.16.0.dist-info/RECORD"
printf 'Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.1-6\n\nPackage: vim\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2:9.0-1\n' > "$S/var/lib/dpkg/status"
printf 'ref: refs/heads/main\n' > "$S/repo/.git/HEAD"
printf '1111111111111111111111111111111111111111\n' > "$S/repo/.git/refs/heads/main"
printf '#!/bin/sh\n' > "$S/repo/.git/hooks/pre-commit"
printf 'tool\n' > "$S/bin/tool"
chmod 755 "$S/bin/tool"

code 0 "$BELAY" check --scope "$S" --json
$VALIDATE < "$T/out" || fail "check --json does not match its schema"
want "$T/out" '"id":1,"kind":"check"'

# ---- changes: one per interpreter, and a privilege change ----
printf 'one\nTWO\nthree\nfour\n' > "$S/notes.txt"
mv "$S/lib/site-packages/six-1.16.0.dist-info" "$S/lib/site-packages/six-1.17.0.dist-info"
printf 'Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2-1\n\nPackage: vim\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 2:9.0-1\n' > "$S/var/lib/dpkg/status"
printf '2222222222222222222222222222222222222222\n' > "$S/repo/.git/refs/heads/main"
printf '#!/bin/sh\nexit 1\n' > "$S/repo/.git/hooks/pre-commit"
chmod 4755 "$S/bin/tool"

code 0 "$BELAY" mark --scope "$S" --json
$VALIDATE < "$T/out" || fail "mark --json does not match its schema"
want "$T/out" '"kind":"mark"'
want "$T/out" '"used":true'

code 0 "$BELAY" diff --scope "$S" --since 1 --to 2
want "$T/out" 'packages and files explained'
want "$T/out" 'upgraded six 1.16.0 -> 1.17.0'
want "$T/out" 'upgraded bash:amd64 5.1-6 -> 5.2-1'
want "$T/out" 'removed vim:amd64 2:9.0-1'
want "$T/out" 'privilege'
want "$T/out" 'bin/tool   setuid added (mode 0755 -> 4755)'
want "$T/out" '+2 -1 lines, first change at line 2'
want "$T/out" 'refs/heads/main 1111111111111111111111111111111111111111 -> 2222222222222222222222222222222222222222'
want "$T/out" 'hook pre-commit changed'

code 0 "$BELAY" diff --scope "$S" --since 1 --to 2 --json
head -1 "$T/out" | grep -q '^{"belay_diff":1,' || fail "diff --json is not diff.v1"
code 1 "$BELAY" diff --scope "$S" --since 1 --to 2 --exit-code
code 0 "$BELAY" diff --scope "$S" --since 2 --exit-code      # nothing since: 0, kept as checkpoint 3

code 0 "$BELAY" log --scope "$S" --json
$VALIDATE < "$T/out" || fail "log --json does not match its schema"
[ "$(wc -l < "$T/out" | tr -d ' ')" = 3 ] || fail "log lists $(wc -l < "$T/out") checkpoints, expected 3"

# ---- refusals and usage ----
code 3 "$BELAY" check --scope "$T/missing"
code 3 "$BELAY" check --scope "$S/notes.txt"
code 2 "$BELAY" check --scope "$S" --bogus
code 2 "$BELAY" diff --scope "$S" --since 99
[ ! -s "$T/out" ] || fail "an error wrote to stdout"

echo "e2e: check, mark, diff and log, unprivileged in a plain directory: ok"
