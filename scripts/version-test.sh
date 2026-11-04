#!/bin/sh
#
# scripts/version.sh and python/build_keys.py's PEP 440 spelling (PY-D2),
# against real git repositories made here:
#
#   a clean tree at the tag v<BASE>            BASE (a release)
#   the tag fetched as the release workflow    BASE
#     does (depth 1, +<sha>:refs/tags/v<BASE>,
#     a lightweight ref)
#   commits after the tag                      BASE+<n>-g<sha>
#   a tracked file changed, or staged          ...-dirty; an untracked file is not
#   a file touched, its content the same       not dirty, and .git/index untouched
#   at a tag that is not v<BASE>               BASE+0-g<sha>
#   no git; no tag; inside another repository  BASE+unknown
#
# Part of `make check`.

set -eu
VS=$(cd "$(dirname "$0")" && pwd -P)/version.sh
PY=$(cd "$(dirname "$0")/../python" && pwd -P)
T=$(mktemp -d "${TMPDIR:-/tmp}/belay-version.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "version-test: FAIL: $*" >&2; exit 1; }
g() { git -c user.name=t -c user.email=t@t -c init.defaultBranch=main -c tag.gpgSign=false -c commit.gpgSign=false "$@"; }
B=0.1.0-alpha.2
want() {  # want DIR EXPECTED WHAT
    got=$(cd "$1" && sh "$VS" "$B")
    [ "$got" = "$2" ] || fail "$3: want $2, got $got"
}

mkdir "$T/plain" && want "$T/plain" "$B+unknown" "no git"

R=$T/repo
g init -q "$R" && printf 'a\n' > "$R/f" && g -C "$R" add f && g -C "$R" commit -q -m one
want "$R" "$B+unknown" "no tag"
g -C "$R" tag -a -m "v$B" "v$B"
want "$R" "$B" "a clean tree at the tag"

F=$T/fetched
g init -q "$F" && g -C "$F" fetch -q --no-tags --depth=1 "file://$R" "+$(g -C "$R" rev-parse HEAD):refs/tags/v$B"
g -C "$F" checkout -q "v$B"
[ "$(g -C "$F" cat-file -t "v$B")" = commit ] || fail "the release-style fetch did not make a lightweight tag"
want "$F" "$B" "the tag as the release workflow fetches it"

printf 'b\n' >> "$R/f" && g -C "$R" commit -q -am two
sha=$(g -C "$R" rev-parse --short HEAD)
want "$R" "$B+1-g$sha" "a commit after the tag"
printf 'c\n' > "$R/untracked" && want "$R" "$B+1-g$sha" "an untracked file"
printf 'd\n' >> "$R/f" && want "$R" "$B+1-g$sha-dirty" "a tracked file changed"
g -C "$R" add f && want "$R" "$B+1-g$sha-dirty" "a change staged"
g -C "$R" reset -q --hard
touch -t 200101010000 "$R/f"         # its stat data in the index is stale now
before=$(ls -i "$R/.git/index")      # git replaces the index by a rename: a new inode
want "$R" "$B+1-g$sha" "a file touched, its content the same"
[ "$(ls -i "$R/.git/index")" = "$before" ] || fail "version.sh wrote .git/index"

g -C "$R" tag -a -m other v9.9.9 && want "$R" "$B+0-g$sha" "at a tag that is not v<BASE>"
mkdir "$R/sub" && want "$R/sub" "$B+unknown" "a subdirectory: inside another repository"

out=$(python3 -I -c '
import sys; sys.path.insert(0, sys.argv[1]); from build_keys import pep440
for v in sys.argv[2:]: print(pep440(v))' "$PY" "$B" "$B+95-ga2054b3" "$B+95-ga2054b3-dirty" "$B+unknown" 0.1.0-rc.1)
[ "$out" = "$(printf '0.1.0a2\n0.1.0a2+95.ga2054b3\n0.1.0a2+95.ga2054b3.dirty\n0.1.0a2+unknown\n0.1.0rc1')" ] \
    || fail "PEP 440 spellings: $out"
echo "version-test: release, release as fetched, development, dirty, untracked, touched, other tags, no git, no tag, nested, PEP 440: ok"
