#!/bin/sh
#
# test/expect/manifest-v1-addendum.md is append-only: every row it had at
# BASE must be, unchanged and in order, the first rows it has at HEAD.
#
# Usage: scripts/check-addendum.sh <base-ref> <head-ref>

set -eu

F=test/expect/manifest-v1-addendum.md
T=$(mktemp -d "${TMPDIR:-/tmp}/check-addendum.XXXXXX")
trap 'rm -rf "$T"' EXIT

git show "$1:$F" 2>/dev/null | grep '^| A' > "$T/old" || true
if [ ! -s "$T/old" ]; then
	echo "check-addendum: no rows at $1"
	exit 0
fi
git show "$2:$F" 2>/dev/null | grep '^| A' > "$T/new" || true
n=$(wc -l < "$T/old")
head -n "$n" "$T/new" > "$T/head"
if ! cmp -s "$T/old" "$T/head"; then
	echo "check-addendum: a row of $F changed or went away between $1 and $2:"
	diff "$T/old" "$T/head" || true
	exit 1
fi
echo "check-addendum: the $n existing row(s) are unchanged"
