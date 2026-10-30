#!/bin/sh
#
# Prints the hashes of the commits scripts/bisect-skip.txt names, for
# `git bisect skip`, found by author date and subject in REV's history.
# Fails, naming the entry, if an entry matches no commit or more than one.
#
# Usage: scripts/bisect-skip.sh [REV]     (default: origin/main, else main)

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
LIST="$HERE/bisect-skip.txt"
if [ $# -ge 1 ]; then
	REV=$1
elif git rev-parse -q --verify origin/main >/dev/null; then
	REV=origin/main
else
	REV=main
fi

git log --format='%H%x09%aI%x09%s' "$REV" | awk -F'\t' -v list="$LIST" '
BEGIN {
	while ((getline line < list) > 0) {
		if (line ~ /^#/ || line == "") continue
		n++; key[n] = line
	}
}
{ k = $2 "\t" $3; for (i = 1; i <= n; i++) if (key[i] == k) { hit[i]++; sha[i] = $1 } }
END {
	bad = 0
	for (i = 1; i <= n; i++) {
		if (hit[i] != 1) {
			printf "bisect-skip: %d commits match: %s\n", hit[i], key[i] > "/dev/stderr"
			bad = 1
		} else print sha[i]
	}
	exit bad
}'
