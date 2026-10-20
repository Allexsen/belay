#!/bin/sh
#
# DCO sign-off check (BELAY_DESIGN.md §4.5).
#
# Every commit in the range must carry a Signed-off-by: line whose name and
# email match the commit author. Enforced from 2026-10-20 forward; earlier
# commits are exempt by decision, with no backfill.
#
# Usage: scripts/check-dco.sh <base-ref> <head-ref>
#        scripts/check-dco.sh              (defaults to origin/main..HEAD)

set -eu

BASE="${1:-origin/main}"
HEAD="${2:-HEAD}"

fail=0
count=0

# %H alone per line; everything else is looked up per commit so that
# multi-line trailers are handled.
for sha in $(git rev-list "$BASE".."$HEAD"); do
	count=$((count + 1))
	author="$(git show -s --format='%an <%ae>' "$sha")"
	subject="$(git show -s --format='%s' "$sha")"

	if ! git show -s --format='%B' "$sha" | grep -qi '^Signed-off-by: '; then
		printf 'FAIL %s missing Signed-off-by\n     %s\n' \
			"$(echo "$sha" | cut -c1-12)" "$subject"
		fail=1
		continue
	fi

	# At least one sign-off must match the author exactly.
	if ! git show -s --format='%B' "$sha" \
		| grep -i '^Signed-off-by: ' \
		| sed 's/^[Ss]igned-off-by: *//' \
		| grep -qxF "$author"; then
		printf 'FAIL %s sign-off does not match author\n     author: %s\n     %s\n' \
			"$(echo "$sha" | cut -c1-12)" "$author" "$subject"
		fail=1
		continue
	fi

	printf 'ok   %s %s\n' "$(echo "$sha" | cut -c1-12)" "$subject"
done

if [ "$count" -eq 0 ]; then
	echo "no commits in range $BASE..$HEAD"
	exit 0
fi

if [ "$fail" -ne 0 ]; then
	cat <<'MSG'

Every commit needs a Signed-off-by line matching its author:

    git commit -s

To fix existing commits:

    git rebase --signoff <base>

MSG
	exit 1
fi

echo
echo "$count commit(s) signed off"
