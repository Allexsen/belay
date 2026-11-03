#!/bin/sh
# The union model against the kernel itself.
#
#   scripts/union-model/run.sh [COUNT [SEED]]      (default: 300 sets from seed 1)
#
# 1. The hand cases (hand.py): layer sets whose outcome is written down from the
#    documentation and the pin -- the redirects among them, which the kernel cannot be
#    asked here -- each also run against the kernel where it can answer.
# 2. COUNT generated sets (gen.py), each read by the model (model.py) as the host would and
#    mounted as a real overlay and walked (kwalk.py), compared by compare.kernel_diffs.
#
# Needs unprivileged user namespaces: everything runs as `unshare -rm`, the overlay mounted
# with `userxattr` (prefix user.overlay.). What that cannot check: NOTES-union-model.md, K1-K8.
# A set that disagrees is kept under $UNION_MODEL_WORK (default: a new temporary directory).
set -u
here=$(cd "$(dirname "$0")" && pwd)
count=${1:-300}
seed=${2:-1}
py=${PYTHON:-python3}

if ! unshare -rm true 2>/dev/null; then
	echo "run.sh: unprivileged user namespaces are unavailable (unshare -rm)" >&2
	exit 2
fi
work=${UNION_MODEL_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/union-model.XXXXXX")}
mkdir -p "$work"
fail=0

echo "== hand cases"
if unshare -r "$py" "$here/hand.py" build "$work/hand" &&
	"$py" "$here/hand.py" verify "$work/hand"; then
	unshare -r rm -rf -- "$work/hand"
else
	fail=1
fi

echo "== $count generated sets"
"$py" "$here/check.py" --count "$count" --seed "$seed" --work "$work/sets" || fail=1

if [ "$fail" -eq 0 ]; then
	unshare -r rm -rf -- "$work/sets"
	rmdir -- "$work" 2>/dev/null || true
	echo "run.sh: all agree"
else
	echo "run.sh: DISAGREEMENTS, kept in $work" >&2
fi
exit $fail
