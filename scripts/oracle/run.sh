#!/usr/bin/env bash
# The diff oracle: belay_diff against an independent reference (written from
# the prose of docs/spec/diff-v1.md and the pins in test/expect/) on a
# generated corpus of valid manifest pairs.
#
#   scripts/oracle/run.sh [n-bases] [seed]
#
# Runs the given seed (default 20261030) and then one random seed, printed
# with the command that reproduces it. Exit 0 only when, for both, every pair
# agrees on its header, every record and every count, every pair of different
# scopes is refused with no output file, and the coverage gate passes.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
N=${1:-200}; SEED=${2:-20261030}
RANDOM_SEED=$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
WORK=$(mktemp -d "${TMPDIR:-/tmp}/belay_oracle.XXXXXX"); trap 'rm -rf "$WORK"' EXIT
# A fresh build directory for this run, linked through the Makefile's one
# archive: no object left behind by an earlier build can be linked here.
make -s -C "$REPO" BUILD="$WORK/build" lib >/dev/null
cc -O2 -std=c11 -I"$REPO/include" -o "$WORK/driver" "$HERE/driver.c" "$WORK/build/libbelay.a"
status=0
for s in "$SEED" "$RANDOM_SEED"; do
    echo "=== seed $s, $N random bases (reproduce: scripts/oracle/run.sh $N $s)"
    rm -rf "$WORK/corpus"
    python3 -I -B "$HERE/gen_corpus.py" "$WORK/corpus" "$N" "$s" > "$WORK/count"
    python3 -I -B "$HERE/compare.py" "$WORK/driver" "$WORK/corpus" || status=1
done
[ "$status" -eq 0 ] && echo "=== oracle: PASS" || echo "=== oracle: FAIL (seeds $SEED and $RANDOM_SEED)"
exit "$status"
