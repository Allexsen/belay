#!/usr/bin/env bash
# The diff oracle: belay_diff against a naive reference on a generated corpus
# of valid manifest pairs. Usage: scripts/oracle/run.sh [n-bases] [seed]
# Exit 0 only when every pair agrees on every record and every count.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
N=${1:-200}; SEED=${2:-20261030}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/belay_oracle.XXXXXX"); trap 'rm -rf "$WORK"' EXIT
make -s -C "$REPO" all >/dev/null
objs=$( (find "$REPO/build/util" "$REPO/build/schema" "$REPO/build/capture" "$REPO/build/diff" \
              "$REPO/build/interp" "$REPO/build/platform" -name '*.o' 2>/dev/null || true) | sort)
cc -O2 -std=c11 -I"$REPO/include" -o "$WORK/driver" "$HERE/driver.c" $objs
python3 -I "$HERE/gen_corpus.py" "$WORK/corpus" "$N" "$SEED" > "$WORK/count"
python3 -I "$HERE/compare.py" "$WORK/driver" "$WORK/corpus"
