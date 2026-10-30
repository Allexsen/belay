#!/usr/bin/env bash
# The diff oracle: belay_diff against a naive reference on a generated corpus
# of valid manifest pairs. Usage: scripts/oracle/run.sh [n-bases] [seed]
# Exit 0 only when every pair agrees on every record and every count.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
N=${1:-200}; SEED=${2:-20261030}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/belay_oracle.XXXXXX"); trap 'rm -rf "$WORK"' EXIT
# A fresh build directory for this run, linked through the Makefile's one
# archive: no object left behind by an earlier build can be linked here.
make -s -C "$REPO" BUILD="$WORK/build" lib >/dev/null
cc -O2 -std=c11 -I"$REPO/include" -o "$WORK/driver" "$HERE/driver.c" "$WORK/build/libbelay.a"
python3 -I "$HERE/gen_corpus.py" "$WORK/corpus" "$N" "$SEED" > "$WORK/count"
python3 -I "$HERE/compare.py" "$WORK/driver" "$WORK/corpus"
