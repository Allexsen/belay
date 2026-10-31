#!/bin/sh
# The dpkg and pip interpreters against the independent reference
# (scripts/reference/README in ref.py's docstring).
#
#   scripts/reference/run.sh [N] [seed]
#
# N random cases (default 300) besides the required cells, seeded by `seed`
# (default 1). Builds the driver first. Exit 0 only when belay and the
# reference agree on every pair and every cell was hit.
set -eu
cd "$(dirname "$0")/../.."
N=${1:-300}
SEED=${2:-1}
BUILD=${BUILD:-build}
${MAKE:-make} -s BUILD="$BUILD" "$BUILD/reference/driver"
exec python3 scripts/reference/run.py --driver "$BUILD/reference/driver" \
	--work "$BUILD/reference/work" --n "$N" --seed "$SEED"
