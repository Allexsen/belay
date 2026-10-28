#!/bin/sh
# observe.sh <scope> <log.ndjson> [interval_s] [duration_s]
#
# Runs measure over <scope> every interval_s seconds (default 10) for
# duration_s seconds (default 86400), appending one JSON line per run to
# <log.ndjson>. Meant to run alongside real work; it never writes into the
# scope (the manifest goes to $TMPDIR and is deleted). Stop it with kill.
# MEASURE_TAG labels the lines; MEASURE_KEEP=DIR keeps every manifest there.
set -u
scope=$1 log=$2 iv=${3:-10} dur=${4:-86400}
here=$(cd "$(dirname "$0")" && pwd)
bin=${MEASURE_BIN:-$here/../../build/bench/measure}
[ -x "$bin" ] || { echo "observe.sh: build it first: make measure" >&2; exit 2; }
start=$(date +%s)
while [ $(( $(date +%s) - start )) -lt "$dur" ]; do
    if [ -n "${MEASURE_KEEP:-}" ]; then
        "$bin" --tag "${MEASURE_TAG:-observe}" --keep "$MEASURE_KEEP" "$scope" >> "$log" 2>> "$log.err"
    else
        "$bin" --tag "${MEASURE_TAG:-observe}" "$scope" >> "$log" 2>> "$log.err"
    fi
    sleep "$iv"
done
