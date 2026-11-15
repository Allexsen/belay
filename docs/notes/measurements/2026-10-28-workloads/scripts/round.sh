#!/bin/bash
# round.sh <name> <scope> <round-label> <command...>
# One workload round: observation loop (2 s, manifests kept) while the
# command runs, then a quiet ground-truth manifest and torn_check on the
# round's manifests. Logs under $WL/<name>/.
set -u
name=$1 scope=$2 label=$3; shift 3
WL=${WL:?}; B=$HOME/workspace/belay
out=$WL/$name; keep=$out/keep_$label; mkdir -p "$keep"
MEASURE_BIN=$B/build/bench/measure MEASURE_KEEP=$keep MEASURE_TAG=$label \
  "$B/bench/measure/observe.sh" "$scope" "$out/log.ndjson" 2 100000 & LP=$!
t0=$(date +%s); bash -c "$*" > "$out/cmd_$label.log" 2>&1; rc=$?
echo "$name/$label: command rc=$rc in $(( $(date +%s) - t0 ))s" | tee -a "$out/rounds.txt"
sleep 3; kill $LP 2>/dev/null; wait $LP 2>/dev/null
sleep 2
"$B/build/bench/measure" --keep "$keep" --tag truth "$scope" > /dev/null
python3 "$B/bench/measure/torn_check.py" "$scope" "$keep"/truth.*.ndjson $(ls "$keep"/$label.*.ndjson 2>/dev/null) > "$out/torn_$label.json"
echo "$name/$label: torn_check exit $?" | tee -a "$out/rounds.txt"
