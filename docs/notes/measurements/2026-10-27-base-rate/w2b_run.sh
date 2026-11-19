#!/bin/bash
# npm workload, second pass: manifests kept, ground truth taken after.
S=$(realpath "$(dirname "$0")"); W=$(realpath "$S/../w2/npmapp"); K=$S/keep_npm; rm -rf $K; mkdir -p $K
cd $W
export MEASURE_BIN=$S/measure2 MEASURE_KEEP=$K
$S/loop.sh $W npm2 1800 2 $S/w2b_npm2.ndjson & LP=$!
for i in 1 2 3; do rm -rf node_modules; t0=$(date +%s); timeout 900 npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1; echo "ci$i rc=$? $(( $(date +%s)-t0 ))s"; done
sleep 4; kill $LP; wait $LP 2>/dev/null
sleep 5
MEASURE_TMP=$S/tmp MEASURE_KEEP=$K $S/measure2 $W truth >> $S/w2b_npm2_truth.ndjson
ls $K | wc -l
