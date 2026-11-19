#!/bin/bash
# npm workload, second pass: manifests kept, ground truth taken after.
S=$(realpath "$(dirname "$0")"); W=$(realpath "$S/../w2/npmapp"); K=$S/keep_npm3; rm -rf $K; mkdir -p $K
cd $W
export MEASURE_BIN=$S/measure3 MEASURE_KEEP=$K
$S/loop.sh $W npm3 1800 2 $S/w2b_npm3.ndjson & LP=$!
for i in 1 2 3; do rm -rf node_modules; t0=$(date +%s); timeout 900 npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1; echo "ci$i rc=$? $(( $(date +%s)-t0 ))s"; done
sleep 4; kill $LP; wait $LP 2>/dev/null
sleep 5
MEASURE_TMP=$S/tmp MEASURE_KEEP=$K $S/measure3 $W truth >> $S/w2b_npm3_truth.ndjson
ls $K | wc -l
