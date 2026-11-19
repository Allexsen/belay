#!/bin/bash
S=$(realpath "$(dirname "$0")"); W=$(realpath "$S/../w2/make"); K=$S/keep_make; rm -rf $K; mkdir -p $K
until grep -q done $S/w2a_make.ndjson.err 2>/dev/null; do sleep 2; done; sleep 30
cd $W
# Determinism: two quiet clean builds must give identical hashes.
for t in detA detB; do make clean >/dev/null 2>&1; make -j8 all build/test/test_md5 >/dev/null 2>&1; make -j8 check >/dev/null 2>&1; make -j8 check-san >/dev/null 2>&1; MEASURE_TMP=$S/tmp MEASURE_KEEP=$K $S/measure2 $W $t >> $S/w2a_det.ndjson; done
export MEASURE_BIN=$S/measure2 MEASURE_KEEP=$K
$S/loop.sh $W make2 630 2 $S/w2a_make2.ndjson & LP=$!
DUR=600 $S/w2a_driver.sh $W
wait $LP
make -j8 check >/dev/null 2>&1; make -j8 check-san >/dev/null 2>&1; sleep 3
MEASURE_TMP=$S/tmp MEASURE_KEEP=$K $S/measure2 $W truth >> $S/w2a_make2_truth.ndjson
ls $K | wc -l
