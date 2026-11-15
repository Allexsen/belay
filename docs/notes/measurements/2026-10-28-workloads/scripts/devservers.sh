#!/bin/bash
set -u
WL=$(cd "$(dirname "$0")" && pwd); B=$HOME/workspace/belay; DUR=${1:-600}
DJ=$WL/dj/devsite; NX=$WL/nx; O=$WL/dev; rm -rf $O; mkdir -p $O/keep_dj
(cd $DJ && exec ../venv/bin/python manage.py runserver 127.0.0.1:8765 > $O/django.log 2>&1) & DJP=$!
(cd $NX && exec npx next dev -p 8766 > $O/next.log 2>&1) & NXP=$!
for i in $(seq 1 90); do
  curl -sf -o /dev/null http://127.0.0.1:8765/list && curl -sf -o /dev/null http://127.0.0.1:8766/ && break; sleep 1
done
echo "servers up after ${i}s"
MEASURE_BIN=$B/build/bench/measure MEASURE_KEEP=$O/keep_dj MEASURE_TAG=dj $B/bench/measure/observe.sh $DJ $O/dj.ndjson 2 100000 & L1=$!
MEASURE_BIN=$B/build/bench/measure MEASURE_TAG=nx $B/bench/measure/observe.sh $NX $O/nx.ndjson 2 100000 & L2=$!
python3 $WL/traffic.py $DUR $DJ $NX > $O/traffic.json
kill $L1 $L2 2>/dev/null; wait $L1 $L2 2>/dev/null
pkill -P $DJP 2>/dev/null; kill $DJP 2>/dev/null; pkill -f 'manage.py runserver 127.0.0.1:8765'; pkill -f 'next dev -p 8766'; pkill -f 'next-server' 2>/dev/null
sleep 2; cat $O/traffic.json; wc -l $O/dj.ndjson $O/nx.ndjson
