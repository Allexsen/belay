#!/bin/bash
# loop.sh <scope> <tag> <seconds> <interval> <log>
scope=$1 tag=$2 dur=$3 iv=$4 log=$5
M=$(dirname "$0")
end=$(( $(date +%s%N)/1000000000 + dur ))   # wall clock only bounds the loop
start=$(awk '{print $1}' /proc/uptime)
while :; do
  now=$(awk '{print $1}' /proc/uptime)
  awk -v s="$start" -v n="$now" -v d="$dur" 'BEGIN{exit !(n-s < d)}' || break
  [ -d "$scope" ] && MEASURE_TMP=$M/tmp "${MEASURE_BIN:-$M/measure}" "$scope" "$tag" >> "$log" 2>>"$log.err"
  sleep "$iv"
done
echo done >> "$log.err"
