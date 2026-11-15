#!/bin/bash
# Real build/test activity in a clone, for 900 s (monotonic).
DUR=${DUR:-900}; cd "$1"; start=$(awk '{print $1}' /proc/uptime); n=0
while awk -v s="$start" -v n="$(awk '{print $1}' /proc/uptime)" -v d="$DUR" 'BEGIN{exit !(n-s < d)}'; do
  make clean >/dev/null 2>&1; make -j8 check >/dev/null 2>&1; make -j8 check-san >/dev/null 2>&1; n=$((n+1))
done
echo "cycles $n"
