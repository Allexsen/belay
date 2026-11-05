#!/bin/bash
# sandbox.sh ROOT WORKSPACE OUT PROGRAM...: run PROGRAM chrooted in the image's filesystem ROOT, read-only, with
# WORKSPACE where the benchmark puts it and OUT at /out. New user, mount, network and PID namespaces: no network, and
# nothing of this machine's filesystem but those two directories. Size-limited tmpfs for what must be writable.
set -eu
if [ "${SB_IN:-}" != 1 ]; then
    exec env SB_IN=1 unshare --user --map-root-user --mount --net --pid --fork --kill-child "$0" "$@"
fi
NR=$1; WS=$2; OUT=$3; shift 3
mount --rbind "$NR" "$NR"; mount -o remount,bind,ro "$NR"
for d in tmp run root var/tmp; do mount -t tmpfs -o size=128m tmpfs "$NR/$d"; done
mount -t tmpfs -o size=1m tmpfs "$NR/dev"
for f in null zero urandom random; do : > "$NR/dev/$f"; mount --bind "/dev/$f" "$NR/dev/$f"; done
mount --bind "$WS" "$NR/home/agent/workspace"; mount --bind "$OUT" "$NR/out"; mount -t proc proc "$NR/proc"
cd "$NR"
exec chroot "$NR" /usr/bin/env -i HOME=/root PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C.UTF-8 PYTHON_VERSION=3.11.18 TMPDIR=/tmp "$@"
