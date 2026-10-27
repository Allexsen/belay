#!/usr/bin/env bash
# Runs inside `unshare -Urm`: builds a scope with a tmpfs directory mount, a
# file bind-mounted from that tmpfs, and a file capability, then has both
# drivers record it. Usage: ns_fixture.sh <old.driver> <new.driver> <workdir>
set -euo pipefail
OLD=$1 NEW=$2 W=$3
mkdir -p "$W/ns/scope/sub" "$W/ns/fs"
mount -t tmpfs none "$W/ns/fs"
echo outside > "$W/ns/fs/file"
mkdir -p "$W/ns/scope/m"
mount -t tmpfs none "$W/ns/scope/m"
echo inside-mount > "$W/ns/scope/m/x"
echo local > "$W/ns/scope/bound"
mount --bind "$W/ns/fs/file" "$W/ns/scope/bound"
echo '#!/bin/true' > "$W/ns/scope/sub/capfile"
python3 -c 'import os,struct,sys; os.setxattr(sys.argv[1], "security.capability", struct.pack("<5I", 0x02000001, 1<<13, 0, 0, 0))' "$W/ns/scope/sub/capfile"
sleep 2
for side in old new; do
    mkdir -p "$W/out/$side/ns"
    drv=$OLD; [ "$side" = new ] && drv=$NEW
    "$drv" "$W/ns/scope" "$W/out/$side/ns"
done
