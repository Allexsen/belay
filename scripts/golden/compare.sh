#!/usr/bin/env bash
# Golden comparison against a base revision (default e04186a, the last commit
# before the capture refactor).
#
#   1. Builds the golden driver and reader against <base> and the working tree.
#   2. Creates one set of fixture trees, lets them age, and has BOTH builds
#      record every scope under three option sets.
#   3. Manifests must be byte-identical (the header's created_ns aside), and
#      so must every stored object.
#   4. A mutation corpus of those manifests must read back identically under
#      both readers: accept/reject, message, and every decoded field.
#
# Usage: scripts/golden/compare.sh [base-ref]     Exit 0 only when all equal.
set -euo pipefail
BASE=${1:-e04186a}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/belay_golden.XXXXXX")
cleanup() { chmod -R u+rwx "$WORK" 2>/dev/null || true; rm -rf "$WORK"
            [ -f "$WORK.shm" ] && rm -rf "$(cat "$WORK.shm")" "$WORK.shm" || true; }
trap cleanup EXIT

build() {   # build <source tree> <out prefix>
    local src=$1 out=$2
    make -s -C "$src" all >/dev/null 2>&1
    local objs
    objs=$( (find "$src/build/util" "$src/build/capture" "$src/build/interp" \
                  "$src/build/platform" -name '*.o' 2>/dev/null || true) | sort)
    cc -O2 -std=c11 -I"$src/include" -o "$out.driver" "$HERE/driver.c" $objs
    cc -O2 -std=c11 -I"$src/include" -o "$out.reader" "$HERE/reader.c" $objs
}

git -C "$REPO" archive "$BASE" | (mkdir -p "$WORK/base" && tar -x -C "$WORK/base")
build "$WORK/base" "$WORK/old"
build "$REPO" "$WORK/new"

python3 "$HERE/make_fixtures.py" "$WORK/fx"
scopes=("$WORK/fx/main" "$WORK/fx/root_unsearchable")
if [ -f "$WORK/fx/shm_path" ]; then
    cp "$WORK/fx/shm_path" "$WORK.shm"
    scopes+=("$(cat "$WORK/fx/shm_path")")
fi
sleep 2                       # older than any "changed during the walk" window

# Mounts and a file capability need a user namespace; both drivers record the
# same namespace-built scope there. Skipped where the host forbids it.
names=()
if unshare -Urm true 2>/dev/null; then
    unshare -Urm "$HERE/ns_fixture.sh" "$WORK/old.driver" "$WORK/new.driver" "$WORK"
    names+=(ns)
else
    echo "skipped: namespace fixture (no unprivileged user namespaces here)"
fi

status=0
for s in "${scopes[@]}"; do
    name=$(basename "$s")
    for side in old new; do
        mkdir -p "$WORK/out/$side/$name"
        "$WORK/$side.driver" "$s" "$WORK/out/$side/$name"
    done
    names+=("$name")
done
for name in "${names[@]}"; do
    for m in default limits spill; do
        a="$WORK/out/old/$name/$m.ndjson" b="$WORK/out/new/$name/$m.ndjson"
        if ! diff <(sed '1s/"created_ns":[0-9]*/"created_ns":X/' "$a") \
                  <(sed '1s/"created_ns":[0-9]*/"created_ns":X/' "$b") > "$WORK/diff" ; then
            echo "DIFFERENT: $name/$m"; head -20 "$WORK/diff"; status=1
        else
            echo "identical: $name/$m ($(($(wc -l < "$a") - 2)) entries)"
        fi
    done
    for side in old new; do
        (cd "$WORK/out/$side/$name" && [ -d store ] && find store -type f -print0 | sort -z \
            | xargs -0 -r sha256sum) > "$WORK/out/$side/$name.store" || true
    done
    if ! cmp -s "$WORK/out/old/$name.store" "$WORK/out/new/$name.store"; then
        echo "DIFFERENT: $name/store"; status=1
    else
        echo "identical: $name/store ($(wc -l < "$WORK/out/old/$name.store") objects)"
    fi
done

printf "coverage (fixture manifests):"
for k in unverified unstable unreadable mount raced target_outside_scope stored xattrs \
         xattrs_sha256 iflags caps path_b64 link_target_b64; do
    printf " %s=%s" "$k" "$(cat "$WORK"/out/old/*/*.ndjson | grep -o "\"$k\":" | wc -l)"
done
echo
python3 "$HERE/mutate.py" "$WORK/corpus" "$WORK"/out/old/*/*.ndjson > "$WORK/corpus.count"
# Keep the corpus for other oracles (the fuzz target's invariants, say).
[ -n "${GOLDEN_CORPUS_OUT:-}" ] && cp -r "$WORK/corpus" "$GOLDEN_CORPUS_OUT"
"$WORK/old.reader" "$WORK"/corpus/* > "$WORK/read.old"
"$WORK/new.reader" "$WORK"/corpus/* > "$WORK/read.new"
accepted=$(grep -c '^-> ACCEPT' "$WORK/read.old" || true)
if ! diff "$WORK/read.old" "$WORK/read.new" > "$WORK/rdiff"; then
    echo "DIFFERENT: reader on the mutation corpus"; head -20 "$WORK/rdiff"; status=1
else
    echo "identical: reader on $(cat "$WORK/corpus.count") ($accepted accepted, the rest rejected)"
fi
exit $status
