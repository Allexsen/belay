#!/bin/sh
#
# The host reader against real containers (test/expect/host-reader.md): run
# as root, on a Linux host whose Docker daemon is local, with a static belay
# (it is also copied into a container, to walk the same tree from inside).
# Each case checks what Docker does first where it relies on it, then belay.
#
#   sudo scripts/host-reader-e2e.sh path/to/static/belay
#
# CI runs it twice: with Docker's overlay2 store and with the containerd store.

set -eu
BELAY=${1:-bin/belay}
case $BELAY in /*) ;; *) BELAY=$PWD/$BELAY ;; esac
[ "$(id -u)" = 0 ] || { echo "host-reader-e2e: run as root" >&2; exit 2; }
T=$(mktemp -d "${TMPDIR:-/tmp}/belay-host-reader.XXXXXX")
CS=""
cleanup() { for c in $CS; do docker rm -f "$c" >/dev/null 2>&1 || true; done; rm -rf "${T:?}"; }
trap cleanup EXIT
fail() { echo "host-reader-e2e: FAIL: $*" >&2; exit 1; }
STORE=$(docker info -f '{{.Driver}}')
export BELAY_STATE_DIR=$T/state
B() { "$BELAY" "$@"; }

# An image whose /workspace sits in its lower layers; a container that then
# changes it in every way overlayfs records: a file edited, one deleted
# (whiteout), a directory deleted and made again (opaque), one renamed in place
# (relative redirect) and across directories (absolute), a mode changed (copy-up).
mkdir "$T/img"
cat > "$T/img/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /workspace/tests /workspace/src/pkg /workspace/old /workspace/lib/deep /workspace/data && \
    echo 'def test_x(): assert 1 == 1' > /workspace/tests/test_x.py && \
    echo 'x = 1' > /workspace/src/a.py && echo 'y = 2' > /workspace/src/pkg/b.py && \
    echo gone > /workspace/old/f && echo q > /workspace/lib/deep/q && echo d > /workspace/data/d && \
    ln -s src/a.py /workspace/link && setfattr -n user.k -v v /workspace/src/a.py 2>/dev/null || true
EOF
docker build -q -t belay-hr-e2e "$T/img" >/dev/null
run() { c=$(docker run -d "$@" belay-hr-e2e sleep 600); CS="$CS $c"; echo "$c"; }
C=$(run)
docker exec "$C" sh -c 'echo "x = 2" > /workspace/src/a.py; rm /workspace/data/d; rm -rf /workspace/old && mkdir /workspace/old &&
    echo new > /workspace/old/n; mv /workspace/src/pkg /workspace/src/pkg2; mkdir -p /workspace/moved;
    mv /workspace/lib/deep /workspace/moved/deep; chmod 600 /workspace/tests/test_x.py'

# ---- the same tree, read from the host and walked from inside ----
docker cp "$BELAY" "$C:/belay" >/dev/null
docker exec -e BELAY_STATE_DIR=/tmp/st "$C" /belay check --scope /workspace --json > "$T/in.json" || fail "the walk inside the container"
docker cp "$C:$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["manifest"])' "$T/in.json")" "$T/in.ndjson" >/dev/null
B check --docker "$C" --scope /workspace --json > "$T/host.json" || fail "the host reader's check"
cp "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["manifest"])' "$T/host.json")" "$T/host.ndjson"
python3 - "$T/in.ndjson" "$T/host.ndjson" "$C" <<'EOF' || fail "the host reader and the walk inside disagree"
import json, sys
def load(p):
    lines = [json.loads(l) for l in open(p)]
    return lines[0], {e["path"]: e for e in lines[1:-1]}
hi, ei = load(sys.argv[1])
hh, eh = load(sys.argv[2])
assert hi["source"] is None, hi["source"]
assert hh["source"]["docker"].startswith(sys.argv[3][:12]), hh["source"]
assert hh["scopes"] == ["/workspace"], hh["scopes"]
# dev and ino differ by design (H-U7), ctime with them; a merged directory's
# nlink is the layer's (the union model's U23); everything else must agree.
skip = {"dev", "ino", "ctime_ns", "stored"}
bad = []
for p in sorted(set(ei) | set(eh)):
    a, b = ei.get(p), eh.get(p)
    if a is None or b is None:
        bad.append("%s: only %s" % (p, "inside" if b is None else "on the host"))
        continue
    for k in sorted((set(a) | set(b)) - skip):
        if k == "nlink" and a.get("type") == "dir":
            continue
        if a.get(k) != b.get(k):
            bad.append("%s: %s inside %r, host %r" % (p, k, a.get(k), b.get(k)))
for x in bad:
    print("  " + x)
for p in ("data/d", "old/f", "src/pkg", "lib/deep", "lib/deep/q"):
    assert p not in eh, p
for p in ("old/n", "src/pkg2/b.py", "moved/deep/q"):
    assert p in eh, p
sys.exit(1 if bad else 0)
EOF

# ---- the protocol: export and verify read a paused container (H-C4) ----
echo '{"belay_protect":2,"protect":[{"path":"tests/**","mode":["no_write","no_delete"]}]}' > "$T/spec.json"
if B baseline export --docker "$C" --scope /workspace --out "$T/b" --protect "$T/spec.json" 2>"$T/err"; then fail "a running container exported"; fi
grep -q "not paused" "$T/err" || fail "the refusal does not say why: $(cat "$T/err")"
docker pause "$C" >/dev/null
B baseline export --docker "$C" --scope /workspace --out "$T/b" --protect "$T/spec.json" --json > "$T/b.json" || fail "export"
docker unpause "$C" >/dev/null
SHA=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["sha256"])' "$T/b.json")
docker exec "$C" sh -c 'echo "def test_x(): pass" > /workspace/tests/test_x.py'
docker pause "$C" >/dev/null
set +e
B verify --docker "$C" --scope /workspace --baseline "$T/b" --baseline-sha256 "$SHA" --protect "$T/spec.json" --exit-code > "$T/policy" 2>"$T/err"
rc=$?
set -e
docker unpause "$C" >/dev/null
[ $rc = 1 ] || fail "verify: exit $rc, expected 1 (a violation): $(cat "$T/err")"
grep -q '"flag":"protected_path_written"' "$T/policy" || fail "the weakened test is not a violation: $(cat "$T/policy")"
# another container of the same image: refused (V3-R4, decision 198)
O=$(run)
docker pause "$O" >/dev/null
set +e
B verify --docker "$O" --scope /workspace --baseline "$T/b" --baseline-sha256 "$SHA" --protect "$T/spec.json" > /dev/null 2>"$T/err"
rc=$?
set -e
[ $rc = 3 ] || fail "another container verified against the bundle: exit $rc"
grep -q "different sources" "$T/err" || fail "not refused for its source: $(cat "$T/err")"
docker unpause "$O" >/dev/null

# ---- privileged: the escape the refusal is for (H-C6, decision 199) ----
P=$(run --privileged)
docker exec "$P" sh -c 'mount -t tmpfs tmpfs /workspace/src && echo hidden > /workspace/src/h && test -f /workspace/src/h'
U=$(awk '$5 == "/"' "/proc/$(docker inspect -f '{{.State.Pid}}' "$P")/mountinfo" | grep -o 'upperdir=[^,]*' | cut -d= -f2)
[ -z "$(find "$U" -name h)" ] || fail "the write under the container's own mount reached its layers: the escape is not one"
set +e
B check --docker "$P" --scope /workspace > /dev/null 2>"$T/err"
rc=$?
set -e
[ $rc = 3 ] && grep -q CAP_SYS_ADMIN "$T/err" || fail "a privileged container read: exit $rc $(cat "$T/err")"
S=$(run --cap-add SYS_ADMIN)
B check --docker "$S" --scope /workspace > /dev/null 2>&1 && fail "a container with CAP_SYS_ADMIN read"

# ---- CAP_LINUX_IMMUTABLE: warned, read; protattr in the iflags (H-C9, H-U8) ----
I=$(run --cap-add LINUX_IMMUTABLE)
docker exec "$I" chattr +i /workspace/src/a.py
B check --docker "$I" --scope /workspace --json > "$T/i.json" 2>"$T/err" || fail "a container with CAP_LINUX_IMMUTABLE refused: $(cat "$T/err")"
grep -q "CAP_LINUX_IMMUTABLE" "$T/err" || fail "no warning for CAP_LINUX_IMMUTABLE"
M=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["manifest"])' "$T/i.json")
python3 - "$M" <<'EOF' || fail "chattr +i inside is not in the host reader's iflags"
import json, sys
e = [json.loads(l) for l in open(sys.argv[1]) if '"path":"src/a.py"' in l][0]
sys.exit(0 if e.get("iflags", 0) & 0x10 else 1)
EOF
docker exec "$I" chattr -i /workspace/src/a.py

# ---- refused: a stopped container, a scope in a volume, not root ----
docker stop -t 0 "$O" >/dev/null
B check --docker "$O" --scope /workspace > /dev/null 2>&1 && fail "a stopped container read"
V=$(run -v "$T:/workspace/vol:ro")
B check --docker "$V" --scope /workspace/vol > /dev/null 2>"$T/err" && fail "a scope in a bind mount read"
grep -q "mount" "$T/err" || fail "the bind mount refusal does not say why"
B check --docker "$V" --scope /workspace --json > "$T/v.json" || fail "a scope with a bind mount below it"
python3 - "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["manifest"])' "$T/v.json")" <<'EOF' || fail "the bind mount is not a boundary"
import json, sys
e = [json.loads(l) for l in open(sys.argv[1]) if '"path":"vol"' in l]
sys.exit(0 if e and e[0].get("mount") is True else 1)
EOF
if su nobody -s /bin/sh -c "BELAY_STATE_DIR=$T/nobody '$BELAY' check --docker '$C' --scope /workspace" >/dev/null 2>&1; then
    fail "read without root"
fi

echo "host-reader-e2e ($STORE): the host reader reads real containers as the pin says: ok"
