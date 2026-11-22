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

# ---- a protected file written and put back: another file in the upper, the same content ----
# (policy-v1, protected_path_touched). tests/test_x.py is in the image; tests/late.py is made in the
# container before the baseline, so it is in the upper layer already.
TC=$(run)
docker exec "$TC" sh -c 'echo "def test_late(): assert True" > /workspace/tests/late.py'
docker pause "$TC" >/dev/null
B baseline export --docker "$TC" --scope /workspace --out "$T/tb" --protect "$T/spec.json" --json > "$T/tb.json" || fail "export (touched)"
docker unpause "$TC" >/dev/null
TSHA=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["sha256"])' "$T/tb.json")
docker exec "$TC" sh -c 'cd /workspace/tests && for f in test_x.py late.py; do cp -p $f /tmp/keep && echo "def test_x(): pass" > $f && cat /tmp/keep > $f && touch -r /tmp/keep $f; done'
docker pause "$TC" >/dev/null
set +e
B verify --docker "$TC" --scope /workspace --baseline "$T/tb" --baseline-sha256 "$TSHA" --protect "$T/spec.json" --exit-code > "$T/tpolicy" 2>"$T/err"
rc=$?
set -e
docker unpause "$TC" >/dev/null
[ $rc = 0 ] || fail "verify (touched): exit $rc, expected 0 (a signal never fails a run): $(cat "$T/err" "$T/tpolicy")"
# `changed` always has ino, and here mtime_ns too: the image's `touch -r` puts the second back, not the
# nanosecond (seen on the first run under real Docker: ["mtime_ns","ino"]).
grep -q '"flag":"protected_path_touched","level":"signal","path":"tests/test_x.py","rule":"tests/\*\*","changed":\[[^]]*"ino"\]' "$T/tpolicy" \
    || fail "a file of the image, changed and put back, is not reported touched: $(cat "$T/tpolicy")"
grep -q '"violations":0,"signals":1,' "$T/tpolicy" || fail "touched is not the one signal: $(cat "$T/tpolicy")"
if grep -q '"path":"tests/late.py"' "$T/tpolicy"; then fail "a file made after the container started carries no trace, and one was reported: $(cat "$T/tpolicy")"; fi
if grep -q '"not_emitted":\[{"flag":"protected_path_touched"' "$T/tpolicy"; then fail "the header of a container run says the kind cannot be emitted"; fi
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

# ---- --system --docker: the container's / by its roots (watch-system WS-1, runtime-v1 RT-12) ----
# Its homes are its own passwd's; its runtime record is its first process's net/ and the
# processes of its cgroup; on the host's network, no listener and netns "host".
cp_id() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$1"; }
runtime_of() { find "$T/state" -path "*/checkpoints/$1/runtime.ndjson" -newer "$2" | head -1; }
H=$(docker run -d belay-hr-e2e sh -c 'while true; do nc -l -p 8080 >/dev/null 2>&1; done & exec sleep 600'); CS="$CS $H"
sleep 1
docker exec "$H" netstat -ltn | grep -q ':8080 ' || fail "the container does not listen on 8080 (busybox nc -l): the case cannot be made"
docker exec "$H" adduser -D -h /srv/app app >/dev/null
touch "$T/before-s1"
B check --system --docker "$H" --json > "$T/s1.json" || fail "check --system --docker"
B manifest --system --docker "$H" --id "$(cp_id "$T/s1.json")" > "$T/s1.ndjson" || fail "manifest --system --docker"
CG=$(sed -n 's/^0:://p' "/proc/$(docker inspect -f '{{.State.Pid}}' "$H")/cgroup")
python3 - "$T/s1.ndjson" "$(runtime_of "$(cp_id "$T/s1.json")" "$T/before-s1")" "$H" "$CG" <<'PY' || fail "the container's roots or its runtime record are not the container's"
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1])]
h = lines[0]
roots = {l["root"] for l in lines if "root" in l and "path" not in l}
assert h["source"]["docker"].startswith(sys.argv[3][:12]), h["source"]
assert "srv/app/.ssh" in roots and "root/.ssh" in roots, sorted(roots)
rt = [json.loads(l) for l in open(sys.argv[2])]
assert isinstance(rt[0]["netns"], int) and rt[0]["root"] is True and rt[0]["source"] == h["source"], rt[0]
l = [x for x in rt if x.get("listener") == "tcp" and x.get("port") == 8080]
cg = sys.argv[4]
assert l and l[0]["holders"] and all(x["cgroup"] == cg or x["cgroup"].startswith(cg + "/") for x in l[0]["holders"]), l
PY
docker exec "$H" adduser -D v >/dev/null
B mark --system --docker "$H" > /dev/null || fail "mark --system --docker"
B diff --system --docker "$H" --since "$(cp_id "$T/s1.json")" > "$T/sdiff" 2>&1 || true
grep -q "user v added" "$T/sdiff" || fail "the container's new user is not said: $(cat "$T/sdiff")"
B check --docker "$H" --scope / > /dev/null 2>"$T/err" && fail "the container's / by --scope after --system (WS-5a)"
grep -q -- "--system" "$T/err" || fail "WS-5a's refusal does not name --system: $(cat "$T/err")"
W=$(run)
B watch start --system --docker "$W" > "$T/wstart" || fail "watch start --system --docker"
grep -q "^kernel record: off: no recorder for a container in this version: a change put back is not seen$" "$T/wstart" \
    || fail "the container's kernel record line: $(cat "$T/wstart")"
docker exec "$W" sh -c 'mkdir -p /etc/sudoers.d && echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/w'
B watch step --system --docker "$W" --session e2e > "$T/wstep" || fail "watch step --system --docker"
B watch stop --system --docker "$W" > "$T/wstop" || fail "watch stop --system --docker"
head -1 "$T/wstop" | grep -q "^belay receipt  / in the container $W (${W%"${W#????????????}"})$" \
    || fail "the receipt does not name the container: $(head -1 "$T/wstop")"
grep -q "etc/sudoers.d/w" "$T/wstop" || fail "the container's sudo rule is not in its receipt"
N=$(docker run -d --network host belay-hr-e2e sleep 600); CS="$CS $N"
touch "$T/before-n"
B check --system --docker "$N" --json > "$T/n.json" || fail "check --system --docker of a container on the host's network"
RTN=$(runtime_of "$(cp_id "$T/n.json")" "$T/before-n")
head -1 "$RTN" | grep -q '"netns":"host"' || fail "the host-network container's netns: $(head -1 "$RTN")"
if grep -q '"listener"' "$RTN"; then fail "listener lines in a host-network container's record"; fi
if su nobody -s /bin/sh -c "BELAY_STATE_DIR=$T/nobody '$BELAY' check --system --docker '$H'" >/dev/null 2>&1; then
    fail "--system --docker read without root"
fi

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
