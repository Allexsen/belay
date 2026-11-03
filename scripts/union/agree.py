#!/usr/bin/env python3
"""belay's union against the union model (scripts/union-model/, its separate
author's): for each seed, the model's generator lays out a set of layers (in a
user namespace, for whiteouts), and model.py and belay's driver read it with the
same arguments; the model author's compare_outputs judges every field. A
manifest keeps an xattr's value as its sha256, so the model's hex values are
hashed first. The model's hand cases run too.

    agree.py DRIVER [COUNT [SEED]]
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(os.path.dirname(HERE), "union-model")
sys.path.insert(0, MODEL)
import compare  # noqa: E402  (the model author's hook)


def norm(lines, model):
    """The two spellings of one meaning made one: the model's xattr values
    hashed (a manifest keeps a digest); protattr as the set of its letters
    (belay derives them from iflags, the model echoes the xattr). A mount
    point's entry carries no xattrs, protattr or content on either side
    (host-reader H-M5, decision 212): compared as it is."""
    out = []
    for l in lines:
        if not l.strip():
            continue
        e = json.loads(l)
        if model and isinstance(e.get("xattrs"), dict):
            e["xattrs"] = {k: hashlib.sha256(bytes.fromhex(v)).hexdigest() for k, v in e["xattrs"].items()}
        if "protattr" in e:
            e["protattr"] = "".join(sorted(set(e["protattr"])))
        out.append(json.dumps(e))
    return out


def one(driver, d, case):
    args = ["--prefix", case["prefix"], "--content"]
    for m in case["mounts"]:
        args += ["--mount", m]
    args += ["--", case["scope"]] + case["layers"]
    mo = subprocess.run([sys.executable, "-I", os.path.join(MODEL, "model.py")] + args,
                        capture_output=True, text=True, errors="surrogateescape")
    bo = subprocess.run([driver] + args, capture_output=True, text=True, errors="surrogateescape")
    if bo.returncode not in (0, 1):
        return ["driver failed: " + bo.stderr.strip()[-400:]]
    if mo.returncode not in (0, 1):
        return ["model failed: " + mo.stderr.strip()[-400:]]
    return compare.compare_outputs(norm(mo.stdout.splitlines(), True), norm(bo.stdout.splitlines(), False))


def main():
    driver = os.path.abspath(sys.argv[1])
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    work = tempfile.mkdtemp(prefix="belay-union-agree-")
    bad = refused = listed = 0
    try:
        for s in range(seed, seed + count):
            d = os.path.join(work, "set-%d" % s)
            g = subprocess.run(["unshare", "-r", sys.executable, "-I", os.path.join(MODEL, "gen.py"),
                                "--seed", str(s), "--out", d], capture_output=True, text=True, errors="surrogateescape")
            if g.returncode != 0:
                print("seed %d: gen failed: %s" % (s, g.stderr.strip()[-300:]))
                bad += 1
                continue
            with open(os.path.join(d, "case.json")) as f:
                case = json.load(f)
            diffs = one(driver, d, case)
            if diffs:
                bad += 1
                print("seed %d: %d difference(s)" % (s, len(diffs)))
                for x in diffs[:8]:
                    print("    " + x)
            else:
                args = sum([["--mount", m] for m in case["mounts"]], [])
                out = subprocess.run([driver, "--prefix", case["prefix"]] + args + ["--", case["scope"]] + case["layers"],
                                     capture_output=True).stdout
                if out.startswith(b'{"refused"'):
                    refused += 1
                else:
                    listed += 1
            subprocess.run(["rm", "-rf", d])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("union-model: %d sets, %d agree (%d listed, %d refused), %d differ" %
          (count, count - bad, listed, refused, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
