#!/usr/bin/env python3
"""The kernel check: generated layer sets, each through the model and through a real overlay.

    check.py [--count N] [--seed S] [--work DIR] [--keep]

For each seed S..S+N-1: gen.py builds a set (in `unshare -r`), model.py reads it as the
host would, kwalk.py mounts it (in `unshare -rm`, userxattr) and walks the merged view, and
compare.kernel_diffs judges. A set that disagrees is kept under WORK/fail-<seed>; the rest
are removed. Exit 1 when any set disagrees.
"""

import argparse
import collections
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True     # nothing left beside the scripts
sys.path.insert(0, HERE)
import compare  # noqa: E402


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def rm(path):
    # Generated sets hold whiteouts, and the kernel's work dir is mode 0: the namespace's
    # root removes them (it owns them all).
    run(["unshare", "-r", "rm", "-rf", "--", path])


def one(seed, work, py):
    d = os.path.join(work, "set-%d" % seed)
    if os.path.lexists(d):
        rm(d)
    g = run(["unshare", "-r", py, os.path.join(HERE, "gen.py"), "--seed", str(seed), "--out", d])
    if g.returncode != 0:
        return d, None, ["gen failed: " + g.stderr.strip()[-400:]], []
    with open(os.path.join(d, "case.json")) as f:
        case = json.load(f)
    argv = [py, os.path.join(HERE, "model.py"), "--prefix", case["prefix"], "--content",
            "--explain"]
    for mt in case["mounts"]:
        argv += ["--mount", mt]
    argv += ["--", case["scope"]] + case["layers"]
    mo = run(argv)
    with open(os.path.join(d, "model.out"), "w") as f:
        f.write(mo.stdout)
    if mo.returncode not in (0, 1):
        return d, case, ["model crashed: " + mo.stderr.strip()[-600:]], []
    ko = run(["unshare", "-rm", py, os.path.join(HERE, "kwalk.py"), os.path.join(d, "case.json")])
    with open(os.path.join(d, "kernel.out"), "w") as f:
        f.write(ko.stdout)
    if ko.returncode != 0:
        return d, case, ["kwalk crashed: " + ko.stderr.strip()[-600:]], []
    diffs, notes = compare.kernel_diffs(case, mo.stdout.splitlines(), ko.stdout.splitlines())
    return d, case, diffs, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--work", default=None)
    ap.add_argument("--keep", action="store_true", help="keep every set, not just failures")
    a = ap.parse_args()
    work = a.work or tempfile.mkdtemp(prefix="union-check-")
    os.makedirs(work, exist_ok=True)
    py = sys.executable
    tally = collections.Counter()
    feats = collections.Counter()
    failed = []
    for seed in range(a.seed, a.seed + a.count):
        d, case, diffs, notes = one(seed, work, py)
        if case:
            for f in case["features"]:
                feats[f] += 1
        for n in notes:
            if n.startswith("compared "):
                tally["entries compared"] += int(n.split()[1])
            elif n.startswith("skipped-tainted "):
                tally["entries behind a redirect, not compared"] += int(n.split()[1])
            elif n.startswith("nlink "):
                tally["dir " + n] += 1
            elif n.startswith("kernel E"):
                tally["kernel " + n.split()[1] + " behind a followed redirect"] += 1
            elif n.startswith("ghost"):
                tally["readdir names lstat cannot find (whiteouts)"] += 1
            else:
                tally[n] += 1
        refused = any(n.startswith("refused") for n in notes)
        if diffs:
            failed.append(seed)
            tally["sets DISAGREEING"] += 1
            print("seed %d: %d difference(s), kept in %s" % (seed, len(diffs), d))
            for x in diffs[:12]:
                print("    " + x)
            continue
        tally["sets refused" if refused else "sets listed"] += 1
        if any(n.startswith("skipped-tainted") for n in notes):
            tally["sets listed with a redirect (partly compared)"] += 1
        if not a.keep:
            rm(d)
    print("== %d sets, seeds %d..%d, work %s" % (a.count, a.seed, a.seed + a.count - 1, work))
    for k in sorted(tally):
        print("  %-60s %d" % (k, tally[k]))
    print("  features (sets):")
    for k in sorted(feats):
        print("    %-58s %d" % (k, feats[k]))
    if failed:
        print("FAILED seeds: %s" % " ".join(map(str, failed)))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
