#!/usr/bin/env python3
"""Runs belay (through the driver) and the reference on every generated pair,
compares the dpkg and pip findings and events byte for byte, and gates on
coverage: every cell a builder declares must be hit at least once.

    run.py --driver build/reference/driver --work DIR [--n N] [--seed S] [--keep]

Exit 0 when every pair agrees and every cell was hit; 1 otherwise. A failing
case's directory is kept under DIR with a `report.txt` beside its manifests.
"""

import argparse
import base64
import collections
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen   # noqa: E402
import ref   # noqa: E402


# ---------------------------------------------------------------- belay's output

def parse_diff(fn):
    with open(fn, "rb") as f:
        lines = f.read().split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    header, trailer = json.loads(lines[0]), json.loads(lines[-1])
    records = {}
    events = []
    for line in lines[1:-1]:
        if line.startswith(b'{"event":'):
            events.append(line)
            continue
        if events:
            raise ValueError("a path record after an event record (E1)")
        o = json.loads(line)
        p = ref.entry_path(o)
        raw = None
        i = line.find(b',"findings":[')
        if i >= 0:
            raw = line[i + len(b',"findings":'):-1]
        records[p] = (o["outcome"], raw)
    return header, records, events, trailer


def compare(belay, mine):
    """The differences, as text lines; empty when they agree."""
    header, records, events, trailer = belay
    diffs = []
    if trailer.get("events") != len(events):
        diffs.append("trailer events %r, %d event records" % (trailer.get("events"), len(events)))
    for p in sorted(set(records) | set(mine.outcomes)):
        bo = records.get(p, ("unchanged", None))[0]
        mo = mine.outcomes.get(p, "unchanged")
        if bo != mo:
            diffs.append("outcome %r: belay %s, reference %s" % (p, bo, mo))
    for p, mf in sorted(mine.claims.items()):
        bf = records.get(p, (None, None))[1]
        rf = mine.findings.get(p)
        if bf != rf:
            diffs.append("findings %r (%s):\n    belay     %s\n    reference %s"
                         % (p, mf, bf.decode("utf-8", "replace") if bf else None,
                            rf.decode("utf-8", "replace") if rf else None))
    bev = [e for e in events if json.loads(e).get("interp") in ("pip", "dpkg")]
    if bev != mine.events:
        i = 0
        while i < min(len(bev), len(mine.events)) and bev[i] == mine.events[i]:
            i += 1
        lo = max(0, i - 2)
        diffs.append("events differ (belay %d, reference %d; first difference at %d):"
                     % (len(bev), len(mine.events), i))
        for tag, lst in (("belay", bev), ("reference", mine.events)):
            diffs.append("  %s:" % tag)
            for e in lst[lo:i + 12]:
                diffs.append("    " + e.decode("utf-8", "replace"))
    return diffs


# ---------------------------------------------------------------- cells

def evs(mine):
    return [json.loads(e) for e in mine.events]


def kinds(mine, interp=None):
    return [e["event"] for e in evs(mine) if interp is None or e["interp"] == interp]


REASON_OF = {"no_store": "no_store", "missing_nostored": "missing", "missing_absent": "missing",
             "missing_unverified": "missing", "corrupt_content": "corrupt",
             "corrupt_symlink": "corrupt", "too_large": "too_large",
             "too_large_rows": "too_large"}


def check_cell(cell, mine):
    """Did this pair's reference output show the cell it was built for?"""
    E = evs(mine)
    K = kinds(mine)

    def has(kind, **kw):
        return any(e["event"] == kind and all(e.get(k) == v for k, v in kw.items()) for e in E)

    if cell.startswith("cu."):
        parts = cell.split(".")
        interp, variant, side = parts[1], parts[2], parts[-1]
        if variant in REASON_OF:
            return has("content_unavailable", interp=interp, reason=REASON_OF[variant], side=side)
        if variant == "one_path_both_sides":
            return has("content_unavailable", interp=interp, side="both")
        if variant == "one_path_two_reasons":
            return sum(1 for e in E if e["event"] == "content_unavailable") == 2
        return False
    simple = {
        "dpkg.installed": lambda: "dpkg_installed" in K,
        "dpkg.removed": lambda: "dpkg_removed" in K,
        "dpkg.upgraded": lambda: "dpkg_upgraded" in K,
        "dpkg.downgraded": lambda: "dpkg_downgraded" in K,
        "dpkg.state_changed.alone": lambda: any(
            e["event"] == "dpkg_state_changed" and not any(
                f["event"] in ("dpkg_upgraded", "dpkg_downgraded") and f["package"] == e["package"]
                and f["arch"] == e["arch"] for f in E) for e in E),
        "dpkg.state_changed.with_upgrade": lambda: any(
            e["event"] == "dpkg_state_changed" and any(
                f["event"] == "dpkg_upgraded" and f["package"] == e["package"]
                and f["arch"] == e["arch"] for f in E) for e in E),
        "dpkg.empty_arch": lambda: any(e.get("arch") == "" for e in E),
        "dpkg.key_repeated_first_wins": lambda: has("dpkg_upgraded", package="curl",
                                                    **{"from": "1.0-1", "to": "2.0-1"}),
        "dpkg.multi_arch": lambda: len({e["arch"] for e in E if e.get("package") == "libssl3"}) >= 3,
        "dpkg.status_added_all_installed": lambda: K and all(k == "dpkg_installed" for k in K),
        "dpkg.status_removed": lambda: "dpkg_removed" in K and "dpkg_state_changed" in K,
        "dpkg.status_short": lambda: has("dpkg_installed", package="curl")
        and has("dpkg_removed", package="wget"),
        "dpkg.continuation_multiline": lambda: has("dpkg_upgraded", package="curl"),
        "dpkg.two_status_files": lambda: len({tuple(e.get("paths", [])) for e in E
                                              if e["interp"] == "dpkg"}) >= 2,
        "pip.installed": lambda: "pip_installed" in K,
        "pip.removed": lambda: "pip_removed" in K,
        "pip.upgraded": lambda: "pip_upgraded" in K,
        "pip.downgraded": lambda: "pip_downgraded" in K,
        "pip.version_changed.pep440_equal": lambda: K.count("pip_version_changed") == 2,
        "pip.version_changed.non_pep440": lambda: K.count("pip_version_changed") == 2,
        "pip.reinstalled.files_added": lambda: any(e.get("files_added", 0) > 0 for e in E),
        "pip.reinstalled.files_removed": lambda: any(e.get("files_removed", 0) > 0 for e in E),
        "pip.reinstalled.changed_hash": lambda: any(e.get("files_changed", 0) > 0 for e in E),
        "pip.reinstalled.changed_size": lambda: any(e.get("files_changed", 0) > 0 for e in E),
        "pip.reinstalled.path_listed_twice": lambda: "pip_reinstalled" in K,
        "pip.diff_dirs_not_paired": lambda: "pip_installed" in K and "pip_removed" in K,
        "pip.normalize_equal_paired": lambda: "pip_upgraded" in K and "pip_downgraded" in K,
        "pip.name_split_first_dash": lambda: has("pip_installed", name="typing",
                                                 version="extensions-4.8.0"),
        "pip.E6.unnameable": lambda: K == ["could_not_interpret"],
        "pip.E6.ambiguous": lambda: K == ["could_not_interpret"],
        "pip.metadata_changes_nothing": lambda: not K and not any(mine.findings.values()),
        "pip.events_order": lambda: len(set(K)) >= 3 and len(K) >= 5,
        "paths_b64": lambda: any("paths_b64" in e for e in E),
        "random": lambda: True,
        "probe.dpkg.E5_bound": lambda: K.count("dpkg_installed") == ref.EVENT_BOUND - 1
        and K[-1] == "and_more",
        "probe.dpkg.E6_line_not_a_field": lambda: K == ["could_not_interpret"],
        "probe.dpkg.E6_value_not_string": lambda: K == ["could_not_interpret"],
        "probe.dpkg.E6_paths_given": lambda: K == ["could_not_interpret"],
        "probe.pip.E6_row_of_two_fields": lambda: K == ["could_not_interpret"],
        "probe.pip.E6_record_not_utf8": lambda: K == ["could_not_interpret"],
        "probe.dpkg.E6_event_text_over_1024": lambda: K == ["could_not_interpret"],
        "probe.dpkg.md5sums_outside_info": lambda: K == ["could_not_interpret"],
    }
    if cell in simple:
        return bool(simple[cell]())
    if cell.startswith("probe."):
        return True
    raise KeyError("no check for cell " + cell)


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", action="store_true", help="keep every case's directory")
    ap.add_argument("--only", help="run only cases whose name contains this")
    a = ap.parse_args()

    t0 = time.time()
    if os.path.exists(a.work):
        shutil.rmtree(a.work)
    os.makedirs(a.work)
    cache = os.path.join(os.path.dirname(os.path.abspath(a.work)), "zero-digests.json")
    cases = gen.all_cases(a.n, a.seed)
    if a.only:
        cases = [c for c in cases if a.only in c.name]
    hits = collections.Counter()
    declared = set()
    failed = []
    pairs = 0
    seen_kinds = collections.Counter()
    for case in cases:
        d = os.path.join(a.work, case.name)
        gen.write_case(case, d, cache)
        before = os.path.join(d, "before.ndjson")
        after = os.path.join(d, "after.ndjson")
        store = os.path.join(d, "store")
        report = []
        for mode in case.modes:
            pairs += 1
            out = os.path.join(d, "diff-%s.ndjson" % mode)
            cmd = [a.driver] + (["--store", store] if mode == "store" else ["--no-store"])
            r = subprocess.run(cmd + [before, after, out], capture_output=True)
            mine = ref.interpret(before, after, store if mode == "store" else None)
            if r.returncode != 0:
                report.append("[%s] driver failed (%d): %s" % (mode, r.returncode,
                                                               r.stderr.decode(errors="replace")))
                continue
            for e in mine.events:
                o = json.loads(e)
                seen_kinds["%s %s" % (o["interp"], o["event"])] += 1
            diffs = compare(parse_diff(out), mine)
            if diffs:
                report.append("[%s]" % mode)
                report += ["  " + x for x in diffs]
            for cell in case.tags[mode]:
                declared.add(cell)
                if check_cell(cell, mine):
                    hits[cell] += 1
                else:
                    report.append("[%s] cell %s not shown by the reference's output" % (mode, cell))
        if report:
            failed.append(case.name)
            with open(os.path.join(d, "report.txt"), "w") as f:
                f.write("\n".join(report) + "\n")
            print("FAIL %s (%s)" % (case.name, os.path.join(d, "report.txt")))
            for line in report[:40]:
                print("  " + line)
        elif not a.keep:
            shutil.rmtree(d)

    print("\nevent records the reference expected, over every pair:")
    for k, n in sorted(seen_kinds.items()):
        print("  %-48s %d" % (k, n))
    print("\ncells (hits):")
    zero = []
    for cell in sorted(declared):
        print("  %-48s %d" % (cell, hits[cell]))
        if hits[cell] == 0:
            zero.append(cell)
    print("\n%d cases, %d pairs, %d failing cases, %.1f s"
          % (len(cases), pairs, len(failed), time.time() - t0))
    if zero:
        print("coverage gate: cells never hit: " + ", ".join(zero))
    if failed:
        print("failing: " + ", ".join(failed))
    return 1 if (failed or zero) else 0


if __name__ == "__main__":
    sys.exit(main())
