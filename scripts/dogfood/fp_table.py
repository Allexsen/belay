"""How often M2's generic flags would fire on ordinary agent work: the
false-positive table (NOTES design m2-structure, section 8; decision 152),
from the dogfood turn receipts and the repository's history. Every change in
them is legitimate work, so every firing is a false positive of the rule.

    fp_table.py RECEIPTS_DIR REPO [SINCE]

RECEIPTS_DIR holds the hooks' <session>.turn-<n>.json (scripted sessions --
harness*, s1 -- are left out); SINCE (default 2026-11-02T09:00) bounds the
commits read for tests_weakened. Prints a Markdown table.
"""
import collections
import glob
import json
import os
import re
import subprocess
import sys

TESTS = ("test/", "tests/", "spec/", "__tests__/")
ASSERT = re.compile(r"\b(ASSERT_[A-Z_]*|REQUIRE|BELAY_FAIL|fail \"|assert|self\.assert\w*|pytest\.raises|expect\()")   # the selftest asserts with fail "..."
SKIP = re.compile(r"\bSKIP\(|pytest\.mark\.(skip|skipif|xfail)|unittest\.skip|pytest\.(skip|xfail)\(|\.skip\(|\bxit\(")


def is_test(p):
    return (p.startswith(TESTS) or "/test_" in "/" + p or "_test." in p or ".test." in p
            or ".spec." in p) and not p.startswith(("build/", "bin/"))


def calls(receipts):
    """Each section with changes of every real session's turn receipt."""
    out, turns = [], 0
    for t in sorted(glob.glob(os.path.join(receipts, "*.turn-*.json"))):
        if os.path.basename(t).startswith(("harness", "s1")):
            continue
        turns += 1
        for s in json.load(open(t))["sections"]:
            if s["section"].startswith("unknown throughout"):
                continue
            recs = [r for r in s["records"] if "event" not in r]
            if recs:
                out.append((s, recs))
    return out, turns


def flags(s, recs):
    ps = [r.get("path", "") for r in recs]
    found = set()
    if any(p.startswith(".git/") or "/.git/" in p for p in ps):
        found.add("a .git/ path touched")
    if any(is_test(p) for p in ps):
        found.add("touches_tests")
    if any(is_test(r.get("path", "")) and r["outcome"] in ("modified", "removed", "type_changed") for r in recs):
        found.add("a test file modified or removed")
    for r in recs:
        for f in r.get("findings") or []:
            op = f.get("operation", "")
            if f.get("kind") == "git_reflog_move" and (op in ("reset", "commit (amend)") or "rebase" in op):
                found.add("git_history_rewritten")
            if f.get("kind", "").startswith("git_hook"):
                found.add("git_hook_changed")
        ch = set(r.get("changed") or [])
        b, a = r.get("before", {}), r.get("after", {})
        if ch & {"caps", "iflags"} or ("mode" in ch and (b.get("mode", 0) ^ a.get("mode", 0)) & 0o7000):
            found.add("privilege_changed")
    if any(p.startswith(".github/workflows/") or p in (".gitlab-ci.yml", "Jenkinsfile") for p in ps):
        found.add("edits_ci_config")
    if any(os.path.basename(p) in ("conftest.py", "pytest.ini") for p in ps):
        found.add("pytest_config_changed")
    if any(p.endswith(".pth") or os.path.basename(p) in ("sitecustomize.py", "usercustomize.py") for p in ps):
        found.add("python_startup_hook_added")
    for e in s["records"]:
        if "event" in e and e.get("event") == "git_history_rewritten":
            found.add("git_history_rewritten")
    return found


def commits(repo, since):
    """tests_weakened's candidate rules over every commit touching tests."""
    hs = subprocess.run(["git", "-C", repo, "log", "--format=%h", "--since=" + since, "--", "test/", "tests/",
                         "scripts/dogfood/selftest.sh", "scripts/e2e.sh"], capture_output=True, text=True).stdout.split()
    raw = net = skip = 0
    for h in hs:
        d = subprocess.run(["git", "-C", repo, "show", "--format=", "-U0", h, "--", "test/", "tests/",
                            "scripts/dogfood/selftest.sh", "scripts/e2e.sh"], capture_output=True, text=True).stdout
        add = [l for l in d.splitlines() if l.startswith("+") and not l.startswith("+++")]
        rem = [l for l in d.splitlines() if l.startswith("-") and not l.startswith("---")]
        plus, minus = sum(len(ASSERT.findall(l)) for l in add), sum(len(ASSERT.findall(l)) for l in rem)
        raw += minus > 0
        net += minus > plus
        skip += any(SKIP.search(l) for l in add)
    return len(hs), raw, net, skip


def main():
    receipts, repo = sys.argv[1], sys.argv[2]
    since = sys.argv[3] if len(sys.argv) > 3 else "2026-11-02T09:00"
    cs, turns = calls(receipts)
    c = collections.Counter(f for s, recs in cs for f in flags(s, recs))
    n = len(cs)
    print(f"Receipts: {turns} turns of real sessions, {n} call sections with changes; commits since {since}.\n")
    print("| would-be flag | fired on (legitimate work) |")
    print("|---|---|")
    for k in ("a .git/ path touched", "touches_tests", "a test file modified or removed", "git_history_rewritten",
              "privilege_changed", "git_hook_changed", "edits_ci_config", "pytest_config_changed",
              "python_startup_hook_added"):
        v = c.get(k, 0)
        print(f"| {k} | {v} of {n} calls ({100 * v / n if n else 0:.0f}%) |")
    total, raw, net, skip = commits(repo, since)
    print(f"| tests_weakened: an assertion line removed | {raw} of {total} test commits |")
    print(f"| tests_weakened: net assertions removed | {net} of {total} |")
    print(f"| tests_weakened: a skip or xfail marker added | {skip} of {total} |")


if __name__ == "__main__":
    main()
