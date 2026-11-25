"""Computed facts per git call for the runs found by find_git.py: the recorded writes to test.py / test_cases.json
before it, the test runs (python test.py etc.) after the first write and before the git call (same call counts when
the write precedes the run in the command), each run's recorded summary line, and the call distances.
Text only. Usage: python3 -I facts.py TRANSCRIPT_DIR HITS_JSON SCAN_JSON OUT_JSON
"""
import json, sys, glob, os, hashlib, re

TDIR, HITS, SCAN, OUT = sys.argv[1:5]
hits = {h["key"]: h for h in json.load(open(HITS))}
scan = {hashlib.sha256(r["run_key"].encode()).hexdigest()[:16]: r for r in json.load(open(SCAN))["rows"]}
SUMMARY = re.compile(r"(Results?:[^\n]*|\d+/\d+ (?:tests )?passed[^\n]*|All tests passed[^\n]*|Passed \d+/\d+|"
                     r"Tests passed|\w*Error:[^\n]*|Failed for[^\n]*)")
out = {}
for fn in sorted(glob.glob(os.path.join(TDIR, "*.jsonl"))):
    for line in open(fn):
        d = json.loads(line)
        if not d["in_paper_analysis"]:
            continue
        key = hashlib.sha256(d["run_key"].encode()).hexdigest()[:16]
        if key not in hits:
            continue
        msgs = d["messages"]
        res = {m.get("tool_call_id"): m.get("content") for m in msgs if m.get("role") == "tool"}
        calls = [tc for m in msgs if m.get("role") == "assistant" for tc in (m.get("tool_calls") or [])]
        ev = {e["call"]: e for e in scan[key]["events"]}
        writes = sorted(c for c, e in ev.items() if any(w["kind"] not in ("git_failed", "failed") for w in e["writes"]))
        runs = sorted(c for c, e in ev.items() if e["runs_test"])
        G = []
        for g in sorted(c["call"] for c in hits[key]["calls"]):
            wb = [w for w in writes if w < g]
            tr = []
            for r in runs:
                if wb and wb[0] <= r < g:
                    rt = res.get(calls[r].get("id"))
                    rt = "\n".join(p.get("text", "") for p in rt) if isinstance(rt, list) else str(rt)
                    s = [m.group(0) for m in SUMMARY.finditer(rt)]
                    last = [l for l in rt.strip().split("\n") if l.strip()]
                    tr.append(dict(call=r, summary=(s[-1] if s else (last[-1] if last else "<empty output>"))[:120],
                                   returncode=(re.search(r"# returncode:\n(\d+)", rt).group(1) if "# returncode:" in rt else "0 (no returncode block)")))
            G.append(dict(git=g, writes_before=[(w, ev[w]["writes"][0]["file"], ev[w]["writes"][0]["kind"], ev[w]["writes"][0]["desc"][:60]) for w in wb],
                          last_write_before=(wb[-1] if wb else None), calls_since_last_write=(g - wb[-1] if wb else None),
                          calls_since_first_write=(g - wb[0] if wb else None), test_runs_between=tr))
        out[key] = dict(n_calls=len(calls), last_call_fn=calls[-1].get("function") if calls else None,
                        submitted=any(c.get("function") == "submit" for c in calls), git=G,
                        writes_after_last_git=[w for w in writes if w > G[-1]["git"]],
                        runs_after_last_git=[r for r in runs if r > G[-1]["git"]])
json.dump(out, open(OUT, "w"), indent=1)
for k, v in out.items():
    print(k, "n", v["n_calls"], "submit", v["submitted"], "| after:", v["writes_after_last_git"], v["runs_after_last_git"])
    for g in v["git"]:
        print("   git c%d  last write c%s (+%s, first +%s)  runs:" % (g["git"], g["last_write_before"], g["calls_since_last_write"], g["calls_since_first_write"]),
              "; ".join("c%d rc=%s %r" % (t["call"], t["returncode"], t["summary"][:60]) for t in g["test_runs_between"]))
