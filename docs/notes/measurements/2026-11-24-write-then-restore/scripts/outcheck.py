"""Independent behavioural check: in runs the dataset hash calls unmodified, does any recorded `python test.py` output
look like a different runner or case file (case count != the original's, or no 'Running N test cases' header)?
Also: recorded message count vs the table's total_messages. Usage: python3 -I outcheck.py DATA"""
import json, sys, glob, os, hashlib, re, collections, csv
data = sys.argv[1]
C = {r["run_key"]: r for r in csv.DictReader(open(os.path.join(data, "per_run_data_all_conditions.csv")))}
RUN = re.compile(r"(python3?\s+(-u\s+)?(\./|/home/agent/workspace/)?test\.py(?![\w.]))")
c = collections.Counter(); odd = []
for fn in sorted(glob.glob(os.path.join(data, "transcripts", "*.jsonl"))):
    for line in open(fn):
        d = json.loads(line)
        if not d["in_paper_analysis"]:
            continue
        c["msgs_match" if str(len(d["messages"])) == C[d["run_key"]]["total_messages"] else "msgs_differ"] += 1
        if d["score"].get("files_modified"):
            continue
        n = d["problem"]["n_visible_test_cases"]
        k = hashlib.sha256(d["run_key"].encode()).hexdigest()[:16]
        msgs = d["messages"]; ci = -1
        for i, m in enumerate(msgs):
            if m.get("role") != "assistant":
                continue
            for tc in m.get("tool_calls") or []:
                ci += 1
                cmd = str((tc.get("arguments") or {}).get("cmd", ""))
                if tc.get("function") != "safe_bash" or not RUN.search(cmd):
                    continue
                res = next((str(m2.get("content")) for m2 in msgs[i + 1:i + 30] if m2.get("role") == "tool" and m2.get("tool_call_id") == tc.get("id")), "")
                c["test_runs"] += 1
                hs = re.findall(r"Running (\d+) test cases", res)
                if hs and all(int(h) == n for h in hs):
                    c["header_ok"] += 1
                elif hs:
                    c["header_other_count"] += 1; odd.append((k, ci, cmd[:80], hs[:3], n))
                elif re.search(r"test\.py[^\n;&]*\|", cmd) or re.search(r"Results: \d+/%d passed" % n, res):
                    c["no_header_piped_or_results_ok"] += 1
                else:
                    c["no_header_other"] += 1; odd.append((k, ci, cmd[:80], res[:120].replace("\n", " / "), n))
print(c)
for o in odd[:40]:
    print(o)
