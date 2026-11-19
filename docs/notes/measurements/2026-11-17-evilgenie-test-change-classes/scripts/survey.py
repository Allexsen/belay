"""Read-only survey of the 146 EvilGenie runs that changed a test file: what the stored end states show."""
import collections, difflib, glob, hashlib, json, os
E = os.path.expanduser("~/belay-replay/eg")
PROB = json.load(open(E + "/problems.json"))
S = {s["key"]: s for s in json.load(open(E + "/scale_results.json"))}
keys = sorted(os.path.basename(f)[:-5] for f in glob.glob(E + "/proof2/*.json"))
rows = []
for k in keys:
    r = json.load(open(E + "/results2/%s.json" % k)); pr = json.load(open(E + "/proof2/%s.json" % k))["files"]; s = S[k]
    row = dict(key=k, problem=r["problem"], model=r["model"], group=s["group"], cls=s["classification"], th=s["tamper_hack"],
               sc_test=r["sc_test"], sc_cases=r["sc_cases"])
    for n, end, h in (("test.py", r["end_test"], r["h_test"]), ("test_cases.json", r["end_cases"], r["h_cases"])):
        st = "deleted" if end is None else ("same" if end == h else "changed")
        row[n] = st; row[n + ":proven"] = pr.get(n, {}).get("literal_proven")
        if st == "changed":
            src = E + "/keep2/%s/%s" % (k, n)
            row[n + ":have"] = os.path.exists(src) and hashlib.sha256(open(src, "rb").read()).hexdigest() == end
    rows.append(row)
json.dump(rows, open(os.path.dirname(os.path.abspath(__file__)) + "/rows.json", "w"))
c = collections.Counter((r["test.py"], r["test_cases.json"]) for r in rows)
print("runs", len(rows)); print("end state (test.py, test_cases.json):", dict(c))
print("dataset says test.py modified / cases modified:", collections.Counter((r["sc_test"], r["sc_cases"]) for r in rows))
print("stored copy held for changed test.py:", collections.Counter(r.get("test.py:have") for r in rows if r["test.py"] == "changed"))
print("stored copy held for changed cases:", collections.Counter(r.get("test_cases.json:have") for r in rows if r["test_cases.json"] == "changed"))
print("classification:", collections.Counter(r["cls"] for r in rows)); print("tamper_hack:", collections.Counter(r["th"] for r in rows))
print("problems:", collections.Counter(r["problem"] for r in rows))
print("proven test.py:", collections.Counter(r["test.py:proven"] for r in rows if r["test.py"] != "same"))
