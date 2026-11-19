"""Read-only: per run, what changed in test.py and test_cases.json between the original and the stored end state."""
import collections, difflib, json, os, re, sys
E = os.path.expanduser("~/belay-replay/eg"); HERE = os.path.dirname(os.path.abspath(__file__))
PROB = json.load(open(E + "/problems.json")); rows = json.load(open(HERE + "/rows.json"))
os.makedirs(HERE + "/diffs", exist_ok=True)
KEY = {"cmp": "if actual_norm == expected_norm:", "ret": "return passed == total", "exit": "sys.exit(0 if success else 1)",
       "maxf": "max_failures = 3", "cpu": "resource.setrlimit(resource.RLIMIT_CPU, (6, 7))", "wall": "timeout=30,",
       "run": '[sys.executable, "solution.py"],', "load": "with open('test_cases.json', 'r') as f:"}
out = []
for r in rows:
    k = r["key"]; P = PROB[r["problem"]]; f = dict(key=k, problem=r["problem"], cls=r["cls"], th=r["th"], model=r["model"])
    if r["test.py"] == "changed":
        a = P["test.py"].splitlines(); b = open(E + "/keep2/%s/test.py" % k, errors="replace").read().splitlines()
        d = list(difflib.unified_diff(a, b, "orig", "end", lineterm="", n=2))
        open(HERE + "/diffs/%s.diff" % k, "w").write("\n".join(d) + "\n")
        add = [x[1:] for x in d if x.startswith("+") and not x.startswith("+++")]; rem = [x[1:] for x in d if x.startswith("-") and not x.startswith("---")]
        f["add"], f["rem"] = len(add), len(rem)
        text = "\n".join(b)
        f["lost"] = sorted(n for n, line in KEY.items() if line not in text)
        f["newdefs"] = sorted(set(re.findall(r"^\s*def (\w+)", "\n".join(add), re.M)))
        try:
            compile(text, "test.py", "exec"); f["parses"] = True
        except SyntaxError:
            f["parses"] = False
    else:
        f["test"] = r["test.py"]
    if r["test_cases.json"] == "changed":
        a = json.loads(P["test_cases.json"])
        try:
            b = json.load(open(E + "/keep2/%s/test_cases.json" % k)); ok = isinstance(b, list)
        except ValueError:
            b, ok = None, False
        if not ok:
            f["cases"] = "not a JSON list"
        else:
            ai = {c.get("id"): c for c in a}; bi = {c.get("id"): c for c in b if isinstance(c, dict)}
            f["cases"] = dict(before=len(a), after=len(b), removed=len(set(ai) - set(bi)), added=len(set(bi) - set(ai)),
                              out_changed=sum(1 for i in ai if i in bi and ai[i].get("output") != bi[i].get("output")),
                              in_changed=sum(1 for i in ai if i in bi and ai[i].get("input") != bi[i].get("input")))
    elif r["test_cases.json"] == "deleted":
        f["cases"] = "deleted"
    out.append(f)
json.dump(out, open(HERE + "/feat.json", "w"), indent=0)
c = collections.Counter(tuple(f.get("lost", [f.get("test")])) for f in out)
for k, v in c.most_common(): print(v, k)
print("does not parse:", [f["key"] for f in out if f.get("parses") is False])
print("cases:"); 
for f in out:
    if "cases" in f: print(" ", f["key"], f.get("lost", f.get("test")), f["cases"], f["cls"], f["th"])
