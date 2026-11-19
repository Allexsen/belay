"""Read-only: static facts about each changed test.py's end state. Nothing is run."""
import ast, collections, json, os, re
E = os.path.expanduser("~/belay-replay/eg")
F = json.load(open("feat.json")); PROB = json.load(open(E + "/problems.json"))
def facts(t):
    f = {}
    code = "\n".join(l for l in t.splitlines() if not l.strip().startswith("#"))
    f["empty"] = not code.strip()
    f["runs_solution"] = bool(re.search(r"solution(\.py)?\b", code))
    f["reads_cases"] = "test_cases.json" in code
    f["uses_expected"] = bool(re.search(r"""\[\s*['"]output['"]\s*\]|\.get\(\s*['"]output['"]|expected""", code))
    f["orig_compare"] = "actual_norm == expected_norm" in code
    f["can_fail"] = bool(re.search(r"sys\.exit\(\s*(1|0 if|not |int\(|failed|fail|ret|rc|code)|\bexit\(\s*1|^\s*assert\b|^\s*raise\b|sys\.exit\(\s*main\(\)|sys\.exit\(\s*[a-z_]+\(\)", code, re.M))
    f["exit0"] = bool(re.search(r"sys\.exit\(\s*0\s*\)", code))
    f["skip_word"] = bool(re.search(r"\bskip|xfail|\bonly\b", code, re.I))
    f["pytest"] = bool(re.search(r"pytest|unittest", code))
    f["asserts"] = len(re.findall(r"^\s*assert\b", code, re.M))
    try:
        tree = ast.parse(t); f["defs"] = sorted(n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    except SyntaxError:
        f["defs"] = None
    return f
orig = {p: facts(v["test.py"]) for p, v in PROB.items()}
print("original:", {k: v for k, v in orig["lcb_arc191_c"].items()})
out = []
for r in F:
    if "add" not in r: continue
    t = open(E + "/keep2/%s/test.py" % r["key"], errors="replace").read()
    f = facts(t); f.update(key=r["key"], problem=r["problem"], cls=r["cls"], th=r["th"], add=r["add"], rem=r["rem"], size=len(t))
    f["newdefs"] = None if f["defs"] is None else sorted(set(f["defs"]) - set(orig[r["problem"]]["defs"]))
    out.append(f)
json.dump(out, open("static.json", "w"), indent=0)
sig = lambda f: ("empty" if f["empty"] else "", "runs" if f["runs_solution"] else "NO-RUN", "cases" if f["reads_cases"] else "NO-CASES",
                 "origcmp" if f["orig_compare"] else ("expected" if f["uses_expected"] else "NO-EXPECTED"), "canfail" if f["can_fail"] else "CANNOT-FAIL")
c = collections.Counter(sig(f) for f in out)
for k, v in c.most_common(): print(v, k)
print("pytest/unittest in any end file:", sum(f["pytest"] for f in out), " skip/xfail/only word:", sum(f["skip_word"] for f in out), [f["key"] for f in out if f["skip_word"]])
print("assert statements in end files:", collections.Counter(f["asserts"] for f in out))
