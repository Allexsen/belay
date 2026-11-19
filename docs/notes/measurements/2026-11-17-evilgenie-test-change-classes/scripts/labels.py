"""labels.py OUT_DIR: one row per run in OUT_DIR/labels.tsv, from rows.json (survey.py), feat.json (feat.py)
and ast.json (astfacts.py) beside this script. Read-only on the replay data; nothing is run."""
import collections, csv, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
D = sys.argv[1]
R = json.load(open(HERE + "/rows.json")); F = {f["key"]: f for f in json.load(open(HERE + "/feat.json"))}
A = json.load(open(HERE + "/ast.json"))


def cases_label(f, r):
    if r["test_cases.json"] == "deleted":
        return "deleted"
    c = f.get("cases")
    if c is None:
        return ""
    if c == "not a JSON list":
        return "emptied (0 bytes)"
    if c["after"] < c["before"]:
        return "fewer cases"
    if c["out_changed"]:
        return "an expected output edited"
    if c["removed"] or c["added"]:
        return "cases added or swapped"
    return "same JSON, bytes differ"


rows = []
for r in R:
    k = r["key"]; f = F[k]; a = A.get(k, {})
    c = f.get("cases") if isinstance(f.get("cases"), dict) else {}
    rows.append(dict(
        key=k, problem=r["problem"], model=r["model"], dataset_classification=r["cls"], tamper_hack=r["th"],
        dataset_says_test_py_modified=r["sc_test"], dataset_says_cases_modified=r["sc_cases"],
        test_py="deleted" if r["test.py"] == "deleted" else a.get("bucket", "unchanged"),
        test_py_write_byte_proven=r.get("test.py:proven"), lines_added=f.get("add", ""), lines_removed=f.get("rem", ""),
        parses=a.get("parses", ""), runs_solution=a.get("runs_solution", ""), reads_cases=a.get("reads_cases", ""),
        reads_expected=a.get("reads_expected", ""), failing_exits=a.get("fail_exit", ""), asserts=a.get("asserts", ""),
        raises=a.get("raises", ""), original_if_present=a.get("orig_if", ""),
        test_cases=cases_label(f, r) or "unchanged", cases_before=c.get("before", ""), cases_after=c.get("after", ""),
        case_ids_removed=c.get("removed", ""), case_ids_added=c.get("added", ""), outputs_changed=c.get("out_changed", ""),
        inputs_changed=c.get("in_changed", "")))
with open(D + "/labels.tsv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0]), delimiter="\t")
    w.writeheader(); w.writerows(rows)
print(len(rows), "rows")
print(collections.Counter(r["test_py"] for r in rows))
print(collections.Counter(r["test_cases"] for r in rows))
print("both files touched:", sum(1 for r in rows if r["test_py"] != "unchanged" and r["test_cases"] != "unchanged"))
