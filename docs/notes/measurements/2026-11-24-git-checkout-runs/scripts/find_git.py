"""Find every recorded tool call that runs a git command, and the runs that point git checkout/restore/reset at a
graded test file. Text only: nothing recorded is executed.

Usage: python3 -I find_git.py TRANSCRIPT_DIR OUT_JSON
Tool-call index: 0-based, counted over all tool calls of the run in recorded order (as in ../2026-11-24-write-then-restore/scripts/scan.py).
Search pattern (the "18"): a tool call whose argument text contains GIT_UNDO_RE, where the matched simple command
(up to the next newline, ';', '&&', '||' or '|') names test.py or test_cases.json, or is `git reset --hard` / `git stash`
with no path (whole tree).
"""
import json, sys, glob, os, re, hashlib, collections

TDIR, OUT = sys.argv[1:3]
ANY_GIT_RE = re.compile(r"(?<![\w./-])git\s+[a-z-]+")
GIT_UNDO_RE = re.compile(r"(?<![\w./-])git\s+(?:-C\s+\S+\s+)?(checkout|restore|reset|stash)\b[^\n;&|]*")
TF_RE = re.compile(r"(?<![\w-])(test\.py|test_cases\.json)(?![\w.])")


def call_text(tc):
    a = tc.get("arguments") or {}
    return "\n".join(str(v) for v in a.values()) if isinstance(a, dict) else str(a)


def result_of(msgs, i, tc):
    for m in msgs[i + 1:i + 40]:
        if m.get("role") == "tool" and m.get("tool_call_id") == tc.get("id"):
            c = m.get("content")
            if isinstance(c, list):
                c = "\n".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in c)
            err = m.get("error")
            return (str(c) if c is not None else "") + ("\n[error] " + json.dumps(err) if err else "")
    return None


any_git = collections.Counter()
any_git_runs = set()
hits = []
subcmds = collections.Counter()
for fn in sorted(glob.glob(os.path.join(TDIR, "*.jsonl"))):
    for line in open(fn):
        d = json.loads(line)
        if not d["in_paper_analysis"]:
            continue
        key = hashlib.sha256(d["run_key"].encode()).hexdigest()[:16]
        msgs = d["messages"]
        ci = -1
        found = []
        for i, m in enumerate(msgs):
            if m.get("role") != "assistant":
                continue
            for tc in m.get("tool_calls") or []:
                ci += 1
                t = call_text(tc)
                for g in ANY_GIT_RE.finditer(t):
                    subcmds[g.group(0).split()[-1]] += 1
                    any_git_runs.add(key)
                for g in GIT_UNDO_RE.finditer(t):
                    seg = g.group(0)
                    names_tf = bool(TF_RE.search(seg))
                    whole = (g.group(1) == "reset" and "--hard" in seg) or g.group(1) == "stash"
                    if names_tf or whole:
                        found.append(dict(call=ci, msg=i, function=tc.get("function"), segment=seg.strip(),
                                          names_test_file=names_tf, result=(result_of(msgs, i, tc) or "")))
        if found:
            hits.append(dict(key=key, run_key=d["run_key"], model=d["model"], condition=d["condition"],
                             problem=d["problem_id"], epoch=d["epoch"], calls=found))
print("runs with any git command:", len(any_git_runs))
print("git subcommands (occurrences):", dict(subcmds.most_common()))
print("runs with git checkout/restore/reset/stash aimed at a test file or the whole tree:", len(hits))
for h in hits:
    print(h["key"], h["model"], h["condition"], h["problem"],
          [(c["call"], c["segment"][:70], c["names_test_file"], c["result"].strip()[:60]) for c in h["calls"]])
json.dump(hits, open(OUT, "w"), indent=1)
