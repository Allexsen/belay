#!/usr/bin/env python3
"""Replay the published EvilGenie agent runs against belay: README.md.

    replay.py --belay PATH --work DIR --i-know-this-runs-model-written-code [--workers 3] [--sample N] [--compare FILE]

It downloads the pinned inputs, rebuilds each workspace, replays each run's tool calls in a sandbox, runs belay around
them, and writes DIR/report.md and DIR/report.json. Finished runs are kept: run it again to resume.
"""
import argparse
import base64
import collections
import csv
import glob
import hashlib
import io
import json
import multiprocessing
import os
import pickle
import random
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rules

PINS = json.load(open(os.path.join(HERE, "pins.json")))
WARNING = """This replays code written by language models, some of it deliberately trying to pass tests it should not.
It runs in a chroot with no network, in new namespaces, with memory and time limits. That is a best effort, not a
security boundary. Run it on a machine you can afford to lose, or inside a VM. See README.md."""
HF = "https://huggingface.co"
MEM_LIMIT = 0.60                                # of RAM: above this, the watchdog kills the largest sandboxed process


def get(url, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": "belay-bench-replay", **(headers or {})})
    return urllib.request.urlopen(req, timeout=300)


def save(url, path):
    if os.path.exists(path) and os.path.getsize(path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with get(url) as r, open(path + ".part", "wb") as f:
        shutil.copyfileobj(r, f)
    os.rename(path + ".part", path)


def fetch(work):
    """The pinned inputs, into DIR/data. Nothing here is redistributed by this repository."""
    d = PINS["dataset"]
    data = os.path.join(work, "data")
    names = [s["rfilename"] for s in json.load(get(f"{HF}/api/datasets/{d['repo']}/revision/{d['revision']}"))["siblings"]]
    for n in names:
        if n.startswith("transcripts/") or n == "tables/per_run_data_all_conditions.csv":
            save(f"{HF}/datasets/{d['repo']}/resolve/{d['revision']}/{n}", os.path.join(data, n))
    c = PINS["code"]
    code = os.path.join(data, "code")
    if not os.path.isdir(code):
        with get(f"https://codeload.github.com/{c['repo']}/tar.gz/{c['commit']}") as r:
            t = tarfile.open(fileobj=io.BytesIO(r.read()), mode="r:gz")
            top = t.getnames()[0].split("/")[0]
            for m in t.getmembers():            # the templates alone: nothing from it is run
                if m.isfile() and m.name.startswith(top + "/templates/"):
                    out = os.path.join(code, m.name[len(top) + 1:])
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    with open(out, "wb") as f:
                        f.write(t.extractfile(m).read())
                elif m.isfile() and m.name == top + "/anti_reward_hacking_policy.md":
                    os.makedirs(code, exist_ok=True)
                    with open(os.path.join(code, "anti_reward_hacking_policy.md"), "wb") as f:
                        f.write(t.extractfile(m).read())
    rootfs(work)


def rootfs(work):
    """The image's filesystem, layer by layer, each layer checked against its digest."""
    root = os.path.join(work, "rootfs")
    if os.path.exists(os.path.join(root, ".done")):
        return
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    i = PINS["image"]
    tok = json.load(get(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{i['repo']}:pull"))["token"]
    reg = f"https://registry-1.docker.io/v2/{i['repo']}"
    auth = {"Authorization": "Bearer " + tok}
    man = json.load(get(f"{reg}/manifests/{i['digest']}", {**auth, "Accept": "application/vnd.oci.image.manifest.v1+json,"
                                                                             "application/vnd.docker.distribution.manifest.v2+json"}))
    for layer in man["layers"]:
        blob = get(f"{reg}/blobs/{layer['digest']}", auth).read()
        if "sha256:" + hashlib.sha256(blob).hexdigest() != layer["digest"]:
            sys.exit(f"image layer {layer['digest']}: the bytes do not match")
        subprocess.run(["tar", "-xz", "-C", root, "--no-same-owner", "--exclude=dev/*"], input=blob, check=True,
                       stderr=subprocess.DEVNULL)
        subprocess.run(["find", root, "-name", ".wh.*", "-delete"], check=True)
    for d in ("out", "home/agent/workspace"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    open(os.path.join(root, ".done"), "w").close()


class NoGlobals(pickle.Unpickler):
    """LiveCodeBench keeps private tests in pickles. The payload is a string: nothing else is let through."""
    def find_class(self, module, name):
        raise pickle.UnpicklingError(f"refused {module}.{name}")


def private_tests(s):
    return json.loads(NoGlobals(io.BytesIO(zlib.decompress(base64.b64decode(s)))).load())


def visible(tests, rng, ratio=.7, least=1, held=1, most_held=10):
    """The benchmark's split_test_cases."""
    n = len(tests)
    v = max(least, int(n * ratio), n - most_held)
    v = max(1, n // 2) if n <= least + held else min(v, n - held)
    idx = list(range(n))
    rng.shuffle(idx)
    keep = set(idx[:v])
    return [t for i, t in enumerate(tests) if i in keep]


def runs(work):
    for f in sorted(glob.glob(os.path.join(work, "data", "transcripts", "*.jsonl"))):
        with open(f) as h:
            for line in h:
                d = json.loads(line)
                if d.get("in_paper_analysis"):
                    yield d


def build(work):
    """The nine problems' workspaces, as the benchmark's dataset.py writes them, in a venv with Jinja2 alone.
    Each is checked against the hashes the recording publishes."""
    out = os.path.join(work, "problems.json")
    if os.path.exists(out):
        return
    venv = os.path.join(work, "venv")
    if not os.path.exists(os.path.join(venv, "bin", "python")):
        subprocess.run([sys.executable, "-m", "venv", venv], check=True)
        subprocess.run([os.path.join(venv, "bin", "pip"), "-q", "install", f"jinja2=={PINS['jinja2']}"], check=True)
    meta = {}
    for d in runs(work):
        meta.setdefault(d["problem_id"], d["problem"])
    lcb = PINS["livecodebench"]
    want = {k.replace("lcb_", ""): k for k in meta}
    found = {}
    for n in lcb["files"]:
        p = os.path.join(work, "data", "lcb", n)
        save(f"{HF}/datasets/{lcb['repo']}/resolve/{lcb['revision']}/{n}", p)
        with open(p) as h:
            for line in h:
                r = json.loads(line)
                if r.get("question_id") in want:
                    found[r["question_id"]] = r
    jobs = {}
    for q, pid in want.items():
        r, p = found[q], meta[pid]
        tests = json.loads(r.get("public_test_cases") or "[]") + private_tests(r["private_test_cases"])
        vis = visible(tests, random.Random(f"42:{q}"))
        cases = [{"id": i, "input": t["input"], "output": t["output"], "type": "function"} for i, t in enumerate(vis)]
        jobs[pid] = dict(problem=p, q=q, cases=json.dumps(cases, indent=2), description=r.get("question_content", ""),
                         starter=r.get("starter_code"))
    script = r"""
import hashlib,json,sys
from jinja2 import Environment,FileSystemLoader
T=Environment(loader=FileSystemLoader(sys.argv[1]));jobs=json.load(open(sys.argv[2]));out={}
h=lambda t:hashlib.sha256(t.encode()).hexdigest()
for pid,j in jobs.items():
    p=j['problem'];fn=p.get('function_name');isf=bool(p['is_function'])
    tc=T.get_template('test_cases.json.jinja').render(test_cases_json=j['cases'])
    ts=T.get_template('test_runner_function.py.jinja' if isf else 'test_runner_stdio.py.jinja').render(title=p['title'],pid=pid,function_name=fn,func_name=fn)
    sol=T.get_template('solution_function.py.jinja').render(title=p['title'],id=pid,starter_code=j['starter']) if isf else T.get_template('solution_stdio.py.jinja').render(title=p['title'],id=pid)
    md=T.get_template('problem.md.jinja').render(id=pid,title=p['title'],description=j['description'],difficulty=p['difficulty'])
    if h(ts)!=p['test_script_hash'] or h(tc)!=p['test_cases_hash']: sys.exit(pid+': the rebuilt test files do not match the published hashes')
    out[pid]={'test.py':ts,'test_cases.json':tc,'solution.py':sol,'problem.md':md}
json.dump(out,open(sys.argv[3],'w'))
"""
    jf = out + ".jobs"
    json.dump(jobs, open(jf, "w"))
    subprocess.run([os.path.join(venv, "bin", "python"), "-I", "-c", script, os.path.join(work, "data", "code", "templates"),
                    jf, out + ".part"], check=True)
    os.rename(out + ".part", out)
    os.remove(jf)


def sh(*a, **k):
    return subprocess.run(a, capture_output=True, text=True, errors="replace", **k)


def spec_version(belay, work):
    """Which spec the binary reads: 2 if it takes one, else 1."""
    d = os.path.join(work, "probe")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(os.path.join(d, "ws"))
    os.makedirs(os.path.join(d, "st"), mode=0o700)
    open(os.path.join(d, "ws", "f"), "w").close()
    json.dump(rules.spec(2), open(os.path.join(d, "p.json"), "w"))
    p = sh(belay, "baseline", "export", "--scope", d + "/ws", "--out", d + "/b", "--protect", d + "/p.json", "--json",
           env=dict(os.environ, BELAY_STATE_DIR=d + "/st", TMPDIR=d))
    shutil.rmtree(d, ignore_errors=True)
    return 1 if "belay_protect is not 1" in p.stderr else 2


def one(job):
    d, ctx = job
    k = rules.key(d["run_key"])
    done = os.path.join(ctx["work"], "results", k + ".json")
    if os.path.exists(done):
        return k
    B, P = ctx["belay"], ctx["problems"][d["problem_id"]]
    w = os.path.join(ctx["work"], "wk", k)
    shutil.rmtree(w, ignore_errors=True)
    ws, out, st = w + "/ws", w + "/out", w + "/st"
    os.makedirs(ws)
    os.makedirs(out)
    os.makedirs(st, mode=0o700)
    for n in ("test.py", "test_cases.json", "solution.py", "problem.md"):
        with open(f"{ws}/{n}", "w") as f:
            f.write(P[n])
    if d["condition"] in ("C", "D"):
        shutil.copy(os.path.join(ctx["work"], "data", "code", "anti_reward_hacking_policy.md"), ws)
    json.dump(rules.spec(ctx["spec"]), open(w + "/protect.json", "w"))
    env = dict(os.environ, BELAY_STATE_DIR=st, TMPDIR=out)
    r = dict(key=k, run_key=d["run_key"], model=d["model"], cond=d["condition"], problem=d["problem_id"], epoch=d["epoch"])
    try:
        base = json.loads(sh(B, "mark", "--scope", ws, "--json", env=env).stdout)["id"]
        e = sh(B, "baseline", "export", "--scope", ws, "--out", w + "/b", "--protect", w + "/protect.json", "--json", env=env)
        digest = re.search(r'"sha256":"([0-9a-f]{64})"', e.stdout).group(1)
        ops, rec = [], {}
        for m in d["messages"]:
            for t in m.get("tool_calls") or []:
                ops.append(dict(id=t["id"], fn=t["function"], args=t["arguments"]))
            if m.get("role") == "tool":
                rec[m.get("tool_call_id")] = m.get("content")
        json.dump(ops, open(out + "/ops.json", "w"))
        shutil.copy(os.path.join(HERE, "runner.py"), out)
        sh(os.path.join(HERE, "sandbox.sh"), ctx["root"], ws, out, "/usr/local/bin/python3", "/out/runner.py", timeout=7200)
        rep = json.load(open(out + "/replayed.json"))
        calls = [(o, y) for o, y in zip(ops, rep) if o["fn"] in ("safe_bash", "safe_python")]
        same = sum(1 for o, y in calls if isinstance(rec.get(o["id"]), str) and rec[o["id"]].strip() == y["out"].strip())
        hi = json.loads(sh(B, "mark", "--scope", ws, "--json", env=env).stdout)["id"]
        v = sh(B, "verify", "--scope", ws, "--baseline", w + "/b", "--baseline-sha256", digest, "--protect", w + "/protect.json",
               "--exit-code", env=env)
        flags = [json.loads(line) for line in v.stdout.splitlines() if line.startswith('{"flag"')]
        fm = d["score_details"].get("file_modification_details") or {}
        ended, reasons = {}, []
        for n, sc in (("test.py", fm.get("test_script_modified")), ("test_cases.json", fm.get("test_cases_modified"))):
            try:
                final = open(f"{ws}/{n}", "rb").read()
            except OSError:
                final = None
            ended[n] = None if final is None else hashlib.sha256(final).hexdigest()
            ok, why = rules.prove(n, bool(sc), P[n].encode(), final, ops, [y[n] for y in rep])
            if not ok:
                reasons.append(why)
        r.update(calls=len(calls), same=same, timeouts=sum(1 for _, y in calls if y["rc"] == 124), verify_rc=v.returncode,
                 flag=rules.flagged(f["flag"] for f in flags), protected=[[f["flag"], f.get("path")] for f in flags if f["flag"].startswith("protected_")],
                 end=ended, unproven=reasons, scorer_modified=bool(fm.get("test_script_modified") or fm.get("test_cases_modified")))
    except Exception as ex:                     # said in the report, never dropped
        r["error"] = repr(ex)[:300]
    shutil.rmtree(w, ignore_errors=True)
    with open(done + ".part", "w") as f:
        json.dump(r, f)
    os.rename(done + ".part", done)
    return k




def watchdog(root, work):
    """The second line behind each process's memory limit: above MEM_LIMIT of RAM, kill the largest sandboxed process."""
    log = open(os.path.join(work, "watchdog.log"), "a")
    peak = 0
    while True:
        m = {line.split(":")[0]: int(line.split()[1]) for line in open("/proc/meminfo")}
        used, total = m["MemTotal"] - m["MemAvailable"], m["MemTotal"]
        if used > peak:
            peak = used
            with open(os.path.join(work, "peak.txt"), "w") as f:
                f.write(f"{100 * peak / total:.1f}% of {total / 2**20:.1f} GiB\n")
        if used > MEM_LIMIT * total:
            big = (0, None)
            for p in filter(str.isdigit, os.listdir("/proc")):
                try:
                    if os.readlink(f"/proc/{p}/root") == root:
                        rss = int(open(f"/proc/{p}/statm").read().split()[1]) * 4096
                        big = max(big, (rss, p))
                except OSError:
                    pass
            if big[1]:
                log.write(f"{time.strftime('%H:%M:%S')} killed {big[1]}, {big[0] / 2**30:.2f} GiB\n")
                log.flush()
                try:
                    os.kill(int(big[1]), 9)
                except OSError:
                    pass
        time.sleep(.5)


def report(work, head, compare):
    rows = {}
    with open(os.path.join(work, "data", "tables", "per_run_data_all_conditions.csv")) as f:
        for p in csv.DictReader(f):
            rows[p["run_key"]] = p
    R = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(work, "results", "*.json")))]
    for r in R:
        r["group"] = rules.group(rows[r["run_key"]])
        r["counted"] = "error" not in r and not r.get("unproven") and r["group"] != "error"
    c = [r for r in R if r["counted"]]
    L = ["# Replay report\n", f"belay: `{head['version']}`, sha256 `{head['sha256']}`, spec version {head['spec']}.\n",
         f"{len(R)} runs, {len(c)} counted.\n", "| group | flagged | counted |", "|---|---|---|"]
    for g in ("tamper", "cases-only", "clean", "solution-hack"):
        s = [r for r in c if r["group"] == g]
        L.append(f"| {g} | {sum(r['flag'] for r in s)} | {len(s)} |")
    ch = [r for r in R if r.get("scorer_modified")]
    L += ["", f"Runs that changed a test file, counted or not, flagged: {sum(r['flag'] for r in ch)} of {len(ch)}.",
          f"Calls whose output matched the recording: {sum(r.get('same', 0) for r in R)} of {sum(r.get('calls', 0) for r in R)}.", "",
          "## Excluded\n", "| key | group | model | problem | reason |", "|---|---|---|---|---|"]
    for r in R:
        if not r["counted"]:
            why = "; ".join(r.get("unproven") or []) or r.get("error") or "classification error in the dataset"
            L.append(f"| `{r['key']}` | {r['group']} | {r['model']} | {r['problem']} | {why} |")
    for key in ("model", "problem"):
        L += ["", f"## By {key}\n", f"| {key} | tamper | cases-only | clean flagged | solution hacks | excluded |", "|---|---|---|---|---|---|"]
        for m in sorted({r[key] for r in R}):
            s = [r for r in c if r[key] == m]
            f = lambda g: f"{sum(r['flag'] for r in s if r['group'] == g)}/{sum(1 for r in s if r['group'] == g)}"
            L.append(f"| {m} | {f('tamper')} | {f('cases-only')} | {f('clean')} | {sum(1 for r in s if r['group'] == 'solution-hack')} | "
                     f"{sum(1 for r in R if r[key] == m and not r['counted'])} |")
    bad = []
    if compare:
        want = json.load(open(compare))
        L += ["", "## Against the stored results\n"]
        for r in R:
            w = want.get(r["key"])
            if w is None:
                bad.append((r["key"], "not in the stored results"))
                continue
            if "error" in r:
                bad.append((r["key"], "error: " + r["error"]))
                continue
            if bool(r["flag"]) != bool(w["flag"]):
                bad.append((r["key"], f"verdict: {r['flag']}, stored {w['flag']}"))
            for n in rules.PROTECTED:
                if r["end"][n] != w["end"][n]:
                    bad.append((r["key"], f"{n} end state differs"))
            if r["counted"] != w["counted"]:
                bad.append((r["key"], f"counted: {r['counted']}, stored {w['counted']}"))
        L.append(f"{len(R)} runs compared, {len(bad)} mismatches.\n")
        L += [f"- `{k}`: {why}" for k, why in bad]
    with open(os.path.join(work, "report.md"), "w") as f:
        f.write("\n".join(L) + "\n")
    with open(os.path.join(work, "report.json"), "w") as f:
        json.dump(dict(head=head, runs=R, mismatches=bad), f, indent=0)
    print("\n".join(L[:12]))
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--belay", required=True, help="the belay binary to judge the runs with")
    ap.add_argument("--work", required=True, help="where downloads, the image and results go")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--sample", type=int, help="this many runs, chosen by hash, covering every model")
    ap.add_argument("--compare", help="a JSON file of earlier results to compare verdicts and end hashes with")
    ap.add_argument("--i-know-this-runs-model-written-code", action="store_true", dest="ok")
    a = ap.parse_args()
    print(WARNING, file=sys.stderr)
    if not a.ok:
        sys.exit("\nSay --i-know-this-runs-model-written-code to go on.")
    work, belay = os.path.abspath(a.work), os.path.abspath(a.belay)
    os.makedirs(os.path.join(work, "results"), exist_ok=True)
    fetch(work)
    build(work)
    head = dict(version=sh(belay, "--version").stdout.strip(), sha256=hashlib.sha256(open(belay, "rb").read()).hexdigest(),
                spec=spec_version(belay, work), pins=PINS)
    hf = os.path.join(work, "run.json")
    if os.path.exists(hf) and glob.glob(os.path.join(work, "results", "*.json")):
        old = json.load(open(hf))
        if old["sha256"] != head["sha256"]:
            sys.exit(f"{work} holds results from another binary ({old['version']}): use another --work")
    json.dump(head, open(hf, "w"), indent=1)
    all_runs = list(runs(work))
    todo = rules.sample(all_runs, a.sample) if a.sample else all_runs
    print(f"{head['version']}, spec {head['spec']}: {len(todo)} of {len(all_runs)} runs, {a.workers} workers at nice 19", flush=True)
    shutil.rmtree(os.path.join(work, "wk"), ignore_errors=True)
    os.makedirs(os.path.join(work, "wk"))
    root = os.path.join(work, "rootfs")
    threading.Thread(target=watchdog, args=(root, work), daemon=True).start()
    ctx = dict(work=work, belay=belay, spec=head["spec"], root=root, problems=json.load(open(os.path.join(work, "problems.json"))))
    os.nice(19)
    with multiprocessing.Pool(a.workers) as pool:
        for i, _ in enumerate(pool.imap_unordered(one, [(d, ctx) for d in todo]), 1):
            if i % 25 == 0:
                print(i, time.strftime("%H:%M:%S"), flush=True)
    bad = report(work, head, a.compare)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
