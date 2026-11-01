"""The M1.5 receipt, from a session's hook log (belay-dogfood).

    receipt.py turn    LOG BELAY SCOPE DIR          the turn just ended: written
                                                    to DIR, one line on stdout (a
                                                    hook's systemMessage) when
                                                    something changed in it
    receipt.py session LOG BELAY SCOPE DIR NOTES    the whole session: written to
                                                    DIR, copied to NOTES when
                                                    interesting
    receipt.py latency LOG...                       per writing tool call: the
                                                    hooks' time, p50 and p95

Attribution (NOTES design m1.5-structure, section 4): the session's
checkpoints, in id order, cut time into intervals; each interval's changes go
to the calls open across it -- one call, several concurrent ones, or none
("between tool calls": background writers). A call opens at its pre
checkpoint and closes at its post one, or, cancelled, at the next stop.
"""
import json
import os
import shutil
import subprocess
import sys
import time

TESTS = ("test/", "tests/", "spec/", "__tests__/")
BUILD = ("build/", "bin/")
SYM = {"added": "A", "removed": "D", "modified": "M", "type_changed": "T",
       "metadata_only": "~", "unknown": "?"}


def load(path):
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except ValueError:
                pass
    return events


def calls_of(events):
    """{tool_use_id: {tool, summary, agent, pre, post}} -- post is the closing
    checkpoint: the call's own, or the next stop's for one cancelled."""
    calls, stops = {}, sorted(e["cp"] for e in events if e.get("event") == "stop" and e.get("cp"))
    for e in events:
        tid = e.get("tool_use_id")
        if not tid or e.get("cp") is None:
            continue
        c = calls.setdefault(tid, {"tool": e.get("tool"), "summary": e.get("summary"),
                                   "agent": e.get("agent"), "pre": None, "post": None,
                                   "ms": 0.0, "cancelled": False})
        if e["event"] == "pre":
            c["pre"] = e["cp"]
        elif e["event"] == "post":
            c["post"] = e["cp"]
        c["ms"] += (e["t1"] - e["t0"]) / 1e6
    for c in calls.values():
        if c["pre"] is not None and c["post"] is None:
            later = [s for s in stops if s > c["pre"]]
            c["post"] = later[0] if later else None
            c["cancelled"] = True
    return calls


def diff(belay, scope, a, b):
    """diff.v1 records and events between checkpoints a and b."""
    p = subprocess.run([belay, "diff", "--scope", scope, "--since", str(a), "--to", str(b), "--json"],
                       capture_output=True, text=True)
    if p.returncode not in (0, 1):
        raise RuntimeError(p.stderr.strip()[:300])
    out = []
    for line in p.stdout.splitlines():
        o = json.loads(line)
        if "belay_diff" in o or "belay_diff_end" in o:
            continue
        out.append(o)
    return out


def label(c):
    who = "" if not c["agent"] else c["agent"] + " "
    s = (c["summary"] or "").replace("\n", " ")
    s = "".join(ch if ch.isprintable() else "?" for ch in s)
    return f"{who}{c['tool']}: {s}" if s else f"{who}{c['tool']}"


def path_of(r):
    return r.get("path") or ("(base64) " + r.get("path_b64", ""))


def line_of(r, outside):
    if "event" in r:
        return f"  {r.get('interp', '')} {r.get('text', '')}"
    s = f"  {SYM.get(r['outcome'], '?')} {path_of(r)}"
    if r["outcome"] == "unknown":
        s += "   unknown: " + ", ".join(r.get("unknown", []))
    elif r.get("findings"):
        s += "   " + r["findings"][0].get("text", "")
    elif r.get("changed"):
        s += "   " + ", ".join(r["changed"])
    if path_of(r) in outside:
        s += "   (also changed outside tool calls)"
    return "".join(ch if ch.isprintable() else "?" for ch in s)


def sections(events, belay, scope, lo, hi):
    """[(heading, records)] for the checkpoints in [lo, hi], and the errors."""
    calls = calls_of(events)
    cps = sorted({e["cp"] for e in events if e.get("cp") is not None and lo <= e["cp"] <= hi})
    groups, errors = {}, [e for e in events if e.get("event") == "error"]
    for a, b in zip(cps, cps[1:]):
        try:
            recs = diff(belay, scope, a, b)
        except RuntimeError as err:
            errors.append({"event": "error", "message": f"checkpoints {a} -> {b}: {err}"})
            continue
        if not recs:
            continue
        open_ = tuple(sorted(t for t, c in calls.items()
                             if c["pre"] is not None and c["post"] is not None and c["pre"] <= a and c["post"] >= b))
        groups.setdefault(open_, []).extend(recs)
    outside = {path_of(r) for r in groups.get((), []) if "event" not in r}
    out = []
    for key, recs in groups.items():
        if not key:
            head = "between tool calls"
        elif len(key) == 1:
            c = calls[key[0]]
            head = label(c) + ("   (cancelled)" if c["cancelled"] else "")
        else:
            head = "during these concurrent calls: " + "; ".join(label(calls[t]) for t in key)
        out.append((head, recs, outside if key else set()))
    return out, errors, calls


def render(scope, belay, secs, errors):
    lines = []
    sha = ""
    try:
        with open(belay, "rb") as f:
            import hashlib
            sha = hashlib.sha256(f.read()).hexdigest()[:12]
    except OSError:
        pass
    ver = subprocess.run([belay, "--version"], capture_output=True, text=True).stdout.strip()
    n = sum(len([r for r in recs if "event" not in r]) for _, recs, _ in secs)
    bg = sum(len(recs) for h, recs, _ in secs if h == "between tool calls")
    lines.append(f"belay receipt  {scope}   {ver} (sha256 {sha}...)")
    head = f"  {n} change{'s' if n != 1 else ''}"
    if bg:
        head += f" · background writers were active ({bg} change{'s' if bg != 1 else ''} outside any tool call)"
    lines.append(head)
    for e in errors:
        lines.append("  receipt incomplete: " + "".join(ch if ch.isprintable() else "?" for ch in e.get("message", "")))
    for head, recs, outside in secs:
        lines.append("")
        lines.append(head)
        build = [r for r in recs if "event" not in r and path_of(r).startswith(BUILD)]
        for r in recs:
            if r in build:
                continue
            lines.append(line_of(r, outside))
        if build:
            lines.append(f"  build output: {len(build)} change{'s' if len(build) != 1 else ''} under build/, bin/")
    return "\n".join(lines) + "\n", n


def interesting(secs):
    why = set()
    for _, recs, _ in secs:
        for r in recs:
            if "event" in r:
                why.add("events")
                continue
            p = path_of(r)
            if p.startswith("test/expect/"):
                why.add("a pin changed")
            if (p.startswith(TESTS) or "/test_" in "/" + p or "_test." in p or ".test." in p or ".spec." in p) \
                    and r["outcome"] in ("modified", "removed", "type_changed"):
                why.add("a test file changed")
            ch = set(r.get("changed", []))
            if ch & {"caps", "iflags"}:
                why.add("privilege")
            b, a = r.get("before", {}), r.get("after", {})
            if "mode" in ch and (b.get("mode", 0) ^ a.get("mode", 0)) & 0o7000:
                why.add("privilege")
            if r["outcome"] in ("type_changed",) and r.get("type") == "lnk":
                why.add("a file became a symlink")
    return sorted(why)


def latency(paths):
    per = []
    for p in paths:
        for c in calls_of(load(p)).values():
            if c["pre"] is not None and not c["cancelled"]:
                per.append(c["ms"])
    if not per:
        print("no writing tool calls")
        return
    per.sort()
    q = lambda f: per[min(len(per) - 1, int(f * len(per)))]
    print(f"{len(per)} writing tool calls: hooks' time per call p50 {q(0.5):.1f} ms, p95 {q(0.95):.1f} ms, "
          f"max {per[-1]:.1f} ms")


def main():
    mode = sys.argv[1]
    if mode == "latency":
        latency(sys.argv[2:])
        return
    log, belay, scope, d = sys.argv[2:6]
    events = load(log)
    sid = os.path.basename(log)[:-len(".jsonl")]
    cps = [e["cp"] for e in events if e.get("cp") is not None]
    if not cps:
        return
    if mode == "turn":
        stops = [e["cp"] for e in events if e.get("event") == "stop" and e.get("cp") is not None]
        hi = stops[-1] if stops else max(cps)
        earlier = [s for s in stops[:-1]] + [e["cp"] for e in events if e.get("event") == "start" and e.get("cp")]
        lo = max([s for s in earlier if s < hi], default=min(cps))
        secs, errors, _ = sections(events, belay, scope, lo, hi)
        text, n = render(scope, belay, secs, errors)
        path = os.path.join(d, f"{sid}.turn-{hi}.txt")
        with open(path, "w") as f:
            f.write(text)
        if n or errors:
            heads = [h for h, _, _ in secs][:3]
            msg = f"belay: {n} change{'s' if n != 1 else ''} this turn"
            if heads:
                msg += " (" + "; ".join(heads) + ")"
            if errors:
                msg += f"; receipt incomplete ({len(errors)} error{'s' if len(errors) != 1 else ''})"
            print(json.dumps({"systemMessage": msg + f" -- {path}"}))
        return
    notes = sys.argv[6]
    secs, errors, calls = sections(events, belay, scope, min(cps), max(cps))
    text, n = render(scope, belay, secs, errors)
    path = os.path.join(d, f"{sid}.receipt.txt")
    with open(path, "w") as f:
        f.write(text)
    with open(os.path.join(d, f"{sid}.receipt.json"), "w") as f:
        json.dump([{"section": h, "records": recs} for h, recs, _ in secs], f)
    why = interesting(secs)
    if why:
        os.makedirs(notes, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d", time.gmtime())
        with open(os.path.join(notes, f"{stamp}-{sid}.md"), "w") as f:
            f.write(f"# Receipt {stamp} {sid}\n\nKept because: {', '.join(why)}.\n\n```\n{text}```\n")


if __name__ == "__main__":
    main()
