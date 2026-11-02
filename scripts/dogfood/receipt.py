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
import re
import shutil
import subprocess
import sys
import time

TESTS = ("test/", "tests/", "spec/", "__tests__/")
BUILD = ("build/", "bin/")
GIT = re.compile(r"^(.*?)\.git(/|$)")      # a repository's bookkeeping, at any depth
LABEL = 60                                  # a call's label in a heading and the Stop line
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


def calls_of(events, d=None, sid=None):
    """{tool_use_id: {tool, summary, full, agent, pre, post}} -- post is the
    closing checkpoint: the call's own, or the next stop's for one
    cancelled; `full` the whole command, from the hook's file for the call
    in `d`, when there is one."""
    calls, stops = {}, sorted(e["cp"] for e in events if e.get("event") == "stop" and e.get("cp"))
    for e in events:
        tid = e.get("tool_use_id")
        if not tid or e.get("cp") is None:
            continue
        if e.get("event") == "background_end":
            continue
        c = calls.setdefault(tid, {"tool": e.get("tool"), "summary": e.get("summary"),
                                   "agent": e.get("agent"), "pre": None, "post": None,
                                   "ms": 0.0, "cancelled": False, "background": None,
                                   "background_end": None})
        if e["event"] == "pre":
            c["pre"] = e["cp"]
        elif e["event"] == "post":
            c["post"] = e["cp"]
            c["background"] = e.get("background")
        c["ms"] += (e["t1"] - e["t0"]) / 1e6
    # A command left running in the background ends at the first hook that
    # saw it gone (belay-dogfood); never seen gone, it runs to the end.
    ends = {}
    for e in events:
        if e.get("event") == "background_end" and e.get("cp") is not None:
            k = e.get("tool_use_id", "")
            ends[k] = min(ends.get(k, e["cp"]), e["cp"])
    for tid, c in calls.items():
        c["background_end"] = ends.get(re.sub(r"[^A-Za-z0-9_-]", "", tid))
    for tid, c in calls.items():
        c["full"] = None
        if d is not None:
            try:
                with open(os.path.join(d, f"{sid}.calls", re.sub(r"[^A-Za-z0-9_-]", "", tid)),
                          encoding="utf-8", errors="replace") as f:
                    c["full"] = f.read()
            except OSError:
                pass
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


def printable(s):
    return "".join(ch if ch.isprintable() else "?" for ch in s)


def privileged(belay, scope, a, b):
    """The paths belay's own receipt lists under "privilege" between
    checkpoints a and b: a file added setuid or with caps, which diff.v1's
    record of an added or removed path does not carry (the receipt reads the
    manifests). Asked only where a directory may fold (decision 116)."""
    p = subprocess.run([belay, "diff", "--scope", scope, "--since", str(a), "--to", str(b)],
                       capture_output=True, text=True)
    out, inside = set(), False
    for line in p.stdout.splitlines():
        if line == "privilege":
            inside = True
        elif inside and line.startswith("  ") and not line.startswith("      "):
            out.add(line[4:].split("   ")[0])
        elif inside and not line.startswith("  "):
            inside = False
    return out


def label(c):
    """The call as a heading and the Stop line name it, read in one glance:
    cut to LABEL characters, with an ellipsis when anything is left out --
    the rest of the line, or other lines (the receipt's detail has them)."""
    who = "" if not c["agent"] else c["agent"] + " "
    first = printable((c["summary"] or "").replace("\n", " "))
    text = f"{who}{c['tool']}: {first}" if first else f"{who}{c['tool']}"
    if len(text) > LABEL:
        return text[:LABEL - 1] + "\u2026"
    return text + "\u2026" if cut(c) else text


def cut(c):
    """Whether the heading leaves part of the call's command out."""
    who = "" if not c["agent"] else c["agent"] + " "
    first = printable((c["summary"] or "").replace("\n", " "))
    text = f"{who}{c['tool']}: {first}" if first else f"{who}{c['tool']}"
    return len(text) > LABEL or bool(c.get("full")) and c["full"] != (c["summary"] or "")


def full_label(c):
    """The whole command, as the hook kept it (its first line otherwise)."""
    who = "" if not c["agent"] else c["agent"] + " "
    s = c.get("full") or c["summary"] or ""
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


def sections(events, belay, scope, lo, hi, persistent=None, d=None, sid=None):
    """[(heading, records)] for the checkpoints in [lo, hi], and the errors.
    `persistent`: (path, reasons) unknown in every interval of the session so
    far, or None at its first turn; returned narrowed to this turn's."""
    calls = calls_of(events, d, sid)
    cps = sorted({e["cp"] for e in events if e.get("cp") is not None and lo <= e["cp"] <= hi})
    # An error has no checkpoint: it is this turn's when it was logged after
    # the stop or start that opened the turn and before the one that ends it
    # (one failure used to be said by every later turn).
    opened = max((i for i, e in enumerate(events) if e.get("cp") == lo and e.get("event") in ("stop", "start")),
                 default=-1)
    closed = min((i for i, e in enumerate(events) if e.get("cp") == hi and e.get("event") in ("stop", "end")),
                 default=len(events))
    groups, errors = {}, [e for i, e in enumerate(events) if e.get("event") == "error" and opened < i < closed]
    seen, intervals = {}, 0
    per = []
    for a, b in zip(cps, cps[1:]):
        try:
            recs = diff(belay, scope, a, b)
        except RuntimeError as err:
            errors.append({"event": "error", "message": f"checkpoints {a} -> {b}: {err}"})
            continue
        intervals += 1
        if any("event" not in r and r.get("type") == "dir" and r["outcome"] in ("added", "removed") for r in recs):
            priv = privileged(belay, scope, a, b)
            for r in recs:
                if "event" not in r and path_of(r) in priv:
                    r["receipt_privilege"] = True
        per.append((a, b, recs))
        for r in recs:
            if "event" not in r and r["outcome"] == "unknown":
                key = (path_of(r), tuple(r.get("unknown", [])))
                seen[key] = seen.get(key, 0) + 1
    # An entry unknown in every interval -- an unreadable directory, say,
    # which is never reported unchanged -- is said once, not once per
    # interval (first real receipt, 2026-11-02: tmp/work/work 41 times).
    here = {k for k, n in seen.items() if n == intervals}
    throughout = here if persistent is None else here & persistent
    for a, b, recs in per:
        recs = [r for r in recs if "event" in r or r["outcome"] != "unknown"
                or (path_of(r), tuple(r.get("unknown", []))) not in throughout]
        if not recs:
            continue
        open_ = tuple(sorted(t for t, c in calls.items()
                             if c["pre"] is not None and c["post"] is not None and c["pre"] <= a and c["post"] >= b))
        # Decision 111: while a command runs in the background, what lands
        # may be its writing -- said so, never put on the open call alone.
        running = tuple(sorted(t for t, c in calls.items()
                               if c["background"] and c["post"] is not None and c["post"] <= a
                               and (c["background_end"] is None or c["background_end"] >= b)))
        groups.setdefault((open_, running), []).extend(recs)
    outside = {path_of(r) for r in groups.get(((), ()), []) if "event" not in r}
    out = []
    if throughout:
        out.append(("unknown throughout the session (never reported unchanged)",
                    [{"path": p, "outcome": "unknown", "unknown": list(u)} for p, u in sorted(throughout)], set(), []))
    for (key, running), recs in groups.items():
        # One line per path in a section: its last record (several intervals
        # of one call, or of the time between calls, touch the same path).
        last = {}
        for r in recs:
            last[("e", len(last)) if "event" in r else path_of(r)] = r
        recs = list(last.values())
        if running:
            head = "a background command may have written these: " + "; ".join(label(calls[t]) for t in running)
            if key:
                head += "   (open at the time: " + "; ".join(label(calls[t]) for t in key) + ")"
        elif not key:
            head = "between tool calls"
        elif len(key) == 1:
            c = calls[key[0]]
            head = label(c) + ("   (cancelled)" if c["cancelled"] else "")
        else:
            head = "during these concurrent calls: " + "; ".join(label(calls[t]) for t in key)
        out.append((head, recs, outside if key or running else set(), [calls[t] for t in running + key]))
    return out, errors, calls, throughout


def folded_git(r):
    """The repository a record's path is git's bookkeeping of ("" for the
    scope's own), or None: what the git interpreter reports -- refs, HEAD,
    hooks, reflog moves, the index (a finding of a git_ kind) -- and every
    path under hooks/ stay visible, as do privilege changes; the rest under a
    .git directory folds to one line (decision 105)."""
    if "event" in r:
        return None
    m = GIT.match(path_of(r))
    if not m or (m.group(2) == "" and r.get("type") != "dir"):     # a .git file points elsewhere
        return None
    if path_of(r)[m.end():].startswith("hooks/") or path_of(r)[m.end():] == "hooks":
        return None
    if any(f.get("kind", "").startswith("git_") for f in r.get("findings") or []):
        return None
    ch = set(r.get("changed") or [])
    b, a = r.get("before", {}), r.get("after", {})
    if ch & {"caps", "iflags"} or "mode" in ch and (b.get("mode", 0) ^ a.get("mode", 0)) & 0o7000:
        return None
    return m.group(1)


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
    counted = [r for h, recs, _, _ in secs if not h.startswith("unknown throughout")   # the same each time
               for r in recs if "event" not in r]
    n = len(counted)
    paths = len({path_of(r) for r in counted})
    bg = sum(len(recs) for h, recs, _, _ in secs if h == "between tool calls")
    lines.append(f"belay receipt  {scope}   {ver} (sha256 {sha}...)")
    head = "  " + changed_line(paths, n)
    if bg:
        head += f" · background writers were active ({bg} change{'s' if bg != 1 else ''} outside any tool call)"
    lines.append(head)
    for e in errors:
        lines.append("  receipt incomplete: " + printable(e.get("message", "")))
    detail = []
    for head, recs, outside, calls in secs:
        refs = []
        for c in calls:
            if cut(c):
                detail.append(c)
                refs.append(f"[{len(detail)}]")
        lines.append("")
        lines.append(head + ("   " + " ".join(refs) if refs else ""))
        build = [r for r in recs if "event" not in r and path_of(r).startswith(BUILD)]
        git = {}
        shown = []
        for r in recs:
            if r in build:
                continue
            repo = folded_git(r)
            if repo is not None:
                git[repo] = git.get(repo, 0) + 1
                continue
            shown.append(r)
        roots, under = folded_dirs(shown)
        for r in shown:
            if id(r) in under:
                continue
            if id(r) in roots and roots[id(r)]:
                k = roots[id(r)]
                lines.append(f"  {SYM[r['outcome']]} {printable(path_of(r))}/ and {k:,} "
                             f"entr{'ies' if k != 1 else 'y'} below it")
                continue
            lines.append(line_of(r, outside))
        if build:
            lines.append(f"  build output: {len(build)} change{'s' if len(build) != 1 else ''} under build/, bin/")
        for repo, k in git.items():
            lines.append(f"  git bookkeeping: {k} change{'s' if k != 1 else ''} under {repo}.git/")
    if detail:
        lines.append("")
        lines.append("the calls in full")
        for k, c in enumerate(detail, 1):
            text = full_label(c).split("\n")
            lines.append(f"  [{k}] " + printable(text[0]))
            lines.extend("      " + printable(t) for t in text[1:])
    return "\n".join(lines) + "\n", n, paths


def changed_line(paths, n):
    """The headline (decision 117): paths, and changes across calls when a
    path changed under more than one call."""
    s = f"{paths:,} path{'s' if paths != 1 else ''} changed"
    return s + (f" ({n:,} changes across calls)" if n != paths else "")


def kept(r):
    """What a folded directory never hides (decision 116): a privilege
    change, a test file, a finding an interpreter other than text's made."""
    p = path_of(r)
    if r.get("receipt_privilege") or set(r.get("changed") or []) & {"caps", "iflags"}:
        return True
    if p.startswith(TESTS) or "/test_" in "/" + p or "_test." in p or ".test." in p or ".spec." in p:
        return True
    return any(not f.get("kind", "").startswith(("text_", "content_unavailable"))
               for f in r.get("findings") or [])


def folded_dirs(recs):
    """A directory added or removed whole, and the entries below it with the
    same outcome, in one line: {id(root): entries folded}, {id(folded)}."""
    roots, under = {}, set()
    dirs = sorted((r for r in recs if "event" not in r and r.get("type") == "dir"
                   and r["outcome"] in ("added", "removed")), key=lambda r: len(path_of(r)))
    for d in dirs:
        if id(d) in under:
            continue
        pre = path_of(d) + "/"
        roots[id(d)] = 0
        for r in recs:
            if "event" not in r and r["outcome"] == d["outcome"] and path_of(r).startswith(pre) and not kept(r):
                if id(r) not in under:
                    under.add(id(r))
                    roots[id(d)] += 1
    return roots, under


def interesting(secs):
    why = set()
    for _, recs, _, _ in secs:
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
            ch = set(r.get("changed") or [])
            if ch & {"caps", "iflags"} or r.get("receipt_privilege"):
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


def turn(events, belay, scope, d, sid, lo, hi):
    """The turn [lo, hi]: its receipt and JSON written; (text, n, paths, path, errors, heads)."""
    pf = os.path.join(d, f"{sid}.persistent.json")
    try:
        with open(pf) as f:
            persistent = {(p, tuple(u)) for p, u in json.load(f)}
    except (OSError, ValueError):
        persistent = None
    secs, errors, _, throughout = sections(events, belay, scope, lo, hi, persistent, d, sid)
    with open(pf, "w") as f:
        json.dump([[p, list(u)] for p, u in sorted(throughout)], f)
    text, n, paths = render(scope, belay, secs, errors)
    path = os.path.join(d, f"{sid}.turn-{hi}.txt")
    with open(path, "w") as f:
        f.write(text)
    with open(os.path.join(d, f"{sid}.turn-{hi}.json"), "w") as f:
        json.dump({"lo": lo, "hi": hi, "changes": n, "paths": paths, "interesting": interesting(secs),
                   "sections": [{"section": h, "calls": [full_label(c) for c in cs], "records": r}
                                for h, r, _, cs in secs]}, f)
    heads = [h for h, _, _, _ in secs if not h.startswith("unknown throughout")][:3]
    return text, n, paths, path, errors, heads


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
    stops = [e["cp"] for e in events if e.get("event") == "stop" and e.get("cp") is not None]
    starts = [e["cp"] for e in events if e.get("event") == "start" and e.get("cp") is not None]
    if mode == "turn":
        hi = stops[-1] if stops else max(cps)
        earlier = stops[:-1] + starts
        lo = max([s for s in earlier if s < hi], default=min(cps))
        _, n, paths, path, errors, heads = turn(events, belay, scope, d, sid, lo, hi)
        if n or errors:
            msg = "belay: " + changed_line(paths, n).replace(" changed", " changed this turn", 1)
            if heads:
                msg += " (" + "; ".join(heads) + ")"
            if errors:
                msg += f"; receipt incomplete ({len(errors)} error{'s' if len(errors) != 1 else ''})"
            print(msg + f" -- {path}")             # the hook makes the Stop's JSON
        return
    # The session: what happened after the last stop as a last turn, then
    # every turn's receipt in order -- nothing diffed twice, so SessionEnd
    # stays within its time budget however long the session was.
    notes = sys.argv[6]
    last = max(stops + starts, default=min(cps))
    if max(cps) > last:
        turn(events, belay, scope, d, sid, last, max(cps))
    turns = []
    for name in os.listdir(d):
        if name.startswith(f"{sid}.turn-") and name.endswith(".json"):
            with open(os.path.join(d, name)) as f:
                turns.append(json.load(f))
    turns.sort(key=lambda t: t["hi"])
    texts, why = [], set()
    for t in turns:
        with open(os.path.join(d, f"{sid}.turn-{t['hi']}.txt")) as f:
            texts.append(f"--- checkpoints {t['lo']} -> {t['hi']}\n" + f.read())
        why |= set(t["interesting"])
    text = "".join(texts)
    with open(os.path.join(d, f"{sid}.receipt.txt"), "w") as f:
        f.write(text)
    if why:
        os.makedirs(notes, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d", time.gmtime())
        with open(os.path.join(notes, f"{stamp}-{sid}.md"), "w") as f:
            f.write(f"# Receipt {stamp} {sid}\n\nKept because: {', '.join(sorted(why))}.\n\n```\n{text}```\n")


if __name__ == "__main__":
    main()
