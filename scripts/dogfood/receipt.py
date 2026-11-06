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
checkpoint and closes at its post one. Claude Code sends no post for a call
that never ran -- denied, or blocked by a hook -- but lists it in the batch
it ends (PostToolBatch): such a call closes where it opened, having changed
nothing. Nor for a call the user interrupted, and no batch either; the next
prompt (UserPromptSubmit) or stop proves it gone: it closes there
(2026-11-04, checked against Claude Code 2.1.318).
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
CALL_LINES = 10                             # a command's lines in "the calls in full" (decision 128)
LISTED = 4                                  # the items a summary line names before "and N more"
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
    closing checkpoint: the call's own; its pre for one that never ran (a
    batch lists it, no post came); else, interrupted, the next prompt's or
    stop's. `full` the whole command, from the hook's file for the call in
    `d`, when there is one."""
    calls = {}
    stops = sorted(e["cp"] for e in events if e.get("event") in ("stop", "prompt") and e.get("cp"))
    batched = {t for e in events if e.get("event") == "batch" for t in e.get("tool_use_ids") or []}
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
    for tid, c in calls.items():
        if c["pre"] is not None and c["post"] is None:
            if re.sub(r"[^A-Za-z0-9_-]", "", tid) in batched:     # never ran: changed nothing
                c["post"], c["not_run"] = c["pre"], True
            else:
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


GIT_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR",
           "GIT_NAMESPACE", "GIT_ALTERNATE_OBJECT_DIRECTORIES")
PATHSPEC = re.compile(rb"pathspec '(.*)' (?:is beyond a symbolic link|is in submodule)", re.I)


def _git(args, cwd, inp=None):
    """git with nothing of the caller's repository selection, and no write
    a read could make (optional locks off, no fsmonitor)."""
    env = {k: v for k, v in os.environ.items() if k not in GIT_ENV}
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return subprocess.run(["git", "-c", "core.fsmonitor=false", *args], cwd=cwd, input=inp,
                          capture_output=True, env=env, timeout=60)


def git_classes(scope, recs):
    """Each record's path outside any .git: "tracked" (in the index or in
    HEAD), "ignored" (git check-ignore) or "untracked" -- as the repository
    is now, not as it was when the records were captured. None when there
    is no git, the scope is in no repository, or git fails: the receipt
    then keeps path order (2026-11-04)."""
    paths = {}
    for r in recs:
        if "event" in r or "path" not in r or GIT.match(r["path"]):
            continue
        paths[r["path"]] = paths.get(r["path"], False) or r.get("type") == "dir" or r.get("type_before") == "dir"
    if not paths:
        return {}
    try:
        rp = _git(["rev-parse", "--show-toplevel", "--show-prefix"], scope)
        if rp.returncode != 0:
            return None
        top, prefix = (rp.stdout.split(b"\n") + [b"", b""])[:2]
        top = os.fsdecode(top)
        lf = _git(["ls-files", "-z"], top)
        if lf.returncode != 0:
            return None
        lt = _git(["ls-tree", "-r", "-z", "--name-only", "HEAD"], top)      # no commit yet: none
        tracked = set(lf.stdout.split(b"\0")) | (set(lt.stdout.split(b"\0")) if lt.returncode == 0 else set())
        tracked.discard(b"")
        holding = set()                                 # directories that hold a tracked file
        for t in tracked:
            i = t.rfind(b"/")
            while i > 0 and t[:i] not in holding:
                holding.add(t[:i])
                i = t.rfind(b"/", 0, i)
        out, ask = {}, {}
        links = {}
        for p, isdir in paths.items():
            full = prefix + os.fsencode(p)
            if full in tracked or full in holding:
                out[p] = "tracked"
                continue
            # git refuses a path below a symlink (the whole call fails): such a
            # path was removed with its directory, and is shown, not folded.
            d, below = os.path.dirname(p), False
            while d and not below:
                if d not in links:
                    links[d] = os.path.islink(os.path.join(scope, d))
                below, d = links[d], os.path.dirname(d)
            if below:
                out[p] = "untracked"
                continue
            ask[full + (b"/" if isdir else b"")] = p
        for _ in range(8):
            if not ask:
                break
            ci = _git(["check-ignore", "-z", "--stdin"], top, b"\0".join(ask) + b"\0")
            if ci.returncode in (0, 1):
                ign = set(ci.stdout.split(b"\0"))
                for f, p in ask.items():
                    out[p] = "ignored" if f in ign else "untracked"
                ask = {}
                break
            m = PATHSPEC.search(ci.stderr)
            bad = next((f for f in ask if m and f.rstrip(b"/") == m.group(1).rstrip(b"/")), None)
            if bad is None:
                return None
            out[ask.pop(bad)] = "untracked"
        return out if not ask else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def ignored_dirs(recs):
    """Git-ignored records counted by their top-level directory, in order:
    [("build/", 210), ("bin/", 2), ("", 1)] -- "" for files at the top."""
    n = {}
    for r in recs:
        p = path_of(r)
        k = p.split("/", 1)[0] + "/" if "/" in p or r.get("type") == "dir" else ""
        n[k] = n.get(k, 0) + 1
    return sorted(n.items())


def ignored_edit(r):
    """A record of an edit to a git-ignored file -- its text changed, or its
    type, not a directory's -- which is never folded: an ignored file an
    agent edits is often .env or local configuration (2026-11-04). A binary
    rewritten (build output) folds by directory, as added and removed
    ignored entries do."""
    if "event" in r or r.get("type") == "dir":
        return False
    return r.get("outcome") == "type_changed" or r.get("outcome") == "modified" and any(
        f.get("kind") in ("text_changed", "text_rewritten") for f in r.get("findings") or [])


def ignored_unknown(cls, r):
    """An unknown row under a git-ignored directory: it folds like a change
    (2026-11-05). A file at the top is under none and stays named, as privilege
    changes and entries marked writer_open do."""
    p = path_of(r)
    return (cls is not None and "event" not in r and r.get("outcome") == "unknown"
            and cls.get(p) == "ignored" and ("/" in p or r.get("type") == "dir") and not privilege_change(r)
            and "writer_open" not in (r.get("unknown") or []))


def unknown_fold(recs):
    """Unknown rows by top-level directory, each with its rows' first reasons,
    most first: [("build/", 214, "listing_incomplete 212, unstable 2")]."""
    n = {}
    for r in recs:
        k = path_of(r).split("/", 1)[0] + "/"
        why = (r.get("unknown") or ["unknown"])[0]
        n.setdefault(k, {}).setdefault(why, 0)
        n[k][why] += 1
    return [(k, sum(v.values()), ", ".join(f"{w} {c:,}" for w, c in sorted(v.items(), key=lambda x: (-x[1], x[0]))))
            for k, v in sorted(n.items())]


def in_place(recs):
    """Reflog moves that left their ref where it was (from == to: a reset
    or a stash in place, which can discard uncommitted work), counted by
    operation: "1 reset in place", "2 checkouts in place"."""
    ops = {}
    for r in recs:
        for f in r.get("findings") or []:
            if f.get("kind") == "git_reflog_move" and f.get("from") == f.get("to"):
                o = f.get("operation", "?")
                ops[o] = ops.get(o, 0) + 1
    return ", ".join(f"{k} {o}{'s' if k != 1 and ' ' not in o else ''} in place" for o, k in sorted(ops.items()))


def line_of(r, outside, ignored=False):
    if "event" in r:
        return f"  {r.get('interp', '')} {short_ids(printable(r.get('text', '')))}"
    s = f"  {SYM.get(r['outcome'], '?')} {path_of(r)}" + ("   (git-ignored)" if ignored else "")
    if r["outcome"] == "unknown":
        s += "   unknown: " + ", ".join(r.get("unknown", []))
    elif r.get("findings"):
        s += "   " + r["findings"][0].get("text", "")
    elif r.get("changed"):
        s += "   " + ", ".join(r["changed"])
    if path_of(r) in outside:
        s += "   (also changed outside tool calls)"
    return "".join(ch if ch.isprintable() else "?" for ch in s)


INACTIVE = "hooks were inactive; these changes are unattributed"


def failure_times(d):
    """When a hook failed or was inactive (belay-dogfood, install.sh): the
    first field of each line of `failing` (since the last Stop) and
    `failures.log` (before it), in nanoseconds."""
    out = []
    for name in ("failing", "failures.log"):
        try:
            with open(os.path.join(d, name), encoding="utf-8", errors="replace") as f:
                for line in f:
                    head = line.split("\t", 1)[0]
                    if head.isdigit():
                        out.append(int(head))
        except OSError:
            pass
    return sorted(out)


def sections(events, belay, scope, lo, hi, persistent=None, d=None, sid=None):
    """[(heading, records)] for the checkpoints in [lo, hi], and the errors.
    `persistent`: (path, reasons) unknown in every interval of the session so
    far, or None at its first turn; returned narrowed to this turn's."""
    calls = calls_of(events, d, sid)
    cps = sorted({e["cp"] for e in events if e.get("cp") is not None and lo <= e["cp"] <= hi})
    # Decision 122: an interval during which a hook failed or was inactive
    # holds calls the log never saw -- what changed then is unattributed,
    # never "between tool calls". Its window: from the first checkpoint's
    # mark to the end of the second's.
    when = {}
    for e in events:
        if e.get("cp") is not None and "t0" in e:
            t0, t1 = when.get(e["cp"], (e["t0"], e["t1"]))
            when[e["cp"]] = (min(t0, e["t0"]), max(t1, e["t1"]))
    failed = failure_times(d) if d is not None else []
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
        wa, wb = when.get(a, (None, None))[0], when.get(b, (None, None))[1]
        if wa is not None and wb is not None and any(wa <= t <= wb for t in failed):
            open_, running = ("inactive",), ()
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
        # Decision 185: a foreground call open heads its interval -- a
        # background command beside it is a note; only an interval with no
        # call open is the background command's (turn-3803: a CI watcher
        # that wrote nothing headed every real edit of the turn).
        if key == ("inactive",):
            head = INACTIVE
        elif not key and running:
            head = "a background command may have written these: " + "; ".join(label(calls[t]) for t in running)
        elif not key:
            head = "between tool calls"
        elif len(key) == 1:
            c = calls[key[0]]
            head = label(c) + ("   (cancelled)" if c["cancelled"] else "")
        else:
            head = "during these concurrent calls: " + "; ".join(label(calls[t]) for t in key)
        if key and key != ("inactive",) and running:
            head += BG_NOTE + "; ".join(label(calls[t]) for t in running) + ")"
        named = [] if key == ("inactive",) else [calls[t] for t in key + running]
        out.append((head, recs, outside if named else set(), named))
    return out, errors, calls, throughout


BG_NOTE = "   (a background command was also running: "


def compiled(p):
    """Compiled Python: a path under __pycache__/, or a .pyc (decision 134)."""
    return p.endswith(".pyc") or "/__pycache__/" in "/" + p or p.endswith("__pycache__")


def folded_git(r, events=False):
    """The repository a record's path is git's bookkeeping of ("" for the
    scope's own), or None: what the git interpreter reports -- refs, HEAD,
    hooks, reflog moves (a finding of a git_ kind) -- and every path under
    hooks/ stay visible, as do privilege changes; the rest under a .git
    directory folds to one line (decision 105), the index's "index changed"
    with it (2026-11-04). With `events` -- git's
    events in the same section (decision 126) -- the events say what the
    findings did, and only hooks and privilege changes stay listed."""
    if "event" in r:
        return None
    m = GIT.match(path_of(r))
    if not m or (m.group(2) == "" and r.get("type") != "dir"):     # a .git file points elsewhere
        return None
    if path_of(r)[m.end():].startswith("hooks/") or path_of(r)[m.end():] == "hooks":
        return None
    gf = [f for f in r.get("findings") or [] if f.get("kind", "").startswith("git_")
          and f.get("kind") != "git_index_changed"]
    if not events and gf and not only_in_place(gf):
        return None
    ch = set(r.get("changed") or [])
    b, a = r.get("before", {}), r.get("after", {})
    if ch & {"caps", "iflags"} or "mode" in ch and (b.get("mode", 0) ^ a.get("mode", 0)) & 0o7000:
        return None
    return m.group(1)


def only_in_place(gf):
    """git's findings on a reflog that gained only moves leaving its ref
    where it was (2026-11-04): those fold, counted (in_place), the rest of
    what git reports stays."""
    moves = [f for f in gf if f.get("kind") == "git_reflog_move"]
    if not moves or any(f.get("from") != f.get("to") for f in moves):
        return False
    rest = [f for f in gf if f.get("kind") != "git_reflog_move"]
    return all(f.get("kind") == "git_reflog_appended" for f in rest) and \
        sum(f.get("entries", 0) for f in rest) in (0, len(moves))


def privilege_change(r):
    """A privilege change on this record: caps, inode flags, a setuid,
    setgid or sticky bit, or one belay's own receipt saw on an added or
    removed file (receipt_privilege)."""
    ch = set(r.get("changed") or [])
    b, a = r.get("before", {}), r.get("after", {})
    return bool(r.get("receipt_privilege") or ch & {"caps", "iflags"}
                or "mode" in ch and (b.get("mode", 0) ^ a.get("mode", 0)) & 0o7000)


def hook_path(p):
    """A path under a repository's hooks/: never folded (decision 105)."""
    m = GIT.match(p)
    return bool(m) and (p[m.end():].startswith("hooks/") or p[m.end():] == "hooks")


def touched(r):
    """A file whose only change is its mtime (decision 127): content, mode,
    owner, caps, xattrs and inode flags all equal; a hook never."""
    return ("event" not in r and r["outcome"] == "metadata_only" and (r.get("changed") or []) == ["mtime_ns"]
            and not hook_path(path_of(r)))


def replaced(r):
    """Replaced with identical content (decision 177) -- a branch switch's
    rewrite: a new inode, and nothing else but the mtime -- content, mode,
    owner, caps, xattrs and inode flags all equal; a directory, its inode
    alone. A hook never."""
    if "event" in r or r["outcome"] != "metadata_only" or hook_path(path_of(r)):
        return False
    changed = set(r.get("changed") or [])
    if "ino" not in changed:
        return False
    return changed == {"ino"} if r.get("type") == "dir" else changed <= {"ino", "mtime_ns"}


def listed(items, total=None):
    """Up to LISTED items, then how many more: a summary never drops one
    silently."""
    total = len(items) if total is None else total
    s = ", ".join(items[:LISTED])
    return s + (f" (and {total - min(len(items), LISTED):,} more)" if total > LISTED else "")


def short(oid):
    return oid[:12] if len(oid) in (40, 64) and all(c in "0123456789abcdef" for c in oid) else oid


OID = re.compile(r"\b([0-9a-f]{12})(?:[0-9a-f]{28}|[0-9a-f]{52})\b")


def short_ids(text):
    """Object ids cut to 12 digits for reading; the JSON keeps them whole."""
    return OID.sub(r"\1", text)


def git_items(recs):
    """What git says, for the summary: its events when it emits them, else
    its findings on refs, HEAD and hooks; hook changes always."""
    out, other = [], 0
    events = [r for r in recs if "event" in r and r.get("interp") == "git"]
    for e in events:
        out.append(short_ids(printable(e.get("text", ""))))
    for r in recs:
        if "event" in r:
            continue
        for f in r.get("findings") or []:
            k = f.get("kind", "")
            if k.startswith("git_hook"):
                out.append(printable(f.get("text", "")))
            elif events:
                continue
            elif k == "git_head_changed":
                out.append(f"HEAD {short(f.get('from', ''))} -> {short(f.get('to', ''))}".replace("refs/heads/", ""))
            elif k in ("git_ref_created", "git_ref_deleted", "git_ref_moved"):
                ref = f.get("ref", "")
                if not ref.startswith("refs/heads/"):
                    other += 1
                    continue
                b = ref[len("refs/heads/"):]
                out.append({"git_ref_created": f"branch {b} created at {short(f.get('to', ''))}",
                            "git_ref_deleted": f"branch {b} deleted",
                            "git_ref_moved": f"{b} -> {short(f.get('to', ''))}"}[k])
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    if other:
        uniq.append(f"{other} other ref{'s' if other != 1 else ''} updated")
    return uniq


def summary(secs, net=None, cls=None):
    """The turn at a glance (decision 125), before any section: what was
    edited (with line counts), added, removed; git; packages; privilege;
    build output; unknown. Each line names a few and counts the rest; the
    sections below hold every record. With `net` -- the diff from the
    turn's first checkpoint to its last -- what was edited, added and
    removed is the turn's net result, and what calls changed and later
    undid is counted as touched and restored (2026-11-04); the sections
    keep each call's own changes. With `cls` (git_classes), git-ignored
    paths are what folds, in place of build/ and bin/."""
    recs = [r for h, rs, _, _ in secs for r in rs]

    def by_path(rs):
        per = {}
        for r in rs:
            if "event" not in r:
                per.setdefault(path_of(r), []).append(r)
        return per

    def folds(p, r):
        if cls is None:
            return p.startswith(BUILD) or p + "/" in BUILD     # build/ itself is build output too
        return cls.get(p) == "ignored" and not privilege_change(r) and r.get("outcome") != "unknown"

    def ign(p):
        return cls is not None and cls.get(p) == "ignored"

    per = by_path(recs)
    files = by_path(net) if net is not None else per
    # A git-ignored file edited in the end is named, never folded (2026-11-04).
    ign_edited = {p for p, rs in files.items() if ign(p) and ignored_edit(rs[-1])
                  and rs[-1].get("outcome") != "unknown" and not compiled(p)}
    edited, added, removed, gone = [], [], [], 0
    ign_named = []
    added_dirs = set()
    unknown, priv, build, pyc = [], [], [], 0
    folded_unknown = []
    for p, rs in per.items():
        if any(privilege_change(r) for r in rs):
            priv.append(f"{SYM.get(rs[-1]['outcome'], '?')} {printable(p)}")
        if folds(p, rs[-1]) and p not in ign_edited:
            build.append(rs[-1])
            continue
        if compiled(p):
            pyc += 1
            continue
        if GIT.match(p):
            continue
        if ignored_unknown(cls, rs[-1]):
            folded_unknown.append(rs[-1])
        elif rs[-1]["outcome"] == "unknown":
            unknown.append(f"{printable(p)} ({', '.join(rs[-1].get('unknown', []))})")
    eligible = {p for p, rs in per.items() if not folds(p, rs[-1]) and not compiled(p) and not GIT.match(p)
                and rs[-1]["outcome"] != "unknown"}
    for p, rs in files.items():
        if (folds(p, rs[-1]) and p not in ign_edited) or compiled(p) or GIT.match(p):
            continue
        outs = [r["outcome"] for r in rs]
        if outs[-1] == "unknown":
            continue
        elif "added" in outs and outs[-1] == "removed":
            gone += 1
        elif "added" in outs:
            added.append(p)
            if rs[-1].get("type") == "dir":
                added_dirs.add(p)
        elif outs[-1] == "removed":
            removed.append(printable(p))
        elif any(o in ("modified", "type_changed") for o in outs):
            plus = minus = 0
            text = False
            for r in rs:
                for f in r.get("findings") or []:
                    if f.get("kind") == "text_changed":
                        plus, minus, text = plus + f.get("lines_added", 0), minus + f.get("lines_deleted", 0), True
                    elif f.get("kind") == "text_rewritten":
                        plus, minus, text = plus + f.get("lines_after", 0), minus + f.get("lines_before", 0), True
            kind = " (type changed)" if "type_changed" in outs else f" +{plus} -{minus}" if text else ""
            (ign_named if p in ign_edited else edited).append(printable(p) + kind)
    # A path back as it was, but for when it was written or which inode
    # holds it (a branch switched back, a stash popped): restored too.
    same = {p for p, rs in files.items() if rs[-1].get("outcome") == "metadata_only"
            and set(rs[-1].get("changed") or []) <= {"mtime_ns", "ctime_ns", "ino", "dev", "nlink"}}
    restored = len(eligible - (set(files) - same)) if net is not None else 0
    # An added directory stands for what was added below it.
    roots = sorted(d for d in added_dirs if not any(d.startswith(o + "/") for o in added_dirs))
    shown = [f"{printable(d)}/ (+{sum(1 for p in added if p.startswith(d + '/'))})" for d in roots]
    shown += [printable(p) for p in sorted(added) if not any(p == d or p.startswith(d + "/") for d in roots)]
    lines = []
    back = f"{restored:,} {'more ' if edited else ''}touched and restored" if restored else ""
    if edited:
        lines.append(f"  edited     {len(edited):,}: {listed(sorted(edited))}" + (f"; {back}" if back else ""))
    elif back:
        lines.append(f"  edited     none in the end; {back}")
    if added or removed or gone:
        parts = []
        if added:
            parts.append(f"added {len(added):,}: {listed(shown)}")
        if removed:
            parts.append(f"removed {len(removed):,}: {listed(sorted(removed))}")
        if gone:
            parts.append(f"{gone:,} added and removed again")
        lines.append("  files      " + "; ".join(parts))
    git = git_items(recs)
    if git:
        lines.append(f"  git        {listed(git)}")
    pk = [f"{r.get('interp', '')} {printable(r.get('text', ''))}" for r in recs
          if "event" in r and r.get("interp") in ("pip", "dpkg")]
    if pk:
        lines.append(f"  packages   {listed(pk)}")
    if priv:
        lines.append(f"  privilege  {listed(sorted(priv))}")
    if build or pyc or ign_named:
        k = len(build)
        if cls is None:
            parts = [f"{k:,} change{'s' if k != 1 else ''} under build/, bin/"] if build else []
        else:
            dirs = [d or "the top directory" for d, _ in ignored_dirs(build)]
            parts = [f"{len(ign_named):,} edited: {listed(sorted(ign_named))}"] if ign_named else []
            if build:
                parts.append(f"{k:,} under {listed([printable(d) for d in dirs])}")
        if pyc:
            parts.append(f"{pyc:,} compiled Python")
        lines.append(f"  {'build  ' if cls is None else 'ignored'}    {'; '.join(parts)}")
    if unknown or folded_unknown:
        parts = [f"{len(unknown):,}: {listed(sorted(unknown))}"] if unknown else []
        parts += [f"{k:,} git-ignored under {printable(d)} ({why})" for d, k, why in unknown_fold(folded_unknown)]
        lines.append(f"  unknown    {'; '.join(parts)}")
    return ["", "summary"] + lines if lines else []


def render(scope, belay, secs, errors, net=None):
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
    cls = git_classes(scope, [r for _, recs, _, _ in secs for r in recs] + (net or []))
    lines.extend(summary(secs, net, cls))
    rank = {"tracked": 0, "untracked": 1, "ignored": 2}
    detail, touches, numbers = [], [], {}
    for head, recs, outside, calls in secs:
        refs = []
        for c in calls:
            if cut(c):
                # One number per call: a background command runs beside many
                # others, and is named in each of their sections.
                if id(c) not in numbers:
                    detail.append(c)
                    numbers[id(c)] = len(detail)
                refs.append(f"[{numbers[id(c)]}]")
        lines.append("")
        lines.append(head + ("   " + " ".join(refs) if refs else ""))
        if cls is None:     # no git, no repository: build/ and bin/ fold by name, as before
            build = [r for r in recs if "event" not in r and path_of(r).startswith(BUILD)]
        else:               # git-ignored paths fold by top-level directory; privilege and unknown stay
            build = [r for r in recs if "event" not in r and cls.get(path_of(r)) == "ignored"
                     and not privilege_change(r) and r.get("outcome") != "unknown" and not ignored_edit(r)]
        folded = [r for r in recs if ignored_unknown(cls, r)]
        pyc = [r for r in recs if "event" not in r and r not in build and r not in folded and compiled(path_of(r))]
        events = any("event" in r and r.get("interp") == "git" for r in recs)
        git = {}
        shown = []
        for r in recs:
            if r in build or r in pyc or r in folded:
                continue
            repo = folded_git(r, events)
            if repo is not None:
                git.setdefault(repo, []).append(r)
                continue
            shown.append(r)
        if cls is not None:     # tracked changes first, then untracked, then ignored edits (2026-11-04)
            shown.sort(key=lambda r: 3 if "event" in r else rank.get(cls.get(path_of(r)), 1))
        roots, under = folded_dirs(shown)
        same = [r for r in shown if touched(r) and id(r) not in under and id(r) not in roots]
        repl = [r for r in shown if replaced(r) and id(r) not in under and id(r) not in roots]
        for r in shown:
            if id(r) in under or r in same or r in repl:
                continue
            if id(r) in roots and roots[id(r)]:
                k = roots[id(r)]
                lines.append(f"  {SYM[r['outcome']]} {printable(path_of(r))}/ and {k:,} "
                             f"entr{'ies' if k != 1 else 'y'} below it")
                continue
            lines.append(line_of(r, outside, cls is not None and cls.get(path_of(r)) == "ignored"))
        if same:
            touches.append([path_of(r) for r in same])
            lines.append(f"  ~ {len(same):,} file{'s' if len(same) != 1 else ''} touched, content unchanged   "
                         f"[t{len(touches)}]")
        if repl:
            touches.append([path_of(r) for r in repl])
            lines.append(f"  ~ {len(repl):,} entr{'ies' if len(repl) != 1 else 'y'} replaced with identical content   "
                         f"[t{len(touches)}]")
        if build and cls is None:
            lines.append(f"  build output: {len(build)} change{'s' if len(build) != 1 else ''} under build/, bin/")
        elif build:
            for d, k in ignored_dirs(build):
                lines.append(f"  git-ignored: {k:,} change{'s' if k != 1 else ''} "
                             + (f"under {printable(d)}" if d else "in the top directory"))
        for d, k, why in unknown_fold(folded):
            lines.append(f"  git-ignored: {k:,} unknown under {printable(d)} ({why})")
        if pyc:
            lines.append(f"  compiled Python: {len(pyc)} change{'s' if len(pyc) != 1 else ''} (__pycache__/, *.pyc)")
        for repo, rs in git.items():
            k, ip = len(rs), in_place(rs)
            lines.append(f"  git bookkeeping: {k} change{'s' if k != 1 else ''} under {repo}.git/"
                         + (f" ({ip})" if ip else ""))
    if detail:
        lines.append("")
        lines.append("the calls in full")
        for k, c in enumerate(detail, 1):
            text = full_label(c).split("\n")
            lines.append(f"  [{k}] " + printable(text[0]))
            lines.extend("      " + printable(t) for t in text[1:CALL_LINES])
            if len(text) > CALL_LINES:      # the whole command is in the turn's JSON ("calls")
                more = len(text) - CALL_LINES
                lines.append(f"      \u2026 {more:,} more line{'s' if more != 1 else ''}")
    if touches:
        lines.append("")
        lines.append("the paths with content unchanged")
        for k, ps in enumerate(touches, 1):
            lines.append(f"  [t{k}] " + printable(ps[0]))
            lines.extend("       " + printable(p) for p in ps[1:])
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
    try:        # the turn's net result, for the summary (2026-11-04); without it, the calls' sum
        net = diff(belay, scope, lo, hi) if lo != hi else []
    except (RuntimeError, ValueError, OSError):
        net = None
    text, n, paths = render(scope, belay, secs, errors, net)
    path = os.path.join(d, f"{sid}.turn-{hi}.txt")
    with open(path, "w") as f:
        f.write(text)
    with open(os.path.join(d, f"{sid}.turn-{hi}.json"), "w") as f:
        json.dump({"lo": lo, "hi": hi, "changes": n, "paths": paths, "interesting": interesting(secs),
                   "errors": len(errors), "heads": stop_heads(secs),
                   "sections": [{"section": h, "calls": [full_label(c) for c in cs], "records": r}
                                for h, r, _, cs in secs]}, f)
    return text, n, paths, path, errors, stop_heads(secs)


def stop_heads(secs):
    """The calls a Stop line names: each once (decision 185) -- the background
    note is the section's, not the line's."""
    heads = []
    for h, _, _, _ in secs:
        h = h.split(BG_NOTE)[0]
        if not h.startswith("unknown throughout") and h not in heads:
            heads.append(h)
    return heads[:3]


def prompted_ns(transcript):
    """When the user's last message came (ns), from the session's transcript:
    the last main-thread entry whose origin is human. A turn a background
    task woke is no message of theirs (decision 197). None when not found."""
    import datetime
    last = None
    try:
        with open(transcript, encoding="utf-8", errors="replace") as f:
            for line in f:
                if '"human"' not in line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("type") == "user" and not e.get("isSidechain") and \
                        (e.get("origin") or {}).get("kind") == "human" and e.get("timestamp"):
                    last = e["timestamp"]
    except OSError:
        return None
    if last is None:
        return None
    try:
        t = datetime.datetime.fromisoformat(last.replace("Z", "+00:00"))
    except ValueError:
        return None
    return int(t.timestamp()) * 10**9 + t.microsecond * 1000


def since_prompt(events, d, sid, hi, transcript):
    """Every turn since the user's message, ending with this Stop's
    (decision 197): (paths, changes, turns, errors, heads, receipt path), or
    None when the message cannot be placed."""
    at = prompted_ns(transcript) if transcript else None
    if at is None:
        return None
    his = [e["cp"] for e in events if e.get("event") == "stop" and e.get("cp") is not None
           and int(e.get("t0") or 0) >= at and e["cp"] <= hi]
    if hi not in his:
        his.append(hi)
    turns = []
    for h in sorted(set(his)):
        try:
            with open(os.path.join(d, f"{sid}.turn-{h}.json")) as f:
                turns.append(json.load(f))
        except (OSError, ValueError):
            return None                             # a turn without its receipt: not summed silently
    paths, n, errors, heads = set(), 0, 0, []
    for t in turns:
        for s in t["sections"]:
            if not s["section"].startswith("unknown throughout"):
                for r in s["records"]:
                    if "event" not in r:
                        paths.add(path_of(r))
                        n += 1
        errors += t.get("errors", 0)
        heads += [h for h in t.get("heads", []) if h not in heads]
    if len(turns) == 1:
        path = os.path.join(d, f"{sid}.turn-{turns[0]['hi']}.txt")
    else:
        path = os.path.join(d, f"{sid}.since-{hi}.txt")
        with open(path, "w") as out:
            for t in turns:
                with open(os.path.join(d, f"{sid}.turn-{t['hi']}.txt")) as f:
                    out.write(f"--- checkpoints {t['lo']} -> {t['hi']}\n" + f.read())
    return len(paths), n, len(turns), errors, heads[:3], path


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
        if mode == "turn":                          # never a Stop without a line (decision 156)
            print("belay: no checkpoint recorded in this session, so no receipt this turn")
        return
    stops = [e["cp"] for e in events if e.get("event") == "stop" and e.get("cp") is not None]
    starts = [e["cp"] for e in events if e.get("event") == "start" and e.get("cp") is not None]
    if mode == "turn":
        hi = stops[-1] if stops else max(cps)
        earlier = stops[:-1] + starts
        lo = max([s for s in earlier if s < hi], default=min(cps))
        _, n, paths, path, errors, heads = turn(events, belay, scope, d, sid, lo, hi)
        errors = len(errors)
        # The span is the user's: every turn since their message, however many
        # a background task woke (decision 197); this turn alone, said so,
        # when their message cannot be placed.
        span = since_prompt(events, d, sid, hi, sys.argv[6] if len(sys.argv) > 6 else "")
        note = ""
        if span:
            paths, n, k, errors, heads, path = span
            when = f"since your message ({k} turn{'s' if k != 1 else ''})"
        else:
            when, note = "this turn", "; your message not found in the transcript"
        if n or errors:
            msg = f"belay: {paths:,} path{'s' if paths != 1 else ''} changed {when}"
            if n != paths:
                msg += f" ({n:,} changes across calls)"
            if heads:
                msg += " (" + "; ".join(heads) + ")"
            if errors:
                msg += f"; receipt incomplete ({errors} error{'s' if errors != 1 else ''})"
        else:                                       # said too: no line is never a quiet turn (decision 156)
            msg = f"belay: nothing changed {when}"
        print(msg + note + f" -- {path}")          # the hook makes the Stop's JSON
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
