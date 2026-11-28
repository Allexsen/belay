#!/usr/bin/env python3
"""belay as a silent recorder for any of the three CLIs (and the fake agent).

    belay_hook.py start                      first step of the session, then a marker
    belay_hook.py hook CLI EVENT             a CLI's hook: reads its JSON on stdin (CLI = claude | codex | agy)
    belay_hook.py stream CLI                 copies a CLI's JSON event stream stdin -> stdout, stepping on tool events
    belay_hook.py final                      last step, closes calls left open, writes the receipt and summary

Each step is `belay watch step --scope $WS --session $BELAY_SESSION [--begin ID | --finish ID] --agent CLI`.
Every step's line(s), exit status and the call it belongs to go to $BENCH_OUT/belay-steps.jsonl. Nothing is
printed to the agent: a hook's stdout carries only what its CLI requires (agy's PreToolUse needs a decision),
so belay's lines never enter the model's context. Exit status is always 0: recording never blocks a tool.

Python standard library only.
"""
import fcntl
import json
import os
import subprocess
import sys
import time

BELAY = os.environ.get("BELAY", "/opt/bench/belay")
WS = os.environ.get("WS", "/home/agent/workspace")
OUT = os.environ.get("BENCH_OUT", "/bench-out")
SESSION = os.environ.get("BELAY_SESSION", "run")
OPEN = os.environ.get("HOOK_STATE", "/tmp/bench-hook-open.json")
LOG = os.path.join(OUT, "belay-steps.jsonl")


def log(rec):
    rec["t"] = time.time()
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")


def belay(*args, deadline=None):
    try:
        p = subprocess.run([BELAY, *args], capture_output=True, text=True, errors="replace",
                           timeout=deadline or 120, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, "", f"{type(e).__name__}: {e}"


def step(cli, event, begin=None, finish=None, tool=None, inp=None, first=False, model=None):
    a = ["watch", "step", "--scope", WS, "--session", SESSION, "--agent", cli]
    if begin:
        a += ["--begin", begin]
    if finish:
        a += ["--finish", finish]
    if first:
        a += ["--first-ok"]
    rc, so, se = belay(*a)
    log({"cli": cli, "event": event, "begin": begin, "finish": finish, "tool": tool,
         "input": (json.dumps(inp)[:4000] if inp is not None else None),
         "lines": [x for x in so.splitlines() if x.strip()], "stderr": se.strip()[:2000], "rc": rc, "model": model})


def opened():
    try:
        return json.load(open(OPEN))
    except (OSError, ValueError):
        return []


def keep(ids):
    tmp = OPEN + ".tmp"
    json.dump(ids, open(tmp, "w"))
    os.replace(tmp, OPEN)


def call_id(cli, d):
    if cli in ("claude", "codex", "fake"):
        return d.get("tool_use_id")
    if cli == "agy":                                # agy's hooks carry no call id: the step index stands in
        return None if d.get("stepIdx") is None else f"s{d['stepIdx']}"
    return None


def tool_of(cli, d):
    if cli == "agy":
        tc = d.get("toolCall") or {}
        return tc.get("name"), tc.get("args")
    return d.get("tool_name"), d.get("tool_input")


def hook(cli, event):
    raw = sys.stdin.read()
    try:
        d = json.loads(raw) if raw.strip() else {}
    except ValueError:
        d = {"unparsed": raw[:2000]}
    tool, inp = tool_of(cli, d)
    cid = call_id(cli, d)
    model = d.get("model") or d.get("modelName")     # Codex: model; agy: modelName (each CLI's own report)
    ev = event.lower()
    if ev in ("pre", "pretooluse"):
        ids = opened()
        cid = cid or f"anon{len(ids)}-{int(time.time() * 1000)}"
        step(cli, event, begin=cid, tool=tool, inp=inp, model=model)
        keep(ids + [cid])
        reply = {"decision": "allow"} if cli == "agy" else None
    elif ev in ("post", "posttooluse", "posttoolusefailure"):
        ids = opened()
        if cid not in ids:                          # agy: Pre and Post may not share a step index
            cid = ids[-1] if ids else None
        step(cli, event, finish=cid, tool=tool, inp=inp, model=model)
        keep([i for i in ids if i != cid])
        reply = {} if cli == "agy" else None
    else:                                           # Stop, SessionEnd, PostToolBatch and the like
        step(cli, event, tool=tool, inp=inp, model=model)
        reply = {} if cli == "agy" else None
    if reply is not None:
        sys.stdout.write(json.dumps(reply))


def stream(cli):
    """Step from the event stream: what a CLI without hooks would allow. The stream is read after the fact,
    so a step can land after the next command has started; hooks are synchronous and are preferred."""
    for line in sys.stdin:
        sys.stdout.write(line)
        sys.stdout.flush()
        try:
            e = json.loads(line)
        except ValueError:
            continue
        begin = finish = tool = None
        if cli == "codex" and e.get("type") in ("item.started", "item.completed"):
            it = e.get("item") or {}
            if it.get("type") in ("command_execution", "file_change", "mcp_tool_call"):
                tool = it.get("type")
                begin, finish = (it.get("id"), None) if e["type"] == "item.started" else (None, it.get("id"))
        elif cli == "agy" and e.get("event") == "step_update":
            su = e.get("step_update") or {}
            if su.get("step_type") == "tool":
                tool = su.get("tool_name")
                cid = f"s{su.get('step_index')}"
                begin, finish = (cid, None) if su.get("state") == "ACTIVE" else (None, cid)
        elif cli == "claude" and e.get("type") in ("assistant", "user"):
            for c in ((e.get("message") or {}).get("content") or []):
                if isinstance(c, dict) and c.get("type") == "tool_use":
                    step(cli, "stream", begin=c.get("id"), tool=c.get("name"))
                elif isinstance(c, dict) and c.get("type") == "tool_result":
                    step(cli, "stream", finish=c.get("tool_use_id"))
            continue
        if begin or finish:
            ids = opened()
            if finish and finish not in ids:
                finish = None
            if begin and begin in ids:
                continue
            step(cli, "stream", begin=begin, finish=finish, tool=tool)
            keep([i for i in ids if i != finish] + ([begin] if begin else []))


def final():
    step("harness", "final")
    rc, so, se = belay("watch", "close", "--scope", WS, "--session", SESSION, "--all")
    log({"cli": "harness", "event": "close", "lines": so.splitlines(), "stderr": se.strip()[:2000], "rc": rc})
    rc, so, se = belay("watch", "receipt", "--scope", WS)
    with open(os.path.join(OUT, "receipt.txt"), "w") as f:
        f.write(so + (("\n[stderr]\n" + se) if se.strip() else "") + f"\n[exit {rc}]\n")
    rc, so, se = belay("watch", "summary", "--scope", WS, "--session", SESSION, "--since", "start")
    with open(os.path.join(OUT, "summary.txt"), "w") as f:
        f.write(so + (("\n[stderr]\n" + se) if se.strip() else "") + f"\n[exit {rc}]\n")


def main():
    a = sys.argv[1:]
    try:
        if a[:1] == ["start"]:
            step("harness", "start", first=True)
            rc, so, se = belay("watch", "mark", "--scope", WS, "--session", SESSION, "--name", "start")
            log({"cli": "harness", "event": "mark", "lines": so.splitlines(), "stderr": se.strip(), "rc": rc})
        elif a[:1] == ["hook"] and len(a) == 3:
            with open(OPEN + ".lock", "a") as lk:     # parallel tool calls: one read-modify-write at a time
                fcntl.flock(lk, fcntl.LOCK_EX)
                hook(a[1], a[2])
        elif a[:1] == ["stream"] and len(a) == 2:
            stream(a[1])
        elif a[:1] == ["final"]:
            final()
        else:
            sys.stderr.write(__doc__)
    except Exception as e:                          # noqa: BLE001 - recording must never break the agent
        try:
            log({"cli": "harness", "event": "hook-error", "error": f"{type(e).__name__}: {e}", "argv": a})
        except OSError:
            pass
        if a[:1] == ["hook"] and a[1:2] == ["agy"] and a[2:3] and a[2].lower().startswith("pre"):
            sys.stdout.write(json.dumps({"decision": "allow"}))
    sys.exit(0)


if __name__ == "__main__":
    main()
