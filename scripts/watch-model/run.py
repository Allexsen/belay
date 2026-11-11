#!/usr/bin/env python3
"""watch-model's black-box harness: `belay watch patterns` against model.py.

For each scenario of gen.py: build the tree in a temporary directory, record it with
`belay watch step --scope DIR --session m --first-ok` (a fresh BELAY_STATE_DIR, mode 0700, and
a HOME, both beside the directory, never above it), then compare with the model:

  the list     what the step said of `.belay-donttouch` (nothing, `line N is not a pattern`, a
               limit passed, could not be read)
  entries      `belay watch patterns --entries`: for every entry of the tree, the kind, level
               and reason, or that no list covers it
  counts       `belay watch patterns`: the user's patterns in order with their counts and the
               `matches nothing` mark, and each built-in row's count
  the table    that the rows printed are the pin's (pattern, label, limits), 94 of them

Every disagreement is printed in full: scenario, path, what the model says, what belay says.
A gate, as policy-model has: every row must have won an entry at least once, and been switched
off at least once by each limit it carries, with belay agreeing there.

BELAY_BIN names the binary (default: the repository's bin/belay); WM_WORKDIR the directory the
scenarios are built in (default: a temporary directory, removed afterwards); WM_JOBS how many
run at once (default 8).

Exit: 0 every comparison agreed and the gate holds; 1 a disagreement, a failed self-test or
the gate; 2 no binary; 3 the binary has no `watch` command.
"""

import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen       # noqa: E402
import model     # noqa: E402
import selftest  # noqa: E402

REPO = model.REPO
BIN = os.environ.get("BELAY_BIN") or os.path.join(REPO, "bin", "belay")
TIMEOUT = 120


def belay(args, env):
    p = subprocess.run([BIN] + args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=TIMEOUT)
    return p.returncode, p.stdout


def unescape(b):
    """A shown path back to bytes: `\\xNN` and a doubled backslash."""
    out = bytearray()
    i = 0
    while i < len(b):
        if b[i:i + 2] == b"\\\\":
            out += b"\\"
            i += 2
        elif b[i:i + 2] == b"\\x" and re.match(rb"[0-9a-fA-F]{2}", b[i + 2:i + 4]):
            out.append(int(b[i + 2:i + 4], 16))
            i += 4
        else:
            out.append(b[i])
            i += 1
    return bytes(out)


def build(sc, root):
    scope = os.path.join(root, "scope")
    os.mkdir(root)
    os.mkdir(scope)
    os.mkdir(os.path.join(root, "home"))
    os.mkdir(os.path.join(root, "state"), 0o700)
    for path in sorted(sc["tree"]):
        ty = sc["tree"][path]
        full = os.path.join(scope, path)
        if ty == "d":
            os.mkdir(full)
        elif ty == "l":
            os.symlink(sc["links"][path], full)
        else:
            with open(full, "wb") as f:
                if path == ".belay-donttouch" and sc["dt"] is not None:
                    f.write(sc["dt"])
                else:
                    f.write(b"x\n")
    env = dict(os.environ)
    env["HOME"] = os.path.join(root, "home")
    env["BELAY_STATE_DIR"] = os.path.join(root, "state")
    env.pop("BELAY_SESSION", None)
    return scope, env


def status_of_step(out):
    """What the step said of `.belay-donttouch`."""
    text = out.decode("utf-8", "replace")
    for line in text.split("\n"):
        if not line.startswith("belay: \U0001F534 "):
            continue
        m = re.search(r"\.belay-donttouch: line (\d+) is not a pattern", line)
        if m:
            return ("line", int(m.group(1))), line
        if "could not read .belay-donttouch" in line:
            return ("unreadable",), line
        if ".belay-donttouch: " in line:
            return ("limit",), line
    if text.strip():
        return ("other",), text.strip()
    return ("ok",), ""


def show_status(st):
    return {"ok": "a valid list, or no file (the step says nothing)", "none": "no file",
            "line": "invalid: line %s is not a pattern" % (st[1] if len(st) > 1 else "?"),
            "limit": "invalid: a limit is passed", "unreadable": "could not be read",
            "other": "another line"}[st[0]]


def run_scenario(M, sc, root):
    """A list of comparisons: (what, agreed, path or '', model says, belay says)."""
    res = []
    scope, env = build(sc, root)
    tree = {p.encode(): t for p, t in sc["tree"].items()}
    status, user = model.list_in_force(tree, sc["dt"])

    rc, out = belay(["watch", "step", "--scope", scope, "--session", "m", "--first-ok"], env)
    bstatus, bline = status_of_step(out)
    mclass = ("ok",) if status[0] in ("ok", "none") else status[:2] if status[0] == "line" else status[:1]
    mshow = show_status(mclass) + (" (%s)" % status[-1] if status[0] in ("line", "limit") else "")
    res.append(("list", mclass == bstatus, ".belay-donttouch", mshow,
                show_status(bstatus) + (": " + bline if bline else "") + ("" if rc == 0 else " [exit %d]" % rc)))

    rc, out = belay(["watch", "patterns", "--scope", scope, "--entries"], env)
    seen = {}
    for line in out.split(b"\n"):
        if not line:
            continue
        f = line.split(b"\t")
        if len(f) != 4:
            res.append(("entries", False, "", "a line KIND<TAB>LEVEL<TAB>REASON<TAB>PATH", repr(line)))
            continue
        path = unescape(f[3])
        v = tuple(x.decode("utf-8", "replace") for x in f[:3])
        if path in seen:
            res.append(("entries", False, path.decode("utf-8", "replace"), "one line an entry", "a second line: %r" % (v,)))
        seen[path] = v
    if rc != 0:
        res.append(("entries", False, "", "exit 0", "exit %d: %r" % (rc, out[:300])))
    wins = []
    for path in sorted(tree):
        c = M.classify(path, tree[path], user)
        want = None if c is None else c[:3]
        got = seen.pop(path, None)
        res.append(("entries", want == got, "%s (%s)" % (path.decode(), {"d": "directory", "f": "file", "l": "symlink"}[tree[path]]),
                    "\t".join(want) if want else "no list covers it" + why_not(M, path, tree[path]),
                    "\t".join(got) if got else "no list covers it"))
        if c is not None and c[3] is not None and want == got:
            wins.append(c[3])
    top = M.classify_top(user)                           # the directory itself, shown as `.`
    want = None if top is None else top[:3]
    got = seen.pop(b".", None)
    res.append(("entries", want == got, ". (the watched directory itself)",
                "\t".join(want) if want else "no list covers it", "\t".join(got) if got else "no list covers it"))
    for path, got in sorted(seen.items()):
        res.append(("entries", False, path.decode("utf-8", "replace"), "no such entry in the tree", "\t".join(got)))

    rc, out = belay(["watch", "patterns", "--scope", scope], env)
    lines = out.decode("utf-8", "replace").split("\n")
    busers, brows, in_rows, nrows = [], [], False, None
    for line in lines:
        m = re.match(r"built-in list: (\d+) rows", line)
        if m:
            in_rows, nrows = True, int(m.group(1))
        elif line.startswith("  "):
            (brows if in_rows else busers).append(line[2:].split("\t"))
    musers = [(M.user_count(u, tree), u) for u in user]
    for i in range(max(len(musers), len(busers))):
        mu = musers[i] if i < len(musers) else None
        bu = busers[i] if i < len(busers) else None
        ms = "no such pattern" if mu is None else "%d\t%s%s" % (mu[0], mu[1].decode("utf-8", "replace"),
                                                                 "\tmatches nothing" if mu[0] == 0 else "")
        bs = "no such pattern" if bu is None else "\t".join(bu)
        if mu is not None and bu is not None and len(bu) >= 2:
            # a pattern is shown escaped like a path; compare its bytes
            same = (str(mu[0]) == bu[0] and unescape(bu[1].encode("utf-8", "surrogateescape")) == mu[1]
                    and (bu[2:] == ["matches nothing"]) == (mu[0] == 0))
        else:
            same = False
        res.append(("counts: user patterns", same, "pattern %d" % (i + 1), ms, bs))
    table_ok = nrows == len(M.rows) == len(brows)
    table_bad = "" if table_ok else "%s rows announced, %d printed" % (nrows, len(brows))
    for r, br in zip(M.rows, brows):
        want_lim = r.limits_text.replace("`", "")
        if len(br) < 3 or br[1] != r.pattern or br[2] != r.label or \
                (br[3] if len(br) > 3 else "--") not in (want_lim, "" if want_lim == "--" else want_lim):
            table_ok = False
            table_bad = table_bad or "%s printed as %r" % (r.id, br)
        n = M.row_count(r, tree)
        res.append(("counts: built-in rows", len(br) >= 1 and br[0] == str(n), "%s %s" % (r.id, r.pattern),
                    str(n), br[0] if br else "nothing"))
    res.append(("the table as printed", table_ok, "", "the pin's %d rows: pattern, label, limits" % len(M.rows),
                table_bad or "the same"))

    offs = []
    for path, ty in tree.items():
        nc = model.split(path)
        for r in M.rows:
            if model.row_applies(r, nc, ty):
                continue
            for lim in ("L1", "L2", "L4"):
                if model.row_applies(r, nc, ty, ignore=(lim,)):
                    offs.append((r.id, lim))
    ok_all = all(x[1] for x in res)
    return res, wins, (offs if ok_all else [])


def why_not(M, path, etype):
    """For a disagreement's text: the rows a limit switched off for this entry."""
    nc = model.split(path)
    out = []
    for r in M.rows:
        if model.row_applies(r, nc, etype):
            continue
        for lim in ("L1", "L2", "L4"):
            if model.row_applies(r, nc, etype, ignore=(lim,)):
                out.append("%s is off by BR-%s" % (r.id, lim))
    return " (%s)" % "; ".join(out) if out else ""


def main(argv):
    if selftest.main():
        return 1
    if not os.path.exists(BIN):
        print("no binary at %s (make bin/belay, or set BELAY_BIN)" % BIN)
        return 2
    p = subprocess.run([BIN, "help", "watch"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0 or b"belay watch patterns" not in p.stdout:
        print("belay watch is not built in %s: nothing to compare yet (exit 3)" % BIN)
        return 3

    M = model.Model()
    scs = gen.scenarios()
    only = argv[0] if argv else None
    if only:
        scs = [s for s in scs if only in s["name"]]
    work = os.environ.get("WM_WORKDIR")
    made = None
    if not work:
        made = work = tempfile.mkdtemp(prefix="belay-watch-model-")
    os.makedirs(work, exist_ok=True)
    home = os.path.realpath(os.path.expanduser("~"))
    if (home + os.sep).startswith(os.path.realpath(work) + os.sep):
        print("WM_WORKDIR %s is above HOME: belay would not watch a directory in it" % work)
        return 2

    results = [None] * len(scs)

    def one(i):
        root = os.path.join(work, "s%04d" % i)
        if os.path.exists(root):
            shutil.rmtree(root)
        try:
            return run_scenario(M, scs[i], root)
        except Exception as e:  # a scenario that could not be run is a disagreement, in full
            return [("could not run", False, "", "a run", "%s: %s" % (type(e).__name__, e))], [], []
        finally:
            if made:
                shutil.rmtree(root, ignore_errors=True)

    with concurrent.futures.ThreadPoolExecutor(int(os.environ.get("WM_JOBS", "8"))) as ex:
        for i, r in enumerate(ex.map(one, range(len(scs)))):
            results[i] = r
    if made:
        shutil.rmtree(made, ignore_errors=True)

    cats, order, bad = {}, [], 0
    won, off = set(), set()
    for sc, (res, wins, offs) in zip(scs, results):
        won.update(wins)
        off.update(offs)
        c = cats.setdefault(sc["category"], [0, 0, 0])
        if sc["category"] not in order:
            order.append(sc["category"])
        c[2] += 1
        for what, agreed, path, msays, bsays in res:
            c[1] += 1
            if agreed:
                c[0] += 1
                continue
            bad += 1
            print("DISAGREE [%s] %s: %s" % (sc["name"], what, path))
            print("  model: %s" % msays)
            print("  belay: %s" % bsays)
    print("%-58s %9s  %s" % ("category (scenarios)", "agreed", "total"))
    tot = [0, 0]
    for k in order:
        a, t, n = cats[k]
        tot[0] += a
        tot[1] += t
        print("%-58s %9d / %d" % ("%s (%d)" % (k, n), a, t))
    print("%-58s %9d / %d" % ("all (%d)" % len(scs), tot[0], tot[1]))

    gate = []
    if not only:
        for r in M.rows:
            if r.id not in won:
                gate.append("%s never won an entry with belay agreeing" % r.id)
            for lim, has in (("L1", r.not_dir), ("L2", r.not_dep), ("L4", bool(r.excepts))):
                if has and (r.id, lim) not in off:
                    gate.append("%s was never switched off by BR-%s in a scenario that agreed" % (r.id, lim))
    for g in gate:
        print("GATE " + g)
    print("%d scenarios; %d comparisons; %d disagreements" % (len(scs), tot[1], bad))
    print("not modelled: BR-L3 (not in a new directory) needs a change, not a current entry")
    return 1 if bad or gate else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
