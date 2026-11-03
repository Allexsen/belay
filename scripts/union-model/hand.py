#!/usr/bin/env python3
"""Hand-made layer sets with the outcome written down from the documentation and the pin.

    unshare -r hand.py build WORKDIR && hand.py verify WORKDIR

What the kernel cannot be asked here (a redirect: under `userxattr` it follows none, see
NOTES-union-model.md U19) is pinned by these cases instead; each says which reading it rests
on. Each case is also run against the kernel, as check.py runs a generated set: in full where
no redirect is followed, around the entries that one is. A case lists its layers (topmost first) as {path: spec}, and the expected entries as
(path, type, layer, layer_path) -- or the pin row that refuses.
"""

import json
import os
import shutil
import stat
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
P = "user.overlay."

# spec: "d" dir, "f" file, "w" whiteout, "l:TARGET" symlink; a dict adds xattrs:
#   {"t": "d", "redirect": "/a", "opaque": "y"}
CASES = [
    ("rename in place (relative redirect), U4",
     [{"etc": "d", "etc/ssl2": {"t": "d", "redirect": "ssl"}, "etc/ssl": "w"},
      {"etc": "d", "etc/ssl": "d", "etc/ssl/cert": "f"}],
     "/", [], [(".", "dir", 0, "/"), ("etc", "dir", 0, "/etc"),
               ("etc/ssl2", "dir", 0, "/etc/ssl2"), ("etc/ssl2/cert", "reg", 1, "/etc/ssl/cert")]),
    ("rename across directories (absolute redirect), U5",
     [{"b": "d", "b/y": {"t": "d", "redirect": "/a/x"}, "a": "d", "a/x": "w"},
      {"a": "d", "a/x": "d", "a/x/f": "f", "a/k": "f"}],
     "/", [], [(".", "dir", 0, "/"), ("a", "dir", 0, "/a"), ("a/k", "reg", 1, "/a/k"),
               ("b", "dir", 0, "/b"), ("b/y", "dir", 0, "/b/y"),
               ("b/y/f", "reg", 1, "/a/x/f")]),
    ("a redirect leading to a lower directory with its own redirect (a chain), U7",
     [{"c": {"t": "d", "redirect": "/b"}, "c/f0": "f", "b": "w"},
      {"b": {"t": "d", "redirect": "/a"}, "b/f1": "f", "a": "w"},
      {"a": "d", "a/f2": "f"}],
     "/", [], [(".", "dir", 0, "/"), ("c", "dir", 0, "/c"), ("c/f0", "reg", 0, "/c/f0"),
               ("c/f1", "reg", 1, "/b/f1"), ("c/f2", "reg", 2, "/a/f2")]),
    ("relative redirect in a middle layer reached through an absolute one, U4 U5 U7",
     [{"s": {"t": "d", "redirect": "/p/r"}},
      {"p": "d", "p/r": {"t": "d", "redirect": "q"}, "p/q": "w"},
      {"p": "d", "p/q": "d", "p/q/f": "f"}],
     "/", [], [(".", "dir", 0, "/"), ("p", "dir", 1, "/p"), ("p/r", "dir", 1, "/p/r"),
               ("p/r/f", "reg", 2, "/p/q/f"), ("s", "dir", 0, "/s"), ("s/f", "reg", 2, "/p/q/f")]),
    ("a child renamed (relative) below a redirected parent: its lower path is the parent's "
     "lower path, U4",
     [{"b": {"t": "d", "redirect": "/a"}, "a": "w"},
      {"a": "d", "a/y": {"t": "d", "redirect": "x"}, "a/x": "w"},
      {"a": "d", "a/x": "d", "a/x/f": "f"}],
     "/", [], [(".", "dir", 0, "/"), ("b", "dir", 0, "/b"), ("b/y", "dir", 1, "/a/y"),
               ("b/y/f", "reg", 2, "/a/x/f")]),
    ("an absolute redirect inside an opaque directory still reaches below, U5",
     [{"z": {"t": "d", "redirect": "/o/d"}},
      {"o": {"t": "d", "opaque": "y"}, "o/d": {"t": "d", "redirect": "/x"}},
      {"x": "d", "x/f": "f", "o": "d", "o/hidden": "f"}],
     "/", [], [(".", "dir", 0, "/"), ("o", "dir", 1, "/o"), ("o/d", "dir", 1, "/o/d"),
               ("o/d/f", "reg", 2, "/x/f"), ("x", "dir", 2, "/x"), ("x/f", "reg", 2, "/x/f"),
               ("z", "dir", 0, "/z"), ("z/f", "reg", 2, "/x/f")]),
    ("a redirect whose target a middle layer whites out: refused, U6",
     [{"b": {"t": "d", "redirect": "/a"}}, {"a": "w"}, {"a": "d", "a/f": "f"}],
     "/", [], "H-U5"),
    ("a redirect whose target is a file below: refused, U6",
     [{"b": {"t": "d", "redirect": "/a"}}, {"a": "f"}],
     "/", [], "H-U5"),
    ("a redirect on the bottom layer: refused, U6",
     [{"k": "f"}, {"b": {"t": "d", "redirect": "/a"}, "a": "d"}],
     "/", [], "H-U5"),
    ("a redirect on an opaque directory is moot, U9",
     [{"b": {"t": "d", "redirect": "/a", "opaque": "y"}, "b/g": "f"},
      {"a": "d", "a/f": "f", "b": "d", "b/h": "f"}],
     "/", [], [(".", "dir", 0, "/"), ("a", "dir", 1, "/a"), ("a/f", "reg", 1, "/a/f"),
               ("b", "dir", 0, "/b"), ("b/g", "reg", 0, "/b/g")]),
    ("a directory over a file over a directory: the lowest is not merged, U2",
     [{"d": "d", "d/g": "f"}, {"d": "f"}, {"d": "d", "d/h": "f"}],
     "/", [], [(".", "dir", 0, "/"), ("d", "dir", 0, "/d"), ("d/g", "reg", 0, "/d/g")]),
    ("a file over a directory, U3",
     [{"d": "f"}, {"d": "d", "d/h": "f"}],
     "/", [], [(".", "dir", 0, "/"), ("d", "reg", 0, "/d")]),
    ("a whiteout in a middle layer, made again above, U1",
     [{"d": "d", "d/n": "f"}, {"d": "w"}, {"d": "d", "d/old": "f"}],
     "/", [], [(".", "dir", 0, "/"), ("d", "dir", 0, "/d"), ("d/n", "reg", 0, "/d/n")]),
    ("the scope through links: `..` above the root stays at it, absolute from the root, H-C3",
     [{"l1": "l:../../../l2", "l2": "l:/real/sub", "real": "d", "real/sub": "d",
       "real/sub/f": "f"}, {"x": "f"}],
     "/l1", [], [(".", "dir", 0, "/real/sub"), ("f", "reg", 0, "/real/sub/f")]),
    ("the scope through a redirected directory, H-C3 U4",
     [{"n": {"t": "d", "redirect": "o"}, "o": "w"}, {"o": "d", "o/s": "d", "o/s/f": "f"}],
     "/n/s", [], [(".", "dir", 1, "/o/s"), ("f", "reg", 1, "/o/s/f")]),
    ("mount points below the scope: listed, not entered, H-M5",
     [{"v": "d", "v/in": "f", "h": "f", "w": "d"}, {"w": "d", "w/x": "f"}],
     "/", ["/v", "/h", "/w/x"],
     [(".", "dir", 0, "/"), ("h", "reg", 0, "/h"), ("v", "dir", 0, "/v"), ("w", "dir", 0, "/w"),
      ("w/x", "reg", 1, "/w/x")]),
    ("a mount point inside another mount is not looked up, U18",
     [{"v": "d"}, {"k": "f"}],
     "/", ["/v", "/v/none/deeper"], [(".", "dir", 0, "/"), ("k", "reg", 1, "/k"),
                                     ("v", "dir", 0, "/v")]),
    ("protattr: the upper layer's honoured, a lower one's not, U15",
     [{"u": {"t": "f", "protattr": "ia"}}, {"l": {"t": "f", "protattr": "i"}}],
     "/", [], [(".", "dir", 0, "/"), ("l", "reg", 1, "/l"), ("u", "reg", 0, "/u")]),
]


def build(root, layers):
    paths = []
    for i, spec in enumerate(layers):
        lr = os.path.join(root, "l%d" % i)
        os.makedirs(lr)
        paths.append(lr)
        for p in sorted(spec, key=lambda s: s.count("/")):
            v = spec[p]
            x = dict(v) if isinstance(v, dict) else {"t": v}
            t = x.pop("t")
            f = os.path.join(lr, p)
            if t == "d":
                os.mkdir(f)
            elif t == "f":
                open(f, "w").close()
            elif t == "w":
                os.mknod(f, 0o600 | stat.S_IFCHR, os.makedev(0, 0))
            elif t.startswith("l:"):
                os.symlink(t[2:], f)
            for k, val in x.items():
                os.setxattr(f, P + k, val.encode(), follow_symlinks=False)
    return paths


def main():
    """`hand.py build WORK` (in `unshare -r`: whiteouts), then `hand.py verify WORK`."""
    mode, work = sys.argv[1], sys.argv[2]
    if mode == "build":
        if os.path.lexists(work):
            shutil.rmtree(work)
        os.makedirs(work)
        for n, (title, layers, scope, mounts, want) in enumerate(CASES):
            d = os.path.join(work, "case%02d" % n)
            paths = build(d, layers)
            os.mkdir(os.path.join(d, "w"))
            os.mkdir(os.path.join(d, "m"))
            redirects = any("redirect" in v for spec in layers for v in spec.values()
                            if isinstance(v, dict))
            with open(os.path.join(d, "case.json"), "w") as f:
                json.dump({"layers": paths, "work": os.path.join(d, "w"),
                           "mnt": os.path.join(d, "m"), "prefix": P, "scope": scope,
                           "mounts": mounts, "expect": want if isinstance(want, str) else None,
                           "inject": title, "features": ["redirect"] if redirects else []}, f)
        return 0
    sys.dont_write_bytecode = True
    sys.path.insert(0, HERE)
    import compare
    bad = 0
    kchecked = 0
    for n, (title, layers, scope, mounts, want) in enumerate(CASES):
        d = os.path.join(work, "case%02d" % n)
        with open(os.path.join(d, "case.json")) as f:
            case = json.load(f)
        argv = [sys.executable, os.path.join(HERE, "model.py"), "--prefix", P]
        for m in mounts:
            argv += ["--mount", m]
        out = subprocess.run(argv + ["--content", "--explain", "--", scope] + case["layers"],
                             capture_output=True, text=True)
        recs = [json.loads(l) for l in out.stdout.splitlines()]
        if isinstance(want, str):
            got = recs[0].get("refused") if len(recs) == 1 else None
            ok = got == want
            shown = got if got else "a listing"
        else:
            got = [(r.get("path"), r.get("type"), r.get("layer"), r.get("layer_path"))
                   for r in recs]
            ok = got == want
            shown = got
            if ok and n == len(CASES) - 1:
                pa = {r["path"]: r["protattr"] for r in recs}
                ok = pa == {".": "", "l": "", "u": "ia"}
                shown = pa
        kern = ""
        if True:
            # The kernel too: in full where no redirect is followed, and around those it is.
            k = subprocess.run(["unshare", "-rm", sys.executable, os.path.join(HERE, "kwalk.py"),
                                os.path.join(d, "case.json")], capture_output=True, text=True)
            diffs, _ = compare.kernel_diffs(case, out.stdout.splitlines(), k.stdout.splitlines())
            kchecked += 1
            part = any(x.startswith("skipped-tainted") or x.startswith("kernel E") for x in _)
            judged = not any(x.endswith("(kernel: not judged)") for x in _)
            kern = "" if diffs else (" (kernel: not judged)" if not judged else
                                     " (kernel agrees, around the redirect)" if part else
                                     " (kernel agrees)")
            if diffs:
                ok = False
                shown = "%s; kernel: %s" % (shown, diffs)
        if ok:
            print("ok   %s%s" % (title, kern))
        else:
            bad += 1
            print("FAIL %s\n     want %s\n     got  %s\n%s" % (title, want, shown, out.stderr))
    print("== %d hand cases, %d failed" % (len(CASES), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
