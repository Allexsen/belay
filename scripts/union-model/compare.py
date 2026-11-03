#!/usr/bin/env python3
"""Comparisons of the union model's output with another view of the same layers.

compare_outputs(model_lines, other_lines)
    THE HOOK for a second program (belay's own driver): its output, in the model's format
    (model.py's docstring and NOTES-union-model.md U22), against the model's for the same
    layers, scope and mounts. Returns a list of differences, empty when they agree.
    CLI: compare.py MODEL_OUTPUT OTHER_OUTPUT  (exit 1 when they differ)

kernel_diffs(case, model_lines, kernel_lines)
    The model (run with --content --explain) against kwalk.py's walk of the real overlay.
    Returns (differences, notes): notes count what was checked and what could not be.
"""

import base64
import json
import os
import sys

# Fields of the format; EXPLAIN_FIELDS are --explain's, never compared.
FORMAT_FIELDS = ("type", "layer", "layer_path", "layer_path_b64", "mode", "uid", "gid", "size",
                 "target", "target_b64", "xattrs", "protattr", "mount", "sha256")
EXPLAIN_FIELDS = ("members", "tainted", "scope", "scope_tainted")


def parse(lines):
    """(refusal or None, {path: record}); `path_b64` keys stay distinct from `path` keys."""
    recs = [json.loads(l) for l in lines if l.strip()]
    if len(recs) == 1 and "refused" in recs[0]:
        return recs[0], {}
    out = {}
    for r in recs:
        if "path" in r or "path_b64" in r:
            out[pathkey(r)] = r
    return None, out


def pathkey(r):
    """An entry's path as its raw bytes, from `path` or `path_b64`."""
    if "path" in r:
        return r["path"].encode("utf-8", "surrogateescape")
    return base64.b64decode(r["path_b64"])


def show(key):
    return key.decode("utf-8", "backslashreplace")


def compare_outputs(model_lines, other_lines):
    """The hook: every format field of every entry, and the refusal row, must agree."""
    diffs = []
    mref, m = parse(model_lines)
    oref, o = parse(other_lines)
    if mref or oref:
        if not (mref and oref):
            diffs.append("refusal: model %s, other %s" % (mref and mref["refused"],
                                                          oref and oref["refused"]))
        elif mref["refused"] != oref["refused"]:
            diffs.append("refusal row: model %s, other %s" % (mref["refused"], oref["refused"]))
        return diffs
    prev = None
    for l in other_lines:
        if not l.strip():
            continue
        p = pathkey(json.loads(l))
        if prev is not None and p <= prev:
            diffs.append("other: not sorted strictly by path bytes at %s" % show(p))
        prev = p
    for k in sorted(set(m) | set(o)):
        if k not in o:
            diffs.append("%s: only in the model" % show(k))
        elif k not in m:
            diffs.append("%s: only in the other" % show(k))
        else:
            for f in FORMAT_FIELDS:
                a, b = m[k].get(f), o[k].get(f)
                if f == "sha256" and (a is None or b is None):
                    continue        # the model writes it only with --content
                if a != b:
                    diffs.append("%s: %s model %r, other %r" % (show(k), f, a, b))
    return diffs


def mapid(idmap, host):
    for inside, outside, count in idmap:
        if outside <= host < outside + count:
            return inside + host - outside
    return 65534        # the overflow id an unmapped one shows as


def comps(p):
    return tuple(c for c in p.split("/") if c)


def kernel_diffs(case, model_lines, kernel_lines):
    diffs, notes = [], []
    mref, m = parse(model_lines)
    krecs = [json.loads(l) for l in kernel_lines if l.strip()]
    if not krecs:
        return ["kernel: no output"], notes
    hdr = krecs[0]
    if "mount_error" in hdr:
        return ["kernel: the overlay did not mount: %s" % hdr["mount_error"]], notes
    expect = case.get("expect")
    redirects = any(f.startswith("redirect") for f in case["features"])

    kscope = hdr.get("scope")
    kc3 = "scope_error" in hdr or hdr.get("scope_through_mount", False)
    mounts = [comps(x) for x in case["mounts"]]
    if kscope is not None:
        ks = comps(kscope)
        kc3 = kc3 or any(ks[:len(mt)] == mt for mt in mounts)
    km5 = False
    if kscope is not None:
        ks = comps(kscope)
        below = [mt for mt in mounts if len(mt) > len(ks) and mt[:len(ks)] == ks]
        for x, ok in hdr["mounts_held"].items():
            mt = comps(x)
            inner = any(len(mt) > len(o) and mt[:len(o)] == o for o in below)
            if mt in below and not inner and ok == "EPERM":
                notes.append("kernel EPERM at the mount point %s (a redirect): not judged" % x)
            elif mt in below and not inner and not ok:
                km5 = True

    if mref:
        row = mref["refused"]
        if expect and row != expect:
            diffs.append("refused %s (%s), planted %s (%s)" % (row, mref["why"], expect,
                                                               case["inject"]))
        elif row == "H-C3" and hdr.get("scope_error") == "EPERM":
            notes.append("refused H-C3 (kernel: EPERM at a redirect, not judged)")
        elif row == "H-C3":
            # The model's reason, as the kernel's errno for it (U16, U18).
            why = mref["why"]
            want = ("ELOOP" if "links" in why else "mount" if "mount" in why else
                    "ENOENT" if "not exist" in why or "empty link" in why else "ENOTDIR")
            # A lookup inside a mount point comes first when the walk meets one, as the
            # model's does; the kernel's own resolution goes on and may fail later.
            got = ("mount" if hdr.get("scope_through_mount") else
                   hdr.get("scope_error", "mount" if kc3 else None))
            if got != want:
                diffs.append("model refused H-C3 (%s); the kernel: %s"
                             % (why, got or "resolved the scope to %s" % kscope))
            else:
                notes.append("refused H-C3, the kernel agrees (%s)" % got)
        elif row == "H-M5" and hdr.get("scope_error") == "EPERM":
            notes.append("refused H-M5 (kernel: EPERM at a redirect, not judged)")
        elif row == "H-M5":
            if kc3:
                diffs.append("model refused H-M5, the kernel's scope fails first")
            elif not km5:
                diffs.append("model refused H-M5 (%s); the kernel holds every mount point"
                             % mref["why"])
            else:
                notes.append("refused H-M5, the kernel agrees")
        elif expect:
            notes.append("refused %s as planted (kernel: not judged)" % row)
        elif row == "H-U5" and redirects:
            notes.append("refused H-U5, a random redirect (kernel: not judged)")
        else:
            diffs.append("refused %s (%s), nothing planted" % (row, mref["why"]))
        return diffs, notes

    if expect:
        diffs.append("listed, but %s was planted (%s)" % (expect, case["inject"]))
    if kc3:
        root = m.get(b".")
        if hdr.get("scope_error") == "EPERM" and root and (root.get("tainted") or
                                                           root.get("scope_tainted")):
            notes.append("kernel EPERM at the scope, where the model followed a redirect")
            notes.append("skipped-tainted %d" % len(m))
        else:
            diffs.append("model listed; the kernel cannot use the scope (%s)"
                         % hdr.get("scope_error", "it is a mount point or below one"))
        return diffs, notes
    if km5:
        diffs.append("model listed; a mount point below the scope is no path of the kernel's view")
    root = m.get(b".")
    if root and root.get("scope") != kscope:
        diffs.append("scope: model %s, kernel %s" % (root.get("scope"), kscope))

    uidmap, gidmap = hdr["uid_map"], hdr["gid_map"]
    k, ghosts, errors = {}, [], []
    for r in krecs[1:]:
        if "ghost" in r:
            ghosts.append(r["ghost"])
        elif "error" in r:
            errors.append(r)
        else:
            k[pathkey(r)] = r

    def tainted_or_below(p):
        while True:
            r = m.get(p)
            if r is not None and r.get("tainted"):
                return True
            if p == b"." or b"/" not in p:
                r = m.get(b".")
                return bool(r and r.get("tainted"))
            p = p.rsplit(b"/", 1)[0]

    def child_tainted(p):
        pre = b"" if p == b"." else p + b"/"
        return any(q.startswith(pre) and b"/" not in q[len(pre):] and q != b"." and
                   r.get("tainted") for q, r in m.items())

    skipped = 0
    blind = []      # directories whose listing the kernel refused (U19 / K3)
    for e in errors:
        key = os.fsencode(e["path"])
        if tainted_or_below(key):
            notes.append("kernel %s at %s, where the model followed a redirect"
                         % (e["error"], e["path"]))
        elif e.get("in") == "readdir" and e["error"] == "EPERM" and child_tainted(key):
            notes.append("kernel EPERM listing %s, a directory with a redirected child"
                         % e["path"])
            blind.append(key)
        else:
            diffs.append("kernel %s at %s (%s)" % (e["error"], e["path"], e.get("in", "lstat")))
    for g in ghosts:
        if os.fsencode(g) in m:
            diffs.append("%s: the kernel's readdir lists it but lstat finds nothing; the model "
                         "lists it" % g)
        else:
            notes.append("ghost")
    compared = 0
    def under_blind(p):
        return any(p.startswith(b"" if d == b"." else d + b"/") and p != d for d in blind)

    for key in sorted(set(m) | set(k)):
        if tainted_or_below(key) or under_blind(key):
            skipped += 1
            continue
        if key not in k:
            if not any(os.fsencode(e["path"]) == key for e in errors):
                diffs.append("%s: only in the model" % show(key))
            continue
        if key not in m:
            diffs.append("%s: only in the kernel's view" % show(key))
            continue
        a, b = m[key], k[key]
        compared += 1
        for f in ("type", "mode", "size", "target", "target_b64", "xattrs", "mount", "sha256"):
            if a.get(f) != b.get(f):
                diffs.append("%s: %s model %r, kernel %r" % (show(key), f, a.get(f), b.get(f)))
        if mapid(uidmap, a["uid"]) != b["uid"] or mapid(gidmap, a["gid"]) != b["gid"]:
            diffs.append("%s: owner model %d:%d (mapped %d:%d), kernel %d:%d"
                         % (show(key), a["uid"], a["gid"], mapid(uidmap, a["uid"]),
                            mapid(gidmap, a["gid"]), b["uid"], b["gid"]))
        if "iflags" in b and sorted(set(a["protattr"])) != sorted(b["iflags"]):
            diffs.append("%s: protattr model %r, kernel flags %r"
                         % (show(key), a["protattr"], b["iflags"]))
        if a["type"] == "dir":
            merged = len(a.get("members", [])) > 1
            notes.append("nlink merged=%s kernel=%d" % (merged, b["nlink"]))
    notes.append("compared %d" % compared)
    if skipped:
        notes.append("skipped-tainted %d" % skipped)
    return diffs, notes


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: compare.py MODEL_OUTPUT OTHER_OUTPUT")
    with open(sys.argv[1]) as f:
        a = f.read().splitlines()
    with open(sys.argv[2]) as f:
        b = f.read().splitlines()
    d = compare_outputs(a, b)
    for x in d:
        print(x)
    sys.exit(1 if d else 0)


if __name__ == "__main__":
    main()
