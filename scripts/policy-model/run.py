#!/usr/bin/env python3
"""policy-model's black-box harness: belay's `baseline export` and `verify` against model.py.

For each scenario of gen.py: build the tree in a temporary directory, export the bundle with a
fresh BELAY_STATE_DIR outside the scope, apply the episode, run verify, and compare its stdout
line by line, and its exit code, with the model's. Every disagreement is printed with the
scenario's name and both lines. A coverage gate, as the oracle has: every flag kind and every
refusal must have been both expected and seen at least once, and each shape of a `writer_open`
entry (manifest v4) on a protected path.

A concurrent writer is real: the harness holds the scenario's files open for writing, or mapped
shared-writable, across the capture. For those scenarios it also takes
a `check` on each side and compares `belay diff --json`'s records and trailer with the model's,
since policy.v1 does not show what V4-D2 and V4-D5 pin.

  python3 -I -B scripts/policy-model/run.py [NAME-SUBSTRING ...]

BELAY_BIN names the binary (default: the repository's bin/belay); PM_WORKDIR the directory the
scenarios are built in (default: /dev/shm when it is a directory, else $TMPDIR); PM_DISKDIR the
one for scenarios built on disk (default: $TMPDIR, else /tmp).

Exit: 0 every line agreed and the gate holds; 1 a disagreement, a self-test failed, or the gate
failed; 3 `belay verify` is not built yet (export was checked; nothing else failed), or
`belay baseline export` is not either.
"""

import base64
import ctypes
import difflib
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gen      # noqa: E402
import model    # noqa: E402
import selftest  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
BIN = os.environ.get("BELAY_BIN") or os.path.join(REPO, "bin", "belay")
READ_LIMIT = 256 * 1024 * 1024
ANY_SHA = "<any sha256: verify keeps no copy of its capture>"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
F_SETLEASE = 1024
F_RDLCK = 0
F_UNLCK = 2
WRITER_SHAPES = ("before only", "after only", "both sides", "one side, before", "one side, after")


def workroot():
    w = os.environ.get("PM_WORKDIR")
    if w:
        return w
    if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK):
        return "/dev/shm"
    return tempfile.gettempdir()


# ---------------------------------------------------------------------------------------------
# A concurrent writer

class Writers:
    """Files held open for writing, or mapped shared-writable with the descriptor closed, until
    release(). `names`: a path, or (path, "mmap"). No byte is written: holding is the whole act,
    and the stat of the file does not move. `inodes`: what the model is told was held."""

    def __init__(self, scope, names):
        self.fds = []
        self.maps = []
        self.inodes = set()
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mmap.restype = ctypes.c_void_p
        libc.mmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int,
                              ctypes.c_int, ctypes.c_long)
        libc.munmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
        self.libc = libc
        for n in names:
            path, how = n if isinstance(n, tuple) else (n, "fd")
            fd = os.open(os.path.join(os.fsencode(scope), gen._b(path)), os.O_WRONLY | os.O_CLOEXEC)
            st = os.fstat(fd)
            self.inodes.add((st.st_dev, st.st_ino))
            if how == "fd":
                self.fds.append(fd)
                continue
            os.close(fd)
            fd = os.open(os.path.join(os.fsencode(scope), gen._b(path)), os.O_RDWR | os.O_CLOEXEC)
            addr = libc.mmap(None, st.st_size, 3, 1, fd, 0)      # PROT_READ|PROT_WRITE, MAP_SHARED
            os.close(fd)
            if addr in (None, ctypes.c_void_p(-1).value):
                raise OSError(ctypes.get_errno(), "mmap of %r" % (path,))
            self.maps.append((addr, st.st_size))

    def release(self):
        for fd in self.fds:
            os.close(fd)
        for addr, size in self.maps:
            self.libc.munmap(addr, size)
        self.fds, self.maps = [], []


def probe_answers(root):
    """V4-4: whether a file the user owns under `root` gets an answer from the lease probe. Asked
    of a file of the harness's own, so that a scenario's expectation need not come from belay."""
    fd, path = tempfile.mkstemp(prefix="pm-probe-", dir=root)
    os.close(fd)
    try:
        kind = subprocess.run(["stat", "-f", "-c", "%T", path], capture_output=True, text=True).stdout.strip()
        if kind == "overlayfs":
            return False
        fd = os.open(path, os.O_RDONLY)
        try:
            fcntl.fcntl(fd, F_SETLEASE, F_RDLCK)
            fcntl.fcntl(fd, F_SETLEASE, F_UNLCK)
            return True
        except OSError:
            return False
        finally:
            os.close(fd)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------------------------
# Measuring the tree (lstat and read, never belay)

TYPES = {stat.S_IFREG: "reg", stat.S_IFDIR: "dir", stat.S_IFLNK: "lnk", stat.S_IFIFO: "fifo",
         stat.S_IFSOCK: "sock", stat.S_IFBLK: "blk", stat.S_IFCHR: "chr"}


def measure(full, st):
    t = TYPES[stat.S_IFMT(st.st_mode)]
    e = {"type": t, "mode": st.st_mode, "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size,
         "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns, "ino": st.st_ino, "dev": st.st_dev,
         "nlink": st.st_nlink, "iflags": None, "caps": None, "xattrs": None, "xattrs_unknown": False,
         "readable": True, "data": None, "link_target": None, "rdev": None}
    if t == "lnk":
        e["link_target"] = os.readlink(full)
    if t in ("blk", "chr"):
        e["rdev"] = st.st_rdev
    if t in ("reg", "dir"):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        if t == "dir":
            flags |= os.O_DIRECTORY
        try:
            fd = os.open(full, flags)
        except PermissionError:
            fd = None
            e["readable"] = False
        if fd is not None:
            try:
                buf = bytearray(8)
                try:
                    fcntl.ioctl(fd, gen.FS_IOC_GETFLAGS, buf, True)
                    e["iflags"] = int.from_bytes(buf[:4], "little")
                except OSError:
                    pass
                if t == "reg" and st.st_size <= READ_LIMIT:
                    chunks = []
                    while True:
                        c = os.read(fd, 1 << 20)
                        if not c:
                            break
                        chunks.append(c)
                    e["data"] = b"".join(chunks)
            finally:
                os.close(fd)
    try:
        names = os.listxattr(full, follow_symlinks=False)
        xs = []
        for n in sorted(names, key=lambda s: s.encode()):
            v = os.getxattr(full, n, follow_symlinks=False)
            if n == "security.capability":
                e["caps"] = v.hex()
            else:
                xs.append("%s=%s" % (n, hashlib.sha256(v).hexdigest()))
        e["xattrs"] = tuple(xs) if xs else None
    except OSError:
        e["xattrs_unknown"] = True
    return e


def snapshot(scope, excludes):
    ex = set(x if isinstance(x, bytes) else x.encode() for x in excludes)
    raw = {}
    excluded = []

    def visit(rel, full):
        st = os.lstat(full)
        e = measure(full, st)
        raw[rel] = e
        if e["type"] == "dir" and e["readable"]:
            for name in sorted(os.listdir(full)):
                crel = name if rel == b"." else rel + b"/" + name
                cfull = os.path.join(full, name)
                if crel in ex:
                    cst = os.lstat(cfull)
                    excluded.append({"path": crel, "reason": "user", "dev": cst.st_dev, "ino": cst.st_ino})
                    continue
                visit(crel, cfull)

    visit(b".", os.fsencode(scope))
    excluded.sort(key=lambda x: x["path"])
    return raw, excluded


# ---------------------------------------------------------------------------------------------
# Comparing

def pairs(line):
    return json.loads(line, object_pairs_hook=lambda ps: [list(p) for p in ps])


def canon(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def fill_wildcards(mp, ap):
    """The model's ANY_SHA takes belay's value when that is 64 hex digits."""
    if isinstance(mp, list) and isinstance(ap, list):
        if len(mp) == 2 and isinstance(mp[0], str) and mp[1] == ANY_SHA:
            return mp
        out = []
        for i, m in enumerate(mp):
            if (isinstance(m, list) and len(m) == 2 and m[1] == ANY_SHA and i < len(ap)
                    and isinstance(ap[i], list) and len(ap[i]) == 2 and ap[i][0] == m[0]
                    and isinstance(ap[i][1], str) and HEX64.match(ap[i][1])):
                out.append([m[0], ap[i][1]])
            else:
                out.append(m)
        return out
    return mp


class Report:
    def __init__(self):
        self.disagreements = 0
        self.notes = []

    def disagree(self, sc, what, model_line, belay_line):
        self.disagreements += 1
        tags = sc.get("tags") or []
        print("DISAGREE %s: %s%s" % (sc["name"], what, (" [rests on %s]" % ", ".join(tags)) if tags else ""))
        if model_line is not None:
            print("  model: %s" % model_line)
        if belay_line is not None:
            print("  belay: %s" % belay_line)


def compare_lines(rep, sc, what, model_objs, stdout):
    act = stdout.split("\n")
    if act and act[-1] == "":
        act.pop()
    else:
        if act:
            rep.disagree(sc, what + ": output does not end in a newline", None, act[-1])
    mp = [pairs(model.enc(o)) for o in model_objs]
    ap = []
    for ln in act:
        try:
            ap.append(pairs(ln))
        except ValueError:
            ap.append(["<not JSON>", ln])
    # header and trailer by position, so wildcards fill in; flags as a sequence
    if mp and ap:
        mp[-1] = fill_wildcards(mp[-1], ap[-1])
    ms = [canon(x) for x in mp]
    as_ = [canon(x) for x in ap]
    sm = difflib.SequenceMatcher(a=ms, b=as_, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        n = max(i2 - i1, j2 - j1)
        for k in range(n):
            m = ms[i1 + k] if i1 + k < i2 else None
            a = as_[j1 + k] if j1 + k < j2 else None
            label = "line %d" % (j1 + k + 1 if a is not None else i1 + k + 1)
            if m is None:
                label += ", belay only"
            elif a is None:
                label += ", model only"
            rep.disagree(sc, "%s %s" % (what, label), m, a)
    return ap


# ---------------------------------------------------------------------------------------------
# Running belay

def belay(args, env, timeout=900):
    p = subprocess.run([BIN] + args, env=env, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout.decode("utf-8", errors="surrogateescape"), \
        p.stderr.decode("utf-8", errors="surrogateescape")


def newest_checkpoint(state):
    best = None
    sd = os.path.join(state, "scopes")
    for s in os.listdir(sd) if os.path.isdir(sd) else []:
        cd = os.path.join(sd, s, "checkpoints")
        for c in os.listdir(cd) if os.path.isdir(cd) else []:
            if c.isdigit() and (best is None or int(c) > best[0]):
                best = (int(c), os.path.join(cd, c, "manifest.ndjson"))
    return best


def corrupt_bundle(data, how):
    if how == "trailing":
        return data + b"x"
    if how == "unknown-key":
        nl = data.index(b"\n")
        hdr = json.loads(data[:nl])
        hdr2 = dict(list(hdr.items())[:2] + [("extra", 1)] + list(hdr.items())[2:])
        return model.enc(hdr2).encode() + data[nl:]
    if how == "short":
        return data[:-1]
    raise ValueError(how)


def rewrite_manifest(data, how, flags=None):
    """The bundle with its manifest member rewritten: "v2" or "v3" (as an earlier release wrote
    it), "container" (a host reader's source), "other-scope" (the bundle's and its manifest's
    scopes another path), "flags" (these entries flagged, `flags` as model.flag_manifest takes it)
    "unguarded-max" (model.unguarded_at_most) or "break:<how>" (model.break_manifest). -> (bytes, its manifest's sha256, its source)."""
    out = []
    pos = 0
    msha = source = None
    while pos < len(data):
        nl = data.index(b"\n", pos)
        hdr = json.loads(data[pos:nl])
        content = data[nl + 1:nl + 1 + hdr["size"]]
        pos = nl + 1 + hdr["size"]
        if how == "other-scope" and "belay_bundle" in hdr:
            hdr["scopes"] = [hdr["scopes"][0] + "-other"]
        if hdr.get("member") == "manifest":
            first, rest = content.split(b"\n", 1)
            mh = json.loads(first)
            if how in ("v2", "v3"):
                content = model.downgrade_manifest(content, int(how[1]))
            elif how == "unguarded-max":
                content = model.unguarded_at_most(content)
            elif how == "flags":
                content = model.flag_manifest(content, flags)
            elif how.startswith("break:"):
                content = model.break_manifest(content, how[len("break:"):])
            else:
                if how == "other-scope":
                    mh["scopes"] = [mh["scopes"][0] + "-other"]
                else:
                    mh["source"] = source = {"docker": "4f1c" * 16, "image": "sha256:" + "91ef" * 16}
                content = model.enc(mh).encode() + b"\n" + rest
            msha = hashlib.sha256(content).hexdigest()
            hdr = {"member": "manifest", "size": len(content), "sha256": msha}
        out.append(model.enc(hdr).encode() + b"\n" + content)
    return b"".join(out), msha, source


def spec_bytes(spec):
    if spec is None:
        return None
    if isinstance(spec, bytes):
        return spec
    return json.dumps(spec).encode()


class Coverage:
    def __init__(self):
        self.expected = {}
        self.seen = {}

    def exp(self, key):
        self.expected[key] = self.expected.get(key, 0) + 1

    def saw(self, key):
        self.seen[key] = self.seen.get(key, 0) + 1


def writer_shape(p, B, A):
    """Which of WRITER_SHAPES a path marked in these manifests has, or None."""
    b, a = B.get(p), A.get(p)
    mb, ma = b is not None and b["writer_open"], a is not None and a["writer_open"]
    if a is None:
        return "one side, before" if mb else None
    if b is None:
        return "one side, after" if ma else None
    return "both sides" if mb and ma else "before only" if mb else "after only" if ma else None


def writer_keys(flags, B, A):
    """path -> the coverage key of a protected_path_unverifiable the marks gave."""
    out = {}
    for f in flags:
        d = dict(f.fields)
        if f.kind == "protected_path_unverifiable" and "writer_open" in d["reasons"]:
            shape = writer_shape(d["path"], B, A)
            if shape is not None:
                out[d["path"]] = "writer_open %s%s" % (shape, ", with another reason" if len(d["reasons"]) > 1 else "")
    return out


def path_of(d):
    return base64.b64decode(d["path_b64"]) if "path_b64" in d else d.get("path", "").encode()


def check_diff(rep, sc, env, scope, since, to, recs, B, A, unguarded):
    """`belay diff --json` against the model: V4-D1..D3's records, V4-D5's trailer."""
    rc, so, se = belay(["diff", "--scope", scope, "--since", str(since), "--to", str(to), "--json", "--all"], env)
    if rc != 0:
        rep.disagree(sc, "diff's exit code", "0", "%d %s" % (rc, se.strip()[:400]))
        return
    lines = [json.loads(ln) for ln in so.splitlines()]
    got = {}
    for d in lines[1:-1]:
        if "outcome" in d:
            got[path_of(d)] = d
    for p in sorted(set(got) | set(recs)):
        d, m = got.get(p), recs.get(p)
        if m is None or d is None:
            if not (d is not None and d.get("outcome") == "unchanged"):
                rep.disagree(sc, "diff: a record on one side only, %r" % (p,), m, d)
            continue
        want = {k: m[k] for k in ("outcome", "type", "type_before", "changed", "unknown") if k in m}
        have = {k: d[k] for k in ("outcome", "type", "type_before", "changed", "unknown") if k in d}
        if want != have:
            rep.disagree(sc, "diff: the record of %r" % (p,), canon(want), canon(have))
        if "writer_open" in m.get("unknown", ()):
            for side in ("before", "after"):
                if "sha256" in d.get(side, {}):
                    rep.disagree(sc, "diff: V4-D2, a %s value carries sha256 at %r" % (side, p), None, canon(d))
                if "type_before" not in m and not set(d.get(side, {})) <= set(m.get("changed", ())):
                    rep.disagree(sc, "diff: a %s value `changed` does not name at %r" % (side, p), None, canon(d))
    tr = lines[-1]
    want = [("before_writer_open", sum(1 for e in B.values() if e["writer_open"])),
            ("after_writer_open", sum(1 for e in A.values() if e["writer_open"])),
            ("before_unguarded", unguarded[0]), ("after_unguarded", unguarded[1])]
    keys = list(tr)
    if keys[-5:-4] != ["after_sha256"] or [(k, tr[k]) for k in keys[-4:]] != want:
        rep.disagree(sc, "diff: V4-D5, the trailer ends", canon(want), canon(list(tr.items())[-5:]))
    if tr.get("provisional") is not False:
        rep.disagree(sc, "diff: V4-D6, provisional", "false", canon(tr.get("provisional")))


def run_scenario(sc, rep, cov, state_of_verify):
    root = os.environ.get("PM_DISKDIR") or tempfile.gettempdir() if sc.get("workdir") == "disk" else workroot()
    if root not in ANSWERED:
        ANSWERED[root] = probe_answers(root)
    if sc["writers"] != ([], []) and not ANSWERED[root]:
        rep.notes.append("%s: skipped, the writer probe does not answer on %s" % (sc["name"], root))
        state_of_verify["no_probe"] = True
        return None
    tmp = tempfile.mkdtemp(prefix="pm-", dir=root)
    holds = []
    try:
        return _run(sc, rep, cov, state_of_verify, tmp, ANSWERED[root], holds)
    finally:
        for h in holds:
            h.release()
        for dp, dns, fns in os.walk(tmp):
            for n in dns:
                try:
                    os.chmod(os.path.join(dp, n), 0o700, follow_symlinks=False)
                except OSError:
                    pass
        shutil.rmtree(tmp, ignore_errors=True)


ANSWERED = {}


def _run(sc, rep, cov, vstate, tmp, answered, holds):
    scope = os.path.join(tmp, "scope")
    state = os.path.join(tmp, "state")
    vtmp = os.path.join(tmp, "vtmp")
    outdir = os.path.join(tmp, "out")
    for d in (scope, state, vtmp, outdir):
        os.mkdir(d, 0o700 if d != scope else 0o755)
    os.chmod(scope, 0o755)
    scope_real = os.path.realpath(scope)
    env = dict(os.environ, BELAY_STATE_DIR=state, TMPDIR=vtmp)
    gen.apply(scope, sc["tree"])
    for x in sc["excludes"]:
        rc, _o, err = belay(["exclude", "--scope", scope, "--add", x], env)
        if rc != 0:
            rep.disagree(sc, "belay exclude --add %s exited %d" % (x, rc), None, err.strip())
            return
    spec_raw = spec_bytes(sc["spec"])
    spec_path = os.path.join(tmp, "spec.json")
    if spec_raw is not None:
        with open(spec_path, "wb") as f:
            f.write(spec_raw)
    hold_b = Writers(scope, sc["writers"][0])
    holds.append(hold_b)
    with_diff = sc["writers"] != ([], []) and not sc["verify"].get("to")
    since = None
    if with_diff:
        belay(["check", "--scope", scope], env)
        since = newest_checkpoint(state)
    raw_b, excl_b = snapshot(scope, sc["excludes"])
    out = os.path.join(scope if sc["out"] == "inside" else outdir, "b.bundle")
    out_real = os.path.join(os.path.realpath(os.path.dirname(out)), "b.bundle")
    args = ["baseline", "export", "--scope", scope, "--out", out]
    if spec_raw is not None:
        args += ["--protect", spec_path]
    args.append("--json")
    rc, so, se = belay(args, env)
    if rc == 2 and "unknown command" in se:
        vstate["no_export"] = True
        return
    hold_b.release()
    ecode, exp = model.export_expect(scope_real, out_real, spec_raw, excl_b, raw_b, hold_b.inodes)
    if sc["refusal"] and not sc["refusal"].startswith("verify:"):
        cov.exp("refusal " + sc["refusal"])
        if rc == ecode:
            cov.saw("refusal " + sc["refusal"])
    if rc != ecode:
        rep.disagree(sc, "export's exit code", str(ecode) + (" (%s)" % exp if ecode else ""),
                     "%d %s" % (rc, se.strip()))
        return
    if spec_raw is not None and model.version_refused(spec_raw) and model.NOT_VERSION_2 not in se:
        rep.disagree(sc, "PV2-1: export's words", model.NOT_VERSION_2, se.strip()[:400])
    if ecode == 4 and model.NO_COPY not in se:
        rep.disagree(sc, "V4-S1: export's words", model.NO_COPY, se.strip()[:400])
    if ecode != 0:
        if so:
            rep.disagree(sc, "export refused, yet wrote standard output", "", so.strip())
        return
    with open(out, "rb") as f:
        bundle = f.read()
    digest = hashlib.sha256(bundle).hexdigest()
    want = {"bundle": out, "sha256": digest, "baseline_integrity": exp["integrity"]}
    compare_lines(rep, sc, "export --json", [want], so)
    guard_b = model.unguarded_count(exp["B"], answered)
    for p in model.check_bundle(bundle, exp, scope_real, guard_b):
        rep.disagree(sc, "the bundle: " + p, None, None)
    for l in exp["integrity"]:
        cov.exp("at_reset " + l["at_reset"])
    try:
        for l in json.loads(so.split("\n")[0]).get("baseline_integrity", []):
            cov.saw("at_reset " + l.get("at_reset"))
    except (ValueError, AttributeError):
        pass

    # the episode
    gen.apply(scope, sc["episode"])
    v = sc["verify"]
    to = v.get("to")
    excludes_after = model.after_excludes(excl_b, list(sc["excludes"]) + list(v.get("excludes_add", [])), to)
    for x in v.get("excludes_add", []):
        belay(["exclude", "--scope", scope, "--add", x], env)
    hold_a = Writers(scope, sc["writers"][1])
    holds.append(hold_a)
    raw_a, excl_a = snapshot(scope, excludes_after)
    to_id = None
    after_sha = ANY_SHA
    hash_after = model.HASH_BOUND_SPEC if exp["spec"] is not None else model.HASH_DEFAULT
    if to == "check":
        rc_c, _o, err = belay(["check", "--scope", scope], env)
        to_id, mpath = newest_checkpoint(state)
        with open(mpath, "rb") as f:
            cdata_after = f.read()
        if v.get("after_flags"):
            cdata_after = model.flag_manifest(cdata_after, v["after_flags"])
            with open(mpath, "wb") as f:
                f.write(cdata_after)
        after_sha = hashlib.sha256(cdata_after).hexdigest()
        hash_after = model.HASH_DEFAULT
    elif to == "trusted":
        belay(["mark", "--scope", scope], env)
        if v.get("mark_writers") == "first":       # V4-R6: the second mark reads it again
            hold_a.release()
            hold_a.inodes = set()
        belay(["mark", "--scope", scope], env)
        to_id, mpath = newest_checkpoint(state)
        with open(mpath, "rb") as f:
            trailer = json.loads(f.read().rstrip(b"\n").rsplit(b"\n", 1)[-1])
        if not trailer.get("trusted"):
            rep.notes.append("%s: the second mark trusted no file, so its premise does not hold" % sc["name"])
    vbundle, vdigest_true = out, digest
    before_sha, before_source = exp["manifest_sha256"], None
    cdata = bundle
    if v.get("manifest"):
        cdata, before_sha, before_source = rewrite_manifest(cdata, v["manifest"], v.get("flags"))
    if v.get("flags"):
        model.apply_flags(exp["B"], v["flags"])
    if v.get("corrupt"):
        cdata = corrupt_bundle(cdata, v["corrupt"])
    if cdata is not bundle:
        vbundle = os.path.join(outdir, "altered.bundle")
        with open(vbundle, "wb") as f:
            f.write(cdata)
        vdigest_true = hashlib.sha256(cdata).hexdigest()
    digest_mode = v.get("digest", "right")
    vdigest = {"right": vdigest_true, "wrong": hashlib.sha256(b"not the bundle").hexdigest(),
               "missing": None}[digest_mode]
    vspec = v.get("spec", "same")
    vspec_raw = spec_raw if vspec == "same" else spec_bytes(vspec)
    args = ["verify", "--scope", scope, "--baseline", vbundle]
    if vdigest is not None:
        args += ["--baseline-sha256", vdigest]
    if vspec_raw is not None:
        vspec_path = spec_path if vspec == "same" else os.path.join(tmp, "spec-verify.json")
        if vspec != "same":
            with open(vspec_path, "wb") as f:
                f.write(vspec_raw)
        args += ["--protect", vspec_path]
    if to_id is not None:
        args += ["--to", str(to_id)]
    if v.get("exit_code", True):
        args.append("--exit-code")

    if v.get("tmpdir") == "inside":         # verify's own state directory, name unknown, below tmp/
        excl_a = excl_a + [{"path": b"tmp/<verify's own state directory>", "reason": "state_dir",
                            "dev": 0, "ino": 0}]

    # the model's expectation, built whether verify exists or not
    A = model.view(raw_a, hash_after, hold_a.inodes)
    model.apply_flags(A, v.get("after_flags", {}))
    refusal = model.verify_refusal(exp, vspec_raw, vdigest, vdigest_true, excl_a, to == "trusted",
                                   before_source,
                                   corrupt=bool(v.get("corrupt")) or str(v.get("manifest")).startswith("break:"),
                                   other_scope=v.get("manifest") == "other-scope", after=A)
    lines = flags = None
    wkeys = {}
    if refusal is None:
        ctx = {"scope": scope_real, "bundle_sha256": vdigest_true, "spec": exp["spec"],
               "before": model.Side(exp["B"], raw_b[b"."]["dev"], excl_b),
               "after": model.Side(A, raw_a[b"."]["dev"], excl_a),
               "bundle_lines": exp["lines"], "outside_scope": exp["outside"],
               "before_sha256": before_sha, "after_sha256": after_sha,
               "walk_counts": (0, 0, sum(1 for e in exp["B"].values() if e["raced"]),      # V4-D6
                               0, 0, sum(1 for e in A.values() if e["raced"]))}
        lines, flags, _recs, _events = model.verify_lines(ctx)
        wkeys = writer_keys(flags, exp["B"], A)
        for k in wkeys.values():
            cov.exp(k)
        ecode_v = model.verify_exit(flags, v.get("exit_code", True))
        for f in flags:
            cov.exp("flag " + f.kind)
            if f.kind in ("package_changed", "tampered_installed_package"):
                cov.exp("flag %s %s" % (f.kind, f.level))
    else:
        ecode_v = refusal
    if sc["refusal"] and sc["refusal"].startswith("verify:"):
        cov.exp("refusal " + sc["refusal"])
    if vstate.get("missing"):
        return
    if with_diff:
        belay(["check", "--scope", scope], env)
        to_cp = newest_checkpoint(state)
    venv = env
    if v.get("tmpdir") == "inside":
        venv = dict(env, TMPDIR=os.path.join(scope, "tmp"))
    rc, so, se = belay(args, venv)
    if with_diff and to_cp[1] is not None:
        hb = model.view(raw_b, model.HASH_DEFAULT, hold_b.inodes)
        ha = model.view(raw_a, model.HASH_DEFAULT, hold_a.inodes)
        ug = (model.unguarded_count(hb, answered), model.unguarded_count(ha, answered))
        for what, cp, want, n in (("before", since, hb, ug[0]), ("after", to_cp, ha, ug[1])):
            with open(cp[1], "rb") as f:
                for p in model.manifest_problems(f.read(), want, n):
                    rep.disagree(sc, "the checkpoint %s: %s" % (what, p), None, None)
        hold_a.release()
        recs = model.diff(model.Side(hb, raw_b[b"."]["dev"], excl_b), model.Side(ha, raw_a[b"."]["dev"], excl_a))
        check_diff(rep, sc, env, scope, since[0], to_cp[0], recs, hb, ha, ug)
    if rc == 2 and "unknown command" in se:
        vstate["missing"] = True
        print("belay verify is not built yet (%s): export checked, verify pending" % se.strip())
        return
    vstate["ran"] = vstate.get("ran", 0) + 1
    if sc["refusal"] and sc["refusal"].startswith("verify:") and rc == ecode_v:
        cov.saw("refusal " + sc["refusal"])
    if rc != ecode_v:
        rep.disagree(sc, "verify's exit code", str(ecode_v), "%d %s" % (rc, se.strip()[:400]))
    if vspec_raw is not None and model.version_refused(vspec_raw) and model.NOT_VERSION_2 not in se:
        rep.disagree(sc, "PV2-1: verify's words", model.NOT_VERSION_2, se.strip()[:400])
    if refusal == 4 and model.database_without_copy(A) is not None and model.NO_COPY not in se:
        rep.disagree(sc, "V4-S1: verify's words", model.NO_COPY, se.strip()[:400])
    if lines is None:
        if so:
            rep.disagree(sc, "verify refused, yet wrote standard output", "", so.strip()[:400])
        return
    ap = compare_lines(rep, sc, "verify", lines, so)
    for a in ap:
        d = dict((k, val) for k, val in a) if a and isinstance(a[0], list) else {}
        if "flag" in d:
            cov.saw("flag " + str(d["flag"]))
            key = wkeys.get(path_of(d)) if d["flag"] == "protected_path_unverifiable" else None
            if key is not None and "writer_open" in d.get("reasons", []):
                cov.saw(key)
            if d["flag"] in ("package_changed", "tampered_installed_package"):
                cov.saw("flag %s %s" % (d["flag"], d.get("level")))


def gate(cov, verify_ran, probe):
    required = ["flag " + k for k in model.KINDS if k != "writes_outside_workdir"]
    required += ["flag %s %s" % (k, l) for k in ("package_changed", "tampered_installed_package")
                 for l in ("violation", "signal")]
    required += ["at_reset " + a for a in ("mismatch", "missing", "not_a_file", "unverified", "no_hash")]
    required += sorted(k for k in cov.expected if k.startswith("refusal "))
    if probe:
        required += ["writer_open %s%s" % (s, x) for s in WRITER_SHAPES for x in ("", ", with another reason")]
    bad = []
    for k in required:
        e, s = cov.expected.get(k, 0), cov.seen.get(k, 0)
        verify_side = k.startswith(("flag ", "refusal verify:", "writer_open "))
        if e == 0:
            bad.append("%s: never expected" % k)
        elif s == 0 and (verify_ran or not verify_side):
            bad.append("%s: expected %d times, never seen" % (k, e))
    print("coverage (expected / seen by belay):")
    for k in required:
        print("  %-52s %4d / %d" % (k, cov.expected.get(k, 0), cov.seen.get(k, 0)))
    return bad


def main(argv):
    fails = selftest.run()
    if fails:
        print("self-tests: %d failed" % fails)
        return 1
    print("self-tests: passed")
    if not os.access(BIN, os.X_OK):
        print("no binary at %s (make bin/belay, or set BELAY_BIN)" % BIN)
        return 1
    scs = [s for s in gen.scenarios() if not argv or any(a in s["name"] for a in argv)]
    rep = Report()
    cov = Coverage()
    vstate = {}
    for sc in scs:
        run_scenario(sc, rep, cov, vstate)
        if vstate.get("no_export"):
            print("belay baseline export is not built in %s: nothing to compare yet (exit 3)" % BIN)
            return 3
    for n in rep.notes:
        print("note: " + n)
    print("%d scenarios; %d verified end to end; %d disagreements" % (len(scs), vstate.get("ran", 0),
                                                                    rep.disagreements))
    bad = gate(cov, not vstate.get("missing"), not vstate.get("no_probe")) if not argv else []
    for b in bad:
        print("GATE " + b)
    if rep.disagreements or bad:
        return 1
    if vstate.get("missing"):
        print("verify pending: exit 3")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
