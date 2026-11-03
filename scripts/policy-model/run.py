#!/usr/bin/env python3
"""policy-model's black-box harness: belay's `baseline export` and `verify` against model.py.

For each scenario of gen.py: build the tree in a temporary directory, export the bundle with a
fresh BELAY_STATE_DIR outside the scope, apply the episode, run verify, and compare its stdout
line by line, and its exit code, with the model's. Every disagreement is printed with the
scenario's name and both lines. A coverage gate, as the oracle has: every flag kind and every
refusal must have been both expected and seen at least once.

  python3 -I -B scripts/policy-model/run.py [NAME-SUBSTRING ...]

BELAY_BIN names the binary (default: the repository's bin/belay); PM_WORKDIR the directory the
scenarios are built in (default: /dev/shm when it is a directory, else $TMPDIR); PM_DISKDIR the
one for scenarios built on disk (default: $TMPDIR, else /tmp).

Exit: 0 every line agreed and the gate holds; 1 a disagreement, a self-test failed, or the gate
failed; 3 `belay verify` is not built yet (export was checked; nothing else failed), or
`belay baseline export` is not either.
"""

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


def workroot():
    w = os.environ.get("PM_WORKDIR")
    if w:
        return w
    if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK):
        return "/dev/shm"
    return tempfile.gettempdir()


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


def rewrite_manifest(data, how):
    """The bundle with its manifest member's header rewritten: "v2" (as an earlier release wrote
    it, no source), "container" (a host reader's source) or "other-scope" (the bundle's and its
    manifest's scopes another path). -> (bytes, its manifest's sha256, its source)."""
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
            if how == "v2":
                mh.pop("source")
                mh["belay_manifest"] = 2
            elif how == "other-scope":
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


def run_scenario(sc, rep, cov, state_of_verify):
    root = os.environ.get("PM_DISKDIR") or tempfile.gettempdir() if sc.get("workdir") == "disk" else workroot()
    tmp = tempfile.mkdtemp(prefix="pm-", dir=root)
    try:
        return _run(sc, rep, cov, state_of_verify, tmp)
    finally:
        for dp, dns, fns in os.walk(tmp):
            for n in dns:
                try:
                    os.chmod(os.path.join(dp, n), 0o700, follow_symlinks=False)
                except OSError:
                    pass
        shutil.rmtree(tmp, ignore_errors=True)


def _run(sc, rep, cov, vstate, tmp):
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
    ecode, exp = model.export_expect(scope_real, out_real, spec_raw, excl_b, raw_b)
    if sc["refusal"] and not sc["refusal"].startswith("verify:"):
        cov.exp("refusal " + sc["refusal"])
        if rc == ecode:
            cov.saw("refusal " + sc["refusal"])
    if rc != ecode:
        rep.disagree(sc, "export's exit code", str(ecode) + (" (%s)" % exp if ecode else ""),
                     "%d %s" % (rc, se.strip()))
        return
    if ecode != 0:
        if so:
            rep.disagree(sc, "export refused, yet wrote standard output", "", so.strip())
        return
    with open(out, "rb") as f:
        bundle = f.read()
    digest = hashlib.sha256(bundle).hexdigest()
    want = {"bundle": out, "sha256": digest, "baseline_integrity": exp["integrity"]}
    compare_lines(rep, sc, "export --json", [want], so)
    for p in model.check_bundle(bundle, exp, scope_real):
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
    raw_a, excl_a = snapshot(scope, excludes_after)
    to_id = None
    after_sha = ANY_SHA
    hash_after = model.HASH_BOUND_SPEC if exp["spec"] is not None else model.HASH_DEFAULT
    if to == "check":
        rc_c, _o, err = belay(["check", "--scope", scope], env)
        to_id, mpath = newest_checkpoint(state)
        with open(mpath, "rb") as f:
            after_sha = hashlib.sha256(f.read()).hexdigest()
        hash_after = model.HASH_DEFAULT
    elif to == "trusted":
        belay(["mark", "--scope", scope], env)
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
        cdata, before_sha, before_source = rewrite_manifest(cdata, v["manifest"])
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
    refusal = model.verify_refusal(exp, vspec_raw, vdigest, vdigest_true, excl_a, to == "trusted",
                                   before_source, corrupt=bool(v.get("corrupt")),
                                   other_scope=v.get("manifest") == "other-scope")
    lines = flags = None
    if refusal is None:
        ctx = {"scope": scope_real, "bundle_sha256": vdigest_true, "spec": exp["spec"],
               "before": model.Side(exp["B"], raw_b[b"."]["dev"], excl_b),
               "after": model.Side(model.view(raw_a, hash_after), raw_a[b"."]["dev"], excl_a),
               "bundle_lines": exp["lines"], "outside_scope": exp["outside"],
               "before_sha256": before_sha, "after_sha256": after_sha}
        lines, flags, _recs, _events = model.verify_lines(ctx)
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
    venv = env
    if v.get("tmpdir") == "inside":
        venv = dict(env, TMPDIR=os.path.join(scope, "tmp"))
    rc, so, se = belay(args, venv)
    if rc == 2 and "unknown command" in se:
        vstate["missing"] = True
        print("belay verify is not built yet (%s): export checked, verify pending" % se.strip())
        return
    vstate["ran"] = vstate.get("ran", 0) + 1
    if sc["refusal"] and sc["refusal"].startswith("verify:") and rc == ecode_v:
        cov.saw("refusal " + sc["refusal"])
    if rc != ecode_v:
        rep.disagree(sc, "verify's exit code", str(ecode_v), "%d %s" % (rc, se.strip()[:400]))
    if lines is None:
        if so:
            rep.disagree(sc, "verify refused, yet wrote standard output", "", so.strip()[:400])
        return
    ap = compare_lines(rep, sc, "verify", lines, so)
    for a in ap:
        d = dict((k, val) for k, val in a) if a and isinstance(a[0], list) else {}
        if "flag" in d:
            cov.saw("flag " + str(d["flag"]))
            if d["flag"] in ("package_changed", "tampered_installed_package"):
                cov.saw("flag %s %s" % (d["flag"], d.get("level")))


def gate(cov, verify_ran):
    required = ["flag " + k for k in model.KINDS if k != "writes_outside_workdir"]
    required += ["flag %s %s" % (k, l) for k in ("package_changed", "tampered_installed_package")
                 for l in ("violation", "signal")]
    required += ["at_reset " + a for a in ("mismatch", "missing", "not_a_file", "unverified", "no_hash")]
    required += sorted(k for k in cov.expected if k.startswith("refusal "))
    bad = []
    for k in required:
        e, s = cov.expected.get(k, 0), cov.seen.get(k, 0)
        verify_side = k.startswith("flag ") or k.startswith("refusal verify:")
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
    bad = gate(cov, not vstate.get("missing")) if not argv else []
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
