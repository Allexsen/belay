#!/usr/bin/env python3
"""Vendors a belay binary into pybelay (PY-D4) and records the key sets of
every fixed line its formats print -- checkpoint.v1, diff.v1's header and
trailer, policy.v1's header and trailer, export's result -- by running that
binary once on a small tree. A header or trailer has no optional key, and the
wheel ships the binary of its own release, so these are the keys pybelay's
strict parse requires, exactly and in order (PY-F*).

    build_keys.py BELAY_BINARY [VENDORED_BINARY]

The key sets are read from BELAY_BINARY (it must run here); VENDORED_BINARY,
when given, is the one the wheel carries (another platform's, of the same
release). The version, from BELAY_BINARY --version, goes to _version.py in
PEP 440 (PY-D2: v0.1.0-alpha.3 is 0.1.0a3; a development build's description
is a local version, 0.1.0-alpha.2+95-ga2054b3-dirty is 0.1.0a2+95.ga2054b3.dirty,
and +unknown stays +unknown).
"""
import hashlib, json, os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def run(b, *a, env):
    r = subprocess.run([b] + list(a), capture_output=True, text=True, env=env)
    if r.returncode not in (0, 1):
        sys.exit("build_keys: %s %s: exit %d: %s" % (b, " ".join(a), r.returncode, r.stderr))
    return [json.loads(l) for l in r.stdout.splitlines() if l.strip()]


def pep440(ver):
    """belay's version as PEP 440 spells it (PY-D2), or exit naming it."""
    m = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)\.?(\d*))?"
                     r"(?:\+(?:(\d+)-g([0-9a-f]+)(-dirty)?|(unknown)))?", ver)
    if m is None:
        sys.exit("build_keys: a version PEP 440 cannot spell: %s" % ver)
    pep = m.group(1) + ({"alpha": "a", "beta": "b", "rc": "rc"}[m.group(2)] + (m.group(3) or "0") if m.group(2) else "")
    if m.group(4) is not None:      # a development build (PY-D2): a local version
        pep += "+%s.g%s%s" % (m.group(4), m.group(5), ".dirty" if m.group(6) else "")
    elif m.group(7) is not None:
        pep += "+unknown"
    return pep


def main():
    src = os.path.abspath(sys.argv[1])
    ven = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else src
    dst = os.path.join(HERE, "pybelay", "_bin")
    os.makedirs(dst, exist_ok=True)
    shutil.copy2(ven, os.path.join(dst, "belay"))
    os.chmod(os.path.join(dst, "belay"), 0o755)
    with open(ven, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    ver = subprocess.run([src, "--version"], capture_output=True, text=True).stdout.split()[1]
    pep = pep440(ver)
    with open(os.path.join(HERE, "pybelay", "_version.py"), "w") as f:
        f.write("__version__ = %r\n" % pep)
    with open(os.path.join(dst, "SHA256"), "w") as f:
        f.write(digest + "\n")
    t = tempfile.mkdtemp(prefix="pybelay-keys-")
    try:
        env = dict(os.environ, BELAY_STATE_DIR=os.path.join(t, "state"))
        sc = os.path.join(t, "scope")
        os.makedirs(os.path.join(sc, "tests"))
        with open(os.path.join(sc, "tests", "test_a.py"), "w") as f:
            f.write("def test_a():\n    assert 1\n")
        cp = run(src, "check", "--scope", sc, "--json", env=env)[0]
        exp = run(src, "baseline", "export", "--scope", sc, "--out", os.path.join(t, "b"), "--json", env=env)[0]
        with open(os.path.join(sc, "tests", "test_a.py"), "w") as f:
            f.write("def test_a():\n    pass\n")
        diff = run(src, "diff", "--scope", sc, "--since", "1", "--json", env=env)
        pol = run(src, "verify", "--scope", sc, "--baseline", os.path.join(t, "b"),
                  "--baseline-sha256", exp["sha256"], env=env)
        keys = {"checkpoint": list(cp), "export": list(exp), "diff_header": list(diff[0]),
                "diff_trailer": list(diff[-1]), "policy_header": list(pol[0]), "policy_trailer": list(pol[-1]),
                "prefilter": list(cp["prefilter"]), "binary_sha256": digest}
    finally:
        shutil.rmtree(t, ignore_errors=True)
    with open(os.path.join(HERE, "pybelay", "_keys.json"), "w") as f:
        json.dump(keys, f, indent=1)
    print("pybelay: vendored %s (sha256 %s), key sets recorded" % (src, digest[:12]))


if __name__ == "__main__":
    main()
