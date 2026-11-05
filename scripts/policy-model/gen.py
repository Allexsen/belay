"""policy-model scenarios: a scope built at reset, an optional protect spec, package databases
inside the tree, and the episode's changes, applied after the bundle is exported.

A scenario is a dict:
  name       unique
  tags       the model's ambiguities (P<n>) its expectation rests on: a disagreement there may be
             the pin's two readings rather than a bug
  tree       ops building the scope at reset
  spec       None, a dict (written as JSON), or raw bytes
  excludes   paths `belay exclude --add` configures before the export
  out        "outside" (default) or "inside" the scope
  episode    ops applied after the export
  verify     options: exit_code (default True), spec ("same", None, dict or bytes), digest
             ("right", "wrong", "missing"), to (None, "check", "trusted"), excludes_add,
             corrupt (None, "trailing", "unknown-key", "short"), manifest ("v2": the bundle's
             manifest rewritten as an earlier release wrote it; "container": with a host
             reader's source; "v3": as v2, keeping `source`; "flags": the entries `flags` names
             given those flags; "break:<how>": a manifest V4-R2 or V4-R3 refuses), flags (path ->
             flag names), after_flags (the same, on a `to: check` checkpoint's manifest),
             mark_writers ("first": with `to: trusted`, the hold ends before the second mark;
             "both": it does not), tmpdir ("inside": verify's $TMPDIR, where it makes its own
             state directory, is the scope's `tmp`)
  refusal    the refusal label it exercises (coverage), if any
  workdir    "disk": built on the disk's temporary directory (ext4 here) rather than PM_WORKDIR,
             for a filesystem that sets its own inode flags on every new file
  writers    (before, after): the files a process holds open for writing across that side's
             capture, each a path, or (path, "mmap") for a shared-writable mapping whose
             descriptor is closed (manifest v4). A hold at export ends before the episode

Ops are tuples; `apply` performs them. Paths are str, or bytes when not UTF-8.
"""

import base64
import fcntl
import hashlib
import os

FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_NODUMP_FL = 0x40

C = ["%040x" % (0x1111111111111111111111111111111111111111 * i) for i in range(1, 6)]


# ---------------------------------------------------------------------------------------------
# Performing ops

def _b(p):
    return p if isinstance(p, bytes) else p.encode("utf-8")


def _mkparents(root, path):
    d = os.path.dirname(os.path.join(root, path))
    if not os.path.isdir(d):
        os.makedirs(d, mode=0o755)


def other_gid():
    for g in os.getgroups():
        if g != os.getgid():
            return g
    return None


def apply(root, ops):
    root = _b(root)
    for op in ops:
        k = op[0]
        p = os.path.join(root, _b(op[1])) if len(op) > 1 else None
        if k == "file":
            _mkparents(root, _b(op[1]))
            with open(p, "wb") as f:
                f.write(op[2])
            os.chmod(p, op[3] if len(op) > 3 else 0o644)
        elif k == "dir":
            os.makedirs(p, mode=0o755, exist_ok=True)
            os.chmod(p, op[2] if len(op) > 2 else 0o755)
        elif k == "symlink":
            _mkparents(root, _b(op[1]))
            os.symlink(_b(op[2]), p)
        elif k == "hardlink":
            _mkparents(root, _b(op[1]))
            os.link(os.path.join(root, _b(op[2])), p)
        elif k == "write":                       # in place: same inode, same mode
            fd = os.open(p, os.O_WRONLY | os.O_TRUNC)
            os.write(fd, op[2])
            os.close(fd)
        elif k == "append":
            with open(p, "ab") as f:
                f.write(op[2])
        elif k == "replace":                     # a new inode renamed over it
            tmp = p + b".tmp-replace"
            with open(tmp, "wb") as f:
                f.write(op[2])
            os.chmod(tmp, op[3] if len(op) > 3 else 0o644)
            os.rename(tmp, p)
        elif k == "rm":
            os.unlink(p)
        elif k == "rmtree":
            for dp, dns, fns in os.walk(p, topdown=False):
                for n in fns:
                    os.unlink(os.path.join(dp, n))
                for n in dns:
                    q = os.path.join(dp, n)
                    if os.path.islink(q):
                        os.unlink(q)
                    else:
                        os.rmdir(q)
            os.rmdir(p)
        elif k == "chmod":
            os.chmod(p, op[2], follow_symlinks=False)
        elif k == "chgrp":
            os.chown(p, -1, op[2], follow_symlinks=False)
        elif k == "same_bytes_same_mtime":       # the same bytes written back, mtime restored
            st = os.stat(p)
            with open(p, "rb") as f:
                data = f.read()
            fd = os.open(p, os.O_WRONLY | os.O_TRUNC)
            os.write(fd, data)
            os.close(fd)
            os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
        elif k == "touch":                       # mtime only
            st = os.stat(p)
            os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        elif k == "chattr":
            fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK)
            try:
                buf = bytearray(8)
                fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf, True)
                v = int.from_bytes(buf[:4], "little") | op[2]
                fcntl.ioctl(fd, FS_IOC_SETFLAGS, bytearray(v.to_bytes(4, "little") + b"\0" * 4), True)
            finally:
                os.close(fd)
        elif k == "setxattr":
            os.setxattr(p, op[2], op[3], follow_symlinks=False)
        elif k == "sparse":
            _mkparents(root, _b(op[1]))
            with open(p, "wb") as f:
                f.truncate(op[2])
            os.chmod(p, 0o644)
        else:
            raise ValueError("unknown op %r" % (k,))


# ---------------------------------------------------------------------------------------------
# Contents

TEST_API = b'''import pytest


def test_one():
    assert 1 + 1 == 2
    assert "a" in "abc"


def test_two():
    with pytest.raises(ZeroDivisionError):
        1 / 0
    assert 0.1 + 0.2 == pytest.approx(0.3)


class TestThing:
    def test_three(self):
        assert True
'''                                   # 6 assertions, 3 tests

TEST_UNIT = b'''import unittest


class TestUnit(unittest.TestCase):
    def test_a(self):
        self.assertEqual(1, 1)
        self.assertTrue(True)

    def test_b(self):
        self.assertIn("a", "abc")
'''                                   # 3 assertions, 2 tests

CONFTEST = b'''import pytest


@pytest.fixture
def client():
    return object()
'''

PYPROJECT = b'''[project]
name = "app"
version = "0.1.0"

[tool.pytest.ini_options]
addopts = "-q"
testpaths = ["tests"]

[tool.black]
line-length = 100
'''

SETUP_CFG = b'''[metadata]
name = app

[tool:pytest]
addopts = -q
'''

TOX_INI = b'''[tox]
envlist = py312

[pytest]
addopts = -q
'''

PYTEST_INI = b'''[pytest]
addopts = -q
'''

CI_YML = b'''name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
'''

GRADER = b'''import sys
print("grading")
sys.exit(0)
'''


def sha(b):
    return hashlib.sha256(b).hexdigest()


BASE = [
    ("file", "README.md", b"# app\n"),
    ("file", "src/app.py", b"def add(a, b):\n    return a + b\n"),
    ("file", "tests/test_api.py", TEST_API),
    ("file", "tests/conftest.py", CONFTEST),
    ("file", "grader/check.py", GRADER),
    ("file", "pyproject.toml", PYPROJECT),
]


def spec_of(*rules, frozen=None, path_dirs=None):
    s = {"belay_protect": 1, "protect": list(rules)}
    if frozen is not None:
        s["frozen_packages"] = frozen
    if path_dirs is not None:
        s["path_dirs"] = path_dirs
    return s


def rule(path, *modes, expected=None):
    r = {"path": path}
    if modes:
        r["mode"] = list(modes)
    if expected is not None:
        r["expected_sha256"] = expected
    return r


# ---------------------------------------------------------------------------------------------
# Package databases

def dpkg_stanza(pkg, version, conffiles=(), arch="amd64", status="install ok installed"):
    s = "Package: %s\nStatus: %s\nPriority: optional\nArchitecture: %s\nVersion: %s\n" % (
        pkg, status, arch, version)
    if conffiles:
        s += "Conffiles:\n" + "".join(" /%s %s\n" % (p, m) for p, m in conffiles)
    s += "Description: %s, for tests\n" % pkg
    return s


def dpkg_ops(packages, root=""):
    """packages: [{pkg, version, files: {path: (data, mode)}, conffiles: {path: data},
    md5_override: {path: md5}, write_files: bool}] -> ops for the database and the files."""
    ops = []
    stanzas = []
    for pk in packages:
        files = pk.get("files", {})
        confs = pk.get("conffiles", {})
        over = pk.get("md5_override", {})
        md5 = lambda p, d: over.get(p, hashlib.md5(d).hexdigest())
        stanzas.append(dpkg_stanza(pk["pkg"], pk["version"],
                                   [(p, md5(p, d)) for p, d in sorted(confs.items())]))
        sums = "".join("%s  %s\n" % (md5(p, d), p) for p, (d, _m) in sorted(files.items()))
        ops.append(("file", root + "var/lib/dpkg/info/%s.md5sums" % pk["pkg"], sums.encode()))
        lst = "".join("/%s\n" % p for p in sorted(list(files) + list(confs)))
        ops.append(("file", root + "var/lib/dpkg/info/%s.list" % pk["pkg"], lst.encode()))
        for p, (d, m) in sorted(files.items()):
            if p not in pk.get("absent", ()):
                ops.append(("file", root + p, d, m))
        for p, d in sorted(confs.items()):
            ops.append(("file", root + p, d))
    ops.append(("file", root + "var/lib/dpkg/status", "\n".join(stanzas).encode()))
    return ops


TOOL_V1 = b"#!/bin/sh\necho tool 1.0\n"
TOOL_V2 = b"#!/bin/sh\necho tool 1.1\n"
TOOL = {"pkg": "tool", "version": "1.0-1",
        "files": {"usr/bin/tool": (TOOL_V1, 0o755),
                  "usr/share/doc/tool/README": (b"tool's readme\n", 0o644)},
        "conffiles": {"etc/tool.conf": b"verbose = false\n"}}
LIBX = {"pkg": "libx", "version": "2.3-1",
        "files": {"usr/lib/libx.so.2": (b"\x7fELF fake library\n", 0o644)}}


def b64sha(d):
    return base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b"=").decode()


SITE = "lib/python3.12/site-packages"


def pip_ops(name, version, files, site=SITE, bad=(), extra_rows=(), write=True):
    """files: {path relative to site (may hold ../): (data, mode)}. bad: rows whose hash is
    wrong. extra_rows: raw RECORD rows. -> ops making the dist-info and the files."""
    di = "%s-%s.dist-info" % (name, version)
    meta = ("Metadata-Version: 2.1\nName: %s\nVersion: %s\n" % (name, version)).encode()
    rows = []
    ops = []
    for rel, (d, m) in sorted(files.items()):
        h = b64sha(d if rel not in bad else d + b"tampered-at-build")
        rows.append("%s,sha256=%s,%d" % (rel, h, len(d)))
        if write:
            ops.append(("file", os.path.normpath(os.path.join(site, rel)), d, m))
    rows.append("%s/METADATA,sha256=%s,%d" % (di, b64sha(meta), len(meta)))
    rows.append("%s/RECORD,," % di)
    rows.extend(extra_rows)
    ops.append(("file", "%s/%s/METADATA" % (site, di), meta))
    ops.append(("file", "%s/%s/RECORD" % (site, di), ("\n".join(rows) + "\n").encode()))
    return ops


FOO_FILES = {"foo/__init__.py": (b"VERSION = '1.0'\n", 0o644),
             "foo/core.py": (b"def run():\n    return 1\n", 0o644)}


# ---------------------------------------------------------------------------------------------
# git

def reflog(entries):
    return "".join("%s %s A U Thor <a@example.com> %d +0000\t%s\n" % (o, n, 1700000000 + i, m)
                   for i, (o, n, m) in enumerate(entries)).encode()


GIT_LOG = [("0" * 40, C[0], "commit (initial): first"), (C[0], C[1], "commit: second")]


def git_ops(repo=".git"):
    return [
        ("file", repo + "/HEAD", b"ref: refs/heads/main\n"),
        ("file", repo + "/config", b"[core]\n\tbare = false\n"),
        ("file", repo + "/refs/heads/main", (C[1] + "\n").encode()),
        ("file", repo + "/logs/refs/heads/main", reflog(GIT_LOG)),
        ("file", repo + "/hooks/pre-commit.sample", b"#!/bin/sh\nexit 0\n", 0o755),
        ("file", repo + "/hooks/pre-push", b"#!/bin/sh\nexit 0\n", 0o755),
        ("file", repo + "/hooks/post-merge", b"#!/bin/sh\nexit 0\n", 0o644),
    ]


# ---------------------------------------------------------------------------------------------
# The scenarios

def S(name, tree, episode=(), spec=None, tags=(), **kw):
    d = {"name": name, "tree": list(tree), "episode": list(episode), "spec": spec,
         "tags": list(tags), "excludes": kw.pop("excludes", []), "out": kw.pop("out", "outside"),
         "verify": kw.pop("verify", {}), "refusal": kw.pop("refusal", None),
         "workdir": kw.pop("workdir", None), "writers": tuple(list(w) for w in kw.pop("writers", ([], [])))}
    assert not kw, kw
    return d


def scenarios():
    out = []
    add = out.append
    TW = spec_of(rule("tests/**", "no_write"))
    GW = spec_of(rule("grader/**", "no_write"))

    # -- protected paths written (PS-M1)
    add(S("pw-modify", BASE, [("write", "tests/test_api.py", TEST_API + b"\n# more\n")], TW))
    add(S("pw-modify-noexitcode", BASE, [("write", "grader/check.py", GRADER + b"# x\n")], GW,
          verify={"exit_code": False}))
    add(S("pw-chmod", BASE, [("chmod", "grader/check.py", 0o664)], GW))
    if other_gid() is not None:
        add(S("pw-chgrp", BASE, [("chgrp", "grader/check.py", other_gid())], GW))
    add(S("pw-mtime-only", BASE, [("touch", "grader/check.py")], GW))
    add(S("pw-same-bytes", BASE, [("same_bytes_same_mtime", "grader/check.py")], GW, tags=["P1"]))
    add(S("pw-rename-over", BASE, [("replace", "grader/check.py", GRADER.replace(b"0", b"1"))], GW))
    add(S("pw-hardlink", BASE + [("hardlink", "elsewhere/check-link.py", "grader/check.py")],
          [("write", "elsewhere/check-link.py", GRADER + b"print('hacked')\n")], GW))
    add(S("pw-type-symlink", BASE, [("rm", "tests/test_api.py"),
                                    ("symlink", "tests/test_api.py", "/etc/hostname")], TW))
    add(S("pw-iflags", BASE, [("chattr", "grader/check.py", FS_NODUMP_FL)], GW))
    add(S("pw-xattr", BASE, [("setxattr", "grader/check.py", "user.note", b"x")], GW))
    add(S("pw-dir-mode", BASE, [("chmod", "grader", 0o700)], GW))
    add(S("pw-first-rule-with-mode", BASE + [("file", "tests/unit/test_u.py", TEST_UNIT)],
          [("write", "tests/unit/test_u.py", TEST_UNIT + b"\n")],
          spec_of(rule("tests/**", "no_create"), rule("tests/unit/**", "no_write"),
                  rule("tests/unit/test_u.py", "no_write"))))

    # -- deleted (PS-M2), created (PS-M3)
    TD = spec_of(rule("tests/**", "no_delete"))
    add(S("pd-remove", BASE, [("rm", "tests/test_api.py")], TD))
    add(S("pd-remove-dir", BASE + [("file", "tests/data/a.txt", b"a\n"), ("file", "tests/data/b.txt", b"b\n")],
          [("rmtree", "tests/data")], TD))
    TC = spec_of(rule("tests/**", "no_create"))
    add(S("pc-create", BASE, [("file", "tests/test_new.py", b"def test_new():\n    assert 1\n")], TC))
    add(S("pc-create-dir", BASE, [("file", "tests/fixtures/x.json", b"{}\n")], TC))
    add(S("pc-modify-not-create", BASE, [("write", "tests/test_api.py", TEST_API + b"\n")], TC))
    add(S("p-all-modes", BASE + [("file", "tests/old_data.txt", b"old\n")],
          [("write", "tests/conftest.py", CONFTEST + b"# x\n"), ("rm", "tests/old_data.txt"),
           ("file", "tests/new_data.txt", b"new\n")],
          spec_of(rule("tests/**", "no_write", "no_delete", "no_create"))))

    # -- expected_sha256 (PS-M4)
    GH = lambda h: spec_of(rule("grader/check.py", "no_write", expected=h))
    add(S("hash-holds", BASE, [], GH(sha(GRADER))))
    add(S("hash-other-bytes", BASE, [("write", "grader/check.py", b"print('pass')\n")], GH(sha(GRADER))))
    add(S("hash-absent", BASE, [("rm", "grader/check.py")], GH(sha(GRADER))))
    add(S("hash-not-regular", BASE, [("rm", "grader/check.py"), ("dir", "grader/check.py")], GH(sha(GRADER))))
    add(S("hash-wrong-at-reset", BASE, [], spec_of(rule("grader/check.py", expected=sha(b"other\n")))))
    add(S("hash-absent-both", BASE, [], spec_of(rule("grader/missing.py", expected=sha(b"x")))))

    # -- fail closed (PS-M5), the hash bound (PS-C3)
    add(S("unverif-big", BASE + [("sparse", "grader/blob.bin", 4294967296 + 1)], [],
          spec_of(rule("grader/**", "no_write"))))
    add(S("unverif-unreadable-at-reset", BASE + [("file", "grader/secret.txt", b"s3cret\n"),
                                                ("chmod", "grader/secret.txt", 0o000)], [],
          GW, tags=["P25"]))
    add(S("unverif-unreadable-episode", BASE + [("file", "grader/secret.txt", b"s3cret\n")],
          [("chmod", "grader/secret.txt", 0o000)], GW, tags=["P25", "P29"]))
    add(S("unverif-added-unreadable", BASE, [("file", "grader/new.txt", b"n\n"), ("chmod", "grader/new.txt", 0o000)],
          spec_of(rule("grader/**", "no_create")), tags=["P6", "P25"]))
    add(S("unverif-no-create-reads-after", BASE + [("sparse", "grader/blob.bin", 4294967296 + 1)], [],
          spec_of(rule("grader/**", "no_create")), tags=["P6"]))

    # -- the dot-segment rule (PS-P4, decision 157)
    add(S("dot-workflows", BASE + [("file", ".github/workflows/ci.yml", CI_YML)],
          [("write", ".github/workflows/ci.yml", CI_YML + b"      - run: true\n")],
          spec_of(rule(".github/workflows/**", "no_write"))))
    add(S("dot-star-skips", BASE + [("file", "tests/.cache/x", b"1\n"), ("file", ".env", b"A=1\n")],
          [("write", "tests/.cache/x", b"2\n"), ("write", ".env", b"A=2\n")],
          spec_of(rule("tests/**", "no_write"), rule("*", "no_write"))))
    add(S("dot-dotstar-matches", BASE + [("file", ".env", b"A=1\n"), ("file", "tests/.cache/x", b"1\n")],
          [("write", ".env", b"A=2\n"), ("write", "tests/.cache/x", b"2\n")],
          spec_of(rule(".*", "no_write"), rule("tests/.cache/**", "no_write"))))
    add(S("dot-conftest-hidden", BASE + [("file", ".hidden/conftest.py", CONFTEST)],
          [("write", ".hidden/conftest.py", CONFTEST + b"# x\n")],
          spec_of(rule("**/conftest.py", "no_write"))))
    add(S("pattern-literal-chars", BASE + [("file", "data/a?[b]\\c.txt", b"1\n"), ("file", "data/ab.txt", b"1\n")],
          [("write", "data/a?[b]\\c.txt", b"2\n"), ("write", "data/ab.txt", b"2\n")],
          spec_of(rule("data/a?[b]\\c.txt", "no_write"), rule("data/a*b*.txt", "no_write"))))

    # -- packages: dpkg
    for frozen in (False, True):
        f = "-frozen" if frozen else "-free"
        PS = spec_of(frozen=frozen)
        D = dpkg_ops([TOOL, LIBX])
        add(S("dpkg-tamper" + f, BASE + D, [("write", "usr/bin/tool", b"#!/bin/sh\necho owned\n")], PS))
        add(S("dpkg-remove-file" + f, BASE + D, [("rm", "usr/share/doc/tool/README")], PS))
        add(S("dpkg-conffile" + f, BASE + D, [("write", "etc/tool.conf", b"verbose = true\n")], PS))
        tool2 = dict(TOOL, version="1.1-1", files=dict(TOOL["files"], **{"usr/bin/tool": (TOOL_V2, 0o755)}))
        add(S("dpkg-upgrade" + f, BASE + D,
              [op for op in dpkg_ops([tool2, LIBX]) if op[1] != "etc/tool.conf"], PS, tags=["P10"]))
        newt = {"pkg": "newtool", "version": "2.0-1", "files": {"usr/bin/newtool": (b"#!/bin/sh\n", 0o755)}}
        add(S("dpkg-install" + f, BASE + D,
              [op for op in dpkg_ops([TOOL, LIBX, newt]) if op[1] not in ("usr/bin/tool", "usr/share/doc/tool/README",
                                                                       "etc/tool.conf", "usr/lib/libx.so.2")],
              PS, tags=["P10"]))
    newt_bad = {"pkg": "newtool", "version": "2.0-1", "files": {"usr/bin/newtool": (b"#!/bin/sh\n", 0o755)},
                "md5_override": {"usr/bin/newtool": "0" * 32}}
    add(S("dpkg-install-inconsistent", BASE + dpkg_ops([TOOL]),
          [op for op in dpkg_ops([TOOL, newt_bad]) if not op[1].startswith(("usr/bin/tool", "usr/share", "etc/"))],
          spec_of(), tags=["P10"]))
    bad_tool = dict(TOOL, md5_override={"usr/share/doc/tool/README": "f" * 32}, absent=("usr/bin/tool",))
    add(S("dpkg-baseline-integrity", BASE + dpkg_ops([bad_tool, LIBX]), [], spec_of(), tags=["P22"]))
    add(S("dpkg-sysroot", dpkg_ops([TOOL], root="sysroot/"),
          [("write", "sysroot/usr/bin/tool", b"#!/bin/sh\necho owned\n")], spec_of(frozen=True)))
    add(S("dpkg-no-spec", BASE + dpkg_ops([TOOL]), [("write", "usr/bin/tool", b"#!/bin/sh\necho x\n")], None))

    # -- packages: pip
    escape = "../../../../../outside/thing.py,sha256=%s,3" % b64sha(b"x\n")
    FOO = pip_ops("foo", "1.0", dict(FOO_FILES, **{"../../../bin/foo": (b"#!/usr/bin/env python3\n", 0o755)}),
                  extra_rows=[escape])
    for frozen in (False, True):
        f = "-frozen" if frozen else "-free"
        PS = spec_of(frozen=frozen)
        add(S("pip-tamper" + f, BASE + FOO, [("write", SITE + "/foo/core.py", b"def run():\n    return 2\n")], PS))
        add(S("pip-tamper-dotdot" + f, BASE + FOO, [("write", "bin/foo", b"#!/bin/sh\necho owned\n")], PS))
        add(S("pip-remove-file" + f, BASE + FOO, [("rm", SITE + "/foo/__init__.py")], PS))
        newer = pip_ops("bar", "2.0", {"bar/__init__.py": (b"X = 1\n", 0o644),
                                       "../../../bin/bar": (b"#!/usr/bin/env python3\n", 0o755)})
        add(S("pip-install" + f, BASE + FOO, newer, PS, tags=["P10"]))
        up = ([("rmtree", SITE + "/foo-1.0.dist-info")] +
              pip_ops("foo", "2.0", dict(FOO_FILES, **{"foo/__init__.py": (b"VERSION = '2.0'\n", 0o644),
                                                       "../../../bin/foo": (b"#!/usr/bin/env python3\n", 0o755)}))
              + [("write", SITE + "/foo/__init__.py", b"VERSION = '2.0'\n")])
        add(S("pip-upgrade" + f, BASE + FOO, [op for op in up if op[1] not in (SITE + "/foo/core.py", "bin/foo")],
              PS, tags=["P10"]))
    add(S("pip-install-inconsistent", BASE + FOO,
          pip_ops("bar", "2.0", {"bar/__init__.py": (b"X = 1\n", 0o644)}, bad={"bar/__init__.py"}),
          spec_of()))
    add(S("pip-reinstall", BASE + FOO,
          [op for op in pip_ops("foo", "1.0", dict(FOO_FILES, **{"foo/core.py": (b"def run():\n    return 3\n", 0o644),
                                                                 "foo/extra.py": (b"E = 1\n", 0o644),
                                                                 "../../../bin/foo": (b"#!/usr/bin/env python3\n", 0o755)}),
                                extra_rows=[escape])
           if op[1] not in (SITE + "/foo/__init__.py", "bin/foo")], spec_of(), tags=["P8", "P10"]))
    add(S("pip-baseline-integrity", BASE + pip_ops("baz", "0.1", {"baz.py": (b"B = 1\n", 0o644),
                                                                   "baz_gone.py": (b"G\n", 0o644)},
                                                   bad={"baz.py"}) + [("rm", SITE + "/baz_gone.py")],
          [], spec_of(), tags=["P22"]))
    add(S("pip-baseline-not-a-file-unverified", BASE + pip_ops("qux", "0.1", {"qux.py": (b"Q\n", 0o644)}, write=False,
                                                               extra_rows=["qux_dir,sha256=%s,1" % b64sha(b"d"),
                                                                           "big.bin,sha256=%s,67108865" % b64sha(b"b")])
          + [("dir", SITE + "/qux_dir"), ("sparse", SITE + "/big.bin", 67108865)], [], None, tags=["P22"]))
    add(S("pip-no-spec", BASE + FOO, [("write", SITE + "/foo/core.py", b"x = 1\n")], None))

    # -- tests weakened, touched
    add(S("tw-assert-removed", BASE, [("write", "tests/test_api.py", TEST_API.replace(b'    assert "a" in "abc"\n', b""))],
          tags=["P13"]))
    add(S("tw-test-removed", BASE, [("write", "tests/test_api.py", TEST_API.split(b"\n\nclass")[0] + b"\n")], tags=["P13"]))
    add(S("tw-skip-added", BASE, [("write", "tests/test_api.py",
                                    TEST_API.replace(b"def test_two", b'@pytest.mark.skip(reason="flaky")\ndef test_two'))],
          tags=["P13"]))
    add(S("tw-markers-all", BASE + [("file", "tests/test_unit.py", TEST_UNIT)],
          [("write", "tests/test_api.py", TEST_API.replace(b"def test_one", b"@pytest.mark.xfail\ndef test_one")
            .replace(b"def test_two():\n", b"@pytest.mark.skipif(True, reason='x')\ndef test_two():\n    pytest.skip('no')\n")),
           ("write", "tests/test_unit.py", TEST_UNIT.replace(b"    def test_b", b"    @unittest.skip('x')\n    def test_b")
            .replace(b"self.assertIn(\"a\", \"abc\")", b"pytest.xfail('later')"))], tags=["P13"]))
    add(S("tw-emptied", BASE, [("write", "tests/test_api.py", b"")], tags=["P13"]))
    add(S("tw-removed", BASE, [("rm", "tests/test_api.py")], tags=["P13"]))
    add(S("tw-added-with-skip", BASE, [("file", "tests/test_new.py", b"import pytest\n\n@pytest.mark.skip\ndef test_x():\n    assert 0\n")],
          tags=["P13"]))
    add(S("tw-more-asserts", BASE, [("write", "tests/test_api.py", TEST_API + b"\n\ndef test_four():\n    assert 4\n")]))
    add(S("tw-conftest-not-counted", BASE, [("write", "tests/conftest.py", b"")]))
    add(S("tw-names", BASE + [("file", "src/app_test.py", b"def test_a():\n    assert 1\n    assert 2\n"),
                              ("file", "src/web.test.py", b"def test_b():\n    assert 1\n"),
                              ("file", "spec/helper.rb", b"x\n"), ("file", "web/app.spec.js", b"x\n"),
                              ("file", "src/__tests__/a.js", b"x\n"), ("file", "test/test.js", b"x\n")],
          [("write", "src/app_test.py", b"def test_a():\n    assert 1\n"), ("write", "src/web.test.py", b"def test_b():\n    pass\n"),
           ("write", "spec/helper.rb", b"y\n"), ("write", "web/app.spec.js", b"y\n"), ("write", "src/__tests__/a.js", b"y\n"),
           ("rm", "test/test.js")], tags=["P12", "P13"]))
    add(S("tw-new-test-dir", BASE, [("file", "tests/integration/test_i.py", b"def test_i():\n    assert 1\n")], tags=["P12"]))
    add(S("tw-not-utf8", BASE, [("file", b"tests/test_\xff.py", b"def test_x():\n    assert 1\n")]))
    add(S("tw-not-utf8-backslash", BASE, [("file", b"tests/a\\b/test_\xfe\\.py", b"def test_x():\n    assert 1\n"),
                                           ("file", "tests/c\\d/test_ok.py", b"def test_y():\n    assert 1\n")]))

    # -- pytest configuration, conftest, CI
    add(S("cfg-pyproject", BASE, [("write", "pyproject.toml", PYPROJECT.replace(b'addopts = "-q"', b'addopts = "-q -p no:randomly"'))], tags=["P15"]))
    add(S("cfg-pyproject-other-table", BASE, [("write", "pyproject.toml", PYPROJECT.replace(b"line-length = 100", b"line-length = 88"))], tags=["P15"]))
    add(S("cfg-setup-tox-ini", BASE + [("file", "setup.cfg", SETUP_CFG), ("file", "tox.ini", TOX_INI), ("file", "pytest.ini", PYTEST_INI)],
          [("write", "setup.cfg", SETUP_CFG + b"filterwarnings = ignore\n"),
           ("write", "tox.ini", TOX_INI.replace(b"envlist = py312", b"envlist = py311")),
           ("write", "pytest.ini", PYTEST_INI + b"xfail_strict = false\n")], tags=["P15"]))
    add(S("cfg-tox-pytest-section", BASE + [("file", "tox.ini", TOX_INI)],
          [("write", "tox.ini", TOX_INI + b"norecursedirs = tests\n")], tags=["P15"]))
    add(S("cfg-added-removed", BASE + [("file", "setup.cfg", SETUP_CFG)],
          [("rm", "setup.cfg"), ("file", "pytest.ini", PYTEST_INI), ("file", "sub/tox.ini", TOX_INI)], tags=["P15"]))
    add(S("conftest-root", BASE + [("file", "conftest.py", CONFTEST)],
          [("write", "conftest.py", CONFTEST + b"import os\nos.environ['X'] = '1'\n")]))
    add(S("ci-files", BASE + [("file", ".github/workflows/ci.yml", CI_YML), ("file", "Jenkinsfile", b"pipeline {}\n"),
                              ("file", ".circleci/config.yml", b"version: 2\n"), ("file", ".github/CODEOWNERS", b"* @x\n")],
          [("write", ".github/workflows/ci.yml", CI_YML.replace(b"pytest", b"true")), ("rm", "Jenkinsfile"),
           ("file", ".gitlab-ci.yml", b"test: {script: [true]}\n"), ("write", ".circleci/config.yml", b"version: 2.1\n"),
           ("file", "azure-pipelines.yml", b"steps: []\n"), ("file", "sub/.travis.yml", b"language: python\n"),
           ("write", ".github/CODEOWNERS", b"* @y\n"), ("file", ".github/workflows/new.yml", CI_YML)], tags=["P14"]))
    add(S("ci-metadata-only", BASE + [("file", ".github/workflows/ci.yml", CI_YML)], [("chmod", ".github/workflows/ci.yml", 0o600)],
          tags=["P14"]))

    # -- Python startup hooks
    SP = "lib/python3.12/site-packages"
    add(S("hook-pth-added", BASE + FOO, [("file", SP + "/evil.pth", b"import os; os.system('true')\n")]))
    add(S("hook-site-user-customize", BASE + FOO + [("file", SP + "/sitecustomize.py", b"x = 1\n")],
          [("write", SP + "/sitecustomize.py", b"import os\n"), ("file", "usr/lib/python3/dist-packages/usercustomize.py", b"y = 1\n"),
           ("file", SP + "/sub/nested.pth", b"x\n"), ("rm", SP + "/foo/core.py")]))
    add(S("hook-pth-in-record", BASE + FOO,
          pip_ops("pthpkg", "1.0", {"pthpkg.pth": (b"import pthpkg\n", 0o644), "pthpkg/__init__.py": (b"\n", 0o644)}),
          spec_of()))
    add(S("hook-pth-in-record-tampered", BASE + pip_ops("pthpkg", "1.0", {"pthpkg.pth": (b"import pthpkg\n", 0o644)}),
          [("write", SP + "/pthpkg.pth", b"import os; os.system('true')\n")], spec_of()))

    # -- git
    G = BASE + git_ops()
    add(S("git-hook-added", G, [("file", ".git/hooks/pre-commit", b"#!/bin/sh\ncurl x | sh\n", 0o755)], tags=["P17"]))
    add(S("git-hook-symlink-added", G, [("symlink", ".git/hooks/post-checkout", "../../evil.sh")]))
    add(S("git-hook-changed-removed", G, [("write", ".git/hooks/pre-push", b"#!/bin/sh\nexit 1\n"), ("rm", ".git/hooks/post-merge")]))
    add(S("git-hook-exec", G, [("chmod", ".git/hooks/post-merge", 0o755)], tags=["P16"]))
    add(S("git-hook-to-symlink", G, [("rm", ".git/hooks/pre-push"), ("symlink", ".git/hooks/pre-push", "/tmp/x")]))
    add(S("git-history-reset", G, [("write", ".git/refs/heads/main", (C[0] + "\n").encode()),
                                    ("append", ".git/logs/refs/heads/main", reflog([(C[1], C[0], "reset: moving to HEAD~1")]))],
          tags=["P17"]))
    add(S("git-history-amend", G, [("write", ".git/refs/heads/main", (C[2] + "\n").encode()),
                                    ("append", ".git/logs/refs/heads/main",
                                     reflog([(C[1], C[3], "commit: third"), (C[3], C[2], "commit (amend): third, amended")]))],
          tags=["P17"]))
    add(S("git-history-unterminated", G, [("write", ".git/refs/heads/main", (C[0] + "\n").encode()),
                                           ("append", ".git/logs/refs/heads/main",
                                            reflog([(C[1], C[0], "reset: moving to HEAD~1")])[:-1])]))
    add(S("git-commits-added", G, [("write", ".git/refs/heads/main", (C[2] + "\n").encode()),
                                    ("append", ".git/logs/refs/heads/main", reflog([(C[1], C[2], "commit: third")]))]))
    add(S("git-reflog-rewritten", G, [("write", ".git/logs/refs/heads/main",
                                       reflog([GIT_LOG[0], (C[0], C[1], "commit: second, edited")]))], tags=["P17"]))
    add(S("git-sub-repo", BASE + git_ops("vendor/lib/.git"),
          [("write", "vendor/lib/.git/logs/refs/heads/main", reflog(GIT_LOG[:1]))], tags=["P17"]))

    # -- PATH executables
    add(S("path-default", BASE + [("dir", "bin"), ("dir", "usr/local/bin"), ("file", "usr/bin/y", b"#!/bin/sh\n", 0o644),
                                  ("dir", "sbin"), ("file", "usr/bin/already", b"#!/bin/sh\n", 0o744)],
          [("file", "bin/newtool", b"#!/bin/sh\n", 0o755), ("symlink", "usr/local/bin/x", "/usr/bin/true"),
           ("chmod", "usr/bin/y", 0o755), ("file", "sbin/data", b"not executable\n", 0o644),
           ("file", "lib/z", b"#!/bin/sh\n", 0o755), ("chmod", "usr/bin/already", 0o755)], tags=["P18"]))
    add(S("path-venv", BASE + [("file", ".venv/pyvenv.cfg", b"home = /usr/bin\n"), ("file", ".venv/bin/python", b"#!py\n", 0o755),
                               ("file", "notvenv/bin/keep", b"x\n")],
          [("file", ".venv/bin/evil", b"#!/bin/sh\n", 0o755), ("file", "notvenv/bin/tool", b"#!/bin/sh\n", 0o755),
           ("file", "newvenv/pyvenv.cfg", b"home = /usr/bin\n"), ("file", "newvenv/bin/python", b"#!py\n", 0o755)],
          tags=["P18"]))
    add(S("path-dirs-custom", BASE + [("dir", "bin"), ("dir", "tools/bin"), ("dir", "a/scripts")],
          [("file", "tools/bin/x", b"#!/bin/sh\n", 0o755), ("file", "bin/y", b"#!/bin/sh\n", 0o755),
           ("file", "a/scripts/z", b"#!/bin/sh\n", 0o700), ("file", ".hidden/scripts/w", b"#!/bin/sh\n", 0o755)],
          spec_of(path_dirs=["tools/bin", "**/scripts"]), tags=["P18"]))
    add(S("path-type-change", BASE + [("file", "bin/tool", b"data\n"), ("file", "bin/other", b"#!/bin/sh\n", 0o755)],
          [("rm", "bin/tool"), ("symlink", "bin/tool", "/usr/bin/true"), ("rm", "bin/other"), ("dir", "bin/other")],
          tags=["P18"]))

    # -- privilege
    add(S("priv-bits", BASE + [("file", "tools/run", b"#!/bin/sh\n", 0o755), ("dir", "shared"),
                               ("file", "tools/old-suid", b"#!/bin/sh\n", 0o4755)],
          [("chmod", "tools/run", 0o6755), ("chmod", "shared", 0o1777), ("rm", "tools/old-suid"),
           ("file", "tools/new-sgid", b"#!/bin/sh\n", 0o2755)], tags=["P4"]))
    add(S("priv-scope-root", BASE, [("chmod", ".", 0o1755)], tags=["P4"]))
    add(S("priv-iflags", BASE, [("chattr", "src/app.py", FS_NODUMP_FL)]))
    add(S("priv-sticky-file-in-bin", BASE + [("dir", "bin")], [("file", "bin/s", b"#!/bin/sh\n", 0o1755)],
          tags=["P18"]))

    # -- more shapes of change
    add(S("pw-symlink-retarget", BASE + [("symlink", "tests/data-link", "a")],
          [("rm", "tests/data-link"), ("symlink", "tests/data-link", "bb")], TW))
    add(S("pw-type-dir-to-file", BASE + [("file", "tests/data/x.txt", b"x\n")],
          [("rmtree", "tests/data"), ("file", "tests/data", b"now a file\n")],
          spec_of(rule("tests/**", "no_write", "no_delete"))))
    add(S("hash-symlink", BASE, [("rm", "grader/check.py"), ("symlink", "grader/check.py", "/etc/passwd")],
          spec_of(rule("grader/check.py", expected=sha(GRADER)))))
    for frozen in (False, True):
        f = "-frozen" if frozen else "-free"
        PS = spec_of(frozen=frozen)
        D = dpkg_ops([TOOL, LIBX])
        add(S("dpkg-remove-package" + f, BASE + D,
              [("rm", "usr/lib/libx.so.2"), ("rm", "var/lib/dpkg/info/libx.md5sums"), ("rm", "var/lib/dpkg/info/libx.list"),
               ("write", "var/lib/dpkg/status", dpkg_stanza("tool", "1.0-1",
                                                            [("etc/tool.conf", hashlib.md5(b"verbose = false\n").hexdigest())]).encode())],
              PS, tags=["P10"]))
        add(S("pip-remove-package" + f, BASE + FOO,
              [("rmtree", SITE + "/foo-1.0.dist-info"), ("rmtree", SITE + "/foo"), ("rm", "bin/foo")], PS, tags=["P10"]))
    add(S("pip-downgrade", BASE + FOO,
          [("rmtree", SITE + "/foo-1.0.dist-info")] + pip_ops("foo", "0.9", FOO_FILES, write=False), spec_of(), tags=["P10"]))
    add(S("pip-version-changed", BASE + FOO,
          [("rmtree", SITE + "/foo-1.0.dist-info")] + pip_ops("foo", "1.0.0", FOO_FILES, write=False), spec_of(),
          tags=["P10"]))
    add(S("git-history-branch-reset-forced", BASE + git_ops(),
          [("write", ".git/refs/heads/main", (C[0] + "\n").encode()),
           ("append", ".git/logs/refs/heads/main",
            reflog([(C[1], C[3], "branch: Reset to origin/main"), (C[3], C[0], "fetch: forced-update")]))], tags=["P17"]))
    for frozen in (False, True):
        f = "-frozen" if frozen else "-free"
        mix_tree = BASE + dpkg_ops([TOOL, LIBX]) + FOO + git_ops() + [("dir", "bin/x"), ("file", "tests/old.txt", b"o\n")]
        mix_ep = ([("write", "grader/check.py", b"print('ok')\n"), ("rm", "tests/old.txt"),
                   ("file", "tests/test_new.py", b"import pytest\n\n@pytest.mark.skip\ndef test_n():\n    assert 1\n"),
                   ("write", "tests/test_api.py", TEST_API.replace(b"    assert True\n", b"    pass\n")),
                   ("write", "usr/bin/tool", b"#!/bin/sh\necho owned\n"), ("write", "etc/tool.conf", b"verbose = true\n"),
                   ("file", ".github/workflows/x.yml", CI_YML), ("file", ".git/hooks/pre-commit", b"#!/bin/sh\n", 0o755),
                   ("write", ".git/refs/heads/main", (C[0] + "\n").encode()),
                   ("append", ".git/logs/refs/heads/main", reflog([(C[1], C[0], "reset: moving to HEAD~1")])),
                   ("file", "bin/newtool", b"#!/bin/sh\n", 0o4755),
                   ("write", "pyproject.toml", PYPROJECT.replace(b'testpaths = ["tests"]', b'testpaths = ["src"]')),
                   ("file", SITE + "/zz.pth", b"import os\n")]
                  + pip_ops("bar", "2.0", {"bar/__init__.py": (b"X = 1\n", 0o644)}))
        add(S("mix-all" + f, mix_tree, mix_ep,
              spec_of(rule("tests/**", "no_write", "no_delete", "no_create"),
                      rule("grader/check.py", "no_write", expected=sha(GRADER)), frozen=frozen),
              tags=["P10", "P13", "P15", "P17"]))

    # -- decision 163: iflags of a file added or removed only when they lock it
    add(S("priv-added-nodump", BASE + [("file", "src/old.py", b"o\n"), ("chattr", "src/old.py", FS_NODUMP_FL)],
          [("file", "src/new.py", b"n\n"), ("chattr", "src/new.py", FS_NODUMP_FL), ("rm", "src/old.py")]))
    add(S("priv-disk-extents", BASE + [("file", "src/kept.py", b"k\n")],
          [("file", "src/added.py", b"a\n"), ("dir", "src/newdir"), ("chattr", "src/kept.py", FS_NODUMP_FL),
           ("rm", "README.md")], workdir="disk"))

    # -- decision 173: a reinstall at the same version has its files judged
    for frozen in (False, True):
        f = "-frozen" if frozen else "-free"
        forged = pip_ops("foo", "1.0", dict(FOO_FILES, **{"foo/core.py": (b"def run():\n    return 'patched'\n", 0o644),
                                                          "../../../bin/foo": (b"#!/usr/bin/env python3\n", 0o755)}),
                         extra_rows=[escape])
        add(S("pip-forged-record" + f, BASE + FOO,
              [op for op in forged if op[1] in (SITE + "/foo/core.py", SITE + "/foo-1.0.dist-info/RECORD")],
              spec_of(frozen=frozen), tags=["P8"]))

    add(S("pip-no-hash-file-modified", BASE + pip_ops("pyc", "1.0", {"pyc/__init__.py": (b"P = 1\n", 0o644)},
                                                      extra_rows=["pyc/__pycache__/__init__.cpython-312.pyc,,"])
          + [("file", SITE + "/pyc/__pycache__/__init__.cpython-312.pyc", b"\x00compiled 1")],
          [("write", SITE + "/pyc/__pycache__/__init__.cpython-312.pyc", b"\x00compiled 2, patched")],
          spec_of(), tags=["P8"]))

    # -- decision 186: a .pyc listed without a hash, judged against its source
    PY = SITE + "/pycpkg/"
    PYC = PY + "__pycache__/"
    pyc_files = {PYC + "__init__.cpython-312.pyc": b"\xcb\x0d\x0d\x0a init", PYC + "core.cpython-312.pyc": b"\xcb\x0d\x0d\x0a core",
                 PYC + "core.cpython-312.opt-1.pyc": b"\xcb\x0d\x0d\x0a core opt", PY + "legacy.pyc": b"\xcb\x0d\x0d\x0a legacy",
                 PYC + "gone.cpython-312.pyc": b"\xcb\x0d\x0d\x0a sourceless"}
    PYCPKG = (pip_ops("pycpkg", "1.0", {"pycpkg/__init__.py": (b"X = 1\n", 0o644),
                                        "pycpkg/core.py": (b"def run():\n    return 1\n", 0o644),
                                        "pycpkg/legacy.py": (b"L = 1\n", 0o644)},
                      extra_rows=[p[len(SITE) + 1:] + ",," for p in sorted(pyc_files)])
              + [("file", p, d) for p, d in sorted(pyc_files.items())])
    for frozen in (False, True):
        f = "-frozen" if frozen else "-free"
        add(S("pyc-patched" + f, BASE + PYCPKG, [("write", PYC + "core.cpython-312.pyc", b"\xcb\x0d\x0d\x0a PATCHED")],
              spec_of(frozen=frozen), tags=["P37"]))
    add(S("pyc-recompiled", BASE + PYCPKG, [("write", PY + "core.py", b"def run():\n    return 2\n"),
                                            ("write", PYC + "core.cpython-312.pyc", b"\xcb\x0d\x0d\x0a core, recompiled")],
          spec_of(), tags=["P37"]))
    add(S("pyc-removed", BASE + PYCPKG, [("rm", PYC + "core.cpython-312.pyc"), ("rm", PY + "legacy.pyc")], spec_of(), tags=["P36"]))
    add(S("pyc-opt1-patched", BASE + PYCPKG, [("write", PYC + "core.cpython-312.opt-1.pyc", b"\xcb\x0d\x0d\x0a PATCHED opt")],
          spec_of(frozen=True), tags=["P37"]))
    add(S("pyc-legacy-patched", BASE + PYCPKG, [("write", PY + "legacy.pyc", b"\xcb\x0d\x0d\x0a PATCHED legacy")],
          spec_of(), tags=["P37"]))
    add(S("pyc-type-changed", BASE + PYCPKG, [("rm", PYC + "__init__.cpython-312.pyc"),
                                              ("symlink", PYC + "__init__.cpython-312.pyc", "/tmp/evil.pyc")],
          spec_of(), tags=["P37"]))
    add(S("pyc-sourceless-patched", BASE + PYCPKG, [("write", PYC + "gone.cpython-312.pyc", b"\xcb\x0d\x0d\x0a PATCHED gone")],
          spec_of(), tags=["P37"]))
    add(S("pyc-metadata-only-unknown", BASE + PYCPKG, [("chmod", PYC + "core.cpython-312.pyc", 0o600),
                                                       ("chmod", PY + "legacy.pyc", 0o000)],
          spec_of(), tags=["P36", "P25"]))
    add(S("pyc-recompiled-opt1-patched", BASE + PYCPKG, [("write", PY + "core.py", b"def run():\n    return 3\n"),
                                                         ("write", PYC + "core.cpython-312.opt-1.pyc", b"\xcb\x0d\x0d\x0a recompiled opt")],
          spec_of(), tags=["P37"]))

    # -- decision 175: the test-file rule, narrowed
    T175 = [("build/test/test_gen.py", b"def test_g():\n    assert 1\n"), ("build/san/test/x.c", b"int x;\n"),
            ("docs/spec/policy.md", b"# spec\n"), ("doc/tests/a.txt", b"a\n"), ("out/tests/r.txt", b"r\n"),
            ("target/debug/foo_test.go", b"package x\n"), ("node_modules/m/test/i.js", b"x\n"),
            ("src/__pycache__/test_a.cpython-312.pyc", b"\0pyc"), ("dist/test_b.py", b"x\n"),
            (".build/tests/t.swift", b"x\n"), ("obj/test_o.c", b"x\n"), ("_build/tests/x", b"x\n"),
            ("src/foo_test.go", b"package foo\n"), ("src/FooTest.java", b"class FooTest {}\n"),
            ("src/BarTests.kt", b"class BarTests\n"), ("src/QuxTest.kt", b"class QuxTest\n"),
            ("src/BazTests.java", b"class BazTests {}\n"), ("lib/x_spec.rb", b"x\n"), ("lib/y_test.rb", b"y\n"),
            ("src/test_a.c", b"x\n"), ("src/b_test.cc", b"x\n"), ("src/test_c.cpp", b"x\n"), ("src/d_test.c", b"x\n"),
            ("src/test_e.cc", b"x\n"), ("src/f_test.cpp", b"x\n"),
            ("web/a.test.tsx", b"x\n"), ("web/b.spec.mjs", b"x\n"), ("web/c.test.cjs", b"x\n"), ("web/d.spec.jsx", b"x\n"),
            ("web/e.test.ts", b"x\n"), ("web/f.spec.js", b"x\n"),
            ("src/g_test.py", b"def test_g():\n    assert 1\n"), ("src/test_h.py", b"def test_h():\n    assert 1\n"),
            ("src/web.test.py", b"x\n"), ("src/Foo.test.java", b"x\n"), ("src/footest.go", b"x\n"),
            ("src/x.spec.rb", b"x\n"), ("src/test_x.h", b"x\n"), ("web/a.test.vue", b"x\n"), ("src/testing.py", b"x\n"),
            ("crates/x/tests/it.rs", b"x\n"), ("app/spec/models/user_spec.rb", b"x\n"), ("src/__tests__/a.vue", b"x\n")]
    add(S("tw-paths-decision-175", BASE + [("file", "build/test/old_test.go", b"package x\n"),
                                           ("file", "docs/spec/old.md", b"# old\n"), ("file", "src/old_test.go", b"package y\n")],
          [("file", p, d) for p, d in T175] + [("rm", "build/test/old_test.go"), ("write", "docs/spec/old.md", b"# new\n"),
                                               ("write", "src/old_test.go", b"package z\n")], tags=["P12", "P34"]))
    add(S("tw-weakened-below-build", BASE + [("file", "build/tests/test_b.py", TEST_API), ("file", "src/c_test.py", TEST_API)],
          [("write", "build/tests/test_b.py", b""), ("write", "src/c_test.py", b"")], tags=["P13", "P34"]))

    # -- decision 174: a text over 1,024 bytes is cut at a character
    many = b"".join(b'@pytest.mark.skip(reason="flaky on the CI runner, number %02d of many")\n' % i for i in range(25))
    add(S("text-cut-markers", BASE, [("write", "tests/test_api.py", TEST_API.replace(b"def test_two", many + b"def test_two"))],
          tags=["P13", "P33"]))
    deep = "/".join(["\u00e9" * 120] * 4)
    add(S("text-cut-long-path", BASE, [("file", "tests/%s/a\u00e9/test_\u00e9.py" % deep, b"def test_x():\n    assert 1\n")],
          spec_of(rule("tests/**", "no_create")), tags=["P33"]))
    add(S("text-cut-not-utf8", BASE, [("file", b"tests/" + b"\xff" * 250 + b"/" + b"\\" * 30 + b"/t.py", b"x\n")],
          tags=["P33"]))
    add(S("text-cut-mid-escape", BASE,
          [("file", b"tests/" + b"/".join([b"a" * 250, b"b" * 250, b"c" * 250, b"d" * 250]) + b"/" + b"\xff" * 10, b"x\n")],
          tags=["P33", "P35"]))

    # -- headers: no spec, empty spec, an exclude that covers nothing protected
    add(S("nospec-mixed", BASE + git_ops(), [("write", "tests/test_api.py", b""), ("file", ".git/hooks/pre-commit", b"#!/bin/sh\n", 0o755)],
          None, tags=["P13"]))
    add(S("empty-spec", BASE, [("write", "grader/check.py", b"x\n"), ("write", "tests/conftest.py", b"")], spec_of()))
    add(S("exclude-not-covering", BASE + [("file", "node_modules/x/index.js", b"1\n")],
          [("write", "node_modules/x/index.js", b"2\n"), ("write", "tests/test_api.py", TEST_API + b"\n")], TW,
          excludes=["node_modules"]))
    add(S("exclude-dot-not-covered", BASE + [("file", ".cache/x.py", b"1\n")], [("write", "tests/test_api.py", TEST_API + b"#\n")],
          spec_of(rule("**/x.py", "no_write"), rule("tests/**", "no_write")), excludes=[".cache"], tags=["P26"]))
    add(S("exclude-below-literal", BASE + [("file", "a/b/c.txt", b"1\n")], [],
          spec_of(rule("a", "no_write")), excludes=["a/b"]))
    add(S("spec-accepted-shapes", BASE,
          [("write", "tests/test_api.py", TEST_API + b"#\n")],
          b' \n{"protect": [{"mode": ["no_delete", "no_write"], "path": "tests/**"}], "path_dirs": [], "belay_protect": 1,'
          b' "frozen_packages": false}\n\t '))
    add(S("verify-to-check", BASE, [("write", "grader/check.py", GRADER + b"#\n")], GW, verify={"to": "check"}))

    # -- export's refusals
    add(S("export-out-inside", BASE, [], TW, out="inside", refusal="export:out-inside"))
    add(S("export-exclude-covers", BASE, [], TW, excludes=["tests"], refusal="export:exclude-covers"))
    add(S("export-exclude-covers-below", BASE + [("file", "vendor/pkg/conftest.py", CONFTEST)], [],
          spec_of(rule("**/conftest.py", "no_write")), excludes=["vendor"], refusal="export:exclude-covers"))
    add(S("export-exclude-covers-pattern-below", BASE + [("file", "tests/fixtures/f.txt", b"f\n")], [],
          spec_of(rule("tests/**", "no_delete")), excludes=["tests/fixtures"], refusal="export:exclude-covers"))
    for label, raw, tags in SPEC_REFUSALS:
        add(S("spec-refused-" + label, BASE, [], raw, tags=tags, refusal="spec:" + label))

    # -- verify's refusals (the export succeeds)
    add(S("verify-digest-wrong", BASE, [], TW, verify={"digest": "wrong"}, refusal="verify:digest-wrong"))
    add(S("verify-digest-missing", BASE, [], TW, verify={"digest": "missing"}, tags=["P23"], refusal="verify:digest-missing"))
    add(S("verify-other-spec", BASE, [], TW, verify={"spec": spec_of(rule("tests/**", "no_delete"))}, refusal="verify:other-spec"))
    add(S("verify-spec-dropped", BASE, [], TW, verify={"spec": None}, tags=["P30"], refusal="verify:spec-dropped"))
    add(S("verify-spec-added", BASE, [], None, verify={"spec": TW}, tags=["P30"], refusal="verify:spec-added"))
    add(S("verify-spec-refused", BASE, [], TW, verify={"spec": b'{"belay_protect":1,"protect":[],"x":1}'},
          tags=["P24"], refusal="verify:spec-refused"))
    add(S("verify-to-trusted", BASE, [("write", "README.md", b"# app 2\n")], TW, verify={"to": "trusted"},
          refusal="verify:to-trusted"))
    add(S("verify-configured-exclude-not-applied", BASE, [("write", "tests/test_api.py", TEST_API + b"#\n")], TW,
          verify={"excludes_add": ["tests"]}))
    add(S("verify-to-excluded-checkpoint", BASE, [], TW, verify={"excludes_add": ["tests"], "to": "check"},
          refusal="verify:exclude-covers-to"))
    add(S("nospec-to-excluded-checkpoint", BASE, [], None, verify={"excludes_add": ["tests"], "to": "check"},
          tags=["P13", "P32"]))
    add(S("verify-own-state-dir-covered", BASE + [("dir", "tmp")], [], spec_of(rule("tmp/**", "no_write")),
          verify={"tmpdir": "inside"}, refusal="verify:state-dir-covers"))
    add(S("verify-v2-bundle", BASE, [("write", "tests/test_api.py", TEST_API.replace(b"        assert True\n", b""))], TW,
          verify={"manifest": "v2"}, tags=["P39"]))
    add(S("verify-v2-bundle-packages", BASE + FOO, [("write", SITE + "/foo/core.py", b"x = 1\n")], spec_of(frozen=True),
          verify={"manifest": "v2"}, tags=["P39"]))
    add(S("verify-container-source", BASE, [], TW, verify={"manifest": "container"}, tags=["P39"],
          refusal="verify:source-differs"))
    add(S("verify-container-source-nospec", BASE, [("write", "README.md", b"x\n")], None, verify={"manifest": "container"},
          tags=["P39"], refusal="verify:source-differs-nospec"))
    # -- decision 214, B-R6: the first refusal is the one said
    add(S("verify-other-scope", BASE, [], TW, verify={"manifest": "other-scope"}, refusal="verify:other-scope"))
    add(S("verify-order-digest-before-source", BASE, [], TW, verify={"manifest": "container", "digest": "wrong"},
          refusal="verify:order-digest-before-source"))
    add(S("verify-order-missing-before-corrupt", BASE, [], TW, verify={"corrupt": "trailing", "digest": "missing"},
          refusal="verify:order-missing-before-corrupt"))
    add(S("verify-order-digest-before-corrupt", BASE, [], TW, verify={"corrupt": "short", "digest": "wrong"},
          refusal="verify:order-digest-before-corrupt"))
    add(S("verify-order-corrupt-before-source", BASE, [], TW, verify={"manifest": "container", "corrupt": "trailing"},
          refusal="verify:order-corrupt-before-source"))
    add(S("verify-order-corrupt-before-scope", BASE, [], TW, verify={"manifest": "other-scope", "corrupt": "unknown-key"},
          refusal="verify:order-corrupt-before-scope"))
    add(S("verify-order-corrupt-before-spec-digest", BASE, [], TW,
          verify={"corrupt": "trailing", "spec": spec_of(rule("tests/**", "no_delete"))},
          tags=["P40"], refusal="verify:order-corrupt-before-spec-digest"))
    add(S("verify-order-spec-refused-before-corrupt", BASE, [], TW,
          verify={"corrupt": "trailing", "spec": b'{"belay_protect":1,"protect":[],"x":1}'},
          tags=["P40"], refusal="verify:order-spec-refused-before-corrupt"))
    for c in ("trailing", "unknown-key", "short"):
        add(S("verify-corrupt-" + c, BASE, [], TW, verify={"corrupt": c}, refusal="verify:corrupt-" + c))
    out.extend(writer_scenarios())
    names = [s["name"] for s in out]
    assert len(names) == len(set(names)), "duplicate scenario names"
    return out


BLOB = b"\x00\x01 no copy is kept of a binary file\n"
BIG = 4294967296 + 1


def writer_scenarios():
    """Manifest v4: a file a process held open for writing, or mapped shared-writable, when it was
    read. A marked entry is never `added`, `removed`, `modified` or `type_changed`, so every rule
    that reads an outcome, a copy or a hash is taken through one here."""
    out = []
    add = out.append
    G = "grader/check.py"
    GW = spec_of(rule("grader/**", "no_write"))
    ND = spec_of(rule("grader/**", "no_delete"))
    NC = spec_of(rule("grader/**", "no_create"))
    ALL = spec_of(rule("grader/**", "no_write", "no_delete", "no_create"))
    GH = lambda h, *m: spec_of(rule(G, *m, expected=h))
    OTHER = b"print('pass')\n"
    NEW = "grader/new.py"

    # -- a marked entry on a protected path: on either side, on both, whatever else differs
    add(S("wo-before-only", BASE, [], GW, writers=([G], [])))
    add(S("wo-after-only", BASE, [], GW, writers=([], [G])))
    add(S("wo-both", BASE, [], GW, writers=([G], [G])))
    add(S("wo-before-modified", BASE, [("write", G, OTHER)], GW, writers=([G], [])))
    add(S("wo-after-modified", BASE, [("write", G, OTHER)], GW, writers=([], [G])))
    add(S("wo-both-modified", BASE, [("write", G, OTHER)], GW, writers=([G], [G])))
    add(S("wo-after-same-size-other-bytes", BASE, [("write", G, GRADER.replace(b"0", b"1"))], GW, writers=([], [G])))
    add(S("wo-after-chmod", BASE, [("chmod", G, 0o600)], GW, writers=([], [G])))
    add(S("wo-after-touch", BASE, [("touch", G)], GW, writers=([], [G])))
    add(S("wo-after-renamed-over", BASE, [("replace", G, OTHER)], GW, writers=([], [G])))
    add(S("wo-before-to-symlink", BASE, [("rm", G), ("symlink", G, "/etc/hostname")], GW, writers=([G], [])))
    add(S("wo-after-from-symlink", BASE + [("symlink", "grader/link", "check.py")],
          [("rm", "grader/link"), ("file", "grader/link", b"now a file\n")], GW, writers=([], ["grader/link"])))
    add(S("wo-before-became-dir", BASE, [("rm", G), ("file", G + "/inner.py", b"x = 1\n")], ALL, writers=([G], []), tags=["P45"]))
    add(S("wo-mmap-before", BASE, [], GW, writers=([(G, "mmap")], [])))
    add(S("wo-mmap-after", BASE, [("write", G, OTHER)], GW, writers=([], [(G, "mmap")])))
    add(S("wo-binary", BASE + [("file", "grader/blob.bin", BLOB)], [], GW, writers=(["grader/blob.bin"], ["grader/blob.bin"])))
    add(S("wo-empty", BASE + [("file", "grader/empty", b"")], [], GW, writers=(["grader/empty"], [])))
    add(S("wo-not-utf8", BASE + [("file", b"grader/\xff.bin", BLOB)], [], GW, writers=([], [b"grader/\xff.bin"])))
    add(S("wo-hardlink-other-name", BASE + [("hardlink", "elsewhere/link.py", G)], [], GW, writers=([], ["elsewhere/link.py"])))
    add(S("wo-first-rule-names-it", BASE, [], spec_of(rule("grader/**", "no_create"), rule(G, "no_write")),
          writers=([G], []), tags=["P5"]))
    add(S("wo-only-other-file-held", BASE, [("write", G, OTHER)], GW, writers=(["README.md"], ["README.md"])))

    # -- on one side only: never added or removed (V4-D3), and protected whatever the side (P50)
    add(S("wo-one-side-before-no-delete", BASE, [("rm", G)], ND, writers=([G], [])))
    add(S("wo-one-side-before-no-write", BASE, [("rm", G)], GW, writers=([G], [])))
    add(S("wo-one-side-before-no-create", BASE, [("rm", G)], NC, writers=([G], []), tags=["P50"]))
    add(S("wo-one-side-after-no-create", BASE, [("file", NEW, b"x = 1\n")], NC, writers=([], [NEW])))
    add(S("wo-one-side-after-no-write", BASE, [("file", NEW, b"x = 1\n")], GW, writers=([], [NEW]), tags=["P50"]))
    add(S("wo-one-side-after-no-delete", BASE, [("file", NEW, b"x = 1\n")], ND, writers=([], [NEW]), tags=["P50"]))
    add(S("wo-one-side-after-all", BASE, [("file", NEW, b"x = 1\n")], ALL, writers=([], [NEW])))
    # V4-S2 with no `writer_open` at all
    add(S("s2-raced-one-side-before-no-create", BASE + [("file", "grader/blob.bin", BLOB)], [("rm", "grader/blob.bin")], NC,
          verify={"manifest": "flags", "flags": {b"grader/blob.bin": ["raced"]}}, tags=["P50"]))
    add(S("s2-raced-one-side-after-no-write", BASE, [("file", "grader/blob.bin", BLOB)], GW,
          verify={"to": "check", "after_flags": {b"grader/blob.bin": ["raced"]}}, tags=["P50"]))
    add(S("s2-not-captured-no-create", BASE + [("file", "grader/sub/x.bin", BLOB)], [("chmod", "grader/sub", 0o000)], NC,
          tags=["P50", "P25"]))
    add(S("wo-one-side-before-excluded-after", BASE, [("write", "README.md", b"x\n")], None, writers=(["tests/test_api.py"], []),
          verify={"excludes_add": ["tests"], "to": "check"}, tags=["P13", "P45"]))

    # -- with another flag: on the other side, or (`raced`, the only one V4-2 allows) the same entry
    sec = "grader/secret.txt"
    add(S("wo-before-unreadable-after", BASE, [("chmod", G, 0o000)], GW, writers=([G], []), tags=["P25", "P29"]))
    add(S("wo-after-unreadable-before", BASE + [("file", sec, b"s\n"), ("chmod", sec, 0o000)], [("chmod", sec, 0o644)], GW,
          writers=([], [sec]), tags=["P25", "P29"]))
    add(S("wo-before-unverified-after", BASE + [("file", "grader/big.bin", BLOB)], [("sparse", "grader/big.bin", BIG)], GW,
          writers=(["grader/big.bin"], [])))
    add(S("wo-after-unverified-before", BASE + [("sparse", "grader/big.bin", BIG)], [("write", "grader/big.bin", BLOB)], GW,
          writers=([], ["grader/big.bin"])))
    add(S("wo-big-file-not-marked", BASE + [("sparse", "data/big.bin", 67108865)], [], None,
          writers=(["data/big.bin"], ["data/big.bin"])))
    TREE_B = BASE + [("file", "grader/blob.bin", BLOB)]
    B_ = b"grader/blob.bin"
    add(S("wo-flag-alone", TREE_B, [], GW, verify={"manifest": "flags", "flags": {B_: ["writer_open"]}}))
    add(S("wo-raced-same-entry-before", TREE_B, [], GW, verify={"manifest": "flags", "flags": {B_: ["raced", "writer_open"]}}))
    add(S("wo-raced-same-entry-after", TREE_B, [], GW, verify={"to": "check", "after_flags": {B_: ["raced", "writer_open"]}}))
    add(S("wo-raced-both-sides", TREE_B, [], GW, verify={"manifest": "flags", "flags": {B_: ["raced", "writer_open"]}, "to": "check",
                                                          "after_flags": {B_: ["writer_open"]}}))
    add(S("wo-raced-other-side", TREE_B, [], GW, verify={"manifest": "flags", "flags": {B_: ["raced"]}, "to": "check",
                                                          "after_flags": {B_: ["writer_open"]}}))
    add(S("wo-raced-one-side-before", TREE_B, [("rm", "grader/blob.bin")], ND,
          verify={"manifest": "flags", "flags": {B_: ["raced", "writer_open"]}}, tags=["P45"]))
    add(S("wo-raced-one-side-after", BASE, [("file", "grader/blob.bin", BLOB)], NC,
          verify={"to": "check", "after_flags": {B_: ["raced", "writer_open"]}}, tags=["P45"]))

    # -- expected_sha256: a marked entry has no hash (V4-D8); `absent`, the type and an unmarked after do not rest on one
    add(S("wo-hash-right-after", BASE, [], GH(sha(GRADER)), writers=([], [G])))
    add(S("wo-hash-wrong-after", BASE, [("write", G, OTHER)], GH(sha(GRADER)), writers=([], [G]), tags=["P42"]))
    add(S("wo-hash-wrong-after-with-no-write", BASE, [("write", G, OTHER)], GH(sha(GRADER), "no_write"), writers=([], [G]), tags=["P42"]))
    add(S("wo-hash-right-before", BASE, [], GH(sha(GRADER)), writers=([G], [])))
    add(S("wo-hash-wrong-before", BASE, [("write", G, OTHER)], GH(sha(GRADER)), writers=([G], [])))
    add(S("wo-hash-absent", BASE, [("rm", G)], GH(sha(GRADER), "no_write"), writers=([G], [])))
    add(S("wo-hash-not-regular", BASE, [("rm", G), ("dir", G)], GH(sha(GRADER)), writers=([G], [])))

    # -- test files: no outcome the rule names (P47), and a marked side has no copy to count from
    T = "tests/test_api.py"
    WEAK = TEST_API.replace(b'    assert "a" in "abc"\n', b"")
    add(S("wo-tests-weakened-after", BASE, [("write", T, WEAK)], writers=([], [T]), tags=["P13", "P47"]))
    add(S("wo-tests-weakened-before", BASE, [("write", T, WEAK)], writers=([T], []), tags=["P13", "P47"]))
    add(S("wo-tests-weakened-both", BASE, [("write", T, WEAK)], writers=([T], [T]), tags=["P13", "P47"]))
    add(S("wo-tests-removed", BASE, [("rm", T)], writers=([T], []), tags=["P13", "P47"]))
    add(S("wo-tests-added-skip", BASE, [("file", "tests/test_new.py", b"import pytest\n\n@pytest.mark.skip\ndef test_x():\n    assert 0\n")],
          writers=([], ["tests/test_new.py"]), tags=["P13", "P47"]))
    add(S("wo-tests-emptied-after", BASE, [("write", T, b"")], writers=([], [T]), tags=["P13", "P46"]))
    add(S("s3-empty-unreadable-after", BASE, [("write", T, b""), ("chmod", T, 0o000)], tags=["P13", "P25", "P46"]))
    add(S("wo-tests-emptied-before-marked", BASE + [("file", "tests/test_e.py", b"")], [("rm", "tests/test_e.py")],
          writers=(["tests/test_e.py"], []), tags=["P13", "P46", "P52"]))
    add(S("s3-empty-to-symlink", BASE + [("file", "tests/test_e.py", b"")], [("rm", "tests/test_e.py"), ("symlink", "tests/test_e.py", "x")],
          tags=["P13", "P52"]))
    add(S("s3-no-asserts-to-dir", BASE + [("file", "tests/test_n.py", b"x = 1\n")], [("rm", "tests/test_n.py"), ("dir", "tests/test_n.py")],
          tags=["P13", "P52"]))
    add(S("wo-tests-empty-before-marked-to-symlink", BASE + [("file", "tests/test_e.py", b"")],
          [("rm", "tests/test_e.py"), ("symlink", "tests/test_e.py", "x")], writers=(["tests/test_e.py"], []), tags=["P13", "P52"]))
    add(S("wo-tests-empty-after-added", BASE, [("file", "tests/test_e.py", b"")], writers=([], ["tests/test_e.py"]), tags=["P13", "P52"]))
    add(S("wo-tests-empty-before-filled", BASE + [("file", "tests/test_e.py", b"")], [("write", "tests/test_e.py", TEST_API)],
          writers=(["tests/test_e.py"], []), tags=["P13", "P46"]))
    add(S("wo-tests-marked-protected", BASE, [("write", T, WEAK)], spec_of(rule("tests/**", "no_write")), writers=([], [T]), tags=["P47"]))

    # -- configuration: an "any outcome" row stands, a row reading copies has none
    add(S("wo-conftest", BASE, [], writers=([], ["tests/conftest.py"]), tags=["P47"]))
    add(S("wo-conftest-one-side", BASE, [("rm", "tests/conftest.py")], writers=(["tests/conftest.py"], []), tags=["P47"]))
    CI = ".github/workflows/ci.yml"
    add(S("wo-ci", BASE + [("file", CI, CI_YML)], [("write", CI, CI_YML + b"      - run: true\n")], writers=([], [CI]), tags=["P47"]))
    add(S("wo-ci-one-side", BASE, [("file", CI, CI_YML)], writers=([], [CI]), tags=["P47"]))
    add(S("wo-pytest-ini", BASE + [("file", "pytest.ini", PYTEST_INI)], [("write", "pytest.ini", PYTEST_INI + b"xfail_strict = false\n")],
          writers=([], ["pytest.ini"]), tags=["P15"]))
    add(S("wo-pytest-ini-emptied", BASE + [("file", "pytest.ini", PYTEST_INI)], [("write", "pytest.ini", b"")],
          writers=([], ["pytest.ini"]), tags=["P15", "P46"]))
    add(S("wo-pyproject-before", BASE, [("write", "pyproject.toml", PYPROJECT.replace(b'addopts = "-q"', b'addopts = "-x"'))],
          writers=(["pyproject.toml"], []), tags=["P15"]))

    # -- PATH, privilege: read from the manifests
    add(S("wo-path-added", BASE + [("dir", "bin")], [("file", "bin/tool", b"#!/bin/sh\n", 0o755)], writers=([], ["bin/tool"]), tags=["P47"]))
    add(S("wo-path-exec-bits", BASE + [("file", "bin/tool", b"#!/bin/sh\n", 0o644)], [("chmod", "bin/tool", 0o755)],
          writers=([], ["bin/tool"]), tags=["P18", "P47"]))
    add(S("wo-path-replaced", BASE + [("dir", "bin/tool")], [("rmtree", "bin/tool"), ("file", "bin/tool", b"#!/bin/sh\n", 0o755)],
          writers=([], ["bin/tool"]), tags=["P47"]))
    add(S("wo-path-added-not-executable", BASE + [("dir", "bin")], [("file", "bin/data", b"x\n", 0o644)], writers=([], ["bin/data"])))
    add(S("wo-path-exec-bits-before-marked", BASE + [("file", "bin/tool", b"#!/bin/sh\n", 0o644)], [("chmod", "bin/tool", 0o755)],
          writers=(["bin/tool"], []), tags=["P47"]))
    add(S("wo-path-exec-bits-both", BASE + [("file", "bin/tool", b"#!/bin/sh\n", 0o644)], [("chmod", "bin/tool", 0o755)],
          writers=(["bin/tool"], ["bin/tool"]), tags=["P47"]))
    add(S("wo-path-exec-already", BASE + [("file", "bin/tool", b"#!/bin/sh\n", 0o755)], [("write", "bin/tool", b"#!/bin/sh\nexit\n")],
          writers=([], ["bin/tool"]), tags=["P47"]))
    add(S("wo-path-before-to-symlink", BASE + [("file", "bin/tool", b"data\n")], [("rm", "bin/tool"), ("symlink", "bin/tool", "/usr/bin/true")],
          writers=(["bin/tool"], []), tags=["P47"]))
    add(S("wo-path-earlier-rule", BASE + [("dir", "bin", 0o000)], [("chmod", "bin", 0o755), ("file", "bin/tool", b"#!/bin/sh\n", 0o755)],
          writers=([], ["bin/tool"]), tags=["P47"]))
    TOOLB = b"bin/tool"
    add(S("wo-path-raced-too-one-side", BASE + [("dir", "bin")], [("file", "bin/tool", b"\x00\n", 0o755)],
          verify={"to": "check", "after_flags": {TOOLB: ["raced", "writer_open"]}}, tags=["P47"]))
    add(S("wo-path-raced-too-exec-bits", BASE + [("file", "bin/tool", b"\x00\n", 0o644)], [("chmod", "bin/tool", 0o755)],
          verify={"to": "check", "after_flags": {TOOLB: ["raced", "writer_open"]}}, tags=["P47"]))
    add(S("d9-raced-one-side", BASE + [("dir", "bin")], [("file", "bin/tool", b"\x00\n", 0o755)],
          verify={"to": "check", "after_flags": {TOOLB: ["raced"]}}, tags=["P47"]))
    add(S("d9-raced-exec-bits", BASE + [("file", "bin/tool", b"\x00\n", 0o644)], [("chmod", "bin/tool", 0o755)],
          verify={"to": "check", "after_flags": {TOOLB: ["raced"]}}, tags=["P47"]))
    add(S("d9-unreadable-exec-bits", BASE + [("file", "bin/tool", b"#!/bin/sh\n", 0o644)], [("chmod", "bin/tool", 0o111)], tags=["P25", "P47"]))
    add(S("d9-raced-before-marked-after", BASE + [("file", "bin/tool", b"\x00\n", 0o644)], [("chmod", "bin/tool", 0o755)],
          verify={"manifest": "flags", "flags": {TOOLB: ["raced"]}, "to": "check", "after_flags": {TOOLB: ["writer_open"]}}, tags=["P47"]))
    add(S("wo-path-exec-unreadable-after", BASE + [("file", "bin/tool", b"#!/bin/sh\n", 0o644)], [("chmod", "bin/tool", 0o111)],
          writers=(["bin/tool"], []), tags=["P25", "P47"]))
    add(S("wo-priv-setuid", BASE + [("file", "tools/run", b"#!/bin/sh\n", 0o755)], [("chmod", "tools/run", 0o4755)],
          writers=([], ["tools/run"])))
    add(S("wo-priv-one-side", BASE, [("file", "tools/new", b"#!/bin/sh\n", 0o2755)], writers=([], ["tools/new"]), tags=["P32"]))

    # -- git: a marked ref or reflog has no copy; a marked hook is `unknown`, which no hook finding names
    Gt = BASE + git_ops()
    REF, LOG = ".git/refs/heads/main", ".git/logs/refs/heads/main"
    RESET = [("write", REF, (C[0] + "\n").encode()), ("append", LOG, reflog([(C[1], C[0], "reset: moving to HEAD~1")]))]
    add(S("wo-git-ref-after", Gt, RESET, writers=([], [REF]), tags=["P17"]))
    add(S("wo-git-reflog-after", Gt, RESET, writers=([], [LOG]), tags=["P17"]))
    add(S("wo-git-reflog-before", Gt, RESET, writers=([LOG], []), tags=["P17"]))
    add(S("wo-git-reflog-rewritten", Gt, [("write", LOG, reflog(GIT_LOG[:1]))], writers=([], [LOG]), tags=["P17"]))
    add(S("wo-git-reflog-removed", Gt, [("rm", LOG)], writers=([LOG], []), tags=["P17"]))
    add(S("wo-git-hook-changed", Gt, [("write", ".git/hooks/pre-push", b"#!/bin/sh\nexit 1\n")], writers=([], [".git/hooks/pre-push"])))
    add(S("wo-git-hook-added", Gt, [("file", ".git/hooks/pre-commit", b"#!/bin/sh\n", 0o755)], writers=([], [".git/hooks/pre-commit"])))
    add(S("wo-git-hook-removed", Gt, [("rm", ".git/hooks/post-merge")], writers=([".git/hooks/post-merge"], [])))
    add(S("wo-git-hook-exec", Gt, [("chmod", ".git/hooks/post-merge", 0o755)], writers=([], [".git/hooks/post-merge"]), tags=["P16"]))

    # -- packages: the file, the database, on either side; frozen or not
    PYCF_EARLY = SITE + "/pycpkg/__pycache__/core.cpython-312.pyc"
    PYC_TREE_EARLY = (pip_ops("pycpkg", "1.0", {"pycpkg/core.py": (b"def run():\n    return 1\n", 0o644)},
                              extra_rows=["pycpkg/__pycache__/core.cpython-312.pyc,,"]) + [("file", PYCF_EARLY, b"\xcb\x0d\x0d\x0a core")])
    FOO = pip_ops("foo", "1.0", FOO_FILES)
    CORE = SITE + "/foo/core.py"
    REC = SITE + "/foo-1.0.dist-info/RECORD"
    D = dpkg_ops([TOOL, LIBX])
    TOOLF, CONF, STATUS = "usr/bin/tool", "etc/tool.conf", "var/lib/dpkg/status"
    bar = pip_ops("bar", "2.0", {"bar/__init__.py": (b"X = 1\n", 0o644)})
    BAR_REC = SITE + "/bar-2.0.dist-info/RECORD"
    for frozen in (False, True):
        f = "-frozen" if frozen else "-free"
        PS = spec_of(frozen=frozen)
        add(S("wo-pip-file-after" + f, BASE + FOO, [], PS, writers=([], [CORE])))
        add(S("wo-pip-file-before-removed" + f, BASE + FOO, [("rm", CORE)], PS, writers=([CORE], [])))
        add(S("wo-pip-record-after" + f, BASE + FOO, [], PS, writers=([], [REC]), tags=["P51"], refusal="verify:writer-held-database"))
        add(S("wo-dpkg-file-after" + f, BASE + D, [("write", TOOLF, b"#!/bin/sh\necho owned\n")], PS, writers=([], [TOOLF])))
        add(S("wo-pip-install-record" + f, BASE + FOO, bar, PS, writers=([], [BAR_REC]), tags=["P51"], refusal="verify:writer-held-database"))
    add(S("wo-pip-record-before", BASE + FOO, [], spec_of(), writers=([REC], []), tags=["P51"], refusal="export:writer-held-database"))
    add(S("wo-pip-record-forged", BASE + FOO,
          [op for op in pip_ops("foo", "1.0", dict(FOO_FILES, **{"foo/core.py": (b"def run():\n    return 9\n", 0o644)}))
           if op[1] in (CORE, REC)], spec_of(), writers=([], [REC]), tags=["P51"], refusal="verify:writer-held-database"))
    add(S("wo-pip-removed-record", BASE + FOO, [("rmtree", SITE + "/foo-1.0.dist-info"), ("rmtree", SITE + "/foo")], spec_of(),
          writers=([REC], []), tags=["P51"], refusal="export:writer-held-database"))
    add(S("wo-pip-install-file", BASE + FOO, bar, spec_of(), writers=([], [SITE + "/bar/__init__.py"]), tags=["P43"]))
    up = ([("rmtree", SITE + "/foo-1.0.dist-info")] + pip_ops("foo", "2.0", FOO_FILES, write=False))
    add(S("wo-pip-upgrade-record", BASE + FOO, up, spec_of(), writers=([], [SITE + "/foo-2.0.dist-info/RECORD"]), tags=["P51"], refusal="verify:writer-held-database"))
    add(S("wo-pip-at-reset-match", BASE + FOO, [], spec_of(), writers=([CORE], []), tags=["P44"]))
    add(S("wo-pip-at-reset-mismatch", BASE + pip_ops("baz", "0.1", {"baz.py": (b"B = 1\n", 0o644)}, bad={"baz.py"}), [], spec_of(),
          writers=([SITE + "/baz.py"], []), tags=["P44"]))
    add(S("wo-pip-pth-in-marked-record", BASE + pip_ops("pthpkg", "1.0", {"pthpkg.pth": (b"import pthpkg\n", 0o644)}),
          [("write", SITE + "/pthpkg.pth", b"import os\n")], spec_of(),
          writers=([], [SITE + "/pthpkg-1.0.dist-info/RECORD"]), tags=["P51"], refusal="verify:writer-held-database"))
    add(S("wo-dpkg-at-reset-mismatch", BASE + dpkg_ops([dict(TOOL, md5_override={"usr/share/doc/tool/README": "f" * 32})]), [], spec_of(),
          writers=(["usr/share/doc/tool/README"], []), tags=["P44"]))
    add(S("wo-pyc-at-reset-no-hash", BASE + PYC_TREE_EARLY, [], spec_of(), writers=([PYCF_EARLY], []), tags=["P44"]))
    add(S("wo-pip-pth-marked", BASE + FOO, [("file", SITE + "/evil.pth", b"import os\n")], writers=([], [SITE + "/evil.pth"]), tags=["P47"]))
    PYCF = SITE + "/pycpkg/__pycache__/core.cpython-312.pyc"
    PYC_TREE = (pip_ops("pycpkg", "1.0", {"pycpkg/core.py": (b"def run():\n    return 1\n", 0o644)},
                        extra_rows=["pycpkg/__pycache__/core.cpython-312.pyc,,"]) + [("file", PYCF, b"\xcb\x0d\x0d\x0a core")])
    add(S("wo-pyc-marked", BASE + PYC_TREE, [("write", PYCF, b"\xcb\x0d\x0d\x0a PATCHED")], spec_of(), writers=([], [PYCF]), tags=["P36"]))
    add(S("wo-dpkg-conffile", BASE + D, [("write", CONF, b"verbose = true\n")], spec_of(), writers=([], [CONF]), tags=["P47"]))
    add(S("wo-dpkg-at-reset", BASE + D, [], spec_of(), writers=([TOOLF], []), tags=["P44"]))
    add(S("wo-dpkg-status-before", BASE + D, [], spec_of(), writers=([STATUS], []), tags=["P51"], refusal="export:writer-held-database"))
    add(S("wo-dpkg-status-to-checkpoint", BASE + D, [], spec_of(), writers=([], [STATUS]), verify={"to": "check"}, tags=["P51"],
          refusal="verify:writer-held-database"))
    add(S("wo-dpkg-status-nospec", BASE + D, [], None, writers=([], [STATUS]), tags=["P51"], refusal="verify:writer-held-database"))
    add(S("wo-dpkg-list-not-refused", BASE + D, [], spec_of(), writers=(["var/lib/dpkg/info/tool.list"], ["var/lib/dpkg/info/tool.list"]),
          tags=["P51"]))
    add(S("wo-pip-metadata-not-refused", BASE + FOO, [], spec_of(), writers=([SITE + "/foo-1.0.dist-info/METADATA"], []), tags=["P51"]))
    add(S("wo-dpkg-md5sums-stray", BASE + D + [("file", "var/lib/dpkg/info/gone.md5sums", b"")], [], spec_of(),
          writers=(["var/lib/dpkg/info/gone.md5sums"], []), tags=["P51"], refusal="export:writer-held-database"))
    add(S("wo-dpkg-status-after", BASE + D, [], spec_of(), writers=([], [STATUS]), tags=["P51"], refusal="verify:writer-held-database"))
    add(S("wo-dpkg-md5sums-before", BASE + D, [], spec_of(), writers=(["var/lib/dpkg/info/tool.md5sums"], []), tags=["P51"], refusal="export:writer-held-database"))
    tool2 = dict(TOOL, version="1.1-1", files=dict(TOOL["files"], **{TOOLF: (TOOL_V2, 0o755)}))
    upg = [op for op in dpkg_ops([tool2, LIBX]) if op[1] != CONF]
    add(S("wo-dpkg-upgrade-status", BASE + D, upg, spec_of(), writers=([], [STATUS]), tags=["P51"], refusal="verify:writer-held-database"))
    add(S("wo-dpkg-upgrade-file", BASE + D, upg, spec_of(), writers=([], [TOOLF]), tags=["P10", "P43"]))

    # -- V4-R6: mark never trusts a marked entry; a writer gone is read again, one still there marked
    add(S("wo-mark-writer-gone", BASE, [], None, writers=([], ["README.md"]), verify={"to": "trusted", "mark_writers": "first"}))
    add(S("wo-mark-hardlink-writer-gone", BASE + [("hardlink", "elsewhere/readme", "README.md")], [], None,
          writers=([], ["elsewhere/readme"]), verify={"to": "trusted", "mark_writers": "first"}))
    add(S("wo-mark-writer-stays", BASE, [], None, writers=([], ["README.md"]), verify={"to": "trusted", "mark_writers": "both"}))

    # -- V4-R2, V4-R4: earlier manifests read as unmarked, and a strict reader's refusals
    add(S("verify-v3-bundle", BASE, [("write", "tests/test_api.py", TEST_API.replace(b"        assert True\n", b""))],
          spec_of(rule("tests/**", "no_write")), verify={"manifest": "v3"}, tags=["P41"]))
    add(S("verify-v3-bundle-packages", BASE + FOO, [("write", CORE, b"x = 1\n")], spec_of(frozen=True), verify={"manifest": "v3"}, tags=["P41"]))
    add(S("verify-v4-unguarded-at-its-bound", BASE, [], None, verify={"manifest": "unguarded-max"}))
    for how in ("trailer-missing-writer-open", "trailer-missing-unguarded", "v3-with-trailer-key", "v3-with-entry-key",
                "count-too-low", "count-too-high", "unguarded-too-large", "false", "not-a-bool", "on-stored", "on-dir", "on-unverified", "no-hash"):
        tree = BASE + [("file", "data/blob.bin", BLOB)] + ([("sparse", "data/big.bin", 67108865)] if how == "on-unverified" else [])
        add(S("verify-v4-refused-" + how, tree, [], None, verify={"manifest": "break:" + how}, refusal="verify:v4-" + how))
    return out


def _j(s):
    return s.encode()


V = '{"belay_protect":1,"protect":[%s]}'
R = '{"path":"tests/**","mode":["no_write"]}'
SPEC_REFUSALS = [
    ("not-json", b"{", []),
    ("trailing-bytes", _j(V % R + " x"), []),
    ("two-objects", _j(V % R + V % R), []),
    ("not-object", b"[]", []),
    ("not-utf8", b'{"belay_protect":1,"protect":[{"path":"t\xff","mode":["no_write"]}]}', []),
    ("over-1mib", _j('{"belay_protect":1,"protect":[]%s}' % (" " * (1 << 20))), []),
    ("nan", b'{"belay_protect":NaN,"protect":[]}', []),
    ("unknown-key", _j('{"belay_protect":1,"protect":[],"frozen":true}'), []),
    ("unknown-rule-key", _j(V % '{"path":"a","mode":["no_write"],"modes":[]}'), []),
    ("dup-key", _j('{"belay_protect":1,"protect":[],"protect":[]}'), []),
    ("dup-rule-key", _j(V % '{"path":"a","path":"b","mode":["no_write"]}'), []),
    ("version-2", _j('{"belay_protect":2,"protect":[]}'), []),
    ("version-string", _j('{"belay_protect":"1","protect":[]}'), []),
    ("version-float", _j('{"belay_protect":1.0,"protect":[]}'), ["P27"]),
    ("version-true", _j('{"belay_protect":true,"protect":[]}'), []),
    ("version-missing", _j('{"protect":[]}'), []),
    ("protect-missing", _j('{"belay_protect":1}'), []),
    ("protect-object", _j('{"belay_protect":1,"protect":{}}'), []),
    ("protect-over-4096", _j(V % ",".join(['{"path":"a","mode":["no_write"]}'] * 4097)), []),
    ("rule-not-object", _j(V % '"tests/**"'), []),
    ("path-missing", _j(V % '{"mode":["no_write"]}'), []),
    ("path-number", _j(V % '{"path":1,"mode":["no_write"]}'), []),
    ("path-leading-slash", _j(V % '{"path":"/tests","mode":["no_write"]}'), []),
    ("path-trailing-slash", _j(V % '{"path":"tests/","mode":["no_write"]}'), []),
    ("path-empty-component", _j(V % '{"path":"a//b","mode":["no_write"]}'), []),
    ("path-dot", _j(V % '{"path":"a/./b","mode":["no_write"]}'), []),
    ("path-dotdot", _j(V % '{"path":"../etc","mode":["no_write"]}'), []),
    ("path-empty", _j(V % '{"path":"","mode":["no_write"]}'), []),
    ("path-over-4096", _j(V % ('{"path":"%s","mode":["no_write"]}' % ("a" * 4097))), []),
    ("mode-string", _j(V % '{"path":"a","mode":"no_write"}'), []),
    ("mode-unknown", _j(V % '{"path":"a","mode":["no_read"]}'), []),
    ("mode-twice", _j(V % '{"path":"a","mode":["no_write","no_write"]}'), []),
    ("mode-number", _j(V % '{"path":"a","mode":[1]}'), []),
    ("mode-none-no-hash", _j(V % '{"path":"a"}'), []),
    ("mode-empty-no-hash", _j(V % '{"path":"a","mode":[]}'), ["P28"]),
    ("hash-uppercase", _j(V % ('{"path":"a","expected_sha256":"%s"}' % ("A" * 64))), []),
    ("hash-short", _j(V % ('{"path":"a","expected_sha256":"%s"}' % ("a" * 63))), []),
    ("hash-null", _j(V % '{"path":"a","mode":["no_write"],"expected_sha256":null}'), []),
    ("hash-with-star", _j(V % ('{"path":"a/*.py","expected_sha256":"%s"}' % ("a" * 64))), []),
    ("frozen-string", _j('{"belay_protect":1,"protect":[],"frozen_packages":"yes"}'), []),
    ("frozen-null", _j('{"belay_protect":1,"protect":[],"frozen_packages":null}'), []),
    ("path-dirs-string", _j('{"belay_protect":1,"protect":[],"path_dirs":"bin"}'), []),
    ("path-dirs-bad-pattern", _j('{"belay_protect":1,"protect":[],"path_dirs":["/bin"]}'), []),
    ("path-dirs-number", _j('{"belay_protect":1,"protect":[],"path_dirs":[1]}'), []),
    ("path-dirs-over-256", _j('{"belay_protect":1,"protect":[],"path_dirs":[%s]}' % ",".join(['"bin"'] * 257)), []),
]
