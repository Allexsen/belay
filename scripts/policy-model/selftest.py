#!/usr/bin/env python3
"""policy-model's self-tests: fixtures whose expected output was computed by hand from the pins,
so the model stands on its own before belay can be compared with it.

  python3 -I -B scripts/policy-model/selftest.py
"""

import base64
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import model  # noqa: E402

FAILS = []


def check(what, got, want):
    if got != want:
        FAILS.append(what)
        print("selftest FAIL %s\n  want: %r\n  got:  %r" % (what, want, got))


def raw(t, mode, data=None, ino=1, mtime=100, iflags=0, link=None, nlink=1):
    return {"type": t, "mode": mode, "uid": 1000, "gid": 1000,
            "size": len(data) if data is not None else (len(link) if link else 4096),
            "mtime_ns": mtime, "ctime_ns": mtime, "ino": ino, "dev": 10, "nlink": nlink,
            "iflags": iflags if t in ("reg", "dir") else None, "caps": None, "xattrs": None,
            "xattrs_unknown": False, "readable": True, "data": data, "link_target": link, "rdev": None}


D = 0o40755
F = 0o100644

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
'''

ZERO_KINDS = ('"protected_path_written":0,"protected_path_deleted":0,"protected_path_created":0,'
              '"protected_hash_mismatch":0,"protected_path_unverifiable":0,"package_changed":0,'
              '"tampered_installed_package":0,"conffile_changed":0,"touches_tests":0,"tests_weakened":0,'
              '"edits_ci_config":0,"pytest_config_changed":0,"conftest_changed":0,'
              '"python_startup_hook_changed":0,"git_hook_changed":0,"git_history_rewritten":0,'
              '"new_executable_on_path":0,"privilege_changed":0,"writes_outside_workdir":0')


def kinds(**n):
    s = ZERO_KINDS
    for k, v in n.items():
        s = s.replace('"%s":0' % k, '"%s":%d' % (k, v))
    return s


NOT_EMITTED = '"not_emitted":[{"flag":"writes_outside_workdir","why":"needs a scope wider than the workdir"}],"tests_counted":["python"]}'


def verify(spec_raw, before, after, lines=(), outside=0):
    spec = model.parse_spec(spec_raw) if spec_raw is not None else None
    hm = model.HASH_BOUND_SPEC if spec else model.HASH_DEFAULT
    ctx = {"scope": "/w", "bundle_sha256": "b" * 64, "spec": spec,
           "before": model.Side(model.view(before, hm), 10, []),
           "after": model.Side(model.view(after, hm), 10, []),
           "bundle_lines": list(lines), "outside_scope": outside,
           "before_sha256": "1" * 64, "after_sha256": "2" * 64}
    out, flags, _r, _e = model.verify_lines(ctx)
    return [model.enc(o) for o in out], flags


def fixture_protected_write():
    spec = b'{"belay_protect":1,"protect":[{"path":"tests/**","mode":["no_write"]}]}'
    before = {b".": raw("dir", D, ino=2), b"tests": raw("dir", D, ino=3),
              b"tests/test_api.py": raw("reg", F, TEST_API, ino=4)}
    after = dict(before)
    after[b"tests/test_api.py"] = raw("reg", F, TEST_API.replace(b"        assert True\n", b""), ino=4, mtime=200)
    after[b"."] = raw("dir", D, ino=2, mtime=300)              # a directory's times: not compared
    got, flags = verify(spec, before, after)
    want = [
        '{"belay_policy":1,"scopes":["/w"],"baseline_sha256":"%s","protect_sha256":"%s","frozen_packages":false,'
        '"before_excluded":[],"after_excluded":[],' % ("b" * 64, hashlib.sha256(spec).hexdigest()) + NOT_EMITTED,
        '{"flag":"protected_path_written","level":"violation","path":"tests/test_api.py","rule":"tests/**",'
        '"outcome":"modified","changed":["size","mtime_ns","sha256"],'
        '"text":"tests/test_api.py: protected by tests/** (no_write), modified","paths":["tests/test_api.py"]}',
        '{"flag":"touches_tests","level":"signal","path":"tests/test_api.py","outcome":"modified",'
        '"text":"tests/test_api.py: test file modified","paths":["tests/test_api.py"]}',
        '{"flag":"tests_weakened","level":"signal","path":"tests/test_api.py","language":"python",'
        '"assertions_before":6,"assertions_after":5,"tests_before":3,"tests_after":3,"markers_added":[],'
        '"text":"tests/test_api.py: assertions 6 -> 5, tests 3 -> 3, markers added: none","paths":["tests/test_api.py"]}',
        '{"belay_policy_end":3,"violations":1,"signals":2,'
        + kinds(protected_path_written=1, touches_tests=1, tests_weakened=1)
        + ',"unknown":0,"packages_outside_scope":0,"packages_no_hash":0,"provisional":false,'
        '"before_sha256":"%s","after_sha256":"%s"}' % ("1" * 64, "2" * 64),
    ]
    check("protected write and weakened test", got, want)
    check("exit with --exit-code", model.verify_exit(flags, True), 1)
    check("exit without --exit-code", model.verify_exit(flags, False), 0)


def fixture_privilege_path():
    before = {b".": raw("dir", D, ino=2), b"bin": raw("dir", D, ino=3)}
    after = dict(before)
    after[b"bin/x"] = raw("reg", 0o104755, b"#!/bin/sh\n", ino=5, mtime=200)
    got, flags = verify(None, before, after)
    want = [
        '{"belay_policy":1,"scopes":["/w"],"baseline_sha256":"%s","protect_sha256":null,"frozen_packages":false,'
        '"before_excluded":[],"after_excluded":[],' % ("b" * 64) + NOT_EMITTED,
        '{"flag":"new_executable_on_path","level":"signal","path":"bin/x","outcome":"added","mode":35309,'
        '"text":"bin/x: executable on PATH, added","paths":["bin/x"]}',
        '{"flag":"privilege_changed","level":"signal","path":"bin/x","what":"iflags","before":"none","after":"0",'
        '"text":"bin/x: iflags none -> 0","paths":["bin/x"]}',
        '{"flag":"privilege_changed","level":"signal","path":"bin/x","what":"setuid","before":"off","after":"on",'
        '"text":"bin/x: setuid off -> on","paths":["bin/x"]}',
        '{"belay_policy_end":3,"violations":0,"signals":3,'
        + kinds(new_executable_on_path=1, privilege_changed=2)
        + ',"unknown":0,"packages_outside_scope":0,"packages_no_hash":0,"provisional":false,'
        '"before_sha256":"%s","after_sha256":"%s"}' % ("1" * 64, "2" * 64),
    ]
    check("privilege and PATH, an added setuid file", got, want)
    check("signals never fail a run", model.verify_exit(flags, True), 0)


def b64sha(d):
    return base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b"=").decode()


def fixture_pip_bundle():
    record = ("foo.py,sha256=%s,2\n../bin/foo,sha256=%s,2\n../../out.py,sha256=%s,1\n"
              "foo-1.0.dist-info/RECORD,,\n" % (b64sha(b"x\n"), b64sha(b"y\n"), b64sha(b"o"))).encode()
    B = {b".": raw("dir", D), b"sp": raw("dir", D), b"sp/foo-1.0.dist-info": raw("dir", D),
         b"sp/foo-1.0.dist-info/RECORD": raw("reg", F, record), b"sp/foo.py": raw("reg", F, b"x\n"),
         b"bin": raw("dir", D), b"bin/foo": raw("reg", 0o100755, b"z\n")}
    code, exp = model.export_expect("/w", "/out/b.bundle", None, [], B)
    check("export exit", code, 0)
    check("packages member", model.packages_member(exp["lines"]).decode().split("\n"), [
        '{"db":"pip","package":"foo","version":"1.0","path":"bin/foo","at_reset":"mismatch"}',
        '{"db":"pip","package":"foo","version":"1.0","path":"sp/foo-1.0.dist-info/RECORD","at_reset":"no_hash"}',
        '{"db":"pip","package":"foo","version":"1.0","path":"sp/foo.py","at_reset":"match"}', ""])
    check("outside_scope", exp["outside"], 1)
    check("baseline_integrity", exp["integrity"], [
        {"db": "pip", "package": "foo", "version": "1.0", "path": "bin/foo", "at_reset": "mismatch"},
        {"db": "pip", "package": "foo", "version": "1.0", "path": "sp/foo-1.0.dist-info/RECORD", "at_reset": "no_hash"}])
    check("--out inside the scope", model.export_expect("/w", "/w/b.bundle", None, [], B)[0], 3)


def fixture_dpkg_bundle_and_tamper():
    tool = b"#!/bin/sh\n"
    conf = b"a = 1\n"
    status = ("Package: tool\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n"
              "Conffiles:\n /etc/tool.conf %s\n" % hashlib.md5(conf).hexdigest()).encode()
    sums = ("%s  usr/bin/tool\n" % hashlib.md5(tool).hexdigest()).encode()
    B = {b".": raw("dir", D), b"etc": raw("dir", D), b"etc/tool.conf": raw("reg", F, conf, ino=7),
         b"usr": raw("dir", D), b"usr/bin": raw("dir", D), b"usr/bin/tool": raw("reg", 0o100755, tool, ino=8),
         b"var": raw("dir", D), b"var/lib": raw("dir", D), b"var/lib/dpkg": raw("dir", D),
         b"var/lib/dpkg/status": raw("reg", F, status), b"var/lib/dpkg/info": raw("dir", D),
         b"var/lib/dpkg/info/tool.md5sums": raw("reg", F, sums)}
    code, exp = model.export_expect("/w", "/out/b.bundle", b'{"belay_protect":1,"protect":[],"frozen_packages":true}', [], B)
    check("dpkg packages member", model.packages_member(exp["lines"]).decode().split("\n"), [
        '{"db":"dpkg","package":"tool:amd64","version":"1.0-1","path":"etc/tool.conf","conffile":true,"at_reset":"match"}',
        '{"db":"dpkg","package":"tool:amd64","version":"1.0-1","path":"usr/bin/tool","at_reset":"match"}', ""])
    A = dict(B)
    A[b"usr/bin/tool"] = raw("reg", 0o100755, b"#!/bin/sh\necho owned\n", ino=8, mtime=200)
    A[b"etc/tool.conf"] = raw("reg", F, b"a = 2\n", ino=7, mtime=200)
    ctx = {"scope": "/w", "bundle_sha256": "b" * 64, "spec": exp["spec"],
           "before": model.Side(exp["B"], 10, []), "after": model.Side(model.view(A, exp["hash_max"]), 10, []),
           "bundle_lines": exp["lines"], "outside_scope": 0, "before_sha256": "1" * 64, "after_sha256": "2" * 64}
    out, flags, _r, _e = model.verify_lines(ctx)
    check("frozen dpkg: tampered is a violation, a conffile a signal", [model.enc(o) for o in out[1:-1]], [
        '{"flag":"tampered_installed_package","level":"violation","db":"dpkg","package":"tool:amd64",'
        '"path":"usr/bin/tool","why":"other bytes","at_reset":"match",'
        '"text":"tool:amd64: installed file usr/bin/tool other bytes","paths":["usr/bin/tool"]}',
        '{"flag":"conffile_changed","level":"signal","package":"tool:amd64","path":"etc/tool.conf","outcome":"modified",'
        '"text":"tool:amd64: conffile etc/tool.conf modified","paths":["etc/tool.conf"]}'])


def fixture_git_reset():
    c1, c2 = "1" * 40, "2" * 40
    log1 = ("0000000000000000000000000000000000000000 %s A <a@b> 1 +0000\tcommit (initial): x\n" % c1).encode()
    log2 = log1 + ("%s %s A <a@b> 2 +0000\tcommit: y\n" % (c1, c2)).encode()
    log3 = log2 + ("%s %s A <a@b> 3 +0000\treset: moving to HEAD~1\n" % (c2, c1)).encode()
    B = {b".": raw("dir", D)}
    for d in (b".git", b".git/refs", b".git/refs/heads", b".git/logs", b".git/logs/refs", b".git/logs/refs/heads"):
        B[d] = raw("dir", D)
    B[b".git/refs/heads/main"] = raw("reg", F, (c2 + "\n").encode(), ino=20)
    B[b".git/logs/refs/heads/main"] = raw("reg", F, log2, ino=21)
    A = dict(B)
    A[b".git/refs/heads/main"] = raw("reg", F, (c1 + "\n").encode(), ino=20, mtime=200)
    A[b".git/logs/refs/heads/main"] = raw("reg", F, log3, ino=21, mtime=200)
    got, _f = verify(None, B, A)
    check("history rewritten by reset", got[1:-1], [
        '{"flag":"git_history_rewritten","level":"signal","repo":".git","branch":"main","how":"reset",'
        '"text":"main in .git: history rewritten by reset",'
        '"paths":[".git/logs/refs/heads/main",".git/refs/heads/main"]}'])
    A[b".git/logs/refs/heads/main"] = raw("reg", F, log1, ino=21, mtime=200)
    A[b".git/refs/heads/main"] = B[b".git/refs/heads/main"]
    got, _f = verify(None, B, A)
    check("reflog rewritten", got[1:-1], [
        '{"flag":"git_history_rewritten","level":"signal","repo":".git","branch":"refs/heads/main",'
        '"text":"refs/heads/main in .git: reflog rewritten","paths":[".git/logs/refs/heads/main"]}'])


def tables():
    P = [("tests/**", "tests", True), ("tests/**", "tests/a/b", True), ("tests/**", "tests/.cache/x", False),
         (".github/workflows/**", ".github/workflows/ci.yml", True), ("tests/.cache/**", "tests/.cache/x", True),
         (".*", ".env", True), ("*", ".env", False), ("tests/test_*.py", "tests/test_a.py", True),
         ("tests/test_*.py", "tests/test_.py", True), ("a?b", "a?b", True), ("a?b", "axb", False),
         ("[x]", "[x]", True), ("a\\b", "a\\b", True), ("**", "a/b", True), ("**/c", "a/.b/c", False),
         ("**/c", "c", True), ("a/*/c", "a/b/c", True), ("a/*/c", "a/b/d/c", False), ("*", "x/y", False),
         ("**", ".", False), ("*rc", ".bashrc", False), ("a*", "A", False)]
    for pat, path, want in P:
        check("match %s %s" % (pat, path), model.pat_match(pat.encode().split(b"/"), path.encode()), want)
    Cv = [("tests/**", "tests", True), ("tests/**", "tests/fixtures", True), ("tests/**", "node_modules", False),
          ("**/conftest.py", "vendor", True), ("**/x.py", ".cache", False), ("a", "a/b", False),
          ("a/b", "a", True), ("tests/**", "tests/.cache", False), ("**", "x", True)]
    for pat, ex, want in Cv:
        check("covers %s %s" % (pat, ex), model.covers(pat.encode().split(b"/"), ex.encode()), want)
    for raw_ in (b'{"belay_protect":1,"protect":[]}',
                 b' {"belay_protect":1,"protect":[{"path":"a/*","mode":["no_create","no_write"]}],"path_dirs":[]} \n'):
        try:
            model.parse_spec(raw_)
        except model.Refused as r:
            check("spec accepted: %r" % raw_, r.why, None)
    for raw_ in (b'{"belay_protect":1,"protect":[],"protect":[]}', b'{"belay_protect":1}', b'{"belay_protect":1,"protect":[]} 1',
                 b'{"belay_protect":1,"protect":[{"path":"a"}]}', b'{"belay_protect":1,"protect":[{"path":"a/","mode":["no_write"]}]}'):
        try:
            model.parse_spec(raw_)
            check("spec refused: %r" % raw_, "accepted", "refused")
        except model.Refused as r:
            check("spec refused with 2: %r" % raw_, r.code, 2)
    check("python counts", model.count_python(TEST_API), (6, 3))
    check("unittest counts", model.count_python(b"class T:\n    def test_a(self):\n        self.assertEqual(1, 1)\n"
                                                b"        np.testing.assert_allclose(a, b)\n    async def test_b(self):\n"
                                                b"        assert(x)\n"), (3, 2))
    check("markers", model.markers_added(TEST_API, TEST_API.replace(b"def test_two", b'@pytest.mark.skip(reason="flaky")\ndef test_two')),
          ['@pytest.mark.skip(reason="flaky")'])
    check("test files", [model.is_test_file(p) for p in (b"tests", b"a/spec/b", b"x/test_y.c", b"y_test.go", b"a.test.js",
                                                          b"b.spec.ts", b"src/app.py", b"testing/x", b"attest_x")],
          [True, True, True, True, True, True, False, False, False])
    check("CI paths", [model.is_ci(p) for p in (b".github/workflows/ci.yml", b".github/workflows", b".github/CODEOWNERS",
                                                b".circleci/config.yml", b"a/.gitlab-ci.yml", b"Jenkinsfile.bak")],
          [True, False, False, True, True, False])
    check("pytest sections", model.pytest_change(b"pyproject.toml", b"[tool.pytest.ini_options]\na = 1\n[x]\n",
                                                 b"[tool.pytest.ini_options]\na = 2\n[x]\n"), "[tool.pytest.ini_options]")
    check("pytest other section", model.pytest_change(b"tox.ini", b"[tox]\na\n[pytest]\nb\n", b"[tox]\nc\n[pytest]\nb\n"), None)
    check("debian order", [model.deb_cmp("1.1-1", "1.0-1") > 0, model.deb_cmp("1.0~rc1", "1.0") < 0,
                           model.deb_cmp("1:0.1", "2.0") > 0], [True, True, True])
    check("pep 440 order", model.pep440_key("2.0") > model.pep440_key("1.0") > model.pep440_key("1.0rc1"), True)
    check("lexical resolution", [model.resolve_lexically(b"a/b/c", "../../../bin/x", "/w"),
                                 model.resolve_lexically(b"a/b/c", "../../../../x", "/w")], [b"bin/x", None])


def run():
    del FAILS[:]
    for f in (tables, fixture_protected_write, fixture_privilege_path, fixture_pip_bundle,
              fixture_dpkg_bundle_and_tamper, fixture_git_reset):
        try:
            f()
        except Exception as e:  # a crash is a failure, named
            FAILS.append(f.__name__)
            print("selftest CRASH %s: %r" % (f.__name__, e))
            import traceback
            traceback.print_exc()
    return len(FAILS)


if __name__ == "__main__":
    n = run()
    print("self-tests: %s" % ("passed" if not n else "%d failed" % n))
    sys.exit(1 if n else 0)
