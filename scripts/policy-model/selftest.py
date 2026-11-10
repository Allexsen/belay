#!/usr/bin/env python3
"""policy-model's self-tests: fixtures whose expected output was computed by hand from the pins,
so the model stands on its own before belay can be compared with it.

  python3 -I -B scripts/policy-model/selftest.py
"""

import base64
import hashlib
import json
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


def verify(spec_raw, before, after, lines=(), outside=0, wb=frozenset(), wa=frozenset()):
    spec = model.parse_spec(spec_raw) if spec_raw is not None else None
    hm = model.HASH_BOUND_SPEC if spec else model.HASH_DEFAULT
    ctx = {"scope": "/w", "bundle_sha256": "b" * 64, "spec": spec,
           "before": model.Side(model.view(before, hm, wb), 10, []),
           "after": model.Side(model.view(after, hm, wa), 10, []),
           "bundle_lines": list(lines), "outside_scope": outside,
           "before_sha256": "1" * 64, "after_sha256": "2" * 64}
    out, flags, _r, _e = model.verify_lines(ctx)
    return [model.enc(o) for o in out], flags


def fixture_protected_write():
    spec = b'{"belay_protect":2,"protect":[{"path":"tests/**","mode":["no_write"]}]}'
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
        '{"flag":"privilege_changed","level":"signal","path":"bin/x","what":"setuid","before":"off","after":"on",'
        '"text":"bin/x: setuid off -> on","paths":["bin/x"]}',
        '{"belay_policy_end":2,"violations":0,"signals":2,'
        + kinds(new_executable_on_path=1, privilege_changed=1)
        + ',"unknown":0,"packages_outside_scope":0,"packages_no_hash":0,"provisional":false,'
        '"before_sha256":"%s","after_sha256":"%s"}' % ("1" * 64, "2" * 64),
    ]
    check("privilege and PATH, an added setuid file (its iflags 0: no record, decision 163)", got, want)
    check("signals never fail a run", model.verify_exit(flags, True), 0)


def fixture_iflags_decision_163():
    before = {b".": raw("dir", D, ino=2), b"d": raw("dir", D, ino=3),
              b"d/gone": raw("reg", F, b"g\n", ino=4, iflags=0x80020),       # extents + append-only
              b"d/plain-gone": raw("reg", F, b"p\n", ino=5, iflags=0x80000),
              b"d/kept": raw("reg", F, b"k\n", ino=6, iflags=0x80000)}
    after = {b".": raw("dir", D, ino=2), b"d": raw("dir", D, ino=3),
             b"d/new": raw("reg", F, b"n\n", ino=7, iflags=0x80010),         # extents + immutable
             b"d/plain-new": raw("reg", F, b"q\n", ino=8, iflags=0x80000),   # extents only: no privilege
             b"d/kept": raw("reg", F, b"k\n", ino=6, iflags=0x80040)}        # + nodump: a change on both sides
    got, _f = verify(None, before, after)
    check("iflags: locking flags on one side, any change on both", got[1:-1], [
        '{"flag":"privilege_changed","level":"signal","path":"d/gone","what":"iflags","before":"524320","after":"none",'
        '"text":"d/gone: iflags 524320 -> none","paths":["d/gone"]}',
        '{"flag":"privilege_changed","level":"signal","path":"d/kept","what":"iflags","before":"524288","after":"524352",'
        '"text":"d/kept: iflags 524288 -> 524352","paths":["d/kept"]}',
        '{"flag":"privilege_changed","level":"signal","path":"d/new","what":"iflags","before":"none","after":"524304",'
        '"text":"d/new: iflags none -> 524304","paths":["d/new"]}'])


def fixture_inode_flags():
    """inode-flags.md by hand, row by row (IF-8 is the receipt's: not this model's). The values:
    0x80000 ext4's extents (524288), 0x1000 its hashed index, 0x40 nodump, 0x10 immutable,
    0x20 append-only."""
    priv = ('{"flag":"privilege_changed","level":"signal","path":"%s","what":"iflags","before":"%s","after":"%s",'
            '"text":"%s: iflags %s -> %s","paths":["%s"]}')

    def P(path, x, y):
        return priv % (path, x, y, path, x, y, path)

    def written(path, changed):
        return ('{"flag":"protected_path_written","level":"violation","path":"%s","rule":"tests/**",'
                '"outcome":"metadata_only","changed":%s,'
                '"text":"%s: protected by tests/** (no_write), metadata_only","paths":["%s"]}' % (path, changed, path, path))

    def recs_of(before, after):
        return model.diff(model.Side(model.view(before, model.HASH_DEFAULT), 10, []),
                          model.Side(model.view(after, model.HASH_DEFAULT), 10, []))

    root = {b".": raw("dir", D, ino=2)}

    # IF-1, IF-2, IF-7: directories at both ends, no spec
    before = {**root, b"d1": raw("dir", D, ino=3, iflags=0x80000), b"d2": raw("dir", D, ino=4, iflags=0x80000),
              b"d3": raw("dir", D, ino=5, iflags=0x80020), b"d4": raw("dir", D, ino=6, iflags=0x80010),
              b"d5": raw("dir", D, ino=7, iflags=0x10)}
    after = {**root, b"d1": raw("dir", D, ino=3, iflags=0x81000),     # hashed index set: does not count
             b"d2": raw("dir", D, ino=4, iflags=0x80010),             # immutable set
             b"d3": raw("dir", D, ino=5, iflags=0x80000),             # append-only cleared
             b"d4": raw("dir", D, ino=6, iflags=0x81010),             # immutable kept, hashed index set (P55)
             b"d5": raw("dir", D, ino=7, iflags=0x20)}                # immutable cleared, append-only set (P55)
    got, _f = verify(None, before, after)
    check("IF-2, IF-7: a directory's flags count only when a locking flag is set or cleared", got[1:-1],
          [P("d2", 524288, 524304), P("d3", 524320, 524288), P("d5", 16, 32)])
    r = recs_of(before, after)
    quiet = {"outcome": "metadata_only", "type": "dir", "changed": ["iflags"]}
    check("IF-9: the diff still lists iflags, metadata_only", [r.get(b"d1"), r.get(b"d4"), r.get(b"d2")], [quiet, quiet, quiet])

    # IF-6 and the pin's example: a spec with tests/** as no_write
    spec = b'{"belay_protect":2,"protect":[{"path":"tests/**","mode":["no_write"]}]}'

    def tests_dir(mode_after, flags_after, spec_raw=spec):
        b = {**root, b"tests": raw("dir", D, ino=3, iflags=0x80000)}
        a = {**root, b"tests": raw("dir", mode_after, ino=3, iflags=flags_after)}
        got, flags = verify(spec_raw, b, a)
        return got[1:-1], model.verify_exit(flags, True)
    check("the example: the hashed index set on tests gives neither", tests_dir(D, 0x81000), ([], 0))
    check("the example: chattr +i tests still gives both", tests_dir(D, 0x80010),
          ([written("tests", '["iflags"]'), P("tests", 524288, 524304)], 1))
    check("IF-6: mode also changed: a violation, changed as the diff lists it; IF-7: no iflags record",
          tests_dir(0o40700, 0x81000), ([written("tests", '["mode","iflags"]')], 1))
    check("IF-6, IF-7: with setgid: its own record, none for iflags", tests_dir(0o42755, 0x81000),
          ([written("tests", '["mode","iflags"]'),
            '{"flag":"privilege_changed","level":"signal","path":"tests","what":"setgid","before":"off","after":"on",'
            '"text":"tests: setgid off -> on","paths":["tests"]}'], 1))
    check("IF-2 unprotected: nothing", tests_dir(D, 0x81000, None), ([], 0))
    check("IF-2 unprotected, locked: the signal", tests_dir(D, 0x80010, None), ([P("tests", 524288, 524304)], 0))

    # IF-4: a regular file at both ends: every change counts, as before
    b = {**root, b"tests": raw("dir", D, ino=3, iflags=0x80000), b"tests/f.txt": raw("reg", F, b"f\n", ino=4, iflags=0x80000)}
    a = {**b, b"tests/f.txt": raw("reg", F, b"f\n", ino=4, iflags=0x80040)}
    got, flags = verify(spec, b, a)
    check("IF-4, IF-6: a regular file's nodump is a violation and a signal", (got[1:-1], model.verify_exit(flags, True)),
          ([written("tests/f.txt", '["iflags"]'), P("tests/f.txt", 524288, 524352)], 1))

    # IF-3: directories added and removed
    before = {**root, b"gone-locked": raw("dir", D, ino=3, iflags=0x80020), b"gone-plain": raw("dir", D, ino=4, iflags=0x81040)}
    after = {**root, b"new-locked": raw("dir", D, ino=5, iflags=0x80010), b"new-plain": raw("dir", D, ino=6, iflags=0x81000)}
    got, _f = verify(None, before, after)
    check("IF-3: an added or removed directory's flags count only when they lock it", got[1:-1],
          [P("gone-locked", 524320, "none"), P("new-locked", "none", 524304)])

    # IF-4's last sentence: a type change is judged as before, a directory at either end (P56, P57)
    before = {**root, b"t": raw("dir", D, ino=3, iflags=0x80000), b"t/a": raw("reg", F, b"a\n", ino=4, iflags=0x80040),
              b"t/b": raw("dir", D, ino=5, iflags=0x81000), b"t/c": raw("reg", F, b"c\n", ino=6, iflags=0x80000)}
    after = {**root, b"t": raw("dir", D, ino=3, iflags=0x80000), b"t/a": raw("dir", D, ino=7, iflags=0x80000),
             b"t/b": raw("reg", F, b"b\n", ino=8, iflags=0x80000), b"t/c": raw("lnk", 0o120777, ino=9, link=b"/x")}
    got, _f = verify(None, before, after)
    check("IF-4: a type change is not under IF-2", got[1:-1],
          [P("t/a", 524352, 524288), P("t/b", 528384, 524288), P("t/c", 524288, "none")])

    # IF-5: flags read on one side only, the same type at both ends
    gspec = b'{"belay_protect":2,"protect":[{"path":"g/**","mode":["no_write"]}]}'
    unread = raw("reg", F, b"k\n", ino=4)
    unread["readable"] = False
    unread["iflags"] = None                       # no descriptor to ask through (P25)
    sub = raw("dir", D, ino=5)
    sub["iflags"] = None                          # a side that could not read them
    before = {**root, b"g": raw("dir", D, ino=3, iflags=0x80000), b"g/sub": sub,
              b"g/x": raw("reg", F, b"k\n", ino=4, iflags=0x80000)}
    after = {**root, b"g": raw("dir", D, ino=3, iflags=0x80000), b"g/sub": raw("dir", D, ino=5, iflags=0x80010),
             b"g/x": unread}
    unver = ('{"flag":"protected_path_unverifiable","level":"violation","path":"%s","rule":"g/**","reasons":%s,'
             '"text":"%s: protected by g/**, cannot be verified: %s","paths":["%s"]}')
    got, _f = verify(gspec, before, after)
    check("IF-5: unverifiable as before, no written, no `none` against a value (a locking one included, P58)", got[1:-1],
          [unver % ("g/sub", '["iflags_unknown"]', "g/sub", "iflags_unknown", "g/sub"),
           unver % ("g/x", '["unverified","unreadable","iflags_unknown"]', "g/x", "unverified, unreadable, iflags_unknown", "g/x")])
    got, _f = verify(None, before, after)
    check("IF-5 without a spec: nothing", got[1:-1], [])
    r = recs_of(before, after)
    check("IF-5: the diff's outcome stays unknown, iflags_unknown", [r[b"g/sub"], r[b"g/x"]],
          [{"outcome": "unknown", "type": "dir", "unknown": ["iflags_unknown"]},
           {"outcome": "unknown", "type": "reg", "unknown": ["unverified", "unreadable", "iflags_unknown"]}])


def fixture_text_cut():
    long_dir = "\u00e9" * 300                       # 600 bytes, two to a character
    p = ("tests/%s/%s/test_x.py" % (long_dir, long_dir)).encode()
    before = {b".": raw("dir", D, ino=2)}
    after = {b".": raw("dir", D, ino=2), b"tests": raw("dir", D, ino=3),
             ("tests/" + long_dir).encode(): raw("dir", D, ino=4), p[:-10]: raw("dir", D, ino=5),
             p: raw("reg", F, b"def test_x():\n    assert 1\n", ino=6)}
    got, _f = verify(None, before, after)
    rec = json.loads(got[-2])
    # "tests/" (6 bytes) + 300 two-byte characters (600) + "/" (1) = 607; 207 more (414) make 1021,
    # the 208th would make 1023 > 1021: the cut keeps 1021 bytes and adds "...", 1024 in all.
    check("text cut at a character", rec["text"], "tests/" + "\u00e9" * 300 + "/" + "\u00e9" * 207 + "...")
    check("text cut, its length", len(rec["text"].encode()), 1024)
    odd = "tests/" + "\u00e9" * 300 + "/a" + "\u00e9" * 300
    check("text cut, an odd boundary", model.cut(odd + ": test file added"), "tests/" + "\u00e9" * 300 + "/a" + "\u00e9" * 206 + "...")
    check("text cut, the field kept whole", rec["path"], p.decode())


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
    code, exp = model.export_expect("/w", "/out/b.bundle", b'{"belay_protect":2,"protect":[],"frozen_packages":true}', [], B)
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


def fixture_pip_reinstall_judged():
    core1, core2 = b"def run():\n    return 1\n", b"def run():\n    return 2\n"

    def rec(core):
        return ("pkg/core.py,sha256=%s,%d\npkg-1.0.dist-info/RECORD,,\n" % (b64sha(core), len(core))).encode()
    B = {b".": raw("dir", D), b"pkg": raw("dir", D), b"pkg/core.py": raw("reg", F, core1, ino=5),
         b"pkg-1.0.dist-info": raw("dir", D), b"pkg-1.0.dist-info/RECORD": raw("reg", F, rec(core1), ino=6)}
    code, exp = model.export_expect("/w", "/out/b.bundle", b'{"belay_protect":2,"protect":[]}', [], B)
    A = dict(B)
    A[b"pkg/core.py"] = raw("reg", F, core2, ino=5, mtime=200)
    A[b"pkg-1.0.dist-info/RECORD"] = raw("reg", F, rec(core2), ino=6, mtime=200)
    ctx = {"scope": "/w", "bundle_sha256": "b" * 64, "spec": exp["spec"],
           "before": model.Side(exp["B"], 10, []), "after": model.Side(model.view(A, exp["hash_max"]), 10, []),
           "bundle_lines": exp["lines"], "outside_scope": 0, "before_sha256": "1" * 64, "after_sha256": "2" * 64}
    out, _flags, _r, _e = model.verify_lines(ctx)
    check("a forged RECORD: reinstalled, and its file judged (decision 173)", [model.enc(o) for o in out[1:-1]], [
        '{"flag":"package_changed","level":"signal","db":"pip","package":"pkg","event":"pip_reinstalled",'
        '"change":"reinstalled pkg 1.0: +0 -0 ~1 files","self_consistent":true,'
        '"text":"pip: reinstalled pkg 1.0: +0 -0 ~1 files","paths":["pkg-1.0.dist-info/RECORD"]}',
        '{"flag":"tampered_installed_package","level":"signal","db":"pip","package":"pkg","path":"pkg/core.py",'
        '"why":"other bytes","at_reset":"match","text":"pkg: installed file pkg/core.py other bytes","paths":["pkg/core.py"]}'])


def fixture_pyc_decision_186():
    core, pyc = b"def run():\n    return 1\n", b"\xcb\x0d\x0d\x0a bytecode"
    record = ("pkg/core.py,sha256=%s,%d\npkg/__pycache__/core.cpython-312.pyc,,\npkg-1.0.dist-info/RECORD,,\n"
              % (b64sha(core), len(core))).encode()
    B = {b".": raw("dir", D), b"pkg": raw("dir", D), b"pkg/core.py": raw("reg", F, core, ino=5),
         b"pkg/__pycache__": raw("dir", D), b"pkg/__pycache__/core.cpython-312.pyc": raw("reg", F, pyc, ino=6),
         b"pkg-1.0.dist-info": raw("dir", D), b"pkg-1.0.dist-info/RECORD": raw("reg", F, record, ino=7)}
    code, exp = model.export_expect("/w", "/out/b.bundle", b'{"belay_protect":2,"protect":[]}', [], B)

    def judge(A):
        ctx = {"scope": "/w", "bundle_sha256": "b" * 64, "spec": exp["spec"],
               "before": model.Side(exp["B"], 10, []), "after": model.Side(model.view(A, exp["hash_max"]), 10, []),
               "bundle_lines": exp["lines"], "outside_scope": 0, "before_sha256": "1" * 64, "after_sha256": "2" * 64}
        out, _f, _r, _e = model.verify_lines(ctx)
        return [model.enc(o) for o in out[1:-1]], json.loads(model.enc(out[-1]))["packages_no_hash"]
    A = dict(B)
    A[b"pkg/__pycache__/core.cpython-312.pyc"] = raw("reg", F, pyc + b" PATCHED", ino=6, mtime=200)
    got, nohash = judge(A)
    check("a .pyc patched under its unchanged source (decision 186)", got, [
        '{"flag":"tampered_installed_package","level":"signal","db":"pip","package":"pkg",'
        '"path":"pkg/__pycache__/core.cpython-312.pyc","why":"other bytes","at_reset":"no_hash",'
        '"text":"pkg: installed file pkg/__pycache__/core.cpython-312.pyc other bytes",'
        '"paths":["pkg/__pycache__/core.cpython-312.pyc"]}'])
    check("packages_no_hash counts the .pyc's line too (P38)", nohash, 2)
    A[b"pkg/core.py"] = raw("reg", F, b"def run():\n    return 2\n", ino=5, mtime=200)
    got, _n = judge(A)
    check("a .pyc recompiled beside its changed source: only the source", got, [
        '{"flag":"tampered_installed_package","level":"signal","db":"pip","package":"pkg","path":"pkg/core.py",'
        '"why":"other bytes","at_reset":"match","text":"pkg: installed file pkg/core.py other bytes","paths":["pkg/core.py"]}'])
    A = dict(B)
    del A[b"pkg/__pycache__/core.cpython-312.pyc"]
    got, _n = judge(A)
    check("a .pyc removed: nothing", got, [])
    check("pyc sources", [model.pyc_source(p) for p in (b"a/__pycache__/m.cpython-312.opt-2.pyc", b"a/m.pyc", b"a/m.py")],
          [b"a/m.py", b"a/m.py", None])


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


def fixture_writer_open():
    """Manifest v4: the example of the pin, then V4-D1..D4 and V4-D7 by hand."""
    spec = b'{"belay_protect":2,"protect":[{"path":"g/**","mode":["no_write"]}]}'
    H = {(10, 4)}                                      # the inode a writer held
    base = {b".": raw("dir", D, ino=2), b"g": raw("dir", D, ino=3)}
    x = raw("reg", F, b"one\n", ino=4)
    moved = raw("reg", F, b"one\n", ino=4, mtime=200)
    other = raw("reg", F, b"three\n", ino=4, mtime=200)

    def rec(b, a, wb=frozenset(), wa=frozenset()):
        B = dict(base)
        A = dict(base)
        if b is not None:
            B[b"g/x"] = b
        if a is not None:
            A[b"g/x"] = a
        r = model.diff(model.Side(model.view(B, model.HASH_DEFAULT, wb), 10, []),
                       model.Side(model.view(A, model.HASH_DEFAULT, wa), 10, []))
        return r.get(b"g/x")
    # the pin's example: the mtime moved, the entry marked
    check("V4's example record", rec(x, moved, wa=H),
          {"outcome": "unknown", "type": "reg", "changed": ["mtime_ns"], "unknown": ["writer_open"]})
    check("nothing differs, marked on one side: still unknown (V4-D1)", rec(x, x, wb=H),
          {"outcome": "unknown", "type": "reg", "unknown": ["writer_open"]})
    check("marked on both, the size differs: unknown, no sha256 in changed (V4-D2)", rec(x, other, wb=H, wa=H),
          {"outcome": "unknown", "type": "reg", "changed": ["size", "mtime_ns"], "unknown": ["writer_open"]})
    check("the type differs: unknown (V4-D1)", rec(x, raw("lnk", 0o120777, ino=4, link=b"t"), wb=H),
          {"outcome": "unknown", "type": "lnk", "type_before": "reg", "changed": ["type"], "unknown": ["writer_open"]})
    check("one side, before: never removed (V4-D3)", rec(x, None, wb=H),
          {"outcome": "unknown", "type": "reg", "unknown": ["writer_open"]})
    check("one side, after: never added (V4-D3)", rec(None, x, wa=H),
          {"outcome": "unknown", "type": "reg", "unknown": ["writer_open"]})
    check("not held: modified, as ever", rec(x, other),
          {"outcome": "modified", "type": "reg", "changed": ["size", "mtime_ns", "sha256"]})
    locked = raw("reg", 0o100000, b"one\n", ino=4, mtime=200)
    locked["readable"] = False
    locked["iflags"] = None
    check("last among the reasons (V4-D4)", rec(x, locked, wb=H)["unknown"],
          ["unverified", "unreadable", "iflags_unknown", "writer_open"])
    check("the order of the reasons ends in writer_open", model.REASON_ORDER[-2:], ("listing_incomplete", "writer_open"))
    # the capture: no copy, no mark without a hash (V4-2, V4-R5)
    v = model.view({b"f": x, b"same": dict(x)}, model.HASH_DEFAULT, H)
    check("held: marked, no copy, every name of the inode", [(e["writer_open"], e["stored"]) for e in v.values()],
          [(True, False), (True, False)])
    check("over the hash limit: unverified, not marked", model.view({b"f": x}, 1, H)[b"f"]["writer_open"], False)
    check("a marked side is not held", model.held(model.view({b"f": x}, model.HASH_DEFAULT, H)[b"f"]), None)
    empty = model.view({b"f": raw("reg", F, b"", ino=4)}, model.HASH_DEFAULT, H)[b"f"]
    check("size 0 counts as held, for tests_weakened, with no copy (V4-S3)", model.test_side(empty), b"")
    check("and only for it (P46)", model.held(empty), None)
    locked0 = raw("reg", 0o100000, b"", ino=4)
    locked0["readable"] = False
    check("a file belay could not read is not held (V4-S3)", model.test_side(model.view({b"f": locked0}, model.HASH_DEFAULT)[b"f"]), None)
    # V4-D7 in policy.v1, and what stays quiet
    B = {**base, b"g/x": x}
    got, flags = verify(spec, B, {**base, b"g/x": other}, wa=H)
    check("a protected path carrying it (V4-D7): unverifiable, never written", got[1:-1], [
        '{"flag":"protected_path_unverifiable","level":"violation","path":"g/x","rule":"g/**","reasons":["writer_open"],'
        '"text":"g/x: protected by g/**, cannot be verified: writer_open","paths":["g/x"]}'])
    check("the trailer: unknown 1, provisional false (V4-D6)", (json.loads(got[-1])["unknown"], json.loads(got[-1])["provisional"]), (1, False))
    check("and a violation fails the run", model.verify_exit(flags, True), 1)
    got, _f = verify(b'{"belay_protect":2,"protect":[{"path":"g/x","expected_sha256":"%s"}]}'
                     % model.sha256(b"one\n").encode(), B, {**base, b"g/x": other}, wa=H)
    check("a marked hash against expected_sha256 stops at unverifiable (V4-D8)",
          [json.loads(ln)["flag"] for ln in got[1:-1]], ["protected_path_unverifiable"])
    got, _f = verify(spec, base, {**base, b"g/x": x}, wa=H)
    check("a new file a writer holds, under no_write only (V4-D7)", json.loads(got[1])["reasons"], ["writer_open"])
    # V4-S2: one side, unknown, no mark: `raced`, under a rule that reads the other side
    hdr = model.view({**base, b"g/x": x}, model.HASH_BOUND_SPEC)
    hdr[b"g/x"]["raced"] = True
    ctx = {"scope": "/w", "bundle_sha256": "b" * 64, "spec": model.parse_spec(b'{"belay_protect":2,"protect":[{"path":"g/**","mode":["no_create"]}]}'),
           "before": model.Side(hdr, 10, []), "after": model.Side(model.view(base, model.HASH_BOUND_SPEC), 10, []),
           "bundle_lines": [], "outside_scope": 0, "before_sha256": "1" * 64, "after_sha256": "2" * 64}
    check("one side, unknown, whichever side the rule reads (V4-S2)", [f.kind for f in model.verify_lines(ctx)[1]],
          ["protected_path_unverifiable"])
    # V4-D9: the mode speaks
    pb = {b".": raw("dir", D, ino=2), b"bin": raw("dir", D, ino=3)}
    tool = raw("reg", 0o100755, b"#!/bin/sh\n", ino=4)
    got, _f = verify(None, pb, {**pb, b"bin/t": tool}, wa=H)
    check("added, if not for the mark (V4-D9)", got[1:-1], [
        '{"flag":"new_executable_on_path","level":"signal","path":"bin/t","outcome":"unknown","mode":33261,'
        '"text":"bin/t: executable on PATH, unknown","provisional":true,"paths":["bin/t"]}'])
    plain = raw("reg", 0o100644, b"#!/bin/sh\n", ino=4)
    got, _f = verify(None, {**pb, b"bin/t": plain}, {**pb, b"bin/t": tool}, wb=H)
    check("execute bits added, marked before (V4-D9)", [json.loads(ln)["outcome"] for ln in got[1:-1]], ["unknown"])
    got, _f = verify(None, pb, {**pb, b"bin/t": plain}, wa=H)
    check("added without an execute bit: nothing", got[1:-1], [])
    # V4-D8: at_reset, self_consistent; V4-S1
    body = b"x = 1\n"
    record = ("pkg.py,sha256=%s,%d\nz.pyc,,\n" % (b64sha(body), len(body))).encode()
    Bp = {b".": raw("dir", D, ino=2), b"pkg-1.0.dist-info": raw("dir", D, ino=3),
          b"pkg-1.0.dist-info/RECORD": raw("reg", F, record, ino=5), b"pkg.py": raw("reg", F, body, ino=4),
          b"z.pyc": raw("reg", F, b"\x00", ino=6)}
    _c, exp = model.export_expect("/w", "/o/b", None, [], Bp, H | {(10, 6)})
    check("at_reset of a marked file, and a row with no hash (V4-D8, P44)", [l["at_reset"] for l in exp["lines"]],
          ["unverified", "no_hash"])
    check("a marked RECORD refuses the export (V4-S1)", model.export_expect("/w", "/o/b", None, [], Bp, {(10, 5)})[0], 4)
    check("V4-S1's list", [model.is_database(p) for p in (b"a-1.dist-info/RECORD", b"a-1.dist-info/METADATA", b"var/lib/dpkg/status",
                                                          b"var/lib/dpkg/info/a.md5sums", b"var/lib/dpkg/info/a.list", b"x.md5sums")],
          [True, False, True, True, False, False])
    ev = model.Event("pip", "pip_installed", {"name": "pkg", "version": "1.0"}, "", [b"pkg-1.0.dist-info/RECORD"], False)
    Ap = model.view(Bp, model.HASH_DEFAULT, H)
    check("self_consistent follows (V4-D8)", model.self_consistent(ev, {}, Ap, "/w"), False)
    check("and holds with no writer", model.self_consistent(ev, {}, model.view(Bp, model.HASH_DEFAULT), "/w"), True)
    tests = {b".": raw("dir", D, ino=2), b"tests": raw("dir", D, ino=3), b"tests/test_api.py": raw("reg", F, TEST_API, ino=4)}
    weak = {**tests, b"tests/test_api.py": raw("reg", F, b"\n", ino=4, mtime=200)}
    got, _f = verify(None, tests, weak, wa=H)
    check("a test file marked: no outcome the rules name, no copy to count (P47)", got[1:-1], [])


def fixture_manifest_v4():
    """V4's Lines, on the pin's example trailer."""
    entry = {"path": "data.bin", "type": "reg", "mode": 33188, "uid": 1000, "gid": 1000, "size": 4, "mtime_ns": 1,
             "ctime_ns": 1, "ino": 92219, "dev": 2096, "nlink": 1, "iflags": 524288, "sha256": "e" * 64, "writer_open": True}
    root = {"path": ".", "type": "dir", "mode": 16877, "uid": 1000, "gid": 1000, "size": 4096, "mtime_ns": 1,
            "ctime_ns": 1, "ino": 2, "dev": 2096, "nlink": 2}
    head = {"belay_manifest": 4, "created_ns": 1, "scopes": ["/w"], "hash": "sha256", "hash_max_bytes": 1, "store_max_bytes": 1,
            "excluded": [], "walk_start_ns": 1, "source": None}
    tail = {"belay_manifest_end": 2, "vanished": 0, "unreadable": 0, "unstable": 0, "mounts": 1, "raced": 0, "trusted": 0,
            "reference": "none", "read_all": "check", "writer_open": 1, "unguarded": 0}
    data = b"".join(model.enc(o).encode() + b"\n" for o in (head, root, entry, tail))
    B = {b".": {"writer_open": False}, b"data.bin": {"writer_open": True}}
    check("the pin's lines hold", model.manifest_problems(data, B, 0), [])
    check("another unguarded count is seen", len(model.manifest_problems(data, B, 3)), 1)
    check("an entry the model did not mark is seen", len(model.manifest_problems(data, {b".": B[b"."], b"data.bin": {"writer_open": False}}, 0)), 1)
    check("writer_open after raced", model.ENTRY_KEY_ORDER[-2:], ("raced", "writer_open"))
    check("the trailer's order", model.V4_TRAILER[-3:], ("read_all", "writer_open", "unguarded"))
    plain = data.replace(b',"writer_open":true', b"").replace(b'"writer_open":1', b'"writer_open":0')
    h3, _e3, t3 = model.read_manifest(model.downgrade_manifest(plain, 3))
    check("v3 keeps source, loses both counts", (h3["belay_manifest"], "source" in h3, "writer_open" in t3, "unguarded" in t3), (3, True, False, False))
    h2, _e2, _t2 = model.read_manifest(model.downgrade_manifest(plain, 2))
    check("v2 loses source", (h2["belay_manifest"], "source" in h2), (2, False))
    flagged = model.flag_manifest(plain, {b"data.bin": ["raced", "writer_open"]})
    _h, es, tr = model.read_manifest(flagged)
    check("flags keep their order, and the counts true", (list(es[1])[-2:], tr["raced"], tr["writer_open"]), (["raced", "writer_open"], 1, 1))
    for bad in ({"writer_open": False}, {"writer_open": True, "stored": "e"}, {"writer_open": True, "unverified": True}):
        o = dict(entry, **bad)
        check("V4-2's when: %r" % (bad,), model.marked_entry_problem(o) is not None, True)
    check("V4-2's when, a good entry", model.marked_entry_problem(entry), None)


def fixture_protect_v2():
    """protect-spec-v2.md by hand."""
    for raw_ in (b'{"belay_protect":1,"protect":[]}', b'{"belay_protect":3,"protect":[]}', b'{"belay_protect":"2","protect":[]}'):
        try:
            model.parse_spec(raw_)
            check("PV2-1 refused: %r" % raw_, "accepted", "refused")
        except model.Refused as r:
            check("PV2-1 its code: %r" % raw_, r.code, 2)
            check("PV2-1 its words: %r" % raw_, r.why,
                  "belay_protect is not 2 (version 1 specs are refused: no_write now forbids deleting; say 2)")
    check("PV2-1 is seen", model.version_refused(b'{"belay_protect":1,"protect":[]}'), True)
    check("PV2-1 not for version 2", model.version_refused(b'{"belay_protect":2,"protect":[]}'), False)
    check("PV2-1 not with no key", model.version_refused(b'{"protect":[]}'), False)
    base = {b".": raw("dir", D, ino=2), b"g": raw("dir", D, ino=3)}
    x = {**base, b"g/x": raw("reg", F, b"one\n", ino=4)}

    def gone(*rules, after=base):
        spec = ('{"belay_protect":2,"protect":[%s]}' % ",".join(rules)).encode()
        got, _f = verify(spec, x, after)
        return got[1:-1]
    deleted = ('{"flag":"protected_path_deleted","level":"violation","path":"g/x","rule":"%s",'
               '"text":"g/x: protected by %s, removed","paths":["g/x"]}')
    nw = '{"path":"%s","mode":["no_write"]}'
    nd = '{"path":"%s","mode":["no_delete"]}'
    check("no_write, deleted (PV2-2)", gone(nw % "g/**"), [deleted % ("g/**", "g/**")])
    check("no_delete, deleted (PV2-3)", gone(nd % "g/**"), [deleted % ("g/**", "g/**")])
    check("both modes, one flag (PV2-3)", gone('{"path":"g/**","mode":["no_write","no_delete"]}'), [deleted % ("g/**", "g/**")])
    check("two rules, one flag, the first's name (PV2-3, PV2-4)", gone(nd % "g/*", nw % "g/**"), [deleted % ("g/*", "g/*")])
    check("the first with either mode (PV2-4)", gone('{"path":"g/x","mode":["no_create"]}', nw % "g/*"), [deleted % ("g/*", "g/*")])
    check("no_create alone: nothing", gone('{"path":"g/x","mode":["no_create"]}'), [])
    hsh = model.sha256(b"one\n")
    check("no_write and expected_sha256: both say theirs", gone('{"path":"g/x","mode":["no_write"],"expected_sha256":"%s"}' % hsh), [
        deleted % ("g/x", "g/x"),
        '{"flag":"protected_hash_mismatch","level":"violation","path":"g/x","expected":"%s","why":"absent",'
        '"text":"g/x: absent, expected sha256 %s","paths":["g/x"]}' % (hsh, hsh)])
    other = {**base, b"g/x": raw("reg", F, b"three\n", ino=4, mtime=200)}
    check("no_delete allows writing (PV2-3)", gone(nd % "g/**", after=other), [])
    check("no_write writing stays written (PV2-2)", json.loads(gone(nw % "g/**", after=other)[0])["flag"], "protected_path_written")


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
    for raw_ in (b'{"belay_protect":2,"protect":[]}',
                 b' {"belay_protect":2,"protect":[{"path":"a/*","mode":["no_create","no_write"]}],"path_dirs":[]} \n'):
        try:
            model.parse_spec(raw_)
        except model.Refused as r:
            check("spec accepted: %r" % raw_, r.why, None)
    for raw_ in (b'{"belay_protect":2,"protect":[],"protect":[]}', b'{"belay_protect":2}', b'{"belay_protect":2,"protect":[]} 1',
                 b'{"belay_protect":2,"protect":[{"path":"a"}]}', b'{"belay_protect":2,"protect":[{"path":"a/","mode":["no_write"]}]}'):
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
    T = [(b"tests", True), (b"a/spec/b", True), (b"x/test_y.c", True), (b"y_test.go", True), (b"a.test.js", True),
         (b"b.spec.ts", True), (b"src/app.py", False), (b"testing/x", False), (b"attest_x", False),
         (b"build/test/x.py", False), (b"docs/spec/a.md", False), (b"src/doc/test_a.py", False),
         (b"node_modules/x/tests/a.js", False), (b"a/__pycache__/test_x.py", False), (b".build/tests/x", False),
         (b"src/foo_test.go", True), (b"src/FooTest.java", True), (b"src/FooTests.kt", True), (b"lib/x_spec.rb", True),
         (b"lib/y_test.rb", True), (b"src/test_a.cpp", True), (b"src/b_test.cc", True), (b"web/c.spec.mjs", True),
         (b"src/web.test.py", False), (b"src/Foo.test.java", False), (b"src/footest.go", False), (b"src/x.spec.rb", False),
         (b"src/test_x.h", False), (b"src/Test.java", True), (b"src/a.test.jsx", True), (b"src/a.test.vue", False),
         (b"src/__tests__/a.vue", True), (b"src/_test.py", True), (b"pkg/test", True), (b"doc_test.go", True)]
    check("test files (decision 175)", [model.is_test_file(p) for p, _w in T], [w for _p, w in T])
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
    for f in (tables, fixture_protected_write, fixture_privilege_path, fixture_iflags_decision_163, fixture_inode_flags,
              fixture_text_cut,
              fixture_pip_reinstall_judged, fixture_pyc_decision_186, fixture_pip_bundle,
              fixture_dpkg_bundle_and_tamper, fixture_git_reset, fixture_writer_open, fixture_manifest_v4, fixture_protect_v2):
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
