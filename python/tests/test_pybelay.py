"""pybelay against its binary (test/expect/pybelay.md, reward.md). Run after
python/build_keys.py has vendored a build: make pybelay-test."""
import json, os, shutil, subprocess, sys, tempfile, unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import pybelay  # noqa: E402
from pybelay import reward  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="pybelay-test-")
        os.environ["BELAY_STATE_DIR"] = os.path.join(self.t, "state")
        self.scope = os.path.join(self.t, "scope")
        os.makedirs(os.path.join(self.scope, "tests"))
        self.write("tests/test_a.py", "def test_a():\n    assert 1 == 1\n")
        self.write("src.py", "x = 1\n")

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def write(self, rel, text):
        with open(os.path.join(self.scope, rel), "w") as f:
            f.write(text)


class Calls(Base):
    def test_check_mark_log_diff(self):
        c = pybelay.check(self.scope)
        self.assertEqual((c.id, c.kind, c.scope), (1, "check", os.path.realpath(self.scope)))
        self.assertIsInstance(c.prefilter, pybelay.Prefilter)
        self.write("src.py", "x = 2\n")
        m = pybelay.mark(self.scope)
        self.assertEqual(m.kind, "mark")
        self.assertEqual([x.id for x in pybelay.log(self.scope)], [1, 2])
        d = pybelay.diff(self.scope, 1, 2)
        self.assertEqual([(r.path, r.outcome) for r in d.records], [("src.py", "modified")])
        self.assertEqual(d.trailer["modified"], 1)
        self.assertEqual(c, pybelay.log(self.scope)[0])           # frozen, equal by content

    def test_export_and_verify(self):
        out = os.path.join(self.t, "bundle")
        b = pybelay.baseline_export(self.scope, out)
        self.assertEqual((len(b.sha256), b.baseline_integrity), (64, ()))
        self.write("tests/test_a.py", "def test_a():\n    pass\n")
        p = pybelay.verify(self.scope, out, b.sha256)
        self.assertEqual(p.violations, 0)
        self.assertIn("tests_weakened", [f.flag for f in p.flags])
        self.assertEqual(p.lines()[0]["belay_policy"], 1)

    def test_errors_by_exit_code(self):
        out = os.path.join(self.t, "bundle")
        pybelay.baseline_export(self.scope, out)
        with self.assertRaises(pybelay.Refused) as e:             # B-R2: the digest checked
            pybelay.verify(self.scope, out, "0" * 64)
        self.assertEqual(e.exception.exit_code, 3)
        with self.assertRaises(pybelay.UsageError):
            pybelay.diff(self.scope, "x")
        with self.assertRaises(pybelay.Refused):
            pybelay.check(os.path.join(self.t, "no-such-dir"))

    def test_a_binary_that_does_not_match_its_digest_runs_nothing(self):
        pkg = os.path.join(self.t, "pkg")
        shutil.copytree(os.path.dirname(pybelay.__file__), os.path.join(pkg, "pybelay"))
        with open(os.path.join(pkg, "pybelay", "_bin", "SHA256"), "w") as f:
            f.write("0" * 64 + "\n")
        r = subprocess.run([sys.executable, "-I", "-c",
                            "import sys; sys.path.insert(0, %r); import pybelay\n"
                            "try:\n    pybelay.check(%r)\nexcept pybelay.BinaryMismatch: print('mismatch')" % (pkg, self.scope)],
                           capture_output=True, text=True, env=dict(os.environ))
        self.assertEqual(r.stdout.strip(), "mismatch", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.t, "state", "scopes")))   # nothing ran

    def test_a_checkpoint_says_what_was_not_read(self):
        """checkpoint-v3 C3-2 to C3-7: the seven fields."""
        c = pybelay.check(self.scope)
        self.assertEqual((c.unreadable, c.sealing, c.basis, c.carried, c.runtime_sha256), (0, 0, "walk", 0, None))
        self.assertEqual((c.journal_seq, c.shadow_lines_sha256), (None, None))
        self.assertEqual(list(pybelay._run(["log", "--scope", self.scope, "--json"])[0][0])[-3:],
                         ["runtime_sha256", "journal_seq", "shadow_lines_sha256"])
        if os.geteuid() == 0:
            self.skipTest("root reads anything: the counts stay 0")
        os.mkdir(os.path.join(self.scope, "secret"))
        self.write("secret/a", "a\n")
        self.write("shadow", "k\n")
        os.chmod(os.path.join(self.scope, "shadow"), 0)
        os.chmod(os.path.join(self.scope, "secret"), 0)
        try:
            c = pybelay.check(self.scope)
            self.assertEqual((c.unreadable, c.sealing), (2, 1))
            d = pybelay.diff(self.scope, 1, 2)
            self.assertEqual((d.trailer["before_sealing"], d.trailer["after_sealing"]), (0, 1))
            self.assertEqual((d.trailer["runtime"], d.runtime), (0, ()))   # runtime-v1 RT-D1: no section here
            os.chmod(os.path.join(self.scope, "shadow"), 0o600)
            self.write("shadow", "longer now\n")
            os.chmod(os.path.join(self.scope, "shadow"), 0)
            self.write("newfile", "n\n")                         # diff-fields O10: an added file not read
            os.chmod(os.path.join(self.scope, "newfile"), 0)
            d = pybelay.diff(self.scope, 2)                       # diff-fields O9
            self.assertEqual([(r.path, r.outcome, r.content_not_read) for r in d.records],
                             [("newfile", "added", ("unreadable",)), ("secret", "unknown", None),
                              ("shadow", "modified", ("unreadable",))])
        finally:
            os.chmod(os.path.join(self.scope, "secret"), 0o700)

    def test_a_checkpoint_made_before_v3_has_none_never_zero(self):
        """C3-7, C3-8: a v2 record read from an older state."""
        pybelay.check(self.scope)
        scopes = os.path.join(self.t, "state", "scopes")
        meta = os.path.join(scopes, os.listdir(scopes)[0], "checkpoints", "1", "meta.json")
        with open(meta) as f:
            m = json.load(f)
        self.assertEqual((m.pop("unreadable"), m.pop("sealing")), (0, 0))     # as the older belay wrote it
        with open(meta, "w") as f:
            f.write(json.dumps(m, separators=(",", ":")) + "\n")
        new = pybelay.mark(self.scope)
        old = pybelay.log(self.scope)[0]
        self.assertEqual((old.id, old.entries), (1, new.entries))
        self.assertEqual((old.unreadable, old.sealing, old.basis, old.carried, old.runtime_sha256,
                          old.journal_seq, old.shadow_lines_sha256), (None,) * 7)
        self.assertEqual((new.unreadable, new.sealing, new.basis), (0, 0, "walk"))
        line = pybelay._run(["log", "--scope", self.scope, "--json"])[0][1]
        del line["journal_seq"]                                     # some of the seven is neither version
        with self.assertRaises(pybelay.FormatError):
            pybelay._checkpoint(line)

    def test_an_unknown_key_is_a_format_error(self):
        line = pybelay._run(["check", "--scope", self.scope, "--json"])[0][0]
        line["nope"] = 1
        with self.assertRaises(pybelay.FormatError):
            pybelay._checkpoint(line)

    def test_a_diffs_runtime_section(self):                         # runtime-v1 RT-D1
        pybelay.check(self.scope)
        lines = pybelay._run(["diff", "--scope", self.scope, "--since", "1", "--json"])[0]
        lines.insert(-1, {"runtime": "listener_opened", "listener": "tcp", "proto": 4, "addr": "0.0.0.0", "port": 80,
                          "holders": None, "text": "opened: tcp 0.0.0.0:80"})
        lines.insert(-1, {"runtime": "a_kind_not_known", "text": "x"})
        d = pybelay._diff(lines)
        self.assertEqual([(r.runtime, r.text, r.fields.get("port")) for r in d.runtime],
                         [("listener_opened", "opened: tcp 0.0.0.0:80", 80), ("a_kind_not_known", "x", None)])
        self.assertEqual(d.records, ())
        lines.insert(-1, {"runtime": "incomplete"})
        with self.assertRaises(pybelay.FormatError):
            pybelay._diff(lines)


class Reward(Base):
    def spec(self):
        p = os.path.join(self.t, "spec.json")
        with open(p, "w") as f:
            json.dump({"belay_protect": 2, "protect": [{"path": "tests/**", "mode": ["no_write"]}]}, f)
        return p

    def test_clean_keeps_the_reward_and_says_why(self):
        g = reward.Guard(self.scope, workdir=self.t, protect=self.spec())
        g.reset()
        self.write("src.py", "x = 3\n")
        j = g.judge(1.0)
        self.assertEqual(j.reward, 1.0)
        m = j.metadata["belay"]
        self.assertEqual((m["violations"], m["zeroed"], m["error"]), (0, False, None))
        self.assertIn("protected_path_written", m["flags"])       # every kind, 0 included
        self.assertEqual(m["policy"][0]["belay_policy"], 1)

    def test_a_violation_zeroes_and_signals_never_count(self):
        g = reward.Guard(self.scope, workdir=self.t, protect=self.spec())
        g.reset()
        self.write("tests/test_a.py", "def test_a():\n    pass\n")
        j = g.judge(0.75)
        self.assertEqual(j.reward, 0.0)
        self.assertTrue(j.metadata["belay"]["zeroed"])
        self.assertGreater(j.metadata["belay"]["flags"]["protected_path_written"], 0)
        g.reset()
        self.write("src.py", "x = 9\n")                         # a signal at most
        self.assertEqual(g.judge(0.75).reward, 0.75)

    def test_fail_closed_unless_asked_to_raise(self):
        for on_error in ("fail_closed", "raise"):
            g = reward.Guard(self.scope, workdir=self.t, on_error=on_error)
            g.reset()
            with open(g._bundle, "ab") as f:                       # the digest no longer matches
                f.write(b"x")
            if on_error == "raise":
                with self.assertRaises(pybelay.Refused):
                    g.judge(1.0)
            else:
                j = g.judge(1.0)
                self.assertEqual(j.reward, 0.0)
                self.assertEqual(j.metadata["belay"]["error"]["type"], "Refused")
                self.assertIsNone(j.metadata["belay"]["violations"])

    def test_judge_without_reset_and_the_bundle_removed(self):
        g = reward.Guard(self.scope, workdir=self.t)
        with self.assertRaises(pybelay.UsageError):
            g.judge(1.0)
        g.reset()
        b = g._bundle
        g.judge(1.0)
        self.assertFalse(os.path.exists(b))                        # RW-6
        with self.assertRaises(pybelay.UsageError):                # RW-7
            g.judge(1.0)


if __name__ == "__main__":
    unittest.main()
