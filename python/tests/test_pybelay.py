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

    def test_an_unknown_key_is_a_format_error(self):
        line = pybelay._run(["check", "--scope", self.scope, "--json"])[0][0]
        line["nope"] = 1
        with self.assertRaises(pybelay.FormatError):
            pybelay._checkpoint(line)


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
