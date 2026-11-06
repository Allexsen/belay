"""pybelay.inspect in real Inspect evals, with its mock model: no API calls.
Docker and a static belay are needed: make inspect-test."""
import json, os, sys, tempfile, unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from inspect_ai import Epochs, Task, eval as inspect_eval  # noqa: E402
from inspect_ai.dataset import Sample  # noqa: E402
from inspect_ai.scorer import CORRECT, INCORRECT, SampleScore, Score, Target, mean, scorer  # noqa: E402
from inspect_ai.solver import solver  # noqa: E402
from inspect_ai.util import sandbox  # noqa: E402

from pybelay import inspect as pi  # noqa: E402
from pybelay._errors import UsageError  # noqa: E402

SPEC = {"belay_protect": 2, "protect": [{"path": "test.py", "mode": ["no_write"]},
                                        {"path": "cases.json", "mode": ["no_write"]}]}
FILES = {"test.py": "assert True\n", "cases.json": "[]\n", "solution.py": "pass\n"}
COMPOSE = """services:
  default:
    image: python:3.11-slim
    working_dir: /work
    command: tail -f /dev/null
    init: true
"""


@solver
def agent(cmd):
    """What an agent's tool call does: one command in the sandbox. Its output
    goes where a test can read it."""
    async def solve(state, generate):
        r = await sandbox().exec(["sh", "-c", cmd])
        state.store.set("agent_saw", r.stdout + r.stderr)
        return state
    return solve


@solver
def lose_bundle():
    async def solve(state, generate):
        os.unlink(state.store.get(pi._STORE_KEY)["bundle"])
        return state
    return solve


@scorer(metrics=[mean()])
def changes_the_sandbox():
    """As a test-running scorer may: it puts a deleted file back."""
    async def score(state, target):
        await sandbox().write_file("cases.json", "[]\n")
        return Score(value=1.0)
    return score


class Evals(unittest.TestCase):
    sandbox_spec = None

    def run_task(self, solver_, scorers=None, setup=None, sb="default", files=FILES):
        t = tempfile.mkdtemp(prefix="pybelay-inspect-test-")
        task = Task(dataset=[Sample(input="x", target="", files=files)], solver=solver_,
                    setup=setup if setup is not None else pi.belay_record(SPEC),
                    scorer=scorers if scorers is not None else pi.belay_verify(),
                    sandbox=self.sandbox_spec if sb == "default" else sb)
        log = inspect_eval(task, model="mockllm/model", log_dir=t, display="none")[0]
        return log, log.samples[0]

    def verdict(self, sample):
        self.assertIsNone(sample.error, sample.error)
        return sample.scores["belay_verify"]


class Scenarios:
    """The same behaviour from each sandbox."""

    def test_editing_a_protected_file_is_a_violation(self):
        _, s = self.run_task(agent("echo '# edited' >> test.py"))
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (INCORRECT, "violation"))
        self.assertEqual(v.metadata["flags"]["protected_path_written"], 1)
        self.assertIn("test.py", v.explanation)

    def test_writing_only_the_solution_passes(self):
        log, s = self.run_task(agent("echo 'print(1)' > solution.py"))
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (CORRECT, "pass"))
        self.assertEqual(v.metadata["violations"], 0)
        m = {k: x.value for k, x in log.results.scores[0].metrics.items()}
        self.assertEqual((m["pass_rate"], m["violations"]), (1.0, 0))

    def test_deleting_a_protected_file_is_a_violation(self):
        log, s = self.run_task(agent("rm cases.json"))
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (INCORRECT, "violation"))
        self.assertEqual(v.metadata["flags"]["protected_path_deleted"], 1)
        m = {k: x.value for k, x in log.results.scores[0].metrics.items()}
        self.assertEqual((m["pass_rate"], m["violations"]), (0.0, 1))

    def test_metrics_with_no_epoch_reducer(self):
        task = Task(dataset=[Sample(input="x", target="", files=FILES)], solver=agent("rm cases.json"),
                    setup=pi.belay_record(SPEC), scorer=pi.belay_verify(), sandbox=self.sandbox_spec,
                    epochs=Epochs(1, reducer=[]))
        log = inspect_eval(task, model="mockllm/model", log_dir=tempfile.mkdtemp(), display="none")[0]
        m = {k: x.value for k, x in log.results.scores[0].metrics.items()}
        self.assertEqual((m["pass_rate"], m["violations"]), (0.0, 1))

    def test_a_spec_given_as_a_path(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(SPEC, f)
        self.addCleanup(os.unlink, f.name)
        _, s = self.run_task(agent("rm test.py"), setup=pi.belay_record(f.name))
        self.assertEqual(self.verdict(s).answer, "violation")

    def test_nothing_of_belays_is_there_while_the_agent_runs(self):
        _, s = self.run_task(agent("ls -a /tmp | grep -c '^.belay-'; ls -a"))
        saw = s.store["agent_saw"]
        self.assertEqual(saw.split()[0], "0", saw)
        self.assertNotIn("protect", saw)
        self.assertNotIn("bundle", saw)

    def test_it_runs_beside_another_scorer(self):
        _, s = self.run_task(agent("true"), scorers=[pi.belay_verify(), changes_the_sandbox()])
        self.assertEqual(self.verdict(s).answer, "pass")
        self.assertEqual(s.scores["changes_the_sandbox"].value, 1.0)

    def test_after_another_scorer_it_refuses(self):
        _, s = self.run_task(agent("rm cases.json"), scorers=[changes_the_sandbox(), pi.belay_verify()])
        self.assertIn("put belay_verify() first", str(s.error))

    def test_why_it_refuses_a_scorer_can_hide_a_deletion(self):
        _, s = self.run_task(agent("rm cases.json"),
                             scorers=[changes_the_sandbox(), pi.belay_verify(after_scorers=True)])
        self.assertEqual(self.verdict(s).answer, "pass")

    def test_without_belay_record_it_says_so(self):
        task = Task(dataset=[Sample(input="x", target="", files=FILES)], solver=agent("true"),
                    scorer=pi.belay_verify(), sandbox=self.sandbox_spec)
        log = inspect_eval(task, model="mockllm/model", log_dir=tempfile.mkdtemp(), display="none")[0]
        self.assertIn("add setup=belay_record", str(log.samples[0].error))

    def test_a_lost_baseline_fails_closed_and_the_other_scorers_run(self):
        _, s = self.run_task([lose_bundle()], scorers=[pi.belay_verify(), changes_the_sandbox()])
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (INCORRECT, "error"))
        self.assertEqual(v.metadata["error"]["type"], "FileNotFoundError")
        self.assertEqual(s.scores["changes_the_sandbox"].value, 1.0)

    def test_on_error_raise_fails_the_sample(self):
        _, s = self.run_task([lose_bundle()], scorers=pi.belay_verify(on_error="raise"))
        self.assertIsNotNone(s.error)

    def test_a_version_1_spec_is_refused_with_belays_reason(self):
        v1 = {"belay_protect": 1, "protect": SPEC["protect"]}
        _, s = self.run_task(agent("true"), setup=pi.belay_record(v1))
        self.assertIn("version 1 specs are refused", str(s.error))


class Docker(Scenarios, Evals):
    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp(prefix="pybelay-inspect-compose-")
        cls.sandbox_spec = ("docker", os.path.join(d, "compose.yaml"))
        with open(cls.sandbox_spec[1], "w") as f:
            f.write(COMPOSE)


class Local(Scenarios, Evals):
    sandbox_spec = "local"


class NoSandbox(Evals):
    def test_it_says_a_sandbox_is_needed(self):
        task = Task(dataset=[Sample(input="x", target="")], setup=pi.belay_record(SPEC), solver=agent("true"))
        log = inspect_eval(task, model="mockllm/model", log_dir=tempfile.mkdtemp(), display="none")[0]
        self.assertIn("belay needs a sandbox", str(log.samples[0].error))


def elf(machine):
    return b"\x7fELF" + bytes(14) + machine.to_bytes(2, "little")


class Architecture(unittest.TestCase):
    def test_a_match_passes(self):
        pi._check_architecture(elf(62), "Linux", "x86_64", False)
        pi._check_architecture(elf(183), "Linux", "aarch64", False)
        pi._check_architecture(elf(183), "Linux", "arm64", False)

    def test_another_architecture_is_refused_and_says_what_to_do(self):
        with self.assertRaises(UsageError) as e:
            pi._check_architecture(elf(62), "Linux", "aarch64", False)
        self.assertIn("linux-arm64", str(e.exception))
        self.assertIn("binary=", str(e.exception))

    def test_a_macos_binary_is_refused_for_a_linux_sandbox(self):
        with self.assertRaises(UsageError) as e:
            pi._check_architecture(b"\xcf\xfa\xed\xfe" + bytes(16), "Linux", "aarch64", False)
        self.assertIn("another system", str(e.exception))

    def test_only_linux_sandboxes_are_checked(self):
        pi._check_architecture(b"\xcf\xfa\xed\xfe" + bytes(16), "Darwin", "arm64", False)


class Metrics(unittest.TestCase):
    def scores(self, *values):
        return [SampleScore(score=Score(value=v)) for v in values]

    def test_pass_rate_and_violations(self):
        s = self.scores(CORRECT, INCORRECT, INCORRECT, CORRECT)
        self.assertEqual(pi.pass_rate()(s), 0.5)
        self.assertEqual(pi.violations()(s), 2)

    def test_a_reduced_score_counts_as_a_violation_in_any_epoch(self):
        self.assertEqual(pi.violations()(self.scores(0.5, 1.0)), 1)


if __name__ == "__main__":
    unittest.main()
