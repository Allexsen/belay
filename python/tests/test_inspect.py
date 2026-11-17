"""pybelay.inspect in real Inspect evals, with its mock model: no API calls.
Docker and a static belay are needed: make inspect-test."""
import asyncio, errno, hashlib, json, os, platform, shutil, subprocess, sys, tempfile, time, unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from inspect_ai import Epochs, Task, eval as inspect_eval  # noqa: E402
from inspect_ai.dataset import Sample  # noqa: E402
from inspect_ai.scorer import CORRECT, INCORRECT, SampleScore, Score, Target, mean, scorer  # noqa: E402
from inspect_ai.scorer import score as inspect_score  # noqa: E402
from inspect_ai.solver import solver  # noqa: E402
from inspect_ai.util import LimitExceededError, SandboxConnection, sandbox, sandboxenv, time_limit  # noqa: E402
from inspect_ai.util._sandbox.local import LocalSandboxEnvironment  # noqa: E402
import anyio  # noqa: E402

from pybelay import inspect as pi  # noqa: E402
from pybelay import _binary  # noqa: E402
from pybelay._errors import BelayError, BinaryMismatch, Refused, UsageError  # noqa: E402

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
def score_midway():
    """What an agent's progress check does: the task's scorers, before the end."""
    async def solve(state, generate):
        state.store.set("midway", [s.answer for s in await inspect_score(state)])
        return state
    return solve


@solver
def break_scope():
    """belay can't judge against a bundle that is not the one it made: a byte more on the host's copy."""
    async def solve(state, generate):
        with open(state.store.get(pi._STORE_KEY)["bundle"], "ab") as f:
            f.write(b"x")
        return state
    return solve


@solver
def forget_record():
    """As when belay_record ran in another process: the store has its copy, this process has none."""
    async def solve(state, generate):
        pi._records.pop(state.uuid)
        return state
    return solve


@solver
def write_in_the_stores_copy():
    """What code with the store can do without setting anything: change a list in place."""
    async def solve(state, generate):
        state.store.get(pi._STORE_KEY)["baseline_integrity"].append("written by the store's writer")
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
        self.assertEqual(v.metadata["where"], "sandbox")
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
        log, s = self.run_task([lose_bundle()], scorers=[pi.belay_verify(), changes_the_sandbox()])
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (INCORRECT, "error"))
        self.assertEqual(v.metadata["error"]["type"], "FileNotFoundError")
        self.assertEqual(v.metadata["where"], "sandbox")
        self.assertEqual(s.scores["changes_the_sandbox"].value, 1.0)
        m = {k: x.value for k, x in log.results.scores[0].metrics.items()}
        self.assertEqual((m["pass_rate"], m["violations"], m["errors"]), (0.0, 0, 1))

    def test_the_bundle_is_gone_once_the_sample_is_scored(self):
        _, s = self.run_task(agent("true"))
        self.assertEqual(self.verdict(s).answer, "pass")
        self.assertFalse(os.path.exists(s.store[pi._STORE_KEY]["bundle"]))

    def test_a_score_before_the_end_keeps_the_bundle_for_the_last(self):
        _, s = self.run_task([score_midway(), agent("rm cases.json")])
        self.assertEqual(s.store["midway"], ["pass"])
        self.assertEqual(self.verdict(s).answer, "violation")
        self.assertFalse(os.path.exists(s.store[pi._STORE_KEY]["bundle"]))

    def test_the_bundle_is_gone_after_a_run_belay_could_not_judge(self):
        _, s = self.run_task([break_scope(), agent("true")])
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (INCORRECT, "error"))
        self.assertEqual(v.metadata["error"]["type"], "Refused")    # belay's own refusal, not ours
        self.assertFalse(os.path.exists(s.store[pi._STORE_KEY]["bundle"]))

    def test_without_its_own_record_it_is_an_error_whatever_the_store_holds(self):
        _, s = self.run_task([forget_record(), agent("true")], scorers=[pi.belay_verify(), changes_the_sandbox()])
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (INCORRECT, "error"))
        self.assertIn("no record of this sample in this process", v.explanation)
        self.assertEqual(s.scores["changes_the_sandbox"].value, 1.0)

    def test_the_stores_copy_is_not_what_is_judged_against(self):
        before = set(pi._records)
        _, s = self.run_task([write_in_the_stores_copy(), agent("true")])
        v = self.verdict(s)
        self.assertEqual(v.answer, "pass")
        self.assertNotIn("written by the store's writer", v.metadata["baseline_integrity"])
        self.assertEqual(set(pi._records), before)                  # and its record went with the final score

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


def host_mode_works_here():
    """where="host" needs a Docker daemon on this machine and root for belay. In CI
    that is a requirement, never a skip."""
    if os.environ.get("CI"):
        return True
    try:
        sudo = os.geteuid() == 0 or subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0
        info = subprocess.run(["docker", "info", "--format", "{{.OperatingSystem}}"], capture_output=True, text=True)
    except OSError:
        return False
    return sudo and info.returncode == 0 and "Docker Desktop" not in info.stdout


class DockerHost(Evals):
    """belay on this machine, reading the sample's container: where="host"."""

    @classmethod
    def setUpClass(cls):
        # Asked here, not when the module is read: sudo and docker are run only for this class.
        if not host_mode_works_here():
            raise unittest.SkipTest("needs a local Docker daemon and root for belay")
        d = tempfile.mkdtemp(prefix="pybelay-inspect-compose-")
        cls.sandbox_spec = ("docker", os.path.join(d, "compose.yaml"))
        with open(cls.sandbox_spec[1], "w") as f:
            f.write(COMPOSE)

    def setUp(self):
        # Sandbox mode cleans up after itself, so looking into the sandbox afterwards
        # shows nothing either way: any use of its scratch directory fails the sample.
        p = mock.patch.object(pi, "_Scratch", side_effect=AssertionError("belay went into the sandbox"))
        p.start()
        self.addCleanup(p.stop)

    def host(self, cmd, scorers=None):
        return self.run_task(agent(cmd), scorers=scorers, setup=pi.belay_record(SPEC, where="host"))

    def test_editing_a_protected_file_is_a_violation_and_the_score_says_where(self):
        _, s = self.host("echo '# edited' >> test.py")
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (INCORRECT, "violation"))
        self.assertEqual(v.metadata["flags"]["protected_path_written"], 1)
        self.assertEqual(v.metadata["where"], "host")
        self.assertTrue(v.metadata["belay_version"])

    def test_writing_only_the_solution_passes(self):
        _, s = self.host("echo 'print(1)' > solution.py")
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (CORRECT, "pass"))
        self.assertEqual(v.metadata["where"], "host")

    def test_deleting_a_protected_file_is_a_violation(self):
        _, s = self.host("rm cases.json")
        self.assertEqual(self.verdict(s).metadata["flags"]["protected_path_deleted"], 1)

    def test_the_agent_sees_nothing_of_belays(self):
        _, s = self.host("ls -a /tmp /work; ps -e 2>/dev/null | grep '[b]elay'; true")
        self.assertEqual(self.verdict(s).answer, "pass")
        self.assertNotIn("belay", s.store.get("agent_saw", ""))

    def test_the_container_runs_again_after_each_reading(self):
        _, s = self.host("echo ran > solution.py && cat solution.py", scorers=[pi.belay_verify(), changes_the_sandbox()])
        self.assertIn("ran", s.store.get("agent_saw", ""))
        self.assertEqual(self.verdict(s).answer, "pass")
        self.assertEqual(s.scores["changes_the_sandbox"].value, 1.0)

    def test_a_store_naming_another_container_changes_nothing(self):
        _, s = self.run_task(edit_store(container="not-the-one"), setup=pi.belay_record(SPEC, where="host"))
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (CORRECT, "pass"))
        self.assertEqual(v.metadata["where"], "host")


@solver
def edit_store(**changes):
    """What code with the sample's store could do to what belay_record kept there."""
    async def solve(state, generate):
        recorded = dict(state.store.get(pi._STORE_KEY))
        recorded.update(changes)
        state.store.set(pi._STORE_KEY, recorded)
        return state
    return solve


@solver
def then(fn):
    async def solve(state, generate):
        fn()
        return state
    return solve


class HostModeThatCannotRun(Evals):
    """Asked for and unable to run, where="host" fails the sample and says why. It
    never runs belay in the sandbox instead (pybelay.md PY-I6). No Docker needed."""

    def refused(self):
        d = tempfile.mkdtemp(prefix="pybelay-inspect-nofallback-")
        files = dict(FILES)
        task = Task(dataset=[Sample(input="x", target="", files=files)], solver=agent("ls -a . /tmp 2>/dev/null; true"),
                    setup=pi.belay_record(SPEC, where="host"), scorer=pi.belay_verify(), sandbox="local")
        log = inspect_eval(task, model="mockllm/model", log_dir=d, display="none")[0]
        return log, log.samples[0]

    def test_a_sandbox_that_is_no_container_fails_the_sample_and_says_why(self):
        log, s = self.refused()
        self.assertIsNotNone(s.error)
        # The words of this refusal alone: on a machine that is not Linux it is still the one given.
        self.assertIn("needs a Docker sandbox, and this one gives no container", str(s.error))
        self.assertEqual(log.status, "error")

    def test_it_does_not_fall_back_to_the_sandbox(self):
        _, s = self.refused()
        # Had belay run in the sandbox instead, there would be a record to judge
        # against and a verdict. There is neither.
        self.assertIsNone(s.store.get(pi._STORE_KEY))
        self.assertFalse(s.scores)

    def test_where_must_be_one_of_the_two(self):
        with self.assertRaises(ValueError):
            pi.belay_record(SPEC, where="outside")
        with self.assertRaises(ValueError):
            pi.belay_record(SPEC, where="auto")

    def test_a_timeout_root_could_not_keep_is_refused_with_host_mode(self):
        for bad in (0, -1, None, 1.5, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                pi.belay_record(SPEC, where="host", timeout=bad)

    def test_binary_is_refused_with_host_mode(self):
        """binary= is only ever copied into a sandbox (PY-D5): the host runs the wheel's own."""
        with self.assertRaises(ValueError) as e:
            pi.belay_record(SPEC, where="host", binary="/usr/bin/true")
        self.assertIn("binary=", str(e.exception))


STAND_IN = '''#!%s -I
"""Stand-ins for docker and sudo: no daemon and no root. Each logs what it was asked.
sudo runs its command as this user, and a reading without `--docker NAME`, so the real
belay reads the stand-in sandbox's own directory."""
import os, sys, time
d = os.environ["PYBELAY_STANDIN"]
tool, args = os.path.basename(sys.argv[0]), sys.argv[1:]


def has(name):
    return os.path.exists(os.path.join(d, name))


def count_down(name):
    """True while the number in the file is above zero; one less each time."""
    if not has(name):
        return False
    with open(os.path.join(d, name)) as f:
        n = int(f.read())
    with open(os.path.join(d, name), "w") as f:
        f.write(str(max(n - 1, 0)))
    return n > 0


with open(os.path.join(d, "log"), "a") as f:
    f.write(tool + " " + " ".join(args) + "\\n")
if tool == "docker":
    mark = os.path.join(d, "paused")
    if args[0] == "pause":
        if has("pause-refused"):
            sys.exit("Error response from daemon: Container c1 is already paused")
        if has("pause-never-arrives"):
            time.sleep(30)
        if has("pause-lands-late"):     # the command is cut short; the daemon acts on it afterwards:
            if os.fork() == 0:          # a moment after it was first asked to unpause
                os.closerange(0, 3)     # or whoever reads this command's output waits for the child
                for _ in range(400):
                    if has("asked-to-unpause"):
                        time.sleep(0.3)
                        open(mark, "w").close()
                        break
                    time.sleep(0.05)
                os._exit(0)
            time.sleep(30)
        open(mark, "w").close()
        if has("pause-hangs"):          # the daemon has the request; the command does not come back
            time.sleep(30)
    elif args[0] == "unpause":
        open(os.path.join(d, "asked-to-unpause"), "w").close()
        if has("unpause-is-slow"):
            time.sleep(1)
        if count_down("unpause-fails"):
            sys.exit("Error response from daemon: cannot unpause")
        if not os.path.exists(mark):
            sys.exit("Error response from daemon: Container c1 is not paused")
        os.unlink(mark)
    sys.exit(0)
assert args[:2] == ["-n", "--"], args
cmd = args[2:]
if has("sudo-allows") and not count_down("sudo-allows"):
    sys.exit("sudo: a password is required")
if "mkdir" in cmd and has("mkdir-warned-and-failed"):
    sys.exit("sudo: unable to resolve host here\\nmkdir: cannot create directory: No space left on device")
if "mkdir" in cmd and has("mkdir-does-not-come-back"):
    os.mkdir(cmd[-1], 0o700)
    time.sleep(30)
if "rm" in cmd and has("rm-does-not-come-back"):
    time.sleep(6)
if "--docker" in cmd:
    i = cmd.index("env")
    if has("something-else-unpauses"):
        os.unlink(os.path.join(d, "paused"))
    if has("belay-is-slow"):
        time.sleep(1)
    if has("belay-sleeps"):
        cmd = cmd[:i] + ["sleep", "30"]
    elif has("belay-ignores-term"):
        cmd = cmd[:i] + ["sh", "-c", 'trap "" TERM; sleep 30']
    elif has("belay-crashes"):
        cmd = cmd[:i] + ["sh", "-c", "kill -SEGV $$"]
    elif has("belay-cannot-be-run"):
        cmd = cmd[:i] + ["env", "/nonexistent/belay"]
    elif has("belay-keeps-writing"):    # until its first file is gone, as belay does until its state is
        cmd = cmd[:i + 3] + ["sh", "-c", 'd="$BELAY_STATE_DIR"; mkdir -p "$d"; : > "$d/first"; i=0; '
                             'while [ -e "$d/first" ]; do : > "$d/f$i" 2>/dev/null; i=$((i+1)); done']
    elif has("belay-outlives-its-timeout"):
        cmd = ["sleep", "6"]
    elif has("belay-refuses"):
        cmd = cmd[:i] + ["sh", "-c", 'echo "belay: --docker c1: the scope is a volume (host-reader H-C3)" >&2; exit 3']
    else:
        j = cmd.index("--docker")
        cmd = cmd[:j] + cmd[j + 2:]
os.execvp(cmd[0], cmd)
'''

STANDS_IN = "the stand-in sudo needs Linux and a user who is not root"
CAN_STAND_IN = platform.system() == "Linux" and os.geteuid() != 0


class StandIns:
    """`docker` and `sudo` first on PATH that are neither, and root's /tmp somewhere of ours."""

    def setUp(self):
        d = self.standin = tempfile.mkdtemp(prefix="pybelay-standin-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.mkdir(os.path.join(d, "bin"))
        os.mkdir(os.path.join(d, "tmp"))
        for name in ("docker", "sudo"):
            with open(os.path.join(d, "bin", name), "w") as f:
                f.write(STAND_IN % sys.executable)
            os.chmod(os.path.join(d, "bin", name), 0o755)
        env = {"PATH": os.path.join(d, "bin") + os.pathsep + os.environ["PATH"], "PYBELAY_STANDIN": d}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("DOCKER_HOST", None)
        p = mock.patch.object(pi, "_HOST_TMP", os.path.join(d, "tmp"))
        p.start()
        self.addCleanup(p.stop)

    def given(self, name, value=""):
        with open(os.path.join(self.standin, name), "w") as f:
            f.write(str(value))

    def asked(self, tool=None):
        try:
            with open(os.path.join(self.standin, "log")) as f:
                lines = f.read().splitlines()
        except FileNotFoundError:
            return []
        return [x for x in lines if tool is None or x.startswith(tool + " ")]

    def paused(self):
        return os.path.exists(os.path.join(self.standin, "paused"))

    def roots_directories(self):
        return os.listdir(os.path.join(self.standin, "tmp"))


@unittest.skipUnless(CAN_STAND_IN, STANDS_IN)
class HostTools(StandIns, unittest.TestCase):
    """One reading by pybelay.inspect's host runner, with the stand-ins: what it asks of
    docker and of root, in what order, and what it leaves when things go wrong."""

    def setUp(self):
        super().setUp()
        self.scope = tempfile.mkdtemp(prefix="pybelay-standin-scope-")
        self.addCleanup(shutil.rmtree, self.scope, ignore_errors=True)
        with open(os.path.join(self.scope, "test.py"), "w") as f:
            f.write("assert True\n")
        self.kept = os.path.join(self.standin, "bundle")

    def host(self, timeout=20):
        return pi._Host("c1", pi._host_binary(), json.dumps(SPEC), timeout)

    async def reading(self, h):
        return await h.run("baseline", "export", "--docker", "c1", "--scope", self.scope, "--out", self.kept,
                           "--protect", h.protect, "--json")

    def whole(self, timeout=20, limit=None):
        """start, one reading, close: as belay_record does. Returns what came of the reading."""
        out = {}

        async def main():
            h = out["host"] = self.host(timeout)
            try:
                try:
                    await h.start()             # outside the limit: a limit is for the reading
                except BaseException:
                    await h.close()
                    raise
                with time_limit(limit):
                    try:
                        out["lines"] = await self.reading(h)
                    finally:
                        await h.close()         # inside it: a cancelled sample still closes
            except BaseException as e:
                out["error"] = e
        anyio.run(main)
        return out

    def test_a_reading_pauses_the_container_and_sets_it_running_again(self):
        out = self.whole()
        self.assertNotIn("error", out)
        self.assertEqual(len(out["lines"][0]["sha256"]), 64)
        asked = [" ".join(x.split()[:2]) if x.startswith("docker") else "sudo " + x.split()[7] for x in self.asked()]
        priv = out["host"].priv
        self.assertEqual(asked, ["sudo mkdir", "sudo install", "sudo install", "sudo " + priv + "/belay",
                                 "docker pause", "sudo env", "docker unpause", "sudo rm"])
        self.assertFalse(self.paused())
        self.assertEqual(self.roots_directories(), [])

    def test_root_is_asked_only_for_timeout_and_runs_a_copy_of_the_checked_binary(self):
        out = self.whole()
        for line in self.asked("sudo"):
            self.assertTrue(line.startswith("sudo -n -- timeout -k 5 20 "), line)
        reading = [x for x in self.asked("sudo") if " baseline export " in x][0].split()
        ran = reading[reading.index("baseline") - 1]
        self.assertEqual(ran, out["host"].priv + "/belay")
        self.assertNotEqual(ran, _binary.binary_path())
        self.assertIn("BELAY_STATE_DIR=" + out["host"].priv + "/state", reading)

    def test_a_cancelled_reading_leaves_the_container_running_and_nothing_of_roots(self):
        self.given("belay-sleeps")
        out = self.whole(limit=1)
        self.assertIsInstance(out["error"], LimitExceededError)
        self.assertEqual(len(self.asked("docker pause")), 1)
        self.assertFalse(self.paused())
        self.assertEqual(self.roots_directories(), [])

    def test_a_pause_that_does_not_come_back_is_undone(self):
        self.given("pause-hangs")
        out = self.whole(timeout=1)
        self.assertIsInstance(out["error"], TimeoutError)
        self.assertFalse(self.paused())
        self.assertFalse([x for x in self.asked("sudo") if " baseline " in x])

    def test_a_pause_that_never_reached_the_daemon_is_only_a_timeout(self):
        self.given("pause-never-arrives")
        out = self.whole(timeout=1)
        self.assertIsInstance(out["error"], TimeoutError)
        self.assertNotIn("paused", str(out["error"]))
        self.assertEqual(len(self.asked("docker unpause")), 2)      # and once more a moment later, in case

    def test_a_pause_the_daemon_acts_on_late_is_still_undone(self):
        self.given("pause-lands-late")
        out = self.whole(timeout=1)
        self.assertIsInstance(out["error"], TimeoutError)
        time.sleep(1)                                               # past the moment the late pause lands
        self.assertFalse(self.paused())
        self.assertEqual(len(self.asked("docker unpause")), 2)      # the first found nothing to undo yet

    def test_a_container_something_else_set_running_is_not_called_paused(self):
        self.given("something-else-unpauses")
        out = self.whole()
        self.assertNotIn("error", out)
        self.assertEqual(len(out["lines"][0]["sha256"]), 64)
        self.assertEqual(len(self.asked("docker unpause")), 1)

    def test_a_pause_docker_refuses_is_said_and_nothing_is_unpaused(self):
        self.given("pause-refused")
        out = self.whole()
        self.assertIsInstance(out["error"], UsageError)
        self.assertIn("already paused", str(out["error"]))
        self.assertEqual(self.asked("docker unpause"), [])

    def test_what_belay_refuses_is_refused_with_its_reason(self):
        self.given("belay-refuses")
        out = self.whole()
        self.assertIsInstance(out["error"], Refused)
        self.assertIn("host-reader H-C3", str(out["error"]))
        self.assertFalse(self.paused())

    def test_a_belay_that_cannot_be_run_is_said_as_that(self):
        self.given("belay-cannot-be-run")
        out = self.whole()
        self.assertIsInstance(out["error"], UsageError)
        self.assertIn("belay could not be run as root (exit 127", str(out["error"]))
        self.assertFalse(self.paused())

    def test_an_unpause_that_fails_once_is_tried_again(self):
        self.given("unpause-fails", 1)
        out = self.whole()
        self.assertNotIn("error", out)
        self.assertEqual(len(self.asked("docker unpause")), 2)
        self.assertFalse(self.paused())

    def test_a_container_left_paused_is_said_together_with_belays_answer(self):
        self.given("unpause-fails", 2)
        out = self.whole()
        self.assertIsInstance(out["error"], UsageError)
        self.assertIn("c1 is still paused", str(out["error"]))
        self.assertIn('"sha256"', str(out["error"]))
        self.assertTrue(self.paused())

    def test_a_container_left_paused_is_said_together_with_belays_refusal(self):
        self.given("unpause-fails", 2)
        self.given("belay-refuses")
        out = self.whole()
        self.assertIn("c1 is still paused", str(out["error"]))
        self.assertIn("host-reader H-C3", str(out["error"]))
        self.assertIsInstance(out["error"], Refused)                # still the kind of error belay's was
        self.assertEqual(out["error"].exit_code, 3)

    def test_a_cancelled_reading_whose_container_stays_paused_is_a_warning(self):
        self.given("belay-sleeps")
        self.given("unpause-fails", 2)
        with self.assertLogs("pybelay.inspect", "WARNING") as logs:
            out = self.whole(limit=1)
        self.assertIsInstance(out["error"], LimitExceededError)
        self.assertIn("paused: `docker unpause` failed twice", logs.output[0])

    def test_a_reading_that_timed_out_is_still_a_timeout_when_the_container_stays_paused(self):
        self.given("belay-sleeps")
        self.given("unpause-fails", 2)
        out = self.whole(timeout=1)
        self.assertIsInstance(out["error"], TimeoutError)
        self.assertIn("belay did not finish within 1 s", str(out["error"]))
        self.assertIn("c1 is still paused", str(out["error"]))

    def test_a_reading_that_outlasts_the_timeout_is_ended_by_roots_own_timeout(self):
        self.given("belay-sleeps")
        t = time.monotonic()
        out = self.whole(timeout=1)
        self.assertIsInstance(out["error"], TimeoutError)
        self.assertIn("belay did not finish within 1 s", str(out["error"]))
        self.assertLess(time.monotonic() - t, 10)
        self.assertFalse(self.paused())

    def test_a_reading_roots_timeout_had_to_kill_is_a_timeout_too(self):
        self.given("belay-ignores-term")
        with mock.patch.object(pi, "_KILL_AFTER", 1):
            out = self.whole(timeout=1)
        self.assertIsInstance(out["error"], TimeoutError)
        self.assertRegex(str(out["error"]), "signal 9|exit 137")
        self.assertFalse(self.paused())

    def test_a_reading_that_died_by_another_signal_failed_and_did_not_time_out(self):
        self.given("belay-crashes")
        out = self.whole()
        self.assertIsInstance(out["error"], pi.Failed)
        self.assertIn("belay was ended by signal 11", str(out["error"]))
        self.assertFalse(self.paused())

    def unkillable(self):
        """As sudo's processes are to the user who started them: a signal is EPERM."""
        real = subprocess.Popen.send_signal

        def send_signal(proc, sig):
            if os.path.basename(list(proc.args)[0]) == "sudo":
                raise PermissionError(errno.EPERM, "Operation not permitted")
            return real(proc, sig)
        p = mock.patch.object(subprocess.Popen, "send_signal", send_signal)
        p.start()
        self.addCleanup(p.stop)

    def test_a_root_process_inspect_cannot_stop_is_a_timeout_not_a_permission_error(self):
        self.unkillable()
        self.given("belay-outlives-its-timeout")
        with mock.patch.object(pi, "_BEHIND", 1):
            out = self.whole(timeout=1)
        self.assertIsInstance(out["error"], TimeoutError)
        self.assertNotIsInstance(out["error"], PermissionError)
        self.assertIn("cannot be stopped from here", str(out["error"]))
        self.assertEqual(len(self.asked("docker pause")), 1)        # it was the reading that was not stopped
        self.assertFalse(self.paused())

    def test_a_cancelled_reading_root_cannot_be_told_to_stop_is_still_a_cancellation(self):
        self.unkillable()
        self.given("belay-sleeps")
        out = self.whole(timeout=3, limit=1)
        self.assertIsInstance(out["error"], LimitExceededError)
        self.assertFalse(self.paused())

    @unittest.skipUnless(sys.version_info >= (3, 11), "asyncio says whether a task is being cancelled from 3.11")
    def test_a_reading_cancelled_by_asyncio_itself_is_still_a_cancellation(self):
        self.unkillable()
        self.given("belay-sleeps")
        out = {}

        async def main():
            h = self.host(3)
            await h.start()
            task = asyncio.ensure_future(self.reading(h))
            while not [x for x in self.asked("sudo") if " baseline export " in x]:
                await asyncio.sleep(0.05)       # not before the reading itself is under way
            await asyncio.sleep(0.2)
            task.cancel()
            try:
                await task
            except BaseException as e:
                out["error"] = e
            await h.close()
        asyncio.run(main())
        self.assertIsInstance(out["error"], asyncio.CancelledError)
        self.assertFalse(self.paused())

    def test_asyncios_own_cancellation_during_the_unpause_waits_for_the_container(self):
        """No shield of anyio's holds off task.cancel(): the unpause is finished first."""
        self.given("unpause-is-slow")
        out = {}

        async def main():
            h = self.host()
            await h.start()
            task = asyncio.ensure_future(self.reading(h))
            while not self.asked("docker unpause"):
                await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except BaseException as e:
                out["error"] = e
            out["paused"] = self.paused()
            await h.close()
        asyncio.run(main())
        self.assertIsInstance(out["error"], asyncio.CancelledError)
        self.assertFalse(out["paused"])
        self.assertEqual(len(self.asked("docker unpause")), 2)      # the one that was cut off, and one more

    def test_a_cancelled_reading_that_goes_on_writing_still_leaves_nothing_of_roots(self):
        """Root's belay cannot be stopped from here, and writes on while its directory is
        removed: one removal is not enough."""
        self.unkillable()
        self.given("belay-keeps-writing")
        out = self.whole(timeout=6, limit=1)
        self.assertIsInstance(out["error"], LimitExceededError)
        self.assertGreater(len(self.asked("sudo")) - 5, 0)          # the removal was asked for
        self.assertEqual(self.roots_directories(), [])

    def test_a_cancelled_reading_that_makes_its_directory_again_is_removed_again(self):
        """Cancelled before belay had made anything: the first removal finds all there was,
        and belay then makes its state, parents and all."""
        self.unkillable()
        self.given("belay-is-slow")
        self.given("belay-keeps-writing")
        out = self.whole(timeout=6, limit=0.5)
        self.assertIsInstance(out["error"], LimitExceededError)
        time.sleep(1)
        self.assertEqual(self.roots_directories(), [])

    def test_a_removal_root_cannot_be_made_to_finish_is_a_warning_and_the_time_limit_stays_one(self):
        self.unkillable()
        self.given("belay-sleeps")
        self.given("rm-does-not-come-back")
        with mock.patch.object(pi, "_BEHIND", 0), self.assertLogs("pybelay.inspect", "WARNING") as logs:
            out = self.whole(timeout=1, limit=1)
        self.assertIsInstance(out["error"], LimitExceededError)     # not a bare CancelledError
        self.assertIn("could not be removed", logs.output[-1])
        self.assertEqual(len([x for x in self.asked("sudo") if " rm -rf " in x]), 6)

    def test_a_directory_whose_making_was_cut_short_is_removed_all_the_same(self):
        self.given("mkdir-does-not-come-back")
        with mock.patch.object(pi, "_BEHIND", 1):
            out = self.whole(timeout=1)
        self.assertIsInstance(out["error"], TimeoutError)
        self.assertEqual(self.roots_directories(), [])

    def test_a_directory_that_was_already_there_is_refused_and_left_alone(self):
        out = {}

        async def main():
            h = self.host()
            os.mkdir(h.priv)
            open(os.path.join(h.priv, "theirs"), "w").close()
            try:
                await h.start()
            except UsageError as e:
                out["error"] = e
            finally:
                await h.close()
            out["kept"] = os.path.exists(os.path.join(h.priv, "theirs"))
        anyio.run(main)
        self.assertIn("could not be made", str(out["error"]))
        self.assertTrue(out["kept"])

    def test_a_helper_that_fails_after_a_warning_of_sudos_is_not_a_refused_sudo(self):
        self.given("mkdir-warned-and-failed")
        out = self.whole()
        self.assertIsInstance(out["error"], UsageError)
        self.assertIn("could not be made", str(out["error"]))
        self.assertNotIn("refused", str(out["error"]))

    def test_readings_take_turns_and_a_container_is_paused_only_in_its_turn(self):
        self.given("belay-is-slow")

        async def one(n):
            h = pi._Host("c%d" % n, pi._host_binary(), json.dumps(SPEC), 20)
            try:
                await h.start()
                await h.run("baseline", "export", "--docker", h.container, "--scope", self.scope,
                            "--out", self.kept + str(n), "--protect", h.protect, "--json")
            finally:
                await h.close()

        async def main():
            async with anyio.create_task_group() as tg:
                for n in (1, 2, 3):
                    tg.start_soon(one, n)
        with mock.patch.object(pi, "_SLOT", "pybelay-host-turns"), mock.patch.object(pi, "_READINGS", 1):
            anyio.run(main)
        self.assertEqual([x.split()[1] for x in self.asked("docker")], ["pause", "unpause"] * 3)

    def test_a_refused_sudo_is_said_and_nothing_is_left_to_remove(self):
        self.given("sudo-allows", 0)
        out = self.whole()
        self.assertIsInstance(out["error"], UsageError)
        self.assertIn("`sudo -n` was refused (sudo: a password is required)", str(out["error"]))
        self.assertEqual(len(self.asked("sudo")), 1)
        self.assertEqual(self.asked("docker"), [])

    def test_sudo_refused_at_the_reading_is_said_as_that(self):
        self.given("sudo-allows", 4)        # the directory, the two files and the version: then no more
        with self.assertLogs("pybelay.inspect", "WARNING") as logs:
            out = self.whole()
        self.assertIsInstance(out["error"], UsageError)
        self.assertIn("`sudo -n` was refused", str(out["error"]))
        self.assertFalse(self.paused())
        # Its directory could not be removed either, and that is said, not swallowed.
        self.assertIn(out["host"].priv, logs.output[0])
        self.assertIn("could not be removed", logs.output[0])

    def test_the_daemon_the_eval_uses_is_the_one_roots_belay_asks(self):
        with mock.patch.dict(os.environ, {"DOCKER_HOST": "unix:///run/user/1000/docker.sock"}):
            out = self.whole()
        self.assertNotIn("error", out)
        reading = [x for x in self.asked("sudo") if " baseline export " in x][0]
        self.assertIn(" DOCKER_HOST=unix:///run/user/1000/docker.sock ", reading)

    def test_an_eval_that_is_root_asks_nothing_of_sudo(self):
        # The real belay then gets --docker as it is, finds it is not root, and says so.
        with mock.patch.object(pi.os, "geteuid", return_value=0):
            out = self.whole()
        self.assertEqual(self.asked("sudo"), [])
        self.assertEqual([x.split()[1] for x in self.asked("docker")], ["pause", "unpause"])
        self.assertIsInstance(out["error"], BelayError)
        self.assertIn("root", str(out["error"]))
        self.assertEqual(self.roots_directories(), [])


class ScratchCancelled(unittest.TestCase):
    def test_a_cancelled_step_still_takes_belay_out_of_the_sandbox(self):
        ran = []

        class Result:
            success, returncode, stdout, stderr = True, 0, "belay 0", ""

        class Env:
            async def exec(self, cmd, **kw):
                await anyio.sleep(0.01)
                ran.append(cmd[0])
                return Result

            async def write_file(self, path, contents, **kw):
                await anyio.sleep(0)

        async def main():
            with anyio.move_on_after(0.5):
                async with pi._Scratch(Env(), b"x", "{}", None, 5):
                    await anyio.sleep(30)
        anyio.run(main)
        self.assertEqual(ran[-1], "rm")

    def scratch_that_does_not_get_in(self, version_ok, delay):
        ran = []

        class Env:
            async def exec(self, cmd, **kw):
                await anyio.sleep(delay if cmd[0] == "chmod" else 0.01)
                ran.append(cmd[0])
                return type("R", (), dict(success=version_ok or "--version" not in cmd, stdout="belay 0",
                                          returncode=0 if version_ok else 126, stderr="cannot execute"))

            async def write_file(self, path, contents, **kw):
                await anyio.sleep(0)
        out = {}

        async def main():
            with anyio.move_on_after(0.5):
                try:
                    async with pi._Scratch(Env(), b"x", "{}", None, 5):
                        out["entered"] = True
                except UsageError as e:
                    out["error"] = e
        anyio.run(main)
        return ran, out

    def test_a_binary_that_does_not_run_in_the_sandbox_is_taken_out_of_it(self):
        ran, out = self.scratch_that_does_not_get_in(version_ok=False, delay=0.01)
        self.assertIn("doesn't run in this sandbox", str(out["error"]))
        self.assertEqual(ran[-1], "rm")

    def test_a_step_cancelled_while_belay_was_going_in_takes_it_out(self):
        ran, out = self.scratch_that_does_not_get_in(version_ok=True, delay=30)
        self.assertNotIn("entered", out)
        self.assertEqual(ran, ["rm"])


@sandboxenv(name="pybelay-spy")
class Spy(LocalSandboxEnvironment):
    """The local sandbox, saying it is the Docker container c1, and keeping what was asked of it."""
    asked = []
    container = "c1"

    @classmethod
    async def sample_init(cls, task_name, config, metadata):
        return {"default": Spy()}

    async def exec(self, cmd, *args, **kw):
        # Inspect asks a new sandbox who it runs as; that one is its own.
        if "inspect_image_path" not in " ".join(cmd):
            Spy.asked.append(["exec"] + list(cmd))
        return await super().exec(cmd, *args, **kw)

    async def write_file(self, file, contents, **kw):
        Spy.asked.append(["write", file])
        return await super().write_file(file, contents, **kw)

    async def connection(self, *, user=None):
        return SandboxConnection(type="docker", command="docker exec -it c1 sh", container=Spy.container)


@unittest.skipUnless(CAN_STAND_IN, STANDS_IN)
class HostModeStandIn(StandIns, Evals):
    """where="host" through whole evals, with the stand-ins and the real belay. No Docker."""
    sandbox_spec = "pybelay-spy"

    def setUp(self):
        super().setUp()
        Spy.asked, Spy.container = [], "c1"

    def host(self, steps, scorers=None):
        return self.run_task(steps, scorers=scorers, setup=pi.belay_record(SPEC, where="host"))

    def test_editing_a_protected_file_is_a_violation_and_the_score_says_where_and_which_belay(self):
        _, s = self.host(agent("echo '# edited' >> test.py"))
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (INCORRECT, "violation"))
        self.assertEqual(v.metadata["flags"]["protected_path_written"], 1)
        self.assertEqual(v.metadata["where"], "host")
        says = subprocess.run([_binary.binary_path(), "--version"], capture_output=True, text=True).stdout.strip()
        self.assertEqual(v.metadata["belay_version"], says)

    def test_nothing_is_asked_of_the_sandbox_but_its_directory_and_the_agents_own_command(self):
        _, s = self.host(agent("echo 'print(1)' > solution.py"))
        self.assertEqual(self.verdict(s).answer, "pass")
        writes = sorted(x[1] for x in Spy.asked if x[0] == "write")
        execs = [x[1:] for x in Spy.asked if x[0] == "exec"]
        self.assertEqual(writes, sorted(FILES))
        self.assertEqual(execs, [["pwd"], ["sh", "-c", "echo 'print(1)' > solution.py"]])

    def test_each_reading_has_its_pause_and_nothing_of_roots_stays(self):
        _, s = self.host(agent("true"))
        self.assertEqual(self.verdict(s).answer, "pass")
        self.assertEqual([x.split()[1] for x in self.asked("docker")], ["pause", "unpause", "pause", "unpause"])
        self.assertFalse(self.paused())
        self.assertEqual(self.roots_directories(), [])

    def test_a_score_before_the_end_and_the_last_one(self):
        _, s = self.host([score_midway(), agent("rm cases.json")])
        self.assertEqual(s.store["midway"], ["pass"])
        self.assertEqual(self.verdict(s).answer, "violation")
        self.assertFalse(os.path.exists(s.store[pi._STORE_KEY]["bundle"]))

    def test_what_belay_refuses_is_an_error_with_its_reason(self):
        _, s = self.host(then(lambda: self.given("belay-refuses")))
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer, v.metadata["where"]), (INCORRECT, "error", "host"))
        self.assertIn("host-reader H-C3", v.explanation)
        self.assertFalse(self.paused())

    def test_on_error_raise_fails_the_sample(self):
        _, s = self.host(then(lambda: self.given("belay-refuses")), scorers=pi.belay_verify(on_error="raise"))
        self.assertIn("host-reader H-C3", str(s.error))

    def test_a_sandbox_whose_container_was_replaced_is_a_run_belay_could_not_judge(self):
        _, s = self.host(then(lambda: setattr(Spy, "container", "c2")))
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (INCORRECT, "error"))
        self.assertIn("not the one belay_record read", v.explanation)
        self.assertEqual(len(self.asked("docker pause")), 1)       # the record's, and no other

    def test_what_the_store_says_changes_nothing_root_is_asked_or_runs(self):
        mark = os.path.join(self.standin, "ran-as-root")
        other = os.path.join(self.standin, "not-belay")
        with open(other, "w") as f:
            f.write("#!/bin/sh\ntouch %s\n" % mark)
        os.chmod(other, 0o755)
        with open(other, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        for changes in (dict(binary=other, binary_sha256=digest), dict(container="another"), dict(timeout=7),
                        dict(scope="/"), dict(bundle=other), dict(where="sandbox"), dict(container=None)):
            if os.path.exists(os.path.join(self.standin, "log")):
                os.unlink(os.path.join(self.standin, "log"))        # each eval's own askings
            Spy.asked = []
            _, s = self.host(edit_store(**changes))
            v = self.verdict(s)
            self.assertEqual((v.answer, v.metadata["where"]), ("pass", "host"), changes)
            self.assertEqual([x.split()[1:3] for x in self.asked("docker")], [["pause", "c1"], ["unpause", "c1"]] * 2)
            asked = "\n".join(self.asked("sudo"))
            for never in ("not-belay", " -k 5 7 ", "--scope / "):
                self.assertNotIn(never, asked, changes)
            self.assertEqual(sorted(x[1] for x in Spy.asked if x[0] == "write"), sorted(FILES), changes)
        self.assertFalse(os.path.exists(mark))

    def test_a_record_of_the_default_mode_is_not_made_a_host_one_by_the_store(self):
        _, s = self.run_task(edit_store(where="host", container="c1"), setup=pi.belay_record(SPEC))
        v = self.verdict(s)
        self.assertEqual((v.answer, v.metadata["where"]), ("pass", "sandbox"))
        self.assertEqual(self.asked(), [])                          # neither sudo nor docker was asked anything

    def test_sudo_refused_at_the_verdict_is_said_as_that(self):
        _, s = self.host(then(lambda: self.given("sudo-allows", 0)))
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (INCORRECT, "error"))
        self.assertIn("`sudo -n` was refused", v.explanation)

    def test_a_container_left_paused_is_said_in_the_verdict(self):
        _, s = self.host(then(lambda: self.given("unpause-fails", 2)))
        v = self.verdict(s)
        self.assertEqual((v.value, v.answer), (INCORRECT, "error"))
        self.assertIn("c1 is still paused", v.explanation)

    def test_it_never_uses_the_sandbox_instead_when_root_cannot_be_had(self):
        self.given("sudo-allows", 0)
        log, s = self.host(agent("true"))
        self.assertIn("`sudo -n` was refused", str(s.error))
        self.assertIsNone(s.store.get(pi._STORE_KEY))
        self.assertFalse(s.scores)
        self.assertEqual([x for x in Spy.asked if x[0] == "exec" and x[1] not in ("pwd", "sh")], [])
        self.assertEqual(sorted(x[1] for x in Spy.asked if x[0] == "write"), sorted(FILES))


class NoSandbox(Evals):
    def test_it_says_a_sandbox_is_needed(self):
        task = Task(dataset=[Sample(input="x", target="")], setup=pi.belay_record(SPEC), solver=agent("true"))
        log = inspect_eval(task, model="mockllm/model", log_dir=tempfile.mkdtemp(), display="none")[0]
        self.assertIn("belay needs a sandbox", str(log.samples[0].error))


def elf(machine):
    return b"\x7fELF" + bytes(14) + machine.to_bytes(2, "little")


MACHO = b"\xcf\xfa\xed\xfe" + bytes(16)
X86, ARM = elf(62), elf(183)


class Layout:
    """A wheel's _bin: its own binary, and the Linux ones a macOS wheel carries."""

    def lay(self, own, x86=None, arm=None):
        d = tempfile.mkdtemp(prefix="pybelay-bin-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)

        def put(name, data):
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
            return hashlib.sha256(data).hexdigest()

        with open(os.path.join(d, "SHA256"), "w") as f:
            f.write(put("belay", own) + "\n")
        for arch, data in (("x86_64", x86), ("arm64", arm)):
            if data is not None:
                with open(os.path.join(d, "linux-%s.sha256" % arch), "w") as f:
                    f.write(put("linux-" + arch, data) + "\n")
        saved = _binary._HERE, _binary._checked
        _binary._HERE, _binary._checked = d, None
        self.addCleanup(lambda: (setattr(_binary, "_HERE", saved[0]), setattr(_binary, "_checked", saved[1])))
        return d


class Selection(Layout, unittest.TestCase):
    def picked(self, system, machine):
        return os.path.basename(pi._pick_binary(None, system, machine))

    def test_a_mac_picks_the_carried_binary_of_the_sandboxs_architecture(self):
        self.lay(MACHO, X86, ARM)
        self.assertEqual(self.picked("Linux", "aarch64"), "linux-arm64")
        self.assertEqual(self.picked("Linux", "arm64"), "linux-arm64")
        self.assertEqual(self.picked("Linux", "x86_64"), "linux-x86_64")
        self.assertEqual(self.picked("Linux", "amd64"), "linux-x86_64")

    def test_a_macs_own_binary_serves_a_macos_sandbox(self):
        self.lay(MACHO, X86, ARM)
        self.assertEqual(self.picked("Darwin", "arm64"), "belay")

    def test_a_linux_wheel_uses_its_own_for_its_own_architecture(self):
        self.lay(X86)
        self.assertEqual(self.picked("Linux", "x86_64"), "belay")
        self.lay(ARM)
        self.assertEqual(self.picked("Linux", "aarch64"), "belay")

    def test_a_linux_wheel_serves_the_other_architecture_from_what_it_carries(self):
        self.lay(X86, arm=ARM)
        self.assertEqual(self.picked("Linux", "x86_64"), "belay")
        self.assertEqual(self.picked("Linux", "aarch64"), "linux-arm64")
        self.lay(ARM, x86=X86)
        self.assertEqual(self.picked("Linux", "aarch64"), "belay")
        self.assertEqual(self.picked("Linux", "x86_64"), "linux-x86_64")

    def test_a_wheel_carrying_nothing_refuses_another_architecture_and_says_what_to_do(self):
        self.lay(X86)
        with self.assertRaises(UsageError) as e:
            self.picked("Linux", "aarch64")
        self.assertIn("linux-arm64", str(e.exception))
        self.assertIn("binary=", str(e.exception))
        self.lay(ARM)
        with self.assertRaises(UsageError) as e:
            self.picked("Linux", "x86_64")
        self.assertIn("linux-x86_64", str(e.exception))

    def test_an_unknown_architecture_is_refused(self):
        self.lay(MACHO, X86, ARM)
        with self.assertRaises(UsageError):
            self.picked("Linux", "riscv64")

    def test_a_carried_binary_that_doesnt_hash_is_refused(self):
        d = self.lay(MACHO, X86, ARM)
        with open(os.path.join(d, "linux-arm64"), "ab") as f:
            f.write(b"x")
        with self.assertRaises(BinaryMismatch):
            self.picked("Linux", "aarch64")

    def test_binary_is_checked_against_the_sandbox(self):
        d = self.lay(MACHO, X86, ARM)
        given = os.path.join(d, "linux-x86_64")
        self.assertEqual(pi._pick_binary(given, "Linux", "x86_64"), given)
        with self.assertRaises(UsageError) as e:
            pi._pick_binary(given, "Linux", "aarch64")
        self.assertIn("binary=", str(e.exception))


class HostBinary(Layout, unittest.TestCase):
    """What where="host" will run on this machine: the wheel's own binary, as checked."""

    def other(self):
        return ARM if platform.machine() == "x86_64" else X86

    def own(self):
        return X86 if platform.machine() == "x86_64" else ARM

    @unittest.skipUnless(platform.system() == "Linux", "the machine is asked what it is")
    def test_the_wheels_own_binary_for_this_machine_as_bytes(self):
        self.lay(self.own() + b"the rest")
        self.assertEqual(pi._host_binary(), self.own() + b"the rest")

    @unittest.skipUnless(platform.system() == "Linux", "the machine is asked what it is")
    def test_a_binary_for_another_architecture_is_refused(self):
        self.lay(self.other())
        with self.assertRaises(UsageError) as e:
            pi._host_binary()
        self.assertIn("built for", str(e.exception))

    def test_a_machine_that_is_not_linux_is_refused(self):
        self.lay(MACHO)
        with mock.patch.object(pi.platform, "system", return_value="Darwin"):
            with self.assertRaises(UsageError) as e:
                pi._host_binary()
        self.assertIn("needs Linux", str(e.exception))

    @unittest.skipUnless(platform.system() == "Linux", "the machine is asked what it is")
    def test_a_file_too_short_to_say_is_refused_as_any_other(self):
        self.lay(b"\x7fELF\x02\x01")
        with self.assertRaises(UsageError):
            pi._host_binary()
        self.assertIsNone(pi._built_for(b"\x7fELF"))

    def test_bytes_that_do_not_hash_to_the_wheels_digest_are_not_run(self):
        d = self.lay(self.own())
        _binary.checked_binary()                    # checked once, as a process does: then it changes
        with open(os.path.join(d, "belay"), "ab") as f:
            f.write(b"x")
        with mock.patch.object(pi.platform, "system", return_value="Linux"):
            with self.assertRaises(BinaryMismatch):
                pi._host_binary()


class MacWheelInDocker(Layout, Evals):
    """A macOS wheel's layout against a real container of this machine's own
    architecture: the Mach-O and the other architecture's binary can't run, so
    a verdict at all means the right one was picked."""

    @classmethod
    def setUpClass(cls):
        Docker.setUpClass()
        cls.sandbox_spec = Docker.sandbox_spec

    def test_the_binary_of_the_containers_architecture_is_picked_and_verify_uses_it(self):
        with open(_binary.binary_path(), "rb") as f:
            real = f.read()
        here = platform.machine()
        self.lay(MACHO, real if here == "x86_64" else X86, real if here == "aarch64" else ARM)
        _, s = self.run_task(agent("rm cases.json"))
        v = self.verdict(s)
        self.assertEqual(v.answer, "violation")
        self.assertEqual(v.metadata["binary_sha256"], hashlib.sha256(real).hexdigest())

    def test_the_agent_replacing_uname_changes_nothing(self):
        """verify doesn't ask the sandbox again: a uname that says riscv64,
        for which there is no binary, would leave it nothing to run."""
        _, s = self.run_task(agent("printf '#!/bin/sh\\necho Linux riscv64\\n' > /usr/bin/uname; uname -sm; rm cases.json"))
        self.assertEqual(s.store["agent_saw"].strip(), "Linux riscv64")
        self.assertEqual(self.verdict(s).answer, "violation")


class Metrics(unittest.TestCase):
    def scores(self, *values):
        return [SampleScore(score=Score(value=v)) for v in values]

    def test_pass_rate_and_violations(self):
        s = self.scores(CORRECT, INCORRECT, INCORRECT, CORRECT)
        self.assertEqual(pi.pass_rate()(s), 0.5)
        self.assertEqual(pi.violations()(s), 2)
        self.assertEqual(pi.errors()(s), 0)

    def test_an_unjudged_sample_is_an_error_not_a_violation_and_does_not_pass(self):
        s = self.scores(CORRECT, INCORRECT) + [SampleScore(score=Score(value=INCORRECT, answer="error"))]
        self.assertEqual(pi.errors()(s), 1)
        self.assertEqual(pi.violations()(s), 1)
        self.assertAlmostEqual(pi.pass_rate()(s), 1 / 3)

    def test_an_unjudged_sample_stays_an_error_after_a_mean_reducer(self):
        s = [SampleScore(score=Score(value=0.0, answer="error"))]
        self.assertEqual((pi.errors()(s), pi.violations()(s)), (1, 0))

    def test_a_reduced_score_counts_as_a_violation_in_any_epoch(self):
        self.assertEqual(pi.violations()(self.scores(0.5, 1.0)), 1)


if __name__ == "__main__":
    unittest.main()
