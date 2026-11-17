"""belay in an Inspect eval: `pip install "pybelay[inspect]"`.

    from pybelay.inspect import belay_record, belay_verify

    Task(
        ...,
        setup=belay_record({"belay_protect": 2, "protect": [
            {"path": "test.py", "mode": ["no_write"]},
        ]}),
        scorer=[belay_verify(), your_scorer()],
    )

belay_record runs before the agent and belay_verify after it. By default each
runs from inside the sample's sandbox, through Inspect's own sandbox calls. So
it works with any sandbox whose files Inspect can reach, and needs nothing on
the Docker host.

With `belay_record(..., where="host")` belay never enters the sandbox: it reads
the sample's Docker container from this machine (`--docker`), with the container
paused for each reading. That needs a Docker daemon on this machine (not Docker
Desktop's VM) and root for belay itself: the eval runs as root, or its user may
run `timeout` through `sudo -n` without a password, which is as much as being
root (python/README.md says what is run).

Nothing of belay's stays in the sandbox while the agent runs: the binary goes in
for each step and comes out again, and the baseline bundle is kept on the host,
as `belay baseline export` says it must be. The same goes for the spec, so an
agent can't read what is protected.
"""
import atexit
import copy
import errno
import glob
import hashlib
import json
import logging
import os
import platform
import shutil
import struct
import tempfile
import uuid
from typing import Any, Dict, List, Optional, Union

try:
    import anyio
    from inspect_ai.scorer import (CORRECT, INCORRECT, Metric, SampleScore, Score, Scorer, Target, metric, scorer,
                                   value_to_float)
    from inspect_ai.solver import Generate, Solver, TaskState, solver
    from inspect_ai.util import OutputLimitExceededError, SandboxEnvironment, sandbox as inspect_sandbox
    from inspect_ai.util import concurrency as inspect_concurrency
    from inspect_ai.util import subprocess as inspect_subprocess
except ImportError as e:
    raise ImportError('pybelay.inspect needs Inspect: pip install "pybelay[inspect]" (%s)' % e) from None

from . import _parsed, _policy
from ._binary import binary_path, carried_binary, checked_binary, checked_bytes
from ._errors import BelayError, Failed, FormatError, UsageError
from .reward import _NOT_KINDS

__all__ = ["belay_record", "belay_verify", "pass_rate", "violations", "errors"]

_STORE_KEY = "pybelay.inspect"
_ELF_MACHINES = {62: "x86_64", 183: "aarch64"}
_ARCH_NAMES = {"arm64": "aarch64", "amd64": "x86_64"}
_ASSET_NAMES = {"aarch64": "arm64"}

_log = logging.getLogger(__name__)
# Where root's directory for one reading is made. /tmp is root's and sticky, which is
# what belay asks of every directory above its state.
_HOST_TMP = "/tmp"
# How many containers are read at once: a reading hashes every file of its scope. One for
# each CPU this process may use.
_READINGS = max(1, len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count() or 1)
# timeout(1): it ended the command; it, or env(1), could not run it. A command that died
# by a signal is mostly not seen as an exit code: timeout dies the same death itself.
_ENDED, _NOT_RUN = 124, (125, 126, 127)
# The name of that limit among Inspect's.
_SLOT = "pybelay-host"
# Seconds root's timeout gives a command between TERM and KILL.
_KILL_AFTER = 5
# Seconds Inspect's own limit stands behind root's: time for timeout(1) to end its command.
_BEHIND = 15

_bundles: Optional[str] = None
# What belay_record recorded, by the sample run's id, in this process only. The sample's
# store holds a copy for the log; belay_verify judges against this one, so nothing that can
# write the store chooses what belay_verify runs or reads. An entry goes at the sample's
# final scoring; a sample that never gets there leaves its entry, as it leaves its bundle.
_records: Dict[str, Dict[str, Any]] = {}


def _bundle_dir() -> str:
    """On the host. belay_verify removes a sample's bundle at its final scoring;
    this directory goes when the process ends, with any a failed sample left."""
    global _bundles
    if _bundles is None:
        _bundles = tempfile.mkdtemp(prefix="pybelay-inspect-")
        atexit.register(shutil.rmtree, _bundles, ignore_errors=True)
    return _bundles


def _spec_text(protect: Union[str, "os.PathLike[str]", Dict[str, Any]]) -> str:
    """The spec as belay will read it. Which versions are good is belay's to say."""
    if isinstance(protect, dict):
        return json.dumps(protect)
    with open(os.fspath(protect), encoding="utf-8") as f:
        return f.read()


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _built_for(head: bytes) -> Optional[str]:
    """The architecture of an ELF binary, by its header, or None for anything else."""
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None
    return _ELF_MACHINES.get(struct.unpack_from("<H", head, 18)[0], "an unknown architecture")


def _pick_binary(given: Optional[str], system: str, machine: str) -> str:
    """The path of the binary to copy into a sandbox that says it is `system`
    `machine` (PY-I5). A wheel's own binary is the host's; it also carries the
    Linux ones it doesn't have, so Linux containers of either architecture are
    served from any host."""
    machine = _ARCH_NAMES.get(machine, machine)
    asset = _ASSET_NAMES.get(machine, machine)
    get = "Download belay-<version>-linux-%s from belay's release and pass its path as binary=." % asset
    if given is not None:
        built = _built_for(_read(given)[:20])
        if system == "Linux" and built != machine:
            raise UsageError("the binary given as binary= is built for %s, and the sandbox is Linux %s. %s"
                             % (built or "another system", machine, get))
        return given
    own = checked_binary()
    if system != "Linux":
        return own
    built = _built_for(_read(own)[:20])
    if built == machine:
        return own
    carried = carried_binary(asset)
    if carried is not None:
        return carried
    raise UsageError("this wheel's belay binary is built for %s, and the sandbox is Linux %s. %s"
                     % (built or "another system", machine, get))


class _Scratch:
    """A directory in the sandbox holding the binary for one step, removed after."""

    def __init__(self, env: SandboxEnvironment, binary: bytes, spec: str, user: Optional[str], timeout: int):
        self.env, self.binary, self.spec, self.user, self.timeout = env, binary, spec, user, timeout
        self.dir = "/tmp/.belay-" + uuid.uuid4().hex
        self.belay = self.dir + "/belay"
        self.protect = self.dir + "/protect.json"

    async def sh(self, *cmd: str):
        return await self.env.exec(list(cmd), user=self.user, timeout=self.timeout,
                                   env={"TMPDIR": self.dir, "BELAY_STATE_DIR": self.dir + "/state"})

    async def write(self, path: str, contents: Union[str, bytes]) -> None:
        # Older Inspects have no user= here, so it goes only when it was asked for.
        await self.env.write_file(path, contents, **({"user": self.user} if self.user else {}))

    async def __aenter__(self) -> "_Scratch":
        try:
            await self.write(self.belay, self.binary)
            await self.write(self.protect, self.spec)
            r = await self.sh("chmod", "700", self.dir, self.belay)
            if not r.success:
                raise UsageError("belay can't run in this sandbox: chmod failed: %s" % r.stderr.strip())
            r = await self.sh(self.belay, "--version")
            if not r.success:
                raise UsageError("the belay binary doesn't run in this sandbox (exit %d: %s). It must be belay's "
                                 "static Linux build, as released; a local build usually isn't static."
                                 % (r.returncode, r.stderr.strip()[:200]))
        except BaseException:
            # No __aexit__ follows an __aenter__ that did not finish: a refusal, or a
            # sample cancelled this early, would leave the binary in the sandbox.
            await self.__aexit__()
            raise
        self.version = r.stdout.strip()
        return self

    async def __aexit__(self, *exc) -> None:
        # Shielded: a step that was cancelled still takes belay out of the sandbox (PY-I4).
        with anyio.move_on_after(60, shield=True):
            await self.sh("rm", "-rf", self.dir)

    async def run(self, *args: str) -> List[dict]:
        r = await self.sh(self.belay, *args)
        return _parsed(r.stdout.encode("utf-8", "surrogateescape"), r.returncode, r.stderr)[0]


async def _sandbox_platform(env: SandboxEnvironment, user: Optional[str], timeout: int):
    u = await env.exec(["uname", "-sm"], user=user, timeout=timeout)
    if not u.success:
        raise UsageError("belay can't run in this sandbox: uname failed: %s" % u.stderr.strip())
    system, _, machine = u.stdout.strip().partition(" ")
    return system, machine


def _cancel_pending() -> bool:
    """A cancellation asyncio itself asked of this task (task.cancel(), wait_for): one
    that anyio's checkpoint does not raise again."""
    try:
        import asyncio
        task = asyncio.current_task()
    except RuntimeError:
        return False
    return task is not None and bool(getattr(task, "cancelling", lambda: 0)())


class _Host:
    """belay on this machine, reading a paused container. Nothing goes into the sandbox.

    One reading has a directory of root's own: a copy of the binary, the spec and belay's
    state, removed afterwards. Every command of root's runs under timeout(1): a process
    sudo started is root's, the eval's user cannot signal it, so root ends it itself and
    Inspect's own limit only stands behind that."""

    def __init__(self, container: str, binary: bytes, spec: str, timeout: int):
        self.container, self.binary, self.spec, self.timeout = container, binary, spec, timeout
        # belay refuses to read a container's layers unless it is root.
        self.root = [] if os.geteuid() == 0 else ["sudo", "-n", "--"]
        # The name is made here, not read back from a tool: it is known before anything is
        # asked of root, so close() can remove it whatever became of the request.
        self.priv = os.path.join(_HOST_TMP, "pybelay-host." + uuid.uuid4().hex)
        self.belay = self.priv + "/belay"
        self.protect = self.priv + "/protect.json"
        self.made = False
        self.cut = False
        self.version = ""

    async def _as_root(self, cmd: List[str], input: Union[str, bytes, None] = None, queue: bool = True,
                       what: Optional[str] = None, limit: Optional[int] = None, shielded: bool = False):
        what, limit = what or cmd[0], self.timeout if limit is None else limit
        argv = self.root + ["timeout", "-k", str(_KILL_AFTER), str(limit)] + cmd
        try:
            r = await inspect_subprocess(argv, input=input, timeout=limit + _BEHIND, concurrency=queue)
        except FileNotFoundError as e:
            raise UsageError('where="host" needs `%s` on this machine (%s)' % (argv[0], e)) from None
        except PermissionError as e:
            if e.errno != errno.EPERM:
                raise
            # Inspect tried to stop root's process and may not. A cancellation goes on as
            # one; root's own timeout ends the process.
            await anyio.lowlevel.checkpoint()
            # Under a shield the task still counts as being cancelled, and is not to be.
            if _cancel_pending() and not shielded:
                raise anyio.get_cancelled_exc_class()() from None
            raise TimeoutError("%s, run as root, did not end within %d s and cannot be stopped from here"
                               % (what, limit + _BEHIND)) from None
        signal = -r.returncode if r.returncode < 0 else r.returncode - 128 if r.returncode > 128 else 0
        if r.returncode == _ENDED or signal in (9, 15):
            how = "signal %d" % signal if signal else "exit %d" % r.returncode
            raise TimeoutError("%s did not finish within %d s, or was killed (%s)" % (what, limit, how))
        if signal:
            raise Failed("%s was ended by signal %d" % (what, signal), None, r.stderr)
        said = [x for x in r.stderr.splitlines() if x.strip()]
        if self.root and r.returncode == 1 and not r.stdout and said and all(x.startswith("sudo:") for x in said):
            raise UsageError("reading a container from this machine needs root for belay, and `sudo -n` was "
                             "refused (%s). Run the eval as root, or let its user run `timeout` through sudo "
                             "without a password." % r.stderr.strip()[:160])
        if r.returncode in _NOT_RUN:
            raise UsageError("%s could not be run as root (exit %d: %s)"
                             % (what, r.returncode, r.stderr.strip()[:200]))
        return r

    async def start(self) -> "_Host":
        # Until mkdir says otherwise: a request that was cut short may have been carried out.
        self.made = True
        try:
            r = await self._as_root(["mkdir", "-m", "700", "--", self.priv])
        except UsageError:
            self.made = False
            raise
        if not r.success:
            self.made = False
            raise UsageError("root's directory for this reading could not be made: %s" % r.stderr.strip()[:200])
        # The bytes that were checked are the bytes root runs, and no path of the eval
        # user's is run as root.
        for path, mode, data in ((self.belay, "700", self.binary), (self.protect, "600", self.spec)):
            r = await self._as_root(["install", "-m", mode, "/dev/stdin", path], input=data)
            if not r.success:
                raise UsageError("root's directory for this reading could not be filled: %s" % r.stderr.strip()[:200])
        r = await self._as_root([self.belay, "--version"], what="belay")
        if not r.success:
            raise UsageError("the belay binary doesn't run on this machine (exit %d: %s)"
                             % (r.returncode, r.stderr.strip()[:200]))
        self.version = r.stdout.strip()
        return self

    async def _unpause(self, sure: bool) -> Optional[str]:
        """Sets the container running again, whatever is going on around it. None, or
        why it is not. `sure` is False when the pause itself was cut short."""
        why: Optional[str] = ""
        late: Optional[BaseException] = None
        with anyio.CancelScope(shield=True):
            for again in (False, True):
                try:
                    r = await inspect_subprocess(["docker", "unpause", self.container],
                                                 timeout=min(self.timeout, 60), concurrency=False)
                    if r.success:
                        why = None
                        break
                    if "is not paused" in r.stderr:
                        # Nothing to undo, unless the pause was cut short and the daemon
                        # has yet to act on it: asked once more, a moment later.
                        if sure or again:
                            why = None
                            break
                        await anyio.sleep(1)
                        continue
                    why = r.stderr.strip()[:200]
                except Exception as e:
                    why = str(e) or type(e).__name__
                except BaseException as e:
                    # A cancellation no shield holds off (asyncio's own): the container
                    # first, and then it goes on.
                    late, why = late or e, type(e).__name__
        left = None if why is None else (
            "the container %s %s paused: `docker unpause` failed twice (%s). Set it running by hand: "
            "docker unpause %s" % (self.container, "is still" if sure else "may still be", why, self.container))
        if late is not None:
            if left:
                _log.warning("pybelay: %s", left)
            raise late
        return left

    async def run(self, *args: str) -> List[dict]:
        """One belay command with the container paused for it, and running again after,
        whatever became of the command."""
        env = ["BELAY_STATE_DIR=" + self.priv + "/state", "TMPDIR=" + self.priv]
        if os.environ.get("DOCKER_HOST"):
            # sudo resets the environment, and root's belay asks the same daemon.
            env.append("DOCKER_HOST=" + os.environ["DOCKER_HOST"])
        cmd = ["env"] + env + [self.belay] + list(args)
        # Waited for before the pause, so that a paused container never waits in a queue:
        # none of the three commands below queues again.
        async with inspect_concurrency(_SLOT, _READINGS):
            asked = sure = False
            try:
                asked = True
                try:
                    p = await inspect_subprocess(["docker", "pause", self.container], timeout=self.timeout,
                                                 concurrency=False)
                except FileNotFoundError as e:
                    asked = False
                    raise UsageError('where="host" needs the `docker` command on this machine (%s)' % e) from None
                if not p.success:
                    asked = False       # Docker said no: nothing of ours to undo
                    raise UsageError("docker pause %s failed: %s" % (self.container, p.stderr.strip()[:200]))
                sure = True
                self.cut = True         # until belay has ended, by itself or by root's timeout
                r = await self._as_root(cmd, queue=False, what="belay")
                self.cut = False
                # What belay refuses is raised here, so that it is said even if the
                # container then cannot be set running.
                lines = _parsed(r.stdout.encode("utf-8", "surrogateescape"), r.returncode, r.stderr)[0]
            except BaseException as e:
                left = await self._unpause(sure) if asked else None
                if left:
                    both = "%s. And %s" % (str(e) or type(e).__name__, left)
                    if isinstance(e, BelayError):       # what belay said, as the kind of error it was
                        raise type(e)(both, e.exit_code, e.stderr) from e
                    if isinstance(e, Exception):
                        raise (TimeoutError if isinstance(e, TimeoutError) else UsageError)(both) from e
                    _log.warning("pybelay: %s", left)     # a cancellation stays one
                raise
            left = await self._unpause(True)
            if left:
                last = (r.stdout.strip().splitlines() or [""])[-1][:300]
                raise UsageError("belay finished its reading (exit %d, last line %s), but %s"
                                 % (r.returncode, last or "none", left))
        return lines

    async def close(self) -> None:
        """Removes root's directory, under a shield. A reading that was cancelled may still
        be writing there, since root's belay cannot be stopped from here: it ends once its
        files are gone, so the removal is tried three times. One that had not yet made its
        state makes the directory again, so after such a reading it is all done once more,
        two seconds later. What is left then is said."""
        if not self.made:
            return
        left = ""
        with anyio.CancelScope(shield=True):
            for late in ((False, True) if self.cut else (False,)):
                if late:
                    await anyio.sleep(2)
                for last in (False, False, True):
                    try:
                        r = await self._as_root(["rm", "-rf", "--", self.priv], queue=False,
                                                limit=min(self.timeout, 60), shielded=True)
                        left = "" if r.success else r.stderr.strip()[:200] or "exit %d" % r.returncode
                    except (BelayError, OSError) as e:
                        left = str(e) or type(e).__name__
                    if not left or last:
                        break
                    await anyio.sleep(1)
        if left:
            _log.warning("pybelay: root's directory %s could not be removed (%s). It holds belay's state for "
                         "one reading; remove it by hand.", self.priv, left)


async def _container(env: SandboxEnvironment) -> str:
    """The Docker container behind a sandbox, by Inspect's own account of it."""
    try:
        conn = await env.connection()
    except (NotImplementedError, ConnectionError) as e:
        raise UsageError('where="host" needs a Docker sandbox, and this one gives no container (%s)' % e) from None
    name = getattr(conn, "container", None)
    if getattr(conn, "type", None) != "docker" or not name:
        raise UsageError('where="host" reads a Docker container from this machine, and this sandbox is %r. '
                         'Use where="sandbox".' % getattr(conn, "type", None))
    return name


def _host_binary() -> bytes:
    """The belay that runs on this machine, as bytes: the wheel's own, checked as it is
    read (PY-D5). It reads the container, whatever is inside it."""
    if platform.system() != "Linux":
        raise UsageError('where="host" needs Linux with a local Docker daemon: belay reads the container\'s '
                         "layers from this machine, and Docker Desktop keeps them in its own VM.")
    data = checked_bytes()
    built = _built_for(data[:20])
    here = _ARCH_NAMES.get(platform.machine(), platform.machine())
    if built != here:
        raise UsageError("this wheel's belay binary is built for %s, and this machine is Linux %s"
                         % (built or "another system", here))
    return data


def _env(name: Optional[str]) -> SandboxEnvironment:
    try:
        return inspect_sandbox(name)
    except ProcessLookupError as e:
        raise UsageError("belay needs a sandbox, and this sample has none: set Task(sandbox=...). (%s)" % e) from None


def _keep(state: TaskState, record: Dict[str, Any]) -> None:
    """The record, for belay_verify (in this process) and for the log (in the store)."""
    _records[state.uuid] = copy.deepcopy(record)
    state.store.set(_STORE_KEY, record)


@solver
def belay_record(protect: Union[str, "os.PathLike[str]", Dict[str, Any]], *, scope: Optional[str] = None,
                 sandbox: Optional[str] = None, user: Optional[str] = None, binary: Optional[str] = None,
                 timeout: int = 300, where: str = "sandbox") -> Solver:
    """Records the sandbox at sample start. Use it as `Task(setup=...)`, which
    runs before the solver even when `--solver` replaces it.

    Args:
        protect: A protect spec, version 2, as a dict or the path of its JSON file.
        scope: The directory to record, in the sandbox. By default its working directory.
        sandbox: The sandbox's name, when a sample has several. By default the default one.
        user: The sandbox user to run as. By default the sandbox's own.
        binary: A static Linux belay on this machine, for a sandbox no binary in the
            wheel suits. By default the wheel's own, or the Linux one it carries
            for the sandbox's architecture. Only copied into a sandbox, never run
            on this machine: with where="host" it is a ValueError.
        timeout: Seconds for each command: in the sandbox, or on this machine with
            where="host" (there root's own `timeout` enforces it).
        where: "sandbox" runs belay inside the sandbox, for the record and for
            belay_verify. "host" runs it on this machine instead and reads the
            sample's Docker container from outside, paused for each reading:
            nothing of belay's enters the sandbox. It needs a Docker daemon on
            this machine and root for belay (the eval as root, or `sudo -n`),
            and runs only the wheel's own binary. When it cannot run, the sample
            fails: belay is never run in the sandbox instead.
    """
    spec = _spec_text(protect)
    if where not in ("sandbox", "host"):
        raise ValueError("where is 'sandbox' or 'host'")
    if where == "host" and not (isinstance(timeout, int) and not isinstance(timeout, bool) and timeout > 0):
        raise ValueError('with where="host", timeout is a whole number of seconds above 0: root\'s own '
                         "`timeout` keeps it")
    if where == "host" and binary is not None:
        raise ValueError('binary= names a binary to copy into a sandbox; where="host" runs only the wheel\'s '
                         "own on this machine")

    async def solve_host(state: TaskState, env: SandboxEnvironment) -> TaskState:
        name = await _container(env)
        data = _host_binary()
        root = scope
        if root is None:
            r = await env.exec(["pwd"], user=user, timeout=timeout)
            if not r.success:
                raise UsageError("the sandbox's working directory could not be read: %s" % r.stderr.strip())
            root = r.stdout.strip()
        h = _Host(name, data, spec, timeout)
        kept = os.path.join(_bundle_dir(), uuid.uuid4().hex)
        try:
            await h.start()
            lines = await h.run("baseline", "export", "--docker", h.container, "--scope", root, "--out", kept,
                                "--protect", h.protect, "--json")
            if len(lines) != 1 or "sha256" not in lines[0]:
                raise FormatError("baseline export printed %r" % (lines,))
        except BaseException:
            for left in [kept] + glob.glob(glob.escape(kept) + ".tmp-*"):
                try:
                    os.unlink(left)
                except OSError:
                    pass
            raise
        finally:
            await h.close()
        _keep(state, {
            "scope": root, "sandbox": sandbox, "user": user, "binary": binary_path(), "timeout": timeout,
            "spec": spec, "bundle": kept, "baseline_sha256": lines[0]["sha256"], "version": h.version,
            "binary_sha256": hashlib.sha256(data).hexdigest(),
            "baseline_integrity": lines[0].get("baseline_integrity", []),
            "where": "host", "container": h.container,
        })
        return state

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        env = _env(sandbox)
        if where == "host":
            return await solve_host(state, env)
        path = _pick_binary(binary, *await _sandbox_platform(env, user, timeout))
        data = _read(path)
        async with _Scratch(env, data, spec, user, timeout) as s:
            root = scope
            if root is None:
                root = (await s.sh("pwd")).stdout.strip()
            out = s.dir + "/bundle"
            lines = await s.run("baseline", "export", "--scope", root, "--out", out,
                                "--protect", s.protect, "--json")
            if len(lines) != 1 or "sha256" not in lines[0]:
                raise FormatError("baseline export printed %r" % (lines,))
            try:
                bundle = await env.read_file(out, text=False)
            except OutputLimitExceededError:
                raise UsageError("this scope's baseline bundle is larger than Inspect will read from a sandbox. "
                                 "Narrow scope=, or raise INSPECT_SANDBOX_MAX_READ_FILE_SIZE.") from None
            sha = lines[0]["sha256"]
            if hashlib.sha256(bundle).hexdigest() != sha:
                raise FormatError("the bundle read from the sandbox doesn't hash to what belay printed")
            kept = os.path.join(_bundle_dir(), uuid.uuid4().hex)
            with open(kept, "wb") as f:
                f.write(bundle)
            _keep(state, {
                "scope": root, "sandbox": sandbox, "user": user, "binary": path, "timeout": timeout,
                "spec": spec, "bundle": kept, "baseline_sha256": sha, "version": s.version,
                "binary_sha256": hashlib.sha256(data).hexdigest(),
                "baseline_integrity": lines[0].get("baseline_integrity", []),
                "where": "sandbox",
            })
        return state

    return solve


# Values arrive as they were scored, or as floats when an epoch reducer ran first.
_to_float = value_to_float()


@metric
def pass_rate() -> Metric:
    """The share of samples with no violation."""
    def compute(scores: List[SampleScore]) -> float:
        return sum(_to_float(s.score.value) for s in scores) / len(scores) if scores else 0.0
    return compute


def _unjudged(s: SampleScore) -> bool:
    return s.score.answer == "error"


@metric
def violations() -> Metric:
    """How many samples had a violation."""
    def compute(scores: List[SampleScore]) -> int:
        return sum(1 for s in scores if _to_float(s.score.value) < 1.0 and not _unjudged(s))
    return compute


@metric
def errors() -> Metric:
    """How many samples belay could not judge. They don't pass, and aren't violations."""
    def compute(scores: List[SampleScore]) -> int:
        return sum(1 for s in scores if _unjudged(s))
    return compute


def _score(recorded: Dict[str, Any], lines: List[dict], version: str) -> Score:
    p = _policy(lines)
    broken = [f.text for f in p.flags if f.level == "violation"]
    kinds = {k: v for k, v in p.trailer.items() if k not in _NOT_KINDS and v}
    note = "%d violation(s), %d signal(s)" % (p.violations, p.signals)
    return Score(
        value=INCORRECT if p.violations else CORRECT,
        answer="violation" if p.violations else "pass",
        explanation="; ".join(broken) if broken else note,
        metadata={"violations": p.violations, "signals": p.signals, "flags": kinds, "policy": p.lines(),
                  "scope": recorded["scope"], "baseline_sha256": recorded["baseline_sha256"],
                  "baseline_integrity": recorded["baseline_integrity"],
                  "belay_version": version, "binary_sha256": recorded["binary_sha256"],
                  "where": recorded.get("where", "sandbox"), "error": None})


@scorer(metrics=[pass_rate(), violations(), errors()])
def belay_verify(*, on_error: str = "fail_closed", after_scorers: bool = False) -> Scorer:
    """Judges the sandbox against what belay_record recorded, with the same spec.

    The value is CORRECT with the answer "pass", or INCORRECT with the answer
    "violation": Inspect's metrics and epoch reducers read those two, and any
    other text as 0. The policy's flags are in the score's metadata.

    Put it first in the Task's scorers: scorers run in order, and one that runs
    tests can change what belay is here to judge. It refuses to run after one.

    Args:
        on_error: "fail_closed" scores a run belay could not judge as INCORRECT,
            with the answer "error", so the eval's other scorers still run. It
            counts in the errors metric, not in violations.
            "raise" fails the sample instead.
        after_scorers: True if the scorers before this one are known to leave
            the sandbox alone.
    """
    if on_error not in ("fail_closed", "raise"):
        raise ValueError("on_error is 'fail_closed' or 'raise'")

    async def score(state: TaskState, target: Target) -> Score:
        stored = state.store.get(_STORE_KEY)
        if stored is None:
            raise UsageError("belay_verify has nothing to judge against: add setup=belay_record(...) to the Task.")
        if state.scores and not after_scorers:
            raise UsageError("belay_verify ran after %s. Scorers run in order and can change the sandbox, which "
                             "can hide a change or invent one: put belay_verify() first in the Task's scorers, "
                             "or pass after_scorers=True if they leave the sandbox alone." % sorted(state.scores))
        # What belay_record kept in this process decides everything run and read here. What
        # the store says changes nothing, whoever wrote it: a tool, or Inspect restoring it.
        recorded = _records.get(state.uuid)
        shown = recorded if recorded is not None else stored if isinstance(stored, dict) else {}
        try:
            if recorded is None:
                raise UsageError("belay_verify has no record of this sample in this process: belay_record ran "
                                 "in another one, or the sample was already scored for the last time. The "
                                 "sample's store is not judged against.")
            env = _env(recorded["sandbox"])
            if recorded["where"] == "host":
                # What runs as root here is the wheel's own binary, never a path the
                # sample's store names.
                data = _host_binary()
                if hashlib.sha256(data).hexdigest() != recorded["binary_sha256"]:
                    raise UsageError("the belay binary changed between belay_record and belay_verify")
                # The container belay_record read, by the name Inspect gives it now:
                # a sandbox that was replaced is not the one recorded.
                name = await _container(env)
                if name != recorded["container"]:
                    raise UsageError("the sandbox's container is not the one belay_record read")
                h = _Host(name, data, recorded["spec"], recorded["timeout"])
                try:
                    await h.start()
                    lines = await h.run("verify", "--docker", h.container, "--scope", recorded["scope"],
                                        "--baseline", recorded["bundle"],
                                        "--baseline-sha256", recorded["baseline_sha256"], "--protect", h.protect)
                finally:
                    await h.close()
                return _score(recorded, lines, h.version)
            # The binary belay_record chose: the sandbox isn't asked again, since the
            # agent has had it since.
            data = _read(recorded["binary"])
            if hashlib.sha256(data).hexdigest() != recorded["binary_sha256"]:
                raise UsageError("the belay binary changed between belay_record and belay_verify")
            with open(recorded["bundle"], "rb") as f:
                bundle = f.read()
            async with _Scratch(env, data, recorded["spec"], recorded["user"], recorded["timeout"]) as s:
                out = s.dir + "/bundle"
                await s.write(out, bundle)
                lines = await s.run("verify", "--scope", recorded["scope"], "--baseline", out,
                                    "--baseline-sha256", recorded["baseline_sha256"], "--protect", s.protect)
                return _score(recorded, lines, s.version)
        except (BelayError, OSError, TimeoutError, RuntimeError, ValueError, OutputLimitExceededError) as e:
            if on_error == "raise":
                raise
            return Score(value=INCORRECT, answer="error", explanation="belay could not judge this run: %s" % e,
                         metadata={"violations": None, "signals": None, "flags": None, "policy": [],
                                   "scope": shown.get("scope"), "baseline_sha256": shown.get("baseline_sha256"),
                                   "where": shown.get("where", "sandbox"),
                                   "error": {"type": type(e).__name__, "message": str(e)}})
        finally:
            # Inspect's score() can run the scorers before the end too, and
            # they will need it again: only the final scoring is the last.
            if state.completed and recorded is not None:
                _records.pop(state.uuid, None)
                try:
                    os.unlink(recorded["bundle"])
                except OSError:
                    pass

    return score
