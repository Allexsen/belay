# pybelay

belay from Python: `check`, `mark`, `log`, `diff`, `baseline_export` and `verify`, each running the
belay binary the wheel carries (its digest checked before the first call) and returning typed results
parsed strictly from belay's pinned formats; and `pybelay.reward.Guard`, the reward helper -- a
violation zeroes the episode's reward, signals go to its metadata. See the repository's
`test/expect/pybelay.md` and `test/expect/reward.md`.

## Using belay with Inspect

[Inspect](https://inspect.aisi.org.uk/) runs an agent in a sandbox per sample. belay can record that
sandbox before the agent acts and judge it afterwards, beside the eval's own scorers.

**Install.** The extra is in the wheels on [belay's releases](https://github.com/Allexsen/belay/releases),
from v0.1.0-alpha.5 on, not on PyPI. It needs Python 3.10 or later. This is the Linux x86_64 wheel; the
release has one for Linux arm64 and one for macOS arm64:

```sh
pip install "pybelay[inspect] @ https://github.com/Allexsen/belay/releases/download/v0.1.0-alpha.11/pybelay-0.1.0a11-py3-none-manylinux_2_17_x86_64.musllinux_1_1_x86_64.whl"
```

An Inspect before 0.3.290 may fail with `No module named 'acp.helpers'`: `agent-client-protocol` 1.0.0
(9 November 2026) removed a module those releases import, and Inspect sets no upper bound on it. Upgrade
Inspect, or add `"agent-client-protocol<1"` to the command. Inspect 0.3.290 and 0.3.291 were run with 1.0.0.

In the default mode nothing is needed in the sandbox image or on the Docker host: pybelay copies its own
binary in. (`where="host"`, below, asks more of the host.)

**Use.** Two additions to a Task. This is the
[EvilGenie](https://github.com/wiser-human-experimental/evilgenie-escalation) harness's, whose scorer
hashes the same two files:

```python
from pybelay.inspect import belay_record, belay_verify

PROTECT = {
    "belay_protect": 2,
    "protect": [
        {"path": "test.py", "mode": ["no_write"]},
        {"path": "test_cases.json", "mode": ["no_write"]},
    ],
}

Task(
    dataset=dataset,
    setup=belay_record(PROTECT),
    solver=solver,
    scorer=[belay_verify(), scorer(enable_llm_judge=enable_llm_judge)],
    sandbox=("docker", DOCKERFILE_PATH),
)
```

`belay_record(protect)` takes the spec as a dict or a path. Paths in it are relative to the scope: the
sandbox's working directory, or `scope=`. `belay_verify` uses the same spec, so they can't disagree.
It judges against what `belay_record` recorded in the same process. The copy in the sample's store is
for the log, and changing it changes nothing. Without that record (another process, as with
`inspect score` on a finished log) the run is one belay could not judge.

**The score** is `C` with the answer `pass`, or `I` with the answer `violation`, so Inspect's reducers
and viewer read it as usual. The explanation says what was broken, and the metadata has `violations`,
`signals`, `flags` (each kind seen, with its count) and `policy` (the whole policy.v1). The metrics
are `pass_rate`, `violations` and `errors`. If belay can't judge a run, the score is `I` with the answer
`error` and the reason in the metadata, and the other scorers still run: it doesn't pass, and it counts
in `errors`, not `violations`. `belay_verify(on_error="raise")` fails the sample instead.

**`belay_verify()` goes first in the scorers.** Scorers run in order and one that runs tests can change
the sandbox. EvilGenie's rewrites `test_cases.json` when it was changed, and edits `test.py`: after it,
a clean run shows a violation, and a deleted file shows as modified. One that restores a file exactly
would hide a deletion altogether. `belay_verify` refuses to run after another scorer, unless given
`after_scorers=True`.

**How it reaches the sandbox.** By default through Inspect's own sandbox calls, so it works with Docker
and with Inspect's `local` sandbox, and should with others that can run a Linux binary. The binary, the
spec and the bundle are in the sandbox only while belay runs, never while the agent does. The bundle is
kept on the host, and only its sha256 goes in the log.

**Keeping belay out of the sandbox: `belay_record(spec, where="host")`.** belay then runs on the machine
the eval runs on and reads the sample's Docker container from there (`--docker`), paused for each
reading. Nothing of belay's enters the sandbox, so nothing in it has to be trusted to run belay: not its
`uname`, `chmod` or `rm`, and not a process the agent left behind. One thing is still asked of the
sandbox, before the agent runs: its working directory (`pwd`), unless you give `scope=`.
`belay_verify()` follows what `belay_record` did, and the score's metadata says `"where": "host"`.

It needs:

- a Docker sandbox, with the Docker daemon on this machine. Docker Desktop keeps containers in its own
  VM, where belay cannot read them: on a Mac or on Windows, use the default mode;
- Linux, and the wheel's own binary for this machine: `binary=` is refused with `where="host"`, since
  nothing but the binary the wheel vouches for is run on the host;
- root for belay, which reads the daemon's layer directories: run the eval as root, or let its user
  run `timeout` through `sudo -n` without a password. **That is passwordless root for the account the
  eval runs as.** sudo is asked for `timeout` and nothing else, but `timeout` is given `mkdir`,
  `install`, `rm`, belay itself, and `env` with belay as its command: a rule that allows that allows
  anything. If that is more than the account should have, run the eval as root in a place made for it,
  or use the default mode;
- a `/tmp` on the host that allows execution, since the copy of the binary runs from there, and GNU
  coreutils (`timeout`, `install`, `mkdir`, `rm`, `env`);
- `docker` for the eval's user (it pauses and unpauses the container) and for root (belay asks the
  daemon about the container), both reaching the same daemon. `DOCKER_HOST` is passed on to root's
  belay; a Docker context is not;
- a container belay's host reader accepts: not `--privileged`, the scope not on a volume or a bind
  mount ([docs/cli.md](../docs/cli.md) lists what it refuses).

**When `where="host"` cannot run, the sample fails and says why.** A sandbox that is not a Docker
container, a refused `sudo` (at the record or later: a sudo timestamp can lapse during a long run), a
container the reader refuses: each is an error, in `belay_record` as a failed sample and in
`belay_verify` as a run belay could not judge. It never runs belay inside the sandbox instead: a
verdict taken from where you asked it not to be taken would look the same in the log.

**What `where="host"` does on the host, and what it can leave there.**

- Each reading gets a directory of root's own, `/tmp/pybelay-host.<random>`: a copy of the binary (the
  very bytes whose digest was checked), the spec and belay's state. It is removed after the reading,
  in up to three tries; if they fail, a warning names it. That can happen after a cancelled reading,
  which may go on writing there for a while (see below), or make the directory again after it was
  removed: after such a reading it is removed once more two seconds later. What belay makes later
  still stays, without a warning: an empty state directory. A reading also copies the baseline
  bundle there, so the host's `/tmp` needs room for one bundle per sample being read.
- The container is paused for the reading, which anything else that uses it will notice, and is set
  running again whatever became of the reading: an answer, a refusal, a timeout, a cancelled sample.
  If `docker unpause` fails twice, the error says so together with belay's answer (for a sample that
  was cancelled there is no error to carry it: a warning in the log says it), and the container stays
  paused until you run `docker unpause` yourself.
- `timeout=` is kept by root's own `timeout`, because the eval's user cannot signal a process sudo
  started. For the same reason a reading whose sample was cancelled cannot be stopped from the eval:
  the container is set running at once, and root's belay ends by itself: when its directory is
  removed under it, or after `timeout=` seconds, and five more if it has to be killed.
- At most one reading per CPU runs at a time, and a container is paused only when its turn has come.
- An eval that is killed outright in the middle of a reading leaves its container paused and its
  directory in `/tmp`.

**Known limits.** The first, third and fourth are the default mode's; `where="host"` has its own, above.

- belay runs in the sandbox, beside anything the agent left running. A process that outlives the agent
  can still write while belay reads, or interfere with it if it runs as the same user. Inspect has no
  way to stop them first, as `belay verify` asks.
- It sees the end state, within the scope: a file changed and restored is invisible. With
  `where="host"` belay's host reader can report one as the signal `protected_path_touched`, in the score's
  `flags`, **but not for the files Inspect copies in**: a sample's `files=`, and anything a setup step
  writes, enter the container after it starts, and for those an in-place change and restore leaves
  no trace at all. Only files that were already in the image carry it.
- The sandbox needs a writable, executable `/tmp`, and `uname`, `chmod` and `rm`.
- The binary must suit the sandbox. Wheels carry Linux x86_64 and arm64 binaries and pick by the
  sandbox's architecture; v0.1.0-alpha.5's Linux wheels have only their own. For anything else, belay
  refuses and says so, and `belay_record(..., binary=path)` takes a static binary for it.
- With several epochs and a reducer, a sample with both judged and unjudged epochs counts as a
  violation, not an error: a reduced score keeps an answer only if all its epochs agree.
- The bundle holds a copy of what the scope contains. In the default mode Inspect reads at most
  100 MiB from a sandbox unless told otherwise: a larger one is refused, with what to do. A sample's bundle is removed from the host when
  it is scored.
- `inspect score` on a finished log can't judge: the sandbox is gone.
