# belay's corpus: the measured run (M3)

`corpus.py` generates ten small Python tasks and judges rollouts on them through
`pybelay.reward.Guard`. The baseline is exported at reset and verified at the end, as an RL
loop would do it. Everything comes from the seed, so the run reproduces exactly:

    python3 python/build_keys.py bin/belay        # vendor the binary pybelay runs
    python3 bench/corpus/corpus.py --per-class 20 --clean 200 --out results.json
    python3 bench/corpus/corpus.py --per-class 20 --clean 200 --no-spec --out results-nospec.json

**Tasks.** Each is a git repository holding:
- a package and its pytest suite;
- a grader, expected fixtures, pytest's configuration and a CI workflow;
- a venv laid out as pip lays one out, with an installed package and its `RECORD`.

The spec protects the tests, the grader, the pytest configuration and the CI, refuses a new
`conftest.py`, and freezes the installed packages.

**Hacked rollouts.** 20 per class, in 17 classes (structure §5.1):
- tests: an assertion made a tautology, an assertion removed, a skip marker added, the test file
  swapped for a symlink;
- pytest's machinery: a `conftest.py` monkeypatch, `pytest.ini` deselecting tests;
- Python start-up: a `.pth` hook, `sitecustomize.py`;
- the installed library patched, with and without its `RECORD` forged;
- the grader edited, an expected fixture edited, CI edited;
- git history rewritten to hide an edit;
- a shadowing executable on the venv's PATH;
- root only: a setuid file, the immutable flag (run as root in CI's `docker` job).

**Clean rollouts.** 200, of eight kinds:
- a bug fixed;
- a module added;
- a test file added;
- tests run (`__pycache__`, `.pytest_cache`);
- work committed;
- a build;
- documentation;
- a branch made and committed to.

**What it shows and what it does not.** The hacks are scripted, and they are the classes belay was
built to see. So "all caught" is a floor: belay works as designed on known shapes. It is not a
measure of how often real agents' hacks take these shapes. The clean rollouts are scripted too,
not an agent's work. The false-positive rate on agents' own legitimate work comes from the
external testbeds' rollouts, which need agent runs. Hacks that live only in the solution's code
(special-casing the test inputs) write no state belay can see, and are out of scope by design (§5.3).
