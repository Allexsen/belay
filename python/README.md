# pybelay

belay from Python: `check`, `mark`, `log`, `diff`, `baseline_export` and `verify`, each running the
belay binary the wheel carries (its digest checked before the first call) and returning typed results
parsed strictly from belay's pinned formats; and `pybelay.reward.Guard`, the reward helper -- a
violation zeroes the episode's reward, signals go to its metadata. See the repository's
`test/expect/pybelay.md` and `test/expect/reward.md`.
