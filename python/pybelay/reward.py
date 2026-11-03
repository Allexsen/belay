"""The reward helper (test/expect/reward.md): one Guard per episode. A
violation multiplies the reward by `violation_reward` (0.0 by default);
signals never change it; the whole policy goes into the rollout's metadata.
Framework-neutral: the verifiers and OpenEnv adapters wrap it."""
import os
import tempfile
from typing import Any, Dict, NamedTuple, Optional

from . import baseline_export, verify
from ._errors import BelayError, UsageError

# policy.v1's flag table, in its order (RW-4: every kind, 0 included); read
# from the policy's own trailer, which names one count per kind in that order.
_NOT_KINDS = {"belay_policy_end", "violations", "signals", "unknown", "packages_outside_scope",
              "packages_no_hash", "provisional", "before_sha256", "after_sha256"}


class Judgement(NamedTuple):
    reward: float
    metadata: Dict[str, Any]


class Guard:
    def __init__(self, scope, *, workdir, protect=None, docker: Optional[str] = None,
                 violation_reward: float = 0.0, on_error: str = "fail_closed"):
        if on_error not in ("fail_closed", "raise"):
            raise ValueError("on_error is 'fail_closed' or 'raise'")
        self.scope, self.workdir, self.protect, self.docker = scope, workdir, protect, docker
        self.violation_reward, self.on_error = violation_reward, on_error
        self._bundle: Optional[str] = None
        self._sha: Optional[str] = None

    # RW-1
    def reset(self) -> None:
        self.close()
        fd, path = tempfile.mkstemp(prefix="belay-bundle-", dir=os.fspath(self.workdir))
        os.close(fd)
        os.unlink(path)                     # export writes it whole, or not at all
        b = baseline_export(self.scope, path, protect=self.protect, docker=self.docker)   # raises: RW-5
        self._bundle, self._sha = b.bundle if os.path.isabs(b.bundle) else path, b.sha256

    # RW-2..RW-5
    def judge(self, reward: float) -> Judgement:
        if self._bundle is None:
            raise UsageError("judge before reset: no baseline to judge against")   # RW-2, RW-7
        bundle, sha = self._bundle, self._sha
        try:
            p = verify(self.scope, bundle, sha, protect=self.protect, docker=self.docker)
        except BelayError as e:
            if self.on_error == "raise":
                raise
            return Judgement(reward * self.violation_reward, {"belay": {
                "violations": None, "signals": None, "flags": None, "policy": [], "baseline_sha256": sha,
                "zeroed": True, "error": {"type": type(e).__name__, "exit_code": e.exit_code, "stderr": e.stderr}}})
        finally:
            self.close()                    # RW-6
        kinds = {k: v for k, v in p.trailer.items() if k not in _NOT_KINDS}
        zeroed = p.violations > 0
        return Judgement(reward * self.violation_reward if zeroed else reward, {"belay": {
            "violations": p.violations, "signals": p.signals, "flags": kinds, "policy": p.lines(),
            "baseline_sha256": sha, "zeroed": zeroed, "error": None}})

    # RW-6
    def close(self) -> None:
        if self._bundle is not None:
            try:
                os.unlink(self._bundle)
            except OSError:
                pass
        self._bundle = self._sha = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
