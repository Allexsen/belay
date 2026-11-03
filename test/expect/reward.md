# Pin: the reward helper's contract

**What this is.** What `pybelay.reward` does to an environment's reward, and what it puts in the
rollout's record (decision 187: "any violation zeroes the reward; signals go into the rollout's
metadata, never into the reward by default"). It is framework-neutral: the verifiers and OpenEnv
adapters are thin wrappers over it, each pinned with its framework's version once that framework's
hooks have been checked against the framework itself (decision 184), and none of them changes a row
below. Written by hand; *proposed 2026-11-03, awaiting the author's OK*.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## The guard

`pybelay.reward.Guard(scope, *, workdir, protect=None, docker=None, violation_reward=0.0,
on_error="fail_closed")`: one per episode.

| id | rule |
|---|---|
| RW-1 | `Guard.reset()`, at the episode's reset: `baseline_export(scope, <a new file in workdir>, protect=protect, docker=docker)`. The bundle's path and digest stay in the guard, in the orchestrator's process: never in the sandbox. `workdir` must not lie inside the scope (the CLI refuses it: B-R4). |
| RW-2 | `Guard.judge(reward)`, at the episode's end: `verify(scope, bundle, digest, protect=protect, docker=docker)`; returns `Judgement(reward, metadata)`. Called before `reset`: `UsageError`, nothing run. |
| RW-3 | **The reward rule.** When the policy has one or more violations (trailer `violations` > 0), the reward returned is `reward * violation_reward`: `0.0` by default. Otherwise it is `reward`, unchanged. Signals never change it: there is no signal term, and no argument adds one (an env author who wants one computes it from the metadata). |
| RW-4 | **The metadata.** `{"belay": {"violations": int, "signals": int, "flags": {<kind>: int}, "policy": [<each policy.v1 line as a JSON object, header first, trailer last>], "baseline_sha256": str, "zeroed": bool, "error": null}}`: `flags` has every kind of policy.v1's flag table, 0 included, in the table's order; `zeroed` says whether RW-3 changed the reward. Plain JSON types only, so any framework can store it. |
| RW-5 | **When belay cannot judge** (`Refused`, `Failed`, `FormatError`, `BinaryMismatch` from `verify`): with `on_error="fail_closed"` (the default) the reward returned is `reward * violation_reward`, and the metadata has `zeroed` `true`, `violations`, `signals` and `flags` `null`, `policy` `[]` and `error` `{"type": <the exception's class name>, "exit_code": int or null, "stderr": str}`: never silent, never a pass. With `on_error="raise"` the exception propagates. A failed `reset` always raises: an episode with no baseline cannot be judged at all. |
| RW-6 | The guard deletes its bundle after `judge` returns, or when the episode is dropped (`Guard.close()`, or the guard used as a context manager). |
| RW-7 | A guard is one episode: `reset` again after `judge` starts a new one with a new bundle; a second `judge` without a new `reset` is a `UsageError`. |
