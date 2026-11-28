# The hook wrapper used in the EvilGenie rerun

[`belay_hook.py`](belay_hook.py) is how belay recorded every tool call in the [rerun of the EvilGenie problems](../RESULTS.md), as it ran there. It calls `belay watch step` before and after each tool call of Claude Code, Codex CLI or Antigravity, and writes what belay printed to a log. It prints nothing to the agent but the reply Antigravity's hooks require (`{"decision": "allow"}`), so belay's lines never reach the model, and it always exits 0, so recording never blocks a tool.

[`codex-hooks.json`](codex-hooks.json) is the Codex CLI hooks file the rerun installed in `$CODEX_HOME/hooks.json`: `PreToolUse` and `PostToolUse` for every tool, and `Stop`.

Python standard library only. It is a benchmark harness's part, published as it ran, not a supported integration.

## How it was run

In each run's container, before the agent started:

    python3 belay_hook.py start

Then the CLI's hooks called it around every tool call (`hook codex pre`, `hook codex post`, `hook codex stop`), and after the agent exited:

    python3 belay_hook.py final

which takes the last step, closes calls left open, and writes `receipt.txt` and `summary.txt`.

`belay_hook.py stream CLI` is a fallback for a CLI whose hooks do not fire: it steps from the CLI's JSON event stream instead, read after the fact, so a step can land after the next command has started. The rerun used the hooks.

Its settings are environment variables: `BELAY` (the binary), `WS` (the directory recorded), `BENCH_OUT` (where the log, receipt and summary go), `BELAY_SESSION`, and `HOOK_STATE` (the file of open call ids). `codex-hooks.json` expects the script at `$OPT/belay_hook.py`.

## What it does not hold against

It runs as the agent's user, in the agent's container. The agent can reach the log, the open-calls file and its lock, and belay's state, as the report's limits say. The rerun recorded careless changes; it does not show that a determined agent could not hide one.
