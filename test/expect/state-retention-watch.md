# Pin: retention of a watch record

**What this is.** What `belay prune` keeps and removes when a scope holds a watch record: the
running record `belay watch` will keep of a directory (one line a step, the full receipt beside
it). It amends `state-retention.md` with exactly the rows below; everything not listed here is as
that pin says. A scope with no watch record is pruned exactly as today.

It is written before `belay watch` exists, from the structure the author approved on 2026-11-10.
Nothing here takes effect until that code does, and a change to that structure changes this pin
first.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## The record

| id | rule |
|---|---|
| WR-1 | A watch record is the directory `watch/` in the scope's state directory. It holds, for each UTC day on which a step was recorded, one ledger file and one receipt file, and the don't-touch list in force as a file named by its sha256. Its format belongs to the state directory, as ST-3 says of a delta: no one outside belay reads it. |
| WR-2 | **The cursor** is the checkpoint the newest readable ledger line names as its end. Every later step diffs against it. |

## Whose checkpoint

| id | rule |
|---|---|
| WR-14 | A checkpoint a `belay watch` step writes is recorded as the watch's in its `meta.json`, as KP-2 records a kept one, and `belay log` shows it. Every other checkpoint is not the watch's: one written by `check`, `mark`, `diff` or `baseline export`, and any written before this rule. |
| WR-15 | `belay prune --watch-only`, beside the limits PR-1 requires, removes a checkpoint only when it is the watch's and outside those limits. A checkpoint that is not the watch's stays whatever its age and whatever the limits, for that run; it is not made kept. The rest of the run is any prune's: PR-4 to PR-11 and WR-3 to WR-9. So what is no checkpoint still goes: a directory under `checkpoints/` with no `meta.json` (a capture that never finished, or a removal a crash cut short), an object no remaining manifest refers to, and PR-11's files. |

## belay prune

| id | amends | rule |
|---|---|---|
| WR-3 | PR-3 | Never removed, whatever the limits: the cursor's checkpoint. This is beside the newest checkpoint, a kept one and `--keep-from`; the cursor is not the newest whenever anything else has captured since. |
| WR-4 | PR-1, PR-2 | A day's ledger file and receipt file are removed together, and only when no checkpoint that day's ledger names remains after the run and the day is not the record's newest. So the limits given for checkpoints (`--keep-days`, `--keep-last`, `--keep-from`, a kept checkpoint) are the limits for the record, and no new option is needed. |
| WR-5 | PR-3 | Never removed: the newest day's two files, and the list file the newest readable ledger line names. A list file no remaining ledger line names is removed. |
| WR-6 | PR-7 | `--dry-run` also says which days a real run would remove and their bytes. `--json` gains `watch_days` (the days, as `YYYY-MM-DD`) and `watch_bytes`. |
| WR-7 | PR-8 | Order: rewrites, checkpoints, the sweep, then the record: for each day a ledger file first and its receipt file after, then list files. A receipt file whose ledger file is gone is read by nothing, so a crash between the two leaves valid state, and running prune again finishes. |
| WR-8 | PR-9 | Prune holds the scope's lock for all of it. A step of `belay watch` waits for the lock up to its deadline and, past it, says in a line that it could not record. Besides prune, one thing in belay removes bytes from a watch record: a step, holding the lock, cuts a torn last line off the newest ledger file. |
| WR-9 | | A record prune cannot read (no ledger line parses) is left whole: nothing under `watch/` is removed, prune says so, and checkpoints are pruned by PR-1 to PR-3 as if there were no record. It is not corrupt state (exit 4): `belay watch` reports such a record itself. |

## The Claude Code plugin

| id | rule |
|---|---|
| WR-10 | Once a day at most, at a Stop, a detached `belay prune --keep-days 7 --watch-only`, as HK-1 does for the dogfood hooks. No `--keep-from` is needed: WR-3 keeps what the next step reads. |
| WR-11 | The plugin prunes only what the watch wrote. Installing it, enabling it and every prune it runs remove no checkpoint the watch did not write: the user's own stay, whatever their age, until the user prunes them. The plugin runs prune in no other form. |
| WR-12 | A failed prune is a line at the next Stop, as HK-2. |

## docs/cli.md

| id | rule |
|---|---|
| WR-13 | DC-1's sentence stands as it is. The state directory's listing gains `watch/`, described in one line, in the PR that adds `belay watch`, so the docs are never ahead of the code. |
