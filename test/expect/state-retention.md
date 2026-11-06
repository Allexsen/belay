# Pin: retention of belay's state

**What this is.** How belay's state directory stops growing without bound: checkpoints stored as deltas,
`belay prune`, garbage collection of the store, `belay mark --keep`, and pruning from the dogfood hooks.
Measured on a real scope, 7,467 checkpoints took 13.35 GiB, 99.9% of each manifest's entries being
identical to the previous one's. The budget: one week of dogfood hooks under 1 GB. Written by hand;
awaits the author's OK.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## Storage

| id | rule |
|---|---|
| ST-1 | The newest checkpoint's manifest is always a whole `manifest.ndjson`, as it is today. |
| ST-2 | When a checkpoint is written, its predecessor becomes `manifest.delta`, a delta against its own predecessor, unless it is a full copy. Every 256th in a chain stays a full copy, so at most 255 deltas lie between a checkpoint and a full copy. |
| ST-3 | A delta rebuilds its manifest byte for byte. Its format belongs to the state directory: no one outside belay reads it. Its first line names the base's id and sha256, and the manifest's sha256 and size. |
| ST-4 | Every rebuild is checked byte for byte against the recorded sha256 before anything reads it, at run time and in tests. A mismatch is corrupt state (exit 4), and nothing partial is used. |
| ST-5 | A delta is written, rebuilt and checked before the whole file it replaces is removed. A crash between the two leaves both, and the whole file is used. |
| ST-6 | Checkpoints already stored as whole files stay so. Nothing is migrated, and both kinds are read. |
| ST-7 | The manifest format is unchanged: manifest-v1 to v4, the baseline bundle, diff.v1 and policy.v1 are untouched. |
| ST-8 | `belay manifest --scope DIR --id N` prints a checkpoint's manifest, rebuilt and checked. Whatever needs a manifest asks it, rather than reading the state directory. |
| ST-9 | Reading a checkpoint at the worst position (255 deltas) stays under twice today's time on a real scope, measured before this merges. If not, the interval in ST-2 becomes smaller. |

## belay prune

| id | rule |
|---|---|
| PR-1 | `belay prune --scope DIR [--keep-days N] [--keep-last N] [--keep-id ID]... [--keep-from ID] [--dry-run] [--json]`. At least one of `--keep-days` and `--keep-last` is required (exit 2). |
| PR-2 | A checkpoint is removed only when it is outside both limits given: older than N days, and not among the last N. |
| PR-3 | Never removed, whatever the limits: the newest checkpoint, a kept one (KP-1), and any from `--keep-from ID` on, which is how a pending diff is protected. |
| PR-4 | A delta that stays and whose base would go is first rewritten, and checked by ST-4, before anything is removed. |
| PR-5 | A removed checkpoint's cached diffs go with it, as does a cached diff from a removed checkpoint held by one that stays. |
| PR-6 | The store is swept in the same run: mark and sweep from every manifest that stays, each rebuilt. An object none refers to is removed, and only such an object. |
| PR-7 | `--dry-run` writes nothing, and says what a real run would remove and free: checkpoints by id, their bytes, the store's objects and bytes. |
| PR-8 | Order: rewrites, then checkpoints (each `meta.json` first, so a half-removed one is no checkpoint), then the sweep. A crash leaves valid state, and running it again finishes. |
| PR-9 | It holds the scope's lock: a capture waits for it. Nothing else in belay deletes from the state directory. |
| PR-10 | A command naming a removed checkpoint is refused, as a checkpoint that never existed is today. |

## Keeping a checkpoint

| id | rule |
|---|---|
| KP-1 | `belay mark --keep` writes a kept checkpoint. A kept checkpoint is never pruned. |
| KP-2 | Kept is recorded in the checkpoint's `meta.json`, and `belay log` shows it. |
| KP-3 | `belay prune --keep-id ID` makes an existing checkpoint kept, for good, so a later prune keeps it too. Under `--dry-run` it records nothing, and the run counts it as kept. |

## The dogfood hooks

| id | rule |
|---|---|
| HK-1 | Once a day at most, at a Stop, a detached `belay prune --keep-days 7 --keep-from ID`, where ID is the first checkpoint of the oldest session that has not ended, so a session's receipt keeps what it reads. |
| HK-2 | A failed prune is recorded as any hook's failure is, and said at the next Stop. |

## docs/cli.md

| id | rule |
|---|---|
| DC-1 | "Nothing in it is deleted by belay." becomes "belay deletes from it only when `belay prune` runs ([test/expect/state-retention.md](../test/expect/state-retention.md)), or when a hook you installed runs it." The store's sentence that follows stays, with "until pruned" added. Changed in the PR that adds prune, so the docs are never ahead of the code. |
