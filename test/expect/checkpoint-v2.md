# Pin: checkpoint.v2, the checkpoints `check`, `mark`, `diff` and `log` print

**What this is.** checkpoint.v1 (`checkpoint-v1.md`) with the changes below. A checkpoint stored as a delta
(state-retention ST-2) has no manifest file, so CK-5 no longer holds for every checkpoint, and that pin
says a key changed in meaning is a `checkpoint.v2`. Written by hand; awaits the author's OK.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

| id | key | type | rule |
|---|---|---|---|
| C2-1 | every key of checkpoint.v1 | as v1 | As `checkpoint-v1.md` says, except as below. |
| C2-2 | `manifest` | string or null | The manifest's path in belay's state directory, or null for a checkpoint stored as a delta. `manifest_b64` as in CK-5, and absent when `manifest` is null. |
| C2-3 | `stored` | string | `whole` or `delta`. What `check` and `mark` print is always `whole` (ST-1); `log` prints either. |
| C2-4 | `kept` | bool | Whether the checkpoint is kept (KP-1). |
| C2-5 | | | `schema/checkpoint.v2.json` replaces `schema/checkpoint.v1.json`. To read a delta's manifest: `belay manifest` (ST-8). |
| C2-6 | | | pybelay follows in the same release: `Checkpoint.manifest` is `str` or `None`, with `stored` and `kept` added (PY-R1 names the keys). |
