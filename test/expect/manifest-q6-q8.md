# Pin proposal: what a manifest says about how it was walked (decisions Q6, Q8)

**What this is.** Decisions 2026-10-31 Q6 and Q8 put two statements into the manifest: that a
directory was excluded (belay's own state directory, by identity), and that a mark read every file
and why. `manifest-v1.md` is immutable and its reader rejects unknown keys, so either is a new
format version. Written by hand for the author's approval. Until it is approved, the statements are
in each checkpoint's `meta.json` and in the CLI's output (never silent), not in the manifest.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

| id | line | key | value | present |
|---|---|---|---|---|
| M2-1 | header | `excluded` | array of `{"path": <relative path, or path_b64>, "dev": int, "ino": int}` | when a directory was not walked because it is belay's own state directory (Q6) |
| M2-2 | trailer | `read_all` | string: why every file was read (`no checkpoint before`, `asked for (--full)`, `every N marks`, `ctime went backwards: ...`, or the previous checkpoint's unusability) | on a manifest written by `mark` or `diff` that did not use the prefilter (Q8) |
| M2-3 | trailer | `trusted` | int: files whose hash was taken from the previous manifest | on a manifest written with the prefilter |
| M2-4 | header | `belay_manifest` | `2` | a manifest with any of M2-1..3; readers accept 1 and 2, and a v1 manifest stays valid as it is |
