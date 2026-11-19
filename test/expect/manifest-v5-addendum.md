# Pin addendum: manifest version 5

**What this is.** Rules added to `manifest-v5.md` after it was merged, as that pin provides. Each
row says which row of it is amended. Where a row here and `manifest-v5.md` differ, this file is
right. Rows V5-A1 to V5-A3 were approved by the author on 2026-11-19, before any release wrote v5.

**Changing it.** Append-only: a row is added at the end, in its own PR, with the author's explicit
OK, and no existing row ever changes.

| id | amends | rule | how established |
|---|---|---|---|
| V5-A1 | V5-2 | **One line per root.** The header's `roots` is an int: the number of root lines. Each root is a line of its own, directly after the header and before the first entry: `{"root": <path relative to the scope>, "class": "content" \| "metadata", "found": true \| false}`, sorted bytewise by path, each once; `root_b64` in place of `root` when the path is not UTF-8. A capture of a whole scope has `"roots":0` and no such line. A reader rejects a count that is not the number of root lines, a root line after an entry, and lines out of order. Wherever `manifest-v5.md` says "`roots` not empty" or "non-empty `roots`" (V5-E3, V5-R4) it means a count that is not 0; V5-D4b reads the root lines; V5-D6 compares the two sets of them. | run on the step-2 build: a line of a manifest is at most 65,536 bytes (addendum A2 of v1), and with the roots in the header a scope with 100 homes could not be captured: the builder's count is about 60 homes at 14 roots each |
| V5-A2 | V5-12 | **One line per racy path.** The trailer's `racy` is an int: the number of racy lines. Each is a line of its own after the last entry and before the trailer: `{"racy": <path>}`, sorted bytewise, each once; `racy_b64` when not UTF-8. At most 65,536 of them; past that the capture is a walk, as V5-12 says. A reader rejects a count that is not the number of racy lines and a racy line naming no entry. | the same limit: 65,536 paths cannot be on one line of 65,536 bytes |
| V5-A3 | the key order | The header: v4's keys, then `roots`, `sealed_key`, `basis`, as before. The trailer: v4's, then `not_read`, `meta`, `sealed`, `carried`, `racy`, as before; only the two types change. Every line of a manifest, root and racy lines included, is within v1's line limit. | follows from V5-A1, V5-A2 |
