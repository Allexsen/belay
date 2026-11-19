# mark: prefilter on an aging reference point vs the full walk (2026-10-31)

For the Phase 5 proposal (NOTES/phase5-structure.md, "mark"). Spike source: `spike_mark_aging.c`
(scratch measurement, not product code), built against main's objects:
`gcc -std=c11 -O2 -Iinclude -Isrc -o spike spike_mark_aging.c build/{util,schema,capture,diff,interp,platform}/*.o`.

Machine: WSL2, kernel 6.18 (fine-grained ctime), ext4, warm page cache, one process per run, 3 runs
each (they agreed within 5%; the middle one shown).

Trees:
- **Go**: `git clone --depth 1 https://github.com/golang/go` -- 18,027 entries, 16,175 regular
  files, 239 MB.
- **nm100k**: generated node_modules-shaped tree (seed 20261031): 1,948 packages, 109,757 entries,
  100,015 regular files (log-normal sizes, median ~1.3 KB), 529 MB.

| run | Go | nm100k |
|---|---|---|
| `check` (real belay_manifest_write, full hashing) | 0.600 s, 6.2 MiB | 1.251 s, 6.5 MiB |
| `check` with hashing off (hash_max_bytes 0): the pipeline without reading content | 0.100 s, 5.3 MiB | 0.574 s, 6.5 MiB |
| spike `hashall`: load prev + stat walk + hash every file | 0.578 s | 1.057 s |
| spike `prefilter`, nothing changed: load prev + stat walk + hash what the rule needs | **0.080 s** (load 0.058, walk 0.024); hashed 1, trusted 16,174 | **0.408 s** (load 0.30, walk 0.11); hashed 1, trusted 100,014 |
| spike `prefilter`, 1% of files appended to | -- | 0.401 s; hashed 1,001 (1,000 changed + 1 racy) |
| spike peak RSS (prev manifest in a naive hash table) | 20 MiB | 33 MiB |

Estimated `mark` = no-hash check + index load + hashing the changed and racy: Go ~0.16 s vs 0.60 s
full; nm100k ~0.87 s vs 1.25 s full (~0.68 s with a compact index loaded by the lexer alone, at the
audit's 0.99 us/entry). The spike excludes writing the manifest; the no-hash check includes it.

**The racy set.** R = the newest ctime among the previous manifest's validated entries: 1 file on
both trees (fine-grained ctime). Counted from the recorded ctimes, the files sharing R's tick at
coarser granularity, right after the bulk write that created each tree:

| granularity | Go | nm100k |
|---|---|---|
| 1 ns (this kernel) | 1 | 1 |
| 4 ms (jiffy; kernels < 6.13) | 1 | 157 |
| 1 s | 15,013 of 16,175 | 36,537 of 100,015 |
| 2 s (FAT) | 16,159 | 36,537 |

With R from observed ctimes alone, an idle tree never ages out of that: R moves only when a newer
ctime is seen. Against the previous manifest file's own ctime (git's index rule; the manifest is on
the scope's device here, written 158 s / 40 s after the trees), the racy set is **0 at every
granularity** -- and it moves forward with every mark.

## After implementation (Phase 5, same machine and trees, 3 runs each; the middle shown)

**Capture level, no store** (`real_capture.c`: belay_manifest_write with and without `previous`,
against the same estimate's terms):

| | full check | mark, nothing changed | the estimate | mark peak RSS |
|---|---|---|---|---|
| Go | 0.629 s | **0.195 s** | ~0.16 s (+22%) | 7.7 MiB |
| nm100k | 1.286 s | **0.929 s** | ~0.87 s (+7%); ~0.68 s with a lexer-only index (+37%) | 15.6 MiB |

Every regular file was trusted (16,175 and 100,015), none racy. A trusted file is still opened
(inode flags need an fd; the differential test found that skipping the open lost `iflags`), as the
"pipeline without reading content" part of the estimate already assumed. The estimate's memory
(3.5 MiB, "16 B an entry, half full") was wrong: a record needs its stat fields and hash, ~72 B,
plus 4 B an index slot -- 9.4 MiB at 100k (first version, records inside the hash table: 45 MiB).

**The CLI, with its content store** (`real_cli.py`: `belay check|mark --json`, one process each):

| | Go | nm100k |
|---|---|---|
| check, the first (fills the store) | 1.289 s | 4.027 s |
| check, again | 0.93 s | 2.81 s |
| mark, nothing changed | **0.27 s** (3.4x) | **1.04 s** (2.7x) |
| mark, 1% of files appended to | 0.28 s | 1.08 s |

The store makes check costlier (copies of small text files), and mark skips that copy for every
trusted file, so the CLI's gain is larger than the capture level's.

**After the review fixes** (same trees, same script, 2026-10-31 evening; R = the previous walk's
start; the copy decided anew, `store_has` per trusted stored file; a sniff of the first 8,000
bytes for an unclaimed file without a copy):

| | Go | nm100k |
|---|---|---|
| check, again | 0.873 s | 2.846 s |
| mark, nothing changed | **0.215 s** (4.1x) | **1.24 s** (2.3x) |
| mark, 1% of files appended to | 0.219 s | 1.30 s |
| trusted | 16,175 (all) | 100,015 (all) |

`store_has` (one fstatat a stored file) costs ~0.13 s at nm100k: 1.13 s with it replaced by the
previous entry's word, 1.26 s with it (3 runs each). It stays: without it a deleted store object
was recorded as present (review 6c). Before the sniff, the Go tree's 756 small binary files were
read on every mark (15,419 trusted, 0.225 s).
