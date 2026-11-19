# Base rates for the walk-consistency design (2026-10-27)

Measured before implementing anything from NOTES/reviews/walk-consistency-design.md.

## Method

- `measure.c` runs belay's unchanged `capture_write` (the code under `belay_manifest_write`)
  through a decorated platform adapter that only observes. Store off; hash limit 64 MiB.
  - Lease probe (Linux): F_SETLEASE F_RDLCK taken and released at once, right after belay opens
    a regular file to hash it, and again at EOF. Nothing is held during the read. EAGAIN means
    some process had the file open for writing, or mapped shared-writable, at that instant.
    Controls: a file held open for write and one with only a shared mapping were refused, an
    idle file wasn't; a Windows process holding a WSL file open over 9p was refused too.
  - Racy rule (review mechanism 2): in visit order, an entry with ctime >= the newest ctime
    seen so far on its device; once per inode; bytes a re-hash would cost.
  - Clock: realtime minus monotonic per run.
- Ground truth (torn reads): npm content is deterministic per path (lockfile); the make build is
  deterministic (two quiet clean builds: 0 of 736 files differ). A clean hash (sha256, none of
  unstable/raced/unreadable) that differs from the final quiet tree's hash is checked against the
  sha256 of the final file's first `size` bytes: equal = a real intermediate state of a file
  being written front to back; not equal = torn.
- Cadence: dogfood every 10 s; workloads every 2 s (more samples; per-run rates unaffected).
- Environment: WSL2, Linux 6.18, ext4. CI: ubuntu-24.04 (6.17) and ubuntu-22.04 (6.8).

## 1-2. Base rates

| workload | runs | entries | files hashed | raced | unstable | vanished | runs with any flag | median check |
|---|---|---|---|---|---|---|---|---|
| dogfood: this repo, 40 min, this measurement session | 238 | 354,264 | 263,359 | 1 | 1 | 0 | 1 (0.4%) | 0.09 s |
| make clean; check; check-san, looped in a clone (25 min) | 760 | 753,841 | 551,440 | 90 | 102 | 28 | 68 (8.9%) | 0.07 s |
| npm: 1 install + 8 `npm ci` (520 MB, 27,867 files) | 165 | 2,392,143 | 2,057,425 | 45,024 | 47,228 | 55,059 | 136 (82%) | 0.61 s |
| pip install | not run: no pip on the machine; downloading it was refused by the permission classifier | | | | | | | |
| dev server | not run: running one means executing downloaded package code, refused by the classifier | | | | | | | |

Identities:
- dogfood: `build/san/test/test_md5` raced and `build/san/test/` unstable, one run, while a gate
  rebuild was linking. `tmp/work/work/` unreadable in all 238 runs: an overlayfs workdir left by
  the session tests, not a race.
- make: build outputs (objects, test binaries) and their directories; `./` twice.
- npm: package files and directories mid-extraction; most often raced: large Windows binaries
  (next-swc `.node`, `tsc.exe`, `libvips-42.dll`).
- No clock steps in any run (about 2.5 h).

## 3. Precondition: a writer had the file open while belay read it

| workload | files hashed | refused by probe | rate | already flagged by today's checks | clean hash under a writer | torn-and-passed vs ground truth |
|---|---|---|---|---|---|---|
| dogfood | 263,359 | 1 | 0.0004% | 1 of 1 (raced) | 0 | no ground truth |
| make | 551,440 | 25 | 0.005% | 11 of 11 (pass 2; pass 1's 14 unclassified) | 0 | 0 of 222,659 |
| npm | 2,057,425 | 3,115 | 0.15% | 732 of 2,021 (passes 2-3) | 1,289 | 0 of 1,292,046 |

npm pass 3, clean hashes under a writer (538): 221 were partial (all confirmed prefixes of the final
file: real intermediate states) and 317 were complete. Every partial-file clean hash in pass 3
was on a refused file (221 of 221); no unrefused file had one.

## 4. Unknown costs

Racy re-capture, extra hash I/O (racy regular-file bytes / hashable bytes):

| filesystem | kernel | tree | extra hash I/O |
|---|---|---|---|
| ext4 | 6.18 (WSL) | dogfood repo | 0.15% |
| ext4 | 6.18 | under make load | 7.7% |
| ext4 | 6.18 | under npm load | 4.6% |
| ext4 | 6.17 / 6.8 | fresh 13k-entry, 218 MB tree, 3 copies each | 0.0-0.1% |
| FAT | 6.17 | same, 6 fresh copies (2 CI runs) | 2.1, 7.4, 70.8, 2.5, 76.9, 97.0% |
| FAT | 6.8 | same, 3 fresh copies | 1.0, 11.2, 19.9% |

Every copy gave the same figure on all five checks over 30 s: the clock-free rule, as specified,
does not decay with age. Entries tied with the newest granule seen so far in visit order stay
racy until they change.

Mount-table fallback (no openat2), 100k-entry tree, check 1.0 s warm: two `mountinfo` reads
0.14-0.27 ms; per-entry prefix check against 32 mount points within noise of the plain iteration
(187-204 ms vs 187-194 ms), so at most ~0.5%.

Raw per-run logs in raw/; the CI job is on branch `measure/base-rate` (not for merge).
