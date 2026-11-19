# Torn reads: how often belay hashes a file state that never existed

The instrument is in [bench/measure/](https://github.com/Allexsen/belay/tree/main/bench/measure). The per-run logs, scripts and working notes of the two measurements are in [docs/notes/measurements/2026-10-27-base-rate/](https://github.com/Allexsen/belay/tree/main/docs/notes/measurements/2026-10-27-base-rate) and [docs/notes/measurements/2026-10-28-workloads/](https://github.com/Allexsen/belay/tree/main/docs/notes/measurements/2026-10-28-workloads).

## What was tested

belay records a file by reading it once and hashing what it read. If another process is writing the file during that read, the bytes read can be part old and part new: a state the file never had. This is a torn read. This study measured how often that happens under ordinary development workloads, and how often a process had the file open for writing at all while belay read it. The last section states what belay records today when it cannot rule a torn read out.

## What a torn read is

belay checks each regular file like this: stat, open, stat the open file, read everything, stat again. If size, mtime or ctime moved, the entry is recorded `unstable`, without a hash. That check catches a write that starts during the read. It does not catch one already in flight when the read began: `write(2)` updates the timestamps first and copies the data afterwards, so the timestamps do not move again while the bytes land. A store through a shared writable mapping moves a timestamp only on the first store to a clean page.

That a torn read can pass the check is established, with a synthetic writer:

- `bench/spike_torn.c` rewrites a 4 MiB file in place, over and over, while a reader runs the same check. On Linux 6.18, 56 of 2,000 reads were torn and passed on ext4, and 11 of 2,000 on tmpfs ([manifest-v1 spec](https://github.com/Allexsen/belay/blob/main/docs/spec/manifest-v1.md), "What a hash, and a stored copy, prove").
- Against a writer storing through a shared mapping, an independent review measured 634 of 1,000 on ext4 (same section).
- With a shared-mapping writer and belay itself, before manifest v4, 30 of 30 captures recorded a hash of bytes the file never held, with no flag ([manifest-v4 pin](https://github.com/Allexsen/belay/blob/main/test/expect/manifest-v4.md)).
- Run once more for this report, on ext4: 19 of 2,000 with the in-place writer, 429 of 1,000 with the mapping writer. The figures vary from run to run.

So the question here is not whether it can happen. It is how often the precondition occurs when the writers are real tools.

## Environment

- Linux 6.18 under WSL2, ext4, one machine. All workload figures below are from it.
- 2026-10-27 and 2026-10-28, before manifest v4 existed. The capture code under measurement did not yet mark entries `writer_open`.
- Tools: pip 24.0 on Python 3.12, Django's development server on SQLite, the Next.js development server, make. The second npm setup used Linux node 18 and npm 9. The first npm measurement's logs show the win32 builds of native packages being installed (`tsc.exe`, `libvips-42.dll`), so the npm that ran there was not that one.

## Method

**The instrument.** `measure` runs belay's own capture code, unchanged, through a platform adapter that only observes, and prints one line of counts per check. A loop ran a check every 2 seconds while the workload ran (every 10 seconds for the working session).

**Writer present.** Right after belay opens a file to hash it, and again at the end of the read, the instrument asks the kernel whether any process has the file open for writing or mapped shared-writable. It does so by taking a read lease and releasing it at once; a refusal means a writer was there at that instant. Nothing is held during the read. Controls: a file held open for writing and a file with only a shared mapping were refused, and an idle file was not.

**Ground truth, deterministic content.** Where the final content of every path is known (an install from a lockfile, a reproducible build, wheels), a check of the quiet tree was taken after the workload ended. Every clean hash recorded during the workload (a hash with none of `unstable`, `raced`, `unreadable`) was compared with the final hash of the same path. A clean hash that differs is torn unless it is the hash of a real earlier state. Two kinds of real earlier state were accepted: a prefix of the final file (a file written front to back, read part-way), and a complete earlier file at that path that was later replaced.

For the make loop, determinism was checked first: two quiet clean builds gave 736 files with no differing hash.

**Ground truth, SQLite.** A database file is rewritten in place and has no deterministic final content. For it, the Django server ran with a preloaded library that logged every write and truncate of the database file, with times. Replaying the log over the initial file rebuilds every state the file had. The replay was checked against the final file. A separate reader applied belay's stability check to the database file every 20 ms and kept a signature of each read that passed. A passing read that equals no rebuilt state is torn.

**Installer write patterns.** dpkg and pip were traced with strace, on a first install and on a reinstall, to see how each file reaches its final content.

## Workloads

| workload | checks | entries | files hashed | raced | unstable | vanished | checks with a flag |
|---|---|---|---|---|---|---|---|
| working session in this repository, 40 min | 238 | 354,264 | 263,359 | 1 | 1 | 0 | 1 |
| `make clean; check; check-san` looped in a clone, 25 min | 760 | 753,841 | 551,440 | 90 | 102 | 28 | 68 |
| npm: 1 install and 8 `npm ci` (520 MB, 27,867 files) | 165 | 2,392,143 | 2,057,425 | 45,024 | 47,228 | 55,059 | 136 |
| pip: numpy, pandas and scipy into a fresh venv, 3 rounds (316 MB, 9,617 files) | 21 | 87,463 | 78,916 | 1,452 | 2,181 | 6,607 | 8 |
| npm, second setup (node 18, npm 9): install and 2 `npm ci` (614 MB, 27,701 files) | 22 | 262,965 | 227,873 | 7,626 | 9,232 | 16,245 | 10 |
| Django runserver with SQLite, 10 min, 146,726 requests, 10 source edits | 298 | 10,011 | 7,925 | 280 | 549 | 52 | 285 |
| Next.js dev server, 10 min, 200,899 requests, 10 source edits | 247 | 2,140,484 | 1,956,725 | 526 | 103 | 0 | 247 |

`raced`, `unstable` and `vanished` are belay's own flags for an entry that changed under the walk. A flagged entry is already reported as not proven; it is not a torn read that passed. The first three rows are the 2026-10-27 measurement and the rest are 2026-10-28.

## Results

### How often a writer had the file open

| workload | files hashed | a writer at open | rate | what belay recorded for those files |
|---|---|---|---|---|
| working session | 263,359 | 1 | 0.0004% | 1 raced |
| make | 551,440 | 25 | 0.005% | second pass (11 files): 11 raced. First pass (14 files): not recorded |
| npm | 2,057,425 | 3,115 | 0.15% | second and third pass (2,021 files): 732 raced, 1,289 a clean hash. First pass (1,094 files): not recorded |
| pip | 78,916 | 0 | 0% | none |
| npm, second setup | 227,873 | 26 | 0.011% | 21 raced, 5 a clean hash |
| Django with SQLite | 7,925 | 474 | 5.98% | `db.sqlite3`: 271 raced, 26 a clean hash. Its journal: 9 raced, 168 a clean hash |
| Next.js dev server | 1,956,725 | 252 | 0.013% | 252 raced |

A clean hash under a writer is the case that matters: belay recorded a hash with no flag while some process could write the file. There were 1,289 in the first npm measurement, 5 in the second, and 194 in the Django run.

### Clean hashes against ground truth

| workload | clean hashes compared | differing from the final file | of those, real earlier states | torn |
|---|---|---|---|---|
| make, second pass | 222,659 | not kept | not kept | 0 |
| npm, second and third pass | 1,292,046 | not kept | not kept | 0 |
| pip, 3 rounds | 77,472 | 3 | 3 | 0 |
| npm, second setup | 219,322 | 15 | 15 | 0 |

No torn hash was found among 1,811,499 clean hashes compared.

What the differing hashes were:

- npm, third pass: of the 538 clean hashes recorded under a writer, 221 were of a partly written file, each confirmed a prefix of the final file, and 317 were of the complete file. In that pass no file without a writer at open had a partial hash.
- pip: the checker reported 3 hashes as torn. Each was a complete earlier version of a package's `RECORD` file, byte-equal to the `RECORD` inside the wheel. pip rewrites that file through a temporary file and a rename.
- npm, second setup: the checker reported 12 as torn. All 12 were the 50-byte `package.json` the project started with, read whole in 12 checks before npm replaced it. 3 more were prefixes of the final file.

The 15 reported hashes were settled by comparing bytes by hand, not by the checker. `torn_check.py` as published sorts a complete earlier version into its own class; the stored outputs predate that.

The working session, the Django run and the Next.js run have no ground truth of this kind: their final content is not deterministic.

### The SQLite oracle

| run | requests | writes logged | replay equals the final file | reads that passed the stability check | torn | passing reads that overlapped a write in progress |
|---|---|---|---|---|---|---|
| 1 | 25,669 | 103,386 | yes | 4,339 of 6,805 | 0 | not recorded |
| 2 | 13,196 | 53,150 | yes | 3,641 of 4,959 | 0 | 13, each a real state |

In run 1, belay's own checks also recorded 21 clean hashes of the database file. Each equals a state the file had within that check's time window.

This is the one workload here whose writer rewrites an existing file in place. In run 2, 13 of 3,641 passing reads overlapped a write in progress.

In both runs the reader was a Python script applying belay's check, not belay. In run 1 the server from a sanity check was still running, so the traffic went to it; its write log had been deleted and was recovered through `/proc`. The first 201 records, written before the initial copy of the database was taken, were skipped. The replay equalling the final file confirms the log is whole.

### How installers write

- dpkg 1.22.6, first install and reinstall: every package file is written beside its final path with the suffix `.dpkg-new` and renamed over. The status database is written as `status-new` and renamed.
- pip 24.0 with the numpy 2.1.3 wheel, fresh and with `--force-reinstall`: the old package's directories are renamed aside and deleted later. Each of the 819 files is then created at its final path and written there, as a new inode. `RECORD`, `INSTALLER` and the 406 compiled `.pyc` files go through a temporary file and a rename.

Neither installer overwrote existing bytes in place. pip's new files are visible at their final paths while they are being written, which is where the partial, real states above come from.

## What belay records today

These measurements were taken before belay marked anything. Since manifest v4, belay asks the same question the instrument asked, at the start and at the end of the read of every regular file it hashes ([manifest-v4 pin](https://github.com/Allexsen/belay/blob/main/test/expect/manifest-v4.md), [command line reference](https://github.com/Allexsen/belay/blob/main/docs/cli.md), "A file being written while it is read"):

- If a process had the file open for writing, or mapped shared-writable, at either point, the entry carries `writer_open`. The hash is kept in the manifest, but no diff compares it and no copy of the file is kept. A diff reports the path as `unknown`, reason `writer_open`, whatever else differs. A protected path carrying it is reported `protected_path_unverifiable`. `mark` reads such a file again on the next capture, whatever its stat says.
- Where the kernel cannot answer, the file is hashed as read and left unmarked, and the manifest's trailer counts it in `unguarded`. That is the case on macOS, on a filesystem without leases, and for a file belay's user does not own without `CAP_LEASE`. Every regular file hashed in a scope on overlayfs is counted too, because there a shared mapping whose file descriptor was closed is not seen. A receipt states the count on one line.
- The diff's trailer carries both counts for both sides.

Checked for this report on the current build (v0.1.0-alpha.9 plus 5 commits, manifest v4), on ext4: with a process holding a 4 MiB file open for writing and writing nothing, a capture recorded the entry with `writer_open`, a hash and no stored copy, and a trailer of `writer_open` 1, `unguarded` 0. The diff against an earlier capture gave `unknown`, reason `writer_open`. After the process exited, the next `mark` read the file again and the diff reported no change.

belay does not hold the lease during the read: it asks and releases at once, so a writer can still open the file between the two questions.

Applied to the workloads above, the 1,488 clean hashes recorded under a writer (1,289, 5 and 194) are entries that would now be `unknown` instead of compared. That is the cost of the rule: a file a process merely holds open for writing stays `unknown` for as long as it does.

## What this does not show

- One machine, one kernel, one filesystem. Nothing was measured on other filesystems, on kernels before 6.13 (where timestamps are coarser), on native Linux outside WSL2, or on macOS.
- Zero torn of 1,811,499 is a base rate for these workloads on this machine. It is not a bound. The installers and the build wrote new files or renamed over old ones, and none overwrote existing bytes in place.
- The only in-place writer measured under a real workload is SQLite. A tool that rewrites large files in place, or writes through a shared mapping, was measured only with the synthetic writer, where torn reads that pass the stability check are common.
- Three workloads have no ground truth for their clean hashes: the working session, Django outside the oracle runs, and the Next.js server. The 194 clean hashes under a writer in the Django run were not checked.
- The ground truth for deterministic content accepts a prefix of the final file as a real state. That holds for a file written front to back once. A torn read that happens to equal such a prefix would be counted as real.
- A writer that opens the file, writes and closes entirely between the two questions, inside one timestamp tick, is seen by neither the probe nor the stat checks. This follows from the kernel's rules; it was not observed.
- A writer on another machine, on a network filesystem that grants leases locally, is not seen.
- On overlayfs, a shared writable mapping whose descriptor was closed is not seen by the probe (measured; [manifest-v1 spec](https://github.com/Allexsen/belay/blob/main/docs/spec/manifest-v1.md)). belay counts those files as `unguarded`; it cannot mark them.
- No workload has been measured again since manifest v4. How many entries real work turns `unknown` under today's rule is inferred above from the earlier counts, not measured.
- The first pass of the make and npm measurements kept no manifests, so its clean hashes were not compared.

## Which figures were recomputed for this report

Recomputed from the per-run logs with the published aggregation: every figure in the workloads table except the sizes, file counts, request counts and edit counts in its first column; the writer counts and outcomes; the clean-hash totals and reported counts for pip and the second npm setup; the count of passing reads in oracle run 2. One figure differs from the working note: it gives 27 clean hashes of `db.sqlite3` under a writer, and the log gives 26.

Taken from the working notes, because the manifests, write logs and traces they rest on were not kept or were not re-read: the two torn counts of the first measurement (0 of 222,659 and 0 of 1,292,046), the 221 and 317 of the third npm pass, the determinism check, the byte comparisons of the 15 reported hashes, both oracle rows apart from the 3,641, and the installer write patterns.

## Reproduction

`bench/measure/README.md` gives the commands: `make measure`, `observe.sh` to run checks in a loop and keep the manifests, `torn_check.py` to compare them with a check of the quiet tree, `summarize.py` for the counts. The workload drivers, the write logger and the oracle scripts are in the two measurement folders. They install and run third-party packages.
