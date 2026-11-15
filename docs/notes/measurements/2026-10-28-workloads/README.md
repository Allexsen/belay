# pip, native npm, dev servers; installer write patterns (2026-10-28)

Linux 6.18 (WSL2), ext4. bench/measure at main 90bd95b, check every 2 s (oracle runs: 1 s and
20 ms). Scripts in scripts/, per-run logs and traces in raw/.

## Base rates

| workload | runs | entries | files hashed | raced | unstable | vanished | runs with a flag |
|---|---|---|---|---|---|---|---|
| pip: numpy+pandas+scipy into a fresh venv, 3 rounds (316 MB, 9,617 files) | 21 | 87,463 | 78,916 | 1,452 | 2,181 | 6,607 | 8 |
| npm, native (node 18, npm 9): install + 2x ci (614 MB, 27,701 files) | 22 | 262,965 | 227,873 | 7,626 | 9,232 | 16,245 | 10 |
| Django runserver + SQLite, 10 min, 146,726 requests, 10 edits | 298 | 10,011 | 7,925 | 280 | 549 | 52 | 285 (96%) |
| Next.js dev, 10 min, 200,899 requests, 10 edits | 247 | 2,140,484 | 1,956,725 | 526 | 103 | 0 | 247 (100%) |

Dev-server flags: Django -- `./` unstable 279x (the -journal file is created and deleted per
transaction), db.sqlite3 raced 271x; Next -- .next/trace raced every run (appended), data/counter.json.

## Writers during reads

| workload | writer at open | of hashed | outcome of those reads | torn vs ground truth |
|---|---|---|---|---|
| pip | 0 | 0% | -- | 0 of 77,472 clean hashes (3 flags were complete earlier RECORD versions, byte-equal to the wheels' RECORD) |
| npm native | 26 | 0.011% | 21 raced, 5 clean hash | 0 of 219,322 (12 flags were the seed package.json, byte-equal); 3 partial real states |
| Django | 474 | 5.98% | db.sqlite3: 27 clean / 271 raced; journal: 168 clean / 9 raced | no ground truth in this run; see the oracle |
| Next dev | 252 | 0.013% | 252 raced, 0 clean | no ground truth (.next contents are not deterministic) |

## SQLite oracle (Django --noreload, writes logged by LD_PRELOAD, every state rebuilt)

| run | requests | db writes logged | replay = final file | passing reads (belay's check) | torn | overlapped a write in progress |
|---|---|---|---|---|---|---|
| 1 | 25,669 | 103,386 | yes | 4,339 of 6,805 (20 ms reader) + belay's own 21 clean hashes | 0 | not recorded |
| 2 | 13,196 | 53,150 | yes | 3,641 of 4,959 | 0 | 13, all real states |

Run 1: the server of the sanity check kept running (stop killed its wrapper only); all traffic went
to it, logging into the deleted w.log, which was recovered from /proc/PID/fd. The first 201
records (sanity writes, before the initial copy) are skipped; the replay check confirms it.

## Installer write patterns (strace)

- dpkg 1.22.6 (`tree`, private root, --force-not-root), first install and reinstall: every package
  file written to `<path>.dpkg-new`, renamed over; status database via `status-new`, renamed.
- pip 24.0 (numpy 2.1.3 wheel), fresh and --force-reinstall: uninstall renames the old package,
  dist-info and .libs directories aside (`~umpy`...), deleted later; then every file (819) is
  written by open(O_WRONLY|O_CREAT|O_TRUNC) directly at its final path -- a new inode, the old
  one moved away; RECORD and INSTALLER rewritten via temp + rename; .pyc (406) via temp + rename.
- So: no installer overwrote existing bytes in place. dpkg renames over; pip does not (except
  RECORD/INSTALLER/.pyc) -- a new file is visible at its final path while being written.
