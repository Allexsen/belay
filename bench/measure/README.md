# measure

The instrument for "is this worth fixing" questions about walk consistency: how often a
precondition actually occurs on real trees, under real work, before anyone builds a mechanism
for it.

It runs belay's own capture code, unchanged, through a decorated platform adapter that only
observes, and prints one JSON line per check.

```sh
make measure                                    # builds build/bench/measure
build/bench/measure --tag mine ~/project        # one check
bench/measure/observe.sh ~/project log.ndjson   # every 10 s for 24 h; kill to stop
bench/measure/summarize.py log.ndjson           # one summary per log
```

`measure` never writes into the scope: the manifest goes to `$TMPDIR` (or `--tmp DIR`) and is
deleted, unless `--keep DIR` keeps it.

## What a line holds

| key | meaning |
|---|---|
| `entries`, `raced`, `unstable`, `unreadable`, `vanished`, `mounts` | belay's own outcome, from the manifest it wrote; `*_paths` lists up to 40 flagged entries |
| `files_hashed`, `bytes_read` | regular files belay opened to hash, and the bytes it read |
| `writer_at_open`, `writer_at_eof` | the platform's `writer_present` probe (the one that gates the content store), right after belay opens each file and when it reaches EOF: `yes` some process had it open for writing or mapped shared-writable, `no`, `unknown` the platform cannot tell (macOS; a filesystem without leases; a file not ours without `CAP_LEASE`) |
| `writer_outcome` | what the manifest recorded for files a writer held: a clean hash, a stored copy, or a flag |
| `writer_paths` | those files (up to 4096) |
| `racy` | the racy rule of the 2026-10-27 design review, which belay does not ship: entries whose ctime was >= the newest seen so far on their device, in visit order, and the bytes a re-hash would cost (`racy_reg_bytes` / `reg_bytes`) |
| `clock_step_s` | how far the wall clock moved against the monotonic one during the check |
| `mount_table` | with `--mounts N` (Linux): the cost of reading the mount table twice and checking every entry against N mount points |

Options: `--store DIR` turns the content store on, so `writer_outcome.stored` shows the store
gate's actual decisions; `--keep DIR` keeps each manifest; `--tag T` labels the line.

## Torn reads against ground truth

A clean hash can be checked only against a known final state. For a workload whose final
content is deterministic per path (`npm ci` from a lockfile, a reproducible build):

```sh
mkdir keep
MEASURE_KEEP=keep MEASURE_TAG=during bench/measure/observe.sh "$tree" log.ndjson 2 &
# ... run the workload to completion, then kill the loop ...
build/bench/measure --keep keep --tag truth "$tree"     # the quiet final tree
bench/measure/torn_check.py "$tree" keep/truth.*.ndjson keep/during.*.ndjson
```

`torn_check.py` sorts every clean hash that differs from the final file into:

- `partial_real_state`: a prefix of the final file, written front to back;
- `complete_earlier_version`: an earlier file at that path, read whole -- later replaced whole
  (its inode differs from the final file's: pip's `RECORD`, npm's `package.json`), or recorded
  identically by two or more checks before being rewritten;
- `torn`: bytes the file never held, as far as the oracle can tell. One sighting of an earlier
  version rewritten in place on the same inode also lands here; it cannot be told from a tear.

It exits 1 if anything is torn.

## Reading the numbers

- A count of zero means the precondition did not occur in that workload, not that it cannot.
  The 2026-10-27 measurements found no torn read in about 1.5 million checked hashes, but none
  of those workloads had an in-place overwriter or a shared-mapping writer, the two kinds that
  tear reads (see the spec, "What a hash, and a stored copy, prove").
- Leases need the file to be ours (or `CAP_LEASE`); run as the owner of the tree, or count
  `unknown`.
- On WSL, a Windows program writing into the Linux filesystem does so through WSL's 9p server,
  a Linux process: the probe sees those writers too.
- The probe holds nothing: a writer is never delayed by more than its two system calls.
