# NFS: a listing older than its directory's attributes (2026-10-28)

Found when deleting the ctime window rule (decision 1, 2026-10-28) turned CI's `filesystems`
job red: test_stress on a loopback NFS export (vers=4.2, writer and checker on the same client)
reported a clean manifest that was not a real state.

| code | runs with an inconsistent clean claim | clean claims |
|---|---|---|
| main d4be8fb (window rule) | 0 of 8 | 1,128 |
| 9fe7d1b (validator only) | 4 of 8 | 857 |
| 9fe7d1b, with diagnostics | 6 cases in 32 runs | 3,400 |
| e13564e (validator re-lists) | 0 in 32 runs | 3,666 |

Diagnostics (throwaway branch measure/nfs-stress, deleted): every case was a file missing from
both listings (A and B) while A's and B's recorded mtime and ctime equalled their values after
the check -- the client served a listing older than the attributes it reported. A fresh
opendir/readdir right after the check showed the file in every case (4 of 4 checked).

Fix (e13564e): the walk records each directory's names (count + two 64-bit hash sums); the
validator lists every recorded directory again through a new open and compares. +0.9% on a
110k-file tree. Test: listing_older_than_its_directory_is_flagged.

Why the window rule had caught it: the destination directory's ctime fell inside the walk, so it
was flagged unstable whatever its listing said. It was load-bearing on NFS for a reason nobody
had written down.
