# Assumptions git makes that are false for belay

## Git tracks content, the exec bit, and symlinks — nothing else
False here: uid/gid, full permission bits, xattrs, device nodes, and
empty dirs are often THE change (`chmod 600 /etc/shadow`).
Consequence: metadata is first-class in belay's object model, not a
sidecar hack like etckeeper's.

## Git derives diffs by comparing snapshots
False here: overlayfs upperdir IS the materialized delta, free, from
the kernel.
Consequence: inverted architecture — native deltas, derived snapshots.

## Git's diff is textual and line-based
False here: "apt installed nginx" is one true line; git would show 2000
changed files.
Consequence: diff is an interpretive stack — raw fs delta, then
package-aware, then config-aware.

## Merge means 3-way line merge
False here: the real operation is "apply my changeset to a base that
drifted."
Consequence: rebase-of-operations, not merge-of-lines.

## The staging area earns its complexity
Unverified. jj deleted it. Decide before v0's `commit`.
