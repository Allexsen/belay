<!-- Phase 3 (diff core) independent review, round 1. 2026-10-30. Fresh agent, no implementation
     context. Branch m1/phase3-diff at 692b6ed + cleanup commits (PR #9).
     Cost: [n] tokens, 844 s (14.1 min), 42 tool calls. Verbatim below. -->

# Independent review: Phase 3 diff core (branch `m1/phase3-diff`, `main..HEAD`, 7 commits)

## Summary

I found no input where the diff core reports a changed or unknowable path as `unchanged`, or leaves it out of the output, against the spec as written. Pairing and ancestry also held up under an independent differential fuzz with adversarial byte names (8,000 pairs, 0 disagreements). Memory stays bounded at 1M entries (1.9 MiB max RSS).

The serious problems are in the proof and at the edges:
- **(1) Field-class table errors are invisible to every check.** This is a gap in the proof, not a live defect today.
- **(2) Two "Obligations on a consumer" are not met** by the diff.v1 output.
- **(3) The interpreter hook drops parts of the approved interface and can abort the whole diff.**

All runs were in a scratch copy made with `git archive HEAD`. Nothing in the repository was modified, and the scratch copy is removed.

---

## Findings

### F1. HIGH: a wrong or missing field class passes every check, including the oracle (class 5; enables class 1)

**Verified by running.** I tested one mutation at a time in a scratch copy: set one field's class to `CC_INFO` in `src/schema/diff_schema.c`, then `make gen && make check && scripts/oracle/run.sh 60`.

| field set to "not compared" | `make check` | oracle |
|---|---|---|
| `uid`, `gid`, `dev`, `nlink`, `iflags`, `caps`, `xattrs`, `rdev`, `mtime_ns`, `link_target` | **passes** | **passes** (890/890 agree) |
| `sha256`, `size`, `mode`, `ino` | fails | **passes** |

**Why the oracle can't catch it.** `reference.py` reads its field classes from the generated table in `docs/spec/diff-v1.md`, which `make gen` builds from the same `diff_schema.c`. A wrong class therefore ends up in both implementations.

**Why the corpus can't catch it either.** `gen_corpus.py` never changes `uid`, `gid`, `dev` (always 2049), `nlink`, `rdev`, `iflags` or `caps` on a same-type pair. Those values only change through the `type` op, which makes the pair `type_changed`.

**The promised safeguard does not exist.** Structure §4 says "a field added to entry.c without a change class fails a coverage test… and -Wswitch". Neither exists for the table:
- `DIFF_FIELDS` uses designated initializers, so a missing row compiles as `{CC_KEY, types=0}`.
- `diff_field_class()` (`diff_schema.c:295-298`) then returns `CC_INFO` because `types` is 0, so `differs()` and its `-Wswitch` are never reached.
- So a field added to `entry.c` later is silently not compared.

**Why there is no live defect today.** Each of these metadata changes also moves `ctime_ns`, so in practice it degrades to `metadata_only ["ctime_ns"]` rather than `unchanged`. But the spec itself says ctime must never be the only evidence for a protected path. A demoted `link_target` or `rdev` would turn `modified` into `metadata_only`.

**Direction:**
- Pin the table independently of the code. One way is a hand-written expected class per field in `test_diff.c` or in the oracle, deliberately duplicated rather than read from the spec.
- Add a static or test assertion that every `F_*` row has an explicit class. A sentinel `CC_UNSET = 0` would turn a gap into a failure.
- Add corpus ops that change each compared field alone on a same-type pair.
- Add one `test_diff.c` case per compared field.

### F2. MEDIUM: diff.v1 cannot say a result is provisional; `vanished` is dropped (class 4; borders class 1)

**Verified by reading.** manifest-v1 "Obligations on a consumer": "Non-zero `vanished`, `unstable` or `raced` in the trailer makes the whole result provisional… Say so." The diff.v1 header and trailer (`emit.c:113-135`, `187-194`; `diff_schema.c:300-331`) carry no field for this, and `belay_diff_stats` has none either. The reader validates both trailers, but their counts are thrown away. `vanished` is the one signal not reflected anywhere in the records.

**Related capture-side gap (reading only; I did not reproduce it; please check).** In `src/capture/walk.c:176`, `cons_listing_add(seen, dname)` adds every name `readdir` returned, *including* names that then vanish before their stat (`visit()` → `OUT_GONE`, nothing recorded, only `vanished++`). The end-of-walk re-listing is compared against `seen`, not against the recorded names. Sequence:
1. A file `x` is listed.
2. It is unlinked before its stat, so it is not recorded and `vanished` becomes 1.
3. It is recreated before the end-of-walk check.
4. The re-listing matches `seen`, so the parent is **not** flagged `unstable`.

The only remaining safety net is the directory's mtime/ctime check, which is the timestamp-granularity limit the second listing exists to remove (NFS, coarse filesystems, kernels before 6.13). The diff then reports `x` as **`removed`** while it exists at the end of the walk. Only `vanished=1` in the trailer would hint at it, and the diff ignores it.

**Direction:**
- Put both manifests' trailer counts, or a single `provisional` flag, in the diff.v1 trailer. It can't go in the header, which is written before the trailers are read.
- On the capture side, either feed `seen` only names that were recorded, or mark the parent `unstable` when a child vanishes.

### F3. MEDIUM: interpreter hook problems Phase 4 will regret (class 6)

All verified by reading: `include/belay/interp.h:91-116`, `src/diff/diff.c:189-203`, `src/interp/explain.c`.

1. **`BELAY_INTERP_ERROR` aborts the whole diff** (`diff.c:201` → `run_pipeline` → no output file). Interpreters will parse content the watched process controls: a RECORD file, dpkg status, git refs. A crafted file that makes an interpreter error would then suppress the entire diff, which is a way to hide every other change. An error should degrade to a decline, optionally with a "could not interpret" finding, and never fail the diff.
2. **Two members of the approved interface are missing.** Structure §3 approved `verdict` (read-only) and `content` (stored copies by hash) in `belay_interp_input`. The shipped struct has only `{path, path_len, before, after}`. Consequences:
   - An interpreter can't tell `modified` from `unknown`. It could emit a confident finding ("3 tests skipped") on a record whose after-state is `raced` or `unstable`.
   - It has no route to `store/`. `belay_diff(before, after, out)` takes only manifest paths, so adding the store means changing the public signature in `include/belay/diff.h`.
3. **No cross-path state and no begin/end hooks.** "numpy 2.1.3 → 2.2.0" is a `…-2.1.3.dist-info` removal plus a `…-2.2.0.dist-info` addition: two paths. A stateless per-path hook can't pair them. Consider a context pointer plus `begin`/`end` calls, or findings not tied to one path.
4. **Findings can produce invalid JSON.** `belay_findings_add` truncates with `snprintf` at 255 bytes, which can cut a multi-byte UTF-8 sequence. `emit.c:172-181` escapes but does not validate UTF-8, and interpreter text often comes from file content. Either validate (with base64 or replacement as fallback) or truncate on a UTF-8 boundary.
5. **The `TEXT` interpreter is unreachable.** `belay_interp_classify` returns `BINARY` for every unclaimed path, so text detection would need content access the hook doesn't give.

### F4. MEDIUM/LOW: orphan parents produce contradictory records (classes 2 and 4; spec ambiguity)

**Verified by running.**
- Before is `.` and `d/x` (orphan, no `d`). After is `.`, `d` (dir) and `d/x`. Output: `{"path":"d","outcome":"added"}`, although the before manifest itself shows `d` existed.
- The reverse gives `d` `removed` while `d/x` is `unchanged`.

This matches the spec text ("handled the same way"), so the code is consistent. But manifest-v1 requires "without… misreporting it", and a second careful implementer could reasonably say that when the side lacking P records a descendant of P, P's absence is not known, so the outcome is `unknown`. It doesn't hide a change, but it is wrong output. Severity depends on whether orphans occur outside corrupted or hand-edited manifests; I believe the writer never produces them.

**Direction:** decide this explicitly in the spec. In a stream it can be detected with look-ahead on the absent side's current entry, up to the end of that side's `P/` range, so it is not O(1) because of siblings like `P!x`. Or make `unknown` the outcome when that side's trailer or reader saw an orphan.

### F5. LOW: rule 5 floods directories with misleading ctime-only records (class 4)

**Verified by running.** Add `d/x`: the after side's `d` has mtime, ctime, size and nlink changed. Output: `d` → `metadata_only`, `"changed":["ctime_ns"]`.

For directories, `mtime_ns`, `size` and `nlink` are classed "not compared", so rule 5 ("only `ctime_ns` differs") fires. The outcome text then says "an attribute the manifest does not record changed", which is false here: the listing is recorded through the children. Every parent of every added or removed file gets such a record, and a large install yields hundreds.

**Direction:** for directories, treat a ctime change explained by a listing change as unchanged, or report it under its own label. At minimum, make the rule's wording cover directories.

### F6. LOW: two other spec disagreements (class 4)

- **`xattrs` attributes are not named.** manifest-v1 requires reporting a change in the xattr set "naming the attributes where `xattrs` is inline". diff.v1 only lists `"xattrs"` in `changed`.
- **Conflicting labels for `unverified`.** manifest-v1's `unverified` row says diff "must report any change to it as **modified (unverified)**", and the obligations say "unchanged (unverified)". diff-v1 says `unknown`. The manifest spec should be brought in line.
- **Nits:**
  - The diff-v1 example record uses path `"build/"`, which the reader rejects (empty component).
  - The record `type` description doesn't cover a one-sided `unknown`. The code uses the present side's type, which is fine.

### F7. LOW: one-sided `iflags` is silently not compared (class 1, theoretical)

**Verified by running.** `f` with `iflags:16` before and no `iflags` after, everything else equal → `unchanged`. On Linux, absence means the ioctl failed (`fsops_linux.c:99-105`), which is "could not read" and not "none". This is the case manifest-v1 forbids for xattrs ("an absent field must never stand for 'could not read'").

It is practically covered: `+i`/`-i` moves ctime, and large files are opened so they have `iflags`. **Direction:** treat `iflags` present on only one side like `xattrs_unknown` (metadata unknown), or document why not.

### F8. LOW: `root_kind` opens each manifest twice and re-reads entries before `.` (classes 3 and 2)

**Verified by running** for the performance part. 1M entries, all named `-d…/…` (so they sort before `.`): 6.0 s, against 3.1 s for the same tree with normal names. RSS is flat in both cases.

**TOCTOU (reading only):** `root_kind()` (`diff.c:152-175`) opens the path again by name. If the manifest is replaced in between, the root's kind comes from a different file. If that file's root was normal and the real one is `unstable`, top-level names sorting before `.` would be `added`/`removed` instead of `unknown`. This needs the state directory to be swapped during a diff.

**Direction:** open once, then use `dup`/`pread`, or reopen through the held fd.

### F9. LOW: smaller items

- `belay_diff` accepts `out_path` equal to an input. It finishes the read, then renames over and destroys that manifest.
- No `fsync` of the directory after the rename.
- The diff output doesn't identify its inputs (no manifest digests or ids), so a diff file can't be tied back to them. This is M2 territory.
- Test hygiene, outside this branch: `test/test_manifest_write.c:199,1268` leaves `/tmp/belay_m_<pid>.ndjson` behind on every `make check`. My 15 runs added about 30 such files to `/tmp`. I did not delete them because the sandbox refused a sweep of `/tmp`.

### Design notes (not defects; for the author's judgement)

These are all decided behaviour, but each makes `unknown` or `metadata_only` permanent noise, which trains users to ignore them:
- Every file above `hash_max_bytes` is `unknown` in every diff, forever.
- Every mount is `unknown` in every diff.
- On macOS every FIFO, socket and device is `unknown`, because they always carry `xattrs_unknown`.
- Overlayfs and remounts can change `dev`/`ino` across a whole tree, which turns into a `metadata_only` flood.

---

## What I checked and found sound

- **Classification** (`classify.c`): rule order, the flag → unknown table, rule 1 (`raced`) ahead of rule 2 (type) in both branches, size or hash as proof under `unverified`, hash limits that differ, link targets under `unreadable`, `caps`/`xattrs` under `xattrs_unknown`, ctime used only when nothing else differs, and the reasons set on every `unknown`.
- **No path to `unchanged` with a flag present.** `unchanged` can't be reached when any flag is on either side; the flag-combination test enumerates this and I agree with it.
- **Symlink size as proof.** An unreadable link's `size` is a real `lstat` value (`capture.c:265-315`, `outcome.c`), so treating it as proof is fair.
- **Ancestry** (`ancestry.c`): I checked the stack invariant by hand: every stacked entry is a prefix of the buffer, and the top is kept while the next byte is `<= '/'`.
  - **Independent fuzz:** random trees over names `a`, `!`, `-`, `.a`, `a\x01`, `\xff`, `0`, `a!`, up to 3 levels, with random unstable, unreadable and mount directories, an unstable root and orphans. I compared `belay_diff` against the reference's prefix-walk ancestor lookup, which is a separate algorithm: 8,000 pairs, 0 disagreements, 0 rejections.
  - **Hand probes passed:** `a\x01` sorting between `a` and `a!b` under an unstable `a`; names before `.` under an unstable root; absence below a file.
- **Pairing** (`pair.c`): a correct merge with an order re-assertion, and the remaining side drained after the other ends. A path is at most 4095 bytes (the reader caps at `sizeof path - 1`), so `last[4096]` and the ancestry arrays can't overflow, and the line cap (64 KiB) covers the worst escaped path plus 16 escaped findings.
- **Memory:** two 1M-entry manifests (10,000 modified) took 3.06 s with 1.9 MiB max RSS. Nothing grows with the number of entries.
- **Refusals and failure:** different scopes are refused before any output. Version and hash algorithm are enforced by the reader. Corruption anywhere, the trailer included, fails the diff with no output file (temporary file unlinked).
- **Emission:** `path_b64` for non-UTF-8 paths and the scope, `changed` in field order, reasons in table order, trailer counts derived only from what was emitted.
- **Existing checks:** `make check` passes in full, and `scripts/oracle/run.sh` gives 2,949 of 2,949 pairs agreeing.
- **Oracle strengths:** its ancestor lookup and xattr digest (taken from the raw line) really are independent of the C code. Its blind spots are the shared field table (F1), the narrow mutation ops (F1), paths of at most 200 bytes, constant `dev`, `created_ns` and scope, and `vanished` always 0. It also never exercises scope refusal; `compare()` returns `(None, None)` there, and `compare.py` would mishandle it.

## Not covered

- I did not run the sanitizers or fuzz targets.
- I did not review `tools/gen_schema.c` beyond `gen-check` passing.
- The capture-side issue in F2 is from reading only.
