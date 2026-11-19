# Independent re-check of the implementer's four oracle edits (2026-10-30)

Fresh agent, own worktree, read only prose, pins and scripts/oracle (never src/, include/, tools/,
test/*.c, test/accounting/, NOTES/). Asked for by the author (message 4, item 8). Verbatim below.

---

**Commit reviewed: d99cce2** ("oracle: enough attempts that the coverage gate does not depend on the seed"). Line numbers below are at d99cce2.
- My worktree was created at d57d7dc (`main`), which has no `scripts/oracle/` and no `docs/spec/diff-v1.md`. So I read the prose, pins and oracle from a `git archive d99cce2` export in scratch.
- After your note I ran `git checkout --detach d99cce2` in the worktree. `diff -rq` shows my exports are byte-identical to the checked-out `docs/`, `scripts/oracle/`, `test/expect/`, and to the whole tree I built the C library from. Nothing needed redoing.
- I re-ran `scripts/oracle/run.sh` from the worktree: PASS. Seed 20261030: 6,193/6,193 pairs agree; random seed 26347515: 6,198/6,198; gate PASS both times.
- The worktree is left detached at d99cce2 and clean. I opened nothing under `src/`, `include/`, `tools/`, `test/*.c`, `test/accounting/` or `NOTES/`.

| Edit | Verdict |
|---|---|
| 1. b605fd8, type-change reasons | Agree |
| 2. a304d0f, trailer fields (reference.py) | Agree in part |
| 3. a304d0f, trailer sum (compare.py) | Agree |
| 4. d99cce2, retry budget 4 → 64 | Agree in part |

## Edit 1: b605fd8, the type-change reasons

**Verdict: agree.** The reference, generator and gate do what the d99cce2 prose says. The changed spec sentence is consistent with the pin and the rest of the prose. What is missing is coverage and a pin, not a wrong output.

**Text relied on:**
- The changed sentence, diff-v1.md:156-159: "`unknown`, for an `unknown` outcome: the reasons of every flag on either side and, when the types are the same, of every field unknown under rule 4 (across a type change no field is compared), in the order of the reasons table".
- Before the commit it read: "the reasons of every flag on either side and of every field unknown under rule 4, in the order of the reasons table".
- diff-v1.md:119-121: "1. `raced` on either side: `unknown`. … 2. Types differ: `type_changed`."
- diff-v1.md:151: "when the types differ, `["type"]`".
- diff-v1.md:116-117: "Flags on **either** side make part of the comparison unknown: their reasons are collected."
- diff-fields.md:61 (`raced`: "flag: everything unknown"), with the legend at :22-23: "on either side it makes X unknown, with the flag's name as the reason".
- diff-fields.md:47 and :31 (`iflags`): "`unknown`: present on one side only makes the outcome `unknown`".

**The ambiguity, and the reading chosen.** Under the old sentence both readings were defensible, as the commit message says.
- (a) List `iflags_unknown`. Rule 4 (diff-v1.md:128-131) has no type condition, and the sentence already applied to paths rule 4 never decides: a same-type raced path lists `iflags_unknown`.
- (b) Don't list it. Rule 4 compares like with like, and across a type change nothing is compared.

The edit chose (b) and wrote it into the prose; under the new sentence (a) is no longer defensible. One prose passage the commit does not cite supports (b). manifest-v1.md:386-388 says Linux does not record "inode flags of symlinks, FIFOs, sockets and devices". So on Linux a reg→lnk change has `iflags` on one side by design, and "absent means it could not be read" would be false there.

One asymmetry remains, though it is not a contradiction. `xattrs_unknown`, rule 4's other metadata reason, is still listed across a raced type change because it is a flag. The parenthesis "no field is compared" would fit flags too, but the sentence names every flag explicitly.

**Consistency with the pin and the rest of the prose: consistent.**
- The pin says nothing about reasons.
- Its `iflags` legend (:31) is about the outcome, and rule 1 makes the outcome `unknown` here anyway.
- The `raced` row (:61) fits listing `raced` alone.
- The new parenthesis matches diff-v1.md:151.

One older pin tension is now exercised by a newly required scenario, "a type change, iflags on one side only" (not raced):
- Read literally, legend :31 makes that `unknown`.
- Rule 2 and the pin's own `type` row (:37) make it `type_changed`.
- O1 (:67) carves the type change out for the hash, but nothing carves it out for `iflags`.

The reference follows rule order and gives `type_changed`. I agree with that, but the pin should say so.

**How I established it:**
- Reading: `git show b605fd8 -- scripts/oracle docs/spec`; at d99cce2, reference.py:293-299, gen_corpus.py:972-995, compare.py:316-317 and 389-395.
- Running hand-made pairs, each validated with the generator's own `violations()`, through the reference at f857a4d (before the edit) and at d99cce2:

| Pair | f857a4d | d99cce2 |
|---|---|---|
| `x`: reg {iflags:16, raced} → lnk {raced} | `["raced","iflags_unknown"]` | `["raced"]` |
| Same change, no `raced` | `type_changed` | `type_changed` |
| Same type, both raced, `iflags` before only | `["raced","iflags_unknown"]` | `["raced","iflags_unknown"]` (same-type case untouched, as the sentence requires) |

- Running `analyze.py` on the fixed-seed corpus: 64 targeted pairs carry the case, and on 71 pairs the two readings give different reasons, so the new pairs do separate them. The case is present in all 262 targeted-only seeds.

**Disagreement:** none.

**What was missed:**
1. **The new pairs reach only half of rule 1's "either side".** Every targeted raced type change has `raced` on both sides: `in_context('raced')` sets it (gen_corpus.py:702-706) and `change_type` keeps it (:950-953). The gate tag at compare.py:391-394 accepts that form.
   - A type change with `raced` on one side only, the realistic case, is never built by a targeted builder: 0 in 262 seeds.
   - Random pairs (200 bases) supply `raced`-before-only type changes in 79 of 122 seeds and `raced`-after-only in 82.
   - With `iflags` also on one side, they appear in 34 seeds (raced on the side that has `iflags`) and 30 (raced on the side that lacks it), out of 122.
   - Concrete input: before `x` reg {iflags:16, sha256}, after `x` lnk {raced}. The prose gives `unknown`, `changed:["type"]`, `unknown:["raced"]`. The reference gives exactly that, and so does the current C (`vsdriver.py`). Nothing is hidden today, but a regression would pass the gate on about a third of random seeds.
   - The fixed seed happens to contain 7 such paths each way. This gap predates the edit (f857a4d was already two-sided).
2. **The decision lives only in prose**, written by the implementer in the commit that made the oracle match the C. diff-fields.md is the file "the oracle reads … instead of the spec" (:7), yet it has no rule for reasons across a type change and no `iflags` carve-out for type changes. If you accept the sentence, pin both.
3. **A residual ambiguity in the same sentence, left open.** Does "a field unknown under rule 4" require rule 4's own condition, "Without such a difference"?
   - The reference lists `iflags_unknown` even when a metadata field differs, and the C agrees.
   - Example: fixed-seed pair-02944 ("becomes a mount root with new timestamps: fifo") gives `unknown:["mount","iflags_unknown"]`, `changed:["dev"]`.
   - The field-level reading the reference uses is the more natural one; the other is weakly defensible.

## Edit 2: a304d0f, the trailer fields in reference.py

**Verdict: agree in part.** The values are right: I found no input where any of the nine fields departs from what the text supports. The problem is sourcing.
- `before_sha256`, `after_sha256`, and which input counts as "before", are defined only in the generated trailer table.
- That table was generated from `src/schema/diff_schema.c` in this same commit.
- The reference's own source rule excludes it (reference.py:13: "Never the generated blocks of the spec"), yet the edit's comment (reference.py:39) calls it "the trailer's prose".
- No pin covers the diff trailer.

**Text relied on:**
- Prose: diff-v1.md:21, the example trailer. It gives the keys, their order and kinds, and shows `after_unstable`:1 alongside the unstable `build` record and `provisional`:true.
- manifest-v1.md:247-248: "**Non-zero `vanished`, `unstable` or `raced` in the trailer makes the whole result provisional**".
- test/expect/manifest-v1.md:55-60: the manifest's trailer keys.
- manifest-v1.md:228-229: a reader rejects "anything after the trailer", so for any accepted input the bytes read are the whole file.
- Generated only: diff-v1.md:72-80, e.g. :79 "The sha256 of the earlier manifest's bytes as this diff read them".

**How I established it:**
- Reading: `git show a304d0f -- scripts/oracle docs`; reference.py:42-45, 182-186, 453-457.
- Running `awk`/`grep` over both specs and both pins with GENERATED blocks skipped: the only non-generated definitions of the diff trailer are diff-v1.md:21 and manifest-v1.md:247.
- Running hand-made pairs; the C agreed on all of them:
  - `vanished` 1 before and 0 after, entries identical: no records, `before_vanished`:1, `provisional`:true.
  - The mirror case: `after_vanished`:3.
  - Nothing set: `provisional`:false.
  - Both digests equal `sha256sum` of each file.

**Ambiguities:**
- **"earlier"/"later"** in the generated rows. Every targeted pair is written both ways (gen_corpus.py:636-638), so in half of them "before" has the later `created_ns`. The reference uses argument order, the only reading consistent with `created_ns` being informational. This is wording.
- **Which bytes are hashed.** The prose names none. The whole file, once, is the natural reading.

**Disagreement:** none.

**What was missed:**
- **The gate requires nothing about the trailer.** The case the trailer text names, provisional from `vanished` alone with no record to explain it, comes only from `mutate_random` (gen_corpus.py:1519-1520).
  - With 200 random bases, a "vanished alone" pair was present in all 122 seeds measured.
  - A pair that is provisional with no record at all was missing in 10 of 122 seeds.
  - In targeted pairs alone, "vanished alone" was missing in 211 of 262 seeds.
  - A diff that took `provisional` from its records instead of the counts would be caught only by random pairs.
  - Suggested scenarios:
    - `vanished` non-zero on one side with no flagged entry;
    - before counts different from after counts;
    - `provisional` false.
- **Cosmetic.** `TRAILER_KEYS` (reference.py:43), which the edit extended, is never read; the order actually checked is built at :453-457. The compare.py docstring (:12) is stale.

## Edit 3: a304d0f, the trailer sum in compare.py

**Verdict: agree.** The sum is not part of the trailer comparison. compare.py:511-513 feeds a statistic printed at :537, and nothing else reads it (grep finds lines 504, 513, 537 only).

The comparison itself is compare.py:256-266:
- the exact key list and order against the reference's trailer;
- every value under a type-strict equality, so `true` ≠ 1;
- `belay_diff_end` against the number of records the driver emitted.

**Text relied on:** diff-v1.md:21 and :64 (generated): "Number of records emitted. Then one count per outcome, named as the outcome, unchanged included."

**How I established it:**
- Reading the lines above.
- Running a two-line Python check: the pre-edit line `outcomes[k] += v` raises `TypeError: unsupported operand type(s) for +=: 'int' and 'str'` on the first new string field. Once edit 2 landed, compare.py could not have run without this edit.

**Does it still check everything the counts promise?** Yes. Restricting a sum that never checked anything loses nothing. Every count, `provisional` and both digests are still compared key by key against the reference, which counts each path once over the union of paths.

**Disagreement:** none. **Missed:** nothing the prose requires.

## Edit 4: d99cce2, the retry budget

**Verdict: agree in part.** It removes the observed flakiness but guarantees nothing; the gate still depends on the seed, now negligibly. The docstring's "must not depend on a random seed's luck" (gen_corpus.py:839-840) holds in practice, not in principle. Prose and pins are silent here, so this judgment is on the oracle's own terms.

**How I established it** (all by running; the C is not involved):
- **Wrapper.** `gen_logged.py` swaps in an identical `try_pair` that logs attempts. It reproduces the generator's corpus byte for byte (`diff -r`, seed 20261030).
- **At 4 attempts** (200 random bases; seeds 1-120, 20261030 and 721274331), 5 of 122 seeds fail the gate: 10, 48, 53, 113 and 721274331.
  - Each misses one reg field pair with `sha256`: (reg, size, sha256) four times, (reg, uid, sha256) once.
  - That confirms the commit's example seed. The rate is about 1 in 24, not the "one seed in a dozen" the docstring claims (:840).
- **At 64 attempts**, 0 of those 122 seeds fail, and 0 of 262 seeds with no random bases. The targeted builders alone satisfy the gate.
- **Per-builder logs** over 262 seeds:
  - No builder label failed in some seeds and succeeded in others.
  - 1,235 of 2,799 labels can never succeed, because the format forbids them (e.g. caps on a non-reg). They now burn 64 attempts each, which costs time only (about 8-10 s per seed).
- **Thin coverage.** 264 of the gate's 404 items rest on exactly one `try_pair` call in every seed: 263 of the 270 field pairs, plus the cell `size` on `lnk`.
  - The weakest such builder is "only size and sha256 differ on a reg". Its per-attempt success is 0.68 (262 successes in 387 attempts). All 64 attempts fail with probability about 4×10⁻³²; at 4 attempts it was about 1.1%.
  - The (`size`, `lnk`) cell has one builder (rule 19 ties a readable link's size to its target). It succeeded at its first attempt in all 262 seeds.

**Can a required cell still be missed?** In principle yes, about 10⁻³¹ per seed. In practice no.

**A gap retries cannot close:** `try_pair` keeps the first valid pair whether or not it covers its item. The thinnest items' builders cover their item by construction, so this is not live today. The deterministic generator should check coverage per item.

**Disagreement:** none.

## Findings outside the four edits
- **MEDIUM.** Raced type changes are generated only with `raced` on both sides. This predates the edits; see edit 1, item 1.
- **LOW.** reference.py:256, written in f857a4d per `git blame`, cites `include/belay/manifest.h` for the xattr digest.
  - The rewrite's commit message lists what its author never read: `src/`, `tools/`, `test/*.c`, `NOTES/`. `include/` is not on that list.
  - The guess never decides a generated pair, because both sides' values are random, so it has no current effect. But the rewrite's independence claim has an exception.
- **LOW.** diff-fields.md:31 contradicts rule 2 for a non-raced type change with `iflags` on one side, which is now a required scenario. It needs an O1-style carve-out.
- **LOW (design question).** A raced type change's record has no `type_before`, which is "For `type_changed` only" (diff-v1.md:51, generated). So the earlier type is lost from the output.
- **LOW.** "earlier/later manifest" in the generated header and trailer rows means "first/second input".
- **LOW.** `HEADER_KEYS` and `TRAILER_KEYS` in reference.py are dead code; the compare.py docstring is stale.

## What I could not check
- **Whether you decided the edit-1 reading somewhere I may read.** The pin's decisions (F7, (a)-(f)) and the reference's ambiguities A2, A7, A9 and A10 live in `NOTES/` or PR discussion, which were off limits.
- **The digests' meaning.** `before_sha256`/`after_sha256` have no prose or pin definition to check against. I could only compare them with `sha256sum` and with the C.
- **A changing input.** A manifest that changes while the diff reads it cannot be built in this oracle.
- **The "65 pairs" figure in b605fd8's message.** Not reproduced; at d99cce2 the fixed seed gives 71, because the generator's random stream has changed since.
- **Why the C agrees.** Not examined. Every C result above is evidence about the C only.

Scratch scripts and per-seed results:
- /tmp/scratchpad/oracle-review/analyze.py
- /tmp/scratchpad/oracle-review/gen_logged.py
- /tmp/scratchpad/oracle-review/batch.py
- /tmp/scratchpad/oracle-review/examples.py
- /tmp/scratchpad/oracle-review/runref.py
- /tmp/scratchpad/oracle-review/vsdriver.py
- /tmp/scratchpad/oracle-review/runs
