# Oracle author, round 2: type_before, the xattr digest formula, mount roots with flags (2026-10-30)

Separate agent (the same oracle author), prose and pins only. Commits 9aa7094, 6525666, 68582ee
on 61951fa (cherry-picked onto m1/phase3-diff). Verbatim below.

---

## Oracle round 2: type_before, the xattr digest formula, mount roots with flags

Round 2 is done: three commits on `oracle-round2`, and `scripts/oracle/run.sh` PASSes on it. The C and the prose disagree nowhere, but the C rejects one kind of manifest the pin says nothing about (an inline xattr set over 8192 bytes). I think the C is right there and the pin has a gap.

**Branch** `oracle-round2`, created with `git checkout -B oracle-round2 61951fa`; `git rev-parse HEAD` gave 61951fa2915849d0e4ca47c29b1c203c2ed2c9f8 before my commits.
- My round-1 commits appear in 61951fa's history as 1929588, d6dfe26 and 1ce5ef2, not the hashes you quoted.
- 61951fa's oracle files are byte-for-byte my 7027e10 (`git diff --quiet`).
- All three commits touch only `scripts/oracle/` and pass `scripts/check-dco.sh 61951fa HEAD`.

| commit | task | prose it follows |
|---|---|---|
| `9aa7094` | A: `type_before` on every type change | `diff-v1.md` 184–185 |
| `6525666` | B: an xattr set and its digest compare by the formula | `manifest-v1.md` 138–140; "Encoding" 22 and 29–31 |
| `68582ee` | C: a mount root on one side, a flag on the other | `diff-v1.md` 169–173 |

## What changed
**A.** The reference now emits `type_before` on every path present on both sides whose types differ: "the type before, whatever the outcome -- `type_changed`, or `unknown` when `raced` is on either side". Before, only `type_changed` carried it.
- compare.py also checks each driver record against that sentence on its own: a `type_changed` must have `type_before`, and `type_before` comes only with `changed ["type"]` and a type different from it.
- The gate gains "raced on both sides". The raced-before-only and raced-after-only cases were already required, and all of them now check `type_before`.

**B.** Round 1's assumption that an inline set and a digest always differ is gone.
- The reference computes the digest by the new rule: "the sha256 of the bytes `xattrs` would hold between its brackets, exactly as a writer emits them…", re-encoding each element by the canonical string grammar.
- New required pairs, on every type, both ways round:
  - the same set inline and by digest: no record;
  - the same set beside a mode change: `changed` names `mode` only;
  - a different set by digest, small or large: `xattrs` in `changed`;
  - two large sets by digest that differ: `xattrs` in `changed`.
- The generator computes each digest with its own JSON writer, and every pair is checked through the reference's formula, so the two implementations agree.
- Both sides satisfy pin rules 2, 3 and 22.

**C.** The gate now requires a directory that becomes a mount root while unstable, or unreadable with `iflags`, on the other side. Expected reasons: `mount` plus that flag's, with no `iflags_unknown`. Nothing else in the changed prose needed oracle work.

## Evidence (all by running)
- **Determinism:** `gen_corpus.py <dir> 200 20261030` run twice, then `diff -r -q`: no difference. Both runs give 19,890 files with the same digest, `c0c11893…33ee`.
- **Gate over seeds:** the fixed seed plus seeds 1–50, 0 random bases (`seeds.sh`: generator plus `compare.py --gate`): **51/51 PASS**, 3682 pairs each, 87/87 scenarios, targeted labels identical pair by pair.
- **`run.sh` on the final content:** 6624/6624 (seed 20261030) and 6647/6647 (seed 4046148858) pairs agree, gate PASS 87/87, refusals 6/6.
  - With A alone: 6551/6551 and 6620/6620.
  - With A+B: 6620/6620 and 6704/6704.
- **Stand-in drivers:**

| driver | caught in |
|---|---|
| no `type_before` on raced type changes | 392 pairs: 128 raced on both sides, 252 raced on one side, 12 below a raced ancestor |
| an inline set and its digest compared as different | 28 pairs |
| the formula with the elements unquoted | 28 pairs |
| the 13 round-1 corruptions | all still caught |

## The one finding: large inline sets
My first version put a set of more than 8192 bytes inline on one side, and the C rejected it: `manifest: xattrs longer than the inline limit` (14 pairs failed in the driver).
- The pin's 22+2 rules say nothing about size.
- The hand-written "Encoding" rule, "every manifest state has exactly one byte representation, and a reader MUST reject anything else" (line 22), supports the C. That holds given the writer's 8192-byte inline limit, which only a generated block states (line 102).

So I treated it as a pin gap, not a C bug, and the generator now uses large sets only on digest sides. If you want the limit pinned, it would need a reader rule in `test/expect/manifest-v1.md`.

## Ambiguities and readings
- **Digest spelling.** The sentence doesn't say how the sha256 is spelled. I used lowercase hex, like every other digest in the format; the C agrees.
- **Small set by digest.** The pin allows it, and no reader can tell a set's size from its digest; the C accepts it. The "compares equal" sentence needs it.
- **Digest of the empty set against an absent `xattrs`.** Not covered: no writer emits it, and the reference treats any digest as different from absence.
- **Settled by the new prose, as I had read them in round 1:** a directory's `size`/`nlink` (line 178), and "plus those of any flags either side carries" (172–173). The C agrees with both.

I read no C. Linux (WSL2) only. Scratch scripts are in `/tmp/scratchpad/oracle-author/tests/`.
