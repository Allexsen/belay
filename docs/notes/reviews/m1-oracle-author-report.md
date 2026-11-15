# Oracle author's report: deterministic gate and the new semantics (2026-10-30)

Separate agent, own worktree, prose and pins only (author's message 4, items 8 and 9). Commits
885bb9b, 5898791, 7027e10 on c7149f9 (cherry-picked onto m1/phase3-diff). Verbatim below.

---

## Oracle update: dir timestamps, raced ancestors, mount-root attributes, trailer, and a deterministic gate

All three commits are in, and the full oracle passes on both trees. The C and the prose never disagreed: every pair matched on header, records and trailer, in both trees, on every seed I ran.

**Branch** `worktree-agent-ID`, on base **c7149f9**.
- My worktree started at b02aff8 (main). I fast-forwarded to 227743d, moved to dcca6b3, then fast-forwarded to c7149f9 as you asked.
- m1/phase3-diff has since moved to 930176b. That commit touches only `include/belay/store.h`, `src/capture/` and `test/` (checked by file name), so it shares no file with my commits. I did not rebase onto it.

| commit | task |
|---|---|
| `885bb9b` | B: the reference follows F5, the raced ancestor, the mount-root column and the trailer prose |
| `5898791` | A: every required pair is built once, by construction, and checked |
| `7027e10` | C: the gate requires the new cases (45 → 81 scenarios) |

All three touch only `scripts/oracle/` (3 files) and pass `scripts/check-dco.sh c7149f9 HEAD`. `git commit -s` puts the Signed-off-by line after the Co-Authored-By line, as in every earlier commit here, so the messages end with the sign-off.

## B: reference.py (and compare.py checks)
Line numbers are `docs/spec/diff-v1.md` at c7149f9 and `test/expect/diff-fields.md`, established by `grep -n`.

- **`dir_timestamps_only`**
  - It is added to the trailer right after `unknown`, as in the Shape example (line 21).
  - Its value is the number of `unchanged` directories whose O5 timestamps differ.
  - It follows "the trailer counts it in `dir_timestamps_only`, which is part of `unchanged`" (172–174) and "counts the directories among `unchanged` whose own timestamps differ" (64–65).
  - The fields counted are the ones pin O5 names (line 71), read at run time. The reference stops if O5 disappears or names a field the table compares on a directory.
- **Raced non-directory ancestor**: implements "It is not a directory and carries `raced`: `unknown`, reason `raced`" (125–126).
- **Mount-root column**
  - A field present on one side only is now unknown under rule 4 only where the pin's `on mount roots` column (line 27) says `compared`. That column is read from the pin.
  - Result: `iflags_unknown` is given on mount-root changes under the current row 47 (`compared`), and not under PR #12 (`not compared`).
  - This is the code reviewer's item 2. The reference had ignored the column in that check.
  - caps/xattrs stay uncompared on mount roots under both pins, by O2 (line 68, "or on a mount root (never read)"), now checked at start-up.
- **Trailer sourcing (finding 2)**
  - Now cited to "### Trailer" (61–72) and to "`before` is the first manifest given…" (24).
  - `HEADER_KEYS` and `TRAILER_KEYS` were dead. Both are now checked at start-up against the Shape example, and asserted on every header and trailer the reference writes.
  - The reference asserts "the counts add up to the number of distinct paths" (63–64).
  - compare.py now checks the driver's own trailer against that paragraph, whatever the reference says: the counts add up, `dir_timestamps_only` is among `unchanged`, and `provisional` is exactly "any of the six is not 0".
- **Independence leak (finding 5)**: the `include/belay/manifest.h` citation is removed.
  - No prose or pin gives the `xattrs_sha256` formula. The only statement is a generated block (`manifest-v1.md` line 103).
  - An inline set against a digest now counts as different. That is a stated assumption: it holds because the generator never derives a digest from a set.
- **Cleanup (finding 6)**: compare.py's docstring is rewritten.

## A: deterministic gate (replaces the retry budget of d99cce2 / 222fb07)
- There are no retries. Each targeted pair is built once. A builder that returns nothing or writes an invalid manifest stops the generator, naming the pair.
- Builders cannot fail:
  - the tree's hash limit is chosen for the change it must hold;
  - a subject is placed under the always-open root, and `fresh_path` always finds a free name;
  - new values differ by construction;
  - `remount()` no longer leaves a device number unchanged (it did 1 time in 9 per off-root device, which made "every entry renumbered" seed-dependent).
- Combinations the frozen format cannot hold are excluded up front by rules tied to the manifest pin (`cell_feasible`, `type_change_feasible`, `one_sided_feasible`), never by trying.
- **Coverage per item (finding 4)**: each pair is checked with compare.py's own coverage code to show its cell, field pair, optional field or scenarios. Then the targeted pairs alone must pass the whole gate, before any random pair is written.
- `compare.py --gate <corpus>` computes the gate with no driver.

## C: new required cases, each built deterministically, both ways round
- **A directory's own timestamps**: only `mtime_ns`, only `ctime_ns`, or both, on a directory and on the root.
- **The same on fifo, sock, blk and chr**: no record and not counted. These tags now require nothing flagged.
- **A directory's timestamps beside**:
  - nlink or size (still counted);
  - a compared field;
  - a flag alike on both sides, or on one side;
  - iflags on one side only.
- **A path missing below a raced or non-raced non-directory**, one and two levels down. Also below one that carries unreadable or mount: "only a directory … seals".
- **Siblings that sort between a name and its children** (`d!x`, `d-x`, `d.x`, code reviewer item 1).
- **A dir or regular file that becomes a mount root, or stops being one**, with iflags, xattrs, caps or `xattrs_unknown` on the other side.
- **Raced type changes with `raced` on one side only**, before or after, with `iflags` on the raced side or the other side (finding 1). Your exact case `reg {iflags, sha256}` → `lnk {raced}` gives `unknown`, `changed ["type"]`, `unknown ["raced"]` in both directions, from both the reference and the C.
- **Trailer (finding 3)**: vanished on one side with nothing flagged and no record; every walk count different between the sides; `provisional` false; the first manifest created after the second.

## Evidence (all by running)
- **Determinism**: `gen_corpus.py <dir> 200 20261030` run twice, then `diff -r -q`: no difference. Both runs give 19,671 files and the same digest, `0f816116…076ec9d1`.
- **Seed independence**: `tests/seeds.sh` runs gen_corpus with 0 random bases plus `compare.py --gate` for the fixed seed and seeds 1–50.
  - Result: **51 of 51 pass**, 3608 pairs each, 81/81 scenarios.
  - The targeted labels are identical pair by pair across all seeds.
  - Commit A alone: 51 of 51 pass (3228 pairs, 45/45).
  - Six large seeds with 200 bases (including 721274331, which d99cce2's message reports as having missed a pair) all pass.
- **Full oracle (`scripts/oracle/run.sh`)**:

| tree | fixed seed 20261030 | random seed | gate |
|---|---|---|---|
| c7149f9 + my 3 commits | 6551/6551 agree | 1344736460: 6558/6558 | 81/81, PASS |
| same + 7f6fa87 + 358e8f0 | 6551/6551 agree | 2908623716: 6584/6584 | 81/81, PASS |

- **Same pair under each pin**: "a reg becomes a mount root, iflags+caps+xattrs read before".
  - Current pin: `["unverified","mount","iflags_unknown"]`.
  - PR #12: `["unverified","mount"]`.
  - Each tree's C agrees with its own pin.
- **Guards**: monkeypatched builders that fail, or that don't show their cell, make the generator stop and name the pair. Dropping the trailer builders makes `check_gate` stop and name the 2 missing scenarios.
- **Stand-in driver** (the reference made wrong one way at a time): all 13 corruptions are caught by the targeted corpus alone.
  - The stack-style ancestor bug ("forgets `d` once `d!x` has passed") is caught only by the new sibling pairs.
  - With the old corpus, a driver lacking the raced-ancestor rule was not detected at all (0 differing pairs); the new corpus finds it in 12.

## Ambiguities, and the reading I chose
1. **"only difference is its own timestamps"** (172) vs O5's "every compared field is equal". I count a directory whose nlink or size also changed. Basis: O5 plus the trailer paragraph. The C agrees.
2. **PR #12's "with no reason that claims something could not be read"** vs "the reasons of every flag on either side" (184). When the non-mount side carries `xattrs_unknown`, I keep that flag's reason. The C agrees under both pins. The sentence would read better if it said it concerns the `iflags_unknown` reason only.
3. **xattrs digest formula**: no allowed source; I use the stated assumption from B.
4. **Trailer outcome order**: the prose says "in the order of the outcomes table", which is generated. I take the order from the Shape example instead.
5. **Mount root "on either side" for timestamps** is unchanged from the earlier reading (A2).
6. **The current pin contradicts itself** on caps/xattrs at mount roots: the column says `compared`, O2 says not. The reference follows O2; PR #12 removes the contradiction.

## Not done
- I did not rebase onto 930176b.
- I ran `run.sh` directly rather than `make oracle`, which runs the same script after building everything.
- Linux (WSL2) only.
- I did not change the behaviour of b605fd8 or a304d0f.
- I read no C, not even `scripts/oracle/driver.c`. For the other directories I looked only at file names (`--stat`) and commit messages.

Scratch test scripts are in `/tmp/scratchpad/oracle-author/tests/` (`seeds.sh`, `neg_gen.py`, `standin.py`, `mutants.sh`, `show.py`, `derive_a.py`, `run_old_gen.py`).
