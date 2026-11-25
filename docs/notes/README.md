# Working notes

These files were written by AI agents under the author's direction while building belay. The author
has not read all of them. They record reasoning and evidence at the time of writing; many are
snapshots of an older commit and say things that are no longer true, including "awaiting approval",
"not fixed" and "open". Where a note disagrees with a pin in `test/expect/` or with a test, the pin
and the test are right.

They are here so that contributors, and the agents they work with, can see why the code is the way
it is and what a claim rests on. They are not documentation: for how belay behaves, read
[`docs/`](..) and the pins.

## Reading them

- Paths written `NOTES/…` refer to this folder. The notes cite each other, and some of what they
  cite is not published here; such a reference cannot be followed.
- A line starting "Note added at export" was added when the file was published.
- Replaced throughout, by rule: the author's username with `user`, session scratch directories
  with `/tmp/scratchpad`, session identifiers with `SESSION-ID`, and the token counts of agent
  runs with `[n]`. Nothing else was rewritten.
- Scripts are kept as evidence of what was run: they hold paths from the machine they ran on and
  are not meant to be run as they are.
- "I" in a note is the agent that wrote it. "The author" is the project's author.

## What is here

| Path | What it is |
|---|---|
| `audit-2026-10.md` | An inventory of 2026-10-20: what existed, measured against the design. |
| `git-assumptions.md` | Why git's storage model does not fit. |
| `m2-structure.md`, `phase3-structure.md`, `phase4-structure.md`, `phase5-structure.md`, `watch-structure.md` | Structure proposals, written before each phase's code: modules, interfaces, what the structure rules out, limits. |
| `pin-proposal-touched-2026-11-13.md` | A proposal for a `protected_path_touched` signal, with false-alarm measurements. |
| `walk-consistency-review-brief.md` | The request for a design review of walk consistency, with the torn-read measurements behind it. |
| `reviews/` | Adversarial reviews by separate agents, by phase and by pull request; several carry the dispositions of their findings. |
| `s3-phase4/`, `s3-phase5/` | Canary (mutation) runs for phases 4 and 5: the mutants, and which test killed each. |
| `measurements/` | Dated measurements with their scripts and raw data: base rates of races under load, installer write patterns, the mark prefilter's timing, a stale NFS listing, a mutation rerun, what the 146 EvilGenie test changes were, and the EvilGenie runs that tried to undo a test change with git. |
| `dogfood/fp-table.md` | How often each would-be flag fired on ordinary work. |
| `dogfood/2026-11-04-setup-outside-scope.md` | A case where a receipt showed changes that the agent's own report left out. |
