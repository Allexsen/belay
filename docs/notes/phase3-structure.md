# Phase 3 (diff core): structure proposal

Status: **proposal, awaiting the author's approval** (standing rule, BELAY_DESIGN.md §0.7). No
implementation code exists for it. 2026-10-30.

## 1. What Phase 3 must do (known requirements only)

- Compare two manifests as a **streaming merge** over their sorted entries, in **bounded memory at 1M
  entries** (the merge spike, bench/bench_merge.c: two 1M-entry manifests in 1.4 MiB, 1.7 s).
- Give every path one outcome: **added, removed, modified, type-changed, metadata-only, unknown**
  (and unchanged, which is counted, not emitted). `raced`, `unstable` and `unverified` map to
  **unknown, never to unchanged**.
- Honour every obligation the manifest spec puts on a consumer ("Obligations on a consumer"):
  refuse different scopes; `unreadable`/`mount` mean contents unknown or not captured; an
  `unstable` directory's children are not a complete listing; a ctime-only change is "changed:
  unrecorded attribute"; compare under the same `hash_max_bytes`; handle **orphans** (an entry
  whose parent is absent) without crashing or misreporting.
- Emit **diff.v1**, generated from one schema source the way the manifest spec is now.
- Define the **interpreter interface** -- `{path, before, after}` → findings, or decline -- that
  Phase 4's interpreters (pip, dpkg, git, text) plug into.

Not in Phase 3: interpreters themselves (Phase 4), integrity and policy (M2), `mark`'s prefilter,
restore. The CLI is open question 1.

## 2. Modules (src/diff/), one job each

```
 reader A ─┐
           ├─ pair.c ──> classify.c ──> interp hook ──> emit.c ──> diff.v1 NDJSON
 reader B ─┘     │            │
                 └─ ancestry.c┘          diff_schema.c (outcomes, field classes, record
                                         fields) feeds classify.c, emit.c, the generator
 diff.c: opens both, checks they are comparable, runs the pipeline, owns errors
```

| module | its one job | what it must not know |
|---|---|---|
| `diff.c` | Orchestration: open both readers, refuse incomparable pairs (scope, version, hash algorithm), run pair → classify → interpret → emit, own error handling and the summary. | How any outcome is decided. |
| `pair.c` | The streaming merge: from two strictly ordered iterators, yield `(before?, after?)` in path order, each path exactly once. Holds two current entries. | Fields, flags, outcomes. |
| `ancestry.c` | For the current path, what its nearest recorded ancestor on each side says: sealed (`unreadable`/`mount`), incomplete (`unstable`), or nothing. A stack of prefix lengths, as the reader's sealed stack. Orphans need no special case: a missing parent just isn't on the stack. | Outcomes. |
| `classify.c` | One function: a pair plus both sides' ancestry → one outcome and the list of changed field classes. Table-driven from `diff_schema.c`: which flags force `unknown`, which field changes mean modified vs metadata-only. The only place an outcome is decided. | Output format, interpreters. |
| `diff_schema.c` | The diff's rules defined once: the outcome set, each manifest field's change class (content / metadata / identity / informational), the flag → `unknown` table, the diff.v1 record fields. The generator (tools/gen_schema.c) emits the diff.v1 spec block from it, with gen-check. | Anything at run time beyond its tables. |
| `emit.c` | Serialize one classified record and its findings as one diff.v1 line; summary counts derived at emission, never kept by hand (the capture side's outcome_count lesson). | How outcomes were decided. |
| interpreter hook (`include/belay/interp.h`, extended) | The interface below. Phase 3 ships the hook and the binary fallback (which declines). | -- |

Estimated size: pair ~120 lines, ancestry ~80, classify ~150, schema ~150, emit ~200, diff ~150.

## 3. Interfaces

```c
/* pair.c */
struct pair_state;                                   /* two readers, two current entries */
int pair_next(struct pair_state *, const struct belay_entry **before,
              const struct belay_entry **after);     /* 1 a pair (one side may be NULL),
                                                        0 done, -1 error */
/* ancestry.c */
enum anc { ANC_NONE, ANC_INCOMPLETE /* unstable dir */, ANC_SEALED /* unreadable, mount */ };
void ancestry_step(struct ancestry *, const struct belay_entry *e);  /* per side, in path order */
enum anc ancestry_of(const struct ancestry *, const char *path, size_t len);

/* classify.c */
struct verdict {
    enum diff_outcome outcome;                       /* from diff_schema.c */
    uint32_t changed;                                /* FBIT set of fields that differ */
    uint32_t why_unknown;                            /* FBIT set of flags that forced unknown */
};
void classify(const struct belay_entry *before, enum anc before_anc,
              const struct belay_entry *after,  enum anc after_anc,
              const struct belay_manifest_header *hb, const struct belay_manifest_header *ha,
              struct verdict *out);

/* interpreters (Phase 4 implements them; Phase 3 defines and calls the hook) */
struct belay_interp_input {
    const char *path; size_t path_len;
    const struct belay_entry *before, *after;        /* NULL for added / removed */
    const struct verdict *verdict;                   /* read-only */
    struct belay_content *content;                   /* stored copies by hash; may say "absent" */
};
enum belay_interp_result { BELAY_INTERP_FINDINGS, BELAY_INTERP_DECLINE, BELAY_INTERP_ERROR };
struct belay_interp {
    enum belay_interp_id id;                         /* dispatch.c already maps paths to ids */
    enum belay_interp_result (*explain)(const struct belay_interp_input *,
                                        struct belay_findings *out);
};
```

The interpreter's output type carries findings (annotations: "package numpy 2.1.3 → 2.2.0",
"3 tests skipped") and nothing else. It **cannot set or change the outcome**: there is no field
for it. Declining is always safe: the record is emitted with the core's outcome and no findings.

## 4. Defect classes the structure makes impossible

| class (known-issues) | how this structure closes it |
|---|---|
| **C1 no-change** (a state reads as "no change") | One function decides outcomes, driven by one table. `unchanged` is reachable only through the table's single row "every compared field equal, no flag in the unknown set on either side, no sealed or incomplete ancestor". Interpreters cannot produce or change an outcome (no field for it), so a plug-in cannot hide a change. A generated test enumerates every flag combination from the schema and asserts none maps to unchanged. |
| **Mis-pairing** (a moved or duplicated path paired wrongly) | Pairs are formed in one place, from inputs the reader already guarantees strictly ordered; pair.c re-asserts order (one comparison per step). |
| **Comparing incomparable manifests** | Refused in one place at open (scope, format version, hash algorithm), before any entry is read. |
| **A field forgotten in comparison** | classify.c loops over the schema's fields with their change classes; a field added to entry.c without a change class fails a coverage test like decoder_reads_every_schema_field_once, and -Wswitch where a switch is used. |
| **C7 docs drift** | diff.v1 spec generated from diff_schema.c; CI gen-check. |
| **Hand-kept counts drifting** | Summary counts derived at emission from emitted records only. |
| **Orphans crashing or misreporting** | ancestry.c works on prefixes of the path stream, never looks a parent up, so an absent parent cannot be dereferenced; an orphan is classified like any entry. Tested explicitly (the test owed since decision 5). |

## 5. Proof standard

- Unit tests per module (pair: interleavings, empty sides, identical inputs; ancestry: sealed vs
  incomplete vs orphan; classify: the generated flag-combination table).
- **A differential oracle**: a deliberately naive reference comparator (Python, both manifests in
  memory, dictionaries, no streaming) run against the C diff on a generated corpus of manifest
  pairs, mutated the way scripts/golden/mutate.py mutates manifests. Identical outcomes for every
  path. The streaming merge is the risky part; a slow obvious implementation is its oracle.
- Bounded memory measured at 1M entries per side (RSS), as for the writer.
- Mutation runs with the clean harness (fresh mtimes): removing the unknown table, the ancestry
  check, the scope check and the order assertion must each fail a test.
- Fuzz: diff.v1 is output, not untrusted input -- no fuzz target unless a diff.v1 reader appears.

## 6. Open questions for the author

1. **CLI in Phase 3?** `belay diff <manifest-a> <manifest-b>` is cheap once the core exists;
   `diff --since <id>` needs the check/store/state-dir wiring. Proposal: the two-manifest form in
   Phase 3, `--since` with `mark`.
2. **diff.v1 shape.** Proposal: NDJSON like the manifest -- a header (both scopes, both headers'
   limits), one line per non-unchanged path, a trailer of derived counts -- so it streams in bounded
   memory too.
3. **Same content, new inode** (a file replaced by rename with identical bytes): metadata-only
   ("replaced") or unchanged? Proposal: metadata-only, identity class, since a replaced binary is
   worth seeing.
4. **`hash_max_bytes` differing between the two manifests:** proposal per the spec -- an entry
   hashed on one side and `unverified` on the other is `unknown`, not modified.
5. **Where diff_schema.c lives**: src/diff/ (proposal) or beside entry.c in src/capture/. It needs
   entry.c's field list either way.
6. **unchanged entries:** counted in the trailer, never emitted (proposal). A `--all` flag can come
   when someone needs it.
