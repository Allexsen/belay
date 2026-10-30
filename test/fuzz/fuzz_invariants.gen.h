/* GENERATED from src/schema/entry.c by tools/gen_schema.c. Do not edit:
 * change the schema, then `make gen`. */
#ifndef BELAY_FUZZ_INVARIANTS_GEN_H
#define BELAY_FUZZ_INVARIANTS_GEN_H

#include "schema/entry.h"

#include <stdlib.h>

/* Aborts unless `e`, as the reader delivered it under header `h`, obeys
 * every schema rule. Fields present are recomputed from the decoded entry
 * (entry_present), not from the keys the reader saw; each rule is
 * expanded here rather than interpreted by entry.c's rule engine. */
static void schema_invariants(const struct belay_manifest_header *h,
                              const struct belay_entry *e) {
    if (F_COUNT != 26 || ENTRY_RULE_COUNT != 22 || ENTRY_HEADER_RULE_COUNT != 2)
        abort();                /* the schema changed: `make gen` */
    if ((unsigned)e->type >= ENTRY_TYPE_COUNT) abort();
    const uint32_t p = entry_present(e);
    const unsigned t = TBIT(e->type);

    /* 1. `mode`'s type bits match `type` (`S_IFMT`; the same values on Linux and macOS). */
    if ((t & 0x7fu) && ENTRY_RULES[0].check(e)) abort();  /* on all */

    /* 2. `xattrs` and `xattrs_sha256` are never both present. */
    if ((t & 0x7fu) && (p & 0x0002000u) && (p & 0x0004000u)) abort();  /* on all: xattrs excludes xattrs_sha256 */

    /* 3. `xattrs_unknown` excludes `xattrs`, `xattrs_sha256` and `caps`. */
    if ((t & 0x7fu) && (p & 0x0008000u) && (p & 0x0007000u)) abort();  /* on all: xattrs_unknown excludes caps, xattrs, xattrs_sha256 */

    /* 4. `caps` appears only on `reg`. */
    if ((t & 0x7eu) && (p & 0x0001000u)) abort();  /* on dir, lnk, fifo, sock, blk, chr: never caps */

    /* 5. A `reg` carries exactly one of `sha256` and `unverified`. */
    if ((t & 0x01u) && __builtin_popcount(p & 0x0030000u) != 1) abort();  /* on reg: exactly one of sha256, unverified */

    /* 6. On a `reg`, `unstable` and `unreadable` each require `unverified`. */
    if ((t & 0x01u) && (p & 0x1040000u) && !(p & 0x0020000u)) abort();  /* on reg: unstable, unreadable needs unverified */

    /* 7. On a `reg`, `unstable` and `unreadable` are never both present. */
    if ((t & 0x01u) && __builtin_popcount(p & 0x1040000u) > 1) abort();  /* on reg: at most one of unstable, unreadable */

    /* 8. A mounted `reg` carries neither `unstable` nor `unreadable`. */
    if ((t & 0x01u) && (p & 0x0800000u) && (p & 0x1040000u)) abort();  /* on reg: mount excludes unstable, unreadable */

    /* 9. A `dir` carries no `sha256`, `unverified` or `stored`. */
    if ((t & 0x02u) && (p & 0x0430000u)) abort();  /* on dir: never sha256, unverified, stored */

    /* 10. A `dir` carries `raced` only with `unreadable` or `mount` (a listed one that changed is `unstable`). */
    if ((t & 0x02u) && (p & 0x2000000u) && !(p & 0x1800000u)) abort();  /* on dir: raced needs mount, unreadable */

    /* 11. A `dir` carries at most one of `unreadable`, `unstable` and `mount`. */
    if ((t & 0x02u) && __builtin_popcount(p & 0x1840000u) > 1) abort();  /* on dir: at most one of unstable, mount, unreadable */

    /* 12. A `lnk` carries no `sha256`, `unverified`, `stored` or `unstable`. */
    if ((t & 0x04u) && (p & 0x0470000u)) abort();  /* on lnk: never sha256, unverified, unstable, stored */

    /* 13. A `fifo`, `sock`, `blk` or `chr` carries no hash fields, `unstable` or `unreadable`. */
    if ((t & 0x78u) && (p & 0x1470000u)) abort();  /* on fifo, sock, blk, chr: never sha256, unverified, unstable, stored, unreadable */

    /* 14. `stored` appears only with `sha256`, and equals it. */
    if ((t & 0x7fu) && ENTRY_RULES[13].check(e)) abort();  /* on all */

    /* 15. `rdev` appears exactly on `blk` and `chr`. */
    if (!(t & 0x60u) != !(p & 0x0080000u)) abort();  /* rdev exactly on blk, chr */

    /* 16. `link_target` (or `link_target_b64`) appears exactly on `lnk`. */
    if (!(t & 0x04u) != !(p & 0x0100000u)) abort();  /* link_target exactly on lnk */

    /* 17. `target_outside_scope` appears only on `lnk`. */
    if ((t & 0x7bu) && (p & 0x0200000u)) abort();  /* on reg, dir, fifo, sock, blk, chr: never target_outside_scope */

    /* 18. A `lnk`'s target is empty only when the link is `unreadable` (empty means unknown). */
    if ((t & 0x04u) && ENTRY_RULES[17].check(e)) abort();  /* on lnk */

    /* 19. A `lnk`'s `size` equals its target's length, unless the link is `unreadable`. */
    if ((t & 0x04u) && ENTRY_RULES[18].check(e)) abort();  /* on lnk */

    /* 20. `target_outside_scope` never accompanies an empty (unknown) target. */
    if ((t & 0x7fu) && ENTRY_RULES[19].check(e)) abort();  /* on all */

    /* 21. A `mount` carries no `sha256`. */
    if ((t & 0x7fu) && (p & 0x0800000u) && (p & 0x0010000u)) abort();  /* on all: mount excludes sha256 */

    /* 22. A `mount` carries no extended metadata (`iflags`, `caps`, `xattrs`, `xattrs_sha256`, `xattrs_unknown`). */
    if ((t & 0x7fu) && (p & 0x0800000u) && (p & 0x000f800u)) abort();  /* on all: mount excludes iflags, caps, xattrs, xattrs_sha256, xattrs_unknown */

    /* Header rule 1 (spec: "What the header determines, holds"). */
    if (ENTRY_HEADER_RULES[0].check(h, e) != NULL) abort();

    /* Header rule 2 (spec: "What the header determines, holds"). */
    if (ENTRY_HEADER_RULES[1].check(h, e) != NULL) abort();
}

#endif
