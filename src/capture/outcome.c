#include "outcome.h"

#include <string.h>

enum {
    SET_UNVERIFIED  = 1u << 0,
    SET_UNSTABLE    = 1u << 1,
    SET_UNREADABLE  = 1u << 2,
    SET_MOUNT       = 1u << 3,      /* and unverified, on a regular file */
    SET_RACED       = 1u << 4,
    SET_XUNKNOWN    = 1u << 5,      /* and nothing of the attributes recorded */
    DROP_HASH       = 1u << 6,
    TARGET_UNKNOWN  = 1u << 7,      /* the link target recorded empty: unknown */
    TARGET_UNKNOWN_IF_NONE = 1u << 8, /* ...unless one was read (a stale one) */
    COUNT_VANISHED  = 1u << 9,
};

#define D EFF_DEFINED
const unsigned OUTCOME_EFFECT[FACET_N][OUT_N] = {
    [FACET_CONTENT] = {
        [OUT_OK]        = D,
        [OUT_CHANGED]   = D | SET_UNVERIFIED | SET_UNSTABLE | DROP_HASH,
        [OUT_DENIED]    = D | SET_UNVERIFIED | SET_UNREADABLE | DROP_HASH,
        [OUT_TOO_LARGE] = D | SET_UNVERIFIED,
        [OUT_GONE]      = D | COUNT_VANISHED,
    },
    [FACET_LISTING] = {
        [OUT_OK]        = D,
        [OUT_CHANGED]   = D | SET_UNSTABLE,
        [OUT_DENIED]    = D | SET_UNREADABLE,
        [OUT_GONE]      = D | SET_UNREADABLE | COUNT_VANISHED,
    },
    [FACET_TARGET] = {
        [OUT_OK]        = D,
        [OUT_DENIED]    = D | SET_UNREADABLE | TARGET_UNKNOWN,
        [OUT_CHANGED]   = D | SET_UNREADABLE | TARGET_UNKNOWN_IF_NONE,
        [OUT_GONE]      = D | COUNT_VANISHED,
    },
    [FACET_ENTRY] = {
        [OUT_OK]        = D,
        [OUT_GONE]      = D | COUNT_VANISHED,
        [OUT_BOUNDARY]  = D | SET_MOUNT,
        [OUT_CHANGED]   = D | SET_RACED,
    },
    [FACET_EXTRAS] = {
        [OUT_OK]        = D,
        [OUT_DENIED]    = D | SET_XUNKNOWN,
    },
};
#undef D

void outcome_apply(struct belay_entry *e, enum facet f, enum outcome o, struct walk_tally *t) {
    const unsigned x = (unsigned)f < FACET_N && (unsigned)o < OUT_N ? OUTCOME_EFFECT[f][o] : 0;
    if (!(x & EFF_DEFINED)) {             /* an outcome nothing defines: fail, never ignore */
        if (t != NULL) t->invalid++;
        return;
    }
    if ((x & COUNT_VANISHED) && t != NULL) t->vanished++;
    if (e == NULL) return;
    if (x & SET_UNVERIFIED) e->unverified = true;
    if (x & SET_UNSTABLE)   e->unstable = true;
    if (x & SET_UNREADABLE) e->unreadable = true;
    if (x & SET_RACED)      e->raced = true;
    if (x & SET_MOUNT) {
        e->is_mount = true;
        if (e->type == BELAY_T_REG) e->unverified = true;
    }
    if (x & DROP_HASH) {
        e->has_hash = e->has_stored = false;
        e->sha256_hex[0] = '\0';
    }
    if (x & SET_XUNKNOWN) {
        e->has_caps = e->has_xattrs = e->xattrs_inline = false;
        e->xattrs_len = 0;
        e->xattrs_unknown = true;
    }
    if ((x & TARGET_UNKNOWN) || ((x & TARGET_UNKNOWN_IF_NONE) && !e->has_link_target)) {
        e->link_target[0] = '\0';
        e->link_target_len = 0;
        e->has_link_target = true;
        e->target_outside_scope = false;
    }
}

void outcome_count(struct belay_manifest_stats *s, const struct belay_entry *e) {
    s->entries++;
    s->unreadable += e->unreadable;
    s->unstable   += e->unstable;
    s->mounts     += e->is_mount;
    s->raced      += e->raced;
}
