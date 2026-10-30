#include "classify.h"

#include <string.h>

/* Whether field `f` differs between the two sides: 1 yes, 0 no, -1 not
 * compared (a side does not know it). Every case of enum entry_field. */
static int differs(enum entry_field f, const struct belay_entry *b, const struct belay_entry *a) {
    const bool xu = b->xattrs_unknown || a->xattrs_unknown;
    switch (f) {
    case F_MODE:   return b->mode != a->mode;
    case F_UID:    return b->uid != a->uid;
    case F_GID:    return b->gid != a->gid;
    case F_SIZE:   return b->size != a->size;
    case F_MTIME:  return b->mtime_ns != a->mtime_ns;
    case F_CTIME:  return b->ctime_ns != a->ctime_ns;
    case F_INO:    return b->ino != a->ino;
    case F_DEV:    return b->dev != a->dev;
    case F_NLINK:  return b->nlink != a->nlink;
    case F_IFLAGS: return b->has_iflags && a->has_iflags ? b->iflags != a->iflags : -1;
    case F_CAPS:
        if (xu) return -1;
        return b->has_caps != a->has_caps || (b->has_caps && strcmp(b->caps_hex, a->caps_hex) != 0);
    case F_XATTRS:
        if (xu) return -1;
        return b->has_xattrs != a->has_xattrs ||
               (b->has_xattrs && strcmp(b->xattrs_sha256_hex, a->xattrs_sha256_hex) != 0);
    case F_SHA256:
        return b->has_hash && a->has_hash ? strcmp(b->sha256_hex, a->sha256_hex) != 0 : -1;
    case F_RDEV:   return b->has_rdev && a->has_rdev ? b->rdev != a->rdev : -1;
    case F_LINK_TARGET:
        if (b->unreadable || a->unreadable || !b->has_link_target || !a->has_link_target) return -1;
        return b->link_target_len != a->link_target_len ||
               memcmp(b->link_target, a->link_target, b->link_target_len) != 0;
    case F_PATH: case F_TYPE: case F_XATTRS_SHA256: case F_XATTRS_UNKNOWN: case F_UNVERIFIED:
    case F_UNSTABLE: case F_TARGET_OUTSIDE: case F_STORED: case F_MOUNT: case F_UNREADABLE:
    case F_RACED: case F_COUNT:
        return -1;
    }
    return -1;
}

void classify_both(const struct belay_entry *b, const struct belay_entry *a, struct verdict *v) {
    memset(v, 0, sizeof *v);
    /* Flags on either side: their reasons, and what they make unknown. */
    const uint32_t flags = entry_present(b) | entry_present(a);
    uint32_t reasons = 0;
    bool raced = false, content_unknown = false, meta_unknown = false;
    for (int f = 0; f < F_COUNT; f++) {
        const struct field_change *c = &DIFF_FIELDS[f];
        if (c->cls != CC_FLAG || !(flags & FBIT(f))) continue;
        reasons |= DRBIT(c->reason);
        raced |= c->unknown == US_ALL;
        content_unknown |= c->unknown == US_CONTENT;
        meta_unknown |= c->unknown == US_METADATA;
    }

    if (b->type != a->type) {                               /* rule 2, after rule 1 */
        v->changed = FBIT(F_TYPE);
        v->outcome = raced ? D_UNKNOWN : D_TYPE_CHANGED;
        if (raced) v->reasons = reasons;
        return;
    }
    bool content_diff = false, meta_diff = false;
    for (int f = 0; f < F_COUNT; f++) {
        const enum change_class cls = diff_field_class((enum entry_field)f, a->type);
        if (cls != CC_CONTENT && cls != CC_METADATA && cls != CC_IDENTITY) continue;
        if (differs((enum entry_field)f, b, a) != 1) continue;
        v->changed |= FBIT(f);
        if (cls == CC_CONTENT) content_diff = true;
        else meta_diff = true;
    }
    if (b->type == BELAY_T_REG && b->has_hash != a->has_hash) content_unknown = true;

    if (raced) v->outcome = D_UNKNOWN;                              /* rule 1 */
    else if (content_diff) v->outcome = D_MODIFIED;                 /* rule 3: proof */
    else if (content_unknown) v->outcome = D_UNKNOWN;
    else if (meta_diff) v->outcome = D_METADATA_ONLY;               /* rule 4 */
    else if (meta_unknown) v->outcome = D_UNKNOWN;
    else if (differs(F_CTIME, b, a) == 1) {                         /* rule 5 */
        v->outcome = D_METADATA_ONLY;
        v->changed |= FBIT(F_CTIME);
    } else v->outcome = D_UNCHANGED;                                /* rule 6 */
    if (v->outcome == D_UNKNOWN) v->reasons = reasons;
}

void classify_one(const struct belay_entry *present, bool is_after, enum anc absent,
                  struct verdict *v) {
    memset(v, 0, sizeof *v);
    if (absent == ANC_SEALED) v->reasons = DRBIT(DR_NOT_CAPTURED);
    else if (absent == ANC_INCOMPLETE) v->reasons = DRBIT(DR_LISTING_INCOMPLETE);
    else if (present->raced) v->reasons = DRBIT(DR_RACED);
    v->outcome = v->reasons ? D_UNKNOWN : is_after ? D_ADDED : D_REMOVED;
}
