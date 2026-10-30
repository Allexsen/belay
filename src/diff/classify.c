#include "classify.h"

#include "util/check.h"

#include <string.h>

/* differs(): 1 yes, 0 no, -1 not compared (a side does not know it), -3 not
 * compared because one side lacks a field whose absence means "could not be
 * read" (metadata unknown). */
#define NOT_COMPARED (-1)
#define NO_ANSWER    (-2)   /* a field with no case: an internal error, never "not compared" */
#define ONE_SIDE     (-3)

/* Whether field `f` differs between the two sides. Every case of enum
 * entry_field, and nothing after the switch that could pass for an answer. */
static int differs(const struct diff_ctx *ctx, enum entry_field f, const struct belay_entry *b,
                   const struct belay_entry *a) {
    /* Extended attributes were read on both sides: none recorded means none.
     * Under xattrs_unknown, or on a mount root (never read), they are not
     * compared, and xattrs_unknown makes the metadata unknown (rule 4). */
    const bool attrs_read = !b->xattrs_unknown && !a->xattrs_unknown && !b->is_mount && !a->is_mount;
    switch (f) {
    case F_MODE:   return b->mode != a->mode;
    case F_UID:    return b->uid != a->uid;
    case F_GID:    return b->gid != a->gid;
    case F_SIZE:   return b->size != a->size;
    case F_MTIME:  return b->mtime_ns != a->mtime_ns;
    case F_CTIME:  return b->ctime_ns != a->ctime_ns;
    case F_INO:
        /* An inode number means something within one device only. */
        if (ctx->remounted || b->dev != a->dev) return NOT_COMPARED;
        return b->ino != a->ino;
    case F_DEV:
        /* The relation to the scope root's device, never the raw number. */
        return (b->dev == ctx->root_dev_before) != (a->dev == ctx->root_dev_after);
    case F_NLINK:  return b->nlink != a->nlink;
    case F_IFLAGS:
        if (b->has_iflags && a->has_iflags) return b->iflags != a->iflags;
        return b->has_iflags == a->has_iflags ? 0 : ONE_SIDE;
    case F_CAPS:
        if (!attrs_read) return NOT_COMPARED;
        return b->has_caps != a->has_caps || (b->has_caps && strcmp(b->caps_hex, a->caps_hex) != 0);
    case F_XATTRS:
        if (!attrs_read) return NOT_COMPARED;
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
    case F_RACED:
        return NOT_COMPARED;
    case F_COUNT:
        break;
    }
    return NO_ANSWER;
}

int classify_both(const struct diff_ctx *ctx, const struct belay_entry *b,
                  const struct belay_entry *a, struct verdict *v) {
    memset(v, 0, sizeof *v);                                /* D_UNDECIDED */
    /* Flags on either side: their reasons, and what they make unknown. */
    const uint32_t flags = entry_present(b) | entry_present(a);
    uint32_t reasons = 0;
    bool raced = false, content_unknown = false, meta_unknown = false;
    for (int f = 0; f < F_COUNT; f++) {
        const struct field_change *c = &DIFF_FIELDS[f];
        BELAY_CHECK(c->cls != CC_UNSET && c->unknown != US_UNSET && c->reason != DR_UNSET &&
                    c->mount_roots != MR_UNSET && c->absent != AM_UNSET, -1);
        if (c->cls != CC_FLAG || !(flags & FBIT(f))) continue;
        BELAY_CHECK(c->reason >= DR_FIRST && c->reason < DR_COUNT && c->unknown != US_NONE, -1);
        reasons |= DRBIT(c->reason);
        raced |= c->unknown == US_ALL;
        content_unknown |= c->unknown == US_CONTENT;
        meta_unknown |= c->unknown == US_METADATA;
    }

    if (b->type != a->type) {                               /* rule 2, after rule 1 */
        v->changed = FBIT(F_TYPE);
        v->outcome = raced ? D_UNKNOWN : D_TYPE_CHANGED;
        if (raced) v->reasons = reasons;
        return 0;
    }
    /* A mount root's own timestamps belong to the mounted filesystem. */
    const bool mount_root = b->is_mount || a->is_mount;
    bool content_diff = false, meta_diff = false;
    for (int f = 0; f < F_COUNT; f++) {
        const enum change_class cls = diff_field_class((enum entry_field)f, a->type);
        BELAY_CHECK(cls != CC_UNSET, -1);
        if (cls != CC_CONTENT && cls != CC_METADATA && cls != CC_IDENTITY && cls != CC_DEVICE &&
            cls != CC_INODE)
            continue;
        if (mount_root && DIFF_FIELDS[f].mount_roots == MR_NOT_COMPARED) continue;
        const int d = differs(ctx, (enum entry_field)f, b, a);
        BELAY_CHECK(d != NO_ANSWER, -1);
        if (d == ONE_SIDE) {                       /* absent = could not be read: rule 4 */
            BELAY_CHECK(DIFF_FIELDS[f].absent == AM_UNKNOWN, -1);
            meta_unknown = true;
            reasons |= DRBIT(DR_IFLAGS_UNKNOWN);
            continue;
        }
        if (d != 1) continue;
        v->changed |= FBIT(f);
        if (cls == CC_CONTENT) content_diff = true;
        else meta_diff = true;
    }
    /* A regular file without a hash carries unverified (entry.c, rule 5), so
     * a hash on one side only is content_unknown already. */

    if (raced) v->outcome = D_UNKNOWN;                              /* rule 1 */
    else if (content_diff) v->outcome = D_MODIFIED;                 /* rule 3: proof */
    else if (content_unknown) v->outcome = D_UNKNOWN;
    else if (meta_diff) v->outcome = D_METADATA_ONLY;               /* rule 4 */
    else if (meta_unknown) v->outcome = D_UNKNOWN;
    else if (diff_field_class(F_CTIME, a->type) == CC_CTIME && !mount_root &&   /* rule 5 */
             differs(ctx, F_CTIME, b, a) == 1) {
        v->outcome = D_METADATA_ONLY;
        v->changed |= FBIT(F_CTIME);
    } else v->outcome = D_UNCHANGED;                                /* rule 6 */
    if (v->outcome == D_UNKNOWN) v->reasons = reasons;
    BELAY_CHECK(v->outcome != D_UNDECIDED, -1);
    return 0;
}

int classify_one(const struct belay_entry *present, bool is_after, enum anc absent,
                 struct verdict *v) {
    memset(v, 0, sizeof *v);                                /* D_UNDECIDED */
    BELAY_CHECK(absent == ANC_NONE || absent == ANC_INCOMPLETE || absent == ANC_SEALED, -1);
    if (absent == ANC_SEALED) v->reasons = DRBIT(DR_NOT_CAPTURED);
    else if (absent == ANC_INCOMPLETE) v->reasons = DRBIT(DR_LISTING_INCOMPLETE);
    else if (present->raced) v->reasons = DRBIT(DR_RACED);
    v->outcome = v->reasons ? D_UNKNOWN : is_after ? D_ADDED : D_REMOVED;
    return 0;
}
