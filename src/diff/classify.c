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
     * Under xattrs_unknown they are not compared, and the flag makes the
     * metadata unknown (rule 4). A mount root's are never read: the table
     * does not compare them there (pin, "on mount roots"). */
    const bool attrs_read = !b->xattrs_unknown && !a->xattrs_unknown;
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
        if (b->writer_open || a->writer_open) return NOT_COMPARED;     /* it may be torn (V4-D2) */
        /* A keyed hash compares with a keyed hash of the same key (V5-D3). */
        if ((b->sealed || a->sealed) && !(b->sealed && a->sealed && ctx->sealed_comparable)) return NOT_COMPARED;
        return b->has_hash && a->has_hash ? strcmp(b->sha256_hex, a->sha256_hex) != 0 : -1;
    case F_RDEV:   return b->has_rdev && a->has_rdev ? b->rdev != a->rdev : -1;
    case F_LINK_TARGET:
        if (b->unreadable || a->unreadable || !b->has_link_target || !a->has_link_target) return -1;
        return b->link_target_len != a->link_target_len ||
               memcmp(b->link_target, a->link_target, b->link_target_len) != 0;
    case F_PATH: case F_TYPE: case F_XATTRS_SHA256: case F_XATTRS_UNKNOWN: case F_UNVERIFIED:
    case F_UNSTABLE: case F_TARGET_OUTSIDE: case F_STORED: case F_MOUNT: case F_UNREADABLE:
    case F_RACED: case F_WRITER_OPEN: case F_NOT_READ: case F_PARTIAL: case F_META: case F_SEALED:
        return NOT_COMPARED;
    case F_COUNT:
        break;
    }
    return NO_ANSWER;
}

/* Why one side's content was not read, for a regular file (pin O9).
 * `unverified` beside unstable, unreadable or mount is there because of
 * them and adds nothing; alone it is the hash limit. */
static uint32_t not_read(const struct belay_entry *e) {
    const uint32_t r = (e->unstable ? DRBIT(DR_UNSTABLE) : 0) | (e->unreadable ? DRBIT(DR_UNREADABLE) : 0) |
                       (e->is_mount ? DRBIT(DR_MOUNT) : 0);
    return r != 0 ? r : e->unverified ? DRBIT(DR_UNVERIFIED) : e->meta ? DRBIT(DR_NOT_READ) : 0;   /* v5: O9 */
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
    /* A mounted regular file is unverified because it is never read: on that
     * side `mount` is the reason (pin O8). On a side without `mount` it is a
     * reason of its own. */
    if (!(b->unverified && !b->is_mount) && !(a->unverified && !a->is_mount))
        reasons &= ~DRBIT(DR_UNVERIFIED);
    /*
     *  Manifest v5's flags (CC_RULE: manifest-v5.md V5-D1 to V5-D4). Each
     *  gives its reason whenever the outcome is unknown; what it makes
     *  unknown depends on the other side:
     *    meta      on one side, the content (V5-D2, as O1 for unverified); on
     *              both, nothing by itself -- see below (V5-D1);
     *    sealed    the content, unless both are sealed under one key (V5-D3);
     *    not_read  a directory: decided here, after the type (V5-D4).
     */
    const bool meta_both = b->meta && a->meta;
    if (b->meta || a->meta) {
        reasons |= DRBIT(DR_NOT_READ);
        content_unknown |= !meta_both;
    }
    if ((b->sealed || a->sealed) && !(b->sealed && a->sealed && ctx->sealed_comparable)) {
        reasons |= DRBIT(DR_SEALED_KEY);
        content_unknown = true;
    }
    if (b->not_read || a->not_read) reasons |= DRBIT(DR_NOT_READ);

    if (b->type != a->type) {                               /* rule 2, after rule 1 */
        v->changed = FBIT(F_TYPE);
        v->outcome = raced ? D_UNKNOWN : D_TYPE_CHANGED;
        if (raced) v->reasons = reasons;
        return 0;
    }
    /* V5-D4: a directory not entered is compared by its type (above), mode
     * and owner, and by nothing else: on both sides and equal, no record; on
     * one side only, or differing, unknown. (Both are directories here: the
     * flag is a directory's and the types are equal.) */
    if (b->not_read || a->not_read) {
        static const enum entry_field OWN[] = { F_MODE, F_UID, F_GID };
        for (size_t i = 0; i < sizeof OWN / sizeof OWN[0]; i++)
            if (differs(ctx, OWN[i], b, a) == 1) v->changed |= FBIT(OWN[i]);
        v->outcome = !raced && b->not_read && a->not_read && v->changed == 0 ? D_UNCHANGED : D_UNKNOWN;
        if (v->outcome == D_UNKNOWN) v->reasons = reasons;
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
    /* V5-D1: neither side read the content, so nothing shows it intact: any
     * difference at all -- a field's, or the ctime alone -- is unknown, never
     * metadata_only (a same-size rewrite moves the same fields). */
    else if (meta_both && (meta_diff || meta_unknown || differs(ctx, F_CTIME, b, a) == 1)) {
        v->outcome = D_UNKNOWN;
        if (!meta_diff) v->changed |= differs(ctx, F_CTIME, b, a) == 1 ? FBIT(F_CTIME) : 0;
    }
    else if (meta_diff) v->outcome = D_METADATA_ONLY;               /* rule 4 */
    else if (meta_unknown) v->outcome = D_UNKNOWN;
    /* A mount root never gets here: its flag made the content unknown. */
    else if (diff_field_class(F_CTIME, a->type) == CC_CTIME &&                  /* rule 5 */
             differs(ctx, F_CTIME, b, a) == 1) {
        v->outcome = D_METADATA_ONLY;
        v->changed |= FBIT(F_CTIME);
    } else {
        v->outcome = D_UNCHANGED;                                   /* rule 6 */
        /* A directory's own timestamps move with its listing, which its
         * children's records report: not compared, only counted (F5). */
        v->dir_timestamps = a->type == BELAY_T_DIR && (differs(ctx, F_MTIME, b, a) == 1 ||
                                                       differs(ctx, F_CTIME, b, a) == 1);
    }
    if (v->outcome == D_UNKNOWN) v->reasons = reasons;
    /* A change proved by what was compared, of a file not read: said (O9). */
    if ((v->outcome == D_MODIFIED || v->outcome == D_METADATA_ONLY) && a->type == BELAY_T_REG)
        v->not_read = not_read(b) | not_read(a);
    BELAY_CHECK(v->outcome != D_UNDECIDED, -1);
    return 0;
}

int classify_one(const struct belay_entry *present, bool is_after, enum anc absent,
                 struct verdict *v) {
    memset(v, 0, sizeof *v);                                /* D_UNDECIDED */
    BELAY_CHECK(absent == ANC_NONE || absent == ANC_INCOMPLETE || absent == ANC_SEALED ||
                absent == ANC_RACED, -1);
    if (absent == ANC_SEALED) v->reasons = DRBIT(DR_NOT_CAPTURED);
    else if (absent == ANC_INCOMPLETE) v->reasons = DRBIT(DR_LISTING_INCOMPLETE);
    else if (absent == ANC_RACED) v->reasons = DRBIT(DR_RACED);
    else {                                  /* no earlier rule decided: the entry's own (V4-D3) */
        if (present->raced) v->reasons |= DRBIT(DR_RACED);
        if (present->writer_open) v->reasons |= DRBIT(DR_WRITER_OPEN);
    }
    v->outcome = v->reasons ? D_UNKNOWN : is_after ? D_ADDED : D_REMOVED;
    /* An added entry says what of it was not read (pin O10): a file's
     * content, as O9 has it for a side; a directory's listing. */
    if (v->outcome == D_ADDED && present->type == BELAY_T_REG) v->not_read = not_read(present);
    if (v->outcome == D_ADDED && present->type == BELAY_T_DIR)
        v->not_read = (present->unreadable ? DRBIT(DR_UNREADABLE) : 0) | (present->is_mount ? DRBIT(DR_MOUNT) : 0);
    return 0;
}
