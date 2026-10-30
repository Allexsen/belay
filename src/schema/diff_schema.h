/*
 *  diff.v1, defined once: the outcomes a path can have, the reasons an
 *  outcome is unknown, how each manifest field takes part in a comparison,
 *  and the lines of the diff.v1 stream. The diff core (src/diff/) decides
 *  outcomes from these tables and nothing else; emit.c writes these names;
 *  the diff.v1 spec's tables are generated from them (tools/gen_schema.c).
 */
#ifndef BELAY_SCHEMA_DIFF_SCHEMA_H
#define BELAY_SCHEMA_DIFF_SCHEMA_H

#include "schema/entry.h"

#define DIFF_VERSION 1

/* One outcome per path. Unchanged is counted, never emitted. Value 0 is no
 * outcome at all: a verdict that was never decided fails, it is never
 * "unchanged" (audit 2026-10, R1). */
enum diff_outcome {
    D_UNDECIDED, D_UNCHANGED, D_ADDED, D_REMOVED, D_MODIFIED, D_TYPE_CHANGED, D_METADATA_ONLY,
    D_UNKNOWN, D_OUTCOME_COUNT
};
#define D_FIRST D_UNCHANGED

/* Why an outcome is unknown: a flag on either side, or what the side that
 * lacks the path says about its ancestor directory. DR_UNSET (0) is a missing
 * cell; DR_NONE is a field that is not a flag. Real reasons start at
 * DR_FIRST. */
enum diff_reason {
    DR_UNSET, DR_NONE,
    DR_RACED, DR_UNSTABLE, DR_UNVERIFIED, DR_UNREADABLE, DR_MOUNT, DR_XATTRS_UNKNOWN,
    DR_IFLAGS_UNKNOWN, DR_LISTING_INCOMPLETE, DR_NOT_CAPTURED,
    DR_COUNT
};
#define DR_FIRST DR_RACED
#define DRBIT(r) (1u << (r))

struct diff_name_def {
    const char *name;
    const char *description;    /* the spec's table (generated) */
};
extern const struct diff_name_def DIFF_OUTCOMES[D_OUTCOME_COUNT];
extern const struct diff_name_def DIFF_REASONS[DR_COUNT];

/*
 *  How a manifest field takes part in a comparison:
 *    CC_KEY       the path: what pairs entries, never compared;
 *    CC_TYPE      a different type is type_changed;
 *    CC_CONTENT   a difference is proof the content changed: modified;
 *    CC_METADATA  a difference with content unchanged: metadata_only;
 *    CC_IDENTITY  the same, but about which object this is;
 *    CC_DEVICE    identity as the entry's relation to its scope root's device
 *                 (same device or not), per side -- never the raw number, which
 *                 overlay, tmpfs and btrfs assign at mount time;
 *    CC_INODE     identity within one device: compared only when the entry's
 *                 dev is the same on both sides, and never across a remount of
 *                 the scope root (ino: a file replaced by rename, same bytes);
 *    CC_CTIME     compared only when nothing else differs: then the change
 *                 is an attribute the manifest does not record;
 *    CC_FLAG      not compared; on either side, makes what `unknown_scope`
 *                 names unknown, for reason `reason`;
 *    CC_INFO      not compared (derived, or bookkeeping).
 *  `types` limits the class to those entry types; elsewhere the field is
 *  CC_INFO (a directory's size and mtime follow its listing, which its
 *  children report). `mount_roots` says whether it is compared on an entry
 *  carrying `mount`. `absent` says what the field's absence on one side means
 *  (test/expect/diff-fields.md pins all of these).
 *
 *  Every cell is explicit: 0 in any column (CC_UNSET, US_UNSET, DR_UNSET,
 *  MR_UNSET, AM_UNSET) is a missing cell, refused by gen_schema and by test_schema, and a classify
 *  that meets one fails the diff. A field that is not a flag says so:
 *  US_NONE, DR_NONE.
 */
enum change_class { CC_UNSET, CC_KEY, CC_TYPE, CC_CONTENT, CC_METADATA, CC_IDENTITY, CC_DEVICE,
                    CC_INODE, CC_CTIME, CC_FLAG, CC_INFO };
enum unknown_scope { US_UNSET, US_NONE, US_CONTENT, US_METADATA, US_ALL };
enum mount_roots { MR_UNSET, MR_COMPARED, MR_NOT_COMPARED };
/* What an optional field's absence on one side means. */
enum absent_means {
    AM_UNSET,
    AM_REQUIRED,         /* never absent */
    AM_FLAG,             /* a flag: absent = not set */
    AM_NONE,             /* absent = none, compared as such */
    AM_NONE_IF_READ,     /* none where the attributes were read; else not compared (unknown) */
    AM_UNKNOWN,          /* absent = could not be read: one side only is unknown */
    AM_WITH_UNVERIFIED,  /* absent only with `unverified`, which makes content unknown */
    AM_ONLY_ON_TYPES,    /* present exactly on its types */
    AM_NA,               /* not compared */
};
struct field_change {
    enum change_class cls;
    unsigned types;             /* TBIT mask */
    enum unknown_scope unknown; /* CC_FLAG */
    enum diff_reason reason;    /* CC_FLAG */
    enum mount_roots mount_roots;
    enum absent_means absent;
    const char *why;            /* the spec's table (generated) */
};
extern const struct field_change DIFF_FIELDS[F_COUNT];

/* The class of field `f` for an entry of type `t`; CC_UNSET when the row's
 * class is missing (the caller fails). */
enum change_class diff_field_class(enum entry_field f, enum belay_entry_type t);

/* The diff.v1 stream: a header line, one record per changed path, a trailer
 * of counts derived from the records. */
enum diff_header_field { DH_VERSION, DH_SCOPES, DH_BEFORE_CREATED, DH_AFTER_CREATED,
                         DH_BEFORE_HASH_MAX, DH_AFTER_HASH_MAX, DH_SCOPE_REMOUNTED,
                         DH_IDENTITY_COMPARED, DH_COUNT };
enum diff_record_field { DF_PATH, DF_OUTCOME, DF_TYPE, DF_TYPE_BEFORE, DF_CHANGED, DF_UNKNOWN,
                         DF_FINDINGS, DF_COUNT };
extern const struct line_field_def DIFF_HEADER_FIELDS[DH_COUNT];
extern const struct line_field_def DIFF_RECORD_FIELDS[DF_COUNT];
/* The trailer: DIFF_TRAILER_END, then one count per outcome, named as the
 * outcome, in enum order, then DIFF_TRAILER_FIELDS: the unchanged directories
 * whose own timestamps differ (decided F5), what the two manifests' trailers
 * said, whether that makes the result provisional, and each input's digest
 * (decided F2; audit L4). The header cannot carry them: it is written before
 * either trailer is read. */
extern const struct line_field_def DIFF_TRAILER_END;
enum diff_trailer_field { DT_DIR_TIMESTAMPS_ONLY, DT_BEFORE_VANISHED, DT_BEFORE_UNSTABLE,
                          DT_BEFORE_RACED, DT_AFTER_VANISHED, DT_AFTER_UNSTABLE, DT_AFTER_RACED,
                          DT_PROVISIONAL, DT_BEFORE_SHA256, DT_AFTER_SHA256, DT_COUNT };
extern const struct line_field_def DIFF_TRAILER_FIELDS[DT_COUNT];

#endif
