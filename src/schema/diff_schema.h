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

/* One outcome per path. Unchanged is counted, never emitted. */
enum diff_outcome {
    D_UNCHANGED, D_ADDED, D_REMOVED, D_MODIFIED, D_TYPE_CHANGED, D_METADATA_ONLY, D_UNKNOWN,
    D_OUTCOME_COUNT
};

/* Why an outcome is unknown: a flag on either side, or what the side that
 * lacks the path says about its ancestor directory. */
enum diff_reason {
    DR_RACED, DR_UNSTABLE, DR_UNVERIFIED, DR_UNREADABLE, DR_MOUNT, DR_XATTRS_UNKNOWN,
    DR_LISTING_INCOMPLETE, DR_NOT_CAPTURED,
    DR_COUNT
};
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
 *    CC_IDENTITY  the same, but about which object this is (ino: a file
 *                 replaced by rename with the same bytes);
 *    CC_CTIME     compared only when nothing else differs: then the change
 *                 is an attribute the manifest does not record;
 *    CC_FLAG      not compared; on either side, makes what `unknown_scope`
 *                 names unknown, for reason `reason`;
 *    CC_INFO      not compared (derived, or bookkeeping).
 *  `types` limits the class to those entry types; elsewhere the field is
 *  CC_INFO (a directory's size and mtime follow its listing, which its
 *  children report).
 */
enum change_class { CC_KEY, CC_TYPE, CC_CONTENT, CC_METADATA, CC_IDENTITY, CC_CTIME, CC_FLAG,
                    CC_INFO };
enum unknown_scope { US_NONE, US_CONTENT, US_METADATA, US_ALL };
struct field_change {
    enum change_class cls;
    unsigned types;             /* TBIT mask */
    enum unknown_scope unknown; /* CC_FLAG */
    enum diff_reason reason;    /* CC_FLAG */
    const char *why;            /* the spec's table (generated) */
};
extern const struct field_change DIFF_FIELDS[F_COUNT];

/* The class of field `f` for an entry of type `t`. */
enum change_class diff_field_class(enum entry_field f, enum belay_entry_type t);

/* The diff.v1 stream: a header line, one record per changed path, a trailer
 * of counts derived from the records. */
enum diff_header_field { DH_VERSION, DH_SCOPES, DH_BEFORE_CREATED, DH_AFTER_CREATED,
                         DH_BEFORE_HASH_MAX, DH_AFTER_HASH_MAX, DH_COUNT };
enum diff_record_field { DF_PATH, DF_OUTCOME, DF_TYPE, DF_TYPE_BEFORE, DF_CHANGED, DF_UNKNOWN,
                         DF_FINDINGS, DF_COUNT };
extern const struct line_field_def DIFF_HEADER_FIELDS[DH_COUNT];
extern const struct line_field_def DIFF_RECORD_FIELDS[DF_COUNT];
/* The trailer: DIFF_TRAILER_END, then one count per outcome, named as the
 * outcome, in enum order. */
extern const struct line_field_def DIFF_TRAILER_END;

#endif
