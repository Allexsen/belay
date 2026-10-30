#include "diff_schema.h"

const struct diff_name_def DIFF_OUTCOMES[D_OUTCOME_COUNT] = {
    [D_UNCHANGED]     = { "unchanged",
        "Every compared field equal and nothing unknown. Counted in the trailer, never emitted. "
        "A directory whose own timestamps alone differ is `unchanged` (its timestamps are not "
        "compared), and counted again in `dir_timestamps_only`." },
    [D_ADDED]         = { "added", "Present after, absent before, and the absence is known." },
    [D_REMOVED]       = { "removed", "Present before, absent after, and the absence is known." },
    [D_MODIFIED]      = { "modified",
        "Content changed: a content field differs (hash, size, link target, device number)." },
    [D_TYPE_CHANGED]  = { "type_changed", "The entry's type differs." },
    [D_METADATA_ONLY] = { "metadata_only",
        "Content unchanged; metadata or identity differs (`changed` names the fields). A "
        "`ctime_ns` change alone on a regular file or symlink is listed too: an attribute the "
        "manifest does not record changed." },
    [D_UNKNOWN]       = { "unknown",
        "Neither side proves a change, and something prevents proving there was none "
        "(`unknown` names why). Never read as unchanged." },
};

const struct diff_name_def DIFF_REASONS[DR_COUNT] = {
    [DR_RACED]       = { "raced",
        "An entry changed after it was recorded: its recorded fields may not be the state at "
        "the end of its walk, so not even a difference proves a change." },
    [DR_UNSTABLE]    = { "unstable",
        "A file changed while read (no hash), or a directory's listing is incomplete." },
    [DR_UNVERIFIED]  = { "unverified",
        "No hash on one side (larger than its `hash_max_bytes`, or not readable)." },
    [DR_UNREADABLE]  = { "unreadable", "The entry's contents could not be captured." },
    [DR_MOUNT]       = { "mount", "A mount root: contents not captured, by design." },
    [DR_XATTRS_UNKNOWN] = { "xattrs_unknown", "Extended attributes could not be read." },
    [DR_IFLAGS_UNKNOWN] = { "iflags_unknown",
        "Inode flags recorded on one side only: absent means they could not be read." },
    [DR_LISTING_INCOMPLETE] = { "listing_incomplete",
        "Absent on a side whose nearest recorded ancestor directory is `unstable`: possibly "
        "present." },
    [DR_NOT_CAPTURED] = { "not_captured",
        "Absent on a side whose nearest recorded ancestor directory is `unreadable` or a "
        "`mount`: nothing below it was captured." },
};

#define T_REG  TBIT(BELAY_T_REG)
#define T_DIR  TBIT(BELAY_T_DIR)
#define T_LNK  TBIT(BELAY_T_LNK)
#define T_DEV  (TBIT(BELAY_T_BLK) | TBIT(BELAY_T_CHR))

#define C MR_COMPARED
#define NC MR_NOT_COMPARED
const struct field_change DIFF_FIELDS[F_COUNT] = {
    [F_PATH]   = { CC_KEY, T_ALL, US_NONE, DR_NONE, C, AM_REQUIRED, "Pairs the entries." },
    [F_TYPE]   = { CC_TYPE, T_ALL, US_NONE, DR_NONE, C, AM_REQUIRED,
                   "A different type is `type_changed`." },
    [F_MODE]   = { CC_METADATA, T_ALL, US_NONE, DR_NONE, C, AM_REQUIRED,
                   "Permission bits (the type bits are `type`)." },
    [F_UID]    = { CC_METADATA, T_ALL, US_NONE, DR_NONE, C, AM_REQUIRED, "Owner." },
    [F_GID]    = { CC_METADATA, T_ALL, US_NONE, DR_NONE, C, AM_REQUIRED, "Group." },
    [F_SIZE]   = { CC_CONTENT, T_REG | T_LNK, US_NONE, DR_NONE, C, AM_REQUIRED,
                   "Proof of a content change without a hash. A directory's follows its listing." },
    [F_MTIME]  = { CC_METADATA, T_REG | T_LNK, US_NONE, DR_NONE, NC, AM_REQUIRED,
                   "Settable by any writer. Not compared on a directory (it follows the listing), "
                   "on a FIFO, socket or device node, or on a mount root: those stamp themselves "
                   "when used." },
    [F_CTIME]  = { CC_CTIME, T_REG | T_LNK, US_NONE, DR_NONE, NC, AM_REQUIRED,
                   "Moves with every change; reported only when nothing else differs. Not "
                   "compared on a directory (it moves with the listing, which its children "
                   "report: the trailer counts such directories), on a FIFO, socket or device "
                   "node, or on a mount root." },
    [F_INO]    = { CC_INODE, T_ALL, US_NONE, DR_NONE, C, AM_REQUIRED,
                   "Same bytes, new inode: replaced (rename-over, as dpkg installs). Compared only "
                   "when the entry's `dev` is the same on both sides, never across a remount of "
                   "the scope root." },
    [F_DEV]    = { CC_DEVICE, T_ALL, US_NONE, DR_NONE, C, AM_REQUIRED,
                   "Whether the entry is on its scope root's device, per side: a change is a real "
                   "mount change. The raw number is not compared (assigned at mount time)." },
    [F_NLINK]  = { CC_IDENTITY, T_ALL & ~T_DIR, US_NONE, DR_NONE, C, AM_REQUIRED,
                   "Hard links added or removed elsewhere. A directory's counts its subdirectories." },
    [F_IFLAGS] = { CC_METADATA, T_ALL, US_NONE, DR_NONE, C, AM_UNKNOWN,
                   "On one side only it is `unknown` (reason `iflags_unknown`): absent means it "
                   "could not be read." },
    [F_CAPS]   = { CC_METADATA, T_ALL, US_NONE, DR_NONE, C, AM_NONE_IF_READ,
                   "A file capability, added or removed: a privilege change. Compared only where "
                   "the attributes were read (no `xattrs_unknown`, not a mount root)." },
    [F_XATTRS] = { CC_METADATA, T_ALL, US_NONE, DR_NONE, C, AM_NONE_IF_READ,
                   "Compared by the set's digest (each element is `name=sha256(value)`), so an "
                   "inline set and a digest-only set compare. Only where the attributes were read." },
    [F_XATTRS_SHA256] = { CC_INFO, T_ALL, US_NONE, DR_NONE, NC, AM_NONE_IF_READ,
                   "Compared as `xattrs`." },
    [F_XATTRS_UNKNOWN] = { CC_FLAG, T_ALL, US_METADATA, DR_XATTRS_UNKNOWN, C, AM_FLAG,
                   "Metadata unknown unless another metadata field proves a change." },
    [F_SHA256] = { CC_CONTENT, T_REG, US_NONE, DR_NONE, C, AM_WITH_UNVERIFIED, "Content digest." },
    [F_UNVERIFIED] = { CC_FLAG, T_ALL, US_CONTENT, DR_UNVERIFIED, C, AM_FLAG,
                   "Content unknown unless size proves a change (different hash limits included)." },
    [F_UNSTABLE] = { CC_FLAG, T_ALL, US_CONTENT, DR_UNSTABLE, C, AM_FLAG,
                   "Content (a directory's listing) unknown unless another content field proves "
                   "a change." },
    [F_RDEV]   = { CC_CONTENT, T_DEV, US_NONE, DR_NONE, C, AM_ONLY_ON_TYPES,
                   "Which device the node refers to." },
    [F_LINK_TARGET] = { CC_CONTENT, T_LNK, US_NONE, DR_NONE, C, AM_ONLY_ON_TYPES,
                   "Compared only when neither side is `unreadable` (empty means unknown)." },
    [F_TARGET_OUTSIDE] = { CC_INFO, T_ALL, US_NONE, DR_NONE, NC, AM_NA,
                   "Derived from the target; advisory." },
    [F_STORED] = { CC_INFO, T_ALL, US_NONE, DR_NONE, NC, AM_NONE, "Bookkeeping: equal to `sha256`." },
    [F_MOUNT]  = { CC_FLAG, T_ALL, US_CONTENT, DR_MOUNT, C, AM_FLAG, "Contents not captured." },
    [F_UNREADABLE] = { CC_FLAG, T_ALL, US_CONTENT, DR_UNREADABLE, C, AM_FLAG,
                   "Contents unknown unless another content field proves a change." },
    [F_RACED]  = { CC_FLAG, T_ALL, US_ALL, DR_RACED, C, AM_FLAG,
                   "Everything unknown: the recorded fields may not be the state at the end of "
                   "the walk, so no difference is proof." },
};
#undef C
#undef NC

enum change_class diff_field_class(enum entry_field f, enum belay_entry_type t) {
    const struct field_change *c = &DIFF_FIELDS[f];
    if (c->cls == CC_UNSET) return CC_UNSET;            /* a missing row: never "not compared" */
    return (c->types & TBIT(t)) ? c->cls : CC_INFO;
}

const struct line_field_def DIFF_HEADER_FIELDS[DH_COUNT] = {
    [DH_VERSION] = { "belay_diff", NULL, "int",
        "Format version. A reader MUST reject a version it does not know." },
    [DH_SCOPES] = { "scopes", "scopes_b64", "array",
        "The scope both manifests record; manifests of different scopes are never compared. "
        "Not valid UTF-8: `scopes_b64`." },
    [DH_BEFORE_CREATED] = { "before_created_ns", NULL, "int", "The earlier manifest's `created_ns`." },
    [DH_AFTER_CREATED] = { "after_created_ns", NULL, "int", "The later manifest's `created_ns`." },
    [DH_BEFORE_HASH_MAX] = { "before_hash_max_bytes", NULL, "int",
        "The earlier manifest's hash limit. When the two differ, a file hashed on one side and "
        "not the other is `unknown` unless its size proves a change." },
    [DH_AFTER_HASH_MAX] = { "after_hash_max_bytes", NULL, "int", "The later manifest's hash limit." },
    [DH_SCOPE_REMOUNTED] = { "scope_remounted", NULL, "bool",
        "The scope root's `dev` differs between the manifests: it was remounted, and devices were "
        "numbered anew." },
    [DH_IDENTITY_COMPARED] = { "identity_compared", NULL, "bool",
        "Whether `ino` was compared: never across a remount of the scope root, since an inode "
        "number means something only within one device. Content still compares by hash." },
};

const struct line_field_def DIFF_RECORD_FIELDS[DF_COUNT] = {
    [DF_PATH] = { "path", "path_b64", "string",
        "As in the manifest: relative to the scope, base64 when not valid UTF-8." },
    [DF_OUTCOME] = { "outcome", NULL, "string", "One of the outcomes below, never `unchanged`." },
    [DF_TYPE] = { "type", NULL, "string", "The entry's type after (before, for `removed`)." },
    [DF_TYPE_BEFORE] = { "type_before", NULL, "string", "For `type_changed` only: the type before." },
    [DF_CHANGED] = { "changed", NULL, "array",
        "The compared fields that differ, in the manifest's field order; absent when none." },
    [DF_UNKNOWN] = { "unknown", NULL, "array",
        "For `unknown` only: the reasons, in the order of the reasons table." },
    [DF_FINDINGS] = { "findings", NULL, "array",
        "What an interpreter explained about the change, one string each; absent when none. "
        "Annotations only: an interpreter never sets or changes the outcome." },
};

const struct line_field_def DIFF_TRAILER_END = { "belay_diff_end", NULL, "int",
    "Number of records emitted. Then one count per outcome, named as the outcome, unchanged "
    "included." };

const struct line_field_def DIFF_TRAILER_FIELDS[DT_COUNT] = {
    [DT_DIR_TIMESTAMPS_ONLY] = { "dir_timestamps_only", NULL, "int",
        "Directories counted in `unchanged` whose `mtime_ns` or `ctime_ns` differs: a "
        "directory's own timestamps move with every name added, removed or renamed in it, which "
        "the records of its children report." },
    [DT_BEFORE_VANISHED] = { "before_vanished", NULL, "int",
        "The earlier manifest's `vanished`: entries gone while its tree was walked." },
    [DT_BEFORE_UNSTABLE] = { "before_unstable", NULL, "int", "The earlier manifest's `unstable`." },
    [DT_BEFORE_RACED]    = { "before_raced", NULL, "int", "The earlier manifest's `raced`." },
    [DT_AFTER_VANISHED]  = { "after_vanished", NULL, "int", "The later manifest's `vanished`." },
    [DT_AFTER_UNSTABLE]  = { "after_unstable", NULL, "int", "The later manifest's `unstable`." },
    [DT_AFTER_RACED]     = { "after_raced", NULL, "int", "The later manifest's `raced`." },
    [DT_PROVISIONAL]     = { "provisional", NULL, "bool",
        "Any of the six counts above is not 0: a tree changed while it was walked, so the result "
        "is provisional (manifest-v1, obligations on a consumer). The records name each flagged "
        "path; `vanished` paths have none." },
    [DT_BEFORE_SHA256]   = { "before_sha256", NULL, "string",
        "The sha256 of the earlier manifest's bytes as this diff read them." },
    [DT_AFTER_SHA256]    = { "after_sha256", NULL, "string",
        "The sha256 of the later manifest's bytes as this diff read them." },
};
