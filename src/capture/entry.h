/*
 *  The manifest entry's schema, defined once: its fields in canonical order,
 *  which entry types may carry each, and the rules that combinations of
 *  fields must obey. The writer checks every entry against it before
 *  emitting; the reader checks every entry it parses; the serializer emits in
 *  its order; the spec's field-rules section and the fuzz target's invariants
 *  are generated from it (tools/gen_schema.c). One copy of the rules.
 *
 *  entry_pack / entry_unpack: a compact binary form of an entry, for the
 *  sorter's records (the path travels as the record's key). Only fields that
 *  are present are packed; variable fields carry their length.
 */
#ifndef BELAY_CAPTURE_ENTRY_H
#define BELAY_CAPTURE_ENTRY_H

#include "belay/manifest.h"

#include <stddef.h>
#include <stdint.h>

#define ENTRY_PATH_MAX   4095u
#define ENTRY_PACK_MAX   (128u + 4096u + 8193u + 129u + 3u * 64u)

/* Fields, in canonical order. path and link_target have a base64 spelling
 * (path_b64, link_target_b64), used for bytes that are not valid UTF-8. */
enum entry_field {
    F_PATH, F_TYPE, F_MODE, F_UID, F_GID, F_SIZE, F_MTIME, F_CTIME, F_INO, F_DEV, F_NLINK,
    F_IFLAGS, F_CAPS, F_XATTRS, F_XATTRS_SHA256, F_XATTRS_UNKNOWN,
    F_SHA256, F_UNVERIFIED, F_UNSTABLE, F_RDEV, F_LINK_TARGET, F_TARGET_OUTSIDE,
    F_STORED, F_MOUNT, F_UNREADABLE, F_RACED,
    F_COUNT
};
#define FBIT(f) (1u << (f))

/* Entry types: the manifest's spelling and the S_IFMT bits `mode` carries
 * (the same values on Linux and macOS). */
#define ENTRY_TYPE_COUNT (BELAY_T_CHR + 1)
#define ENTRY_IFMT       0170000u      /* the type bits of `mode` */
struct entry_type_def {
    const char *name;
    uint32_t ifmt;
};
extern const struct entry_type_def ENTRY_TYPES[ENTRY_TYPE_COUNT];

/* Entry types as a bitmask: TBIT(BELAY_T_REG) ... */
#define TBIT(t)   (1u << (t))
#define T_ALL     (TBIT(BELAY_T_REG) | TBIT(BELAY_T_DIR) | TBIT(BELAY_T_LNK) | TBIT(BELAY_T_FIFO) | \
                   TBIT(BELAY_T_SOCK) | TBIT(BELAY_T_BLK) | TBIT(BELAY_T_CHR))

struct entry_field_def {
    const char *name;
    const char *alt;            /* base64 spelling, or NULL */
    const char *kind;           /* "string", "int", "bool", "array" */
    bool required;              /* on every entry */
    const char *description;    /* the spec's Entries table (generated) */
};
extern const struct entry_field_def ENTRY_FIELDS[F_COUNT];

enum entry_rule_kind {
    R_FORBID,       /* none of `a` */
    R_IMPLIES,      /* any of `a` requires any of `b` */
    R_EXCLUSIVE,    /* at most one of `a` */
    R_EXACTLY_ONE,  /* exactly one of `a` (msg: both, msg2: neither) */
    R_EXCLUDES,     /* any of `a` excludes all of `b` */
    R_PRESENT_IFF,  /* `a` present exactly on `types` (msg: missing, msg2: extra) */
    R_CHECK,        /* check(e) is true: violated */
};

struct entry_rule {
    enum entry_rule_kind kind;
    unsigned types;             /* entry types the rule applies to (all, for PRESENT_IFF) */
    uint32_t a, b;              /* FBIT masks */
    bool (*check)(const struct belay_entry *e);
    const char *msg, *msg2;     /* the reader's error messages */
    const char *doc;            /* for the generated spec */
};
extern const struct entry_rule ENTRY_RULES[];
extern const size_t ENTRY_RULE_COUNT;

/* Which fields `e` carries, as FBIT bits. */
uint32_t entry_present(const struct belay_entry *e);

/* Checks `e` (carrying the fields `present`) against every rule, in order.
 * 0, or -1 with belay_err set to the first rule violated. */
int entry_check(const struct belay_entry *e, uint32_t present);

/* Rules that need the manifest's header (scope, hash limit): check returns
 * the reader's message, or NULL. */
struct entry_header_rule {
    const char *(*check)(const struct belay_manifest_header *h, const struct belay_entry *e);
    const char *doc;            /* for the generated spec */
};
extern const struct entry_header_rule ENTRY_HEADER_RULES[];
extern const size_t ENTRY_HEADER_RULE_COUNT;

int entry_check_header(const struct belay_manifest_header *h, const struct belay_entry *e);

/* Bytes written, or 0 when the entry does not fit `cap`. */
size_t entry_pack(const struct belay_entry *e, unsigned char *buf, size_t cap);

/* Rebuilds `e` from a packed form and its path. 0, or -1 if malformed. */
int entry_unpack(const unsigned char *buf, size_t len, const unsigned char *path,
                 size_t path_len, struct belay_entry *e);

#endif
