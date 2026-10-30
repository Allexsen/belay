/*
 *  The manifest's decoding layer: objects to fields. Each schema field is
 *  read by one case of decode_field -- the mirror of serialize.c's
 *  put_field -- with the key names from ENTRY_FIELDS; the header and trailer
 *  have their own decoders. What the decoded values must satisfy together is
 *  entry.c's business (entry_check), not this file's.
 */
#ifndef BELAY_CAPTURE_MANIFEST_DECODE_H
#define BELAY_CAPTURE_MANIFEST_DECODE_H

#include "belay/manifest.h"
#include "capture/entry.h"
#include "capture/manifest_lex.h"

#include <stdint.h>

/* The order fields are decoded in, which decides which error a line with
 * several bad fields reports. Kept from the reader before this structure,
 * so no message changed; every schema field appears exactly once (tested). */
extern const enum entry_field DECODE_ORDER[F_COUNT];

/* An entry line: canonical key order, every field, then the schema's rules.
 * 0, or -1 with the error set. */
int decode_entry(const struct obj *o, struct belay_entry *e);

/* The header line. */
int decode_header(const struct obj *o, struct belay_manifest_header *h);

/* The trailer line's six values, in order: entries, vanished, unreadable,
 * unstable, mounts, raced. */
int decode_trailer(const struct obj *o, uint64_t v[6]);

#endif
