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
#include "schema/entry.h"
#include "capture/manifest_lex.h"

#include <stdint.h>

/* The order fields are decoded in, which decides which error a line with
 * several bad fields reports. Kept from the reader before this structure,
 * so no message changed; every schema field appears exactly once (tested). */
extern const enum entry_field DECODE_ORDER[F_COUNT];

/* An entry line: canonical key order, every field, then the schema's rules.
 * 0, or -1 with the error set. */
int decode_entry(const struct obj *o, struct belay_entry *e);

/* The header line, version 1 or 2, each by its own key set; a v2 header's
 * `excluded` decoded into `excluded` (BELAY_EXCLUDED_MAX), which
 * h->excluded then points at. */
int decode_header(const struct obj *o, struct belay_manifest_header *h, struct belay_excluded *excluded);

/* The trailer line's values, indexed by enum trailer_field; for version 2
 * also `trusted`, `reference` and `read_all` into *t. */
int decode_trailer(const struct obj *o, uint64_t version, uint64_t v[TR_COUNT], struct belay_manifest_stats *t);

#endif
