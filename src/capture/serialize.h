/* One entry as one canonical NDJSON line. */
#ifndef BELAY_CAPTURE_SERIALIZE_H
#define BELAY_CAPTURE_SERIALIZE_H

#include "belay/manifest.h"
#include "schema/entry.h"

#include <stddef.h>

/* Writes the line, newline included, into buf. 0, or -1 if it does not fit. */
int entry_serialize(const struct belay_entry *e, char *buf, size_t cap, size_t *len);

/* One field of `e`, key included, appended at buf + *w: exactly as
 * entry_serialize writes it (the base64 spelling for bytes that are not
 * UTF-8). 0, or -1 with belay_err RANGE when it does not fit. diff.v1's
 * before/after values (test/expect/diff-values.md) are written with it. */
int entry_put_field(const struct belay_entry *e, enum entry_field f, char *buf, size_t cap, size_t *w);

#endif
