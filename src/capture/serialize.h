/* One entry as one canonical NDJSON line. */
#ifndef BELAY_CAPTURE_SERIALIZE_H
#define BELAY_CAPTURE_SERIALIZE_H

#include "belay/manifest.h"

#include <stddef.h>

/* Writes the line, newline included, into buf. 0, or -1 if it does not fit. */
int entry_serialize(const struct belay_entry *e, char *buf, size_t cap, size_t *len);

#endif
