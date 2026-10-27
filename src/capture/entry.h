/*
 *  The manifest entry, as capture handles it.
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

/* Bytes written, or 0 when the entry does not fit `cap`. */
size_t entry_pack(const struct belay_entry *e, unsigned char *buf, size_t cap);

/* Rebuilds `e` from a packed form and its path. 0, or -1 if malformed. */
int entry_unpack(const unsigned char *buf, size_t len, const unsigned char *path,
                 size_t path_len, struct belay_entry *e);

#endif
