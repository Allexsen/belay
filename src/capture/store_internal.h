/*
 *  The store's internal entry point: belay_store_open with an explicit
 *  platform adapter (fsops.h), which a commit syncs the store's directories
 *  through. Capture passes its own, so a test that decorates it sees them.
 */
#ifndef BELAY_CAPTURE_STORE_INTERNAL_H
#define BELAY_CAPTURE_STORE_INTERNAL_H

#include "belay/store.h"
#include "fsops.h"

int store_open(const struct fsops *ops, const char *dir, struct belay_store **out);
/* Is object `hex` there: a regular file (no link followed, no FIFO opened)
 * of `size` bytes? Its bytes are verified whenever it is read (content.c);
 * this is for mark, which records a copy it does not make again. */
bool store_has(struct belay_store *s, const char *hex, uint64_t size);

#endif
