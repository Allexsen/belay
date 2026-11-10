#ifndef BELAY_WATCH_WATCH_CMD_H
#define BELAY_WATCH_WATCH_CMD_H

#include <stddef.h>

#include "watch/watch.h"

/* The full receipt of a directory, newest step first, appended to `out`:
 * each step's section as `belay diff --all` printed it, or the line that
 * says it is missing (TL-13). Read without the lock. 0 with the number of
 * steps shown; -1 with belay_err. */
int watch_receipt(const char *scope, struct wsb *out, size_t *n_steps);

/* That text as a file in the record, its own path on its second line; the
 * path into `path`. 0, or -1 with belay_err. */
int watch_receipt_file(const char *scope, const struct wsb *text, char *path, size_t cap);

#endif
