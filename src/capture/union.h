/*
 *  The host reader's union (test/expect/host-reader.md, "The union"): an
 *  fsops decorator that shows the merged view of a container's overlay
 *  layers, read from the layer directories on the host, so the walker,
 *  consistency, hashing and the store run on it unchanged.
 *
 *  A directory of the merged view is the real fd of its topmost layer's
 *  directory, with the lower layers' directories at that path (its
 *  contributors) kept beside it, by fd number and checked by identity on
 *  every use: a number reused for anything else is never taken for one.
 *  Every entry's stat, content, link target, xattrs and iflags are those of
 *  the layer file that supplies it (H-U7), the overlay's own xattrs left out
 *  (H-U6) and `protattr` added to the iflags (H-U8). Whatever the pin
 *  refuses is kept in `refused`: the capture made over it is discarded.
 */
#ifndef BELAY_CAPTURE_UNION_H
#define BELAY_CAPTURE_UNION_H

#include "capture/fsops.h"

#include <stddef.h>

#define UNION_LAYERS_MAX 128

struct union_fs;

/* The union of `n` layer directories, topmost first (each fd opened by the
 * caller, a directory, held by the union from here on and closed by
 * union_free), their overlay xattrs named under `prefix` ("trusted.overlay."),
 * and the container's other mount points (absolute paths in it, "/" not
 * among them). NULL with belay_err on failure. */
struct union_fs *union_new(const struct fsops *base, const int *layer_fds, size_t n, const char *prefix,
                           const char *const *mounts, size_t nmounts);
void union_free(struct union_fs *u);

/* The table capture uses: the merged view through the union's directories,
 * the real filesystem through any other fd (AT_FDCWD included). */
const struct fsops *union_ops(struct union_fs *u);

/* The scope `path` (absolute, in the container) resolved in the merged view
 * as H-C3 says: each component looked up by the union, a symbolic link
 * followed inside the container's root (an absolute target from that root,
 * `..` at the root staying there), at most 40 links, the result a directory
 * and neither a mount point nor below one. Its directory fd, or -1 with
 * belay_err (BELAY_ERR_INVALID: refused, the reason said). The canonical
 * path it resolved to is written to `canon` (`cap` bytes). */
int union_open_scope(struct union_fs *u, const char *path, char *canon, size_t cap);

/* What the pin refuses, met during the capture ("" when nothing was). */
const char *union_refused(const struct union_fs *u);

#endif
