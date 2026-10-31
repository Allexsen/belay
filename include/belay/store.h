/*
 *  Content store (M1 step 2.4).
 *
 *  BLAST RADIUS: copies the user's files into belay's own state directory.
 *  It never writes anywhere else, and every write follows the §5.1.1 rule:
 *  relative to a held directory fd, O_NOFOLLOW, O_EXCL for anything created.
 *
 *  Layout: <dir>/<first 2 hex>/<remaining 62 hex>, named by the content's
 *  sha256 (git's fan-out, so no directory holds more than 1/256th of the
 *  objects). Objects are 0600: a stored copy of a private file must not become
 *  readable by others. Staging files live in <dir> as ".tmp-*" and are renamed
 *  into place.
 *
 *  INTEGRITY IS VERIFIED ON READ, not trusted on write. A commit whose object
 *  already exists keeps the existing file (dedup without rewriting) unless its
 *  size is not the staged size -- a copy a crash emptied or cut short, which
 *  is replaced -- and
 *  objects are not fsynced individually -- only the directories that hold
 *  their names are, by belay_store_sync -- so an object may be stale,
 *  planted or truncated by a crash (manifest-v1, "What survives a power
 *  loss"; on macOS fsync does not reach the disk, and the last sync is a
 *  barrier that orders the names before the manifest). belay_store_verify() hashes an object and checks
 *  it against its own name; every consumer must call it before trusting
 *  content.
 */
#ifndef BELAY_STORE_H
#define BELAY_STORE_H

#include <stdbool.h>
#include <stddef.h>

struct belay_store;

/* Opens `dir`, creating it (mode 0700, one level only) if absent. Refuses a
 * `dir` whose final component is a symlink. */
int  belay_store_open(const char *dir, struct belay_store **out);
void belay_store_close(struct belay_store *s);

/* One object being staged. Lives on the caller's stack. */
struct belay_store_tx {
    struct belay_store *s;
    int  fd;
    char tmp[64];
    bool live;
};

int  belay_store_begin(struct belay_store *s, struct belay_store_tx *tx);
int  belay_store_write(struct belay_store_tx *tx, const void *buf, size_t n);

/*
 *  Publishes the staged bytes as object `hex`, which the CALLER computed over
 *  exactly those bytes. `hex` must be 64 lowercase hex characters; anything
 *  else is rejected before it can become a path. If the object exists and is
 *  a regular file of the staged size it is kept and the staged copy
 *  discarded; one of another size is replaced by the staged copy. If something
 *  other than a regular file sits at the object's name, that is an error.
 *  The transaction is finished either way. The object's name, renamed in or
 *  found there, survives a crash once belay_store_sync has returned 0.
 */
int  belay_store_commit(struct belay_store_tx *tx, const char *hex);

/*
 *  Makes the names of the objects committed since the last call survive a
 *  crash: syncs each fan-out directory holding one (renamed in, or found
 *  there -- an earlier capture may have renamed it and failed before its
 *  sync), once, then the store directory and its parent, which hold the
 *  names above. Not the objects' bytes (see above). 0, or -1 with belay_err
 *  naming the directory whose sync failed or that could not be opened for
 *  it: a manifest naming these objects must then not be published.
 */
int  belay_store_sync(struct belay_store *s);

/* Discards the staged bytes. Safe on a finished or never-begun transaction. */
void belay_store_abort(struct belay_store_tx *tx);

/* 1 = object present and its content hashes to `hex`; 0 = missing, not a
 * regular file, or content mismatch (belay_err_* says which); -1 = I/O error. */
int  belay_store_verify(struct belay_store *s, const char *hex);

#endif /* BELAY_STORE_H */
