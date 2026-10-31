/*
 *  git's text formats the git interpreter reads, without object access:
 *  a ref file (HEAD or a loose ref), packed-refs, and a reflog
 *  (gitrepository-layout(5), git-update-ref(1) "Logging updates"). Pure,
 *  bounded, no allocation: the repository is written by the watched process.
 */
#ifndef BELAY_INTERP_GITFMT_H
#define BELAY_INTERP_GITFMT_H

#include <stdbool.h>
#include <stddef.h>

#define GIT_NAME_MAX 1024u              /* bytes of a ref name or reflog operation */

/* An object id: 40 (SHA-1) or 64 (SHA-256) lowercase hex digits. */
bool git_oid(const char *s, size_t n);

/* A ref file's first line: "ref: <name>" (symbolic: *sym true, *val the
 * name) or an object id (*sym false). 0, or -1 with belay_err CORRUPT. */
int git_ref_value(const char *buf, size_t len, bool *sym, const char **val, size_t *val_len);

typedef int (*git_packed_fn)(const char *ref, size_t ref_len, const char *oid, size_t oid_len,
                             void *ctx);
/* packed-refs: each "<oid> <ref>" line, in file order; "#" header lines and
 * "^<oid>" peeled lines are skipped. 0, -1 (CORRUPT), or fn's non-zero. */
int git_packed_each(const char *buf, size_t len, git_packed_fn fn, void *ctx);

struct git_reflog_entry {
    const char *old_oid, *new_oid, *operation;      /* into the buffer */
    size_t oid_len, operation_len;
    size_t line;
    const char *message;                            /* everything after the tab */
    size_t message_len;
};
typedef int (*git_reflog_fn)(const struct git_reflog_entry *e, void *ctx);
/* A reflog: each "<old> <new> <identity> <time> <zone>\t<message>" line, in
 * file order. The operation is the message up to its first ':' (all of it
 * when there is none), trimmed. 0, -1 (CORRUPT), or fn's non-zero. */
int git_reflog_each(const char *buf, size_t len, git_reflog_fn fn, void *ctx);

#endif
