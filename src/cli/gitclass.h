/*
 *  What git says of a scope's paths, for the human receipt only (2026-11-04):
 *  each one tracked (in the index, or in HEAD), ignored (git check-ignore) or
 *  untracked -- as the repository is now, not as it was when a checkpoint
 *  was captured. NDJSON and policy output never use it.
 *
 *  It runs git: `rev-parse --show-toplevel --show-prefix` in the scope, then
 *  `ls-files -z`, `ls-tree -r -z --name-only HEAD` and `check-ignore -z
 *  --stdin` at the repository's top, with optional locks off, no fsmonitor
 *  and none of the caller's GIT_DIR-like variables: nothing it runs writes to
 *  the repository. No git, no repository, or any failure: -1, and the
 *  receipt keeps path order.
 */
#ifndef BELAY_CLI_GITCLASS_H
#define BELAY_CLI_GITCLASS_H

#include <stdbool.h>
#include <stddef.h>

enum { GC_UNTRACKED = 0, GC_TRACKED = 1, GC_IGNORED = 2 };

/* n paths relative to `scope` (bytes, lens[i] long; dir[i] when the entry
 * is a directory on either side): out[i] set to a GC_ value. 0; -1 when git
 * cannot say (out untouched). Never sets belay_err. */
int gitclass(const char *scope, const char *const *paths, const size_t *lens, const bool *dir, size_t n,
             unsigned char *out);

#endif
