/*
 *  Lexical path utilities — ARGUMENT VALIDATION ONLY.
 *
 *  BELAY_DESIGN.md §5.1.1 is binding here. These functions operate purely on
 *  strings: they touch no filesystem, follow no symlink, and prove nothing
 *  about where a path actually lands. They exist to validate user-supplied
 *  --scope arguments before anything is opened.
 *
 *  Containment during a walk is by construction (root dirfd + openat/fstatat
 *  with AT_SYMLINK_NOFOLLOW / O_NOFOLLOW), NOT by calling these.
 *
 *  There is deliberately no realpath-based "is this inside?" helper. Such a
 *  check is racy by construction — the answer can change between check and
 *  use — and any caller relying on it would be relying on a lie.
 */
#ifndef BELAY_PATH_H
#define BELAY_PATH_H

#include <stddef.h>

/*
 *  Normalizes `in` into `out` lexically:
 *    - collapses duplicate separators  (a//b   -> a/b)
 *    - removes "." components          (a/./b  -> a/b)
 *    - strips trailing slashes         (a/b/   -> a/b)
 *    - preserves a leading "/" exactly (absolute stays absolute)
 *
 *  ".." is REJECTED, not resolved. Resolving it lexically is unsound in the
 *  presence of symlinks: for `a/link/..` where link -> /etc, the lexical
 *  answer "a" and the real answer "/" differ. A caller that wants to accept
 *  ".." must resolve it against the real filesystem itself.
 *
 *  Returns 0 on success, -1 on failure with belay_err_* set:
 *    BELAY_ERR_INVALID  empty input, a ".." component, or an embedded NUL
 *    BELAY_ERR_RANGE    result does not fit in `outsz`
 *
 *  `out` is NUL-terminated on success and left unspecified on failure.
 *  Byte-transparent: path bytes are not assumed to be UTF-8.
 */
int belay_path_normalize(char *out, size_t outsz, const char *in);

/*
 *  True when `path` is lexically equal to, or a component-wise descendant of,
 *  `root`. Both are normalized internally, so either may be unnormalized.
 *
 *  Component-wise means "/a/b" is within "/a" but "/ab" is NOT — a plain
 *  string prefix test would wrongly accept it.
 *
 *  Returns 1 within, 0 not within, -1 on error (belay_err_* set). A caller
 *  that treats -1 as false would accept a malformed path, so check for -1.
 *
 *  Says NOTHING about symlinks. See the header comment.
 */
int belay_path_within_lexical(const char *root, const char *path);

#endif /* BELAY_PATH_H */
