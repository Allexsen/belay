/*
 *  Lexical path utilities — ARGUMENT VALIDATION ONLY.
 *
 *  BELAY_DESIGN.md §5.1.1 is binding here. These functions operate purely on
 *  strings: they touch no filesystem, follow no symlink, and prove nothing
 *  about where a path actually lands. They exist to validate the scope
 *  argument of belay_manifest_write before anything is opened, and to compute the advisory
 *  (never decisive) target_outside_scope annotation of a recorded symlink.
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

#include <stdbool.h>
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
 *    BELAY_ERR_INVALID  empty input or a ".." component
 *    BELAY_ERR_RANGE    result does not fit in `outsz`
 *
 *  Takes a NUL-terminated string and has no length parameter, so an embedded
 *  NUL simply ends the path -- bytes after it are never examined, including a
 *  ".." that follows one. Callers that hold a length (a scope read from a file
 *  or an environment buffer rather than argv) must reject interior NULs
 *  themselves before calling. Scope arguments from argv cannot contain NUL.
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

/*
 *  The advisory `target_outside_scope` annotation of a symlink (§5.1.1): does
 *  a link at `link_path` (scope-relative, as a manifest records it) whose
 *  target is `target` point lexically outside `scope`? An absolute target is
 *  compared with the scope by belay_path_within_lexical; a relative one is
 *  resolved from the link's own directory, ".." popping a component and
 *  popping above the scope root meaning outside. Nothing is followed, so the
 *  answer can be wrong in both directions -- which is why it is an annotation
 *  and never an input to a decision. A target the lexical check cannot judge
 *  (a ".." inside an absolute target, an overlong one) counts as outside.
 *
 *  One function for the writer, which records the annotation, and the reader,
 *  which recomputes it: a flag either side could set freely would give one
 *  state two encodings. `target` is NUL-terminated, `tlen` bytes long.
 */
bool belay_link_target_outside(const char *scope, const char *link_path, size_t link_len,
                               const char *target, size_t tlen);

#endif /* BELAY_PATH_H */
