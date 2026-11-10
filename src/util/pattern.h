/*
 *  The one pattern matcher (test/expect/protect-spec.md PS-P1 to PS-P4;
 *  test/expect/watch-v1.md WD-1 to WD-5). A pattern is relative, its
 *  components separated by '/'; a component `**` matches any number of
 *  whole components, none included; in any other component `*` matches any
 *  run of bytes within it; nothing else is special.
 *
 *  Two dialects, by switches. The protect spec's has none: a wildcard
 *  never matches a component that starts with '.' (PS-P4), and bytes are
 *  compared as they are. The watch lists' has PATTERN_DOTS, and a caller
 *  that lets a match on a directory cover what is below it reads
 *  PATTERN_ABOVE from the answer.
 */
#ifndef BELAY_UTIL_PATTERN_H
#define BELAY_UTIL_PATTERN_H

#include <stdbool.h>
#include <stddef.h>

#define PATTERN_MAX 4096u       /* bytes of a pattern (PS-P1) */

/* switches */
#define PATTERN_DOTS   1u       /* `*` and `**` match names that start with '.' (WD-1) */
#define PATTERN_NOCASE 2u       /* ASCII letters compare case-insensitively (WD-4) */

/* answers of pattern_match, or'ed */
#define PATTERN_SELF  1u        /* the pattern matches the path */
#define PATTERN_ABOVE 2u        /* the pattern matches a proper ancestor of the path */

/* Whether `p` is a pattern (PS-P1): not empty, at most PATTERN_MAX bytes,
 * no NUL, no leading or trailing '/', no empty, "." or ".." component. */
bool pattern_valid(const char *p, size_t n);

/* How many `**` components `p` has. */
size_t pattern_globstars(const char *p, size_t n);

/* Whether the pattern matches `path`, or an ancestor of it: PATTERN_SELF,
 * PATTERN_ABOVE, both or 0. */
unsigned pattern_match(const char *pat, size_t plen, const char *path, size_t n, unsigned switches);

/* Whether the pattern could match `dir` or something below it: `dir` is
 * the pattern's match, or a prefix of one. An empty `dir` is the top. */
bool pattern_covers(const char *pat, size_t plen, const char *dir, size_t n, unsigned switches);

#endif
