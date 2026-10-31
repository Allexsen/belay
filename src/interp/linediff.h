/*
 *  Line counts for the text interpreter (finding kinds text_changed and
 *  text_rewritten): lines deleted and added by the longest common
 *  subsequence of lines -- any correct algorithm gives the same numbers --
 *  and the first line past the common prefix. Myers' algorithm on line
 *  hashes, bounded by the edit distance, so a large rewrite costs at most
 *  (lines) x LINEDIFF_D_MAX steps.
 */
#ifndef BELAY_INTERP_LINEDIFF_H
#define BELAY_INTERP_LINEDIFF_H

#include <stdbool.h>
#include <stddef.h>

#define LINEDIFF_D_MAX 2000u

/* A line is its bytes up to and including '\n', or the bytes after the
 * last '\n' when there are any: "a" and "a\n" are different lines. */
size_t line_count(const char *s, size_t n);

struct line_delta {
    size_t lines_a, lines_b;
    size_t first_changed;       /* 1-based, in a: the common prefix's lines + 1 */
    bool counted;               /* the edit distance is at most LINEDIFF_D_MAX: */
    size_t deleted, added;      /*   then lines_a - lcs and lines_b - lcs */
};

/* 0, or -1 with belay_err NOMEM. */
int line_delta(const char *a, size_t al, const char *b, size_t bl, struct line_delta *out);

#endif
