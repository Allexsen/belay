/*
 *  Steps into the short lines (test/expect/watch-v1.md: LN, SM). A pure
 *  function of its arguments: no files, no locks, no JSON.
 */
#ifndef BELAY_WATCH_LINES_H
#define BELAY_WATCH_LINES_H

#include "watch/watch.h"

/* The caller's words (SM-6). */
struct wwords {
    const char *call;       /* "tool call" */
    const char *span;       /* "this turn" */
    const char *tail;       /* " · full receipt: /belay:receipt", or "" */
};

/* A step's lines, each ending in '\n', appended to `out`: its troubles,
 * then one line for what changed. Nothing when it changed nothing and had
 * no trouble (LN-1). */
void lines_step(struct wsb *out, const struct wstep *s);

/* A summary of `n` steps for `session` (SM-1 to SM-7). `standing`: troubles
 * that last (TL-9, TL-10), NULL-terminated or NULL. `gone`: the day before
 * which the record was pruned, or NULL. */
void lines_summary(struct wsb *out, const struct wstep *steps, size_t n, const char *session,
                   const char *const *standing, const char *gone, const struct wwords *w);

#endif
