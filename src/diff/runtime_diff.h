/*
 *  The `runtime` section of a diff (test/expect/runtime-v1.md, RT-D1 to
 *  RT-D5): the two captures' runtime records compared. Runtime changes are
 *  not interpreter events -- an event must list a path -- so the section is
 *  its own: after the events, before the trailer.
 */
#ifndef BELAY_DIFF_RUNTIME_H
#define BELAY_DIFF_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

struct rtdiff;

/*
 *  Reads the records at `before` and `after` (either NULL: that capture has
 *  none) and decides the section. NULL for both: no section (*out NULL).
 *  0, or -1 with belay_err (CORRUPT: a file that is not a runtime record).
 */
int  rtdiff_open(const char *before, const char *after, struct rtdiff **out);
void rtdiff_free(struct rtdiff *d);

/* RT-D4: whether a listener of the section is held by systemd alone, so
 * the after-manifest's `.socket` unit files are wanted. */
bool rtdiff_wants_units(const struct rtdiff *d);
/* Whether `path` (relative to the scope) is a `.socket` unit file whose
 * text is wanted: `<...>systemd/system/<name>.socket` or `.../user/...`. */
bool rtdiff_unit_path(const char *path, size_t len);
/* One unit file's text, as the after-manifest's copy holds it. */
int  rtdiff_unit(struct rtdiff *d, const char *path, size_t len, const char *text, size_t tlen);

/* Writes the section's records to `f`; *n their number. 0, or -1. */
int  rtdiff_write(struct rtdiff *d, FILE *f, size_t *n);

#endif
