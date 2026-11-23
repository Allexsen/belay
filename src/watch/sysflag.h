/*
 *  What a system watch flags and notes (test/expect/watch-system.md, WS-F1
 *  to WS-F17, WS-N1 to WS-N5, WS-L1), over one diff: its events, its path
 *  records -- by the roots of its two manifests -- and its runtime records.
 *  watch-v1's list does not apply to a system scope: this one does.
 *
 *  The diff is read three times: what to ask dpkg's lists about (the
 *  packaged file of a unit an override changes, a listener's or service's
 *  executable, the records under metadata roots), then the events and the
 *  runtime records, then the path records -- a record whose path a flagged
 *  or noted event names is that event's, and is not named or counted again.
 */
#ifndef BELAY_WATCH_SYSFLAG_H
#define BELAY_WATCH_SYSFLAG_H

#include "watch/watch.h"

/* A path row (WS-F5 to WS-F9, WS-F14, WS-F15): matched as watch-v1's are
 * (WD-1 to WD-4); a directory covers what is below it. */
struct sysrow { const char *id; enum wkind kind; const char *label, *pattern, *except; };
extern const struct sysrow sysflag_rows[];
extern const size_t sysflag_n_rows;

/* The rows that read events, fields or runtime records, as `watch patterns
 * --system` lists them: id, then what. */
extern const char *const sysflag_event_rows[][2];
extern const size_t sysflag_n_event_rows;

/* The shell startup files of a home (WS-6), relative to it. */
extern const char *const sysflag_home_files[];
extern const size_t sysflag_n_home_files;

/* The step `s` gets the diff at `diff` between the manifests `before` and
 * `after` (whose roots name the homes and the metadata roots), with the
 * store at `store` for dpkg's lists. `mode` is the manifests' fields
 * (privilege, sealed). 0, or -1 with belay_err. */
int sysflag_step(const char *diff, const char *before, const char *after, const char *store, receipt_mode_fn mode,
                 void *mode_ctx, struct wstep *s);

/* Whether the path matches a row, and which (`watch patterns --system`). */
const struct sysrow *sysflag_row_of(const char *path, size_t len);

/* "+a, -b": the roots of `after` that `before` does not list, then the
 * reverse, by path and class; NULL in *out when they are the same (WS-10).
 * Those of one home added or removed together are one item, "+home/v (14
 * paths)", unless `all`. 0, or -1 (memory). */
struct belay_manifest_header;
int sysflag_roots_changed(const struct belay_manifest_header *before, const struct belay_manifest_header *after, bool all,
                          char **out);

#endif
