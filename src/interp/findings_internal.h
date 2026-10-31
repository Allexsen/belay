/*
 *  The core's side of findings and events (belay/interp.h): what the diff
 *  sets up before an interpreter runs, and how the emitter writes them.
 */
#ifndef BELAY_INTERP_FINDINGS_INTERNAL_H
#define BELAY_INTERP_FINDINGS_INTERNAL_H

#include "belay/interp.h"

#include <stdio.h>

struct sbuf { char *p; size_t len, cap; };

struct belay_findings {
    int interp;                 /* who is explaining: kinds are checked against it */
    struct sbuf objs;           /* serialized objects, comma-separated */
    size_t last;                /* where the last kept object starts in objs */
    size_t n, extra;            /* kept; past FINDINGS_PER_RECORD, counted */
    bool oom;                   /* an add failed: the diff fails, whatever was returned */
};

struct ev_per {
    struct sbuf recs;           /* serialized event lines */
    size_t last;                /* where the last kept line starts in recs */
    size_t n, extra;
    bool broken;                /* an event broke its kind's row: E6 */
    bool oom;
    struct sbuf claimed;        /* paths given to the interpreter: (size_t len, bytes)... */
    size_t nclaimed;
};

struct belay_events {
    int interp;                 /* whose end hook is running */
    struct ev_per per[BELAY_INTERP_COUNT];
};

void findings_reset(struct belay_findings *f, int interp);
void findings_free(struct belay_findings *f);
size_t findings_count(const struct belay_findings *f);
bool findings_oom(const struct belay_findings *f);
/* `,"findings":[...]` when there are any. 0, or -1 (write error). */
int findings_write(const struct belay_findings *f, FILE *out);

void events_init(struct belay_events *ev);
void events_free(struct belay_events *ev);
/* Records that `interp` was given `path` (for E6). 0, or -1 (NOMEM). */
int events_claim(struct belay_events *ev, int interp, const char *path, size_t len);
bool events_oom(const struct belay_events *ev, int interp);
bool events_broken(const struct belay_events *ev, int interp);
/* E6: drops `interp`'s events for one could_not_interpret naming its paths. */
int events_failed(struct belay_events *ev, int interp);
size_t events_count(const struct belay_events *ev);
/* Every event line, by interpreter (E4). 0, or -1 (write error). */
int events_write(const struct belay_events *ev, FILE *out);

#endif
