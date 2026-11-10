/*
 *  `belay watch`: a running record of one directory while an agent works
 *  in it (test/expect/watch-v1.md; the record's files and their pruning:
 *  test/expect/state-retention-watch.md).
 *
 *    watch_cmd.c   the commands, and the supervisor every one that captures runs under
 *    ledger.c      the record, under the scope's lock
 *    flag.c        what is flagged, and why
 *    lines.c       steps -> the short lines (pure)
 *    util/pattern.c  the matcher
 *
 *  Shared here: a step as the ledger keeps it and the lines read it, and a
 *  growable string.
 */
#ifndef BELAY_WATCH_WATCH_H
#define BELAY_WATCH_WATCH_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "watch/flag.h"

#define WATCH_ID_MAX   96       /* bytes of a session, call or agent id, and of a marker's name */
#define WATCH_LINE_MAX 65536    /* a ledger line (LN-8) */
#define WATCH_OUTCOMES 6        /* added, removed, modified, type changed, metadata changed, not compared */

extern const char *const watch_outcome_word[WATCH_OUTCOMES];
int watch_outcome_index(const char *word);

/* A growable string. `bad` once memory ran out: every later write is dropped. */
struct wsb { char *p; size_t n, cap; bool bad; };
void wsb_f(struct wsb *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void wsb_json(struct wsb *b, const char *s);        /* s as a JSON string, quotes included; not UTF-8: "?" */

/* One step, as its ledger line holds it. */
struct wstep {
    char session[WATCH_ID_MAX + 1];
    int64_t ns;
    long from, to;                      /* checkpoints; from 0: a first step */
    uint64_t changes;                   /* path records of its diff */
    char **calls;                       /* the calls open at any time in its interval; none: outside calls */
    size_t n_calls;
    struct wflag *flags;                /* flagged and noted, in the diff's order */
    size_t n_flags;
    uint64_t cut_flag[WK_COUNT], cut_note[WK_COUNT];    /* flagged or noted and not kept in `flags` (LN-8) */
    uint64_t counts[WATCH_OUTCOMES];    /* the entries neither flagged nor noted, by outcome */
    char *names[3];                     /* those entries named, when there are three or fewer */
    size_t n_names;
    char *under;                        /* the top-level directory most of them are under, shown; NULL: none */
    uint64_t n_under;
    char **trouble;                     /* lines of "The record could not be kept", without the prefix */
    size_t n_trouble;
    char sec_file[40];                  /* its section of the receipt: file, offset, length, sha256 */
    long sec_off, sec_len;
    char sec_sha[65];
};
void wstep_free(struct wstep *s);
int  wstep_add_trouble(struct wstep *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#endif
