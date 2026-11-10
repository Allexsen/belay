/*
 *  One event of `belay watch`: a list of operations run by one worker,
 *  under one supervisor, one hold of the scope's lock and one deadline
 *  (test/expect/watch-v1.md TM; NOTES/watch-structure.md sections 3 to 5).
 *  The commands of watch_cmd.c and the Claude Code adapter both come here.
 */
#ifndef BELAY_WATCH_RUN_H
#define BELAY_WATCH_RUN_H

#include "watch/lines.h"
#include "watch/watch.h"

enum wop_kind {
    WOP_STEP,           /* capture, diff against the cursor, record; arg: a call id for how 1 and 2 */
    WOP_CLOSE,          /* calls that will never finish; arg: their ids, separated by a space */
    WOP_CLOSE_SESSION,  /* every open call of the session */
    WOP_CLOSE_AGENT,    /* the session's open calls of one agent; arg: the agent, "" the main thread */
    WOP_MARK,           /* a named marker; arg: its name */
    WOP_FORGET,         /* the session is over: its markers and counters go */
    WOP_SUMMARY,        /* the steps since a marker; arg: its name */
};

enum { WSTEP_PLAIN, WSTEP_BEGIN, WSTEP_FINISH };

struct wop { enum wop_kind op; const char *arg; int how; };

#define WATCH_OPS_MAX 8
#define WATCH_DEADLINE_S 45     /* TM-1 */
#define WATCH_SECOND_S   10     /* TM-2: 55 s, counted from the deadline */
#define WATCH_BACKOFF    3      /* TM-3 */

struct wreq {
    const char *scope;          /* as given; resolved by the worker */
    const char *session;
    const char *agent;          /* of a call begun by this event; "" the main thread */
    struct wop ops[WATCH_OPS_MAX];
    size_t n_ops;
    bool first_ok;              /* a first step is expected: the session is starting (TL-1) */
    long deadline_s;
    struct wwords words;
};

/* Runs the event. Its lines, each ending in '\n', are appended to `out`:
 * always at least the line that says why nothing could be recorded. 0 when
 * the record was kept; 3 when the directory is refused; 4 otherwise. */
int watch_run(const struct wreq *q, struct wsb *out);

/* `belay watch summary`: the steps since the session's marker `name`, read
 * without the lock; nothing is written. 0, or -1 with belay_err. */
int watch_summary(const struct wreq *q, const char *name, struct wsb *out);

/* Whether a resolved directory is too wide to watch (TL-14): "/", $HOME,
 * or one $HOME is inside. */
bool watch_too_wide(const char *resolved);

/* Test hooks, NULL in the binary: called in the worker when it reaches a
 * stage ("waiting for the lock", "capturing", "matching", "rendering",
 * "committing" before it asks, "writing the record" after the answer), so a test can
 * stall or kill it there. */
extern void (*watch_stage_hook)(const char *stage);
/* Test hooks: the clock a step reads (NULL: the system's), and the second
 * limit in milliseconds past the deadline. */
extern int64_t (*watch_clock)(void);
extern long watch_second_ms;

#endif
