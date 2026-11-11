/*
 *  The watch record (test/expect/state-retention-watch.md WR-1, WR-2;
 *  NOTES/watch-structure.md section 4): `watch/` in the scope's state
 *  directory, holding per UTC day a ledger file (one JSON line per attempt,
 *  step, close, marker or kill) and a receipt file (each step's full
 *  section), and the don't-touch list in force as a file named by its
 *  sha256. The format is belay's own: nothing outside belay reads it.
 *
 *  Every line carries the running state, so the newest line that parses
 *  says where the record stands. A writer holds the scope's lock; readers
 *  take none and ignore a torn last line. It does not know what a flag is.
 */
#ifndef BELAY_WATCH_LEDGER_H
#define BELAY_WATCH_LEDGER_H

#include <limits.h>

#include "cli/state.h"
#include "util/jsonr.h"
#include "watch/watch.h"

#define LEDGER_VERSION 1
#define W_OPEN_MAX 48
#define W_MARK_MAX 32
#define W_KILL_MAX 16
#define W_TOLD_MAX 32

struct wcall { char id[WATCH_ID_MAX + 1], session[WATCH_ID_MAX + 1], agent[WATCH_ID_MAX + 1]; int64_t ns; };
/* ns: when the marker was set; seen_ns: when its session last fired (TM-4) */
struct wmark { char session[WATCH_ID_MAX + 1], name[WATCH_ID_MAX + 1], day[11]; long off; int64_t ns, seen_ns; };
struct wkill { char session[WATCH_ID_MAX + 1]; long n; };

struct wstate {
    long cursor;                        /* WR-2: the checkpoint the next step diffs against; 0: none */
    int64_t cursor_ns;                  /* when it was made: an id is used again once its checkpoint is gone */
    char list[65];                      /* the don't-touch list in force, by sha256; "": none */
    char list_trouble[200];             /* TL-9 or TL-10 while it lasts; "": none */
    struct wcall open[W_OPEN_MAX];
    size_t n_open;
    struct wmark marks[W_MARK_MAX];
    size_t n_marks;
    struct wkill kills[W_KILL_MAX];     /* steps killed at the deadline in a row, by session (TM-3) */
    size_t n_kills;
    char told[W_TOLD_MAX][WATCH_ID_MAX + 1];    /* sessions told what is not read (CV-2) */
    size_t n_told;
};

struct ledger {
    int dfd;                    /* watch/; -1: there is none */
    bool write;
    char day[11];               /* the newest ledger file's day; "": no ledger file */
    struct wstate st;
    bool unreadable;            /* ledger files, and no line of any parses (TL-12) */
    bool unfinished;            /* the newest line is an attempt: a step that did not finish (TL-8) */
    char dir[PATH_MAX + 80];    /* for messages */
};

/* Whether `s` can be an id or a marker's name: 1 to WATCH_ID_MAX bytes,
 * printable ASCII, no space, quote or backslash. */
bool ledger_id_valid(const char *s);

/* Opens the record. `write` (the caller holds the lock): `watch/` is made,
 * and the newest ledger file is cut back to its last line that parses.
 * 0; -1 with belay_err. With no record, 0 and dfd -1 (read) or an empty one. */
int  ledger_open(const struct state *st, bool write, struct ledger *l);
void ledger_close(struct ledger *l);

/* The day a line written at `ns` goes to: today, or the newest file's day
 * when the clock is behind it. */
void ledger_day(const struct ledger *l, int64_t ns, char day[11]);

/* Appends one line with the state as it is now, and syncs it. `body`: the
 * line's own members, each followed by a comma ("\"name\":\"x\","), or "".
 * *off: where the next line will start in that day's file. 0, or -1. */
int ledger_append(struct ledger *l, const char *type, const char *session, int64_t ns, const char *body, long *off);

/* A step's line. Flags that do not fit a line are counted into the step's
 * cut_flag and cut_note (LN-8), which this changes. */
int ledger_append_step(struct ledger *l, struct wstep *s);

/* A step's section of the receipt, appended to its day's file and synced
 * before its line is written; fills the step's sec_ fields. 0, or -1. */
int ledger_section_write(struct ledger *l, struct wstep *s, const char *text, size_t len);

/* The section a step line names: malloc'd, *len bytes; NULL when it is
 * missing or does not hash to what the line says (TL-13). */
char *ledger_section_read(const struct ledger *l, const struct wstep *s, size_t *len);

/* The list in force, kept as watch/list-<sha256>. */
int   ledger_list_write(struct ledger *l, const char *bytes, size_t len, char hex[65]);
char *ledger_list_read(const struct ledger *l, const char *hex, size_t *len);

/* The days that have a ledger file, ascending; *n of them, malloc'd. 0, or -1. */
int ledger_days(const struct ledger *l, char (**days)[11], size_t *n);

/* Every line that parses of `day`'s ledger file from offset `from`, in
 * order: fn(ctx, line, type) -- 0 to go on, anything else stops and is
 * returned. 0 at the end; -1 with belay_err when the file cannot be read. */
typedef int (*ledger_line_fn)(void *ctx, const struct jval *line, const char *type);
int ledger_read(const struct ledger *l, const char *day, long from, ledger_line_fn fn, void *ctx);

/* A line's running state into *s; false when it has none that belay wrote. */
bool ledger_state(const struct jval *line, struct wstate *s);

/* A step line into *s (wstep_free it). 0, or -1 when it is not one. */
int ledger_step(const struct jval *line, struct wstep *s);

/* Test hook: called after a step's section is synced and before its line is
 * written. NULL in the binary. */
extern void (*ledger_before_line)(void);
/* Test hook: the Nth line a process writes fails as a full disk would (1: the first). 0 in the binary. */
extern long ledger_fail_at;

#endif
