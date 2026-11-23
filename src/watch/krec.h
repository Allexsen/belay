/*
 *  The kernel record of a system watch (test/expect/kernel-record.md): the
 *  recorder process, its journal, the barrier a capture takes in it, and
 *  what the watch knows of the record's state.
 *
 *  In the scope's state directory, under watch/:
 *
 *    journal.<n>      a segment: one JSON line an event, `seq` rising by one;
 *                     <n> is the seq of its first line (K5). A new segment
 *                     begins after each barrier.
 *    recorder.lock    held (flock) by the recorder for as long as it runs
 *    recorder         its id, 16 hex digits, one line
 *    recorder.stop    made by `watch stop`: the recorder ends when it sees it
 *    krec             the record's state for the receipt (WS-R3), one line
 *    barrier.<random> made and removed by a capture (K7)
 *
 *  The lines of a journal are read as hostile input: a line that is not one
 *  the recorder writes makes the interval it lies in unusable, never a
 *  wrong answer.
 *
 *  The seam for tests: with BELAY_TEST_KREC naming a file, the recorder
 *  reads that file as its queue of events instead of a fanotify group
 *  (recorder.c says the lines), and needs no privilege. Everything after
 *  the read of an event is the same code.
 */
#ifndef BELAY_WATCH_KREC_H
#define BELAY_WATCH_KREC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cli/state.h"

/* An event's mask: the kernel's own bits (fanotify), named here so that
 * nothing outside the recorder needs its header. */
#define KR_MODIFY      0x00000002u
#define KR_ATTRIB      0x00000004u
#define KR_CLOSE_WRITE 0x00000008u
#define KR_CREATE      0x00000100u
#define KR_DELETE      0x00000200u
#define KR_RENAME      0x10000000u
#define KR_ONDIR       0x40000000u

#define KR_NAME_MAX 255
#define KR_LINE_MAX 8192            /* a journal line, its newline included */

enum kev_kind { KEV_EVENT, KEV_START, KEV_OVERFLOW, KEV_MOUNTS, KEV_BARRIER };

struct kev {
    enum kev_kind kind;
    uint64_t seq;
    int64_t time_ns;
    uint32_t mask;
    bool has_ino;               /* the object resolved: dev, ino */
    uint64_t dev, ino;
    bool named;                 /* a named event: the directory and the name */
    bool has_dir;               /* its directory resolved */
    uint64_t dir_dev, dir_ino;
    char name[KR_NAME_MAX + 1]; /* bytes, not NUL-terminated within name_len; a NUL follows */
    size_t name_len;
    bool renamed;               /* a rename: where to */
    bool has_to;
    uint64_t to_dev, to_ino;
    char to_name[KR_NAME_MAX + 1];
    size_t to_len;
    char recorder[17];          /* KEV_START */
    bool iflags_events;         /* KEV_START (K6) */
};

/* One line of a journal, without its newline. 0, or -1: not one. */
int krec_parse(const char *line, size_t n, struct kev *e);

/* What the watch knows of its kernel record, kept in watch/krec and written
 * under the state's lock. */
struct krec_status {
    bool on;
    int64_t since_ns;
    char recorder[17];          /* the recorder that journaled the last barrier */
    bool iflags_events;
    char walked[512];           /* "; walked every time: boot (vfat)", or "" (K2a) */
    bool gap;
    int64_t gap_from_ns, gap_to_ns;
    char gap_why[128];
    char off_why[160];
    long long last_seq;         /* the last barrier's; 0: none yet */
    int64_t last_ns;            /* when it was taken */
};
/* 0 with *k; 1 when the watch has none (never started under this version);
 * -1 with belay_err. */
int krec_status_read(const struct state *st, struct krec_status *k);
int krec_status_write(const struct state *st, const struct krec_status *k);

/* Starts the recorder of this watch (K1): `roots` are the capture's roots,
 * relative to the scope. Returns 0 with k->on, k->recorder, k->walked and
 * k->iflags_events set, or with k->on false and k->off_why saying why it
 * cannot run (K4); -1 with belay_err only when the state cannot be written. */
int krec_start(const struct state *st, const char *const *roots, size_t n_roots, struct krec_status *k);
/* Ends it and waits for it (K1). Nothing when none runs. */
void krec_stop(const struct state *st);
/* Whether a recorder of this watch runs, and which. */
bool krec_alive(const struct state *st, char id[17]);
/* Removes every segment: a new watch begins. */
void krec_forget(const struct state *st);
/* Removes the segments that hold nothing after `oldest_seq` (K5, prune). */
void krec_prune(const struct state *st, long long oldest_seq);

/* The barrier (K7): 0 with its seq and the file's ctime_ns; 1 when the
 * recorder did not answer in `wait_ms`; -1 with belay_err. */
int krec_barrier(const struct state *st, int wait_ms, long long *seq, int64_t *ctime_ns);

/* Every record with after < seq <= upto, in order. 0; 1 when a segment is
 * gone or a line is not the recorder's (nothing more is handed on); -1 with
 * belay_err, or when `fn` returned -1. */
typedef int (*krec_fn)(void *ctx, const struct kev *e);
int krec_scan(const struct state *st, long long after, long long upto, krec_fn fn, void *ctx);

/* ---- the recorder process (recorder.c) ---- */

struct recorder_cfg {
    const char *wdir;           /* <state>/watch */
    const char *state_dir;      /* the scope's state directory: its filesystem is marked too (K2) */
    const char *root;           /* the scope: `/`, or the directory a test put in its place */
    const char *fixture;        /* BELAY_TEST_KREC, or NULL: fanotify */
    const char *const *roots;   /* the capture's roots, relative to `root` */
    size_t n_roots;
    int ready_fd;               /* one line is written here: "K<id> <iflags 0|1><walked>\n", or "E<why>\n" */
};
/* Never returns. */
void recorder_run(const struct recorder_cfg *c);

/* The filesystems under the roots, from a mount table (K2, K2a, K3): the
 * mount points to mark, and the receipt's words for those walked every
 * time. `table`: /proc/self/mountinfo, or a file shaped like it whose mount
 * points are relative to `root`. 0; 1 with `why` when nothing can be marked. */
struct krec_plan {
    char mark[16][4096];
    size_t n_mark;
    char walked[512];
    uint64_t sum;               /* of the lines that matter: a change is `mounts_changed` (K6) */
};
int krec_plan(const char *table, bool relative, const char *root, const char *const *roots, size_t n_roots,
              struct krec_plan *out, char why[160]);

#endif
