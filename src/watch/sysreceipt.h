/*
 *  A system watch's receipt (test/expect/watch-system.md WS-R1 to WS-R6):
 *  its first three lines -- could not read, kernel record, end state -- the
 *  sections receipt.c renders from the diff of the watch's first
 *  checkpoint and its last, and its last two -- not compared, not read.
 */
#ifndef BELAY_WATCH_SYSRECEIPT_H
#define BELAY_WATCH_SYSRECEIPT_H

#include "cli/state.h"
#include "watch/ledger.h"

/*
 *  The kernel record as the receipt states it (WS-R3, kernel-record.md).
 *  STEP 7 SETS THIS. Until the recorder exists, watch_kernel_record() says
 *  it is off, and why; the recorder's state, once there is one, is read in
 *  that function and nowhere else, and watch_walk_reason() says why a
 *  capture is a walk (`walking (<reason>)`, WS-3a).
 */
struct wkrec {
    bool on;
    int64_t since_ns;                   /* on: since when */
    bool gap;                           /* on, with a gap */
    int64_t gap_from_ns, gap_to_ns;
    char gap_why[128];
    char off_why[160];                  /* off: the kernel's message, or "not root" */
    char walked[512];                   /* "; walked every time: boot (vfat)", or "" (kernel-record K2a) */
    bool iflags_events;                 /* false: "; inode flags as of the last walk" */
};
void watch_kernel_record(const struct wstate *w, struct wkrec *k);
const char *watch_walk_reason(void);

/* The receipt's opening lines for checkpoint `cp`: `could not read` (with
 * the `not root:` line under it when it is true) and `kernel record`. */
int sysreceipt_head(const struct state *st, long cp, const struct wstate *w, struct wsb *out);

/* The whole receipt, `from` to `to` (`to` made at `to_ns` by a walk). 0, or -1 with belay_err. */
int sysreceipt(const struct state *st, const struct wstate *w, long from, long to, int64_t to_ns, struct wsb *out);

#endif
