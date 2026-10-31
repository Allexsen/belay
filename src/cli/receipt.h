/*
 *  The receipt: diff.v1 rendered for a person (NOTES/phase5-structure.md §5;
 *  decisions §14.7, Q4 of Phase 4). It decides nothing the diff did not:
 *  events first, then every privilege change (caps, inode flags, setuid,
 *  setgid, sticky) -- never folded, never filtered -- then the other
 *  records by path; each record at most RECEIPT_FINDINGS findings, then
 *  "and N more"; flagged entries named on their own lines, no global
 *  "provisional" banner.
 */
#ifndef BELAY_CLI_RECEIPT_H
#define BELAY_CLI_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define RECEIPT_FINDINGS 15     /* per record, then "and N more" */
#define RECEIPT_FOLD     50     /* events or other records shown, then "and N more" (unless all) */

/* A path's mode on a side (0 before, 1 after): 0 and *mode, or -1 when the
 * side does not record the path. Records arrive in path order, so a lookup
 * may move forward only. diff.v1 does not carry values yet (pin PR #24). */
typedef int (*receipt_mode_fn)(void *ctx, int side, const char *path, size_t len, uint32_t *mode);

struct receipt_opts {
    const char *from, *to;      /* how the two sides are named in the heading */
    bool all;                   /* nothing folded */
    receipt_mode_fn mode;       /* NULL: setuid/setgid/sticky cannot be told from other mode changes */
    void *mode_ctx;
};

/* Reads diff.v1 from `diff`, writes the receipt to `out`. 0; -1 with
 * belay_err (a line that is not diff.v1, memory, write). */
int receipt_render(FILE *diff, FILE *out, const struct receipt_opts *o);

#endif
