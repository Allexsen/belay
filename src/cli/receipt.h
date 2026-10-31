/*
 *  The receipt: diff.v1 rendered for a person (NOTES/phase5-structure.md §5;
 *  decisions §14.7, Q4 of Phase 4). It decides nothing the diff did not:
 *  events first, then every privilege change (caps, inode flags, setuid,
 *  setgid, sticky) -- never folded, never filtered -- then the other
 *  records by path; each record at most RECEIPT_FINDINGS findings, then
 *  "and N more"; flagged entries named on their own lines, no global
 *  "provisional" banner. Every string from the diff is printed escaped:
 *  control bytes, C1 controls, invisible format and bidi characters and
 *  bytes that are not UTF-8 as \xNN, a
 *  backslash as \\ -- a path cannot forge a line, a heading or a terminal
 *  sequence (review 2026-10-31, Phase 5, 7).
 */
#ifndef BELAY_CLI_RECEIPT_H
#define BELAY_CLI_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define RECEIPT_FINDINGS 15     /* per record, then "and N more" */
#define RECEIPT_FOLD     50     /* events or other records shown, then "and N more" (unless all) */

/* What the receipt needs of a path on one side that diff.v1 does not carry
 * yet (pin PR #24): its mode, and whether it has file capabilities. */
struct receipt_meta {
    uint32_t mode;
    bool has_caps;
};

/* A path's metadata on a side (0 before, 1 after): 0 and *m, or -1 when the
 * side does not record the path. Records arrive in path order, so a lookup
 * may move forward only. `path` is the bytes, base64 already decoded. */
typedef int (*receipt_mode_fn)(void *ctx, int side, const char *path, size_t len, struct receipt_meta *m);

struct receipt_opts {
    const char *from, *to;      /* how the two sides are named in the heading */
    bool all;                   /* nothing folded */
    receipt_mode_fn mode;       /* NULL: setuid/setgid/sticky and caps on added or removed files cannot be told */
    void *mode_ctx;
};

/* Reads diff.v1 from `diff`, writes the receipt to `out`. 0; -1 with
 * belay_err (a line that is not diff.v1, memory, write). */
int receipt_render(FILE *diff, FILE *out, const struct receipt_opts *o);

/* `s` written to `f` escaped as the receipt escapes paths: for any text
 * belay prints that came from the filesystem or its own state (a scope, a
 * reason read back, an error naming a path). */
void receipt_fputs(FILE *f, const char *s);

#endif
