/*
 *  What cli.c shares with the M2 commands in verify.c: the one-line usage
 *  and failure conventions (cli.h's exit codes) and the scope opened as
 *  every command opens it.
 */
#ifndef BELAY_CLI_INTERNAL_H
#define BELAY_CLI_INTERNAL_H

#include <stdbool.h>
#include <stdio.h>

#include "state.h"
#include "receipt.h"

#include "belay/manifest.h"

int  cli_usage(FILE *err, const char *why);     /* one line; EXIT_USAGE */
int  cli_failed(FILE *err);                     /* belay_err as one line; EXIT_REFUSED for INVALID, else EXIT_FAILED */
void cli_err_line(FILE *err);                   /* belay_err as one line */
int  cli_open_scope(const char *scope, const char *docker, bool create, struct state *st, FILE *err);   /* 0, or an exit code; docker NULL: the host */

/* The receipt's mode lookup: a forward-only cursor on each manifest, as
 * records arrive in path order; its classifier (git on the scope as it is
 * now); and every path either side of a diff did not walk, once. */
struct cli_cursor { struct belay_manifest_reader *r; struct belay_entry e; int got; };
struct cli_modes { struct cli_cursor side[2]; };
int  cli_mode_of(void *ctx, int side, const char *path, size_t len, struct receipt_meta *m);
int  cli_classify(void *ctx, const char *const *paths, const size_t *lens, const bool *dir, size_t n, unsigned char *out);
void cli_not_compared(FILE *out, const struct belay_manifest_header *hb, const struct belay_manifest_header *ha,
                      const char *prefix);

int  cmd_baseline(int argc, char **argv, FILE *out, FILE *err);
int  cmd_watch(int argc, char **argv, FILE *out, FILE *err);
int  cmd_hook(int argc, char **argv, FILE *out, FILE *err);
int  cmd_verify(int argc, char **argv, FILE *out, FILE *err);
int  cmd_prune(int argc, char **argv, FILE *out, FILE *err);
int  cmd_manifest(int argc, char **argv, FILE *out, FILE *err);

#endif
