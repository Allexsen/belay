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

int  cli_usage(FILE *err, const char *why);     /* one line; EXIT_USAGE */
int  cli_failed(FILE *err);                     /* belay_err as one line; EXIT_REFUSED for INVALID, else EXIT_FAILED */
void cli_err_line(FILE *err);                   /* belay_err as one line */
int  cli_open_scope(const char *scope, bool create, struct state *st, FILE *err);   /* 0, or an exit code */

int  cmd_baseline(int argc, char **argv, FILE *out, FILE *err);

#endif
