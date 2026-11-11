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

/* The Claude Code adapter (hook_claude.c). What it reads of a hook's input:
 * the top level of one JSON object, however deep its values are. `calls`:
 * the ids of tool_calls, separated by a space, malloc'd or NULL. */
struct hook_claude_in {
    char session[97], call[97], agent[97], source[32], command[64], cwd[PATH_MAX];
    bool notification;          /* the prompt is a background task's, not the user's */
    char *calls;
};
int hook_claude_parse(const char *buf, size_t len, struct hook_claude_in *out);    /* 0, or -1 when it is not such an object */
int hook_claude(const char *event, const char *scope, FILE *in, FILE *out);
extern bool hook_claude_prunes;      /* test hook: false, and a Stop starts no detached prune */         /* always 0 */
int  cmd_verify(int argc, char **argv, FILE *out, FILE *err);
int  cmd_prune(int argc, char **argv, FILE *out, FILE *err);
int  cmd_manifest(int argc, char **argv, FILE *out, FILE *err);

#endif
