/*
 *  The belay command line (NOTES/phase5-structure.md §3; decisions Q3, Q4,
 *  Q7, Q9): check, mark, diff, log, help, --version. Every failure is one
 *  line on stderr and one exit code, with one meaning each:
 *
 *    0  done (for diff, whatever it found, unless --exit-code)
 *    1  diff --exit-code: a record that is not unchanged, unknown included
 *    2  usage: an unknown option, a missing argument, a bad id
 *    3  refused: the scope cannot be resolved, is not a directory, changed
 *       during resolution; the state is another scope's
 *    4  failed: I/O, corrupt state, out of memory
 *
 *  --json output is never mixed with an error: errors go to stderr only.
 */
#ifndef BELAY_CLI_CLI_H
#define BELAY_CLI_CLI_H

#include <stdio.h>

enum { EXIT_DONE = 0, EXIT_CHANGES = 1, EXIT_USAGE = 2, EXIT_REFUSED = 3, EXIT_FAILED = 4 };

/* Runs one command; returns its exit code. `out` and `err` are where it
 * writes (stdout and stderr in the binary). */
int cli_main(int argc, char **argv, FILE *out, FILE *err);

#endif
