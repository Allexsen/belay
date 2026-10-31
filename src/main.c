/*
 *  belay entry point: the command line (src/cli/cli.c).
 *
 *  The session engine (src/session/, M4) is not wired to the binary: an
 *  unfinished sandbox command in the M1 binary would be a claim the project
 *  cannot yet make (decision 2026-10-31, Q7). It still builds on Linux, and
 *  its tests run, so it does not rot.
 */
#include "cli/cli.h"

#include <stdio.h>

int main(int argc, char **argv) {
    return cli_main(argc, argv, stdout, stderr);
}
