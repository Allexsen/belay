/*
 *  The reference harness's driver (scripts/reference/): runs belay_diff on one
 *  manifest pair, with a store or without one, through the public API only.
 *
 *      driver --store DIR before.ndjson after.ndjson out.ndjson
 *      driver --no-store  before.ndjson after.ndjson out.ndjson
 *
 *  Exit 0 when the diff was written; 1 with belay's error on stderr when
 *  belay_diff refused or failed; 2 on a usage error.
 */
#include <stdio.h>
#include <string.h>

#include "belay/diff.h"
#include "belay/error.h"

static int usage(void)
{
    fprintf(stderr, "usage: driver (--store DIR | --no-store) before after out\n");
    return 2;
}

int main(int argc, char **argv)
{
    struct belay_diff_opts opts = { .store_dir = NULL };
    int i = 1;

    if (argc < 2)
        return usage();
    if (strcmp(argv[i], "--store") == 0) {
        if (argc != 6)
            return usage();
        opts.store_dir = argv[i + 1];
        i += 2;
    } else if (strcmp(argv[i], "--no-store") == 0) {
        if (argc != 5)
            return usage();
        i += 1;
    } else {
        return usage();
    }
    if (belay_diff(argv[i], argv[i + 1], argv[i + 2], &opts, NULL) != 0) {
        fprintf(stderr, "belay_diff: %s\n", belay_err_msg());
        return 1;
    }
    return 0;
}
