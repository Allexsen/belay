/* Runs belay_diff on one pair: driver [--store DIR] <before> <after> <out>.
 * Without --store the diff is given no options (NULL), so no store; with it,
 * the options name DIR as the store (diff-v1, "Content": "the store given to
 * the diff (`belay_diff`'s options)"). Exit 0, or 1 with belay's error on
 * stderr. */
#include "belay/diff.h"
#include "belay/error.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    struct belay_diff_opts opts = { .store_dir = NULL };
    int i = 1;
    if (argc == 6 && strcmp(argv[1], "--store") == 0) {
        opts.store_dir = argv[2];
        i = 3;
    } else if (argc != 4) {
        fprintf(stderr, "usage: driver [--store DIR] <before> <after> <out>\n");
        return 2;
    }
    if (belay_diff(argv[i], argv[i + 1], argv[i + 2], opts.store_dir ? &opts : NULL, NULL) != 0) {
        fprintf(stderr, "%s\n", belay_err_msg());
        return 1;
    }
    return 0;
}
