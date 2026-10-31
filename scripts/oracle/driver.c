/* Runs belay_diff on one pair: driver <before> <after> <out>. Exit 0, or 1
 * with belay's error on stderr. */
#include "belay/diff.h"
#include "belay/error.h"

#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: driver <before> <after> <out>\n"); return 2; }
    if (belay_diff(argv[1], argv[2], argv[3], NULL, NULL) != 0) {
        fprintf(stderr, "%s\n", belay_err_msg());
        return 1;
    }
    return 0;
}
