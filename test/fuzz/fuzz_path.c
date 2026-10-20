/*
 *  Fuzz target for the lexical path utilities (BELAY_DESIGN.md §0.4c).
 *
 *  Build with libFuzzer:
 *    clang -fsanitize=fuzzer,address,undefined -Iinclude -Isrc \
 *          test/fuzz/fuzz_path.c src/util/path.c src/util/error.c -o fuzz_path
 *
 *  The contract being fuzzed: for ANY input bytes, these functions must not
 *  crash, read out of bounds, or write past `outsz`. They may reject.
 */
#include "belay/path.h"
#include "belay/error.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 8192) return 0;

    /* NUL-terminate a copy: the API takes C strings, and an embedded NUL in
     * the middle is simply a shorter string, which is valid input to fuzz. */
    char *in = malloc(size + 1);
    if (in == NULL) return 0;
    memcpy(in, data, size);
    in[size] = '\0';

    /* Vary the output buffer size from the input itself, so truncation paths
     * and exact-fit boundaries get exercised rather than only the roomy case. */
    const size_t outsz = (size_t)(data[0] % 64) + 1;
    char *out = malloc(outsz);
    if (out == NULL) { free(in); return 0; }

    if (belay_path_normalize(out, outsz, in) == 0) {
        /* On success the result must be NUL-terminated within the buffer. */
        if (memchr(out, '\0', outsz) == NULL) abort();
    }

    /* Both arguments from the same bytes: self-comparison plus whatever the
     * split produces. Return value must be exactly -1, 0 or 1. */
    int r = belay_path_within_lexical(in, in);
    if (r != -1 && r != 0 && r != 1) abort();

    char *mid = strchr(in, '/');
    if (mid != NULL) {
        r = belay_path_within_lexical(in, mid + 1);
        if (r != -1 && r != 0 && r != 1) abort();
    }

    belay_err_clear();
    free(out);
    free(in);
    return 0;
}
