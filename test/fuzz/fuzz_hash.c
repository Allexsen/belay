/*
 *  Fuzz target for the vendored hashes (§0.4c).
 *
 *  The property fuzzed is not "matches a reference" -- there is no reference
 *  in-process -- but the streaming invariant: for ANY input and ANY chunking,
 *  incremental hashing must equal one-shot hashing. A bitlen or buffer bug in
 *  update() shows up here and is invisible to single-call vector tests.
 */
#include "belay/hash.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    /* First byte picks the chunk size, so the fuzzer explores split patterns
     * rather than only the one-shot path. */
    const size_t chunk = (size_t)data[0] + 1;
    const uint8_t *msg = data + 1;
    const size_t len = size - 1;

    uint8_t one[BELAY_SHA256_DIGEST_LEN], inc[BELAY_SHA256_DIGEST_LEN];
    struct belay_sha256 a, b;

    belay_sha256_init(&a);
    belay_sha256_update(&a, msg, len);
    belay_sha256_final(&a, one);

    belay_sha256_init(&b);
    for (size_t off = 0; off < len; off += chunk) {
        size_t take = len - off < chunk ? len - off : chunk;
        belay_sha256_update(&b, msg + off, take);
    }
    belay_sha256_final(&b, inc);

    if (memcmp(one, inc, sizeof one) != 0) abort();

    uint8_t m1[BELAY_MD5_DIGEST_LEN], m2[BELAY_MD5_DIGEST_LEN];
    struct belay_md5 c, d;

    belay_md5_init(&c);
    belay_md5_update(&c, msg, len);
    belay_md5_final(&c, m1);

    belay_md5_init(&d);
    for (size_t off = 0; off < len; off += chunk) {
        size_t take = len - off < chunk ? len - off : chunk;
        belay_md5_update(&d, msg + off, take);
    }
    belay_md5_final(&d, m2);

    if (memcmp(m1, m2, sizeof m1) != 0) abort();

    /* Hex encoding must always terminate inside the buffer. */
    char hex[BELAY_SHA256_HEX_LEN + 1];
    belay_hex_encode(hex, one, sizeof one);
    if (strlen(hex) != BELAY_SHA256_HEX_LEN) abort();

    return 0;
}
