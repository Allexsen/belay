/*
 *  Hashing for belay.
 *
 *  Vendored rather than linked (decided M1 phase 1):
 *    - the design calls for one static binary with no runtime deps (§5.6);
 *    - the integrity layer must verify against dpkg md5sums and pip RECORD
 *      (§5.3), so MD5 is required regardless, and OpenSSL 3 deprecated its
 *      direct MD5 API;
 *    - a vendored file builds identically on Linux and macOS with no
 *      pkg-config, which §9.1 requires.
 *
 *  MD5 IS NOT A SECURITY PRIMITIVE HERE. It exists only to compare against
 *  hashes that dpkg already recorded in that algorithm. Never use it for
 *  protected-path verification (§6.3) -- that is SHA-256's job.
 */
#ifndef BELAY_HASH_H
#define BELAY_HASH_H

#include <stddef.h>
#include <stdint.h>

#define BELAY_SHA256_DIGEST_LEN 32
#define BELAY_SHA256_HEX_LEN    64   /* excludes the NUL */
#define BELAY_MD5_DIGEST_LEN    16
#define BELAY_MD5_HEX_LEN       32   /* excludes the NUL */

struct belay_sha256 {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
};

struct belay_md5 {
    uint32_t state[4];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
};

/* Streaming interface: init, update any number of times with any chunk sizes,
 * then final. Hashing a 5GB file must not require 5GB of memory. */
void belay_sha256_init(struct belay_sha256 *c);
void belay_sha256_update(struct belay_sha256 *c, const void *data, size_t len);
void belay_sha256_final(struct belay_sha256 *c, uint8_t out[BELAY_SHA256_DIGEST_LEN]);

void belay_md5_init(struct belay_md5 *c);
void belay_md5_update(struct belay_md5 *c, const void *data, size_t len);
void belay_md5_final(struct belay_md5 *c, uint8_t out[BELAY_MD5_DIGEST_LEN]);

/*
 *  Lowercase hex, NUL-terminated. `out` must hold at least
 *  BELAY_*_HEX_LEN + 1 bytes.
 */
void belay_hex_encode(char *out, const uint8_t *digest, size_t digest_len);

#endif /* BELAY_HASH_H */
