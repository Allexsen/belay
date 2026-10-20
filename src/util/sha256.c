/*
 *  SHA-256 (FIPS 180-4).
 *
 *  Written from the specification. Public domain / CC0 — no third-party code
 *  is vendored here, so there is no upstream license to carry.
 *
 *  Endian-independent: all word access goes through explicit big-endian
 *  load/store helpers rather than casting the input buffer, so this is correct
 *  on both x86_64 and arm64 (§9.1 tests both).
 */
#include "belay/hash.h"

#include <string.h>

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define CH(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)      (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define BSIG1(x)      (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SSIG0(x)      (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SSIG1(x)      (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void sha256_block(struct belay_sha256 *c, const uint8_t *blk) {
    uint32_t w[64];

    for (int i = 0; i < 16; i++) w[i] = load_be32(blk + i * 4);
    for (int i = 16; i < 64; i++)
        w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];

    uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
    uint32_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t t2 = BSIG0(a) + MAJ(a, b, cc);
        h = g; g = f; f = e;
        e = d + t1;
        d = cc; cc = b; b = a;
        a = t1 + t2;
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

void belay_sha256_init(struct belay_sha256 *c) {
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
    c->bitlen = 0;
    c->buflen = 0;
}

void belay_sha256_update(struct belay_sha256 *c, const void *data, size_t len) {
    const uint8_t *p = data;

    /* bitlen counts the message, not the buffer: it must advance even for
     * bytes that only land in buf and are processed by a later call. */
    c->bitlen += (uint64_t)len * 8;

    if (c->buflen > 0) {
        size_t need = 64 - c->buflen;
        size_t take = len < need ? len : need;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        len -= take;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }

    while (len >= 64) {
        sha256_block(c, p);
        p += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(c->buf, p, len);
        c->buflen = len;
    }
}

void belay_sha256_final(struct belay_sha256 *c, uint8_t out[BELAY_SHA256_DIGEST_LEN]) {
    const uint64_t bits = c->bitlen;

    /* Pad: 0x80, then zeros, then the 64-bit big-endian bit count. If the
     * length field does not fit in this block, one extra block is emitted --
     * that is the 55/56/57-byte boundary the tests exercise. */
    c->buf[c->buflen++] = 0x80;
    if (c->buflen > 56) {
        memset(c->buf + c->buflen, 0, 64 - c->buflen);
        sha256_block(c, c->buf);
        c->buflen = 0;
    }
    memset(c->buf + c->buflen, 0, 56 - c->buflen);

    store_be32(c->buf + 56, (uint32_t)(bits >> 32));
    store_be32(c->buf + 60, (uint32_t)bits);
    sha256_block(c, c->buf);

    for (int i = 0; i < 8; i++) store_be32(out + i * 4, c->state[i]);
}

void belay_hex_encode(char *out, const uint8_t *digest, size_t digest_len) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < digest_len; i++) {
        out[i * 2]     = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[digest_len * 2] = '\0';
}
