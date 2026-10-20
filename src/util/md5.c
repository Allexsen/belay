/*
 *  MD5 (RFC 1321).
 *
 *  Written from the specification. Public domain / CC0 — no third-party code
 *  is vendored, so there is no upstream license to carry.
 *
 *  NOT A SECURITY PRIMITIVE. MD5 is collision-broken and is here for exactly
 *  one reason: dpkg records md5sums and pip's RECORD historically used it, so
 *  verifying against those databases (§5.3) requires computing the same
 *  algorithm they did. Protected-path verification (§6.3) uses SHA-256.
 *
 *  Little-endian word order, unlike SHA-256's big-endian. Access goes through
 *  explicit helpers so this is correct on x86_64 and arm64 alike.
 */
#include "belay/hash.h"

#include <string.h>

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint8_t S[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void md5_block(struct belay_md5 *c, const uint8_t *blk) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++) m[i] = load_le32(blk + i * 4);

    uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];

    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16)      { f = (b & cc) | (~b & d);       g = i; }
        else if (i < 32) { f = (d & b) | (~d & cc);       g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ cc ^ d;                g = (3 * i + 5) % 16; }
        else             { f = cc ^ (b | ~d);             g = (7 * i) % 16; }

        f = f + a + K[i] + m[g];
        a = d;
        d = cc;
        cc = b;
        b = b + ROL32(f, S[i]);
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
}

void belay_md5_init(struct belay_md5 *c) {
    c->state[0] = 0x67452301;
    c->state[1] = 0xefcdab89;
    c->state[2] = 0x98badcfe;
    c->state[3] = 0x10325476;
    c->bitlen = 0;
    c->buflen = 0;
}

void belay_md5_update(struct belay_md5 *c, const void *data, size_t len) {
    const uint8_t *p = data;
    c->bitlen += (uint64_t)len * 8;

    if (c->buflen > 0) {
        size_t need = 64 - c->buflen;
        size_t take = len < need ? len : need;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        len -= take;
        if (c->buflen == 64) {
            md5_block(c, c->buf);
            c->buflen = 0;
        }
    }

    while (len >= 64) {
        md5_block(c, p);
        p += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(c->buf, p, len);
        c->buflen = len;
    }
}

void belay_md5_final(struct belay_md5 *c, uint8_t out[BELAY_MD5_DIGEST_LEN]) {
    const uint64_t bits = c->bitlen;

    c->buf[c->buflen++] = 0x80;
    if (c->buflen > 56) {
        memset(c->buf + c->buflen, 0, 64 - c->buflen);
        md5_block(c, c->buf);
        c->buflen = 0;
    }
    memset(c->buf + c->buflen, 0, 56 - c->buflen);

    /* Little-endian length, low word first -- the opposite of SHA-256. */
    store_le32(c->buf + 56, (uint32_t)bits);
    store_le32(c->buf + 60, (uint32_t)(bits >> 32));
    md5_block(c, c->buf);

    for (int i = 0; i < 4; i++) store_le32(out + i * 4, c->state[i]);
}
