/*
 *  SHA-256 tests.
 *
 *  Vectors are FIPS 180-4 / NIST CAVP plus the classic published values.
 *  The padding-boundary cases (55/56/57/63/64/65 bytes) matter most: those are
 *  where the length field stops fitting in the final block and an extra block
 *  is emitted.
 */
#include "belay_test.h"
#include "belay/hash.h"

#include <stdlib.h>
#include <string.h>

static const char *sha256_hex(const void *data, size_t len) {
    static char hex[BELAY_SHA256_HEX_LEN + 1];
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    struct belay_sha256 c;
    belay_sha256_init(&c);
    belay_sha256_update(&c, data, len);
    belay_sha256_final(&c, d);
    belay_hex_encode(hex, d, sizeof d);
    return hex;
}

static const char *sha256_str(const char *s) { return sha256_hex(s, strlen(s)); }

TEST(nist_known_vectors) {
    /* FIPS 180-4 examples. */
    ASSERT_EQ_STR("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                  sha256_str(""));
    ASSERT_EQ_STR("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                  sha256_str("abc"));
    ASSERT_EQ_STR("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                  sha256_str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    ASSERT_EQ_STR("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
                  sha256_str("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                             "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
}

/* 'a' x 1,000,000 -- the standard long-message vector. Also the only test
 * that exercises many thousands of block iterations. */
TEST(nist_million_a) {
    char *buf = malloc(1000000);
    ASSERT_TRUE(buf != NULL);
    memset(buf, 'a', 1000000);
    ASSERT_EQ_STR("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
                  sha256_hex(buf, 1000000));
    free(buf);
}

/* The padding boundaries. At 56 bytes the 0x80 lands at offset 56, leaving no
 * room for the 8-byte length, so an extra block must be emitted. Off-by-one
 * here is the single most common SHA bug. */
TEST(padding_boundaries) {
    char b[200];
    memset(b, 'a', sizeof b);

    /* Cross-checked against an independent implementation; see the
     * sha256sum differential test in the phase report. */
    ASSERT_EQ_STR("9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
                  sha256_hex(b, 55));
    ASSERT_EQ_STR("b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
                  sha256_hex(b, 56));
    ASSERT_EQ_STR("f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6",
                  sha256_hex(b, 57));
    ASSERT_EQ_STR("7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
                  sha256_hex(b, 63));
    ASSERT_EQ_STR("ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
                  sha256_hex(b, 64));
    ASSERT_EQ_STR("635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
                  sha256_hex(b, 65));
    /* Second-block boundary: 119/120 repeat the 55/56 situation one block on. */
    ASSERT_EQ_STR("31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb",
                  sha256_hex(b, 119));
    ASSERT_EQ_STR("2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c",
                  sha256_hex(b, 120));
}

/* Streaming must equal one-shot for every chunking pattern. A bitlen bug that
 * only shows with split input is invisible to single-call tests. */
TEST(streaming_equals_one_shot) {
    char buf[1000];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (char)(i * 7 + 3);

    char want[BELAY_SHA256_HEX_LEN + 1];
    strcpy(want, sha256_hex(buf, sizeof buf));

    const size_t chunks[] = { 1, 2, 3, 7, 31, 63, 64, 65, 127, 128, 333, 999 };
    for (size_t ci = 0; ci < sizeof chunks / sizeof chunks[0]; ci++) {
        const size_t n = chunks[ci];
        struct belay_sha256 c;
        belay_sha256_init(&c);
        for (size_t off = 0; off < sizeof buf; off += n) {
            size_t take = sizeof buf - off < n ? sizeof buf - off : n;
            belay_sha256_update(&c, buf + off, take);
        }
        uint8_t d[BELAY_SHA256_DIGEST_LEN];
        char got[BELAY_SHA256_HEX_LEN + 1];
        belay_sha256_final(&c, d);
        belay_hex_encode(got, d, sizeof d);
        ASSERT_EQ_STR(want, got);
    }
}

/* Zero-length update calls must be harmless no-ops. */
TEST(empty_updates_are_noops) {
    struct belay_sha256 c;
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    char got[BELAY_SHA256_HEX_LEN + 1];

    belay_sha256_init(&c);
    belay_sha256_update(&c, "", 0);
    belay_sha256_update(&c, "abc", 3);
    belay_sha256_update(&c, "", 0);
    belay_sha256_final(&c, d);
    belay_hex_encode(got, d, sizeof d);
    ASSERT_EQ_STR("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", got);
}

/* Binary data including NULs and high bytes -- file content is not text. */
TEST(handles_binary_data) {
    uint8_t bin[256];
    for (size_t i = 0; i < sizeof bin; i++) bin[i] = (uint8_t)i;
    const char *h = sha256_hex(bin, sizeof bin);
    ASSERT_EQ_INT(BELAY_SHA256_HEX_LEN, (int)strlen(h));
}

TEST(hex_encode_is_lowercase_and_terminated) {
    uint8_t d[4] = { 0x00, 0x0f, 0xa5, 0xff };
    char out[9];
    belay_hex_encode(out, d, sizeof d);
    ASSERT_EQ_STR("000fa5ff", out);
    ASSERT_EQ_INT('\0', out[8]);
}

int main(void) {
    RUN(nist_known_vectors);
    RUN(nist_million_a);
    RUN(padding_boundaries);
    RUN(streaming_equals_one_shot);
    RUN(empty_updates_are_noops);
    RUN(handles_binary_data);
    RUN(hex_encode_is_lowercase_and_terminated);
    return belay_test_report();
}
