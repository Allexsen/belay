/*
 *  MD5 tests. Vectors from RFC 1321 appendix A.5.
 *
 *  MD5 is here only to verify against hashes dpkg and pip already recorded
 *  (§5.3). It is not used for protected-path verification (§6.3).
 */
#include "belay_test.h"
#include "belay/hash.h"

#include <stdlib.h>
#include <string.h>

static const char *md5_hex(const void *data, size_t len) {
    static char hex[BELAY_MD5_HEX_LEN + 1];
    uint8_t d[BELAY_MD5_DIGEST_LEN];
    struct belay_md5 c;
    belay_md5_init(&c);
    belay_md5_update(&c, data, len);
    belay_md5_final(&c, d);
    belay_hex_encode(hex, d, sizeof d);
    return hex;
}

static const char *md5_str(const char *s) { return md5_hex(s, strlen(s)); }

TEST(rfc1321_vectors) {
    ASSERT_EQ_STR("d41d8cd98f00b204e9800998ecf8427e", md5_str(""));
    ASSERT_EQ_STR("0cc175b9c0f1b6a831c399e269772661", md5_str("a"));
    ASSERT_EQ_STR("900150983cd24fb0d6963f7d28e17f72", md5_str("abc"));
    ASSERT_EQ_STR("f96b697d7cb7938d525a2f31aaf161d0", md5_str("message digest"));
    ASSERT_EQ_STR("c3fcd3d76192e4007dfb496cca67e13b",
                  md5_str("abcdefghijklmnopqrstuvwxyz"));
    ASSERT_EQ_STR("d174ab98d277d9f5a5611c2c9f419d9f",
                  md5_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
    ASSERT_EQ_STR("57edf4a22be3c955ac49da2e2107b67a",
                  md5_str("123456789012345678901234567890123456789012345678901234567890"
                          "12345678901234567890"));
}

/* Same padding boundaries as SHA-256; MD5's length field is little-endian,
 * which is an easy place to get the byte order backwards. */
TEST(padding_boundaries) {
    char b[200];
    memset(b, 'a', sizeof b);
    /* Cross-checked against md5sum; see the differential test in the report. */
    ASSERT_EQ_STR("ef1772b6dff9a122358552954ad0df65", md5_hex(b, 55));
    ASSERT_EQ_STR("3b0c8ac703f828b04c6c197006d17218", md5_hex(b, 56));
    ASSERT_EQ_STR("652b906d60af96844ebd21b674f35e93", md5_hex(b, 57));
    ASSERT_EQ_STR("014842d480b571495a4a0363793f7367", md5_hex(b, 64));
    ASSERT_EQ_STR("c743a45e0d2e6a95cb859adae0248435", md5_hex(b, 65));
}

TEST(streaming_equals_one_shot) {
    char buf[777];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (char)(i * 11 + 5);

    char want[BELAY_MD5_HEX_LEN + 1];
    strcpy(want, md5_hex(buf, sizeof buf));

    const size_t chunks[] = { 1, 3, 17, 63, 64, 65, 128, 500 };
    for (size_t ci = 0; ci < sizeof chunks / sizeof chunks[0]; ci++) {
        const size_t n = chunks[ci];
        struct belay_md5 c;
        belay_md5_init(&c);
        for (size_t off = 0; off < sizeof buf; off += n) {
            size_t take = sizeof buf - off < n ? sizeof buf - off : n;
            belay_md5_update(&c, buf + off, take);
        }
        uint8_t d[BELAY_MD5_DIGEST_LEN];
        char got[BELAY_MD5_HEX_LEN + 1];
        belay_md5_final(&c, d);
        belay_hex_encode(got, d, sizeof d);
        ASSERT_EQ_STR(want, got);
    }
}

TEST(handles_binary_and_nuls) {
    uint8_t bin[300];
    for (size_t i = 0; i < sizeof bin; i++) bin[i] = (uint8_t)(i % 256);
    ASSERT_EQ_INT(BELAY_MD5_HEX_LEN, (int)strlen(md5_hex(bin, sizeof bin)));

    /* NULs are ordinary bytes to a hash. */
    const char z[4] = { 0, 0, 0, 0 };
    ASSERT_EQ_STR("f1d3ff8443297732862df21dc4e57262", md5_hex(z, 4));
}

int main(void) {
    RUN(rfc1321_vectors);
    RUN(padding_boundaries);
    RUN(streaming_equals_one_shot);
    RUN(handles_binary_and_nuls);
    return belay_test_report();
}
