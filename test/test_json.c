/*
 *  JSON escaping, UTF-8 validation, base64.
 *
 *  These three are the byte-exactness layer of the manifest format: a path
 *  that survives a write/read round trip unchanged is the whole requirement,
 *  and filesystem paths are arbitrary bytes.
 */
#include "belay_test.h"
#include "belay/json.h"
#include "belay/error.h"

#include <string.h>

static const char *esc(const char *in) {
    static char out[1024];
    if (belay_json_escape(out, sizeof out, in, strlen(in)) == -1) return NULL;
    return out;
}

TEST(escape_handles_required_characters) {
    ASSERT_EQ_STR("plain",        esc("plain"));
    ASSERT_EQ_STR("a\\\"b",       esc("a\"b"));
    ASSERT_EQ_STR("a\\\\b",       esc("a\\b"));
    ASSERT_EQ_STR("a\\nb",        esc("a\nb"));
    ASSERT_EQ_STR("a\\tb",        esc("a\tb"));
    ASSERT_EQ_STR("a\\rb",        esc("a\rb"));
    ASSERT_EQ_STR("a\\bb",        esc("a\bb"));
    ASSERT_EQ_STR("a\\fb",        esc("a\fb"));
}

/* Control bytes without a short form need \u00XX. An unescaped 0x01 in output
 * would be invalid JSON that most parsers reject. */
TEST(escape_uses_u_form_for_other_controls) {
    ASSERT_EQ_STR("a\\u0001b", esc("a\x01" "b"));
    ASSERT_EQ_STR("\\u001f",   esc("\x1f"));
    ASSERT_EQ_STR("\\u000b",   esc("\x0b"));
}

/* '/' is legal escaped or not; leaving it bare keeps paths readable. */
TEST(escape_leaves_slash_bare) {
    ASSERT_EQ_STR("a/b/c", esc("a/b/c"));
}

/* Valid UTF-8 >= 0x80 passes through: valid UTF-8 is valid JSON. */
TEST(escape_passes_through_valid_utf8) {
    ASSERT_EQ_STR("caf\xc3\xa9", esc("caf\xc3\xa9"));
    ASSERT_EQ_STR("\xe6\x97\xa5", esc("\xe6\x97\xa5"));
}

TEST(escape_reports_truncation) {
    char small[4];
    ASSERT_EQ_INT(-1, belay_json_escape(small, sizeof small, "abcdef", 6));
    ASSERT_EQ_INT(BELAY_ERR_RANGE, belay_err_code());
    /* An escape that expands must also be caught:  needs 6 bytes and
     * cannot fit a 4-byte buffer. */
    ASSERT_EQ_INT(-1, belay_json_escape(small, sizeof small, "\x01", 1));
    belay_err_clear();
}

TEST(utf8_accepts_well_formed) {
    ASSERT_TRUE(belay_utf8_valid("", 0));
    ASSERT_TRUE(belay_utf8_valid("ascii", 5));
    ASSERT_TRUE(belay_utf8_valid("\xc2\xa0", 2));          /* U+00A0, 2-byte */
    ASSERT_TRUE(belay_utf8_valid("\xe0\xa0\x80", 3));      /* U+0800, 3-byte */
    ASSERT_TRUE(belay_utf8_valid("\xef\xbf\xbf", 3));      /* U+FFFF */
    ASSERT_TRUE(belay_utf8_valid("\xf0\x90\x80\x80", 4));  /* U+10000, 4-byte */
    ASSERT_TRUE(belay_utf8_valid("\xf4\x8f\xbf\xbf", 4));  /* U+10FFFF, max */
}

/* Each of these decodes to something a conforming decoder must refuse. If any
 * were accepted, belay_json_escape would emit invalid JSON. */
TEST(utf8_rejects_malformed) {
    ASSERT_FALSE(belay_utf8_valid("\xff", 1));
    ASSERT_FALSE(belay_utf8_valid("\x80", 1));                 /* lone continuation */
    ASSERT_FALSE(belay_utf8_valid("\xc0\x80", 2));             /* overlong NUL */
    ASSERT_FALSE(belay_utf8_valid("\xc1\xbf", 2));             /* overlong */
    ASSERT_FALSE(belay_utf8_valid("\xe0\x80\x80", 3));         /* overlong */
    ASSERT_FALSE(belay_utf8_valid("\xf0\x80\x80\x80", 4));     /* overlong */
    ASSERT_FALSE(belay_utf8_valid("\xed\xa0\x80", 3));         /* surrogate D800 */
    ASSERT_FALSE(belay_utf8_valid("\xed\xbf\xbf", 3));         /* surrogate DFFF */
    ASSERT_FALSE(belay_utf8_valid("\xf4\x90\x80\x80", 4));     /* > U+10FFFF */
    ASSERT_FALSE(belay_utf8_valid("\xf8" "\x88" "\x80" "\x80" "\x80", 5)); /* 5-byte form */
    ASSERT_FALSE(belay_utf8_valid("\xc2", 1));                 /* truncated */
    ASSERT_FALSE(belay_utf8_valid("\xe2\x82", 2));             /* truncated */
    ASSERT_FALSE(belay_utf8_valid("\xf0\x9f\x92", 3));         /* truncated */
    ASSERT_FALSE(belay_utf8_valid("a\xff" "b", 3));
}

/* A NUL is valid UTF-8 and valid in a JSON string, but never valid in a path.
 * That check belongs to the manifest reader, not here (§5.1.1). */
TEST(utf8_treats_nul_as_valid_byte) {
    ASSERT_TRUE(belay_utf8_valid("a\0b", 3));
}

TEST(base64_matches_rfc4648_vectors) {
    char out[32];
    ASSERT_EQ_INT(0, belay_base64_encode(out, sizeof out, "", 0));
    ASSERT_EQ_STR("", out);
    ASSERT_EQ_INT(0, belay_base64_encode(out, sizeof out, "f", 1));
    ASSERT_EQ_STR("Zg==", out);
    ASSERT_EQ_INT(0, belay_base64_encode(out, sizeof out, "fo", 2));
    ASSERT_EQ_STR("Zm8=", out);
    ASSERT_EQ_INT(0, belay_base64_encode(out, sizeof out, "foo", 3));
    ASSERT_EQ_STR("Zm9v", out);
    ASSERT_EQ_INT(0, belay_base64_encode(out, sizeof out, "foob", 4));
    ASSERT_EQ_STR("Zm9vYg==", out);
    ASSERT_EQ_INT(0, belay_base64_encode(out, sizeof out, "fooba", 5));
    ASSERT_EQ_STR("Zm9vYmE=", out);
    ASSERT_EQ_INT(0, belay_base64_encode(out, sizeof out, "foobar", 6));
    ASSERT_EQ_STR("Zm9vYmFy", out);
}

TEST(base64_round_trips_arbitrary_bytes) {
    unsigned char in[256];
    for (size_t i = 0; i < sizeof in; i++) in[i] = (unsigned char)i;

    char enc[512];
    ASSERT_EQ_INT(0, belay_base64_encode(enc, sizeof enc, in, sizeof in));

    unsigned char dec[256];
    size_t dlen = 0;
    ASSERT_EQ_INT(0, belay_base64_decode(dec, sizeof dec, &dlen, enc));
    ASSERT_EQ_INT((int)sizeof in, (int)dlen);
    ASSERT_EQ_INT(0, memcmp(in, dec, sizeof in));
}

/* Lenient decoding would let two different inputs mean the same path, so
 * every malformed form must be refused rather than repaired. */
TEST(base64_decode_rejects_malformed) {
    unsigned char out[64];
    size_t olen;

    ASSERT_EQ_INT(-1, belay_base64_decode(out, sizeof out, &olen, "Zm9"));      /* not %4 */
    ASSERT_EQ_INT(-1, belay_base64_decode(out, sizeof out, &olen, "Zm9v!"));    /* not %4 */
    ASSERT_EQ_INT(-1, belay_base64_decode(out, sizeof out, &olen, "Zm9!"));     /* bad char */
    ASSERT_EQ_INT(-1, belay_base64_decode(out, sizeof out, &olen, "Zm 9"));     /* space */
    ASSERT_EQ_INT(-1, belay_base64_decode(out, sizeof out, &olen, "Z=m9"));     /* misplaced pad */
    ASSERT_EQ_INT(-1, belay_base64_decode(out, sizeof out, &olen, "Zg==Zg==")); /* pad mid-stream */
    belay_err_clear();
}

/* Found by independent review: two encodings for one byte string. */
TEST(base64_decode_rejects_non_canonical_forms) {
    unsigned char out[16];
    size_t olen;
    ASSERT_EQ_INT(0, belay_base64_decode(out, sizeof out, &olen, "/w=="));   /* canonical 0xff */
    ASSERT_TRUE(olen == 1 && out[0] == 0xff);
    ASSERT_EQ_INT(-1, belay_base64_decode(out, sizeof out, &olen, "/x=="));  /* stray low bits */
    ASSERT_EQ_INT(-1, belay_base64_decode(out, sizeof out, &olen, "Zm9=")); /* stray bits, 2 bytes */
    ASSERT_EQ_INT(-1, belay_base64_decode(out, sizeof out, &olen, "//=A")); /* pad then data */
    belay_err_clear();
    /* Every canonical encoding still round-trips. */
    for (int len = 0; len < 8; len++) {
        unsigned char in[8];
        for (int i = 0; i < len; i++) in[i] = (unsigned char)(0xff - i * 37);
        char enc[32];
        ASSERT_EQ_INT(0, belay_base64_encode(enc, sizeof enc, in, (size_t)len));
        ASSERT_EQ_INT(0, belay_base64_decode(out, sizeof out, &olen, enc));
        ASSERT_TRUE(olen == (size_t)len && memcmp(in, out, (size_t)len) == 0);
    }
}

TEST(base64_reports_small_output_buffer) {
    char tiny[4];
    ASSERT_EQ_INT(-1, belay_base64_encode(tiny, sizeof tiny, "foobar", 6));
    ASSERT_EQ_INT(BELAY_ERR_RANGE, belay_err_code());

    unsigned char dtiny[2];
    size_t olen;
    ASSERT_EQ_INT(-1, belay_base64_decode(dtiny, sizeof dtiny, &olen, "Zm9vYmFy"));
    belay_err_clear();
}

int main(void) {
    RUN(escape_handles_required_characters);
    RUN(escape_uses_u_form_for_other_controls);
    RUN(escape_leaves_slash_bare);
    RUN(escape_passes_through_valid_utf8);
    RUN(escape_reports_truncation);
    RUN(utf8_accepts_well_formed);
    RUN(utf8_rejects_malformed);
    RUN(utf8_treats_nul_as_valid_byte);
    RUN(base64_matches_rfc4648_vectors);
    RUN(base64_round_trips_arbitrary_bytes);
    RUN(base64_decode_rejects_malformed);
    RUN(base64_decode_rejects_non_canonical_forms);
    RUN(base64_reports_small_output_buffer);
    return belay_test_report();
}
