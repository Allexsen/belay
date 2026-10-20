#include "belay/json.h"
#include "belay/error.h"

#include <string.h>

int belay_json_escape(char *out, size_t outsz, const char *in, size_t len) {
    if (out == NULL || in == NULL || outsz == 0) {
        belay_err_set(BELAY_ERR_INVALID, 0, "json_escape: null argument");
        return -1;
    }

    static const char hex[] = "0123456789abcdef";
    size_t w = 0;

    /* Appends n bytes, reserving room for the NUL. */
    #define PUT(p, n)                                                        \
        do {                                                                 \
            if (w + (n) >= outsz) {                                          \
                belay_err_set(BELAY_ERR_RANGE, 0,                            \
                              "json_escape: needs more than %zu bytes", outsz); \
                return -1;                                                   \
            }                                                                \
            memcpy(out + w, (p), (n));                                       \
            w += (n);                                                        \
        } while (0)

    for (size_t i = 0; i < len; i++) {
        const unsigned char ch = (unsigned char)in[i];
        switch (ch) {
        case '"':  PUT("\\\"", 2); break;
        case '\\': PUT("\\\\", 2); break;
        case '\b': PUT("\\b", 2);  break;
        case '\f': PUT("\\f", 2);  break;
        case '\n': PUT("\\n", 2);  break;
        case '\r': PUT("\\r", 2);  break;
        case '\t': PUT("\\t", 2);  break;
        default:
            if (ch < 0x20) {
                /* RFC 8259 requires escaping every control character; only
                 * some have short forms. '/' is NOT escaped: legal either way,
                 * and leaving it readable matters for paths. */
                char u[6] = { '\\', 'u', '0', '0', hex[ch >> 4], hex[ch & 0x0f] };
                PUT(u, 6);
            } else {
                /* >= 0x80 passes through: valid UTF-8 is valid JSON. The
                 * caller guarantees validity via belay_utf8_valid(). */
                PUT(in + i, 1);
            }
        }
    }

    #undef PUT
    out[w] = '\0';
    return 0;
}

bool belay_utf8_valid(const char *in, size_t len) {
    const unsigned char *p = (const unsigned char *)in;
    size_t i = 0;

    while (i < len) {
        const unsigned char c = p[i];
        size_t need;
        uint32_t cp;

        if (c < 0x80) { i++; continue; }

        if ((c & 0xe0) == 0xc0)      { need = 1; cp = c & 0x1f; }
        else if ((c & 0xf0) == 0xe0) { need = 2; cp = c & 0x0f; }
        else if ((c & 0xf8) == 0xf0) { need = 3; cp = c & 0x07; }
        else return false;  /* 0x80-0xBF continuation as a lead, or 0xF8+ */

        if (i + need >= len) return false;  /* truncated sequence at end */

        for (size_t k = 1; k <= need; k++) {
            const unsigned char cc = p[i + k];
            if ((cc & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3f);
        }

        /* Overlong encodings, surrogates and out-of-range all have to be
         * rejected: each is a byte sequence that decodes to something a
         * conforming UTF-8 decoder must refuse, and letting them through
         * would emit invalid JSON. */
        if (need == 1 && cp < 0x80)    return false;
        if (need == 2 && cp < 0x800)   return false;
        if (need == 3 && cp < 0x10000) return false;
        if (cp > 0x10ffff)             return false;
        if (cp >= 0xd800 && cp <= 0xdfff) return false;

        i += need + 1;
    }
    return true;
}

static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int belay_base64_encode(char *out, size_t outsz, const void *in, size_t len) {
    if (out == NULL || (in == NULL && len > 0)) {
        belay_err_set(BELAY_ERR_INVALID, 0, "base64_encode: null argument");
        return -1;
    }

    const size_t need = 4 * ((len + 2) / 3) + 1;
    if (outsz < need) {
        belay_err_set(BELAY_ERR_RANGE, 0,
                      "base64_encode: needs %zu bytes, have %zu", need, outsz);
        return -1;
    }

    const unsigned char *p = in;
    size_t w = 0;
    size_t i = 0;

    while (i + 2 < len) {
        const uint32_t v = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8) | p[i + 2];
        out[w++] = b64[(v >> 18) & 0x3f];
        out[w++] = b64[(v >> 12) & 0x3f];
        out[w++] = b64[(v >> 6) & 0x3f];
        out[w++] = b64[v & 0x3f];
        i += 3;
    }

    if (i < len) {
        const size_t rem = len - i;   /* 1 or 2 */
        uint32_t v = (uint32_t)p[i] << 16;
        if (rem == 2) v |= (uint32_t)p[i + 1] << 8;
        out[w++] = b64[(v >> 18) & 0x3f];
        out[w++] = b64[(v >> 12) & 0x3f];
        out[w++] = rem == 2 ? b64[(v >> 6) & 0x3f] : '=';
        out[w++] = '=';
    }

    out[w] = '\0';
    return 0;
}

int belay_base64_decode(void *out, size_t outsz, size_t *outlen, const char *in) {
    if (out == NULL || in == NULL || outlen == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "base64_decode: null argument");
        return -1;
    }

    /* Reverse table built once; -1 marks every byte outside the alphabet, so
     * whitespace and newlines are rejected rather than skipped. Lenient
     * decoding would let two different inputs mean the same path. */
    static signed char rev[256];
    static int rev_ready;
    if (!rev_ready) {
        memset(rev, -1, sizeof rev);
        for (int i = 0; i < 64; i++) rev[(unsigned char)b64[i]] = (signed char)i;
        rev_ready = 1;
    }

    const size_t inlen = strlen(in);
    if (inlen == 0) { *outlen = 0; return 0; }
    if (inlen % 4 != 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "base64_decode: length %zu is not a multiple of 4", inlen);
        return -1;
    }

    size_t pad = 0;
    if (in[inlen - 1] == '=') pad++;
    if (inlen >= 2 && in[inlen - 2] == '=') pad++;

    const size_t need = inlen / 4 * 3 - pad;
    if (outsz < need) {
        belay_err_set(BELAY_ERR_RANGE, 0,
                      "base64_decode: needs %zu bytes, have %zu", need, outsz);
        return -1;
    }

    unsigned char *o = out;
    size_t w = 0;

    for (size_t i = 0; i < inlen; i += 4) {
        signed char q[4];
        for (int k = 0; k < 4; k++) {
            const char c = in[i + k];
            if (c == '=') {
                /* Padding is only legal in the final group's last two slots. */
                if (i + 4 != inlen || k < 2) {
                    belay_err_set(BELAY_ERR_CORRUPT, 0,
                                  "base64_decode: misplaced padding at offset %zu", i + k);
                    return -1;
                }
                q[k] = 0;
            } else {
                q[k] = rev[(unsigned char)c];
                if (q[k] < 0) {
                    belay_err_set(BELAY_ERR_CORRUPT, 0,
                                  "base64_decode: invalid byte 0x%02x at offset %zu",
                                  (unsigned char)c, i + k);
                    return -1;
                }
            }
        }

        const uint32_t v = ((uint32_t)q[0] << 18) | ((uint32_t)q[1] << 12) |
                           ((uint32_t)q[2] << 6)  | (uint32_t)q[3];

        if (w < need) o[w++] = (unsigned char)(v >> 16);
        if (w < need) o[w++] = (unsigned char)(v >> 8);
        if (w < need) o[w++] = (unsigned char)v;
    }

    *outlen = w;
    return 0;
}
