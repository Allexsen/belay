/*
 *  The trust store's interpreter (test/expect/system-interpreters.md TS-1
 *  to TS-3; finding-kinds.md, trust_anchor_*). The tree is the shape TS-1
 *  measured: `update-ca-certificates` adds `etc/ssl/certs/probe-ca.pem ->
 *  /usr/local/share/ca-certificates/probe-ca.crt` and `a1c079ef.0 ->
 *  probe-ca.pem` and rewrites the bundle; a packaged anchor's link ends at
 *  `/usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt`, which
 *  `ca-certificates` owns.
 *
 *  The four certificates are real, self-signed, made once with `openssl req
 *  -x509` (OpenSSL 3.0.13); the subject and fingerprint expected of each
 *  are what `openssl x509 -noout -subject -fingerprint -sha256` printed for
 *  it. The file standing in for ISRG Root X1 holds one of them, not that
 *  root: only its place in the tree is the measured one.
 */
#include "sys_test.h"

#include "interp/x509name.h"

#include "belay/json.h"

/* subject=C = US, O = Probe Org, CN = Probe CA */
#define PEM1 \
    "-----BEGIN CERTIFICATE-----\n" \
    "MIIDSTCCAjGgAwIBAgIUOAGKQ8DmmMcJllwrnQ2U9HNMztkwDQYJKoZIhvcNAQEL\n" \
    "BQAwNDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCVByb2JlIE9yZzERMA8GA1UEAwwI\n" \
    "UHJvYmUgQ0EwHhcNMjYxMTIyMTMwNzAzWhcNMzYxMTE5MTMwNzAzWjA0MQswCQYD\n" \
    "VQQGEwJVUzESMBAGA1UECgwJUHJvYmUgT3JnMREwDwYDVQQDDAhQcm9iZSBDQTCC\n" \
    "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOTz8xGQfH2armu/pZRsDszR\n" \
    "hAue20GUt+uRVoOWfEwyCfPibn4HK0KL8Zaj0yl/TwjIl7Vcr4+8LVvF7hQYSYlH\n" \
    "4en8ZaZ+76GIoP6tu/mX+YFhpflLuoHPMaFzE/9U9w6dcIOUqQTFmO5HSvsBb7FG\n" \
    "xTQbOkFrwHSH+i8CvE/KZNWve6NMC705CyGl9aqECeGvkhaIxmhWVIauQNBiQkzT\n" \
    "4dwr+4/0M4cqD3BC3pfc2noMJkaIIsZfkZsHF8KRcKPw2thsEfhU8ExxFgHeMp2q\n" \
    "3mWMxGhUrm6bDHSgfzutIWlNKaV3KloF1LhxZJaapPZLyToEJzrusx7ZH2d4kwcC\n" \
    "AwEAAaNTMFEwHQYDVR0OBBYEFAhGWTHAmEcfNsyp7jTkAiGnzCyoMB8GA1UdIwQY\n" \
    "MBaAFAhGWTHAmEcfNsyp7jTkAiGnzCyoMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI\n" \
    "hvcNAQELBQADggEBAK2qNu2WThHnm+eb9nkMlUGeeVCbNkJIRy920mIGI/zMnPDx\n" \
    "qPXXfgyIRomtmXZtkxTg6TtD0B83UlgVU9+G+QFvjwhYPR/ouNjVc2MawD7YP+jx\n" \
    "h0ZLoicXIk3rd/rAWZTXSPYFTgIuNebP6OnkTt5cFeFeGAA+lJWFuufAS/whdcmZ\n" \
    "Ed1n/y3hf14bY5KRu2PGNmidFoGCbW4iHxsUVfydmbCO0WNy91DMgPLty2hUik2J\n" \
    "DhLG43YO5mTwQZDYqRhtWG0ZoClDD3b9/ynXFgzCrrb0KJguO8yGpMGpQ9j6g8rq\n" \
    "bbcYYkz5u0BHELBqK3IOsk8VS5/u0ZvfTjDnRnA=\n" \
    "-----END CERTIFICATE-----\n"
#define SUBJ1 "C = US, O = Probe Org, CN = Probe CA"
#define FP1 "C8:23:39:95:DE:4E:A4:EA:FF:1B:92:E9:6B:12:48:A3:08:73:F5:A1:B4:EC:DB:D0:BB:A0:B4:7C:6E:A1:D5:42"

#define PEM2 \
    "-----BEGIN CERTIFICATE-----\n" \
    "MIICcTCCAhegAwIBAgIUOefkc5Z+63SMVIFxEeWMwTwGChcwCgYIKoZIzj0EAwIw\n" \
    "gY0xCzAJBgNVBAYTAkZJMRAwDgYDVQQIDAdVdXNpbWFhMREwDwYDVQQHDAhIZWxz\n" \
    "aW5raTETMBEGA1UECgwKRXhhbXBsZSBPeTEMMAoGA1UECwwDT3BzMRUwEwYDVQQD\n" \
    "DAxleGFtcGxlLnRlc3QxHzAdBgkqhkiG9w0BCQEWEG9wc0BleGFtcGxlLnRlc3Qw\n" \
    "HhcNMjYxMTIyMTMwNzAzWhcNMzYxMTE5MTMwNzAzWjCBjTELMAkGA1UEBhMCRkkx\n" \
    "EDAOBgNVBAgMB1V1c2ltYWExETAPBgNVBAcMCEhlbHNpbmtpMRMwEQYDVQQKDApF\n" \
    "eGFtcGxlIE95MQwwCgYDVQQLDANPcHMxFTATBgNVBAMMDGV4YW1wbGUudGVzdDEf\n" \
    "MB0GCSqGSIb3DQEJARYQb3BzQGV4YW1wbGUudGVzdDBZMBMGByqGSM49AgEGCCqG\n" \
    "SM49AwEHA0IABBgWfHSYRWD5T62RVe6grNscm2j473a8gSp2FHDWQlORdfcjD1z/\n" \
    "HX5gKUlx0VCNBuCivUQ90uMYh226PICr/zijUzBRMB0GA1UdDgQWBBSrWBHzYVKK\n" \
    "L3EVuX1SfAIql2C0DTAfBgNVHSMEGDAWgBSrWBHzYVKKL3EVuX1SfAIql2C0DTAP\n" \
    "BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCJm+pLG07yMkleh74k\n" \
    "bGS0wBrmuzj5oRFb/0kZMC3VfgIge8oI3FI6kl386D95G1ZYFt1/jICt+J7bEiFs\n" \
    "87x4Ryg=\n" \
    "-----END CERTIFICATE-----\n"
#define SUBJ2 "C = FI, ST = Uusimaa, L = Helsinki, O = Example Oy, OU = Ops, CN = example.test, emailAddress = ops@example.test"
#define FP2 "AC:92:E5:2B:A7:2E:C2:FF:98:DF:42:5E:94:B5:A3:23:02:5A:67:99:F2:C6:C1:71:F0:88:89:6D:BC:7E:90:0F"

/* two domain components, a multi-valued RDN (in its encoded order), a PrintableString */
#define PEM3 \
    "-----BEGIN CERTIFICATE-----\n" \
    "MIICCDCCAa2gAwIBAgIUS/O+ynz331ZT6F34h0aIBs+ccPMwCgYIKoZIzj0EAwIw\n" \
    "WTEUMBIGCgmSJomT8ixkARkWBHRlc3QxFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxl\n" \
    "MRswCwYDVQQLDARib3RoMAwGA1UEAwwFbXVsdGkxCzAJBgNVBAUTAjQyMB4XDTI2\n" \
    "MTEyMjEzMDcwM1oXDTM2MTExOTEzMDcwM1owWTEUMBIGCgmSJomT8ixkARkWBHRl\n" \
    "c3QxFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxlMRswCwYDVQQLDARib3RoMAwGA1UE\n" \
    "AwwFbXVsdGkxCzAJBgNVBAUTAjQyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n" \
    "z5NVVTdQsktXYjVcMhNLW+UapEvb+Klaen5RrvCY2Fz/VhpcyZS8ODJVvOnD5Ck7\n" \
    "u/WVIYQh4Iasv8DbnaoJgKNTMFEwHQYDVR0OBBYEFKNTCLHNKVamsZ/L6hL58S14\n" \
    "WwCfMB8GA1UdIwQYMBaAFKNTCLHNKVamsZ/L6hL58S14WwCfMA8GA1UdEwEB/wQF\n" \
    "MAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAKc2wJxVhTORZtdWXtzISRWXDEwo9BM5\n" \
    "58rTDPd9D0ORAiEAg0sTkeT5R9xR4QnQDs6oPDDvCT28yZC4yqshSIASKBw=\n" \
    "-----END CERTIFICATE-----\n"
#define SUBJ3 "DC = test, DC = example, OU = both + CN = multi, serialNumber = 42"
#define FP3 "65:08:1F:76:6C:48:CE:8C:25:E0:E7:21:9D:7E:36:E9:EC:FB:40:61:0F:8B:3D:0F:AD:E4:21:EB:88:34:5F:4D"

/* openssl: subject=O = "T\C3\ABst, Inc ", title = "#x", UID = u1, street = 1 Main St -- values it quotes */
#define PEM4 \
    "-----BEGIN CERTIFICATE-----\n" \
    "MIIB6zCCAZGgAwIBAgIUZ1OS+btbWp3PKhOnN1uJ+pVS1hEwCgYIKoZIzj0EAwIw\n" \
    "SzEUMBIGA1UECgwLVMOrc3QsIEluYyAxCzAJBgNVBAwMAiN4MRIwEAYKCZImiZPy\n" \
    "LGQBAQwCdTExEjAQBgNVBAkMCTEgTWFpbiBTdDAeFw0yNjExMjIxMzE1NDFaFw0z\n" \
    "NjExMTkxMzE1NDFaMEsxFDASBgNVBAoMC1TDq3N0LCBJbmMgMQswCQYDVQQMDAIj\n" \
    "eDESMBAGCgmSJomT8ixkAQEMAnUxMRIwEAYDVQQJDAkxIE1haW4gU3QwWTATBgcq\n" \
    "hkjOPQIBBggqhkjOPQMBBwNCAASClStkhDtSMMUV7iyX7H7+609pJHQv00mCnPnf\n" \
    "HiNuTE5c8hL5iwjMeuIp2gG9kKunqPy6PZk/Zr8IFI25PZqHo1MwUTAdBgNVHQ4E\n" \
    "FgQUV8VQNGgOIR8jQHCB03X4y6/6SyQwHwYDVR0jBBgwFoAUV8VQNGgOIR8jQHCB\n" \
    "03X4y6/6SyQwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBUdMDm\n" \
    "55U/UUkMsJ3Ofe0cfmSV5JbVO770bYeshmQajgIhAM0S3BEj3FpN+J0rbiVLbg5w\n" \
    "eNdaijTSO2fyh3laBjzP\n" \
    "-----END CERTIFICATE-----\n"
#define FP4 "EE:E7:75:CA:E7:16:A3:B3:9F:24:DE:44:53:8D:4A:CF:9E:6A:35:B9:11:EA:93:0B:80:AE:1F:A1:F5:10:AB:A8"

#define CERTS "etc/ssl/certs"
#define LIST "var/lib/dpkg/info/ca-certificates.list"
#define ISRG "usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt"
#define PROBE "usr/local/share/ca-certificates/probe-ca.crt"

/* One event as the diff writes it. `mid` is the JSON of subject, fingerprint
 * and owner, each with its leading comma, or "". */
#define EVS(kind, words, path, target, mid, subj, more) \
    "{\"event\":\"" kind "\",\"interp\":\"trust\",\"path\":\"" path "\",\"target\":\"" target "\"" mid \
    ",\"text\":\"certificate " words " the trust store: " subj " (" path ")\"" more ",\"paths\":[\"" path "\"]}\n"
#define EVN(kind, words, path, target, mid, more) \
    "{\"event\":\"" kind "\",\"interp\":\"trust\",\"path\":\"" path "\",\"target\":\"" target "\"" mid \
    ",\"text\":\"certificate " words " the trust store: " path "\"" more ",\"paths\":[\"" path "\"]}\n"
#define SF(s, f) ",\"subject\":\"" s "\",\"fingerprint\":\"" f "\""

static int count(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

/* ---- TS-2: the subject and the fingerprint, against openssl's ---- */

static const char *pem_says(const char *pem, size_t n) {
    static char out[X509_SUBJECT_MAX + X509_FP_LEN + 16];
    char fp[X509_FP_LEN + 1], subject[X509_SUBJECT_MAX + 1];
    size_t sl = 0;
    if (!x509_pem_one(pem, n, fp, subject, &sl)) return "(none)";
    if (sl == (size_t)-1) snprintf(out, sizeof out, "(no subject)|%s", fp);
    else snprintf(out, sizeof out, "%.*s|%s", (int)sl, subject, fp);
    return out;
}
#define SAYS(pem) pem_says(pem, strlen(pem))

TEST(subject_and_fingerprint_are_what_openssl_prints) {
    ASSERT_EQ_STR(SUBJ1 "|" FP1, SAYS(PEM1));
    ASSERT_EQ_STR(SUBJ2 "|" FP2, SAYS(PEM2));
    ASSERT_EQ_STR(SUBJ3 "|" FP3, SAYS(PEM3));
    /* A value openssl quotes or escapes: the subject is not written; the fingerprint is. */
    ASSERT_EQ_STR("(no subject)|" FP4, SAYS(PEM4));
    /* Text around the block, CRLF line ends, the base64 on one line: the same certificate. */
    ASSERT_EQ_STR(SUBJ1 "|" FP1, SAYS("# Probe CA\nsubject=whatever\n" PEM1 "trailing text\n"));
    static char crlf[4096], one[4096];
    size_t w = 0, o = 0;
    const char *body = strchr(PEM1, '\n') + 1, *end = strstr(PEM1, "-----END");
    for (const char *p = PEM1; *p; p++) {
        if (*p == '\n') crlf[w++] = '\r';
        crlf[w++] = *p;
        if (!(*p == '\n' && p >= body && p + 1 < end)) one[o++] = *p;
    }
    ASSERT_EQ_STR(SUBJ1 "|" FP1, pem_says(crlf, w));
    ASSERT_EQ_STR(SUBJ1 "|" FP1, pem_says(one, o));
    /* Exactly one certificate: two say nothing, nor does none, nor one cut short. */
    ASSERT_EQ_STR("(none)", SAYS(PEM1 PEM2));
    ASSERT_EQ_STR("(none)", SAYS("no certificate here\n"));
    ASSERT_EQ_STR("(none)", SAYS(""));
    ASSERT_EQ_STR("(none)", pem_says(PEM1, 700));
    ASSERT_EQ_STR("(none)", pem_says(PEM1, strlen(PEM1) - 10));           /* no END line */
    ASSERT_EQ_STR("(none)", SAYS("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"));
    ASSERT_EQ_STR("(none)", SAYS("-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n"));
    /* Another PEM object is not a certificate. */
    ASSERT_EQ_STR("(none)", SAYS("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"));
}

/* DER by hand, wrapped as PEM: each element `tag, length, content`. */
static size_t g_n;
static unsigned char g_der[70000];
static size_t tlv(unsigned char *out, unsigned tag, const unsigned char *in, size_t n) {
    size_t w = 0;
    out[w++] = (unsigned char)tag;
    if (n < 128) out[w++] = (unsigned char)n;
    else if (n < 256) { out[w++] = 0x81; out[w++] = (unsigned char)n; }
    else { out[w++] = 0x82; out[w++] = (unsigned char)(n >> 8); out[w++] = (unsigned char)n; }
    memmove(out + w, in, n);
    return w + n;
}
static const char *der_says(const unsigned char *der, size_t n) {
    static char pem[140000];
    char *b64 = malloc(4 * ((n + 2) / 3) + 1);
    if (b64 == NULL || belay_base64_encode(b64, 4 * ((n + 2) / 3) + 1, der, n) != 0) { free(b64); return "(encode)"; }
    snprintf(pem, sizeof pem, "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", b64);
    free(b64);
    return pem_says(pem, strlen(pem));
}
/* A certificate whose subject Name has the content `name` (and whose other
 * fields are the least the reader walks past), into g_der. */
static void cert_with_name(const unsigned char *name, size_t n) {
    static unsigned char tbs[66000], t[66000];
    static const unsigned char serial[] = { 0x02, 0x01, 0x01 }, empty[] = { 0x30, 0x00 };
    size_t w = 0;
    memcpy(tbs + w, serial, 3); w += 3;
    memcpy(tbs + w, empty, 2); w += 2;          /* signature */
    memcpy(tbs + w, empty, 2); w += 2;          /* issuer */
    memcpy(tbs + w, empty, 2); w += 2;          /* validity */
    w += tlv(tbs + w, 0x30, name, n);           /* subject */
    const size_t tl = tlv(t, 0x30, tbs, w);
    g_n = tlv(g_der, 0x30, t, tl);
}
/* One RDN of one attribute: OID 2.5.4.3 (CN), a value of `tag`. */
static size_t rdn(unsigned char *out, unsigned tag, const char *val, size_t vn) {
    unsigned char atv[2048], seq[2048];
    static const unsigned char cn[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    memcpy(atv, cn, 5);
    const size_t an = 5 + tlv(atv + 5, tag, (const unsigned char *)val, vn);
    const size_t sn = tlv(seq, 0x30, atv, an);
    return tlv(out, 0x31, seq, sn);
}
#define FPANY "|"       /* a fingerprint follows; which is not this test's matter */

/* The file is written by the watched machine: every length is checked, and
 * what is not one certificate's DER says nothing. */
TEST(hostile_der_and_pem_say_nothing_and_read_nothing_past_their_end) {
    unsigned char name[4096];
    size_t n = rdn(name, 0x0c, "ok", 2);
    cert_with_name(name, n);
    ASSERT_TRUE(strncmp("CN = ok|", der_says(g_der, g_n), 8) == 0);
    /* a string type that is not written as its bytes (BMPString): no subject, a fingerprint */
    n = rdn(name, 0x1e, "\0o\0k", 4);
    cert_with_name(name, n);
    ASSERT_TRUE(strncmp("(no subject)|", der_says(g_der, g_n), 13) == 0);
    n = rdn(name, 0x1e, "ok", 2);               /* whatever its bytes: the type decides */
    cert_with_name(name, n);
    ASSERT_TRUE(strncmp("(no subject)|", der_says(g_der, g_n), 13) == 0);
    /* control bytes, bytes that are not ASCII, an empty value, a leading blank */
    static const struct { const char *v; size_t n; } NOT[] = { { "a\nb", 3 }, { "a\x1b[0m", 5 }, { "\xff\xfe", 2 },
        { "caf\xc3\xa9", 5 }, { "", 0 }, { " a", 2 }, { "a ", 2 }, { "#a", 2 }, { "a,b", 3 }, { "a+b", 3 },
        { "a\"b", 3 }, { "a\\b", 3 }, { "a<b", 3 }, { "a>b", 3 }, { "a;b", 3 }, { "a\x7f", 2 } };
    for (size_t i = 0; i < sizeof NOT / sizeof NOT[0]; i++) {
        n = rdn(name, 0x0c, NOT[i].v, NOT[i].n);
        cert_with_name(name, n);
        if (strncmp("(no subject)|", der_says(g_der, g_n), 13) != 0) BELAY_FAIL("value %zu: %s", i, der_says(g_der, g_n));
    }
    /* an unknown attribute type is written in dotted form: 1.2.3.4 is 2a 03 04 */
    static const unsigned char unknown[] = { 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x0c, 0x02, 'x', 'y' };
    cert_with_name(unknown, sizeof unknown);
    ASSERT_TRUE(strncmp("1.2.3.4 = xy|", der_says(g_der, g_n), 13) == 0);
    /* a subject over 1,024 bytes is not written */
    static char longv[1100];
    memset(longv, 'a', sizeof longv);
    n = rdn(name, 0x0c, longv, 1019);           /* "CN = " and 1,019: 1,024 exactly */
    cert_with_name(name, n);
    ASSERT_TRUE(strncmp("CN = aaaa", der_says(g_der, g_n), 9) == 0);
    n = rdn(name, 0x0c, longv, 1020);
    cert_with_name(name, n);
    ASSERT_TRUE(strncmp("(no subject)|", der_says(g_der, g_n), 13) == 0);
    /* an empty Name is an empty subject */
    cert_with_name(name, 0);
    ASSERT_TRUE(strncmp("|", der_says(g_der, g_n), 1) == 0);

    /* Malformed: each says nothing. Cut at every length; every byte of the
     * head flipped to a length past the end; an indefinite length; bytes
     * after the certificate; an RDN that is not a SET, an empty SET, an
     * attribute with a third element, an OID cut inside an arc. */
    n = rdn(name, 0x0c, "ok", 2);
    cert_with_name(name, n);
    for (size_t cut = 0; cut < g_n; cut++)
        if (strcmp("(none)", der_says(g_der, cut)) != 0) BELAY_FAIL("cut at %zu: %s", cut, der_says(g_der, cut));
    for (size_t at = 0; at < g_n; at++) {
        unsigned char copy[256];
        static const unsigned char LEN[] = { 0x7f, 0x80, 0x81, 0x84, 0x85, 0xff };
        for (size_t k = 0; k < sizeof LEN; k++) {
            memcpy(copy, g_der, g_n);
            copy[at] = LEN[k];
            der_says(copy, g_n);                /* whatever it says, it reads nothing past the end (the sanitizer build) */
        }
    }
    unsigned char bad[300];
    /* an element longer than the one it is in, though inside the file: the
     * Name one byte shorter than the RDN it holds (the Name's length is byte 14) */
    memcpy(bad, g_der, g_n);
    REQUIRE(bad[13] == 0x30 && bad[14] == 13);
    bad[14] = 12;
    ASSERT_EQ_STR("(none)", der_says(bad, g_n));
    memcpy(bad, g_der, g_n);
    bad[1] = 0x80;                              /* indefinite */
    ASSERT_EQ_STR("(none)", der_says(bad, g_n));
    memcpy(bad, g_der, g_n);
    bad[g_n] = 0x00;
    ASSERT_EQ_STR("(none)", der_says(bad, g_n + 1));
    static const unsigned char notset[] = { 0x30, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x00 };
    cert_with_name(notset, sizeof notset);
    ASSERT_EQ_STR("(none)", der_says(g_der, g_n));
    static const unsigned char emptyset[] = { 0x31, 0x00 };
    cert_with_name(emptyset, sizeof emptyset);
    ASSERT_EQ_STR("(none)", der_says(g_der, g_n));
    static const unsigned char third[] = { 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, 'a', 0x0c, 0x01, 'b' };
    cert_with_name(third, sizeof third);
    ASSERT_EQ_STR("(none)", der_says(g_der, g_n));
    static const unsigned char cutoid[] = { 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x83, 0x0c, 0x01, 'a' };
    cert_with_name(cutoid, sizeof cutoid);
    ASSERT_EQ_STR("(none)", der_says(g_der, g_n));
    static const unsigned char hugearc[] = { 0x31, 0x12, 0x30, 0x10, 0x06, 0x0b, 0x55, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                             0xff, 0xff, 0x7f, 0x0c, 0x01, 'a' };
    cert_with_name(hugearc, sizeof hugearc);
    ASSERT_EQ_STR("(none)", der_says(g_der, g_n));
    /* nesting: 1,000 SEQUENCEs inside one another is not a certificate; nothing recurses */
    static unsigned char nest[8000], tmp[8000];
    size_t nn = 0;
    for (int i = 0; i < 1000; i++) { const size_t k = tlv(tmp, 0x30, nest, nn); memcpy(nest, tmp, k); nn = k; }
    ASSERT_EQ_STR("(none)", der_says(nest, nn));
    /* 60,000 RDNs: read, and too long to write */
    static unsigned char many[66000];
    size_t mn = 0;
    for (int i = 0; i < 5000; i++) mn += rdn(many + mn, 0x0c, "x", 1);
    cert_with_name(many, mn);
    ASSERT_TRUE(strncmp("(no subject)|", der_says(g_der, g_n), 13) == 0);
    /* PEM: a NUL byte, 100,000 lines of base64, 100,000 BEGIN lines */
    ASSERT_EQ_STR("(none)", pem_says(PEM1 "\0", strlen(PEM1) + 1));
    char *big = malloc(100000 * 65 + 200);
    REQUIRE(big != NULL);
    size_t w = (size_t)sprintf(big, "-----BEGIN CERTIFICATE-----\n");
    for (int i = 0; i < 100000; i++) { memset(big + w, 'A', 64); big[w + 64] = '\n'; w += 65; }
    w += (size_t)sprintf(big + w, "-----END CERTIFICATE-----\n");
    ASSERT_EQ_STR("(none)", pem_says(big, w));
    w = 0;
    for (int i = 0; i < 100000; i++) w += (size_t)sprintf(big + w, "-----BEGIN CERTIFICATE-----\n");
    ASSERT_EQ_STR("(none)", pem_says(big, w));
    free(big);
}

/* ---- TS-1 ---- */

static void base_tree(void) {
    t_reset();
    t_file("var/lib/dpkg/diversions", "", 0644);
    t_file(LIST, "/.\n/usr/share/ca-certificates/mozilla\n/" ISRG "\n", 0644);
    t_file(ISRG, PEM2, 0644);
    t_file(CERTS "/ca-certificates.crt", PEM2, 0644);
}

/* What update-ca-certificates was seen to add: exactly one anchor a
 * certificate, its hash link and the bundle being no anchors; the target
 * where the link ends, the owner the target's, the subject and fingerprint
 * the target's. */
TEST(an_anchor_added_is_one_event_with_its_target_owner_and_subject) {
    base_tree();
    REQUIRE(t_snap(1) == 0);
    t_file(PROBE, PEM1, 0644);
    t_link(CERTS "/probe-ca.pem", "/" PROBE);
    t_link(CERTS "/a1c079ef.0", "probe-ca.pem");
    t_link(CERTS "/ISRG_Root_X1.pem", "/" ISRG);
    t_link(CERTS "/4042bcee.0", "ISRG_Root_X1.pem");
    t_file(CERTS "/ca-certificates.crt", PEM2 PEM1, 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EVS("trust_anchor_added", "added to", CERTS "/ISRG_Root_X1.pem", ISRG, SF(SUBJ2, FP2) ",\"owner\":\"ca-certificates\"", SUBJ2, "")
        EVS("trust_anchor_added", "added to", CERTS "/probe-ca.pem", PROBE, SF(SUBJ1, FP1) ",\"owner\":null", SUBJ1, ""),
        t_events(1, 2));
    /* The records of the hash links, the bundle and the certificate file stand, with no finding. */
    const char *d = t_diff(1, 2);
    ASSERT_TRUE(strstr(t_record(d, CERTS "/a1c079ef.0"), "\"outcome\":\"added\"") != NULL);
    ASSERT_TRUE(strstr(t_record(d, CERTS "/a1c079ef.0"), "findings") == NULL);
    ASSERT_TRUE(strstr(t_record(d, CERTS "/ca-certificates.crt"), "\"outcome\":\"modified\"") != NULL);
    ASSERT_TRUE(strstr(t_record(d, PROBE), "\"outcome\":\"added\"") != NULL);
    ASSERT_TRUE(strstr(t_record(d, CERTS "/probe-ca.pem"), "findings") == NULL);

    /* Removed, the certificate file still there: the same, by the after-manifest. */
    t_rm(CERTS "/probe-ca.pem");
    t_rm(CERTS "/a1c079ef.0");
    t_file(CERTS "/ca-certificates.crt", PEM2, 0644);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(EVS("trust_anchor_removed", "removed from", CERTS "/probe-ca.pem", PROBE, SF(SUBJ1, FP1) ",\"owner\":null", SUBJ1, ""),
                  t_events(2, 3));
    /* Removed with its certificate file: the target is the path the link
     * named, and what it held cannot be told. */
    t_rm(CERTS "/ISRG_Root_X1.pem");
    t_rm(CERTS "/4042bcee.0");
    t_rm(ISRG);
    REQUIRE(t_snap(4) == 0);
    ASSERT_EQ_STR(EVN("trust_anchor_removed", "removed from", CERTS "/ISRG_Root_X1.pem", ISRG, ",\"owner\":\"ca-certificates\"", ""),
                  t_events(3, 4));
}

/* A regular file is an anchor too: its own target, its own content. A link
 * whose text changed, and a file whose content did, are one removed and one
 * added (SI-3). With no dpkg database nothing is said of the owner. */
TEST(a_file_anchor_and_a_changed_anchor) {
    t_reset();
    t_file(PROBE, PEM1, 0644);
    t_file("usr/local/share/ca-certificates/other.crt", PEM3, 0644);
    t_file(CERTS "/local.crt", PEM3, 0644);
    t_link(CERTS "/probe-ca.pem", "/" PROBE);
    REQUIRE(t_snap(1) == 0);
    t_file(CERTS "/local.crt", PEM1, 0644);
    t_link(CERTS "/probe-ca.pem", "../../../usr/local/share/ca-certificates/./other.crt");
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EVS("trust_anchor_removed", "removed from", CERTS "/local.crt", CERTS "/local.crt", SF(SUBJ3, FP3), SUBJ3, "")
        EVS("trust_anchor_added", "added to", CERTS "/local.crt", CERTS "/local.crt", SF(SUBJ1, FP1), SUBJ1, "")
        EVS("trust_anchor_removed", "removed from", CERTS "/probe-ca.pem", PROBE, SF(SUBJ1, FP1), SUBJ1, "")
        EVS("trust_anchor_added", "added to", CERTS "/probe-ca.pem", "usr/local/share/ca-certificates/other.crt", SF(SUBJ3, FP3), SUBJ3, ""),
        t_events(1, 2));
    /* A file that is no certificate, one with two, one openssl would quote. */
    t_file(CERTS "/junk.pem", "hello\n", 0644);
    t_file(CERTS "/two.pem", PEM1 PEM2, 0644);
    t_file(CERTS "/quoted.crt", PEM4, 0644);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(
        EVN("trust_anchor_added", "added to", CERTS "/junk.pem", CERTS "/junk.pem", "", "")
        EVN("trust_anchor_added", "added to", CERTS "/quoted.crt", CERTS "/quoted.crt", ",\"fingerprint\":\"" FP4 "\"", "")
        EVN("trust_anchor_added", "added to", CERTS "/two.pem", CERTS "/two.pem", "", ""),
        t_events(2, 3));
    /* Only the mode or the times changed: nothing. */
    char p[700];
    snprintf(p, sizeof p, "%s/root/" CERTS "/junk.pem", g_dir);
    REQUIRE(chmod(p, 0600) == 0);
    REQUIRE(t_snap(4) == 0);
    ASSERT_EQ_STR("", t_events(3, 4));
}

/* ---- chains, by hand: the after-manifest is the entries given ---- */

static struct belay_entry lnk(const char *path, const char *target) {
    struct belay_entry e = t_entry(path, BELAY_T_LNK, 0777, NULL);
    e.has_link_target = true;
    e.link_target_len = strlen(target);
    memcpy(e.link_target, target, e.link_target_len);
    return e;
}

/* The events of one anchor link at `path` with the text `text`, added, the
 * after-manifest being after[0..n). */
static const char *chain(struct t_run *r, const char *path, const char *text, const struct belay_entry *after, size_t n) {
    tr_begin(r, BELAY_INTERP_TRUST);
    const struct belay_entry a = lnk(path, text);
    tr_path(r, path, NULL, &a, "added");
    return tr_end(r, after, n);
}

TEST(the_target_is_where_the_chain_of_links_ends_by_the_after_manifest) {
    struct t_run r;
    /* two links, then a file with a kept copy: its path, its certificate */
    struct belay_entry two[3];
    two[0] = lnk("etc/alternatives/ca.crt", "../../usr/share/x/real.crt");
    two[1] = lnk("etc/ssl/certs/b.crt", "/etc/alternatives/ca.crt");
    two[2] = t_entry("usr/share/x/real.crt", BELAY_T_REG, 0644, t_put(PEM3));
    ASSERT_EQ_STR(EVS("trust_anchor_added", "added to", CERTS "/a.pem", "usr/share/x/real.crt", SF(SUBJ3, FP3), SUBJ3, ""),
                  chain(&r, CERTS "/a.pem", "b.crt", two, 3));
    tr_free(&r);
    /* the file there, nothing kept of it (a metadata root's): the target, and no more */
    two[2] = t_entry("usr/share/x/real.crt", BELAY_T_REG, 0644, NULL);
    two[2].meta = true;
    ASSERT_EQ_STR(EVN("trust_anchor_added", "added to", CERTS "/a.pem", "usr/share/x/real.crt", "", ""),
                  chain(&r, CERTS "/a.pem", "b.crt", two, 3));
    tr_free(&r);
    /* the manifest lacks what the link names: the last path named */
    ASSERT_EQ_STR(EVN("trust_anchor_added", "added to", CERTS "/a.pem", "usr/share/x/real.crt", "", ""),
                  chain(&r, CERTS "/a.pem", "b.crt", two, 2));
    tr_free(&r);
    ASSERT_EQ_STR(EVN("trust_anchor_added", "added to", CERTS "/a.pem", "etc/ssl/certs/b.crt", "", ""),
                  chain(&r, CERTS "/a.pem", "b.crt", NULL, 0));
    tr_free(&r);
    /* a directory where the chain ends: its path */
    const struct belay_entry d = t_entry("usr/share/x", BELAY_T_DIR, 0755, NULL);
    ASSERT_EQ_STR(EVN("trust_anchor_added", "added to", CERTS "/a.pem", "usr/share/x", "", ""),
                  chain(&r, CERTS "/a.pem", "/usr/share/x/", &d, 1));
    tr_free(&r);
    /* a loop ends after 8 links, at a path of it; nothing hangs */
    struct belay_entry loop[2];
    loop[0] = lnk("etc/ssl/certs/x.pem", "y.pem");
    loop[1] = lnk("etc/ssl/certs/y.pem", "x.pem");
    ASSERT_EQ_STR(EVN("trust_anchor_added", "added to", CERTS "/x.pem", "etc/ssl/certs/y.pem", "", ""),
                  chain(&r, CERTS "/x.pem", "y.pem", loop, 2));
    tr_free(&r);
    /* `..` does not climb above the root; `.` and empty components are nothing */
    const struct belay_entry f = t_entry("opt/c.crt", BELAY_T_REG, 0644, t_put(PEM1));
    ASSERT_EQ_STR(EVS("trust_anchor_added", "added to", CERTS "/a.pem", "opt/c.crt", SF(SUBJ1, FP1), SUBJ1, ""),
                  chain(&r, CERTS "/a.pem", "../../../../../..//opt/./c.crt", &f, 1));
    tr_free(&r);
    /* a text that names the root itself, an empty text: the link's own path */
    ASSERT_EQ_STR(EVN("trust_anchor_added", "added to", CERTS "/a.pem", CERTS "/a.pem", "", ""), chain(&r, CERTS "/a.pem", "/", NULL, 0));
    tr_free(&r);
    ASSERT_EQ_STR(EVN("trust_anchor_added", "added to", CERTS "/a.pem", CERTS "/a.pem", "", ""), chain(&r, CERTS "/a.pem", "../../..", NULL, 0));
    tr_free(&r);
    /* a tree inside the scope: an absolute text is read from that tree's root, and `..` stops there */
    const struct belay_entry in = t_entry("srv/root/usr/share/c.crt", BELAY_T_REG, 0644, t_put(PEM1));
    ASSERT_EQ_STR(EVS("trust_anchor_added", "added to", "srv/root/" CERTS "/a.pem", "srv/root/usr/share/c.crt", SF(SUBJ1, FP1), SUBJ1, ""),
                  chain(&r, "srv/root/" CERTS "/a.pem", "/usr/share/c.crt", &in, 1));
    tr_free(&r);
    ASSERT_EQ_STR(EVS("trust_anchor_added", "added to", "srv/root/" CERTS "/a.pem", "srv/root/usr/share/c.crt", SF(SUBJ1, FP1), SUBJ1, ""),
                  chain(&r, "srv/root/" CERTS "/a.pem", "../../../../../usr/share/c.crt", &in, 1));
    tr_free(&r);
}

/* What is no anchor is declined; an unknown outcome is read and its event
 * provisional; a sealed file or one with no copy is an anchor of which no
 * more can be told. Never could_not_interpret: nothing here is parsed that
 * the event needs. */
TEST(what_is_no_anchor_is_declined_and_what_cannot_be_read_is_still_named) {
    struct t_run r;
    tr_begin(&r, BELAY_INTERP_TRUST);
    const struct belay_entry cert = t_entry("x", BELAY_T_REG, 0644, t_put(PEM1));
    const struct belay_entry hash = lnk(CERTS "/a1c079ef.0", "probe-ca.pem");
    static const char *const NOT[] = { CERTS "/a1c079ef.0", CERTS "/ca-certificates.crt", CERTS "/sub/x.pem", CERTS "/README",
                                       CERTS "/x.pem.bak", "usr/local/share/ca-certificates/probe-ca.crt",
                                       "usr/local/share/ca-certificates/sub/x.crt", "etc/ssl/x.pem", "etc/ssl/certsx/x.pem",
                                       "ssl/certs/x.pem" };
    for (size_t i = 0; i < sizeof NOT / sizeof NOT[0]; i++) {
        ASSERT_EQ_STR("", tr_path(&r, NOT[i], NULL, i == 0 ? &hash : &cert, "added"));
        ASSERT_EQ_INT(BELAY_INTERP_DECLINE, (int)r.last);
    }
    const struct belay_entry dir = t_entry(CERTS "/d.pem", BELAY_T_DIR, 0755, NULL);
    ASSERT_EQ_STR("", tr_path(&r, CERTS "/d.pem", NULL, &dir, "added"));
    ASSERT_EQ_STR("", tr_path(&r, CERTS "/m.pem", &cert, &cert, "metadata_only"));
    ASSERT_EQ_STR("", tr_end(&r, NULL, 0));
    tr_free(&r);

    tr_begin(&r, BELAY_INTERP_TRUST);
    struct belay_entry sealed = t_entry(CERTS "/s.pem", BELAY_T_REG, 0600, NULL);
    sealed.sealed = true;
    ASSERT_EQ_STR("", tr_path(&r, CERTS "/s.pem", NULL, &sealed, "added"));
    const struct belay_entry gone = t_entry(CERTS "/g.crt", BELAY_T_REG, 0644,
                                            "0000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_EQ_STR("", tr_path(&r, CERTS "/g.crt", &gone, NULL, "removed"));
    ASSERT_EQ_STR("", tr_path(&r, CERTS "/u.pem", NULL, &cert, "unknown"));
    /* a directory that became an anchor: the anchor added, nothing removed */
    ASSERT_EQ_STR("", tr_path(&r, CERTS "/t.pem", &dir, &cert, "type_changed"));
    /* a link whose text could not be read names nothing */
    struct belay_entry blind = lnk(CERTS "/b.pem", "/opt/stale.crt");     /* the last text read, which may be stale */
    blind.unreadable = true;
    struct belay_entry none = t_entry(CERTS "/n.pem", BELAY_T_LNK, 0777, NULL);
    memcpy(none.link_target, "/opt/x.crt", 10);                           /* bytes in the buffer, and no text recorded */
    none.link_target_len = 10;
    ASSERT_EQ_STR("", tr_path(&r, CERTS "/n.pem", NULL, &none, "added"));
    ASSERT_EQ_STR("", tr_path(&r, CERTS "/b.pem", NULL, &blind, "added"));
    ASSERT_EQ_STR(
        EVN("trust_anchor_added", "added to", CERTS "/b.pem", CERTS "/b.pem", "", "")
        EVN("trust_anchor_removed", "removed from", CERTS "/g.crt", CERTS "/g.crt", "", "")
        EVN("trust_anchor_added", "added to", CERTS "/n.pem", CERTS "/n.pem", "", "")
        EVN("trust_anchor_added", "added to", CERTS "/s.pem", CERTS "/s.pem", "", "")
        EVS("trust_anchor_added", "added to", CERTS "/t.pem", CERTS "/t.pem", SF(SUBJ1, FP1), SUBJ1, "")
        EVS("trust_anchor_added", "added to", CERTS "/u.pem", CERTS "/u.pem", SF(SUBJ1, FP1), SUBJ1, ",\"provisional\":true"),
        tr_end(&r, NULL, 0));
    tr_free(&r);
}

/* Hostile names and texts: a link text that is not UTF-8 or very long, a
 * thousand anchors in one diff, each followed. */
TEST(hostile_links_and_many_anchors) {
    struct t_run r;
    /* a text that is not UTF-8: the path it names is the target, which the core then refuses as a string (E9) */
    ASSERT_EQ_STR("{\"event\":\"invalid_finding\",\"interp\":\"trust\",\"text\":\"invalid finding\",\"paths\":[\"" CERTS "/a.pem\"]}\n",
                  chain(&r, CERTS "/a.pem", "\xff\xfe.crt", NULL, 0));
    tr_free(&r);
    /* a text of 4,095 bytes: longer than a manifest's path once resolved -- names nothing */
    static char longt[4096];
    memset(longt, 'a', 4095);
    ASSERT_EQ_STR(EVN("trust_anchor_added", "added to", CERTS "/a.pem", CERTS "/a.pem", "", ""), chain(&r, CERTS "/a.pem", longt, NULL, 0));
    tr_free(&r);
    /* 1,000 anchors, each a link to one file: 1,000 events, one certificate read for each */
    tr_begin(&r, BELAY_INTERP_TRUST);
    for (int i = 0; i < 1000; i++) {
        char p[64];
        snprintf(p, sizeof p, CERTS "/n%04d.pem", i);
        const struct belay_entry a = lnk(p, "/opt/c.crt");
        tr_path(&r, p, NULL, &a, "added");
    }
    const struct belay_entry f = t_entry("opt/c.crt", BELAY_T_REG, 0644, t_put(PEM1));
    const char *ev = tr_end(&r, &f, 1);
    ASSERT_EQ_INT(1000, count(ev, "\"target\":\"opt/c.crt\",\"subject\":\"" SUBJ1 "\""));
    ASSERT_EQ_INT(1000, count(ev, "\n"));
    tr_free(&r);
}

int main(void) {
    t_begin("trust");
    RUN(subject_and_fingerprint_are_what_openssl_prints);
    RUN(hostile_der_and_pem_say_nothing_and_read_nothing_past_their_end);
    RUN(an_anchor_added_is_one_event_with_its_target_owner_and_subject);
    RUN(a_file_anchor_and_a_changed_anchor);
    RUN(the_target_is_where_the_chain_of_links_ends_by_the_after_manifest);
    RUN(what_is_no_anchor_is_declined_and_what_cannot_be_read_is_still_named);
    RUN(hostile_links_and_many_anchors);
    free(g_text);
    t_end();
    return belay_test_report();
}
