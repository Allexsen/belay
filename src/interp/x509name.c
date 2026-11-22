#include "x509name.h"

#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char BEGIN[] = "-----BEGIN CERTIFICATE-----";
static const char END[] = "-----END CERTIFICATE-----";

static const char *find(const char *s, const char *e, const char *what) {
    const size_t n = strlen(what);
    for (; s + n <= e; s++) {
        s = memchr(s, '-', (size_t)(e - s));
        if (s == NULL || s + n > e) return NULL;
        if (memcmp(s, what, n) == 0) return s;
    }
    return NULL;
}

/* ---- DER: one element at a time, definite lengths only ---- */

struct der { const unsigned char *p, *e; };

/* The element at d->p: its tag, and its content as *in; d moves past it.
 * false: cut short, an indefinite or over-long length, a multi-byte tag. */
static bool der_next(struct der *d, unsigned *tag, struct der *in) {
    if (d->e - d->p < 2) return false;
    *tag = d->p[0];
    if ((*tag & 0x1f) == 0x1f) return false;
    size_t len = d->p[1];
    const unsigned char *q = d->p + 2;
    if (len & 0x80) {
        const size_t nb = len & 0x7f;
        if (nb == 0 || nb > 4 || (size_t)(d->e - q) < nb) return false;
        len = 0;
        for (size_t i = 0; i < nb; i++) len = (len << 8) | q[i];
        q += nb;
    }
    if ((size_t)(d->e - q) < len) return false;
    *in = (struct der){ q, q + len };
    d->p = q + len;
    return true;
}

static bool der_expect(struct der *d, unsigned want, struct der *in) {
    unsigned tag;
    return der_next(d, &tag, in) && tag == want;
}

/* ---- the subject ---- */

static const struct { const char *oid, *name; } NAMES[] = {
    { "2.5.4.3", "CN" }, { "2.5.4.4", "SN" }, { "2.5.4.5", "serialNumber" }, { "2.5.4.6", "C" },
    { "2.5.4.7", "L" }, { "2.5.4.8", "ST" }, { "2.5.4.9", "street" }, { "2.5.4.10", "O" },
    { "2.5.4.11", "OU" }, { "2.5.4.12", "title" }, { "2.5.4.13", "description" },
    { "2.5.4.15", "businessCategory" }, { "2.5.4.17", "postalCode" }, { "2.5.4.42", "GN" },
    { "2.5.4.43", "initials" }, { "2.5.4.46", "dnQualifier" }, { "2.5.4.97", "organizationIdentifier" },
    { "1.2.840.113549.1.9.1", "emailAddress" }, { "0.9.2342.19200300.100.1.25", "DC" },
    { "0.9.2342.19200300.100.1.1", "UID" }, { "1.3.6.1.4.1.311.60.2.1.1", "jurisdictionL" },
    { "1.3.6.1.4.1.311.60.2.1.2", "jurisdictionST" }, { "1.3.6.1.4.1.311.60.2.1.3", "jurisdictionC" },
};

/* An OID's content in dotted form. false: not one, or an arc past 64 bits. */
static bool oid_dotted(struct der o, char *out, size_t cap) {
    size_t w = 0;
    uint64_t arc = 0;
    bool first = true, in_arc = false;
    if (o.p == o.e) return false;
    for (const unsigned char *p = o.p; p < o.e; p++) {
        if (!in_arc && *p == 0x80) return false;            /* a leading zero: not DER */
        if (arc >> 57) return false;
        arc = (arc << 7) | (*p & 0x7f);
        in_arc = (*p & 0x80) != 0;
        if (in_arc) continue;
        int k;
        if (first) {
            const unsigned a = arc < 40 ? 0 : arc < 80 ? 1 : 2;
            k = snprintf(out + w, cap - w, "%u.%" PRIu64, a, arc - 40u * a);
            first = false;
        } else {
            k = snprintf(out + w, cap - w, ".%" PRIu64, arc);
        }
        if (k < 0 || (size_t)k >= cap - w) return false;
        w += (size_t)k;
        arc = 0;
    }
    return !in_arc;
}

/* Whether OpenSSL writes the value as its bytes, with no quote or escape. */
static bool plain_value(unsigned tag, struct der v) {
    if (tag != 0x13 && tag != 0x0c && tag != 0x16 && tag != 0x14) return false;
    const size_t n = (size_t)(v.e - v.p);
    if (n == 0 || v.p[0] == '#' || v.p[0] == ' ' || v.p[n - 1] == ' ') return false;
    for (size_t i = 0; i < n; i++)
        if (v.p[i] < 0x20 || v.p[i] > 0x7e || strchr(",+\"\\<>;", v.p[i]) != NULL) return false;
    return true;
}

/* The Name at `name` into subject. false: malformed DER (nothing is said of
 * the certificate). *len is (size_t)-1 when the subject is not written. */
static bool subject_of(struct der name, char *subject, size_t *len) {
    size_t w = 0;
    bool written = true, first_rdn = true;
    while (name.p < name.e) {
        struct der set, atv, oid, val;
        unsigned vt;
        if (!der_expect(&name, 0x31, &set) || set.p == set.e) return false;
        bool first_atv = true;
        while (set.p < set.e) {
            if (!der_expect(&set, 0x30, &atv) || !der_expect(&atv, 0x06, &oid) || !der_next(&atv, &vt, &val) ||
                atv.p != atv.e)
                return false;
            char dotted[256];
            if (!oid_dotted(oid, dotted, sizeof dotted)) return false;
            const char *nm = dotted;
            for (size_t i = 0; i < sizeof NAMES / sizeof NAMES[0]; i++)
                if (strcmp(NAMES[i].oid, dotted) == 0) nm = NAMES[i].name;
            if (!plain_value(vt, val)) written = false;
            if (written) {
                const char *sep = first_atv ? (first_rdn ? "" : ", ") : " + ";
                const size_t need = strlen(sep) + strlen(nm) + 3 + (size_t)(val.e - val.p);
                if (w + need > X509_SUBJECT_MAX) written = false;
                else w += (size_t)snprintf(subject + w, X509_SUBJECT_MAX + 1 - w, "%s%s = %.*s", sep, nm,
                                           (int)(val.e - val.p), (const char *)val.p);
            }
            first_atv = false;
        }
        first_rdn = false;
    }
    *len = written ? w : (size_t)-1;
    return true;
}

/* Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version OPTIONAL,
 * serialNumber, signature, issuer, validity, subject, ... }, ... } (RFC 5280). */
static bool cert_subject(const unsigned char *der, size_t n, char *subject, size_t *len) {
    struct der all = { der, der + n }, cert, tbs, x, name;
    unsigned tag;
    if (!der_expect(&all, 0x30, &cert) || all.p != all.e) return false;     /* one element, the whole of it */
    if (!der_expect(&cert, 0x30, &tbs)) return false;
    if (!der_next(&tbs, &tag, &x)) return false;
    if (tag == 0xa0 && !der_next(&tbs, &tag, &x)) return false;             /* the version, then the serial */
    if (tag != 0x02) return false;
    if (!der_expect(&tbs, 0x30, &x) || !der_expect(&tbs, 0x30, &x) || !der_expect(&tbs, 0x30, &x) ||
        !der_expect(&tbs, 0x30, &name))
        return false;
    return subject_of(name, subject, len);
}

bool x509_pem_one(const char *buf, size_t len, char fp[X509_FP_LEN + 1], char *subject, size_t *subject_len) {
    const char *e = buf + len;
    const char *b = find(buf, e, BEGIN);
    if (b == NULL || memchr(buf, '\0', len) != NULL) return false;
    b += sizeof BEGIN - 1;
    if (find(b, e, BEGIN) != NULL) return false;            /* a second certificate: not one anchor */
    const char *end = find(b, e, END);
    if (end == NULL) return false;
    char *b64 = malloc((size_t)(end - b) + 1);
    unsigned char *der = malloc(3 * ((size_t)(end - b) / 4) + 4);
    bool ok = false;
    size_t n = 0, dn = 0;
    if (b64 == NULL || der == NULL) goto done;
    for (const char *p = b; p < end; p++)
        if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') b64[n++] = *p;
    b64[n] = '\0';
    if (n == 0 || belay_base64_decode(der, 3 * (n / 4) + 4, &dn, b64) != 0) { belay_err_clear(); goto done; }
    if (!cert_subject(der, dn, subject, subject_len)) goto done;
    struct belay_sha256 c;
    uint8_t d[32];
    belay_sha256_init(&c);
    belay_sha256_update(&c, der, dn);
    belay_sha256_final(&c, d);
    for (size_t i = 0; i < 32; i++) snprintf(fp + 3 * i, 4, "%02X%s", d[i], i < 31 ? ":" : "");
    ok = true;
done:
    free(b64);
    free(der);
    return ok;
}
