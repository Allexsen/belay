/*
 *  What the trust store's interpreter reads of a certificate (system-
 *  interpreters.md TS-2): from a PEM file that holds exactly one
 *  certificate, the sha256 of its DER and its subject, written as OpenSSL
 *  3.0's `openssl x509 -noout -subject` writes it after `subject=`. Nothing
 *  is validated: not the signature, not the dates, not the chain. The file
 *  is written by the watched machine, so every length is checked.
 */
#ifndef BELAY_INTERP_X509NAME_H
#define BELAY_INTERP_X509NAME_H

#include <stdbool.h>
#include <stddef.h>

#define X509_FP_LEN 95u         /* 32 bytes as uppercase hex pairs joined by ':' */
#define X509_SUBJECT_MAX 1024u

/* false: the buffer does not hold exactly one `-----BEGIN CERTIFICATE-----`
 * block whose base64 decodes to one DER certificate -- nothing is said.
 * true: fp is set (NUL-terminated); *subject_len is the subject's length in
 * `subject` (X509_SUBJECT_MAX + 1 bytes), or (size_t)-1 when it is not
 * written: a value OpenSSL would quote or escape (anything but printable
 * ASCII; one of , + " \ < > ; a leading # or blank, a trailing blank; an
 * empty value), a string type other than PrintableString, UTF8String,
 * IA5String and T61String, or a subject over X509_SUBJECT_MAX bytes. */
bool x509_pem_one(const char *buf, size_t len, char fp[X509_FP_LEN + 1], char *subject, size_t *subject_len);

#endif
