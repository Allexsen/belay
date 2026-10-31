/*
 *  Minimal JSON output, plus the UTF-8 and base64 helpers the manifest format
 *  needs for byte-exact path encoding.
 *
 *  Write-only by design: belay emits JSON for manifests and for --json output.
 *  The manifest reader parses manifests directly; the CLI reads its own
 *  meta.json and diff.v1 back through src/cli/jsonr.c (bounded depth). A
 *  general-purpose parser is a much larger attack surface than this needs.
 */
#ifndef BELAY_JSON_H
#define BELAY_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 *  Escapes `len` bytes of `in` as the *contents* of a JSON string (no
 *  surrounding quotes) into `out`.
 *
 *  Escapes per RFC 8259: `"` `\` and every control byte below 0x20, using the
 *  short forms where they exist and \u00XX otherwise.
 *
 *  REQUIRES valid UTF-8. Bytes >= 0x80 pass through unchanged, so invalid
 *  UTF-8 in would produce invalid JSON out. Callers must test with
 *  belay_utf8_valid() first and fall back to base64 -- that is exactly why
 *  the manifest has path_b64.
 *
 *  Returns 0 on success, -1 with belay_err_* set if the result does not fit.
 */
int belay_json_escape(char *out, size_t outsz, const char *in, size_t len);

/* True when `len` bytes of `in` are well-formed UTF-8. Rejects overlong
 * encodings, surrogate halves, and anything above U+10FFFF -- a permissive
 * check would let invalid bytes reach belay_json_escape(). */
bool belay_utf8_valid(const char *in, size_t len);

/* Standard base64 with padding. Needs 4*((len+2)/3)+1 bytes of output. */
int belay_base64_encode(char *out, size_t outsz, const void *in, size_t len);

/* Decodes base64. Rejects any character outside the alphabet, wrong padding,
 * and a length that is not a multiple of 4. `*outlen` receives the byte count.
 * Needs 3*(strlen(in)/4) bytes of output. */
int belay_base64_decode(void *out, size_t outsz, size_t *outlen, const char *in);

#endif /* BELAY_JSON_H */
