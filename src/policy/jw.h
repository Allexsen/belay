/*
 *  One JSON line built in memory, for the bundle's header lines and package
 *  lines and for policy.v1: keys in the order written, strings escaped as
 *  the manifest escapes them, bytes that are not UTF-8 under `<key>_b64`.
 *  Errors are sticky: `oom` once anything failed, and nothing after it is
 *  written.
 */
#ifndef BELAY_POLICY_JW_H
#define BELAY_POLICY_JW_H

#include <stdbool.h>
#include <stddef.h>

struct jw {
    char *b;
    size_t n, cap;
    bool oom;
};

void jw_reset(struct jw *w);            /* empty, keeping the buffer */
void jw_free(struct jw *w);
void jw_raw(struct jw *w, const char *s, size_t n);
void jw_fmt(struct jw *w, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* "<s>", escaped: s must be UTF-8 (a key, a name belay chose). */
void jw_str(struct jw *w, const char *s, size_t n);
/* "<key>":"<s>" when s is UTF-8, else "<key>_b64":"<base64>". */
void jw_bytes(struct jw *w, const char *key, const char *s, size_t n);

#endif
