#include "policy/jw.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "belay/json.h"

static bool room(struct jw *w, size_t more) {
    if (w->oom) return false;
    if (w->n + more + 1 <= w->cap) return true;
    size_t cap = w->cap ? w->cap : 256;
    while (cap < w->n + more + 1) cap *= 2;
    char *b = realloc(w->b, cap);
    if (b == NULL) {
        w->oom = true;
        return false;
    }
    w->b = b;
    w->cap = cap;
    return true;
}

void jw_reset(struct jw *w) {
    w->n = 0;
    w->oom = false;
    if (w->b != NULL) w->b[0] = '\0';
}

void jw_free(struct jw *w) {
    free(w->b);
    memset(w, 0, sizeof *w);
}

void jw_raw(struct jw *w, const char *s, size_t n) {
    if (!room(w, n)) return;
    memcpy(w->b + w->n, s, n);
    w->n += n;
    w->b[w->n] = '\0';
}

void jw_fmt(struct jw *w, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    const int k = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (k < 0 || !room(w, (size_t)k)) {
        w->oom = true;
        return;
    }
    va_start(ap, fmt);
    vsnprintf(w->b + w->n, (size_t)k + 1, fmt, ap);
    va_end(ap);
    w->n += (size_t)k;
}

void jw_str(struct jw *w, const char *s, size_t n) {
    /* each byte at most \u00XX: 6 bytes, and the quotes */
    if (!room(w, 6 * n + 2)) return;
    w->b[w->n++] = '"';
    if (belay_json_escape(w->b + w->n, w->cap - w->n, s, n) == -1) {
        w->oom = true;
        return;
    }
    w->n += strlen(w->b + w->n);
    w->b[w->n++] = '"';
    w->b[w->n] = '\0';
}

void jw_bytes(struct jw *w, const char *key, const char *s, size_t n) {
    if (belay_utf8_valid(s, n)) {
        jw_fmt(w, "\"%s\":", key);
        jw_str(w, s, n);
        return;
    }
    const size_t need = 4 * ((n + 2) / 3) + 1;
    jw_fmt(w, "\"%s_b64\":\"", key);
    if (!room(w, need)) return;
    if (belay_base64_encode(w->b + w->n, w->cap - w->n, s, n) == -1) {
        w->oom = true;
        return;
    }
    w->n += strlen(w->b + w->n);
    jw_raw(w, "\"", 1);
}
