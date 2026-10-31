#include "stanza.h"

#include "belay/error.h"

#include <stdbool.h>
#include <string.h>

static bool blank(char c) { return c == ' ' || c == '\t' || c == '\r'; }

static bool name_is(const char *n, size_t l, const char *want) {
    if (l != strlen(want)) return false;
    for (size_t i = 0; i < l; i++) {
        char c = n[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != want[i]) return false;
    }
    return true;
}

static int flush(struct stanza_pkg *p, size_t *count, stanza_fn fn, void *ctx) {
    if (p->line == 0) return 0;                          /* nothing open */
    if (p->package == NULL) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "dpkg status: stanza at line %zu has no Package", p->line);
        return -1;
    }
    if (++*count > STANZA_MAX) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "dpkg status: more than %u stanzas", STANZA_MAX);
        return -1;
    }
    const int r = fn(p, ctx);
    memset(p, 0, sizeof *p);
    return r;
}

int stanza_each(const char *buf, size_t len, stanza_fn fn, void *ctx) {
    struct stanza_pkg p;
    memset(&p, 0, sizeof p);
    size_t count = 0, lineno = 0, i = 0;
    while (i < len) {
        const char *nl = memchr(buf + i, '\n', len - i);
        const size_t end = nl != NULL ? (size_t)(nl - buf) : len;
        const char *l = buf + i;
        size_t ll = end - i;
        lineno++;
        i = nl != NULL ? end + 1 : len;
        size_t k = 0;
        while (k < ll && blank(l[k])) k++;
        if (k == ll) {                                     /* blank: the stanza ends */
            const int r = flush(&p, &count, fn, ctx);
            if (r != 0) return r;
            continue;
        }
        if (l[0] == ' ' || l[0] == '\t') {                 /* continuation */
            if (p.line == 0) {
                belay_err_set(BELAY_ERR_CORRUPT, 0, "dpkg status: line %zu continues nothing", lineno);
                return -1;
            }
            continue;
        }
        const char *colon = memchr(l, ':', ll);
        if (colon == NULL || colon == l) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "dpkg status: line %zu is not a field", lineno);
            return -1;
        }
        if (p.line == 0) p.line = lineno;
        const size_t nlen = (size_t)(colon - l);
        size_t vs = nlen + 1, ve = ll;
        while (vs < ve && blank(l[vs])) vs++;
        while (ve > vs && blank(l[ve - 1])) ve--;
        if (ve - vs > STANZA_VALUE_MAX) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "dpkg status: line %zu: value over %u bytes", lineno,
                          STANZA_VALUE_MAX);
            return -1;
        }
        const char **slot = NULL;
        size_t *slen = NULL;
        if (name_is(l, nlen, "package")) { slot = &p.package; slen = &p.package_len; }
        else if (name_is(l, nlen, "architecture")) { slot = &p.arch; slen = &p.arch_len; }
        else if (name_is(l, nlen, "version")) { slot = &p.version; slen = &p.version_len; }
        else if (name_is(l, nlen, "status")) { slot = &p.status; slen = &p.status_len; }
        if (slot != NULL && *slot == NULL) {
            *slot = l + vs;
            *slen = ve - vs;
        }
    }
    return flush(&p, &count, fn, ctx);
}
