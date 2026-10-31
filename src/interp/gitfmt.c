#include "gitfmt.h"

#include "belay/error.h"

#include <string.h>

bool git_oid(const char *s, size_t n) {
    if (n != 40 && n != 64) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

/* The next line of [*i, len): its start and length, without "\n" or "\r\n". */
static bool next_line(const char *buf, size_t len, size_t *i, const char **l, size_t *ll) {
    if (*i >= len) return false;
    const char *nl = memchr(buf + *i, '\n', len - *i);
    const size_t end = nl != NULL ? (size_t)(nl - buf) : len;
    *l = buf + *i;
    *ll = end - *i;
    if (*ll > 0 && (*l)[*ll - 1] == '\r') (*ll)--;
    *i = nl != NULL ? end + 1 : len;
    return true;
}

int git_ref_value(const char *buf, size_t len, bool *sym, const char **val, size_t *val_len) {
    size_t i = 0, ll = 0;
    const char *l = NULL;
    if (!next_line(buf, len, &i, &l, &ll)) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "git: an empty ref");
        return -1;
    }
    while (ll > 0 && (l[ll - 1] == ' ' || l[ll - 1] == '\t')) ll--;
    if (ll > 5 && memcmp(l, "ref: ", 5) == 0) {
        size_t k = 5;
        while (k < ll && l[k] == ' ') k++;
        if (k == ll || ll - k > GIT_NAME_MAX || memchr(l + k, ' ', ll - k) != NULL) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "git: not a symbolic ref");
            return -1;
        }
        *sym = true;
        *val = l + k;
        *val_len = ll - k;
        return 0;
    }
    if (!git_oid(l, ll)) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "git: a ref that is neither an object id nor symbolic");
        return -1;
    }
    *sym = false;
    *val = l;
    *val_len = ll;
    return 0;
}

int git_packed_each(const char *buf, size_t len, git_packed_fn fn, void *ctx) {
    size_t i = 0, ll, line = 0;
    const char *l;
    while (next_line(buf, len, &i, &l, &ll)) {
        line++;
        if (ll == 0 || l[0] == '#') continue;
        if (l[0] == '^') {
            if (!git_oid(l + 1, ll - 1)) goto bad;
            continue;
        }
        const char *sp = memchr(l, ' ', ll);
        if (sp == NULL || !git_oid(l, (size_t)(sp - l))) goto bad;
        const size_t rl = ll - (size_t)(sp - l) - 1;
        if (rl == 0 || rl > GIT_NAME_MAX || memchr(sp + 1, ' ', rl) != NULL) goto bad;
        const int r = fn(sp + 1, rl, l, (size_t)(sp - l), ctx);
        if (r != 0) return r;
        continue;
    bad:
        belay_err_set(BELAY_ERR_CORRUPT, 0, "git: packed-refs line %zu is malformed", line);
        return -1;
    }
    return 0;
}

int git_reflog_each(const char *buf, size_t len, git_reflog_fn fn, void *ctx) {
    size_t i = 0, ll, line = 0;
    const char *l;
    while (next_line(buf, len, &i, &l, &ll)) {
        line++;
        if (ll == 0) continue;
        const char *tab = memchr(l, '\t', ll);
        const char *sp1 = memchr(l, ' ', ll);
        if (tab == NULL || sp1 == NULL) goto bad;
        const size_t ol = (size_t)(sp1 - l);
        if (!git_oid(l, ol) || (size_t)(tab - l) < 2 * ol + 2 || sp1[1 + ol] != ' ' ||
            !git_oid(sp1 + 1, ol))
            goto bad;
        const char *msg = tab + 1;
        const size_t ml = ll - (size_t)(msg - l);
        const char *colon = memchr(msg, ':', ml);
        size_t opl = colon != NULL ? (size_t)(colon - msg) : ml;
        size_t os = 0;
        while (os < opl && msg[os] == ' ') os++;
        while (opl > os && msg[opl - 1] == ' ') opl--;
        if (opl - os > GIT_NAME_MAX) goto bad;
        const struct git_reflog_entry e = { l, sp1 + 1, msg + os, ol, opl - os, line, msg, ml };
        const int r = fn(&e, ctx);
        if (r != 0) return r;
        continue;
    bad:
        belay_err_set(BELAY_ERR_CORRUPT, 0, "git: reflog line %zu is malformed", line);
        return -1;
    }
    return 0;
}
