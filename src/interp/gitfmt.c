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

static bool hexdig(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
static bool space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }

/* An id of either case at s, of the run's length (40 or 64 hex digits, no
 * more): lowercased in place; its length, or 0. */
static size_t oid_at(char *s, size_t n) {
    size_t k = 0;
    while (k < n && k <= 64 && hexdig(s[k])) k++;
    if (k != 40 && k != 64) return 0;
    for (size_t i = 0; i < k; i++)
        if (s[i] >= 'A' && s[i] <= 'F') s[i] = (char)(s[i] - 'A' + 'a');
    return k;
}

int git_ref_value(char *buf, size_t len, bool *sym, const char **val, size_t *val_len) {
    if (len >= 4 && memcmp(buf, "ref:", 4) == 0) {
        const char *nl = memchr(buf, '\n', len);
        size_t ll = nl != NULL ? (size_t)(nl - buf) : len, k = 4;
        while (k < ll && (buf[k] == ' ' || buf[k] == '\t')) k++;
        while (ll > k && space(buf[ll - 1])) ll--;
        if (k == ll || ll - k > GIT_NAME_MAX || memchr(buf + k, ' ', ll - k) != NULL ||
            memchr(buf + k, '\t', ll - k) != NULL) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "git: not a symbolic ref");
            return -1;
        }
        *sym = true;
        *val = buf + k;
        *val_len = ll - k;
        return 0;
    }
    const size_t ol = oid_at(buf, len);
    if (ol == 0 || (ol < len && !space(buf[ol]))) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "git: a ref that is neither an object id nor symbolic");
        return -1;
    }
    *sym = false;
    *val = buf;
    *val_len = ol;
    return 0;
}

int git_packed_each(char *buf, size_t len, git_packed_fn fn, void *ctx) {
    size_t i = 0, ll, line = 0;
    const char *l;
    /* git refuses a packed-refs whose last line has no newline ("unterminated
     * line", git 2.43.0): a side git cannot parse (decision 183, E10). */
    if (len > 0 && buf[len - 1] != '\n') {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "git: packed-refs ends without a newline (git refuses it)");
        return -1;
    }
    while (next_line(buf, len, &i, &l, &ll)) {
        line++;
        if (ll == 0 || l[0] == '#') continue;
        char *w = buf + (l - buf);
        if (l[0] == '^') {
            if (ll < 2 || oid_at(w + 1, ll - 1) != ll - 1) goto bad;      /* an id, not none */
            continue;
        }
        const char *sp = memchr(l, ' ', ll);
        if (sp == NULL || sp == l || oid_at(w, (size_t)(sp - l)) != (size_t)(sp - l)) goto bad;
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

/* git's reading of one reflog line (refs/files-backend.c, as git 2.43.0
 * behaves: decision 202): the entry, or false for a line git skips. */
static bool reflog_entry(char *l, size_t ll, struct git_reflog_entry *e) {
    const size_t ol = oid_at(l, ll);
    if (ol == 0 || ll < 2 * ol + 2 || l[ol] != ' ' || oid_at(l + ol + 1, ll - ol - 1) != ol || l[2 * ol + 1] != ' ')
        return false;
    char *p = l + 2 * ol + 2;
    const char *gt = memchr(p, '>', ll - (size_t)(p - l));
    if (gt == NULL || (size_t)(gt - l) + 2 > ll || gt[1] != ' ') return false;
    /* The time as strtoumax reads it: leading whitespace, a sign, digits;
     * git skips the line when that is 0 (no digits, or zeros only). */
    const char *z = gt + 2, *const eol = l + ll;
    while (z < eol && space(*z)) z++;
    if (z < eol && (*z == '+' || *z == '-')) z++;
    bool nonzero = false;
    const char *const digits = z;
    for (; z < eol && *z >= '0' && *z <= '9'; z++) nonzero = nonzero || *z != '0';
    if (z == digits || !nonzero) return false;
    const size_t zl = ll - (size_t)(z - l);
    if (zl < 6 || z[0] != ' ' || (z[1] != '+' && z[1] != '-') || !(z[2] >= '0' && z[2] <= '9') ||
        !(z[3] >= '0' && z[3] <= '9') || !(z[4] >= '0' && z[4] <= '9') || !(z[5] >= '0' && z[5] <= '9'))
        return false;
    const char *msg = z + 6;
    if (msg < l + ll && *msg == '\t') msg++;
    *e = (struct git_reflog_entry){ .old_oid = l, .new_oid = l + ol + 1, .oid_len = ol, .message = msg,
                                     .message_len = ll - (size_t)(msg - l) };
    return true;
}

int git_reflog_each(char *buf, size_t len, git_reflog_fn fn, void *ctx, size_t *ignored) {
    size_t i = 0, ll, line = 0, skipped = 0;
    const char *l;
    /* A last line without its newline is no entry: git does not read it
     * (git 2.43.0 shows a reflog so cut without that line; decision 183). */
    while (len > 0 && buf[len - 1] != '\n') len--;
    while (next_line(buf, len, &i, &l, &ll)) {
        line++;
        struct git_reflog_entry e;
        if (!reflog_entry(buf + (l - buf), ll, &e)) {
            skipped++;                          /* git skips it; said as a count (decision 202) */
            continue;
        }
        const char *colon = memchr(e.message, ':', e.message_len);
        size_t opl = colon != NULL ? (size_t)(colon - e.message) : e.message_len;
        size_t os = 0;
        while (os < opl && e.message[os] == ' ') os++;
        while (opl > os && e.message[opl - 1] == ' ') opl--;
        e.operation = e.message + os;
        e.operation_len = opl - os;
        e.line = line;
        const int r = fn(&e, ctx);
        if (r != 0) return r;
    }
    if (ignored != NULL) *ignored = skipped;
    return 0;
}
