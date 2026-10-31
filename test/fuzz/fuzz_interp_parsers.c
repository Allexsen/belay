/*
 *  Fuzz target for the interpreters' parsers (§0.4c; Phase 4, decided
 *  2026-10-31): every parser meets bytes the watched process wrote. The
 *  first byte picks the parser; the rest is its input. For ANY input: no
 *  crash, no read or write out of bounds, and the parser's own invariants --
 *  values inside the buffer and their bounds, the same answer twice, version
 *  orders reflexive and antisymmetric, line counts that add up.
 */
#include "belay/error.h"
#include "interp/gitfmt.h"
#include "interp/linediff.h"
#include "interp/record_csv.h"
#include "interp/stanza.h"
#include "interp/versions.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *g_buf;
static size_t g_len, g_count;

static void inside(const char *p, size_t n, size_t max) {
    if (p == NULL) { if (n != 0) abort(); return; }
    if (p < g_buf || p + n > g_buf + g_len || n > max) abort();
}

static int on_pkg(const struct stanza_pkg *p, void *c) {
    (void)c;
    inside(p->package, p->package_len, g_len);
    inside(p->arch, p->arch_len, g_len);
    inside(p->version, p->version_len, g_len);
    inside(p->status, p->status_len, g_len);
    if (p->package == NULL) abort();
    g_count++;
    return 0;
}

static int on_row(const struct record_row *r, void *c) {
    (void)c;
    if (r->path_len > RECORD_FIELD_MAX || r->hash_len > RECORD_FIELD_MAX || r->size_len > RECORD_FIELD_MAX)
        abort();
    if (strlen(r->path) > r->path_len || r->path[r->path_len] != '\0') abort();
    g_count++;
    return 0;
}

static int on_packed(const char *ref, size_t rl, const char *oid, size_t ol, void *c) {
    (void)c;
    inside(ref, rl, GIT_NAME_MAX);
    if (!git_oid(oid, ol)) abort();
    g_count++;
    return 0;
}

static int on_log(const struct git_reflog_entry *e, void *c) {
    (void)c;
    if (!git_oid(e->old_oid, e->oid_len) || !git_oid(e->new_oid, e->oid_len)) abort();
    inside(e->operation, e->operation_len, GIT_NAME_MAX);
    g_count++;
    return 0;
}

static int sign(int x) { return (x > 0) - (x < 0); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 65536) return 0;
    const char *b = (const char *)data + 1;
    const size_t n = size - 1;
    g_buf = b;
    g_len = n;
    size_t first;
    int r1, r2;
    switch (data[0] % 6) {
    case 0:
        g_count = 0; r1 = stanza_each(b, n, on_pkg, NULL); first = g_count;
        g_count = 0; r2 = stanza_each(b, n, on_pkg, NULL);
        if (r1 != r2 || first != g_count) abort();
        break;
    case 1:
        g_count = 0; r1 = record_each(b, n, on_row, NULL); first = g_count;
        g_count = 0; r2 = record_each(b, n, on_row, NULL);
        if (r1 != r2 || first != g_count) abort();
        break;
    case 2: {
        g_count = 0;
        (void)git_packed_each(b, n, on_packed, NULL);
        (void)git_reflog_each(b, n, on_log, NULL);
        bool sym;
        const char *v;
        size_t vl;
        if (git_ref_value(b, n, &sym, &v, &vl) == 0) {
            inside(v, vl, GIT_NAME_MAX);
            if (!sym && !git_oid(v, vl)) abort();
        }
        break;
    }
    case 3: case 4: {                       /* two versions, split at the first NUL */
        const char *z = memchr(b, '\0', n);
        const size_t al = z ? (size_t)(z - b) : n / 2, bl = n - al - (z ? 1 : 0);
        const char *bb = b + al + (z ? 1 : 0);
        if (debver_cmp(b, al, b, al) != 0) abort();
        if (sign(debver_cmp(b, al, bb, bl)) != -sign(debver_cmp(bb, bl, b, al))) abort();
        int c1 = 0, c2 = 0;
        const int o1 = pep440_cmp(b, al, bb, bl, &c1), o2 = pep440_cmp(bb, bl, b, al, &c2);
        if (o1 != o2 || (o1 == 0 && sign(c1) != -sign(c2))) abort();
        if (pep440_cmp(b, al, b, al, &c1) == 0 && c1 != 0) abort();
        break;
    }
    case 5: {
        const char *z = memchr(b, '\0', n);
        const size_t al = z ? (size_t)(z - b) : n / 2, bl = n - al - (z ? 1 : 0);
        struct line_delta d;
        if (line_delta(b, al, b + al + (z ? 1 : 0), bl, &d) != 0) break;
        if (d.lines_a != line_count(b, al)) abort();
        if (d.first_changed < 1 || d.first_changed > (d.lines_a < d.lines_b ? d.lines_a : d.lines_b) + 1) abort();
        if (d.counted && (d.deleted > d.lines_a || d.added > d.lines_b ||
                          d.lines_a - d.deleted != d.lines_b - d.added))
            abort();
        break;
    }
    }
    belay_err_clear();
    return 0;
}
