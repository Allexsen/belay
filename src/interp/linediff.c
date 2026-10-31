#include "linediff.h"

#include "belay/error.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

size_t line_count(const char *s, size_t n) {
    size_t c = 0;
    for (size_t i = 0; i < n; i++) c += s[i] == '\n';
    return c + (n > 0 && s[n - 1] != '\n');
}

struct line { const char *p; size_t n; uint64_t h; };

static struct line *split(const char *s, size_t n, size_t count) {
    struct line *v = malloc((count ? count : 1) * sizeof *v);
    if (v == NULL) return NULL;
    size_t k = 0, st = 0;
    for (size_t i = 0; i < n; i++)
        if (s[i] == '\n' || i + 1 == n) {
            uint64_t h = 1469598103934665603ULL;           /* FNV-1a */
            for (size_t j = st; j <= i; j++) h = (h ^ (unsigned char)s[j]) * 1099511628211ULL;
            v[k++] = (struct line){ s + st, i + 1 - st, h };
            st = i + 1;
        }
    return v;
}

static bool same(const struct line *x, const struct line *y) {
    return x->h == y->h && x->n == y->n && memcmp(x->p, y->p, x->n) == 0;
}

int line_delta(const char *a, size_t al, const char *b, size_t bl, struct line_delta *out) {
    memset(out, 0, sizeof *out);
    const size_t N = line_count(a, al), M = line_count(b, bl);
    out->lines_a = N;
    out->lines_b = M;
    struct line *x = split(a, al, N), *y = split(b, bl, M);
    long *V = malloc((2 * LINEDIFF_D_MAX + 3) * sizeof *V);
    if (x == NULL || y == NULL || V == NULL) {
        free(x); free(y); free(V);
        belay_err_set(BELAY_ERR_NOMEM, 0, "text: out of memory");
        return -1;
    }
    size_t pre = 0;
    while (pre < N && pre < M && same(&x[pre], &y[pre])) pre++;
    out->first_changed = pre + 1;
    /* Myers: V[k] is the furthest x on diagonal k = x - y after d edits. */
    const long off = (long)LINEDIFF_D_MAX + 1;
    V[off + 1] = 0;
    for (long d = 0; d <= (long)LINEDIFF_D_MAX && !out->counted; d++) {
        for (long k = -d; k <= d; k += 2) {
            long xi = (k == -d || (k != d && V[off + k - 1] < V[off + k + 1])) ? V[off + k + 1]
                                                                              : V[off + k - 1] + 1;
            long yi = xi - k;
            while (xi < (long)N && yi < (long)M && same(&x[xi], &y[yi])) { xi++; yi++; }
            V[off + k] = xi;
            if (xi >= (long)N && yi >= (long)M) {
                const size_t lcs = (N + M - (size_t)d) / 2;
                out->deleted = N - lcs;
                out->added = M - lcs;
                out->counted = true;
                break;
            }
        }
    }
    free(x); free(y); free(V);
    return 0;
}
