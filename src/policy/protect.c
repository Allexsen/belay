#define _GNU_SOURCE
#include "policy/protect.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"
#include "util/jsonr.h"

/* ---- patterns (PS-P1 to PS-P4) ---- */

struct comp { const char *s; size_t n; };

#define COMPS_MAX (PROTECT_PATTERN_MAX / 2 + 1)    /* a path of 4,096 bytes has no more */

/* The components of `p`, at most `max`; (size_t)-1 when there are more. */
static size_t split(const char *p, size_t n, struct comp *out, size_t max) {
    size_t k = 0, i = 0;
    while (i <= n) {
        const char *sl = i < n ? memchr(p + i, '/', n - i) : NULL;
        const size_t e = sl != NULL ? (size_t)(sl - p) : n;
        if (k == max) return (size_t)-1;
        out[k++] = (struct comp){ p + i, e - i };
        if (sl == NULL) break;
        i = e + 1;
    }
    return k;
}

bool protect_pattern_valid(const char *p, size_t n) {
    if (n == 0 || n > PROTECT_PATTERN_MAX || memchr(p, '\0', n) != NULL) return false;
    if (p[0] == '/' || p[n - 1] == '/') return false;
    size_t i = 0;
    while (i < n) {
        const char *sl = memchr(p + i, '/', n - i);
        const size_t e = sl != NULL ? (size_t)(sl - p) : n;
        const size_t l = e - i;
        if (l == 0 || (l == 1 && p[i] == '.') || (l == 2 && p[i] == '.' && p[i + 1] == '.')) return false;
        i = e + 1;
    }
    return true;
}

static bool is_globstar(struct comp c) { return c.n == 2 && c.s[0] == '*' && c.s[1] == '*'; }

/* One component against one pattern component: `*` any run of bytes, the
 * rest themselves; a name starting with '.' only by a pattern component
 * that starts with '.' itself (PS-P4). */
static bool comp_match(struct comp pc, struct comp c) {
    if (c.n > 0 && c.s[0] == '.' && (pc.n == 0 || pc.s[0] != '.')) return false;
    size_t pi = 0, si = 0, star = (size_t)-1, mark = 0;
    while (si < c.n) {
        if (pi < pc.n && pc.s[pi] == '*') {
            star = pi++;
            mark = si;
        } else if (pi < pc.n && pc.s[pi] == c.s[si]) {
            pi++;
            si++;
        } else if (star != (size_t)-1) {
            pi = star + 1;
            si = ++mark;
        } else {
            return false;
        }
    }
    while (pi < pc.n && pc.s[pi] == '*') pi++;
    return pi == pc.n;
}

/* The pattern positions live once `path`'s components are consumed: a
 * `**` takes any number of whole components, none starting with '.'
 * (PS-P2, PS-P4). `live` has room for the pattern's components + 1.
 * false when either cannot be split. */
static bool run(const char *pat, size_t plen, const char *path, size_t n, bool *live, size_t *np) {
    static _Thread_local struct comp pc[COMPS_MAX], sc[COMPS_MAX];
    static _Thread_local bool next[COMPS_MAX + 1];
    const size_t P = split(pat, plen, pc, COMPS_MAX);
    const size_t S = n == 0 ? 0 : split(path, n, sc, COMPS_MAX);
    if (P == (size_t)-1 || S == (size_t)-1) return false;
    memset(live, 0, P + 1);
    live[0] = true;
    for (size_t i = 0; i < P && live[i] && is_globstar(pc[i]); i++) live[i + 1] = true;
    for (size_t k = 0; k < S; k++) {
        memset(next, 0, P + 1);
        bool any = false;
        for (size_t i = 0; i < P; i++) {
            if (!live[i]) continue;
            if (is_globstar(pc[i])) {
                if (sc[k].n > 0 && sc[k].s[0] != '.') next[i] = any = true;
            } else if (comp_match(pc[i], sc[k])) {
                next[i + 1] = any = true;
            }
        }
        for (size_t i = 0; i < P; i++)          /* a `**` also takes none */
            if (next[i] && is_globstar(pc[i])) next[i + 1] = true;
        memcpy(live, next, P + 1);
        if (!any) break;
    }
    *np = P;
    return true;
}

bool protect_match(const char *pat, size_t plen, const char *path, size_t n) {
    static _Thread_local bool live[COMPS_MAX + 1];
    size_t P;
    return run(pat, plen, path, n, live, &P) && live[P];
}

bool protect_covers(const char *pat, size_t plen, const char *dir, size_t n) {
    static _Thread_local bool live[COMPS_MAX + 1];
    size_t P;
    if (!run(pat, plen, dir, n, live, &P)) return false;
    for (size_t i = 0; i <= P; i++)
        if (live[i]) return true;
    return false;
}

/* ---- the spec (PS-1 to PS-7, PS-R1 to PS-R3) ---- */

static int refuse(struct protect_spec *s, struct jval *v, const char *what, size_t at) {
    protect_free(s);
    if (v != NULL) jsonr_free(v);
    if (at != (size_t)-1)
        belay_err_set(BELAY_ERR_INVALID, 0, "protect spec: rule %zu: %s", at + 1, what);
    else
        belay_err_set(BELAY_ERR_INVALID, 0, "protect spec: %s", what);
    return -1;
}

/* Every key of `o` is one of `keys` (NULL-ended) and none is given twice. */
static bool keys_ok(const struct jval *o, const char *const *keys) {
    for (size_t i = 0; i < o->n; i++) {
        bool known = false;
        for (const char *const *k = keys; *k != NULL; k++) known = known || strcmp(o->keys[i], *k) == 0;
        if (!known) return false;
        for (size_t j = 0; j < i; j++)
            if (strcmp(o->keys[i], o->keys[j]) == 0) return false;
    }
    return true;
}

static bool hex64(const struct jval *v) {
    if (v->t != J_STR || v->s_len != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((v->s[i] >= '0' && v->s[i] <= '9') || (v->s[i] >= 'a' && v->s[i] <= 'f'))) return false;
    return true;
}

int protect_parse(const char *buf, size_t len, struct protect_spec *out) {
    memset(out, 0, sizeof *out);
    if (len > PROTECT_SPEC_MAX) return refuse(out, NULL, "larger than 1 MiB", (size_t)-1);
    if (!belay_utf8_valid(buf, len)) return refuse(out, NULL, "not UTF-8", (size_t)-1);
    struct belay_sha256 h;
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_init(&h);
    belay_sha256_update(&h, buf, len);
    belay_sha256_final(&h, d);
    belay_hex_encode(out->sha256, d, sizeof d);

    struct jval v;
    if (jsonr_parse(buf, len, &v) == -1) return refuse(out, NULL, "not one JSON object", (size_t)-1);
    if (v.t != J_OBJ) return refuse(out, &v, "not one JSON object", (size_t)-1);
    static const char *const top[] = { "belay_protect", "protect", "frozen_packages", "path_dirs", NULL };
    if (!keys_ok(&v, top)) return refuse(out, &v, "a key unknown or given twice", (size_t)-1);
    const struct jval *ver = jget(&v, "belay_protect");
    if (ver == NULL || ver->t != J_NUM || !ver->integer || ver->i != 1)
        return refuse(out, &v, "belay_protect is not 1", (size_t)-1);

    const struct jval *fp = jget(&v, "frozen_packages");
    if (fp != NULL && fp->t != J_BOOL) return refuse(out, &v, "frozen_packages is not a bool", (size_t)-1);
    out->frozen_packages = fp != NULL && fp->b;

    const struct jval *pd = jget(&v, "path_dirs");
    if (pd != NULL) {
        if (pd->t != J_ARR || pd->n > PROTECT_DIRS_MAX)
            return refuse(out, &v, "path_dirs is not an array of at most 256 patterns", (size_t)-1);
        out->has_path_dirs = true;
        out->path_dirs = calloc(pd->n + 1, sizeof *out->path_dirs);
        if (out->path_dirs == NULL) return refuse(out, &v, "out of memory", (size_t)-1);
        for (size_t i = 0; i < pd->n; i++) {
            const struct jval *p = &pd->kids[i];
            if (p->t != J_STR || !protect_pattern_valid(p->s, p->s_len))
                return refuse(out, &v, "path_dirs holds something not a pattern", (size_t)-1);
            if ((out->path_dirs[i] = strdup(p->s)) == NULL) return refuse(out, &v, "out of memory", (size_t)-1);
            out->n_path_dirs++;
        }
    }

    const struct jval *pr = jget(&v, "protect");
    if (pr == NULL || pr->t != J_ARR) return refuse(out, &v, "protect is not an array", (size_t)-1);
    if (pr->n > PROTECT_RULES_MAX) return refuse(out, &v, "more than 4,096 rules", (size_t)-1);
    if (pr->n > 0 && (out->rules = calloc(pr->n, sizeof *out->rules)) == NULL)
        return refuse(out, &v, "out of memory", (size_t)-1);
    static const char *const rk[] = { "path", "mode", "expected_sha256", NULL };
    for (size_t i = 0; i < pr->n; i++) {
        const struct jval *r = &pr->kids[i];
        if (r->t != J_OBJ || !keys_ok(r, rk)) return refuse(out, &v, "a key unknown or given twice", i);
        const struct jval *p = jget(r, "path");
        if (p == NULL || p->t != J_STR || !protect_pattern_valid(p->s, p->s_len))
            return refuse(out, &v, "path is not a pattern", i);
        struct protect_rule *x = &out->rules[i];
        if ((x->path = strdup(p->s)) == NULL) return refuse(out, &v, "out of memory", i);
        x->path_len = p->s_len;
        out->n_rules++;
        const struct jval *m = jget(r, "mode");
        if (m != NULL) {
            if (m->t != J_ARR) return refuse(out, &v, "mode is not an array", i);
            for (size_t k = 0; k < m->n; k++) {
                const struct jval *e = &m->kids[k];
                unsigned bit = 0;
                if (e->t == J_STR && strcmp(e->s, "no_write") == 0 && e->s_len == 8) bit = PROTECT_NO_WRITE;
                else if (e->t == J_STR && strcmp(e->s, "no_delete") == 0 && e->s_len == 9) bit = PROTECT_NO_DELETE;
                else if (e->t == J_STR && strcmp(e->s, "no_create") == 0 && e->s_len == 9) bit = PROTECT_NO_CREATE;
                if (bit == 0 || (x->modes & bit)) return refuse(out, &v, "mode holds an unknown or repeated mode", i);
                x->modes |= bit;
            }
        }
        const struct jval *sh = jget(r, "expected_sha256");
        if (sh != NULL) {
            if (!hex64(sh)) return refuse(out, &v, "expected_sha256 is not 64 lowercase hex digits", i);
            if (memchr(x->path, '*', x->path_len) != NULL)
                return refuse(out, &v, "expected_sha256 with a pattern that has a '*'", i);
            x->has_sha256 = true;
            memcpy(x->sha256, sh->s, 65);
        }
        if (x->modes == 0 && !x->has_sha256) return refuse(out, &v, "neither a mode nor expected_sha256", i);
    }
    jsonr_free(&v);
    return 0;
}

int protect_load(const char *path, struct protect_spec *out) {
    memset(out, 0, sizeof *out);
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "protect spec %s: cannot open", path);
        return -1;
    }
    char *buf = malloc(PROTECT_SPEC_MAX + 1);
    if (buf == NULL) {
        close(fd);
        belay_err_set(BELAY_ERR_NOMEM, 0, "protect spec: out of memory");
        return -1;
    }
    size_t len = 0;
    for (;;) {
        const ssize_t r = read(fd, buf + len, PROTECT_SPEC_MAX + 1 - len);
        if (r == -1 && errno == EINTR) continue;
        if (r == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "protect spec %s: cannot read", path);
            free(buf);
            close(fd);
            return -1;
        }
        if (r == 0 || (len += (size_t)r) == PROTECT_SPEC_MAX + 1) break;
    }
    close(fd);
    const int rc = protect_parse(buf, len, out);
    free(buf);
    return rc;
}

void protect_free(struct protect_spec *s) {
    if (s == NULL) return;
    for (size_t i = 0; i < s->n_rules; i++) free(s->rules[i].path);
    free(s->rules);
    for (size_t i = 0; i < s->n_path_dirs; i++) free(s->path_dirs[i]);
    free(s->path_dirs);
    memset(s, 0, sizeof *s);
}
