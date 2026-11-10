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
#include "util/pattern.h"

/* ---- patterns (PS-P1 to PS-P4): the one matcher, with no switch on ---- */

bool protect_pattern_valid(const char *p, size_t n) { return pattern_valid(p, n); }

bool protect_match(const char *pat, size_t plen, const char *path, size_t n) {
    return (pattern_match(pat, plen, path, n, 0) & PATTERN_SELF) != 0;
}

bool protect_covers(const char *pat, size_t plen, const char *dir, size_t n) {
    return pattern_covers(pat, plen, dir, n, 0);
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
    if (ver == NULL || ver->t != J_NUM || !ver->integer || ver->i != 2)
        return refuse(out, &v, "belay_protect is not 2 (version 1 specs are refused: no_write now forbids deleting; say 2)",
                      (size_t)-1);

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
