/*
 *  The `runtime` section (runtime_diff.h; runtime-v1.md RT-D1 to RT-D5).
 *  Each record file is the capture's own, checked against the sha256 its
 *  checkpoint recorded before it gets here; it is still parsed as input:
 *  every line's keys, in their order, and the trailer's counts.
 */
#define _GNU_SOURCE
#include "runtime_diff.h"

#include "util/jsonr.h"

#include "belay/error.h"
#include "belay/json.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RT_LINE_MAX (1u << 20)

struct sb { char *p; size_t n, cap; bool bad; };

static void sb_put(struct sb *b, const char *s, size_t n) {
    if (b->bad) return;
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 1024;
        while (cap < b->n + n + 1) {
            if (cap > SIZE_MAX / 2) { b->bad = true; return; }
            cap *= 2;
        }
        char *p = realloc(b->p, cap);
        if (p == NULL) { b->bad = true; return; }
        b->p = p;
        b->cap = cap;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

static void sbs(struct sb *b, const char *s) { sb_put(b, s, strlen(s)); }

/* The last `/` of n bytes (memrchr is not everywhere). */
static const char *last_slash(const char *p, size_t n) {
    while (n > 0)
        if (p[--n] == '/') return p + n;
    return NULL;
}

/* Room for one more of `size` bytes in *v. */
static bool grow(void **v, size_t n, size_t *cap, size_t size) {
    if (n < *cap) return true;
    const size_t c = *cap ? 2 * *cap : 64;
    void *p = realloc(*v, c * size);
    if (p == NULL) return false;
    *v = p;
    *cap = c;
    return true;
}

/* A JSON string of `len` bytes that are UTF-8. */
static void sb_json(struct sb *b, const char *s, size_t len) {
    char *e = malloc(6 * len + 3);
    if (e == NULL || belay_json_escape(e, 6 * len + 3, s, len) == -1) {
        b->bad = true;
        free(e);
        belay_err_clear();
        return;
    }
    sb_put(b, "\"", 1);
    sbs(b, e);
    sb_put(b, "\"", 1);
    free(e);
}

/* Bytes for a text: what is not UTF-8 becomes `?`. */
static void sb_text(struct sb *b, const char *s, size_t len) {
    for (size_t i = 0; i < len;) {
        size_t n = 1;
        const unsigned char c = (unsigned char)s[i];
        if (c >= 0x80) n = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 1;
        if (i + n <= len && belay_utf8_valid(s + i, n)) sb_put(b, s + i, n);
        else { sb_put(b, "?", 1); n = 1; }
        i += n;
    }
}

/* A value as it was read: strings re-escaped, integers as integers. */
static void sb_jval(struct sb *b, const struct jval *v) {
    switch (v->t) {
    case J_NULL: sbs(b, "null"); break;
    case J_BOOL: sbs(b, v->b ? "true" : "false"); break;
    case J_NUM: {
        char n[32];
        snprintf(n, sizeof n, "%lld", (long long)v->i);
        sbs(b, n);
        break;
    }
    case J_STR: sb_json(b, v->s, v->s_len); break;
    case J_ARR:
        sb_put(b, "[", 1);
        for (size_t i = 0; i < v->n; i++) {
            if (i) sb_put(b, ",", 1);
            sb_jval(b, &v->kids[i]);
        }
        sb_put(b, "]", 1);
        break;
    case J_OBJ:
        sb_put(b, "{", 1);
        for (size_t i = 0; i < v->n; i++) {
            if (i) sb_put(b, ",", 1);
            sb_json(b, v->keys[i], strlen(v->keys[i]));
            sb_put(b, ":", 1);
            sb_jval(b, &v->kids[i]);
        }
        sb_put(b, "}", 1);
        break;
    }
}

/* ---- one record file ---- */

struct bytes { char *p; size_t n; bool null; };

struct rl {                     /* a listener line */
    struct jval v;
    const char *kind;
    int proto;                  /* -1: null */
    struct bytes addr;
    long port;                  /* -1: null */
    bool systemd;               /* held by pid 1's cgroup alone (RT-D2, RT-D4) */
    char **names;               /* its holders' names (RT-D2), sorted, each once */
    size_t nnames;
    bool held_known, held_none;
    size_t at;                  /* its place in the file */
};

struct rs {                     /* a service line */
    struct jval v;
    struct bytes name;
    bool has_start;
    int64_t start;
};

struct side {
    bool have;
    struct rl *l;
    size_t nl;
    struct rs *s;
    size_t ns;
    int64_t holders_unknown;
};

struct unit { char *name; char *stream, *dgram; /* NUL-separated values */ size_t sl, dl; };

struct rtdiff {
    struct side side[2];
    struct unit *u;
    size_t nu, capu;
};

/* The member `key`, or `key_b64` decoded: 1 with *out; 0 when neither; -1. */
static int bytes_of(const struct jval *o, size_t i, const char *key, struct bytes *out) {
    if (i >= o->n) return 0;
    const char *k = o->keys[i];
    const size_t kl = strlen(key);
    const struct jval *v = &o->kids[i];
    *out = (struct bytes){ 0 };
    if (strcmp(k, key) == 0) {
        if (v->t == J_NULL) { out->null = true; return 1; }
        if (v->t != J_STR || !belay_utf8_valid(v->s, v->s_len)) return -1;
        if ((out->p = malloc(v->s_len + 1)) == NULL) return -1;
        memcpy(out->p, v->s, v->s_len + 1);
        out->n = v->s_len;
        return 1;
    }
    if (strncmp(k, key, kl) == 0 && strcmp(k + kl, "_b64") == 0) {
        if (v->t != J_STR) return -1;
        const size_t cap = 3 * (v->s_len / 4) + 1;
        if ((out->p = malloc(cap)) == NULL) return -1;
        if (belay_base64_decode(out->p, cap, &out->n, v->s) == -1 || belay_utf8_valid(out->p, out->n)) {
            free(out->p);
            out->p = NULL;
            belay_err_clear();
            return -1;
        }
        out->p[out->n] = '\0';
        return 1;
    }
    return 0;
}

static bool key_at(const struct jval *o, size_t i, const char *key) {
    return i < o->n && strcmp(o->keys[i], key) == 0;
}

static bool int_at(const struct jval *o, size_t i, int64_t lo, int64_t hi) {
    return i < o->n && o->kids[i].t == J_NUM && o->kids[i].integer && o->kids[i].i >= lo && o->kids[i].i <= hi;
}

/* The last component of `p` that ends `.service`; NULL when none. */
static const char *last_service(const char *p, size_t n, size_t *len) {
    const char *best = NULL;
    size_t i = 0;
    while (i < n) {
        while (i < n && p[i] == '/') i++;
        const size_t s = i;
        while (i < n && p[i] != '/') i++;
        if (i - s > 8 && memcmp(p + i - 8, ".service", 8) == 0) {
            best = p + s;
            *len = i - s;
        }
    }
    return best;
}

static int str_cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* RT-D2: each holder's name -- the last `.service` component of its
 * cgroup; without one, its exe's last component; `systemd` for pid 1's
 * cgroup -- each once, sorted. */
static int holder_names(struct rl *l, const struct jval *h) {
    l->held_known = h->t == J_ARR;
    if (!l->held_known) return 0;
    l->held_none = h->n == 0;
    l->systemd = h->n > 0;
    if (h->n && (l->names = calloc(h->n, sizeof *l->names)) == NULL) return -1;
    for (size_t i = 0; i < h->n; i++) {
        const struct jval *o = &h->kids[i];
        struct bytes exe, cg;
        if (o->t != J_OBJ || o->n != 2 || bytes_of(o, 0, "exe", &exe) != 1) return -1;
        if (bytes_of(o, 1, "cgroup", &cg) != 1) { free(exe.p); return -1; }
        size_t sl = 0;
        const char *svc = cg.null ? NULL : last_service(cg.p, cg.n, &sl);
        const bool init = !cg.null && cg.n == 11 && memcmp(cg.p, "/init.scope", 11) == 0;
        l->systemd &= init;
        struct sb nm = { 0 };
        if (init) sbs(&nm, "systemd");
        else if (svc != NULL) sb_text(&nm, svc, sl);
        else if (exe.null) sbs(&nm, "(exe not read)");
        else {
            const char *base = last_slash(exe.p, exe.n);
            base = base != NULL ? base + 1 : exe.p;
            sb_text(&nm, base, exe.n - (size_t)(base - exe.p));
        }
        free(exe.p);
        free(cg.p);
        if (nm.bad || nm.p == NULL) { free(nm.p); return -1; }
        bool dup = false;
        for (size_t k = 0; k < l->nnames && !dup; k++) dup = strcmp(l->names[k], nm.p) == 0;
        if (dup) free(nm.p);
        else l->names[l->nnames++] = nm.p;
    }
    if (l->nnames) qsort(l->names, l->nnames, sizeof *l->names, str_cmp);
    return 0;
}

/* A listener line (RT-2): its keys in order, each value of its type. */
static int listener_line(struct rl *l, struct jval *v) {
    l->v = *v;
    size_t i = 1;
    const struct jval *k = &v->kids[0];
    if (k->t != J_STR) return -1;
    const bool unix_ = strcmp(k->s, "unix") == 0, udp = strcmp(k->s, "udp") == 0;
    if (!unix_ && !udp && strcmp(k->s, "tcp") != 0) return -1;
    l->kind = k->s;
    if (!key_at(v, i, "proto")) return -1;
    if (unix_ ? v->kids[i].t != J_NULL : !(int_at(v, i, 4, 4) || int_at(v, i, 6, 6))) return -1;
    l->proto = unix_ ? -1 : (int)v->kids[i].i;
    i++;
    if (bytes_of(v, i++, "addr", &l->addr) != 1 || l->addr.null) return -1;
    if (!key_at(v, i, "port")) return -1;
    if (unix_ ? v->kids[i].t != J_NULL : !int_at(v, i, 0, 65535)) return -1;
    l->port = unix_ ? -1 : (long)v->kids[i].i;
    i++;
    if (key_at(v, i, "client_range")) {
        if (!udp || v->kids[i].t != J_BOOL || !v->kids[i].b) return -1;
        i++;
    }
    if (!key_at(v, i, "holders") || i + 1 != v->n) return -1;
    if (v->kids[i].t != J_NULL && v->kids[i].t != J_ARR) return -1;
    return holder_names(l, &v->kids[i]);
}

/* A service line (RT-3). */
static int service_line(struct rs *s, struct jval *v) {
    s->v = *v;
    struct bytes exe;
    if (v->n != 4 || bytes_of(v, 0, "service", &s->name) != 1 || s->name.null || !int_at(v, 1, 1, INT64_MAX) ||
        !key_at(v, 1, "processes") || bytes_of(v, 2, "exe", &exe) != 1 || !key_at(v, 3, "started_ns"))
        return -1;
    free(exe.p);
    s->has_start = v->kids[3].t != J_NULL;
    if (s->has_start && !int_at(v, 3, 0, INT64_MAX)) return -1;
    s->start = s->has_start ? v->kids[3].i : 0;
    return 0;
}

static int read_side(const char *path, struct side *sd) {
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "diff: cannot read %s", path);
        return -1;
    }
    char *line = NULL;
    size_t cap = 0, lineno = 0, capl = 0, caps = 0;
    ssize_t got;
    bool trailer = false, ok = true;
    sd->have = true;
    while (ok && (got = getline(&line, &cap, f)) > 0) {
        lineno++;
        struct jval v;
        if (trailer || (size_t)got > RT_LINE_MAX || line[got - 1] != '\n' ||
            jsonr_parse(line, (size_t)got - 1, &v) == -1) {
            ok = false;
            break;
        }
        if (v.t != J_OBJ || v.n == 0) {
            jsonr_free(&v);
            ok = false;
        } else if (lineno == 1) {
            ok = v.n == 4 && key_at(&v, 0, "belay_runtime") && int_at(&v, 0, 1, 1) && key_at(&v, 1, "netns") &&
                 key_at(&v, 2, "root") && key_at(&v, 3, "source");
            jsonr_free(&v);
        } else if (key_at(&v, 0, "listener")) {
            if (sd->ns || !grow((void **)&sd->l, sd->nl, &capl, sizeof *sd->l)) {
                jsonr_free(&v);
                ok = false;
                break;
            }
            struct rl *l = &sd->l[sd->nl++];
            *l = (struct rl){ .at = sd->nl - 1 };
            ok = listener_line(l, &v) == 0;
        } else if (key_at(&v, 0, "service") || key_at(&v, 0, "service_b64")) {
            if (!grow((void **)&sd->s, sd->ns, &caps, sizeof *sd->s)) {
                jsonr_free(&v);
                ok = false;
                break;
            }
            struct rs *s = &sd->s[sd->ns++];
            *s = (struct rs){ 0 };
            ok = service_line(s, &v) == 0;
        } else if (key_at(&v, 0, "listeners")) {
            size_t unknown = 0;
            for (size_t i = 0; i < sd->nl; i++) unknown += !sd->l[i].held_known;
            ok = v.n == 3 && int_at(&v, 0, (int64_t)sd->nl, (int64_t)sd->nl) && key_at(&v, 1, "services") &&
                 int_at(&v, 1, (int64_t)sd->ns, (int64_t)sd->ns) && key_at(&v, 2, "holders_unknown") &&
                 int_at(&v, 2, (int64_t)unknown, (int64_t)unknown);
            sd->holders_unknown = (int64_t)unknown;
            trailer = true;
            jsonr_free(&v);
        } else {
            jsonr_free(&v);
            ok = false;
        }
    }
    const bool rerr = ferror(f);
    free(line);
    fclose(f);
    if (!ok || !trailer || rerr) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "diff: %s is not a runtime record (line %zu)", path, lineno);
        return -1;
    }
    return 0;
}

static void free_side(struct side *sd) {
    for (size_t i = 0; i < sd->nl; i++) {
        jsonr_free(&sd->l[i].v);
        free(sd->l[i].addr.p);
        for (size_t k = 0; k < sd->l[i].nnames; k++) free(sd->l[i].names[k]);
        free(sd->l[i].names);
    }
    for (size_t i = 0; i < sd->ns; i++) {
        jsonr_free(&sd->s[i].v);
        free(sd->s[i].name.p);
    }
    free(sd->l);
    free(sd->s);
}

void rtdiff_free(struct rtdiff *d) {
    if (d == NULL) return;
    free_side(&d->side[0]);
    free_side(&d->side[1]);
    for (size_t i = 0; i < d->nu; i++) {
        free(d->u[i].name);
        free(d->u[i].stream);
        free(d->u[i].dgram);
    }
    free(d->u);
    free(d);
}

/* RT-D2's key: (listener, proto, addr, port); ordered as RT-2 sorts. */
static int lkey(const struct rl *x, const struct rl *y) {
    int c = strcmp(x->kind, y->kind);
    if (c) return c;
    if (x->port != y->port) return x->port < y->port ? -1 : 1;
    const size_t n = x->addr.n < y->addr.n ? x->addr.n : y->addr.n;
    if ((c = memcmp(x->addr.p, y->addr.p, n)) != 0) return c;
    if (x->addr.n != y->addr.n) return x->addr.n < y->addr.n ? -1 : 1;
    return (x->proto > y->proto) - (x->proto < y->proto);
}

static int lsort(const void *a, const void *b) {
    const struct rl *x = a, *y = b;
    const int c = lkey(x, y);
    return c ? c : (x->at > y->at) - (x->at < y->at);
}

static int skey(const struct rs *x, const struct rs *y) {
    const size_t n = x->name.n < y->name.n ? x->name.n : y->name.n;
    const int c = memcmp(x->name.p, y->name.p, n);
    return c ? c : (x->name.n > y->name.n) - (x->name.n < y->name.n);
}

static int ssort(const void *a, const void *b) { return skey(a, b); }

int rtdiff_open(const char *before, const char *after, struct rtdiff **out) {
    *out = NULL;
    if (before == NULL && after == NULL) return 0;
    struct rtdiff *d = calloc(1, sizeof *d);
    if (d == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "diff: out of memory");
        return -1;
    }
    const char *p[2] = { before, after };
    for (int k = 0; k < 2; k++) {
        if (p[k] == NULL) continue;
        if (read_side(p[k], &d->side[k]) == -1) {
            rtdiff_free(d);
            return -1;
        }
        struct side *sd = &d->side[k];
        if (sd->nl) qsort(sd->l, sd->nl, sizeof *sd->l, lsort);
        if (sd->ns) qsort(sd->s, sd->ns, sizeof *sd->s, ssort);
        for (size_t i = 1; i < sd->ns; i++)
            if (skey(&sd->s[i - 1], &sd->s[i]) == 0) {      /* one line per cgroup */
                belay_err_set(BELAY_ERR_CORRUPT, 0, "diff: %s is not a runtime record (a service twice)", p[k]);
                rtdiff_free(d);
                return -1;
            }
    }
    *out = d;
    return 0;
}

/* The listeners the section names: those on one side only, paired by key
 * in order (two sockets with one key, as SO_REUSEPORT makes, are two). */
static bool compared(const struct rtdiff *d) { return d->side[0].have && d->side[1].have; }

bool rtdiff_wants_units(const struct rtdiff *d) {
    if (d == NULL || !compared(d)) return false;
    for (int k = 0; k < 2; k++)
        for (size_t i = 0; i < d->side[k].nl; i++)
            if (d->side[k].l[i].systemd) return true;
    return false;
}

bool rtdiff_unit_path(const char *path, size_t len) {
    const char *name = last_slash(path, len);
    if (name == NULL) return false;
    const size_t nl = len - (size_t)(name - path) - 1, dl = (size_t)(name - path);
    if (nl <= 7 || memcmp(path + len - 7, ".socket", 7) != 0) return false;
    static const char *const DIRS[] = { "systemd/system", "systemd/user" };
    for (size_t i = 0; i < 2; i++) {
        const size_t n = strlen(DIRS[i]);
        if (dl >= n && memcmp(path + dl - n, DIRS[i], n) == 0 && (dl == n || path[dl - n - 1] == '/')) return true;
    }
    return false;
}

static int add_value(char **v, size_t *n, const char *s, size_t len) {
    char *p = realloc(*v, *n + len + 1);
    if (p == NULL) return -1;
    memcpy(p + *n, s, len);
    p[*n + len] = '\0';
    *v = p;
    *n += len + 1;
    return 0;
}

int rtdiff_unit(struct rtdiff *d, const char *path, size_t len, const char *text, size_t tlen) {
    const char *name = last_slash(path, len);
    name = name != NULL ? name + 1 : path;
    if (!grow((void **)&d->u, d->nu, &d->capu, sizeof *d->u)) goto oom;
    struct unit *u = &d->u[d->nu];
    *u = (struct unit){ .name = strndup(name, len - (size_t)(name - path)) };
    if (u->name == NULL) goto oom;
    d->nu++;
    /* `ListenStream=` and `ListenDatagram=` lines: the value, trimmed. */
    for (size_t i = 0; i < tlen;) {
        const char *nl = memchr(text + i, '\n', tlen - i);
        size_t e = nl != NULL ? (size_t)(nl - text) : tlen, s = i;
        i = e + 1;
        while (s < e && (text[s] == ' ' || text[s] == '\t')) s++;
        while (e > s && (text[e - 1] == ' ' || text[e - 1] == '\t' || text[e - 1] == '\r')) e--;
        /* systemd's: the key, spaces, `=`, spaces, the value. */
        static const struct { const char *k; size_t n; } KEYS[] = { { "ListenStream", 12 }, { "ListenDatagram", 14 } };
        for (int k = 0; k < 2; k++) {
            if (e - s < KEYS[k].n || memcmp(text + s, KEYS[k].k, KEYS[k].n) != 0) continue;
            size_t vs = s + KEYS[k].n;
            while (vs < e && (text[vs] == ' ' || text[vs] == '\t')) vs++;
            if (vs == e || text[vs++] != '=') continue;
            while (vs < e && (text[vs] == ' ' || text[vs] == '\t')) vs++;
            if (vs < e && add_value(k ? &u->dgram : &u->stream, k ? &u->dl : &u->sl, text + vs, e - vs) == -1) goto oom;
        }
    }
    return 0;
oom:
    belay_err_set(BELAY_ERR_NOMEM, 0, "diff: out of memory");
    return -1;
}

/* RT-D4: whether a value of `ListenStream=` (tcp, unix) or (udp)
 * `ListenDatagram=` is this listener's: a port, alone or after a `:`, or a
 * unix socket's path, whole. */
static bool value_is(const struct rl *l, const char *v) {
    if (l->port < 0) return strlen(v) == l->addr.n && memcmp(v, l->addr.p, l->addr.n) == 0;
    char port[8];
    const size_t pn = (size_t)snprintf(port, sizeof port, "%ld", l->port), vn = strlen(v);
    return vn >= pn && strcmp(v + vn - pn, port) == 0 && (vn == pn || v[vn - pn - 1] == ':');
}

static void matches(struct sb *b, const struct rtdiff *d, const struct rl *l) {
    char **names = d->nu ? calloc(d->nu, sizeof *names) : NULL;
    size_t n = 0;
    const bool udp = strcmp(l->kind, "udp") == 0;
    for (size_t i = 0; i < d->nu; i++) {
        const char *vals = udp ? d->u[i].dgram : d->u[i].stream;
        const size_t vl = udp ? d->u[i].dl : d->u[i].sl;
        bool hit = false;
        for (size_t o = 0; o < vl && !hit; o += strlen(vals + o) + 1) hit = value_is(l, vals + o);
        if (hit && names != NULL) names[n++] = d->u[i].name;
    }
    if (n) qsort(names, n, sizeof *names, str_cmp);
    sbs(b, ",\"matches\":[");
    for (size_t i = 0, w = 0; i < n; i++) {
        if (i && strcmp(names[i], names[i - 1]) == 0) continue;     /* a unit and its override */
        if (w++) sb_put(b, ",", 1);
        struct sb t = { 0 };
        sb_text(&t, names[i], strlen(names[i]));
        if (t.bad) b->bad = true;
        else sb_json(b, t.p != NULL ? t.p : "", t.n);
        free(t.p);
    }
    sb_put(b, "]", 1);
    if (d->nu && names == NULL) b->bad = true;
    free(names);
}

/* `tcp 0.0.0.0:80`, `tcp [::]:22`, `unix /run/x.sock`. */
static void where(struct sb *t, const struct rl *l) {
    sbs(t, l->kind);
    sb_put(t, " ", 1);
    if (l->port < 0) { sb_text(t, l->addr.p, l->addr.n); return; }
    char port[24];
    snprintf(port, sizeof port, ":%ld", l->port);
    if (l->proto == 6) sb_put(t, "[", 1);
    sb_text(t, l->addr.p, l->addr.n);
    if (l->proto == 6) sb_put(t, "]", 1);
    sbs(t, port);
}

static void listener_record(struct sb *b, const struct rtdiff *d, const struct rl *l, bool opened) {
    sbs(b, opened ? "{\"runtime\":\"listener_opened\"" : "{\"runtime\":\"listener_closed\"");
    for (size_t i = 0; i < l->v.n; i++) {
        sb_put(b, ",", 1);
        sb_json(b, l->v.keys[i], strlen(l->v.keys[i]));
        sb_put(b, ":", 1);
        sb_jval(b, &l->v.kids[i]);
    }
    if (l->systemd) matches(b, d, l);
    struct sb t = { 0 };
    sbs(&t, opened ? "opened: " : "closed: ");
    where(&t, l);
    if (l->held_known && l->held_none) sbs(&t, " (no process holds it)");
    else if (l->held_known) {
        sbs(&t, " held by ");
        for (size_t i = 0; i < l->nnames; i++) {
            if (i) sbs(&t, ", ");
            sbs(&t, l->names[i]);
        }
    }
    sbs(b, ",\"text\":");
    if (t.bad) b->bad = true;
    else sb_json(b, t.p, t.n);
    free(t.p);
    sbs(b, "}\n");
}

static void service_record(struct sb *b, const struct rs *s, const char *kind, const char *verb) {
    sbs(b, "{\"runtime\":\"");
    sbs(b, kind);
    sb_put(b, "\"", 1);
    for (size_t i = 0; i < 3; i++) {             /* service, processes, exe: not started_ns */
        sb_put(b, ",", 1);
        sb_json(b, s->v.keys[i], strlen(s->v.keys[i]));
        sb_put(b, ":", 1);
        sb_jval(b, &s->v.kids[i]);
    }
    struct sb t = { 0 };
    sbs(&t, verb);
    size_t ul = 0;
    const char *unit = last_service(s->name.p, s->name.n, &ul);
    if (unit != NULL) sb_text(&t, unit, ul);
    else sb_text(&t, s->name.p, s->name.n);
    sbs(b, ",\"text\":");
    if (t.bad) b->bad = true;
    else sb_json(b, t.p, t.n);
    free(t.p);
    sbs(b, "}\n");
}

int rtdiff_write(struct rtdiff *d, FILE *f, size_t *n) {
    *n = 0;
    if (d == NULL) return 0;
    struct sb b = { 0 };
    const struct side *sb_ = &d->side[0], *sa = &d->side[1];
    /* RT-D5: first, what makes the section less than whole. */
    static const char *const WHY[4] = { "no_record_before", "no_record_after", "holders_unknown_before",
                                        "holders_unknown_after" };
    static const char *const SAID[4] = { "no runtime record before", "no runtime record after",
                                         "holders not read before", "holders not read after" };
    const bool why[4] = { !sb_->have, !sa->have, sb_->have && sb_->holders_unknown > 0,
                          sa->have && sa->holders_unknown > 0 };
    if (why[0] || why[1] || why[2] || why[3]) {
        struct sb t = { 0 };
        sbs(&b, "{\"runtime\":\"incomplete\",\"why\":[");
        sbs(&t, "runtime incomplete: ");
        for (int i = 0, w = 0; i < 4; i++) {
            if (!why[i]) continue;
            if (w++) { sb_put(&b, ",", 1); sbs(&t, "; "); }
            sb_put(&b, "\"", 1);
            sbs(&b, WHY[i]);
            sb_put(&b, "\"", 1);
            sbs(&t, SAID[i]);
        }
        sbs(&b, "],\"text\":");
        if (t.bad) b.bad = true;
        else sb_json(&b, t.p, t.n);
        free(t.p);
        sbs(&b, "}\n");
        (*n)++;
    }
    if (compared(d)) {
        /* RT-D2: by key, closed before opened. */
        size_t i = 0, j = 0;
        while (i < sb_->nl || j < sa->nl) {
            const int c = i == sb_->nl ? 1 : j == sa->nl ? -1 : lkey(&sb_->l[i], &sa->l[j]);
            if (c == 0) { i++; j++; continue; }
            if (c < 0) listener_record(&b, d, &sb_->l[i++], false);
            else listener_record(&b, d, &sa->l[j++], true);
            (*n)++;
        }
        /* RT-D3: by service. */
        i = j = 0;
        while (i < sb_->ns || j < sa->ns) {
            const int c = i == sb_->ns ? 1 : j == sa->ns ? -1 : skey(&sb_->s[i], &sa->s[j]);
            if (c == 0) {
                const struct rs *x = &sb_->s[i++], *y = &sa->s[j++];
                if (!x->has_start || !y->has_start || x->start == y->start) continue;
                service_record(&b, y, "service_restarted", "restarted: ");
            } else if (c < 0) {
                service_record(&b, &sb_->s[i++], "service_stopped", "stopped: ");
            } else {
                service_record(&b, &sa->s[j++], "service_started", "started: ");
            }
            (*n)++;
        }
    }
    int rc = 0;
    if (b.bad) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "diff: out of memory");
        rc = -1;
    } else if (b.n && fwrite(b.p, 1, b.n, f) != b.n) {
        belay_err_set(BELAY_ERR_IO, errno, "diff: write failed");
        rc = -1;
    }
    free(b.p);
    return rc;
}
