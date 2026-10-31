#include "jsonr.h"

#include <stdlib.h>
#include <string.h>

struct cur { const char *p, *e; int depth; };

static void ws(struct cur *c) { while (c->p < c->e && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r')) c->p++; }

static int hexv(char h) {
    if (h >= '0' && h <= '9') return h - '0';
    if (h >= 'a' && h <= 'f') return h - 'a' + 10;
    if (h >= 'A' && h <= 'F') return h - 'A' + 10;
    return -1;
}

static void put_utf8(char *o, size_t *w, unsigned cp) {
    if (cp < 0x80) o[(*w)++] = (char)cp;
    else if (cp < 0x800) { o[(*w)++] = (char)(0xC0 | cp >> 6); o[(*w)++] = (char)(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) { o[(*w)++] = (char)(0xE0 | cp >> 12); o[(*w)++] = (char)(0x80 | (cp >> 6 & 0x3F));
                             o[(*w)++] = (char)(0x80 | (cp & 0x3F)); }
    else { o[(*w)++] = (char)(0xF0 | cp >> 18); o[(*w)++] = (char)(0x80 | (cp >> 12 & 0x3F));
           o[(*w)++] = (char)(0x80 | (cp >> 6 & 0x3F)); o[(*w)++] = (char)(0x80 | (cp & 0x3F)); }
}

static int str(struct cur *c, char **out, size_t *len) {
    if (c->p >= c->e || *c->p != '"') return -1;
    c->p++;
    char *o = malloc((size_t)(c->e - c->p) + 1);
    if (o == NULL) return -1;
    size_t w = 0;
    while (c->p < c->e && *c->p != '"') {
        if (*c->p != '\\') { o[w++] = *c->p++; continue; }
        if (++c->p >= c->e) break;
        const char k = *c->p++;
        switch (k) {
        case '"': o[w++] = '"'; break;
        case '\\': o[w++] = '\\'; break;
        case '/': o[w++] = '/'; break;
        case 'b': o[w++] = '\b'; break;
        case 'f': o[w++] = '\f'; break;
        case 'n': o[w++] = '\n'; break;
        case 'r': o[w++] = '\r'; break;
        case 't': o[w++] = '\t'; break;
        case 'u': {
            if (c->e - c->p < 4) { free(o); return -1; }
            unsigned cp = 0;
            for (int i = 0; i < 4; i++) {
                const int h = hexv(c->p[i]);
                if (h < 0) { free(o); return -1; }
                cp = cp * 16 + (unsigned)h;
            }
            c->p += 4;
            put_utf8(o, &w, cp);
            break;
        }
        default: free(o); return -1;
        }
    }
    if (c->p >= c->e) { free(o); return -1; }
    c->p++;
    o[w] = '\0';
    *out = o;
    *len = w;
    return 0;
}

static int val(struct cur *c, struct jval *v);

static int grow(struct jval *v, size_t *cap, bool keys) {
    if (v->n < *cap) return 0;
    const size_t nc = *cap ? *cap * 2 : 4;
    struct jval *k = realloc(v->kids, nc * sizeof *k);
    if (k == NULL) return -1;
    v->kids = k;
    if (keys) {
        char **kk = realloc(v->keys, nc * sizeof *kk);
        if (kk == NULL) return -1;
        v->keys = kk;
    }
    *cap = nc;
    return 0;
}

static int val(struct cur *c, struct jval *v) {
    memset(v, 0, sizeof *v);
    ws(c);
    if (c->p >= c->e) return -1;
    const char ch = *c->p;
    if (ch == '{' || ch == '[') {
        if (++c->depth > JSONR_DEPTH) return -1;
        const bool obj = ch == '{';
        v->t = obj ? J_OBJ : J_ARR;
        c->p++;
        size_t cap = 0;
        ws(c);
        if (c->p < c->e && *c->p == (obj ? '}' : ']')) { c->p++; c->depth--; return 0; }
        for (;;) {
            if (grow(v, &cap, obj) == -1) return -1;
            if (obj) {
                ws(c);
                size_t kl;
                if (str(c, &v->keys[v->n], &kl) == -1) return -1;
                ws(c);
                if (c->p >= c->e || *c->p != ':') { free(v->keys[v->n]); return -1; }
                c->p++;
            }
            if (val(c, &v->kids[v->n]) == -1) { if (obj) free(v->keys[v->n]); return -1; }
            v->n++;
            ws(c);
            if (c->p < c->e && *c->p == ',') { c->p++; continue; }
            if (c->p < c->e && *c->p == (obj ? '}' : ']')) { c->p++; c->depth--; return 0; }
            return -1;
        }
    }
    if (ch == '"') { v->t = J_STR; return str(c, &v->s, &v->s_len); }
    if (c->e - c->p >= 4 && memcmp(c->p, "true", 4) == 0) { v->t = J_BOOL; v->b = true; c->p += 4; return 0; }
    if (c->e - c->p >= 5 && memcmp(c->p, "false", 5) == 0) { v->t = J_BOOL; c->p += 5; return 0; }
    if (c->e - c->p >= 4 && memcmp(c->p, "null", 4) == 0) { v->t = J_NULL; c->p += 4; return 0; }
    if (ch == '-' || (ch >= '0' && ch <= '9')) {
        char buf[64];
        size_t n = 0;
        bool integer = true;
        while (c->p < c->e && n < sizeof buf - 1 &&
               (strchr("+-0123456789", *c->p) || *c->p == '.' || *c->p == 'e' || *c->p == 'E')) {
            if (*c->p == '.' || *c->p == 'e' || *c->p == 'E') integer = false;
            buf[n++] = *c->p++;
        }
        buf[n] = '\0';
        v->t = J_NUM;
        v->num = strtod(buf, NULL);
        v->i = integer ? strtoll(buf, NULL, 10) : (int64_t)v->num;
        return 0;
    }
    return -1;
}

int jsonr_parse(const char *text, size_t len, struct jval *out) {
    struct cur c = { text, text + len, 0 };
    if (val(&c, out) == -1) { jsonr_free(out); return -1; }
    ws(&c);
    if (c.p != c.e) { jsonr_free(out); return -1; }
    return 0;
}

void jsonr_free(struct jval *v) {
    if (v == NULL) return;
    free(v->s);
    for (size_t i = 0; i < v->n; i++) {
        jsonr_free(&v->kids[i]);
        if (v->keys) free(v->keys[i]);
    }
    free(v->kids);
    free(v->keys);
    memset(v, 0, sizeof *v);
}

const struct jval *jget(const struct jval *o, const char *key) {
    if (o == NULL || o->t != J_OBJ) return NULL;
    for (size_t i = 0; i < o->n; i++)
        if (strcmp(o->keys[i], key) == 0) return &o->kids[i];
    return NULL;
}

const char *jstr(const struct jval *o, const char *key) {
    const struct jval *v = jget(o, key);
    return v != NULL && v->t == J_STR ? v->s : "";
}

int64_t jint(const struct jval *o, const char *key, int64_t def) {
    const struct jval *v = jget(o, key);
    return v != NULL && v->t == J_NUM ? v->i : def;
}
