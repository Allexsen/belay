/*
 *  The config interpreter (test/expect/system-config.md; finding-kinds.md,
 *  config_*): for a few files whose grammar is fixed, the key that changed
 *  instead of a count of lines. It states the text of one file, never the
 *  setting in force (CF-X3): includes, drop-in order, first-match rules
 *  and built-in defaults are the tool's.
 *
 *  A second claim: the file's own interpreter -- text, or systemd for a
 *  unit file -- explains it too, and its findings stand (CF-6). config
 *  adds events only.
 *
 *  Each side is tokenized into (context, key, value) triples (CF-1): the
 *  context is the enclosing block headers, or the section, as written;
 *  the value is the rest of the directive, each run of whitespace made one
 *  space. Per (context, key) (CF-2): one occurrence on each side, the two
 *  values differing, is config_key_changed; otherwise the values on each
 *  side are a set, and each on one side only is config_key_removed or
 *  config_key_added. A repeated key is never changed. Two blocks under one
 *  parent, or two sections, with one header on a side (CF-3), a side that
 *  does not tokenize, or one too large (CF-4): config_not_keyed, its why
 *  the first of `too large`, `does not parse`, `a block header is not
 *  unique` that holds. Events come by path, then context, then key,
 *  removed before added (CF-5): each (context, key) is given its place in
 *  that order as its `line`, which the shared order (E13) then keeps.
 *
 *  A symbolic link is no file of its path: a side that is one is absent,
 *  and its target's file is keyed where it is (sites-enabled). A side that
 *  is another non-regular file, sealed, under a metadata root, without a
 *  copy that can be read, or holding a NUL is could_not_interpret (SI-2),
 *  as an event; the record is the first claim's.
 *
 *  Input is hostile: every length is checked, nothing recurses, nginx's
 *  blocks nest at most NGINX_DEPTH_MAX deep, and a side gives at most
 *  CONFIG_TRIPLES_MAX triples.
 */
#include "builtins.h"
#include "config.h"
#include "stored.h"
#include "sysev.h"

#include "belay/hash.h"
#include "belay/manifest.h"

#include <stdlib.h>
#include <string.h>

#define CONFIG_TRIPLES_MAX 65536u           /* of one side: more is `too large` (CF-4) */
#define NGINX_DEPTH_MAX    64u              /* blocks within blocks: deeper does not parse */
#define ARENA_MAX          (64u * 1024u * 1024u)

static const char *const GRAMMAR[] = { "", "nginx", "sshd", "ini", "keyvalue", "namevalue" };

/* ---- the claims ---- */

/* `abs` is directly in a directory whose path ends `dir` (with its
 * slashes), its name ending `suffix` and longer than it (NULL: any name). */
static bool in_dir(const char *abs, size_t n, const char *dir, const char *suffix) {
    size_t bl, dl;
    const char *base = sys_base(abs, n, &bl, &dl);
    if (bl == 0 || !sys_ends(abs, dl, dir)) return false;
    return suffix == NULL || (bl > strlen(suffix) && sys_ends(base, bl, suffix));
}

/* etc/systemd/<x>.conf.d/<y>.conf */
static bool systemd_conf_d(const char *abs, size_t n) {
    size_t bl, dl, pbl, pdl;
    sys_base(abs, n, &bl, &dl);
    if (bl <= 5 || !sys_ends(abs, n, ".conf") || dl < 2 || !sys_ends(abs, dl, ".conf.d/")) return false;
    sys_base(abs, dl - 1, &pbl, &pdl);
    return pbl > 7 && sys_ends(abs, pdl, "/etc/systemd/");
}

enum config_grammar config_grammar(const char *abs, size_t n) {
    if (sys_ends(abs, n, "/etc/nginx/nginx.conf") || in_dir(abs, n, "/etc/nginx/conf.d/", ".conf") ||
        in_dir(abs, n, "/etc/nginx/sites-available/", NULL) || in_dir(abs, n, "/etc/nginx/sites-enabled/", NULL) ||
        in_dir(abs, n, "/etc/nginx/modules-enabled/", NULL) || in_dir(abs, n, "/etc/nginx/snippets/", NULL))
        return CONFIG_NGINX;
    if (sys_ends(abs, n, "/etc/ssh/sshd_config") || in_dir(abs, n, "/etc/ssh/sshd_config.d/", ".conf"))
        return CONFIG_SSHD;
    if (sys_ends(abs, n, "/etc/sysctl.conf") || in_dir(abs, n, "/etc/sysctl.d/", ".conf")) return CONFIG_KEYVALUE;
    if (sys_ends(abs, n, "/etc/login.defs")) return CONFIG_NAMEVALUE;
    if (in_dir(abs, n, "/etc/systemd/", ".conf") || systemd_conf_d(abs, n) || systemd_unit_file_path(abs, n))
        return CONFIG_INI;
    return CONFIG_NONE;
}

/* ---- the triples of both sides ---- */

enum why { W_OK, W_UNIQUE, W_PARSE, W_LARGE };      /* the last that holds wins */
static const char *const WHY[] = { "", "a block header is not unique", "does not parse", "too large" };

struct ctxe {                   /* a block or a section; 0 is the top level, of both sides */
    uint32_t parent, off, len, depth, rank;
    uint8_t side;
};
struct triple { uint32_t ctx, koff, klen, voff, vlen; uint8_t side; };

struct keyed {
    enum config_grammar g;
    char *a; size_t alen, acap;                 /* every string, by offset */
    struct ctxe *c; size_t nc, cc;
    struct triple *t; size_t nt, ct;
    size_t per_side[2];
    enum why why[2];
    bool oom;
};

static void *grow(void *p, size_t *cap, size_t need, size_t size, bool *oom) {
    if (need <= *cap) return p;
    size_t nc = *cap ? *cap : 64;
    while (nc < need) nc *= 2;
    void *q = realloc(p, nc * size);
    if (q == NULL) { *oom = true; return NULL; }
    *cap = nc;
    return q;
}

/* Appends n bytes; their offset. */
static uint32_t put(struct keyed *k, const char *s, size_t n) {
    if (k->oom || k->alen + n > ARENA_MAX) { k->oom = true; return 0; }
    char *a = grow(k->a, &k->acap, k->alen + n + 1, 1, &k->oom);
    if (a == NULL) return 0;
    k->a = a;
    const uint32_t off = (uint32_t)k->alen;
    if (n) memcpy(k->a + off, s, n);
    k->alen += n;
    return off;
}

static bool ws_line(char c) { return c == ' ' || c == '\t'; }
static bool ws_any(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

/* [s, s+n) without its outer whitespace, each inner run made one space. */
static uint32_t put_norm(struct keyed *k, const char *s, size_t n, uint32_t *len, bool (*ws)(char)) {
    const uint32_t off = put(k, "", 0);
    const size_t start = k->alen;
    bool gap = false;
    for (size_t i = 0; i < n && !k->oom; i++) {
        if (ws(s[i])) { gap = true; continue; }
        if (gap && k->alen > start) put(k, " ", 1);
        gap = false;
        put(k, s + i, 1);
    }
    *len = (uint32_t)(k->alen - start);
    return off;
}

static uint32_t new_ctx(struct keyed *k, int side, uint32_t parent, uint32_t off, uint32_t len) {
    struct ctxe *c = grow(k->c, &k->cc, k->nc + 1, sizeof *c, &k->oom);
    if (c == NULL) return 0;
    k->c = c;
    k->c[k->nc] = (struct ctxe){ .parent = parent, .off = off, .len = len, .depth = k->c[parent].depth + 1,
                                 .side = (uint8_t)side };
    return (uint32_t)k->nc++;
}

/* false when the side has as many as it may: it is `too large`. */
static bool add(struct keyed *k, int side, uint32_t ctx, uint32_t koff, uint32_t klen, uint32_t voff, uint32_t vlen) {
    if (k->per_side[side] == CONFIG_TRIPLES_MAX) { k->why[side] = W_LARGE; return false; }
    struct triple *t = grow(k->t, &k->ct, k->nt + 1, sizeof *t, &k->oom);
    if (t == NULL) return false;
    k->t = t;
    k->t[k->nt++] = (struct triple){ ctx, koff, klen, voff, vlen, (uint8_t)side };
    k->per_side[side]++;
    return true;
}

/* The next physical line at *p: [*s, *e) trimmed of spaces and tabs. */
static bool next_line(const char **p, const char *end, const char **s, const char **e) {
    if (*p >= end) return false;
    const char *nl = memchr(*p, '\n', (size_t)(end - *p));
    *s = *p;
    *e = nl ? nl : end;
    *p = nl ? nl + 1 : end;
    sys_trim(s, e);
    return true;
}

static bool ieq(const char *a, size_t an, const char *b) {
    const size_t bn = strlen(b);
    if (an != bn) return false;
    for (size_t i = 0; i < an; i++) {
        char x = a[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (x != b[i]) return false;
    }
    return true;
}

/* ---- CF-L: namevalue (`NAME value`), CF-K: keyvalue (`key = value`) ---- */

static void tok_namevalue(struct keyed *k, int side, const char *b, size_t n) {
    const char *p = b, *s, *e;
    while (next_line(&p, b + n, &s, &e) && !k->oom) {
        if (s == e || *s == '#') continue;
        const char *w = s;
        while (w < e && !ws_line(*w)) w++;
        const uint32_t ko = put(k, s, (size_t)(w - s));
        uint32_t vl, vo = put_norm(k, w, (size_t)(e - w), &vl, ws_line);
        if (!add(k, side, 0, ko, (uint32_t)(w - s), vo, vl)) return;
    }
}

static void tok_keyvalue(struct keyed *k, int side, const char *b, size_t n) {
    const char *p = b, *s, *e;
    while (next_line(&p, b + n, &s, &e) && !k->oom) {
        if (s == e || *s == '#' || *s == ';') continue;
        const char *eq = memchr(s, '=', (size_t)(e - s));
        if (eq == NULL) { k->why[side] = W_PARSE; return; }
        const char *ks = s, *ke = eq;
        sys_trim(&ks, &ke);
        if (ks == ke) { k->why[side] = W_PARSE; return; }
        const uint32_t ko = put(k, ks, (size_t)(ke - ks));
        uint32_t vl, vo = put_norm(k, eq + 1, (size_t)(e - eq - 1), &vl, ws_line);
        if (!add(k, side, 0, ko, (uint32_t)(ke - ks), vo, vl)) return;
    }
}

/* ---- CF-I: ini ---- */

/* One logical line of an ini file, trimmed: a section or an assignment. */
static bool ini_logical(struct keyed *k, int side, const char *s, const char *e, uint32_t *cur) {
    sys_trim(&s, &e);
    if (s == e) return true;
    if (*s == '[') {
        if (e - s < 3 || e[-1] != ']') { k->why[side] = W_PARSE; return false; }
        const uint32_t off = put(k, s + 1, (size_t)(e - s - 2));
        *cur = new_ctx(k, side, 0, off, (uint32_t)(e - s - 2));
        return !k->oom;
    }
    const char *eq = memchr(s, '=', (size_t)(e - s));
    if (eq == NULL) { k->why[side] = W_PARSE; return false; }
    const char *ks = s, *ke = eq;
    sys_trim(&ks, &ke);
    if (ks == ke) { k->why[side] = W_PARSE; return false; }
    const uint32_t ko = put(k, ks, (size_t)(ke - ks));
    uint32_t vl, vo = put_norm(k, eq + 1, (size_t)(e - eq - 1), &vl, ws_line);
    return add(k, side, *cur, ko, (uint32_t)(ke - ks), vo, vl);
}

/* `#` and `;` begin a comment, which ends at its line whatever its last
 * byte; a trailing `\` joins the next line, a space in its place, and a
 * comment within a continuation is skipped (systemd.syntax(7)). */
static void tok_ini(struct keyed *k, int side, const char *b, size_t n) {
    char *join = malloc(n + 1);
    if (join == NULL) { k->oom = true; return; }
    size_t jl = 0;
    bool cont = false;
    uint32_t cur = 0;
    const char *p = b, *s, *e;
    while (next_line(&p, b + n, &s, &e) && !k->oom) {
        if (s < e && (*s == '#' || *s == ';')) continue;
        if (s == e && !cont) continue;
        const bool more = s < e && e[-1] == '\\';
        const size_t take = (size_t)(e - s) - (more ? 1 : 0);
        memcpy(join + jl, s, take);
        jl += take;
        if (more) { join[jl++] = ' '; cont = true; continue; }
        cont = false;
        if (!ini_logical(k, side, join, join + jl, &cur)) { jl = 0; break; }
        jl = 0;
    }
    if (jl > 0 && !k->oom && k->why[side] == W_OK) ini_logical(k, side, join, join + jl, &cur);
    free(join);
}

/* ---- CF-S: sshd ---- */

static void tok_sshd(struct keyed *k, int side, const char *b, size_t n) {
    uint32_t cur = 0;
    const char *p = b, *s, *e;
    while (next_line(&p, b + n, &s, &e) && !k->oom) {
        if (s == e || *s == '#') continue;
        const char *w = s;
        while (w < e && !ws_line(*w) && *w != '=') w++;
        if (w == s) { k->why[side] = W_PARSE; return; }
        if (ieq(s, (size_t)(w - s), "match")) {             /* a context to the next Match or the end */
            uint32_t hl, ho = put_norm(k, s, (size_t)(e - s), &hl, ws_line);
            cur = new_ctx(k, side, 0, ho, hl);
            continue;
        }
        const char *v = w;
        while (v < e && ws_line(*v)) v++;
        if (v < e && *v == '=') v++;
        const uint32_t ko = put(k, s, (size_t)(w - s));
        uint32_t vl, vo = put_norm(k, v, (size_t)(e - v), &vl, ws_line);
        if (!add(k, side, cur, ko, (uint32_t)(w - s), vo, vl)) return;
    }
}

/* ---- CF-N: nginx ---- */

static bool word_start(const char *b, size_t from, size_t j) {
    return j == from || ws_any(b[j - 1]) || b[j - 1] == ';' || b[j - 1] == '{' || b[j - 1] == '}';
}

/* The `}` closing the block whose text begins at `from`, by nginx's
 * tokens: quotes at a word's start with backslash escapes, `#` at a word's
 * start to the end of the line, `${` a variable's brace. */
static bool close_nginx(const char *b, size_t n, size_t from, size_t *end) {
    size_t depth = 1;
    for (size_t j = from; j < n; j++) {
        const char c = b[j];
        if (c == '\\') { j++; continue; }
        if ((c == '"' || c == '\'') && word_start(b, from, j)) {
            for (j++; j < n && b[j] != c; j++)
                if (b[j] == '\\') j++;
            if (j >= n) return false;
            continue;
        }
        if (c == '#' && word_start(b, from, j)) {
            const char *nl = memchr(b + j, '\n', n - j);
            if (nl == NULL) return false;
            j = (size_t)(nl - b);
            continue;
        }
        if (c == '$' && j + 1 < n && b[j + 1] == '{') {
            const char *cl = memchr(b + j, '}', n - j);
            if (cl == NULL) return false;
            j = (size_t)(cl - b);
            continue;
        }
        if (c == '{') depth++;
        else if (c == '}' && --depth == 0) { *end = j; return true; }
    }
    return false;
}

/* A Lua long bracket at j (`[`, `=`*level, `[`): its level, or -1. */
static long long_open(const char *b, size_t n, size_t j) {
    if (j >= n || b[j] != '[') return -1;
    size_t i = j + 1;
    while (i < n && b[i] == '=') i++;
    return i < n && b[i] == '[' ? (long)(i - j - 1) : -1;
}

/* Past the long bracket of `level` opened at j: the index after its close. */
static bool long_close(const char *b, size_t n, size_t j, long level, size_t *after) {
    for (size_t i = j + (size_t)level + 2; i < n; i++) {
        if (b[i] != ']') continue;
        size_t q = i + 1;
        while (q < n && b[q] == '=') q++;
        if (q < n && b[q] == ']' && (long)(q - i - 1) == level) { *after = q + 1; return true; }
    }
    return false;
}

/* The same for a `*_by_lua_block`, by Lua's tokens: strings, long
 * brackets, `--` comments. */
static bool close_lua(const char *b, size_t n, size_t from, size_t *end) {
    size_t depth = 1;
    for (size_t j = from; j < n; ) {
        const char c = b[j];
        long lv;
        if (c == '-' && j + 1 < n && b[j + 1] == '-') {
            if ((lv = long_open(b, n, j + 2)) >= 0) {
                if (!long_close(b, n, j + 2, lv, &j)) return false;
            } else {
                const char *nl = memchr(b + j, '\n', n - j);
                j = nl ? (size_t)(nl - b) + 1 : n;
            }
            continue;
        }
        if ((lv = long_open(b, n, j)) >= 0) {
            if (!long_close(b, n, j, lv, &j)) return false;
            continue;
        }
        if (c == '"' || c == '\'') {
            for (j++; j < n && b[j] != c; j++)
                if (b[j] == '\\') j++;
            if (j >= n) return false;
            j++;
            continue;
        }
        if (c == '{') depth++;
        else if (c == '}' && --depth == 0) { *end = j; return true; }
        j++;
    }
    return false;
}

static bool opaque(const char *w, size_t n, bool *lua) {
    static const char *const OPAQUE[] = { "map", "types", "geo", "split_clients", "charset_map" };
    *lua = sys_ends(w, n, "_by_lua_block");
    if (*lua) return true;
    for (size_t i = 0; i < sizeof OPAQUE / sizeof OPAQUE[0]; i++)
        if (n == strlen(OPAQUE[i]) && memcmp(w, OPAQUE[i], n) == 0) return true;
    return false;
}

static void hex64(const uint8_t d[BELAY_SHA256_DIGEST_LEN], char out[64]) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < BELAY_SHA256_DIGEST_LEN; i++) { out[2 * i] = H[d[i] >> 4]; out[2 * i + 1] = H[d[i] & 15]; }
}

/* A directive is words to `;`; a block is words then `{ ... }`; `#` at a
 * word's start runs to the end of the line; a word that starts with a
 * quote runs to the same quote, backslash escaping, and is followed by
 * whitespace, `;` or `{`; outside quotes a backslash escapes the next
 * byte and `${` opens a variable's name. The key is the first word and
 * the value the others, each as written, one space between; a block's
 * header is all its words so. */
static void tok_nginx(struct keyed *k, int side, const char *b, size_t n) {
    uint32_t stack[NGINX_DEPTH_MAX + 1];
    size_t depth = 0, nw = 0, i = 0;
    uint32_t koff = 0, klen = 0;
    stack[0] = 0;
    while (i < n && !k->oom) {
        const char c = b[i];
        if (ws_any(c)) { i++; continue; }
        if (c == '#') {
            const char *nl = memchr(b + i, '\n', n - i);
            i = nl ? (size_t)(nl - b) + 1 : n;
            continue;
        }
        if (c == ';' || c == '{') {
            if (nw == 0) goto fail;
            const uint32_t all = (uint32_t)(k->alen - koff);        /* the words, as the header */
            const uint32_t voff = nw > 1 ? koff + klen + 1 : koff + klen, vlen = nw > 1 ? all - klen - 1 : 0;
            i++;
            nw = 0;
            bool lua;
            if (c == ';') {
                if (!add(k, side, stack[depth], koff, klen, voff, vlen)) return;
            } else if (opaque(k->a + koff, klen, &lua)) {
                size_t end;
                if (!(lua ? close_lua : close_nginx)(b, n, i, &end)) goto fail;
                struct belay_sha256 h;
                uint8_t d[BELAY_SHA256_DIGEST_LEN];
                char hex[64];
                belay_sha256_init(&h);
                belay_sha256_update(&h, b + i, end - i);
                belay_sha256_final(&h, d);
                hex64(d, hex);
                const uint32_t ho = put(k, hex, sizeof hex);
                if (!add(k, side, stack[depth], koff, all, ho, sizeof hex)) return;
                i = end + 1;
            } else {
                if (depth == NGINX_DEPTH_MAX) goto fail;
                const uint32_t id = new_ctx(k, side, stack[depth], koff, all);
                if (k->oom) return;
                stack[++depth] = id;
            }
            continue;
        }
        if (c == '}') {
            if (nw > 0 || depth == 0) goto fail;
            depth--;
            i++;
            continue;
        }
        const size_t w0 = i;                                        /* a word */
        if (c == '"' || c == '\'') {
            for (i++; i < n && b[i] != c; i++)
                if (b[i] == '\\') i++;
            if (i >= n) goto fail;
            i++;
            if (i < n && !ws_any(b[i]) && b[i] != ';' && b[i] != '{') goto fail;
        } else {
            while (i < n) {
                const char x = b[i];
                if (x == '\\') { i += 2; continue; }
                if (x == '$' && i + 1 < n && b[i + 1] == '{') {
                    const char *cl = memchr(b + i, '}', n - i);
                    if (cl == NULL) goto fail;
                    i = (size_t)(cl - b) + 1;
                    continue;
                }
                if (ws_any(x) || x == ';' || x == '{' || x == '}') break;
                i++;
            }
            if (i > n) i = n;
        }
        if (nw == 0) { koff = put(k, b + w0, i - w0); klen = (uint32_t)(i - w0); }
        else { put(k, " ", 1); put(k, b + w0, i - w0); }
        nw++;
    }
    if (nw == 0 && depth == 0) return;
fail:
    k->why[side] = W_PARSE;
}

/* ---- comparing ---- */

/* A stable merge sort with a context: qsort has none, and the order must
 * not depend on the library. */
typedef int (*cmp_fn)(const struct keyed *k, const void *a, const void *b);
static bool msort(void *base, size_t n, size_t size, cmp_fn cmp, const struct keyed *k) {
    if (n < 2) return true;
    char *a = base, *t = malloc(n * size);
    if (t == NULL) return false;
    for (size_t w = 1; w < n; w *= 2) {
        for (size_t lo = 0; lo < n; lo += 2 * w) {
            size_t mid = lo + w < n ? lo + w : n, hi = lo + 2 * w < n ? lo + 2 * w : n, i = lo, j = mid, o = lo;
            while (i < mid && j < hi) {
                if (cmp(k, a + j * size, a + i * size) < 0) memcpy(t + o++ * size, a + j++ * size, size);
                else memcpy(t + o++ * size, a + i++ * size, size);
            }
            memcpy(t + o * size, a + i * size, (mid - i) * size);
            o += mid - i;
            memcpy(t + o * size, a + j * size, (hi - j) * size);
        }
        memcpy(a, t, n * size);
    }
    free(t);
    return true;
}

static int bytes_cmp(const char *a, size_t an, const char *b, size_t bn) {
    const int c = an && bn ? memcmp(a, b, an < bn ? an : bn) : 0;
    return c ? c : (an > bn) - (an < bn);
}

static int fold_cmp(const char *a, size_t an, const char *b, size_t bn) {
    for (size_t i = 0; i < an && i < bn; i++) {
        unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x >= 'A' && x <= 'Z') x = (unsigned char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (unsigned char)(y - 'A' + 'a');
        if (x != y) return x < y ? -1 : 1;
    }
    return (an > bn) - (an < bn);
}

/* The headers of a context, outermost first: *n of them. */
static void chain(const struct keyed *k, uint32_t id, uint32_t out[NGINX_DEPTH_MAX + 1], size_t *n) {
    size_t d = k->c[id].depth;
    *n = d;
    for (uint32_t x = id; x != 0 && d > 0; x = k->c[x].parent) out[--d] = x;
}

static int ctx_cmp(const struct keyed *k, const void *pa, const void *pb) {
    uint32_t ca[NGINX_DEPTH_MAX + 1], cb[NGINX_DEPTH_MAX + 1];
    size_t na, nb;
    chain(k, *(const uint32_t *)pa, ca, &na);
    chain(k, *(const uint32_t *)pb, cb, &nb);
    for (size_t i = 0; i < na && i < nb; i++) {
        const struct ctxe *x = &k->c[ca[i]], *y = &k->c[cb[i]];
        const int c = bytes_cmp(k->a + x->off, x->len, k->a + y->off, y->len);
        if (c) return c;
    }
    return (na > nb) - (na < nb);
}

/* CF-3, of one level: by parent, then header. */
static int sibling_cmp(const struct keyed *k, const void *pa, const void *pb) {
    const struct ctxe *x = &k->c[*(const uint32_t *)pa], *y = &k->c[*(const uint32_t *)pb];
    if (x->side != y->side) return x->side < y->side ? -1 : 1;
    if (x->parent != y->parent) return x->parent < y->parent ? -1 : 1;
    return bytes_cmp(k->a + x->off, x->len, k->a + y->off, y->len);
}

static int key_cmp(const struct keyed *k, const struct triple *x, const struct triple *y) {
    if (k->c[x->ctx].rank != k->c[y->ctx].rank) return k->c[x->ctx].rank < k->c[y->ctx].rank ? -1 : 1;
    return (k->g == CONFIG_SSHD ? fold_cmp : bytes_cmp)(k->a + x->koff, x->klen, k->a + y->koff, y->klen);
}

static int triple_cmp(const struct keyed *k, const void *pa, const void *pb) {
    const struct triple *x = pa, *y = pb;
    int c = key_cmp(k, x, y);
    if (c == 0) c = bytes_cmp(k->a + x->voff, x->vlen, k->a + y->voff, y->vlen);
    return c ? c : (x->side > y->side) - (x->side < y->side);
}

/* Ranks the contexts by their headers (equal lists, equal rank) and marks
 * a side whose blocks repeat a header under one parent (CF-3). 0, -1. */
static int rank_contexts(struct keyed *k) {
    uint32_t *ix = malloc((k->nc ? k->nc : 1) * sizeof *ix);
    if (ix == NULL) return -1;
    for (size_t i = 0; i < k->nc; i++) ix[i] = (uint32_t)i;
    if (!msort(ix + 1, k->nc - 1, sizeof *ix, sibling_cmp, k)) { free(ix); return -1; }
    for (size_t i = 2; i < k->nc; i++)
        if (sibling_cmp(k, &ix[i - 1], &ix[i]) == 0 && k->why[k->c[ix[i]].side] == W_OK)
            k->why[k->c[ix[i]].side] = W_UNIQUE;
    if (!msort(ix, k->nc, sizeof *ix, ctx_cmp, k)) { free(ix); return -1; }
    uint32_t r = 0;
    for (size_t i = 0; i < k->nc; i++) {
        if (i > 0 && ctx_cmp(k, &ix[i - 1], &ix[i]) != 0) r++;
        k->c[ix[i]].rank = r;
    }
    free(ix);
    return 0;
}

/* ---- the interpreter ---- */

struct config { struct sysevs *ev; bool failed; };

static void *begin(void) {
    struct config *s = calloc(1, sizeof *s);
    if (s != NULL && (s->ev = sysevs_new()) == NULL) { free(s); s = NULL; }
    return s;
}

static enum belay_interp_result done(struct config *st) {
    return st->failed || sysevs_failed(st->ev) ? BELAY_INTERP_ERROR : BELAY_INTERP_DECLINE;
}

static enum belay_interp_result cannot(struct config *st, const struct belay_interp_input *in) {
    sysevs_not_interpreted(st->ev, in->path, in->path_len, sys_prov(in));
    return done(st);
}

static enum belay_interp_result not_keyed(struct config *st, const struct belay_interp_input *in,
                                          enum config_grammar g, enum why w) {
    const struct belay_fv v[] = { { .s = in->path, .len = in->path_len }, { .s = GRAMMAR[g], .len = strlen(GRAMMAR[g]) },
                                  { .s = WHY[w], .len = strlen(WHY[w]) } };
    sysevs_add(st->ev, FK_CONFIG_NOT_KEYED, in->path, in->path_len, 0, SYS_REMOVED, sys_prov(in), v, 3);
    return done(st);
}

static void key_event(struct config *st, const struct belay_interp_input *in, const struct keyed *k, int kind,
                      uint32_t place, const struct triple *t, const struct triple *to) {
    struct belay_fv ctx[NGINX_DEPTH_MAX + 1];
    uint32_t ch[NGINX_DEPTH_MAX + 1];
    size_t nc;
    chain(k, t->ctx, ch, &nc);
    for (size_t i = 0; i < nc; i++) ctx[i] = (struct belay_fv){ .s = k->a + k->c[ch[i]].off, .len = k->c[ch[i]].len };
    const struct triple *kt = to != NULL ? to : t;                  /* changed: the key as written after */
    const struct belay_fv v[] = {
        { .s = in->path, .len = in->path_len }, { .s = GRAMMAR[k->g], .len = strlen(GRAMMAR[k->g]) },
        { .list = ctx, .nlist = nc }, { .s = k->a + kt->koff, .len = kt->klen },
        { .s = k->a + t->voff, .len = t->vlen }, { .s = to ? k->a + to->voff : NULL, .len = to ? to->vlen : 0 },
    };
    sysevs_add(st->ev, kind, in->path, in->path_len, place, kind == FK_CONFIG_KEY_REMOVED ? SYS_REMOVED : SYS_ADDED,
               sys_prov(in), v, to != NULL ? 6 : 5);
}

/* CF-2 over the sorted triples, one (context, key) at a time. */
static void compare(struct config *st, const struct belay_interp_input *in, const struct keyed *k) {
    uint32_t place = 0;
    for (size_t g = 0; g < k->nt; ) {
        size_t h = g + 1, occ[2] = { 0, 0 };
        while (h < k->nt && key_cmp(k, &k->t[g], &k->t[h]) == 0) h++;
        for (size_t i = g; i < h; i++) occ[k->t[i].side]++;
        place++;
        if (occ[0] == 1 && occ[1] == 1) {
            const struct triple *b = k->t[g].side == 0 ? &k->t[g] : &k->t[g + 1];
            const struct triple *a = k->t[g].side == 0 ? &k->t[g + 1] : &k->t[g];
            if (bytes_cmp(k->a + b->voff, b->vlen, k->a + a->voff, a->vlen) != 0)
                key_event(st, in, k, FK_CONFIG_KEY_CHANGED, place, b, a);
        } else {
            for (size_t i = g; i < h; ) {                           /* each value, on which sides */
                size_t j = i + 1;
                bool on[2] = { false, false };
                on[k->t[i].side] = true;
                while (j < h && bytes_cmp(k->a + k->t[i].voff, k->t[i].vlen, k->a + k->t[j].voff, k->t[j].vlen) == 0)
                    on[k->t[j++].side] = true;
                if (on[0] != on[1])
                    key_event(st, in, k, on[0] ? FK_CONFIG_KEY_REMOVED : FK_CONFIG_KEY_ADDED, place, &k->t[i], NULL);
                i = j;
            }
        }
        g = h;
    }
}

static bool is_reg(const struct belay_entry *e) { return e != NULL && e->type == BELAY_T_REG; }

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct config *st = state;
    (void)out;                                  /* events only: the record is the first claim's (CF-6) */
    if (st == NULL) return BELAY_INTERP_ERROR;
    const enum config_grammar g = config_grammar(in->abs_path, in->abs_len);
    if (g == CONFIG_NONE || strcmp(in->outcome, "metadata_only") == 0) return BELAY_INTERP_DECLINE;
    const struct belay_entry *e[2] = { in->before, in->after };
    for (int s = 0; s < 2; s++)
        if (e[s] != NULL && e[s]->type == BELAY_T_LNK) e[s] = NULL;     /* no file of its path */
    if (!is_reg(e[0]) && !is_reg(e[1])) return BELAY_INTERP_DECLINE;
    for (int s = 0; s < 2; s++)
        if (e[s] != NULL && (e[s]->type != BELAY_T_REG || e[s]->sealed || e[s]->meta)) return cannot(st, in);
    for (int s = 0; s < 2; s++)
        if (e[s] != NULL && e[s]->size > BELAY_KEEP_KEYED_MAX) return not_keyed(st, in, g, W_LARGE);

    unsigned char *buf[2] = { NULL, NULL };
    size_t len[2] = { 0, 0 };
    for (int s = 0; s < 2; s++) {
        if (e[s] == NULL) continue;
        const enum stored_why w = stored_read(in, (enum side)s, BELAY_KEEP_KEYED_MAX, &buf[s], &len[s]);
        if (w == SW_TOO_LARGE) { free(buf[0]); free(buf[1]); return not_keyed(st, in, g, W_LARGE); }
        if (w != SW_OK || memchr(buf[s], '\0', len[s]) != NULL) { free(buf[0]); free(buf[1]); return cannot(st, in); }
    }

    struct keyed k = { .g = g };
    k.c = malloc(sizeof *k.c);
    k.cc = k.nc = k.c != NULL ? 1 : 0;
    if (k.c == NULL) k.oom = true;
    else k.c[0] = (struct ctxe){ 0 };
    static void (*const TOK[])(struct keyed *, int, const char *, size_t) = {
        NULL, tok_nginx, tok_sshd, tok_ini, tok_keyvalue, tok_namevalue };
    for (int s = 0; s < 2 && !k.oom; s++)
        if (buf[s] != NULL) TOK[g](&k, s, (const char *)buf[s], len[s]);
    if (!k.oom && rank_contexts(&k) == -1) k.oom = true;
    const enum why why = k.why[0] > k.why[1] ? k.why[0] : k.why[1];
    if (k.oom) st->failed = true;
    else if (why != W_OK) not_keyed(st, in, g, why);
    else if (!msort(k.t, k.nt, sizeof *k.t, triple_cmp, &k)) st->failed = true;
    else compare(st, in, &k);
    free(k.a);
    free(k.c);
    free(k.t);
    free(buf[0]);
    free(buf[1]);
    return done(st);
}

static enum belay_interp_result end(void *state, struct belay_events *ev) {
    struct config *st = state;
    if (st == NULL) return BELAY_INTERP_ERROR;
    enum belay_interp_result r = ev != NULL ? sysevs_emit(st->ev, ev, NULL) : BELAY_INTERP_FINDINGS;
    if (st->failed) r = BELAY_INTERP_ERROR;
    sysevs_free(st->ev);
    free(st);
    return r;
}

const struct belay_interp INTERP_CONFIG = { BELAY_INTERP_CONFIG, begin, explain, end, NULL };
