#define _GNU_SOURCE
#include "policy/bundle.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "belay/error.h"
#include "belay/hash.h"
#include "belay/interp.h"
#include "belay/json.h"
#include "belay/manifest.h"
#include "belay/store.h"
#include "policy/jw.h"
#include "util/jsonr.h"

#define COPY_MAX ((size_t)1 << 30)          /* one stored copy, read whole */
#define PACKAGES_MAX ((size_t)1 << 30)      /* the packages member, read whole */

static void hexdigest(struct belay_sha256 *h, char out[65]) {
    uint8_t d[32];
    belay_sha256_final(h, d);
    belay_hex_encode(out, d, 32);
}

static bool hex64(const char *s, size_t n) {
    if (n != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

/* ---- the stored keys a manifest names, sorted, each once ---- */

struct keys { char (*k)[65]; size_t n, cap; };

static int keycmp(const void *a, const void *b) { return memcmp(a, b, 64); }

static int manifest_keys(const char *manifest, struct keys *out, struct belay_manifest_header *hdr) {
    memset(out, 0, sizeof *out);
    struct belay_manifest_reader *r;
    if (belay_manifest_open(manifest, &r) == -1) return -1;
    if (hdr != NULL) *hdr = *belay_manifest_header(r);
    static struct belay_entry e;
    int rc;
    while ((rc = belay_manifest_next(r, &e)) == 1) {
        if (!e.has_stored) continue;
        if (out->n == out->cap) {
            const size_t cap = out->cap ? 2 * out->cap : 1024;
            void *v = realloc(out->k, cap * sizeof *out->k);
            if (v == NULL) {
                belay_manifest_close(r);
                belay_err_set(BELAY_ERR_NOMEM, 0, "bundle: out of memory");
                return -1;
            }
            out->k = v;
            out->cap = cap;
        }
        memcpy(out->k[out->n++], e.stored_hex, 65);
    }
    belay_manifest_close(r);
    if (rc != 0) return -1;
    if (out->n > 1) qsort(out->k, out->n, sizeof *out->k, keycmp);
    size_t w = 0;
    for (size_t i = 0; i < out->n; i++)
        if (w == 0 || memcmp(out->k[w - 1], out->k[i], 64) != 0) memmove(out->k[w++], out->k[i], 65);
    out->n = w;
    return 0;
}

/* ---- writing ---- */

struct out { int fd; struct belay_sha256 h; const char *path; };

static int put(struct out *o, const void *b, size_t n) {
    belay_sha256_update(&o->h, b, n);
    const char *p = b;
    while (n > 0) {
        const ssize_t w = write(o->fd, p, n);
        if (w == -1 && errno == EINTR) continue;
        if (w == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "%s: cannot write", o->path);
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int put_line(struct out *o, struct jw *w) {
    if (w->oom || w->n > BUNDLE_LINE_MAX) {
        belay_err_set(w->oom ? BELAY_ERR_NOMEM : BELAY_ERR_RANGE, 0, "bundle: a header line does not fit");
        return -1;
    }
    jw_raw(w, "\n", 1);
    return w->oom ? -1 : put(o, w->b, w->n);
}

/* sha256 of the file at `path`, and its size. */
static int file_digest(const char *path, char hex[65], uint64_t *size) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot open", path);
        return -1;
    }
    struct belay_sha256 h;
    belay_sha256_init(&h);
    static unsigned char buf[1 << 16];
    uint64_t n = 0;
    for (;;) {
        const ssize_t r = read(fd, buf, sizeof buf);
        if (r == -1 && errno == EINTR) continue;
        if (r == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "%s: cannot read", path);
            close(fd);
            return -1;
        }
        if (r == 0) break;
        belay_sha256_update(&h, buf, (size_t)r);
        n += (uint64_t)r;
    }
    close(fd);
    hexdigest(&h, hex);
    *size = n;
    return 0;
}

static int put_file(struct out *o, const char *path, const char *want, uint64_t size) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot open", path);
        return -1;
    }
    struct belay_sha256 h;
    belay_sha256_init(&h);
    static unsigned char buf[1 << 16];
    uint64_t n = 0;
    int rc = 0;
    for (;;) {
        const ssize_t r = read(fd, buf, sizeof buf);
        if (r == -1 && errno == EINTR) continue;
        if (r == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "%s: cannot read", path);
            rc = -1;
            break;
        }
        if (r == 0) break;
        belay_sha256_update(&h, buf, (size_t)r);
        n += (uint64_t)r;
        if ((rc = put(o, buf, (size_t)r)) == -1) break;
    }
    close(fd);
    char got[65];
    hexdigest(&h, got);
    if (rc == 0 && (n != size || strcmp(got, want) != 0)) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s changed while it was bundled", path);
        rc = -1;
    }
    return rc;
}

static int package_lines(const struct pkg_list *l, struct jw *w) {
    for (size_t i = 0; i < l->n; i++) {
        const struct pkg_line *x = &l->v[i];
        if (!belay_utf8_valid(x->package, strlen(x->package)) || !belay_utf8_valid(x->version, strlen(x->version))) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "bundle: a package name or version that is not UTF-8 (%s)", x->path);
            return -1;
        }
        jw_fmt(w, "{\"db\":\"%s\",\"package\":", pkg_db_name(x->db));
        jw_str(w, x->package, strlen(x->package));
        jw_raw(w, ",\"version\":", 11);
        jw_str(w, x->version, strlen(x->version));
        jw_raw(w, ",", 1);
        jw_bytes(w, "path", x->path, x->path_len);
        if (x->conffile) jw_raw(w, ",\"conffile\":true", 16);
        jw_fmt(w, ",\"at_reset\":\"%s\"}\n", pkg_at_reset_name(x->at_reset));
    }
    if (w->oom) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "bundle: out of memory");
        return -1;
    }
    return 0;
}

int bundle_write(const char *out_path, const char *manifest, const char *store_dir,
                 const struct pkg_list *packages, const struct bundle_meta *m, char sha256[65]) {
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof tmp, "%s.tmp-XXXXXX", out_path) >= (int)sizeof tmp) {
        belay_err_set(BELAY_ERR_RANGE, 0, "%s: path too long", out_path);
        return -1;
    }
    struct out o = { .fd = mkostemp(tmp, O_CLOEXEC), .path = out_path };
    if (o.fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot create", tmp);
        return -1;
    }
    belay_sha256_init(&o.h);
    struct jw w = { 0 }, pk = { 0 };
    struct keys ks = { 0 };
    struct belay_content *c = NULL;
    unsigned char *buf = NULL;
    size_t members = 0;
    int rc = -1;

    jw_fmt(&w, "{\"belay_bundle\":1,\"size\":0,\"created_ns\":%lld,\"belay_version\":", (long long)m->created_ns);
    jw_str(&w, m->belay_version, strlen(m->belay_version));
    jw_raw(&w, ",", 1);
    if (belay_utf8_valid(m->scope, strlen(m->scope))) {
        jw_raw(&w, "\"scopes\":[", 10);
        jw_str(&w, m->scope, strlen(m->scope));
    } else {                                    /* as the manifest writes it: base64 */
        char b64[4 * ((sizeof m->scope + 2) / 3) + 1];
        if (belay_base64_encode(b64, sizeof b64, m->scope, strlen(m->scope)) == -1) goto out;
        jw_fmt(&w, "\"scopes_b64\":[\"%s\"", b64);
    }
    jw_fmt(&w, "],\"hash_max_bytes\":%llu,\"protect_sha256\":", (unsigned long long)m->hash_max_bytes);
    if (m->has_protect) jw_fmt(&w, "\"%s\"}", m->protect_sha256);
    else jw_raw(&w, "null}", 5);
    if (put_line(&o, &w) == -1) goto out;
    members++;

    char mh[65];
    uint64_t ms;
    if (file_digest(manifest, mh, &ms) == -1) goto out;
    jw_reset(&w);
    jw_fmt(&w, "{\"member\":\"manifest\",\"size\":%llu,\"sha256\":\"%s\"}", (unsigned long long)ms, mh);
    if (put_line(&o, &w) == -1 || put_file(&o, manifest, mh, ms) == -1) goto out;
    members++;

    if (manifest_keys(manifest, &ks, NULL) == -1) goto out;
    if (ks.n > 0 && belay_content_open(store_dir, &c) == -1) goto out;
    for (size_t i = 0; i < ks.n; i++) {
        size_t len;
        if (belay_content_get(c, ks.k[i], COPY_MAX, &buf, &len) == -1) goto out;
        jw_reset(&w);
        jw_fmt(&w, "{\"member\":\"copy\",\"size\":%zu,\"sha256\":\"%s\"}", len, ks.k[i]);
        if (put_line(&o, &w) == -1 || put(&o, buf, len) == -1) goto out;
        free(buf);
        buf = NULL;
        members++;
    }

    if (package_lines(packages, &pk) == -1) goto out;
    struct belay_sha256 ph;
    char phx[65];
    belay_sha256_init(&ph);
    belay_sha256_update(&ph, pk.b != NULL ? pk.b : "", pk.n);
    hexdigest(&ph, phx);
    jw_reset(&w);
    jw_fmt(&w, "{\"member\":\"packages\",\"size\":%zu,\"sha256\":\"%s\",\"outside_scope\":%llu}", pk.n, phx,
           (unsigned long long)packages->outside_scope);
    if (put_line(&o, &w) == -1 || put(&o, pk.b != NULL ? pk.b : "", pk.n) == -1) goto out;
    members++;

    jw_reset(&w);
    jw_fmt(&w, "{\"member\":\"end\",\"size\":0,\"members\":%zu}", members);
    if (put_line(&o, &w) == -1) goto out;
    if (fsync(o.fd) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot sync", tmp);
        goto out;
    }
    if (rename(tmp, out_path) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot rename into place", out_path);
        goto out;
    }
    hexdigest(&o.h, sha256);
    rc = 0;
out:
    free(buf);
    belay_content_close(c);
    free(ks.k);
    jw_free(&w);
    jw_free(&pk);
    close(o.fd);
    if (rc == -1) unlink(tmp);
    return rc;
}

/* ---- reading ---- */

struct in {
    int fd;
    unsigned char buf[1 << 16];
    size_t pos, len;
    uint64_t at;                        /* bytes consumed */
};

static int fill(struct in *r) {
    if (r->pos < r->len) return 1;
    for (;;) {
        const ssize_t n = read(r->fd, r->buf, sizeof r->buf);
        if (n == -1 && errno == EINTR) continue;
        if (n == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "bundle: cannot read");
            return -1;
        }
        r->pos = 0;
        r->len = (size_t)n;
        return n > 0;
    }
}

static int corrupt(const char *what, uint64_t at) {
    belay_err_set(BELAY_ERR_CORRUPT, 0, "bundle: %s (at byte %llu)", what, (unsigned long long)at);
    return -1;
}

/* A header line, its newline aside, into line (NUL-terminated). 1, 0 at the
 * end of the file, -1. */
static int read_line(struct in *r, char *line, size_t *n) {
    size_t k = 0;
    for (;;) {
        const int f = fill(r);
        if (f == -1) return -1;
        if (f == 0) {
            if (k == 0) return 0;
            return corrupt("a header line without its newline", r->at);
        }
        const unsigned char *nl = memchr(r->buf + r->pos, '\n', r->len - r->pos);
        const size_t take = nl != NULL ? (size_t)(nl - (r->buf + r->pos)) : r->len - r->pos;
        if (k + take > BUNDLE_LINE_MAX) return corrupt("a header line longer than 65,536 bytes", r->at);
        memcpy(line + k, r->buf + r->pos, take);
        k += take;
        r->pos += take + (nl != NULL);
        r->at += take + (nl != NULL);
        if (nl != NULL) {
            line[k] = '\0';
            *n = k;
            return 1;
        }
    }
}

typedef int (*sink_fn)(void *ctx, const unsigned char *b, size_t n);

/* Exactly `size` bytes of content, to `sink`, hashed. */
static int read_content(struct in *r, uint64_t size, sink_fn sink, void *ctx, char hex[65]) {
    struct belay_sha256 h;
    belay_sha256_init(&h);
    while (size > 0) {
        const int f = fill(r);
        if (f == -1) return -1;
        if (f == 0) return corrupt("a member shorter than its size", r->at);
        size_t take = r->len - r->pos;
        if (take > size) take = (size_t)size;
        belay_sha256_update(&h, r->buf + r->pos, take);
        if (sink(ctx, r->buf + r->pos, take) == -1) return -1;
        r->pos += take;
        r->at += take;
        size -= take;
    }
    hexdigest(&h, hex);
    return 0;
}

static int sink_fd(void *ctx, const unsigned char *b, size_t n) {
    const int fd = *(const int *)ctx;
    while (n > 0) {
        const ssize_t w = write(fd, b, n);
        if (w == -1 && errno == EINTR) continue;
        if (w == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "bundle: cannot write the manifest");
            return -1;
        }
        b += w;
        n -= (size_t)w;
    }
    return 0;
}

static int sink_tx(void *ctx, const unsigned char *b, size_t n) { return belay_store_write(ctx, b, n); }

struct membuf { unsigned char *b; size_t n; };
static int sink_mem(void *ctx, const unsigned char *b, size_t n) {
    struct membuf *m = ctx;
    memcpy(m->b + m->n, b, n);
    m->n += n;
    return 0;
}

/* The header line's object, its keys exactly `keys` in that order. */
static int header(const char *line, size_t n, const char *const *keys, struct jval *v, uint64_t at) {
    if (jsonr_parse(line, n, v) == -1 || v->t != J_OBJ) return corrupt("a header line that is not one JSON object", at);
    size_t k = 0;
    for (; keys[k] != NULL; k++) {
        const char *alt = strcmp(keys[k], "scopes") == 0 ? "scopes_b64" : NULL;
        if (k >= v->n || (strcmp(v->keys[k], keys[k]) != 0 && (alt == NULL || strcmp(v->keys[k], alt) != 0))) {
            jsonr_free(v);
            return corrupt("a header line whose keys are not its row's, in order", at);
        }
    }
    if (k != v->n) {
        jsonr_free(v);
        return corrupt("a header line with a key its row does not have", at);
    }
    return 0;
}

static bool uint_of(const struct jval *v, uint64_t *out) {
    if (v == NULL || v->t != J_NUM || !v->integer || v->i < 0) return false;
    *out = (uint64_t)v->i;
    return true;
}

static bool member_is(const struct jval *v, const char *name) {
    const struct jval *m = jget(v, "member");
    return m != NULL && m->t == J_STR && strcmp(m->s, name) == 0 && strlen(name) == m->s_len;
}

/* One package line (B-P1 to B-P6), in its keys' order. */
static int package_line(const char *l, size_t n, struct pkg_list *out, uint64_t at) {
    struct jval v;
    if (jsonr_parse(l, n, &v) == -1 || v.t != J_OBJ) return corrupt("a package line that is not one JSON object", at);
    size_t k = 0;
    int rc = -1;
    const struct jval *db = NULL, *pk = NULL, *ver = NULL, *path = NULL, *cf = NULL, *ar = NULL;
    bool b64 = false;
    if (k < v.n && strcmp(v.keys[k], "db") == 0) db = &v.kids[k++];
    if (k < v.n && strcmp(v.keys[k], "package") == 0) pk = &v.kids[k++];
    if (k < v.n && strcmp(v.keys[k], "version") == 0) ver = &v.kids[k++];
    if (k < v.n && (strcmp(v.keys[k], "path") == 0 || (b64 = strcmp(v.keys[k], "path_b64") == 0))) path = &v.kids[k++];
    if (k < v.n && strcmp(v.keys[k], "conffile") == 0) cf = &v.kids[k++];
    if (k < v.n && strcmp(v.keys[k], "at_reset") == 0) ar = &v.kids[k++];
    enum pkg_db d = PKG_DPKG;
    enum pkg_at_reset a = AT_UNSET;
    if (db == NULL || pk == NULL || ver == NULL || path == NULL || ar == NULL || k != v.n) goto bad;
    if (db->t != J_STR || pk->t != J_STR || ver->t != J_STR || path->t != J_STR || ar->t != J_STR) goto bad;
    if (strcmp(db->s, "pip") == 0) d = PKG_PIP;
    else if (strcmp(db->s, "dpkg") != 0) goto bad;
    if (cf != NULL && (cf->t != J_BOOL || !cf->b || d != PKG_DPKG)) goto bad;
    for (int i = AT_MATCH; i < AT_UNSET; i++)
        if (strcmp(ar->s, pkg_at_reset_name((enum pkg_at_reset)i)) == 0) a = (enum pkg_at_reset)i;
    if (a == AT_UNSET) goto bad;
    char p[4096 + 4];
    size_t pl = path->s_len;
    if (b64) {
        if (belay_base64_decode(p, sizeof p, &pl, path->s) == -1 || belay_utf8_valid(p, pl)) goto bad;
    } else {
        if (pl == 0 || pl >= sizeof p || memchr(path->s, '\0', pl) != NULL) goto bad;
        memcpy(p, path->s, pl);
    }
    if (pl == 0 || pl > 4095) goto bad;
    rc = pkgdb_add(out, d, pk->s, ver->s, p, pl, cf != NULL, a);
    jsonr_free(&v);
    return rc;
bad:
    jsonr_free(&v);
    return corrupt("a package line its rows do not allow", at);
}

static int pathcmp(const char *a, size_t al, const char *b, size_t bl) {
    const int c = memcmp(a, b, al < bl ? al : bl);
    return c != 0 ? c : (al > bl) - (al < bl);
}

static int packages_parse(const unsigned char *b, size_t n, struct pkg_list *out, uint64_t at) {
    size_t k = 0;
    while (k < n) {
        const unsigned char *nl = memchr(b + k, '\n', n - k);
        if (nl == NULL) return corrupt("a package line without its newline", at + k);
        const size_t e = (size_t)(nl - b);
        if (package_line((const char *)b + k, e - k, out, at + k) == -1) return -1;
        if (out->n > 1) {                       /* sorted by db, package, path; none repeated (B-6) */
            const struct pkg_line *p = &out->v[out->n - 2], *q = &out->v[out->n - 1];
            int c = p->db != q->db ? (p->db < q->db ? -1 : 1) : strcmp(p->package, q->package);
            if (c == 0) c = pathcmp(p->path, p->path_len, q->path, q->path_len);
            if (c > 0) return corrupt("package lines out of order", at + k);
            if (c == 0 && p->conffile == q->conffile) return corrupt("a package line repeated", at + k);
        }
        k = e + 1;
    }
    return 0;
}

/* Copies `path` to `dest` (created), hashing; 0 when the bytes hash to want. */
static int copy_checked(const char *path, const char *dest, const char *want) {
    const int in = open(path, O_RDONLY | O_CLOEXEC);
    if (in == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot open", path);
        return -1;
    }
    const int out = open(dest, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (out == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot create", dest);
        close(in);
        return -1;
    }
    struct belay_sha256 h;
    belay_sha256_init(&h);
    static unsigned char buf[1 << 16];
    int rc = 0;
    for (;;) {
        const ssize_t r = read(in, buf, sizeof buf);
        if (r == -1 && errno == EINTR) continue;
        if (r == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "%s: cannot read", path);
            rc = -1;
            break;
        }
        if (r == 0) break;
        belay_sha256_update(&h, buf, (size_t)r);
        if ((rc = sink_fd((void *)&out, buf, (size_t)r)) == -1) break;
    }
    close(in);
    if (close(out) == -1 && rc == 0) {
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot write", dest);
        rc = -1;
    }
    char got[65];
    hexdigest(&h, got);
    if (rc == 0 && strcmp(got, want) != 0) {
        belay_err_set(BELAY_ERR_INVALID, 0, "%s: its bytes are not the bundle given (sha256 %s, not %s)", path, got, want);
        rc = -1;
    }
    if (rc == -1) unlink(dest);
    return rc;
}

int bundle_read(const char *path, const char *want, const char *workdir, const char *manifest_out,
                const char *store_dir, struct bundle *out) {
    memset(out, 0, sizeof *out);
    if (want == NULL || !hex64(want, strlen(want))) {
        belay_err_set(BELAY_ERR_INVALID, 0, "the bundle's sha256 must be 64 lowercase hex digits");
        return -1;
    }
    char copy[PATH_MAX];
    if (snprintf(copy, sizeof copy, "%s/bundle", workdir) >= (int)sizeof copy) {
        belay_err_set(BELAY_ERR_RANGE, 0, "%s: path too long", workdir);
        return -1;
    }
    if (copy_checked(path, copy, want) == -1) return -1;

    static struct in r;
    memset(&r, 0, sizeof r);
    r.fd = open(copy, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (r.fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot open", copy);
        return -1;
    }
    static char line[BUNDLE_LINE_MAX + 1];
    size_t n;
    struct jval v = { 0 };
    struct belay_store *st = NULL;
    struct keys copies = { 0 }, named = { 0 };
    struct membuf pm = { 0 };
    int mfd = -1, rc = -1;
    size_t members = 0;
    uint64_t at = 0, size;
    char got[65];

    /* bundle (B-3) */
    static const char *const K_BUNDLE[] = { "belay_bundle", "size", "created_ns", "belay_version", "scopes",
                                            "hash_max_bytes", "protect_sha256", NULL };
    if (read_line(&r, line, &n) != 1) { if (belay_err_code() == 0) corrupt("empty", 0); goto out; }
    if (header(line, n, K_BUNDLE, &v, at) == -1) goto out;
    {
        const struct jval *ver = jget(&v, "belay_bundle"), *sz = jget(&v, "size"), *cr = jget(&v, "created_ns"),
                          *bv = jget(&v, "belay_version"), *sc = &v.kids[4], *hm = jget(&v, "hash_max_bytes"),
                          *ps = jget(&v, "protect_sha256");
        uint64_t one, zero, hmb, crn;
        if (!uint_of(ver, &one) || one != 1) { corrupt("not belay_bundle 1", at); goto out; }
        if (!uint_of(sz, &zero) || zero != 0 || !uint_of(cr, &crn) || bv->t != J_STR || !uint_of(hm, &hmb) ||
            sc->t != J_ARR || sc->n != 1 || sc->kids[0].t != J_STR ||
            sc->kids[0].s_len >= sizeof out->meta.scope || (ps->t != J_NULL && (ps->t != J_STR || !hex64(ps->s, ps->s_len)))) {
            corrupt("a bundle line its row does not allow", at);
            goto out;
        }
        if (strcmp(v.keys[4], "scopes_b64") == 0) {   /* not UTF-8: base64, as the manifest has it */
            size_t sl;
            if (belay_base64_decode(out->meta.scope, sizeof out->meta.scope - 1, &sl, sc->kids[0].s) == -1 ||
                memchr(out->meta.scope, '\0', sl) != NULL || belay_utf8_valid(out->meta.scope, sl)) {
                corrupt("a scope in base64 that is not one", at);
                goto out;
            }
            out->meta.scope[sl] = '\0';
        } else if (memchr(sc->kids[0].s, '\0', sc->kids[0].s_len) != NULL) {
            corrupt("a scope with a NUL in it", at);
            goto out;
        } else {
            snprintf(out->meta.scope, sizeof out->meta.scope, "%s", sc->kids[0].s);
        }
        out->meta.created_ns = (int64_t)crn;
        out->meta.hash_max_bytes = hmb;
        snprintf(out->meta.belay_version, sizeof out->meta.belay_version, "%s", bv->s);
        out->meta.has_protect = ps->t == J_STR;
        if (out->meta.has_protect) memcpy(out->meta.protect_sha256, ps->s, 65);
    }
    jsonr_free(&v);
    members++;
    at = r.at;

    /* manifest (B-4) */
    static const char *const K_MEMBER[] = { "member", "size", "sha256", NULL };
    if (read_line(&r, line, &n) != 1) { if (belay_err_code() == 0) corrupt("no manifest member", at); goto out; }
    if (header(line, n, K_MEMBER, &v, at) == -1) goto out;
    if (!member_is(&v, "manifest") || !uint_of(jget(&v, "size"), &size) || !hex64(jstr(&v, "sha256"), strlen(jstr(&v, "sha256")))) {
        corrupt("not a manifest member", at);
        goto out;
    }
    memcpy(out->manifest_sha256, jstr(&v, "sha256"), 65);
    jsonr_free(&v);
    if ((mfd = open(manifest_out, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot create", manifest_out);
        goto out;
    }
    if (read_content(&r, size, sink_fd, &mfd, got) == -1) goto out;
    if (strcmp(got, out->manifest_sha256) != 0) { corrupt("the manifest's bytes are not its sha256", at); goto out; }
    if (close(mfd) == -1) {
        mfd = -1;
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot write", manifest_out);
        goto out;
    }
    mfd = -1;
    members++;
    at = r.at;

    /* copies (B-5), then packages (B-6) */
    if (belay_store_open(store_dir, &st) == -1) goto out;
    static const char *const K_PACKAGES[] = { "member", "size", "sha256", "outside_scope", NULL };
    for (;;) {
        if (read_line(&r, line, &n) != 1) { if (belay_err_code() == 0) corrupt("no packages member", at); goto out; }
        if (jsonr_parse(line, n, &v) == -1 || v.t != J_OBJ) { corrupt("a header line that is not one JSON object", at); goto out; }
        const bool is_copy = member_is(&v, "copy");
        jsonr_free(&v);
        if (!is_copy) break;
        if (header(line, n, K_MEMBER, &v, at) == -1) goto out;
        const char *key = jstr(&v, "sha256");
        if (!uint_of(jget(&v, "size"), &size) || !hex64(key, strlen(key))) { corrupt("a copy line its row does not allow", at); goto out; }
        if (copies.n > 0 && memcmp(copies.k[copies.n - 1], key, 64) >= 0) { corrupt("copies not in ascending sha256 order", at); goto out; }
        if (copies.n == copies.cap) {
            const size_t cap = copies.cap ? 2 * copies.cap : 1024;
            void *p = realloc(copies.k, cap * sizeof *copies.k);
            if (p == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "bundle: out of memory"); goto out; }
            copies.k = p;
            copies.cap = cap;
        }
        memcpy(copies.k[copies.n++], key, 65);
        jsonr_free(&v);
        struct belay_store_tx tx;
        if (belay_store_begin(st, &tx) == -1) goto out;
        if (read_content(&r, size, sink_tx, &tx, got) == -1) { belay_store_abort(&tx); goto out; }
        if (strcmp(got, copies.k[copies.n - 1]) != 0) {
            belay_store_abort(&tx);
            corrupt("a copy whose bytes do not hash to its key", at);
            goto out;
        }
        if (belay_store_commit(&tx, got) == -1) goto out;
        members++;
        at = r.at;
    }
    if (header(line, n, K_PACKAGES, &v, at) == -1) goto out;
    {
        char want_p[65];
        uint64_t os;
        if (!member_is(&v, "packages") || !uint_of(jget(&v, "size"), &size) || size > PACKAGES_MAX ||
            !uint_of(jget(&v, "outside_scope"), &os) || !hex64(jstr(&v, "sha256"), strlen(jstr(&v, "sha256")))) {
            corrupt("not a packages member", at);
            goto out;
        }
        memcpy(want_p, jstr(&v, "sha256"), 65);
        jsonr_free(&v);
        if ((pm.b = malloc(size ? size : 1)) == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "bundle: out of memory"); goto out; }
        if (read_content(&r, size, sink_mem, &pm, got) == -1) goto out;
        if (strcmp(got, want_p) != 0) { corrupt("the package lines' bytes are not their sha256", at); goto out; }
        if (packages_parse(pm.b, pm.n, &out->packages, r.at - size) == -1) goto out;
        out->packages.outside_scope = os;
    }
    members++;
    at = r.at;

    /* end (B-7), then nothing */
    static const char *const K_END[] = { "member", "size", "members", NULL };
    if (read_line(&r, line, &n) != 1) { if (belay_err_code() == 0) corrupt("no end member", at); goto out; }
    if (header(line, n, K_END, &v, at) == -1) goto out;
    {
        uint64_t zero, m;
        if (!member_is(&v, "end") || !uint_of(jget(&v, "size"), &zero) || zero != 0 || !uint_of(jget(&v, "members"), &m) || m != members) {
            corrupt("an end line its row does not allow", at);
            goto out;
        }
    }
    jsonr_free(&v);
    {
        const int f = fill(&r);
        if (f == -1) goto out;
        if (f == 1) { corrupt("bytes after the end member", r.at); goto out; }
    }

    /* the manifest: one a strict reader reads, of this scope and limit,
     * naming exactly the copies held (B-R3) */
    struct belay_manifest_header mh;
    if (manifest_keys(manifest_out, &named, &mh) == -1) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "bundle: its manifest is not one a reader accepts: %s", belay_err_msg());
        goto out;
    }
    if (strcmp(mh.scope, out->meta.scope) != 0 || mh.hash_max_bytes != out->meta.hash_max_bytes) {
        corrupt("its manifest is of another scope or hash limit than its bundle line says", 0);
        goto out;
    }
    if (named.n != copies.n || (named.n > 0 && memcmp(named.k, copies.k, named.n * sizeof *named.k) != 0)) {
        corrupt("the copies are not exactly those its manifest names", 0);
        goto out;
    }
    if (belay_store_sync(st) == -1) goto out;
    rc = 0;
out:
    jsonr_free(&v);
    if (mfd != -1) close(mfd);
    close(r.fd);
    belay_store_close(st);
    free(copies.k);
    free(named.k);
    free(pm.b);
    if (rc == -1) pkgdb_free(&out->packages);
    return rc;
}

void bundle_free(struct bundle *b) {
    if (b != NULL) pkgdb_free(&b->packages);
}
