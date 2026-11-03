#define _GNU_SOURCE
#include "policy/pkgdb.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "belay/error.h"
#include "belay/hash.h"
#include "belay/interp.h"
#include "belay/json.h"
#include "belay/manifest.h"
#include "interp/record_csv.h"
#include "interp/stanza.h"

const char *pkg_at_reset_name(enum pkg_at_reset a) {
    static const char *const N[] = { "match", "mismatch", "missing", "not_a_file", "unverified", "no_hash", "" };
    return N[a];
}

const char *pkg_db_name(enum pkg_db d) { return d == PKG_DPKG ? "dpkg" : "pip"; }

/* The last `c` in the first n bytes of p, or NULL (memrchr, which macOS
 * lacks). */
static const char *last_of(const char *p, int c, size_t n) {
    while (n > 0)
        if (p[--n] == (char)c) return p + n;
    return NULL;
}

static char *dupn(const char *s, size_t n) {
    char *c = malloc(n + 1);
    if (c != NULL) {
        if (n) memcpy(c, s, n);
        c[n] = '\0';
    }
    return c;
}

int pkgdb_add(struct pkg_list *l, enum pkg_db db, const char *package, const char *version,
              const char *path, size_t path_len, bool conffile, enum pkg_at_reset at) {
    if (l->n == l->cap) {
        const size_t cap = l->cap ? 2 * l->cap : 256;
        struct pkg_line *v = realloc(l->v, cap * sizeof *v);
        if (v == NULL) goto nomem;
        l->v = v;
        l->cap = cap;
    }
    struct pkg_line *x = &l->v[l->n];
    memset(x, 0, sizeof *x);
    x->db = db;
    x->conffile = conffile;
    x->at_reset = at;
    x->package = dupn(package, strlen(package));
    x->version = dupn(version, strlen(version));
    x->path = dupn(path, path_len);
    x->path_len = path_len;
    if (x->package == NULL || x->version == NULL || x->path == NULL) {
        free(x->package);
        free(x->version);
        free(x->path);
        goto nomem;
    }
    l->n++;
    return 0;
nomem:
    belay_err_set(BELAY_ERR_NOMEM, 0, "package lines: out of memory");
    return -1;
}

void pkgdb_free(struct pkg_list *l) {
    if (l == NULL) return;
    for (size_t i = 0; i < l->n; i++) {
        free(l->v[i].package);
        free(l->v[i].version);
        free(l->v[i].path);
    }
    free(l->v);
    memset(l, 0, sizeof *l);
}

static int pathcmp(const char *a, size_t al, const char *b, size_t bl) {
    const int c = memcmp(a, b, al < bl ? al : bl);
    return c != 0 ? c : (al > bl) - (al < bl);
}

static int by_db_package_path(const void *x, const void *y) {
    const struct pkg_line *a = x, *b = y;
    if (a->db != b->db) return a->db < b->db ? -1 : 1;
    const int c = strcmp(a->package, b->package);
    return c != 0 ? c : pathcmp(a->path, a->path_len, b->path, b->path_len);
}

void pkgdb_sort(struct pkg_list *l) {
    if (l->n > 1) qsort(l->v, l->n, sizeof *l->v, by_db_package_path);
}

/* ---- what the manifest holds: the databases and their stored copies ---- */

struct dbfile {
    char *path;                 /* relative to the scope */
    size_t path_len;
    char stored[65];            /* "" when the manifest kept no copy */
};

struct found {
    struct dbfile *f;
    size_t n, cap;
    char scope[4096];
};

static bool ends_with(const char *p, size_t n, const char *suf) {
    const size_t l = strlen(suf);
    return n >= l && memcmp(p + n - l, suf, l) == 0 && (n == l || p[n - l - 1] == '/');
}

/* The files pkgdb reads: dpkg's status and md5sums, pip's RECORDs. */
static bool wanted(const char *p, size_t n) {
    if (ends_with(p, n, "var/lib/dpkg/status")) return true;
    if (n > 17 && memcmp(p + n - 17, ".dist-info/RECORD", 17) == 0) return true;
    if (n > 8 && memcmp(p + n - 8, ".md5sums", 8) == 0) {
        const char *sl = last_of(p, '/', n);
        const size_t d = sl != NULL ? (size_t)(sl - p) : 0;
        return sl != NULL && ends_with(p, d, "var/lib/dpkg/info");
    }
    return false;
}

static int collect(const char *manifest, struct found *fd) {
    struct belay_manifest_reader *r;
    if (belay_manifest_open(manifest, &r) == -1) return -1;
    snprintf(fd->scope, sizeof fd->scope, "%s", belay_manifest_header(r)->scope);
    static struct belay_entry e;
    int rc;
    while ((rc = belay_manifest_next(r, &e)) == 1) {
        if (e.type != BELAY_T_REG || !wanted(e.path, e.path_len)) continue;
        if (fd->n == fd->cap) {
            const size_t cap = fd->cap ? 2 * fd->cap : 64;
            struct dbfile *v = realloc(fd->f, cap * sizeof *v);
            if (v == NULL) {
                belay_manifest_close(r);
                belay_err_set(BELAY_ERR_NOMEM, 0, "package databases: out of memory");
                return -1;
            }
            fd->f = v;
            fd->cap = cap;
        }
        struct dbfile *x = &fd->f[fd->n];
        if ((x->path = dupn(e.path, e.path_len)) == NULL) {
            belay_manifest_close(r);
            belay_err_set(BELAY_ERR_NOMEM, 0, "package databases: out of memory");
            return -1;
        }
        x->path_len = e.path_len;
        snprintf(x->stored, sizeof x->stored, "%s", e.has_stored ? e.stored_hex : "");
        fd->n++;
    }
    belay_manifest_close(r);
    return rc == 0 ? 0 : -1;
}

static void found_free(struct found *fd) {
    for (size_t i = 0; i < fd->n; i++) free(fd->f[i].path);
    free(fd->f);
}

static int copy_of(const struct belay_content *c, const struct dbfile *f, unsigned char **buf, size_t *len) {
    if (f->stored[0] == '\0') {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%.*s: no stored copy (a writer held it open?): capture again",
                      (int)f->path_len, f->path);
        return -1;
    }
    return belay_content_get(c, f->stored, PKGDB_COPY_MAX, buf, len);
}

/* `root` (n bytes, "" or ending in '/') + `rel` (m bytes), lexically: "."
 * and "" components dropped, ".." taking one back; false when it climbs out
 * of the scope or the result is too long. */
static bool join(const char *root, size_t n, const char *rel, size_t m, char *out, size_t cap, size_t *outn) {
    if (n + m + 1 > cap) return false;
    memcpy(out, root, n);
    size_t o = n, i = 0;
    while (o > 0 && out[o - 1] == '/') o--;      /* no trailing '/' while joining */
    while (i < m) {
        const char *sl = memchr(rel + i, '/', m - i);
        const size_t e = sl != NULL ? (size_t)(sl - rel) : m;
        const size_t l = e - i;
        if (l == 0 || (l == 1 && rel[i] == '.')) {
            /* nothing */
        } else if (l == 2 && rel[i] == '.' && rel[i + 1] == '.') {
            if (o == 0) return false;
            const char *b = last_of(out, '/', o);
            o = b != NULL ? (size_t)(b - out) : 0;
        } else {
            if (o > 0) out[o++] = '/';
            memcpy(out + o, rel + i, l);
            o += l;
        }
        i = e + 1;
    }
    if (o == 0) return false;
    out[o] = '\0';
    *outn = o;
    return true;
}

static bool hexn(const char *s, size_t n, size_t want) {
    if (n != want) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

/* ---- dpkg ---- */

struct stz { char *package, *arch, *version, *conffiles; size_t conffiles_len; };
struct stzs { struct stz *v; size_t n, cap; };

static int stz_add(const struct stanza_pkg *p, void *ctx) {
    struct stzs *s = ctx;
    if (s->n == s->cap) {
        const size_t cap = s->cap ? 2 * s->cap : 256;
        struct stz *v = realloc(s->v, cap * sizeof *v);
        if (v == NULL) return -1;
        s->v = v;
        s->cap = cap;
    }
    struct stz *x = &s->v[s->n];
    x->package = dupn(p->package, p->package_len);
    x->arch = dupn(p->arch != NULL ? p->arch : "", p->arch != NULL ? p->arch_len : 0);
    x->version = dupn(p->version != NULL ? p->version : "", p->version != NULL ? p->version_len : 0);
    x->conffiles = dupn(p->conffiles != NULL ? p->conffiles : "", p->conffiles != NULL ? p->conffiles_len : 0);
    x->conffiles_len = p->conffiles != NULL ? p->conffiles_len : 0;
    s->n++;
    if (x->package == NULL || x->arch == NULL || x->version == NULL || x->conffiles == NULL) return -1;
    return 0;
}

static void stzs_free(struct stzs *s) {
    for (size_t i = 0; i < s->n; i++) {
        free(s->v[i].package);
        free(s->v[i].arch);
        free(s->v[i].version);
        free(s->v[i].conffiles);
    }
    free(s->v);
}

/* The stanza a `<name>[:<arch>].md5sums` file belongs to, or NULL. */
static const struct stz *stanza_of(const struct stzs *s, const char *name, size_t n) {
    const char *colon = memchr(name, ':', n);
    const size_t pl = colon != NULL ? (size_t)(colon - name) : n;
    for (size_t i = 0; i < s->n; i++) {
        if (strlen(s->v[i].package) != pl || memcmp(s->v[i].package, name, pl) != 0) continue;
        if (colon == NULL || (strlen(s->v[i].arch) == n - pl - 1 && memcmp(s->v[i].arch, colon + 1, n - pl - 1) == 0))
            return &s->v[i];
    }
    return NULL;
}

/* A root's lines: its md5sums files and its status's Conffiles. */
static int dpkg_root(const struct belay_content *c, const struct found *fd, const struct dbfile *status,
                     struct pkg_list *out) {
    const size_t rl = status->path_len - strlen("var/lib/dpkg/status");   /* "" or ".../" */
    unsigned char *buf;
    size_t len;
    if (copy_of(c, status, &buf, &len) == -1) return -1;
    struct stzs s = { 0 };
    if (stanza_each((const char *)buf, len, stz_add, &s) != 0) {
        if (belay_err_code() == 0) belay_err_set(BELAY_ERR_NOMEM, 0, "dpkg status: out of memory");
        free(buf);
        stzs_free(&s);
        return -1;
    }
    free(buf);
    int rc = 0;
    char path[4096 + 64], pkg[1024];
    size_t pn;
    /* md5sums: "<32 hex>  <path below the root>" a line */
    for (size_t i = 0; i < fd->n && rc == 0; i++) {
        const struct dbfile *f = &fd->f[i];
        static const char INFO[] = "var/lib/dpkg/info/";
        if (f->path_len <= rl + sizeof INFO - 1 + 8 || memcmp(f->path, status->path, rl) != 0 ||
            memcmp(f->path + rl, INFO, sizeof INFO - 1) != 0 || memcmp(f->path + f->path_len - 8, ".md5sums", 8) != 0)
            continue;
        const char *name = f->path + rl + sizeof INFO - 1;
        const size_t nl = f->path_len - rl - (sizeof INFO - 1) - 8;
        if (memchr(name, '/', nl) != NULL) continue;
        const struct stz *z = stanza_of(&s, name, nl);
        if (z != NULL) snprintf(pkg, sizeof pkg, "%s:%s", z->package, z->arch);
        else snprintf(pkg, sizeof pkg, "%.*s", (int)nl, name);
        if (copy_of(c, f, &buf, &len) == -1) { rc = -1; break; }
        size_t k = 0;
        while (k < len && rc == 0) {
            const unsigned char *nlp = memchr(buf + k, '\n', len - k);
            const size_t e = nlp != NULL ? (size_t)(nlp - buf) : len;
            const char *l = (const char *)buf + k;
            const size_t ll = e - k;
            k = e + 1;
            if (ll == 0) continue;
            if (ll < 35 || !hexn(l, 32, 32) || l[32] != ' ' || l[33] != ' ') {
                belay_err_set(BELAY_ERR_CORRUPT, 0, "%.*s: a line is not \"<md5>  <path>\"", (int)f->path_len, f->path);
                rc = -1;
                break;
            }
            if (!join(status->path, rl, l + 34, ll - 34, path, sizeof path, &pn)) {
                out->outside_scope++;
                continue;
            }
            if (pkgdb_add(out, PKG_DPKG, pkg, z != NULL ? z->version : "", path, pn, false, AT_UNSET) == -1) {
                rc = -1;
                break;
            }
            memcpy(out->v[out->n - 1].expected, l, 32);
            out->v[out->n - 1].expected[32] = '\0';
        }
        free(buf);
    }
    /* Conffiles: " /etc/x <md5>[ obsolete]" a line; "newconffile" is no hash */
    for (size_t i = 0; i < s.n && rc == 0; i++) {
        const char *b = s.v[i].conffiles;
        const size_t bl = s.v[i].conffiles_len;
        snprintf(pkg, sizeof pkg, "%s:%s", s.v[i].package, s.v[i].arch);
        size_t k = 0;
        while (k < bl && rc == 0) {
            const char *nlp = memchr(b + k, '\n', bl - k);
            const size_t e = nlp != NULL ? (size_t)(nlp - b) : bl;
            const char *l = b + k;
            size_t ll = e - k;
            k = e + 1;
            while (ll > 0 && (l[0] == ' ' || l[0] == '\t')) l++, ll--;
            while (ll > 0 && (l[ll - 1] == ' ' || l[ll - 1] == '\r')) ll--;
            if (ll == 0) continue;
            const char *sp = memchr(l, ' ', ll);
            if (sp == NULL || l[0] != '/') continue;      /* not a conffile line: nothing to check */
            const size_t plen = (size_t)(sp - l);
            const char *h = sp + 1;
            const char *he = memchr(h, ' ', ll - plen - 1);
            const size_t hl = he != NULL ? (size_t)(he - h) : ll - plen - 1;
            if (!join(status->path, rl, l + 1, plen - 1, path, sizeof path, &pn)) {
                out->outside_scope++;
                continue;
            }
            if (pkgdb_add(out, PKG_DPKG, pkg, s.v[i].version, path, pn, true, AT_UNSET) == -1) { rc = -1; break; }
            if (hexn(h, hl, 32)) {
                memcpy(out->v[out->n - 1].expected, h, 32);
                out->v[out->n - 1].expected[32] = '\0';
            }
        }
    }
    stzs_free(&s);
    return rc;
}

/* ---- pip ---- */

/* urlsafe base64 without padding, of 32 bytes, as lowercase hex. */
static bool b64url_sha256(const char *s, size_t n, char hex[65]) {
    char b[64];
    if (n != 43) return false;
    for (size_t i = 0; i < n; i++) b[i] = s[i] == '-' ? '+' : s[i] == '_' ? '/' : s[i];
    b[43] = '=';
    b[44] = '\0';
    uint8_t d[48];
    size_t dl;
    if (belay_base64_decode(d, sizeof d, &dl, b) == -1 || dl != 32) return false;
    belay_hex_encode(hex, d, 32);
    return true;
}

struct rec_ctx {
    struct pkg_list *out;
    const char *parent, *name, *version, *scope;
    size_t parent_len;
    int rc;
};

static int rec_row(const struct record_row *r, void *ctx) {
    struct rec_ctx *x = ctx;
    char path[4096 + 64];
    size_t pn;
    bool in;
    if (r->path_len > 0 && r->path[0] == '/') {    /* absolute: below the scope's own path, or outside */
        const size_t sl = strlen(x->scope);
        const bool root = sl == 1;                  /* the scope is "/" */
        in = root ? join("", 0, r->path + 1, r->path_len - 1, path, sizeof path, &pn)
                  : r->path_len > sl + 1 && memcmp(r->path, x->scope, sl) == 0 && r->path[sl] == '/' &&
                    join("", 0, r->path + sl + 1, r->path_len - sl - 1, path, sizeof path, &pn);
    } else {
        in = join(x->parent, x->parent_len, r->path, r->path_len, path, sizeof path, &pn);
    }
    if (!in) {
        x->out->outside_scope++;
        return 0;
    }
    if (pkgdb_add(x->out, PKG_PIP, x->name, x->version, path, pn, false, AT_UNSET) == -1) return -1;
    if (r->hash_len > 7 && memcmp(r->hash, "sha256=", 7) == 0)
        (void)b64url_sha256(r->hash + 7, r->hash_len - 7, x->out->v[x->out->n - 1].expected);
    return 0;
}

static int pip_record(const struct belay_content *c, const struct dbfile *f, const char *scope, struct pkg_list *out) {
    /* <parent>/<name>-<version>.dist-info/RECORD */
    const size_t dl = f->path_len - strlen("/RECORD");
    const char *slash = last_of(f->path, '/', dl);
    const size_t ps = slash != NULL ? (size_t)(slash - f->path) + 1 : 0;   /* the parent, '/' kept */
    const char *dist = f->path + ps;
    const size_t distl = dl - ps - strlen(".dist-info");
    const char *dash = memchr(dist, '-', distl);
    char name[1024], version[1024];
    snprintf(name, sizeof name, "%.*s", (int)(dash != NULL ? (size_t)(dash - dist) : distl), dist);
    snprintf(version, sizeof version, "%.*s", dash != NULL ? (int)(distl - (size_t)(dash - dist) - 1) : 0,
             dash != NULL ? dash + 1 : "");
    unsigned char *buf;
    size_t len;
    if (copy_of(c, f, &buf, &len) == -1) return -1;
    struct rec_ctx x = { out, f->path, name, version, scope, ps, 0 };
    const int r = record_each((const char *)buf, len, rec_row, &x);
    free(buf);
    if (r != 0 && belay_err_code() == 0) belay_err_set(BELAY_ERR_NOMEM, 0, "pip RECORD: out of memory");
    return r == 0 ? 0 : -1;
}

int pkgdb_list(const char *manifest, const char *store_dir, struct pkg_list *out) {
    memset(out, 0, sizeof *out);
    struct found fd = { 0 };
    struct belay_content *c = NULL;
    int rc = collect(manifest, &fd);
    if (rc == 0 && fd.n > 0) rc = belay_content_open(store_dir, &c);
    for (size_t i = 0; i < fd.n && rc == 0; i++) {
        const struct dbfile *f = &fd.f[i];
        if (ends_with(f->path, f->path_len, "var/lib/dpkg/status")) rc = dpkg_root(c, &fd, f, out);
        else if (f->path_len > 7 && memcmp(f->path + f->path_len - 7, "/RECORD", 7) == 0)
            rc = pip_record(c, f, fd.scope, out);
    }
    belay_content_close(c);
    found_free(&fd);
    if (rc == -1) {
        pkgdb_free(out);
        return -1;
    }
    pkgdb_sort(out);
    return 0;
}

/* ---- at reset ---- */

/* The file at `rel` below `rootfd`, opened without following a symlink at
 * any component. An fd, or -1 with errno. */
static int open_below(int rootfd, const char *rel, size_t n) {
    char comp[4096];
    int dfd = dup(rootfd);
    size_t i = 0;
    while (dfd != -1) {
        const char *sl = memchr(rel + i, '/', n - i);
        const size_t e = sl != NULL ? (size_t)(sl - rel) : n;
        if (e - i >= sizeof comp) {
            close(dfd);
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(comp, rel + i, e - i);
        comp[e - i] = '\0';
        const int fd = openat(dfd, comp, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (sl != NULL ? O_DIRECTORY : 0));
        const int saved = errno;
        close(dfd);
        errno = saved;
        if (sl == NULL) return fd;
        dfd = fd;
        i = e + 1;
    }
    return -1;
}

/* MD5 and sha256 of the file, in one read. 0, or -1 with errno. */
static int hash_both(int rootfd, const char *rel, size_t n, char md5[33], char sha[65]) {
    const int fd = open_below(rootfd, rel, n);
    if (fd == -1) return -1;
    struct stat st;
    if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    struct belay_md5 m;
    struct belay_sha256 s;
    belay_md5_init(&m);
    belay_sha256_init(&s);
    static unsigned char buf[1 << 16];
    for (;;) {
        const ssize_t r = read(fd, buf, sizeof buf);
        if (r == -1 && errno == EINTR) continue;
        if (r == -1) {
            const int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        if (r == 0) break;
        belay_md5_update(&m, buf, (size_t)r);
        belay_sha256_update(&s, buf, (size_t)r);
    }
    close(fd);
    uint8_t d[32];
    belay_md5_final(&m, d);
    belay_hex_encode(md5, d, 16);
    belay_sha256_final(&s, d);
    belay_hex_encode(sha, d, 32);
    return 0;
}

static int line_at(const struct belay_entry *e, struct pkg_line *x, int rootfd) {
    if (e->type != BELAY_T_REG) { x->at_reset = AT_NOT_A_FILE; return 0; }
    if (x->expected[0] == '\0') { x->at_reset = AT_NO_HASH; return 0; }
    if (!e->has_hash) { x->at_reset = AT_UNVERIFIED; return 0; }
    if (x->db == PKG_PIP) {
        x->at_reset = strcmp(x->expected, e->sha256_hex) == 0 ? AT_MATCH : AT_MISMATCH;
        return 0;
    }
    char md5[33], sha[65];
    if (hash_both(rootfd, x->path, x->path_len, md5, sha) == -1 || strcmp(sha, e->sha256_hex) != 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s: not the bytes the capture recorded (it changed during the export): "
                      "export again", x->path);
        return -1;
    }
    x->at_reset = strcmp(md5, x->expected) == 0 ? AT_MATCH : AT_MISMATCH;
    return 0;
}

static const struct pkg_list *g_sort;
static int by_path(const void *a, const void *b) {
    const struct pkg_line *x = &g_sort->v[*(const size_t *)a], *y = &g_sort->v[*(const size_t *)b];
    return pathcmp(x->path, x->path_len, y->path, y->path_len);
}

int pkgdb_check(const char *manifest, const char *scope, struct pkg_list *l) {
    if (l->n == 0) return 0;
    size_t *ix = malloc(l->n * sizeof *ix);
    if (ix == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "package lines: out of memory");
        return -1;
    }
    for (size_t i = 0; i < l->n; i++) ix[i] = i;
    g_sort = l;
    qsort(ix, l->n, sizeof *ix, by_path);
    const int rootfd = open(scope, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct belay_manifest_reader *r = NULL;
    if (rootfd == -1) belay_err_set(BELAY_ERR_IO, errno, "%s: cannot open", scope);
    int rc = rootfd == -1 ? -1 : belay_manifest_open(manifest, &r);
    static struct belay_entry e;
    size_t k = 0;
    while (rc == 0 && k < l->n) {
        const int nr = belay_manifest_next(r, &e);
        if (nr == -1) { rc = -1; break; }
        if (nr == 0) break;
        while (k < l->n && pathcmp(l->v[ix[k]].path, l->v[ix[k]].path_len, e.path, e.path_len) < 0)
            l->v[ix[k++]].at_reset = AT_MISSING;
        while (rc == 0 && k < l->n && pathcmp(l->v[ix[k]].path, l->v[ix[k]].path_len, e.path, e.path_len) == 0)
            rc = line_at(&e, &l->v[ix[k++]], rootfd);
    }
    while (rc == 0 && k < l->n) l->v[ix[k++]].at_reset = AT_MISSING;
    belay_manifest_close(r);
    if (rootfd != -1) close(rootfd);
    free(ix);
    return rc;
}
