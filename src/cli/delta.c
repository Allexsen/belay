/*
 *  See delta.h. A rebuild never copies a manifest per delta: lines are
 *  pointers into the buffers read, a delta rearranges pointers, and the bytes
 *  are written and hashed once, at the end. So the cost of a long chain is
 *  reading its small files.
 */
#define _GNU_SOURCE

#include "delta.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "belay/error.h"
#include "belay/hash.h"
#include "util/jsonr.h"

struct line { const char *p; size_t n; };
struct buf { char *p; size_t n; };

struct header {
    long base, chain;
    uint64_t size;
    char sha[65], base_sha[65];
    size_t body;                /* where the operations start */
};

static void hash_hex(const char *p, size_t n, char out[65]) {
    struct belay_sha256 c;
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_init(&c);
    belay_sha256_update(&c, p, n);
    belay_sha256_final(&c, d);
    belay_hex_encode(out, d, sizeof d);
}

/* checkpoints/<id>/<name>, whole, never through a link. 1; 0 when it isn't
 * there; -1 with belay_err. */
static int read_file(const struct state *st, long id, const char *name, struct buf *b) {
    char rel[64];
    snprintf(rel, sizeof rel, "%ld/%s", id, name);
    const int fd = openat(st->cp_fd, rel, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        if (errno == ENOENT) return 0;
        belay_err_set(BELAY_ERR_CORRUPT, errno, "%s/checkpoints/%s is not a file belay wrote", st->dir, rel);
        return -1;
    }
    struct stat s;
    if (fstat(fd, &s) == -1 || !S_ISREG(s.st_mode)) {
        close(fd);
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints/%s is not a file belay wrote", st->dir, rel);
        return -1;
    }
    b->n = (size_t)s.st_size;
    b->p = malloc(b->n + 1);
    if (b->p == NULL) {
        close(fd);
        belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        return -1;
    }
    size_t got = 0;
    while (got < b->n) {
        const ssize_t k = read(fd, b->p + got, b->n - got);
        if (k == -1 && errno == EINTR) continue;
        if (k <= 0) break;
        got += (size_t)k;
    }
    close(fd);
    if (got != b->n) {
        free(b->p);
        b->p = NULL;
        belay_err_set(BELAY_ERR_IO, errno, "cannot read %s/checkpoints/%s", st->dir, rel);
        return -1;
    }
    b->p[b->n] = '\0';
    return 1;
}

static int parse_header(const struct state *st, long id, const struct buf *b, struct header *h) {
    const char *nl = memchr(b->p, '\n', b->n);
    struct jval v;
    if (nl == NULL || jsonr_parse(b->p, (size_t)(nl - b->p), &v) == -1 || v.t != J_OBJ) {
        if (nl != NULL && v.t != J_OBJ) jsonr_free(&v);
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints/%ld/manifest.delta is not a delta belay wrote", st->dir, id);
        return -1;
    }
    h->base = (long)jint(&v, "base", 0);
    h->chain = (long)jint(&v, "chain", 0);
    h->size = (uint64_t)jint(&v, "size", -1);
    snprintf(h->sha, sizeof h->sha, "%s", jstr(&v, "sha256"));
    snprintf(h->base_sha, sizeof h->base_sha, "%s", jstr(&v, "base_sha256"));
    const bool ok = jint(&v, "belay_delta", 0) == 1 && h->base > 0 && h->base < id && strlen(h->sha) == 64;
    jsonr_free(&v);
    if (!ok) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints/%ld/manifest.delta is not a delta belay wrote", st->dir, id);
        return -1;
    }
    h->body = (size_t)(nl - b->p) + 1;
    return 0;
}

/* `b` split into lines, each with its newline: none is lost, so joining them
 * is the file again. */
static struct line *split(const char *p, size_t n, size_t *count) {
    size_t lines = 0;
    for (const char *c = p, *e = p + n; c < e; lines++) {
        const char *nl = memchr(c, '\n', (size_t)(e - c));
        c = nl == NULL ? e : nl + 1;
    }
    struct line *out = malloc((lines ? lines : 1) * sizeof *out);
    if (out == NULL) return NULL;
    size_t i = 0;
    for (const char *c = p, *e = p + n; c < e; i++) {
        const char *nl = memchr(c, '\n', (size_t)(e - c));
        const char *end = nl == NULL ? e : nl + 1;
        out[i].p = c;
        out[i].n = (size_t)(end - c);
        c = end;
    }
    *count = lines;
    return out;
}

/* One delta over `in`: a new array, the lines still in their buffers. */
static struct line *apply(const struct line *in, size_t n_in, const char *ops, size_t n_ops, size_t hint, size_t *n_out) {
    size_t cap = hint + 16, out_n = 0, j = 0;
    struct line *out = malloc(cap * sizeof *out);
    if (out == NULL) return NULL;
    for (const char *c = ops, *e = ops + n_ops; c < e;) {
        const char *nl = memchr(c, '\n', (size_t)(e - c));
        const char op = *c;
        if (nl == NULL) goto bad;
        if (op == '=' || op == '-') {
            char *end;
            const unsigned long k = strtoul(c + 1, &end, 10);
            if (end != nl || k > n_in - j) goto bad;
            if (op == '=') {
                if (out_n + k > cap) {
                    cap = (out_n + k) * 2;
                    struct line *q = realloc(out, cap * sizeof *out);
                    if (q == NULL) goto bad;
                    out = q;
                }
                memcpy(out + out_n, in + j, k * sizeof *out);
                out_n += k;
            }
            j += k;
        } else if (op == '+') {
            if (out_n == cap) {
                cap *= 2;
                struct line *q = realloc(out, cap * sizeof *out);
                if (q == NULL) goto bad;
                out = q;
            }
            out[out_n].p = c + 1;
            out[out_n].n = (size_t)(nl + 1 - (c + 1));
            out_n++;
        } else {
            goto bad;
        }
        c = nl + 1;
    }
    *n_out = out_n;
    return out;
bad:
    free(out);
    return NULL;
}

/* Checkpoint `id`'s manifest as lines, every buffer they point into in
 * *bufs. The bytes aren't checked here: rebuild() does, whole. */
static int chain_lines(const struct state *st, long id, struct line **lines, size_t *n, struct buf **bufs, size_t *n_bufs,
                       struct header *top) {
    size_t cap = 16;
    struct buf *b = malloc(cap * sizeof *b);
    if (b == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory"); return -1; }
    struct header *hs = malloc(cap * sizeof *hs);
    if (hs == NULL) { free(b); belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory"); return -1; }
    size_t depth = 0, held = 0;
    long cur = id;
    int rc = -1;
    for (;;) {
        if (depth == cap) {
            cap *= 2;
            struct buf *q = realloc(b, cap * sizeof *b);
            struct header *r = q == NULL ? NULL : realloc(hs, cap * sizeof *hs);
            if (q != NULL) b = q;
            if (r == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory"); goto out; }
            hs = r;
        }
        const int whole = read_file(st, cur, "manifest.ndjson", &b[depth]);
        if (whole == -1) goto out;
        if (whole == 1) {
            held = depth + 1;
            break;
        }
        const int d = read_file(st, cur, "manifest.delta", &b[depth]);
        if (d == -1) goto out;
        if (d == 0) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints/%ld has no manifest", st->dir, cur);
            goto out;
        }
        depth++;
        held = depth;
        if (parse_header(st, cur, &b[depth - 1], &hs[depth - 1]) == -1) goto out;
        cur = hs[depth - 1].base;
    }
    size_t count;
    struct line *l = split(b[depth].p, b[depth].n, &count);
    if (l == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory"); goto out; }
    for (size_t i = depth; i-- > 0;) {
        size_t next;
        if (i + 1 < depth && strcmp(hs[i].base_sha, hs[i + 1].sha) != 0) {
            free(l);
            belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints: a delta's base is not the one it was made from", st->dir);
            goto out;
        }
        struct line *o = apply(l, count, b[i].p + hs[i].body, b[i].n - hs[i].body, count, &next);
        free(l);
        if (o == NULL) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints: a delta does not apply", st->dir);
            goto out;
        }
        l = o;
        count = next;
    }
    if (depth > 0) *top = hs[0];
    else memset(top, 0, sizeof *top);
    *lines = l;
    *n = count;
    rc = 0;
out:
    free(hs);
    *bufs = b;
    *n_bufs = held;
    return rc;
}

static void free_bufs(struct buf *b, size_t n) {
    for (size_t i = 0; i < n; i++) free(b[i].p);
    free(b);
}

/* The rebuilt bytes, checked against what the delta recorded (ST-4). */
static int rebuild(const struct state *st, long id, struct buf *out) {
    struct line *l = NULL;
    size_t n = 0, nb = 0;
    struct buf *bufs = NULL;
    struct header top;
    out->p = NULL;
    if (chain_lines(st, id, &l, &n, &bufs, &nb, &top) == -1) {
        free_bufs(bufs, nb);
        return -1;
    }
    size_t size = 0;
    for (size_t i = 0; i < n; i++) size += l[i].n;
    out->p = malloc(size + 1);
    int rc = -1;
    if (out->p == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
    } else {
        size_t w = 0;
        for (size_t i = 0; i < n; i++) {
            memcpy(out->p + w, l[i].p, l[i].n);
            w += l[i].n;
        }
        out->n = size;
        char sha[65];
        hash_hex(out->p, size, sha);
        if (size != top.size || strcmp(sha, top.sha) != 0) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints/%ld: the rebuilt manifest does not match what was recorded",
                          st->dir, id);
            free(out->p);
            out->p = NULL;
        } else {
            rc = 0;
        }
    }
    free(l);
    free_bufs(bufs, nb);
    return rc;
}

bool manifest_is_delta(const struct state *st, long id) {
    char rel[64];
    struct stat s;
    snprintf(rel, sizeof rel, "%ld/manifest.ndjson", id);
    if (fstatat(st->cp_fd, rel, &s, AT_SYMLINK_NOFOLLOW) == 0) return false;
    snprintf(rel, sizeof rel, "%ld/manifest.delta", id);
    return fstatat(st->cp_fd, rel, &s, AT_SYMLINK_NOFOLLOW) == 0;
}

int manifest_acquire(const struct state *st, long id, struct manifest_file *m) {
    m->temporary = false;
    if (state_check_manifest(st, id) == -1) return -1;
    if (!manifest_is_delta(st, id)) {
        state_manifest(st, id, m->path, sizeof m->path);
        return 0;
    }
    struct buf b;
    if (rebuild(st, id, &b) == -1) return -1;
    const char *tmp = getenv("TMPDIR");
    snprintf(m->path, sizeof m->path, "%s/belay-manifest.XXXXXX", tmp != NULL && tmp[0] == '/' ? tmp : "/tmp");
    const int fd = mkstemp(m->path);
    if (fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot create a temporary manifest");
        free(b.p);
        return -1;
    }
    size_t w = 0;
    while (w < b.n) {
        const ssize_t k = write(fd, b.p + w, b.n - w);
        if (k == -1 && errno == EINTR) continue;
        if (k <= 0) break;
        w += (size_t)k;
    }
    const bool ok = w == b.n;
    close(fd);
    free(b.p);
    if (!ok) {
        unlink(m->path);
        belay_err_set(BELAY_ERR_IO, errno, "cannot write a temporary manifest");
        return -1;
    }
    m->temporary = true;
    return 0;
}

int manifest_acquire_header(const struct state *st, long id, struct manifest_file *m) {
    m->temporary = false;
    if (!manifest_is_delta(st, id)) return manifest_acquire(st, id, m);
    struct buf b;
    struct header h;
    if (read_file(st, id, "manifest.delta", &b) != 1) return manifest_acquire(st, id, m);
    if (parse_header(st, id, &b, &h) == -1) { free(b.p); return -1; }
    const char *line = b.p + h.body;
    const char *nl = h.body < b.n ? memchr(line, '\n', b.n - h.body) : NULL;
    if (nl == NULL || *line != '+') {       /* the header unchanged: only a rebuild has it */
        free(b.p);
        return manifest_acquire(st, id, m);
    }
    const char *tmp = getenv("TMPDIR");
    snprintf(m->path, sizeof m->path, "%s/belay-manifest.XXXXXX", tmp != NULL && tmp[0] == '/' ? tmp : "/tmp");
    const int fd = mkstemp(m->path);
    const size_t n = (size_t)(nl + 1 - (line + 1));
    const bool ok = fd != -1 && write(fd, line + 1, n) == (ssize_t)n;
    if (fd != -1) close(fd);
    free(b.p);
    if (!ok) {
        if (fd != -1) unlink(m->path);
        belay_err_set(BELAY_ERR_IO, errno, "cannot write a temporary manifest");
        return -1;
    }
    m->temporary = true;
    return 0;
}

void manifest_release(struct manifest_file *m) {
    if (m->temporary) unlink(m->path);
    m->temporary = false;
}

int manifest_delta_base(const struct state *st, long id, long *base, uint64_t *size, uint64_t *stored) {
    struct buf b;
    *base = 0;
    *size = *stored = 0;
    const int got = read_file(st, id, "manifest.delta", &b);
    if (got != 1) return got == 0 ? 0 : -1;
    struct header h;
    const int rc = parse_header(st, id, &b, &h);
    *stored = (uint64_t)b.n;
    free(b.p);
    if (rc == -1) return -1;
    *base = h.base;
    if (manifest_is_delta(st, id)) *size = h.size;      /* no whole file beside it: one will be written */
    return 0;
}

int manifest_make_whole(const struct state *st, long id) {
    struct buf b;
    if (!manifest_is_delta(st, id)) {       /* the newest: whole already, and its delta must not outlive its base */
        char rel[64];
        snprintf(rel, sizeof rel, "%ld/manifest.delta", id);
        unlinkat(st->cp_fd, rel, 0);
        return 0;
    }
    if (rebuild(st, id, &b) == -1) return -1;
    char name[16], shown[PATH_MAX + 160];
    snprintf(name, sizeof name, "%ld", id);
    snprintf(shown, sizeof shown, "%s/checkpoints/%ld/manifest.ndjson", st->dir, id);
    const int dfd = openat(st->cp_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int rc = -1;
    if (dfd == -1) belay_err_set(BELAY_ERR_CORRUPT, errno, "%s is not a directory belay made", shown);
    else {
        rc = state_write_whole(dfd, "manifest.ndjson", b.p, b.n, shown);
        if (rc == 0) unlinkat(dfd, "manifest.delta", 0);
        close(dfd);
    }
    free(b.p);
    return rc;
}

/* A line's hash, for finding it in the base. */
static uint64_t line_hash(const struct line *l) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < l->n; i++) h = (h ^ (unsigned char)l->p[i]) * 1099511628211ULL;
    return h;
}

/* The operations turning `a` into `b`, into *out. */
static int encode(const struct line *a, size_t na, const struct line *b, size_t nb, struct buf *out) {
    size_t slots = 16;
    while (slots < na * 2) slots *= 2;
    uint32_t *table = calloc(slots, sizeof *table);     /* index + 1 */
    size_t cap = 4096, w = 0;
    char *o = malloc(cap);
    if (table == NULL || o == NULL) {
        free(table);
        free(o);
        belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        return -1;
    }
    for (size_t i = 0; i < na; i++) {
        size_t s = line_hash(&a[i]) & (slots - 1);
        while (table[s] != 0) s = (s + 1) & (slots - 1);
        table[s] = (uint32_t)i + 1;
    }
    size_t j = 0, run = 0;
#define NEED(k) do { if (w + (k) + 32 > cap) { while (w + (k) + 32 > cap) cap *= 2; char *q = realloc(o, cap); \
        if (q == NULL) { free(o); free(table); belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory"); return -1; } o = q; } } while (0)
#define FLUSH() do { if (run) { NEED(0); w += (size_t)sprintf(o + w, "=%zu\n", run); run = 0; } } while (0)
    for (size_t i = 0; i < nb; i++) {
        size_t at = SIZE_MAX;
        if (j < na && a[j].n == b[i].n && memcmp(a[j].p, b[i].p, b[i].n) == 0) at = j;
        else {
            for (size_t s = line_hash(&b[i]) & (slots - 1); table[s] != 0; s = (s + 1) & (slots - 1)) {
                const size_t k = table[s] - 1;
                if (k >= j && a[k].n == b[i].n && memcmp(a[k].p, b[i].p, b[i].n) == 0 && k < at) at = k;
            }
        }
        if (at == SIZE_MAX) {
            FLUSH();
            NEED(b[i].n + 2);
            o[w++] = '+';
            memcpy(o + w, b[i].p, b[i].n);
            w += b[i].n;
        } else {
            if (at > j) {
                FLUSH();
                NEED(0);
                w += (size_t)sprintf(o + w, "-%zu\n", at - j);
                j = at;
            }
            run++;
            j++;
        }
    }
    FLUSH();
#undef FLUSH
#undef NEED
    free(table);
    out->p = o;
    out->n = w;
    return 0;
}

void manifest_store_delta(const struct state *st, long prev, long id) {
    struct buf a = { 0 }, b = { 0 }, ops = { 0 }, old = { 0 };
    struct line *la = NULL, *lb = NULL, *check = NULL;
    size_t na = 0, nb = 0, nc = 0;
    char *file = NULL;
    if (prev == 0 || read_file(st, prev, "manifest.ndjson", &a) != 1 || read_file(st, id, "manifest.ndjson", &b) != 1) goto out;
    if (a.n == 0 || b.n == 0 || a.p[a.n - 1] != '\n' || b.p[b.n - 1] != '\n') goto out;
    long chain = 0;
    const int has = read_file(st, prev, "manifest.delta", &old);
    if (has == -1) goto out;
    if (has == 1) {
        struct header h;
        if (parse_header(st, prev, &old, &h) == -1) goto out;
        chain = h.chain;
    }
    if (chain + 1 <= DELTA_CHAIN_MAX) {
        la = split(a.p, a.n, &na);
        lb = split(b.p, b.n, &nb);
        if (la == NULL || lb == NULL || encode(la, na, lb, nb, &ops) == -1) goto out;
        check = apply(la, na, ops.p, ops.n, nb, &nc);
        if (check == NULL || nc != nb) goto out;
        for (size_t i = 0; i < nb; i++)
            if (check[i].n != lb[i].n || memcmp(check[i].p, lb[i].p, lb[i].n) != 0) goto out;
        char sha[65], base_sha[65], head[320];
        hash_hex(b.p, b.n, sha);
        hash_hex(a.p, a.n, base_sha);
        const int hn = snprintf(head, sizeof head,
                                "{\"belay_delta\":1,\"base\":%ld,\"base_sha256\":\"%s\",\"sha256\":\"%s\",\"size\":%zu,\"chain\":%ld}\n",
                                prev, base_sha, sha, b.n, chain + 1);
        file = malloc((size_t)hn + ops.n);
        if (file == NULL) goto out;
        memcpy(file, head, (size_t)hn);
        memcpy(file + hn, ops.p, ops.n);
        char name[16], shown[PATH_MAX + 160];
        snprintf(name, sizeof name, "%ld", id);
        snprintf(shown, sizeof shown, "%s/checkpoints/%ld/manifest.delta", st->dir, id);
        const int dfd = openat(st->cp_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dfd == -1) goto out;
        const int rc = state_write_whole(dfd, "manifest.delta", file, (size_t)hn + ops.n, shown);
        close(dfd);
        if (rc == -1) goto out;
    }
    /* prev's own delta was checked when it was written: its whole file can go. */
    if (has == 1) {
        char rel[64];
        snprintf(rel, sizeof rel, "%ld/manifest.ndjson", prev);
        unlinkat(st->cp_fd, rel, 0);
    }
out:
    belay_err_clear();
    free(a.p);
    free(b.p);
    free(old.p);
    free(ops.p);
    free(la);
    free(lb);
    free(check);
    free(file);
}
