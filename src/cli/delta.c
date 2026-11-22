/*
 *  See delta.h. Nothing here holds a manifest (test/expect/capture-scale.md,
 *  SC-M2): a chain of deltas is a chain of line sources, each handing on its
 *  base's lines or its own one at a time, and the rebuilt bytes are hashed
 *  as they are written. A delta is written by one pass over the two
 *  manifests side by side: both are sorted by path, so a line of the newer
 *  one is in the older at the older's current line or nowhere. Memory is a
 *  line buffer for each file open, whatever the manifests hold.
 *
 *  A rebuilt manifest is a file in the scope's state directory, under tmp/
 *  (SC-M3), held locked while it is used: whatever is found there unlocked
 *  was left by a run that was killed, and is removed.
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
#include <dirent.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"
#include "belay/manifest.h"
#include "capture/manifest_lex.h"
#include "util/jsonr.h"

struct header {
    long base, chain;
    uint64_t size;
    char sha[65], base_sha[65];
};

/* ---- lines of a file, one at a time ---- */

/* A line is at most a manifest's longest (BELAY_MANIFEST_LINE_MAX), its
 * newline, and in a delta the operation's one byte before it. */
#define LINE_BYTES ((size_t)BELAY_MANIFEST_LINE_MAX + 2)

struct lr {
    int fd;
    char *buf;
    size_t cap, lo, hi;
    bool eof;
    uint64_t bytes;             /* handed out so far */
    struct belay_sha256 sha;    /* of them, when `hashing` */
    bool hashing;
    char last;                  /* the last byte handed out */
};

static int lr_open(struct lr *r, int fd, size_t cap, bool hashing) {
    memset(r, 0, sizeof *r);
    r->fd = fd;
    r->cap = cap < LINE_BYTES ? LINE_BYTES : cap;
    r->buf = malloc(r->cap);
    r->hashing = hashing;
    if (hashing) belay_sha256_init(&r->sha);
    if (r->buf == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        return -1;
    }
    return 0;
}

static void lr_close(struct lr *r) {
    if (r->fd != -1) close(r->fd);
    free(r->buf);
    r->fd = -1;
    r->buf = NULL;
}

/* The next line with its newline (the last may have none): 1 with *p and
 * *n, valid until the next call; 0 at the end; -1 with belay_err (IO, or
 * CORRUPT for a line no manifest holds). */
static int lr_line(struct lr *r, const char **p, size_t *n) {
    for (;;) {
        const char *nl = r->hi > r->lo ? memchr(r->buf + r->lo, '\n', r->hi - r->lo) : NULL;
        if (nl != NULL || (r->eof && r->hi > r->lo)) {
            *p = r->buf + r->lo;
            *n = nl != NULL ? (size_t)(nl + 1 - *p) : r->hi - r->lo;
            r->lo += *n;
            r->bytes += *n;
            r->last = (*p)[*n - 1];
            if (r->hashing) belay_sha256_update(&r->sha, *p, *n);
            return 1;
        }
        if (r->eof) return 0;
        if (r->lo > 0) {
            memmove(r->buf, r->buf + r->lo, r->hi - r->lo);
            r->hi -= r->lo;
            r->lo = 0;
        }
        if (r->hi == r->cap) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "a line longer than any a manifest holds");
            return -1;
        }
        const ssize_t k = read(r->fd, r->buf + r->hi, r->cap - r->hi);
        if (k == -1 && errno == EINTR) continue;
        if (k == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot read a manifest");
            return -1;
        }
        if (k == 0) r->eof = true;
        r->hi += (size_t)k;
    }
}

static void sha_hex(struct belay_sha256 *c, char out[65]) {
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_final(c, d);
    belay_hex_encode(out, d, sizeof d);
}

/* checkpoints/<id>/<name> to read, never through a link: its descriptor; -2
 * when it isn't there; -1 with belay_err. *size: its length. */
static int open_file(const struct state *st, long id, const char *name, uint64_t *size) {
    char rel[64];
    snprintf(rel, sizeof rel, "%ld/%s", id, name);
    const int fd = openat(st->cp_fd, rel, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        if (errno == ENOENT) return -2;
        belay_err_set(BELAY_ERR_CORRUPT, errno, "%s/checkpoints/%s is not a file belay wrote", st->dir, rel);
        return -1;
    }
    struct stat s;
    if (fstat(fd, &s) == -1 || !S_ISREG(s.st_mode)) {
        close(fd);
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints/%s is not a file belay wrote", st->dir, rel);
        return -1;
    }
    if (size != NULL) *size = (uint64_t)s.st_size;
    return fd;
}

/* A delta's first line (its newline included). */
static int parse_header(const struct state *st, long id, const char *line, size_t n, struct header *h) {
    struct jval v;
    const bool whole = n > 0 && line[n - 1] == '\n';
    if (!whole || jsonr_parse(line, n - 1, &v) == -1 || v.t != J_OBJ) {
        if (whole && v.t != J_OBJ) jsonr_free(&v);
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
    return 0;
}

/* ---- a manifest as a source of lines: a whole file, or a delta over one ---- */

struct src {
    struct lr r;
    struct src *base;           /* NULL: a whole file */
    struct header h;            /* a delta's */
    unsigned long copy;         /* lines of the base still to hand on */
    const struct state *st;
};

static void src_free(struct src *s) {
    while (s != NULL) {
        struct src *b = s->base;
        lr_close(&s->r);
        free(s);
        s = b;
    }
}

static int does_not_apply(const struct state *st) {
    belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints: a delta does not apply", st->dir);
    return -1;
}

/* The next line of the manifest `s` stands for: as lr_line. */
static int src_next(struct src *s, const char **p, size_t *n) {
    if (s->base == NULL) return lr_line(&s->r, p, n);
    for (;;) {
        if (s->copy > 0) {
            const int g = src_next(s->base, p, n);
            if (g == 0) return does_not_apply(s->st);
            if (g == 1) s->copy--;
            return g;
        }
        const char *l;
        size_t ln;
        const int g = lr_line(&s->r, &l, &ln);
        if (g <= 0) return g;
        if (l[ln - 1] != '\n') return does_not_apply(s->st);
        if (l[0] == '+') {
            *p = l + 1;
            *n = ln - 1;
            return 1;
        }
        if (l[0] != '=' && l[0] != '-') return does_not_apply(s->st);
        unsigned long k = 0;
        if (ln < 3 || ln > 21) return does_not_apply(s->st);
        for (size_t i = 1; i + 1 < ln; i++) {
            if (l[i] < '0' || l[i] > '9') return does_not_apply(s->st);
            k = k * 10 + (unsigned long)(l[i] - '0');
        }
        if (l[0] == '=') {
            s->copy = k;
            continue;
        }
        for (; k > 0; k--) {
            const char *q;
            size_t qn;
            const int b = src_next(s->base, &q, &qn);
            if (b == 0) return does_not_apply(s->st);
            if (b == -1) return -1;
        }
    }
}

/* A delta read from `fd` (its header line first) over `base`; both are the
 * source's from here on, whatever is returned. */
static struct src *src_delta(const struct state *st, long id, int fd, struct src *base) {
    struct src *s = calloc(1, sizeof *s);
    if (s == NULL || lr_open(&s->r, fd, 0, false) == -1) {
        if (s == NULL) belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        close(fd);
        free(s);
        src_free(base);
        return NULL;
    }
    s->st = st;
    s->base = base;
    const char *l;
    size_t ln;
    const int g = lr_line(&s->r, &l, &ln);
    if (g == -1 || parse_header(st, id, g == 1 ? l : "", g == 1 ? ln : 0, &s->h) == -1) {
        if (g == -1)
            belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints/%ld/manifest.delta is not a delta belay wrote", st->dir, id);
        src_free(s);
        return NULL;
    }
    return s;
}

static struct src *src_whole(const struct state *st, int fd) {
    struct src *s = calloc(1, sizeof *s);
    if (s == NULL || lr_open(&s->r, fd, (size_t)1 << 20, false) == -1) {
        if (s == NULL) belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        close(fd);
        free(s);
        return NULL;
    }
    s->st = st;
    return s;
}

/* Checkpoint `id`'s manifest as a source: its whole file, or its delta over
 * its base's, down to a whole file. NULL with belay_err. */
static struct src *chain_open(const struct state *st, long id) {
    const int whole = open_file(st, id, "manifest.ndjson", NULL);
    if (whole == -1) return NULL;
    if (whole >= 0) return src_whole(st, whole);
    const int d = open_file(st, id, "manifest.delta", NULL);
    if (d == -1) return NULL;
    if (d == -2) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints/%ld has no manifest", st->dir, id);
        return NULL;
    }
    /* The header first: it names the base, which is below this id (so a chain ends). */
    struct src *top = src_delta(st, id, d, NULL);
    if (top == NULL) return NULL;
    top->base = chain_open(st, top->h.base);
    if (top->base == NULL) {
        src_free(top);
        return NULL;
    }
    if (top->base->base != NULL && strcmp(top->h.base_sha, top->base->h.sha) != 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints: a delta's base is not the one it was made from", st->dir);
        src_free(top);
        return NULL;
    }
    return top;
}

/* Every line of `s` to `out` (NULL: nowhere), hashed: 0 with the bytes'
 * count and sha256, or -1 with belay_err. */
static int src_drain(struct src *s, FILE *out, uint64_t *size, char sha[65]) {
    struct belay_sha256 c;
    belay_sha256_init(&c);
    *size = 0;
    const char *p;
    size_t n;
    int g;
    while ((g = src_next(s, &p, &n)) == 1) {
        belay_sha256_update(&c, p, n);
        *size += n;
        if (out != NULL && fwrite(p, 1, n, out) != n) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot write a temporary manifest");
            return -1;
        }
    }
    if (g == -1) return -1;
    sha_hex(&c, sha);
    return 0;
}

/* ---- temporaries: the scope's state directory, tmp/ ---- */

/* A name is <pid>.<n>.<random>: the pid so a process never takes its own
 * for a leftover where flock is a lock of the process (NFS). */
static bool own_name(const char *name) {
    char mine[32];
    const int k = snprintf(mine, sizeof mine, "%ld.", (long)getpid());
    return strncmp(name, mine, (size_t)k) == 0;
}

/* What a killed run left: every file there no process holds locked. */
static void tmp_sweep(int tfd) {
    const int dup_fd = dup(tfd);
    DIR *d = dup_fd == -1 ? NULL : fdopendir(dup_fd);
    if (d == NULL) {
        if (dup_fd != -1) close(dup_fd);
        return;
    }
    rewinddir(d);
    for (struct dirent *e; (e = readdir(d)) != NULL;) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0 || own_name(e->d_name)) continue;
        const int fd = openat(tfd, e->d_name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (fd == -1) continue;
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) unlinkat(tfd, e->d_name, 0);
        close(fd);
    }
    closedir(d);
}

/* A new file under tmp/, locked until it is closed, after the leftovers
 * there are removed: its descriptor, its name in `name` and tmp/'s
 * descriptor in *tfd (the caller closes both); -1 with belay_err. */
static int tmp_create(const struct state *st, char name[64], int *tfd) {
    static unsigned long counter;
    if (mkdirat(st->dir_fd, "tmp", 0700) == -1 && errno != EEXIST) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot create a temporary manifest in %s/tmp", st->dir);
        return -1;
    }
    *tfd = openat(st->dir_fd, "tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (*tfd == -1) {
        belay_err_set(BELAY_ERR_CORRUPT, errno, "%s/tmp is not a directory belay made", st->dir);
        return -1;
    }
    tmp_sweep(*tfd);
    for (int tries = 0; tries < 16; tries++) {
        struct timespec ts = { 0, 0 };
        clock_gettime(CLOCK_REALTIME, &ts);
        const unsigned long rnd = (unsigned long)ts.tv_sec ^ ((unsigned long)ts.tv_nsec * 2654435761UL);
        snprintf(name, 64, "%ld.%lu.%08lx", (long)getpid(), counter++, rnd & 0xffffffffUL);
        const int fd = openat(*tfd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd == -1 && errno == EEXIST) continue;
        if (fd == -1) break;
        /* Another run's sweep may have taken it for a leftover before the
         * lock was this one's: then it is gone, and another is made. */
        struct stat s;
        if (flock(fd, LOCK_EX) == 0 && fstat(fd, &s) == 0 && s.st_nlink > 0) return fd;
        close(fd);
    }
    belay_err_set(BELAY_ERR_IO, errno, "cannot create a temporary manifest in %s/tmp", st->dir);
    close(*tfd);
    *tfd = -1;
    return -1;
}

/* The rebuilt bytes into `out`, checked against what the delta recorded (ST-4). */
static int rebuild(const struct state *st, long id, FILE *out) {
    struct src *s = chain_open(st, id);
    if (s == NULL) return -1;
    uint64_t size;
    char sha[65];
    int rc = src_drain(s, out, &size, sha);
    if (rc == 0 && out != NULL && fflush(out) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot write a temporary manifest");
        rc = -1;
    }
    if (rc == 0 && (s->base == NULL || size != s->h.size || strcmp(sha, s->h.sha) != 0)) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints/%ld: the rebuilt manifest does not match what was recorded",
                      st->dir, id);
        rc = -1;
    }
    src_free(s);
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

/* A temporary for `m`, open for writing: the stream, or NULL with belay_err. */
static FILE *temporary(const struct state *st, struct manifest_file *m) {
    char name[64];
    int tfd;
    const int fd = tmp_create(st, name, &tfd);
    if (fd == -1) return NULL;
    close(tfd);
    FILE *f = fdopen(fd, "wb");
    if (f == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot create a temporary manifest");
        close(fd);
        return NULL;
    }
    snprintf(m->path, sizeof m->path, "%s/tmp/%s", st->dir, name);
    /* The lock goes with the descriptor: a second one keeps it until release. */
    const int held = dup(fd);
    if (held == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot create a temporary manifest");
        fclose(f);
        unlink(m->path);
        return NULL;
    }
    m->held = held + 1;
    m->temporary = true;
    return f;
}

int manifest_acquire(const struct state *st, long id, struct manifest_file *m) {
    m->temporary = false;
    m->held = 0;
    m->skip = 0;
    if (state_check_manifest(st, id) == -1) return -1;
    if (!manifest_is_delta(st, id)) {
        state_manifest(st, id, m->path, sizeof m->path);
        return 0;
    }
    FILE *f = temporary(st, m);
    if (f == NULL) return -1;
    int rc = rebuild(st, id, f);
    if (fclose(f) != 0 && rc == 0) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot write a temporary manifest");
        rc = -1;
    }
    if (rc == -1) manifest_release(m);
    return rc;
}

int manifest_acquire_header(const struct state *st, long id, struct manifest_file *m) {
    m->temporary = false;
    m->held = 0;
    m->skip = 0;
    if (!manifest_is_delta(st, id)) return manifest_acquire(st, id, m);
    const int d = open_file(st, id, "manifest.delta", NULL);
    if (d < 0) {
        belay_err_clear();
        return manifest_acquire(st, id, m);
    }
    struct lr r;
    if (lr_open(&r, d, 0, false) == -1) {
        close(d);
        return -1;
    }
    struct header h;
    const char *l;
    size_t ln;
    int g = lr_line(&r, &l, &ln);
    if (g != 1 || parse_header(st, id, l, ln, &h) == -1) {
        if (g == 0) parse_header(st, id, "", 0, &h);        /* says what it is not */
        lr_close(&r);
        return -1;
    }
    const size_t first = ln;
    g = lr_line(&r, &l, &ln);
    const bool own = g == 1 && l[0] == '+' && l[ln - 1] == '\n';
    lr_close(&r);
    if (!own) {                             /* the header unchanged: only a rebuild has it */
        belay_err_clear();
        return manifest_acquire(st, id, m);
    }
    snprintf(m->path, sizeof m->path, "%s/checkpoints/%ld/manifest.delta", st->dir, id);
    m->skip = (long)first + 1;
    return 0;
}

void manifest_release(struct manifest_file *m) {
    if (m->temporary) unlink(m->path);
    if (m->temporary && m->held > 0) close(m->held - 1);
    m->temporary = false;
    m->held = 0;
}

int manifest_delta_base(const struct state *st, long id, long *base, uint64_t *size, uint64_t *stored) {
    *base = 0;
    *size = *stored = 0;
    const int d = open_file(st, id, "manifest.delta", stored);
    if (d == -2) return 0;
    if (d == -1) return -1;
    struct lr r;
    if (lr_open(&r, d, 0, false) == -1) {
        close(d);
        return -1;
    }
    struct header h;
    const char *l;
    size_t ln;
    const int g = lr_line(&r, &l, &ln);
    const int rc = g == -1 ? -1 : parse_header(st, id, g == 1 ? l : "", g == 1 ? ln : 0, &h);
    lr_close(&r);
    if (rc == -1) return -1;
    *base = h.base;
    if (manifest_is_delta(st, id)) *size = h.size;      /* no whole file beside it: one will be written */
    return 0;
}

/* tmp/<name> made checkpoints/<id>/<as>, durable: 0, or -1 with belay_err. */
static int publish(const struct state *st, int tfd, const char *name, int fd, long id, const char *as) {
    char rel[64], shown[PATH_MAX + 160];
    snprintf(rel, sizeof rel, "%ld/%s", id, as);
    snprintf(shown, sizeof shown, "%s/checkpoints/%ld/%s", st->dir, id, as);
    if (fsync(fd) != 0 || renameat(tfd, name, st->cp_fd, rel) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot write %s", shown);
        return -1;
    }
    snprintf(rel, sizeof rel, "%ld", id);
    const int dfd = openat(st->cp_fd, rel, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd != -1) {
        if (fsync(dfd) != 0) { /* in place; only its durability is in doubt */ }
        close(dfd);
    }
    return 0;
}

int manifest_make_whole(const struct state *st, long id) {
    if (!manifest_is_delta(st, id)) {       /* the newest: whole already, and its delta must not outlive its base */
        char rel[64];
        snprintf(rel, sizeof rel, "%ld/manifest.delta", id);
        unlinkat(st->cp_fd, rel, 0);
        return 0;
    }
    char name[64], rel[64];
    int tfd;
    const int fd = tmp_create(st, name, &tfd);
    if (fd == -1) return -1;
    const int wfd = dup(fd);
    FILE *f = wfd == -1 ? NULL : fdopen(wfd, "wb");
    int rc = -1;
    if (f == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot create a temporary manifest");
        if (wfd != -1) close(wfd);
    } else {
        rc = rebuild(st, id, f);
        if (fclose(f) != 0 && rc == 0) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot write a temporary manifest");
            rc = -1;
        }
    }
    if (rc == 0) rc = publish(st, tfd, name, fd, id, "manifest.ndjson");
    if (rc == 0) {
        snprintf(rel, sizeof rel, "%ld/manifest.delta", id);
        unlinkat(st->cp_fd, rel, 0);
    } else {
        unlinkat(tfd, name, 0);
    }
    close(fd);
    close(tfd);
    return rc;
}

/* ---- writing a delta: one pass over two manifests in path order ---- */

/*
 *  Where a line stands in a manifest: its part (the header, the root lines,
 *  the entries, the racy lines, the trailer -- in that order, manifest-v5
 *  and its addendum) and within a part its path, decoded, which is what the
 *  lines are sorted by. A line that is none of these sorts after them all,
 *  by its bytes. The order only decides which lines a delta copies: a delta
 *  is checked against the manifest it stands for before it is kept, so a
 *  line placed wrongly costs bytes, never a wrong rebuild.
 */
struct key { int part; size_t len; char path[4096]; };

static bool key_string(const char *body, size_t n, bool b64, struct key *k) {
    size_t e = 0;
    while (e < n && body[e] != '"') e += body[e] == '\\' ? 2 : 1;
    if (e >= n) return false;
    if (!b64) return lex_decode_string(body, e, k->path, sizeof k->path, &k->len) == 0;
    char enc[5600];
    if (e >= sizeof enc) return false;
    memcpy(enc, body, e);
    enc[e] = '\0';
    return belay_base64_decode(k->path, sizeof k->path, &k->len, enc) == 0;
}

static void line_key(const char *p, size_t n, bool first, struct key *k) {
    static const struct { const char *prefix; int part; bool b64; } KINDS[] = {
        { "{\"path\":\"", 2, false },  { "{\"path_b64\":\"", 2, true },
        { "{\"root\":\"", 1, false },  { "{\"root_b64\":\"", 1, true },
        { "{\"racy\":\"", 3, false },  { "{\"racy_b64\":\"", 3, true },
    };
    k->len = 0;
    if (first) { k->part = 0; return; }
    for (size_t i = 0; i < sizeof KINDS / sizeof KINDS[0]; i++) {
        const size_t pl = strlen(KINDS[i].prefix);
        if (n > pl && memcmp(p, KINDS[i].prefix, pl) == 0 && key_string(p + pl, n - pl, KINDS[i].b64, k)) {
            k->part = KINDS[i].part;
            return;
        }
    }
    static const char END[] = "{\"belay_manifest_end\":";
    if (n > sizeof END - 1 && memcmp(p, END, sizeof END - 1) == 0) { k->part = 4; return; }
    k->part = 5;
    k->len = n < sizeof k->path ? n : sizeof k->path;
    memcpy(k->path, p, k->len);
}

static int key_cmp(const struct key *a, const struct key *b) {
    if (a->part != b->part) return a->part < b->part ? -1 : 1;
    const size_t m = a->len < b->len ? a->len : b->len;
    const int c = memcmp(a->path, b->path, m);
    return c != 0 ? c : (a->len > b->len) - (a->len < b->len);
}

struct enc {
    struct lr a, b;             /* the base and the manifest */
    struct key ka, kb;
    const char *la;             /* the base's current line */
    size_t na;
    bool have_a, first_a;
};

static int enc_advance(struct enc *e) {
    const int g = lr_line(&e->a, &e->la, &e->na);
    if (g == -1) return -1;
    e->have_a = g == 1;
    if (e->have_a) line_key(e->la, e->na, e->first_a, &e->ka);
    e->first_a = false;
    return 0;
}

/* The operations turning the base into the manifest, onto `ops`; both files
 * are read to their ends, so their hashes and sizes are known after. */
static int encode(struct enc *e, FILE *ops) {
    unsigned long run = 0, skipped = 0;
    e->first_a = true;
    if (enc_advance(e) == -1) return -1;
    const char *lb;
    size_t nb;
    bool first_b = true;
    int g;
    while ((g = lr_line(&e->b, &lb, &nb)) == 1) {
        line_key(lb, nb, first_b, &e->kb);
        first_b = false;
        while (e->have_a && key_cmp(&e->ka, &e->kb) < 0) {     /* gone from the manifest */
            skipped++;
            if (enc_advance(e) == -1) return -1;
        }
        if (e->have_a && e->na == nb && memcmp(e->la, lb, nb) == 0) {
            if (skipped > 0) {
                if (run > 0 && fprintf(ops, "=%lu\n", run) < 0) return -1;
                if (fprintf(ops, "-%lu\n", skipped) < 0) return -1;
                run = skipped = 0;
            }
            run++;
            if (enc_advance(e) == -1) return -1;
        } else {
            if (run > 0 && fprintf(ops, "=%lu\n", run) < 0) return -1;
            run = 0;
            if (fputc('+', ops) == EOF || fwrite(lb, 1, nb, ops) != nb) return -1;
        }
    }
    if (g == -1) return -1;
    if (run > 0 && fprintf(ops, "=%lu\n", run) < 0) return -1;
    while (e->have_a)                                           /* for its hash */
        if (enc_advance(e) == -1) return -1;
    return 0;
}

void manifest_store_delta(const struct state *st, long prev, long id) {
    struct enc *e = calloc(1, sizeof *e);
    char ops_name[64] = "", out_name[64] = "";
    int tfd = -1, ops_fd = -1, out_fd = -1;
    FILE *ops = NULL, *out = NULL;
    struct src *check = NULL;
    if (e != NULL) e->a.fd = e->b.fd = -1;
    if (e == NULL || prev == 0) goto out;
    int fd = open_file(st, prev, "manifest.ndjson", NULL);
    if (fd < 0 || lr_open(&e->a, fd, (size_t)1 << 20, true) == -1) { if (fd >= 0) close(fd); e->a.fd = -1; goto out; }
    fd = open_file(st, id, "manifest.ndjson", NULL);
    if (fd < 0 || lr_open(&e->b, fd, (size_t)1 << 20, true) == -1) { if (fd >= 0) close(fd); e->b.fd = -1; goto out; }
    long chain = 0;
    bool has = false;
    {
        char rel[64];
        struct stat s;
        snprintf(rel, sizeof rel, "%ld/manifest.delta", prev);
        if (fstatat(st->cp_fd, rel, &s, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
            const int d = open_file(st, prev, "manifest.delta", NULL);
            if (d < 0) goto out;
            struct lr r;
            if (lr_open(&r, d, 0, false) == -1) { close(d); goto out; }
            struct header h;
            const char *l;
            size_t ln;
            const int g = lr_line(&r, &l, &ln);
            const int rc = g == 1 ? parse_header(st, prev, l, ln, &h) : -1;
            lr_close(&r);
            if (rc == -1) goto out;
            chain = h.chain;
            has = true;
        }
    }
    if (chain + 1 <= DELTA_CHAIN_MAX) {
        ops_fd = tmp_create(st, ops_name, &tfd);
        if (ops_fd == -1) goto out;
        const int wfd = dup(ops_fd);
        ops = wfd == -1 ? NULL : fdopen(wfd, "w+b");
        if (ops == NULL) { if (wfd != -1) close(wfd); goto out; }
        if (encode(e, ops) == -1 || fflush(ops) != 0) goto out;
        if (e->a.bytes == 0 || e->b.bytes == 0 || e->a.last != '\n' || e->b.last != '\n') goto out;
        char sha[65], base_sha[65];
        sha_hex(&e->b.sha, sha);
        sha_hex(&e->a.sha, base_sha);
        int tfd2;
        out_fd = tmp_create(st, out_name, &tfd2);
        if (out_fd == -1) goto out;
        close(tfd2);
        const int ofd = dup(out_fd);
        out = ofd == -1 ? NULL : fdopen(ofd, "wb");
        if (out == NULL) { if (ofd != -1) close(ofd); goto out; }
        if (fprintf(out, "{\"belay_delta\":1,\"base\":%ld,\"base_sha256\":\"%s\",\"sha256\":\"%s\",\"size\":%llu,\"chain\":%ld}\n",
                    prev, base_sha, sha, (unsigned long long)e->b.bytes, chain + 1) < 0)
            goto out;
        rewind(ops);
        static char copy[1 << 16];
        size_t k;
        while ((k = fread(copy, 1, sizeof copy, ops)) > 0)
            if (fwrite(copy, 1, k, out) != k) goto out;
        if (ferror(ops) || fflush(out) != 0) goto out;
        /* Checked before it is kept: the delta over its base is the manifest, byte for byte. */
        const int dfd = openat(tfd, out_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        const int bfd = dfd == -1 ? -1 : open_file(st, prev, "manifest.ndjson", NULL);
        if (bfd < 0) { if (dfd != -1) close(dfd); goto out; }
        struct src *base = src_whole(st, bfd);
        if (base == NULL) { close(dfd); goto out; }
        check = src_delta(st, id, dfd, base);
        if (check == NULL) goto out;
        uint64_t size;
        char got[65];
        if (src_drain(check, NULL, &size, got) == -1 || size != e->b.bytes || strcmp(got, sha) != 0) goto out;
        if (publish(st, tfd, out_name, out_fd, id, "manifest.delta") == -1) goto out;
        out_name[0] = '\0';
    }
    /* prev's own delta was checked when it was written: its whole file can go. */
    if (has) {
        char rel[64];
        snprintf(rel, sizeof rel, "%ld/manifest.ndjson", prev);
        unlinkat(st->cp_fd, rel, 0);
    }
out:
    belay_err_clear();
    src_free(check);
    if (ops != NULL) fclose(ops);
    if (out != NULL) fclose(out);
    if (tfd != -1) {
        if (ops_name[0] != '\0') unlinkat(tfd, ops_name, 0);
        if (out_name[0] != '\0') unlinkat(tfd, out_name, 0);
        close(tfd);
    }
    if (ops_fd != -1) close(ops_fd);
    if (out_fd != -1) close(out_fd);
    if (e != NULL) {
        if (e->a.fd != -1 || e->a.buf != NULL) lr_close(&e->a);
        if (e->b.fd != -1 || e->b.buf != NULL) lr_close(&e->b);
        free(e);
    }
}
