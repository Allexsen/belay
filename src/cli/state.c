#define _GNU_SOURCE
#include "state.h"

#include "jsonr.h"
#include "../utils.h"

#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"
#include "belay/manifest.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Every path here is built from the state root, which state_root() refuses
 * within 128 bytes of PATH_MAX; GCC cannot see that bound through the
 * struct, so its truncation warning is noise in this file only. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

void (*scope_resolve_hook)(const char *resolved) = NULL;
void (*state_capture_hook)(const char *scope) = NULL;

int scope_resolve(const char *arg, struct scope *out) {
    if (arg == NULL || arg[0] == '\0') {
        belay_err_set(BELAY_ERR_INVALID, 0, "the scope is empty");
        return -1;
    }
    /* realpath() once (§5.1.1): "..", ".", "//" and symlinks resolved
     * against the real filesystem, never lexically. */
    char *real = realpath(arg, NULL);
    if (real == NULL) {
        const int e = errno;          /* missing, not a directory, unreadable, too long, a loop */
        belay_err_set(e == ENOENT || e == ENOTDIR || e == EACCES || e == ENAMETOOLONG || e == ELOOP
                          ? BELAY_ERR_INVALID : BELAY_ERR_IO, e, "cannot resolve the scope %s", arg);
        return -1;
    }
    if (strlen(real) >= sizeof out->path) {
        belay_err_set(BELAY_ERR_RANGE, 0, "the scope's path is too long");
        free(real);
        return -1;
    }
    struct stat st;
    if (stat(real, &st) == -1 || !S_ISDIR(st.st_mode)) {
        belay_err_set(BELAY_ERR_INVALID, 0, "the scope %s is not a directory", real);
        free(real);
        return -1;
    }
    if (scope_resolve_hook != NULL) scope_resolve_hook(real);

    /* The resolved path, one component at a time, never following a link:
     * anything swapped in since realpath() is refused. */
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    char *save = NULL, *copy = strdup(real);
    if (fd == -1 || copy == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot open /");
        if (fd != -1) close(fd);
        free(copy);
        free(real);
        return -1;
    }
    for (char *c = strtok_r(copy, "/", &save); c != NULL; c = strtok_r(NULL, "/", &save)) {
        const int next = openat(fd, c, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        const int e = errno;
        close(fd);
        if (next == -1) {
            if (e == ELOOP || e == ENOTDIR || e == ENOENT)
                belay_err_set(BELAY_ERR_INVALID, e, "the scope %s changed during resolution", real);
            else
                belay_err_set(e == EACCES ? BELAY_ERR_INVALID : BELAY_ERR_IO, e, "cannot open the scope %s", real);
            free(copy);
            free(real);
            return -1;
        }
        fd = next;
    }
    free(copy);
    if (fstat(fd, &st) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot stat the scope %s", real);
        close(fd);
        free(real);
        return -1;
    }
    close(fd);
    snprintf(out->path, sizeof out->path, "%s", real);
    out->dev = (uint64_t)st.st_dev;
    out->ino = (uint64_t)st.st_ino;
    free(real);
    return 0;
}

/* ---- the state directory ---- */

static int state_root(char *buf, size_t cap) {
    const char *d = getenv("BELAY_STATE_DIR");
    int n;
    if (d != NULL && d[0] != '\0') n = snprintf(buf, cap, "%s", d);
    else if ((d = getenv("XDG_STATE_HOME")) != NULL && d[0] == '/') n = snprintf(buf, cap, "%s/belay", d);
    else if ((d = getenv("HOME")) != NULL && d[0] == '/') n = snprintf(buf, cap, "%s/.local/state/belay", d);
    else {
        belay_err_set(BELAY_ERR_INVALID, 0, "no state directory: set HOME, XDG_STATE_HOME or BELAY_STATE_DIR");
        return -1;
    }
    if (n < 0 || (size_t)n >= cap - 128) {
        belay_err_set(BELAY_ERR_RANGE, 0, "the state directory's path is too long");
        return -1;
    }
    return 0;
}

int state_open(const struct scope *sc, bool create, struct state *st) {
    memset(st, 0, sizeof *st);
    st->lock_fd = -1;
    st->scope = *sc;
    if (state_root(st->root, sizeof st->root) == -1) return -1;
    char hex[65];
    {
        struct belay_sha256 h;
        uint8_t d[32];
        belay_sha256_init(&h);
        belay_sha256_update(&h, sc->path, strlen(sc->path));
        belay_sha256_final(&h, d);
        belay_hex_encode(hex, d, sizeof d);
    }
    snprintf(st->dir, sizeof st->dir, "%s/scopes/%.16s", st->root, hex);
    snprintf(st->store, sizeof st->store, "%s/store", st->dir);
    char path[PATH_MAX + 32];
    if (create) {
        snprintf(path, sizeof path, "%s/checkpoints", st->dir);
        if (mkdir_p(st->root, 0700) == -1 || mkdir_p(path, 0700) == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot create the state directory %s", st->dir);
            return -1;
        }
    }
    struct stat rs;
    if (stat(st->root, &rs) == 0) {
        st->root_dev = (uint64_t)rs.st_dev;
        st->root_ino = (uint64_t)rs.st_ino;
    }
    /* The scope file names the scope this directory is for: a hash collision
     * would be two scopes in one directory, refused. */
    snprintf(path, sizeof path, "%s/scope", st->dir);
    FILE *f = fopen(path, "r");
    if (f != NULL) {
        char have[PATH_MAX + 2] = "";
        if (fgets(have, sizeof have, f) == NULL) have[0] = '\0';
        fclose(f);
        have[strcspn(have, "\n")] = '\0';
        if (strcmp(have, sc->path) != 0) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "%s belongs to the scope %s", st->dir, have);
            return -1;
        }
    } else if (create) {
        char tmp[PATH_MAX + 48];
        snprintf(tmp, sizeof tmp, "%s.tmp", path);
        FILE *w = fopen(tmp, "w");
        if (w == NULL || fprintf(w, "%s\n", sc->path) < 0 || fflush(w) != 0 || fsync(fileno(w)) != 0) {
            if (w != NULL) fclose(w);
            belay_err_set(BELAY_ERR_IO, errno, "cannot write %s", path);
            return -1;
        }
        fclose(w);
        if (rename(tmp, path) == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot write %s", path);
            return -1;
        }
    }
    if (create) {
        snprintf(path, sizeof path, "%s/lock", st->dir);
        st->lock_fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (st->lock_fd == -1 || flock(st->lock_fd, LOCK_EX) == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot lock %s", path);
            return -1;
        }
    }
    return 0;
}

void state_close(struct state *st) {
    if (st->lock_fd != -1) close(st->lock_fd);       /* releases the lock */
    st->lock_fd = -1;
}

void state_manifest(const struct state *st, long id, char *buf, size_t cap) {
    snprintf(buf, cap, "%s/checkpoints/%ld/manifest.ndjson", st->dir, id);
}

/* ---- checkpoints ---- */

static int read_meta(const char *path, struct checkpoint *c) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    char buf[8192];
    const size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    struct jval v;
    if (jsonr_parse(buf, n, &v) == -1) return -1;
    memset(c, 0, sizeof *c);
    c->id = (long)jint(&v, "id", -1);
    snprintf(c->kind, sizeof c->kind, "%s", jstr(&v, "kind"));
    c->created_ns = jint(&v, "created_ns", 0);
    c->entries = (uint64_t)jint(&v, "entries", 0);
    c->raced = (uint64_t)jint(&v, "raced", 0);
    c->unstable = (uint64_t)jint(&v, "unstable", 0);
    c->vanished = (uint64_t)jint(&v, "vanished", 0);
    c->excluded = (uint64_t)jint(&v, "excluded", 0);
    const struct jval *p = jget(&v, "provisional");
    c->provisional = p != NULL && p->t == J_BOOL && p->b;
    const struct jval *pf = jget(&v, "prefilter");
    const struct jval *used = jget(pf, "used");
    c->full = !(used != NULL && used->t == J_BOOL && used->b);
    snprintf(c->full_reason, sizeof c->full_reason, "%s", jstr(pf, "full_reason"));
    c->trusted = (uint64_t)jint(pf, "trusted", 0);
    c->racy = (uint64_t)jint(pf, "racy", 0);
    jsonr_free(&v);
    return c->id >= 0 ? 0 : -1;
}

static int by_id(const void *a, const void *b) {
    const long x = ((const struct checkpoint *)a)->id, y = ((const struct checkpoint *)b)->id;
    return (x > y) - (x < y);
}

/* Every numeric directory under checkpoints/, complete or not: the next id
 * is past them all, so a capture that failed half way is never reused. */
static long highest_dir(const struct state *st) {
    char path[PATH_MAX + 32];
    snprintf(path, sizeof path, "%s/checkpoints", st->dir);
    DIR *d = opendir(path);
    long hi = 0;
    if (d == NULL) return 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        char *end;
        const long id = strtol(de->d_name, &end, 10);
        if (*end == '\0' && end != de->d_name && id > hi) hi = id;
    }
    closedir(d);
    return hi;
}

int state_list(const struct state *st, struct checkpoint **out, size_t *n) {
    *out = NULL;
    *n = 0;
    char path[PATH_MAX + 64];
    snprintf(path, sizeof path, "%s/checkpoints", st->dir);
    DIR *d = opendir(path);
    if (d == NULL) return errno == ENOENT ? 0 : (belay_err_set(BELAY_ERR_IO, errno, "cannot list %s", path), -1);
    size_t cap = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        char *end;
        const long id = strtol(de->d_name, &end, 10);
        if (*end != '\0' || end == de->d_name || id <= 0) continue;
        char meta[PATH_MAX + 96];
        snprintf(meta, sizeof meta, "%s/%ld/meta.json", path, id);
        struct checkpoint c;
        if (read_meta(meta, &c) == -1 || c.id != id) continue;      /* not complete: not a checkpoint */
        if (*n == cap) {
            cap = cap ? cap * 2 : 16;
            struct checkpoint *q = realloc(*out, cap * sizeof *q);
            if (q == NULL) {
                closedir(d);
                belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
                return -1;
            }
            *out = q;
        }
        (*out)[(*n)++] = c;
    }
    closedir(d);
    if (*n > 1) qsort(*out, *n, sizeof **out, by_id);
    return 0;
}

static int write_meta(const struct state *st, const struct checkpoint *c) {
    char path[PATH_MAX + 96], tmp[PATH_MAX + 112], esc[6 * PATH_MAX + 8], why[6 * 160 + 8];
    snprintf(path, sizeof path, "%s/checkpoints/%ld/meta.json", st->dir, c->id);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if (belay_json_escape(esc, sizeof esc, st->scope.path, strlen(st->scope.path)) == -1 ||
        belay_json_escape(why, sizeof why, c->full_reason, strlen(c->full_reason)) == -1)
        return -1;
    FILE *f = fopen(tmp, "w");
    if (f == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot write %s", tmp);
        return -1;
    }
    fprintf(f, "{\"id\":%ld,\"kind\":\"%s\",\"created_ns\":%lld,\"scope\":\"%s\",\"entries\":%llu,"
               "\"raced\":%llu,\"unstable\":%llu,\"vanished\":%llu,\"provisional\":%s,\"excluded\":%llu,"
               "\"prefilter\":{\"used\":%s,\"trusted\":%llu,\"racy\":%llu,\"full_reason\":\"%s\"}}\n",
            c->id, c->kind, (long long)c->created_ns, esc, (unsigned long long)c->entries,
            (unsigned long long)c->raced, (unsigned long long)c->unstable, (unsigned long long)c->vanished,
            c->provisional ? "true" : "false", (unsigned long long)c->excluded, c->full ? "false" : "true",
            (unsigned long long)c->trusted, (unsigned long long)c->racy, why);
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        belay_err_set(BELAY_ERR_IO, errno, "cannot write %s", tmp);
        return -1;
    }
    fclose(f);
    if (rename(tmp, path) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot write %s", path);
        return -1;
    }
    char dir[PATH_MAX + 64];
    snprintf(dir, sizeof dir, "%s/checkpoints/%ld", st->dir, c->id);
    const int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd != -1) {
        if (fsync(dfd) != 0) { /* the checkpoint is already in place */ }
        close(dfd);
    }
    return 0;
}

static int64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}

int state_capture(struct state *st, const struct capture_req *req, struct checkpoint *out) {
    struct checkpoint *list = NULL;
    size_t n = 0;
    if (state_list(st, &list, &n) == -1) return -1;
    const long id = highest_dir(st) + 1;
    char dir[PATH_MAX + 128], manifest[PATH_MAX + 160], prev[PATH_MAX + 160];
    snprintf(dir, sizeof dir, "%s/checkpoints/%ld", st->dir, id);
    if (mkdir(dir, 0700) == -1) {
        free(list);
        belay_err_set(BELAY_ERR_IO, errno, "cannot create %s", dir);
        return -1;
    }
    state_manifest(st, id, manifest, sizeof manifest);

    struct checkpoint c = { 0 };
    c.id = id;
    snprintf(c.kind, sizeof c.kind, "%s", req->kind);
    c.created_ns = now_ns();
    c.full = true;

    /* Prefilter against the latest checkpoint unless a full walk is due
     * (Q8): asked for, none before, or N marks since the last full one. */
    const char *previous = NULL;
    if (req->prefilter && n > 0) {
        long since_full = 0;
        for (size_t i = n; i-- > 0 && !list[i].full;) since_full++;
        if (req->force_full) snprintf(c.full_reason, sizeof c.full_reason, "asked for (--full)");
        else if (req->full_every > 0 && since_full + 1 >= req->full_every)
            snprintf(c.full_reason, sizeof c.full_reason, "every %ld marks", req->full_every);
        else {
            state_manifest(st, list[n - 1].id, prev, sizeof prev);
            previous = prev;
        }
    } else if (req->prefilter) {
        snprintf(c.full_reason, sizeof c.full_reason, "no checkpoint before");
    }
    free(list);

    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT, .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
        .store_dir = st->store, .previous = previous,
        .exclude = st->root_ino != 0, .exclude_dev = st->root_dev, .exclude_ino = st->root_ino,
        .expect_root = true, .root_dev = st->scope.dev, .root_ino = st->scope.ino,
    };
    struct belay_manifest_stats s;
    if (state_capture_hook != NULL) state_capture_hook(st->scope.path);
    if (belay_manifest_write(manifest, st->scope.path, &o, &s) == -1) return -1;
    if (previous != NULL && !s.prefilter && s.prefilter_skipped != NULL) {
        snprintf(c.full_reason, sizeof c.full_reason, "%s", s.prefilter_skipped);
    } else if (previous != NULL && s.prefilter && s.previous_newest_ns != INT64_MIN &&
               s.newest_ctime_ns < s.previous_newest_ns) {
        /* Q8: ctime went backwards -- nothing read on trust is trusted; the
         * walk is done again, reading every file. */
        snprintf(c.full_reason, sizeof c.full_reason,
                 "ctime went backwards: newest %lld below the previous %lld",
                 (long long)s.newest_ctime_ns, (long long)s.previous_newest_ns);
        o.previous = NULL;
        if (belay_manifest_write(manifest, st->scope.path, &o, &s) == -1) return -1;
    } else if (previous != NULL) {
        c.full = false;
        c.trusted = s.trusted;
        c.racy = s.racy;
    }
    c.entries = s.entries;
    c.raced = s.raced;
    c.unstable = s.unstable;
    c.vanished = s.vanished;
    c.excluded = s.excluded;
    c.provisional = s.raced || s.unstable || s.vanished;
    if (write_meta(st, &c) == -1) return -1;
    *out = c;
    return 0;
}
