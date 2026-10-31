#define _GNU_SOURCE
#include "state.h"

#include "jsonr.h"
#include "receipt.h"
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

/* Ancestors need only search permission (review 2026-10-31, Phase 5, 13). */
#if defined(O_PATH)
#define DIR_WALK O_PATH
#elif defined(O_SEARCH)
#define DIR_WALK O_SEARCH
#else
#define DIR_WALK O_RDONLY
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
    int fd = open("/", DIR_WALK | O_DIRECTORY | O_CLOEXEC);
    char *save = NULL, *copy = strdup(real);
    if (fd == -1 || copy == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot open /");
        if (fd != -1) close(fd);
        free(copy);
        free(real);
        return -1;
    }
    for (char *c = strtok_r(copy, "/", &save); c != NULL; c = strtok_r(NULL, "/", &save)) {
        const int next = openat(fd, c, DIR_WALK | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
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
    if (d != NULL && d[0] != '\0' && d[0] != '/') {
        belay_err_set(BELAY_ERR_INVALID, 0, "BELAY_STATE_DIR must be an absolute path");
        return -1;
    }
    if (d != NULL && d[0] != '\0') n = snprintf(buf, cap, "%s", d);
    else if ((d = getenv("XDG_STATE_HOME")) != NULL && d[0] == '/') n = snprintf(buf, cap, "%s/belay", d);
    else if ((d = getenv("HOME")) != NULL && d[0] == '/') n = snprintf(buf, cap, "%s/.local/state/belay", d);
    else {
        belay_err_set(BELAY_ERR_INVALID, 0, "no state directory: set HOME, XDG_STATE_HOME or BELAY_STATE_DIR");
        return -1;
    }
    if (n < 0 || (size_t)n >= cap - 128) {
        belay_err_set(BELAY_ERR_INVALID, 0, "the state directory's path is too long");
        return -1;
    }
    return 0;
}

/* The directory `name` under `pfd`, made first when `create`; never through
 * a symlink. The fd, or -1: errno ENOENT when it is not there and not made,
 * else belay_err. */
static int dir_at(int pfd, const char *name, bool create, const char *shown) {
    if (create && mkdirat(pfd, name, 0700) == -1 && errno != EEXIST) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot create %s", shown);
        return -1;
    }
    const int fd = openat(pfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        const int e = errno;
        if (e == ENOENT && !create) return -1;
        if (e == ELOOP || e == ENOTDIR)
            belay_err_set(BELAY_ERR_CORRUPT, e, "%s is not a directory belay made (a symlink?)", shown);
        else
            belay_err_set(BELAY_ERR_IO, e, "cannot open %s", shown);
        errno = e;
        return -1;
    }
    return fd;
}

/* A file under `dfd` read whole, at most `cap` - 1 bytes: a regular file
 * opened without following a symlink or waiting on a FIFO. Its length, or
 * -1 with belay_err (CORRUPT: not a regular file, larger than that); errno
 * ENOENT, with no belay_err, when it is not there. */
static ssize_t read_small(int dfd, const char *name, char *buf, size_t cap, const char *shown) {
    const int fd = openat(dfd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        const int e = errno;
        if (e == ENOENT) return -1;
        belay_err_set(e == ELOOP ? BELAY_ERR_CORRUPT : BELAY_ERR_IO, e, "cannot read %s", shown);
        errno = e;
        return -1;
    }
    struct stat fs;
    if (fstat(fd, &fs) == -1 || !S_ISREG(fs.st_mode) || (uint64_t)fs.st_size >= cap) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s is not a file belay wrote", shown);
        close(fd);
        errno = EINVAL;
        return -1;
    }
    size_t n = 0;
    for (;;) {
        const ssize_t k = read(fd, buf + n, cap - 1 - n);
        if (k == -1 && errno == EINTR) continue;
        if (k == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", shown);
            close(fd);
            return -1;
        }
        if (k == 0) break;
        n += (size_t)k;
        if (n == cap - 1) {
            char c;
            if (read(fd, &c, 1) == 1) {         /* it grew past the bound */
                belay_err_set(BELAY_ERR_CORRUPT, 0, "%s is not a file belay wrote", shown);
                close(fd);
                errno = EINVAL;
                return -1;
            }
            break;
        }
    }
    close(fd);
    buf[n] = '\0';
    return (ssize_t)n;
}

/* `name` under `dfd`, replaced whole by `len` bytes: a temporary made
 * O_EXCL|O_NOFOLLOW (any stale one, or anything planted there, unlinked
 * first, never followed), synced, renamed over it, the directory synced.
 * Called with the lock held. 0, or -1 with belay_err. */
static int write_whole(int dfd, const char *name, const char *data, size_t len, const char *shown) {
    char tmp[64];
    snprintf(tmp, sizeof tmp, "%s.tmp", name);
    if (unlinkat(dfd, tmp, 0) == -1 && errno != ENOENT) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot write %s", shown);
        return -1;
    }
    const int fd = openat(dfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot write %s", shown);
        return -1;
    }
    size_t w = 0;
    while (w < len) {
        const ssize_t k = write(fd, data + w, len - w);
        if (k == -1 && errno == EINTR) continue;
        if (k <= 0) break;
        w += (size_t)k;
    }
    if (w != len || fsync(fd) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot write %s", shown);
        close(fd);
        unlinkat(dfd, tmp, 0);
        return -1;
    }
    close(fd);
    if (renameat(dfd, tmp, dfd, name) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot write %s", shown);
        unlinkat(dfd, tmp, 0);
        return -1;
    }
    if (fsync(dfd) != 0) { /* in place; only its durability is in doubt */ }
    return 0;
}

/* Every directory above `real` (resolved) must be the user's or root's, and
 * writable by no one else unless sticky: whoever can rename one of them can
 * put another directory where the state root was checked to be (second
 * review 2026-10-31, D2). Group write is allowed for the user's own group.
 * 0, or -1 with belay_err INVALID. */
static int ancestors_safe(const char *real) {
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s", real);
    for (char *slash = strrchr(p, '/'); slash != NULL; slash = strrchr(p, '/')) {
        if (slash == p) slash[1] = '\0';
        else *slash = '\0';
        struct stat a;
        if (lstat(p, &a) == -1) {
            belay_err_set(BELAY_ERR_INVALID, errno, "cannot check %s, above the state directory", p);
            return -1;
        }
        const bool sticky = (a.st_mode & S_ISVTX) != 0;
        if (a.st_uid != geteuid() && a.st_uid != 0) {
            belay_err_set(BELAY_ERR_INVALID, 0, "%s, above the state directory, belongs to uid %lu", p,
                          (unsigned long)a.st_uid);
            return -1;
        }
        if (!sticky && ((a.st_mode & 002) || ((a.st_mode & 020) && a.st_gid != getegid()))) {
            belay_err_set(BELAY_ERR_INVALID, 0, "%s, above the state directory, is writable by others (mode %04o)",
                          p, (unsigned)(a.st_mode & 07777));
            return -1;
        }
        if (strcmp(p, "/") == 0) break;
    }
    return 0;
}

/* Whether `path` is `dir` or below it, both resolved. */
static bool within(const char *path, const char *dir) {
    const size_t n = strlen(dir);
    if (n == 1 && dir[0] == '/') return true;
    return strncmp(path, dir, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

int state_open(const struct scope *sc, bool create, struct state *st, FILE *note) {
    memset(st, 0, sizeof *st);
    st->dir_fd = st->cp_fd = st->lock_fd = -1;
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
    hex[16] = '\0';
    snprintf(st->dir, sizeof st->dir, "%s/scopes/%s", st->root, hex);   /* resolved below, once the root is */
    snprintf(st->store, sizeof st->store, "%s/store", st->dir);
    if (create && mkdir_p(st->root, 0700) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot create the state directory %s", st->root);
        return -1;
    }
    /* The root is named by the environment, so it is followed; everything
     * below it is opened from it. */
    const int rfd = open(st->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rfd == -1) {
        if (errno == ENOENT && !create) return 0;              /* nothing recorded yet */
        belay_err_set(BELAY_ERR_IO, errno, "cannot open the state directory %s", st->root);
        return -1;
    }
    struct stat rs;
    if (fstat(rfd, &rs) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot stat the state directory %s", st->root);
        close(rfd);
        return -1;
    }
    /* Another user's root, or one others can write, could hold links that
     * send belay's writes elsewhere: refused (review 2026-10-31, Phase 5, 1). */
    if (rs.st_uid != geteuid()) {
        belay_err_set(BELAY_ERR_INVALID, 0, "the state directory %s belongs to uid %lu, not to uid %lu",
                      st->root, (unsigned long)rs.st_uid, (unsigned long)geteuid());
        close(rfd);
        return -1;
    }
    if (rs.st_mode & 022) {
        belay_err_set(BELAY_ERR_INVALID, 0, "the state directory %s is writable by others (mode %04o)",
                      st->root, (unsigned)(rs.st_mode & 07777));
        close(rfd);
        return -1;
    }
    st->root_dev = (uint64_t)rs.st_dev;
    st->root_ino = (uint64_t)rs.st_ino;
    /* From here the root is its resolved path, its ancestors checked, and it
     * must still be the directory checked above: the manifest writer and
     * diff reach their files by path (second review 2026-10-31, D1, D2). */
    {
        char *rr = realpath(st->root, NULL);
        struct stat again;
        if (rr == NULL || strlen(rr) >= sizeof st->root - 128 || stat(rr, &again) == -1 ||
            again.st_dev != rs.st_dev || again.st_ino != rs.st_ino) {
            belay_err_set(BELAY_ERR_INVALID, 0, "the state directory %s changed while it was opened", st->root);
            free(rr);
            close(rfd);
            return -1;
        }
        snprintf(st->root, sizeof st->root, "%s", rr);
        free(rr);
    }
    if (ancestors_safe(st->root) == -1) {
        close(rfd);
        return -1;
    }
    snprintf(st->dir, sizeof st->dir, "%s/scopes/%s", st->root, hex);
    snprintf(st->store, sizeof st->store, "%s/store", st->dir);
    /* A scope that is the state directory, or inside it, would record
     * belay's own writes (review 2026-10-31, Phase 5, 9). */
    if (within(sc->path, st->root) || (sc->dev == st->root_dev && sc->ino == st->root_ino)) {
        belay_err_set(BELAY_ERR_INVALID, 0, "the scope %s is belay's state directory %s or inside it",
                      sc->path, st->root);
        close(rfd);
        return -1;
    }
    char shown[PATH_MAX + 96];
    snprintf(shown, sizeof shown, "%s/scopes", st->root);
    const int sfd = dir_at(rfd, "scopes", create, shown);
    close(rfd);
    if (sfd == -1) return errno == ENOENT && !create ? 0 : -1;
    st->dir_fd = dir_at(sfd, hex, create, st->dir);
    close(sfd);
    if (st->dir_fd == -1) return errno == ENOENT && !create ? 0 : -1;

    /* The lock first: nothing in the directory is written without it. */
    if (create) {
        snprintf(shown, sizeof shown, "%s/lock", st->dir);
        /* Made O_EXCL, else the one there opened: captures racing on a
         * first use each made it with a plain O_CREAT, and on macOS some of
         * those opens failed (CI, 2026-10-31: "cannot open .../lock"). */
        for (int tries = 0; tries < 8; tries++) {
            st->lock_fd = openat(st->dir_fd, "lock", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                                 0600);
            if (st->lock_fd != -1 || errno != EEXIST) break;
            st->lock_fd = openat(st->dir_fd, "lock", O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
            if (st->lock_fd != -1 || errno != ENOENT) break;
        }
        struct stat ls;
        if (st->lock_fd == -1 || fstat(st->lock_fd, &ls) == -1 || !S_ISREG(ls.st_mode)) {
            belay_err_set(errno == ELOOP ? BELAY_ERR_CORRUPT : BELAY_ERR_IO, errno, "cannot open %s", shown);
            return -1;
        }
        /* O_NONBLOCK kept a FIFO from hanging the open; a regular file now,
         * it goes, so the blocking flock below does not depend on what a
         * platform does with a nonblocking descriptor. */
        const int fl = fcntl(st->lock_fd, F_GETFL);
        if (fl == -1 || fcntl(st->lock_fd, F_SETFL, fl & ~O_NONBLOCK) == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot lock %s", shown);
            return -1;
        }
        if (flock(st->lock_fd, LOCK_EX | LOCK_NB) == -1) {
            if (errno != EWOULDBLOCK) {
                belay_err_set(BELAY_ERR_IO, errno, "cannot lock %s", shown);
                return -1;
            }
            if (note != NULL) {
                fputs("belay: waiting for another belay working on ", note);
                receipt_fputs(note, sc->path);
                fputs("\n", note);
                fflush(note);
            }
            while (flock(st->lock_fd, LOCK_EX) == -1) {
                if (errno == EINTR) continue;
                belay_err_set(BELAY_ERR_IO, errno, "cannot lock %s", shown);
                return -1;
            }
        }
    }

    /* The scope file names the scope this directory is for: a hash collision,
     * or a directory moved, would be two scopes in one directory, refused. */
    char have[PATH_MAX + 2];
    snprintf(shown, sizeof shown, "%s/scope", st->dir);
    const ssize_t hn = read_small(st->dir_fd, "scope", have, sizeof have, shown);
    if (hn >= 0) {
        if (hn == 0 || have[hn - 1] != '\n' || (size_t)hn - 1 != strlen(sc->path) ||
            memcmp(have, sc->path, (size_t)hn - 1) != 0) {
            have[strcspn(have, "\n")] = '\0';
            belay_err_set(BELAY_ERR_CORRUPT, 0, "%s belongs to the scope %s", st->dir, have);
            return -1;
        }
    } else if (errno != ENOENT) {
        return -1;
    } else if (create) {
        const size_t pl = strlen(sc->path);
        memcpy(have, sc->path, pl);
        have[pl] = '\n';
        if (write_whole(st->dir_fd, "scope", have, pl + 1, shown) == -1) return -1;
    }
    snprintf(shown, sizeof shown, "%s/checkpoints", st->dir);
    st->cp_fd = dir_at(st->dir_fd, "checkpoints", create, shown);
    if (st->cp_fd == -1) return errno == ENOENT && !create ? 0 : -1;
    return 0;
}

void state_close(struct state *st) {
    if (st->lock_fd != -1) close(st->lock_fd);       /* releases the lock */
    if (st->cp_fd != -1) close(st->cp_fd);
    if (st->dir_fd != -1) close(st->dir_fd);
    st->lock_fd = st->cp_fd = st->dir_fd = -1;
}

void state_manifest(const struct state *st, long id, char *buf, size_t cap) {
    snprintf(buf, cap, "%s/checkpoints/%ld/manifest.ndjson", st->dir, id);
}

long state_id_parse(const char *s) {
    if (s == NULL || s[0] < '1' || s[0] > '9') return 0;
    long id = 0;
    for (size_t i = 0; s[i] != '\0'; i++) {
        if (i >= STATE_ID_DIGITS || s[i] < '0' || s[i] > '9') return 0;
        id = id * 10 + (s[i] - '0');
    }
    return id;
}

/* ---- checkpoints ---- */

#define META_MAX 65536      /* a meta.json: a scope path escaped, twice over, fits */

/* Checkpoint `name`'s meta.json into *c. 1; 0 when it has none (a capture
 * that never finished); -1 with belay_err. */
static int read_meta(const struct state *st, const char *name, long id, struct checkpoint *c) {
    char shown[PATH_MAX + 160];
    snprintf(shown, sizeof shown, "%s/checkpoints/%s", st->dir, name);
    const int dfd = dir_at(st->cp_fd, name, false, shown);
    if (dfd == -1) return errno == ENOENT ? 0 : -1;
    static char buf[META_MAX];
    snprintf(shown, sizeof shown, "%s/checkpoints/%s/meta.json", st->dir, name);
    const ssize_t n = read_small(dfd, "meta.json", buf, sizeof buf, shown);
    close(dfd);
    if (n == -1) return errno == ENOENT ? 0 : -1;
    struct jval v;
    if (jsonr_parse(buf, (size_t)n, &v) == -1 || v.t != J_OBJ) {
        if (v.t != J_OBJ) jsonr_free(&v);
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s is not a checkpoint's meta.json", shown);
        return -1;
    }
    memset(c, 0, sizeof *c);
    c->id = (long)jint(&v, "id", -1);
    const struct jval *jid = jget(&v, "id");
    const char *kind = jstr(&v, "kind");
    const struct jval *pf = jget(&v, "prefilter");
    const char *reason = jstr(pf, "full_reason");
    /* What is printed back must be what belay wrote (second review
     * 2026-10-31, D5): an integral id, a known kind, a UTF-8 reason. */
    if (jid == NULL || jid->t != J_NUM || jid->num != (double)jid->i ||
        (strcmp(kind, "check") && strcmp(kind, "mark") && strcmp(kind, "diff")) ||
        !belay_utf8_valid(reason, strlen(reason))) {
        jsonr_free(&v);
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s is not a checkpoint's meta.json", shown);
        return -1;
    }
    snprintf(c->kind, sizeof c->kind, "%s", kind);
    c->created_ns = jint(&v, "created_ns", 0);
    c->entries = (uint64_t)jint(&v, "entries", 0);
    c->raced = (uint64_t)jint(&v, "raced", 0);
    c->unstable = (uint64_t)jint(&v, "unstable", 0);
    c->vanished = (uint64_t)jint(&v, "vanished", 0);
    c->excluded = (uint64_t)jint(&v, "excluded", 0);
    c->walk_start_ns = jint(&v, "walk_start_ns", 0);
    const struct jval *p = jget(&v, "provisional");
    c->provisional = p != NULL && p->t == J_BOOL && p->b;
    const struct jval *used = jget(pf, "used");
    c->walk_start_reference = strcmp(jstr(pf, "reference"), "walk_start") == 0;
    c->full = !(used != NULL && used->t == J_BOOL && used->b);
    snprintf(c->full_reason, sizeof c->full_reason, "%s", jstr(pf, "full_reason"));
    c->trusted = (uint64_t)jint(pf, "trusted", 0);
    c->racy = (uint64_t)jint(pf, "racy", 0);
    jsonr_free(&v);
    if (c->id != id) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s names checkpoint %ld", shown, c->id);
        return -1;
    }
    return 1;
}

static int by_id(const void *a, const void *b) {
    const long x = ((const struct checkpoint *)a)->id, y = ((const struct checkpoint *)b)->id;
    return (x > y) - (x < y);
}

/* checkpoints/, read: each id directory once. The highest id seen, complete
 * or not, into *hi -- the next id is past them all, so a capture that failed
 * half way is never reused; with `list`, the complete ones too. */
static int scan(const struct state *st, struct checkpoint **out, size_t *n, long *hi) {
    if (out != NULL) { *out = NULL; *n = 0; }
    *hi = 0;
    if (st->cp_fd == -1) return 0;
    const int fd = dup(st->cp_fd);
    DIR *d = fd == -1 ? NULL : fdopendir(fd);
    if (d == NULL) {
        if (fd != -1) close(fd);
        belay_err_set(BELAY_ERR_IO, errno, "cannot list %s/checkpoints", st->dir);
        return -1;
    }
    rewinddir(d);
    size_t cap = 0;
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d)) != NULL) {
        const long id = state_id_parse(de->d_name);    /* "05", "+5", 20 digits: not ids */
        if (id == 0) continue;
        if (id > *hi) *hi = id;
        if (out == NULL) continue;
        struct checkpoint c;
        const int got = read_meta(st, de->d_name, id, &c);
        if (got == -1) { rc = -1; break; }
        if (got == 0) continue;                         /* not complete: not a checkpoint */
        if (*n == cap) {
            cap = cap ? cap * 2 : 16;
            struct checkpoint *q = realloc(*out, cap * sizeof *q);
            if (q == NULL) {
                belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
                rc = -1;
                break;
            }
            *out = q;
        }
        (*out)[(*n)++] = c;
    }
    closedir(d);
    if (rc == -1 && out != NULL) {
        free(*out);
        *out = NULL;
        *n = 0;
    }
    if (rc == 0 && out != NULL && *n > 1) qsort(*out, *n, sizeof **out, by_id);
    return rc;
}

int state_list(const struct state *st, struct checkpoint **out, size_t *n) {
    long hi;
    return scan(st, out, n, &hi);
}

/* `s` as a JSON string member: "key":"..." when UTF-8, else
 * "key_b64":"..." (review 2026-10-31, Phase 5, 12). Into buf; -1 when it
 * does not fit. */
int state_json_member(char *buf, size_t cap, const char *key, const char *s) {
    const size_t len = strlen(s);
    const bool utf8 = belay_utf8_valid(s, len);
    const int k = snprintf(buf, cap, "\"%s%s\":\"", key, utf8 ? "" : "_b64");
    if (k < 0 || (size_t)k >= cap) return -1;
    if ((utf8 ? belay_json_escape(buf + k, cap - (size_t)k - 1, s, len)
              : belay_base64_encode(buf + k, cap - (size_t)k - 1, s, len)) == -1) return -1;
    strcat(buf, "\"");
    return 0;
}

const char *state_reference(const struct checkpoint *c) {
    return c->full ? "none" : c->walk_start_reference ? "walk_start" : "newest_ctime";
}

int state_check_manifest(const struct state *st, long id) {
    char name[16], shown[PATH_MAX + 160];
    snprintf(name, sizeof name, "%ld", id);
    snprintf(shown, sizeof shown, "%s/checkpoints/%ld", st->dir, id);
    if (st->cp_fd == -1) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s is missing", shown);
        return -1;
    }
    const int dfd = dir_at(st->cp_fd, name, false, shown);
    if (dfd == -1) {
        if (errno == ENOENT) belay_err_set(BELAY_ERR_CORRUPT, 0, "%s is missing", shown);
        return -1;
    }
    snprintf(shown, sizeof shown, "%s/checkpoints/%ld/manifest.ndjson", st->dir, id);
    const int fd = openat(dfd, "manifest.ndjson", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    const int e = errno;
    close(dfd);
    struct stat fs;
    if (fd == -1 || fstat(fd, &fs) == -1 || !S_ISREG(fs.st_mode)) {
        belay_err_set(fd == -1 && e == ENOENT ? BELAY_ERR_CORRUPT : fd == -1 && e != ELOOP ? BELAY_ERR_IO
                                                                                            : BELAY_ERR_CORRUPT,
                      fd == -1 ? e : 0, "%s is not a manifest belay wrote", shown);
        if (fd != -1) close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int write_meta(const struct state *st, int dfd, const struct checkpoint *c) {
    static char scope[6 * PATH_MAX + 32], why[6 * 160 + 8], buf[META_MAX];
    char shown[PATH_MAX + 128];
    snprintf(shown, sizeof shown, "%s/checkpoints/%ld/meta.json", st->dir, c->id);
    if (state_json_member(scope, sizeof scope, "scope", st->scope.path) == -1 ||
        belay_json_escape(why, sizeof why, c->full_reason, strlen(c->full_reason)) == -1)
        return -1;
    const int n = snprintf(buf, sizeof buf,
            "{\"id\":%ld,\"kind\":\"%s\",\"created_ns\":%lld,%s,\"entries\":%llu,"
            "\"raced\":%llu,\"unstable\":%llu,\"vanished\":%llu,\"provisional\":%s,\"excluded\":%llu,"
            "\"walk_start_ns\":%lld,"
            "\"prefilter\":{\"used\":%s,\"reference\":\"%s\",\"trusted\":%llu,\"racy\":%llu,\"full_reason\":\"%s\"}}\n",
            c->id, c->kind, (long long)c->created_ns, scope, (unsigned long long)c->entries,
            (unsigned long long)c->raced, (unsigned long long)c->unstable, (unsigned long long)c->vanished,
            c->provisional ? "true" : "false", (unsigned long long)c->excluded, (long long)c->walk_start_ns,
            c->full ? "false" : "true", state_reference(c), (unsigned long long)c->trusted,
            (unsigned long long)c->racy, why);
    if (n < 0 || (size_t)n >= sizeof buf) {
        belay_err_set(BELAY_ERR_RANGE, 0, "%s: too large", shown);
        return -1;
    }
    return write_whole(dfd, "meta.json", buf, (size_t)n, shown);
}

static int64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}

int state_capture(struct state *st, const struct capture_req *req, struct checkpoint *out) {
    struct checkpoint *list = NULL;
    size_t n = 0;
    long hi;
    if (scan(st, &list, &n, &hi) == -1) return -1;
    if (hi >= 999999999L) {
        free(list);
        belay_err_set(BELAY_ERR_RANGE, 0, "%s: no checkpoint ids left", st->dir);
        return -1;
    }
    const long id = hi + 1;
    char name[16], dir[PATH_MAX + 128], manifest[PATH_MAX + 160], prev[PATH_MAX + 160];
    snprintf(name, sizeof name, "%ld", id);
    snprintf(dir, sizeof dir, "%s/checkpoints/%ld", st->dir, id);
    if (mkdirat(st->cp_fd, name, 0700) == -1) {
        free(list);
        belay_err_set(BELAY_ERR_IO, errno, "cannot create %s", dir);
        return -1;
    }
    const int dfd = dir_at(st->cp_fd, name, false, dir);
    if (dfd == -1) {
        free(list);
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
    int64_t previous_start = 0;
    if (req->prefilter && n > 0) {
        long since_full = 0;
        for (size_t i = n; i-- > 0 && !list[i].full;) since_full++;
        if (req->force_full) snprintf(c.full_reason, sizeof c.full_reason, "asked for (--full)");
        else if (req->full_every > 0 && since_full + 1 >= req->full_every)
            snprintf(c.full_reason, sizeof c.full_reason, "every %ld marks", req->full_every);
        else {
            /* Opened from the fds first: a link or FIFO planted there is
             * corrupt state, not a manifest to trust (second review, D1). */
            if (state_check_manifest(st, list[n - 1].id) == -1) {
                free(list);
                close(dfd);
                return -1;
            }
            state_manifest(st, list[n - 1].id, prev, sizeof prev);
            previous = prev;
            previous_start = list[n - 1].walk_start_ns;
        }
    } else if (req->prefilter) {
        snprintf(c.full_reason, sizeof c.full_reason, "no checkpoint before");
    }
    free(list);

    struct belay_manifest_opts o = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT, .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
        .store_dir = st->store, .previous = previous, .previous_start_ns = previous_start,
        .exclude = st->root_ino != 0, .exclude_dev = st->root_dev, .exclude_ino = st->root_ino,
        .expect_root = true, .root_dev = st->scope.dev, .root_ino = st->scope.ino,
    };
    struct belay_manifest_stats s;
    if (state_capture_hook != NULL) state_capture_hook(st->scope.path);
    int rc = -1;
    if (belay_manifest_write(manifest, st->scope.path, &o, &s) == -1) goto out;
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
        if (belay_manifest_write(manifest, st->scope.path, &o, &s) == -1) goto out;
    } else if (previous != NULL) {
        c.full = false;
        c.trusted = s.trusted;
        c.racy = s.racy;
        c.walk_start_reference = previous_start > 0;
    }
    c.entries = s.entries;
    c.raced = s.raced;
    c.unstable = s.unstable;
    c.vanished = s.vanished;
    c.excluded = s.excluded;
    c.walk_start_ns = s.walk_start_ns;
    c.provisional = s.raced || s.unstable || s.vanished;
    if (write_meta(st, dfd, &c) == -1) goto out;
    *out = c;
    rc = 0;
out:
    close(dfd);
    return rc;
}
