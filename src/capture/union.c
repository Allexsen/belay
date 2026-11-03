/*
 *  The host reader's union: see union.h, and test/expect/host-reader.md
 *  ("The union", H-U1..H-U10) for every rule below.
 */
#define _GNU_SOURCE
#include "capture/union.h"

#include "belay/error.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/fs.h>                   /* FS_IMMUTABLE_FL, FS_APPEND_FL */
#include <sys/sysmacros.h>
#define PROT_I ((uint64_t)FS_IMMUTABLE_FL)
#define PROT_A ((uint64_t)FS_APPEND_FL)
#else
#define PROT_I 0u
#define PROT_A 0u
#endif

#define LINKS_MAX 40                    /* H-C3 */
#define DIR_FLAGS (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)

struct contrib { int layer, fd; };      /* one layer's directory at a merged path */

/* A directory of the merged view: c[0].fd is the fd capture holds (never
 * closed here unless `owned`); the others are the union's. */
struct udir {
    dev_t dev;
    ino_t ino;
    bool owned;
    char *path;                         /* in the container: "/" or "/a/b" */
    size_t n;
    struct contrib c[];
};

struct union_fs {
    struct fsops ops;                   /* this table; ctx is the union */
    const struct fsops *base;
    size_t n;
    int layer[UNION_LAYERS_MAX];
    char pfx[32];
    size_t pfxl;
    char **mounts;
    size_t nmounts;
    struct udir **dir;                  /* by fd number */
    size_t ndir;
    int root;                           /* the merged "/", the union's own */
    char scope[4096];                   /* the scope union_open_scope resolved */
    ino_t last_ino;                     /* the last file opened, and its layer (in_upper) */
    dev_t last_dev;
    int last_layer;
    char refused[512];
};

/* A listing of a merged directory, or the base's of any other. */
struct ulist { bool merged; void *base; char **names; size_t n, i; };

static void refuse(struct union_fs *u, const char *fmt, ...) {
    if (u->refused[0] != '\0') return;  /* the first reason is the one said */
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(u->refused, sizeof u->refused, fmt, ap);
    va_end(ap);
}

const char *union_refused(const struct union_fs *u) { return u->refused; }

static bool whiteout(const struct stat *st) { return S_ISCHR(st->st_mode) && st->st_rdev == makedev(0, 0); }

/* One of the overlay's xattrs of `fd` (its name after the prefix): its
 * length, or -1 (absent: errno ENODATA). */
static ssize_t ovl_get(struct union_fs *u, int fd, const char *what, char *buf, size_t cap) {
    char name[64];
    snprintf(name, sizeof name, "%s%s", u->pfx, what);
    const struct xsrc x = { .fd = fd, .path = NULL, .own = -1 };
    return u->base->xattr_get(u->base->ctx, &x, name, buf, cap);
}

/* H-U6: the overlay's xattrs belay acts on or ignores; any other refused. */
static bool known_ovl(const char *suffix) {
    static const char *const K[] = { "opaque", "redirect", "protattr", "origin", "impure", "uuid", NULL };
    for (const char *const *k = K; *k != NULL; k++)
        if (strcmp(suffix, *k) == 0) return true;
    return false;
}

static void check_ovl_names(struct union_fs *u, const char *list, size_t len, const char *path) {
    for (size_t i = 0; i < len;) {
        const char *nm = list + i;
        const size_t l = strnlen(nm, len - i);
        if (l > u->pfxl && strncmp(nm, u->pfx, u->pfxl) == 0 && !known_ovl(nm + u->pfxl))
            refuse(u, "H-U6: an overlay xattr belay does not handle (%s) on %s", nm, path);
        i += l + 1;
    }
}

static void check_dir_xattrs(struct union_fs *u, int fd, const char *path) {
    char list[4096];
    const struct xsrc x = { .fd = fd, .path = NULL, .own = -1 };
    const ssize_t ln = u->base->xattr_list(u->base->ctx, &x, list, sizeof list);
    if (ln > 0) check_ovl_names(u, list, (size_t)ln, path);
}

/* The registered directory behind fd, checked by identity: a number now
 * naming something else is forgotten. */
static void drop(struct union_fs *u, int fd) {
    if (fd < 0 || (size_t)fd >= u->ndir || u->dir[fd] == NULL) return;
    struct udir *d = u->dir[fd];
    for (size_t i = 1; i < d->n; i++) close(d->c[i].fd);
    if (d->owned) close(d->c[0].fd);
    free(d->path);
    free(d);
    u->dir[fd] = NULL;
}

static struct udir *dir_of(struct union_fs *u, int fd) {
    if (fd < 0 || (size_t)fd >= u->ndir || u->dir[fd] == NULL) return NULL;
    struct stat st;
    if (u->base->fstat(u->base->ctx, fd, &st) != 0 || st.st_dev != u->dir[fd]->dev ||
        st.st_ino != u->dir[fd]->ino) {
        struct udir *d = u->dir[fd];
        d->owned = false;               /* the number is someone else's now */
        drop(u, fd);
        return NULL;
    }
    return u->dir[fd];
}

/* Registers c[0].fd as a merged directory with these contributors (taken
 * over: closed with it). 0, or -1 with errno, everything closed but c[0]. */
static int reg(struct union_fs *u, const struct contrib *c, size_t n, const char *path, bool owned) {
    const int fd = c[0].fd;
    struct stat st;
    struct udir *d = NULL;
    char *p = strdup(path);
    if (p == NULL || u->base->fstat(u->base->ctx, fd, &st) != 0 ||
        (d = malloc(sizeof *d + n * sizeof d->c[0])) == NULL)
        goto fail;
    if ((size_t)fd >= u->ndir) {
        size_t m = u->ndir ? u->ndir : 64;
        while (m <= (size_t)fd) m *= 2;
        struct udir **t = realloc(u->dir, m * sizeof *t);
        if (t == NULL) goto fail;
        memset(t + u->ndir, 0, (m - u->ndir) * sizeof *t);
        u->dir = t;
        u->ndir = m;
    }
    drop(u, fd);
    *d = (struct udir){ .dev = st.st_dev, .ino = st.st_ino, .owned = owned, .path = p, .n = n };
    memcpy(d->c, c, n * sizeof *c);
    u->dir[fd] = d;
    return 0;
fail: {
        const int e = errno ? errno : ENOMEM;
        free(p);
        free(d);
        for (size_t i = 1; i < n; i++) close(c[i].fd);
        errno = e;
        return -1;
    }
}

static char *join(const char *dir, const char *name) {
    const size_t dl = strcmp(dir, "/") == 0 ? 0 : strlen(dir), nl = strlen(name);
    char *p = malloc(dl + nl + 2);
    if (p == NULL) return NULL;
    memcpy(p, dir, dl);
    p[dl] = '/';
    memcpy(p + dl + 1, name, nl + 1);
    return p;
}

/* H-U1, H-U2: the layer that supplies `name` in `d` -- its directory fd
 * there, and the entry's stat. 0, or -1 with errno (ENOENT: absent, a
 * whiteout included). */
static int find(struct union_fs *u, const struct udir *d, const char *name, int *pfd, struct stat *st) {
    for (size_t i = 0; i < d->n; i++) {
        if (u->base->fstatat(u->base->ctx, d->c[i].fd, name, st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) continue;
            return -1;
        }
        if (whiteout(st)) break;
        *pfd = d->c[i].fd;
        return 0;
    }
    errno = ENOENT;
    return -1;
}

/* A directory at `path` (absolute, in the container) within one layer,
 * component by component, no link followed: its fd, or -1 (ENOENT: none
 * there; ENOTDIR: a whiteout or a non-directory on the way). */
static int layer_dir(struct union_fs *u, int layer, const char *path, bool *stop) {
    *stop = false;
    int fd = u->base->openat(u->base->ctx, u->layer[layer], ".", DIR_FLAGS);
    if (fd == -1) return -1;
    char comp[256];
    for (const char *p = path; *p != '\0';) {
        while (*p == '/') p++;
        if (*p == '\0') break;
        const char *e = strchr(p, '/');
        const size_t l = e != NULL ? (size_t)(e - p) : strlen(p);
        if (l >= sizeof comp) {
            close(fd);
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(comp, p, l);
        comp[l] = '\0';
        p += l;
        struct stat st;
        const int sr = u->base->fstatat(u->base->ctx, fd, comp, &st, AT_SYMLINK_NOFOLLOW);
        if (sr != 0 || !S_ISDIR(st.st_mode)) {
            const int err = sr != 0 && errno == ENOENT ? ENOENT : ENOTDIR;   /* a whiteout or a file: hidden */
            close(fd);
            errno = err;
            return -1;
        }
        const int nfd = u->base->openat(u->base->ctx, fd, comp, DIR_FLAGS);
        close(fd);
        if (nfd == -1) return -1;
        fd = nfd;
        /* an opaque directory on the way: nothing below this layer (the
         * union model's U5, as the kernel looks a path up layer by layer) */
        char v[8];
        while (*p == '/') p++;
        if (*p != '\0' && ovl_get(u, fd, "opaque", v, sizeof v) >= 0) *stop = true;
    }
    return fd;
}

/* A redirect belay follows (the union model's U10): not empty, no NUL; a
 * relative one a single name; an absolute one components that are neither
 * empty, `.` nor `..` ("/" alone included). */
static bool redirect_ok(const char *v, size_t n) {
    if (n == 0 || memchr(v, '\0', n) != NULL) return false;
    if (v[0] != '/') return strchr(v, '/') == NULL && strcmp(v, ".") != 0 && strcmp(v, "..") != 0;
    for (const char *p = v; *p != '\0';) {
        p++;                                            /* past the '/' */
        const char *e = strchr(p, '/');
        const size_t l = e != NULL ? (size_t)(e - p) : strlen(p);
        if (l == 0 || (l == 1 && p[0] == '.') || (l == 2 && p[0] == '.' && p[1] == '.')) return false;
        p += l;
    }
    return true;
}

/* H-U3..H-U5: the directories that make up the merged directory `name` of
 * `d`, topmost first, each opened. Its count (0: not a directory there),
 * or -1 with errno. */
static ssize_t stack(struct union_fs *u, const struct udir *d, const char *name, struct contrib *out) {
    char *path = join(d->path, name);
    if (path == NULL) return -1;
    char look[4096];                    /* the name in the parent, or the path from the root */
    bool abs = false, redirected = false;
    snprintf(look, sizeof look, "%s", name);
    size_t n = 0;
    const int top = d->c[0].layer;
    for (int L = top; L < (int)u->n; L++) {
        int fd = -1;
        bool stop = false;
        if (abs) {
            fd = layer_dir(u, L, look, &stop);
            if (fd == -1 && errno == ENOENT) {
                if (stop) break;
                continue;
            }
            if (fd == -1 && errno == ENOTDIR) break;          /* hidden from here down */
            if (fd == -1) goto err;
        } else {
            int pfd = -1;
            for (size_t i = 0; i < d->n; i++)
                if (d->c[i].layer == L) pfd = d->c[i].fd;
            if (pfd == -1) continue;                          /* the parent is not in this layer */
            struct stat st;
            if (u->base->fstatat(u->base->ctx, pfd, look, &st, AT_SYMLINK_NOFOLLOW) != 0) {
                if (errno == ENOENT) continue;
                goto err;
            }
            if (whiteout(&st) || !S_ISDIR(st.st_mode)) break;  /* a whiteout, or a non-directory: below is hidden */
            fd = u->base->openat(u->base->ctx, pfd, look, DIR_FLAGS);
            if (fd == -1) goto err;
        }
        out[n++] = (struct contrib){ L, fd };
        redirected = false;
        if (stop) break;
        check_dir_xattrs(u, fd, path);
        char v[4096];
        ssize_t vl = ovl_get(u, fd, "opaque", v, sizeof v);
        if (vl >= 0) {
            if (!(vl == 1 && v[0] == 'y')) refuse(u, "H-U3: an opaque value other than y on %s", path);
            break;
        }
        vl = ovl_get(u, fd, "redirect", v, sizeof v - 1);
        if (vl >= 0) {
            v[vl] = '\0';
            if (!redirect_ok(v, (size_t)vl)) {
                refuse(u, "H-U5: a malformed redirect on %s", path);
                break;
            }
            if (v[0] == '/') {
                abs = true;
                snprintf(look, sizeof look, "%s", v);
            } else if (strchr(v, '/') != NULL) {
                refuse(u, "H-U5: a relative redirect with a slash on %s", path);
                break;
            } else if (abs) {                                  /* the same parent, from the root */
                char *sl = strrchr(look, '/');
                if (sl != NULL) sl[1] = '\0';
                const size_t ll = strlen(look), rl = strlen(v);
                if (ll + rl >= sizeof look) {
                    refuse(u, "H-U5: a redirect on %s too long", path);
                    break;
                }
                memcpy(look + ll, v, rl + 1);
            } else {
                snprintf(look, sizeof look, "%s", v);
            }
            redirected = true;
        }
    }
    if (redirected) refuse(u, "H-U5: a redirect on %s that no layer below holds", path);
    free(path);
    return (ssize_t)n;
err: {
        const int e = errno;
        for (size_t i = 0; i < n; i++) close(out[i].fd);
        free(path);
        errno = e;
        return -1;
    }
}

static bool is_mount(const struct union_fs *u, const char *dir, const char *name) {
    char *p = join(dir, name);
    bool m = false;
    for (size_t i = 0; p != NULL && i < u->nmounts && !m; i++) m = strcmp(p, u->mounts[i]) == 0;
    free(p);
    return m;
}

/* ---- the table ---- */

static int u_stat_mount(void *ctx, int dfd, const char *name, struct stat *st, bool *mount_root, bool *mount_known) {
    struct union_fs *u = ctx;
    const struct udir *d = dir_of(u, dfd);
    if (d == NULL) return u->base->stat_mount(u->base->ctx, dfd, name, st, mount_root, mount_known);
    *mount_known = true;                /* the container's mount table says (H-M5) */
    *mount_root = false;
    if (name[0] == '\0') return u->base->fstat(u->base->ctx, dfd, st);
    int pfd;
    if (find(u, d, name, &pfd, st) != 0) return -1;
    *mount_root = is_mount(u, d->path, name);
    if (!S_ISDIR(st->st_mode)) {                       /* H-U3, H-U5: those are a directory's alone */
        struct xsrc x = { .fd = -1, .path = NULL, .own = -1 };
        if (u->base->xattr_source_open(u->base->ctx, pfd, name, st, &x) == 0) {
            char v[8];
            char nm[64];
            snprintf(nm, sizeof nm, "%sopaque", u->pfx);
            if (u->base->xattr_get(u->base->ctx, &x, nm, v, sizeof v) >= 0)
                refuse(u, "H-U3: an opaque xattr on a non-directory, %s/%s", d->path, name);
            snprintf(nm, sizeof nm, "%sredirect", u->pfx);
            if (u->base->xattr_get(u->base->ctx, &x, nm, v, sizeof v) >= 0 || errno == ERANGE)
                refuse(u, "H-U5: a redirect on a non-directory, %s/%s", d->path, name);
            u->base->xattr_source_close(u->base->ctx, &x);
        }
    }
    return 0;
}

static int u_fstatat(void *ctx, int dfd, const char *name, struct stat *st, int flags) {
    struct union_fs *u = ctx;
    /* the scope by its path (consistency's end-of-walk re-check): resolved
     * again in the container, never on the host */
    if (dfd == AT_FDCWD && u->scope[0] != '\0' && strcmp(name, u->scope) == 0) {
        char canon[4096];
        char keep[sizeof u->scope];
        memcpy(keep, u->scope, sizeof keep);
        const int fd = union_open_scope(u, keep, canon, sizeof canon);
        if (fd == -1) {
            belay_err_clear();
            errno = ENOENT;
            return -1;
        }
        const int r = u->base->fstat(u->base->ctx, fd, st);
        close(fd);
        return r;
    }
    const struct udir *d = dir_of(u, dfd);
    if (d == NULL || name[0] == '\0' || strcmp(name, ".") == 0)
        return u->base->fstatat(u->base->ctx, dfd, name, st, flags);
    int pfd;
    if (find(u, d, name, &pfd, st) != 0) return -1;
    return (flags & AT_SYMLINK_NOFOLLOW) || !S_ISLNK(st->st_mode) ? 0
         : u->base->fstatat(u->base->ctx, pfd, name, st, flags);
}

static int u_fstat(void *ctx, int fd, struct stat *st) {
    struct union_fs *u = ctx;
    return u->base->fstat(u->base->ctx, fd, st);
}

static int u_openat(void *ctx, int dfd, const char *name, int flags) {
    struct union_fs *u = ctx;
    const struct udir *d = dir_of(u, dfd);
    if (d == NULL) {
        const int fd = u->base->openat(u->base->ctx, dfd, name, flags);
        if (fd >= 0) drop(u, fd);
        return fd;
    }
    if (name[0] == '\0' || strcmp(name, ".") == 0) {      /* the same merged directory, again */
        struct contrib c[UNION_LAYERS_MAX];
        c[0] = (struct contrib){ d->c[0].layer, u->base->openat(u->base->ctx, dfd, ".", flags) };
        if (c[0].fd == -1) return -1;
        size_t n = 1;
        for (size_t i = 1; i < d->n; i++) {      /* a new open each: a dup would share its offset */
            c[n] = (struct contrib){ d->c[i].layer, u->base->openat(u->base->ctx, d->c[i].fd, ".", DIR_FLAGS) };
            if (c[n].fd == -1) break;
            n++;
        }
        if (n != d->n || reg(u, c, n, d->path, false) != 0) {
            const int e = errno;
            for (size_t i = 0; i < n; i++) close(c[i].fd);
            errno = e;
            return -1;
        }
        return c[0].fd;
    }
    int pfd;
    struct stat st;
    if (find(u, d, name, &pfd, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) {
        const int fd = u->base->openat(u->base->ctx, pfd, name, flags);
        if (fd >= 0) {
            drop(u, fd);
            u->last_ino = st.st_ino;
            u->last_dev = st.st_dev;
            u->last_layer = -1;
            for (size_t i = 0; i < d->n; i++)
                if (d->c[i].fd == pfd) u->last_layer = d->c[i].layer;
        }
        return fd;
    }
    struct contrib c[UNION_LAYERS_MAX];
    const ssize_t n = stack(u, d, name, c);
    if (n <= 0) {
        if (n == 0) errno = ENOENT;
        return -1;
    }
    char *p = join(d->path, name);
    if (p == NULL || reg(u, c, (size_t)n, p, false) != 0) {
        const int e = errno ? errno : ENOMEM;
        if (p == NULL)
            for (ssize_t i = 1; i < n; i++) close(c[i].fd);
        close(c[0].fd);
        free(p);
        errno = e;
        return -1;
    }
    free(p);
    return c[0].fd;
}

static ssize_t u_readlinkat(void *ctx, int dfd, const char *name, char *buf, size_t n) {
    struct union_fs *u = ctx;
    const struct udir *d = dir_of(u, dfd);
    if (d == NULL) return u->base->readlinkat(u->base->ctx, dfd, name, buf, n);
    int pfd;
    struct stat st;
    if (find(u, d, name, &pfd, &st) != 0) return -1;
    return u->base->readlinkat(u->base->ctx, pfd, name, buf, n);
}

static ssize_t u_read(void *ctx, int fd, void *buf, size_t n) {
    struct union_fs *u = ctx;
    return u->base->read(u->base->ctx, fd, buf, n);
}

static int by_name(const void *a, const void *b) {
    const char *const *x = a, *const *y = b;
    return strcmp(*x, *y);
}

/* The merged listing (H-U2, H-U4): every name of every contributor, each
 * once, the topmost spelling deciding -- a whiteout hides it. Names carry
 * their layer rank in a prefix while sorted, so the topmost sorts first. */
static void *u_dir_open(void *ctx, int dfd) {
    struct union_fs *u = ctx;
    struct ulist *l = calloc(1, sizeof *l);
    if (l == NULL) return NULL;
    const struct udir *d = dir_of(u, dfd);
    if (d == NULL) {
        l->base = u->base->dir_open(u->base->ctx, dfd);
        if (l->base == NULL) {
            free(l);
            return NULL;
        }
        return l;
    }
    l->merged = true;
    size_t cap = 0, all = 0;
    char **raw = NULL;
    for (size_t i = 0; i < d->n; i++) {
        /* each contributor listed through a new open of it: a stream shares
         * its offset with every dup of the fd, and an earlier listing ran
         * to the end (consistency.c's relist says the same of the walk) */
        const int lfd = u->base->openat(u->base->ctx, d->c[i].fd, ".", DIR_FLAGS);
        void *it = lfd == -1 ? NULL : u->base->dir_open(u->base->ctx, lfd);
        if (lfd != -1) close(lfd);
        if (it == NULL) goto fail;
        const char *nm;
        while ((nm = u->base->dir_next(u->base->ctx, it)) != NULL) {
            if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0) continue;
            struct stat st;
            const bool wo = u->base->fstatat(u->base->ctx, d->c[i].fd, nm, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
                            whiteout(&st);
            if (all == cap) {
                cap = cap ? 2 * cap : 64;
                char **t = realloc(raw, cap * sizeof *t);
                if (t == NULL) {
                    u->base->dir_close(u->base->ctx, it);
                    goto fail;
                }
                raw = t;
            }
            /* name, NUL, rank (3 digits), whiteout flag: sorts by name, then rank */
            const size_t nl = strlen(nm);
            char *e = malloc(nl + 6);
            if (e == NULL) {
                u->base->dir_close(u->base->ctx, it);
                goto fail;
            }
            memcpy(e, nm, nl + 1);
            snprintf(e + nl + 1, 5, "%03u%c", (unsigned)i % 1000u, wo ? 'w' : '-');   /* i < UNION_LAYERS_MAX */
            raw[all++] = e;
        }
        const int err = errno;
        u->base->dir_close(u->base->ctx, it);
        if (err != 0) {
            errno = err;
            goto fail;
        }
    }
    /* by name (up to its NUL); among equal names, the lowest rank wins */
    if (all > 1) qsort(raw, all, sizeof *raw, by_name);   /* raw is NULL when the directory is empty */
    l->names = malloc((all ? all : 1) * sizeof *l->names);
    if (l->names == NULL) goto fail;
    for (size_t i = 0; i < all;) {
        size_t best = i;
        size_t j = i;
        while (j < all && strcmp(raw[j], raw[i]) == 0) {
            if (strcmp(raw[j] + strlen(raw[j]) + 1, raw[best] + strlen(raw[best]) + 1) < 0) best = j;
            j++;
        }
        if (raw[best][strlen(raw[best]) + 4] != 'w') l->names[l->n++] = raw[best];
        else free(raw[best]);
        for (size_t k = i; k < j; k++)
            if (k != best) free(raw[k]);
        i = j;
    }
    free(raw);
    return l;
fail: {
        const int e = errno ? errno : ENOMEM;
        for (size_t i = 0; i < all; i++) free(raw[i]);
        free(raw);
        free(l->names);
        free(l);
        errno = e;
        return NULL;
    }
}

static const char *u_dir_next(void *ctx, void *dir) {
    struct union_fs *u = ctx;
    struct ulist *l = dir;
    if (!l->merged) return u->base->dir_next(u->base->ctx, l->base);
    errno = 0;
    return l->i < l->n ? l->names[l->i++] : NULL;
}

static void u_dir_close(void *ctx, void *dir) {
    struct union_fs *u = ctx;
    struct ulist *l = dir;
    if (!l->merged) u->base->dir_close(u->base->ctx, l->base);
    for (size_t i = 0; i < l->n; i++) free(l->names[i]);
    free(l->names);
    free(l);
}

static int u_xattr_source_open(void *ctx, int pfd, const char *name, const struct stat *st, struct xsrc *x) {
    struct union_fs *u = ctx;
    const struct udir *d = dir_of(u, pfd);
    if (d == NULL) return u->base->xattr_source_open(u->base->ctx, pfd, name, st, x);
    int lfd;
    struct stat s;
    if (find(u, d, name, &lfd, &s) != 0) return -1;
    return u->base->xattr_source_open(u->base->ctx, lfd, name, st, x);
}

static void u_xattr_source_close(void *ctx, struct xsrc *x) {
    struct union_fs *u = ctx;
    u->base->xattr_source_close(u->base->ctx, x);
}

/* H-U6: the overlay's own xattrs are not the file's; one belay does not
 * know is refused. */
static ssize_t u_xattr_list(void *ctx, const struct xsrc *x, char *buf, size_t n) {
    struct union_fs *u = ctx;
    const ssize_t ln = u->base->xattr_list(u->base->ctx, x, buf, n);
    if (ln <= 0) return ln;
    check_ovl_names(u, buf, (size_t)ln, "an entry");
    size_t w = 0;
    for (size_t i = 0; i < (size_t)ln;) {
        const size_t l = strnlen(buf + i, (size_t)ln - i);
        if (!(l >= u->pfxl && strncmp(buf + i, u->pfx, u->pfxl) == 0)) {
            memmove(buf + w, buf + i, l + 1);
            w += l + 1;
        }
        i += l + 1;
    }
    return (ssize_t)w;
}

static ssize_t u_xattr_get(void *ctx, const struct xsrc *x, const char *name, void *buf, size_t n) {
    struct union_fs *u = ctx;
    if (strncmp(name, u->pfx, u->pfxl) == 0) {
        errno = ENODATA;
        return -1;
    }
    return u->base->xattr_get(u->base->ctx, x, name, buf, n);
}

/* Whether the open file `fd` (stat `st`) is the upper layer's: a merged
 * directory by its topmost layer; a file by the last one opened through the
 * union, which capture reads right after opening it. */
static bool in_upper(struct union_fs *u, int fd, const struct stat *st) {
    const struct udir *d = dir_of(u, fd);
    if (d != NULL) return d->c[0].layer == 0;
    return st->st_ino == u->last_ino && st->st_dev == u->last_dev && u->last_layer == 0;
}

/* H-U8: the layer file's flags, with protattr's added -- from the upper
 * layer only, where the kernel reads it (the union model's U15, probed). */
static int u_inode_flags(void *ctx, int fd, const struct stat *st, uint64_t *out) {
    struct union_fs *u = ctx;
    int r = u->base->inode_flags(u->base->ctx, fd, st, out);
    if (fd < 0 || !in_upper(u, fd, st)) return r;
    char v[16];
    const ssize_t vl = ovl_get(u, fd, "protattr", v, sizeof v);
    if (vl < 0) return r;
    if (vl == 0) refuse(u, "H-U8: an empty protattr%s", "");
    uint64_t f = r == 0 ? *out : 0;
    for (ssize_t i = 0; i < vl; i++) {
        if (v[i] == 'i') f |= PROT_I;
        else if (v[i] == 'a') f |= PROT_A;
        else refuse(u, "H-U8: a protattr value belay does not know (%.*s)", (int)vl, v);
    }
    *out = f;
    return 0;
}

static bool u_is_overlay(void *ctx, int root_fd) {
    (void)ctx;
    (void)root_fd;
    return false;                       /* the layers are read, not the overlay */
}

static int u_writer_present(void *ctx, int fd) {
    struct union_fs *u = ctx;
    return u->base->writer_present(u->base->ctx, fd);
}

static void u_probe_begin(void *ctx) {
    struct union_fs *u = ctx;
    u->base->probe_begin(u->base->ctx);
}

static void u_probe_end(void *ctx) {
    struct union_fs *u = ctx;
    u->base->probe_end(u->base->ctx);
}

static int u_clock(void *ctx, struct timespec *ts) {
    struct union_fs *u = ctx;
    return u->base->clock(u->base->ctx, ts);
}

static FILE *u_tmpfile_in(void *ctx, const char *dir, const char *tmpl) {
    struct union_fs *u = ctx;
    return u->base->tmpfile_in(u->base->ctx, dir, tmpl);
}

static int u_fsync(void *ctx, int fd) {
    struct union_fs *u = ctx;
    return u->base->fsync(u->base->ctx, fd);
}

static int u_barrier(void *ctx, int fd) {
    struct union_fs *u = ctx;
    return u->base->barrier(u->base->ctx, fd);
}

const struct fsops *union_ops(struct union_fs *u) { return &u->ops; }

/* ---- construction ---- */

struct union_fs *union_new(const struct fsops *base, const int *layer_fds, size_t n, const char *prefix,
                           const char *const *mounts, size_t nmounts) {
    if (n == 0 || n > UNION_LAYERS_MAX || strlen(prefix) >= sizeof ((struct union_fs *)0)->pfx) {
        belay_err_set(BELAY_ERR_INVALID, 0, "union: %zu layers (at most %d)", n, UNION_LAYERS_MAX);
        return NULL;
    }
    struct union_fs *u = calloc(1, sizeof *u);
    if (u == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, errno, "union");
        return NULL;
    }
    u->ops = (struct fsops){
        .ctx = u, .stat_mount = u_stat_mount, .fstatat = u_fstatat, .fstat = u_fstat, .openat = u_openat,
        .readlinkat = u_readlinkat, .read = u_read, .dir_open = u_dir_open, .dir_next = u_dir_next,
        .dir_close = u_dir_close, .xattr_source_open = u_xattr_source_open,
        .xattr_source_close = u_xattr_source_close, .xattr_list = u_xattr_list, .xattr_get = u_xattr_get,
        .inode_flags = u_inode_flags, .is_overlay = u_is_overlay, .writer_present = u_writer_present,
        .probe_begin = u_probe_begin, .probe_end = u_probe_end, .clock = u_clock, .tmpfile_in = u_tmpfile_in,
        .fsync = u_fsync, .barrier = u_barrier,
    };
    u->base = base;
    u->n = n;
    u->root = -1;
    memcpy(u->layer, layer_fds, n * sizeof *layer_fds);
    snprintf(u->pfx, sizeof u->pfx, "%s", prefix);
    u->pfxl = strlen(u->pfx);
    if (nmounts > 0) {
        u->mounts = calloc(nmounts, sizeof *u->mounts);
        if (u->mounts == NULL) goto nomem;
        for (; u->nmounts < nmounts; u->nmounts++)
            if ((u->mounts[u->nmounts] = strdup(mounts[u->nmounts])) == NULL) goto nomem;
    }
    /* "/": every layer's root -- the kernel ignores `opaque` and `redirect`
     * on a layer's root (the union model's U8, probed: every root merges) */
    struct contrib c[UNION_LAYERS_MAX];
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        c[k] = (struct contrib){ (int)i, base->openat(base->ctx, layer_fds[i], ".", DIR_FLAGS) };
        if (c[k].fd == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "union: cannot open layer %zu", i);
            for (size_t j = 0; j < k; j++) close(c[j].fd);
            union_free(u);
            return NULL;
        }
        check_dir_xattrs(u, c[k].fd, "/");
        k++;
    }
    if (reg(u, c, k, "/", true) != 0) {
        belay_err_set(BELAY_ERR_NOMEM, errno, "union");
        close(c[0].fd);
        union_free(u);
        return NULL;
    }
    u->root = c[0].fd;
    return u;
nomem:
    belay_err_set(BELAY_ERR_NOMEM, errno, "union");
    union_free(u);
    return NULL;
}

void union_free(struct union_fs *u) {
    if (u == NULL) return;
    for (size_t fd = 0; fd < u->ndir; fd++) {
        if (u->dir[fd] == NULL) continue;
        /* a primary capture held is closed by capture; only the union's own */
        drop(u, (int)fd);
    }
    free(u->dir);
    for (size_t i = 0; i < u->n; i++) close(u->layer[i]);
    for (size_t i = 0; i < u->nmounts; i++) free(u->mounts[i]);
    free(u->mounts);
    free(u);
}

/* ---- the scope (H-C3) ---- */

int union_open_scope(struct union_fs *u, const char *path, char *canon, size_t cap) {
    if (path[0] != '/') {
        belay_err_set(BELAY_ERR_INVALID, 0, "--scope with --docker is a path inside the container: absolute");
        return -1;
    }
    char pending[8192], done[4096] = "";
    snprintf(pending, sizeof pending, "%s", path);
    int links = 0;
    int cur = u_openat(u, u->root, ".", DIR_FLAGS);
    if (cur == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "union: the container's root");
        return -1;
    }
    char *p = pending;
    while (*p != '\0') {
        while (*p == '/') p++;
        if (*p == '\0') break;
        char comp[256];
        const char *e = strchr(p, '/');
        const size_t l = e != NULL ? (size_t)(e - p) : strlen(p);
        if (l >= sizeof comp) goto toolong;
        memcpy(comp, p, l);
        comp[l] = '\0';
        p += l;
        if (strcmp(comp, ".") == 0) continue;
        if (strcmp(comp, "..") != 0) {                /* a name looked up inside a mount: not the layers' (U18) */
            const char *here = done[0] != '\0' ? done : "/";
            for (size_t i = 0; i < u->nmounts; i++) {
                const size_t ml = strlen(u->mounts[i]);
                if (strncmp(here, u->mounts[i], ml) == 0 && (here[ml] == '\0' || here[ml] == '/')) {
                    belay_err_set(BELAY_ERR_INVALID, 0, "--scope %s: the scope's path enters another mount, %s "
                                  "(host-reader H-C3)", path, u->mounts[i]);
                    close(cur);
                    return -1;
                }
            }
        }
        if (strcmp(comp, "..") == 0) {                /* back up; at the root, stay */
            char *sl = strrchr(done, '/');
            if (sl != NULL) *sl = '\0';
            close(cur);
            cur = u_openat(u, u->root, ".", DIR_FLAGS);
            for (char *q = done; cur != -1 && *q != '\0';) {
                char c2[256];
                q++;
                const char *e2 = strchr(q, '/');
                const size_t l2 = e2 != NULL ? (size_t)(e2 - q) : strlen(q);
                memcpy(c2, q, l2);
                c2[l2] = '\0';
                q += l2;
                const int nx = u_openat(u, cur, c2, DIR_FLAGS);
                close(cur);
                cur = nx;
            }
            if (cur == -1) goto io;
            continue;
        }
        struct stat st;
        if (u_fstatat(u, cur, comp, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (u->refused[0] != '\0') {              /* met on the way: said first */
                belay_err_set(BELAY_ERR_INVALID, 0, "--scope %s: %s", path, u->refused);
                close(cur);
                return -1;
            }
            belay_err_set(BELAY_ERR_INVALID, 0, "--scope %s: %s%s/%s does not exist in the container (host-reader H-C3)", path,
                          errno == ENOENT ? "" : "(cannot read) ", done, comp);
            close(cur);
            return -1;
        }
        if (S_ISLNK(st.st_mode)) {
            if (++links > LINKS_MAX) {
                belay_err_set(BELAY_ERR_INVALID, 0, "--scope %s: more than %d symbolic links (host-reader H-C3)", path, LINKS_MAX);
                close(cur);
                return -1;
            }
            char t[4096];
            const ssize_t tl = u_readlinkat(u, cur, comp, t, sizeof t - 1);
            if (tl <= 0) goto io;
            t[tl] = '\0';
            char rest[8192];
            snprintf(rest, sizeof rest, "%s/%s", t, p);
            snprintf(pending, sizeof pending, "%s", rest);
            p = pending;
            if (t[0] == '/') {                       /* from the container's root */
                done[0] = '\0';
                close(cur);
                cur = u_openat(u, u->root, ".", DIR_FLAGS);
                if (cur == -1) goto io;
            }
            continue;
        }
        if (!S_ISDIR(st.st_mode)) {
            belay_err_set(BELAY_ERR_INVALID, 0, "--scope %s: %s/%s is not a directory (host-reader H-C3)", path, done, comp);
            close(cur);
            return -1;
        }
        const int nx = u_openat(u, cur, comp, DIR_FLAGS);
        close(cur);
        cur = nx;
        if (cur == -1) goto io;
        if (strlen(done) + l + 2 > sizeof done) goto toolong;
        strcat(done, "/");
        strcat(done, comp);
    }
    if (done[0] == '\0') strcpy(done, "/");
    /* neither a mount point nor below one: the overlay does not hold it */
    for (size_t i = 0; i < u->nmounts; i++) {
        const size_t ml = strlen(u->mounts[i]);
        if (strncmp(done, u->mounts[i], ml) == 0 && (done[ml] == '\0' || done[ml] == '/')) {
            belay_err_set(BELAY_ERR_INVALID, 0,
                          "--scope %s: %s is a volume or bind mount (%s), not in the container's layers: "
                          "capture its host source as a scope of its own, without --docker (host-reader H-C3)",
                          path, done, u->mounts[i]);
            close(cur);
            return -1;
        }
    }
    /* H-M5: every mount point below the scope is an entry of the union,
     * reached from the root without a link (the union model's U17) */
    const size_t dl = strcmp(done, "/") == 0 ? 0 : strlen(done);
    for (size_t i = 0; i < u->nmounts; i++) {
        const char *m = u->mounts[i];
        if (strncmp(m, done, dl) != 0 || m[dl] != '/' || m[dl + 1] == '\0') continue;
        bool nested = false;                                 /* below another mount: not read (U18) */
        for (size_t j = 0; j < u->nmounts && !nested; j++) {
            const size_t ml = strlen(u->mounts[j]);
            nested = j != i && ml < strlen(m) && strncmp(m, u->mounts[j], ml) == 0 && m[ml] == '/';
        }
        if (nested) continue;
        int at = u_openat(u, u->root, ".", DIR_FLAGS);
        bool ok = at != -1;
        char comp[256];
        for (const char *q = m + 1; ok && *q != '\0';) {
            const char *e2 = strchr(q, '/');
            const size_t l2 = e2 != NULL ? (size_t)(e2 - q) : strlen(q);
            if (l2 == 0 || l2 >= sizeof comp) { ok = false; break; }
            memcpy(comp, q, l2);
            comp[l2] = '\0';
            q += l2 + (e2 != NULL);
            struct stat ms;
            if (u_fstatat(u, at, comp, &ms, AT_SYMLINK_NOFOLLOW) != 0) { ok = false; break; }
            if (*q == '\0') break;                          /* the mount point itself: any type */
            if (!S_ISDIR(ms.st_mode)) { ok = false; break; }
            const int nx = u_openat(u, at, comp, DIR_FLAGS);
            close(at);
            at = nx;
            ok = at != -1;
        }
        if (at != -1) close(at);
        if (!ok) {
            belay_err_set(BELAY_ERR_INVALID, 0, "--scope %s: the mount point %s is not in the container's layers "
                          "(host-reader H-M5)", path, m);
            close(cur);
            return -1;
        }
    }
    snprintf(canon, cap, "%s", done);
    snprintf(u->scope, sizeof u->scope, "%s", done);
    return cur;
toolong:
    belay_err_set(BELAY_ERR_INVALID, 0, "--scope %s: too long", path);
    close(cur);
    return -1;
io:
    belay_err_set(BELAY_ERR_IO, errno, "--scope %s: cannot read the container's layers", path);
    if (cur != -1) close(cur);
    return -1;
}
