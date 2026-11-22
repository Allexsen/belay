/*
 *  The roots of a capture of a whole machine (test/expect/watch-system.md,
 *  WS-6 to WS-9), resolved as the machine is when the capture starts: the
 *  fixed lists, and three roots and twelve files for every home directory of
 *  its etc/passwd that can be one (WS-8a).
 *
 *  BLAST RADIUS: reads the scope's etc/passwd and stats directories under
 *  the scope, each from the scope's descriptor, never through a symbolic
 *  link. What it returns is a list of relative paths: the walk that uses it
 *  opens every component itself, without following links (walk.c), so a
 *  path that changed since is recorded as it is then, never followed.
 */
#define _GNU_SOURCE
#include "belay/manifest.h"

#include "belay/error.h"
#include "belay/json.h"
#include "fsops.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* WS-6: read. */
static const char *const CONTENT[] = { "etc", "usr/local", "root", "var/spool/cron", "var/lib/dpkg",
                                       "var/lib/apt/extended_states", "usr/lib/systemd", "boot/grub/grub.cfg" };
/* WS-7: statted and opened, never read. The second list, when directories. */
static const char *const METADATA[] = { "usr", "var", "opt", "srv", "boot" };
static const char *const METADATA_IF_DIR[] = { "bin", "sbin", "lib", "lib32", "lib64", "libx32" };
/* WS-8: under the roots, not entered. */
static const char *const NOT_READ[] = { "var/log", "var/cache", "var/tmp", "var/lib/docker", "var/lib/containerd",
                                        "var/lib/snapd", "var/snap" };
/* WS-6: in every home. The files are the shell startup files: listed found
 * or not, and never sealed (manifest-v5 V5-E5). */
static const char *const HOME_DIRS[] = { ".ssh", ".config/systemd/user" };
static const char *const HOME_FILES[] = { ".profile", ".bash_profile", ".bash_login", ".bashrc", ".bash_logout",
                                          ".zshenv", ".zprofile", ".zshrc", ".zlogin", ".cshrc", ".login",
                                          ".config/fish/config.fish" };
#define N(a) (sizeof(a) / sizeof(a)[0])

struct build {
    struct belay_root *roots;
    size_t n, cap;
    char *names;
    size_t used, names_cap;
    bool oom;
};

/* The roots point into `names` by offset until the list is whole (the
 * buffer moves as it grows). */
static void add(struct build *b, const char *dir, const char *leaf, enum belay_root_class cls, bool plain) {
    const size_t dl = dir != NULL ? strlen(dir) : 0, ll = strlen(leaf), need = dl + (dl ? 1 : 0) + ll + 1;
    if (b->oom) return;
    if (b->n == b->cap) {
        const size_t nc = b->cap ? b->cap * 2 : 64;
        struct belay_root *r = realloc(b->roots, nc * sizeof *r);
        if (r == NULL) { b->oom = true; return; }
        b->roots = r;
        b->cap = nc;
    }
    if (b->used + need > b->names_cap) {
        const size_t nc = (b->names_cap ? b->names_cap * 2 : 4096) + need;
        char *s = realloc(b->names, nc);
        if (s == NULL) { b->oom = true; return; }
        b->names = s;
        b->names_cap = nc;
    }
    char *p = b->names + b->used;
    if (dl) { memcpy(p, dir, dl); p[dl] = '/'; }
    memcpy(p + dl + (dl ? 1 : 0), leaf, ll + 1);
    b->roots[b->n++] = (struct belay_root){ .path = (const char *)(uintptr_t)b->used, .cls = cls, .plain = plain };
    b->used += need;
}

static int by_path(const void *a, const void *b) {
    return strcmp(((const struct belay_root *)a)->path, ((const struct belay_root *)b)->path);
}

/* Whether `rel` under the scope is a directory itself, not a link to one. */
static bool is_dir(int root_fd, const char *rel) {
    struct stat st;
    return fstatat(root_fd, rel, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(st.st_mode);
}

static bool at_or_under(const char *path, const char *dir) {
    const size_t n = strlen(dir);
    return strncmp(path, dir, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

/*
 *  WS-8a: a home is used only when it is an absolute path other than "/",
 *  every component of it is a real directory (no symbolic link), it is on a
 *  filesystem the capture enters, and it does not lie in a not-read
 *  directory of WS-8. `home` is relative to the scope here (the leading "/"
 *  taken off), canonical.
 */
static bool home_usable(const struct fsops *ops, int root_fd, uint64_t root_dev, char *home, char **table, bool *asked) {
    for (size_t i = 0; i < N(NOT_READ); i++)
        if (at_or_under(home, NOT_READ[i])) return false;
    /* Each prefix in turn: a link anywhere on the way is refused before
     * anything is looked up through it. */
    for (char *s = home; ; s++) {
        if (*s != '/' && *s != '\0') continue;
        const char keep = *s;
        *s = '\0';
        struct stat st;
        bool mr = false, mk = false;
        int r = ops->stat_mount(ops->ctx, root_fd, home, &st, &mr, &mk);
        if (r != 0) {                   /* no statx here: lstat, and the device decides */
            mk = false;
            r = fstatat(root_fd, home, &st, AT_SYMLINK_NOFOLLOW);
        }
        const bool dir = r == 0 && S_ISDIR(st.st_mode);
        const bool mount = dir && (mk ? mr : (uint64_t)st.st_dev != root_dev);
        bool ok = dir;
        if (ok && mount) {              /* V5-E6, V5-A5: a whole filesystem of a listed type */
            uint64_t id;
            if (!*asked) {
                *asked = true;
                *table = ops->mountinfo(ops->ctx);
            }
            ok = ops->mount_id(ops->ctx, root_fd, home, &id) == 0 && fsops_mount_whole_listed(*table, id);
        }
        *s = keep;
        if (!ok) return false;
        if (keep == '\0') return true;
    }
}

/* A passwd home as a path relative to the scope, canonical, into `out`:
 * false when it is not absolute, is "/", or has an empty, "." or ".."
 * component. Any other bytes are a path's (a root line writes what is not
 * UTF-8 as root_b64). Trailing slashes are dropped. */
static bool home_rel(const char *home, size_t len, char *out, size_t cap) {
    while (len > 1 && home[len - 1] == '/') len--;
    if (len < 2 || home[0] != '/' || len - 1 >= cap) return false;
    memcpy(out, home + 1, len - 1);
    out[len - 1] = '\0';
    for (const char *c = out; ; ) {
        const char *e = strchr(c, '/');
        const size_t n = e != NULL ? (size_t)(e - c) : strlen(c);
        if (n == 0 || (n == 1 && c[0] == '.') || (n == 2 && c[0] == '.' && c[1] == '.')) return false;
        if (e == NULL) break;
        c = e + 1;
    }
    return true;
}

/* etc/passwd of the scope, opened without following a link at either
 * component; NULL when there is none to read (no homes then). */
static FILE *open_passwd(int root_fd) {
    const int etc = openat(root_fd, "etc", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (etc == -1) return NULL;
    const int fd = openat(etc, "passwd", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    close(etc);
    struct stat st;
    if (fd == -1) return NULL;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return NULL; }
    FILE *f = fdopen(fd, "rb");
    if (f == NULL) close(fd);
    return f;
}

int belay_system_roots(const char *scope, struct belay_system_roots *out) {
    return sysroots_resolve(fsops_default(), scope, out);
}

int sysroots_resolve(const struct fsops *ops, const char *scope, struct belay_system_roots *out) {
    memset(out, 0, sizeof *out);
    char *table = NULL;
    bool asked = false;
    const int root_fd = open(scope, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct stat rst;
    if (root_fd == -1 || fstat(root_fd, &rst) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot open %s", scope);
        if (root_fd != -1) close(root_fd);
        return -1;
    }
    struct build b = { 0 };
    for (size_t i = 0; i < N(CONTENT); i++) add(&b, NULL, CONTENT[i], BELAY_ROOT_CONTENT, false);
    for (size_t i = 0; i < N(METADATA); i++) add(&b, NULL, METADATA[i], BELAY_ROOT_METADATA, false);
    for (size_t i = 0; i < N(METADATA_IF_DIR); i++)
        if (is_dir(root_fd, METADATA_IF_DIR[i])) add(&b, NULL, METADATA_IF_DIR[i], BELAY_ROOT_METADATA, false);
    if (is_dir(root_fd, "lib")) add(&b, NULL, "lib/systemd", BELAY_ROOT_CONTENT, false);    /* WS-6 */

    /*
     *  The sixth field of every line; a line without one names no home. The
     *  file is not ours to trust: it is read byte by byte, so a line holding
     *  a NUL byte (its fields cannot be told apart from what follows it) or
     *  longer than a line can be is dropped by itself, and the line after it
     *  is a line of its own. A last line without a newline is a line.
     *
     *  The homes are collected first, each once, then looked at: a passwd of
     *  100,000 lines naming one home makes one home's roots, not 100,000
     *  times as many to sort away.
     */
    FILE *pw = open_passwd(root_fd);
    /* Sized by the manifest's path limit (4096 with the NUL), the same on
     * every platform; not by PATH_MAX, which is 1024 on macOS and would make
     * which homes are read depend on where belay was built. */
    char line[2 * 4096], rel[4096];
    struct build homes = { 0 };         /* candidate homes, relative; `roots` unused but for the paths */
    size_t ll = 0;
    bool bad = false;
    for (int ch = pw != NULL ? getc(pw) : EOF; pw != NULL; ch = getc(pw)) {
        if (ch != '\n' && ch != EOF) {
            if (ch == '\0' || ll + 1 >= sizeof line) bad = true;
            else line[ll++] = (char)ch;
            continue;
        }
        if (!bad && ll > 0) {
            line[ll] = '\0';
            const char *f = line;
            int field = 0;
            while (field < 5 && (f = strchr(f, ':')) != NULL) { f++; field++; }
            /* WS-8a leaves a home out when it cannot be one; so is one whose
             * deepest root would not fit a path (PATH_MAX with its NUL). */
            if (f != NULL && field == 5 && home_rel(f, strcspn(f, ":"), rel, sizeof rel) &&
                strlen(rel) + sizeof "/.config/systemd/user" < 4096 && strlen(rel) + sizeof "/.config/fish/config.fish" < 4096)
                add(&homes, NULL, rel, BELAY_ROOT_CONTENT, false);
        }
        ll = 0;
        bad = false;
        if (ch == EOF) break;
    }
    for (size_t i = 0; !homes.oom && i < homes.n; i++) homes.roots[i].path = homes.names + (uintptr_t)homes.roots[i].path;
    if (!homes.oom && homes.n > 1) qsort(homes.roots, homes.n, sizeof *homes.roots, by_path);
    for (size_t i = 0; !homes.oom && i < homes.n; i++) {
        if (i > 0 && strcmp(homes.roots[i - 1].path, homes.roots[i].path) == 0) continue;
        snprintf(rel, sizeof rel, "%s", homes.roots[i].path);
        if (!home_usable(ops, root_fd, (uint64_t)rst.st_dev, rel, &table, &asked)) continue;
        for (size_t k = 0; k < N(HOME_DIRS); k++) add(&b, rel, HOME_DIRS[k], BELAY_ROOT_CONTENT, false);
        for (size_t k = 0; k < N(HOME_FILES); k++) add(&b, rel, HOME_FILES[k], BELAY_ROOT_CONTENT, true);
    }
    free(table);
    if (homes.oom) b.oom = true;
    free(homes.roots);
    free(homes.names);
    const bool read_failed = pw != NULL && ferror(pw);
    if (pw != NULL) fclose(pw);
    close(root_fd);
    if (b.oom || read_failed) {
        free(b.roots);
        free(b.names);
        if (b.oom) belay_err_set(BELAY_ERR_NOMEM, 0, "system roots: out of memory");
        else belay_err_set(BELAY_ERR_IO, errno, "cannot read %s/etc/passwd", scope);
        return -1;
    }
    for (size_t i = 0; i < b.n; i++) b.roots[i].path = b.names + (uintptr_t)b.roots[i].path;
    qsort(b.roots, b.n, sizeof *b.roots, by_path);
    size_t w = 0;                       /* a home named on two lines: once */
    for (size_t i = 0; i < b.n; i++)
        if (w == 0 || strcmp(b.roots[w - 1].path, b.roots[i].path) != 0) b.roots[w++] = b.roots[i];
    out->roots = b.roots;
    out->n_roots = w;
    out->names = b.names;
    out->not_read = NOT_READ;
    out->n_not_read = N(NOT_READ);
    return 0;
}

void belay_system_roots_free(struct belay_system_roots *r) {
    if (r == NULL) return;
    free(r->roots);
    free(r->names);
    memset(r, 0, sizeof *r);
}
