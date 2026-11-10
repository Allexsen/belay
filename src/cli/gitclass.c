/*
 *  gitclass: see gitclass.h. Each git behaviour relied on was checked against
 *  git 2.43.0 first (2026-11-04): check-ignore matches a path below an
 *  ignored directory, existing or not, and a directory given with a trailing
 *  slash; a path below a symlink makes the whole call fail ("pathspec ... is
 *  beyond a symbolic link", exit 128), as one in a submodule does; ls-files
 *  and ls-tree print paths from the top when run there; rev-parse
 *  --show-prefix is the scope's path below the top, "" at the top.
 */
#define _GNU_SOURCE
#include "cli/gitclass.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

struct buf { char *p; size_t n, cap; };

static int put(struct buf *b, const void *d, size_t k) {
    if (b->n + k + 1 > b->cap) {
        size_t c = b->cap ? b->cap : 4096;
        while (b->n + k + 1 > c) c *= 2;
        char *q = realloc(b->p, c);
        if (q == NULL) return -1;
        b->p = q;
        b->cap = c;
    }
    memcpy(b->p + b->n, d, k);
    b->n += k;
    b->p[b->n] = '\0';
    return 0;
}

/* The caller's environment without what would point git at another
 * repository or index, and with optional locks off (no opportunistic index
 * write). NULL on memory. */
static char **child_env(void) {
    static const char *const DROP[] = { "GIT_DIR=", "GIT_WORK_TREE=", "GIT_INDEX_FILE=", "GIT_OBJECT_DIRECTORY=",
                                        "GIT_COMMON_DIR=", "GIT_NAMESPACE=", "GIT_ALTERNATE_OBJECT_DIRECTORIES=",
                                        "GIT_OPTIONAL_LOCKS=" };
    size_t n = 0;
    while (environ[n] != NULL) n++;
    char **e = malloc((n + 2) * sizeof *e);
    if (e == NULL) return NULL;
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        bool drop = false;
        for (size_t d = 0; d < sizeof DROP / sizeof DROP[0]; d++)
            drop |= strncmp(environ[i], DROP[d], strlen(DROP[d])) == 0;
        if (!drop) e[k++] = environ[i];
    }
    e[k++] = "GIT_OPTIONAL_LOCKS=0";
    e[k] = NULL;
    return e;
}

/* git argv (argv[0] "git"), standard input from in_fd (-1: /dev/null), its
 * output in *out, the start of its errors in err: its exit status, or -1. */
static int run_git(char *const argv[], int in_fd, struct buf *out, char *err, size_t errcap) {
    int po[2] = { -1, -1 }, pe[2] = { -1, -1 }, nul = -1, rc = -1;
    size_t en = 0;
    err[0] = '\0';
    if (pipe(po) != 0) return -1;
    if (pipe(pe) != 0) { close(po[0]); close(po[1]); return -1; }
    for (int i = 0; i < 2; i++) { fcntl(po[i], F_SETFD, FD_CLOEXEC); fcntl(pe[i], F_SETFD, FD_CLOEXEC); }
    if (in_fd < 0 && (nul = open("/dev/null", O_RDONLY | O_CLOEXEC)) == -1) goto closeall;
    char **env = child_env();
    if (env == NULL) goto closeall;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, in_fd >= 0 ? in_fd : nul, 0);
    posix_spawn_file_actions_adddup2(&fa, po[1], 1);
    posix_spawn_file_actions_adddup2(&fa, pe[1], 2);
    pid_t pid;
    const int sr = posix_spawnp(&pid, "git", &fa, NULL, argv, env);
    posix_spawn_file_actions_destroy(&fa);
    free(env);
    close(po[1]);
    close(pe[1]);
    po[1] = pe[1] = -1;
    if (sr != 0) goto closeall;
    bool bad = false;
    struct pollfd pf[2] = { { po[0], POLLIN, 0 }, { pe[0], POLLIN, 0 } };
    while (pf[0].fd >= 0 || pf[1].fd >= 0) {
        if (poll(pf, 2, -1) == -1) {
            if (errno == EINTR) continue;
            bad = true;
            break;
        }
        for (int i = 0; i < 2; i++) {
            if (pf[i].fd < 0 || !(pf[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            char b[65536];
            const ssize_t r = read(pf[i].fd, b, sizeof b);
            if (r > 0 && i == 0) bad |= put(out, b, (size_t)r) == -1;
            else if (r > 0) {
                const size_t k = (size_t)r < errcap - 1 - en ? (size_t)r : errcap - 1 - en;
                memcpy(err + en, b, k);
                en += k;
                err[en] = '\0';
            } else if (r == 0 || errno != EINTR) {
                pf[i].fd = -1;
            }
        }
    }
    int st = 0;
    while (waitpid(pid, &st, 0) == -1 && errno == EINTR) {}
    rc = bad || !WIFEXITED(st) ? -1 : WEXITSTATUS(st);
closeall:
    for (int i = 0; i < 2; i++) {
        if (po[i] >= 0) close(po[i]);
        if (pe[i] >= 0) close(pe[i]);
    }
    if (nul >= 0) close(nul);
    return rc;
}

static int cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* Pointers to the NUL-separated strings of b, appended to *v. */
static int split(struct buf *b, char ***v, size_t *n, size_t *cap) {
    for (size_t i = 0; i < b->n;) {
        const size_t k = strlen(b->p + i);
        if (k > 0) {
            if (*n == *cap) {
                const size_t c = *cap ? *cap * 2 : 1024;
                char **q = realloc(*v, c * sizeof *q);
                if (q == NULL) return -1;
                *v = q;
                *cap = c;
            }
            (*v)[(*n)++] = b->p + i;
        }
        i += k + 1;
    }
    return 0;
}

static bool has(char *const *v, size_t n, const char *s) {
    return n > 0 && bsearch(&s, v, n, sizeof *v, cmp) != NULL;
}

/* Whether a sorted list holds an entry below directory `d` (with its "/"). */
static bool holds(char *const *v, size_t n, const char *d, size_t dl) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        const size_t m = lo + (hi - lo) / 2;
        if (strcmp(v[m], d) < 0) lo = m + 1;
        else hi = m;
    }
    return lo < n && strncmp(v[lo], d, dl) == 0;
}

int gitclass(const char *scope, const char *const *paths, const size_t *lens, const bool *dir, size_t n,
             unsigned char *out) {
    if (n == 0) return 0;
    int rc = -1;
    char err[4096], *top = NULL, *prefix = NULL;
    struct buf rp = { 0 }, lf = { 0 }, lt = { 0 }, in = { 0 }, ci = { 0 }, full = { 0 };
    char **tr = NULL, **ig = NULL;
    size_t ntr = 0, ctr = 0, nig = 0, cig = 0;
    size_t *ask = NULL;                 /* indices still to ask check-ignore about */
    size_t nask = 0;
    unsigned char *cls = calloc(n, 1);
    char *last = NULL;                  /* the last parent checked for a symlink, and its answer */
    bool last_link = false;
    if (cls == NULL || (ask = malloc(n * sizeof *ask)) == NULL) goto done;

    char *rpa[] = { "git", "-c", "core.fsmonitor=false", "-C", (char *)scope, "rev-parse", "--show-toplevel",
                    "--show-prefix", NULL };
    if (run_git(rpa, -1, &rp, err, sizeof err) != 0 || rp.p == NULL) goto done;
    char *nl = strchr(rp.p, '\n');
    if (nl == NULL) goto done;
    *nl = '\0';
    top = rp.p;
    prefix = nl + 1;
    if ((nl = strchr(prefix, '\n')) != NULL) *nl = '\0';
    if (top[0] != '/') goto done;

    char *lfa[] = { "git", "-c", "core.fsmonitor=false", "-C", top, "ls-files", "-z", NULL };
    if (run_git(lfa, -1, &lf, err, sizeof err) != 0) goto done;
    char *lta[] = { "git", "-c", "core.fsmonitor=false", "-C", top, "ls-tree", "-r", "-z", "--name-only", "HEAD", NULL };
    if (run_git(lta, -1, &lt, err, sizeof err) != 0) lt.n = 0;          /* no commit yet: nothing in HEAD */
    if (split(&lf, &tr, &ntr, &ctr) == -1 || split(&lt, &tr, &ntr, &ctr) == -1) goto done;
    if (ntr > 0) qsort(tr, ntr, sizeof *tr, cmp);         /* none tracked: no array to sort */

    const size_t pl = strlen(prefix);
    for (size_t i = 0; i < n; i++) {
        full.n = 0;
        if (put(&full, prefix, pl) == -1 || put(&full, paths[i], lens[i]) == -1) goto done;
        if (memchr(paths[i], '\0', lens[i]) != NULL) { cls[i] = GC_UNTRACKED; continue; }
        if (has(tr, ntr, full.p)) { cls[i] = GC_TRACKED; continue; }
        if (dir[i]) {
            if (put(&full, "/", 1) == -1) goto done;
            if (holds(tr, ntr, full.p, full.n)) { cls[i] = GC_TRACKED; continue; }
        }
        /* below a symlink now: git would refuse the whole call; shown, not
         * folded. The answer for a path's nearest parent is kept: paths
         * arrive in order, so its siblings follow it. */
        bool link = false;
        size_t np = lens[i];
        while (np > 0 && paths[i][np - 1] != '/') np--;
        if (np > 0) {
            np--;                                           /* the nearest parent: paths[i][0..np) */
            char *near = malloc(strlen(scope) + np + 2);
            if (near == NULL) goto done;
            sprintf(near, "%s/%.*s", scope, (int)np, paths[i]);
            if (last != NULL && strcmp(last, near) == 0) {
                link = last_link;
                free(near);
            } else {
                const size_t sc = strlen(scope);
                for (size_t k = strlen(near); k > sc && !link;) {
                    struct stat s;
                    near[k] = '\0';
                    link = lstat(near, &s) == 0 && S_ISLNK(s.st_mode);
                    while (k > sc && near[k - 1] != '/') k--;
                    if (k > sc) k--;                        /* the next parent up */
                }
                sprintf(near, "%s/%.*s", scope, (int)np, paths[i]);
                free(last);
                last = near;
                last_link = link;
            }
        }
        if (link) { cls[i] = GC_UNTRACKED; continue; }
        ask[nask++] = i;
    }

    for (int tries = 0; nask > 0; tries++) {
        if (tries == 8) goto done;
        in.n = 0;
        for (size_t a = 0; a < nask; a++) {
            const size_t i = ask[a];
            if (put(&in, prefix, pl) == -1 || put(&in, paths[i], lens[i]) == -1 ||
                (dir[i] && put(&in, "/", 1) == -1) || put(&in, "", 1) == -1)
                goto done;
        }
        const char *tmp = getenv("TMPDIR");
        char tpl[PATH_MAX];
        snprintf(tpl, sizeof tpl, "%s/belay-gitclass.XXXXXX", tmp != NULL && tmp[0] == '/' ? tmp : "/tmp");
        const int fd = mkstemp(tpl);
        if (fd == -1) goto done;
        unlink(tpl);
        size_t w = 0;
        while (w < in.n) {
            const ssize_t r = write(fd, in.p + w, in.n - w);
            if (r <= 0) break;
            w += (size_t)r;
        }
        if (w != in.n || lseek(fd, 0, SEEK_SET) != 0) { close(fd); goto done; }
        char *cia[] = { "git", "-c", "core.fsmonitor=false", "-C", top, "check-ignore", "-z", "--stdin", NULL };
        ci.n = 0;
        const int r = run_git(cia, fd, &ci, err, sizeof err);
        close(fd);
        if (r == 0 || r == 1) {
            nig = 0;
            if (split(&ci, &ig, &nig, &cig) == -1) goto done;
            if (nig > 0) qsort(ig, nig, sizeof *ig, cmp);
            for (size_t a = 0; a < nask; a++) {
                const size_t i = ask[a];
                full.n = 0;
                if (put(&full, prefix, pl) == -1 || put(&full, paths[i], lens[i]) == -1 ||
                    (dir[i] && put(&full, "/", 1) == -1))
                    goto done;
                cls[ask[a]] = has(ig, nig, full.p) ? GC_IGNORED : GC_UNTRACKED;
            }
            nask = 0;
            break;
        }
        /* a path git refuses: it alone is untracked, the rest asked again */
        const char *q = strstr(err, "athspec '");
        if (q == NULL) goto done;
        q += 9;
        const char *e = strchr(q, '\'');
        if (e == NULL) goto done;
        size_t ql = (size_t)(e - q), found = nask;
        while (ql > 0 && q[ql - 1] == '/') ql--;
        for (size_t a = 0; a < nask && found == nask; a++) {
            const size_t i = ask[a];
            size_t fl = pl + lens[i];
            if (fl == ql && memcmp(q, prefix, pl < ql ? pl : ql) == 0 && memcmp(q + pl, paths[i], lens[i]) == 0)
                found = a;
        }
        if (found == nask) goto done;
        cls[ask[found]] = GC_UNTRACKED;
        ask[found] = ask[--nask];
    }
    memcpy(out, cls, n);
    rc = 0;
done:
    free(cls);
    free(ask);
    free(last);
    free(tr);
    free(ig);
    free(rp.p);
    free(lf.p);
    free(lt.p);
    free(in.p);
    free(ci.p);
    free(full.p);
    return rc;
}
