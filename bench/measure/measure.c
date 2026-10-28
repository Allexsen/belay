/*
 *  measure: what a check meets on a real tree, for "is this worth fixing"
 *  questions (README.md beside this file). One check per run, one JSON line
 *  on stdout.
 *
 *  belay's own capture runs unchanged, through a decorated platform adapter
 *  that only observes:
 *    - belay's outcome: entries, raced / unstable / unreadable / vanished,
 *      and the flagged paths (read back from the manifest it wrote);
 *    - writers: right after belay opens a regular file to hash it, and again
 *      at EOF, the platform's writer_present probe (the one that gates the
 *      store; on Linux a read lease taken and released at once). For every
 *      file a writer held, what the manifest then recorded for it;
 *    - the racy rule of the 2026-10-27 design review, not shipped: in visit
 *      order, an entry whose ctime is >= the newest seen so far on its
 *      device, once per inode, and the bytes a re-hash would cost;
 *    - the wall clock against the monotonic one, so a stepped clock shows;
 *    - with --mounts N (Linux), the cost of a mount-table fallback.
 *
 *  usage: measure [--tag T] [--store DIR] [--keep DIR] [--tmp DIR]
 *                 [--mounts N] <scope>
 */
#define _GNU_SOURCE
#include "capture/capture.h"
#include "capture/ident.h"
#include "belay/error.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAXFD   65536
#define FLAGGED 40          /* paths listed per flag */
#define WRITERS 4096        /* files a writer held, per run */
#define PATHB   4200        /* an entry path (4095) plus a scope prefix */

static const struct fsops *real;
static struct fsops ops;

/* ---- writers ---------------------------------------------------------- */

enum { W_NO, W_YES, W_UNKNOWN };
static struct { int reading; } tr[MAXFD];
static struct {
    size_t hashed, at_open[3], at_eof[3];
    unsigned long long bytes_read;
    char held[WRITERS][PATHB];      /* absolute paths, sorted before lookup */
    size_t n_held;
} w;

static int probe(int fd) {
    const int r = real->writer_present(real->ctx, fd);
    return r == 1 ? W_YES : r == 0 ? W_NO : W_UNKNOWN;
}

static void fd_path(int fd, char *out, size_t n) {
    out[0] = '\0';
#ifdef F_GETPATH
    char p[PATH_MAX];
    if (fcntl(fd, F_GETPATH, p) == 0) snprintf(out, n, "%s", p);
#else
    char l[64];
    snprintf(l, sizeof l, "/proc/self/fd/%d", fd);
    const ssize_t k = readlink(l, out, n - 1);
    out[k > 0 ? k : 0] = '\0';
#endif
}

static void held(int fd) {
    if (w.n_held < WRITERS) fd_path(fd, w.held[w.n_held++], PATHB);
}

static int t_openat(void *ctx, int dfd, const char *name, int flags) {
    (void)ctx;
    const int fd = real->openat(real->ctx, dfd, name, flags);
    if (fd < 0 || fd >= MAXFD) return fd;
    tr[fd].reading = 0;
#ifdef O_PATH
    if (flags & O_PATH) return fd;
#endif
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_DIRECTORY)) return fd;
    struct stat st;
    if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)) return fd;
    w.hashed++;
    const int p = probe(fd);
    w.at_open[p]++;
    if (p == W_YES) held(fd);
    tr[fd].reading = 1 + (p == W_YES);      /* 2: already listed */
    return fd;
}

static ssize_t t_read(void *ctx, int fd, void *buf, size_t n) {
    (void)ctx;
    const ssize_t r = real->read(real->ctx, fd, buf, n);
    if (fd < 0 || fd >= MAXFD || !tr[fd].reading) return r;
    if (r > 0) { w.bytes_read += (unsigned long long)r; return r; }
    if (r == 0) {
        const int p = probe(fd);
        w.at_eof[p]++;
        if (p == W_YES && tr[fd].reading == 1) held(fd);
    }
    tr[fd].reading = 0;
    return r;
}

/* ---- racy rule, in visit order, once per inode ------------------------- */

#define HSET (1u << 20)
static struct { uint64_t dev, ino; } seen[HSET];
static unsigned char used[HSET];
static struct { uint64_t dev; int64_t max; } devmax[64];
static int ndev;
static struct {
    size_t entries, racy, racy_reg;
    unsigned long long racy_reg_bytes, reg_bytes;
} rr;
static uint64_t hash_max = 64ull << 20;

static int first_time(uint64_t dev, uint64_t ino) {
    const uint64_t h = (dev * 0x9E3779B97F4A7C15ull) ^ (ino * 0xC2B2AE3D27D4EB4Full);
    for (unsigned i = (unsigned)(h & (HSET - 1));; i = (i + 1) & (HSET - 1)) {
        if (!used[i]) { used[i] = 1; seen[i].dev = dev; seen[i].ino = ino; return 1; }
        if (seen[i].dev == dev && seen[i].ino == ino) return 0;
    }
}

static void racy_observe(const struct stat *st) {
    const struct ident id = ident_of_stat(st);
    if (rr.entries >= HSET / 2 || !first_time(id.dev, id.ino)) return;
    rr.entries++;
    int d = 0;
    while (d < ndev && devmax[d].dev != id.dev) d++;
    if (d == ndev) {
        if (ndev == 64) return;
        devmax[ndev].dev = id.dev;
        devmax[ndev].max = INT64_MIN;
        ndev++;
    }
    const int reg = S_ISREG(st->st_mode) && id.size <= hash_max;
    if (reg) rr.reg_bytes += id.size;
    if (id.ctime_ns >= devmax[d].max) {
        rr.racy++;
        if (reg) { rr.racy_reg++; rr.racy_reg_bytes += id.size; }
    }
    if (id.ctime_ns > devmax[d].max) devmax[d].max = id.ctime_ns;
}

static int t_stat_mount(void *ctx, int dfd, const char *name, struct stat *st, bool *mr, bool *mk) {
    (void)ctx;
    const int r = real->stat_mount(real->ctx, dfd, name, st, mr, mk);
    if (r == 0) racy_observe(st);
    return r;
}

static int t_fstatat(void *ctx, int dfd, const char *name, struct stat *st, int flags) {
    (void)ctx;
    const int r = real->fstatat(real->ctx, dfd, name, st, flags);
    if (r == 0) racy_observe(st);
    return r;
}

/* ---- what the manifest recorded ----------------------------------------- */

struct flagged { size_t n; char p[FLAGGED][PATHB]; };
static struct flagged f_raced, f_unstable, f_unreadable;
static struct { size_t clean_hash, stored, unstable, raced, unreadable, unverified; } wo;
static const char *g_scope;

static void add(struct flagged *x, const struct belay_entry *e) {
    if (x->n < FLAGGED)
        snprintf(x->p[x->n], PATHB, "%s%s", e->path, e->type == BELAY_T_DIR ? "/" : "");
    x->n++;
}

static int cmpstr(const void *a, const void *b) { return strcmp(a, b); }

static int collect(const struct belay_entry *e, void *ctx) {
    (void)ctx;
    if (e->raced) add(&f_raced, e);
    if (e->unstable) add(&f_unstable, e);
    if (e->unreadable) add(&f_unreadable, e);
    if (w.n_held && e->type == BELAY_T_REG) {
        char abs[PATHB + 4096];
        const size_t sl = strlen(g_scope);
        snprintf(abs, sizeof abs, "%s%s%s", g_scope, g_scope[sl - 1] == '/' ? "" : "/", e->path);
        if (bsearch(abs, w.held, w.n_held, PATHB, cmpstr)) {
            if (e->raced) wo.raced++;
            else if (e->unstable) wo.unstable++;
            else if (e->unreadable) wo.unreadable++;
            else if (e->has_hash) wo.clean_hash++;
            else wo.unverified++;
            if (e->has_stored) wo.stored++;
        }
    }
    return 0;
}

/* ---- mount-table fallback (Linux) ---------------------------------------- */

static double now_s(clockid_t c) {
    struct timespec t;
    clock_gettime(c, &t);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
}

struct mt { const char *scope; size_t nm; size_t entries; };
static int mt_check(const struct belay_entry *e, void *ctx) {
    struct mt *t = ctx;
    char abs[PATHB + 4096], mp[PATHB + 64];
    snprintf(abs, sizeof abs, "%s/%s", t->scope, e->path);
    const size_t al = strlen(abs);
    for (size_t i = 0; i < t->nm; i++) {      /* N mount points, none matching */
        snprintf(mp, sizeof mp, "%s/__no_such_mount_%zu", t->scope, i);
        const size_t l = strlen(mp);
        if (al >= l && memcmp(abs, mp, l) == 0 && (abs[l] == '/' || abs[l] == '\0')) break;
    }
    t->entries++;
    return 0;
}

static size_t read_mountinfo(void) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (f == NULL) return 0;
    char line[4096];
    size_t n = 0;
    while (fgets(line, sizeof line, f)) n++;
    fclose(f);
    return n;
}

/* ---- output -------------------------------------------------------------- */

static void jstr(const char *s) {
    putchar('"');
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') putchar('\\');
        if ((unsigned char)*s < 0x20) printf("\\u%04x", *s); else putchar(*s);
    }
    putchar('"');
}

static void jflag(const char *key, const struct flagged *x) {
    printf(",\"%s\":%zu,\"%s_paths\":[", key, x->n, key);
    for (size_t i = 0; i < x->n && i < FLAGGED; i++) { if (i) putchar(','); jstr(x->p[i]); }
    putchar(']');
}

static void usage(void) {
    fprintf(stderr, "usage: measure [--tag T] [--store DIR] [--keep DIR] [--tmp DIR] "
                    "[--mounts N] <scope>\n");
    exit(2);
}

int main(int argc, char **argv) {
    const char *tag = "run", *store = NULL, *keep = NULL, *scope = NULL;
    const char *tmp = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    int mounts = -1;
    for (int i = 1; i < argc; i++) {
        if (i + 1 < argc && strcmp(argv[i], "--tag") == 0) tag = argv[++i];
        else if (i + 1 < argc && strcmp(argv[i], "--store") == 0) store = argv[++i];
        else if (i + 1 < argc && strcmp(argv[i], "--keep") == 0) keep = argv[++i];
        else if (i + 1 < argc && strcmp(argv[i], "--tmp") == 0) tmp = argv[++i];
        else if (i + 1 < argc && strcmp(argv[i], "--mounts") == 0) mounts = atoi(argv[++i]);
        else if (argv[i][0] != '-' && scope == NULL) scope = argv[i];
        else usage();
    }
    if (scope == NULL) usage();
    static char real_scope[PATH_MAX];
    if (realpath(scope, real_scope) == NULL) { perror(scope); return 2; }
    g_scope = real_scope;

    real = fsops_default();
    ops = *real;
    ops.openat = t_openat;
    ops.read = t_read;
    ops.stat_mount = t_stat_mount;
    ops.fstatat = t_fstatat;

    char out[PATH_MAX];
    snprintf(out, sizeof out, "%s/measure.%d.ndjson", tmp, (int)getpid());
    struct belay_manifest_opts o = {
        .hash_max_bytes = hash_max,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
        .store_dir = store,
    };
    struct belay_manifest_stats st = { 0 };

    const double off0 = now_s(CLOCK_REALTIME) - now_s(CLOCK_MONOTONIC);
    double mt_read = 0;
    if (mounts >= 0) { const double a = now_s(CLOCK_MONOTONIC); read_mountinfo(); mt_read += now_s(CLOCK_MONOTONIC) - a; }
    /* This driver probes every hashed file, store or not: bracket it as a
     * capture with a store is (SIGIO; see fsops_linux.c). */
    real->probe_begin(real->ctx);
    const double t0 = now_s(CLOCK_MONOTONIC);
    const int rc = capture_write(&ops, out, real_scope, &o, &st);
    const double t1 = now_s(CLOCK_MONOTONIC);
    real->probe_end(real->ctx);
    const double off1 = now_s(CLOCK_REALTIME) - now_s(CLOCK_MONOTONIC);

    printf("{\"tag\":");
    jstr(tag);
    printf(",\"scope\":");
    jstr(real_scope);
    printf(",\"realtime\":%.3f,\"wall_s\":%.4f,\"rc\":%d", now_s(CLOCK_REALTIME), t1 - t0, rc);
    if (rc != 0) {
        printf(",\"err\":");
        jstr(belay_err_msg());
        printf("}\n");
        unlink(out);
        return 1;
    }
    qsort(w.held, w.n_held, PATHB, cmpstr);
    belay_manifest_read(out, collect, NULL);
    printf(",\"entries\":%zu,\"vanished\":%zu,\"mounts\":%zu", st.entries, st.vanished, st.mounts);
    jflag("raced", &f_raced);
    jflag("unstable", &f_unstable);
    jflag("unreadable", &f_unreadable);
    printf(",\"files_hashed\":%zu,\"bytes_read\":%llu", w.hashed, w.bytes_read);
    printf(",\"writer_at_open\":{\"yes\":%zu,\"no\":%zu,\"unknown\":%zu}",
           w.at_open[W_YES], w.at_open[W_NO], w.at_open[W_UNKNOWN]);
    printf(",\"writer_at_eof\":{\"yes\":%zu,\"no\":%zu,\"unknown\":%zu}",
           w.at_eof[W_YES], w.at_eof[W_NO], w.at_eof[W_UNKNOWN]);
    printf(",\"writer_outcome\":{\"clean_hash\":%zu,\"stored\":%zu,\"unstable\":%zu,\"raced\":%zu,"
           "\"unreadable\":%zu,\"unverified\":%zu}",
           wo.clean_hash, wo.stored, wo.unstable, wo.raced, wo.unreadable, wo.unverified);
    printf(",\"writer_paths\":[");
    for (size_t i = 0; i < w.n_held; i++) { if (i) putchar(','); jstr(w.held[i]); }
    printf("]");
    printf(",\"racy\":{\"entries_seen\":%zu,\"racy\":%zu,\"racy_reg\":%zu,\"racy_reg_bytes\":%llu,"
           "\"reg_bytes\":%llu}", rr.entries, rr.racy, rr.racy_reg, rr.racy_reg_bytes, rr.reg_bytes);
    printf(",\"clock_step_s\":%.3f", off1 - off0);

    if (mounts >= 0) {
        const double a = now_s(CLOCK_MONOTONIC);
        const size_t n = read_mountinfo();
        mt_read += now_s(CLOCK_MONOTONIC) - a;
        struct mt with = { real_scope, (size_t)mounts, 0 }, none = { real_scope, 0, 0 };
        const double b = now_s(CLOCK_MONOTONIC);
        belay_manifest_read(out, mt_check, &with);
        const double c = now_s(CLOCK_MONOTONIC);
        belay_manifest_read(out, mt_check, &none);
        const double d = now_s(CLOCK_MONOTONIC);
        printf(",\"mount_table\":{\"lines\":%zu,\"read_twice_s\":%.6f,\"check_s\":%.4f,"
               "\"baseline_s\":%.4f,\"mount_points\":%d}", n, mt_read, c - b, d - c, mounts);
    }
    printf("}\n");

    if (keep != NULL) {
        char k[PATH_MAX];
        snprintf(k, sizeof k, "%s/%s.%.0f.%d.ndjson", keep, tag, now_s(CLOCK_REALTIME) * 1000,
                 (int)getpid());
        if (rename(out, k) == 0) return 0;
    }
    unlink(out);
    return 0;
}
