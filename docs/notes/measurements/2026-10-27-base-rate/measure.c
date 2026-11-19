/*
 *  Base-rate measurement for the walk-consistency design review. NOT the
 *  design: belay's own capture_write runs unchanged; a decorated platform
 *  adapter only observes.
 *
 *  Per run, one JSON line:
 *    - belay's own outcome: entries, raced/unstable/unreadable/vanished, and
 *      the paths flagged (from the manifest it wrote);
 *    - lease probe (Linux): right after belay opens a regular file to hash
 *      it, and again when it reaches EOF, take F_SETLEASE F_RDLCK and release
 *      it at once. EAGAIN = some process had the file open for writing (or
 *      mapped shared-writable) at that instant. Nothing is held during the
 *      read, so writers are never blocked by more than the two syscalls.
 *    - racy rule (review, mechanism 2): in visit order, an entry whose ctime
 *      is >= the newest ctime seen so far on its device; counted once per
 *      inode, with the bytes a re-hash would cost for regular files.
 *    - clock: realtime minus monotonic at start and end (WSL steps it).
 *
 *  usage: measure <scope> <tag> [--mounts N]
 *    --mounts: also time the mount-table fallback (mountinfo read twice, and
 *    every recorded path checked against N synthetic mount points).
 */
#define _GNU_SOURCE
#include "capture/capture.h"
#include "belay/error.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAXFD 65536
#define LIST 40
#define ELIST 4096

static const struct fsops *real;
static struct fsops ops;

enum probe { P_NONE, P_OK, P_EAGAIN, P_EACCES, P_OTHER };
struct track { int active; enum probe at_open; uint64_t bytes; };
static struct track tr[MAXFD];

static struct {
    size_t files_opened, probe_ok, probe_eagain, probe_eacces, probe_other;
    size_t eof_probed, eof_eagain, no_eof;
    uint64_t bytes_read;
    size_t racy_entries, racy_reg, stat_seen;
    uint64_t racy_reg_bytes, reg_bytes_hashable;
    char eagain_open[ELIST][512]; size_t n_eagain_open;
    char eagain_eof[LIST][512];  size_t n_eagain_eof;
} m;

static uint64_t hash_max = 64ull << 20;

/* ---- lease probe ---- */
static enum probe probe(int fd) {
    if (fcntl(fd, F_SETLEASE, F_RDLCK) == 0) {
        fcntl(fd, F_SETLEASE, F_UNLCK);
        return P_OK;
    }
    if (errno == EAGAIN) return P_EAGAIN;
    if (errno == EACCES) return P_EACCES;
    return P_OTHER;
}

static void fd_path(int fd, char *out, size_t n) {
    char l[64];
    snprintf(l, sizeof l, "/proc/self/fd/%d", fd);
    const ssize_t k = readlink(l, out, n - 1);
    out[k > 0 ? k : 0] = '\0';
}

static int t_openat(void *ctx, int dfd, const char *name, int flags) {
    (void)ctx;
    const int fd = real->openat(real->ctx, dfd, name, flags);
    if (fd < 0 || fd >= MAXFD) return fd;
    if (tr[fd].active) m.no_eof++;
    tr[fd].active = 0;
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & (O_DIRECTORY | O_PATH))) return fd;
    struct stat st;
    if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)) return fd;
    m.files_opened++;
    const enum probe p = probe(fd);
    switch (p) {
    case P_OK: m.probe_ok++; break;
    case P_EAGAIN:
        m.probe_eagain++;
        if (m.n_eagain_open < ELIST) fd_path(fd, m.eagain_open[m.n_eagain_open++], 512);
        break;
    case P_EACCES: m.probe_eacces++; break;
    default: m.probe_other++; break;
    }
    tr[fd] = (struct track){ 1, p, 0 };
    return fd;
}

static ssize_t t_read(void *ctx, int fd, void *buf, size_t n) {
    (void)ctx;
    const ssize_t r = real->read(real->ctx, fd, buf, n);
    if (fd < 0 || fd >= MAXFD || !tr[fd].active) return r;
    if (r > 0) { tr[fd].bytes += (uint64_t)r; m.bytes_read += (uint64_t)r; return r; }
    tr[fd].active = 0;
    if (r == 0) {
        m.eof_probed++;
        if (probe(fd) == P_EAGAIN) {
            m.eof_eagain++;
            if (m.n_eagain_eof < LIST) fd_path(fd, m.eagain_eof[m.n_eagain_eof++], 512);
        }
    }
    return r;
}

/* ---- racy rule, once per inode, in visit order ---- */
#define HSET (1u << 20)
static struct { uint64_t dev, ino; } seen[HSET];
static unsigned char used[HSET];
static struct { uint64_t dev; int64_t max; } devmax[64];
static int ndev;

static int first_time(uint64_t dev, uint64_t ino) {
    uint64_t h = (dev * 0x9E3779B97F4A7C15ull) ^ (ino * 0xC2B2AE3D27D4EB4Full);
    for (unsigned i = (unsigned)(h & (HSET - 1));; i = (i + 1) & (HSET - 1)) {
        if (!used[i]) { used[i] = 1; seen[i].dev = dev; seen[i].ino = ino; return 1; }
        if (seen[i].dev == dev && seen[i].ino == ino) return 0;
    }
}

static void racy_observe(const struct stat *st) {
    if (!first_time((uint64_t)st->st_dev, (uint64_t)st->st_ino)) return;
    m.stat_seen++;
    const int64_t c = (int64_t)st->st_ctim.tv_sec * 1000000000 + st->st_ctim.tv_nsec;
    int d = 0;
    while (d < ndev && devmax[d].dev != (uint64_t)st->st_dev) d++;
    if (d == ndev) { if (ndev == 64) return; devmax[ndev].dev = st->st_dev; devmax[ndev].max = INT64_MIN; ndev++; }
    const int reg = S_ISREG(st->st_mode);
    if (reg && (uint64_t)st->st_size <= hash_max) m.reg_bytes_hashable += (uint64_t)st->st_size;
    if (c >= devmax[d].max) {
        m.racy_entries++;
        if (reg && (uint64_t)st->st_size <= hash_max) { m.racy_reg++; m.racy_reg_bytes += (uint64_t)st->st_size; }
    }
    if (c > devmax[d].max) devmax[d].max = c;
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

/* ---- flagged entries, from the manifest belay wrote ---- */
static struct { size_t n; char p[LIST][300]; } fl_raced, fl_unstable, fl_unreadable;
static void add(void *l, const struct belay_entry *e) {
    typeof(fl_raced) *x = l;
    if (x->n < LIST) snprintf(x->p[x->n], 300, "%s%s", e->path, e->type == BELAY_T_DIR ? "/" : "");
    x->n++;
}
static const char *g_scope;
static struct { size_t clean_hash, unstable, raced, unreadable, unverified, missing; } ecls;
static int cmpstr(const void *a, const void *b) { return strcmp((const char *)a, (const char *)b); }
static int collect(const struct belay_entry *e, void *ctx) {
    (void)ctx;
    if (m.n_eagain_open && e->type == BELAY_T_REG) {
        char abs[4600];
        snprintf(abs, sizeof abs, "%s/%s", g_scope, e->path);
        if (bsearch(abs, m.eagain_open, m.n_eagain_open, 512, cmpstr)) {
            if (e->raced) ecls.raced++;
            else if (e->unstable) ecls.unstable++;
            else if (e->unreadable) ecls.unreadable++;
            else if (e->has_hash) ecls.clean_hash++;
            else ecls.unverified++;
        }
    }
    if (e->raced) add(&fl_raced, e);
    if (e->unstable) add(&fl_unstable, e);
    if (e->unreadable) add(&fl_unreadable, e);
    return 0;
}

/* ---- mount-table fallback cost ---- */
static double now_s(clockid_t c) { struct timespec t; clock_gettime(c, &t); return t.tv_sec + t.tv_nsec / 1e9; }

static size_t read_mountinfo(char mp[][512], size_t cap) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) return 0;
    char line[4096]; size_t n = 0;
    while (n < cap && fgets(line, sizeof line, f)) {
        char *s = line; for (int i = 0; i < 4 && s; i++) { s = strchr(s, ' '); if (s) s++; }
        if (!s) continue;
        char *e = strchr(s, ' '); if (!e) continue;
        snprintf(mp[n++], 512, "%.*s", (int)(e - s), s);
    }
    fclose(f);
    return n;
}

struct mt { const char *scope; char (*mps)[512]; size_t nm; size_t hits; size_t entries; };
static int mt_check(const struct belay_entry *e, void *ctx) {
    struct mt *t = ctx;
    char abs[4600];
    snprintf(abs, sizeof abs, "%s/%s", t->scope, e->path);
    const size_t al = strlen(abs);
    for (size_t i = 0; i < t->nm; i++) {
        const size_t l = strlen(t->mps[i]);
        if (al >= l && memcmp(abs, t->mps[i], l) == 0 && (abs[l] == '/' || abs[l] == '\0')) { t->hits++; break; }
    }
    t->entries++;
    return 0;
}

static void jstr_list(const char *key, char l[][512], size_t n, size_t shown) {
    printf(",\"%s\":[", key);
    for (size_t i = 0; i < shown && i < n; i++) printf("%s\"%s\"", i ? "," : "", l[i]);
    printf("]");
}
static void jflag(const char *key, typeof(fl_raced) *x) {
    printf(",\"%s\":%zu,\"%s_paths\":[", key, x->n, key);
    for (size_t i = 0; i < x->n && i < LIST; i++) {
        printf("%s\"", i ? "," : "");
        for (const char *c = x->p[i]; *c; c++) { if (*c == '"' || *c == '\\') putchar('\\'); putchar(*c); }
        printf("\"");
    }
    printf("]");
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: measure <scope> <tag> [--mounts N]\n"); return 2; }
    int mounts = -1;
    if (argc == 5 && strcmp(argv[3], "--mounts") == 0) mounts = atoi(argv[4]);
    signal(SIGIO, SIG_IGN);     /* a lease break must never kill us */

    real = fsops_default();
    ops = *real;
    ops.openat = t_openat; ops.read = t_read;
    ops.stat_mount = t_stat_mount; ops.fstatat = t_fstatat;

    char out[512];
    snprintf(out, sizeof out, "%s/m.%d.ndjson", getenv("MEASURE_TMP") ? getenv("MEASURE_TMP") : "/tmp", (int)getpid());
    struct belay_manifest_opts o = { .hash_max_bytes = hash_max, .store_max_bytes = 0 };
    struct belay_manifest_stats st = { 0 };

    const double off0 = now_s(CLOCK_REALTIME) - now_s(CLOCK_MONOTONIC);
    const double t0 = now_s(CLOCK_MONOTONIC);
    static char mp0[256][512];
    double mt_read = 0;
    if (mounts >= 0) { const double a = now_s(CLOCK_MONOTONIC); read_mountinfo(mp0, 256); mt_read += now_s(CLOCK_MONOTONIC) - a; }
    const int rc = capture_write(&ops, out, argv[1], &o, &st);
    const double t1 = now_s(CLOCK_MONOTONIC);
    const double off1 = now_s(CLOCK_REALTIME) - now_s(CLOCK_MONOTONIC);

    printf("{\"tag\":\"%s\",\"wall\":%.4f,\"rc\":%d", argv[2], t1 - t0, rc);
    if (rc != 0) { printf(",\"err\":\"%s\"}\n", belay_err_msg()); unlink(out); return 1; }
    g_scope = argv[1];
    qsort(m.eagain_open, m.n_eagain_open, 512, cmpstr);
    belay_manifest_read(out, collect, NULL);
    printf(",\"eagain_cls\":{\"clean_hash\":%zu,\"unstable\":%zu,\"raced\":%zu,\"unreadable\":%zu,\"unverified\":%zu}",
           ecls.clean_hash, ecls.unstable, ecls.raced, ecls.unreadable, ecls.unverified);
    printf(",\"entries\":%zu,\"vanished\":%zu,\"mounts\":%zu", st.entries, st.vanished, st.mounts);
    jflag("raced", &fl_raced); jflag("unstable", &fl_unstable); jflag("unreadable", &fl_unreadable);
    printf(",\"files_opened\":%zu,\"bytes_read\":%llu,\"probe_ok\":%zu,\"probe_eagain\":%zu,"
           "\"probe_eacces\":%zu,\"probe_other\":%zu,\"eof_probed\":%zu,\"eof_eagain\":%zu,\"no_eof\":%zu",
           m.files_opened, (unsigned long long)m.bytes_read, m.probe_ok, m.probe_eagain,
           m.probe_eacces, m.probe_other, m.eof_probed, m.eof_eagain, m.no_eof);
    jstr_list("eagain_open_paths", m.eagain_open, m.n_eagain_open, ELIST);
    jstr_list("eagain_eof_paths", m.eagain_eof, m.n_eagain_eof, LIST);
    printf(",\"stat_seen\":%zu,\"racy_entries\":%zu,\"racy_reg\":%zu,\"racy_reg_bytes\":%llu,\"reg_bytes_hashable\":%llu",
           m.stat_seen, m.racy_entries, m.racy_reg, (unsigned long long)m.racy_reg_bytes,
           (unsigned long long)m.reg_bytes_hashable);
    printf(",\"clock_off_start\":%.3f,\"clock_step\":%.3f", off0, off1 - off0);

    if (mounts >= 0) {
        static char mp1[256][512];
        const double a = now_s(CLOCK_MONOTONIC);
        const size_t n1 = read_mountinfo(mp1, 256);
        mt_read += now_s(CLOCK_MONOTONIC) - a;
        /* Worst case for the per-entry check: N mount points, none matching. */
        static char syn[256][512];
        const size_t nm = (size_t)mounts < 256 ? (size_t)mounts : 256;
        for (size_t i = 0; i < nm; i++) snprintf(syn[i], 512, "%s/__no_such_mount_%zu", argv[1], i);
        struct mt t = { argv[1], syn, nm, 0, 0 };
        const double b = now_s(CLOCK_MONOTONIC);
        belay_manifest_read(out, mt_check, &t);
        const double c = now_s(CLOCK_MONOTONIC);
        struct mt t0r = { argv[1], syn, 0, 0, 0 };
        belay_manifest_read(out, mt_check, &t0r);
        const double d = now_s(CLOCK_MONOTONIC);
        printf(",\"mt_mountinfo_entries\":%zu,\"mt_read_2x_s\":%.6f,\"mt_check_s\":%.4f,"
               "\"mt_baseline_iter_s\":%.4f,\"mt_n\":%zu,\"mt_entries\":%zu",
               n1, mt_read, c - b, d - c, nm, t.entries);
    }
    printf("}\n");
    if (getenv("MEASURE_KEEP")) {
        static unsigned long seq;
        char keep[600];
        snprintf(keep, sizeof keep, "%s/%s.%ld.%lu.ndjson", getenv("MEASURE_KEEP"), argv[2], (long)time(NULL), (unsigned long)getpid() + seq++);
        if (rename(out, keep) == 0) return 0;
    }
    unlink(out);
    return 0;
}
