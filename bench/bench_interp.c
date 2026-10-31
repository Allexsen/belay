/*
 *  What the interpreters cost (Phase 4, decision Q5: per-diff state bounded
 *  and measured on the largest real dpkg status): time and peak memory of
 *  one interpreter over one diff's paths, its end hook included, its inputs
 *  read from a store as a diff reads them. Each scenario runs in a process
 *  of its own (`run`), so its peak RSS is its own; `none` is the baseline.
 *
 *    bench_interp gen <dir> [status]   write every scenario's store objects
 *    bench_interp run <dir> <scenario> one scenario: seconds, peak RSS, output
 *    bench_interp all <dir> [status]   gen, then each scenario in a child
 *
 *  [status] is a real dpkg status to build the dpkg scenarios from (default
 *  /var/lib/dpkg/status): its stanzas, copied under new names to ~3 MB.
 */
#define _GNU_SOURCE
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/interp.h"
#include "belay/manifest.h"
#include "interp/findings_internal.h"
#include "schema/finding_schema.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char g_dir[512];

/* ---- a growable buffer, and the store ---- */

struct buf { char *p; size_t n, cap; };
static void bput(struct buf *b, const char *s, size_t n) {
    if (b->n + n + 1 > b->cap) {
        b->cap = (b->n + n + 1) * 2;
        b->p = realloc(b->p, b->cap);
        if (b->p == NULL) abort();
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}
static void bprintf(struct buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void bprintf(struct buf *b, const char *fmt, ...) {
    char tmp[8192];
    va_list a;
    va_start(a, fmt);
    const int n = vsnprintf(tmp, sizeof tmp, fmt, a);
    va_end(a);
    bput(b, tmp, (size_t)n);
}

static void store_put(const char *data, size_t n, char hex[65]) {
    struct belay_sha256 c;
    uint8_t h[32];
    char p[700];
    belay_sha256_init(&c);
    belay_sha256_update(&c, data, n);
    belay_sha256_final(&c, h);
    belay_hex_encode(hex, h, sizeof h);
    snprintf(p, sizeof p, "%s/store/%.2s", g_dir, hex);
    mkdir(p, 0700);
    snprintf(p, sizeof p, "%s/store/%.2s/%s", g_dir, hex, hex + 2);
    FILE *f = fopen(p, "wb");
    if (f == NULL || (n && fwrite(data, 1, n, f) != n)) abort();
    fclose(f);
}

/* name -> hex, kept in <dir>/names so `run` finds each scenario's objects. */
static void name_put(const char *name, struct buf *b) {
    char hex[65], p[700];
    store_put(b->p ? b->p : "", b->n, hex);
    snprintf(p, sizeof p, "%s/names", g_dir);
    FILE *f = fopen(p, "a");
    fprintf(f, "%s %s %zu\n", name, hex, b->n);
    fclose(f);
    printf("  %-22s %10zu bytes\n", name, b->n);
    free(b->p);
    memset(b, 0, sizeof *b);
}

static int name_get(const char *name, char hex[65]) {
    char p[700], n[128], h[65];
    size_t len;
    snprintf(p, sizeof p, "%s/names", g_dir);
    FILE *f = fopen(p, "r");
    if (f == NULL) return -1;
    while (fscanf(f, "%127s %64s %zu", n, h, &len) == 3)
        if (strcmp(n, name) == 0) { memcpy(hex, h, 65); fclose(f); return 0; }
    fclose(f);
    return -1;
}

/* ---- generating the inputs ---- */

static char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    struct buf b = { 0 };
    char tmp[65536];
    size_t r;
    while ((r = fread(tmp, 1, sizeof tmp, f)) > 0) bput(&b, tmp, r);
    fclose(f);
    *n = b.n;
    return b.p;
}

/* The real status's stanzas, copied under new package names until ~3 MB;
 * the after side upgrades every 10th package, removes every 50th (Status
 * "deinstall ok config-files") and installs one new package per 50. */
static void gen_dpkg(const char *status) {
    size_t n;
    char *real = slurp(status, &n);
    if (real == NULL) { fprintf(stderr, "cannot read %s\n", status); exit(1); }
    struct buf b = { 0 }, a = { 0 };
    size_t pkgs = 0;
    for (int copy = 0; b.n < 3u * 1024u * 1024u; copy++) {
        char *s = real;
        while (s < real + n) {
            char *e = strstr(s, "\n\n");
            e = e ? e + 2 : real + n;
            const char *pk = strstr(s, "Package: ");
            if (pk == NULL || pk >= e) { s = e; continue; }
            const char *eol = strchr(pk, '\n');
            pkgs++;
            /* before: the stanza with its Package renamed */
            bput(&b, s, (size_t)(pk - s));
            bprintf(&b, "Package: %.*s-c%d", (int)(eol - pk - 9), pk + 9, copy);
            bput(&b, eol, (size_t)(e - eol));
            if (pkgs % 50 == 0) {                               /* removed */
                bprintf(&a, "Package: %.*s-c%d\nStatus: deinstall ok config-files\nVersion: 1\n\n",
                        (int)(eol - pk - 9), pk + 9, copy);
            } else {
                bput(&a, s, (size_t)(pk - s));
                bprintf(&a, "Package: %.*s-c%d", (int)(eol - pk - 9), pk + 9, copy);
                const char *v = strstr(eol, "\nVersion: ");
                if (pkgs % 10 == 0 && v != NULL && v < e) {     /* upgraded */
                    const char *ve = strchr(v + 1, '\n');
                    bput(&a, eol, (size_t)(ve - eol));
                    bput(&a, "+bench1", 7);
                    bput(&a, ve, (size_t)(e - ve));
                } else {
                    bput(&a, eol, (size_t)(e - eol));
                }
            }
            if (pkgs % 50 == 0)
                bprintf(&a, "Package: newpkg%zu\nStatus: install ok installed\nArchitecture: amd64\n"
                            "Version: 1.0-1\n\n", pkgs);
            s = e;
        }
    }
    free(real);
    printf("  dpkg: %zu packages before\n", pkgs);
    name_put("status_before", &b);
    name_put("status_after", &a);

    /* The parser's bound: 262,144 stanzas, every one installed after. */
    struct buf big = { 0 };
    for (int i = 0; i < 262144; i++)
        bprintf(&big, "Package: p%d\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.%d\n\n", i, i);
    name_put("status_bound", &big);
}

static void gen_pip(void) {
    struct buf b = { 0 }, a = { 0 };
    for (int i = 0; i < 10000; i++) {
        bprintf(&b, "pkg/sub%d/module_%d.py,sha256=%064d,%d\n", i % 97, i, i, 1000 + i);
        if (i % 7 == 0) continue;                                       /* removed */
        bprintf(&a, "pkg/sub%d/module_%d.py,sha256=%064d,%d\n", i % 97, i, i % 5 ? i : i + 1, 1000 + i);
    }
    for (int i = 0; i < 1500; i++) bprintf(&a, "pkg/new/added_%d.py,sha256=%064d,10\n", i, i);
    name_put("record_before", &b);
    name_put("record_after", &a);
    /* At the bound: 262,144 rows of 64 bytes, 16 MiB a side, every row changed. */
    for (int i = 0; i < 262144; i++) {
        bprintf(&b, "p/%08d.py,sha256=%034d,%07d\n", i, i, i);
        bprintf(&a, "p/%08d.py,sha256=%034d,%07d\n", i, i + 1, i);
    }
    name_put("record_bound_before", &b);
    name_put("record_bound_after", &a);
}

static void gen_text(void) {
    struct buf b = { 0 }, a = { 0 };
    /* 200,000 lines, 1,000 of them changed, spread: edit distance 2,000. */
    for (int i = 0; i < 200000; i++) {
        bprintf(&b, "line %d of a long configuration file, value=%d\n", i, i);
        bprintf(&a, i % 200 == 0 ? "line %d CHANGED value=%d\n" : "line %d of a long configuration file, value=%d\n", i, i);
    }
    name_put("text_before", &b);
    name_put("text_after", &a);
}

static void gen_git(void) {
    struct buf b = { 0 }, a = { 0 };
    bput(&b, "# pack-refs with: peeled fully-peeled sorted \n", 46);
    bput(&a, "# pack-refs with: peeled fully-peeled sorted \n", 46);
    for (int i = 0; i < 100000; i++) {
        bprintf(&b, "%040d refs/tags/v%06d\n", i, i);
        bprintf(&a, "%040d refs/tags/v%06d\n", i % 2 ? i : i + 1, i);
    }
    name_put("packed_before", &b);
    name_put("packed_after", &a);
}

/* ---- running one scenario ---- */

static struct belay_entry entry(const char *name) {
    struct belay_entry e;
    memset(&e, 0, sizeof e);
    e.type = BELAY_T_REG;
    e.mode = 0644;
    if (name != NULL) {
        if (name_get(name, e.stored_hex) == -1) { fprintf(stderr, "no object %s: run gen\n", name); exit(1); }
        e.has_stored = true;
    }
    return e;
}

struct sink { struct belay_findings f; struct belay_events ev; size_t findings; };

static void path(struct sink *k, enum belay_interp_id id, void *st, struct belay_content *c,
                 const char *abs, const struct belay_entry *b, const struct belay_entry *a,
                 const char *outcome) {
    const struct belay_interp *it = belay_interp_builtin(id);
    findings_reset(&k->f, id);
    if (it->end) events_claim(&k->ev, id, abs + 3, strlen(abs) - 3);
    const struct belay_interp_input in = { abs + 3, strlen(abs) - 3, abs, strlen(abs), b, a, outcome, 0, c };
    if (it->explain(st, &in, &k->f) == BELAY_INTERP_ERROR) { fprintf(stderr, "%s: error\n", abs); exit(1); }
    k->findings += findings_count(&k->f);
}

static int run(const char *scenario) {
    struct belay_content *c = NULL;
    char store[700];
    snprintf(store, sizeof store, "%s/store", g_dir);
    if (belay_content_open(store, &c) == -1) { fprintf(stderr, "%s\n", belay_err_msg()); return 1; }
    struct sink k;
    memset(&k, 0, sizeof k);
    events_init(&k.ev);
    enum belay_interp_id id = BELAY_INTERP_BINARY;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    void *st = NULL;
    if (strcmp(scenario, "none") == 0) {
        /* the baseline: a process that opened the store */
    } else if (strcmp(scenario, "dpkg_3mb") == 0 || strcmp(scenario, "dpkg_bound") == 0) {
        id = BELAY_INTERP_DPKG;
        st = belay_interp_builtin(id)->begin();
        const bool bound = strcmp(scenario, "dpkg_bound") == 0;
        const struct belay_entry b = entry("status_before"), a = entry(bound ? "status_bound" : "status_after");
        path(&k, id, st, c, "/s/var/lib/dpkg/status", bound ? NULL : &b, &a, bound ? "added" : "modified");
    } else if (strcmp(scenario, "pip_record_10k") == 0) {
        id = BELAY_INTERP_PIP;
        st = belay_interp_builtin(id)->begin();
        const struct belay_entry b = entry("record_before"), a = entry("record_after");
        path(&k, id, st, c, "/s/sp/big-1.0.dist-info/RECORD", &b, &a, "modified");
    } else if (strcmp(scenario, "pip_record_bound") == 0) {
        id = BELAY_INTERP_PIP;
        st = belay_interp_builtin(id)->begin();
        const struct belay_entry b = entry("record_bound_before"), a = entry("record_bound_after");
        path(&k, id, st, c, "/s/sp/big-1.0.dist-info/RECORD", &b, &a, "modified");
    } else if (strcmp(scenario, "pip_5000_upgrades") == 0 || strcmp(scenario, "pip_100k_installs") == 0) {
        id = BELAY_INTERP_PIP;
        st = belay_interp_builtin(id)->begin();
        const struct belay_entry e = entry(NULL);
        const bool many = strcmp(scenario, "pip_100k_installs") == 0;
        char p[256];
        for (int i = 0; i < (many ? 100000 : 5000); i++) {
            if (!many) {
                snprintf(p, sizeof p, "/s/sp/package_%05d-1.%d.dist-info/RECORD", i, i);
                path(&k, id, st, c, p, &e, NULL, "removed");
            }
            snprintf(p, sizeof p, "/s/sp/package_%05d-2.%d.dist-info/RECORD", i, i);
            path(&k, id, st, c, p, NULL, &e, "added");
        }
    } else if (strcmp(scenario, "text_200k_lines") == 0) {
        id = BELAY_INTERP_TEXT;
        const struct belay_entry b = entry("text_before"), a = entry("text_after");
        path(&k, id, st, c, "/s/etc/big.conf", &b, &a, "modified");
    } else if (strcmp(scenario, "git_packed_100k") == 0) {
        id = BELAY_INTERP_GIT;
        const struct belay_entry b = entry("packed_before"), a = entry("packed_after");
        path(&k, id, st, c, "/s/r/.git/packed-refs", &b, &a, "modified");
    } else {
        fprintf(stderr, "unknown scenario %s\n", scenario);
        return 1;
    }
    const struct belay_interp *it = belay_interp_builtin(id);
    if (it->end != NULL) {
        k.ev.interp = id;
        if (it->end(st, &k.ev) == BELAY_INTERP_ERROR) { fprintf(stderr, "end: error\n"); return 1; }
    }
    FILE *null = fopen("/dev/null", "w");
    events_write(&k.ev, null);
    fclose(null);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("%-20s %8.3f s %8ld KiB peak  %7zu findings %7zu events\n", scenario,
           (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9, ru.ru_maxrss,
           k.findings, events_count(&k.ev));
    findings_free(&k.f);
    events_free(&k.ev);
    belay_content_close(c);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: bench_interp gen|run|all <dir> [status|scenario]\n");
        return 2;
    }
    snprintf(g_dir, sizeof g_dir, "%s", argv[2]);
    if (strcmp(argv[1], "run") == 0 && argc == 4) return run(argv[3]);
    if (strcmp(argv[1], "gen") == 0 || strcmp(argv[1], "all") == 0) {
        char p[700];
        mkdir(g_dir, 0700);
        snprintf(p, sizeof p, "%s/store", g_dir);
        mkdir(p, 0700);
        snprintf(p, sizeof p, "%s/names", g_dir);
        unlink(p);
        gen_dpkg(argc > 3 ? argv[3] : "/var/lib/dpkg/status");
        gen_pip();
        gen_text();
        gen_git();
        if (strcmp(argv[1], "gen") == 0) return 0;
        static const char *const S[] = { "none", "dpkg_3mb", "dpkg_bound", "pip_record_10k",
                                         "pip_record_bound", "pip_5000_upgrades", "pip_100k_installs", "text_200k_lines",
                                         "git_packed_100k" };
        for (size_t i = 0; i < sizeof S / sizeof S[0]; i++) {
            fflush(stdout);
            const pid_t pid = fork();
            if (pid == 0) execl("/proc/self/exe", argv[0], "run", g_dir, S[i], (char *)NULL), _exit(127);
            int ws;
            waitpid(pid, &ws, 0);
            if (!WIFEXITED(ws) || WEXITSTATUS(ws) != 0) return 1;
        }
        return 0;
    }
    return 2;
}
