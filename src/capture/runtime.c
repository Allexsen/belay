/*
 *  The runtime record (belay/runtime.h; test/expect/runtime-v1.md). Every
 *  byte comes from the proc file system's text, read by belay: no program
 *  of the watched machine is run. That text is input like any other -- a
 *  tree shaped like /proc is what the tests give -- so every line and field
 *  is bounded and checked, and a line of the kernel's fixed formats that
 *  does not parse is an error, never a guess.
 */
#define _GNU_SOURCE
#include "belay/runtime.h"

#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LINE_MAX_BYTES 4096     /* a line of net/{tcp,udp,unix}: the kernel's are under 300 */
#define SMALL_MAX      65536    /* a process's cgroup or stat file */
#define LINK_MAX_BYTES 8192     /* a readlink: the kernel's d_path is one page */

/* ---- a growing buffer ---- */

struct sb { char *p; size_t n, cap; bool bad; };

static void sb_put(struct sb *b, const char *s, size_t n) {
    if (b->bad) return;
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->n + n + 1) {
            if (cap > SIZE_MAX / 2) { b->bad = true; return; }
            cap *= 2;
        }
        char *p = realloc(b->p, cap);
        if (p == NULL) { b->bad = true; return; }
        b->p = p;
        b->cap = cap;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

static void sbf(struct sb *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sbf(struct sb *b, const char *fmt, ...) {
    char tmp[256];
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof tmp) { b->bad = true; return; }
    sb_put(b, tmp, (size_t)n);
}

/* `"key":"value"`, or `"key_b64":"..."` when the bytes are not UTF-8 (as a
 * manifest's path_b64), or `"key":null` for NULL. */
static void sb_str(struct sb *b, const char *key, const char *s) {
    if (s == NULL) { sbf(b, "\"%s\":null", key); return; }
    const size_t len = strlen(s);
    char *e = malloc(6 * len + 5);
    if (e == NULL) { b->bad = true; return; }
    if (belay_utf8_valid(s, len)) {
        if (belay_json_escape(e, 6 * len + 5, s, len) == -1) b->bad = true;
        else { sbf(b, "\"%s\":\"", key); sb_put(b, e, strlen(e)); sb_put(b, "\"", 1); }
    } else if (belay_base64_encode(e, 6 * len + 5, s, len) == -1) {
        b->bad = true;
    } else {
        sbf(b, "\"%s_b64\":\"", key);
        sb_put(b, e, strlen(e));
        sb_put(b, "\"", 1);
    }
    free(e);
}

/* ---- reading ---- */

/* The next line of `f` into buf (no newline): 1; 0 at the end; 2 for a line
 * longer than the buffer, read past and not given. */
static int next_line(FILE *f, char *buf, size_t cap) {
    if (fgets(buf, (int)cap, f) == NULL) return 0;
    size_t n = strlen(buf);
    if (n > 0 && buf[n - 1] == '\n') { buf[n - 1] = '\0'; return 1; }
    if (n + 1 < cap) return 1;                  /* the last line, without its newline */
    int c;
    while ((c = fgetc(f)) != EOF && c != '\n') {}
    return 2;
}

/* A whole small file: 0 with *buf (NUL-terminated) and *len; -1 with errno
 * (EFBIG when it is over `max`). */
static int slurp(const char *path, char **buf, size_t *len, size_t max) {
    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd == -1) return -1;
    char *p = malloc(max + 1);
    size_t n = 0;
    ssize_t r = 0;
    if (p == NULL) { close(fd); errno = ENOMEM; return -1; }
    while (n <= max && ((r = read(fd, p + n, max + 1 - n)) > 0 || (r == -1 && errno == EINTR)))
        if (r > 0) n += (size_t)r;
    const int err = errno;
    close(fd);
    if (r == -1 || n > max) {
        free(p);
        errno = r == -1 ? err : EFBIG;
        return -1;
    }
    p[n] = '\0';
    *buf = p;
    *len = n;
    return 0;
}

/* readlink, NUL-terminated and copied; NULL when it cannot be read whole. */
static char *link_text(const char *path) {
    static char buf[LINK_MAX_BYTES];
    const ssize_t n = readlink(path, buf, sizeof buf);
    if (n <= 0 || (size_t)n >= sizeof buf) return NULL;
    buf[n] = '\0';
    if (memchr(buf, '\0', (size_t)n) != NULL) return NULL;
    return strdup(buf);
}

static bool hexval(const char *s, size_t n, uint64_t *out) {
    uint64_t v = 0;
    if (n == 0 || n > 16) return false;
    for (size_t i = 0; i < n; i++) {
        const int c = (unsigned char)s[i];
        const int d = c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10
                    : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
        if (d < 0) return false;
        v = v << 4 | (uint64_t)d;
    }
    *out = v;
    return true;
}

static bool decval(const char *s, uint64_t *out) {
    uint64_t v = 0;
    if (*s == '\0') return false;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || v > (UINT64_MAX - 9) / 10) return false;
        v = v * 10 + (uint64_t)(*s - '0');
    }
    *out = v;
    return true;
}

/* ---- the listeners ---- */

enum kind { K_TCP, K_UDP, K_UNIX };
static const char *const KIND[] = { "tcp", "udp", "unix" };

struct holder { char *exe, *cgroup; };

struct listener {
    enum kind kind;
    int proto;                  /* 4, 6; 0 for unix */
    char *addr;
    long port;                  /* -1 for unix */
    bool client_range;
    uint64_t inode;
    struct holder *h;
    size_t nh, caph;
    char *holders;              /* the JSON of `holders`, built once it is known */
};

struct listeners { struct listener *v; size_t n, cap; };

static int add_listener(struct listeners *ls, struct listener l) {
    if (ls->n == ls->cap) {
        const size_t cap = ls->cap ? 2 * ls->cap : 64;
        struct listener *v = realloc(ls->v, cap * sizeof *v);
        if (v == NULL) return -1;
        ls->v = v;
        ls->cap = cap;
    }
    ls->v[ls->n++] = l;
    return 0;
}

/* An address of net/tcp or net/udp: 8 hex digits (IPv4) or 32 (IPv6), each
 * group of 8 the kernel's print of a 32-bit word as it lies in memory. */
static bool proc_addr(const char *hex, size_t n, char *out, size_t cap, bool *zero) {
    unsigned char b[16];
    if (n != 8 && n != 32) return false;
    for (size_t w = 0; w < n / 8; w++) {
        uint64_t v;
        if (!hexval(hex + 8 * w, 8, &v)) return false;
        const uint32_t u = (uint32_t)v;
        memcpy(b + 4 * w, &u, 4);
    }
    *zero = true;
    for (size_t i = 0; i < n / 2; i++) *zero &= b[i] == 0;
    return out == NULL || inet_ntop(n == 8 ? AF_INET : AF_INET6, b, out, (socklen_t)cap) != NULL;
}

/* Splits `s` at runs of spaces into at most `max` fields. */
static size_t fields(char *s, char **f, size_t max) {
    size_t n = 0;
    while (n < max) {
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '\0') break;
        f[n++] = s;
        while (*s && *s != ' ' && *s != '\t') s++;
        if (*s) *s++ = '\0';
    }
    return n;
}

/* One of net/tcp, tcp6, udp, udp6 (RT-5, RT-6). A file that is not there
 * has no sockets (a kernel without IPv6); one that cannot be parsed is an
 * error. */
static int read_inet(const char *net, const char *name, enum kind kind, int proto, const long range[2],
                     struct listeners *ls) {
    char path[PATH_MAX + 32], line[LINE_MAX_BYTES];
    snprintf(path, sizeof path, "%s/%s", net, name);
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        if (errno == ENOENT) return 0;
        belay_err_set(BELAY_ERR_IO, errno, "runtime: cannot read %s", path);
        return -1;
    }
    int got, rc = 0;
    size_t lineno = 0;
    while (rc == 0 && (got = next_line(f, line, sizeof line)) != 0) {
        if (lineno++ == 0) continue;                    /* the column titles */
        char *fl[12];
        const size_t nf = got == 1 ? fields(line, fl, 12) : 0;
        char *lc = nf >= 10 ? strchr(fl[1], ':') : NULL, *rc_ = nf >= 10 ? strchr(fl[2], ':') : NULL;
        uint64_t lport, rport, st, ino;
        char addr[INET6_ADDRSTRLEN];
        bool lzero, rzero;
        const size_t alen = proto == 4 ? 8 : 32;
        if (lc == NULL || rc_ == NULL || (size_t)(lc - fl[1]) != alen || (size_t)(rc_ - fl[2]) != alen ||
            strlen(lc + 1) != 4 || strlen(rc_ + 1) != 4 || !hexval(lc + 1, 4, &lport) || !hexval(rc_ + 1, 4, &rport) ||
            strlen(fl[3]) != 2 || !hexval(fl[3], 2, &st) || !decval(fl[9], &ino) ||
            !proc_addr(fl[1], alen, addr, sizeof addr, &lzero) || !proc_addr(fl[2], alen, NULL, 0, &rzero)) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "runtime: %s line %zu is not the kernel's format", path, lineno);
            rc = -1;
            break;
        }
        (void)lzero;
        /* TCP: LISTEN (0A). UDP: unconnected -- the remote address and port
         * zero; a connected socket is a client's. */
        if (kind == K_TCP ? st != 0x0A : !(rzero && rport == 0)) continue;
        struct listener l = { .kind = kind, .proto = proto, .port = (long)lport, .inode = ino,
                              .client_range = kind == K_UDP && (long)lport >= range[0] && (long)lport <= range[1] };
        if ((l.addr = strdup(addr)) == NULL || add_listener(ls, l) == -1) {
            free(l.addr);
            belay_err_set(BELAY_ERR_NOMEM, 0, "runtime: out of memory");
            rc = -1;
        }
    }
    if (rc == 0 && ferror(f)) {
        belay_err_set(BELAY_ERR_IO, errno, "runtime: cannot read %s", path);
        rc = -1;
    }
    fclose(f);
    return rc;
}

/* net/unix (RT-7): the listening ones (__SO_ACCEPTCON) with a path that
 * does not begin `@` (an abstract name). The path is the rest of the line,
 * as the kernel printed it -- a name with a newline in it cannot be told
 * from the line after, and a line that does not parse is no listener. */
static int read_unix(const char *net, struct listeners *ls) {
    char path[PATH_MAX + 32], line[LINE_MAX_BYTES];
    snprintf(path, sizeof path, "%s/unix", net);
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        if (errno == ENOENT) return 0;
        belay_err_set(BELAY_ERR_IO, errno, "runtime: cannot read %s", path);
        return -1;
    }
    int got, rc = 0;
    size_t lineno = 0;
    while (rc == 0 && (got = next_line(f, line, sizeof line)) != 0) {
        if (lineno++ == 0 || got != 1) continue;
        char *p = line, *fl[7];
        size_t nf = 0;
        while (nf < 7) {                                /* Num: RefCount Protocol Flags Type St Inode */
            while (*p == ' ') p++;
            if (*p == '\0') break;
            fl[nf++] = p;
            while (*p && *p != ' ') p++;
            if (*p == '\0') break;
            *p++ = '\0';
        }
        uint64_t flags, ino;
        const size_t numlen = nf == 7 ? strlen(fl[0]) : 0;
        if (nf != 7 || numlen < 2 || fl[0][numlen - 1] != ':' || !hexval(fl[3], strlen(fl[3]), &flags) ||
            !decval(fl[6], &ino) || *p == '\0' || *p == '@')
            continue;
        if (!(flags & 0x10000)) continue;
        struct listener l = { .kind = K_UNIX, .proto = 0, .port = -1, .inode = ino };
        if ((l.addr = strdup(p)) == NULL || add_listener(ls, l) == -1) {
            free(l.addr);
            belay_err_set(BELAY_ERR_NOMEM, 0, "runtime: out of memory");
            rc = -1;
        }
    }
    if (rc == 0 && ferror(f)) {
        belay_err_set(BELAY_ERR_IO, errno, "runtime: cannot read %s", path);
        rc = -1;
    }
    fclose(f);
    return rc;
}

/* sys/net/ipv4/ip_local_port_range: two numbers (RT-6). */
static int port_range(const char *proc, long range[2]) {
    char path[PATH_MAX + 64], *buf;
    size_t len;
    snprintf(path, sizeof path, "%s/sys/net/ipv4/ip_local_port_range", proc);
    if (slurp(path, &buf, &len, 256) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "runtime: cannot read %s", path);
        return -1;
    }
    char *f[3];
    const size_t n = fields(buf, f, 3);
    uint64_t lo, hi;
    if (n == 2) {
        char *nl = strchr(f[1], '\n');
        if (nl != NULL) *nl = '\0';
    }
    const bool ok = n == 2 && decval(f[0], &lo) && decval(f[1], &hi) && lo <= hi && hi <= 65535;
    free(buf);
    if (!ok) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "runtime: %s is not two port numbers", path);
        return -1;
    }
    range[0] = (long)lo;
    range[1] = (long)hi;
    return 0;
}

/* ---- the processes ---- */

struct proc {
    long pid;
    char *exe, *cgroup;         /* NULL: not read */
    uint64_t start;             /* clock ticks after boot */
    bool have_start;
};

struct procs { struct proc *v; size_t n, cap; };

/* The path of the cgroup v2 line (`0::<path>`) of `buf`, copied; NULL when
 * it has none. */
static char *v2_line(const char *buf, size_t len) {
    const char *p = buf, *end = buf + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *le = nl != NULL ? nl : end;
        if (le - p >= 3 && memcmp(p, "0::", 3) == 0) return strndup(p + 3, (size_t)(le - p - 3));
        p = le + 1;
    }
    return NULL;
}

/* Field 22 of /proc/<pid>/stat: the 20th after the last `)`. */
static bool start_ticks(const char *buf, uint64_t *out) {
    const char *p = strrchr(buf, ')');
    if (p == NULL) return false;
    p++;
    for (int i = 0; i < 20; i++) {
        while (*p == ' ') p++;
        if (*p == '\0' || *p == '\n') return false;
        if (i == 19) {
            char num[24];
            size_t n = strcspn(p, " \n");
            if (n == 0 || n >= sizeof num) return false;
            memcpy(num, p, n);
            num[n] = '\0';
            return decval(num, out);
        }
        while (*p && *p != ' ' && *p != '\n') p++;
    }
    return false;
}

/* One process: 1 with *pr; 0 when it is gone (it holds nothing now); -1. */
static int read_proc(const char *proc, long pid, struct proc *pr) {
    char path[PATH_MAX + 64], *buf;
    size_t len;
    *pr = (struct proc){ .pid = pid };
    snprintf(path, sizeof path, "%s/%ld/cgroup", proc, pid);
    if (slurp(path, &buf, &len, SMALL_MAX) == 0) {
        pr->cgroup = v2_line(buf, len);
        free(buf);
    } else if (errno == ENOENT || errno == ESRCH) {
        return 0;
    }
    snprintf(path, sizeof path, "%s/%ld/stat", proc, pid);
    if (slurp(path, &buf, &len, SMALL_MAX) == 0) {
        pr->have_start = start_ticks(buf, &pr->start);
        free(buf);
    }
    snprintf(path, sizeof path, "%s/%ld/exe", proc, pid);
    pr->exe = link_text(path);
    return 1;
}

/* RT-12: a process's cgroup is the container's `cg`, or below it (a
 * container's own systemd makes such cgroups). The root cgroup "/" holds
 * only what is in it itself: below it is the whole machine. */
static bool in_cgroup(const char *pcg, const char *cg) {
    if (pcg == NULL) return false;
    const size_t n = strlen(cg);
    return strncmp(pcg, cg, n) == 0 && (pcg[n] == '\0' || (pcg[n] == '/' && strcmp(cg, "/") != 0));
}

static int pid_cmp(const void *a, const void *b) {
    const long x = *(const long *)a, y = *(const long *)b;
    return (x > y) - (x < y);
}

/* The numeric entries of the proc root, sorted. */
static int list_pids(const char *proc, long **out, size_t *n) {
    DIR *d = opendir(proc);
    if (d == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "runtime: cannot list %s", proc);
        return -1;
    }
    long *v = NULL;
    size_t cap = 0;
    *n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        uint64_t pid;
        if (!decval(e->d_name, &pid) || pid == 0 || pid > LONG_MAX) continue;
        if (*n == cap) {
            cap = cap ? 2 * cap : 256;
            long *nv = realloc(v, cap * sizeof *v);
            if (nv == NULL) {
                free(v);
                closedir(d);
                belay_err_set(BELAY_ERR_NOMEM, 0, "runtime: out of memory");
                return -1;
            }
            v = nv;
        }
        v[(*n)++] = (long)pid;
    }
    closedir(d);
    if (*n) qsort(v, *n, sizeof *v, pid_cmp);
    *out = v;
    return 0;
}

struct by_inode { uint64_t inode; size_t at; };

static int inode_cmp(const void *a, const void *b) {
    const uint64_t x = ((const struct by_inode *)a)->inode, y = ((const struct by_inode *)b)->inode;
    return (x > y) - (x < y);
}

static int nullcmp(const char *a, const char *b) {
    if (a == NULL || b == NULL) return (a != NULL) - (b != NULL);
    return strcmp(a, b);
}

static int holder_cmp(const void *a, const void *b) {
    const struct holder *x = a, *y = b;
    const int c = nullcmp(x->exe, y->exe);
    return c ? c : nullcmp(x->cgroup, y->cgroup);
}

static int add_holder(struct listener *l, const struct proc *pr) {
    for (size_t i = 0; i < l->nh; i++)
        if (nullcmp(l->h[i].exe, pr->exe) == 0 && nullcmp(l->h[i].cgroup, pr->cgroup) == 0) return 0;
    if (l->nh == l->caph) {
        const size_t cap = l->caph ? 2 * l->caph : 4;
        struct holder *v = realloc(l->h, cap * sizeof *v);
        if (v == NULL) return -1;
        l->h = v;
        l->caph = cap;
    }
    l->h[l->nh++] = (struct holder){ pr->exe, pr->cgroup };     /* borrowed from the process */
    return 0;
}

/* RT-8: as root, each process's descriptors that are a listener's socket.
 * 1 when every process that is there was read; 0 when one's descriptors
 * could not be (the holders are then not known); -1. */
static int holders(const char *proc, const struct procs *ps, struct listeners *ls) {
    struct by_inode *ix = ls->n ? malloc(ls->n * sizeof *ix) : NULL;
    if (ls->n && ix == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "runtime: out of memory");
        return -1;
    }
    for (size_t i = 0; i < ls->n; i++) ix[i] = (struct by_inode){ ls->v[i].inode, i };
    if (ls->n) qsort(ix, ls->n, sizeof *ix, inode_cmp);
    int rc = 1;
    for (size_t p = 0; p < ps->n && rc != -1 && ls->n; p++) {
        char path[PATH_MAX + 64];
        snprintf(path, sizeof path, "%s/%ld/fd", proc, ps->v[p].pid);
        DIR *d = opendir(path);
        if (d == NULL) {
            if (errno != ENOENT && errno != ESRCH) rc = 0;      /* there, and not readable */
            continue;
        }
        const int dfd = dirfd(d);
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            char t[64];
            const ssize_t n = readlinkat(dfd, e->d_name, t, sizeof t - 1);
            if (n <= 0) continue;
            t[n] = '\0';
            uint64_t ino;
            const size_t tl = (size_t)n;
            if (tl < 10 || memcmp(t, "socket:[", 8) != 0 || t[tl - 1] != ']') continue;
            t[tl - 1] = '\0';
            if (!decval(t + 8, &ino)) continue;
            const struct by_inode key = { ino, 0 };
            const struct by_inode *hit = bsearch(&key, ix, ls->n, sizeof *ix, inode_cmp);
            if (hit != NULL && add_holder(&ls->v[hit->at], &ps->v[p]) == -1) {
                belay_err_set(BELAY_ERR_NOMEM, 0, "runtime: out of memory");
                rc = -1;
                break;
            }
        }
        closedir(d);
    }
    free(ix);
    return rc;
}

/* ---- the services (RT-3) ---- */

static bool is_service(const char *cg) {
    if (cg == NULL) return false;
    const char *last = strrchr(cg, '/');
    last = last != NULL ? last + 1 : cg;
    const size_t n = strlen(last);
    return n > 8 && strcmp(last + n - 8, ".service") == 0;
}

/* By cgroup, then the oldest first: start time, then pid. */
static int svc_cmp(const void *a, const void *b) {
    const struct proc *x = *(const struct proc *const *)a, *y = *(const struct proc *const *)b;
    int c = strcmp(x->cgroup, y->cgroup);
    if (c) return c;
    if (x->have_start != y->have_start) return x->have_start ? -1 : 1;
    if (x->start != y->start) return x->start < y->start ? -1 : 1;
    return (x->pid > y->pid) - (x->pid < y->pid);
}

/* ---- writing ---- */

static void holders_json(struct sb *b, const struct listener *l, bool known) {
    if (!known) { sb_put(b, "null", 4); return; }
    sb_put(b, "[", 1);
    for (size_t i = 0; i < l->nh; i++) {
        sb_put(b, i ? ",{" : "{", i ? 2 : 1);
        sb_str(b, "exe", l->h[i].exe);
        sb_put(b, ",", 1);
        sb_str(b, "cgroup", l->h[i].cgroup);
        sb_put(b, "}", 1);
    }
    sb_put(b, "]", 1);
}

/* RT-2: by listener, port, addr; then proto and holders, so that the same
 * inputs give the same bytes. */
static int listener_cmp(const void *a, const void *b) {
    const struct listener *x = a, *y = b;
    if (x->kind != y->kind) return x->kind < y->kind ? -1 : 1;
    if (x->port != y->port) return x->port < y->port ? -1 : 1;
    int c = strcmp(x->addr, y->addr);
    if (c) return c;
    if (x->proto != y->proto) return x->proto < y->proto ? -1 : 1;
    return strcmp(x->holders, y->holders);
}

static bool write_all(int fd, const char *p, size_t n) {
    while (n > 0) {
        const ssize_t w = write(fd, p, n);
        if (w == -1 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w;
        n -= (size_t)w;
    }
    return true;
}

static int publish(const char *out_path, const struct sb *b, char hex[65]) {
    char tmp[PATH_MAX + 32];
    if ((size_t)snprintf(tmp, sizeof tmp, "%s.tmp.XXXXXX", out_path) >= sizeof tmp) {
        belay_err_set(BELAY_ERR_RANGE, 0, "runtime: %s: too long", out_path);
        return -1;
    }
    const int fd = mkstemp(tmp);                /* mode 600 */
    if (fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "runtime: cannot create %s", tmp);
        return -1;
    }
    bool ok = fchmod(fd, 0600) == 0 && write_all(fd, b->p, b->n) && fsync(fd) == 0;
    const int err = errno;
    close(fd);
    if (ok && rename(tmp, out_path) != 0) ok = false;
    if (!ok) {
        const int e2 = errno ? errno : err;
        unlink(tmp);
        belay_err_set(BELAY_ERR_IO, e2, "runtime: cannot write %s", out_path);
        return -1;
    }
    struct belay_sha256 h;
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_init(&h);
    belay_sha256_update(&h, b->p, b->n);
    belay_sha256_final(&h, d);
    belay_hex_encode(hex, d, sizeof d);
    return 0;
}

int belay_runtime_capture(const struct belay_runtime_opts *opts, const char *out_path,
                          struct belay_runtime_stats *stats) {
    if (opts == NULL || opts->proc_root == NULL || out_path == NULL || stats == NULL || opts->net_pid < 0) {
        belay_err_set(BELAY_ERR_INVALID, 0, "runtime: null argument");
        return -1;
    }
    const char *proc = opts->proc_root;
    char net[PATH_MAX], ns[PATH_MAX];
    struct stat sb;
    if (opts->net_pid > 0) {
        snprintf(net, sizeof net, "%s/%ld/net", proc, opts->net_pid);
        snprintf(ns, sizeof ns, "%s/%ld/ns/net", proc, opts->net_pid);
    } else {
        snprintf(net, sizeof net, "%s/net", proc);
        snprintf(ns, sizeof ns, "%s/self/ns/net", proc);
    }
    if (stat(net, &sb) != 0 || !S_ISDIR(sb.st_mode)) return 0;     /* no proc file system here */
    /* RT-12: the container's cgroup, and whether its network is the host's */
    char *cg = NULL;
    bool host_net = false;
    if (opts->container) {
        char p[PATH_MAX], *buf;
        size_t len;
        snprintf(p, sizeof p, "%s/%ld/cgroup", proc, opts->net_pid);
        if (slurp(p, &buf, &len, SMALL_MAX) == 0) {
            cg = v2_line(buf, len);
            free(buf);
        }
        if (cg == NULL) {
            belay_err_set(BELAY_ERR_IO, errno, "runtime: no cgroup v2 path for the container's first process (%s)", p);
            return -1;
        }
        snprintf(p, sizeof p, "%s/self/ns/net", proc);
        char *mine = link_text(p), *its = link_text(ns);
        host_net = mine != NULL && its != NULL && strcmp(mine, its) == 0;
        free(mine);
        free(its);
    }

    const bool root = opts->root < 0 ? geteuid() == 0 : opts->root > 0;
    struct listeners ls = { 0 };
    struct procs ps = { 0 };
    long *pids = NULL, range[2];
    size_t npids = 0;
    struct sb b = { 0 };
    int rc = -1;
    if (!host_net && (port_range(proc, range) == -1 || read_inet(net, "tcp", K_TCP, 4, range, &ls) == -1 ||
                      read_inet(net, "tcp6", K_TCP, 6, range, &ls) == -1 ||
                      read_inet(net, "udp", K_UDP, 4, range, &ls) == -1 ||
                      read_inet(net, "udp6", K_UDP, 6, range, &ls) == -1 || read_unix(net, &ls) == -1))
        goto out;
    if (list_pids(proc, &pids, &npids) == -1) goto out;
    if (npids && (ps.v = calloc(npids, sizeof *ps.v)) == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "runtime: out of memory");
        goto out;
    }
    for (size_t i = 0; i < npids; i++) {
        const int got = read_proc(proc, pids[i], &ps.v[ps.n]);
        if (got == 1 && cg != NULL && !in_cgroup(ps.v[ps.n].cgroup, cg)) {     /* RT-12: not the container's */
            free(ps.v[ps.n].exe);
            free(ps.v[ps.n].cgroup);
            continue;
        }
        if (got == 1) ps.n++;
    }
    /* RT-9: not root, no holders are read: another user's descriptors are
     * closed to belay, so what it could read would be a part told as all. */
    int known = 0;
    if (root && (known = holders(proc, &ps, &ls)) == -1) goto out;
    size_t unknown = 0;
    for (size_t i = 0; i < ls.n; i++) {
        struct sb hb = { 0 };
        if (ls.v[i].nh) qsort(ls.v[i].h, ls.v[i].nh, sizeof *ls.v[i].h, holder_cmp);
        holders_json(&hb, &ls.v[i], known == 1);
        if (hb.bad) { free(hb.p); b.bad = true; break; }
        ls.v[i].holders = hb.p;
        unknown += known != 1;
    }
    if (!b.bad && ls.n) qsort(ls.v, ls.n, sizeof *ls.v, listener_cmp);

    /* RT-1: the header. */
    const char *nsl = link_text(ns);
    uint64_t nsino = 0;
    bool have_ns = false;
    if (nsl != NULL) {
        const size_t n = strlen(nsl);
        if (n > 6 && memcmp(nsl, "net:[", 5) == 0 && nsl[n - 1] == ']') {
            char num[24];
            if (n - 6 < sizeof num) {
                memcpy(num, nsl + 5, n - 6);
                num[n - 6] = '\0';
                have_ns = decval(num, &nsino);
            }
        }
        free((void *)nsl);
    }
    sb_put(&b, "{\"belay_runtime\":1,\"netns\":", 27);
    if (host_net) sb_put(&b, "\"host\"", 6);
    else if (have_ns) sbf(&b, "%llu", (unsigned long long)nsino);
    else sb_put(&b, "null", 4);
    sbf(&b, ",\"root\":%s,\"source\":", root ? "true" : "false");
    const char *src = opts->source_json != NULL ? opts->source_json : "null";
    sb_put(&b, src, strlen(src));
    sb_put(&b, "}\n", 2);
    /* RT-2 */
    for (size_t i = 0; i < ls.n && !b.bad; i++) {
        const struct listener *l = &ls.v[i];
        sbf(&b, "{\"listener\":\"%s\",", KIND[l->kind]);
        if (l->proto) sbf(&b, "\"proto\":%d,", l->proto);
        else sb_put(&b, "\"proto\":null,", 13);
        sb_str(&b, "addr", l->addr);
        if (l->port >= 0) sbf(&b, ",\"port\":%ld", l->port);
        else sb_put(&b, ",\"port\":null", 12);
        if (l->client_range) sb_put(&b, ",\"client_range\":true", 20);
        sb_put(&b, ",\"holders\":", 11);
        sb_put(&b, l->holders, strlen(l->holders));
        sb_put(&b, "}\n", 2);
    }
    /* RT-3 */
    size_t nsvc = 0;
    struct proc **sv = ps.n ? malloc(ps.n * sizeof *sv) : NULL;
    if (ps.n && sv == NULL) b.bad = true;
    size_t m = 0;
    for (size_t i = 0; sv != NULL && i < ps.n; i++)
        if (is_service(ps.v[i].cgroup)) sv[m++] = &ps.v[i];
    if (m) qsort(sv, m, sizeof *sv, svc_cmp);
    const long hz = sysconf(_SC_CLK_TCK);
    for (size_t i = 0; i < m && !b.bad;) {
        size_t j = i;
        while (j < m && strcmp(sv[j]->cgroup, sv[i]->cgroup) == 0) j++;
        const struct proc *old = sv[i];
        sb_put(&b, "{", 1);
        sb_str(&b, "service", old->cgroup);
        sbf(&b, ",\"processes\":%zu,", j - i);
        sb_str(&b, "exe", old->exe);
        if (old->have_start && hz > 0 && old->start / (uint64_t)hz <= (uint64_t)INT64_MAX / 1000000000u - 1)
            sbf(&b, ",\"started_ns\":%llu}\n",
                (unsigned long long)(old->start / (uint64_t)hz * 1000000000u +
                                     old->start % (uint64_t)hz * 1000000000u / (uint64_t)hz));
        else
            sb_put(&b, ",\"started_ns\":null}\n", 20);
        nsvc++;
        i = j;
    }
    free(sv);
    /* RT-4 */
    sbf(&b, "{\"listeners\":%zu,\"services\":%zu,\"holders_unknown\":%zu}\n", ls.n, nsvc, unknown);
    if (b.bad) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "runtime: out of memory");
        goto out;
    }
    if (publish(out_path, &b, stats->sha256) == -1) goto out;
    stats->listeners = ls.n;
    stats->services = nsvc;
    stats->holders_unknown = unknown;
    rc = 1;
out:
    for (size_t i = 0; i < ls.n; i++) {
        free(ls.v[i].addr);
        free(ls.v[i].h);
        free(ls.v[i].holders);
    }
    free(ls.v);
    for (size_t i = 0; i < ps.n; i++) {
        free(ps.v[i].exe);
        free(ps.v[i].cgroup);
    }
    free(ps.v);
    free(pids);
    free(b.p);
    free(cg);
    return rc;
}
