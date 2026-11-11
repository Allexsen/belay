#define _GNU_SOURCE
#include "watch/ledger.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"

#define FILE_MAX ((size_t)1 << 30)      /* a day's file: read whole, never more than this */

void (*ledger_before_line)(void) = NULL;
long ledger_fail_at = 0;
long ledger_fail_sync_at = 0;
bool ledger_fail_dirsync = false;
static long g_puts, g_syncs;

void wsb_json(struct wsb *b, const char *s) {
    const size_t n = strlen(s);
    char *e = malloc(6 * n + 1);
    if (e == NULL) { b->bad = true; return; }
    if (!belay_utf8_valid(s, n) || belay_json_escape(e, 6 * n + 1, s, n) == -1) {
        belay_err_clear();
        wsb_f(b, "\"?\"");
    } else {
        wsb_f(b, "\"%s\"", e);
    }
    free(e);
}

bool ledger_id_valid(const char *s) {
    const size_t n = s == NULL ? 0 : strlen(s);
    if (n == 0 || n > WATCH_ID_MAX) return false;
    for (size_t i = 0; i < n; i++)
        if (s[i] <= 0x20 || s[i] >= 0x7f || s[i] == '"' || s[i] == '\\') return false;
    return true;
}

/* The platform's barrier where there is one (macOS), so what was written
 * reaches the disk before what is written next. */
static int barrier(int fd) {
#ifdef F_BARRIERFSYNC
    if (fcntl(fd, F_BARRIERFSYNC) == 0) return 0;
#endif
    return fsync(fd);
}

/* put_line's sync of the line it has just written; a test can make the Nth fail. */
static int line_sync(int fd) {
    if (ledger_fail_sync_at != 0 && ++g_syncs == ledger_fail_sync_at) { errno = EIO; return -1; }
    return barrier(fd);
}

static void day_of(int64_t ns, char day[11]) {
    const time_t t = (time_t)(ns / 1000000000LL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(day, 11, "%Y-%m-%d", &tm);
}

static bool is_day(const char *s) {
    for (int i = 0; i < 10; i++)
        if (i == 4 || i == 7 ? s[i] != '-' : s[i] < '0' || s[i] > '9') return false;
    return true;
}

/* "ledger-YYYY-MM-DD.ndjson" -> the day, or false. */
static bool ledger_name(const char *name, char day[11]) {
    if (strlen(name) != 24 || strncmp(name, "ledger-", 7) != 0 || strcmp(name + 17, ".ndjson") != 0 || !is_day(name + 7))
        return false;
    memcpy(day, name + 7, 10);
    day[10] = '\0';
    return true;
}

/* A file of watch/ read whole: a regular file, opened without following a
 * link or waiting. 0 with *buf (malloc'd, NUL after the end); 1 when it is
 * not there; -1 with belay_err. */
static int read_all(const struct ledger *l, const char *name, char **buf, size_t *len) {
    const int fd = openat(l->dfd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        if (errno == ENOENT) return 1;
        belay_err_set(errno == ELOOP ? BELAY_ERR_CORRUPT : BELAY_ERR_IO, errno, "cannot read %s/%s", l->dir, name);
        return -1;
    }
    struct stat fs;
    if (fstat(fd, &fs) == -1 || !S_ISREG(fs.st_mode) || (uint64_t)fs.st_size > FILE_MAX) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/%s is not a file belay wrote", l->dir, name);
        close(fd);
        return -1;
    }
    char *p = malloc((size_t)fs.st_size + 1);
    if (p == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        close(fd);
        return -1;
    }
    size_t n = 0;
    while (n < (size_t)fs.st_size) {
        const ssize_t k = read(fd, p + n, (size_t)fs.st_size - n);
        if (k == -1 && errno == EINTR) continue;
        if (k == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot read %s/%s", l->dir, name);
            free(p);
            close(fd);
            return -1;
        }
        if (k == 0) break;
        n += (size_t)k;
    }
    close(fd);
    p[n] = '\0';
    *buf = p;
    *len = n;
    return 0;
}

/* ---- the state ---- */

static void state_json(struct wsb *b, const struct wstate *s) {
    wsb_f(b, "\"state\":{\"cursor\":%ld,\"cursor_ns\":%lld,\"list\":\"%s\",\"list_trouble\":", s->cursor,
          (long long)s->cursor_ns, s->list);
    wsb_json(b, s->list_trouble);
    wsb_f(b, ",\"open\":[");
    for (size_t i = 0; i < s->n_open; i++)
        wsb_f(b, "%s[\"%s\",\"%s\",\"%s\",%lld]", i ? "," : "", s->open[i].id, s->open[i].session, s->open[i].agent,
              (long long)s->open[i].ns);
    wsb_f(b, "],\"marks\":[");
    for (size_t i = 0; i < s->n_marks; i++)
        wsb_f(b, "%s[\"%s\",\"%s\",\"%s\",%ld,%lld,%lld]", i ? "," : "", s->marks[i].session, s->marks[i].name,
              s->marks[i].day, s->marks[i].off, (long long)s->marks[i].ns, (long long)s->marks[i].seen_ns);
    wsb_f(b, "],\"kills\":[");
    for (size_t i = 0; i < s->n_kills; i++) wsb_f(b, "%s[\"%s\",%ld]", i ? "," : "", s->kills[i].session, s->kills[i].n);
    wsb_f(b, "],\"told\":[");
    for (size_t i = 0; i < s->n_told; i++) wsb_f(b, "%s\"%s\"", i ? "," : "", s->told[i]);
    wsb_f(b, "]}");
}

static bool state_parse(const struct jval *line, struct wstate *s);

static bool id_at(const struct jval *arr, size_t i, char *out) {
    if (arr == NULL || arr->t != J_ARR || i >= arr->n || arr->kids[i].t != J_STR) return false;
    /* an agent may be "": the main thread */
    if (arr->kids[i].s_len != 0 && !ledger_id_valid(arr->kids[i].s)) return false;
    snprintf(out, WATCH_ID_MAX + 1, "%s", arr->kids[i].s);
    return true;
}

static bool int_at(const struct jval *arr, size_t i, int64_t *out) {
    if (arr == NULL || arr->t != J_ARR || i >= arr->n || arr->kids[i].t != J_NUM || !arr->kids[i].integer) return false;
    *out = arr->kids[i].i;
    return true;
}

bool ledger_state(const struct jval *line, struct wstate *s) { return state_parse(line, s); }

/* A line's state into *s. false when the line has none that belay wrote. */
static bool state_parse(const struct jval *line, struct wstate *s) {
    const struct jval *v = jget(line, "state");
    if (v == NULL || v->t != J_OBJ || jint(line, "belay_watch", 0) != LEDGER_VERSION) return false;
    memset(s, 0, sizeof *s);
    s->cursor = (long)jint(v, "cursor", -1);
    s->cursor_ns = jint(v, "cursor_ns", 0);
    const char *list = jstr(v, "list");
    if (s->cursor < 0 || s->cursor > 999999999L || (list[0] != '\0' && strlen(list) != 64)) return false;
    for (const char *c = list; *c != '\0'; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f'))) return false;
    snprintf(s->list, sizeof s->list, "%s", list);
    snprintf(s->list_trouble, sizeof s->list_trouble, "%s", jstr(v, "list_trouble"));
    const struct jval *a = jget(v, "open");
    if (a == NULL || a->t != J_ARR || a->n > W_OPEN_MAX) return false;
    for (size_t i = 0; i < a->n; i++) {
        struct wcall *c = &s->open[s->n_open++];
        int64_t ns;
        if (!id_at(&a->kids[i], 0, c->id) || !id_at(&a->kids[i], 1, c->session) || !id_at(&a->kids[i], 2, c->agent) ||
            !int_at(&a->kids[i], 3, &ns) || c->id[0] == '\0' || c->session[0] == '\0')
            return false;
        c->ns = ns;
    }
    a = jget(v, "marks");
    if (a == NULL || a->t != J_ARR || a->n > W_MARK_MAX) return false;
    for (size_t i = 0; i < a->n; i++) {
        struct wmark *m = &s->marks[s->n_marks++];
        char day[WATCH_ID_MAX + 1];
        int64_t off, ns;
        if (!id_at(&a->kids[i], 0, m->session) || !id_at(&a->kids[i], 1, m->name) || !id_at(&a->kids[i], 2, day) ||
            !int_at(&a->kids[i], 3, &off) || !int_at(&a->kids[i], 4, &ns) || strlen(day) != 10 || !is_day(day) ||
            off < 0 || m->session[0] == '\0' || m->name[0] == '\0')
            return false;
        memcpy(m->day, day, 11);
        m->off = (long)off;
        m->ns = ns;
        int64_t seen;
        m->seen_ns = int_at(&a->kids[i], 5, &seen) ? seen : ns;     /* a line written before this field */
    }
    a = jget(v, "kills");
    if (a == NULL || a->t != J_ARR || a->n > W_KILL_MAX) return false;
    for (size_t i = 0; i < a->n; i++) {
        int64_t n;
        if (!id_at(&a->kids[i], 0, s->kills[s->n_kills].session) || !int_at(&a->kids[i], 1, &n) || n < 0) return false;
        s->kills[s->n_kills++].n = (long)n;
    }
    a = jget(v, "told");
    if (a == NULL || a->t != J_ARR || a->n > W_TOLD_MAX) return false;
    for (size_t i = 0; i < a->n; i++)
        if (!id_at(a, i, s->told[s->n_told++])) return false;
    return true;
}

/* ---- opening ---- */

int ledger_days(const struct ledger *l, char (**days)[11], size_t *n) {
    *days = NULL;
    *n = 0;
    if (l->dfd == -1) return 0;
    const int fd = dup(l->dfd);
    DIR *d = fd == -1 ? NULL : fdopendir(fd);
    if (d == NULL) {
        if (fd != -1) close(fd);
        belay_err_set(BELAY_ERR_IO, errno, "cannot list %s", l->dir);
        return -1;
    }
    rewinddir(d);
    size_t cap = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char day[11];
        if (!ledger_name(e->d_name, day)) continue;
        if (*n == cap) {
            cap = cap ? cap * 2 : 16;
            char (*q)[11] = realloc(*days, cap * sizeof **days);
            if (q == NULL) {
                closedir(d);
                free(*days);
                *days = NULL;
                belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
                return -1;
            }
            *days = q;
        }
        memcpy((*days)[(*n)++], day, 11);
    }
    closedir(d);
    for (size_t i = 1; i < *n; i++)             /* few: an insertion sort */
        for (size_t j = i; j > 0 && strcmp((*days)[j - 1], (*days)[j]) > 0; j--) {
            char t[11];
            memcpy(t, (*days)[j], 11);
            memcpy((*days)[j], (*days)[j - 1], 11);
            memcpy((*days)[j - 1], t, 11);
        }
    return 0;
}

/* The newest line of `buf` that parses and carries a state: its end in
 * *end (0: none), its state in *st, whether it is an attempt in *attempt. */
static void newest_line(const char *buf, size_t len, size_t *end, struct wstate *st, bool *attempt) {
    *end = 0;
    size_t e = len;
    while (e > 0) {
        /* the line that ends at or before e: [b, nl] */
        size_t nl = e;
        while (nl > 0 && buf[nl - 1] != '\n') nl--;
        if (nl == 0) return;                    /* no complete line before e */
        size_t b = nl - 1;
        while (b > 0 && buf[b - 1] != '\n') b--;
        struct jval v;
        if (nl - 1 - b <= WATCH_LINE_MAX && jsonr_parse(buf + b, nl - 1 - b, &v) == 0) {
            const bool ok = v.t == J_OBJ && state_parse(&v, st);
            if (ok) *attempt = strcmp(jstr(&v, "t"), "attempt") == 0;
            jsonr_free(&v);
            if (ok) { *end = nl; return; }
        } else {
            belay_err_clear();
        }
        e = b;
        if (b == 0) return;
    }
}

int ledger_open(const struct state *st, bool write, struct ledger *l) {
    memset(l, 0, sizeof *l);
    l->dfd = -1;
    l->write = write;
    snprintf(l->dir, sizeof l->dir, "%s/watch", st->dir);
    if (st->dir_fd == -1) return 0;
    if (write && mkdirat(st->dir_fd, "watch", 0700) == -1 && errno != EEXIST) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot create %s", l->dir);
        return -1;
    }
    l->dfd = openat(st->dir_fd, "watch", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (l->dfd == -1) {
        if (errno == ENOENT && !write) return 0;
        belay_err_set(errno == ELOOP || errno == ENOTDIR ? BELAY_ERR_CORRUPT : BELAY_ERR_IO, errno,
                      "%s is not a directory belay made", l->dir);
        return -1;
    }
    char (*days)[11];
    size_t n;
    if (ledger_days(l, &days, &n) == -1) return -1;
    int rc = 0;
    for (size_t i = n; i-- > 0;) {
        char name[32], *buf;
        size_t len, end;
        snprintf(name, sizeof name, "ledger-%s.ndjson", days[i]);
        const int r = read_all(l, name, &buf, &len);
        if (r == -1) { rc = -1; break; }
        if (r == 1) continue;
        if (i + 1 == n) memcpy(l->day, days[i], 11);
        bool attempt = false;
        newest_line(buf, len, &end, &l->st, &attempt);
        free(buf);
        if (i + 1 == n && write && end < len) {
            /* repair: a torn tail is cut off the newest file (WR-8) */
            const int fd = openat(l->dfd, name, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
            if (fd == -1 || ftruncate(fd, (off_t)end) == -1 || barrier(fd) == -1) {
                belay_err_set(BELAY_ERR_IO, errno, "cannot repair %s/%s", l->dir, name);
                if (fd != -1) close(fd);
                rc = -1;
                break;
            }
            close(fd);
            if (end == 0) {                     /* nothing of it parsed: it holds no line */
                unlinkat(l->dfd, name, 0);
                l->day[0] = '\0';
                if (i > 0) memcpy(l->day, days[i - 1], 11);
            }
        }
        if (end > 0) {
            l->unreadable = false;
            l->unfinished = attempt && i + 1 == n;
            free(days);
            return 0;
        }
        l->unreadable = true;
    }
    free(days);
    memset(&l->st, 0, sizeof l->st);
    return rc;
}

void ledger_close(struct ledger *l) {
    if (l->dfd != -1) close(l->dfd);
    l->dfd = -1;
}

void ledger_day(const struct ledger *l, int64_t ns, char day[11]) {
    day_of(ns, day);
    if (l->day[0] != '\0' && strcmp(day, l->day) < 0) memcpy(day, l->day, 11);    /* a clock gone back starts no older file */
}

/* ---- writing ---- */

static int write_all(int fd, const char *p, size_t n) {
    size_t w = 0;
    while (w < n) {
        const ssize_t k = write(fd, p + w, n - w);
        if (k == -1 && errno == EINTR) continue;
        if (k <= 0) return -1;
        w += (size_t)k;
    }
    return 0;
}

/* One whole line onto its day's file. A new day's file is made under a
 * temporary name with this line in it, then renamed: it never exists empty. */
static int put_line(struct ledger *l, int64_t ns, const char *line, size_t len, long *off) {
    char day[11], name[32];
    ledger_day(l, ns, day);
    snprintf(name, sizeof name, "ledger-%s.ndjson", day);
    if (len > WATCH_LINE_MAX) {
        belay_err_set(BELAY_ERR_RANGE, 0, "%s/%s: a line of %zu bytes", l->dir, name, len);
        return -1;
    }
    if (ledger_fail_at != 0 && ++g_puts == ledger_fail_at) {
        belay_err_set(BELAY_ERR_IO, 0, "cannot write %s/%s (a test's failure)", l->dir, name);
        return -1;
    }
    const bool fresh = strcmp(day, l->day) != 0;
    char tmp[48];
    snprintf(tmp, sizeof tmp, ".tmp-ledger-%ld", (long)getpid());
    if (fresh) unlinkat(l->dfd, tmp, 0);
    const int fd = fresh ? openat(l->dfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)
                         : openat(l->dfd, name, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
    struct stat fs;
    if (fd == -1 || fstat(fd, &fs) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot write %s/%s", l->dir, name);
        if (fd != -1) close(fd);
        if (fresh) unlinkat(l->dfd, tmp, 0);
        return -1;
    }
    /* From the first byte written, a failure must not leave the line, or part
     * of it, in the file: the caller will say it was not written, and a line
     * that stayed would be read all the same (re-review of #132: a step line
     * whose sync failed was said lost and recorded twice). So it is taken
     * back -- an appended line cut off again, a new day's file removed. */
    bool renamed = false;
    if (write_all(fd, line, len) == -1 || line_sync(fd) == -1 ||
        (fresh && renameat(l->dfd, tmp, l->dfd, name) == -1) || (fresh && (renamed = true, ledger_fail_dirsync ? (errno = EIO, true) : fsync(l->dfd) == -1))) {
        const int e = errno;
        const bool gone = fresh ? unlinkat(l->dfd, renamed ? name : tmp, 0) == 0 || errno == ENOENT
                                : ftruncate(fd, fs.st_size) == 0;
        close(fd);
        if (gone) {
            belay_err_set(BELAY_ERR_IO, e, "cannot write %s/%s", l->dir, name);
            return -1;
        }
        /* It could not be taken back either: the line stands, and the record
         * goes on from it. That it may not have reached the disk is said. */
        l->unconfirmed = true;
    } else {
        close(fd);
    }
    memcpy(l->day, day, 11);
    if (off != NULL) *off = (long)fs.st_size + (long)len;
    return 0;
}

static void head(struct wsb *b, const char *type, const char *session, int64_t ns) {
    wsb_f(b, "{\"belay_watch\":%d,\"t\":\"%s\",\"ns\":%lld,\"session\":\"%s\",", LEDGER_VERSION, type, (long long)ns, session);
}

int ledger_append(struct ledger *l, const char *type, const char *session, int64_t ns, const char *body, long *off) {
    struct wsb b = { 0 };
    head(&b, type, session, ns);
    wsb_f(&b, "%s", body);
    state_json(&b, &l->st);
    wsb_f(&b, "}\n");
    if (b.bad) {
        free(b.p);
        belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        return -1;
    }
    const int rc = put_line(l, ns, b.p, b.n, off);
    free(b.p);
    return rc;
}

int ledger_append_step(struct ledger *l, struct wstep *s) {
    struct wsb rest = { 0 }, b = { 0 };
    /* everything but the flags, so what is left of the line is known */
    wsb_f(&rest, "\"from\":%ld,\"to\":%ld,\"changes\":%llu,\"calls\":[", s->from, s->to, (unsigned long long)s->changes);
    for (size_t i = 0; i < s->n_calls; i++) wsb_f(&rest, "%s\"%s\"", i ? "," : "", s->calls[i]);
    wsb_f(&rest, "],\"counts\":[");
    for (int i = 0; i < WATCH_OUTCOMES; i++) wsb_f(&rest, "%s%llu", i ? "," : "", (unsigned long long)s->counts[i]);
    wsb_f(&rest, "],\"names\":[");
    for (size_t i = 0; i < s->n_names; i++) { wsb_f(&rest, "%s", i ? "," : ""); wsb_json(&rest, s->names[i]); }
    wsb_f(&rest, "],\"under\":[");
    if (s->under != NULL) { wsb_json(&rest, s->under); wsb_f(&rest, ",%llu", (unsigned long long)s->n_under); }
    wsb_f(&rest, "],\"trouble\":[");
    for (size_t i = 0; i < s->n_trouble; i++) { wsb_f(&rest, "%s", i ? "," : ""); wsb_json(&rest, s->trouble[i]); }
    wsb_f(&rest, "],\"sec\":[\"%s\",%ld,%ld,\"%s\"],", s->sec_file, s->sec_off, s->sec_len, s->sec_sha);
    state_json(&rest, &l->st);
    head(&b, "step", s->session, s->ns);
    /* room for the two arrays of cut counts, at 21 digits a number */
    const size_t fixed = b.n + rest.n + 2 * WK_COUNT * 22 + 64;
    wsb_f(&b, "\"flags\":[");
    size_t kept = 0;
    for (size_t i = 0; i < s->n_flags && !b.bad && !rest.bad; i++) {
        const size_t before = b.n;
        wsb_f(&b, "%s[%d,%d,", kept ? "," : "", (int)s->flags[i].kind, s->flags[i].note ? 1 : 0);
        wsb_json(&b, s->flags[i].text);
        wsb_f(&b, "]");
        if (b.n + fixed > WATCH_LINE_MAX) {     /* LN-8: counted, not kept */
            b.n = before;
            b.p[b.n] = '\0';
            for (size_t j = i; j < s->n_flags; j++) {
                if (s->flags[j].note) s->cut_note[s->flags[j].kind]++;
                else s->cut_flag[s->flags[j].kind]++;
                free(s->flags[j].text);
            }
            s->n_flags = i;
            break;
        }
        kept++;
    }
    wsb_f(&b, "],\"cut_flag\":[");
    for (int k = 0; k < WK_COUNT; k++) wsb_f(&b, "%s%llu", k ? "," : "", (unsigned long long)s->cut_flag[k]);
    wsb_f(&b, "],\"cut_note\":[");
    for (int k = 0; k < WK_COUNT; k++) wsb_f(&b, "%s%llu", k ? "," : "", (unsigned long long)s->cut_note[k]);
    wsb_f(&b, "],%s}\n", rest.p != NULL ? rest.p : "");
    const bool bad = b.bad || rest.bad;
    free(rest.p);
    if (bad) {
        free(b.p);
        belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        return -1;
    }
    if (ledger_before_line != NULL) ledger_before_line();
    const int rc = put_line(l, s->ns, b.p, b.n, NULL);
    free(b.p);
    return rc;
}

static void sha_hex(const char *p, size_t n, char hex[65]) {
    struct belay_sha256 c;
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_init(&c);
    belay_sha256_update(&c, p, n);
    belay_sha256_final(&c, d);
    belay_hex_encode(hex, d, sizeof d);
}

int ledger_section_write(struct ledger *l, struct wstep *s, const char *text, size_t len) {
    char day[11];
    ledger_day(l, s->ns, day);
    snprintf(s->sec_file, sizeof s->sec_file, "receipt-%s.txt", day);
    const int fd = openat(l->dfd, s->sec_file, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat fs;
    if (fd == -1 || fstat(fd, &fs) == -1 || !S_ISREG(fs.st_mode) || write_all(fd, text, len) == -1 || barrier(fd) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot write %s/%s", l->dir, s->sec_file);
        if (fd != -1) close(fd);
        return -1;
    }
    close(fd);
    s->sec_off = (long)fs.st_size;
    s->sec_len = (long)len;
    sha_hex(text, len, s->sec_sha);
    return 0;
}

char *ledger_section_read(const struct ledger *l, const struct wstep *s, size_t *len) {
    char *buf, hex[65];
    size_t n;
    if (l->dfd == -1 || strncmp(s->sec_file, "receipt-", 8) != 0 || strchr(s->sec_file, '/') != NULL ||
        read_all(l, s->sec_file, &buf, &n) != 0) {
        belay_err_clear();
        return NULL;
    }
    if (s->sec_off < 0 || s->sec_len < 0 || (size_t)s->sec_off > n || (size_t)s->sec_len > n - (size_t)s->sec_off) {
        free(buf);
        return NULL;
    }
    sha_hex(buf + s->sec_off, (size_t)s->sec_len, hex);
    if (strcmp(hex, s->sec_sha) != 0) {
        free(buf);
        return NULL;
    }
    memmove(buf, buf + s->sec_off, (size_t)s->sec_len);
    buf[s->sec_len] = '\0';
    *len = (size_t)s->sec_len;
    return buf;
}

int ledger_list_write(struct ledger *l, const char *bytes, size_t len, char hex[65]) {
    char name[80], shown[PATH_MAX + 200];
    sha_hex(bytes, len, hex);
    snprintf(name, sizeof name, "list-%s", hex);
    snprintf(shown, sizeof shown, "%s/%s", l->dir, name);
    struct stat fs;
    if (fstatat(l->dfd, name, &fs, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(fs.st_mode) && (size_t)fs.st_size == len) return 0;
    return state_write_whole(l->dfd, name, bytes, len, shown);
}

char *ledger_list_read(const struct ledger *l, const char *hex, size_t *len) {
    char name[80], *buf, got[65];
    snprintf(name, sizeof name, "list-%.64s", hex);
    if (l->dfd == -1 || strlen(hex) != 64 || read_all(l, name, &buf, len) != 0) {
        belay_err_clear();
        return NULL;
    }
    sha_hex(buf, *len, got);
    if (strcmp(got, hex) != 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

/* ---- reading ---- */

int ledger_read(const struct ledger *l, const char *day, long from, ledger_line_fn fn, void *ctx) {
    char name[32], *buf;
    size_t len;
    snprintf(name, sizeof name, "ledger-%.10s.ndjson", day);
    if (l->dfd == -1) return 0;
    const int r = read_all(l, name, &buf, &len);
    if (r != 0) return r == 1 ? 0 : -1;
    int rc = 0;
    size_t b = from > 0 && (size_t)from <= len ? (size_t)from : 0;
    while (b < len && rc == 0) {
        const char *nl = memchr(buf + b, '\n', len - b);
        if (nl == NULL) break;                  /* a torn last line is ignored */
        const size_t n = (size_t)(nl - (buf + b));
        struct jval v;
        if (n <= WATCH_LINE_MAX && jsonr_parse(buf + b, n, &v) == 0) {
            if (v.t == J_OBJ && jint(&v, "belay_watch", 0) == LEDGER_VERSION) rc = fn(ctx, &v, jstr(&v, "t"));
            jsonr_free(&v);
        } else {
            belay_err_clear();
        }
        b += n + 1;
    }
    free(buf);
    return rc;
}

static bool u64_at(const struct jval *arr, size_t i, uint64_t *out) {
    int64_t v;
    if (!int_at(arr, i, &v) || v < 0) return false;
    *out = (uint64_t)v;
    return true;
}

int ledger_step(const struct jval *line, struct wstep *s) {
    memset(s, 0, sizeof *s);
    if (strcmp(jstr(line, "t"), "step") != 0 || !ledger_id_valid(jstr(line, "session"))) return -1;
    snprintf(s->session, sizeof s->session, "%s", jstr(line, "session"));
    s->ns = jint(line, "ns", 0);
    s->from = (long)jint(line, "from", 0);
    s->to = (long)jint(line, "to", 0);
    s->changes = (uint64_t)jint(line, "changes", 0);
    const struct jval *a = jget(line, "calls");
    if (a != NULL && a->t == J_ARR && a->n > 0) {
        if ((s->calls = calloc(a->n, sizeof *s->calls)) == NULL) goto bad;
        for (size_t i = 0; i < a->n; i++) {
            if (a->kids[i].t != J_STR || (s->calls[i] = strdup(a->kids[i].s)) == NULL) goto bad;
            s->n_calls++;
        }
    }
    a = jget(line, "flags");
    if (a != NULL && a->t == J_ARR && a->n > 0) {
        if ((s->flags = calloc(a->n, sizeof *s->flags)) == NULL) goto bad;
        for (size_t i = 0; i < a->n; i++) {
            const struct jval *f = &a->kids[i];
            int64_t kind, note;
            if (!int_at(f, 0, &kind) || !int_at(f, 1, &note) || kind < 0 || kind >= WK_COUNT || f->n < 3 ||
                f->kids[2].t != J_STR || (s->flags[i].text = strdup(f->kids[2].s)) == NULL)
                goto bad;
            s->flags[i].kind = (enum wkind)kind;
            s->flags[i].note = note != 0;
            s->n_flags++;
        }
    }
    for (size_t k = 0; k < WK_COUNT; k++) {
        if (!u64_at(jget(line, "cut_flag"), k, &s->cut_flag[k]) || !u64_at(jget(line, "cut_note"), k, &s->cut_note[k]))
            goto bad;
    }
    for (size_t k = 0; k < WATCH_OUTCOMES; k++)
        if (!u64_at(jget(line, "counts"), k, &s->counts[k])) goto bad;
    a = jget(line, "names");
    for (size_t i = 0; a != NULL && a->t == J_ARR && i < a->n && i < 3; i++) {
        if (a->kids[i].t != J_STR || (s->names[i] = strdup(a->kids[i].s)) == NULL) goto bad;
        s->n_names++;
    }
    a = jget(line, "under");
    if (a != NULL && a->t == J_ARR && a->n == 2) {
        if (a->kids[0].t != J_STR || !u64_at(a, 1, &s->n_under) || (s->under = strdup(a->kids[0].s)) == NULL) goto bad;
    }
    a = jget(line, "trouble");
    if (a != NULL && a->t == J_ARR && a->n > 0) {
        if ((s->trouble = calloc(a->n, sizeof *s->trouble)) == NULL) goto bad;
        for (size_t i = 0; i < a->n; i++) {
            if (a->kids[i].t != J_STR || (s->trouble[i] = strdup(a->kids[i].s)) == NULL) goto bad;
            s->n_trouble++;
        }
    }
    a = jget(line, "sec");
    int64_t off, len;
    if (a == NULL || a->t != J_ARR || a->n != 4 || a->kids[0].t != J_STR || a->kids[3].t != J_STR ||
        !int_at(a, 1, &off) || !int_at(a, 2, &len) || a->kids[0].s_len >= sizeof s->sec_file ||
        a->kids[3].s_len >= sizeof s->sec_sha)
        goto bad;
    snprintf(s->sec_file, sizeof s->sec_file, "%s", a->kids[0].s);
    snprintf(s->sec_sha, sizeof s->sec_sha, "%s", a->kids[3].s);
    s->sec_off = (long)off;
    s->sec_len = (long)len;
    return 0;
bad:
    wstep_free(s);
    return -1;
}
