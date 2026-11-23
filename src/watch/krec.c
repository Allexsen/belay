#define _GNU_SOURCE
#include "watch/krec.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "belay/error.h"
#include "belay/json.h"
#include "util/jsonr.h"

/* ---- a journal line ---- */

static bool u64_of(const struct jval *o, const char *key, uint64_t *out) {
    const struct jval *v = jget(o, key);
    if (v == NULL || v->t != J_NUM || !v->integer || v->i < 0) return false;
    *out = (uint64_t)v->i;
    return true;
}

/* A name, as `key` or `key_b64`: at most KR_NAME_MAX bytes, none a NUL or a slash. */
static bool name_of(const struct jval *o, const char *key, char *out, size_t *len) {
    char k64[24];
    snprintf(k64, sizeof k64, "%s_b64", key);
    const struct jval *v = jget(o, key), *b = jget(o, k64);
    if ((v == NULL) == (b == NULL)) return false;
    if (v != NULL) {
        if (v->t != J_STR || v->s_len == 0 || v->s_len > KR_NAME_MAX) return false;
        memcpy(out, v->s, v->s_len);
        *len = v->s_len;
    } else {
        if (b->t != J_STR || b->s_len > 4 * ((KR_NAME_MAX + 2) / 3) ||
            belay_base64_decode(out, KR_NAME_MAX, len, b->s) != 0 || *len == 0)
            return false;
    }
    out[*len] = '\0';
    return memchr(out, '\0', *len) == NULL && memchr(out, '/', *len) == NULL;
}

/* dev and ino under `d` and `i`: the inode may be null (it did not resolve). */
static bool obj_of(const struct jval *o, const char *d, const char *i, bool *has, uint64_t *dev, uint64_t *ino) {
    const struct jval *v = jget(o, i);
    if (v == NULL) return false;
    if (v->t == J_NULL) { *has = false; *dev = *ino = 0; return true; }
    *has = true;
    return u64_of(o, d, dev) && u64_of(o, i, ino);
}

int krec_parse(const char *line, size_t n, struct kev *e) {
    struct jval v;
    memset(e, 0, sizeof *e);
    if (n == 0 || n >= KR_LINE_MAX || jsonr_parse(line, n, &v) == -1) return -1;
    int rc = -1;
    if (v.t != J_OBJ) goto out;
    const int64_t t = jint(&v, "time_ns", -1);
    if (!u64_of(&v, "seq", &e->seq) || e->seq == 0 || t < 0) goto out;
    e->time_ns = t;
    const struct jval *rec = jget(&v, "record");
    if (rec != NULL) {
        if (rec->t != J_STR) goto out;
        if (strcmp(rec->s, "overflow") == 0) e->kind = KEV_OVERFLOW;
        else if (strcmp(rec->s, "mounts_changed") == 0) e->kind = KEV_MOUNTS;
        else if (strcmp(rec->s, "barrier") == 0) {
            e->kind = KEV_BARRIER;
            if (!name_of(&v, "name", e->name, &e->name_len)) goto out;
        } else if (strcmp(rec->s, "start") == 0) {
            e->kind = KEV_START;
            const char *id = jstr(&v, "recorder");
            const struct jval *fl = jget(&v, "iflags_events");
            if (strlen(id) != 16 || strspn(id, "0123456789abcdef") != 16 || fl == NULL || fl->t != J_BOOL) goto out;
            memcpy(e->recorder, id, 17);
            e->iflags_events = fl->b;
        } else goto out;
        rc = 0;
        goto out;
    }
    e->kind = KEV_EVENT;
    uint64_t mask;
    if (!u64_of(&v, "mask", &mask) || mask > UINT32_MAX) goto out;
    e->mask = (uint32_t)mask;
    if (!obj_of(&v, "dev", "ino", &e->has_ino, &e->dev, &e->ino)) goto out;
    if (jget(&v, "dir_ino") != NULL) {
        e->named = true;
        if (!obj_of(&v, "dir_dev", "dir_ino", &e->has_dir, &e->dir_dev, &e->dir_ino) ||
            !name_of(&v, "name", e->name, &e->name_len))
            goto out;
    }
    if (jget(&v, "to_dir_ino") != NULL) {
        e->renamed = true;
        if (!e->named || !obj_of(&v, "to_dir_dev", "to_dir_ino", &e->has_to, &e->to_dev, &e->to_ino) ||
            !name_of(&v, "to_name", e->to_name, &e->to_len))
            goto out;
    }
    rc = 0;
out:
    jsonr_free(&v);
    return rc;
}

/* ---- the files ---- */

static int wdir_fd(const struct state *st, bool create) {
    if (st->dir_fd == -1) return -1;
    if (create && mkdirat(st->dir_fd, "watch", 0700) == -1 && errno != EEXIST) return -1;
    return openat(st->dir_fd, "watch", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

static int u64_cmp(const void *a, const void *b) {
    const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* The segments' first seqs, ascending: malloc'd, *n of them. -1: memory. */
static int segments(int wfd, uint64_t **out, size_t *n) {
    *out = NULL;
    *n = 0;
    const int dfd = dup(wfd);
    DIR *d = dfd == -1 ? NULL : fdopendir(dfd);
    if (d == NULL) {
        if (dfd != -1) close(dfd);
        return 0;
    }
    rewinddir(d);
    size_t cap = 0;
    int rc = 0;
    for (struct dirent *e; (e = readdir(d)) != NULL;) {
        if (strncmp(e->d_name, "journal.", 8) != 0) continue;
        const char *p = e->d_name + 8;
        const size_t dl = strlen(p);
        if (dl == 0 || dl > 18 || strspn(p, "0123456789") != dl) continue;
        if (*n == cap) {
            uint64_t *g = realloc(*out, (cap = cap ? cap * 2 : 16) * sizeof **out);
            if (g == NULL) { rc = -1; break; }
            *out = g;
        }
        (*out)[(*n)++] = strtoull(p, NULL, 10);
    }
    closedir(d);
    if (rc == 0 && *n > 1) qsort(*out, *n, sizeof **out, u64_cmp);
    return rc;
}

static FILE *segment_open(int wfd, uint64_t first) {
    char name[40];
    snprintf(name, sizeof name, "journal.%llu", (unsigned long long)first);
    const int fd = openat(wfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd == -1) return NULL;
    struct stat s;
    FILE *f = fstat(fd, &s) == 0 && S_ISREG(s.st_mode) ? fdopen(fd, "r") : NULL;
    if (f == NULL) close(fd);
    return f;
}

/* The next line of `f` into `e`: 1; 0 at the end (or at a line still being
 * written, which has no newline yet); -1 when it is not a journal's. */
static int next_line(FILE *f, struct kev *e) {
    char line[KR_LINE_MAX];
    const long at = ftell(f);
    if (fgets(line, sizeof line, f) == NULL) {
        clearerr(f);                    /* the end now; the recorder appends */
        return 0;
    }
    const size_t n = strlen(line);
    if (n == 0 || line[n - 1] != '\n') {
        if (n + 1 < sizeof line && feof(f)) {       /* the recorder is in the middle of it */
            clearerr(f);
            if (at >= 0) fseek(f, at, SEEK_SET);
            return 0;
        }
        return -1;
    }
    return krec_parse(line, n - 1, e) == 0 ? 1 : -1;
}

int krec_scan(const struct state *st, long long after, long long upto, krec_fn fn, void *ctx) {
    if (after < 0 || upto < after) return 1;
    if (upto == after) return 0;
    const int wfd = wdir_fd(st, false);
    if (wfd == -1) return 1;
    uint64_t *seg = NULL;
    size_t n = 0;
    struct kev *e = malloc(sizeof *e);
    int rc = e == NULL || segments(wfd, &seg, &n) == -1 ? -1 : 0;
    if (rc == -1) belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
    uint64_t want = (uint64_t)after + 1;        /* the next seq to hand on */
    size_t i = 0;
    while (i + 1 < n && seg[i + 1] <= want) i++;
    if (rc == 0 && (n == 0 || seg[i] > want)) rc = 1;
    uint64_t at = n > 0 ? seg[i] : 0;
    for (; rc == 0 && i < n && want <= (uint64_t)upto; i++) {
        if (seg[i] != at) { rc = 1; break; }            /* a segment between the two is gone */
        FILE *f = segment_open(wfd, seg[i]);
        if (f == NULL) { rc = 1; break; }
        int g;
        while ((g = next_line(f, e)) == 1) {
            if (e->seq != at) { g = -1; break; }        /* every seq, once, in order */
            at++;
            if (e->seq < want) continue;
            if (e->seq > (uint64_t)upto) break;
            want = e->seq + 1;
            if (fn != NULL && fn(ctx, e) == -1) { rc = -1; break; }
        }
        fclose(f);
        if (g == -1 && rc == 0) rc = 1;
    }
    if (rc == 0 && want <= (uint64_t)upto) rc = 1;      /* it ends before the interval does */
    free(seg);
    free(e);
    close(wfd);
    return rc;
}

void krec_forget(const struct state *st) {
    const int wfd = wdir_fd(st, false);
    if (wfd == -1) return;
    uint64_t *seg = NULL;
    size_t n = 0;
    if (segments(wfd, &seg, &n) == 0)
        for (size_t i = 0; i < n; i++) {
            char name[40];
            snprintf(name, sizeof name, "journal.%llu", (unsigned long long)seg[i]);
            unlinkat(wfd, name, 0);
        }
    free(seg);
    unlinkat(wfd, "krec", 0);
    close(wfd);
}

void krec_prune(const struct state *st, long long oldest_seq) {
    const int wfd = wdir_fd(st, false);
    if (wfd == -1) return;
    uint64_t *seg = NULL;
    size_t n = 0;
    if (segments(wfd, &seg, &n) == 0)
        /* a segment ends where the next begins: it holds nothing after
         * oldest_seq when the next one's first line is at or before the
         * one after it. The newest is the recorder's and stays. */
        for (size_t i = 0; i + 1 < n; i++) {
            if (oldest_seq < 0 || seg[i + 1] > (uint64_t)oldest_seq + 1) break;
            char name[40];
            snprintf(name, sizeof name, "journal.%llu", (unsigned long long)seg[i]);
            unlinkat(wfd, name, 0);
        }
    free(seg);
    close(wfd);
}

/* ---- the watch's state of it ---- */

int krec_status_read(const struct state *st, struct krec_status *k) {
    memset(k, 0, sizeof *k);
    const int wfd = wdir_fd(st, false);
    if (wfd == -1) return 1;
    const int fd = openat(wfd, "krec", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    close(wfd);
    if (fd == -1) return 1;
    char buf[2048];
    const ssize_t got = read(fd, buf, sizeof buf - 1);
    close(fd);
    struct jval v;
    if (got <= 0 || jsonr_parse(buf, (size_t)got - (buf[got - 1] == '\n'), &v) == -1) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/watch/krec is not what belay wrote", st->dir);
        return -1;
    }
    const struct jval *on = jget(&v, "on"), *fl = jget(&v, "iflags_events");
    k->on = on != NULL && on->t == J_BOOL && on->b;
    k->iflags_events = fl == NULL || fl->t != J_BOOL || fl->b;
    k->since_ns = jint(&v, "since_ns", 0);
    k->gap_from_ns = jint(&v, "gap_from_ns", 0);
    k->gap_to_ns = jint(&v, "gap_to_ns", 0);
    k->gap = k->gap_from_ns != 0;
    k->last_seq = jint(&v, "last_seq", 0);
    k->last_ns = jint(&v, "last_ns", 0);
    snprintf(k->recorder, sizeof k->recorder, "%s", jstr(&v, "recorder"));
    snprintf(k->walked, sizeof k->walked, "%s", jstr(&v, "walked"));
    snprintf(k->gap_why, sizeof k->gap_why, "%s", jstr(&v, "gap_why"));
    snprintf(k->off_why, sizeof k->off_why, "%s", jstr(&v, "off_why"));
    jsonr_free(&v);
    return 0;
}

int krec_status_write(const struct state *st, const struct krec_status *k) {
    char walked[6 * sizeof k->walked + 8], gap[6 * sizeof k->gap_why + 8], off[6 * sizeof k->off_why + 8], buf[8192];
    const int wfd = wdir_fd(st, true);
    if (wfd == -1 || belay_json_escape(walked, sizeof walked, k->walked, strlen(k->walked)) == -1 ||
        belay_json_escape(gap, sizeof gap, k->gap_why, strlen(k->gap_why)) == -1 ||
        belay_json_escape(off, sizeof off, k->off_why, strlen(k->off_why)) == -1) {
        if (wfd != -1) close(wfd);
        belay_err_set(BELAY_ERR_IO, errno, "cannot write %s/watch/krec", st->dir);
        return -1;
    }
    const int n = snprintf(buf, sizeof buf,
                           "{\"on\":%s,\"since_ns\":%lld,\"recorder\":\"%s\",\"iflags_events\":%s,\"walked\":\"%s\","
                           "\"gap_from_ns\":%lld,\"gap_to_ns\":%lld,\"gap_why\":\"%s\",\"off_why\":\"%s\","
                           "\"last_seq\":%lld,\"last_ns\":%lld}\n",
                           k->on ? "true" : "false", (long long)k->since_ns, k->recorder, k->iflags_events ? "true" : "false",
                           walked, (long long)(k->gap ? k->gap_from_ns : 0), (long long)(k->gap ? k->gap_to_ns : 0), gap, off,
                           k->last_seq, (long long)k->last_ns);
    int rc = -1;
    const int fd = openat(wfd, "krec.tmp", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd != -1 && n > 0 && (size_t)n < sizeof buf && write(fd, buf, (size_t)n) == n && fsync(fd) == 0 &&
        renameat(wfd, "krec.tmp", wfd, "krec") == 0)
        rc = 0;
    if (rc == -1) belay_err_set(BELAY_ERR_IO, errno, "cannot write %s/watch/krec", st->dir);
    if (fd != -1) close(fd);
    close(wfd);
    return rc;
}

/* ---- the recorder, from outside ---- */

bool krec_alive(const struct state *st, char id[17]) {
    if (id != NULL) id[0] = '\0';
    const int wfd = wdir_fd(st, false);
    if (wfd == -1) return false;
    bool alive = false;
    const int fd = openat(wfd, "recorder.lock", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd != -1) {
        if (flock(fd, LOCK_EX | LOCK_NB) == -1) alive = errno == EWOULDBLOCK;
        else flock(fd, LOCK_UN);
        close(fd);
    }
    if (alive && id != NULL) {
        const int rf = openat(wfd, "recorder", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        char buf[32];
        const ssize_t got = rf == -1 ? -1 : read(rf, buf, sizeof buf);
        if (rf != -1) close(rf);
        if (got >= 16 && strspn(buf, "0123456789abcdef") >= 16) {
            memcpy(id, buf, 16);
            id[16] = '\0';
        }
    }
    close(wfd);
    return alive;
}

static void nap(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

void krec_stop(const struct state *st) {
    if (!krec_alive(st, NULL)) return;
    const int wfd = wdir_fd(st, false);
    if (wfd == -1) return;
    const int fd = openat(wfd, "recorder.stop", O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd != -1) close(fd);
    for (int i = 0; i < 2500 && krec_alive(st, NULL); i++) nap(2);
    unlinkat(wfd, "recorder.stop", 0);
    unlinkat(wfd, "recorder", 0);
    close(wfd);
}

int krec_start(const struct state *st, const char *const *roots, size_t n_roots, struct krec_status *k) {
    const char *fixture = getenv("BELAY_TEST_KREC");
    memset(k, 0, sizeof *k);
    k->iflags_events = true;
    if (fixture != NULL && fixture[0] == '\0') fixture = NULL;
    if (fixture == NULL && geteuid() != 0) {            /* K4: fanotify_init would say so */
        snprintf(k->off_why, sizeof k->off_why, "not root");
        return 0;
    }
#ifndef __linux__
    if (fixture == NULL) {
        snprintf(k->off_why, sizeof k->off_why, "no kernel record on this system");
        return 0;
    }
#endif
    krec_stop(st);                      /* one recorder a watch (K1) */
    char wdir[sizeof st->dir + 8];
    snprintf(wdir, sizeof wdir, "%s/watch", st->dir);
    const int wfd = wdir_fd(st, true);
    int p[2];
    if (wfd == -1 || pipe(p) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot start the recorder in %s", wdir);
        if (wfd != -1) close(wfd);
        return -1;
    }
    close(wfd);
    fflush(NULL);
    const pid_t child = fork();
    if (child == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot start the recorder");
        close(p[0]);
        close(p[1]);
        return -1;
    }
    if (child == 0) {
        /* A session of its own, and no parent to wait for it: it outlives
         * the command, the adapter's hook and the terminal (K1). */
        setsid();
        if (fork() != 0) _exit(0);
        const struct recorder_cfg c = { wdir, st->dir, st->scope.path, fixture, roots, n_roots, p[1] };
        /* nothing of the command's stays open in it: the state's lock is a descriptor */
        const long top = sysconf(_SC_OPEN_MAX);
        for (int fd = 0; fd < (top > 0 && top < 65536 ? (int)top : 1024); fd++)
            if (fd != p[1]) close(fd);
        const int nul = open("/dev/null", O_RDWR);
        if (nul != -1) {
            for (int fd = 0; fd < 3; fd++)
                if (fd != p[1] && nul != fd) dup2(nul, fd);
            if (nul > 2) close(nul);
        }
        recorder_run(&c);
        _exit(0);
    }
    close(p[1]);
    int status;
    while (waitpid(child, &status, 0) == -1 && errno == EINTR) { }
    char line[800];
    size_t have = 0;
    struct pollfd pf = { p[0], POLLIN, 0 };
    for (int waited = 0; have + 1 < sizeof line && memchr(line, '\n', have) == NULL && waited < 10000;) {
        const int pr = poll(&pf, 1, 100);
        if (pr == -1 && errno != EINTR) break;
        if (pr <= 0) { waited += 100; continue; }
        const ssize_t got = read(p[0], line + have, sizeof line - 1 - have);
        if (got <= 0) break;
        have += (size_t)got;
    }
    close(p[0]);
    line[have] = '\0';
    char *nl = strchr(line, '\n');
    if (nl != NULL) *nl = '\0';
    /* "K<16 hex> <0|1><walked>" */
    if (nl != NULL && line[0] == 'K' && strlen(line) >= 19 && strspn(line + 1, "0123456789abcdef") == 16 && line[17] == ' ' &&
        (line[18] == '0' || line[18] == '1')) {
        k->on = true;
        memcpy(k->recorder, line + 1, 16);
        k->recorder[16] = '\0';
        k->iflags_events = line[18] == '1';
        snprintf(k->walked, sizeof k->walked, "%.*s", (int)sizeof k->walked - 1, line + 19);
    } else {
        snprintf(k->off_why, sizeof k->off_why, "%.*s", (int)sizeof k->off_why - 1, nl != NULL && line[0] == 'E' && line[1] != '\0' ? line + 1
                                                                                                  : "the recorder did not start");
    }
    return 0;
}

/* ---- the barrier ---- */

int krec_barrier(const struct state *st, int wait_ms, long long *seq, int64_t *ctime_ns) {
    *seq = 0;
    *ctime_ns = 0;
    const int wfd = wdir_fd(st, false);
    if (wfd == -1) return 1;
    uint64_t *seg = NULL;
    size_t n = 0;
    struct kev *e = malloc(sizeof *e);
    if (e == NULL || segments(wfd, &seg, &n) == -1) {
        free(e);
        close(wfd);
        belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        return -1;
    }
    FILE *f = n > 0 ? segment_open(wfd, seg[n - 1]) : NULL;
    free(seg);
    int rc = 1;
    if (f == NULL) goto out;
    int g;
    while ((g = next_line(f, e)) == 1) { }      /* what is there already is not the answer */
    if (g == -1) goto out;
    /* the file: its name random, so nothing else of the directory is taken for it */
    char name[40];
    unsigned char rnd[8] = { 0 };
    const int ur = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (ur == -1 || read(ur, rnd, sizeof rnd) != (ssize_t)sizeof rnd) {
        const uint64_t v = (uint64_t)getpid() * 2654435761u ^ (uint64_t)time(NULL);
        memcpy(rnd, &v, sizeof rnd);
    }
    if (ur != -1) close(ur);
    snprintf(name, sizeof name, "barrier.%02x%02x%02x%02x%02x%02x%02x%02x", rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5],
             rnd[6], rnd[7]);
    const int bfd = openat(wfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat bs;
    if (bfd == -1 || fstat(bfd, &bs) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot take a barrier in %s/watch", st->dir);
        if (bfd != -1) close(bfd);
        rc = -1;
        goto out;
    }
    close(bfd);
    unlinkat(wfd, name, 0);
#ifdef __APPLE__
    *ctime_ns = (int64_t)bs.st_ctimespec.tv_sec * 1000000000LL + bs.st_ctimespec.tv_nsec;
#else
    *ctime_ns = (int64_t)bs.st_ctim.tv_sec * 1000000000LL + bs.st_ctim.tv_nsec;
#endif
    /* The seam: the file a test gave the recorder as its queue gets the
     * event the kernel would have queued for the create. */
    const char *fixture = getenv("BELAY_TEST_KREC");
    if (fixture != NULL && fixture[0] != '\0') {
        char l[64];
        const int ll = snprintf(l, sizeof l, "B %s\n", name);
        const int ffd = open(fixture, O_WRONLY | O_APPEND | O_CLOEXEC);
        if (ffd != -1) {
            if (write(ffd, l, (size_t)ll) != ll) { /* then it does not answer */ }
            close(ffd);
        }
    }
    for (int waited = 0; rc == 1 && waited <= wait_ms; waited += 2) {
        while ((g = next_line(f, e)) == 1)
            if (e->kind == KEV_BARRIER && e->name_len == strlen(name) && memcmp(e->name, name, e->name_len) == 0) {
                *seq = (long long)e->seq;
                rc = 0;
                break;
            }
        if (g == -1) break;
        if (rc == 1) nap(2);
    }
out:
    if (f != NULL) fclose(f);
    free(e);
    close(wfd);
    return rc;
}

/* ---- the filesystems under the roots ---- */

/* A field of mountinfo, its \ooo escapes undone: its length, or 0 when it does not fit. */
static size_t unescape(const char *p, size_t n, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        char c = p[i];
        if (c == '\\' && i + 3 < n && p[i + 1] >= '0' && p[i + 1] <= '3' && p[i + 2] >= '0' && p[i + 2] <= '7' &&
            p[i + 3] >= '0' && p[i + 3] <= '7') {
            c = (char)((p[i + 1] - '0') * 64 + (p[i + 2] - '0') * 8 + (p[i + 3] - '0'));
            i += 3;
        }
        if (o + 1 >= cap) return 0;
        out[o++] = c;
    }
    out[o] = '\0';
    return o;
}

static bool under(const char *p, const char *dir) {
    const size_t dl = strlen(dir);
    if (dl == 1 && dir[0] == '/') return p[0] == '/';
    return strncmp(p, dir, dl) == 0 && (p[dl] == '\0' || p[dl] == '/');
}

int krec_plan(const char *table, bool relative, const char *root, const char *const *roots, size_t n_roots,
              struct krec_plan *out, char why[160]) {
    static const char *const ENTERED[] = { "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "f2fs", "zfs" };
    memset(out, 0, sizeof *out);
    why[0] = '\0';
    FILE *f = fopen(table, "r");
    if (f == NULL) {
        snprintf(why, 160, "the mount table cannot be read");
        return 1;
    }
    const size_t rl = strcmp(root, "/") == 0 ? 0 : strlen(root);
    /* the mount each root is on: the longest mount point at or above it, the last such line */
    struct at { char mp[4096]; char type[32]; bool is_root_of; } *m = calloc(1, sizeof *m), *best = calloc(n_roots + 1, sizeof *best);
    char *line = NULL;
    size_t cap = 0;
    if (m == NULL || best == NULL) goto done;
    for (int pass = 0; pass < 2; pass++) {
        rewind(f);
        ssize_t got;
        while ((got = getline(&line, &cap, f)) > 0) {
            /* id parent maj:min root mountpoint ... - type source options */
            const char *p = line;
            for (int k = 0; k < 4 && p != NULL; k++) {
                p = strchr(p, ' ');
                if (p != NULL) p++;
            }
            const char *sep = p != NULL ? strstr(p, " - ") : NULL;
            if (p == NULL || sep == NULL) continue;
            const size_t ml = strcspn(p, " ");
            char mp[4096], rel[4096];
            if (unescape(p, ml, rel, sizeof rel) == 0 || rel[0] != '/') continue;
            if (relative) {
                if ((size_t)snprintf(mp, sizeof mp, "%s%s", rl ? root : "", strcmp(rel, "/") == 0 && rl ? "" : rel) >= sizeof mp) continue;
            } else {
                snprintf(mp, sizeof mp, "%s", rel);
            }
            const size_t tl = strcspn(sep + 3, " \n");
            if (tl == 0 || tl >= sizeof m->type) continue;
            snprintf(m->mp, sizeof m->mp, "%s", mp);
            memcpy(m->type, sep + 3, tl);
            m->type[tl] = '\0';
            if (pass == 0) {
                for (size_t r = 0; r < n_roots; r++) {
                    char rp[4096];
                    if ((size_t)snprintf(rp, sizeof rp, "%s/%s", rl ? root : "", roots[r]) >= sizeof rp) continue;
                    if (under(rp, m->mp) && strlen(m->mp) >= strlen(best[r].mp)) best[r] = *m;
                }
                continue;
            }
            /* the second pass: a mount that holds a root, or lies at or under one */
            bool matters = false;
            for (size_t r = 0; r < n_roots && !matters; r++) {
                char rp[4096];
                if ((size_t)snprintf(rp, sizeof rp, "%s/%s", rl ? root : "", roots[r]) >= sizeof rp) continue;
                matters = (strcmp(best[r].mp, m->mp) == 0 && strcmp(best[r].type, m->type) == 0) || under(m->mp, rp);
            }
            if (!matters) continue;
            for (const char *c = line; *c != '\0'; c++) out->sum = out->sum * 1099511628211ULL + (unsigned char)*c;
            bool entered = false;
            for (size_t t = 0; t < sizeof ENTERED / sizeof ENTERED[0]; t++) entered |= strcmp(ENTERED[t], m->type) == 0;
            if (!entered) continue;                 /* K3: a `mount` entry, neither marked nor walked */
            if (strcmp(m->type, "ext4") == 0) {
                bool have = false;
                for (size_t i = 0; i < out->n_mark; i++) have |= strcmp(out->mark[i], m->mp) == 0;
                if (!have && out->n_mark < sizeof out->mark / sizeof out->mark[0])
                    snprintf(out->mark[out->n_mark++], sizeof out->mark[0], "%s", m->mp);
            } else {
                const char *shown = strlen(m->mp) > rl + 1 ? m->mp + rl + 1 : "/";
                char one[4200];
                snprintf(one, sizeof one, "%s (%s)", shown, m->type);
                if (strstr(out->walked, one) == NULL) {
                    const size_t wl = strlen(out->walked);
                    snprintf(out->walked + wl, sizeof out->walked - wl, "; walked every time: %s", one);
                }
            }
        }
    }
done:
    free(line);
    free(m);
    free(best);
    fclose(f);
    if (out->n_mark == 0) {
        snprintf(why, 160, "no ext4 filesystem under the roots");
        return 1;
    }
    return 0;
}

/* ---- touched ---- */

#define TOUCHED_BUF ((size_t)1 << 18)       /* pairs held before they go to the file: 4 MiB */

struct tset {
    uint64_t *buf;              /* TOUCHED_BUF pairs */
    size_t n;
    int tfd;                    /* the state's tmp/ */
    char name[64], next[64];    /* the file, and the one a merge writes */
    bool bad;                   /* an overflow, or another recorder's start, in the interval */
    bool failed;
};

static int pair_cmp(const void *a, const void *b) {
    const uint64_t *x = a, *y = b;
    return x[0] != y[0] ? (x[0] > y[0]) - (x[0] < y[0]) : (x[1] > y[1]) - (x[1] < y[1]);
}

/* What is held, sorted and each once, merged into the file. */
static int tset_spill(struct tset *t) {
    if (t->n == 0) return 0;
    qsort(t->buf, t->n, 16, pair_cmp);
    size_t u = 0;
    for (size_t i = 0; i < t->n; i++)
        if (u == 0 || pair_cmp(t->buf + 2 * (u - 1), t->buf + 2 * i) != 0) {
            t->buf[2 * u] = t->buf[2 * i];
            t->buf[2 * u + 1] = t->buf[2 * i + 1];
            u++;
        }
    const int in = openat(t->tfd, t->name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    const int out = openat(t->tfd, t->next, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    FILE *fi = in == -1 ? NULL : fdopen(in, "rb"), *fo = out == -1 ? NULL : fdopen(out, "wb");
    int rc = fi != NULL && fo != NULL ? 0 : -1;
    uint64_t have[2];
    bool more = rc == 0 && fread(have, 16, 1, fi) == 1;
    size_t i = 0;
    while (rc == 0 && (more || i < u)) {
        const int c = !more ? 1 : i == u ? -1 : pair_cmp(have, t->buf + 2 * i);
        const uint64_t *w = c <= 0 ? have : t->buf + 2 * i;
        if (fwrite(w, 16, 1, fo) != 1) rc = -1;
        if (c <= 0) more = fread(have, 16, 1, fi) == 1;
        if (c >= 0) i++;
    }
    if (fi != NULL) fclose(fi); else if (in != -1) close(in);
    if (fo != NULL && fclose(fo) != 0) rc = -1;
    if (fo == NULL && out != -1) close(out);
    if (rc == 0 && renameat(t->tfd, t->next, t->tfd, t->name) == -1) rc = -1;
    t->n = 0;
    return rc;
}

static int tset_event(void *ctx, const struct kev *e) {
    struct tset *t = ctx;
    t->bad |= e->kind == KEV_OVERFLOW || e->kind == KEV_START;
    if (e->kind != KEV_EVENT || !(e->mask & KR_MODIFY) || !e->has_ino) return 0;
    if (t->n == TOUCHED_BUF && tset_spill(t) == -1) {
        t->failed = true;
        return -1;
    }
    t->buf[2 * t->n] = e->dev;
    t->buf[2 * t->n + 1] = e->ino;
    t->n++;
    return 0;
}

void krec_touched_done(struct krec_touched *t) {
    if (t->fd > 0) {
        unlink(t->path);
        close(t->fd - 1);
    }
    t->fd = 0;
    t->available = false;
}

int krec_touched(const struct state *st, long from, long to, struct krec_touched *out) {
    memset(out, 0, sizeof *out);
    struct checkpoint *list = NULL;
    size_t n = 0;
    if (state_list(st, &list, &n) == -1) return -1;
    const struct checkpoint *a = NULL, *b = NULL;
    for (size_t i = 0; i < n; i++) {
        if (list[i].id == from) a = &list[i];
        if (list[i].id == to) b = &list[i];
    }
    long long sa = 0, sb = 0;
    if (a != NULL && b != NULL && a->journal_seq > 0 && b->journal_seq >= a->journal_seq &&
        strcmp(a->recorder, b->recorder) == 0) {
        sa = a->journal_seq;
        sb = b->journal_seq;
    }
    free(list);
    if (sa == 0) return 0;
    static unsigned serial;
    struct tset t = { 0 };
    char tmp[sizeof st->dir + 8];
    snprintf(tmp, sizeof tmp, "%s/tmp", st->dir);
    if (mkdir(tmp, 0700) == -1 && errno != EEXIST) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot create %s", tmp);
        return -1;
    }
    t.tfd = open(tmp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    t.buf = malloc(TOUCHED_BUF * 16);
    snprintf(t.name, sizeof t.name, "%ld.touched.%u", (long)getpid(), serial);
    snprintf(t.next, sizeof t.next, "%ld.touched.%u.next", (long)getpid(), serial++);
    /* held locked: a file found there unlocked is a killed run's (capture-scale SC-M3) */
    const int fd = t.tfd == -1 ? -1 : openat(t.tfd, t.name, O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    int rc = -1;
    if (t.buf == NULL || fd == -1 || flock(fd, LOCK_EX | LOCK_NB) == -1) {
        belay_err_set(t.buf == NULL ? BELAY_ERR_NOMEM : BELAY_ERR_IO, errno, "cannot write a temporary file in %s", tmp);
        goto out;
    }
    const int got = krec_scan(st, sa, sb, tset_event, &t);
    if (got == -1 || (got == 0 && !t.bad && tset_spill(&t) == -1)) {
        if (got != -1 || t.failed) belay_err_set(BELAY_ERR_IO, errno, "cannot write a temporary file in %s", tmp);
        goto out;
    }
    rc = 0;
    if (got == 0 && !t.bad) {
        out->available = true;
        out->fd = fd + 1;
        snprintf(out->path, sizeof out->path, "%s/%s", tmp, t.name);
    }
out:
    if (t.tfd != -1) {
        unlinkat(t.tfd, t.next, 0);
        if (!out->available) unlinkat(t.tfd, t.name, 0);
        close(t.tfd);
    }
    if (fd != -1 && !out->available) close(fd);
    free(t.buf);
    return rc;
}
