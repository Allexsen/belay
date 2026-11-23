/*
 *  The recorder (test/expect/kernel-record.md K1 to K6): one process a
 *  watch, reading the kernel's events and appending them to the journal.
 *  It resolves no path and filters none; it never stops reading for a walk.
 *
 *  Its source of events is a fanotify group (Linux, root), or, for tests,
 *  a file read as the queue (BELAY_TEST_KREC), one event a line, paths
 *  relative to the scope:
 *
 *    <letters> <path>      an event for the object at <path>, with its
 *                          directory and name; letters: M modify, W close
 *                          after write, A attribute, + create, - delete,
 *                          d the object is a directory
 *    X <letters> <path>    the same, the object not resolving (`ino: null`)
 *    U <letters>           neither the object nor a directory resolves
 *    R <old><TAB><new>     a rename
 *    overflow              the kernel dropped events
 *    mounts_changed        the mount table changed under the roots
 *    B <name>              the create of a barrier file (written by the
 *                          capture that made it, krec_barrier)
 *    iflags false          first line only: the inode-flag self-test fails
 *
 *  Either way an event becomes a line by the same code, and everything
 *  that reads the journal is the same.
 */
#define _GNU_SOURCE
#include "watch/krec.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "belay/json.h"

#ifdef __linux__
#include <sys/fanotify.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <linux/fs.h>
#ifndef FAN_REPORT_TARGET_FID
#define FAN_REPORT_TARGET_FID 0x00001000
#endif
#ifndef FAN_RENAME
#define FAN_RENAME 0x10000000
#endif
#ifndef FAN_EVENT_INFO_TYPE_OLD_DFID_NAME
#define FAN_EVENT_INFO_TYPE_OLD_DFID_NAME 10
#endif
#ifndef FAN_EVENT_INFO_TYPE_NEW_DFID_NAME
#define FAN_EVENT_INFO_TYPE_NEW_DFID_NAME 12
#endif
#define MARKS_MAX 17
#endif

struct rec {
    const struct recorder_cfg *c;
    int wfd;                    /* watch/ */
    uint64_t wdev, wino;
    uint64_t seq;               /* the last one written */
    int seg;                    /* the segment being written */
    char seg_name[40];
    char id[17];
    char out[1 << 16];
    size_t n;
    bool iflags_events;
    char walked[512];
    /* the test queue */
    int fx;
#ifdef __linux__
    int fan;
    int mfd[MARKS_MAX];         /* a descriptor on each marked filesystem's root (K2) */
    fsid_t mfs[MARKS_MAX];
    int nm;
    int mounts;                 /* /proc/self/mountinfo, polled (K6) */
    uint64_t mounts_sum;
#endif
};

/* What an event names: an object, or a directory. */
struct obj { bool has; uint64_t dev, ino; };

static int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void flush(struct rec *r) {
    for (size_t off = 0; off < r->n;) {
        const ssize_t k = write(r->seg, r->out + off, r->n - off);
        if (k == -1 && errno == EINTR) continue;
        if (k <= 0) break;              /* the state directory is going, or full: nothing to say it to */
        off += (size_t)k;
    }
    r->n = 0;
}

static void put(struct rec *r, const char *line, size_t n) {
    if (n >= KR_LINE_MAX) return;
    if (r->n + n > sizeof r->out) flush(r);
    memcpy(r->out + r->n, line, n);
    r->n += n;
}

/* `"key":"name"`, or `"key_b64":"..."` when the bytes are not UTF-8 (K5). */
static int name_member(char *out, size_t cap, const char *key, const char *name, size_t len) {
    char body[6 * KR_NAME_MAX + 8];
    if (len == 0 || len > KR_NAME_MAX) return -1;
    if (belay_utf8_valid(name, len) && memchr(name, '\0', len) == NULL) {
        if (belay_json_escape(body, sizeof body, name, len) == -1) return -1;
        return snprintf(out, cap, ",\"%s\":\"%s\"", key, body);
    }
    if (belay_base64_encode(body, sizeof body, name, len) == -1) return -1;
    return snprintf(out, cap, ",\"%s_b64\":\"%s\"", key, body);
}

static int obj_member(char *out, size_t cap, const char *d, const char *i, const struct obj *o) {
    if (!o->has) return snprintf(out, cap, ",\"%s\":0,\"%s\":null", d, i);
    return snprintf(out, cap, ",\"%s\":%llu,\"%s\":%llu", d, (unsigned long long)o->dev, i, (unsigned long long)o->ino);
}

static void record(struct rec *r, const char *what, const char *more) {
    char line[KR_LINE_MAX];
    const int n = snprintf(line, sizeof line, "{\"seq\":%llu,\"time_ns\":%lld,\"record\":\"%s\"%s}\n",
                           (unsigned long long)++r->seq, (long long)now_ns(), what, more);
    if (n > 0 && (size_t)n < sizeof line) put(r, line, (size_t)n);
}

/* One event, as a line (K5). `dir` NULL: not a named event. */
static void event(struct rec *r, uint32_t mask, const struct obj *o, const struct obj *dir, const char *name, size_t name_len,
                  const struct obj *to, const char *to_name, size_t to_len) {
    char line[KR_LINE_MAX];
    size_t n = 0;
    int k = snprintf(line, sizeof line, "{\"seq\":%llu,\"time_ns\":%lld,\"mask\":%u", (unsigned long long)(r->seq + 1),
                     (long long)now_ns(), (unsigned)mask);
    n += (size_t)k;
    k = obj_member(line + n, sizeof line - n, "dev", "ino", o);
    n += (size_t)k;
    if (dir != NULL) {
        k = obj_member(line + n, sizeof line - n, "dir_dev", "dir_ino", dir);
        n += (size_t)k;
        k = name_member(line + n, sizeof line - n, "name", name, name_len);
        if (k < 0 || n + (size_t)k + 4 >= sizeof line) return;        /* a name no directory holds */
        n += (size_t)k;
        if (to != NULL) {
            k = obj_member(line + n, sizeof line - n, "to_dir_dev", "to_dir_ino", to);
            n += (size_t)k;
            k = name_member(line + n, sizeof line - n, "to_name", to_name, to_len);
            if (k < 0 || n + (size_t)k + 4 >= sizeof line) return;
            n += (size_t)k;
        }
    }
    line[n++] = '}';
    line[n++] = '\n';
    r->seq++;
    put(r, line, n);
}

static void ignore_segment(struct rec *r, bool add);

/* A new segment, named by the seq of its first line. */
static int segment(struct rec *r) {
    if (r->seg != -1) {
        flush(r);
        ignore_segment(r, false);
        close(r->seg);
    }
    snprintf(r->seg_name, sizeof r->seg_name, "journal.%llu", (unsigned long long)(r->seq + 1));
    r->seg = openat(r->wfd, r->seg_name, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (r->seg == -1) return -1;
    ignore_segment(r, true);
    return 0;
}

/* The create of a barrier file was seen: said, on disk, and a new segment (K5, K7). */
static void barrier(struct rec *r, const char *name, size_t len) {
    char more[6 * KR_NAME_MAX + 32];
    if (name_member(more, sizeof more, "name", name, len) < 0) return;
    record(r, "barrier", more);
    if (segment(r) == -1) _exit(0);
}

/* The seq of the last line the journal has: the next recorder goes on from it. */
static uint64_t last_seq(int wfd) {
    uint64_t best = 0, hi = 0;
    bool any = false;
    const int dfd = dup(wfd);
    DIR *d = dfd == -1 ? NULL : fdopendir(dfd);
    if (d == NULL) {
        if (dfd != -1) close(dfd);
        return 0;
    }
    for (struct dirent *e; (e = readdir(d)) != NULL;) {
        if (strncmp(e->d_name, "journal.", 8) != 0 || strspn(e->d_name + 8, "0123456789") != strlen(e->d_name + 8)) continue;
        const uint64_t f = strtoull(e->d_name + 8, NULL, 10);
        if (!any || f > hi) hi = f;
        any = true;
    }
    closedir(d);
    if (!any) return 0;
    best = hi > 0 ? hi - 1 : 0;
    char name[40];
    snprintf(name, sizeof name, "journal.%llu", (unsigned long long)hi);
    const int fd = openat(wfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FILE *f = fd == -1 ? NULL : fdopen(fd, "r");
    if (f == NULL) {
        if (fd != -1) close(fd);
        return best + (1u << 20);       /* unreadable: far past anything it may hold */
    }
    static char line[KR_LINE_MAX];
    static struct kev e;
    uint64_t lines = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        const size_t n = strlen(line);
        lines++;
        if (n > 0 && line[n - 1] == '\n' && krec_parse(line, n - 1, &e) == 0 && e.seq > best) best = e.seq;
    }
    fclose(f);
    if (best < hi - 1 + lines) best = hi - 1 + lines;   /* lines that do not read still took their place */
    return best;
}

static bool stopping(const struct rec *r) {
    struct stat s;
    return faccessat(r->wfd, "recorder.stop", F_OK, 0) == 0 || fstat(r->wfd, &s) == -1 || s.st_nlink == 0 ||
           faccessat(r->wfd, ".", F_OK, 0) == -1;
}

static void ready(const struct rec *r, const char *fmt, ...) {
    char line[800];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line - 1, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if ((size_t)n > sizeof line - 2) n = (int)sizeof line - 2;
    for (int i = 0; i < n; i++)
        if (line[i] == '\n') line[i] = ' ';
    line[n++] = '\n';
    if (write(r->c->ready_fd, line, (size_t)n) != n) { /* the starter is gone */ }
    close(r->c->ready_fd);
}

/* ---- the test queue ---- */

static uint32_t letters(const char *p, size_t n) {
    uint32_t m = 0;
    for (size_t i = 0; i < n; i++)
        m |= p[i] == 'M' ? KR_MODIFY : p[i] == 'W' ? KR_CLOSE_WRITE : p[i] == 'A' ? KR_ATTRIB : p[i] == '+' ? KR_CREATE
           : p[i] == '-' ? KR_DELETE : p[i] == 'd' ? KR_ONDIR : 0x80000000u;
    return m;
}

/* The object at <root>/<rel>, not followed; and its directory and name. */
static void fx_where(const struct rec *r, const char *rel, struct obj *o, struct obj *dir, const char **name) {
    char p[2 * PATH_MAX];
    struct stat s;
    snprintf(p, sizeof p, "%s/%s", r->c->root, rel);
    o->has = lstat(p, &s) == 0;
    o->dev = o->has ? (uint64_t)s.st_dev : 0;
    o->ino = o->has ? (uint64_t)s.st_ino : 0;
    char *slash = strrchr(p, '/');
    *name = strrchr(rel, '/') != NULL ? strrchr(rel, '/') + 1 : rel;
    *slash = '\0';
    dir->has = stat(p, &s) == 0 && S_ISDIR(s.st_mode);
    dir->dev = dir->has ? (uint64_t)s.st_dev : 0;
    dir->ino = dir->has ? (uint64_t)s.st_ino : 0;
}

static void fx_line(struct rec *r, char *l) {
    struct obj o, dir, to;
    const char *name, *to_name;
    if (strcmp(l, "overflow") == 0) { record(r, "overflow", ""); return; }
    if (strcmp(l, "mounts_changed") == 0) { record(r, "mounts_changed", ""); return; }
    if (strncmp(l, "iflags ", 7) == 0) return;
    if (l[0] == 'B' && l[1] == ' ') { barrier(r, l + 2, strlen(l + 2)); return; }
    if (l[0] == 'R' && l[1] == ' ') {
        char *tab = strchr(l + 2, '\t');
        if (tab == NULL) return;
        *tab = '\0';
        struct obj gone;
        fx_where(r, l + 2, &gone, &dir, &name);
        fx_where(r, tab + 1, &o, &to, &to_name);
        struct stat s;
        char p[2 * PATH_MAX];
        snprintf(p, sizeof p, "%s/%s", r->c->root, tab + 1);
        const bool isdir = lstat(p, &s) == 0 && S_ISDIR(s.st_mode);
        event(r, KR_RENAME | (isdir ? KR_ONDIR : 0), &o, &dir, name, strlen(name), &to, to_name, strlen(to_name));
        return;
    }
    const bool unresolved = l[0] == 'X' && l[1] == ' ', nothing = l[0] == 'U' && l[1] == ' ';
    char *p = unresolved || nothing ? l + 2 : l;
    const size_t ll = strcspn(p, " ");
    const uint32_t mask = letters(p, ll);
    if (ll == 0 || (mask & 0x80000000u)) return;
    if (nothing) {
        o.has = false;
        event(r, mask, &o, NULL, NULL, 0, NULL, NULL, 0);
        return;
    }
    if (p[ll] != ' ' || p[ll + 1] == '\0') return;
    fx_where(r, p + ll + 1, &o, &dir, &name);
    if (unresolved) o.has = false;
    event(r, mask, &o, &dir, name, strlen(name), NULL, NULL, 0);
}

static void fx_loop(struct rec *r) {
    static char buf[2 * PATH_MAX + 64];
    size_t have = 0;
    for (;;) {
        if (have >= sizeof buf - 1) have = 0;           /* a line no queue holds */
        const size_t room = sizeof buf - 1 - have;
        const ssize_t got = read(r->fx, buf + have, room);
        if (got > 0 && (size_t)got <= room) {
            have += (size_t)got;
            char *nl;
            size_t lo = 0;
            while ((nl = memchr(buf + lo, '\n', have - lo)) != NULL) {
                *nl = '\0';
                if (memchr(buf + lo, '\0', (size_t)(nl - (buf + lo))) == NULL) fx_line(r, buf + lo);
                lo = (size_t)(nl + 1 - buf);
            }
            memmove(buf, buf + lo, have - lo);
            have -= lo;
            flush(r);
            continue;
        }
        if (stopping(r)) return;
        struct timespec ts = { 0, 2000000L };
        nanosleep(&ts, NULL);
    }
}

/* ---- fanotify ---- */

#ifdef __linux__

static void ignore_segment(struct rec *r, bool add) {
    /* K5: the journal's own writes are not events */
    if (r->fan == -1) return;
    if (fanotify_mark(r->fan, (add ? FAN_MARK_ADD : FAN_MARK_REMOVE) | FAN_MARK_IGNORED_MASK | (add ? FAN_MARK_IGNORED_SURV_MODIFY : 0),
                      FAN_MODIFY | FAN_CLOSE_WRITE, r->wfd, r->seg_name) == -1) { /* then its lines name it: more lines, no wrong one */ }
}

/* dev and ino of what a handle names, by a stat of it opened (K5). */
static void by_handle(const struct rec *r, const void *fsid, struct file_handle *h, struct obj *o) {
    o->has = false;
    o->dev = o->ino = 0;
    for (int pass = 0; pass < 2 && !o->has; pass++)
        for (int i = 0; i < r->nm && !o->has; i++) {
            if ((memcmp(&r->mfs[i], fsid, sizeof r->mfs[i]) == 0) != (pass == 0)) continue;
            const int d = open_by_handle_at(r->mfd[i], h, O_PATH | O_CLOEXEC);
            if (d == -1) continue;
            struct stat s;
            if (fstat(d, &s) == 0) {
                o->has = true;
                o->dev = (uint64_t)s.st_dev;
                o->ino = (uint64_t)s.st_ino;
            }
            close(d);
        }
}

/* One event of the queue: `m` is whole within the buffer (FAN_EVENT_OK). */
static void fan_event(struct rec *r, const struct fanotify_event_metadata *m) {
    if (m->fd >= 0) close(m->fd);                       /* none is asked for */
    if (m->mask & FAN_Q_OVERFLOW) { record(r, "overflow", ""); return; }
    if (m->event_len < m->metadata_len || m->metadata_len < sizeof *m) return;
    struct obj o = { 0 }, dir = { 0 }, to = { 0 };
    const char *name = NULL, *to_name = NULL;
    size_t name_len = 0, to_len = 0;
    bool named = false, renamed = false;
    const char *p = (const char *)m + m->metadata_len, *end = (const char *)m + m->event_len;
    while ((size_t)(end - p) >= sizeof(struct fanotify_event_info_header)) {
        struct fanotify_event_info_header h;
        memcpy(&h, p, sizeof h);
        if (h.len < sizeof h || h.len > (size_t)(end - p)) break;
        const size_t fixed = sizeof(struct fanotify_event_info_fid) + sizeof(struct file_handle);
        const bool is_name = h.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME || h.info_type == FAN_EVENT_INFO_TYPE_OLD_DFID_NAME ||
                             h.info_type == FAN_EVENT_INFO_TYPE_NEW_DFID_NAME;
        if ((is_name || h.info_type == FAN_EVENT_INFO_TYPE_FID || h.info_type == FAN_EVENT_INFO_TYPE_DFID) && h.len >= fixed) {
            /* the record is aligned as the kernel wrote it; its handle's length is checked before it is used */
            struct fanotify_event_info_fid *f = (struct fanotify_event_info_fid *)(void *)p;
            struct file_handle *fh = (struct file_handle *)(void *)f->handle;
            if (fh->handle_bytes <= h.len - fixed && fh->handle_bytes <= MAX_HANDLE_SZ) {
                const char *nm = (const char *)fh->f_handle + fh->handle_bytes;
                const size_t room = h.len - fixed - fh->handle_bytes;
                const size_t nl = strnlen(nm, room);
                struct obj got;
                by_handle(r, &f->fsid, fh, &got);
                if (h.info_type == FAN_EVENT_INFO_TYPE_FID) o = got;
                else if (h.info_type == FAN_EVENT_INFO_TYPE_DFID) { if (!named) dir = got; }
                else if (nl > 0 && nl < room && nl <= KR_NAME_MAX) {
                    if (h.info_type == FAN_EVENT_INFO_TYPE_NEW_DFID_NAME) {
                        to = got; to_name = nm; to_len = nl; renamed = true;
                    } else {
                        dir = got; name = nm; name_len = nl; named = true;
                    }
                }
            }
        }
        p += h.len;
    }
    const uint32_t mask = (uint32_t)(m->mask & (FAN_MODIFY | FAN_ATTRIB | FAN_CLOSE_WRITE | FAN_CREATE | FAN_DELETE | FAN_RENAME | FAN_ONDIR));
    if (renamed && !named) return;                      /* a rename with no old name: not the kernel's */
    event(r, mask, &o, named ? &dir : NULL, name, name_len, renamed ? &to : NULL, to_name, to_len);
    if (named && (mask & KR_CREATE) && dir.has && dir.dev == r->wdev && dir.ino == r->wino && name_len > 8 &&
        memcmp(name, "barrier.", 8) == 0)
        barrier(r, name, name_len);
}

static uint64_t mounts_sum(const struct rec *r) {
    struct krec_plan *pl = malloc(sizeof *pl);
    char why[160];
    if (pl == NULL) return 0;
    krec_plan("/proc/self/mountinfo", false, r->c->root, r->c->roots, r->c->n_roots, pl, why);
    const uint64_t s = pl->sum;
    free(pl);
    return s;
}

/* K6: sets and clears the immutable flag on a file of its own and looks for the event. */
static bool iflags_probe(struct rec *r) {
    const int fd = openat(r->wfd, "iflags.probe", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat s;
    int fl = 0;
    bool seen = false;
    if (fd == -1 || fstat(fd, &s) == -1 || ioctl(fd, FS_IOC_GETFLAGS, &fl) == -1) goto out;
    static char drain[1 << 16];
    while (read(r->fan, drain, sizeof drain) > 0) { }           /* what came before is not the answer */
    int with = fl | FS_IMMUTABLE_FL;
    if (ioctl(fd, FS_IOC_SETFLAGS, &with) == -1) goto out;
    ioctl(fd, FS_IOC_SETFLAGS, &fl);
    for (int waited = 0; waited < 500 && !seen; waited += 20) {
        struct pollfd pf = { r->fan, POLLIN, 0 };
        if (poll(&pf, 1, 20) <= 0) continue;
        const ssize_t n = read(r->fan, drain, sizeof drain);
        if (n <= 0) continue;
        ssize_t left = n;
        for (const struct fanotify_event_metadata *m = (const void *)drain; FAN_EVENT_OK(m, left); m = FAN_EVENT_NEXT(m, left)) {
            if (m->fd >= 0) close(m->fd);
            if (!(m->mask & FAN_ATTRIB) || m->event_len < m->metadata_len + sizeof(struct fanotify_event_info_fid) + sizeof(struct file_handle))
                continue;
            const char *p = (const char *)m + m->metadata_len, *end = (const char *)m + m->event_len;
            while ((size_t)(end - p) >= sizeof(struct fanotify_event_info_header)) {
                struct fanotify_event_info_header h;
                memcpy(&h, p, sizeof h);
                if (h.len < sizeof h || h.len > (size_t)(end - p)) break;
                const size_t fixed = sizeof(struct fanotify_event_info_fid) + sizeof(struct file_handle);
                if (h.info_type == FAN_EVENT_INFO_TYPE_FID && h.len >= fixed) {
                    struct fanotify_event_info_fid *f = (struct fanotify_event_info_fid *)(void *)p;
                    struct file_handle *fh = (struct file_handle *)(void *)f->handle;
                    struct obj o = { 0 };
                    if (fh->handle_bytes <= h.len - fixed) by_handle(r, &f->fsid, fh, &o);
                    seen |= o.has && o.dev == (uint64_t)s.st_dev && o.ino == (uint64_t)s.st_ino;
                }
                p += h.len;
            }
        }
    }
out:
    if (fd != -1) close(fd);
    unlinkat(r->wfd, "iflags.probe", 0);
    return seen;
}

/* The group and its marks (K1, K2). 0, or -1 with `why`: the kernel's message (K4). */
static int fan_open(struct rec *r, char why[200]) {
    r->fan = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID | FAN_CLOEXEC | FAN_NONBLOCK,
                           O_RDONLY | O_CLOEXEC);
    if (r->fan == -1) {
        snprintf(why, 200, "%s", strerror(errno));
        return -1;
    }
    struct krec_plan *pl = malloc(sizeof *pl);
    char pw[160];
    if (pl == NULL || krec_plan("/proc/self/mountinfo", false, r->c->root, r->c->roots, r->c->n_roots, pl, pw) != 0) {
        snprintf(why, 200, "%s", pl == NULL ? "out of memory" : pw);
        free(pl);
        return -1;
    }
    snprintf(r->walked, sizeof r->walked, "%s", pl->walked);
    r->mounts_sum = pl->sum;
    const uint64_t mask = FAN_MODIFY | FAN_CLOSE_WRITE | FAN_ATTRIB | FAN_CREATE | FAN_DELETE | FAN_RENAME | FAN_ONDIR;
    /* the state directory's filesystem last: marked when it is not one of them (K2) */
    for (size_t i = 0; i <= pl->n_mark; i++) {
        const char *path = i < pl->n_mark ? pl->mark[i] : r->c->state_dir;
        const int d = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        struct statfs sf;
        if (d == -1 || fstatfs(d, &sf) == -1) {
            snprintf(why, 200, "%s: %s", path, strerror(errno));
            if (d != -1) close(d);
            free(pl);
            return -1;
        }
        bool have = false;
        for (int k = 0; k < r->nm; k++) have |= memcmp(&r->mfs[k], &sf.f_fsid, sizeof sf.f_fsid) == 0;
        if (have || r->nm == MARKS_MAX) { close(d); continue; }
        if (fanotify_mark(r->fan, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, AT_FDCWD, path) == -1) {
            snprintf(why, 200, "%s", strerror(errno));
            close(d);
            free(pl);
            return -1;
        }
        r->mfd[r->nm] = d;
        r->mfs[r->nm++] = sf.f_fsid;
    }
    free(pl);
    r->mounts = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
    return 0;
}

static void fan_loop(struct rec *r) {
    static _Alignas(struct fanotify_event_metadata) char buf[1 << 16];
    for (;;) {
        struct pollfd pf[2] = { { r->fan, POLLIN, 0 }, { r->mounts, POLLPRI | POLLERR, 0 } };
        const int pr = poll(pf, r->mounts != -1 ? 2 : 1, 100);
        if (pr == -1 && errno != EINTR) return;
        if (pr > 0 && r->mounts != -1 && (pf[1].revents & (POLLPRI | POLLERR))) {
            const uint64_t s = mounts_sum(r);           /* K6: only a change at, below or over what is entered */
            if (s != r->mounts_sum) record(r, "mounts_changed", "");
            r->mounts_sum = s;
        }
        if (pr > 0 && (pf[0].revents & POLLIN)) {
            ssize_t n;
            while ((n = read(r->fan, buf, sizeof buf)) > 0) {
                ssize_t left = n;
                for (const struct fanotify_event_metadata *m = (const void *)buf; FAN_EVENT_OK(m, left); m = FAN_EVENT_NEXT(m, left)) {
                    if (m->vers != FANOTIFY_METADATA_VERSION) return;
                    fan_event(r, m);
                }
            }
        }
        flush(r);
        if (stopping(r)) return;
    }
}

#else

static void ignore_segment(struct rec *r, bool add) {
    (void)r;
    (void)add;
}

#endif

void recorder_run(const struct recorder_cfg *c) {
    static struct rec r;
    r.c = c;
    r.seg = r.fx = -1;
#ifdef __linux__
    r.fan = r.mounts = -1;
#endif
    r.iflags_events = true;
    r.wfd = open(c->wdir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat ws;
    if (r.wfd == -1 || fstat(r.wfd, &ws) == -1) {
        ready(&r, "Ethe watch's directory cannot be opened");
        _exit(1);
    }
    r.wdev = (uint64_t)ws.st_dev;
    r.wino = (uint64_t)ws.st_ino;
    const int lock = openat(r.wfd, "recorder.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock == -1 || flock(lock, LOCK_EX | LOCK_NB) == -1) {
        ready(&r, "Ea recorder of this watch is running already");
        _exit(1);
    }
    unlinkat(r.wfd, "recorder.stop", 0);
    if (c->fixture != NULL) {
        r.fx = open(c->fixture, O_RDONLY | O_CLOEXEC);
        if (r.fx == -1) {
            ready(&r, "E%s", strerror(errno));
            _exit(1);
        }
        char first[16] = "";
        if (pread(r.fx, first, sizeof first - 1, 0) > 0 && strncmp(first, "iflags false\n", 13) == 0) r.iflags_events = false;
        /* the filesystems, from a table the test may put beside the queue */
        char table[PATH_MAX + 16], why[160];
        struct krec_plan *pl = malloc(sizeof *pl);
        snprintf(table, sizeof table, "%s.mountinfo", c->fixture);
        if (pl != NULL && access(table, R_OK) == 0) {
            if (krec_plan(table, true, c->root, c->roots, c->n_roots, pl, why) != 0) {
                ready(&r, "E%s", why);
                _exit(1);
            }
            snprintf(r.walked, sizeof r.walked, "%s", pl->walked);
        }
        free(pl);
    } else {
#ifdef __linux__
        char why[200];
        if (fan_open(&r, why) == -1) {
            ready(&r, "E%s", why);
            _exit(1);
        }
#else
        ready(&r, "Eno kernel record on this system");
        _exit(1);
#endif
    }
    r.seq = last_seq(r.wfd);
    /* its id: nothing but a name for this process's run */
    unsigned char rnd[8] = { 0 };
    const int ur = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (ur == -1 || read(ur, rnd, sizeof rnd) != (ssize_t)sizeof rnd) {
        const uint64_t v = (uint64_t)getpid() * 2654435761u ^ (uint64_t)now_ns();
        memcpy(rnd, &v, sizeof rnd);
    }
    if (ur != -1) close(ur);
    for (int i = 0; i < 8; i++) snprintf(r.id + 2 * i, 3, "%02x", rnd[i]);
    const int idf = openat(r.wfd, "recorder", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (idf == -1 || write(idf, r.id, 16) != 16 || write(idf, "\n", 1) != 1 || segment(&r) == -1) {
        ready(&r, "Ethe journal cannot be written: %s", strerror(errno));
        _exit(1);
    }
    close(idf);
#ifdef __linux__
    if (r.fan != -1) r.iflags_events = iflags_probe(&r);
#endif
    char more[96];
    snprintf(more, sizeof more, ",\"recorder\":\"%s\",\"pid\":%ld,\"iflags_events\":%s", r.id, (long)getpid(),
             r.iflags_events ? "true" : "false");
    record(&r, "start", more);
    flush(&r);
    ready(&r, "K%s %d%s", r.id, r.iflags_events ? 1 : 0, r.walked);
    if (r.fx != -1) fx_loop(&r);
#ifdef __linux__
    else fan_loop(&r);
#endif
    flush(&r);
    _exit(0);
}
