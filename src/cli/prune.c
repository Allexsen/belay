/*
 *  belay prune (test/expect/state-retention.md, PR-1..PR-10, KP-3): removes
 *  checkpoints outside the limits given, and the store's objects no remaining
 *  checkpoint refers to. The only thing in belay that deletes from the state
 *  directory.
 *
 *  Everything a run will do is decided first, reading every manifest that
 *  stays: one that doesn't read stops the run with nothing removed, and
 *  --dry-run takes the same path, so what it says is what a run would do.
 *
 *  That reading takes minutes on a busy scope, and every capture would wait
 *  for it. So it is done without the lock, and again under the lock for what
 *  was captured meanwhile: a new checkpoint can name a stored copy that nothing
 *  else named, and what it names must not be swept.
 */
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "belay/error.h"
#include "belay/manifest.h"
#include "cli.h"
#include "cli_internal.h"
#include "delta.h"
#include "state.h"

#define NS_PER_DAY 86400000000000LL

struct object { char hex[65]; uint64_t size; bool marked; };

void (*prune_between_passes)(void) = NULL;

/* The store's objects and what the unlocked pass found. */
struct marks { struct object *objects; size_t n; long upto; };

struct plan {
    bool *goes;                 /* per checkpoint in the list */
    size_t n_goes, n_kept;
    uint64_t bytes;
    struct object *objects;
    size_t n_objects, n_swept;
    uint64_t swept_bytes;
    long *stale;                /* directories without a meta.json, below the newest id */
    size_t n_stale;
    char (*temps)[64];          /* store/.tmp-* a killed capture left (PR-11) */
    size_t n_temps;
    long *rewrite;              /* deltas that stay, whose base goes (PR-4) */
    size_t n_rewrite;
    uint64_t grows;             /* what those whole files will take */
};

static int by_hex(const void *a, const void *b) {
    return strcmp(((const struct object *)a)->hex, ((const struct object *)b)->hex);
}

static bool all_hex(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return s[n] == '\0';
}

/* The store's objects, sorted. A name that is not an object's (a commit that
 * never finished) is no object: it is left alone. */
static int store_list(const struct state *st, struct plan *p) {
    const int sfd = openat(st->dir_fd, "store", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (sfd == -1) {
        if (errno == ENOENT) return 0;
        belay_err_set(BELAY_ERR_CORRUPT, errno, "%s is not a store belay made", st->store);
        return -1;
    }
    DIR *d = fdopendir(sfd);
    if (d == NULL) {
        close(sfd);
        belay_err_set(BELAY_ERR_IO, errno, "cannot list %s", st->store);
        return -1;
    }
    size_t cap = 0;
    int rc = 0;
    struct dirent *de;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (strlen(de->d_name) != 2 || !all_hex(de->d_name, 2)) continue;
        const int ffd = openat(sfd, de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        DIR *f = ffd == -1 ? NULL : fdopendir(ffd);
        if (f == NULL) {
            if (ffd != -1) close(ffd);
            belay_err_set(BELAY_ERR_CORRUPT, errno, "%s/%s is not a directory belay made", st->store, de->d_name);
            rc = -1;
            break;
        }
        struct dirent *e;
        while ((e = readdir(f)) != NULL) {
            struct stat s;
            if (strlen(e->d_name) != 62 || !all_hex(e->d_name, 62)) continue;
            if (fstatat(ffd, e->d_name, &s, AT_SYMLINK_NOFOLLOW) == -1 || !S_ISREG(s.st_mode)) continue;
            if (p->n_objects == cap) {
                cap = cap ? cap * 2 : 1024;
                struct object *q = realloc(p->objects, cap * sizeof *q);
                if (q == NULL) {
                    belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
                    rc = -1;
                    break;
                }
                p->objects = q;
            }
            struct object *o = &p->objects[p->n_objects++];
            memcpy(o->hex, de->d_name, 2);
            memcpy(o->hex + 2, e->d_name, 63);
            o->size = (uint64_t)s.st_size;
            o->marked = false;
        }
        closedir(f);
    }
    closedir(d);
    if (rc == 0 && p->n_objects > 1) qsort(p->objects, p->n_objects, sizeof *p->objects, by_hex);
    return rc;
}

/* A killed capture's temporaries: store/.tmp-*, older than a day (PR-11). A
 * running capture holds the lock, and these are removed only under it; a day
 * covers a dry run, which holds none. */
static int store_temps(const struct state *st, int64_t now, struct plan *p) {
    const int fd = openat(st->dir_fd, "store", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) return errno == ENOENT ? 0 : (belay_err_set(BELAY_ERR_CORRUPT, errno, "%s is not a store belay made", st->store), -1);
    DIR *d = fdopendir(fd);
    if (d == NULL) {
        close(fd);
        belay_err_set(BELAY_ERR_IO, errno, "cannot list %s", st->store);
        return -1;
    }
    size_t cap = 0;
    int rc = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        struct stat s;
        if (strncmp(e->d_name, ".tmp-", 5) != 0 || strlen(e->d_name) >= sizeof *p->temps) continue;
        if (fstatat(fd, e->d_name, &s, AT_SYMLINK_NOFOLLOW) == -1 || !S_ISREG(s.st_mode)) continue;
        if ((int64_t)s.st_mtime * 1000000000LL > now - NS_PER_DAY) continue;
        if (p->n_temps == cap) {
            cap = cap ? cap * 2 : 16;
            char (*q)[64] = realloc(p->temps, cap * sizeof *q);
            if (q == NULL) {
                belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
                rc = -1;
                break;
            }
            p->temps = q;
        }
        snprintf(p->temps[p->n_temps++], sizeof *p->temps, "%s", e->d_name);
        p->swept_bytes += (uint64_t)s.st_size;
    }
    closedir(d);
    return rc;
}

static int mark_entry(const struct belay_entry *e, void *ctx) {
    struct plan *p = ctx;
    if (!e->has_stored || p->n_objects == 0) return 0;
    struct object key;
    memcpy(key.hex, e->stored_hex, sizeof key.hex);
    struct object *o = bsearch(&key, p->objects, p->n_objects, sizeof *p->objects, by_hex);
    if (o != NULL) o->marked = true;
    return 0;
}

/* What belay writes in a checkpoint's directory, a killed capture's leftovers
 * included (manifest_write.c). Anything else is not belay's to remove. */
static bool ours(const char *n) {
    return !strcmp(n, "manifest.ndjson") || !strcmp(n, "manifest.delta") || !strcmp(n, "manifest.delta.tmp") ||
           !strcmp(n, "meta.json") || !strcmp(n, "meta.json.tmp") ||
           !strncmp(n, "diff-from-", 10) || !strncmp(n, "manifest.ndjson.tmp.", 20) || !strncmp(n, "manifest.ndjson.run.", 20);
}

/* What a checkpoint's directory holds, in bytes. Refused here, before anything
 * goes, if it holds what belay did not write: a dry run says so too, and a run
 * never stops half way for it. */
static int dir_bytes(const struct state *st, long id, uint64_t *bytes) {
    char name[16];
    snprintf(name, sizeof name, "%ld", id);
    const int fd = openat(st->cp_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *d = fd == -1 ? NULL : fdopendir(fd);
    if (d == NULL) {
        if (fd != -1) close(fd);
        belay_err_set(BELAY_ERR_CORRUPT, errno, "%s/checkpoints/%ld is not a directory belay made", st->dir, id);
        return -1;
    }
    struct dirent *e;
    int rc = 0;
    while ((e = readdir(d)) != NULL) {
        struct stat s;
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (!ours(e->d_name)) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "%s/checkpoints/%ld holds what belay did not write", st->dir, id);
            rc = -1;
            break;
        }
        if (fstatat(fd, e->d_name, &s, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(s.st_mode)) *bytes += (uint64_t)s.st_size;
    }
    closedir(d);
    return rc;
}

/* A killed capture's run directory: the sorter's files, then itself. */
static void remove_run_dir(int parent, const char *name) {
    const int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *d = fd == -1 ? NULL : fdopendir(fd);
    if (d == NULL) {
        if (fd != -1) close(fd);
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) unlinkat(fd, e->d_name, 0);
    closedir(d);
    unlinkat(parent, name, AT_REMOVEDIR);
}

/* The directories under checkpoints/ with no meta.json, below `newest`: a
 * capture that failed, or a removal a crash cut short (PR-8). */
static int stale_dirs(const struct state *st, long newest, struct plan *p) {
    const int fd = dup(st->cp_fd);
    DIR *d = fd == -1 ? NULL : fdopendir(fd);
    if (d == NULL) {
        if (fd != -1) close(fd);
        belay_err_set(BELAY_ERR_IO, errno, "cannot list %s/checkpoints", st->dir);
        return -1;
    }
    rewinddir(d);
    size_t cap = 0;
    int rc = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        const long id = state_id_parse(e->d_name);
        struct stat s;
        char meta[32];
        if (id == 0 || id >= newest) continue;
        snprintf(meta, sizeof meta, "%ld/meta.json", id);
        if (fstatat(st->cp_fd, meta, &s, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) continue;
        if (p->n_stale == cap) {
            cap = cap ? cap * 2 : 16;
            long *q = realloc(p->stale, cap * sizeof *q);
            if (q == NULL) {
                belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
                rc = -1;
                break;
            }
            p->stale = q;
        }
        p->stale[p->n_stale++] = id;
    }
    closedir(d);
    return rc;
}

/* A checkpoint's directory, gone: meta.json first, so what a crash leaves is
 * no checkpoint (PR-8). Only what belay writes there is removed: anything
 * else is corrupt state, and stays. */
static int remove_checkpoint(const struct state *st, long id) {
    char name[16];
    snprintf(name, sizeof name, "%ld", id);
    const int fd = openat(st->cp_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        belay_err_set(BELAY_ERR_CORRUPT, errno, "%s/checkpoints/%ld is not a directory belay made", st->dir, id);
        return -1;
    }
    if (unlinkat(fd, "meta.json", 0) == -1 && errno != ENOENT) {
        close(fd);
        belay_err_set(BELAY_ERR_IO, errno, "cannot remove %s/checkpoints/%ld/meta.json", st->dir, id);
        return -1;
    }
    const int dup_fd = dup(fd);
    DIR *d = dup_fd == -1 ? NULL : fdopendir(dup_fd);
    if (d == NULL) {
        if (dup_fd != -1) close(dup_fd);
        close(fd);
        belay_err_set(BELAY_ERR_IO, errno, "cannot list %s/checkpoints/%ld", st->dir, id);
        return -1;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        if (ours(n) && unlinkat(fd, n, 0) == -1 && errno == EISDIR) remove_run_dir(fd, n);
        else if (ours(n) && errno == EPERM) remove_run_dir(fd, n);      /* macOS says so of a directory */
    }
    closedir(d);
    close(fd);
    if (unlinkat(st->cp_fd, name, AT_REMOVEDIR) == -1) {
        belay_err_set(BELAY_ERR_CORRUPT, errno, "%s/checkpoints/%ld holds what belay did not write", st->dir, id);
        return -1;
    }
    return 0;
}

/* The id in a cached diff's name, diff-from-<id>.ndjson, or 0 if it isn't one. */
static long cached_since(const char *name) {
    if (strncmp(name, "diff-from-", 10) != 0) return 0;
    const char *id = name + 10, *dot = strchr(id, '.');
    char digits[16];
    if (dot == NULL || strcmp(dot, ".ndjson") != 0 || (size_t)(dot - id) >= sizeof digits) return 0;
    memcpy(digits, id, (size_t)(dot - id));
    digits[dot - id] = '\0';
    return state_id_parse(digits);
}

/* A cached diff from a checkpoint that is gone, held by one that stays
 * (PR-5): counted into *bytes, and removed when `remove`. */
static int orphan_diffs(const struct state *st, long id, const struct checkpoint *list, const bool *goes, size_t n,
                        bool remove, uint64_t *bytes) {
    char name[16];
    snprintf(name, sizeof name, "%ld", id);
    const int fd = openat(st->cp_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    const int dup_fd = fd == -1 ? -1 : dup(fd);
    DIR *d = dup_fd == -1 ? NULL : fdopendir(dup_fd);
    if (d == NULL) {
        if (dup_fd != -1) close(dup_fd);
        if (fd != -1) close(fd);
        belay_err_set(BELAY_ERR_IO, errno, "cannot list %s/checkpoints/%ld", st->dir, id);
        return -1;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        const long since = cached_since(e->d_name);
        if (since == 0) continue;
        bool stays = false;
        for (size_t lo = 0, hi = n; lo < hi;) {
            const size_t mid = lo + (hi - lo) / 2;
            if (list[mid].id == since) { stays = !goes[mid]; break; }
            if (list[mid].id < since) lo = mid + 1; else hi = mid;
        }
        if (stays) continue;
        struct stat s;
        if (fstatat(fd, e->d_name, &s, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(s.st_mode)) *bytes += (uint64_t)s.st_size;
        if (remove) unlinkat(fd, e->d_name, 0);
    }
    closedir(d);
    close(fd);
    return 0;
}

static void ranges(FILE *out, const struct checkpoint *list, const bool *pick, size_t n, bool json) {
    bool first = true;
    for (size_t i = 0; i < n; i++) {
        if (!pick[i]) continue;
        size_t j = i;
        while (j + 1 < n && pick[j + 1] && list[j + 1].id == list[j].id + 1) j++;
        if (json) fprintf(out, "%s[%ld,%ld]", first ? "" : ",", list[i].id, list[j].id);
        else if (i == j) fprintf(out, "%s%ld", first ? "" : ", ", list[i].id);
        else fprintf(out, "%s%ld-%ld", first ? "" : ", ", list[i].id, list[j].id);
        first = false;
        i = j;
    }
}

static int prune(struct state *st, long days, long last, long from, const long *ids, size_t n_ids, bool dry, bool json,
                 bool quiet, bool real, struct marks *m, FILE *out, FILE *err) {
    struct checkpoint *list = NULL;
    size_t n = 0;
    struct plan p = { 0 };
    int rc = 0;
    bool *kept = NULL;
    if (st->cp_fd == -1 || state_list(st, &list, &n) == -1 || n == 0) {
        if (belay_err_code() != BELAY_OK) { rc = cli_failed(err); goto out; }
        if (n_ids > 0) {
            char why[64];
            snprintf(why, sizeof why, "no checkpoint %ld", ids[0]);
            rc = cli_usage(err, why);
            goto out;
        }
        if (json) fprintf(out, "{\"dry_run\":%s,\"removed\":0,\"remaining\":0,\"kept\":0,\"bytes\":0,\"store_objects\":0,"
                               "\"store_temps\":0,\"store_bytes\":0,\"unfinished\":0,\"ids\":[],\"kept_ids\":[]}\n", real ? "false" : "true");
        else fputs("no checkpoints of the scope\n", out);
        goto out;
    }
    p.goes = calloc(n, sizeof *p.goes);
    kept = calloc(n, sizeof *kept);
    p.rewrite = calloc(n, sizeof *p.rewrite);
    if (p.goes == NULL || kept == NULL || p.rewrite == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        rc = cli_failed(err);
        goto out;
    }
    for (size_t k = 0; k < n_ids; k++) {
        bool found = false;
        for (size_t i = 0; i < n && !found; i++)
            if (list[i].id == ids[k]) found = kept[i] = true;
        if (!found) {
            char why[64];
            snprintf(why, sizeof why, "no checkpoint %ld", ids[k]);
            rc = cli_usage(err, why);
            goto out;
        }
    }
    if (from > list[n - 1].id) {
        char why[160];
        snprintf(why, sizeof why, "--keep-from %ld is past the newest checkpoint, %ld: it protects nothing", from, list[n - 1].id);
        rc = cli_usage(err, why);
        goto out;
    }
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    const int64_t now = (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
    /* A limit further back than the clock's start keeps everything: days *
     * NS_PER_DAY must not wrap, or asking to keep more would keep less. */
    const int64_t cutoff = days > now / NS_PER_DAY ? INT64_MIN : now - (int64_t)days * NS_PER_DAY;
    for (size_t i = 0; i < n; i++) {
        const bool newest = i + 1 == n;
        const bool in_age = days >= 0 && list[i].created_ns >= cutoff;
        const bool in_last = last >= 0 && n - i <= (size_t)last;
        const bool from_on = from > 0 && list[i].id >= from;
        kept[i] = kept[i] || list[i].kept;
        if (kept[i]) p.n_kept++;
        if (newest || kept[i] || in_age || in_last || from_on) continue;
        p.goes[i] = true;
        p.n_goes++;
        if (dir_bytes(st, list[i].id, &p.bytes) == -1) { rc = cli_failed(err); goto out; }
    }
    /* Everything that stays is read before anything goes. */
    p.objects = m->objects;
    p.n_objects = m->n;
    const bool listed = m->objects != NULL;
    if ((!listed && store_list(st, &p) == -1) || stale_dirs(st, list[n - 1].id, &p) == -1) {
        m->objects = p.objects;
        rc = cli_failed(err);
        goto out;
    }
    m->objects = p.objects;
    m->n = p.n_objects;
    for (size_t i = 0; i < p.n_stale; i++) {
        if (dir_bytes(st, p.stale[i], &p.bytes) == -1) { rc = cli_failed(err); goto out; }
    }
    for (size_t i = 0; i < n; i++)
        if (!p.goes[i] && orphan_diffs(st, list[i].id, list, p.goes, n, false, &p.bytes) == -1) { rc = cli_failed(err); goto out; }
    for (size_t i = 0; i < n; i++) {
        if (p.goes[i] || list[i].id <= m->upto) continue;
        struct manifest_file mf;
        if (manifest_acquire(st, list[i].id, &mf) == -1) { rc = cli_failed(err); goto out; }
        const int read = belay_manifest_read(mf.path, mark_entry, &p);
        manifest_release(&mf);
        if (read == -1) { rc = cli_failed(err); goto out; }
    }
    /* A delta that stays and whose base goes (PR-4). */
    for (size_t i = 0; i < n; i++) {
        long base;
        uint64_t size, stored;
        if (p.goes[i]) continue;
        if (manifest_delta_base(st, list[i].id, &base, &size, &stored) == -1) { rc = cli_failed(err); goto out; }
        if (base == 0) continue;
        bool gone = true;
        for (size_t lo = 0, hi = n; lo < hi;) {
            const size_t mid = lo + (hi - lo) / 2;
            if (list[mid].id == base) { gone = p.goes[mid]; break; }
            if (list[mid].id < base) lo = mid + 1; else hi = mid;
        }
        if (!gone) continue;
        p.rewrite[p.n_rewrite++] = list[i].id;
        p.bytes += stored;
        p.grows += size;
    }
    p.bytes = p.bytes > p.grows ? p.bytes - p.grows : 0;
    m->upto = list[n - 1].id;
    if (store_temps(st, now, &p) == -1) { rc = cli_failed(err); goto out; }
    for (size_t i = 0; i < p.n_objects; i++)
        if (!p.objects[i].marked) {
            p.n_swept++;
            p.swept_bytes += p.objects[i].size;
        }
    if (!dry) {
        for (size_t i = 0; i < n; i++)
            if (kept[i] && !list[i].kept && state_keep(st, list[i].id) == -1) { rc = cli_failed(err); goto out; }
        for (size_t i = 0; i < p.n_rewrite; i++)
            if (manifest_make_whole(st, p.rewrite[i]) == -1) { rc = cli_failed(err); goto out; }
        for (size_t i = 0; i < n; i++)
            if (p.goes[i] && remove_checkpoint(st, list[i].id) == -1) { rc = cli_failed(err); goto out; }
        for (size_t i = 0; i < p.n_stale; i++)
            if (remove_checkpoint(st, p.stale[i]) == -1) { rc = cli_failed(err); goto out; }
        uint64_t counted = 0;
        for (size_t i = 0; i < n; i++)
            if (!p.goes[i] && orphan_diffs(st, list[i].id, list, p.goes, n, true, &counted) == -1) { rc = cli_failed(err); goto out; }
        /* The removals land before the sweep starts: a checkpoint must never
         * outlive, after a power cut, the objects it refers to. */
        if (fsync(st->cp_fd) == -1) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot sync %s/checkpoints", st->dir);
            rc = cli_failed(err);
            goto out;
        }
        for (size_t i = 0; i < p.n_objects; i++) {
            if (p.objects[i].marked) continue;
            char rel[80];
            snprintf(rel, sizeof rel, "store/%.2s/%s", p.objects[i].hex, p.objects[i].hex + 2);
            if (unlinkat(st->dir_fd, rel, 0) == -1 && errno != ENOENT) {
                belay_err_set(BELAY_ERR_IO, errno, "cannot remove %s/%s", st->dir, rel);
                rc = cli_failed(err);
                goto out;
            }
        }
        for (size_t i = 0; i < p.n_temps; i++) {
            char rel[80];
            snprintf(rel, sizeof rel, "store/%s", p.temps[i]);
            if (unlinkat(st->dir_fd, rel, 0) == -1 && errno != ENOENT) {
                belay_err_set(BELAY_ERR_IO, errno, "cannot remove %s/%s", st->dir, rel);
                rc = cli_failed(err);
                goto out;
            }
        }
    }
    if (quiet) goto out;
    if (json) {
        fprintf(out, "{\"dry_run\":%s,\"removed\":%zu,\"remaining\":%zu,\"kept\":%zu,\"bytes\":%" PRIu64
                ",\"store_objects\":%zu,\"store_temps\":%zu,\"store_bytes\":%" PRIu64 ",\"unfinished\":%zu,\"ids\":[",
                dry ? "true" : "false", p.n_goes, n - p.n_goes, p.n_kept, p.bytes, p.n_swept, p.n_temps, p.swept_bytes, p.n_stale);
        ranges(out, list, p.goes, n, true);
        fputs("],\"kept_ids\":[", out);
        ranges(out, list, kept, n, true);
        fputs("]}\n", out);
    } else {
        const char *verb = dry ? "would remove" : "removed";
        fprintf(out, "%s %zu of %zu checkpoints, %" PRIu64 " bytes", verb, p.n_goes, n, p.bytes);
        if (p.n_goes) {
            fputs(": ", out);
            ranges(out, list, p.goes, n, false);
        }
        fprintf(out, "\n%s %zu store objects", verb, p.n_swept);
        if (p.n_temps) fprintf(out, " and %zu left by killed captures", p.n_temps);
        fprintf(out, ", %" PRIu64 " bytes\n", p.swept_bytes);
        if (p.n_stale) fprintf(out, "%s %zu unfinished directories\n", verb, p.n_stale);
        if (p.n_kept) {
            fprintf(out, "kept %zu: ", p.n_kept);
            ranges(out, list, kept, n, false);
            fputc('\n', out);
        }
    }
out:
    free(list);
    free(kept);
    free(p.goes);
    free(p.stale);
    free(p.rewrite);
    free(p.temps);
    return rc;
}

/* Digits only, at most STATE_ID_DIGITS of them, as --full-every. */
static bool number(const char *s, long *v) {
    const size_t n = s == NULL ? 0 : strlen(s);
    if (n == 0 || n > STATE_ID_DIGITS || strspn(s, "0123456789") != n) return false;
    *v = strtol(s, NULL, 10);
    return true;
}

int cmd_prune(int argc, char **argv, FILE *out, FILE *err) {
    const char *scope = NULL, *docker = NULL;
    long days = -1, last = -1, from = 0;
    bool dry = false, json = false;
    struct marks m = { 0 };
    long *ids = calloc((size_t)argc, sizeof *ids);
    size_t n_ids = 0;
    int rc = 0;
    if (ids == NULL) return cli_usage(err, "out of memory");
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--dry-run")) { dry = true; continue; }
        if (!strcmp(a, "--json")) { json = true; continue; }
        const bool known = !strcmp(a, "--scope") || !strcmp(a, "--docker") || !strcmp(a, "--keep-days") ||
                           !strcmp(a, "--keep-last") || !strcmp(a, "--keep-id") || !strcmp(a, "--keep-from");
        char why[256];
        if (!known) {
            snprintf(why, sizeof why, "unknown option %.200s", a);
            rc = cli_usage(err, why);
            goto done;
        }
        if (i + 1 >= argc) {
            snprintf(why, sizeof why, "%s needs a value", a);
            rc = cli_usage(err, why);
            goto done;
        }
        const char *v = argv[++i];
        long x = 0;
        if (strcmp(a, "--keep-id") && ((!strcmp(a, "--scope") && scope) || (!strcmp(a, "--docker") && docker) ||
                                       (!strcmp(a, "--keep-days") && days >= 0) || (!strcmp(a, "--keep-last") && last >= 0) ||
                                       (!strcmp(a, "--keep-from") && from))) {
            snprintf(why, sizeof why, "%s given twice", a);
            rc = cli_usage(err, why);
            goto done;
        }
        if (!strcmp(a, "--scope")) scope = v;
        else if (!strcmp(a, "--docker")) docker = v;
        else if (!strcmp(a, "--keep-days") ? !number(v, &days) : !strcmp(a, "--keep-last") ? !number(v, &last) : false) {
            snprintf(why, sizeof why, "%s needs a number", a);
            rc = cli_usage(err, why);
            goto done;
        } else if (!strcmp(a, "--keep-id") || !strcmp(a, "--keep-from")) {
            x = state_id_parse(v);
            if (x == 0) {
                snprintf(why, sizeof why, "%s needs a checkpoint id", a);
                rc = cli_usage(err, why);
                goto done;
            }
            if (!strcmp(a, "--keep-id")) ids[n_ids++] = x;
            else from = x;
        }
    }
    if (scope == NULL) { rc = cli_usage(err, "--scope DIR is required"); goto done; }
    if (days < 0 && last < 0) { rc = cli_usage(err, "--keep-days or --keep-last is required"); goto done; }
    struct state st;
    /* The long read, with no lock: nothing is written, and captures go on. */
    rc = cli_open_scope(scope, docker, false, &st, err);
    if (rc) goto done;
    rc = prune(&st, days, last, from, ids, n_ids, true, json, !dry, !dry, &m, out, err);
    state_close(&st);
    if (rc || dry || m.upto == 0) goto done;    /* nothing there: no state made for it */
    if (prune_between_passes != NULL) prune_between_passes();
    rc = cli_open_scope(scope, docker, true, &st, err);
    if (rc) goto done;
    rc = prune(&st, days, last, from, ids, n_ids, false, json, false, true, &m, out, err);
    state_close(&st);
done:
    free(m.objects);
    free(ids);
    return rc;
}

/* belay manifest (ST-8): for whatever needs a manifest, rather than reading the
 * state directory. */
int cmd_manifest(int argc, char **argv, FILE *out, FILE *err) {
    const char *scope = NULL, *docker = NULL, *id_text = NULL;
    for (int i = 2; i < argc; i++) {
        const char **val = !strcmp(argv[i], "--scope") ? &scope : !strcmp(argv[i], "--docker") ? &docker
                         : !strcmp(argv[i], "--id") ? &id_text : NULL;
        char why[256];
        if (val == NULL || i + 1 >= argc || *val != NULL) {
            snprintf(why, sizeof why, "%s: unknown, given twice, or missing its value", argv[i]);
            return cli_usage(err, why);
        }
        *val = argv[++i];
    }
    const long id = state_id_parse(id_text);
    if (scope == NULL) return cli_usage(err, "--scope DIR is required");
    if (id == 0) return cli_usage(err, "--id needs a checkpoint id");
    struct state st;
    int rc = cli_open_scope(scope, docker, false, &st, err);
    if (rc) return rc;
    struct manifest_file mf;
    const int exists = state_checkpoint_exists(&st, id);
    if (exists != 1) {
        char why[64];
        belay_err_clear();
        snprintf(why, sizeof why, "no checkpoint %ld", id);
        rc = cli_usage(err, why);
    } else if (manifest_acquire(&st, id, &mf) == -1) {
        rc = cli_failed(err);
    } else {
        FILE *f = fopen(mf.path, "r");
        char buf[65536];
        size_t k;
        if (f == NULL) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", mf.path);
            rc = cli_failed(err);
        } else {
            while ((k = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, k, out);
            fclose(f);
        }
        manifest_release(&mf);
    }
    state_close(&st);
    return rc;
}
