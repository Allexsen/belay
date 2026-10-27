#define _GNU_SOURCE
#include "ident.h"

/* Saturating rather than overflowing (undefined behaviour; a year-2300 mtime
 * used to wrap to year 1715). Saturation can map two far-future times to one
 * value, but ctime still changes on every metadata change, so no change is
 * hidden. */
int64_t ident_ns(int64_t sec, long nsec) {
    if (sec > (INT64_MAX - nsec) / 1000000000) return INT64_MAX;
    if (sec < INT64_MIN / 1000000000 + 1)      return INT64_MIN;
    return sec * 1000000000 + nsec;
}

struct ident ident_of_stat(const struct stat *st) {
#ifdef __APPLE__
    const struct timespec *m = &st->st_mtimespec, *c = &st->st_ctimespec;
#else
    const struct timespec *m = &st->st_mtim, *c = &st->st_ctim;
#endif
    return (struct ident){
        .ino = (uint64_t)st->st_ino, .dev = (uint64_t)st->st_dev,
        .size = (uint64_t)st->st_size, .mode = (uint32_t)st->st_mode,
        .mtime_ns = ident_ns((int64_t)m->tv_sec, m->tv_nsec),
        .ctime_ns = ident_ns((int64_t)c->tv_sec, c->tv_nsec),
    };
}

struct ident ident_of_entry(const struct belay_entry *e) {
    return (struct ident){ .ino = e->ino, .dev = e->dev, .size = e->size, .mode = e->mode,
                           .mtime_ns = e->mtime_ns, .ctime_ns = e->ctime_ns };
}

unsigned ident_diff(const struct ident *a, const struct ident *b) {
    unsigned d = 0;
    if (a->ino != b->ino)                           d |= ID_INO;
    if (a->dev != b->dev)                           d |= ID_DEV;
    if ((a->mode & S_IFMT) != (b->mode & S_IFMT))   d |= ID_TYPE;
    if ((a->mode & ~(uint32_t)S_IFMT) != (b->mode & ~(uint32_t)S_IFMT)) d |= ID_PERM;
    if (a->size != b->size)                         d |= ID_SIZE;
    if (a->mtime_ns != b->mtime_ns)                 d |= ID_MTIME;
    if (a->ctime_ns != b->ctime_ns)                 d |= ID_CTIME;
    return d;
}
