/*
 *  Identity of a filesystem object at one moment: which object it is (inode,
 *  device), what it is (type, permissions), and what state it was in (size,
 *  mtime, ctime). Every "is this still the thing we recorded?" question in
 *  capture is a comparison of two idents over a named set of fields.
 */
#ifndef BELAY_CAPTURE_IDENT_H
#define BELAY_CAPTURE_IDENT_H

#include "belay/manifest.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

struct ident {
    uint64_t ino, dev, size;
    int64_t  mtime_ns, ctime_ns;
    uint32_t mode;
};

enum {
    ID_INO   = 1u << 0,
    ID_DEV   = 1u << 1,
    ID_TYPE  = 1u << 2,
    ID_PERM  = 1u << 3,
    ID_SIZE  = 1u << 4,
    ID_MTIME = 1u << 5,
    ID_CTIME = 1u << 6,
};
#define ID_OBJECT (ID_INO | ID_DEV)           /* the same object */
#define ID_MODE   (ID_TYPE | ID_PERM)
#define ID_TIMES  (ID_MTIME | ID_CTIME)       /* unchanged since */
#define ID_ALL    (ID_OBJECT | ID_MODE | ID_SIZE | ID_TIMES)

/* Seconds + nanoseconds as nanoseconds, saturating outside 1678..2262. */
int64_t ident_ns(int64_t sec, long nsec);

struct ident ident_of_stat(const struct stat *st);
struct ident ident_of_entry(const struct belay_entry *e);

/* The fields in which a and b differ, as an ID_* mask. */
unsigned ident_diff(const struct ident *a, const struct ident *b);

static inline bool ident_same(const struct ident *a, const struct ident *b, unsigned fields) {
    return (ident_diff(a, b) & fields) == 0;
}

#endif
