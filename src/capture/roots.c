/*
 *  The roots of a version 5 capture (test/expect/manifest-v5.md): matching a
 *  path against the sorted list a caller gave.
 */
#define _GNU_SOURCE
#include <limits.h>

#include "capture_internal.h"

#include "belay/error.h"
#include "belay/json.h"

#include <string.h>

/* memcmp order of (a, al) against (b, bl) followed by `tail` (0: nothing). */
static int cmp_key(const char *a, size_t al, const char *b, size_t bl, char tail) {
    const size_t m = al < bl ? al : bl;
    const int c = memcmp(a, b, m);
    if (c != 0) return c;
    if (al <= bl) return al < bl || tail ? -1 : 0;
    if (!tail) return 1;
    return (unsigned char)a[bl] < (unsigned char)tail ? -1 : (unsigned char)a[bl] > (unsigned char)tail ? 1
           : al == bl + 1 ? 0 : 1;
}

/* The first root not below `key` + tail in byte order. */
static size_t lower(const struct belay_manifest_opts *o, const char *key, size_t len, char tail) {
    size_t lo = 0, hi = o->n_roots;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        const char *r = o->roots[mid].path;
        if (cmp_key(r, strlen(r), key, len, tail) < 0) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

int roots_match(const struct belay_manifest_opts *o, const char *rel, size_t len, size_t *idx, bool *below) {
    /* Every root below `rel` starts with rel + "/", and they sort together
     * from the first root at or after that key. */
    const size_t b = lower(o, rel, len, '/');
    *below = b < o->n_roots && strlen(o->roots[b].path) > len + 1 && memcmp(o->roots[b].path, rel, len) == 0 &&
             o->roots[b].path[len] == '/';
    const size_t i = lower(o, rel, len, 0);
    if (i < o->n_roots && strlen(o->roots[i].path) == len && memcmp(o->roots[i].path, rel, len) == 0) {
        *idx = i;
        return RM_EXACT;
    }
    return *below ? RM_ABOVE : RM_NONE;
}

bool roots_not_read(const struct belay_manifest_opts *o, const char *rel, size_t len) {
    for (size_t i = 0; i < o->n_not_read; i++)
        if (strlen(o->not_read[i]) == len && memcmp(o->not_read[i], rel, len) == 0) return true;
    return false;
}

static bool canonical(const char *p) {
    if (p == NULL || p[0] == '\0' || p[0] == '/') return false;
    for (const char *c = p; ; ) {
        const char *e = strchr(c, '/');
        const size_t n = e != NULL ? (size_t)(e - c) : strlen(c);
        if (n == 0 || (n == 1 && c[0] == '.') || (n == 2 && c[0] == '.' && c[1] == '.')) return false;
        if (e == NULL) return true;
        c = e + 1;
    }
}

int roots_check(const struct belay_manifest_opts *o) {
    for (size_t i = 0; i < o->n_roots; i++) {
        const char *p = o->roots[i].path;
        if (!canonical(p) || strlen(p) >= PATH_CAP ||
            (i > 0 && strcmp(o->roots[i - 1].path, p) >= 0)) {
            belay_err_set(BELAY_ERR_INVALID, 0, "manifest: the roots are not canonical relative paths, "
                          "sorted, each once (at \"%s\")", p != NULL ? p : "");
            return -1;
        }
    }
    for (size_t i = 0; i < o->n_not_read; i++)
        if (!canonical(o->not_read[i])) {
            belay_err_set(BELAY_ERR_INVALID, 0, "manifest: a not-read path is not a canonical relative path");
            return -1;
        }
    return 0;
}

/*
 *  manifest-v5 V5-E6 with its addendum V5-A5, from the mount table's text. A
 *  line of /proc/self/mountinfo (proc(5)):
 *      36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
 *      id parent dev root  point  options  optional... - type source super-options
 *  The mount is entered only when its `root` is "/" -- the whole filesystem,
 *  not a directory or a file of it bound somewhere -- and its type, the
 *  first field after the " - " separator, is on the list. Fields are
 *  separated by single spaces and escape a space as \040, so the fourth
 *  field is the root whatever the paths hold.
 */
bool fsops_mount_whole_listed(const char *mountinfo, uint64_t id) {
    static const char *const ENTERED[] = { "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "f2fs", "zfs" };
    for (const char *l = mountinfo; l != NULL && *l != '\0'; ) {
        const char *nl = strchr(l, '\n');
        const size_t ll = nl != NULL ? (size_t)(nl - l) : strlen(l);
        uint64_t got = 0;
        size_t i = 0;
        while (i < ll && l[i] >= '0' && l[i] <= '9') got = got * 10 + (uint64_t)(l[i++] - '0');
        if (i > 0 && i < ll && l[i] == ' ' && got == id) {
            const char *f = l;                  /* to the fourth field */
            for (int k = 0; k < 3 && f != NULL; k++) {
                f = memchr(f, ' ', ll - (size_t)(f - l));
                if (f != NULL) f++;
            }
            if (f == NULL || (size_t)(f - l) + 2 > ll || f[0] != '/' || f[1] != ' ') return false;
            const char *sep = NULL;             /* " - " after the optional fields */
            for (const char *q = f; (size_t)(q - l) + 3 <= ll; q++)
                if (q[0] == ' ' && q[1] == '-' && q[2] == ' ') { sep = q + 3; break; }
            if (sep == NULL) return false;
            const size_t tl = strcspn(sep, " \n");
            for (size_t t = 0; t < sizeof ENTERED / sizeof ENTERED[0]; t++)
                if (strlen(ENTERED[t]) == tl && (size_t)(sep - l) + tl <= ll && memcmp(ENTERED[t], sep, tl) == 0) return true;
            return false;
        }
        l = nl != NULL ? nl + 1 : NULL;
    }
    return false;
}
