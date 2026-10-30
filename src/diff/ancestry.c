#include "ancestry.h"

#include <string.h>

enum anc ancestry_kind(const struct belay_entry *e) {
    if (e->type != BELAY_T_DIR) return ANC_NONE;    /* nothing lives below a non-directory */
    if (e->unreadable || e->is_mount) return ANC_SEALED;
    if (e->unstable) return ANC_INCOMPLETE;
    return ANC_NONE;
}

void ancestry_init(struct ancestry *a, enum anc root) {
    a->root = root;
    a->n = 0;
}

/* Drops the stacked entries `path` has passed for good. The top T (a prefix
 * of the buffer) still matters while `path` starts with T and the byte after
 * it is '/' (below T) or lower ("T!x" sorts before everything below T). The
 * entries under a kept top are its prefixes, so they are kept too. */
static void pop_for(struct ancestry *a, const char *path, size_t len) {
    while (a->n > 0) {
        const size_t tl = a->len[a->n - 1];
        if (len > tl && memcmp(path, a->path, tl) == 0 && (unsigned char)path[tl] <= '/') return;
        a->n--;
    }
}

void ancestry_feed(struct ancestry *a, const struct belay_entry *e) {
    if (e->path_len == 1 && e->path[0] == '.') return;      /* given up front */
    pop_for(a, e->path, e->path_len);
    if (e->path_len >= ANC_PATH_MAX) return;                 /* not a manifest path */
    memcpy(a->path, e->path, e->path_len);                   /* the stack's prefixes are kept */
    a->len[a->n] = e->path_len;
    a->kind[a->n] = (unsigned char)ancestry_kind(e);
    a->n++;
}

enum anc ancestry_of(struct ancestry *a, const char *path, size_t len) {
    pop_for(a, path, len);
    for (size_t i = a->n; i > 0; i--)
        if (path[a->len[i - 1]] == '/') return (enum anc)a->kind[i - 1];
    return a->root;
}
