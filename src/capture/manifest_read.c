/*
 *  Manifest reader: the public iterator, composing three layers, each with
 *  one job --
 *    manifest_lex.c     bytes -> objects: the grammar, canonical key order;
 *    manifest_decode.c  objects -> fields: one case per schema field, then
 *                       entry_check (entry.c) and the header's rules;
 *    manifest_stream.c  rules over the sequence: order, sealed directories,
 *                       the root, the trailer's counts.
 *  A strict parser for exactly the language the writer emits; the grammar,
 *  and why it is a grammar rather than a key search, are in manifest_lex.h.
 *
 *  Treat input as hostile: a manifest can be hand-edited, truncated by a full
 *  disk, or crafted. Strictness is the point -- a reader that repairs what it
 *  can lets two different files mean the same thing.
 */
#define _GNU_SOURCE

#include "belay/manifest.h"
#include "schema/entry.h"
#include "capture/manifest_lex.h"
#include "capture/manifest_decode.h"
#include "capture/manifest_stream.h"
#include "belay/path.h"
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Iterator                                                                  */
/* ------------------------------------------------------------------------ */

struct belay_manifest_reader {
    FILE  *f;
    char  *line;            /* LINE_MAX_BYTES + 1 */
    size_t len;
    size_t lineno;
    int    state;           /* 0 open, 1 ended cleanly, -1 failed (sticky) */

    struct belay_manifest_header header;
    struct belay_excluded excluded[BELAY_EXCLUDED_MAX];   /* header.excluded points here (v2) */
    /* Version 5's lines that are not entries (manifest-v5-addendum V5-A1,
     * V5-A2). The roots, read with the header: header.roots points at
     * `roots`, each path its own allocation, ROOTS_MAX at most. The racy
     * paths, read after the last entry: one buffer, BELAY_RACY_MAX at most. */
    struct belay_root *roots;
    size_t n_roots, cap_roots;
    bool   header_only;         /* belay_manifest_open_header: no root line was asked for */
    off_t  entries_at;          /* where the first entry line starts */
    char  *racy;                /* the paths, each NUL-terminated */
    size_t *racy_at;            /* each one's offset in `racy`; racy_len its length */
    size_t *racy_len;
    size_t racy_used, racy_cap, n_racy, cap_racy;
    struct belay_manifest_stats  trailer;
    bool   have_trailer;

    struct belay_sha256 digest; /* of every byte read; final once ended */
    char   digest_hex[65];

    struct stream st;           /* rules over the sequence (manifest_stream.c) */
};

const struct belay_manifest_header *
belay_manifest_header(const struct belay_manifest_reader *r) {
    return r == NULL ? NULL : &r->header;
}

const struct belay_manifest_stats *
belay_manifest_trailer(const struct belay_manifest_reader *r) {
    return (r != NULL && r->have_trailer) ? &r->trailer : NULL;
}

/* One line, as lex_line, and its bytes (with the newline) into the digest. */
static int next_line(struct belay_manifest_reader *r) {
    const int got = lex_line(r->f, r->line, &r->len, &r->lineno);
    if (got == 1) {
        belay_sha256_update(&r->digest, r->line, r->len);
        belay_sha256_update(&r->digest, "\n", 1);
    }
    return got;
}

static void err_at_line(size_t lineno) {
    char msg[600];
    snprintf(msg, sizeof msg, "%s (line %zu)", belay_err_msg(), lineno);
    belay_err_set(belay_err_code(), belay_err_errno(), "%s", msg);
}

void belay_manifest_close(struct belay_manifest_reader *r) {
    if (r == NULL) return;
    if (r->f != NULL) fclose(r->f);
    free(r->line);
    for (size_t i = 0; i < r->n_roots; i++) free((char *)(uintptr_t)r->roots[i].path);
    free(r->roots);
    free(r->racy);
    free(r->racy_at);
    free(r->racy_len);
    free(r);
}

/* The header line, the digest restarted with it. 0, or -1 with the error set. */
static int read_header(struct belay_manifest_reader *r, struct belay_manifest_header *h) {
    belay_sha256_init(&r->digest);
    const int got = next_line(r);
    if (got == -1) return -1;
    if (got == 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: file is empty");
        return -1;
    }
    struct obj o;
    if (lex_object(r->line, r->len, &o) == -1 || decode_header(&o, h, r->excluded) == -1) {
        err_at_line(r->lineno);
        return -1;
    }
    return 0;
}

static bool is_root_line(const struct obj *o) {
    return lex_get(o, ROOT_FIELDS[RT_PATH].name) != NULL || lex_get(o, ROOT_FIELDS[RT_PATH].alt) != NULL;
}
/* The trailer has a key `racy` too (the count): a racy line is not the trailer. */
static bool is_trailer(const struct obj *o) { return lex_get(o, TRAILER_FIELDS[TR_ENTRIES].name) != NULL; }
static bool is_racy_line(const struct obj *o) {
    return !is_trailer(o) && (lex_get(o, RACY_FIELD.name) != NULL || lex_get(o, RACY_FIELD.alt) != NULL);
}

/* memcmp order of two byte strings. */
static int cmp_bytes(const char *a, size_t al, const char *b, size_t bl) {
    const int c = memcmp(a, b, al < bl ? al : bl);
    return c != 0 ? c : (al > bl) - (al < bl);
}

/*
 *  The root lines (manifest-v5-addendum V5-A1): exactly header.n_roots of
 *  them directly after the header, sorted bytewise by path, each once. Kept
 *  on the first read; on a re-read (rewind) checked against what was kept.
 *  0, or -1 with the error set.
 */
static int read_roots(struct belay_manifest_reader *r, const struct belay_manifest_header *h, bool again) {
    static _Thread_local char path[4096];
    for (size_t i = 0; i < h->n_roots; i++) {
        const int got = next_line(r);
        struct obj o;
        if (got == -1) return -1;
        if (got == 0 || lex_root_line(r->line, r->len, &o) == -1 || !is_root_line(&o)) {
            /* not a root line: the count is wrong, whatever the line is */
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: the header says %zu roots, read %zu", h->n_roots, i);
            return -1;
        }
        struct belay_root root;
        size_t len;
        if (decode_root_line(&o, path, sizeof path, &len, &root) == -1) { err_at_line(r->lineno); return -1; }
        if (again) {
            if (i >= r->n_roots || strlen(r->roots[i].path) != len || memcmp(r->roots[i].path, path, len) != 0 ||
                r->roots[i].cls != root.cls || r->roots[i].found != root.found) {
                belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: the roots changed while they were read");
                return -1;
            }
            continue;
        }
        if (i > 0 && cmp_bytes(r->roots[i - 1].path, strlen(r->roots[i - 1].path), path, len) >= 0) {
            lex_corrupt("roots out of order");
            err_at_line(r->lineno);
            return -1;
        }
        if (r->n_roots == r->cap_roots) {
            const size_t nc = r->cap_roots ? 2 * r->cap_roots : 64;
            struct belay_root *g = realloc(r->roots, nc * sizeof *g);
            if (g == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory"); return -1; }
            r->roots = g;
            r->cap_roots = nc;
        }
        char *copy = malloc(len + 1);
        if (copy == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory"); return -1; }
        memcpy(copy, path, len + 1);
        root.path = copy;
        r->roots[r->n_roots++] = root;
    }
    r->entries_at = ftello(r->f);
    return 0;
}

static int open_file(const char *path, bool header_only, struct belay_manifest_reader **out);

int belay_manifest_open(const char *path, struct belay_manifest_reader **out) { return open_file(path, false, out); }

int belay_manifest_open_header(const char *path, struct belay_manifest_reader **out) {
    return open_file(path, true, out);
}

static int open_file(const char *path, bool header_only, struct belay_manifest_reader **out) {
    if (path == NULL || out == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_open: null argument");
        return -1;
    }
    *out = NULL;

    struct belay_manifest_reader *r = calloc(1, sizeof *r);
    if (r == NULL || (r->line = malloc(LINE_MAX_BYTES + 1)) == NULL) {
        free(r);
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        return -1;
    }
    /* O_NONBLOCK: a FIFO in a manifest's place never blocks the open; it is
     * refused as not a regular file (review 2026-10-31, Phase 5, 2). */
    const int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    struct stat st;
    if (fd == -1 || fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || (r->f = fdopen(fd, "rb")) == NULL) {
        if (fd != -1 && (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)))
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: %s is not a regular file", path);
        else
            belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot open %s", path);
        if (fd != -1 && r->f == NULL) close(fd);
        belay_manifest_close(r);
        return -1;
    }

    if (read_header(r, &r->header) == -1 || (!header_only && read_roots(r, &r->header, false) == -1)) {
        belay_manifest_close(r);
        return -1;
    }
    r->header.roots = header_only ? NULL : r->roots;
    if (header_only) {              /* a header, not a manifest to read on */
        r->header_only = true;
        r->state = -1;
        belay_err_clear();
    }
    *out = r;
    return 0;
}

int belay_manifest_rewind(struct belay_manifest_reader *r) {
    if (r == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_rewind: null argument");
        return -1;
    }
    if (fseek(r->f, 0, SEEK_SET) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot rewind");
        r->state = -1;
        return -1;
    }
    clearerr(r->f);
    r->lineno = 0;
    r->state = 0;
    r->have_trailer = false;
    memset(&r->trailer, 0, sizeof r->trailer);
    memset(&r->st, 0, sizeof r->st);
    r->n_racy = r->racy_used = 0;
    struct belay_manifest_header again;
    if (r->header_only) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_rewind: opened for its header alone");
        r->state = -1;
        return -1;
    }
    if (read_header(r, &again) == -1 || read_roots(r, &again, true) == -1) {
        r->state = -1;
        return -1;
    }
    again.roots = r->roots;
    if (memcmp(&again, &r->header, sizeof again) != 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: the header changed while it was read");
        r->state = -1;
        return -1;
    }
    return 0;
}

int belay_manifest_digest(const struct belay_manifest_reader *r, char hex[65]) {
    if (r == NULL || hex == NULL || r->state != 1) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_digest: not read to its end");
        return -1;
    }
    memcpy(hex, r->digest_hex, 65);
    return 0;
}

static int fail(struct belay_manifest_reader *r) {
    err_at_line(r->lineno);
    r->state = -1;
    return -1;
}

/*
 *  V5-A2: a racy line names an entry. The racy paths and the entries are both
 *  sorted, and the entries are behind us: they are read once more from the
 *  same open file, their paths alone, and merged against the racy paths; then
 *  the file is put back where it was. Only a manifest with racy lines pays
 *  for it. Called with the trailer line read, before it is decoded; reads it
 *  again. 0, or -1 with the error set.
 */
static int racy_name_entries(struct belay_manifest_reader *r) {
    static _Thread_local char path[4096];
    const off_t after = ftello(r->f);
    const size_t trailer_len = r->len, lineno = r->lineno;
    if (after == -1 || fseeko(r->f, r->entries_at, SEEK_SET) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot seek");
        return -1;
    }
    size_t i = 0;
    int rc = 0;
    while (i < r->n_racy) {
        size_t n;
        if (lex_line(r->f, r->line, &r->len, &n) != 1) break;
        struct obj o;
        if (lex_object(r->line, r->len, &o) == -1) { belay_err_clear(); break; }
        if (is_racy_line(&o) || is_trailer(&o)) break;
        const struct pair *pj = lex_get(&o, ENTRY_FIELDS[F_PATH].name), *pb = lex_get(&o, ENTRY_FIELDS[F_PATH].alt);
        size_t len = 0;
        /* the line passed the reader a moment ago: decoded as it was then */
        if (pj != NULL) {
            if (lex_decode_string(pj->val, pj->vlen, path, sizeof path - 1, &len) == -1) { belay_err_clear(); break; }
        } else if (pb != NULL && pb->vlen < 8192) {
            char b64[8192];
            memcpy(b64, pb->val, pb->vlen);
            b64[pb->vlen] = '\0';
            if (belay_base64_decode(path, sizeof path - 1, &len, b64) == -1) { belay_err_clear(); break; }
        } else {
            break;
        }
        const int c = cmp_bytes(path, len, r->racy + r->racy_at[i], r->racy_len[i]);
        if (c == 0) i++;
        else if (c > 0) break;                  /* past it: no entry has this path */
    }
    if (i < r->n_racy) {
        lex_corrupt("a racy line names no entry");
        rc = -1;
    }
    /* back to the trailer line, read again without counting it twice */
    size_t n;
    if (fseeko(r->f, after - (off_t)trailer_len - 1, SEEK_SET) != 0 || lex_line(r->f, r->line, &r->len, &n) != 1 ||
        r->len != trailer_len) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot seek");
        return -1;
    }
    r->lineno = lineno;
    return rc;
}

/* One racy line, kept: sorted strictly, BELAY_RACY_MAX at most. */
static int keep_racy(struct belay_manifest_reader *r, const struct obj *o) {
    static _Thread_local char path[4096];
    size_t len;
    if (decode_racy_line(o, path, sizeof path, &len) == -1) return -1;
    if (r->n_racy > 0 && cmp_bytes(r->racy + r->racy_at[r->n_racy - 1], r->racy_len[r->n_racy - 1], path, len) >= 0)
        return lex_corrupt("racy paths out of order");
    if (r->n_racy == BELAY_RACY_MAX) return lex_corrupt("too many racy paths");
    if (r->n_racy == r->cap_racy) {
        const size_t nc = r->cap_racy ? 2 * r->cap_racy : 64;
        size_t *a = realloc(r->racy_at, nc * sizeof *a);
        if (a != NULL) r->racy_at = a;
        size_t *l = a != NULL ? realloc(r->racy_len, nc * sizeof *l) : NULL;
        if (l == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory"); return -1; }
        r->racy_len = l;
        r->cap_racy = nc;
    }
    if (r->racy_used + len + 1 > r->racy_cap) {
        const size_t nc = 2 * r->racy_cap + len + 1;
        char *g = realloc(r->racy, nc);
        if (g == NULL) { belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory"); return -1; }
        r->racy = g;
        r->racy_cap = nc;
    }
    memcpy(r->racy + r->racy_used, path, len);
    r->racy[r->racy_used + len] = '\0';
    r->racy_at[r->n_racy] = r->racy_used;
    r->racy_len[r->n_racy++] = len;
    r->racy_used += len + 1;
    r->st.n_racy = r->n_racy;
    return 0;
}

size_t belay_manifest_racy(const struct belay_manifest_reader *r, size_t i, const char **path) {
    if (r == NULL || i >= r->n_racy) return 0;
    *path = r->racy + r->racy_at[i];
    return r->racy_len[i];
}

static int parse_trailer(struct belay_manifest_reader *r, const struct obj *o) {
    uint64_t v[TR_COUNT];
    if (decode_trailer(o, &r->header, v, &r->trailer) == -1) return -1;
    if (stream_end(&r->st, &r->header, v, &r->trailer) == -1) return -1;
    r->trailer.entries    = (size_t)v[TR_ENTRIES];
    r->trailer.vanished   = (size_t)v[TR_VANISHED];
    r->trailer.unreadable = (size_t)v[TR_UNREADABLE];
    r->trailer.unstable   = (size_t)v[TR_UNSTABLE];
    r->trailer.mounts     = (size_t)v[TR_MOUNTS];
    r->trailer.raced      = (size_t)v[TR_RACED];
    r->trailer.sealing    = r->st.n_sealing;      /* counted, not read: no trailer key holds it */
    return 0;
}

int belay_manifest_next(struct belay_manifest_reader *r, struct belay_entry *e) {
    if (r == NULL || e == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_next: null argument");
        return -1;
    }
    if (r->state != 0) return r->state == 1 ? 0 : -1;

    const int got = next_line(r);
    if (got == -1) { r->state = -1; return -1; }
    if (got == 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "manifest: no end marker after %zu entries (truncated?)", r->st.n_entries);
        r->state = -1;
        return -1;
    }

    struct obj o;
    if (r->len == 0) { lex_corrupt("blank line"); return fail(r); }
    if (lex_object(r->line, r->len, &o) == -1) {
        /* a root line here is said to be one, whatever its `found` */
        char why[512];
        snprintf(why, sizeof why, "%s", belay_err_msg());
        if (r->header.version >= 5 && lex_root_line(r->line, r->len, &o) == 0 && is_root_line(&o))
            lex_corrupt("a root line past the header's count, or after an entry");
        else
            belay_err_set(BELAY_ERR_CORRUPT, 0, "%s", why);
        return fail(r);
    }

    /* Version 5's other lines (V5-A1, V5-A2). In an earlier version their
     * keys are unknown ones, refused as any entry's would be. */
    if (r->header.version >= 5 && is_root_line(&o)) {
        lex_corrupt("a root line past the header's count, or after an entry");
        return fail(r);
    }
    if (r->header.version >= 5 && is_racy_line(&o)) {
        if (keep_racy(r, &o) == -1) return fail(r);
        return belay_manifest_next(r, e);       /* the next line: no entry was read */
    }

    if (lex_get(&o, TRAILER_FIELDS[TR_ENTRIES].name) != NULL) {
        if (r->n_racy > 0) {
            if (racy_name_entries(r) == -1) return fail(r);
            if (lex_object(r->line, r->len, &o) == -1) return fail(r);
        }
        if (parse_trailer(r, &o) == -1) return fail(r);
        const int more = next_line(r);
        if (more != 0) {
            if (more == 1) lex_corrupt("data after the end marker");
            r->state = -1;
            return -1;
        }
        uint8_t d[BELAY_SHA256_DIGEST_LEN];
        belay_sha256_final(&r->digest, d);
        belay_hex_encode(r->digest_hex, d, sizeof d);
        r->have_trailer = true;
        r->state = 1;
        return 0;
    }

    if (r->n_racy > 0) {
        lex_corrupt("an entry after a racy line");
        return fail(r);
    }
    if (decode_entry(&o, r->header.version, e) == -1) return fail(r);
    if (entry_check_header(&r->header, e) == -1) return fail(r);
    /* v2: nothing at or below an excluded path is recorded (V2-2); a
     * manifest that records one is not what a writer writes. */
    for (size_t i = 0; i < r->header.n_excluded; i++) {
        const struct belay_excluded *x = &r->header.excluded[i];
        if (e->path_len >= x->path_len && memcmp(e->path, x->path, x->path_len) == 0 &&
            (e->path_len == x->path_len || e->path[x->path_len] == '/')) {
            lex_corrupt("an entry at or below an excluded path");
            return fail(r);
        }
    }

    if (stream_entry(&r->st, &r->header, e) == -1) return fail(r);
    return 1;
}

int belay_manifest_read(const char *path, belay_entry_fn fn, void *ctx) {
    if (path == NULL || fn == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_read: null argument");
        return -1;
    }
    struct belay_manifest_reader *r;
    if (belay_manifest_open(path, &r) == -1) return -1;

    struct belay_entry *e = malloc(sizeof *e);
    if (e == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        belay_manifest_close(r);
        return -1;
    }
    /* `got` is the iterator's status; `rc` is what this returns. Kept apart
     * so a callback stopping the walk with 1 is passed through. */
    int rc = 0, got;
    while ((got = belay_manifest_next(r, e)) == 1) {
        const int c = fn(e, ctx);
        if (c != 0) { rc = c; break; }
    }
    if (got == -1) rc = -1;
    free(e);
    belay_manifest_close(r);
    return rc;
}

