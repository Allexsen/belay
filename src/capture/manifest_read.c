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
    if (lex_object(r->line, r->len, &o) == -1 || decode_header(&o, h) == -1) {
        err_at_line(r->lineno);
        return -1;
    }
    return 0;
}

int belay_manifest_open(const char *path, struct belay_manifest_reader **out) {
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
    r->f = fopen(path, "rb");
    if (r->f == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot open %s", path);
        belay_manifest_close(r);
        return -1;
    }

    if (read_header(r, &r->header) == -1) {
        belay_manifest_close(r);
        return -1;
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
    struct belay_manifest_header again;
    if (read_header(r, &again) == -1) {
        r->state = -1;
        return -1;
    }
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

static int parse_trailer(struct belay_manifest_reader *r, const struct obj *o) {
    uint64_t v[TR_COUNT];
    if (decode_trailer(o, v) == -1) return -1;
    if (stream_end(&r->st, v) == -1) return -1;
    r->trailer.entries    = (size_t)v[TR_ENTRIES];
    r->trailer.vanished   = (size_t)v[TR_VANISHED];
    r->trailer.unreadable = (size_t)v[TR_UNREADABLE];
    r->trailer.unstable   = (size_t)v[TR_UNSTABLE];
    r->trailer.mounts     = (size_t)v[TR_MOUNTS];
    r->trailer.raced      = (size_t)v[TR_RACED];
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
    if (lex_object(r->line, r->len, &o) == -1) return fail(r);

    if (lex_get(&o, TRAILER_FIELDS[TR_ENTRIES].name) != NULL) {
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

    if (decode_entry(&o, e) == -1) return fail(r);
    if (entry_check_header(&r->header, e) == -1) return fail(r);

    if (stream_entry(&r->st, e) == -1) return fail(r);
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
