#define _GNU_SOURCE
#include "previous.h"

#include "fsops.h"
#include "ident.h"

#include "belay/error.h"
#include <fcntl.h>
#include <unistd.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Records in a dense array; an open-addressing table of 32-bit indices
 * (0 empty, else index + 1), at most half full: ~85 bytes a file. */
struct prev_index {
    struct prev_rec *rec;
    size_t n, cap;
    uint32_t *slot;
    size_t nslot;
    size_t bytes;
};

static uint64_t mix(uint64_t dev, uint64_t ino) {
    uint64_t h = dev * 0x9E3779B97F4A7C15ULL ^ ino;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return h;
}

static size_t find_slot(const struct prev_index *p, uint64_t dev, uint64_t ino) {
    size_t j = mix(dev, ino) & (p->nslot - 1);
    while (p->slot[j] != 0) {
        const struct prev_rec *r = &p->rec[p->slot[j] - 1];
        if (r->dev == dev && r->ino == ino) return j;
        j = (j + 1) & (p->nslot - 1);
    }
    return j;
}

/* 0; 1 over PREV_BYTES_MAX; -1 out of memory. */
static int put(struct prev_index *p, const struct prev_rec *r) {
    if (p->n == p->cap) {
        const size_t c = p->cap ? p->cap * 2 : 1024;
        if (p->n >= UINT32_MAX / 2 || p->bytes + (c - p->cap) * sizeof *p->rec > PREV_BYTES_MAX) return 1;
        struct prev_rec *q = realloc(p->rec, c * sizeof *q);
        if (q == NULL) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "mark: out of memory");
            return -1;
        }
        p->bytes += (c - p->cap) * sizeof *p->rec;
        p->rec = q;
        p->cap = c;
    }
    if ((p->n + 1) * 2 > p->nslot) {
        const size_t ns = p->nslot ? p->nslot * 2 : 2048;
        if (p->bytes + (ns - p->nslot) * sizeof *p->slot > PREV_BYTES_MAX) return 1;
        uint32_t *s = calloc(ns, sizeof *s);
        if (s == NULL) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "mark: out of memory");
            return -1;
        }
        p->bytes += (ns - p->nslot) * sizeof *p->slot;
        free(p->slot);
        p->slot = s;
        p->nslot = ns;
        for (size_t i = 0; i < p->n; i++) p->slot[find_slot(p, p->rec[i].dev, p->rec[i].ino)] = (uint32_t)(i + 1);
    }
    const size_t j = find_slot(p, r->dev, r->ino);
    if (p->slot[j] != 0) {                                  /* two entries, one inode: trust neither */
        p->rec[p->slot[j] - 1].size = UINT64_MAX;
        return 0;
    }
    p->rec[p->n] = *r;
    p->slot[j] = (uint32_t)(++p->n);
    return 0;
}

const struct prev_rec *prev_find(const struct prev_index *p, uint64_t dev, uint64_t ino) {
    if (p == NULL || p->nslot == 0) return NULL;
    const size_t j = find_slot(p, dev, ino);
    return p->slot[j] ? &p->rec[p->slot[j] - 1] : NULL;
}

static int hexv(char c) { return c <= '9' ? c - '0' : c - 'a' + 10; }

void prev_hex(const struct prev_rec *r, char out[65]) {
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2 * i] = H[r->sha256[i] >> 4]; out[2 * i + 1] = H[r->sha256[i] & 15]; }
    out[64] = '\0';
}

/* Times as the manifest records them (ident.c: saturated, portable). */
bool prev_trusted(const struct prev_rec *r, const struct stat *st, int64_t reference_ns) {
    if (r == NULL) return false;
    const struct ident s = ident_of_stat(st);
    return r->dev == s.dev && r->ino == s.ino && r->mode == s.mode && r->size == s.size &&
           r->mtime_ns == s.mtime_ns && r->ctime_ns == s.ctime_ns && r->ctime_ns < reference_ns;
}

int prev_load(const struct fsops *ops, const char *path, const char *scope, uint64_t root_dev,
              const struct belay_manifest_opts *opts, struct prev_index **out,
              struct prev_info *info, const char **why) {
    (void)ops;
    (void)root_dev;
    *out = NULL;
    *why = NULL;
    memset(info, 0, sizeof *info);
    info->newest_validated_ns = INT64_MIN;
    struct belay_manifest_reader *rd = NULL;
    if (belay_manifest_open(path, &rd) == -1) {
        belay_err_clear();
        *why = "the previous checkpoint cannot be read";
        return 1;
    }
    const struct belay_manifest_header *h = belay_manifest_header(rd);
    if (strcmp(h->scope, scope) != 0) { *why = "the previous checkpoint is of another scope"; goto refuse; }
    if (h->hash_max_bytes != opts->hash_max_bytes || h->store_max_bytes != opts->store_max_bytes) {
        *why = "the previous checkpoint used other limits";
        goto refuse;
    }
    info->hash_max_bytes = h->hash_max_bytes;
    info->store_max_bytes = h->store_max_bytes;
    struct prev_index *p = calloc(1, sizeof *p);
    if (p == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "mark: out of memory");
        belay_manifest_close(rd);
        return -1;
    }
    struct belay_entry *e = malloc(sizeof *e);
    if (e == NULL) {
        free(p);
        belay_err_set(BELAY_ERR_NOMEM, 0, "mark: out of memory");
        belay_manifest_close(rd);
        return -1;
    }
    int got, rc = 0;
    while ((got = belay_manifest_next(rd, e)) == 1) {
        if (!e->raced && !e->unstable && !e->unreadable && e->ctime_ns > info->newest_validated_ns)
            info->newest_validated_ns = e->ctime_ns;
        if (e->type != BELAY_T_REG || !e->has_hash || e->raced || e->unstable) continue;
        struct prev_rec r = { e->dev, e->ino, e->size, e->mtime_ns, e->ctime_ns, e->mode,
                              e->has_stored, { 0 } };
        for (int k = 0; k < 32; k++)          /* the reader checked: 64 lowercase hex digits */
            r.sha256[k] = (uint8_t)(hexv(e->sha256_hex[2 * k]) << 4 | hexv(e->sha256_hex[2 * k + 1]));
        if ((rc = put(p, &r)) != 0) break;
        info->files++;
    }
    free(e);
    if (got == -1) {
        belay_err_clear();
        rc = 1;
        *why = "the previous checkpoint cannot be read";
    }
    belay_manifest_close(rd);
    if (rc != 0) {
        prev_free(p);
        if (rc == 1 && *why == NULL) *why = "the previous checkpoint is too large to index";
        return rc;
    }
    /* R: the previous walk's start on the scope's clock, when known (opts);
     * else its newest validated ctime (decision Q2's fallback). */
    info->reference_ns = opts->previous_start_ns > 0 ? opts->previous_start_ns : info->newest_validated_ns;
    *out = p;
    return 0;
refuse:
    belay_manifest_close(rd);
    return 1;
}

void prev_free(struct prev_index *p) {
    if (p == NULL) return;
    free(p->slot);
    free(p->rec);
    free(p);
}
