/* Temporaries beside the output, and the manifest header. */
#define _GNU_SOURCE
#include "capture_internal.h"

#include "belay/error.h"
#include "belay/json.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Anonymous temporaries beside the output, through the platform adapter. */

FILE *cap_tmpfile(void *ctx) {
    const struct tmpdir *t = ctx;
    return t->ops->tmpfile_in(t->ops->ctx, t->dir, t->tmpl);
}

static int by_path(const void *a, const void *b) {
    const struct belay_excluded *x = a, *y = b;
    const size_t m = x->path_len < y->path_len ? x->path_len : y->path_len;
    const int c = memcmp(x->path, y->path, m);
    return c ? c : (x->path_len > y->path_len) - (x->path_len < y->path_len);
}

/* The header line, without its newline, into `f`: the fields of
 * test/expect/manifest-v2.md, `excluded` sorted by path bytes. 0, or -1 with
 * belay_err. */
static int format_header(FILE *f, long long created, const char *scope_real,
                         const struct belay_excluded *xs, size_t nx, long long walk_start_ns,
                         unsigned long long hash_max, unsigned long long store_max,
                         const char *src_docker, const char *src_image, char *buf) {
    /* Same rule as entry paths: JSON for valid UTF-8, base64 otherwise.
     * Before, a non-UTF-8 scope was written raw and the line was not JSON. */
    const size_t sl = strlen(scope_real);
    const bool utf8 = belay_utf8_valid(scope_real, sl);
    if ((utf8 ? belay_json_escape(buf, LINE_CAP, scope_real, sl)
              : belay_base64_encode(buf, LINE_CAP, scope_real, sl)) == -1) return -1;
    const struct line_field_def *H = HEADER_FIELDS;   /* the names, from the schema */
    if (fprintf(f, "{\"%s\":%d,\"%s\":%lld,\"%s\":[\"%s\"],\"%s\":\"sha256\",\"%s\":%llu,\"%s\":%llu",
                H[H_VERSION].name, BELAY_MANIFEST_VERSION, H[H_CREATED].name, created,
                utf8 ? H[H_SCOPES].name : H[H_SCOPES].alt, buf, H[H_HASH].name,
                H[H_HASH_MAX].name, hash_max, H[H_STORE_MAX].name, store_max) < 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: header write failed");
        return -1;
    }
    /* Version 2 (test/expect/manifest-v2.md): what was not walked, sorted by
     * path bytes, then when the walk began. */
    struct belay_excluded sorted[BELAY_EXCLUDED_MAX];
    if (nx > BELAY_EXCLUDED_MAX) nx = BELAY_EXCLUDED_MAX;
    memcpy(sorted, xs, nx * sizeof *xs);
    qsort(sorted, nx, sizeof *sorted, by_path);
    const struct line_field_def *X = EXCLUDED_FIELDS;
    int w = fprintf(f, ",\"%s\":[", HEADER2_FIELDS[H2_EXCLUDED].name);
    for (size_t i = 0; i < nx && w >= 0; i++) {
        const struct belay_excluded *x = &sorted[i];
        const bool pu = belay_utf8_valid(x->path, x->path_len);
        if ((pu ? belay_json_escape(buf, LINE_CAP, x->path, x->path_len)
                : belay_base64_encode(buf, LINE_CAP, x->path, x->path_len)) == -1) return -1;
        w = fprintf(f, "%s{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":%llu,\"%s\":%llu}", i ? "," : "",
                    pu ? X[EX_PATH].name : X[EX_PATH].alt, buf, X[EX_REASON].name,
                    x->reason == BELAY_EXCLUDE_STATE_DIR ? "state_dir" : "user", X[EX_DEV].name,
                    (unsigned long long)x->dev, X[EX_INO].name, (unsigned long long)x->ino);
    }
    if (w < 0 || fprintf(f, "],\"%s\":%lld", HEADER2_FIELDS[H2_WALK_START].name, walk_start_ns) < 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: header write failed");
        return -1;
    }
    /* Version 3 (test/expect/manifest-v3.md): where the capture came from.
     * The ids are checked where they are taken (docker.c): hex and "sha256:". */
    if ((src_docker == NULL
             ? fprintf(f, ",\"%s\":null}", HEADER3_FIELDS[H3_SOURCE].name)
             : fprintf(f, ",\"%s\":{\"%s\":\"%s\",\"%s\":\"%s\"}}", HEADER3_FIELDS[H3_SOURCE].name,
                       SOURCE_FIELDS[SRC_DOCKER].name, src_docker, SOURCE_FIELDS[SRC_IMAGE].name, src_image)) < 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: header write failed");
        return -1;
    }
    return 0;
}

/* `the header` formatted whole in memory first: a line over the reader's
 * bound (A2) is never written -- the capture fails, loudly, instead of
 * leaving a manifest nothing can read (decision 112). */
int cap_write_header(const struct fsops *ops, FILE *f, const char *scope_real,
                     const struct belay_excluded *xs, size_t nx, int64_t walk_start_ns,
                     const struct belay_manifest_opts *opts, char *buf) {
    struct timespec now;
    ops->clock(ops->ctx, &now);
    const long long created = (long long)ident_ns((int64_t)now.tv_sec, now.tv_nsec);
    char *line = NULL;
    size_t len = 0;
    FILE *m = open_memstream(&line, &len);
    if (m == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, errno, "manifest: header");
        return -1;
    }
    const int r = format_header(m, created, scope_real, xs, nx, walk_start_ns > 0 ? walk_start_ns : 0,
                                (unsigned long long)opts->hash_max_bytes,
                                (unsigned long long)opts->store_max_bytes, opts->source_docker,
                                opts->source_docker != NULL ? opts->source_image : NULL, buf);
    if (fclose(m) != 0 && r == 0) {
        free(line);
        belay_err_set(BELAY_ERR_NOMEM, errno, "manifest: header");
        return -1;
    }
    if (r == -1) {
        free(line);
        return -1;
    }
    if (len > BELAY_MANIFEST_LINE_MAX) {
        size_t bytes = 0;
        for (size_t i = 0; i < nx; i++) bytes += xs[i].path_len;
        belay_err_set(BELAY_ERR_RANGE, 0, "manifest: the header line would be %zu bytes, over the %d-byte "
                      "line limit: %zu excluded paths, %zu bytes of names -- fewer or shorter excludes",
                      len, BELAY_MANIFEST_LINE_MAX, nx, bytes);
        free(line);
        return -1;
    }
    const bool ok = fwrite(line, 1, len, f) == len && fputc('\n', f) != EOF;
    free(line);
    if (!ok) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: header write failed");
        return -1;
    }
    return 0;
}

long belay_manifest_header_bound(const char *scope_real, const char *const *paths, size_t n,
                                 const char *state_rel) {
    /* Every number at its widest; what the walk will find there unknown. */
    static struct belay_excluded xs[BELAY_EXCLUDED_MAX];
    size_t nx = 0;
    for (size_t i = 0; i <= n && nx < BELAY_EXCLUDED_MAX; i++) {
        const char *p = i < n ? paths[i] : state_rel;
        if (p == NULL) continue;
        const size_t pl = strlen(p);
        if (pl >= sizeof xs[0].path) {
            belay_err_set(BELAY_ERR_RANGE, 0, "manifest: path too long");
            return -1;
        }
        memcpy(xs[nx].path, p, pl + 1);
        xs[nx].path_len = pl;
        xs[nx].reason = i < n ? BELAY_EXCLUDE_USER : BELAY_EXCLUDE_STATE_DIR;
        xs[nx].dev = xs[nx].ino = UINT64_MAX;
        nx++;
    }
    char *buf = malloc(LINE_CAP), *line = NULL;
    size_t len = 0;
    FILE *m = buf != NULL ? open_memstream(&line, &len) : NULL;
    if (m == NULL) {
        free(buf);
        belay_err_set(BELAY_ERR_NOMEM, errno, "manifest: header");
        return -1;
    }
    /* the widest source: a container's */
    static const char D[] = "0000000000000000000000000000000000000000000000000000000000000000";
    const int r = format_header(m, (long long)INT64_MIN, scope_real, xs, nx, (long long)INT64_MIN,
                                UINT64_MAX, UINT64_MAX, D, "sha256:" "0000000000000000000000000000000000000000000000000000000000000000", buf);
    const int c = fclose(m);
    free(buf);
    free(line);
    if (r == -1) return -1;
    if (c != 0) {
        belay_err_set(BELAY_ERR_NOMEM, errno, "manifest: header");
        return -1;
    }
    return (long)len;
}
