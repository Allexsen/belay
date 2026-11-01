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

int cap_write_header(const struct fsops *ops, FILE *f, const char *scope_real,
                     const struct belay_excluded *xs, size_t nx, int64_t walk_start_ns,
                     const struct belay_manifest_opts *opts, char *buf) {
    struct timespec now;
    ops->clock(ops->ctx, &now);
    const long long created = (long long)ident_ns((int64_t)now.tv_sec, now.tv_nsec);

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
                H[H_HASH_MAX].name, (unsigned long long)opts->hash_max_bytes,
                H[H_STORE_MAX].name, (unsigned long long)opts->store_max_bytes) < 0) {
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
    if (w < 0 || fprintf(f, "],\"%s\":%lld}\n", HEADER2_FIELDS[H2_WALK_START].name,
                         (long long)(walk_start_ns > 0 ? walk_start_ns : 0)) < 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: header write failed");
        return -1;
    }
    return 0;
}
