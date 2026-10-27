/* Temporaries beside the output, and the manifest header. */
#define _GNU_SOURCE
#include "capture_internal.h"

#include "belay/error.h"
#include "belay/json.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Anonymous temporaries beside the output, through the platform adapter. */

FILE *cap_tmpfile(void *ctx) {
    const struct tmpdir *t = ctx;
    return t->ops->tmpfile_in(t->ops->ctx, t->dir, t->tmpl);
}

int cap_write_header(const struct fsops *ops, FILE *f, const char *scope_real,
                        const struct belay_manifest_opts *opts, char *buf) {
    struct timespec now;
    ops->clock(ops->ctx, BELAY_CLOCK_REAL, &now);
    const long long created = (long long)ident_ns((int64_t)now.tv_sec, now.tv_nsec);

    /* Same rule as entry paths: JSON for valid UTF-8, base64 otherwise.
     * Before, a non-UTF-8 scope was written raw and the line was not JSON. */
    const size_t sl = strlen(scope_real);
    const bool utf8 = belay_utf8_valid(scope_real, sl);
    if ((utf8 ? belay_json_escape(buf, LINE_CAP, scope_real, sl)
              : belay_base64_encode(buf, LINE_CAP, scope_real, sl)) == -1) return -1;
    if (fprintf(f,
                "{\"belay_manifest\":%d,\"created_ns\":%lld,\"%s\":[\"%s\"]"
                ",\"hash\":\"sha256\",\"hash_max_bytes\":%llu"
                ",\"store_max_bytes\":%llu}\n",
                BELAY_MANIFEST_VERSION, created, utf8 ? "scopes" : "scopes_b64", buf,
                (unsigned long long)opts->hash_max_bytes,
                (unsigned long long)opts->store_max_bytes) < 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: header write failed");
        return -1;
    }
    return 0;
}
