#include "stored.h"

#include "belay/error.h"
#include "belay/manifest.h"
#include "schema/finding_schema.h"

#include <errno.h>
#include <string.h>

const struct belay_entry *side_entry(const struct belay_interp_input *in, enum side s) {
    return s == SIDE_BEFORE ? in->before : in->after;
}

enum stored_why stored_read(const struct belay_interp_input *in, enum side s, size_t max,
                            unsigned char **buf, size_t *len) {
    const struct belay_entry *e = side_entry(in, s);
    *buf = NULL;
    *len = 0;
    if (e == NULL || !e->has_stored) return SW_MISSING;
    if (in->content == NULL) return SW_NO_STORE;
    if (belay_content_get(in->content, e->stored_hex, max, buf, len) == 0) return SW_OK;
    const int code = belay_err_code(), err = belay_err_errno();
    belay_err_clear();
    if (code == BELAY_ERR_RANGE) return SW_TOO_LARGE;
    if (code == BELAY_ERR_CORRUPT) return err == ENOENT ? SW_MISSING : SW_CORRUPT;
    return SW_ERROR;
}

const char *stored_why_name(enum stored_why w) {
    static const char *const N[SW_COUNT] = { [SW_OK] = "ok", [SW_NO_STORE] = "no_store",
        [SW_MISSING] = "missing", [SW_TOO_LARGE] = "too_large", [SW_CORRUPT] = "corrupt",
        [SW_ERROR] = "error" };
    return (unsigned)w < SW_COUNT ? N[w] : "error";
}

const char *side_name(enum side s) { return s == SIDE_BEFORE ? "before" : "after"; }

int stored_unavailable(struct belay_findings *out, enum stored_why w, enum side s) {
    const char *r = stored_why_name(w), *sd = side_name(s);
    const struct belay_fv v[] = { { .s = r, .len = strlen(r) }, { .s = sd, .len = strlen(sd) } };
    return belay_finding(out, FK_CONTENT_UNAVAILABLE, v, 2);
}
