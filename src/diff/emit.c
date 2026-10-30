#include "emit.h"

#include "belay/error.h"
#include "belay/json.h"
#include "util/check.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* The longest record: a 4095-byte path escaped at six bytes a byte, every
 * field name, and BELAY_FINDINGS_MAX findings escaped likewise. */
#define EMIT_LINE_CAP (64u * 1024u)

struct buf { char *p; size_t w; };

static int ap(struct buf *b, const char *fmt, ...) {
    va_list a;
    va_start(a, fmt);
    const int n = vsnprintf(b->p + b->w, EMIT_LINE_CAP - b->w, fmt, a);
    va_end(a);
    if (n < 0 || (size_t)n >= EMIT_LINE_CAP - b->w) {
        belay_err_set(BELAY_ERR_RANGE, 0, "diff: record exceeds %u bytes", EMIT_LINE_CAP);
        return -1;
    }
    b->w += (size_t)n;
    return 0;
}

/* A JSON string body: the bytes escaped. */
static int ap_escaped(struct buf *b, const char *s, size_t len) {
    if (belay_json_escape(b->p + b->w, EMIT_LINE_CAP - b->w, s, len) == -1) return -1;
    b->w += strlen(b->p + b->w);
    return 0;
}

/* "key":"…" for valid UTF-8, "key_b64":"…" otherwise -- the manifest's rule. */
static int ap_bytes(struct buf *b, const struct line_field_def *d, const char *s, size_t len) {
    const bool utf8 = belay_utf8_valid(s, len);
    if (ap(b, "\"%s\":\"", utf8 ? d->name : d->alt) == -1) return -1;
    if (utf8) {
        if (ap_escaped(b, s, len) == -1) return -1;
    } else {
        if (belay_base64_encode(b->p + b->w, EMIT_LINE_CAP - b->w, s, len) == -1) return -1;
        b->w += strlen(b->p + b->w);
    }
    return ap(b, "\"");
}

static int put_line(struct emitter *em, struct buf *b) {
    if (ap(b, "\n") == -1) return -1;
    if (fwrite(b->p, 1, b->w, em->f) != b->w) {
        belay_err_set(BELAY_ERR_IO, errno, "diff: write failed");
        return -1;
    }
    return 0;
}

int emit_open(struct emitter *em, FILE *f) {
    memset(em, 0, sizeof *em);
    em->f = f;
    em->line = malloc(EMIT_LINE_CAP);
    if (em->line == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "diff: out of memory");
        return -1;
    }
    return 0;
}

void emit_close(struct emitter *em) {
    free(em->line);
    em->line = NULL;
}

int emit_header(struct emitter *em, const struct belay_manifest_header *hb,
                const struct belay_manifest_header *ha, bool scope_remounted) {
    const struct line_field_def *H = DIFF_HEADER_FIELDS;
    struct buf b = { em->line, 0 };
    const size_t sl = strlen(hb->scope);
    const bool utf8 = belay_utf8_valid(hb->scope, sl);
    if (ap(&b, "{\"%s\":%d,\"%s\":[\"", H[DH_VERSION].name, DIFF_VERSION,
           utf8 ? H[DH_SCOPES].name : H[DH_SCOPES].alt) == -1)
        return -1;
    if (utf8) {
        if (ap_escaped(&b, hb->scope, sl) == -1) return -1;
    } else {
        if (belay_base64_encode(b.p + b.w, EMIT_LINE_CAP - b.w, hb->scope, sl) == -1) return -1;
        b.w += strlen(b.p + b.w);
    }
    if (ap(&b, "\"],\"%s\":%lld,\"%s\":%lld,\"%s\":%llu,\"%s\":%llu,\"%s\":%s,\"%s\":%s}",
           H[DH_BEFORE_CREATED].name, (long long)hb->created_ns,
           H[DH_AFTER_CREATED].name, (long long)ha->created_ns,
           H[DH_BEFORE_HASH_MAX].name, (unsigned long long)hb->hash_max_bytes,
           H[DH_AFTER_HASH_MAX].name, (unsigned long long)ha->hash_max_bytes,
           H[DH_SCOPE_REMOUNTED].name, scope_remounted ? "true" : "false",
           H[DH_IDENTITY_COMPARED].name, scope_remounted ? "false" : "true") == -1)
        return -1;
    return put_line(em, &b);
}

int emit_path(struct emitter *em, const struct belay_entry *before,
              const struct belay_entry *after, const struct verdict *v,
              const struct belay_findings *findings) {
    BELAY_CHECK(v->outcome >= D_FIRST && v->outcome < D_OUTCOME_COUNT, -1);
    BELAY_CHECK(!v->dir_timestamps || v->outcome == D_UNCHANGED, -1);
    em->count[v->outcome]++;
    em->dir_timestamps += v->dir_timestamps;
    if (v->outcome == D_UNCHANGED) return 0;
    const struct line_field_def *R = DIFF_RECORD_FIELDS;
    const struct belay_entry *e = after != NULL ? after : before;
    struct buf b = { em->line, 0 };
    if (ap(&b, "{") == -1 || ap_bytes(&b, &R[DF_PATH], e->path, e->path_len) == -1) return -1;
    if (ap(&b, ",\"%s\":\"%s\",\"%s\":\"%s\"", R[DF_OUTCOME].name, DIFF_OUTCOMES[v->outcome].name,
           R[DF_TYPE].name, ENTRY_TYPES[e->type].name) == -1)
        return -1;
    /* Whenever both types are known and differ: a raced type change, unknown,
     * keeps the type it had too (decided 2026-10-30). */
    if (before != NULL && after != NULL && before->type != after->type &&
        ap(&b, ",\"%s\":\"%s\"", R[DF_TYPE_BEFORE].name, ENTRY_TYPES[before->type].name) == -1)
        return -1;
    if (v->changed) {
        if (ap(&b, ",\"%s\":[", R[DF_CHANGED].name) == -1) return -1;
        const char *sep = "";
        for (int f = 0; f < F_COUNT; f++) {
            if (!(v->changed & FBIT(f))) continue;
            if (ap(&b, "%s\"%s\"", sep, ENTRY_FIELDS[f].name) == -1) return -1;
            sep = ",";
        }
        if (ap(&b, "]") == -1) return -1;
    }
    if (v->outcome == D_UNKNOWN && v->reasons) {
        if (ap(&b, ",\"%s\":[", R[DF_UNKNOWN].name) == -1) return -1;
        const char *sep = "";
        for (int r = DR_FIRST; r < DR_COUNT; r++) {
            if (!(v->reasons & DRBIT(r))) continue;
            if (ap(&b, "%s\"%s\"", sep, DIFF_REASONS[r].name) == -1) return -1;
            sep = ",";
        }
        if (ap(&b, "]") == -1) return -1;
    }
    if (findings != NULL && findings->n > 0) {
        if (ap(&b, ",\"%s\":[", R[DF_FINDINGS].name) == -1) return -1;
        for (size_t i = 0; i < findings->n; i++) {
            if (ap(&b, "%s\"", i ? "," : "") == -1 ||
                ap_escaped(&b, findings->item[i], strlen(findings->item[i])) == -1 ||
                ap(&b, "\"") == -1)
                return -1;
        }
        if (ap(&b, "]") == -1) return -1;
    }
    if (ap(&b, "}") == -1) return -1;
    em->records++;
    return put_line(em, &b);
}

int emit_trailer(struct emitter *em, const struct diff_inputs *in) {
    struct buf b = { em->line, 0 };
    if (ap(&b, "{\"%s\":%zu", DIFF_TRAILER_END.name, em->records) == -1) return -1;
    for (int o = D_FIRST; o < D_OUTCOME_COUNT; o++)
        if (ap(&b, ",\"%s\":%zu", DIFF_OUTCOMES[o].name, em->count[o]) == -1) return -1;
    if (ap(&b, ",\"%s\":%zu", DIFF_TRAILER_FIELDS[DT_DIR_TIMESTAMPS_ONLY].name,
           em->dir_timestamps) == -1)
        return -1;
    const struct { enum diff_trailer_field f; size_t v; } counts[] = {
        { DT_BEFORE_VANISHED, in->before->vanished }, { DT_BEFORE_UNSTABLE, in->before->unstable },
        { DT_BEFORE_RACED, in->before->raced },       { DT_AFTER_VANISHED, in->after->vanished },
        { DT_AFTER_UNSTABLE, in->after->unstable },   { DT_AFTER_RACED, in->after->raced },
    };
    em->provisional = false;
    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        if (ap(&b, ",\"%s\":%zu", DIFF_TRAILER_FIELDS[counts[i].f].name, counts[i].v) == -1) return -1;
        em->provisional |= counts[i].v != 0;
    }
    if (ap(&b, ",\"%s\":%s,\"%s\":\"%s\",\"%s\":\"%s\"}", DIFF_TRAILER_FIELDS[DT_PROVISIONAL].name,
           em->provisional ? "true" : "false", DIFF_TRAILER_FIELDS[DT_BEFORE_SHA256].name,
           in->before_sha256, DIFF_TRAILER_FIELDS[DT_AFTER_SHA256].name, in->after_sha256) == -1)
        return -1;
    return put_line(em, &b);
}
