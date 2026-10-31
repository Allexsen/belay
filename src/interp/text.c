/*
 *  The text interpreter (finding-kinds.md, text_*): for a path no other
 *  interpreter claims, stored on every side it exists on, its lines --
 *  counted when added or removed, compared when modified. Stateless.
 */
#include "builtins.h"
#include "linediff.h"
#include "stored.h"

#include "schema/finding_schema.h"

#include <stdlib.h>
#include <string.h>

#define TEXT_MAX   (16u * 1024u * 1024u)    /* bytes of one side read */
#define TEXT_LINES 1048576u                 /* lines of one side: line_delta keeps 24 bytes
                                               a line (review 2026-10-31, 12) */

static bool is(const struct belay_interp_input *in, const char *outcome) {
    return strcmp(in->outcome, outcome) == 0;
}

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    (void)state;
    /* Only a change of content is described: metadata_only has none, and an
     * unknown outcome is not a proven change for lines to describe. */
    if (!is(in, "added") && !is(in, "removed") && !is(in, "modified")) return BELAY_INTERP_DECLINE;
    unsigned char *buf[2] = { NULL, NULL };
    size_t len[2] = { 0, 0 };
    bool ok = true, error = false;
    for (int s = SIDE_BEFORE; s <= SIDE_AFTER; s++) {
        if (side_entry(in, (enum side)s) == NULL) continue;
        enum stored_why w = stored_read(in, (enum side)s, TEXT_MAX, &buf[s], &len[s]);
        if (w == SW_OK && line_count((const char *)buf[s], len[s]) > TEXT_LINES) w = SW_TOO_LARGE;
        if (w == SW_OK) continue;
        ok = false;
        if (w == SW_ERROR) error = true;
        else if (stored_unavailable(out, w, (enum side)s) == -1) error = true;
    }
    enum belay_interp_result r = error ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    if (ok) {
        const char *a = (const char *)buf[0], *b = (const char *)buf[1];
        if (in->before == NULL || in->after == NULL) {
            const struct belay_fv v[] = { { .i = in->before ? line_count(a, len[0]) : line_count(b, len[1]) } };
            if (belay_finding(out, in->before ? FK_TEXT_REMOVED : FK_TEXT_ADDED, v, 1) == -1) r = BELAY_INTERP_ERROR;
        } else {
            struct line_delta d;
            if (line_delta(a, len[0], b, len[1], &d) == -1) {
                r = BELAY_INTERP_ERROR;
            } else if (d.counted) {
                const struct belay_fv v[] = { { .i = d.added }, { .i = d.deleted }, { .i = d.first_changed } };
                if (belay_finding(out, FK_TEXT_CHANGED, v, 3) == -1) r = BELAY_INTERP_ERROR;
            } else {
                const struct belay_fv v[] = { { .i = d.lines_a }, { .i = d.lines_b }, { .i = d.first_changed } };
                if (belay_finding(out, FK_TEXT_REWRITTEN, v, 3) == -1) r = BELAY_INTERP_ERROR;
            }
        }
    }
    free(buf[0]);
    free(buf[1]);
    return r;
}

const struct belay_interp INTERP_TEXT = { BELAY_INTERP_TEXT, NULL, explain, NULL };
