/*
 *  Interpreter explanations (belay/interp.h). One slot per interpreter; an
 *  empty slot declines. Phase 3 defines the interface and leaves every slot
 *  empty: the binary fallback has nothing to add to the core's outcome.
 */
#include "belay/interp.h"

#include <stdio.h>
#include <string.h>

typedef enum belay_interp_result (*explain_fn)(const struct belay_interp_input *in,
                                               struct belay_findings *out);

static const explain_fn EXPLAIN[BELAY_INTERP_COUNT] = { 0 };

int belay_findings_add(struct belay_findings *f, const char *text) {
    if (f->n == BELAY_FINDINGS_MAX) return -1;
    snprintf(f->item[f->n++], BELAY_FINDING_BYTES, "%s", text);
    return 0;
}

enum belay_interp_result belay_interp_explain(enum belay_interp_id id,
                                              const struct belay_interp_input *in,
                                              struct belay_findings *out) {
    out->n = 0;
    if ((unsigned)id >= BELAY_INTERP_COUNT || EXPLAIN[id] == NULL) return BELAY_INTERP_DECLINE;
    return EXPLAIN[id](in, out);
}
