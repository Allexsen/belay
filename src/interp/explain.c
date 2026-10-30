/*
 *  Interpreter explanations (belay/interp.h). One built-in per interpreter;
 *  one with no explain declines. Phase 3 defines the interface and every
 *  built-in declines: the binary fallback has nothing to add to the core's
 *  outcome, and Phase 4 adds pip, dpkg, git and text.
 */
#include "belay/interp.h"

#include <string.h>

static const struct belay_interp BUILTIN[BELAY_INTERP_COUNT] = {
    [BELAY_INTERP_BINARY] = { BELAY_INTERP_BINARY, NULL, NULL, NULL },
    [BELAY_INTERP_TEXT]   = { BELAY_INTERP_TEXT, NULL, NULL, NULL },
    [BELAY_INTERP_PIP]    = { BELAY_INTERP_PIP, NULL, NULL, NULL },
    [BELAY_INTERP_DPKG]   = { BELAY_INTERP_DPKG, NULL, NULL, NULL },
    [BELAY_INTERP_GIT]    = { BELAY_INTERP_GIT, NULL, NULL, NULL },
};

const struct belay_interp *belay_interp_builtin(enum belay_interp_id id) {
    return (unsigned)id < BELAY_INTERP_COUNT ? &BUILTIN[id] : &BUILTIN[BELAY_INTERP_BINARY];
}

int belay_findings_add(struct belay_findings *f, const char *text) {
    if (f->n >= BELAY_FINDINGS_MAX) return -1;       /* an interpreter may have set n past it */
    size_t n = strlen(text);
    if (n > BELAY_FINDING_BYTES - 1) {
        /* Back to the start of the character the cut falls in: at most three
         * bytes, the most a UTF-8 sequence continues. Text that is not UTF-8
         * stays so, for the emitter to replace. */
        n = BELAY_FINDING_BYTES - 1;
        size_t back = 0;
        while (back < 3 && ((unsigned char)text[n - back] & 0xC0) == 0x80) back++;
        if (((unsigned char)text[n - back] & 0xC0) != 0x80) n -= back;
    }
    memcpy(f->item[f->n], text, n);
    f->item[f->n][n] = '\0';
    f->n++;
    return 0;
}
