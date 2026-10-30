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
    if (f->n == BELAY_FINDINGS_MAX) return -1;
    size_t n = strlen(text);
    if (n > BELAY_FINDING_BYTES - 1) {
        n = BELAY_FINDING_BYTES - 1;
        while (n > 0 && ((unsigned char)text[n] & 0xC0) == 0x80) n--;   /* text[n] continues a character */
    }
    memcpy(f->item[f->n], text, n);
    f->item[f->n][n] = '\0';
    f->n++;
    return 0;
}
