#include "belay/interp.h"

#include <fnmatch.h>
#include <string.h>

/*
 *  One row per claim. First match wins, so more specific rows come first
 *  (git's index, hash-only, before nothing else could catch it -- the order
 *  only matters where two patterns overlap, and none do today).
 *
 *  Each row is a decision about what a later diff will need:
 *    dpkg  status: which packages are installed, at which version.
 *          The per-package md5sums files: hashes M2's integrity check
 *          verifies against -- they must be the BASELINE copies (§6).
 *          The per-package list files: which package owns which path.
 *    pip   RECORD: installed files and their hashes; METADATA: name/version.
 *    git   HEAD, packed-refs and everything under refs: ref moves. Hooks:
 *          executable code, so the content is kept. index: changed or not.
 */
struct rule {
    const char *pattern;
    enum belay_interp_id interp;
    enum belay_keep keep;
};

static const struct rule rules[] = {
    { "*/var/lib/dpkg/status",            BELAY_INTERP_DPKG, BELAY_KEEP_STORE },
    { "*/var/lib/dpkg/info/*.md5sums",    BELAY_INTERP_DPKG, BELAY_KEEP_STORE },
    { "*/var/lib/dpkg/info/*.list",       BELAY_INTERP_DPKG, BELAY_KEEP_STORE },

    { "*.dist-info/RECORD",               BELAY_INTERP_PIP,  BELAY_KEEP_STORE },
    { "*.dist-info/METADATA",             BELAY_INTERP_PIP,  BELAY_KEEP_STORE },

    { "*/.git/index",                     BELAY_INTERP_GIT,  BELAY_KEEP_HASH  },
    { "*/.git/HEAD",                      BELAY_INTERP_GIT,  BELAY_KEEP_STORE },
    { "*/.git/packed-refs",               BELAY_INTERP_GIT,  BELAY_KEEP_STORE },
    { "*/.git/refs/*",                    BELAY_INTERP_GIT,  BELAY_KEEP_STORE },
    { "*/.git/hooks/*",                   BELAY_INTERP_GIT,  BELAY_KEEP_STORE },
};

void belay_interp_classify(const char *abs_path, size_t len, struct belay_claim *out) {
    out->interp = BELAY_INTERP_BINARY;
    out->keep = BELAY_KEEP_DEFAULT;

    /* fnmatch needs a C string. Paths are bounded by the manifest's 4096-byte
     * cap plus the scope; anything longer is simply unclaimed. */
    char buf[8192];
    if (len >= sizeof buf || memchr(abs_path, '\0', len) != NULL) return;
    memcpy(buf, abs_path, len);
    buf[len] = '\0';

    for (size_t i = 0; i < sizeof rules / sizeof rules[0]; i++) {
        if (fnmatch(rules[i].pattern, buf, 0) == 0) {
            out->interp = rules[i].interp;
            out->keep = rules[i].keep;
            return;
        }
    }
}

const char *belay_interp_name(enum belay_interp_id id) {
    switch (id) {
    case BELAY_INTERP_BINARY: return "binary";
    case BELAY_INTERP_TEXT:   return "text";
    case BELAY_INTERP_PIP:    return "pip";
    case BELAY_INTERP_DPKG:   return "dpkg";
    case BELAY_INTERP_GIT:    return "git";
    default:                  return "unknown";
    }
}
