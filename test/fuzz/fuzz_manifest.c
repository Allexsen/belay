/*
 *  Fuzz target for the manifest reader (BELAY_DESIGN.md §0.4c).
 *
 *  The reader is one of the two places untrusted input meets parsing (the
 *  other is the path utilities). A manifest can be hand-edited, truncated by a
 *  full disk, or deliberately crafted, so the contract fuzzed is: for ANY
 *  input bytes, the reader must either parse cleanly or fail -- never crash,
 *  read out of bounds, or hand the callback an entry that violates its own
 *  invariants.
 *
 *  The invariant checks in `check_entry` matter as much as the crash check: a
 *  reader that silently produced a path containing a NUL would pass a
 *  memory-safety-only oracle while breaking the §5.1.1 rule.
 */
#include "belay/manifest.h"
#include "belay/error.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int check_entry(const struct belay_entry *e, void *ctx) {
    (void)ctx;

    /* §5.1.1: a path reaching the callback must never contain a NUL. */
    if (memchr(e->path, '\0', e->path_len) != NULL) abort();

    /* A zero-length path is meaningless and must have been rejected. */
    if (e->path_len == 0) abort();

    /* path_len must be within the buffer. */
    if (e->path_len >= sizeof e->path) abort();

    /* A hash and the unverified flag are mutually exclusive by construction. */
    if (e->has_hash && e->unverified) abort();

    /* A recorded hash must be exactly 64 lowercase hex characters. */
    if (e->has_hash) {
        if (strlen(e->sha256_hex) != 64) abort();
        for (int i = 0; i < 64; i++) {
            const char c = e->sha256_hex[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) abort();
        }
    }

    /* Only symlinks carry targets, and a symlink must carry one. */
    if ((e->type == BELAY_T_LNK) != e->has_link_target) abort();

    if (e->has_link_target) {
        if (memchr(e->link_target, '\0', e->link_target_len) != NULL) abort();
        if (e->link_target_len >= sizeof e->link_target) abort();
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 1u << 20) return 0;

    /* The reader takes a path, so the input has to reach it as a file. A
     * fixed name per process keeps this cheap; libFuzzer is single-threaded
     * per worker. */
    static char path[256];
    if (path[0] == '\0')
        snprintf(path, sizeof path, "/tmp/belay_fuzz_manifest_%d", (int)getpid());

    FILE *f = fopen(path, "wb");
    if (f == NULL) return 0;
    if (size > 0) {
        if (fwrite(data, 1, size, f) != size) { fclose(f); return 0; }
    }
    fclose(f);

    /* Return value is unconstrained -- success or failure are both fine. What
     * must not happen is a crash or a violated invariant. */
    belay_manifest_read(path, check_entry, NULL);
    belay_err_clear();

    return 0;
}
