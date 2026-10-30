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
 *  The invariant checks matter as much as the crash check: a reader that
 *  silently produced a path containing a NUL would pass a memory-safety-only
 *  oracle while breaking the §5.1.1 rule. The schema's rules (which fields
 *  and flags go together) are generated from src/schema/entry.c into
 *  fuzz_invariants.gen.h; what is checked by hand here is decoding: lengths,
 *  NULs, hex shape and canonical paths, which the schema does not describe.
 */
#include "belay/manifest.h"
#include "belay/error.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 *  The format's rules, written by hand from test/expect/manifest-v1.md (the
 *  frozen v1 pin) -- not generated from src/schema/entry.c and not calling its
 *  predicates, so a wrong or missing rule in the code is caught here instead
 *  of being copied (audit 2026-10, M4). Fields present are read from the
 *  decoded entry directly, not through entry_present().
 */
#define P_IFLAGS  e->has_iflags
#define P_CAPS    e->has_caps
#define P_XATTRS  (e->has_xattrs && e->xattrs_inline)
#define P_XSHA    (e->has_xattrs && !e->xattrs_inline)
#define P_XUNK    e->xattrs_unknown
#define P_SHA     e->has_hash
#define P_UNVER   e->unverified
#define P_UNSTAB  e->unstable
#define P_RDEV    e->has_rdev
#define P_TARGET  e->has_link_target
#define P_OUTSIDE e->target_outside_scope
#define P_STORED  e->has_stored
#define P_MOUNT   e->is_mount
#define P_UNREAD  e->unreadable
#define P_RACED   e->raced

static const unsigned IFMT[] = { 0100000, 0040000, 0120000, 0010000, 0140000, 0060000, 0020000 };

/* The lexical rule of header rule 2, from its statement: an absolute target
 * leaves the scope unless it is the scope or below it; a relative one leaves
 * it when its ".." climb above the scope root, starting from the link's own
 * directory. */
static bool target_leaves_scope(const char *scope, const struct belay_entry *e) {
    const char *t = e->link_target;
    const size_t tl = e->link_target_len;
    if (tl > 0 && t[0] == '/') {
        const size_t sl = strlen(scope);
        if (strcmp(scope, "/") == 0) return false;
        if (tl < sl || memcmp(t, scope, sl) != 0) return true;
        if (tl > sl && t[sl] != '/') return true;
        for (size_t i = sl; i < tl; ) {               /* a ".." below the scope may climb out */
            while (i < tl && t[i] == '/') i++;
            size_t j = i;
            while (j < tl && t[j] != '/') j++;
            if (j - i == 2 && t[i] == '.' && t[i + 1] == '.') return true;
            i = j;
        }
        return false;
    }
    long depth = 0;                                   /* components of the link's directory */
    for (size_t i = 0; i < e->path_len; i++) if (e->path[i] == '/') depth++;
    for (size_t i = 0; i < tl; ) {
        size_t j = i;
        while (j < tl && t[j] != '/') j++;
        const size_t n = j - i;
        if (n == 2 && t[i] == '.' && t[i + 1] == '.') {
            if (--depth < 0) return true;
        } else if (n > 0 && !(n == 1 && t[i] == '.')) {
            depth++;
        }
        i = j + 1;
    }
    return false;
}

static void schema_invariants(const struct belay_manifest_header *h, const struct belay_entry *e) {
    if ((unsigned)e->type > BELAY_T_CHR) abort();
    const bool reg = e->type == BELAY_T_REG, dir = e->type == BELAY_T_DIR, lnk = e->type == BELAY_T_LNK;
    const bool dev = e->type == BELAY_T_BLK || e->type == BELAY_T_CHR;
    const bool node = e->type == BELAY_T_FIFO || e->type == BELAY_T_SOCK || dev;
    /* 1 */ if ((e->mode & 0170000) != IFMT[e->type]) abort();
    /* 2 */ if (P_XATTRS && P_XSHA) abort();
    /* 3 */ if (P_XUNK && (P_XATTRS || P_XSHA || P_CAPS)) abort();
    /* 4 */ if (!reg && P_CAPS) abort();
    /* 5 */ if (reg && (int)P_SHA + (int)P_UNVER != 1) abort();
    /* 6 */ if (reg && (P_UNSTAB || P_UNREAD) && !P_UNVER) abort();
    /* 7 */ if (reg && P_UNSTAB && P_UNREAD) abort();
    /* 8 */ if (reg && P_MOUNT && (P_UNSTAB || P_UNREAD)) abort();
    /* 9 */ if (dir && (P_SHA || P_UNVER || P_STORED)) abort();
    /* 10 */ if (dir && P_RACED && !(P_UNREAD || P_MOUNT)) abort();
    /* 11 */ if (dir && (int)P_UNREAD + (int)P_UNSTAB + (int)P_MOUNT > 1) abort();
    /* 12 */ if (lnk && (P_SHA || P_UNVER || P_STORED || P_UNSTAB)) abort();
    /* 13 */ if (node && (P_SHA || P_UNVER || P_STORED || P_UNSTAB || P_UNREAD)) abort();
    /* 14 */ if (P_STORED && (!P_SHA || strcmp(e->stored_hex, e->sha256_hex) != 0)) abort();
    /* 15 */ if (P_RDEV != dev) abort();
    /* 16 */ if (P_TARGET != lnk) abort();
    /* 17 */ if (!lnk && P_OUTSIDE) abort();
    /* 18 */ if (lnk && e->link_target_len == 0 && !P_UNREAD) abort();
    /* 19 */ if (lnk && !P_UNREAD && e->size != e->link_target_len) abort();
    /* 20 */ if (P_OUTSIDE && e->link_target_len == 0) abort();
    /* 21 */ if (P_MOUNT && P_SHA) abort();
    /* 22 */ if (P_MOUNT && (P_IFLAGS || P_CAPS || P_XATTRS || P_XSHA || P_XUNK)) abort();
    /* header 1 */
    if (reg && P_SHA && e->size > h->hash_max_bytes) abort();
    if (reg && P_UNVER && !P_UNSTAB && !P_UNREAD && !P_MOUNT && e->size <= h->hash_max_bytes) abort();
    /* header 2 */
    if (lnk && P_OUTSIDE != (!P_UNREAD && target_leaves_scope(h->scope, e))) abort();
}

static void check_entry(const struct belay_manifest_header *h, const struct belay_entry *e) {
    schema_invariants(h, e);

    /* §5.1.1: a path reaching the callback must never contain a NUL. */
    if (memchr(e->path, '\0', e->path_len) != NULL) abort();

    /* A zero-length path is meaningless and must have been rejected. */
    if (e->path_len == 0) abort();

    /* path_len must be within the buffer. */
    if (e->path_len >= sizeof e->path) abort();

    /* A recorded hash must be exactly 64 lowercase hex characters. */
    if (e->has_hash) {
        if (strlen(e->sha256_hex) != 64) abort();
        for (int i = 0; i < 64; i++) {
            const char c = e->sha256_hex[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) abort();
        }
    }

    /* An inline xattr set is a decoded set, within the inline limit. */
    if (e->xattrs_inline && (!e->has_xattrs || e->xattrs_len > BELAY_XATTRS_INLINE_MAX)) abort();

    /* Canonical paths only: no empty, "." or ".." component except a lone ".". */
    if (!(e->path_len == 1 && e->path[0] == '.')) {
        if (e->path[0] == '/' || e->path[e->path_len - 1] == '/') abort();
        for (size_t i = 0; i < e->path_len; ) {
            size_t j = i;
            while (j < e->path_len && e->path[j] != '/') j++;
            const size_t n = j - i;
            if (n == 0) abort();
            if (n == 1 && e->path[i] == '.') abort();
            if (n == 2 && e->path[i] == '.' && e->path[i + 1] == '.') abort();
            i = j + 1;
        }
    }

    if (e->has_link_target) {
        if (memchr(e->link_target, '\0', e->link_target_len) != NULL) abort();
        if (e->link_target_len >= sizeof e->link_target) abort();
    }
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
    struct belay_manifest_reader *r;
    if (belay_manifest_open(path, &r) == 0) {
        static struct belay_entry e;
        while (belay_manifest_next(r, &e) == 1) check_entry(belay_manifest_header(r), &e);
        belay_manifest_close(r);
    }
    belay_err_clear();

    return 0;
}
