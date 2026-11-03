/*
 *  The baseline bundle (test/expect/baseline-bundle.md): what `belay
 *  baseline export` writes at reset and `belay verify` judges against --
 *  the baseline manifest, its stored copies, and what each package
 *  database said of its files at reset. One file: members, each a header
 *  line in the manifest's canonical encoding followed by exactly `size`
 *  bytes (B-1, B-2).
 *
 *  It is read only through its digest (B-R2): the file is copied into a
 *  directory of the reader's own, hashed as it is copied, and parsed only
 *  once that copy's bytes are the ones given -- nothing a policy could have
 *  written is ever parsed.
 */
#ifndef BELAY_POLICY_BUNDLE_H
#define BELAY_POLICY_BUNDLE_H

#include <stdbool.h>
#include <stdint.h>

#include "policy/pkgdb.h"

#define BUNDLE_LINE_MAX 65536u          /* a header line's bytes, its newline aside (B-1) */

struct bundle_meta {
    int64_t created_ns;
    char scope[4096];
    uint64_t hash_max_bytes;
    bool has_protect;
    char protect_sha256[65];
    char belay_version[64];
};

/* Writes the bundle to `out_path` (through a temporary beside it, renamed
 * into place): the manifest at `manifest`, every copy it names from
 * `store_dir`, the package lines (their at_reset filled), and its digest
 * into `sha256` (B-R1). 0, or -1 with belay_err and nothing at out_path. */
int bundle_write(const char *out_path, const char *manifest, const char *store_dir,
                 const struct pkg_list *packages, const struct bundle_meta *m, char sha256[65]);

struct bundle {
    struct bundle_meta meta;
    char manifest_sha256[65];
    struct pkg_list packages;           /* with the outside_scope count */
};

/* Reads the bundle at `path`, whose bytes must hash to `want`: the copy
 * kept as <workdir>/bundle, the manifest written to `manifest_out`, the
 * copies committed to the store at `store_dir`. 0; -1 with belay_err:
 * INVALID when `want` is not 64 lowercase hex or the bytes hash otherwise
 * (nothing of it parsed); CORRUPT when it breaks a row of the pin (B-R3);
 * IO, NOMEM. */
int bundle_read(const char *path, const char *want, const char *workdir, const char *manifest_out,
                const char *store_dir, struct bundle *out);

void bundle_free(struct bundle *b);

#endif
