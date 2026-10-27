/*
 *  Golden driver: writes manifests of one scope under several option sets,
 *  using only the public API, so the same source builds against any revision.
 *
 *  Usage: driver <scope> <outdir>
 *  Writes <outdir>/{default,limits,spill}.ndjson and the store <outdir>/store.
 */
#include "belay/manifest.h"
#include "belay/error.h"

#include <stdio.h>
#include <string.h>

static int run(const char *scope, const char *out, const char *name,
               struct belay_manifest_opts o) {
    char m[4096];
    snprintf(m, sizeof m, "%s/%s.ndjson", out, name);
    struct belay_manifest_stats st;
    if (belay_manifest_write(m, scope, &o, &st) != 0) {
        printf("%s: write failed: %s\n", name, belay_err_msg());
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: driver <scope> <outdir>\n"); return 2; }
    char store[4096];
    snprintf(store, sizeof store, "%s/store", argv[2]);
    struct belay_manifest_opts def = {
        .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
        .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT,
    };
    struct belay_manifest_opts limits = {
        .hash_max_bytes = 4096, .store_max_bytes = 1024, .store_dir = store,
    };
    struct belay_manifest_opts spill = def;
    spill.run_bytes = 1;                         /* clamped to the minimum */
    return run(argv[1], argv[2], "default", def) | run(argv[1], argv[2], "limits", limits) |
           run(argv[1], argv[2], "spill", spill);
}
