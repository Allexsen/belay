#define _GNU_SOURCE
/*
 *  M2's commands (decision 145): `belay baseline export`, at reset; `belay
 *  verify`, after the episode. Judgement kept apart from description: the
 *  bundle and policy.v1 are formats of their own, diff.v1 and the manifest
 *  unchanged (test/expect/baseline-bundle.md, policy-v1.md).
 */
#include "cli.h"
#include "cli_internal.h"
#include "receipt.h"
#include "state.h"

#include "belay/belay.h"
#include "belay/error.h"
#include "belay/manifest.h"
#include "policy/bundle.h"
#include "policy/jw.h"
#include "policy/pkgdb.h"
#include "policy/protect.h"

#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* A spec refused is a usage error (PS-R2: exit 2); one that cannot be read
 * is a failure. */
static int load_spec(const char *path, struct protect_spec *spec, FILE *err) {
    if (protect_load(path, spec) == 0) return 0;
    if (belay_err_code() == BELAY_ERR_INVALID) {
        cli_err_line(err);
        belay_err_clear();
        return EXIT_USAGE;
    }
    return cli_failed(err);
}

/* Whether `path`'s directory is the scope or below it (B-R4). -1 when it
 * cannot be resolved. */
static int inside_scope(const char *path, const char *scope) {
    char tmp[PATH_MAX], real[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", path);
    if (realpath(dirname(tmp), real) == NULL) {
        belay_err_set(BELAY_ERR_INVALID, errno, "%s: its directory cannot be resolved", path);
        return -1;
    }
    const size_t sl = strlen(scope);
    if (strcmp(scope, "/") == 0) return 1;
    return strncmp(real, scope, sl) == 0 && (real[sl] == '\0' || real[sl] == '/');
}

/* PS-C2: no exclusion -- a configured exclude, belay's state directory in
 * the scope -- covers a protected pattern. 0, or an exit code. */
static int exclusions_cover(const struct state *st, const struct protect_spec *spec, FILE *err) {
    static struct excludes ex;
    if (state_excludes_read(st, &ex) == -1) return cli_failed(err);
    const char *rel = state_rel(st);
    for (size_t i = 0; i <= ex.n; i++) {
        const char *x = i < ex.n ? ex.path[i] : rel;
        if (x == NULL) continue;
        for (size_t k = 0; k < spec->n_rules; k++) {
            if (!protect_covers(spec->rules[k].path, spec->rules[k].path_len, x, strlen(x))) continue;
            fputs("belay: refused: ", err);
            receipt_fputs(err, x);
            fputs(i < ex.n ? " is excluded" : " is belay's state directory, not walked", err);
            fputs(", and protects nothing from being seen: it covers the protected ", err);
            receipt_fputs(err, spec->rules[k].path);
            fputs(" (protect-spec PS-C2)\n", err);
            return EXIT_REFUSED;
        }
    }
    return 0;
}

static void export_out(FILE *out, bool json, const char *path, const char *sha, const struct pkg_list *pk) {
    size_t bad = 0;
    for (size_t i = 0; i < pk->n; i++) bad += pk->v[i].at_reset != AT_MATCH;
    if (json) {
        struct jw w = { 0 };
        jw_raw(&w, "{", 1);
        jw_bytes(&w, "bundle", path, strlen(path));
        jw_fmt(&w, ",\"sha256\":\"%s\",\"baseline_integrity\":[", sha);
        size_t k = 0;
        for (size_t i = 0; i < pk->n; i++) {
            const struct pkg_line *x = &pk->v[i];
            if (x->at_reset == AT_MATCH) continue;
            jw_fmt(&w, "%s{\"db\":\"%s\",\"package\":", k++ ? "," : "", pkg_db_name(x->db));
            jw_str(&w, x->package, strlen(x->package));
            jw_raw(&w, ",\"version\":", 11);
            jw_str(&w, x->version, strlen(x->version));
            jw_raw(&w, ",", 1);
            jw_bytes(&w, "path", x->path, x->path_len);
            jw_fmt(&w, ",\"at_reset\":\"%s\"}", pkg_at_reset_name(x->at_reset));
        }
        jw_raw(&w, "]}\n", 3);
        if (!w.oom) fwrite(w.b, 1, w.n, out);
        else fputs("{}\n", out);        /* cannot happen short of memory: the write fails below */
        jw_free(&w);
        return;
    }
    fputs("bundle ", out);
    receipt_fputs(out, path);
    fprintf(out, "\nsha256 %s\n", sha);
    fprintf(out, "packages: %zu files listed by their databases", pk->n);
    if (pk->outside_scope) fprintf(out, ", %llu outside the scope (never checked)", (unsigned long long)pk->outside_scope);
    fprintf(out, "\nbaseline integrity: %zu file%s not as %s database says%s\n", bad, bad == 1 ? "" : "s",
            bad == 1 ? "its" : "their", bad ? " (already so at reset: never an episode's)" : "");
    for (size_t i = 0; i < pk->n; i++) {
        const struct pkg_line *x = &pk->v[i];
        if (x->at_reset == AT_MATCH) continue;
        fprintf(out, "  %s %s %s: ", pkg_at_reset_name(x->at_reset), pkg_db_name(x->db), x->package);
        receipt_fputs(out, x->path);
        fputc('\n', out);
    }
}

int cmd_baseline(int argc, char **argv, FILE *out, FILE *err) {
    if (argc < 3 || strcmp(argv[2], "export") != 0) return cli_usage(err, "baseline needs a subcommand: export");
    const char *scope = NULL, *outp = NULL, *protect = NULL;
    bool json = false;
    for (int i = 3; i < argc; i++) {
        const char *a = argv[i];
        const char **val = NULL;
        if (!strcmp(a, "--json")) {
            json = true;
            continue;
        }
        if (!strcmp(a, "--scope")) val = &scope;
        else if (!strcmp(a, "--out")) val = &outp;
        else if (!strcmp(a, "--protect")) val = &protect;
        else {
            char why[256];
            snprintf(why, sizeof why, "unknown option %.200s", a);
            return cli_usage(err, why);
        }
        if (*val != NULL) {
            char why[64];
            snprintf(why, sizeof why, "%s given twice", a);
            return cli_usage(err, why);
        }
        if (i + 1 >= argc) {
            char why[64];
            snprintf(why, sizeof why, "%s needs a value", a);
            return cli_usage(err, why);
        }
        *val = argv[++i];
    }
    if (scope == NULL) return cli_usage(err, "--scope DIR is required");
    if (outp == NULL) return cli_usage(err, "--out FILE is required");

    struct protect_spec spec = { 0 };
    int rc = protect != NULL ? load_spec(protect, &spec, err) : 0;
    if (rc) return rc;
    struct state st;
    if ((rc = cli_open_scope(scope, true, &st, err)) != 0) {
        protect_free(&spec);
        return rc;
    }
    struct pkg_list pk = { 0 };
    const int in = inside_scope(outp, st.scope.path);
    if (in != 0) {
        if (in == 1) belay_err_set(BELAY_ERR_INVALID, 0, "--out %s is inside the scope: the bundle must leave it", outp);
        rc = cli_failed(err);
        goto done;
    }
    if (protect != NULL && (rc = exclusions_cover(&st, &spec, err)) != 0) goto done;

    const struct capture_req req = { "check", false, false, 0, protect != NULL ? PROTECT_HASH_MAX_BYTES : 0 };
    struct checkpoint c;
    char manifest[PATH_MAX + 160], sha[65];
    if (state_capture(&st, &req, &c) == -1) { rc = cli_failed(err); goto done; }
    state_manifest(&st, c.id, manifest, sizeof manifest);
    if (pkgdb_list(manifest, st.store, &pk) == -1 || pkgdb_check(manifest, st.scope.path, &pk) == -1) {
        rc = cli_failed(err);
        goto done;
    }
    struct bundle_meta m = { .created_ns = c.created_ns, .has_protect = protect != NULL,
                             .hash_max_bytes = req.hash_max_bytes ? req.hash_max_bytes : BELAY_HASH_MAX_BYTES_DEFAULT };
    snprintf(m.scope, sizeof m.scope, "%s", st.scope.path);
    snprintf(m.belay_version, sizeof m.belay_version, "%s", BELAY_VERSION_STRING);
    if (protect != NULL) memcpy(m.protect_sha256, spec.sha256, 65);
    if (bundle_write(outp, manifest, st.store, &pk, &m, sha) == -1) { rc = cli_failed(err); goto done; }
    export_out(out, json, outp, sha, &pk);
done:
    pkgdb_free(&pk);
    protect_free(&spec);
    state_close(&st);
    return rc;
}
