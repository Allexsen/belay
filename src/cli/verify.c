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
#include "policy/policy.h"
#include "policy/protect.h"
#include "belay/diff.h"
#include "belay/interp.h"
#include "belay/store.h"

#include <errno.h>
#include <ftw.h>
#include <sys/stat.h>
#include <unistd.h>
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
        JW_LIT(&w, "{");
        jw_bytes(&w, "bundle", path, strlen(path));
        jw_fmt(&w, ",\"sha256\":\"%s\",\"baseline_integrity\":[", sha);
        size_t k = 0;
        for (size_t i = 0; i < pk->n; i++) {
            const struct pkg_line *x = &pk->v[i];
            if (x->at_reset == AT_MATCH) continue;
            jw_fmt(&w, "%s{\"db\":\"%s\",\"package\":", k++ ? "," : "", pkg_db_name(x->db));
            jw_str(&w, x->package, strlen(x->package));
            JW_LIT(&w, ",\"version\":");
            jw_str(&w, x->version, strlen(x->version));
            JW_LIT(&w, ",");
            jw_bytes(&w, "path", x->path, x->path_len);
            jw_fmt(&w, ",\"at_reset\":\"%s\"}", pkg_at_reset_name(x->at_reset));
        }
        JW_LIT(&w, "]}\n");
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
    const char *scope = NULL, *outp = NULL, *protect = NULL, *docker = NULL;
    bool json = false;
    for (int i = 3; i < argc; i++) {
        const char *a = argv[i];
        const char **val = NULL;
        if (!strcmp(a, "--json")) {
            json = true;
            continue;
        }
        if (!strcmp(a, "--scope")) val = &scope;
        else if (!strcmp(a, "--docker")) val = &docker;
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
    if ((rc = cli_open_scope(scope, docker, true, &st, err)) != 0) {
        protect_free(&spec);
        return rc;
    }
    struct pkg_list pk = { 0 };
    const int in = docker != NULL ? 0 : inside_scope(outp, st.scope.path);   /* a container's scope is not the host's */
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

/* ---- verify ---- */

static int rm_one(const char *p, const struct stat *sb, int flag, struct FTW *f) {
    (void)sb, (void)f;
    return flag == FTW_DP ? rmdir(p) : unlink(p);
}

/* The bundle's manifest's header: its exclusions, kept for verify's own
 * capture (the same paths left out on both sides) and checked against the
 * spec (PS-C2). */
static int bundle_excludes(const char *manifest, struct excludes *ex, const struct protect_spec *spec, FILE *err) {
    struct belay_manifest_reader *r;
    if (belay_manifest_open(manifest, &r) == -1) return cli_failed(err);
    const struct belay_manifest_header *h = belay_manifest_header(r);
    int rc = 0;
    ex->n = 0;
    for (size_t i = 0; i < h->n_excluded && rc == 0; i++) {
        const struct belay_excluded *x = &h->excluded[i];
        for (size_t k = 0; spec != NULL && k < spec->n_rules; k++) {
            if (!protect_covers(spec->rules[k].path, spec->rules[k].path_len, x->path, x->path_len)) continue;
            fputs("belay: refused: a capture did not walk ", err);
            receipt_fputs(err, x->path);
            fputs(", which covers the protected ", err);
            receipt_fputs(err, spec->rules[k].path);
            fputs(" (protect-spec PS-C2)\n", err);
            rc = EXIT_REFUSED;
            break;
        }
        if (x->reason == BELAY_EXCLUDE_USER && ex->n < STATE_EXCLUDES_MAX)
            snprintf(ex->path[ex->n++], sizeof ex->path[0], "%.*s", (int)x->path_len, x->path);
    }
    belay_manifest_close(r);
    return rc;
}

/* `--to ID`: the scope's own checkpoint, its copies brought into verify's
 * store. With a spec, only one that trusted nothing (PS-C1). */
static int checkpoint_after(const struct scope *sc, long id, const struct protect_spec *spec, const char *store,
                            char *manifest, size_t cap, FILE *err) {
    const char *saved = state_root_override;
    state_root_override = NULL;
    struct state own;
    int rc = sc->docker[0] != '\0' ? (state_open(sc, false, &own, err) == -1 ? cli_failed(err) : 0)
                                    : cli_open_scope(sc->path, NULL, false, &own, err);
    state_root_override = saved;
    if (rc) return rc;
    if (state_check_manifest(&own, id) == -1) {
        belay_err_set(BELAY_ERR_INVALID, 0, "checkpoint %ld does not exist", id);
        state_close(&own);
        cli_err_line(err);
        belay_err_clear();
        return EXIT_USAGE;
    }
    state_manifest(&own, id, manifest, cap);
    struct belay_manifest_reader *r = NULL;
    struct belay_content *c = NULL;
    struct belay_store *st = NULL;
    static struct belay_entry e;
    rc = -1;
    if (belay_manifest_open(manifest, &r) == -1 || belay_content_open(own.store, &c) == -1 ||
        belay_store_open(store, &st) == -1)
        goto out;
    int n;
    while ((n = belay_manifest_next(r, &e)) == 1) {
        if (!e.has_stored) continue;
        unsigned char *buf;
        size_t len;
        if (belay_content_get(c, e.stored_hex, (size_t)1 << 30, &buf, &len) == -1) goto out;
        struct belay_store_tx tx;
        const int w = belay_store_begin(st, &tx) == -1 || belay_store_write(&tx, buf, len) == -1 ||
                      belay_store_commit(&tx, e.stored_hex) == -1 ? -1 : 0;
        free(buf);
        if (w == -1) goto out;
    }
    if (n == -1) goto out;
    if (spec != NULL && belay_manifest_trailer(r)->trusted != 0) {
        belay_err_set(BELAY_ERR_INVALID, 0, "checkpoint %ld trusted %zu files it did not read: with a protect spec, "
                      "--to takes only one that read every file (a check, or mark --full)", id,
                      belay_manifest_trailer(r)->trusted);
        goto out;
    }
    rc = belay_store_sync(st) == -1 ? -1 : 0;
out:
    belay_manifest_close(r);
    belay_content_close(c);
    belay_store_close(st);
    state_close(&own);
    return rc == -1 ? cli_failed(err) : rc;
}

int cmd_verify(int argc, char **argv, FILE *out, FILE *err) {
    const char *scope = NULL, *baseline = NULL, *sha = NULL, *protect = NULL, *to = NULL, *docker = NULL;
    bool exit_code = false;
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        const char **val = NULL;
        if (!strcmp(a, "--exit-code")) {
            exit_code = true;
            continue;
        }
        if (!strcmp(a, "--scope")) val = &scope;
        else if (!strcmp(a, "--docker")) val = &docker;
        else if (!strcmp(a, "--baseline")) val = &baseline;
        else if (!strcmp(a, "--baseline-sha256")) val = &sha;
        else if (!strcmp(a, "--protect")) val = &protect;
        else if (!strcmp(a, "--to")) val = &to;
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
    if (baseline == NULL) return cli_usage(err, "--baseline FILE is required");
    long to_id = 0;
    if (to != NULL && (to_id = state_id_parse(to)) == 0) return cli_usage(err, "--to needs a checkpoint id");
    if (sha == NULL) {                      /* B-R2: never a bundle the policy could have written */
        fputs("belay: refused: --baseline-sha256 HEX is required: a bundle is read only by its digest\n", err);
        return EXIT_REFUSED;
    }
    struct protect_spec spec = { 0 };
    int rc = protect != NULL ? load_spec(protect, &spec, err) : 0;
    if (rc) return rc;
    struct scope sc;
    if ((docker != NULL ? scope_resolve_docker(docker, scope, true, &sc, err) : scope_resolve(scope, &sc)) == -1) {
        protect_free(&spec);
        return cli_failed(err);
    }

    /* a work directory made fresh: verify's own state, never one prepared */
    const char *tmp = getenv("TMPDIR");
    char work[PATH_MAX], root[PATH_MAX + 16], before[PATH_MAX + 32], dpath[PATH_MAX + 32], after[PATH_MAX + 160];
    snprintf(work, sizeof work, "%s/belay-verify.XXXXXX", tmp != NULL && tmp[0] == '/' ? tmp : "/tmp");
    if (mkdtemp(work) == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot create a work directory in %s", tmp != NULL ? tmp : "/tmp");
        protect_free(&spec);
        return cli_failed(err);
    }
    snprintf(root, sizeof root, "%s/state", work);
    snprintf(before, sizeof before, "%s/before.ndjson", work);
    snprintf(dpath, sizeof dpath, "%s/diff.ndjson", work);
    struct state st = { .dir_fd = -1, .cp_fd = -1, .lock_fd = -1 };
    struct bundle bd = { 0 };
    bool opened = false;
    if (mkdir(root, 0700) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "%s: cannot create", root);
        rc = cli_failed(err);
        goto done;
    }
    state_root_override = root;
    if (state_open(&sc, true, &st, err) == -1) { rc = cli_failed(err); goto done; }
    opened = true;

    if (bundle_read(baseline, sha, work, before, st.store, &bd) == -1) { rc = cli_failed(err); goto done; }
    if (strcmp(bd.meta.scope, st.scope.path) != 0) {
        belay_err_set(BELAY_ERR_INVALID, 0, "the bundle is of another scope (%s)", bd.meta.scope);
        rc = cli_failed(err);
        goto done;
    }
    if (bd.meta.has_protect != (protect != NULL) || (protect != NULL && strcmp(bd.meta.protect_sha256, spec.sha256) != 0)) {
        belay_err_set(BELAY_ERR_INVALID, 0, bd.meta.has_protect
                      ? "the bundle was exported with protect spec %s: verify takes that spec, and only it (PS-R3)"
                      : "the bundle was exported without a protect spec%s: verify takes none (PS-R3)",
                      bd.meta.has_protect ? bd.meta.protect_sha256 : "");
        rc = cli_failed(err);
        goto done;
    }
    static struct excludes ex;
    if ((rc = bundle_excludes(before, &ex, protect != NULL ? &spec : NULL, err)) != 0) goto done;
    if (protect != NULL && (rc = exclusions_cover(&st, &spec, err)) != 0) goto done;   /* verify's own state dir */
    if (ex.n > 0 && state_excludes_write(&st, &ex) == -1) { rc = cli_failed(err); goto done; }

    if (to_id != 0) {
        if ((rc = checkpoint_after(&sc, to_id, protect != NULL ? &spec : NULL, st.store, after, sizeof after, err)) != 0)
            goto done;
        static struct excludes ignored;         /* its own exclusions, against the spec too (PS-C2) */
        if ((rc = bundle_excludes(after, &ignored, protect != NULL ? &spec : NULL, err)) != 0) goto done;
    } else {
        const struct capture_req req = { "check", false, false, 0, bd.meta.hash_max_bytes };
        struct checkpoint c;
        if (state_capture(&st, &req, &c) == -1) { rc = cli_failed(err); goto done; }
        state_manifest(&st, c.id, after, sizeof after);
    }
    const struct belay_diff_opts dopts = { .store_dir = st.store };
    if (belay_diff(before, after, dpath, &dopts, NULL) == -1) { rc = cli_failed(err); goto done; }
    const struct policy_in pin = { before, after, dpath, st.store, st.scope.path, to_id == 0, &bd, sha,
                                   protect != NULL ? &spec : NULL };
    struct policy_stats ps;
    if (policy_run(&pin, out, &ps) == -1) { rc = cli_failed(err); goto done; }
    rc = exit_code && ps.violations > 0 ? EXIT_CHANGES : EXIT_DONE;
done:
    state_root_override = NULL;
    if (opened) state_close(&st);
    bundle_free(&bd);
    protect_free(&spec);
    nftw(work, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    return rc;
}
