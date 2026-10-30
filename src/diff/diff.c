/*
 *  belay_diff (belay/diff.h): orchestration only. Opens both manifests,
 *  refuses incomparable ones, and runs the pipeline one path at a time --
 *    pair.c      the merge: each path once, (before, after);
 *    ancestry.c  for the side lacking a path, its nearest recorded ancestor;
 *    classify.c  the outcome, the only place one is decided;
 *    interpreters (belay/interp.h)  findings, never an outcome;
 *    emit.c      the diff.v1 line, and every count.
 *  Memory is two current entries, two ancestry stacks and one output line,
 *  whatever the manifests' size.
 */
#define _GNU_SOURCE
#include "belay/diff.h"

#include "ancestry.h"
#include "classify.h"
#include "emit.h"
#include "pair.h"

#include "belay/error.h"
#include "belay/interp.h"
#include "belay/manifest.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The scope root's kind, which ancestry needs before the root's own line:
 * "." sorts after names such as "!x". Reads this manifest up to ".", which
 * holds only the few entries sorting before it. */
static int root_kind(const char *path, enum anc *out) {
    struct belay_manifest_reader *r;
    if (belay_manifest_open(path, &r) == -1) return -1;
    struct belay_entry *e = malloc(sizeof *e);
    int rc = -1, got;
    if (e == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "diff: out of memory");
        belay_manifest_close(r);
        return -1;
    }
    while ((got = belay_manifest_next(r, e)) == 1) {
        if (e->path_len == 1 && e->path[0] == '.') {
            *out = ancestry_kind(e);
            rc = 0;
            break;
        }
        if ((unsigned char)e->path[0] >= '.') break;        /* sorts after ".": no root */
    }
    if (got != -1 && rc == -1)
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: no entry for the scope root \".\"");
    free(e);
    belay_manifest_close(r);
    return rc;
}

struct run {
    struct belay_manifest_reader *rb, *ra;
    struct pair_state *pair;
    struct ancestry *anc;       /* [0] before, [1] after */
    struct emitter em;
    FILE *out;
    char tmp[PATH_MAX + 16];
    char abs[2 * PATH_MAX];     /* scope + "/" + path, for interpreter dispatch */
    struct belay_findings findings;
};

/* The interpreter that claims this path explains the change, if it can. */
static int explain(struct run *x, const struct belay_entry *b, const struct belay_entry *a,
                   const char *scope) {
    const struct belay_entry *e = a != NULL ? a : b;
    const size_t sl = strlen(scope), sep = sl > 1 ? 1 : 0;
    x->findings.n = 0;
    if (sl + sep + e->path_len >= sizeof x->abs) return 0;
    memcpy(x->abs, scope, sl);
    if (sep) x->abs[sl] = '/';
    memcpy(x->abs + sl + sep, e->path, e->path_len);
    struct belay_claim claim;
    belay_interp_classify(x->abs, sl + sep + e->path_len, &claim);
    const struct belay_interp_input in = { e->path, e->path_len, b, a };
    if (belay_interp_explain(claim.interp, &in, &x->findings) == BELAY_INTERP_ERROR) return -1;
    return 0;
}

static int run_pipeline(struct run *x) {
    const struct belay_manifest_header *hb = belay_manifest_header(x->rb);
    const struct belay_manifest_header *ha = belay_manifest_header(x->ra);
    if (strcmp(hb->scope, ha->scope) != 0) {
        belay_err_set(BELAY_ERR_INVALID, 0,
                      "diff: the manifests record different scopes (%s, %s); refusing", hb->scope,
                      ha->scope);
        return -1;
    }
    if (emit_header(&x->em, hb, ha) == -1) return -1;
    const struct belay_entry *b, *a;
    int got;
    while ((got = pair_next(x->pair, &b, &a)) == 1) {
        struct verdict v;
        if (b != NULL && a != NULL) {
            if (classify_both(b, a, &v) == -1) return -1;
        } else {
            const struct belay_entry *e = b != NULL ? b : a;
            const enum anc absent = ancestry_of(&x->anc[b != NULL ? 1 : 0], e->path, e->path_len);
            if (classify_one(e, a != NULL, absent, &v) == -1) return -1;
        }
        if (b != NULL) ancestry_feed(&x->anc[0], b);
        if (a != NULL) ancestry_feed(&x->anc[1], a);
        if (v.outcome != D_UNCHANGED && explain(x, b, a, hb->scope) == -1) return -1;
        if (emit_path(&x->em, b, a, &v, v.outcome != D_UNCHANGED ? &x->findings : NULL) == -1)
            return -1;
    }
    if (got == -1) return -1;
    return emit_trailer(&x->em);
}

int belay_diff(const char *before, const char *after, const char *out_path,
               struct belay_diff_stats *stats) {
    if (before == NULL || after == NULL || out_path == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "diff: null argument");
        return -1;
    }
    enum anc root_b, root_a;
    if (root_kind(before, &root_b) == -1 || root_kind(after, &root_a) == -1) return -1;

    struct run *x = calloc(1, sizeof *x);
    int rc = -1;
    bool tmp_live = false;
    if (x == NULL || (x->anc = malloc(2 * sizeof *x->anc)) == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "diff: out of memory");
        free(x);
        return -1;
    }
    ancestry_init(&x->anc[0], root_b);
    ancestry_init(&x->anc[1], root_a);
    if (belay_manifest_open(before, &x->rb) == -1 || belay_manifest_open(after, &x->ra) == -1)
        goto done;
    if ((x->pair = pair_new(x->rb, x->ra)) == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "diff: out of memory");
        goto done;
    }
    if ((size_t)snprintf(x->tmp, sizeof x->tmp, "%s.XXXXXX", out_path) >= sizeof x->tmp) {
        belay_err_set(BELAY_ERR_RANGE, 0, "diff: output path too long");
        goto done;
    }
    const int fd = mkstemp(x->tmp);
    if (fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "diff: cannot create %s", x->tmp);
        goto done;
    }
    tmp_live = true;
    if ((x->out = fdopen(fd, "wb")) == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "diff: fdopen");
        close(fd);
        goto done;
    }
    if (emit_open(&x->em, x->out) == -1 || run_pipeline(x) == -1) goto done;
    if (fflush(x->out) != 0 || fsync(fileno(x->out)) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "diff: write failed");
        goto done;
    }
    const int closed = fclose(x->out);
    x->out = NULL;
    if (closed != 0 || rename(x->tmp, out_path) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "diff: cannot write %s", out_path);
        goto done;
    }
    tmp_live = false;
    if (stats != NULL) {
        const size_t *c = x->em.count;
        *stats = (struct belay_diff_stats){
            .records = x->em.records, .unchanged = c[D_UNCHANGED], .added = c[D_ADDED],
            .removed = c[D_REMOVED], .modified = c[D_MODIFIED], .type_changed = c[D_TYPE_CHANGED],
            .metadata_only = c[D_METADATA_ONLY], .unknown = c[D_UNKNOWN],
        };
    }
    rc = 0;
done:
    if (x->out != NULL) fclose(x->out);
    if (tmp_live) unlink(x->tmp);
    emit_close(&x->em);
    pair_free(x->pair);
    belay_manifest_close(x->rb);
    belay_manifest_close(x->ra);
    free(x->anc);
    free(x);
    return rc;
}
