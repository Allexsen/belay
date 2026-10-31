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

#include "interp/findings_internal.h"
#include "schema/finding_schema.h"

#include "ancestry.h"
#include "classify.h"
#include "diff_run.h"
#include "emit.h"
#include "pair.h"

#include "belay/error.h"
#include "belay/interp.h"
#include "belay/json.h"
#include "belay/manifest.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The scope root, which ancestry needs before the root's own line ("." sorts
 * after names such as "!x") and whose device every entry's device relation
 * needs. Reads the open manifest up to "." -- the few entries sorting before
 * it -- and rewinds it: one file, read twice, never a path opened twice
 * (decided F8). The pipeline checks the root it meets is this one. */
static int find_root(struct belay_manifest_reader *r, struct belay_entry *root) {
    int rc = -1, got;
    while ((got = belay_manifest_next(r, root)) == 1) {
        if (root->path_len == 1 && root->path[0] == '.') {
            rc = 0;
            break;
        }
        if ((unsigned char)root->path[0] >= '.') break;     /* sorts after ".": no root */
    }
    if (got != -1 && rc == -1)
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: no entry for the scope root \".\"");
    if (rc == 0 && belay_manifest_rewind(r) == -1) return -1;
    return rc;
}

/* The output must not be an input, however it is spelled ("./a", a link):
 * compared by device and inode, not by name (decided F9). */
static int refuse_input_as_output(const char *out_path, const char *before, const char *after) {
    struct stat o, i;
    if (stat(out_path, &o) == -1) return 0;                 /* nothing there yet */
    const char *in[2] = { before, after };
    for (int k = 0; k < 2; k++)
        if (stat(in[k], &i) == 0 && i.st_dev == o.st_dev && i.st_ino == o.st_ino) {
            belay_err_set(BELAY_ERR_INVALID, 0, "diff: the output %s is the input %s; refusing",
                          out_path, in[k]);
            return -1;
        }
    return 0;
}

/* The rename into place survives a crash only once its directory is synced.
 * Done where the directory can be opened (a write-and-search-only drop
 * directory cannot be); never a failure: the output is already complete and
 * in place, and the diff has succeeded (review F3). */
static void sync_dir_of(const char *path) {
    char dir[PATH_MAX];
    const char *slash = strrchr(path, '/');
    if (slash == NULL) snprintf(dir, sizeof dir, ".");
    else if (slash == path) snprintf(dir, sizeof dir, "/");
    else snprintf(dir, sizeof dir, "%.*s", (int)(slash - path), path);
    const int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd == -1) return;
    if (fsync(fd) != 0) { /* nothing left to undo: see above */ }
    close(fd);
}

struct run {
    struct belay_manifest_reader *rb, *ra;
    struct belay_entry root[2];     /* [0] before, [1] after: as find_root read them */
    struct diff_ctx ctx;
    struct pair_state *pair;
    struct ancestry *anc;       /* [0] before, [1] after */
    struct emitter em;
    FILE *out;
    char tmp[PATH_MAX + 16];
    char abs[2 * PATH_MAX];     /* scope + "/" + path, for interpreter dispatch */
    struct belay_findings findings;
    struct belay_events events;
    const struct belay_interp *const *interp;
    struct belay_content *content;      /* NULL: no store */
    void *state[BELAY_INTERP_COUNT];
    bool begun, ended[BELAY_INTERP_COUNT];  /* ended: each end hook is called once */
};

/* The interpreter that claims this path explains the change, if it can. What
 * it adds can only add to the record, and its failures stay in its own output
 * (R11): an error is the one finding could_not_interpret, and a finding that
 * breaks its kind's row is invalid_finding (belay_finding checks each). */
static int explain(struct run *x, const struct belay_entry *b, const struct belay_entry *a,
                   const struct verdict *v, const char *scope) {
    const struct belay_entry *e = a != NULL ? a : b;
    const size_t sl = strlen(scope), sep = sl > 1 ? 1 : 0;
    findings_reset(&x->findings, BELAY_INTERP_BINARY);    /* nothing of the last path survives */
    if (sl + sep + e->path_len >= sizeof x->abs) return 0;
    memcpy(x->abs, scope, sl);
    if (sep) x->abs[sl] = '/';
    memcpy(x->abs + sl + sep, e->path, e->path_len);
    struct belay_claim claim;
    belay_interp_classify(x->abs, sl + sep + e->path_len, &claim);
    const enum belay_interp_id id = belay_interp_dispatch(&claim, b, a);
    const struct belay_interp *it = x->interp[id];
    if (it->explain == NULL) return 0;
    if (it->end != NULL && events_claim(&x->events, id, e->path, e->path_len) == -1) return -1;
    findings_reset(&x->findings, id);
    const struct belay_interp_input in = { e->path, e->path_len, x->abs, sl + sep + e->path_len, b, a,
                                           DIFF_OUTCOMES[v->outcome].name, v->changed,
                                           x->content };
    const enum belay_interp_result r = it->explain(x->state[id], &in, &x->findings);
    if (findings_oom(&x->findings)) return -1;
    if (r == BELAY_INTERP_FINDINGS) return 0;
    findings_reset(&x->findings, id);
    if (r == BELAY_INTERP_DECLINE) return 0;
    return belay_finding(&x->findings, FK_COULD_NOT_INTERPRET, NULL, 0);
}

/* Each end hook, with the sink for its events; one that fails, or added an
 * event that broke its kind's row, has its events replaced by one
 * could_not_interpret naming the paths it was given (diff-events E6). */
static int end_all(struct run *x) {
    for (int i = 0; i < BELAY_INTERP_COUNT; i++) {
        if (x->interp[i]->end == NULL) continue;
        x->events.interp = i;
        x->ended[i] = true;
        const enum belay_interp_result r = x->interp[i]->end(x->state[i], &x->events);
        if (events_oom(&x->events, i)) return -1;
        if ((r == BELAY_INTERP_ERROR || events_broken(&x->events, i)) &&
            events_failed(&x->events, i) == -1)
            return -1;
    }
    return 0;
}

/* Manifests of different scopes are never compared: refused on their
 * headers, before any entry is read. */
static int same_scope(struct run *x) {
    const struct belay_manifest_header *hb = belay_manifest_header(x->rb);
    const struct belay_manifest_header *ha = belay_manifest_header(x->ra);
    if (strcmp(hb->scope, ha->scope) == 0) return 0;
    belay_err_set(BELAY_ERR_INVALID, 0,
                  "diff: the manifests record different scopes (%s, %s); refusing", hb->scope,
                  ha->scope);
    return -1;
}

static int run_pipeline(struct run *x) {
    const struct belay_manifest_header *hb = belay_manifest_header(x->rb);
    const struct belay_manifest_header *ha = belay_manifest_header(x->ra);
    if (emit_header(&x->em, hb, ha, x->ctx.remounted) == -1) return -1;
    const struct belay_entry *b, *a;
    int got;
    while ((got = pair_next(x->pair, &b, &a)) == 1) {
        const struct belay_entry *side[2] = { b, a };
        for (int k = 0; k < 2; k++)
            if (side[k] != NULL && side[k]->path_len == 1 && side[k]->path[0] == '.' &&
                memcmp(side[k], &x->root[k], sizeof x->root[k]) != 0) {
                belay_err_set(BELAY_ERR_CORRUPT, 0, "diff: the %s manifest changed while it was read",
                              k ? "after" : "before");
                return -1;
            }
        struct verdict v;
        if (b != NULL && a != NULL) {
            if (classify_both(&x->ctx, b, a, &v) == -1) return -1;
        } else {
            const struct belay_entry *e = b != NULL ? b : a;
            const enum anc absent = ancestry_of(&x->anc[b != NULL ? 1 : 0], e->path, e->path_len);
            if (classify_one(e, a != NULL, absent, &v) == -1) return -1;
        }
        if (b != NULL) ancestry_feed(&x->anc[0], b);
        if (a != NULL) ancestry_feed(&x->anc[1], a);
        if (v.outcome != D_UNCHANGED && explain(x, b, a, &v, hb->scope) == -1) return -1;
        if (emit_path(&x->em, b, a, &v, v.outcome != D_UNCHANGED ? &x->findings : NULL) == -1)
            return -1;
    }
    if (got == -1 || end_all(x) == -1 || emit_events(&x->em, &x->events) == -1) return -1;
    char sb[65], sa[65];
    if (belay_manifest_digest(x->rb, sb) == -1 || belay_manifest_digest(x->ra, sa) == -1) return -1;
    const struct diff_inputs in = { belay_manifest_trailer(x->rb), belay_manifest_trailer(x->ra),
                                    sb, sa };
    return emit_trailer(&x->em, &in);
}

int belay_diff(const char *before, const char *after, const char *out_path,
               const struct belay_diff_opts *opts, struct belay_diff_stats *stats) {
    const struct belay_interp *builtin[BELAY_INTERP_COUNT];
    for (int i = 0; i < BELAY_INTERP_COUNT; i++)
        builtin[i] = belay_interp_builtin((enum belay_interp_id)i);
    return diff_run(before, after, out_path, opts, stats, builtin);
}

int diff_run(const char *before, const char *after, const char *out_path,
             const struct belay_diff_opts *opts, struct belay_diff_stats *stats,
             const struct belay_interp *const interp[BELAY_INTERP_COUNT]) {
    if (before == NULL || after == NULL || out_path == NULL || interp == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "diff: null argument");
        return -1;
    }
    if (refuse_input_as_output(out_path, before, after) == -1) return -1;

    struct run *x = calloc(1, sizeof *x);
    int rc = -1;
    bool tmp_live = false;
    if (x == NULL || (x->anc = malloc(2 * sizeof *x->anc)) == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "diff: out of memory");
        free(x);
        return -1;
    }
    if (opts != NULL && opts->store_dir != NULL &&
        belay_content_open(opts->store_dir, &x->content) == -1)
        goto done;
    if (belay_manifest_open(before, &x->rb) == -1 || belay_manifest_open(after, &x->ra) == -1 ||
        same_scope(x) == -1 || find_root(x->rb, &x->root[0]) == -1 ||
        find_root(x->ra, &x->root[1]) == -1)
        goto done;
    ancestry_init(&x->anc[0], ancestry_kind(&x->root[0]));
    ancestry_init(&x->anc[1], ancestry_kind(&x->root[1]));
    const uint64_t dev_b = x->root[0].dev, dev_a = x->root[1].dev;
    x->ctx = (struct diff_ctx){ .root_dev_before = dev_b, .root_dev_after = dev_a,
                                .remounted = dev_b != dev_a };
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
    x->interp = interp;
    events_init(&x->events);
    for (int i = 0; i < BELAY_INTERP_COUNT; i++)
        x->state[i] = interp[i]->begin != NULL ? interp[i]->begin() : NULL;
    x->begun = true;
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
    sync_dir_of(out_path);
    if (stats != NULL) {
        const size_t *c = x->em.count;
        *stats = (struct belay_diff_stats){
            .records = x->em.records, .events = x->em.events, .unchanged = c[D_UNCHANGED], .added = c[D_ADDED],
            .removed = c[D_REMOVED], .modified = c[D_MODIFIED], .type_changed = c[D_TYPE_CHANGED],
            .metadata_only = c[D_METADATA_ONLY], .unknown = c[D_UNKNOWN],
            .dir_timestamps_only = x->em.dir_timestamps, .provisional = x->em.provisional,
        };
    }
    rc = 0;
done:
    for (int i = 0; x->begun && i < BELAY_INTERP_COUNT; i++)
        if (!x->ended[i] && interp[i]->end != NULL) interp[i]->end(x->state[i], NULL);
    findings_free(&x->findings);
    events_free(&x->events);
    if (x->out != NULL) fclose(x->out);
    if (tmp_live) unlink(x->tmp);
    emit_close(&x->em);
    belay_content_close(x->content);
    pair_free(x->pair);
    belay_manifest_close(x->rb);
    belay_manifest_close(x->ra);
    free(x->anc);
    free(x);
    return rc;
}
