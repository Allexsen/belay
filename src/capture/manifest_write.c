/*
 *  Manifest writer: the capture pipeline.
 *
 *    walk -> capture -> sorter -> consistency -> serializer -> publish
 *
 *  walk.c visits the scope; capture.c records each entry, reporting what it
 *  found through outcome_apply; runs.c holds every entry, packed and sorted
 *  by path, in bounded memory; consistency.c re-checks every entry once the
 *  walk is over; serialize.c writes each entry as one canonical line; the
 *  output goes to a temporary name and is renamed into place, so a crash or
 *  a full disk never leaves a partial manifest at `out_path`. Every OS call
 *  goes through the platform adapter (fsops.h).
 *
 *  BLAST RADIUS. Reads the user's real filesystem; writes only its own
 *  manifest file, anonymous temporaries beside it, and store objects.
 *  Containment is by construction (BELAY_DESIGN.md §5.1.1):
 *
 *    - realpath() runs exactly once, on the scope, then the result is opened
 *      as a dirfd and never used as a string again.
 *    - Every descent is openat(parent_fd, name, O_DIRECTORY|O_NOFOLLOW|...),
 *      so a directory replaced by a symlink mid-walk fails rather than
 *      redirecting the walk; every stat is relative to a held dirfd, with
 *      AT_SYMLINK_NOFOLLOW.
 *    - A mount root is a boundary: recorded, never read or descended.
 */
#define _GNU_SOURCE

#include "belay/manifest.h"
#include "belay/error.h"
#include "belay/path.h"
#include "belay/store.h"

#include "capture.h"
#include "capture_internal.h"
#include "serialize.h"
#include "store_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* The rename into place survives a crash only once its directory is synced.
 * Done where the directory can be opened; never a failure: the manifest is
 * already complete and in place (decided 2026-10-30, as the diff's output,
 * review F3). */
static void sync_dir_of(const struct fsops *ops, const char *path) {
    char dir[PATH_MAX];
    const char *slash = strrchr(path, '/');
    if (slash == NULL) snprintf(dir, sizeof dir, ".");
    else if (slash == path) snprintf(dir, sizeof dir, "/");
    else snprintf(dir, sizeof dir, "%.*s", (int)(slash - path), path);
    const int fd = ops->openat(ops->ctx, AT_FDCWD, dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd == -1) return;
    if (ops->fsync(ops->ctx, fd) != 0) { /* nothing left to undo: see above */ }
    close(fd);
}

int capture_write(const struct fsops *ops, const char *out_path, const char *scope,
                  const struct belay_manifest_opts *opts, struct belay_manifest_stats *stats) {
    if (out_path == NULL || scope == NULL || opts == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest_write: null argument");
        return -1;
    }
    if (strlen(out_path) > PATH_MAX - 32) {
        belay_err_set(BELAY_ERR_RANGE, 0, "manifest_write: output path too long");
        return -1;
    }

    /* Lexical validation first, so a ".." scope never reaches realpath. */
    char nscope[4096];
    if (belay_path_normalize(nscope, sizeof nscope, scope) == -1) return -1;

    char *real = realpath(nscope, NULL);
    if (real == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot resolve scope %s", nscope);
        return -1;
    }
    const int root_fd = ops->openat(ops->ctx, AT_FDCWD, real, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot open scope %s", real);
        free(real);
        return -1;
    }
    struct stat rst;
    if (ops->fstat(ops->ctx, root_fd, &rst) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: fstat scope");
        close(root_fd);
        free(real);
        return -1;
    }
    if (opts->expect_root && ((uint64_t)rst.st_dev != opts->root_dev || (uint64_t)rst.st_ino != opts->root_ino)) {
        belay_err_set(BELAY_ERR_INVALID, 0, "manifest: the scope %s changed during resolution", real);
        close(root_fd);
        free(real);
        return -1;
    }

    int rc = -1;
    struct tmpdir td = { .ops = ops };
    snprintf(td.tmpl, sizeof td.tmpl, "%s.run.XXXXXX", out_path);
    {
        const char *slash = strrchr(out_path, '/');
        if (slash == NULL)            snprintf(td.dir, sizeof td.dir, ".");
        else if (slash == out_path)   snprintf(td.dir, sizeof td.dir, "/");
        else snprintf(td.dir, sizeof td.dir, "%.*s", (int)(slash - out_path), out_path);
    }
    FILE *verdicts = NULL;
    struct belay_entry *ebuf = malloc(sizeof *ebuf);

    struct walk_ctx *wc = calloc(1, sizeof *wc);
    char *rel = malloc(PATH_CAP);
    char outtmp[PATH_MAX + 32];
    bool outtmp_live = false;   /* a temp output exists on disk and must go */
    bool probing = false;       /* ops->probe_begin ran: end it */
    FILE *out = NULL;
    snprintf(outtmp, sizeof outtmp, "%s.tmp.XXXXXX", out_path);

    if (wc == NULL || rel == NULL || ebuf == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        goto cleanup;
    }
    /* The budget is raised to hold at least one maximal record. */
    wc->runs = runs_new(opts->run_bytes == 0 ? RUN_BYTES : opts->run_bytes, PATH_CAP,
                        RECORD_MAX, cap_tmpfile, &td);
    if (wc->runs == NULL) goto cleanup;
    wc->pack = malloc(RECORD_MAX);
    wc->line = malloc(LINE_CAP);
    wc->readbuf = malloc(READ_CHUNK);
    wc->xlist = malloc(XLIST_CAP + 1);
    wc->xnames = malloc((XLIST_CAP / 2 + 1) * sizeof *wc->xnames);
    if (wc->pack == NULL || wc->line == NULL || wc->readbuf == NULL || wc->xlist == NULL ||
        wc->xnames == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
        goto cleanup;
    }
    wc->ops = ops;
    wc->opts = opts;
    wc->root_dev = (uint64_t)rst.st_dev;
    wc->scope = real;
    wc->scope_len = strlen(real);
    wc->newest_ctime_ns = INT64_MIN;

    struct prev_info pinfo = { 0 };
    const char *prev_why = NULL;
    if (opts->previous != NULL) {
        const int pr = prev_load(ops, opts->previous, real, wc->root_dev, opts, &wc->prev, &pinfo, &prev_why);
        if (pr == -1) goto cleanup;
        wc->reference_ns = pinfo.reference_ns;
    }

    /* Once per walk: can statx be used here, and is the scope on overlayfs?
     * (See stat_entry and the crossing rule in visit.) */
    {
        struct stat probe_st;
        bool mr, mk;
        wc->statx_ok = ops->stat_mount(ops->ctx, root_fd, "", &probe_st, &mr, &mk) == 0;
        wc->scope_overlay = ops->is_overlay(ops->ctx, root_fd);
    }

    if (opts->store_dir != NULL) {
        wc->abs = malloc(PATH_MAX * 2);
        if (wc->abs == NULL) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "manifest: out of memory");
            goto cleanup;
        }
        memcpy(wc->abs, real, wc->scope_len);
        if (store_open(ops, opts->store_dir, &wc->store) == -1) goto cleanup;
        /* Copies are gated by the writer probe (capture.c), which needs
         * the platform prepared for it until the capture is over. */
        ops->probe_begin(ops->ctx);
        probing = true;
    }

    /* The scope root itself is an entry, path ".". Without it a chmod or
     * chown on the root is invisible. Like every directory it is emitted
     * after its listing, so a listing that failed part way is recorded on it. */
    memset(&wc->e, 0, sizeof wc->e);
    cap_fill_from_stat(&wc->e, &rst);
    wc->extras_done = false;
    if (cap_read_extras(wc, root_fd, -1, ".", &rst) == -1) goto cleanup;
    wc->e.path[0] = '.';
    wc->e.path_len = 1;
    struct belay_entry root_e;
    memcpy(&root_e, &wc->e, sizeof root_e);
    struct listing root_seen = { 0, 0, 0 };

    /* A scope root that can be listed but not searched has contents belay
     * cannot stat: flag it, rather than fail on its first child. */
    struct stat probe;
    if (ops->fstatat(ops->ctx, root_fd, ".", &probe, AT_SYMLINK_NOFOLLOW) != 0) {
        outcome_apply(&root_e, FACET_LISTING, OUT_DENIED, &wc->tally);
    } else {
        rel[0] = '\0';
        const int wr = cap_walk(root_fd, rel, PATH_CAP, 0, 0, wc, &root_seen);
        if (wr == -1) goto cleanup;

        if (wr == W_INCOMPLETE) outcome_apply(&root_e, FACET_LISTING, OUT_CHANGED, &wc->tally);
    }
    if (cap_emit(wc, &root_e, &root_seen) == -1) goto cleanup;

    /* Every entry is recorded. Re-check them all before the output file
     * exists, so belay's own output is never seen as a change. */
    if (runs_seal(wc->runs) == -1) goto cleanup;
    verdicts = cap_tmpfile(&td);
    if (verdicts == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot create temporary file");
        goto cleanup;
    }
    if (cap_recheck(wc, root_fd, ebuf, verdicts) == -1) goto cleanup;

    /* Output goes to a temporary name and is renamed into place. */
    const int ofd = mkstemp(outtmp);
    if (ofd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot create %s", outtmp);
        goto cleanup;
    }
    outtmp_live = true;
    out = fdopen(ofd, "wb");
    if (out == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: fdopen");
        close(ofd);
        goto cleanup;
    }
    if (cap_write_header(ops, out, real, opts, wc->line) == -1) goto cleanup;

    /* The output pass: each entry with its re-check verdict applied, counted
     * as emitted, serialized once. */
    struct belay_manifest_stats tally = { 0 };
    struct belay_manifest_header hdr = { .hash_max_bytes = opts->hash_max_bytes };
    snprintf(hdr.scope, sizeof hdr.scope, "%s", real);
    if (runs_rewind(wc->runs) == -1) goto cleanup;
    const unsigned char *key, *val;
    uint32_t klen, vlen;
    int got;
    while ((got = runs_next(wc->runs, &key, &klen, &val, &vlen)) == 1) {
        struct listing unused;
        if (cap_record_unpack(val, vlen, key, klen, ebuf, &unused) == -1) goto cleanup;
        const int v = cons_verdict_get(verdicts, key, klen);
        if (v == -1) goto cleanup;
        if (v == VERDICT_LISTING) outcome_apply(ebuf, FACET_LISTING, OUT_CHANGED, &wc->tally);
        if (v == VERDICT_ENTRY)   outcome_apply(ebuf, FACET_ENTRY, OUT_CHANGED, &wc->tally);
        /* The schema the reader enforces, enforced here first: a writer bug
         * fails this write instead of producing a manifest nothing can read. */
        if (entry_check(ebuf, entry_present(ebuf)) == -1 || entry_check_header(&hdr, ebuf) == -1) {
            char why[512];
            snprintf(why, sizeof why, "%s", belay_err_msg());
            belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: internal error, entry \"%.*s\": %s",
                          (int)ebuf->path_len, ebuf->path, why);
            goto cleanup;
        }
        outcome_count(&tally, ebuf);
        size_t llen;
        if (entry_serialize(ebuf, wc->line, LINE_CAP, &llen) == -1) goto cleanup;
        if (fwrite(wc->line, 1, llen, out) != llen) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: write failed");
            goto cleanup;
        }
    }
    if (got == -1) goto cleanup;
    if (fgetc(verdicts) != EOF) {
        belay_err_set(BELAY_ERR_INTERNAL, 0,
                      "manifest: internal error: more re-check verdicts than records");
        goto cleanup;
    }
    if (wc->tally.invalid != 0) {
        belay_err_set(BELAY_ERR_INTERNAL, 0,
                      "manifest: internal error: %zu outcome(s) the effect table does not define",
                      wc->tally.invalid);
        goto cleanup;
    }
    if (tally.entries != runs_count(wc->runs)) {
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "manifest: internal error, %zu entries walked but %zu written",
                      runs_count(wc->runs), tally.entries);
        goto cleanup;
    }

    /* The trailer makes a manifest self-delimiting: a file cut off at a line
     * boundary would otherwise be indistinguishable from a complete one with
     * fewer entries. It also records what the walk could not capture. */
    const size_t tv[TR_COUNT] = {
        [TR_ENTRIES] = tally.entries, [TR_VANISHED] = wc->tally.vanished,
        [TR_UNREADABLE] = tally.unreadable, [TR_UNSTABLE] = tally.unstable,
        [TR_MOUNTS] = tally.mounts, [TR_RACED] = tally.raced,
    };
    int tw = fputc('{', out) == EOF ? -1 : 0;
    for (size_t i = 0; i < TR_COUNT && tw >= 0; i++)
        tw = fprintf(out, "%s\"%s\":%zu", i ? "," : "", TRAILER_FIELDS[i].name, tv[i]);
    if (tw < 0 || fputs("}\n", out) == EOF) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: trailer write failed");
        goto cleanup;
    }

    if (fflush(out) != 0 || ops->fsync(ops->ctx, fileno(out)) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: flush failed");
        goto cleanup;
    }
    const int cerr = fclose(out);
    out = NULL;
    if (cerr != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: close failed");
        goto cleanup;
    }
    /* The names of the copies it records survive a crash before it does, or
     * it is not published (decided 2026-10-31); their bytes are verified on
     * read (store.h). */
    if (belay_store_sync(wc->store) == -1) goto cleanup;
    if (rename(outtmp, out_path) != 0) {
        belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot rename into %s", out_path);
        goto cleanup;
    }
    outtmp_live = false;
    sync_dir_of(ops, out_path);

    if (stats != NULL) {
        *stats = tally;
        stats->vanished = wc->tally.vanished;
        stats->store_failed = wc->store_failed;
        stats->excluded = wc->excluded;
        stats->prefilter = wc->prev != NULL;
        stats->prefilter_skipped = prev_why;
        stats->trusted = wc->trusted;
        stats->racy = wc->racy;
        stats->newest_ctime_ns = wc->newest_ctime_ns;
        stats->previous_newest_ns = wc->prev != NULL ? pinfo.newest_validated_ns : INT64_MIN;
        stats->reference_ns = wc->reference_ns;
    }
    rc = 0;

cleanup:
    if (probing) ops->probe_end(ops->ctx);
    if (out != NULL) fclose(out);
    if (outtmp_live) unlink(outtmp);
    if (verdicts != NULL) fclose(verdicts);
    free(ebuf);
    if (wc != NULL) {
        runs_free(wc->runs);
        free(wc->pack);
        free(wc->line);
        free(wc->readbuf);
        free(wc->xlist);
        free(wc->xnames);
        free(wc->abs);
        prev_free(wc->prev);
        belay_store_close(wc->store);
    }
    free(wc);
    free(rel);
    close(root_fd);
    free(real);
    return rc;
}

int belay_manifest_write(const char *out_path, const char *scope,
                         const struct belay_manifest_opts *opts,
                         struct belay_manifest_stats *stats) {
    return capture_write(fsops_default(), out_path, scope, opts, stats);
}
