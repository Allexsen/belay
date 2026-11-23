#define _GNU_SOURCE
#include "watch/sysreceipt.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "belay/diff.h"
#include "belay/error.h"
#include "belay/manifest.h"
#include "cli/cli_internal.h"
#include "cli/delta.h"
#include "cli/receipt.h"
#include "watch/krec.h"
#include "watch/sysflag.h"

#define LISTED 20
/* WS-R3's reason for a container (--docker needs root, so never "not root") */
#define DOCKER_NO_RECORD "no recorder for a container in this version"       /* entries `could not read` and `not read` name, then a count (WS-R2, WS-R5) */

/* ---- the kernel record: STEP 7 SETS THIS ---- */

void watch_kernel_record(const struct state *st, struct wkrec *k) {
    static struct krec_status s;
    memset(k, 0, sizeof *k);
    k->iflags_events = true;
    const int got = krec_status_read(st, &s);
    belay_err_clear();
    if (got != 0) {             /* a watch started before there was a recorder, or a state that does not read */
        snprintf(k->off_why, sizeof k->off_why, "%s", geteuid() == 0 ? "the watch was started without one" : "not root");
        return;
    }
    k->on = s.on;
    k->since_ns = s.since_ns;
    k->gap = s.gap;
    k->gap_from_ns = s.gap_from_ns;
    k->gap_to_ns = s.gap_to_ns;
    k->iflags_events = s.iflags_events;
    snprintf(k->gap_why, sizeof k->gap_why, "%s", s.gap_why);
    snprintf(k->off_why, sizeof k->off_why, "%s", s.off_why);
    snprintf(k->walked, sizeof k->walked, "%s", s.walked);
}

static void iso(int64_t ns, char out[32]) {
    const time_t t = (time_t)(ns / 1000000000LL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static int nomem(void) {
    belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
    return -1;
}

static bool at_or_under(const char *p, size_t n, const char *d) {
    const size_t dl = strlen(d);
    return n >= dl && memcmp(p, d, dl) == 0 && (n == dl || p[dl] == '/');
}

/* `holders_unknown` of a checkpoint's runtime record: its last line's. */
static long holders_unknown(const struct state *st, long cp) {
    char path[PATH_MAX + 200];
    if (state_runtime(st, cp, path, sizeof path) != 1) { belay_err_clear(); return 0; }
    FILE *f = fopen(path, "r");
    if (f == NULL) return 0;
    char *line = NULL, *last = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, f) > 0) { free(last); last = strdup(line); }
    free(line);
    fclose(f);
    const char *h = last != NULL ? strstr(last, "\"holders_unknown\":") : NULL;
    const long n = h != NULL ? strtol(h + 18, NULL, 10) : 0;
    free(last);
    return n;
}

int sysreceipt_head(const struct state *st, long cp, const struct wstate *w, struct wsb *out) {
    struct manifest_file mf = { .temporary = false };
    struct belay_manifest_reader *r = NULL;
    if (manifest_acquire(st, cp, &mf) == -1 || belay_manifest_open(mf.path, &r) == -1) {
        manifest_release(&mf);
        return -1;
    }
    static struct belay_entry e;
    int got;
    size_t n = 0;
    bool sudo = false, cron = false, keys = false;
    wsb_f(out, "could not read:");
    while ((got = belay_manifest_next(r, &e)) == 1) {
        if (!e.unreadable) continue;
        if (n < LISTED) {
            char *s = receipt_escaped(e.path, e.path_len);
            wsb_f(out, "%s %s", n ? "," : "", s != NULL ? s : "?");
            out->bad |= s == NULL;
            free(s);
        }
        n++;
        sudo |= at_or_under(e.path, e.path_len, "etc/sudoers") || at_or_under(e.path, e.path_len, "etc/sudoers.d");
        cron |= at_or_under(e.path, e.path_len, "var/spool/cron");
        keys |= (e.path_len > 5 && memcmp(e.path + e.path_len - 5, "/.ssh", 5) == 0) ||
                (e.path_len >= 4 && memcmp(e.path, ".ssh", 4) == 0) || strstr(e.path, "/.ssh/") != NULL;
    }
    belay_manifest_close(r);
    manifest_release(&mf);
    if (got == -1) return -1;
    if (n == 0) wsb_f(out, " nothing");
    else if (n > LISTED) wsb_f(out, ", and %zu more", n - LISTED);
    wsb_f(out, "\n");
    struct wkrec k;
    watch_kernel_record(st, &k);
    if (st->scope.docker[0] != '\0' && !k.on)        /* WS-R3: kernel-record K20, K21 are not built yet */
        snprintf(k.off_why, sizeof k.off_why, "%s", DOCKER_NO_RECORD);
    if (geteuid() != 0) {               /* WS-R2: each part only when it is true of this run */
        const bool holders = holders_unknown(st, cp) > 0;
        struct wsb parts = { 0 };
        if (sudo) wsb_f(&parts, "no sudoers");
        if (cron) wsb_f(&parts, "%sno user crontabs", parts.n ? ", " : "");
        if (keys) wsb_f(&parts, "%sno other users' keys", parts.n ? ", " : "");
        if (holders) wsb_f(&parts, "%sno holders of ports", parts.n ? ", " : "");
        if (!k.on) wsb_f(&parts, "%sno kernel record", parts.n ? ", " : "");
        if (parts.n) wsb_f(out, "  not root: %s\n", parts.p);
        out->bad |= parts.bad;
        free(parts.p);
    }
    char a[32], b[32];
    if (k.on && k.gap) {
        iso(k.since_ns, a);
        wsb_f(out, "kernel record: on since %s, with a gap from ", a);
        iso(k.gap_from_ns, a);
        iso(k.gap_to_ns, b);
        wsb_f(out, "%s to %s (%s)", a, b, k.gap_why);
    } else if (k.on) {
        iso(k.since_ns, a);
        wsb_f(out, "kernel record: on since %s, whole%s", a, k.walked);
    } else {
        wsb_f(out, "kernel record: off: %s: a change put back is not seen", k.off_why);
    }
    if (k.on && !k.iflags_events) wsb_f(out, "; inode flags as of the last walk");
    if (w->n_late > 0) {                /* WS-3c */
        wsb_f(out, "; %zu step%s reported late (walk%s of ", w->n_late, w->n_late == 1 ? "" : "s", w->n_late == 1 ? "" : "s");
        for (size_t i = 0; i < w->n_late && i < W_LATE_MAX; i++) wsb_f(out, "%s%ld s", i ? ", " : "", w->late[i]);
        if (w->n_late > W_LATE_MAX) wsb_f(out, " and %zu more", w->n_late - W_LATE_MAX);
        wsb_f(out, ")");
    }
    wsb_f(out, "\n");
    return out->bad ? nomem() : 0;
}

/* ---- the sections' records ---- */

struct secctx { struct cli_modes *m; char **homes; size_t n_homes; };

static int section_of(void *ctx, const char *path, size_t len, bool dir) {
    const struct secctx *c = ctx;
    const struct sysrow *row = sysflag_row_of(path, len);
    if (row != NULL && row->kind == WK_TRUST) return RS_TRUST;
    if (row != NULL && row->kind == WK_FIREWALL) return RS_FIREWALL;
    if (dir || at_or_under(path, len, "root")) return -1;
    for (size_t i = 0; i < c->n_homes; i++)
        if (at_or_under(path, len, c->homes[i])) return -1;
    for (int side = 0; side < 2; side++) {          /* WS-F12 */
        struct receipt_meta m;
        memset(&m, 0, sizeof m);
        if (cli_mode_of(c->m, side, path, len, &m) == 0 && m.sealed) return RS_SECRET;
    }
    return -1;
}

int sysreceipt(const struct state *st, const struct wstate *w, long from, long to, int64_t to_ns, struct wsb *out) {
    struct manifest_file mf_a = { .temporary = false }, mf_b = { .temporary = false };
    struct cli_modes m = { 0 };
    struct wsb head = { 0 }, tail = { 0 };
    char *roots = NULL, *text = NULL, **homes = NULL;
    const char **meta = NULL;
    size_t n_homes = 0, n_meta = 0, len = 0;
    FILE *in = NULL, *mem = NULL;
    int rc = -1;
    char d[PATH_MAX + 200];
    snprintf(d, sizeof d, "%s/checkpoints/%ld/diff-from-%ld.ndjson", st->dir, to, from);
    if (manifest_acquire(st, from, &mf_a) == -1 || manifest_acquire(st, to, &mf_b) == -1) goto out;
    static char lines_a[PATH_MAX + 200], lines_b[PATH_MAX + 200], rt_a[PATH_MAX + 200], rt_b[PATH_MAX + 200];
    const int la = state_shadow_lines(st, from, lines_a, sizeof lines_a);
    const int lb = la == -1 ? -1 : state_shadow_lines(st, to, lines_b, sizeof lines_b);
    const int ra = lb == -1 ? -1 : state_runtime(st, from, rt_a, sizeof rt_a);
    const int rb = ra == -1 ? -1 : state_runtime(st, to, rt_b, sizeof rt_b);
    if (rb == -1) goto out;
    char ida[65] = "", idb[65] = "";             /* diff-fields ID-1 */
    if (!manifest_event_identity(st, from, ida)) ida[0] = '\0';
    if (!manifest_event_identity(st, to, idb)) idb[0] = '\0';
    const struct belay_diff_opts dopts = { .before_identity = ida[0] ? ida : NULL, .after_identity = idb[0] ? idb : NULL,
                                           .store_dir = st->store, .shadow_lines_before = la == 1 ? lines_a : NULL,
                                           .shadow_lines_after = lb == 1 ? lines_b : NULL,
                                           .runtime_before = ra == 1 ? rt_a : NULL, .runtime_after = rb == 1 ? rt_b : NULL };
    struct belay_diff_stats ds;
    if (belay_diff(mf_a.path, mf_b.path, d, &dopts, &ds) == -1) goto out;
    if (belay_manifest_open(mf_a.path, &m.side[0].r) == -1 || belay_manifest_open(mf_b.path, &m.side[1].r) == -1) goto out;
    const struct belay_manifest_header *ha = belay_manifest_header(m.side[0].r), *hb = belay_manifest_header(m.side[1].r);
    if (sysflag_roots_changed(ha, hb, &roots) == -1) goto out;
    if ((homes = calloc(hb->n_roots + 1, sizeof *homes)) == NULL || (meta = calloc(hb->n_roots + 1, sizeof *meta)) == NULL) {
        nomem();
        goto out;
    }
    wsb_f(&tail, "\nnot compared:");
    for (size_t i = 0; i < hb->n_roots; i++) {
        const char *p = hb->roots[i].path;
        const size_t n = strlen(p);
        if (n > 5 && memcmp(p + n - 5, "/.ssh", 5) == 0 && (homes[n_homes] = strndup(p, n - 5)) != NULL) n_homes++;
        if (hb->roots[i].cls == BELAY_ROOT_METADATA) {
            meta[n_meta++] = p;
            if (hb->roots[i].found) wsb_f(&tail, "%s %s", tail.n > 14 ? "," : "", p);     /* WS-R5 */
        }
    }
    if (tail.n == 14) wsb_f(&tail, " nothing");
    /* the head: could not read, kernel record, end state */
    if (sysreceipt_head(st, to, w, &head) == -1) goto out;
    char at[32];
    iso(to_ns, at);
    wsb_f(&head, "end state: by a walk at %s\n", at);                                   /* WS-R4 */
    /* not read: the directories not entered, in the end state */
    for (int sd = 0; sd < 2; sd++) m.side[sd].got = 0;
    {
        static struct belay_entry e;
        struct belay_manifest_reader *r = NULL;
        size_t n = 0;
        int got;
        wsb_f(&tail, "\nnot read:");
        if (belay_manifest_open(mf_b.path, &r) == -1) goto out;
        while ((got = belay_manifest_next(r, &e)) == 1) {
            if (!e.not_read) continue;
            if (n++ < LISTED) {
                char *s = receipt_escaped(e.path, e.path_len);
                wsb_f(&tail, "%s %s", n > 1 ? "," : "", s != NULL ? s : "?");
                free(s);
            }
        }
        belay_manifest_close(r);
        if (got == -1) goto out;
        if (n == 0) wsb_f(&tail, " nothing");
        else if (n > LISTED) wsb_f(&tail, ", and %zu more", n - LISTED);
        wsb_f(&tail, "\n");
    }
    for (int sd = 0; sd < 2; sd++) m.side[sd].got = belay_manifest_next(m.side[sd].r, &m.side[sd].e);
    if (head.bad || tail.bad) { nomem(); goto out; }
    struct secctx sx = { &m, homes, n_homes };
    const struct receipt_sections sec = { head.p, roots, NULL /* put back: step 7 */, tail.p, section_of, &sx, meta, n_meta };
    struct cli_owners own = { { mf_a.path, mf_b.path }, st->store };
    struct cli_system sys = { mf_b.path, st->store };
    const struct receipt_opts ro = { .from = NULL, .to = NULL, .all = false, .mode = cli_mode_of, .mode_ctx = &m,
                                     .owner = cli_owner_of, .owner_ctx = &own, .system = cli_system_of,
                                     .system_ctx = &sys, .sections = &sec };
    if ((in = fopen(d, "r")) == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", d);
        goto out;
    }
    if ((mem = open_memstream(&text, &len)) == NULL) { nomem(); goto out; }
    char *scope = receipt_escaped(st->scope.path, strlen(st->scope.path));
    fprintf(mem, "belay receipt  %s", scope != NULL ? scope : "");
    free(scope);
    if (st->scope.docker[0] != '\0') {                /* WS-1: the container's / */
        char *name = receipt_escaped(st->scope.docker, strlen(st->scope.docker));
        fprintf(mem, " in the container %s (%.12s)", name != NULL ? name : "?", st->scope.docker_id);
        free(name);
    }
    fputc('\n', mem);
    if (receipt_render(in, mem, &ro) == -1) goto out;
    if (fclose(mem) != 0) { mem = NULL; nomem(); goto out; }
    mem = NULL;
    wsb_f(out, "%s", text != NULL ? text : "");
    rc = out->bad ? nomem() : 0;
out:
    if (mem != NULL) fclose(mem);
    if (in != NULL) fclose(in);
    free(text);
    free(roots);
    for (size_t i = 0; i < n_homes; i++) free(homes[i]);
    free(homes);
    free(meta);
    free(head.p);
    free(tail.p);
    belay_manifest_close(m.side[0].r);
    belay_manifest_close(m.side[1].r);
    manifest_release(&mf_a);
    manifest_release(&mf_b);
    return rc;
}
