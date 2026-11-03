#define _GNU_SOURCE
#include "cli.h"
#include "cli_internal.h"

#include "receipt.h"
#include "state.h"

#include "belay/belay.h"
#include "belay/diff.h"
#include "belay/error.h"
#include "belay/json.h"
#include "belay/manifest.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


/* ---- help ---- */

static const char USAGE[] =
    "usage: belay <command> [options]\n"
    "\n"
    "  check --scope DIR [--json]            record the scope as a new checkpoint, reading every file\n"
    "  mark  --scope DIR [--full] [--full-every N] [--json]\n"
    "                                        a checkpoint after the latest, reading only what may have changed\n"
    "  diff  --scope DIR --since ID [--to ID] [--full-every N] [--json] [--exit-code] [--all]\n"
    "                                        what changed from checkpoint ID to ID (or to now, kept as a checkpoint)\n"
    "  log   --scope DIR [--json]            the scope's checkpoints\n"
    "  exclude --scope DIR [--add PATH | --remove PATH]\n"
    "                                        paths the scope's captures do not walk (each one named in every manifest)\n"
    "  baseline export --scope DIR --out FILE [--protect SPEC] [--json]\n"
    "                                        the baseline bundle a later verify judges against\n"
    "  verify --scope DIR --baseline FILE --baseline-sha256 HEX [--protect SPEC] [--to ID] [--exit-code]\n"
    "                                        what the changes since the baseline mean: policy.v1\n"

    "  help [command]                        this, or one command's options\n"
    "  --version\n"
    "\n"
    "  --docker CONTAINER on any of these: the scope is a path inside a Docker container, read from its\n"
    "                                        layers on the host (Linux, root; export and verify: paused)\n"
    "exit codes: 0 done, 1 diff --exit-code found a change (verify: a violation), 2 usage, 3 refused, 4 failed\n";

static const struct { const char *cmd, *text; } HELP[] = {
    { "check", "usage: belay check --scope DIR [--json]\n"
               "  Records DIR as a new checkpoint in the state directory, reading every file.\n"
               "  --json  print the checkpoint as one JSON object (schema/checkpoint.v1.json)\n" },
    { "mark",  "usage: belay mark --scope DIR [--full] [--full-every N] [--json]\n"
               "  A checkpoint after the scope's latest: a file that cannot have changed since --\n"
               "  same inode, mode, size, mtime and ctime, ctime before the reference point -- is\n"
               "  not read again. Reads every file when there is no checkpoint before, with\n"
               "  --full, every N marks (default 50; 0: never), when ctime is seen going\n"
               "  backwards, or when the previous checkpoint cannot be used; the output says why.\n"
               "  --json  print the checkpoint as one JSON object (schema/checkpoint.v1.json)\n" },
    { "diff",  "usage: belay diff --scope DIR --since ID [--to ID] [--full-every N] [--json] [--exit-code] [--all]\n"
               "  What changed from checkpoint ID: to checkpoint --to, or to the scope now, which\n"
               "  is kept as a new checkpoint.\n"
               "  --json       print diff.v1 (docs/spec/diff-v1.md) instead of a receipt\n"
               "  --exit-code  exit 1 when any path is not unchanged (unknown included)\n"
               "  --all        show every line of the receipt, nothing folded\n" },
    { "exclude", "usage: belay exclude --scope DIR [--add PATH | --remove PATH]\n"
               "  The paths, relative to DIR, that this scope's captures do not walk -- for speed\n"
               "  (node_modules), never for noise: each one is a blind spot, named in every\n"
               "  manifest's header and every receipt. Lists them; --add or --remove one first.\n"
               "  Matched exactly; at most 31.\n" },
    { "baseline", "usage: belay baseline export --scope DIR --out FILE [--protect SPEC] [--json]\n"
               "  At reset, before the policy runs: records DIR reading every file, and writes the\n"
               "  baseline bundle (test/expect/baseline-bundle.md) to FILE, outside DIR -- the\n"
               "  manifest, its stored copies, and what each package database says of its files.\n"
               "  Prints the bundle's sha256, which verify needs, and every file not as its\n"
               "  database says (already so at reset: never blamed on the episode).\n"
               "  --protect  the task's protect spec (test/expect/protect-spec.md): its files\n"
               "             always hashed (up to 4 GiB), never excludable\n"
               "  --json     one JSON line: bundle, sha256, baseline_integrity\n" },
    { "verify", "usage: belay verify --scope DIR --baseline FILE --baseline-sha256 HEX [--protect SPEC] [--to ID] [--exit-code]\n"
               "  After the episode, the policy stopped: records DIR reading every file, in a state\n"
               "  directory of its own made fresh, and writes policy.v1 (test/expect/policy-v1.md):\n"
               "  what changed since the bundle, against the task's expectations. The bundle is read\n"
               "  only when its bytes hash to HEX.\n"
               "  --protect    the protect spec the bundle was exported with, and only it\n"
               "  --to ID      judge checkpoint ID of the scope's own state instead (with a spec,\n"
               "               only one that read every file)\n"
               "  --exit-code  exit 1 when any record is a violation (signals never)\n" },
    { "log",   "usage: belay log --scope DIR [--json]\n"
               "  The scope's checkpoints: id, kind, time, entries.\n"
               "  --json  one checkpoint a line (schema/checkpoint.v1.json)\n" },
};

/* belay_err's message as one line: it may name a path, escaped as the
 * receipt escapes paths (second review 2026-10-31, D5). */
static void err_line(FILE *err) {
    fputs("belay: ", err);
    receipt_fputs(err, belay_err_msg());
    fputc('\n', err);
}

/* A usage error: one line (review 2026-10-31, Phase 5, 15). */
static int usage(FILE *err, const char *why) {
    fputs("belay: ", err);
    receipt_fputs(err, why);          /* it may quote an argument */
    fputs(" (belay help lists the commands and options)\n", err);
    return EXIT_USAGE;
}

/* The exit code for a failure belay_err describes: a refusal (INVALID) is
 * 3, anything else -- I/O, corrupt state, memory -- is 4. */
static int failed(FILE *err) {
    const int code = belay_err_code();
    err_line(err);
    belay_err_clear();
    return code == BELAY_ERR_INVALID ? EXIT_REFUSED : EXIT_FAILED;
}

int cli_usage(FILE *err, const char *why) { return usage(err, why); }
int cli_failed(FILE *err) { return failed(err); }
void cli_err_line(FILE *err) { err_line(err); }

/* ---- options ---- */

struct opts {
    const char *scope, *since, *to, *add, *remove, *docker;
    bool json, full, exit_code, all, full_every_set;
    long full_every;
};

static int parse(int argc, char **argv, struct opts *o, FILE *err) {
    memset(o, 0, sizeof *o);
    o->full_every = 50;
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        const char **val = NULL;
        if (!strcmp(a, "--json")) o->json = true;
        else if (!strcmp(a, "--full")) o->full = true;
        else if (!strcmp(a, "--exit-code")) o->exit_code = true;
        else if (!strcmp(a, "--all")) o->all = true;
        else if (!strcmp(a, "--scope")) val = &o->scope;
        else if (!strcmp(a, "--docker")) val = &o->docker;
        else if (!strcmp(a, "--since")) val = &o->since;
        else if (!strcmp(a, "--to")) val = &o->to;
        else if (!strcmp(a, "--add")) val = &o->add;
        else if (!strcmp(a, "--remove")) val = &o->remove;
        else if (!strcmp(a, "--full-every")) {
            const char *v = i + 1 < argc ? argv[++i] : "";
            const size_t vl = strlen(v);
            if (vl == 0 || vl > STATE_ID_DIGITS || strspn(v, "0123456789") != vl)
                return usage(err, "--full-every needs a number (0: never)");
            o->full_every = strtol(v, NULL, 10);
            o->full_every_set = true;
            continue;
        } else {
            char why[256];
            snprintf(why, sizeof why, "unknown option %.200s", a);
            return usage(err, why);
        }
        if (val != NULL && *val != NULL) {      /* the last value won in silence (D6) */
            char why[64];
            snprintf(why, sizeof why, "%s given twice", a);
            return usage(err, why);
        }
        if (val != NULL) {
            if (i + 1 >= argc) {
                char why[64];
                snprintf(why, sizeof why, "%s needs a value", a);
                return usage(err, why);
            }
            *val = argv[++i];
        }
    }
    if (o->scope == NULL) return usage(err, "--scope DIR is required");
    return 0;
}

/* Strict (review 2026-10-31, Phase 5, 10): digits, no leading zero, at
 * most STATE_ID_DIGITS -- the same rule the state directory's names obey. */
static bool parse_id(const char *s, long *id) {
    *id = state_id_parse(s);
    return *id != 0;
}

/* ---- output ---- */

static void iso(int64_t ns, char *buf, size_t cap) {
    const time_t t = (time_t)(ns / 1000000000LL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* A path that is not UTF-8 is "scope_b64" / "manifest_b64" (review
 * 2026-10-31, Phase 5, 12), as in the manifest. */
static void json_checkpoint(FILE *out, const struct state *st, const struct checkpoint *c) {
    static char esc[6 * PATH_MAX + 32], why[6 * 160 + 8], man[PATH_MAX + 160], mesc[6 * (PATH_MAX + 160) + 32];
    state_manifest(st, c->id, man, sizeof man);
    if (state_json_member(esc, sizeof esc, "scope", st->scope.path) == -1 ||
        state_json_member(mesc, sizeof mesc, "manifest", man) == -1 ||
        belay_json_escape(why, sizeof why, c->full_reason, strlen(c->full_reason)) == -1) {
        belay_err_clear();
        why[0] = '\0';                 /* cannot happen: the buffers hold a PATH_MAX path escaped */
    }
    /* The excluded paths by name, from the manifest's header: a count alone
     * named no blind spot (review 2026-11-02, D2). */
    static char xs[BELAY_EXCLUDED_MAX * (6 * PATH_MAX + 64) + 8];
    size_t xw = (size_t)snprintf(xs, sizeof xs, "[");
    struct belay_manifest_reader *r = NULL;
    char src[200] = "null";             /* CK-16: the manifest's source (manifest-v3 V3-2) */
    if (state_check_manifest(st, c->id) == 0 && belay_manifest_open(man, &r) == 0) {
        const struct belay_manifest_header *h = belay_manifest_header(r);
        if (h->source_docker[0] != '\0')
            snprintf(src, sizeof src, "{\"docker\":\"%s\",\"image\":\"%s\"}", h->source_docker, h->source_image);
        static char one[6 * PATH_MAX + 32];
        for (size_t i = 0; c->excluded && i < h->n_excluded; i++) {
            if (state_json_member(one, sizeof one, "path", h->excluded[i].path) == -1) continue;
            xw += (size_t)snprintf(xs + xw, sizeof xs - xw, "%s{%s,\"reason\":\"%s\"}", xw > 1 ? "," : "", one,
                                   h->excluded[i].reason == BELAY_EXCLUDE_STATE_DIR ? "state_dir" : "user");
        }
        belay_manifest_close(r);
    }
    belay_err_clear();
    snprintf(xs + xw, sizeof xs - xw, "]");
    fprintf(out, "{\"id\":%ld,\"kind\":\"%s\",\"created_ns\":%lld,%s,%s,"
                 "\"entries\":%llu,\"raced\":%llu,\"unstable\":%llu,\"vanished\":%llu,\"provisional\":%s,"
                 "\"excluded\":%llu,\"excluded_paths\":%s,\"prefilter\":{\"used\":%s,\"reference\":\"%s\",\"trusted\":%llu,"
                 "\"racy\":%llu,\"full_reason\":\"%s\"},\"source\":%s}\n",
            c->id, c->kind, (long long)c->created_ns, esc, mesc, (unsigned long long)c->entries,
            (unsigned long long)c->raced, (unsigned long long)c->unstable, (unsigned long long)c->vanished,
            c->provisional ? "true" : "false", (unsigned long long)c->excluded, xs, c->full ? "false" : "true",
            state_reference(c), (unsigned long long)c->trusted, (unsigned long long)c->racy, why, src);
}

/* What a manifest's header says was not walked, one line each (Q6;
 * decision 2026-11-01, 3: every exclude is named, never silent). */
static void excluded_notes(FILE *out, const struct belay_manifest_header *h, const char *verb) {
    for (size_t i = 0; i < h->n_excluded; i++) {
        const struct belay_excluded *x = &h->excluded[i];
        fprintf(out, "  %s: ", verb);
        receipt_fputs(out, x->path);
        fputs(x->reason == BELAY_EXCLUDE_STATE_DIR ? " (belay's own state directory)\n"
                                                   : " (excluded for this scope)\n", out);
    }
}

/* What a capture must say on every capture (Q6, never silent): it raced,
 * or left paths out. */
static void capture_notes(FILE *out, const struct state *st, const struct checkpoint *c) {
    if (c->raced || c->unstable || c->vanished)
        fprintf(out, "  changing while captured: %llu raced, %llu unstable, %llu vanished\n",
                (unsigned long long)c->raced, (unsigned long long)c->unstable, (unsigned long long)c->vanished);
    if (!c->excluded) return;
    /* The names, from the manifest's own header: it is what was recorded. */
    char man[PATH_MAX + 160];
    struct belay_manifest_reader *r = NULL;
    state_manifest(st, c->id, man, sizeof man);
    if (state_check_manifest(st, c->id) == 0 && belay_manifest_open(man, &r) == 0) {
        excluded_notes(out, belay_manifest_header(r), "not recorded");
        belay_manifest_close(r);
    } else {
        belay_err_clear();
        fprintf(out, "  not recorded: %llu excluded paths (the manifest cannot be read to name them)\n",
                (unsigned long long)c->excluded);
    }
}

static int open_scope(const struct opts *o, bool create, struct state *st, FILE *err);

/* Every path either side of a diff did not walk, once: not compared,
 * whatever the other side holds there (decision 2026-11-01, 3). Under a
 * "not compared" heading, or, with `prefix` (stderr beside --json), one
 * prefixed line each. */
static void not_compared(FILE *out, const struct belay_manifest_header *hb,
                         const struct belay_manifest_header *ha, const char *prefix) {
    const struct belay_manifest_header *hs[2] = { hb, ha };
    bool heading = false;
    for (int sd = 0; sd < 2; sd++)
        for (size_t i = 0; i < hs[sd]->n_excluded; i++) {
            const struct belay_excluded *x = &hs[sd]->excluded[i];
            bool seen = false;
            for (size_t j = 0; sd == 1 && j < hs[0]->n_excluded; j++)
                seen |= hs[0]->excluded[j].path_len == x->path_len &&
                        memcmp(hs[0]->excluded[j].path, x->path, x->path_len) == 0;
            if (seen) continue;
            const char *why = x->reason == BELAY_EXCLUDE_STATE_DIR ? "belay's own state directory"
                                                                   : "excluded for this scope";
            if (prefix != NULL) {
                fprintf(out, "%snot compared: ", prefix);
                receipt_fputs(out, x->path);
                fprintf(out, " (%s)\n", why);
                continue;
            }
            if (!heading) fputs("\nnot compared\n", out);
            heading = true;
            fputs("  ", out);
            receipt_fputs(out, x->path);
            fprintf(out, "   %s\n", why);
        }
}

static int cmd_exclude(const struct opts *o, FILE *out, FILE *err) {
    if (o->add != NULL && o->remove != NULL) return usage(err, "--add and --remove, one at a time");
    const char *p = o->add != NULL ? o->add : o->remove;
    if (p != NULL && !state_exclude_valid(p))
        return usage(err, "an exclude is a path relative to the scope, without '.', '..' or empty parts");
    struct state st;
    int rc = open_scope(o, p != NULL, &st, err);
    if (rc) return rc;
    static struct excludes x;
    if (state_excludes_read(&st, &x) == -1) {
        rc = failed(err);
        goto done;
    }
    size_t at = x.n;
    for (size_t i = 0; p != NULL && i < x.n; i++) if (!strcmp(x.path[i], p)) at = i;
    if (o->add != NULL && at == x.n) {
        if (x.n == STATE_EXCLUDES_MAX) {
            fprintf(err, "belay: at most %d excludes\n", STATE_EXCLUDES_MAX);
            rc = EXIT_USAGE;
            goto done;
        }
        snprintf(x.path[x.n++], PATH_MAX, "%s", o->add);
        /* A list whose header line could not fit would make every capture
         * fail (decision 112): refused here, before it is kept. */
        static const char *xs[STATE_EXCLUDES_MAX];
        for (size_t i = 0; i < x.n; i++) xs[i] = x.path[i];
        const long need = belay_manifest_header_bound(st.scope.path, xs, x.n, state_rel(&st));
        if (need == -1) {
            rc = failed(err);
            goto done;
        }
        if (need > BELAY_MANIFEST_LINE_MAX) {
            fprintf(err, "belay: with this exclude a manifest's header could need %ld bytes, over its "
                         "%d-byte line limit: fewer or shorter excludes\n", need, BELAY_MANIFEST_LINE_MAX);
            rc = EXIT_USAGE;
            goto done;
        }
    } else if (o->remove != NULL && at < x.n) {
        memmove(x.path[at], x.path[at + 1], (x.n - at - 1) * sizeof x.path[0]);
        x.n--;
    } else if (o->remove != NULL) {
        fputs("belay: ", err);                    /* never a silent success (D6) */
        receipt_fputs(err, o->remove);
        fputs(" is not excluded\n", err);
        rc = EXIT_USAGE;
        goto done;
    }
    if (p != NULL && state_excludes_write(&st, &x) == -1) {
        rc = failed(err);
        goto done;
    }
    for (size_t i = 0; i < x.n; i++) {
        receipt_fputs(out, x.path[i]);
        fputc('\n', out);
    }
    if (x.n == 0) fputs("no excludes: every path in the scope is walked\n", out);
done:
    state_close(&st);
    return rc;
}

static void text_checkpoint(FILE *out, const struct state *st, const struct checkpoint *c) {
    char t[32];
    iso(c->created_ns, t, sizeof t);
    fprintf(out, "%s %ld  %s  %llu entries", c->kind, c->id, t, (unsigned long long)c->entries);
    if (!c->full) {
        fprintf(out, ", %llu files not read again (unchanged)", (unsigned long long)c->trusted);
        /* Said, never silent: the weaker reference point (docs/cli.md;
         * second review 2026-10-31, D3). */
        if (!c->walk_start_reference)
            fputs("; reference point: the newest ctime recorded (belay's state is on another filesystem)", out);
    } else if (c->full_reason[0]) {
        fputs(", every file read (", out);
        receipt_fputs(out, c->full_reason);
        fputc(')', out);
    }
    fputc('\n', out);
    capture_notes(out, st, c);
}

/* ---- commands ---- */

/* A scope that cannot be resolved is refused (3) whatever the cause, but
 * memory; state that cannot be opened follows its error (3 or 4). */
static int open_scope_paused(const struct opts *o, bool need_paused, bool create, struct state *st, FILE *err) {
    struct scope sc;
    st->dir_fd = st->cp_fd = st->lock_fd = -1;
    if ((o->docker != NULL ? scope_resolve_docker(o->docker, o->scope, need_paused, &sc, err)
                           : scope_resolve(o->scope, &sc)) == -1) {
        if (belay_err_code() == BELAY_ERR_NOMEM) return failed(err);
        err_line(err);
        belay_err_clear();
        return EXIT_REFUSED;
    }
    if (state_open(&sc, create, st, err) == -1) {
        state_close(st);
        return failed(err);
    }
    return 0;
}

static int open_scope(const struct opts *o, bool create, struct state *st, FILE *err) {
    return open_scope_paused(o, false, create, st, err);
}

int cli_open_scope(const char *scope, const char *docker, bool create, struct state *st, FILE *err) {
    struct opts o;
    memset(&o, 0, sizeof o);
    o.scope = scope;
    o.docker = docker;
    return open_scope_paused(&o, docker != NULL, create, st, err);   /* export: paused (H-C4) */
}

static int cmd_capture(const struct opts *o, const char *kind, FILE *out, FILE *err) {
    struct state st;
    int rc = open_scope(o, true, &st, err);
    if (rc) return rc;
    const struct capture_req req = { kind, strcmp(kind, "mark") == 0, o->full, o->full_every, 0 };
    struct checkpoint c;
    if (state_capture(&st, &req, &c) == -1) {
        rc = failed(err);
    } else {
        if (o->json) json_checkpoint(out, &st, &c);
        else text_checkpoint(out, &st, &c);
    }
    state_close(&st);
    return rc;
}

static int cmd_log(const struct opts *o, FILE *out, FILE *err) {
    struct state st;
    int rc = open_scope(o, false, &st, err);
    if (rc) return rc;
    struct checkpoint *list;
    size_t n;
    if (state_list(&st, &list, &n) == -1) rc = failed(err);
    else {
        for (size_t i = 0; i < n; i++) {
            if (o->json) json_checkpoint(out, &st, &list[i]);
            else text_checkpoint(out, &st, &list[i]);
        }
        if (n == 0 && !o->json) fprintf(out, "no checkpoints of the scope\n");
        free(list);
    }
    state_close(&st);
    return rc;
}

/* The receipt's mode lookup: a forward-only cursor on each manifest, as
 * records arrive in path order. */
struct cursor { struct belay_manifest_reader *r; struct belay_entry e; int got; };
struct modes { struct cursor side[2]; };

static int pathcmp(const char *a, size_t al, const char *b, size_t bl) {
    const int c = memcmp(a, b, al < bl ? al : bl);
    return c ? c : (al > bl) - (al < bl);
}

static int mode_of(void *ctx, int side, const char *path, size_t len, struct receipt_meta *m) {
    struct cursor *c = &((struct modes *)ctx)->side[side];
    while (c->got == 1 && pathcmp(c->e.path, c->e.path_len, path, len) < 0)
        c->got = belay_manifest_next(c->r, &c->e);
    if (c->got != 1 || pathcmp(c->e.path, c->e.path_len, path, len) != 0) return -1;
    m->mode = c->e.mode;
    m->has_caps = c->e.has_caps;
    return 0;
}

static int cmd_diff(const struct opts *o, FILE *out, FILE *err) {
    long from, to = 0;
    if (!parse_id(o->since, &from)) return usage(err, "diff needs --since ID, a checkpoint id");
    if (o->to != NULL && !parse_id(o->to, &to)) return usage(err, "--to needs a checkpoint id");
    struct state st;
    /* Opened without creating anything until the ids are known to exist:
     * a diff of a scope never captured leaves no state behind (D8). */
    int rc = open_scope(o, false, &st, err);
    if (rc) return rc;
    struct checkpoint *list = NULL, now = { 0 };
    size_t n = 0;
    char a[PATH_MAX + 160], b[PATH_MAX + 160], d[PATH_MAX + 200], label_a[64], label_b[64];
    struct modes m = { 0 };
    FILE *in = NULL;
    if (state_list(&st, &list, &n) == -1) { rc = failed(err); goto done; }
    bool have_from = false, have_to = to == 0;
    for (size_t i = 0; i < n; i++) {
        if (list[i].id == from) have_from = true;
        if (list[i].id == to) have_to = true;
    }
    if (!have_from || !have_to) {
        fprintf(err, "belay: no checkpoint %ld of ", have_from ? to : from);
        receipt_fputs(err, st.scope.path);
        fputs(" (belay log --scope lists them)\n", err);
        rc = EXIT_USAGE;
        goto done;
    }
    state_close(&st);                            /* a capture, and diff-from-N written: under the lock */
    if ((rc = open_scope(o, true, &st, err)) != 0) goto done;
    if (state_check_manifest(&st, from) == -1 || (to != 0 && state_check_manifest(&st, to) == -1)) {
        rc = failed(err);
        goto done;
    }
    if (to == 0) {
        /* Q3: the capture is kept as a checkpoint, prefiltered as a mark. */
        const struct capture_req req = { "diff", true, false, o->full_every, 0 };
        if (state_capture(&st, &req, &now) == -1) { rc = failed(err); goto done; }
        to = now.id;
        snprintf(label_b, sizeof label_b, "now (checkpoint %ld)", to);
    } else {
        snprintf(label_b, sizeof label_b, "checkpoint %ld", to);
    }
    snprintf(label_a, sizeof label_a, "checkpoint %ld", from);
    state_manifest(&st, from, a, sizeof a);
    state_manifest(&st, to, b, sizeof b);
    snprintf(d, sizeof d, "%s/checkpoints/%ld/diff-from-%ld.ndjson", st.dir, to, from);
    const struct belay_diff_opts dopts = { .store_dir = st.store };
    struct belay_diff_stats ds;
    if (belay_diff(a, b, d, &dopts, &ds) == -1) { rc = failed(err); goto done; }
    in = fopen(d, "r");
    if (in == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", d);
        rc = failed(err);
        goto done;
    }
    if (o->json) {
        char buf[65536];
        size_t k;
        while ((k = fread(buf, 1, sizeof buf, in)) > 0) fwrite(buf, 1, k, out);
        if (ferror(in)) {
            belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", d);
            rc = failed(err);
            goto done;
        }
        /* Never in the JSON: the capture's notes, and every path either
         * side did not walk, on stderr -- with --to too, both sides
         * (review 2026-11-02, D2: a clean-looking diff named no blind spot). */
        if (now.id != 0 && (now.raced || now.unstable || now.vanished))
            capture_notes(err, &st, &(struct checkpoint){ .id = now.id, .raced = now.raced,
                                                          .unstable = now.unstable, .vanished = now.vanished });
        if (belay_manifest_open(a, &m.side[0].r) == -1 || belay_manifest_open(b, &m.side[1].r) == -1) {
            rc = failed(err);
            goto done;
        }
        not_compared(err, belay_manifest_header(m.side[0].r), belay_manifest_header(m.side[1].r), "belay: ");
    } else {
        if (belay_manifest_open(a, &m.side[0].r) == -1 || belay_manifest_open(b, &m.side[1].r) == -1) {
            rc = failed(err);
            goto done;
        }
        for (int s = 0; s < 2; s++) m.side[s].got = belay_manifest_next(m.side[s].r, &m.side[s].e);
        const struct receipt_opts ro = { label_a, label_b, o->all, mode_of, &m };
        if (receipt_render(in, out, &ro) == -1) { rc = failed(err); goto done; }
        if (now.id != 0 && (now.raced || now.unstable || now.vanished)) {
            fprintf(out, "\ncheckpoint %ld, captured now\n", now.id);
            capture_notes(out, &st, &(struct checkpoint){ .id = now.id, .raced = now.raced,
                                                          .unstable = now.unstable, .vanished = now.vanished });
        }
        not_compared(out, belay_manifest_header(m.side[0].r), belay_manifest_header(m.side[1].r), NULL);
    }
    if (o->exit_code && ds.records > 0) rc = EXIT_CHANGES;
done:
    if (in != NULL) fclose(in);
    belay_manifest_close(m.side[0].r);
    belay_manifest_close(m.side[1].r);
    free(list);
    state_close(&st);
    return rc;
}

static int run(int argc, char **argv, FILE *out, FILE *err) {
    if (argc < 2) return usage(err, "no command");
    const char *cmd = argv[1];
    if (!strcmp(cmd, "--version") || !strcmp(cmd, "version")) {
        fprintf(out, "belay %s (manifest v2, diff.v1)\n", BELAY_VERSION_STRING);
        return EXIT_DONE;
    }
    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        if (argc >= 3)
            for (size_t i = 0; i < sizeof HELP / sizeof HELP[0]; i++)
                if (!strcmp(argv[2], HELP[i].cmd)) { fputs(HELP[i].text, out); return EXIT_DONE; }
        if (argc >= 3) return usage(err, "no such command");
        fputs(USAGE, out);
        return EXIT_DONE;
    }
    for (int i = 2; i < argc; i++)
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h"))
            for (size_t k = 0; k < sizeof HELP / sizeof HELP[0]; k++)
                if (!strcmp(cmd, HELP[k].cmd)) { fputs(HELP[k].text, out); return EXIT_DONE; }
    if (!strcmp(cmd, "baseline")) return cmd_baseline(argc, argv, out, err);
    if (!strcmp(cmd, "verify")) return cmd_verify(argc, argv, out, err);
    struct opts o;
    const bool known = !strcmp(cmd, "check") || !strcmp(cmd, "mark") || !strcmp(cmd, "diff") || !strcmp(cmd, "log") ||
                       !strcmp(cmd, "exclude");
    if (!known) {
        char why[256];
        snprintf(why, sizeof why, "unknown command %.200s", cmd);
        return usage(err, why);
    }
    const int pr = parse(argc, argv, &o, err);
    if (pr) return pr;
    if (strcmp(cmd, "diff") && (o.since || o.to || o.exit_code || o.all))
        return usage(err, "--since, --to, --exit-code and --all are diff's");
    if (strcmp(cmd, "mark") && o.full) return usage(err, "--full is mark's");
    if ((!strcmp(cmd, "check") || !strcmp(cmd, "log") || !strcmp(cmd, "exclude")) && o.full_every_set)
        return usage(err, "--full-every is mark's and diff's");
    if (strcmp(cmd, "exclude") && (o.add || o.remove)) return usage(err, "--add and --remove are exclude's");
    if (!strcmp(cmd, "exclude") && o.json) return usage(err, "exclude has no --json");
    if (!strcmp(cmd, "exclude")) return cmd_exclude(&o, out, err);
    if (!strcmp(cmd, "check")) return cmd_capture(&o, "check", out, err);
    if (!strcmp(cmd, "mark")) return cmd_capture(&o, "mark", out, err);
    if (!strcmp(cmd, "diff")) return cmd_diff(&o, out, err);
    return cmd_log(&o, out, err);
}

/* Output that could not be written is a failure, exit 4 (review 2026-10-31,
 * Phase 5, 14): a full disk under `belay diff --json > f` must not exit 0. */
int cli_main(int argc, char **argv, FILE *out, FILE *err) {
    const int rc = run(argc, argv, out, err);
    errno = 0;
    const int e = fflush(out) != 0 ? errno : 0;
    if ((e != 0 || ferror(out)) && rc != EXIT_FAILED) {
        fprintf(err, "belay: cannot write the output%s%s\n", e ? ": " : "", e ? strerror(e) : "");
        return EXIT_FAILED;
    }
    return rc;
}
