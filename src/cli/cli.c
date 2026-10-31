#define _GNU_SOURCE
#include "cli.h"

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
    "  help [command]                        this, or one command's options\n"
    "  --version\n"
    "\n"
    "exit codes: 0 done, 1 diff --exit-code found a change, 2 usage, 3 refused, 4 failed\n";

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

/* ---- options ---- */

struct opts {
    const char *scope, *since, *to;
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
        else if (!strcmp(a, "--since")) val = &o->since;
        else if (!strcmp(a, "--to")) val = &o->to;
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
    fprintf(out, "{\"id\":%ld,\"kind\":\"%s\",\"created_ns\":%lld,%s,%s,"
                 "\"entries\":%llu,\"raced\":%llu,\"unstable\":%llu,\"vanished\":%llu,\"provisional\":%s,"
                 "\"excluded\":%llu,\"prefilter\":{\"used\":%s,\"reference\":\"%s\",\"trusted\":%llu,"
                 "\"racy\":%llu,\"full_reason\":\"%s\"}}\n",
            c->id, c->kind, (long long)c->created_ns, esc, mesc, (unsigned long long)c->entries,
            (unsigned long long)c->raced, (unsigned long long)c->unstable, (unsigned long long)c->vanished,
            c->provisional ? "true" : "false", (unsigned long long)c->excluded, c->full ? "false" : "true",
            state_reference(c), (unsigned long long)c->trusted, (unsigned long long)c->racy, why);
}

/* What a capture must say on every capture (Q6, never silent): it raced,
 * or skipped belay's own state directory. */
static void capture_notes(FILE *out, const struct state *st, const struct checkpoint *c) {
    if (c->raced || c->unstable || c->vanished)
        fprintf(out, "  changing while captured: %llu raced, %llu unstable, %llu vanished\n",
                (unsigned long long)c->raced, (unsigned long long)c->unstable, (unsigned long long)c->vanished);
    /* Q6: never silent -- the walk skipped belay's own state directory. */
    if (c->excluded) {
        fputs("  not recorded: belay's own state directory ", out);
        receipt_fputs(out, st->root);
        fputs(" (inside the scope)\n", out);
    }
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
static int open_scope(const struct opts *o, bool create, struct state *st, FILE *err) {
    struct scope sc;
    st->dir_fd = st->cp_fd = st->lock_fd = -1;
    if (scope_resolve(o->scope, &sc) == -1) {
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

static int cmd_capture(const struct opts *o, const char *kind, FILE *out, FILE *err) {
    struct state st;
    int rc = open_scope(o, true, &st, err);
    if (rc) return rc;
    const struct capture_req req = { kind, strcmp(kind, "mark") == 0, o->full, o->full_every };
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
        const struct capture_req req = { "diff", true, false, o->full_every };
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
        if (now.id != 0) capture_notes(err, &st, &now);     /* never in the JSON */
    } else {
        if (belay_manifest_open(a, &m.side[0].r) == -1 || belay_manifest_open(b, &m.side[1].r) == -1) {
            rc = failed(err);
            goto done;
        }
        for (int s = 0; s < 2; s++) m.side[s].got = belay_manifest_next(m.side[s].r, &m.side[s].e);
        const struct receipt_opts ro = { label_a, label_b, o->all, mode_of, &m };
        if (receipt_render(in, out, &ro) == -1) { rc = failed(err); goto done; }
        if (now.id != 0 && (now.raced || now.unstable || now.vanished || now.excluded)) {
            fprintf(out, "\ncheckpoint %ld, captured now\n", now.id);
            capture_notes(out, &st, &now);
        }
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
        fprintf(out, "belay %s (manifest v1, diff.v1)\n", BELAY_VERSION_STRING);
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
    struct opts o;
    const bool known = !strcmp(cmd, "check") || !strcmp(cmd, "mark") || !strcmp(cmd, "diff") || !strcmp(cmd, "log");
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
    if ((!strcmp(cmd, "check") || !strcmp(cmd, "log")) && o.full_every_set)
        return usage(err, "--full-every is mark's and diff's");
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
