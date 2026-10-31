#define _GNU_SOURCE
#include "cli.h"

#include "receipt.h"
#include "state.h"

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

#define BELAY_VERSION "0.1.0-dev"

/* ---- help ---- */

static const char USAGE[] =
    "usage: belay <command> [options]\n"
    "\n"
    "  check --scope DIR [--json]            record the scope as a new checkpoint, reading every file\n"
    "  mark  --scope DIR [--full] [--full-every N] [--json]\n"
    "                                        a checkpoint after the latest, reading only what may have changed\n"
    "  diff  --scope DIR --since ID [--to ID] [--json] [--exit-code] [--all]\n"
    "                                        what changed from checkpoint ID to ID (or to now, kept as a checkpoint)\n"
    "  log   --scope DIR [--json]            the scope's checkpoints\n"
    "  help [command]                        this, or one command's options\n"
    "  --version\n"
    "\n"
    "exit codes: 0 done, 1 diff --exit-code found a change, 2 usage, 3 refused, 4 failed\n";

static const struct { const char *cmd, *text; } HELP[] = {
    { "check", "usage: belay check --scope DIR [--json]\n"
               "  Records DIR as a new checkpoint in the state directory, reading every file.\n"
               "  --json  print the checkpoint as one JSON object (schema/check.v1.json)\n" },
    { "mark",  "usage: belay mark --scope DIR [--full] [--full-every N] [--json]\n"
               "  A checkpoint after the scope's latest: a file that cannot have changed since --\n"
               "  same inode, mode, size, mtime and ctime, ctime before the reference point -- is\n"
               "  not read again. Reads every file when there is no checkpoint before, with\n"
               "  --full, every N marks (default 50), or when ctime is seen going backwards.\n"
               "  --json  print the checkpoint as one JSON object (schema/mark.v1.json)\n" },
    { "diff",  "usage: belay diff --scope DIR --since ID [--to ID] [--json] [--exit-code] [--all]\n"
               "  What changed from checkpoint ID: to checkpoint --to, or to the scope now, which\n"
               "  is kept as a new checkpoint.\n"
               "  --json       print diff.v1 (docs/spec/diff-v1.md) instead of a receipt\n"
               "  --exit-code  exit 1 when any path is not unchanged (unknown included)\n"
               "  --all        show every line of the receipt, nothing folded\n" },
    { "log",   "usage: belay log --scope DIR [--json]\n"
               "  The scope's checkpoints: id, kind, time, entries.\n"
               "  --json  one JSON object a line (schema/log.v1.json)\n" },
};

static int usage(FILE *err, const char *why) {
    if (why != NULL) fprintf(err, "belay: %s\n", why);
    fputs(USAGE, err);
    return EXIT_USAGE;
}

/* The exit code for a failure belay_err describes. */
static int failed(FILE *err, int refusal) {
    const int code = belay_err_code();
    fprintf(err, "belay: %s\n", belay_err_msg());
    belay_err_clear();
    if (refusal || code == BELAY_ERR_INVALID) return EXIT_REFUSED;
    return EXIT_FAILED;
}

/* ---- options ---- */

struct opts {
    const char *scope, *since, *to;
    bool json, full, exit_code, all;
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
            if (i + 1 >= argc) return usage(err, "--full-every needs a number");
            char *end;
            o->full_every = strtol(argv[++i], &end, 10);
            if (*end != '\0' || o->full_every < 0) return usage(err, "--full-every needs a number");
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

static bool parse_id(const char *s, long *id) {
    char *end;
    if (s == NULL || *s == '\0') return false;
    *id = strtol(s, &end, 10);
    return *end == '\0' && *id > 0;
}

/* ---- output ---- */

static void iso(int64_t ns, char *buf, size_t cap) {
    const time_t t = (time_t)(ns / 1000000000LL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void json_checkpoint(FILE *out, const struct state *st, const struct checkpoint *c) {
    char esc[6 * PATH_MAX + 8], why[6 * 160 + 8], man[PATH_MAX + 160], mesc[6 * (PATH_MAX + 160) + 8];
    state_manifest(st, c->id, man, sizeof man);
    belay_json_escape(esc, sizeof esc, st->scope.path, strlen(st->scope.path));
    belay_json_escape(why, sizeof why, c->full_reason, strlen(c->full_reason));
    belay_json_escape(mesc, sizeof mesc, man, strlen(man));
    fprintf(out, "{\"id\":%ld,\"kind\":\"%s\",\"created_ns\":%lld,\"scope\":\"%s\",\"manifest\":\"%s\","
                 "\"entries\":%llu,\"raced\":%llu,\"unstable\":%llu,\"vanished\":%llu,\"provisional\":%s,"
                 "\"excluded\":%llu,\"prefilter\":{\"used\":%s,\"trusted\":%llu,\"racy\":%llu,\"full_reason\":\"%s\"}}\n",
            c->id, c->kind, (long long)c->created_ns, esc, mesc, (unsigned long long)c->entries,
            (unsigned long long)c->raced, (unsigned long long)c->unstable, (unsigned long long)c->vanished,
            c->provisional ? "true" : "false", (unsigned long long)c->excluded, c->full ? "false" : "true",
            (unsigned long long)c->trusted, (unsigned long long)c->racy, why);
}

static void text_checkpoint(FILE *out, const struct state *st, const struct checkpoint *c) {
    char t[32];
    iso(c->created_ns, t, sizeof t);
    fprintf(out, "%s %ld  %s  %llu entries", c->kind, c->id, t, (unsigned long long)c->entries);
    if (!c->full) fprintf(out, ", %llu files not read again (unchanged)", (unsigned long long)c->trusted);
    else if (c->full_reason[0]) fprintf(out, ", every file read (%s)", c->full_reason);
    fputc('\n', out);
    if (c->raced || c->unstable || c->vanished)
        fprintf(out, "  changing while captured: %llu raced, %llu unstable, %llu vanished\n",
                (unsigned long long)c->raced, (unsigned long long)c->unstable, (unsigned long long)c->vanished);
    /* Q6: never silent -- the walk skipped belay's own state directory. */
    if (c->excluded) fprintf(out, "  not recorded: belay's own state directory %s (inside the scope)\n", st->root);
}

/* ---- commands ---- */

static int open_scope(const struct opts *o, bool create, struct state *st, FILE *err) {
    struct scope sc;
    if (scope_resolve(o->scope, &sc) == -1) return failed(err, 1);
    if (state_open(&sc, create, st) == -1) {
        const int code = belay_err_code();
        state_close(st);
        return failed(err, code == BELAY_ERR_CORRUPT);
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
        rc = failed(err, 0);
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
    if (state_list(&st, &list, &n) == -1) rc = failed(err, 0);
    else {
        for (size_t i = 0; i < n; i++) {
            if (o->json) json_checkpoint(out, &st, &list[i]);
            else text_checkpoint(out, &st, &list[i]);
        }
        if (n == 0 && !o->json) fprintf(out, "no checkpoints of %s\n", st.scope.path);
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

static int mode_of(void *ctx, int side, const char *path, size_t len, uint32_t *mode) {
    struct cursor *c = &((struct modes *)ctx)->side[side];
    while (c->got == 1 && pathcmp(c->e.path, c->e.path_len, path, len) < 0)
        c->got = belay_manifest_next(c->r, &c->e);
    if (c->got != 1 || pathcmp(c->e.path, c->e.path_len, path, len) != 0) return -1;
    *mode = c->e.mode;
    return 0;
}

static int cmd_diff(const struct opts *o, FILE *out, FILE *err) {
    long from, to = 0;
    if (!parse_id(o->since, &from)) return usage(err, "diff needs --since ID, a checkpoint id");
    if (o->to != NULL && !parse_id(o->to, &to)) return usage(err, "--to needs a checkpoint id");
    struct state st;
    int rc = open_scope(o, true, &st, err);
    if (rc) return rc;
    struct checkpoint *list = NULL, now;
    size_t n = 0;
    char a[PATH_MAX + 160], b[PATH_MAX + 160], d[PATH_MAX + 200], label_a[64], label_b[64];
    struct modes m = { 0 };
    FILE *in = NULL;
    if (state_list(&st, &list, &n) == -1) { rc = failed(err, 0); goto done; }
    bool have_from = false, have_to = to == 0;
    for (size_t i = 0; i < n; i++) {
        if (list[i].id == from) have_from = true;
        if (list[i].id == to) have_to = true;
    }
    if (!have_from || !have_to) {
        fprintf(err, "belay: no checkpoint %ld of %s (belay log --scope lists them)\n",
                have_from ? to : from, st.scope.path);
        rc = EXIT_USAGE;
        goto done;
    }
    if (to == 0) {
        /* Q3: the capture is kept as a checkpoint, prefiltered as a mark. */
        const struct capture_req req = { "diff", true, false, o->full_every };
        if (state_capture(&st, &req, &now) == -1) { rc = failed(err, 0); goto done; }
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
    if (belay_diff(a, b, d, &dopts, &ds) == -1) { rc = failed(err, 0); goto done; }
    in = fopen(d, "r");
    if (in == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", d);
        rc = failed(err, 0);
        goto done;
    }
    if (o->json) {
        char buf[65536];
        size_t k;
        while ((k = fread(buf, 1, sizeof buf, in)) > 0) fwrite(buf, 1, k, out);
    } else {
        if (belay_manifest_open(a, &m.side[0].r) == -1 || belay_manifest_open(b, &m.side[1].r) == -1) {
            rc = failed(err, 0);
            goto done;
        }
        for (int s = 0; s < 2; s++) m.side[s].got = belay_manifest_next(m.side[s].r, &m.side[s].e);
        const struct receipt_opts ro = { label_a, label_b, o->all, mode_of, &m };
        if (receipt_render(in, out, &ro) == -1) { rc = failed(err, 0); goto done; }
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

int cli_main(int argc, char **argv, FILE *out, FILE *err) {
    if (argc < 2) return usage(err, NULL);
    const char *cmd = argv[1];
    if (!strcmp(cmd, "--version") || !strcmp(cmd, "version")) {
        fprintf(out, "belay %s (manifest v1, diff.v1)\n", BELAY_VERSION);
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
    if (!strcmp(cmd, "check")) return cmd_capture(&o, "check", out, err);
    if (!strcmp(cmd, "mark")) return cmd_capture(&o, "mark", out, err);
    if (!strcmp(cmd, "diff")) return cmd_diff(&o, out, err);
    return cmd_log(&o, out, err);
}
