/*
 *  What the tests of the system interpreters share (test/expect/system-
 *  interpreters.md): a tree of real files under a temporary directory,
 *  captured with the real capture and compared with the real diff, so a
 *  test sees the claims, the kept copies, the lookups and the events as a
 *  user's `belay diff` would; and, for the cases no capture of this binary
 *  produces (a sealed entry, a copy gone from the store), one interpreter
 *  driven by hand over entries written here. Every expectation is written
 *  by hand from the pin, never from a run.
 */
#ifndef BELAY_SYS_TEST_H
#define BELAY_SYS_TEST_H

#define _GNU_SOURCE
#include "belay_test.h"
#include "belay/diff.h"
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/interp.h"
#include "belay/manifest.h"
#include "interp/findings_internal.h"
#include "interp/lookup_internal.h"
#include "schema/finding_schema.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SYS_UNUSED __attribute__((unused))

static char g_dir[200];         /* the temporary directory: root/, store/, m<k>, d */

static SYS_UNUSED void t_begin(const char *name) {
    const char *tmp = getenv("TMPDIR");
    umask(022);                 /* the fixtures' modes are the tests', not the caller's */
    snprintf(g_dir, sizeof g_dir, "%s/belay-%s-XXXXXX", tmp != NULL && tmp[0] ? tmp : "/tmp", name);
    if (mkdtemp(g_dir) == NULL) { perror("mkdtemp"); exit(2); }
    char p[400];
    snprintf(p, sizeof p, "%s/root", g_dir);
    mkdir(p, 0755);
}

static SYS_UNUSED void t_end(void) {
    char cmd[900];
    snprintf(cmd, sizeof cmd, "chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    if (system(cmd) != 0) { /* best effort */ }
}

/* A new, empty tree and store (one test's fixtures never reach another's). */
static SYS_UNUSED void t_reset(void) {
    char cmd[900];
    snprintf(cmd, sizeof cmd, "chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s/root' '%s/store' && mkdir '%s/root'",
             g_dir, g_dir, g_dir, g_dir);
    if (system(cmd) != 0) BELAY_FAIL("cannot reset %s", g_dir);
}

static SYS_UNUSED void t_parents(const char *rel) {
    char p[700];
    snprintf(p, sizeof p, "%s/root/%s", g_dir, rel);
    for (char *s = p + strlen(g_dir) + 6; (s = strchr(s, '/')) != NULL; s++) {
        *s = '\0';
        mkdir(p, 0755);
        *s = '/';
    }
}

/* `n` bytes as the file `rel` of the tree, mode `mode`. */
static SYS_UNUSED void t_bytes(const char *rel, const char *data, size_t n, unsigned mode) {
    char p[700];
    t_parents(rel);
    snprintf(p, sizeof p, "%s/root/%s", g_dir, rel);
    unlink(p);
    FILE *f = fopen(p, "wb");
    if (f == NULL) { BELAY_FAIL("cannot write %s: %s", p, strerror(errno)); return; }
    if (n && fwrite(data, 1, n, f) != n) BELAY_FAIL("short write to %s", p);
    fclose(f);
    if (chmod(p, (mode_t)mode) != 0) BELAY_FAIL("chmod %s", p);
}
static SYS_UNUSED void t_file(const char *rel, const char *text, unsigned mode) { t_bytes(rel, text, strlen(text), mode); }

static SYS_UNUSED void t_link(const char *rel, const char *target) {
    char p[700];
    t_parents(rel);
    snprintf(p, sizeof p, "%s/root/%s", g_dir, rel);
    unlink(p);
    if (symlink(target, p) != 0) BELAY_FAIL("symlink %s: %s", p, strerror(errno));
}

static SYS_UNUSED void t_dir(const char *rel) {
    char p[700];
    snprintf(p, sizeof p, "%s/", rel);
    t_parents(p);
}

static SYS_UNUSED void t_rm(const char *rel) {
    char p[700];
    snprintf(p, sizeof p, "%s/root/%s", g_dir, rel);
    if (unlink(p) != 0 && rmdir(p) != 0) BELAY_FAIL("cannot remove %s: %s", p, strerror(errno));
}

/* Captures the tree as manifest `k`, copies kept in the store. */
static SYS_UNUSED int t_snap(int k) {
    char m[400], root[400], store[400];
    snprintf(m, sizeof m, "%s/m%d", g_dir, k);
    snprintf(root, sizeof root, "%s/root", g_dir);
    snprintf(store, sizeof store, "%s/store", g_dir);
    struct belay_manifest_opts o;
    memset(&o, 0, sizeof o);
    o.hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT;
    o.store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT;
    o.store_dir = store;
    unlink(m);
    if (belay_manifest_write(m, root, &o, NULL) != 0) {
        BELAY_FAIL("capture %d: %s", k, belay_err_msg());
        belay_err_clear();
        return -1;
    }
    return 0;
}

static char *g_text;            /* the last diff read, or its event lines */

static SYS_UNUSED char *t_slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    size_t cap = 1 << 16, n = 0, got;
    char *b = malloc(cap);
    while (b != NULL && (got = fread(b + n, 1, cap - n - 1, f)) > 0) {
        n += got;
        if (n + 1 == cap) { char *q = realloc(b, cap *= 2); if (q == NULL) { free(b); b = NULL; } else b = q; }
    }
    fclose(f);
    if (b != NULL) b[n] = '\0';
    return b;
}

/* The diff of manifests a and b with the store, whole; "" with a failure
 * said when it fails. With `shadow`, the two captures' per-line digest files
 * (accounts, SA-6) are given as the CLI gives them. */
static SYS_UNUSED const char *t_diff_opts(int a, int b, const struct belay_diff_opts *given) {
    char ma[400], mb[400], d[400], store[400];
    snprintf(ma, sizeof ma, "%s/m%d", g_dir, a);
    snprintf(mb, sizeof mb, "%s/m%d", g_dir, b);
    snprintf(d, sizeof d, "%s/d", g_dir);
    snprintf(store, sizeof store, "%s/store", g_dir);
    struct belay_diff_opts o;
    memset(&o, 0, sizeof o);
    if (given != NULL) o = *given;
    o.store_dir = store;
    free(g_text);
    g_text = NULL;
    if (belay_diff(ma, mb, d, &o, NULL) != 0) {
        BELAY_FAIL("diff %d %d: %s", a, b, belay_err_msg());
        belay_err_clear();
        return "";
    }
    g_text = t_slurp(d);
    return g_text != NULL ? g_text : "";
}
static SYS_UNUSED const char *t_diff(int a, int b) { return t_diff_opts(a, b, NULL); }

/* Only the event lines of `diff`, in place. */
static SYS_UNUSED const char *t_only_events(char *diff) {
    char *w = diff;
    for (char *l = diff; l != NULL && *l; ) {
        char *nl = strchr(l, '\n');
        const size_t n = nl ? (size_t)(nl - l) + 1 : strlen(l);
        if (strncmp(l, "{\"event\":", 9) == 0) { memmove(w, l, n); w += n; }
        l = nl ? nl + 1 : NULL;
    }
    if (w != NULL) *w = '\0';
    return diff != NULL ? diff : "";
}

/* The event lines of the diff of manifests a and b. */
static SYS_UNUSED const char *t_events(int a, int b) {
    t_diff(a, b);
    return t_only_events(g_text);
}

/* The record of `path` in the last whole diff read (t_diff), as its line,
 * or "" when it has none. Static slot. */
static SYS_UNUSED const char *t_record(const char *diff, const char *path) {
    static char line[70000];
    char key[4200];
    snprintf(key, sizeof key, "{\"path\":\"%s\",", path);
    const char *l = strstr(diff, key);
    line[0] = '\0';
    if (l == NULL || (l != diff && l[-1] != '\n')) return line;
    const char *nl = strchr(l, '\n');
    snprintf(line, sizeof line, "%.*s", (int)(nl ? nl - l : (long)strlen(l)), l);
    return line;
}

/* ---- one interpreter by hand: a store of objects named by their sha256 ---- */

static SYS_UNUSED const char *t_put_n(const char *data, size_t n) {
    static char hex[16][65];
    static int k;
    char *h = hex[k++ % 16], p[500];
    struct belay_sha256 c;
    uint8_t dg[32];
    belay_sha256_init(&c);
    belay_sha256_update(&c, data, n);
    belay_sha256_final(&c, dg);
    belay_hex_encode(h, dg, sizeof dg);
    snprintf(p, sizeof p, "%s/store", g_dir);
    mkdir(p, 0700);
    snprintf(p, sizeof p, "%s/store/%.2s", g_dir, h);
    mkdir(p, 0700);
    snprintf(p, sizeof p, "%s/store/%.2s/%s", g_dir, h, h + 2);
    FILE *f = fopen(p, "wb");
    if (f == NULL) return h;
    if (n && fwrite(data, 1, n, f) != n) { /* the assertions say */ }
    fclose(f);
    return h;
}
static SYS_UNUSED const char *t_put(const char *text) { return t_put_n(text, strlen(text)); }

static SYS_UNUSED struct belay_entry t_entry(const char *path, enum belay_entry_type type, unsigned mode,
                                             const char *stored) {
    struct belay_entry e;
    memset(&e, 0, sizeof e);
    e.path_len = strlen(path);
    memcpy(e.path, path, e.path_len);
    e.type = type;
    e.mode = mode;
    if (stored != NULL) {
        e.has_stored = true;
        snprintf(e.stored_hex, sizeof e.stored_hex, "%s", stored);
    }
    return e;
}

struct t_run {
    const struct belay_interp *it;
    enum belay_interp_id id;
    void *state;
    struct belay_findings f;
    struct belay_events ev;
    struct belay_content *c;
    struct belay_lookup lk;
    enum belay_interp_result last;
    char *out;
};

static SYS_UNUSED void tr_begin(struct t_run *r, enum belay_interp_id id) {
    char store[400];
    memset(r, 0, sizeof *r);
    r->id = id;
    r->it = belay_interp_builtin(id);
    r->state = r->it->begin ? r->it->begin() : NULL;
    events_init(&r->ev);
    snprintf(store, sizeof store, "%s/store", g_dir);
    mkdir(store, 0700);
    if (belay_content_open(store, &r->c) == -1) { r->c = NULL; belay_err_clear(); }
    lookup_init(&r->lk, r->c);
}

static SYS_UNUSED const char *tr_capture(struct t_run *r, bool events) {
    size_t n;
    free(r->out);
    r->out = NULL;
    FILE *m = open_memstream(&r->out, &n);
    if (m == NULL) return "(no stream)";
    const int rc = events ? events_write(&r->ev, m) : findings_write(&r->f, m);
    fclose(m);
    return rc == 0 ? r->out : "(write failed)";
}

/* One path as the diff gives it, the scope "/s": the path's findings. */
static SYS_UNUSED const char *tr_path(struct t_run *r, const char *rel, const struct belay_entry *b,
                                      const struct belay_entry *a, const char *outcome) {
    char abs[4200];
    snprintf(abs, sizeof abs, "/s/%s", rel);
    findings_reset(&r->f, r->id);
    if (r->it->end != NULL) events_claim(&r->ev, r->id, rel, strlen(rel));
    const struct belay_interp_input in = { rel, strlen(rel), abs, strlen(abs), b, a, outcome, 0, r->c };
    r->last = r->it->explain ? r->it->explain(r->state, &in, &r->f) : BELAY_INTERP_DECLINE;
    if (r->last == BELAY_INTERP_DECLINE) findings_reset(&r->f, r->id);
    if (r->last == BELAY_INTERP_ERROR) {
        findings_reset(&r->f, r->id);
        findings_core(&r->f, FK_COULD_NOT_INTERPRET);
    }
    return tr_capture(r, false);
}

/* The lookups and the end hook as the diff runs them, the after-manifest
 * being `after[0..n)` (in path order): the event lines. */
static SYS_UNUSED const char *tr_end(struct t_run *r, const struct belay_entry *after, size_t n) {
    bool failed = false;
    r->lk.current = (int)r->id;
    for (int round = 0; round < BELAY_LOOKUP_ROUNDS && r->it->prepare != NULL && !failed; round++) {
        if (r->it->prepare(r->state, &r->lk) == BELAY_INTERP_ERROR) failed = true;
        if (lookup_wanted(&r->lk) == 0) break;
        for (size_t i = 0; i < n; i++) lookup_feed(&r->lk, &after[i]);
        lookup_round_end(&r->lk);
        if (r->lk.hook_failed[r->id]) failed = true;
    }
    if (lookup_owner_pending(&r->lk)) {
        for (size_t i = 0; i < n; i++) lookup_owner_feed(&r->lk, &after[i]);
        lookup_owner_done(&r->lk);
    }
    r->ev.interp = r->id;
    const enum belay_interp_result e = r->it->end ? r->it->end(r->state, &r->ev) : BELAY_INTERP_DECLINE;
    r->state = NULL;
    if (failed || e == BELAY_INTERP_ERROR || events_broken(&r->ev, r->id)) events_failed(&r->ev, r->id);
    return tr_capture(r, true);
}

static SYS_UNUSED void tr_free(struct t_run *r) {
    if (r->state != NULL && r->it->end != NULL) r->it->end(r->state, NULL);
    findings_free(&r->f);
    events_free(&r->ev);
    lookup_free(&r->lk);
    belay_content_close(r->c);
    free(r->out);
}

#endif
