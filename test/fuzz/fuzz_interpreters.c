/*
 *  Fuzz target for the interpreters (Phase 4 proof standard: one per
 *  interpreter, over (before, after) content pairs). The first byte picks
 *  the interpreter and the file it is given; the rest, split at the first
 *  "\n--\n", is the stored copy before and after, written to a store as a
 *  capture would. For ANY content: no crash, no out-of-bounds access; the
 *  output valid UTF-8; every event line an object starting `{"event":"` and
 *  ending `}`; at most 4,096 findings; no built-in ever adds an event that
 *  breaks its kind's row (it fails its end hook instead, E6); text, pip and
 *  dpkg never an invalid_finding (their strings are checked before they are
 *  given); and the same bytes twice.
 */
#define _GNU_SOURCE
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/interp.h"
#include "belay/json.h"
#include "belay/manifest.h"
#include "interp/findings_internal.h"
#include "schema/finding_schema.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_store[128];

/* An invariant broke: say which, then crash for the fuzzer. */
#define BROKEN(what) (fprintf(stderr, "fuzz_interpreters: %s (line %d)\n", what, __LINE__), abort())

static const struct { enum belay_interp_id id; const char *abs; } CASES[] = {
    { BELAY_INTERP_TEXT, "/s/notes.txt" },
    { BELAY_INTERP_PIP,  "/s/site-packages/six-1.16.0.dist-info/RECORD" },
    { BELAY_INTERP_DPKG, "/s/var/lib/dpkg/status" },
    { BELAY_INTERP_GIT,  "/s/r/.git/HEAD" },
    { BELAY_INTERP_GIT,  "/s/r/.git/refs/heads/main" },
    { BELAY_INTERP_GIT,  "/s/r/.git/packed-refs" },
    { BELAY_INTERP_GIT,  "/s/r/.git/logs/HEAD" },
    { BELAY_INTERP_GIT,  "/s/r/.git/hooks/pre-commit" },
};
#define NCASES (sizeof CASES / sizeof CASES[0])

static void put(const uint8_t *d, size_t n, char hex[65]) {
    struct belay_sha256 c;
    uint8_t h[32];
    char p[300];
    belay_sha256_init(&c);
    belay_sha256_update(&c, d, n);
    belay_sha256_final(&c, h);
    belay_hex_encode(hex, h, sizeof h);
    snprintf(p, sizeof p, "%s/%.2s", g_store, hex);
    mkdir(p, 0700);
    snprintf(p, sizeof p, "%s/%.2s/%s", g_store, hex, hex + 2);
    FILE *f = fopen(p, "wb");
    if (f == NULL) abort();
    if (n && fwrite(d, 1, n, f) != n) abort();
    fclose(f);
}

static void check_utf8(const char *s, size_t n) {
    if (!belay_utf8_valid(s, n)) BROKEN("output not UTF-8");
}

/* One run: the findings and the event lines, as the diff would write them. */
static char *once(size_t which, const char *outcome, struct belay_entry *b, struct belay_entry *a,
                  struct belay_content *c, size_t *len) {
    const struct belay_interp *it = belay_interp_builtin(CASES[which].id);
    const char *abs = CASES[which].abs;
    struct belay_findings f;
    struct belay_events ev;
    memset(&f, 0, sizeof f);
    findings_reset(&f, CASES[which].id);
    events_init(&ev);
    void *st = it->begin ? it->begin() : NULL;
    if (it->end) events_claim(&ev, CASES[which].id, abs + 3, strlen(abs) - 3);
    const struct belay_interp_input in = { abs + 3, strlen(abs) - 3, abs, strlen(abs), b, a, outcome, 0, c };
    enum belay_interp_result r = it->explain(st, &in, &f);
    if (findings_oom(&f)) BROKEN("out of memory");
    if (r != BELAY_INTERP_FINDINGS) findings_reset(&f, CASES[which].id);
    if (r == BELAY_INTERP_ERROR) belay_finding(&f, FK_COULD_NOT_INTERPRET, NULL, 0);
    ev.interp = CASES[which].id;
    if (it->end) {
        const enum belay_interp_result e = it->end(st, &ev);
        if (events_broken(&ev, CASES[which].id)) BROKEN("an event broke its row");
        if (e == BELAY_INTERP_ERROR) events_failed(&ev, CASES[which].id);
    }
    belay_err_clear();
    char *out = NULL;
    FILE *m = open_memstream(&out, len);
    if (m == NULL || findings_write(&f, m) != 0 || fputs("\n", m) == EOF || events_write(&ev, m) != 0) abort();
    fclose(m);
    if (findings_count(&f) > FINDINGS_PER_RECORD) BROKEN("over 4,096 findings");
    for (const char *l = memchr(out, '\n', *len); l != NULL && l + 1 < out + *len;) {
        const char *e = memchr(l + 1, '\n', (size_t)(out + *len - l - 1));     /* each event line */
        if (e == NULL || strncmp(l + 1, "{\"event\":\"", 10) != 0 || e[-1] != '}')
            BROKEN("an event line that is not one object");
        l = e;
    }
    if (CASES[which].id != BELAY_INTERP_GIT && strstr(out, "\"invalid_finding\"") != NULL)
        BROKEN("an invalid_finding from text, pip or dpkg");
    findings_free(&f);
    events_free(&ev);
    return out;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    if (g_store[0] == '\0') {
        snprintf(g_store, sizeof g_store, "/tmp/belay_fuzz_interp_%d", (int)getpid());
        mkdir(g_store, 0700);
    }
    const size_t which = data[0] % NCASES;
    const int shape = (data[0] / NCASES) % 4;       /* modified, added, removed, metadata_only */
    const int exec = data[1] & 1;
    data += 2;
    size = size - 2;
    const uint8_t *sep = memmem(data, size, "\n--\n", 4);
    const size_t bl = sep ? (size_t)(sep - data) : size / 2;
    const uint8_t *after = sep ? sep + 4 : data + bl;
    const size_t al = size - (size_t)(after - data);

    struct belay_entry b, a;
    memset(&b, 0, sizeof b);
    memset(&a, 0, sizeof a);
    b.type = a.type = BELAY_T_REG;
    b.mode = exec ? 0755 : 0644;
    a.mode = 0755;
    b.has_stored = a.has_stored = true;
    put(data, bl, b.stored_hex);
    put(after, al, a.stored_hex);
    struct belay_content *c = NULL;
    if (belay_content_open(g_store, &c) == -1) abort();

    static const char *const OUTCOME[] = { "modified", "added", "removed", "metadata_only" };
    struct belay_entry *pb = shape == 1 ? NULL : &b, *pa = shape == 2 ? NULL : &a;
    size_t n1, n2;
    char *o1 = once(which, OUTCOME[shape], pb, pa, c, &n1);
    char *o2 = once(which, OUTCOME[shape], pb, pa, c, &n2);
    if (n1 != n2 || memcmp(o1, o2, n1) != 0) BROKEN("not deterministic");
    check_utf8(o1, n1);
    free(o1);
    free(o2);
    belay_content_close(c);
    return 0;
}
