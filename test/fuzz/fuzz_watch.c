/*
 *  Fuzz target for what `belay watch` parses from outside its own code
 *  (NOTES/watch-structure.md section 11): .belay-donttouch, which the
 *  watched process writes; a ledger line, which anything running as the
 *  user can write; and the hook's standard input.
 *
 *  The first byte picks the reader. The properties: no reader crashes or
 *  reads out of bounds on any input; what a reader accepts obeys its own
 *  limits; and an accepted step renders to lines without a fault.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "belay/error.h"
#include "cli/cli_internal.h"
#include "util/jsonr.h"
#include "util/pattern.h"
#include "watch/flag.h"
#include "watch/ledger.h"
#include "watch/lines.h"

static void dont_touch(const char *buf, size_t len) {
    struct dtlist l;
    char why[96];
    if (dtlist_parse(buf, len, &l, why, sizeof why) == -1) {
        if (why[0] == '\0') abort();                    /* a refusal always says why */
        return;
    }
    if (l.n > DT_PATTERNS_MAX || len > DT_FILE_MAX) abort();
    static const char *const paths[] = { "a", ".env", "src/x/y.c", ".git/hooks/pre-push", "a/b/c/d/e/f/g" };
    for (size_t i = 0; i < l.n; i++) {
        if (!pattern_valid(l.pat[i], l.len[i]) || pattern_globstars(l.pat[i], l.len[i]) > DT_GLOBSTARS) abort();
        for (size_t p = 0; p < sizeof paths / sizeof paths[0]; p++)
            pattern_match(l.pat[i], l.len[i], paths[p], strlen(paths[p]), PATTERN_DOTS);
    }
    for (size_t p = 0; p < sizeof paths / sizeof paths[0]; p++) flag_covers(&l, paths[p], strlen(paths[p]));
    dtlist_free(&l);
}

static void ledger_line(const char *buf, size_t len) {
    struct jval v;
    if (jsonr_parse(buf, len, &v) == -1) {
        belay_err_clear();
        return;
    }
    if (v.t == J_OBJ) {
        static struct wstate st;
        if (ledger_state(&v, &st) &&
            (st.n_open > W_OPEN_MAX || st.n_marks > W_MARK_MAX || st.n_kills > W_KILL_MAX || st.n_told > W_TOLD_MAX))
            abort();
        struct wstep s;
        if (ledger_step(&v, &s) == 0) {
            for (size_t i = 0; i < s.n_flags; i++)
                if ((unsigned)s.flags[i].kind >= WK_COUNT || s.flags[i].text == NULL) abort();
            struct wsb out = { 0 };
            const struct wwords w = { "tool call", "this turn", "" };
            lines_step(&out, &s);
            lines_summary(&out, &s, 1, "me", NULL, NULL, &w);
            free(out.p);
            wstep_free(&s);
        }
    }
    jsonr_free(&v);
}

static void hook_input(const char *buf, size_t len) {
    static struct hook_claude_in h;
    if (hook_claude_parse(buf, len, &h) == -1) return;
    /* whatever was kept is a string that ends, and a call id is one a ledger line can hold */
    if (strlen(h.session) > 96 || strlen(h.call) > 96 || strlen(h.agent) > 96 || strlen(h.cwd) >= sizeof h.cwd) abort();
    for (const char *id = h.calls; id != NULL && *id != '\0';) {
        const size_t n = strcspn(id, " ");
        char one[128];
        if (n == 0 || n > 96) abort();
        memcpy(one, id, n);
        one[n] = '\0';
        if (!ledger_id_valid(one)) abort();
        id += n + (id[n] == ' ');
    }
    free(h.calls);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    char *buf = malloc(size);           /* exactly size - 1 bytes and no terminator: an overread is caught */
    if (buf == NULL) return 0;
    memcpy(buf, data + 1, size - 1);
    switch (data[0] % 3) {
    case 0: dont_touch(buf, size - 1); break;
    case 1: ledger_line(buf, size - 1); break;
    default: hook_input(buf, size - 1); break;
    }
    free(buf);
    return 0;
}
