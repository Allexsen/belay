/*
 *  Findings and event records, the core's side (pins test/expect/finding-
 *  kinds.md and diff-events.md): what an interpreter passes is checked
 *  against its kind's row, its text rendered from the template, and the
 *  bounds hold. Expectations are written from the pins, byte for byte.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "belay/interp.h"
#include "interp/findings_internal.h"
#include "schema/finding_schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define S(x) { .s = (x), .len = sizeof(x) - 1 }
#define I(x) { .i = (x) }

static char *g_out;              /* the last thing written; freed by the next */

static const char *written_by(const struct belay_findings *f, const struct belay_events *ev) {
    size_t n;
    free(g_out);
    g_out = NULL;
    FILE *m = open_memstream(&g_out, &n);
    if (m == NULL) return "(no stream)";
    const int r = f ? findings_write(f, m) : events_write(ev, m);
    fclose(m);
    return r == 0 ? g_out : "(write failed)";
}
static const char *written(const struct belay_findings *f) { return written_by(f, NULL); }
static const char *ev_written(const struct belay_events *ev) { return written_by(NULL, ev); }

TEST(a_finding_is_its_fields_in_order_then_its_rendered_text) {
    struct belay_findings f = { 0 };
    findings_reset(&f, BELAY_INTERP_TEXT);
    const struct belay_fv v[] = { I(3), I(1), I(42) };
    ASSERT_EQ_INT(0, belay_finding(&f, FK_TEXT_CHANGED, v, 3));
    ASSERT_EQ_STR(",\"findings\":[{\"kind\":\"text_changed\",\"lines_added\":3,\"lines_deleted\":1,"
                  "\"first_changed_line\":42,\"text\":\"+3 -1 lines, first change at line 42\"}]",
                  written(&f));
    findings_free(&f);
}

TEST(strings_and_bools_render_and_escape) {
    struct belay_findings f = { 0 };
    findings_reset(&f, BELAY_INTERP_GIT);
    const struct belay_fv v[] = { S("pre\"commit"), { .b = true } };
    ASSERT_EQ_INT(0, belay_finding(&f, FK_GIT_HOOK_EXECUTABLE_CHANGED, v, 2));
    ASSERT_EQ_STR(",\"findings\":[{\"kind\":\"git_hook_executable_changed\",\"hook\":\"pre\\\"commit\","
                  "\"executable\":true,\"text\":\"hook pre\\\"commit executable: true\"}]",
                  written(&f));
    findings_free(&f);
}

TEST(no_findings_write_nothing) {
    struct belay_findings f = { 0 };
    findings_reset(&f, BELAY_INTERP_TEXT);
    ASSERT_EQ_STR("", written(&f));
    findings_free(&f);
}

/* finding-kinds.md, "The object": every way a finding can break its row. */
TEST(a_finding_that_breaks_its_row_is_invalid_finding) {
    static char big[FINDING_STRING_MAX + 1];
    memset(big, 'a', sizeof big);
    static char edge[FINDING_STRING_MAX];
    memset(edge, 'a', sizeof edge);
    const struct belay_fv ok2[] = { S("missing"), S("after") };
    const struct belay_fv bad_utf8[] = { S("mi\xffssing"), S("after") };
    const struct belay_fv nul[] = { { .s = "a\0b", .len = 3 }, S("after") };
    const struct belay_fv over[] = { { .s = big, .len = sizeof big }, S("after") };
    const struct belay_fv text_over[] = { { .s = edge, .len = sizeof edge }, S("after") };
    const struct belay_fv null_s[] = { { .s = NULL, .len = 3 }, S("after") };
    const struct { const char *why; int interp, kind; const struct belay_fv *v; size_t n; } C[] = {
        { "no kind", BELAY_INTERP_PIP, FK_UNSET, ok2, 2 },
        { "past the last kind", BELAY_INTERP_PIP, FK_COUNT, ok2, 2 },
        { "negative kind", BELAY_INTERP_PIP, -1, ok2, 2 },
        { "a field missing", BELAY_INTERP_PIP, FK_CONTENT_UNAVAILABLE, ok2, 1 },
        { "a field extra", BELAY_INTERP_PIP, FK_CONTENT_UNAVAILABLE, ok2, 3 },
        { "not UTF-8", BELAY_INTERP_PIP, FK_CONTENT_UNAVAILABLE, bad_utf8, 2 },
        { "a NUL inside", BELAY_INTERP_PIP, FK_CONTENT_UNAVAILABLE, nul, 2 },
        { "a string over 1024 bytes", BELAY_INTERP_PIP, FK_CONTENT_UNAVAILABLE, over, 2 },
        { "text over 1024 bytes", BELAY_INTERP_PIP, FK_CONTENT_UNAVAILABLE, text_over, 2 },
        { "a NULL string with a length", BELAY_INTERP_PIP, FK_CONTENT_UNAVAILABLE, null_s, 2 },
        { "another interpreter's kind", BELAY_INTERP_PIP, FK_TEXT_ADDED, ok2, 1 },
        { "the binary fallback's content kind", BELAY_INTERP_BINARY, FK_CONTENT_UNAVAILABLE, ok2, 2 },
        { "an event kind on a path", BELAY_INTERP_PIP, FK_PIP_INSTALLED, ok2, 2 },
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        struct belay_findings f = { 0 };
        findings_reset(&f, C[i].interp);
        ASSERT_EQ_INT(0, belay_finding(&f, C[i].kind, C[i].v, C[i].n));
        if (strcmp(written(&f), ",\"findings\":[{\"kind\":\"invalid_finding\",\"text\":\"invalid finding\"}]") != 0)
            BELAY_FAIL("%s: %s", C[i].why, g_out);
        findings_free(&f);
    }
    /* S3 K3: a field the template does not name is still required. */
    {
        struct belay_findings g = { 0 };
        findings_reset(&g, BELAY_INTERP_GIT);
        const struct belay_fv h[] = { S("pre-commit") };
        ASSERT_EQ_INT(0, belay_finding(&g, FK_GIT_HOOK_ADDED, h, 1));
        ASSERT_EQ_STR(",\"findings\":[{\"kind\":\"invalid_finding\",\"text\":\"invalid finding\"}]", written(&g));
        findings_free(&g);
    }
    /* S3 K6: the text bound holds when the last thing rendered is a field. */
    {
        static char x[500], y[600];
        memset(x, 'x', sizeof x);
        memset(y, 'y', sizeof y);
        struct belay_findings g = { 0 };
        findings_reset(&g, BELAY_INTERP_GIT);
        const struct belay_fv h[] = { { .s = x, .len = sizeof x }, { .s = y, .len = sizeof y } };
        ASSERT_EQ_INT(0, belay_finding(&g, FK_GIT_HEAD_CHANGED, h, 2));      /* 5 + 500 + 4 + 600 */
        ASSERT_EQ_STR(",\"findings\":[{\"kind\":\"invalid_finding\",\"text\":\"invalid finding\"}]", written(&g));
        findings_reset(&g, BELAY_INTERP_GIT);                                 /* 1,024 exactly: kept */
        const struct belay_fv k[] = { { .s = x, .len = sizeof x }, { .s = y, .len = 515 } };
        ASSERT_EQ_INT(0, belay_finding(&g, FK_GIT_HEAD_CHANGED, k, 2));
        ASSERT_TRUE(strstr(written(&g), "\"kind\":\"git_head_changed\"") != NULL);
        findings_free(&g);
    }
    /* The bounds themselves are allowed: exactly 1024 bytes of string. */
    struct belay_findings f = { 0 };
    findings_reset(&f, BELAY_INTERP_GIT);
    const struct belay_fv hook[] = { { .s = edge, .len = sizeof edge } };
    ASSERT_EQ_INT(0, belay_finding(&f, FK_GIT_HOOK_REMOVED, hook, 1));
    ASSERT_TRUE(strstr(written(&f), "invalid_finding") != NULL);    /* text: "hook " + 1024 > 1024 */
    findings_reset(&f, BELAY_INTERP_GIT);
    const struct belay_fv hook2[] = { { .s = edge, .len = FINDING_STRING_MAX - 13 } };
    ASSERT_EQ_INT(0, belay_finding(&f, FK_GIT_HOOK_REMOVED, hook2, 1));
    ASSERT_TRUE(strstr(written(&f), "\"kind\":\"git_hook_removed\"") != NULL);  /* text: 1024 exactly */
    findings_free(&f);
}

/* Decision Q4: at most 4,096 findings on a record; past that the last place
 * is one and_more counting the rest. */
TEST(past_4096_findings_the_last_is_and_more) {
    struct belay_findings f = { 0 };
    const struct belay_fv v[] = { I(1) };
    findings_reset(&f, BELAY_INTERP_TEXT);
    for (int i = 0; i < 4096; i++) ASSERT_EQ_INT(0, belay_finding(&f, FK_TEXT_ADDED, v, 1));
    const char *w = written(&f);
    ASSERT_TRUE(strstr(w, "and_more") == NULL);
    size_t n = 0;
    for (const char *p = w; (p = strstr(p, "\"kind\":")) != NULL; p++) n++;
    ASSERT_EQ_INT(4096, (int)n);

    findings_reset(&f, BELAY_INTERP_TEXT);
    for (int i = 0; i < 4098; i++) ASSERT_EQ_INT(0, belay_finding(&f, FK_TEXT_ADDED, v, 1));
    w = written(&f);
    n = 0;
    for (const char *p = w; (p = strstr(p, "\"kind\":")) != NULL; p++) n++;
    ASSERT_EQ_INT(4096, (int)n);
    const size_t l = strlen(w);
    const char tail[] = ",{\"kind\":\"and_more\",\"n\":3,\"text\":\"and 3 more\"}]";
    ASSERT_TRUE(l > sizeof tail && strcmp(w + l - (sizeof tail - 1), tail) == 0);
    findings_free(&f);
}

/* ---- events ---- */

static int ev(struct belay_events *e, int interp, int kind, const struct belay_fv *v, size_t n,
              const char *const *paths, size_t np) {
    size_t lens[16];
    for (size_t i = 0; i < np; i++) lens[i] = strlen(paths[i]);
    e->interp = interp;
    return belay_event(e, kind, v, n, paths, lens, np);
}

/* E2, E3: fields, then text, then the paths sorted bytewise, each once. */
TEST(an_event_lists_its_paths_sorted_and_once) {
    struct belay_events e;
    events_init(&e);
    const struct belay_fv v[] = { S("numpy"), S("2.1.0") };
    const char *const p[] = { "b/RECORD", "a/METADATA", "b/RECORD", "B" };
    ASSERT_EQ_INT(0, ev(&e, BELAY_INTERP_PIP, FK_PIP_INSTALLED, v, 2, p, 4));
    ASSERT_EQ_STR("{\"event\":\"pip_installed\",\"interp\":\"pip\",\"name\":\"numpy\",\"version\":\"2.1.0\","
                  "\"text\":\"installed numpy 2.1.0\",\"paths\":[\"B\",\"a/METADATA\",\"b/RECORD\"]}\n",
                  ev_written(&e));
    ASSERT_EQ_INT(1, (int)events_count(&e));
    events_free(&e);
}

/* E3: one path that is not UTF-8 makes every path base64. */
TEST(an_event_with_a_non_utf8_path_lists_them_all_in_base64) {
    struct belay_events e;
    events_init(&e);
    const struct belay_fv v[] = { S("x"), S("1") };
    const char *const p[] = { "a", "\xff" };
    ASSERT_EQ_INT(0, ev(&e, BELAY_INTERP_PIP, FK_PIP_REMOVED, v, 2, p, 2));
    ASSERT_TRUE(strstr(ev_written(&e), ",\"paths_b64\":[\"YQ==\",\"/w==\"]}\n") != NULL);
    events_free(&e);
}

/* E4: by interpreter, text, pip, dpkg, git, whatever order they were added. */
TEST(events_are_written_by_interpreter_in_the_pinned_order) {
    struct belay_events e;
    events_init(&e);
    const char *const p[] = { "x" };
    const struct belay_fv d[] = { S("bash"), S("amd64"), S("5.2") };
    const struct belay_fv q[] = { S("numpy"), S("2.1.0") };
    const struct belay_fv c[] = { S("no_store"), S("both") };
    ASSERT_EQ_INT(0, ev(&e, BELAY_INTERP_DPKG, FK_DPKG_INSTALLED, d, 3, p, 1));
    ASSERT_EQ_INT(0, ev(&e, BELAY_INTERP_PIP, FK_PIP_INSTALLED, q, 2, p, 1));
    ASSERT_EQ_INT(0, ev(&e, BELAY_INTERP_DPKG, FK_CONTENT_UNAVAILABLE, c, 2, p, 1));
    const char *w = ev_written(&e);
    const char *pip = strstr(w, "\"pip_installed\""), *dpkg = strstr(w, "\"dpkg_installed\""),
               *cu = strstr(w, "\"content_unavailable\"");
    ASSERT_TRUE(pip != NULL && dpkg != NULL && cu != NULL && pip < dpkg && dpkg < cu);
    events_free(&e);
}

/* An event that breaks its row is an interpreter bug: its events become E6's
 * one could_not_interpret, naming the paths it was given. */
TEST(an_invalid_event_fails_its_interpreter) {
    const struct belay_fv v[] = { S("numpy"), S("2.1.0") };
    const char *const p[] = { "x" };
    const struct { const char *why; int kind; size_t n, np; } C[] = {
        { "a path-level kind", FK_TEXT_ADDED, 1, 1 },
        { "no paths", FK_PIP_INSTALLED, 2, 0 },
        { "a field missing", FK_PIP_INSTALLED, 1, 1 },
        { "another interpreter's kind", FK_DPKG_INSTALLED, 2, 1 },
        { "and_more from an interpreter", FK_AND_MORE, 1, 1 },
        { "could_not_interpret from an interpreter", FK_COULD_NOT_INTERPRET, 0, 1 },
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        struct belay_events e;
        events_init(&e);
        ASSERT_EQ_INT(0, events_claim(&e, BELAY_INTERP_PIP, "z/RECORD", 8));
        ASSERT_EQ_INT(0, events_claim(&e, BELAY_INTERP_PIP, "a/RECORD", 8));
        ASSERT_EQ_INT(0, ev(&e, BELAY_INTERP_PIP, FK_PIP_INSTALLED, v, 2, p, 1));
        ASSERT_EQ_INT(0, ev(&e, BELAY_INTERP_PIP, C[i].kind, v, C[i].n, p, C[i].np));
        if (!events_broken(&e, BELAY_INTERP_PIP)) BELAY_FAIL("%s: not marked broken", C[i].why);
        ASSERT_EQ_INT(0, events_failed(&e, BELAY_INTERP_PIP));
        if (strcmp(ev_written(&e), "{\"event\":\"could_not_interpret\",\"interp\":\"pip\","
                                   "\"text\":\"could not interpret\",\"paths\":[\"a/RECORD\",\"z/RECORD\"]}\n") != 0)
            BELAY_FAIL("%s: %s", C[i].why, g_out);
        ASSERT_EQ_INT(1, (int)events_count(&e));
        events_free(&e);
    }
}

/* E6 with nothing claimed: no event at all (nothing to name). */
TEST(a_failed_interpreter_that_was_given_nothing_emits_nothing) {
    struct belay_events e;
    events_init(&e);
    ASSERT_EQ_INT(0, events_failed(&e, BELAY_INTERP_GIT));
    ASSERT_EQ_STR("", ev_written(&e));
    events_free(&e);
}

/* E5: at most 65,536 events per interpreter; the last place is and_more. */
TEST(past_65536_events_the_last_is_and_more) {
    struct belay_events e;
    events_init(&e);
    const struct belay_fv v[] = { S("n"), S("1") };
    const char *const p[] = { "x" };
    for (int i = 0; i < 65536 + 4; i++) ASSERT_EQ_INT(0, ev(&e, BELAY_INTERP_PIP, FK_PIP_INSTALLED, v, 2, p, 1));
    for (int i = 0; i < 65536; i++) ASSERT_EQ_INT(0, ev(&e, BELAY_INTERP_DPKG, FK_CONTENT_UNAVAILABLE,
                                                       (const struct belay_fv[]){ S("missing"), S("after") }, 2, p, 1));
    const char *w = ev_written(&e);
    size_t lines = 0, more = 0;
    for (const char *q = w; *q; q++) lines += *q == '\n';
    for (const char *q = w; (q = strstr(q, "\"and_more\"")) != NULL; q++) more++;
    ASSERT_EQ_INT(2 * 65536, (int)lines);
    ASSERT_EQ_INT(1, (int)more);
    ASSERT_TRUE(strstr(w, "{\"event\":\"and_more\",\"interp\":\"pip\",\"n\":5,\"text\":\"and 5 more\",\"paths\":[]}\n") != NULL);
    events_free(&e);
}

int main(void) {
    RUN(a_finding_is_its_fields_in_order_then_its_rendered_text);
    RUN(strings_and_bools_render_and_escape);
    RUN(no_findings_write_nothing);
    RUN(a_finding_that_breaks_its_row_is_invalid_finding);
    RUN(past_4096_findings_the_last_is_and_more);
    RUN(an_event_lists_its_paths_sorted_and_once);
    RUN(an_event_with_a_non_utf8_path_lists_them_all_in_base64);
    RUN(events_are_written_by_interpreter_in_the_pinned_order);
    RUN(an_invalid_event_fails_its_interpreter);
    RUN(a_failed_interpreter_that_was_given_nothing_emits_nothing);
    RUN(past_65536_events_the_last_is_and_more);
    free(g_out);
    return belay_test_report();
}
