/*
 *  The built-in interpreters, one by one (finding-kinds.md, diff-events.md):
 *  each given paths as the diff gives them -- the entries, the verdict, a
 *  store -- and its findings and events read back as the diff would write
 *  them. Fixtures are written from the formats' documentation (deb-control(5)
 *  and dpkg's status database, PEP 376 and the wheel spec's RECORD,
 *  gitrepository-layout(5) and git-update-ref(1)), and every expectation by
 *  hand from the pins, byte for byte, never from a run.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/interp.h"
#include "belay/manifest.h"
#include "interp/findings_internal.h"
#include "schema/finding_schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_store[256];

/* ---- a store, written by hand: objects named by their sha256 ---- */

static void sha_hex(const char *data, size_t n, char out[65]) {
    struct belay_sha256 c;
    uint8_t d[32];
    belay_sha256_init(&c);
    belay_sha256_update(&c, data, n);
    belay_sha256_final(&c, d);
    belay_hex_encode(out, d, sizeof d);
}

/* `data` stored under `name` (its own hash unless a name is given). */
static void put_as(const char *name, const char *data, size_t n) {
    char p[400];
    snprintf(p, sizeof p, "%s/%.2s", g_store, name);
    mkdir(g_store, 0700);
    mkdir(p, 0700);
    snprintf(p, sizeof p, "%s/%.2s/%s", g_store, name, name + 2);
    FILE *f = fopen(p, "wb");
    if (f == NULL) return;
    if (n && fwrite(data, 1, n, f) != n) { /* the assertions say */ }
    fclose(f);
}

/* A stored copy of `data`: its name, in a static slot (8 live at once). */
static const char *put(const char *data) {
    static char hex[8][65];
    static int k;
    char *h = hex[k++ % 8];
    sha_hex(data, strlen(data), h);
    put_as(h, data, strlen(data));
    return h;
}

/* A name no object has. */
#define ABSENT "0000000000000000000000000000000000000000000000000000000000000000"

static struct belay_entry file(const char *stored, unsigned mode) {
    struct belay_entry e;
    memset(&e, 0, sizeof e);
    e.type = BELAY_T_REG;
    e.mode = mode ? mode : 0644;
    if (stored != NULL) {
        e.has_stored = true;
        snprintf(e.stored_hex, sizeof e.stored_hex, "%s", stored);
    }
    return e;
}

static struct belay_entry other(enum belay_entry_type t, unsigned mode) {
    struct belay_entry e;
    memset(&e, 0, sizeof e);
    e.type = t;
    e.mode = mode;
    return e;
}

/* ---- running one interpreter over paths, then its end hook ---- */

struct run {
    const struct belay_interp *it;
    enum belay_interp_id id;
    void *state;
    struct belay_findings f;
    struct belay_events ev;
    struct belay_content *c;
    enum belay_interp_result last;
    char *out;                  /* the last findings or events written */
};

static void r_begin(struct run *r, enum belay_interp_id id, bool store) {
    memset(r, 0, sizeof *r);
    r->id = id;
    r->it = belay_interp_builtin(id);
    r->state = r->it->begin ? r->it->begin() : NULL;
    events_init(&r->ev);
    if (store) {
        mkdir(g_store, 0700);
        if (belay_content_open(g_store, &r->c) == -1) r->c = NULL;
    }
}

static const char *capture(struct run *r, bool events) {
    size_t n;
    free(r->out);
    r->out = NULL;
    FILE *m = open_memstream(&r->out, &n);
    if (m == NULL) return "(no stream)";
    const int rc = events ? events_write(&r->ev, m) : findings_write(&r->f, m);
    fclose(m);
    return rc == 0 ? r->out : "(write failed)";
}

/* One path, `abs` under the scope "/s": its findings as the record carries
 * them (`,"findings":[...]`, or "" for none). */
static const char *r_path(struct run *r, const char *abs, const struct belay_entry *b,
                          const struct belay_entry *a, const char *outcome) {
    const char *rel = abs + 3;
    findings_reset(&r->f, r->id);
    if (r->it->end != NULL) events_claim(&r->ev, r->id, rel, strlen(rel));
    const struct belay_interp_input in = { rel, strlen(rel), abs, strlen(abs), b, a, outcome, 0, r->c };
    r->last = r->it->explain(r->state, &in, &r->f);
    if (r->last == BELAY_INTERP_DECLINE) findings_reset(&r->f, r->id);
    if (r->last == BELAY_INTERP_ERROR) {
        findings_reset(&r->f, r->id);
        belay_finding(&r->f, FK_COULD_NOT_INTERPRET, NULL, 0);
    }
    return capture(r, false);
}

/* The end hook, as the diff runs it (E6 on failure): the event lines. */
static const char *r_end(struct run *r) {
    r->ev.interp = r->id;
    const enum belay_interp_result e = r->it->end ? r->it->end(r->state, &r->ev) : BELAY_INTERP_DECLINE;
    if (e == BELAY_INTERP_ERROR || events_broken(&r->ev, r->id)) events_failed(&r->ev, r->id);
    return capture(r, true);
}

static void r_free(struct run *r) {
    findings_free(&r->f);
    events_free(&r->ev);
    belay_content_close(r->c);
    free(r->out);
}

#define F1(x) ",\"findings\":[" x "]"

/* ================================ text ================================= */

TEST(text_counts_lines_by_their_longest_common_subsequence) {
    struct run r;
    r_begin(&r, BELAY_INTERP_TEXT, true);
    const struct belay_entry b = file(put("a\nb\nc\n"), 0), a = file(put("a\nB\nc\nd\n"), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"text_changed\",\"lines_added\":2,\"lines_deleted\":1,"
                     "\"first_changed_line\":2,\"text\":\"+2 -1 lines, first change at line 2\"}"),
                  r_path(&r, "/s/notes.txt", &b, &a, "modified"));
    /* A last line without a newline is a line, and differs from one with. */
    const struct belay_entry b2 = file(put("x\ny"), 0), a2 = file(put("x\ny\n"), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"text_changed\",\"lines_added\":1,\"lines_deleted\":1,"
                     "\"first_changed_line\":2,\"text\":\"+1 -1 lines, first change at line 2\"}"),
                  r_path(&r, "/s/t", &b2, &a2, "modified"));
    /* Lines appended: the first change is past before's last line. */
    const struct belay_entry b3 = file(put("x\n"), 0), a3 = file(put("x\ny\n"), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"text_changed\",\"lines_added\":1,\"lines_deleted\":0,"
                     "\"first_changed_line\":2,\"text\":\"+1 -0 lines, first change at line 2\"}"),
                  r_path(&r, "/s/t", &b3, &a3, "modified"));
    r_free(&r);
}

TEST(text_added_and_removed_give_their_line_count) {
    struct run r;
    r_begin(&r, BELAY_INTERP_TEXT, true);
    const struct belay_entry a = file(put("one\ntwo"), 0), e = file(put(""), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"text_added\",\"lines\":2,\"text\":\"2 lines\"}"),
                  r_path(&r, "/s/new", NULL, &a, "added"));
    ASSERT_EQ_STR(F1("{\"kind\":\"text_removed\",\"lines\":0,\"text\":\"0 lines\"}"),
                  r_path(&r, "/s/old", &e, NULL, "removed"));
    r_free(&r);
}

/* Past 2,000 lines of edit distance the counts are not computed. */
TEST(text_past_2000_lines_of_difference_is_rewritten) {
    static char x[30000], y[30000];
    size_t wx = 0, wy = 0;
    for (int i = 0; i < 1001; i++) {
        wx += (size_t)snprintf(x + wx, sizeof x - wx, "a%d\n", i);
        wy += (size_t)snprintf(y + wy, sizeof y - wy, "b%d\n", i);
    }
    struct run r;
    r_begin(&r, BELAY_INTERP_TEXT, true);
    struct belay_entry b = file(put(x), 0), a = file(put(y), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"text_rewritten\",\"lines_before\":1001,\"lines_after\":1001,"
                     "\"first_changed_line\":1,\"text\":\"rewritten: 1001 lines before, 1001 after, "
                     "first change at line 1\"}"),
                  r_path(&r, "/s/big", &b, &a, "modified"));
    /* 1,000 replaced is 2,000 lines of difference: still counted. */
    wy = 0;
    for (int i = 0; i < 1001; i++)
        wy += (size_t)snprintf(y + wy, sizeof y - wy, i == 0 ? "a%d\n" : "b%d\n", i);
    a = file(put(y), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"text_changed\",\"lines_added\":1000,\"lines_deleted\":1000,"
                     "\"first_changed_line\":2,\"text\":\"+1000 -1000 lines, first change at line 2\"}"),
                  r_path(&r, "/s/big", &b, &a, "modified"));
    r_free(&r);
}

TEST(text_describes_only_a_proven_change_of_content) {
    struct run r;
    r_begin(&r, BELAY_INTERP_TEXT, true);
    const struct belay_entry b = file(put("a\n"), 0), a = file(put("b\n"), 0);
    ASSERT_EQ_STR("", r_path(&r, "/s/f", &b, &a, "metadata_only"));
    ASSERT_EQ_STR("", r_path(&r, "/s/f", &b, &a, "unknown"));
    r_free(&r);
}

/* Decision 2026-10-31: never a silent decline where a copy cannot be read. */
TEST(text_says_why_a_copy_cannot_be_read) {
    struct run r;
    r_begin(&r, BELAY_INTERP_TEXT, false);                  /* no store */
    const struct belay_entry b = file(put("a\n"), 0), a = file(put("b\n"), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"content_unavailable\",\"reason\":\"no_store\",\"side\":\"before\","
                     "\"text\":\"content unavailable (before): no_store\"},"
                     "{\"kind\":\"content_unavailable\",\"reason\":\"no_store\",\"side\":\"after\","
                     "\"text\":\"content unavailable (after): no_store\"}"),
                  r_path(&r, "/s/f", &b, &a, "modified"));
    r_free(&r);

    r_begin(&r, BELAY_INTERP_TEXT, true);
    const struct belay_entry gone = file(ABSENT, 0);
    put_as("1111111111111111111111111111111111111111111111111111111111111111", "not that\n", 9);
    const struct belay_entry bad = file("1111111111111111111111111111111111111111111111111111111111111111", 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"content_unavailable\",\"reason\":\"missing\",\"side\":\"after\","
                     "\"text\":\"content unavailable (after): missing\"}"),
                  r_path(&r, "/s/f", &b, &gone, "modified"));
    ASSERT_EQ_STR(F1("{\"kind\":\"content_unavailable\",\"reason\":\"corrupt\",\"side\":\"before\","
                     "\"text\":\"content unavailable (before): corrupt\"}"),
                  r_path(&r, "/s/f", &bad, NULL, "removed"));
    ASSERT_EQ_INT(BELAY_OK, belay_err_code());          /* handled, not left set */
    r_free(&r);
}

TEST(text_says_a_copy_over_its_bound_is_too_large) {
    const size_t n = 16u * 1024u * 1024u + 1;
    char *big = malloc(n + 1);
    REQUIRE(big != NULL);
    memset(big, 'x', n);
    big[n] = '\0';
    struct run r;
    r_begin(&r, BELAY_INTERP_TEXT, true);
    const struct belay_entry a = file(put(big), 0);
    free(big);
    ASSERT_EQ_STR(F1("{\"kind\":\"content_unavailable\",\"reason\":\"too_large\",\"side\":\"after\","
                     "\"text\":\"content unavailable (after): too_large\"}"),
                  r_path(&r, "/s/huge", NULL, &a, "added"));
    r_free(&r);
}

/* ================================= git ================================= */

#define OA "1111111111111111111111111111111111111111"
#define OB "2222222222222222222222222222222222222222"
#define OC "3333333333333333333333333333333333333333"
#define OD "4444444444444444444444444444444444444444"

TEST(git_head_names_the_symbolic_ref_or_the_commit) {
    struct run r;
    r_begin(&r, BELAY_INTERP_GIT, true);
    const struct belay_entry b = file(put("ref: refs/heads/main\n"), 0);
    const struct belay_entry a = file(put("ref: refs/heads/dev\n"), 0);
    const struct belay_entry d = file(put(OA "\n"), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"git_head_changed\",\"from\":\"refs/heads/main\",\"to\":\"refs/heads/dev\","
                     "\"text\":\"HEAD refs/heads/main -> refs/heads/dev\"}"),
                  r_path(&r, "/s/repo/.git/HEAD", &b, &a, "modified"));
    ASSERT_EQ_STR(F1("{\"kind\":\"git_head_changed\",\"from\":\"refs/heads/dev\",\"to\":\"" OA "\","
                     "\"text\":\"HEAD refs/heads/dev -> " OA "\"}"),
                  r_path(&r, "/s/repo/.git/HEAD", &a, &d, "modified"));
    r_free(&r);
}

TEST(git_loose_refs_are_created_deleted_and_moved) {
    struct run r;
    r_begin(&r, BELAY_INTERP_GIT, true);
    const struct belay_entry x = file(put(OA "\n"), 0), y = file(put(OB "\n"), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"git_ref_created\",\"ref\":\"refs/heads/x\",\"to\":\"" OA "\","
                     "\"text\":\"created refs/heads/x at " OA "\"}"),
                  r_path(&r, "/s/r/.git/refs/heads/x", NULL, &x, "added"));
    ASSERT_EQ_STR(F1("{\"kind\":\"git_ref_deleted\",\"ref\":\"refs/tags/v1\",\"from\":\"" OA "\","
                     "\"text\":\"deleted refs/tags/v1 (was " OA ")\"}"),
                  r_path(&r, "/s/r/.git/refs/tags/v1", &x, NULL, "removed"));
    ASSERT_EQ_STR(F1("{\"kind\":\"git_ref_moved\",\"ref\":\"refs/heads/main\",\"from\":\"" OA "\",\"to\":\"" OB "\","
                     "\"text\":\"refs/heads/main " OA " -> " OB "\"}"),
                  r_path(&r, "/s/r/.git/refs/heads/main", &x, &y, "modified"));
    /* A ref whose name holds "/.git/" is still the outer repository's. */
    ASSERT_TRUE(strstr(r_path(&r, "/s/r/.git/refs/heads/.git/z", NULL, &x, "added"),
                       "\"ref\":\"refs/heads/.git/z\"") != NULL);
    r_free(&r);
}

TEST(git_packed_refs_are_compared_ref_by_ref) {
    struct run r;
    r_begin(&r, BELAY_INTERP_GIT, true);
    const struct belay_entry b = file(put("# pack-refs with: peeled fully-peeled sorted \n"
                                          OA " refs/heads/a\n" OB " refs/tags/v1\n^" OC "\n"
                                          OD " refs/heads/gone\n"), 0);
    const struct belay_entry a = file(put("# pack-refs with: peeled fully-peeled sorted \n"
                                          OA " refs/heads/a\n" OC " refs/heads/b\n" OD " refs/tags/v1\n"), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"git_ref_created\",\"ref\":\"refs/heads/b\",\"to\":\"" OC "\","
                     "\"text\":\"created refs/heads/b at " OC "\"},"
                     "{\"kind\":\"git_ref_deleted\",\"ref\":\"refs/heads/gone\",\"from\":\"" OD "\","
                     "\"text\":\"deleted refs/heads/gone (was " OD ")\"},"
                     "{\"kind\":\"git_ref_moved\",\"ref\":\"refs/tags/v1\",\"from\":\"" OB "\",\"to\":\"" OD "\","
                     "\"text\":\"refs/tags/v1 " OB " -> " OD "\"}"),
                  r_path(&r, "/s/r/.git/packed-refs", &b, &a, "modified"));
    r_free(&r);
}

/* Hooks from the manifest alone: content hash and mode, never content. */
TEST(git_hooks_are_added_removed_changed_or_made_executable) {
    struct run r;
    r_begin(&r, BELAY_INTERP_GIT, false);
    const struct belay_entry x = file(NULL, 0755), n = file(NULL, 0644);
    ASSERT_EQ_STR(F1("{\"kind\":\"git_hook_added\",\"hook\":\"pre-commit\",\"executable\":true,"
                     "\"text\":\"hook pre-commit added\"}"),
                  r_path(&r, "/s/r/.git/hooks/pre-commit", NULL, &x, "added"));
    ASSERT_EQ_STR(F1("{\"kind\":\"git_hook_removed\",\"hook\":\"pre-push\",\"text\":\"hook pre-push removed\"}"),
                  r_path(&r, "/s/r/.git/hooks/pre-push", &x, NULL, "removed"));
    ASSERT_EQ_STR(F1("{\"kind\":\"git_hook_changed\",\"hook\":\"pre-commit\",\"executable\":false,"
                     "\"text\":\"hook pre-commit changed\"}"),
                  r_path(&r, "/s/r/.git/hooks/pre-commit", &x, &n, "modified"));
    ASSERT_EQ_STR(F1("{\"kind\":\"git_hook_executable_changed\",\"hook\":\"post-checkout\",\"executable\":true,"
                     "\"text\":\"hook post-checkout executable: true\"}"),
                  r_path(&r, "/s/r/.git/hooks/post-checkout", &n, &x, "metadata_only"));
    ASSERT_EQ_STR("", r_path(&r, "/s/r/.git/hooks/post-checkout", &x, &x, "metadata_only"));
    r_free(&r);
}

TEST(git_index_is_changed_and_nothing_more) {
    struct run r;
    r_begin(&r, BELAY_INTERP_GIT, false);
    const struct belay_entry e = file(NULL, 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"git_index_changed\",\"text\":\"index changed\"}"),
                  r_path(&r, "/s/r/.git/index", &e, &e, "modified"));
    ASSERT_EQ_STR("", r_path(&r, "/s/r/.git/index", &e, &e, "metadata_only"));
    r_free(&r);
}

#define WHO " A U Thor <author@example.com> 1700000000 +0000\t"

/* Q3: the entries appended, and each that is not a plain commit or a
 * fast-forward with git's own operation. */
TEST(git_reflog_entries_appended_and_the_moves_that_are_not_commits) {
    struct run r;
    r_begin(&r, BELAY_INTERP_GIT, true);
    const char *first = "0000000000000000000000000000000000000000 " OA WHO "commit (initial): start\n";
    char after[2048];
    snprintf(after, sizeof after, "%s"
             OA " " OB WHO "commit: two\n"
             OB " " OA WHO "reset: moving to HEAD~1\n"
             OA " " OC WHO "merge topic: Fast-forward\n"
             OC " " OD WHO "commit (amend): two, again\n"
             OD " " OB WHO "rebase (finish): returning to refs/heads/main\n", first);
    const struct belay_entry b = file(put(first), 0), a = file(put(after), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"git_reflog_appended\",\"ref\":\"HEAD\",\"entries\":5,"
                     "\"text\":\"HEAD: 5 reflog entries\"},"
                     "{\"kind\":\"git_reflog_move\",\"ref\":\"HEAD\",\"from\":\"" OB "\",\"to\":\"" OA "\","
                     "\"operation\":\"reset\",\"text\":\"HEAD " OB " -> " OA " by reset\"},"
                     "{\"kind\":\"git_reflog_move\",\"ref\":\"HEAD\",\"from\":\"" OC "\",\"to\":\"" OD "\","
                     "\"operation\":\"commit (amend)\",\"text\":\"HEAD " OC " -> " OD " by commit (amend)\"},"
                     "{\"kind\":\"git_reflog_move\",\"ref\":\"HEAD\",\"from\":\"" OD "\",\"to\":\"" OB "\","
                     "\"operation\":\"rebase (finish)\",\"text\":\"HEAD " OD " -> " OB " by rebase (finish)\"}"),
                  r_path(&r, "/s/r/.git/logs/HEAD", &b, &a, "modified"));
    /* A new branch's reflog: every entry appended, its ref named. */
    ASSERT_EQ_STR(F1("{\"kind\":\"git_reflog_appended\",\"ref\":\"refs/heads/x\",\"entries\":1,"
                     "\"text\":\"refs/heads/x: 1 reflog entries\"}"),
                  r_path(&r, "/s/r/.git/logs/refs/heads/x", NULL, &b, "added"));
    r_free(&r);
}

TEST(git_reflog_that_is_not_appended_to_is_rewritten) {
    struct run r;
    r_begin(&r, BELAY_INTERP_GIT, true);
    const char *one = OA " " OB WHO "commit: one\n";
    char two[512];
    snprintf(two, sizeof two, "%s" OB " " OC WHO "commit: two\n", one);
    const struct belay_entry b = file(put(two), 0), a = file(put(one), 0);
    const char *want = F1("{\"kind\":\"git_reflog_rewritten\",\"ref\":\"refs/heads/main\","
                          "\"text\":\"refs/heads/main: reflog rewritten\"}");
    ASSERT_EQ_STR(want, r_path(&r, "/s/r/.git/logs/refs/heads/main", &b, &a, "modified"));
    ASSERT_EQ_STR(want, r_path(&r, "/s/r/.git/logs/refs/heads/main", &b, NULL, "removed"));
    /* An entry altered in place is not an append, even at the same length. */
    char edited[512];
    snprintf(edited, sizeof edited, "%s", two);
    edited[strlen(edited) - 2] = 'X';
    const struct belay_entry e = file(put(edited), 0);
    ASSERT_EQ_STR(want, r_path(&r, "/s/r/.git/logs/refs/heads/main", &b, &e, "modified"));
    /* S3 G8: before a prefix of after, but ending inside a line that after
     * goes on with: that line was altered. */
    char cut[512], longer[1024];
    snprintf(cut, sizeof cut, "%.*s", (int)strlen(one) - 1, one);
    snprintf(longer, sizeof longer, "%s more\n" OB " " OC WHO "commit: two\n", cut);
    const struct belay_entry c1 = file(put(cut), 0), c2 = file(put(longer), 0);
    ASSERT_EQ_STR(want, r_path(&r, "/s/r/.git/logs/refs/heads/main", &c1, &c2, "modified"));
    /* S3 G10: a removed reflog needs no copy to say so. */
    const struct belay_entry none = file(NULL, 0);
    ASSERT_EQ_STR(want, r_path(&r, "/s/r/.git/logs/refs/heads/main", &none, NULL, "removed"));
    r_free(&r);
}

/* A reflog over the store limit was never stored: said, never silent. */
TEST(git_reflog_without_a_copy_is_content_unavailable) {
    struct run r;
    r_begin(&r, BELAY_INTERP_GIT, true);
    const struct belay_entry b = file(NULL, 0), a = file(NULL, 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"content_unavailable\",\"reason\":\"missing\",\"side\":\"before\","
                     "\"text\":\"content unavailable (before): missing\"},"
                     "{\"kind\":\"content_unavailable\",\"reason\":\"missing\",\"side\":\"after\","
                     "\"text\":\"content unavailable (after): missing\"}"),
                  r_path(&r, "/s/r/.git/logs/HEAD", &b, &a, "modified"));
    r_free(&r);
}

TEST(git_ref_that_cannot_be_parsed_could_not_be_interpreted) {
    struct run r;
    r_begin(&r, BELAY_INTERP_GIT, true);
    const struct belay_entry b = file(put("not a ref\n"), 0), a = file(put(OA "\n"), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"could_not_interpret\",\"text\":\"could not interpret\"}"),
                  r_path(&r, "/s/r/.git/refs/heads/main", &b, &a, "modified"));
    ASSERT_EQ_INT(BELAY_OK, belay_err_code());
    r_free(&r);
}

/* Review 2026-10-31, findings 2 and 5: a side on which a claimed path is
 * not a regular file counts as absent -- a new ref namespace's directory is
 * no rewritten reflog, a directory under hooks/ no hook. */
TEST(git_paths_that_are_not_files_are_absent) {
    struct run r;
    r_begin(&r, BELAY_INTERP_GIT, true);
    const struct belay_entry d = other(BELAY_T_DIR, 0755), l = other(BELAY_T_LNK, 0777), x = file(NULL, 0755);
    ASSERT_EQ_STR("", r_path(&r, "/s/r/.git/logs/refs/heads/feature", NULL, &d, "added"));
    ASSERT_EQ_STR("", r_path(&r, "/s/r/.git/logs/refs/heads/feature", &d, NULL, "removed"));
    ASSERT_EQ_STR("", r_path(&r, "/s/r/.git/hooks/pre-push.d", NULL, &d, "added"));
    ASSERT_EQ_STR("", r_path(&r, "/s/r/.git/hooks/pre-commit", NULL, &l, "added"));
    ASSERT_EQ_STR("", r_path(&r, "/s/r/.git/refs/heads/feature", NULL, &d, "added"));
    ASSERT_EQ_STR("", r_path(&r, "/s/r/.git/index", NULL, &d, "added"));
    ASSERT_EQ_STR(F1("{\"kind\":\"git_hook_removed\",\"hook\":\"post-merge\",\"text\":\"hook post-merge removed\"}"),
                  r_path(&r, "/s/r/.git/hooks/post-merge", &x, &l, "type_changed"));
    r_free(&r);
}

/* Review 2026-10-31, finding 9: a ref file rewritten with the same value
 * names no move. */
TEST(git_a_ref_rewritten_to_the_same_value_says_nothing) {
    struct run r;
    r_begin(&r, BELAY_INTERP_GIT, true);
    const struct belay_entry a = file(put(OA "\n"), 0), b = file(put(OA "  \n"), 0);
    const struct belay_entry h1 = file(put("ref: refs/heads/main\n"), 0), h2 = file(put("ref:  refs/heads/main\nextra\n"), 0);
    ASSERT_EQ_STR("", r_path(&r, "/s/r/.git/refs/heads/main", &a, &b, "modified"));
    ASSERT_EQ_STR("", r_path(&r, "/s/r/.git/HEAD", &h1, &h2, "modified"));
    r_free(&r);
}

/* ================================= pip ================================= */

#define SP "/s/lib/python3.12/site-packages/"
#define REC(d) SP d ".dist-info/RECORD"
#define REL(d) "lib/python3.12/site-packages/" d ".dist-info/RECORD"

TEST(pip_installs_removals_and_version_changes_are_events) {
    struct run r;
    r_begin(&r, BELAY_INTERP_PIP, false);
    const struct belay_entry e = file(NULL, 0);
    ASSERT_EQ_STR("", r_path(&r, REC("numpy-1.26.4"), &e, NULL, "removed"));
    ASSERT_EQ_STR("", r_path(&r, REC("numpy-2.1.0"), NULL, &e, "added"));
    ASSERT_EQ_STR("", r_path(&r, REC("requests-2.32.3"), NULL, &e, "added"));
    ASSERT_EQ_STR("", r_path(&r, REC("Django-5.0"), &e, NULL, "removed"));
    ASSERT_EQ_STR("", r_path(&r, REC("django-4.2"), NULL, &e, "added"));
    ASSERT_EQ_STR("", r_path(&r, REC("weird-abc"), &e, NULL, "removed"));
    ASSERT_EQ_STR("", r_path(&r, REC("weird-1.0"), NULL, &e, "added"));
    ASSERT_EQ_STR("", r_path(&r, REC("same-1.0"), &e, NULL, "removed"));
    ASSERT_EQ_STR("", r_path(&r, REC("same-1.0.0"), NULL, &e, "added"));
    ASSERT_EQ_STR("", r_path(&r, REC("zope_interface-6.0"), &e, NULL, "removed"));
    ASSERT_EQ_STR(
        "{\"event\":\"pip_downgraded\",\"interp\":\"pip\",\"name\":\"django\",\"from\":\"5.0\",\"to\":\"4.2\","
        "\"text\":\"downgraded django 5.0 -> 4.2\",\"paths\":[\"" REL("Django-5.0") "\",\"" REL("django-4.2") "\"]}\n"
        "{\"event\":\"pip_upgraded\",\"interp\":\"pip\",\"name\":\"numpy\",\"from\":\"1.26.4\",\"to\":\"2.1.0\","
        "\"text\":\"upgraded numpy 1.26.4 -> 2.1.0\",\"paths\":[\"" REL("numpy-1.26.4") "\",\"" REL("numpy-2.1.0") "\"]}\n"
        "{\"event\":\"pip_installed\",\"interp\":\"pip\",\"name\":\"requests\",\"version\":\"2.32.3\","
        "\"text\":\"installed requests 2.32.3\",\"paths\":[\"" REL("requests-2.32.3") "\"]}\n"
        "{\"event\":\"pip_version_changed\",\"interp\":\"pip\",\"name\":\"same\",\"from\":\"1.0\",\"to\":\"1.0.0\","
        "\"text\":\"same 1.0 -> 1.0.0\",\"paths\":[\"" REL("same-1.0.0") "\",\"" REL("same-1.0") "\"]}\n"
        "{\"event\":\"pip_version_changed\",\"interp\":\"pip\",\"name\":\"weird\",\"from\":\"abc\",\"to\":\"1.0\","
        "\"text\":\"weird abc -> 1.0\",\"paths\":[\"" REL("weird-1.0") "\",\"" REL("weird-abc") "\"]}\n"
        "{\"event\":\"pip_removed\",\"interp\":\"pip\",\"name\":\"zope_interface\",\"version\":\"6.0\","
        "\"text\":\"removed zope_interface 6.0\",\"paths\":[\"" REL("zope_interface-6.0") "\"]}\n",
        r_end(&r));
    r_free(&r);
}

/* Pairs are by the directory holding the dist-info and the PEP 503 name. */
TEST(pip_pairs_within_one_directory_by_normalized_name) {
    struct run r;
    r_begin(&r, BELAY_INTERP_PIP, false);
    const struct belay_entry e = file(NULL, 0);
    r_path(&r, "/s/a/Foo_Bar-1.0.dist-info/RECORD", &e, NULL, "removed");
    r_path(&r, "/s/a/foo.bar-2.0.dist-info/RECORD", NULL, &e, "added");
    r_path(&r, "/s/b/foo-1.0.dist-info/RECORD", &e, NULL, "removed");
    r_path(&r, "/s/c/foo-2.0.dist-info/RECORD", NULL, &e, "added");
    r_path(&r, "/s/c/foo-0.9.dist-info/RECORD", &e, NULL, "removed");      /* S3 P7 */
    r_path(&r, "/s/d/foo-3.0.dist-info/RECORD", NULL, &e, "added");
    ASSERT_EQ_STR(
        "{\"event\":\"pip_installed\",\"interp\":\"pip\",\"name\":\"foo\",\"version\":\"3.0\","
        "\"text\":\"installed foo 3.0\",\"paths\":[\"d/foo-3.0.dist-info/RECORD\"]}\n"
        "{\"event\":\"pip_removed\",\"interp\":\"pip\",\"name\":\"foo\",\"version\":\"1.0\","
        "\"text\":\"removed foo 1.0\",\"paths\":[\"b/foo-1.0.dist-info/RECORD\"]}\n"
        "{\"event\":\"pip_upgraded\",\"interp\":\"pip\",\"name\":\"foo\",\"from\":\"0.9\",\"to\":\"2.0\","
        "\"text\":\"upgraded foo 0.9 -> 2.0\",\"paths\":[\"c/foo-0.9.dist-info/RECORD\",\"c/foo-2.0.dist-info/RECORD\"]}\n"
        "{\"event\":\"pip_upgraded\",\"interp\":\"pip\",\"name\":\"foo.bar\",\"from\":\"1.0\",\"to\":\"2.0\","
        "\"text\":\"upgraded foo.bar 1.0 -> 2.0\",\"paths\":[\"a/Foo_Bar-1.0.dist-info/RECORD\","
        "\"a/foo.bar-2.0.dist-info/RECORD\"]}\n",
        r_end(&r));
    r_free(&r);
}

/* PEP 376 / the wheel spec: RECORD rows are path, hash, size; the RECORD's
 * own row has neither. */
TEST(pip_reinstall_counts_files_by_record_row) {
    struct run r;
    r_begin(&r, BELAY_INTERP_PIP, true);
    const struct belay_entry b = file(put(
        "six.py,sha256=AAAA,34549\n"
        "six-1.16.0.dist-info/METADATA,sha256=BBBB,1795\n"
        "six-1.16.0.dist-info/RECORD,,\n"
        "\"odd,name.py\",sha256=CCCC,10\n"
        "grow.py,sha256=EEEE,10\n"), 0);
    const struct belay_entry a = file(put(
        "six.py,sha256=ZZZZ,34549\r\n"
        "six-1.16.0.dist-info/METADATA,sha256=BBBB,1796\r\n"
        "six-1.16.0.dist-info/RECORD,,\r\n"
        "six-1.16.0.dist-info/INSTALLER,sha256=DDDD,4\r\n"
        "grow.py,sha256=EEEE,100\r\n"), 0);
    ASSERT_EQ_STR("", r_path(&r, REC("six-1.16.0"), &b, &a, "modified"));
    ASSERT_EQ_STR(
        "{\"event\":\"pip_reinstalled\",\"interp\":\"pip\",\"name\":\"six\",\"version\":\"1.16.0\","
        "\"files_added\":1,\"files_removed\":1,\"files_changed\":3,"
        "\"text\":\"reinstalled six 1.16.0: +1 -1 ~3 files\",\"paths\":[\"" REL("six-1.16.0") "\"]}\n",
        r_end(&r));
    r_free(&r);
}

TEST(pip_metadata_and_unproven_changes_add_nothing) {
    struct run r;
    r_begin(&r, BELAY_INTERP_PIP, false);
    const struct belay_entry e = file(NULL, 0);
    ASSERT_EQ_STR("", r_path(&r, SP "six-1.16.0.dist-info/METADATA", &e, &e, "modified"));
    ASSERT_EQ_STR("", r_path(&r, REC("six-1.16.0"), &e, &e, "metadata_only"));
    ASSERT_EQ_STR("", r_path(&r, REC("six-1.16.0"), &e, NULL, "unknown"));
    ASSERT_EQ_STR("", r_end(&r));
    r_free(&r);
}

/* Never silent: unreadable on its path and as one event per reason. */
TEST(pip_record_that_cannot_be_read_is_said_on_the_path_and_as_an_event) {
    struct run r;
    r_begin(&r, BELAY_INTERP_PIP, false);
    const struct belay_entry b = file(put("x,,\n"), 0), a = file(put("y,,\n"), 0), e = file(NULL, 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"content_unavailable\",\"reason\":\"no_store\",\"side\":\"before\","
                     "\"text\":\"content unavailable (before): no_store\"},"
                     "{\"kind\":\"content_unavailable\",\"reason\":\"no_store\",\"side\":\"after\","
                     "\"text\":\"content unavailable (after): no_store\"}"),
                  r_path(&r, REC("six-1.16.0"), &b, &a, "modified"));
    r_path(&r, REC("attrs-23.1.0"), &b, &a, "modified");
    r_path(&r, REC("idna-3.7"), NULL, &e, "added");                     /* needs no content */
    ASSERT_EQ_STR(
        "{\"event\":\"content_unavailable\",\"interp\":\"pip\",\"reason\":\"no_store\",\"side\":\"both\","
        "\"text\":\"content unavailable (both): no_store\",\"paths\":[\"" REL("attrs-23.1.0") "\",\""
        REL("six-1.16.0") "\"]}\n"
        "{\"event\":\"pip_installed\",\"interp\":\"pip\",\"name\":\"idna\",\"version\":\"3.7\","
        "\"text\":\"installed idna 3.7\",\"paths\":[\"" REL("idna-3.7") "\"]}\n",
        r_end(&r));
    r_free(&r);

    r_begin(&r, BELAY_INTERP_PIP, true);
    const struct belay_entry gone = file(ABSENT, 0);
    r_path(&r, REC("six-1.16.0"), &b, &gone, "modified");
    ASSERT_EQ_STR(
        "{\"event\":\"content_unavailable\",\"interp\":\"pip\",\"reason\":\"missing\",\"side\":\"after\","
        "\"text\":\"content unavailable (after): missing\",\"paths\":[\"" REL("six-1.16.0") "\"]}\n",
        r_end(&r));
    r_free(&r);
}

/* What the finding kinds cannot say fails the end hook (E6), never a guess. */
TEST(pip_what_cannot_be_named_or_paired_fails_the_end_hook) {
    struct run r;
    r_begin(&r, BELAY_INTERP_PIP, false);
    const struct belay_entry e = file(NULL, 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"could_not_interpret\",\"text\":\"could not interpret\"}"),
                  r_path(&r, SP "nodash.dist-info/RECORD", NULL, &e, "added"));
    r_path(&r, REC("requests-2.32.3"), NULL, &e, "added");
    ASSERT_EQ_STR("{\"event\":\"could_not_interpret\",\"interp\":\"pip\",\"text\":\"could not interpret\","
                  "\"paths\":[\"lib/python3.12/site-packages/nodash.dist-info/RECORD\",\""
                  REL("requests-2.32.3") "\"]}\n",
                  r_end(&r));
    r_free(&r);

    /* The reference author's case B: RECORD is UTF-8 text; one that is not
     * cannot be parsed. */
    r_begin(&r, BELAY_INTERP_PIP, true);
    const struct belay_entry rb = file(put("six.py,sha256=A,1\n"), 0), ra = file(put("six.py,sha256=A,1\nsix/\xff.py,sha256=X,1\n"), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"could_not_interpret\",\"text\":\"could not interpret\"}"),
                  r_path(&r, REC("six-1.16.0"), &rb, &ra, "modified"));
    ASSERT_TRUE(strncmp(r_end(&r), "{\"event\":\"could_not_interpret\"", 30) == 0);
    r_free(&r);

    r_begin(&r, BELAY_INTERP_PIP, false);
    r_path(&r, REC("numpy-1.26.4"), &e, NULL, "removed");
    r_path(&r, REC("numpy-1.26.3"), &e, NULL, "removed");
    r_path(&r, REC("numpy-2.1.0"), NULL, &e, "added");
    ASSERT_TRUE(strncmp(r_end(&r), "{\"event\":\"could_not_interpret\"", 30) == 0);
    r_free(&r);
}

/* Review 2026-10-31, finding 4: a RECORD's rows are bounded (262,144); past
 * that the side is too_large, never gigabytes of rows. */
TEST(pip_a_record_past_its_row_bound_is_too_large) {
    const size_t rows = 262145;
    char *big = malloc(rows * 4 + 1);
    REQUIRE(big != NULL);
    for (size_t i = 0; i < rows; i++) memcpy(big + 4 * i, "x,,\n", 4);
    big[rows * 4] = '\0';
    struct run r;
    r_begin(&r, BELAY_INTERP_PIP, true);
    const struct belay_entry b = file(put("x,,\n"), 0), a = file(put(big), 0);
    free(big);
    ASSERT_EQ_STR(F1("{\"kind\":\"content_unavailable\",\"reason\":\"too_large\",\"side\":\"after\","
                     "\"text\":\"content unavailable (after): too_large\"}"),
                  r_path(&r, REC("six-1.16.0"), &b, &a, "modified"));
    ASSERT_EQ_STR("{\"event\":\"content_unavailable\",\"interp\":\"pip\",\"reason\":\"too_large\",\"side\":\"after\","
                  "\"text\":\"content unavailable (after): too_large\",\"paths\":[\"" REL("six-1.16.0") "\"]}\n",
                  r_end(&r));
    r_free(&r);
}

/* Review 2026-10-31, finding 12: a text side over 1,048,576 lines is
 * too_large (the line diff keeps 24 bytes a line). */
TEST(text_past_its_line_bound_is_too_large) {
    const size_t n = 1048577;
    char *nl = malloc(n + 1);
    REQUIRE(nl != NULL);
    memset(nl, '\n', n);
    nl[n] = '\0';
    struct run r;
    r_begin(&r, BELAY_INTERP_TEXT, true);
    const struct belay_entry a = file(put(nl), 0);
    free(nl);
    ASSERT_EQ_STR(F1("{\"kind\":\"content_unavailable\",\"reason\":\"too_large\",\"side\":\"after\","
                     "\"text\":\"content unavailable (after): too_large\"}"),
                  r_path(&r, "/s/lines", NULL, &a, "added"));
    r_free(&r);
}

/* ================================= dpkg ================================ */

#define STATUS "/s/var/lib/dpkg/status"
#define STATUS_REL "var/lib/dpkg/status"

/* deb-control(5): stanzas of "Field: value", continuation lines start with
 * a space, " ." an empty line of a multi-line value; a blank line between
 * stanzas. Status is "want flag state". */
static const char DPKG_BEFORE[] =
    "Package: bash\n"
    "Essential: yes\n"
    "Status: install ok installed\n"
    "Priority: required\n"
    "Architecture: amd64\n"
    "Version: 5.2.15-2+b2\n"
    "Description: GNU Bourne Again SHell\n"
    " Bash is an sh-compatible command language interpreter.\n"
    " .\n"
    " It is a superset.\n"
    "\n"
    "Package: curl\n"
    "Status: install ok installed\n"
    "Architecture: amd64\n"
    "Version: 7.88.1-10+deb12u5\n"
    "\n"
    "Package: libc6\n"
    "Status: install ok installed\n"
    "Architecture: amd64\n"
    "Version: 2.36-9\n"
    "\n"
    "Package: vim\n"
    "Status: install ok installed\n"
    "Architecture: amd64\n"
    "Version: 2:9.0.1378-2\n"
    "\n"
    "Package: oldlib\n"
    "Status: deinstall ok config-files\n"
    "Architecture: amd64\n"
    "Version: 1.0-1\n"
    "Conffiles:\n"
    " /etc/oldlib.conf 0123456789abcdef0123456789abcdef\n";

static const char DPKG_AFTER[] =
    "Package: bash\n"
    "Status: hold ok installed\n"
    "Architecture: amd64\n"
    "Version: 5.2.15-2+b2\n"
    "\n"
    "Package: curl\n"
    "Status: deinstall ok config-files\n"
    "Architecture: amd64\n"
    "Version: 7.88.1-10+deb12u5\n"
    "\n"
    "Package: git\n"
    "Status: install ok installed\n"
    "Architecture: amd64\n"
    "Version: 1:2.39.2-1.1\n"
    "\n"
    "Package: libc6\n"
    "Status: install ok installed\n"
    "Architecture: amd64\n"
    "Version: 2.36-9+deb12u4\n"
    "\n"
    "Package: libc6\n"
    "Status: install ok installed\n"
    "Architecture: i386\n"
    "Version: 2.36-9+deb12u4\n"
    "\n"
    "Package: vim\n"
    "Status: install ok installed\n"
    "Architecture: amd64\n"
    "Version: 2:9.0.1378-1\n";

#define EV(kind, fields, text) "{\"event\":\"" kind "\",\"interp\":\"dpkg\"," fields ",\"text\":\"" text \
                               "\",\"paths\":[\"" STATUS_REL "\"]}\n"

TEST(dpkg_status_deltas_are_events_in_package_order) {
    struct run r;
    r_begin(&r, BELAY_INTERP_DPKG, true);
    const struct belay_entry b = file(put(DPKG_BEFORE), 0), a = file(put(DPKG_AFTER), 0);
    ASSERT_EQ_STR("", r_path(&r, STATUS, &b, &a, "modified"));
    ASSERT_EQ_STR(
        EV("dpkg_state_changed", "\"package\":\"bash\",\"arch\":\"amd64\",\"from\":\"install ok installed\","
           "\"to\":\"hold ok installed\"", "bash:amd64 install ok installed -> hold ok installed")
        EV("dpkg_removed", "\"package\":\"curl\",\"arch\":\"amd64\",\"version\":\"7.88.1-10+deb12u5\"",
           "removed curl:amd64 7.88.1-10+deb12u5")
        EV("dpkg_installed", "\"package\":\"git\",\"arch\":\"amd64\",\"version\":\"1:2.39.2-1.1\"",
           "installed git:amd64 1:2.39.2-1.1")
        EV("dpkg_upgraded", "\"package\":\"libc6\",\"arch\":\"amd64\",\"from\":\"2.36-9\",\"to\":\"2.36-9+deb12u4\"",
           "upgraded libc6:amd64 2.36-9 -> 2.36-9+deb12u4")
        EV("dpkg_installed", "\"package\":\"libc6\",\"arch\":\"i386\",\"version\":\"2.36-9+deb12u4\"",
           "installed libc6:i386 2.36-9+deb12u4")
        EV("dpkg_state_changed", "\"package\":\"oldlib\",\"arch\":\"amd64\",\"from\":\"deinstall ok config-files\","
           "\"to\":\"\"", "oldlib:amd64 deinstall ok config-files -> ")
        EV("dpkg_downgraded", "\"package\":\"vim\",\"arch\":\"amd64\",\"from\":\"2:9.0.1378-2\",\"to\":\"2:9.0.1378-1\"",
           "downgraded vim:amd64 2:9.0.1378-2 -> 2:9.0.1378-1"),
        r_end(&r));
    r_free(&r);
}

/* A status file added (a new root) installs everything in it. */
TEST(dpkg_a_new_status_installs_what_it_lists) {
    struct run r;
    r_begin(&r, BELAY_INTERP_DPKG, true);
    const struct belay_entry a = file(put("Package: zlib1g\nStatus: install ok installed\n"
                                          "Version: 1:1.2.13.dfsg-1\n"), 0);
    r_path(&r, STATUS, NULL, &a, "added");
    ASSERT_EQ_STR(EV("dpkg_installed", "\"package\":\"zlib1g\",\"arch\":\"\",\"version\":\"1:1.2.13.dfsg-1\"",
                     "installed zlib1g: 1:1.2.13.dfsg-1"),
                  r_end(&r));
    r_free(&r);
}

TEST(dpkg_info_files_and_unproven_changes_add_nothing) {
    struct run r;
    r_begin(&r, BELAY_INTERP_DPKG, false);
    const struct belay_entry e = file(NULL, 0);
    ASSERT_EQ_STR("", r_path(&r, "/s/var/lib/dpkg/info/bash.list", &e, &e, "modified"));
    ASSERT_EQ_STR("", r_path(&r, STATUS, &e, &e, "metadata_only"));
    ASSERT_EQ_STR("", r_path(&r, STATUS, &e, &e, "unknown"));
    ASSERT_EQ_STR("", r_end(&r));
    r_free(&r);
}

/* The reason this kind exists: a changed status with no store must not read
 * as "no packages changed". */
TEST(dpkg_status_that_cannot_be_read_is_never_no_change) {
    struct run r;
    r_begin(&r, BELAY_INTERP_DPKG, false);
    const struct belay_entry b = file(put(DPKG_BEFORE), 0), a = file(put(DPKG_AFTER), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"content_unavailable\",\"reason\":\"no_store\",\"side\":\"before\","
                     "\"text\":\"content unavailable (before): no_store\"},"
                     "{\"kind\":\"content_unavailable\",\"reason\":\"no_store\",\"side\":\"after\","
                     "\"text\":\"content unavailable (after): no_store\"}"),
                  r_path(&r, STATUS, &b, &a, "modified"));
    ASSERT_EQ_STR("{\"event\":\"content_unavailable\",\"interp\":\"dpkg\",\"reason\":\"no_store\","
                  "\"side\":\"both\",\"text\":\"content unavailable (both): no_store\","
                  "\"paths\":[\"" STATUS_REL "\"]}\n",
                  r_end(&r));
    r_free(&r);

    /* S3 U7: a status removed, with no store: side before. */
    r_begin(&r, BELAY_INTERP_DPKG, false);
    r_path(&r, STATUS, &b, NULL, "removed");
    ASSERT_EQ_STR("{\"event\":\"content_unavailable\",\"interp\":\"dpkg\",\"reason\":\"no_store\","
                  "\"side\":\"before\",\"text\":\"content unavailable (before): no_store\","
                  "\"paths\":[\"" STATUS_REL "\"]}\n",
                  r_end(&r));
    r_free(&r);

    /* One side corrupt, in a second root: its own reason and side. */
    r_begin(&r, BELAY_INTERP_DPKG, true);
    put_as("2222222222222222222222222222222222222222222222222222222222222222", "Package: x\n", 11);
    const struct belay_entry bad = file("2222222222222222222222222222222222222222222222222222222222222222", 0);
    const struct belay_entry ok = file(put(DPKG_BEFORE), 0);
    r_path(&r, "/s/c1/var/lib/dpkg/status", &ok, &bad, "modified");
    r_path(&r, "/s/c2/var/lib/dpkg/status", NULL, &bad, "added");
    ASSERT_EQ_STR("{\"event\":\"content_unavailable\",\"interp\":\"dpkg\",\"reason\":\"corrupt\","
                  "\"side\":\"after\",\"text\":\"content unavailable (after): corrupt\","
                  "\"paths\":[\"c1/var/lib/dpkg/status\",\"c2/var/lib/dpkg/status\"]}\n",
                  r_end(&r));
    r_free(&r);
}

TEST(dpkg_status_that_cannot_be_parsed_fails_the_end_hook) {
    struct run r;
    r_begin(&r, BELAY_INTERP_DPKG, true);
    const struct belay_entry b = file(put(DPKG_BEFORE), 0), a = file(put("this is not a stanza\n"), 0);
    ASSERT_EQ_STR(F1("{\"kind\":\"could_not_interpret\",\"text\":\"could not interpret\"}"),
                  r_path(&r, STATUS, &b, &a, "modified"));
    ASSERT_EQ_STR("{\"event\":\"could_not_interpret\",\"interp\":\"dpkg\",\"text\":\"could not interpret\","
                  "\"paths\":[\"" STATUS_REL "\"]}\n",
                  r_end(&r));
    ASSERT_EQ_INT(BELAY_OK, belay_err_code());
    r_free(&r);
}

/* Found by fuzz_interpreters: an empty status or RECORD is no packages or
 * rows, never a sort of nothing from NULL (undefined; check-san). */
TEST(empty_files_are_nothing_listed) {
    struct run r;
    r_begin(&r, BELAY_INTERP_DPKG, true);
    const struct belay_entry e = file(put(""), 0);
    ASSERT_EQ_STR("", r_path(&r, STATUS, NULL, &e, "added"));
    ASSERT_EQ_STR("", r_end(&r));
    r_free(&r);
    r_begin(&r, BELAY_INTERP_PIP, true);
    const struct belay_entry x = file(put("x.py,,\n"), 0);
    ASSERT_EQ_STR("", r_path(&r, REC("six-1.16.0"), &e, &x, "modified"));
    ASSERT_TRUE(strstr(r_end(&r), "\"files_added\":1,\"files_removed\":0,\"files_changed\":0") != NULL);
    r_free(&r);
    r_begin(&r, BELAY_INTERP_GIT, true);
    ASSERT_EQ_STR("", r_path(&r, "/s/r/.git/packed-refs", &e, &e, "modified"));
    r_free(&r);
}

/* Found by fuzz_interpreters: a NUL inside a field is UTF-8 but no string
 * field's value; dpkg checks with the core's own rule, so it fails its end
 * hook itself rather than handing the core an event that breaks its row. */
TEST(dpkg_a_field_with_a_nul_fails_the_end_hook_not_the_row) {
    static const char st[] = "Package: git\nStatus: install ok installed\nVersion: 2\0x\n";
    char hex[65];
    sha_hex(st, sizeof st - 1, hex);
    put_as(hex, st, sizeof st - 1);
    struct run r;
    r_begin(&r, BELAY_INTERP_DPKG, true);
    const struct belay_entry b = file(put("Package: git\nStatus: install ok installed\nVersion: 1\n"), 0);
    const struct belay_entry a = file(hex, 0);
    r_path(&r, STATUS, &b, &a, "modified");
    r.ev.interp = r.id;
    const enum belay_interp_result e = r.it->end(r.state, &r.ev);
    ASSERT_EQ_INT(BELAY_INTERP_ERROR, e);
    ASSERT_FALSE(events_broken(&r.ev, BELAY_INTERP_DPKG));
    r_free(&r);
}

/* Review 2026-10-31, finding 3: every value fits, but the event's text
 * would not (two 600-byte versions): dpkg fails its own end hook (E6),
 * rather than handing the core an event that breaks its row. */
TEST(dpkg_an_event_whose_text_would_not_fit_fails_the_end_hook) {
    static char b[2000], a[2000], v1[601], v2[601];
    memset(v1, '1', 600);
    memset(v2, '2', 600);
    snprintf(b, sizeof b, "Package: bash\nStatus: install ok installed\nVersion: 5.1\n\n"
                          "Package: big\nStatus: install ok installed\nVersion: %s\n", v1);
    snprintf(a, sizeof a, "Package: bash\nStatus: install ok installed\nVersion: 5.2\n\n"
                          "Package: big\nStatus: install ok installed\nVersion: %s\n", v2);
    struct run r;
    r_begin(&r, BELAY_INTERP_DPKG, true);
    const struct belay_entry eb = file(put(b), 0), ea = file(put(a), 0);
    r_path(&r, STATUS, &eb, &ea, "modified");
    r.ev.interp = r.id;
    ASSERT_EQ_INT(BELAY_INTERP_ERROR, r.it->end(r.state, &r.ev));
    ASSERT_FALSE(events_broken(&r.ev, BELAY_INTERP_DPKG));
    r_free(&r);
}

/* ================================ binary =============================== */

TEST(binary_declines_everything) {
    const struct belay_interp *it = belay_interp_builtin(BELAY_INTERP_BINARY);
    ASSERT_TRUE(it->explain == NULL && it->begin == NULL && it->end == NULL);
}

int main(void) {
    snprintf(g_store, sizeof g_store, "/tmp/belay_interpreters_%d", (int)getpid());
    RUN(text_counts_lines_by_their_longest_common_subsequence);
    RUN(text_added_and_removed_give_their_line_count);
    RUN(text_past_2000_lines_of_difference_is_rewritten);
    RUN(text_describes_only_a_proven_change_of_content);
    RUN(text_says_why_a_copy_cannot_be_read);
    RUN(text_says_a_copy_over_its_bound_is_too_large);
    RUN(git_head_names_the_symbolic_ref_or_the_commit);
    RUN(git_loose_refs_are_created_deleted_and_moved);
    RUN(git_packed_refs_are_compared_ref_by_ref);
    RUN(git_hooks_are_added_removed_changed_or_made_executable);
    RUN(git_index_is_changed_and_nothing_more);
    RUN(git_reflog_entries_appended_and_the_moves_that_are_not_commits);
    RUN(git_reflog_that_is_not_appended_to_is_rewritten);
    RUN(git_reflog_without_a_copy_is_content_unavailable);
    RUN(git_ref_that_cannot_be_parsed_could_not_be_interpreted);
    RUN(git_paths_that_are_not_files_are_absent);
    RUN(git_a_ref_rewritten_to_the_same_value_says_nothing);
    RUN(pip_installs_removals_and_version_changes_are_events);
    RUN(pip_pairs_within_one_directory_by_normalized_name);
    RUN(pip_reinstall_counts_files_by_record_row);
    RUN(pip_metadata_and_unproven_changes_add_nothing);
    RUN(pip_record_that_cannot_be_read_is_said_on_the_path_and_as_an_event);
    RUN(pip_what_cannot_be_named_or_paired_fails_the_end_hook);
    RUN(pip_a_record_past_its_row_bound_is_too_large);
    RUN(text_past_its_line_bound_is_too_large);
    RUN(dpkg_status_deltas_are_events_in_package_order);
    RUN(dpkg_a_new_status_installs_what_it_lists);
    RUN(dpkg_info_files_and_unproven_changes_add_nothing);
    RUN(dpkg_status_that_cannot_be_read_is_never_no_change);
    RUN(dpkg_status_that_cannot_be_parsed_fails_the_end_hook);
    RUN(empty_files_are_nothing_listed);
    RUN(dpkg_a_field_with_a_nul_fails_the_end_hook_not_the_row);
    RUN(dpkg_an_event_whose_text_would_not_fit_fails_the_end_hook);
    RUN(binary_declines_everything);
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_store);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
