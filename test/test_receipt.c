/*
 *  Receipts (src/cli/receipt.c; NOTES/phase5-structure.md §5): diff.v1 in,
 *  the receipt out, both written by hand here -- never from a run. Events
 *  first; privilege changes (caps, inode flags, setuid, setgid, sticky)
 *  never folded; at most 15 findings a record, then "and N more"; flagged
 *  entries named on their own line, no banner.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "cli/receipt.h"

#include "belay/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define HEAD "{\"belay_diff\":1,\"scopes\":[\"/w\"],\"before_created_ns\":1,\"after_created_ns\":2,\"before_hash_max_bytes\":1,\"after_hash_max_bytes\":1,\"scope_remounted\":false,\"identity_compared\":true}\n"
#define TRAIL(mod, add, md, unk, ev, vb, va) \
    "{\"belay_diff_end\":9,\"unchanged\":1,\"added\":" add ",\"removed\":0,\"modified\":" mod ",\"type_changed\":0,\"metadata_only\":" md ",\"unknown\":" unk ",\"dir_timestamps_only\":0,\"events\":" ev ",\"before_vanished\":" vb ",\"before_unstable\":0,\"before_raced\":0,\"after_vanished\":" va ",\"after_unstable\":0,\"after_raced\":0,\"provisional\":false,\"before_sha256\":\"x\",\"after_sha256\":\"y\"}\n"

/* bin/tool goes 0755 -> 4755; everything else keeps 0644. */
static int fake_mode(void *ctx, int side, const char *path, size_t len, struct receipt_meta *m) {
    (void)ctx;
    if (len == 8 && memcmp(path, "bin/tool", 8) == 0) { m->mode = side ? 0104755 : 0100755; return 0; }
    m->mode = 0100644;
    m->has_caps = false;
    return 0;
}

/* Each side's paths, by table: a path absent from a side is not there. */
struct side_meta { const char *path; size_t len; uint32_t mode; bool caps; };
static const struct side_meta *g_sides[2];
static int table_mode(void *ctx, int side, const char *path, size_t len, struct receipt_meta *m) {
    (void)ctx;
    for (const struct side_meta *t = g_sides[side]; t != NULL && t->path != NULL; t++)
        if (t->len == len && memcmp(t->path, path, len) == 0) {
            m->mode = t->mode;
            m->has_caps = t->caps;
            return 0;
        }
    return -1;
}

static char *g_text;
static receipt_mode_fn g_fn = fake_mode;

static int render(const char *diff, bool all) {
    FILE *in = fmemopen((void *)diff, strlen(diff), "r");
    size_t n;
    free(g_text);
    g_text = NULL;
    FILE *out = open_memstream(&g_text, &n);
    const struct receipt_opts o = { "checkpoint 3", "checkpoint 4", all, g_fn, NULL };
    const int r = receipt_render(in, out, &o);
    fclose(in);
    fclose(out);
    return r;
}

TEST(a_receipt_puts_events_then_privilege_then_changes) {
    static char diff[16384];
    char findings[4096] = "";
    size_t w = 0;
    for (int i = 1; i <= 17; i++)
        w += (size_t)snprintf(findings + w, sizeof findings - w, "%s{\"kind\":\"x\",\"text\":\"finding %d\"}",
                              i > 1 ? "," : "", i);
    snprintf(diff, sizeof diff, HEAD
        "{\"path\":\"bin/tool\",\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"mode\",\"ctime_ns\"]}\n"
        "{\"path\":\"bin/x\",\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"ctime_ns\",\"caps\"]}\n"
        "{\"path\":\"build/out.log\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"raced\"]}\n"
        "{\"path\":\"etc/conf\",\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"mode\"]}\n"
        "{\"path\":\"src/big.c\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"size\"],\"findings\":[%s]}\n"
        "{\"path\":\"tests/t.py\",\"outcome\":\"added\",\"type\":\"reg\",\"findings\":[{\"kind\":\"text_added\",\"lines\":4,\"text\":\"4 lines\"}]}\n"
        "{\"event\":\"pip_upgraded\",\"interp\":\"pip\",\"name\":\"numpy\",\"from\":\"1\",\"to\":\"2\",\"text\":\"upgraded numpy 1 -> 2\",\"paths\":[\"a\",\"b\"]}\n"
        "{\"event\":\"dpkg_installed\",\"interp\":\"dpkg\",\"package\":\"git\",\"arch\":\"\",\"version\":\"1\",\"text\":\"installed git: 1\",\"provisional\":true,\"paths\":[\"s\"]}\n"
        TRAIL("1", "1", "3", "1", "2", "0", "2"), findings);
    ASSERT_EQ_INT(0, render(diff, false));
    static char want[8192];
    w = (size_t)snprintf(want, sizeof want,
        "belay diff  /w  checkpoint 3 -> checkpoint 4\n"
        "  1 modified · 1 added · 3 metadata_only · 1 unknown    events: 2\n"
        "  0 entries vanished while the before walk ran, 2 while the after walk ran\n"
        "\n"
        "packages and files explained\n"
        "  pip   upgraded numpy 1 -> 2\n"
        "  dpkg  installed git: 1 (provisional: a path it came from is unknown)\n"
        "\n"
        "privilege\n"
        "  ~ bin/tool   setuid added (mode 0755 -> 4755)\n"
        "  ~ bin/x   capabilities changed\n"
        "\n"
        "changes\n"
        "  ? build/out.log   unknown: raced\n"
        "  ~ etc/conf   mode\n"
        "  M src/big.c");
    for (int i = 1; i <= 15; i++) w += (size_t)snprintf(want + w, sizeof want - w, "\n      finding %d", i);
    snprintf(want + w, sizeof want - w,
        "\n      and 2 more\n"
        "  A tests/t.py\n"
        "      4 lines\n");
    ASSERT_EQ_STR(want, g_text);
}

/* Past 50, events and other changes fold; privilege never does; --all
 * shows everything. */
TEST(long_sections_fold_but_privilege_never_does) {
    static char diff[1 << 16];
    size_t w = (size_t)snprintf(diff, sizeof diff, HEAD);
    for (int i = 0; i < 60; i++)
        w += (size_t)snprintf(diff + w, sizeof diff - w,
                              "{\"path\":\"p%02d\",\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"iflags\"]}\n", i);
    for (int i = 0; i < 60; i++)
        w += (size_t)snprintf(diff + w, sizeof diff - w,
                              "{\"path\":\"q%02d\",\"outcome\":\"added\",\"type\":\"reg\"}\n", i);
    snprintf(diff + w, sizeof diff - w, TRAIL("0", "60", "60", "0", "0", "0", "0"));
    ASSERT_EQ_INT(0, render(diff, false));
    ASSERT_TRUE(strstr(g_text, "  ~ p59   inode flags changed\n") != NULL);   /* all 60 privilege */
    ASSERT_TRUE(strstr(g_text, "  A q49\n") != NULL && strstr(g_text, "  A q50\n") == NULL);
    ASSERT_TRUE(strstr(g_text, "  and 10 more (--all shows them)\n") != NULL);
    ASSERT_EQ_INT(0, render(diff, true));
    ASSERT_TRUE(strstr(g_text, "  A q59\n") != NULL && strstr(g_text, "and 10 more") == NULL);
}

TEST(no_changes_says_so) {
    ASSERT_EQ_INT(0, render(HEAD TRAIL("0", "0", "0", "0", "0", "0", "0"), false));
    ASSERT_EQ_STR("belay diff  /w  checkpoint 3 -> checkpoint 4\n  no changes\n", g_text);
}

/* A diff cut short, or a line that is not diff.v1, is an error: a receipt is
 * never rendered from part of a diff. */
TEST(a_truncated_or_malformed_diff_renders_nothing) {
    ASSERT_EQ_INT(-1, render(HEAD "{\"path\":\"a\",\"outcome\":\"added\",\"type\":\"reg\"}\n", false));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    belay_err_clear();
    ASSERT_EQ_INT(-1, render(HEAD "not json\n", false));
    belay_err_clear();
}

/* Review 2026-10-31, Phase 5, 7: setuid on a path that is not UTF-8, a
 * file added setuid, a file removed with capabilities -- each a privilege
 * change, never folded; and nothing in a path or a text forges a line, a
 * heading or a terminal sequence. */
TEST(privilege_is_found_whatever_the_path_and_the_outcome) {
    static const struct side_meta before[] = {
        { "bad\xffname", 8, 0100755, false }, { "gone", 4, 0100755, true }, { NULL, 0, 0, false } };
    static const struct side_meta after[] = {
        { "bad\xffname", 8, 0104755, false }, { "newsuid", 7, 0104755, false }, { NULL, 0, 0, false } };
    g_sides[0] = before;
    g_sides[1] = after;
    g_fn = table_mode;
    static char diff[1 << 16];
    size_t w = (size_t)snprintf(diff, sizeof diff, HEAD);
    for (int i = 0; i < 60; i++)        /* enough to fold the changes */
        w += (size_t)snprintf(diff + w, sizeof diff - w,
                              "{\"path\":\"a%02d\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"size\"]}\n", i);
    w += (size_t)snprintf(diff + w, sizeof diff - w,
        "{\"path_b64\":\"YmFk/25hbWU=\",\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"mode\"]}\n"
        "{\"path\":\"g\\n\\nprivilege\\n  nothing here\\u001b[2J\",\"outcome\":\"added\",\"type\":\"reg\","
        "\"findings\":[{\"kind\":\"x\",\"text\":\"t\\u009b31m\\\\x41\"}]}\n"
        "{\"path\":\"gone\",\"outcome\":\"removed\",\"type\":\"reg\"}\n"
        "{\"path\":\"newsuid\",\"outcome\":\"added\",\"type\":\"reg\"}\n");
    snprintf(diff + w, sizeof diff - w, TRAIL("60", "2", "1", "0", "0", "0", "0"));
    ASSERT_EQ_INT(0, render(diff, false));
    ASSERT_TRUE(strstr(g_text, "\nprivilege\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  ~ bad\\xffname   setuid added (mode 0755 -> 4755)\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  A newsuid   setuid added (new, mode 4755)\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  D gone   capabilities removed\n") != NULL);
    ASSERT_TRUE(render(diff, true) == 0);
    ASSERT_TRUE(strstr(g_text, "  A g\\x0a\\x0aprivilege\\x0a  nothing here\\x1b[2J\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "      t\\xc2\\x9b31m\\\\x41\n") != NULL);
    ASSERT_TRUE(strchr(g_text, '\x1b') == NULL);
    const char *first = strstr(g_text, "\nprivilege\n");
    ASSERT_TRUE(first != NULL && strstr(first + 1, "\nprivilege\n") == NULL);   /* one heading, not forged */
    g_fn = fake_mode;
}

/* S7 2026-10-31, row 73: an entry belay could not capture reliably is named
 * on its own line -- unknown records never fold. */
TEST(unknown_records_never_fold) {
    static char diff[1 << 16];
    size_t w = (size_t)snprintf(diff, sizeof diff, HEAD);
    for (int i = 0; i < 60; i++)
        w += (size_t)snprintf(diff + w, sizeof diff - w,
                              "{\"path\":\"a%02d\",\"outcome\":\"added\",\"type\":\"reg\"}\n", i);
    w += (size_t)snprintf(diff + w, sizeof diff - w,
        "{\"path\":\"zz\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"raced\"]}\n");
    snprintf(diff + w, sizeof diff - w, TRAIL("0", "60", "0", "1", "0", "0", "0"));
    ASSERT_EQ_INT(0, render(diff, false));
    ASSERT_TRUE(strstr(g_text, "  ? zz   unknown: raced\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "and 10 more") != NULL);
}

/* S7 2026-10-31, row 171: a version this reader does not know is rejected;
 * review 12: a scope that is not UTF-8 is shown from scopes_b64. */
TEST(a_diff_of_another_version_is_rejected_and_b64_scopes_shown) {
    ASSERT_EQ_INT(-1, render("{\"belay_diff\":2,\"scopes\":[\"/w\"]}\n" TRAIL("0", "0", "0", "0", "0", "0", "0"), false));
    belay_err_clear();
    ASSERT_EQ_INT(0, render("{\"belay_diff\":1,\"scopes_b64\":[\"L2JhZP8=\"],\"before_created_ns\":1}\n"
                            TRAIL("0", "0", "0", "0", "0", "0", "0"), false));
    ASSERT_EQ_STR("belay diff  /bad\\xff  checkpoint 3 -> checkpoint 4\n  no changes\n", g_text);
}

/* Review 2026-10-31, Phase 5, 16: a line of many short strings costs memory
 * in its length, not its length squared. Under an address-space limit, the
 * old reader (each string sized by the rest of the line) failed. */
TEST(a_line_of_many_strings_is_read_in_linear_memory) {
    enum { K = 200000 };
    const size_t cap = 64 + (size_t)K * 32 + 1024;
    char *diff = malloc(cap);
    REQUIRE(diff != NULL);
    size_t w = (size_t)snprintf(diff, cap, HEAD "{\"path\":\"p\",\"outcome\":\"modified\",\"type\":\"reg\",\"findings\":[");
    for (int i = 0; i < K; i++) w += (size_t)snprintf(diff + w, cap - w, "%s{\"text\":\"x\"}", i ? "," : "");
    snprintf(diff + w, cap - w, "]}\n" TRAIL("1", "0", "0", "0", "0", "0", "0"));
    /* The bound is enforced where RLIMIT_AS is (Linux) and nothing reserves
     * address space wholesale (no ASan); elsewhere the same input runs
     * without it, for the sanitizer's sake. */
#if defined(__linux__) && !defined(__SANITIZE_ADDRESS__)
    struct rlimit old, lim;
    getrlimit(RLIMIT_AS, &old);
    FILE *st = fopen("/proc/self/statm", "r");
    unsigned long pages = 0;
    if (st) { if (fscanf(st, "%lu", &pages) != 1) pages = 0; fclose(st); }
    REQUIRE(pages != 0);
    lim.rlim_cur = (rlim_t)pages * (rlim_t)sysconf(_SC_PAGESIZE) + ((rlim_t)1 << 30);   /* now + 1 GiB */
    lim.rlim_max = old.rlim_max;
    setrlimit(RLIMIT_AS, &lim);
#endif
    const int rc = render(diff, false);
#if defined(__linux__) && !defined(__SANITIZE_ADDRESS__)
    setrlimit(RLIMIT_AS, &old);
#endif
    free(diff);
    ASSERT_EQ_INT(0, rc);
    ASSERT_TRUE(g_text != NULL && strstr(g_text, "and 199985 more") != NULL);
}

int main(void) {
    RUN(a_receipt_puts_events_then_privilege_then_changes);
    RUN(long_sections_fold_but_privilege_never_does);
    RUN(no_changes_says_so);
    RUN(a_truncated_or_malformed_diff_renders_nothing);
    RUN(privilege_is_found_whatever_the_path_and_the_outcome);
    RUN(unknown_records_never_fold);
    RUN(a_diff_of_another_version_is_rejected_and_b64_scopes_shown);
    RUN(a_line_of_many_strings_is_read_in_linear_memory);
    free(g_text);
    return belay_test_report();
}
