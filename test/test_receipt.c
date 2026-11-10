/*
 *  Receipts (src/cli/receipt.c; NOTES/phase5-structure.md §5): diff.v1 in,
 *  the receipt out, both written by hand here -- never from a run. Events
 *  first; privilege changes (caps, inode flags, setuid, setgid, sticky)
 *  never folded; at most 15 findings a record, then "and N more"; flagged
 *  entries named on their own line, no banner.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "capture/fsops.h"
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
struct side_meta { const char *path; size_t len; uint32_t mode; bool caps; bool has_iflags; uint64_t iflags; };
static const struct side_meta *g_sides[2];
static int table_mode(void *ctx, int side, const char *path, size_t len, struct receipt_meta *m) {
    (void)ctx;
    for (const struct side_meta *t = g_sides[side]; t != NULL && t->path != NULL; t++)
        if (t->len == len && memcmp(t->path, path, len) == 0) {
            m->mode = t->mode;
            m->has_caps = t->caps;
            m->has_iflags = t->has_iflags;
            m->iflags = t->iflags;
            return 0;
        }
    return -1;
}

static char *g_text;
static receipt_mode_fn g_fn = fake_mode;

/* git's view, faked: src/ tracked, out/ and the top's x.log ignored, the
 * rest untracked; or, with g_class_fails, git unavailable. */
static bool g_class_fails;
static size_t g_classified;
static int fake_class(void *ctx, const char *const *paths, const size_t *lens, const bool *dir, size_t n,
                      unsigned char *out) {
    (void)ctx; (void)dir; (void)lens;
    if (g_class_fails) return -1;
    g_classified = n;
    for (size_t i = 0; i < n; i++)
        out[i] = !strncmp(paths[i], "src/", 4) ? 1 : !strncmp(paths[i], "out", 3) || !strcmp(paths[i], "x.log") ? 2 : 0;
    return 0;
}
static receipt_class_fn g_class;
static const char *g_note;

static int render(const char *diff, bool all) {
    FILE *in = fmemopen((void *)diff, strlen(diff), "r");
    size_t n;
    free(g_text);
    g_text = NULL;
    FILE *out = open_memstream(&g_text, &n);
    const struct receipt_opts o = { "checkpoint 3", "checkpoint 4", all, g_fn, NULL, g_class, NULL, g_note };
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
        "  2 entries changed while they were read (checkpoint 4); running belay again settles them\n"
        "\n"
        "events\n"
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

/* test/expect/inode-flags.md, IF-2 to IF-4 and IF-8, by hand: a directory
 * whose flags changed without a locking flag (ext4's hashed index, set when
 * it outgrows a block) is no privilege change and is still shown; a regular
 * file's flags are; an entry that comes or goes is named only when it holds
 * immutable or append-only. LOCK is whichever of those the platform has. */
TEST(inode_flags_are_privilege_only_where_the_pin_counts_them) {
    const uint64_t LOCK = belay_iflags_locking & (~belay_iflags_locking + 1), OTHER = 0x1000, BASE = 0x80000;
    REQUIRE(LOCK != 0 && (OTHER & belay_iflags_locking) == 0 && (BASE & belay_iflags_locking) == 0);
    const struct side_meta before[] = {
        { "grew", 4, 0040755, false, true, BASE },      { "file", 4, 0100644, false, true, BASE },
        { "lockdir", 7, 0040755, false, true, BASE },   { "gone", 4, 0100644, false, true, BASE | LOCK },
        { "goneplain", 9, 0100644, false, true, BASE }, { NULL, 0, 0, false, false, 0 } };
    const struct side_meta after[] = {
        { "grew", 4, 0040755, false, true, BASE | OTHER }, { "file", 4, 0100644, false, true, BASE | OTHER },
        { "lockdir", 7, 0040755, false, true, BASE | LOCK }, { "locked", 6, 0100644, false, true, BASE | LOCK },
        { "plain", 5, 0100644, false, true, BASE },        { NULL, 0, 0, false, false, 0 } };
    g_sides[0] = before;
    g_sides[1] = after;
    g_fn = table_mode;
    ASSERT_EQ_INT(0, render(HEAD
        "{\"path\":\"file\",\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"iflags\"]}\n"
        "{\"path\":\"gone\",\"outcome\":\"removed\",\"type\":\"reg\"}\n"
        "{\"path\":\"goneplain\",\"outcome\":\"removed\",\"type\":\"reg\"}\n"
        "{\"path\":\"grew\",\"outcome\":\"metadata_only\",\"type\":\"dir\",\"changed\":[\"iflags\"]}\n"
        "{\"path\":\"lockdir\",\"outcome\":\"metadata_only\",\"type\":\"dir\",\"changed\":[\"iflags\"]}\n"
        "{\"path\":\"locked\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        "{\"path\":\"plain\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        TRAIL("0", "2", "3", "0", "0", "0", "0"), true));
    g_fn = fake_mode;
    const char *priv = strstr(g_text, "\nprivilege\n"), *rest = strstr(g_text, "\nchanges\n");
    REQUIRE(priv != NULL && rest != NULL && priv < rest);
    const size_t pl = (size_t)(rest - priv);
    static char p[4096];
    snprintf(p, sizeof p, "%.*s", (int)pl, priv);
    ASSERT_TRUE(strstr(p, "  ~ file   inode flags changed\n") != NULL);            /* IF-4 */
    ASSERT_TRUE(strstr(p, "  ~ lockdir   inode flags changed\n") != NULL);         /* IF-2, a locking flag */
    ASSERT_TRUE(strstr(p, "  A locked   inode flags set\n") != NULL);              /* IF-3, IF-8 */
    ASSERT_TRUE(strstr(p, "  D gone   inode flags removed\n") != NULL);
    ASSERT_TRUE(strstr(p, "grew") == NULL);                                         /* IF-2 */
    ASSERT_TRUE(strstr(p, "plain") == NULL);                                        /* IF-3: covers goneplain too */
    ASSERT_TRUE(strstr(rest, "  ~ grew   iflags\n") != NULL);                      /* IF-8: still shown */
    ASSERT_TRUE(strstr(rest, "  A plain\n") != NULL && strstr(rest, "  D goneplain\n") != NULL);
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

/* Second review 2026-10-31, D6 and D8: invisible format and bidi
 * characters, overlong forms, surrogates, DEL and code points past
 * U+10FFFF are shown as bytes; a type change that is also a privilege
 * change says both. */
TEST(invisible_and_invalid_bytes_are_shown_and_a_type_change_is_said) {
    static const struct side_meta before[] = { { "tc", 2, 0040755, false }, { NULL, 0, 0, false } };
    static const struct side_meta after[] = { { "tc", 2, 0104755, false }, { NULL, 0, 0, false } };
    g_sides[0] = before;
    g_sides[1] = after;
    g_fn = table_mode;
    const int rc = render(HEAD
        "{\"path\":\"rlo\\u202eexe.txt\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        "{\"path_b64\":\"YcCvYu2ggGP0kICAZH8=\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        "{\"path\":\"tc\",\"outcome\":\"type_changed\",\"type\":\"reg\",\"type_before\":\"dir\"}\n"
        "{\"path\":\"zw\\u200bj\\u2028x\\ufeff\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        TRAIL("0", "3", "0", "0", "0", "0", "0"), false);
    g_fn = fake_mode;
    ASSERT_EQ_INT(0, rc);
    ASSERT_TRUE(strstr(g_text, "  A rlo\\xe2\\x80\\xaeexe.txt\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  A a\\xc0\\xafb\\xed\\xa0\\x80c\\xf4\\x90\\x80\\x80d\\x7f\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  T tc   dir -> reg, setuid added (mode 0755 -> 4755)\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  A zw\\xe2\\x80\\x8bj\\xe2\\x80\\xa8x\\xef\\xbb\\xbf\n") != NULL);
}

/* Decision 2026-11-01, 7: no banner, but one line counting the entries that
 * changed while they were read -- raced, unstable or vanished, either side
 * -- saying a re-run settles them. */
TEST(entries_that_changed_while_read_are_counted_in_one_line) {
    ASSERT_EQ_INT(0, render(HEAD "{\"belay_diff_end\":9,\"unchanged\":1,\"added\":0,\"removed\":0,\"modified\":0,"
        "\"type_changed\":0,\"metadata_only\":0,\"unknown\":0,\"dir_timestamps_only\":0,\"events\":0,"
        "\"before_vanished\":0,\"before_unstable\":0,\"before_raced\":1,\"after_vanished\":0,\"after_unstable\":0,"
        "\"after_raced\":0,\"provisional\":true,\"before_sha256\":\"x\",\"after_sha256\":\"y\"}\n", false));
    ASSERT_EQ_STR("belay diff  /w  checkpoint 3 -> checkpoint 4\n  no changes\n"
                  "  1 entry changed while it was read (checkpoint 3); a diff from a later checkpoint avoids it\n",
                  g_text);
    ASSERT_EQ_INT(0, render(HEAD "{\"belay_diff_end\":9,\"unchanged\":1,\"added\":0,\"removed\":0,\"modified\":0,"
        "\"type_changed\":0,\"metadata_only\":0,\"unknown\":0,\"dir_timestamps_only\":0,\"events\":0,"
        "\"before_vanished\":0,\"before_unstable\":2,\"before_raced\":0,\"after_vanished\":0,\"after_unstable\":0,"
        "\"after_raced\":1,\"provisional\":true,\"before_sha256\":\"x\",\"after_sha256\":\"y\"}\n", false));
    ASSERT_TRUE(strstr(g_text, "  1 entry changed while it was read (checkpoint 4); running belay again settles it;"
                               " 2 entries changed while they were read (checkpoint 3); a diff from a later"
                               " checkpoint avoids them\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "provisional") == NULL);                 /* no banner */
    /* Review 2026-11-01, D2: a hostile trailer's counts saturate, never wrap
     * (the old sum overflowed int64 and printed nothing). */
    ASSERT_EQ_INT(0, render(HEAD "{\"belay_diff_end\":9,\"unchanged\":1,\"added\":0,\"removed\":0,\"modified\":0,"
        "\"type_changed\":0,\"metadata_only\":0,\"unknown\":0,\"dir_timestamps_only\":0,\"events\":0,"
        "\"before_vanished\":9223372036854775807,\"before_unstable\":9223372036854775807,"
        "\"before_raced\":9223372036854775807,\"after_vanished\":0,\"after_unstable\":0,"
        "\"after_raced\":0,\"provisional\":true,\"before_sha256\":\"x\",\"after_sha256\":\"y\"}\n", false));
    ASSERT_TRUE(strstr(g_text, "  18446744073709551615 entries changed while they were read (checkpoint 3)") != NULL);
}

/* Review 2026-11-01, D4: findings past the cap end in and_more, which
 * stands for n more: "and N more" counts them. */
TEST(and_more_findings_are_counted_in_the_receipt) {
    static char diff[8192];
    char findings[4096] = "";
    size_t w = 0;
    for (int i = 1; i <= 19; i++)
        w += (size_t)snprintf(findings + w, sizeof findings - w, "%s{\"kind\":\"x\",\"text\":\"finding %d\"}",
                              i > 1 ? "," : "", i);
    snprintf(findings + w, sizeof findings - w, ",{\"kind\":\"and_more\",\"n\":1000,\"text\":\"and 1000 more\"}");
    snprintf(diff, sizeof diff, HEAD "{\"path\":\"r\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"size\"],"
             "\"findings\":[%s]}\n" TRAIL("1", "0", "0", "0", "0", "0", "0"), findings);
    ASSERT_EQ_INT(0, render(diff, false));
    ASSERT_TRUE(strstr(g_text, "      finding 15\n      and 1004 more\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "finding 16") == NULL);
}

/* Decision 2026-11-01, 5: a receipt shows the values diff.v1 carries where a
 * person reads them -- a mode in octal, an owner, a size, a link target --
 * and the other changed fields by name. */
TEST(a_receipt_shows_the_values_a_person_reads) {
    ASSERT_EQ_INT(0, render(HEAD
        "{\"path\":\"etc/conf\",\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"mode\",\"uid\",\"ctime_ns\"],"
        "\"before\":{\"mode\":33188,\"uid\":1000,\"ctime_ns\":1},\"after\":{\"mode\":33152,\"uid\":0,\"ctime_ns\":2}}\n"
        "{\"path\":\"l\",\"outcome\":\"modified\",\"type\":\"lnk\",\"changed\":[\"link_target\"],"
        "\"before\":{\"link_target\":\"a\"},\"after\":{\"link_target\":\"/etc/\\u001bshadow\"}}\n"
        TRAIL("1", "0", "1", "0", "0", "0", "0"), false));
    ASSERT_TRUE(strstr(g_text, "  ~ etc/conf   mode 0644 -> 0600, uid 1000 -> 0, ctime_ns\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  M l   link_target a -> /etc/\\x1bshadow\n") != NULL);
}

/* Decision 2026-11-01, 5 (R11's coverage): a value the receipt prints is
 * attacker-controlled -- a link target, or a string where a number belongs
 * in a diff belay did not write -- and goes through the escaping paths and
 * texts do: no terminal sequence, no forged line or heading. */
TEST(values_the_receipt_prints_are_escaped) {
    ASSERT_EQ_INT(0, render(HEAD
        "{\"path\":\"l\",\"outcome\":\"modified\",\"type\":\"lnk\",\"changed\":[\"link_target\"],"
        "\"before\":{\"link_target\":\"ok\"},"
        "\"after\":{\"link_target\":\"x\\n\\nprivilege\\n  ~ all fine\\u001b[2J\\u009b31m\\u202e\\\\\"}}\n"
        "{\"path\":\"m\",\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"uid\"],"
        "\"before\":{\"uid\":\"\\u001b]0;pwned\\u0007\"},\"after\":{\"uid\":0}}\n"
        TRAIL("1", "0", "1", "0", "0", "0", "0"), true));
    ASSERT_TRUE(strstr(g_text, "  M l   link_target ok -> x\\x0a\\x0aprivilege\\x0a  ~ all fine\\x1b[2J"
                               "\\xc2\\x9b31m\\xe2\\x80\\xae\\\\\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  ~ m   uid \\x1b]0;pwned\\x07 -> 0\n") != NULL);
    ASSERT_TRUE(strchr(g_text, '\x1b') == NULL && strchr(g_text, '\x07') == NULL);
    ASSERT_TRUE(strstr(g_text, "\nprivilege\n") == NULL);              /* no forged heading */
}

/* 2026-11-04: with git's view, tracked changes first and never cut;
 * untracked next, the only rows the fold counts; ignored ones one line per
 * top-level directory; --all lists everything. Without it, path order. */
TEST(tracked_first_untracked_cut_ignored_folded_by_directory) {
    static char diff[65536];
    size_t w = (size_t)snprintf(diff, sizeof diff, "%s", HEAD);
    for (int i = 0; i < 60; i++)
        w += (size_t)snprintf(diff + w, sizeof diff - w, "{\"path\":\"a%03d.txt\",\"outcome\":\"added\",\"type\":\"reg\"}\n", i);
    w += (size_t)snprintf(diff + w, sizeof diff - w, "%s",
        "{\"path\":\"out\",\"outcome\":\"added\",\"type\":\"dir\"}\n"
        "{\"path\":\"out/a.o\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        "{\"path\":\"out/b.o\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        "{\"path\":\"src/m.c\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"sha256\"]}\n"
        "{\"path\":\"src/n.c\",\"outcome\":\"removed\",\"type\":\"reg\"}\n"
        "{\"path\":\"x.log\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        TRAIL("1", "64", "0", "0", "0", "0", "0"));
    g_class = fake_class;
    g_class_fails = false;
    g_note = "as the repository is now";
    ASSERT_EQ_INT(0, render(diff, false));
    ASSERT_EQ_INT(66, (int)g_classified);
    const char *m = strstr(g_text, "\nchanges\n  M src/m.c   sha256\n  D src/n.c\n  A a000.txt\n");
    ASSERT_TRUE(m != NULL);
    ASSERT_TRUE(strstr(g_text, "  A a049.txt\n  and 10 more (--all shows them)\n"
                               "  git-ignored: 3 changes under out/\n  git-ignored: 1 change in the top directory\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "a050.txt") == NULL && strstr(g_text, "out/a.o") == NULL);
    ASSERT_TRUE(strstr(g_text, "  as the repository is now\n") != NULL);
    ASSERT_EQ_INT(0, render(diff, true));                           /* --all: every row, nothing folded */
    ASSERT_TRUE(strstr(g_text, "  A a059.txt\n  A out\n  A out/a.o\n  A out/b.o\n  A x.log\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "git-ignored") == NULL && strstr(g_text, "more") == NULL);
    g_class_fails = true;                                           /* git cannot say: path order, as before */
    ASSERT_EQ_INT(0, render(diff, false));
    ASSERT_TRUE(strstr(g_text, "\nchanges\n  A a000.txt\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  and 16 more (--all shows them)\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "as the repository is now") == NULL);
    g_class = NULL;
    g_class_fails = false;
    g_note = NULL;
}

/* A repository's .git folds to one line (decision 105, as the dogfood
 * receipt): what git reports there stays unless git's events are in the
 * diff; hooks stay; a reflog that only moved a ref where it was folds, the
 * move counted -- a reset in place may have discarded work -- and so does
 * the index's "index changed" (2026-11-04). */
TEST(git_bookkeeping_folds_and_counts_moves_in_place) {
    static const char *const recs =
        "{\"path\":\".git/hooks/pre-commit\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        "{\"path\":\".git/index\",\"outcome\":\"modified\",\"type\":\"reg\",\"findings\":[{\"kind\":\"git_index_changed\",\"text\":\"index changed\"}]}\n"
        "{\"path\":\".git/logs/HEAD\",\"outcome\":\"modified\",\"type\":\"reg\",\"findings\":["
        "{\"kind\":\"git_reflog_appended\",\"ref\":\"HEAD\",\"entries\":2,\"text\":\"HEAD: 2 reflog entries\"},"
        "{\"kind\":\"git_reflog_move\",\"ref\":\"HEAD\",\"from\":\"aa\",\"to\":\"aa\",\"operation\":\"reset\",\"text\":\"HEAD aa -> aa by reset\"},"
        "{\"kind\":\"git_reflog_move\",\"ref\":\"HEAD\",\"from\":\"aa\",\"to\":\"aa\",\"operation\":\"reset\",\"text\":\"HEAD aa -> aa by reset\"}]}\n"
        "{\"path\":\".git/objects/ab/cd\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        "{\"path\":\"src/m.c\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"sha256\"]}\n"
        "{\"path\":\"vendor/lib/.git/objects/o\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        "{\"path\":\"wt/.git\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"sha256\"]}\n";
    static char diff[8192];
    snprintf(diff, sizeof diff, HEAD "%s" TRAIL("4", "3", "0", "0", "0", "0", "0"), recs);
    ASSERT_EQ_INT(0, render(diff, false));
    ASSERT_TRUE(strstr(g_text, "  M src/m.c   sha256\n  M wt/.git   sha256\n  A .git/hooks/pre-commit\n"
                               "  git bookkeeping: 3 changes under .git/ (2 resets in place)\n"
                               "  git bookkeeping: 1 change under vendor/lib/.git/\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "by reset") == NULL);
    snprintf(diff, sizeof diff, HEAD "%s{\"event\":\"git_head_switched\",\"interp\":\"git\",\"text\":\"HEAD main -> dev\"}\n"
             TRAIL("4", "3", "0", "0", "1", "0", "0"), recs);
    ASSERT_EQ_INT(0, render(diff, false));                          /* git's events say it: the same */
    ASSERT_TRUE(strstr(g_text, "  A .git/hooks/pre-commit\n  git bookkeeping: 3 changes under .git/ (2 resets in place)\n") != NULL);
    ASSERT_EQ_INT(0, render(diff, true));
    ASSERT_TRUE(strstr(g_text, "bookkeeping") == NULL && strstr(g_text, "  A .git/objects/ab/cd\n") != NULL);
}

/* An edit to a git-ignored file is named, never folded: often .env or local
 * configuration. Its text or its type changed; a binary rewritten (build
 * output), an entry added or removed, a directory: those fold (2026-11-04). */
TEST(ignored_text_edits_are_named_and_the_rest_ignored_folds) {
    static const char diff[] = HEAD
        "{\"path\":\"out\",\"outcome\":\"modified\",\"type\":\"dir\",\"changed\":[\"mtime_ns\"]}\n"
        "{\"path\":\"out/a.o\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"sha256\"]}\n"
        "{\"path\":\"out/b.o\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        "{\"path\":\"out/config.env\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"sha256\"],\"findings\":"
        "[{\"kind\":\"text_changed\",\"lines_added\":1,\"lines_deleted\":0,\"text\":\"+1 -0 lines, first change at line 3\"}]}\n"
        "{\"path\":\"out/link\",\"outcome\":\"type_changed\",\"type\":\"symlink\",\"type_before\":\"reg\"}\n"
        "{\"path\":\"src/m.c\",\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"sha256\"]}\n"
        "{\"path\":\"x.log\",\"outcome\":\"removed\",\"type\":\"reg\"}\n"
        TRAIL("7", "7", "0", "0", "0", "0", "0");
    g_class = fake_class;
    g_class_fails = false;
    ASSERT_EQ_INT(0, render(diff, false));
    ASSERT_TRUE(strstr(g_text, "\nchanges\n  M src/m.c   sha256\n"
                               "  M out/config.env   (git-ignored)\n      +1 -0 lines, first change at line 3\n"
                               "  T out/link   (git-ignored)   reg -> symlink\n"
                               "  git-ignored: 3 changes under out/\n  git-ignored: 1 change in the top directory\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "out/a.o") == NULL && strstr(g_text, "out/b.o") == NULL);
    g_class = NULL;
}

/* Unknown rows under an ignored directory fold, counted by reason, most first;
 * on tracked and untracked paths, and at the top, they stay named (2026-11-05). */
TEST(ignored_unknown_rows_fold_by_directory_and_reason) {
    static const char diff[] = HEAD
        "{\"path\":\"a.txt\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"unstable\"]}\n"
        "{\"path\":\"out\",\"outcome\":\"unknown\",\"type\":\"dir\",\"unknown\":[\"listing_incomplete\"]}\n"
        "{\"path\":\"out/a.o\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"listing_incomplete\"]}\n"
        "{\"path\":\"out/b.o\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"raced\",\"unverified\"]}\n"
        "{\"path\":\"out/c.o\",\"outcome\":\"added\",\"type\":\"reg\"}\n"
        "{\"path\":\"out/held\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"raced\",\"writer_open\"]}\n"
        "{\"path\":\"src/m.c\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"raced\"]}\n"
        "{\"path\":\"x.log\",\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"writer_open\"]}\n"
        TRAIL("0", "1", "0", "7", "0", "0", "0");
    g_class = fake_class;
    g_class_fails = false;
    ASSERT_EQ_INT(0, render(diff, false));
    ASSERT_TRUE(strstr(g_text, "  ? src/m.c   unknown: raced\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  ? a.txt   unknown: unstable\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  ? x.log   (git-ignored)   unknown: writer_open\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  git-ignored: 1 change under out/\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "  git-ignored: 3 unknown under out/ (listing_incomplete 2, raced 1)\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "out/a.o") == NULL);
    ASSERT_TRUE(strstr(g_text, "  ? out/held   (git-ignored)   unknown: raced, writer_open\n") != NULL);   /* never folded */
    ASSERT_EQ_INT(0, render(diff, true));                           /* --all: every row */
    ASSERT_TRUE(strstr(g_text, "  ? out/a.o   unknown: listing_incomplete\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "git-ignored:") == NULL);
    g_class = NULL;
}

/* Manifest v4: what the writer probe could not ask, on one line, only when
 * there is something to say. */
TEST(files_hashed_unguarded_are_said_on_one_line) {
    static const char tail[] = ",\"before_writer_open\":0,\"after_writer_open\":0,\"before_unguarded\":3,\"after_unguarded\":4}\n";
    static char diff[2048], end[1024];
    snprintf(end, sizeof end, "%s", TRAIL("0", "0", "0", "0", "0", "0", "0"));
    char *close_brace = strrchr(end, '}');
    REQUIRE(close_brace != NULL);
    snprintf(close_brace, sizeof end - (size_t)(close_brace - end), "%s", tail);
    snprintf(diff, sizeof diff, "%s%s", HEAD, end);
    ASSERT_EQ_INT(0, render(diff, false));
    ASSERT_TRUE(strstr(g_text, "  hashed with no check for a concurrent writer: 3 before, 4 after\n") != NULL);
    snprintf(diff, sizeof diff, HEAD "%s", TRAIL("0", "0", "0", "0", "0", "0", "0"));
    ASSERT_EQ_INT(0, render(diff, false));
    ASSERT_TRUE(strstr(g_text, "concurrent writer") == NULL);
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
    RUN(invisible_and_invalid_bytes_are_shown_and_a_type_change_is_said);
    RUN(entries_that_changed_while_read_are_counted_in_one_line);
    RUN(and_more_findings_are_counted_in_the_receipt);
    RUN(a_receipt_shows_the_values_a_person_reads);
    RUN(values_the_receipt_prints_are_escaped);
    RUN(tracked_first_untracked_cut_ignored_folded_by_directory);
    RUN(git_bookkeeping_folds_and_counts_moves_in_place);
    RUN(ignored_text_edits_are_named_and_the_rest_ignored_folds);
    RUN(inode_flags_are_privilege_only_where_the_pin_counts_them);
    RUN(files_hashed_unguarded_are_said_on_one_line);
    RUN(ignored_unknown_rows_fold_by_directory_and_reason);
    free(g_text);
    return belay_test_report();
}
