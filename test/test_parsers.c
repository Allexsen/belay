/*
 *  The interpreters' parsers (src/interp/): fixtures written from the
 *  formats' documents -- deb-control(5), PEP 376 and the wheel spec,
 *  gitrepository-layout(5) and git-update-ref(1) -- never from a run; the
 *  line counts against an independent dynamic program.
 */
#include "belay_test.h"
#include "belay/error.h"
#include "interp/gitfmt.h"
#include "interp/linediff.h"
#include "interp/record_csv.h"
#include "interp/stanza.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- dpkg status ---- */

static char g_seen[8][200];
static int g_n;
static int keep_pkg(const struct stanza_pkg *p, void *c) {
    (void)c;
    if (g_n < 8)
        snprintf(g_seen[g_n], sizeof g_seen[g_n], "%.*s|%.*s|%.*s|%.*s",
                 (int)p->package_len, p->package ? p->package : "", (int)p->arch_len,
                 p->arch ? p->arch : "", (int)p->version_len, p->version ? p->version : "",
                 (int)p->status_len, p->status ? p->status : "");
    g_n++;
    return 0;
}

TEST(a_dpkg_status_file_gives_each_package) {
    const char *s =
        "Package: bash\n"
        "Status: install ok installed\n"
        "Priority: required\n"
        "Architecture: amd64\n"
        "Version: 5.2.21-2ubuntu4\n"
        "Description: GNU Bourne Again SHell\n"
        " Bash is an sh-compatible command language interpreter.\n"
        " .\n"
        "\n"
        "package: libfoo1\n"                       /* field names are case-insensitive */
        "STATUS:   deinstall ok config-files  \n"
        "Version: 1:2.0~rc1-3\n"
        "\n\n"
        "Package: held\r\n"
        "Status: hold ok installed\r\n"
        "Architecture: all\r\n"
        "Version: 1.0\r\n";
    g_n = 0;
    ASSERT_EQ_INT(0, stanza_each(s, strlen(s), keep_pkg, NULL));
    ASSERT_EQ_INT(3, g_n);
    ASSERT_TRUE(strcmp(g_seen[0], "bash|amd64|5.2.21-2ubuntu4|install ok installed") == 0);
    ASSERT_TRUE(strcmp(g_seen[1], "libfoo1||1:2.0~rc1-3|deinstall ok config-files") == 0);
    ASSERT_TRUE(strcmp(g_seen[2], "held|all|1.0|hold ok installed") == 0);
}

/* A field the parser does not read may be any length: real status files
 * carry Depends and Static-Built-Using lines of several KiB (found running
 * on a real /var/lib/dpkg/status, 2026-10-31). */
TEST(a_long_field_that_is_not_read_is_fine) {
    char *s = malloc(8192);
    REQUIRE(s != NULL);
    int w = sprintf(s, "Package: go-tool\nStatus: install ok installed\nStatic-Built-Using: ");
    memset(s + w, 'x', 5000);
    w += 5000;
    w += sprintf(s + w, "\nVersion: 1.0\n");
    g_n = 0;
    ASSERT_EQ_INT(0, stanza_each(s, (size_t)w, keep_pkg, NULL));
    ASSERT_EQ_INT(1, g_n);
    ASSERT_TRUE(strcmp(g_seen[0], "go-tool||1.0|install ok installed") == 0);
    free(s);
}

TEST(a_malformed_dpkg_status_is_an_error) {
    static const char *const bad[] = {
        "Package: a\nnot a field\n",                /* neither field nor continuation */
        " continuation first\n",
        "Status: install ok installed\n",           /* no Package */
        ": no name\n",
        "Package: a\nVersion: 1.1\n .5\n",        /* a simple field folded (Policy 5.1) */
        "Package: a\nStatus: install ok\n installed\n",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        g_n = 0;
        if (stanza_each(bad[i], strlen(bad[i]), keep_pkg, NULL) != -1 || belay_err_code() != BELAY_ERR_CORRUPT)
            BELAY_FAIL("accepted: %s", bad[i]);
        belay_err_clear();
    }
}

/* The reference author's case B (2026-10-31): a read field of any length
 * parses -- one too long for an event breaks only that event (E9), not the
 * file. Before, 1,025 bytes made the whole status unparseable. */
TEST(a_long_read_field_parses) {
    char *big = malloc(1025 + 40);
    REQUIRE(big != NULL);
    int w = sprintf(big, "Package: ");
    memset(big + w, 'x', 1025);
    big[w + 1025] = '\n';
    g_n = 0;
    ASSERT_EQ_INT(0, stanza_each(big, (size_t)w + 1026, keep_pkg, NULL));
    ASSERT_EQ_INT(1, (int)g_n);
    free(big);
}

/* ---- pip RECORD ---- */

static int keep_row(const struct record_row *r, void *c) {
    (void)c;
    if (g_n < 8) snprintf(g_seen[g_n], sizeof g_seen[g_n], "%s|%s|%s", r->path, r->hash, r->size);
    g_n++;
    return 0;
}

TEST(a_pip_record_gives_each_row) {
    const char *s =
        "numpy/__init__.py,sha256=AbC-_1,1234\n"
        "\"numpy/odd,name.py\",sha256=x,5\r\n"
        "\"say \"\"hi\"\".txt\",,\n"                /* quotes doubled; empty hash, size */
        "\n"
        "numpy-2.2.0.dist-info/RECORD,,\n";
    g_n = 0;
    ASSERT_EQ_INT(0, record_each(s, strlen(s), keep_row, NULL));
    ASSERT_EQ_INT(4, g_n);
    ASSERT_TRUE(strcmp(g_seen[0], "numpy/__init__.py|sha256=AbC-_1|1234") == 0);
    ASSERT_TRUE(strcmp(g_seen[1], "numpy/odd,name.py|sha256=x|5") == 0);
    ASSERT_TRUE(strcmp(g_seen[2], "say \"hi\".txt||") == 0);
    ASSERT_TRUE(strcmp(g_seen[3], "numpy-2.2.0.dist-info/RECORD||") == 0);
}

TEST(a_malformed_pip_record_is_an_error) {
    static const char *const bad[] = {
        "a,b\n", "a,b,c,d\n", "\"unterminated,b,c\n", "a\"b,c,d\n", "\"a\"x,b,c\n", "a,b,c\rx\n",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        g_n = 0;
        if (record_each(bad[i], strlen(bad[i]), keep_row, NULL) != -1 || belay_err_code() != BELAY_ERR_CORRUPT)
            BELAY_FAIL("accepted: %s", bad[i]);
        belay_err_clear();
    }
}

/* ---- git ---- */

#define O1 "0123456789abcdef0123456789abcdef01234567"
#define O2 "89abcdef0123456789abcdef0123456789abcdef"

static int keep_packed(const char *ref, size_t rl, const char *oid, size_t ol, void *c) {
    (void)c;
    if (g_n < 8) snprintf(g_seen[g_n], sizeof g_seen[g_n], "%.*s=%.*s", (int)rl, ref, (int)ol, oid);
    g_n++;
    return 0;
}

static int keep_log(const struct git_reflog_entry *e, void *c) {
    (void)c;
    if (g_n < 8)
        snprintf(g_seen[g_n], sizeof g_seen[g_n], "%.2s>%.2s:%.*s", e->old_oid, e->new_oid,
                 (int)e->operation_len, e->operation);
    g_n++;
    return 0;
}

/* The parsers lowercase ids in place: each case gets its own copy. */
static char g_buf[4096];
static char *mut(const char *s) {
    snprintf(g_buf, sizeof g_buf, "%s", s);
    return g_buf;
}

TEST(git_ref_files_packed_refs_and_reflogs_parse) {
    bool sym;
    const char *v;
    size_t vl;
    ASSERT_EQ_INT(0, git_ref_value(mut("ref: refs/heads/main\n"), 21, &sym, &v, &vl));
    ASSERT_TRUE(sym && vl == 15 && memcmp(v, "refs/heads/main", 15) == 0);
    ASSERT_EQ_INT(0, git_ref_value(mut(O1 "\n"), 41, &sym, &v, &vl));
    ASSERT_TRUE(!sym && vl == 40);
    ASSERT_EQ_INT(-1, git_ref_value(mut("not a ref\n"), 10, &sym, &v, &vl));
    belay_err_clear();
    /* an object id is 40 or 64 lowercase hex digits, nothing else */
    ASSERT_TRUE(git_oid(O1, 40) && git_oid(O1 O1 "012345678901234567890123", 64));
    ASSERT_FALSE(git_oid(O1, 39) || git_oid(O1 "0", 41) || git_oid(O1 O1, 80));
    ASSERT_FALSE(git_oid("0123456789ABCDEF0123456789abcdef01234567", 40));
    ASSERT_EQ_INT(-1, git_ref_value(mut("0123456789abcdef0123456789abcdef0123456\n"), 40, &sym, &v, &vl));
    belay_err_clear();
    const char *packed = "# pack-refs with: peeled fully-peeled sorted \n"
                         O1 " refs/heads/main\n" O2 " refs/tags/v1\n^" O1 "\n";
    g_n = 0;
    ASSERT_EQ_INT(0, git_packed_each(mut(packed), strlen(packed), keep_packed, NULL));
    ASSERT_EQ_INT(2, g_n);
    ASSERT_TRUE(strcmp(g_seen[1], "refs/tags/v1=" O2) == 0);
    const char *log =
        O1 " " O2 " A U Thor <a@example.com> 1761000000 +0400\tcommit (amend): fix\n"
        O2 " " O1 " A U Thor <a@example.com> 1761000100 +0400\treset: moving to HEAD~1\n"
        O1 " " O2 " A U Thor <a@example.com> 1761000200 +0400\trebase (finish): returning\n"
        O2 " " O1 " A U Thor <a@example.com> 1761000300 +0400\tno colon here\n";
    g_n = 0;
    size_t ign = 9;
    ASSERT_EQ_INT(0, git_reflog_each(mut(log), strlen(log), keep_log, NULL, &ign));
    ASSERT_EQ_INT(4, g_n);
    ASSERT_EQ_INT(0, (int)ign);
    ASSERT_TRUE(strcmp(g_seen[0], "01>89:commit (amend)") == 0);
    ASSERT_TRUE(strcmp(g_seen[1], "89>01:reset") == 0);
    ASSERT_TRUE(strcmp(g_seen[2], "01>89:rebase (finish)") == 0);
    ASSERT_TRUE(strcmp(g_seen[3], "89>01:no colon here") == 0);
}

/* Refs as git 2.43.0 reads them (decision 202): each case below was probed
 * with `git rev-parse --verify` and `git symbolic-ref` first. */
TEST(refs_are_read_as_git_reads_them) {
    static const char *const read[] = {
        O1 "   \n", O1 "\r\n", O1 " junk\n", O1 "\tx\n", O1 "\n" O2 "\n", O1,
        "0123456789ABCDEF0123456789ABCDEF01234567\n", "0123456789ABCDEF0123456789ABCDEF01234567 x\n",
    };
    for (size_t i = 0; i < sizeof read / sizeof read[0]; i++) {
        bool sym = true;
        const char *v;
        size_t vl;
        if (git_ref_value(mut(read[i]), strlen(read[i]), &sym, &v, &vl) != 0 || sym || !git_oid(v, vl))
            BELAY_FAIL("not read as git reads it: %s", read[i]);
    }
    static const char *const broken[] = { O1 "junk\n", " " O1 "\n", "0123456789abcdef0123456789abcdef0123456\n",
                                          "REF: refs/heads/main\n", "ref: refs/heads/main junk\n", "ref:\n" };
    for (size_t i = 0; i < sizeof broken / sizeof broken[0]; i++) {
        bool sym;
        const char *v;
        size_t vl;
        if (git_ref_value(mut(broken[i]), strlen(broken[i]), &sym, &v, &vl) != -1)
            BELAY_FAIL("read a ref git calls broken: %s", broken[i]);
        belay_err_clear();
    }
    static const char *const symbolic[] = { "ref: refs/heads/main   \n", "ref: refs/heads/main\r\n",
                                            "ref:  refs/heads/main\n", "ref:refs/heads/main\n", "ref:\trefs/heads/main\n" };
    for (size_t i = 0; i < sizeof symbolic / sizeof symbolic[0]; i++) {
        bool sym = false;
        const char *v;
        size_t vl;
        if (git_ref_value(mut(symbolic[i]), strlen(symbolic[i]), &sym, &v, &vl) != 0 || !sym || vl != 15 ||
            memcmp(v, "refs/heads/main", 15) != 0)
            BELAY_FAIL("not read as git reads it: %s", symbolic[i]);
    }
    /* uppercase in packed-refs too, lowercased */
    const char *pk = "0123456789ABCDEF0123456789ABCDEF01234567 refs/heads/main\n";
    g_n = 0;
    ASSERT_EQ_INT(0, git_packed_each(mut(pk), strlen(pk), keep_packed, NULL));
    ASSERT_TRUE(g_n == 1 && strcmp(g_seen[0], "refs/heads/main=" O1) == 0);
}

/* Reflog lines as git 2.43.0 reads them (decision 202): each probed with
 * `git reflog show` between two good entries. */
#define ID O1 " " O2 " "
TEST(reflog_lines_git_skips_are_skipped_and_counted) {
    static const char *const entry[] = {
        ID "a <a@b> 1700000000 +0000\tcommit: x", ID "a <a@b> 1700000000 +0000", ID "a <a@b> 1700000000 +0000 x",
        ID "a <a@b> 1700000000 +0000x\tx", ID "a a@b> 1700000000 +0000\tx", ID "<> 1700000000 +0000\tx",
        ID "a <a@b>  1700000000 +0000\tx", ID "a <a@b> +1700000000 +0000\tx", ID "a <a@b> -5 +0000\tx",
        ID "a <a@b> 99999999999999999999999999999999999999 +0000\tx", ID "a <a@b> 1700000000 +0000\tx\r",
        "0123456789ABCDEF0123456789ABCDEF01234567 " O2 " a <a@b> 1700000000 +0000\tx",
    };
    static const char *const skipped[] = {
        "", "   ", "this is not a reflog entry", "123456789abcdef0123456789abcdef01234567 " O2 " a <a@b> 1 +0000\tx",
        ID "a <a@b> notatime +0000\tx", O1 " " O2 " 1700000000 +0000\tx", "a\001b", ID "a <a@b> 0 +0000\tx",
        ID "a <a@b> 1700000000 +00\tx", ID "a <a@b> 1700000000 0000\tx", O1 "  " O2 " a <a@b> 1700000000 +0000\tx",
        " " ID "a <a@b> 1700000000 +0000\tx", ID "a> <a@b> 1700000000 +0000\tx", ID "a <a@b>\t1700000000 +0000\tx",
    };
    char log[4096];
    for (int want = 1; want >= 0; want--) {
        const char *const *set = want ? entry : skipped;
        const size_t n = want ? sizeof entry / sizeof entry[0] : sizeof skipped / sizeof skipped[0];
        for (size_t i = 0; i < n; i++) {
            const int w = snprintf(log, sizeof log, "%s%s\n%s", ID "a <a@b> 1 +0000\tc\n", set[i], ID "a <a@b> 2 +0000\td\n");
            size_t ign = 99;
            g_n = 0;
            if (git_reflog_each(log, (size_t)w, keep_log, NULL, &ign) != 0) BELAY_FAIL("refused: %s", set[i]);
            if (g_n != 2 + want || ign != (size_t)!want) BELAY_FAIL("%s: %d entries, %zu ignored", set[i], g_n, ign);
        }
    }
    /* a last line without its newline: neither an entry nor counted (decision 183) */
    const int w = snprintf(log, sizeof log, "%s%s", ID "a <a@b> 1 +0000\tc\n", "garbage, cut");
    size_t ign = 99;
    g_n = 0;
    ASSERT_EQ_INT(0, git_reflog_each(log, (size_t)w, keep_log, NULL, &ign));
    ASSERT_TRUE(g_n == 1 && ign == 0);
}
#undef ID

/* ---- line counts, against an independent O(NM) dynamic program ---- */

static size_t lines_of(const char *s, size_t n, const char **st, size_t *ln) {
    size_t k = 0, b = 0;
    for (size_t i = 0; i < n; i++)
        if (s[i] == '\n' || i + 1 == n) { st[k] = s + b; ln[k++] = i + 1 - b; b = i + 1; }
    return k;
}

static size_t lcs_dp(const char *a, size_t al, const char *b, size_t bl) {
    const char *as[64], *bs[64];
    size_t an[64], bn[64], t[65][65] = { { 0 } };
    const size_t N = lines_of(a, al, as, an), M = lines_of(b, bl, bs, bn);
    for (size_t i = 1; i <= N; i++)
        for (size_t j = 1; j <= M; j++)
            t[i][j] = (an[i - 1] == bn[j - 1] && memcmp(as[i - 1], bs[j - 1], an[i - 1]) == 0)
                          ? t[i - 1][j - 1] + 1
                          : (t[i - 1][j] > t[i][j - 1] ? t[i - 1][j] : t[i][j - 1]);
    return t[N][M];
}

TEST(line_counts_match_the_longest_common_subsequence) {
    ASSERT_EQ_INT(3, (int)line_count("a\nb\nc", 5));          /* a final line without '\n' */
    ASSERT_EQ_INT(3, (int)line_count("a\nb\nc\n", 6));
    ASSERT_EQ_INT(0, (int)line_count("", 0));
    struct line_delta d;
    ASSERT_EQ_INT(0, line_delta("a\nb\nc\n", 6, "a\nx\nc\nd\n", 8, &d));
    ASSERT_TRUE(d.counted && d.deleted == 1 && d.added == 2 && d.first_changed == 2);
    ASSERT_EQ_INT(0, line_delta("a", 1, "a\n", 2, &d));          /* the newline is the change */
    ASSERT_TRUE(d.counted && d.deleted == 1 && d.added == 1 && d.first_changed == 1);
    srand(20261031);
    char a[64], b[64];
    for (int round = 0; round < 2000; round++) {          /* random line soups over 3 words */
        size_t al = 0, bl = 0;
        const int na = rand() % 12, nb = rand() % 12;
        for (int k = 0; k < na; k++) { a[al++] = (char)('a' + rand() % 3); a[al++] = '\n'; }
        for (int k = 0; k < nb; k++) { b[bl++] = (char)('a' + rand() % 3); b[bl++] = '\n'; }
        if (rand() % 4 == 0 && al > 0) al--;              /* sometimes no final newline */
        REQUIRE(line_delta(a, al, b, bl, &d) == 0);
        const size_t lcs = lcs_dp(a, al, b, bl);
        if (!d.counted || d.deleted != d.lines_a - lcs || d.added != d.lines_b - lcs)
            BELAY_FAIL("round %d: got -%zu +%zu, want -%zu +%zu", round, d.deleted, d.added,
                       d.lines_a - lcs, d.lines_b - lcs);
    }
}

/* The pinned bound (finding kinds, text_rewritten): counted up to 2,000
 * edits, not past them. n lines that all differ are 2n edits. */
static bool counted_with(size_t n, struct line_delta *d) {
    char *a = malloc(n * 2 + 1), *b = malloc(n * 2 + 1);
    if (a == NULL || b == NULL) abort();
    for (size_t i = 0; i < n; i++) { a[2 * i] = 'a'; a[2 * i + 1] = '\n'; b[2 * i] = 'b'; b[2 * i + 1] = '\n'; }
    if (line_delta(a, n * 2, b, n * 2, d) != 0) abort();
    free(a);
    free(b);
    return d->counted;
}

TEST(a_rewrite_past_the_bound_is_not_counted) {
    struct line_delta d;
    ASSERT_TRUE(counted_with(1000, &d));                       /* 2,000 edits */
    ASSERT_TRUE(d.deleted == 1000 && d.added == 1000);
    ASSERT_FALSE(counted_with(1001, &d));                      /* 2,002 edits */
    ASSERT_TRUE(d.lines_a == 1001 && d.lines_b == 1001 && d.first_changed == 1);
}

int main(void) {
    RUN(a_dpkg_status_file_gives_each_package);
    RUN(a_long_field_that_is_not_read_is_fine);
    RUN(a_malformed_dpkg_status_is_an_error);
    RUN(a_long_read_field_parses);
    RUN(a_pip_record_gives_each_row);
    RUN(a_malformed_pip_record_is_an_error);
    RUN(git_ref_files_packed_refs_and_reflogs_parse);
    RUN(refs_are_read_as_git_reads_them);
    RUN(reflog_lines_git_skips_are_skipped_and_counted);
    RUN(line_counts_match_the_longest_common_subsequence);
    RUN(a_rewrite_past_the_bound_is_not_counted);
    return belay_test_report();
}
