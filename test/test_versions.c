/*
 *  Version orderings (src/interp/versions.c), from the formats' own
 *  documents, never from a run: PEP 440's ordering example, and Debian's
 *  rules in deb-version(7) and Policy 5.6.12.
 */
#include "belay_test.h"
#include "interp/versions.h"

#include <string.h>

static int deb(const char *a, const char *b) { return debver_cmp(a, strlen(a), b, strlen(b)); }

static int pep(const char *a, const char *b, int *ok) {
    int c = 0;
    *ok = pep440_cmp(a, strlen(a), b, strlen(b), &c) == 0;
    return c;
}

/* Each list strictly ascending: every earlier one sorts before every later
 * one, both ways round, and each equals itself. */
TEST(debian_versions_sort_as_documented) {
    static const char *const up[] = {
        "~~", "~~a", "~", "0", "0.9~rc1", "0.9", "1.0~beta", "1.0~rc1", "1.0", "1.0-1", "1.0-1+b1",
        "1.0-2", "1.0a", "1.0b", "1.0+a", "1.00.1", "1.2", "1.10", "2:0.1", "10:0",
    };
    const size_t n = sizeof up / sizeof up[0];
    for (size_t i = 0; i < n; i++) {
        if (deb(up[i], up[i]) != 0) BELAY_FAIL("%s != itself", up[i]);
        for (size_t j = i + 1; j < n; j++)
            if (!(deb(up[i], up[j]) < 0 && deb(up[j], up[i]) > 0))
                BELAY_FAIL("%s should sort before %s", up[i], up[j]);
    }
    ASSERT_EQ_INT(0, deb("1.0", "1.0-0") == 0 ? 0 : 1);      /* no revision is revision 0 */
    ASSERT_TRUE(deb("1.01", "1.1") == 0);                    /* numbers compare numerically */
    ASSERT_TRUE(deb("0:1.0", "1.0") == 0);                   /* no epoch is epoch 0 */
}

TEST(pep440_versions_sort_as_the_pep_shows) {
    /* PEP 440, "Summary of permitted suffixes and relative ordering". */
    static const char *const up[] = {
        "1.dev0", "1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12",
        "1.0b1.dev456", "1.0b2", "1.0b2.post345.dev456", "1.0b2.post345", "1.0rc1.dev456",
        "1.0rc1", "1.0", "1.0+abc.5", "1.0+abc.7", "1.0+5", "1.0.post456.dev34", "1.0.post456",
        "1.0.15", "1.1.dev1",
    };
    const size_t n = sizeof up / sizeof up[0];
    int ok;
    for (size_t i = 0; i < n; i++) {
        if (pep(up[i], up[i], &ok) != 0 || !ok) BELAY_FAIL("%s != itself", up[i]);
        for (size_t j = i + 1; j < n; j++) {
            const int x = pep(up[i], up[j], &ok);
            int okr;
            const int y = pep(up[j], up[i], &okr);
            if (!ok || !okr || !(x < 0 && y > 0)) BELAY_FAIL("%s should sort before %s", up[i], up[j]);
        }
    }
    /* Normalization (PEP 440, "Normalization"): these name one version. */
    static const char *const same[][2] = {
        { "1.0", "1.0.0" }, { "1.0a1", "1.0alpha1" }, { "1.0b1", "1.0-beta.1" },
        { "1.0rc1", "1.0c1" }, { "1.0.post1", "1.0-1" }, { "1.0.post0", "1.0.post" },
        { "1.0.dev0", "1.0dev" }, { "v1.0", "1.0" }, { "1.0RC1", "1.0rc1" }, { "0!1.0", "1.0" },
        /* PEP 440 Appendix B: a separator may follow a pre, post or dev
         * signifier with no number (the reference author's case C). */
        { "2a.", "2a0" }, { "1.0.post.", "1.0.post0" }, { "1.0rc--1", "1.0rc0.post1" },
        { "1.0.dev-", "1.0.dev0" },
    };
    for (size_t i = 0; i < sizeof same / sizeof same[0]; i++)
        if (pep(same[i][0], same[i][1], &ok) != 0 || !ok)
            BELAY_FAIL("%s and %s should be equal", same[i][0], same[i][1]);
    /* Not versions: not comparable, never guessed. */
    static const char *const bad[] = { "", "abc", "1.0-", "1..0", "1.0+", "1.0+a..b", "1.0 ", "latest" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        pep(bad[i], "1.0", &ok);
        if (ok) BELAY_FAIL("\"%s\" should not parse", bad[i]);
    }
}

int main(void) {
    RUN(debian_versions_sort_as_documented);
    RUN(pep440_versions_sort_as_the_pep_shows);
    return belay_test_report();
}
