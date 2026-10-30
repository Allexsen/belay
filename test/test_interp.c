/*
 *  Interpreter dispatch. Pure classification, so every case is a path in and
 *  a claim out. The near-misses matter as much as the hits: a false claim
 *  stores content needlessly, a missed claim loses the baseline an
 *  interpreter needs.
 */
#include "belay_test.h"
#include "belay/interp.h"
#include "belay/json.h"

#include <string.h>

static struct belay_claim cls(const char *p) {
    struct belay_claim c;
    belay_interp_classify(p, strlen(p), &c);
    return c;
}

#define EXPECT(path, I, K)                                                   \
    do {                                                                     \
        struct belay_claim _c = cls(path);                                   \
        if (_c.interp != (I) || _c.keep != (K))                              \
            BELAY_FAIL("%s: got %s/%d", path, belay_interp_name(_c.interp),  \
                       (int)_c.keep);                                        \
    } while (0)

TEST(dpkg_claims_status_and_baseline_databases) {
    EXPECT("/var/lib/dpkg/status", BELAY_INTERP_DPKG, BELAY_KEEP_STORE);
    EXPECT("/var/lib/dpkg/info/bash.md5sums", BELAY_INTERP_DPKG, BELAY_KEEP_STORE);
    EXPECT("/var/lib/dpkg/info/libc6:amd64.list", BELAY_INTERP_DPKG, BELAY_KEEP_STORE);
    /* A container root or a host reader's rootfs path. */
    EXPECT("/var/lib/docker/overlay2/ab12/diff/var/lib/dpkg/status",
           BELAY_INTERP_DPKG, BELAY_KEEP_STORE);
}

TEST(dpkg_near_misses_are_not_claimed) {
    EXPECT("/var/lib/dpkg/status-old", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/var/lib/dpkg/status.bak", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/var/lib/dpkg/info/bash.postinst", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/home/u/notes/var/lib/dpkg", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
}

TEST(pip_claims_dist_info_records) {
    EXPECT("/usr/lib/python3/dist-packages/numpy-2.1.0.dist-info/RECORD",
           BELAY_INTERP_PIP, BELAY_KEEP_STORE);
    EXPECT("/home/u/.venv/lib/python3.12/site-packages/requests-2.32.3.dist-info/METADATA",
           BELAY_INTERP_PIP, BELAY_KEEP_STORE);
    EXPECT("/x/numpy-2.1.0.dist-info/INSTALLER", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/x/numpy-2.1.0.dist-info/RECORD.jws", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
}

TEST(git_claims_refs_hooks_and_hashes_the_index) {
    EXPECT("/repo/.git/HEAD", BELAY_INTERP_GIT, BELAY_KEEP_STORE);
    EXPECT("/repo/.git/packed-refs", BELAY_INTERP_GIT, BELAY_KEEP_STORE);
    EXPECT("/repo/.git/refs/heads/main", BELAY_INTERP_GIT, BELAY_KEEP_STORE);
    EXPECT("/repo/.git/refs/remotes/origin/feature/x", BELAY_INTERP_GIT, BELAY_KEEP_STORE);
    EXPECT("/repo/.git/hooks/pre-commit", BELAY_INTERP_GIT, BELAY_KEEP_STORE);
    /* The index can be hundreds of MB; M1 only needs to know it changed. */
    EXPECT("/repo/.git/index", BELAY_INTERP_GIT, BELAY_KEEP_HASH);
}

/* Objects and packs are explicitly out of M1's git scope (no zlib), so they
 * must not be claimed -- claiming them would store every pack. */
TEST(git_objects_and_packs_are_not_claimed) {
    EXPECT("/repo/.git/objects/pack/pack-abc.pack", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/repo/.git/objects/ab/cdef0123", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/repo/.git/config", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/repo/src/.githooks/pre-commit", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
}

TEST(unclaimed_and_hostile_inputs_fall_back_to_binary) {
    EXPECT("/home/u/src/main.c", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);

    /* An embedded NUL must not truncate the path into a claimed one. */
    const char tricky[] = "/var/lib/dpkg/status\0.not-really";
    struct belay_claim c;
    belay_interp_classify(tricky, sizeof tricky - 1, &c);
    ASSERT_EQ_INT(BELAY_INTERP_BINARY, c.interp);

    /* Over-long input is unclaimed, never read past. */
    static char big[9000];
    memset(big, 'a', sizeof big);
    belay_interp_classify(big, sizeof big, &c);
    ASSERT_EQ_INT(BELAY_INTERP_BINARY, c.interp);
}

TEST(names_are_stable) {
    ASSERT_EQ_STR("pip", belay_interp_name(BELAY_INTERP_PIP));
    ASSERT_EQ_STR("dpkg", belay_interp_name(BELAY_INTERP_DPKG));
    ASSERT_EQ_STR("git", belay_interp_name(BELAY_INTERP_GIT));
    ASSERT_EQ_STR("binary", belay_interp_name(BELAY_INTERP_BINARY));
    ASSERT_EQ_STR("unknown", belay_interp_name(BELAY_INTERP_COUNT));
}

/* F3: a finding is cut on a character boundary, never inside a UTF-8
 * sequence -- interpreter text comes from file content. */
TEST(a_long_finding_is_cut_between_characters) {
    char text[600];
    size_t w = 0;                                /* two-byte characters: the 255-byte cut */
    while (w + 2 < sizeof text) { text[w++] = '\xc3'; text[w++] = '\xa9'; }   /* falls inside one */
    text[w] = '\0';
    struct belay_findings f = { 0 };
    ASSERT_EQ_INT(0, belay_findings_add(&f, text));
    const size_t n = strlen(f.item[0]);
    ASSERT_TRUE(n <= BELAY_FINDING_BYTES - 1);
    ASSERT_TRUE(belay_utf8_valid(f.item[0], n));
    ASSERT_EQ_INT(BELAY_FINDING_BYTES - 2, (int)n);
}

/* Review F2: an interpreter controls `n`; past the cap the helper must not
 * write (it compared with ==). A guard after the buffer catches a write. */
TEST(no_finding_is_added_past_the_cap) {
    static struct { struct belay_findings f; char guard[2 * BELAY_FINDING_BYTES]; } g;
    memset(&g, 0, sizeof g);
    g.f.n = BELAY_FINDINGS_MAX + 1;
    ASSERT_EQ_INT(-1, belay_findings_add(&g.f, "x"));
    for (size_t i = 0; i < sizeof g.guard; i++) if (g.guard[i] != 0) { BELAY_FAIL("byte %zu of the guard written", i); break; }
}

/* Review F9: a cut backs up at most three bytes, the most a UTF-8 sequence
 * continues; text that is not UTF-8 stays so, for the emitter to replace,
 * rather than turning into a valid prefix by losing its bad bytes. */
TEST(a_cut_never_makes_bad_text_look_valid) {
    char text[400];
    memcpy(text, "abc", 3);
    memset(text + 3, 0x80, sizeof text - 4);
    text[sizeof text - 1] = '\0';
    struct belay_findings f = { 0 };
    ASSERT_EQ_INT(0, belay_findings_add(&f, text));
    ASSERT_FALSE(belay_utf8_valid(f.item[0], strlen(f.item[0])));
}

int main(void) {
    RUN(dpkg_claims_status_and_baseline_databases);
    RUN(dpkg_near_misses_are_not_claimed);
    RUN(pip_claims_dist_info_records);
    RUN(git_claims_refs_hooks_and_hashes_the_index);
    RUN(git_objects_and_packs_are_not_claimed);
    RUN(unclaimed_and_hostile_inputs_fall_back_to_binary);
    RUN(names_are_stable);
    RUN(a_long_finding_is_cut_between_characters);
    RUN(no_finding_is_added_past_the_cap);
    RUN(a_cut_never_makes_bad_text_look_valid);
    return belay_test_report();
}
