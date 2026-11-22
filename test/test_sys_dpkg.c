/*
 *  dpkg's `auto` (test/expect/system-interpreters.md SD-1): whether apt's
 *  record of the after-manifest marks the event's package automatic. The
 *  stanzas are apt's own shape (`Package`, `Architecture`, `Auto-Installed`),
 *  and the first fixture is SD-1's measured case: after `apt-get install
 *  nginx`, nginx has no stanza and nginx-common has `Auto-Installed: 1`.
 */
#include "sys_test.h"

#define STATUS "var/lib/dpkg/status"
#define STATES "var/lib/apt/extended_states"

#define PKG(name, arch, ver) "Package: " name "\nStatus: install ok installed\nArchitecture: " arch "\nVersion: " ver "\n\n"
#define EV(kind, fields, text) "{\"event\":\"" kind "\",\"interp\":\"dpkg\"," fields ",\"text\":\"" text "\",\"paths\":[\"" STATUS "\"]}\n"

TEST(auto_is_what_apts_record_says_of_the_package_after) {
    t_reset();
    t_file(STATUS, PKG("bash", "amd64", "5.2.21-2ubuntu4") PKG("zlib1g", "amd64", "1:1.3-1") , 0644);
    t_file(STATES, "Package: zlib1g\nArchitecture: amd64\nAuto-Installed: 1\n\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(STATUS, PKG("bash", "amd64", "5.2.21-2ubuntu5") PKG("nginx", "amd64", "1.24.0-2ubuntu7")
                   PKG("nginx-common", "all", "1.24.0-2ubuntu7") PKG("zlib1g", "amd64", "1:1.2-1"), 0644);
    t_file(STATES, "Package: zlib1g\nArchitecture: amd64\nAuto-Installed: 1\n\n"
                   "Package: nginx-common\nArchitecture: all\nAuto-Installed: 1\n\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EV("dpkg_upgraded", "\"package\":\"bash\",\"arch\":\"amd64\",\"from\":\"5.2.21-2ubuntu4\",\"to\":\"5.2.21-2ubuntu5\",\"auto\":false",
           "upgraded bash:amd64 5.2.21-2ubuntu4 -> 5.2.21-2ubuntu5")
        EV("dpkg_installed", "\"package\":\"nginx\",\"arch\":\"amd64\",\"version\":\"1.24.0-2ubuntu7\",\"auto\":false",
           "installed nginx:amd64 1.24.0-2ubuntu7")
        EV("dpkg_installed", "\"package\":\"nginx-common\",\"arch\":\"all\",\"version\":\"1.24.0-2ubuntu7\",\"auto\":true",
           "installed nginx-common:all 1.24.0-2ubuntu7")
        EV("dpkg_downgraded", "\"package\":\"zlib1g\",\"arch\":\"amd64\",\"from\":\"1:1.3-1\",\"to\":\"1:1.2-1\",\"auto\":true",
           "downgraded zlib1g:amd64 1:1.3-1 -> 1:1.2-1"),
        t_events(1, 2));
}

/* The record usually did not change in the diff: it is looked up (SI-4),
 * and a state change carries auto as well. A removal never does. */
TEST(auto_comes_from_a_record_that_did_not_change_and_a_removal_has_none) {
    t_reset();
    t_file(STATUS, PKG("held", "amd64", "1") PKG("gone", "amd64", "2"), 0644);
    t_file(STATES, "Package: held\nArchitecture: amd64\nAuto-Installed: 1\n\n"
                   "Package: gone\nArchitecture: amd64\nAuto-Installed: 1\n\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(STATUS, "Package: held\nStatus: hold ok installed\nArchitecture: amd64\nVersion: 1\n\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EV("dpkg_removed", "\"package\":\"gone\",\"arch\":\"amd64\",\"version\":\"2\"", "removed gone:amd64 2")
        EV("dpkg_state_changed", "\"package\":\"held\",\"arch\":\"amd64\",\"from\":\"install ok installed\",\"to\":\"hold ok installed\",\"auto\":true",
           "held:amd64 install ok installed -> hold ok installed"),
        t_events(1, 2));
}

/* Absent, never assumed: no record in the scope says nothing of auto. */
TEST(auto_is_absent_without_apts_record) {
    t_reset();
    t_file(STATUS, "", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(STATUS, PKG("nginx", "amd64", "1.24.0-2ubuntu7"), 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(EV("dpkg_installed", "\"package\":\"nginx\",\"arch\":\"amd64\",\"version\":\"1.24.0-2ubuntu7\"",
                     "installed nginx:amd64 1.24.0-2ubuntu7"), t_events(1, 2));
    /* A record removed in this diff is not in the after-manifest either. */
    t_reset();
    t_file(STATUS, "", 0644);
    t_file(STATES, "Package: nginx\nArchitecture: amd64\nAuto-Installed: 1\n\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(STATUS, PKG("nginx", "amd64", "1.24.0-2ubuntu7"), 0644);
    t_rm(STATES);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(EV("dpkg_installed", "\"package\":\"nginx\",\"arch\":\"amd64\",\"version\":\"1.24.0-2ubuntu7\"",
                     "installed nginx:amd64 1.24.0-2ubuntu7"), t_events(1, 2));
}

/* One event by hand: the status before and after, and the after-manifest's
 * record as `states` (NULL: an entry with no copy that can be read). */
static const char *one(const char *before, const char *after, const char *states, bool entry) {
    static struct t_run r;
    static bool live;
    if (live) tr_free(&r);
    live = true;
    tr_begin(&r, BELAY_INTERP_DPKG);
    const struct belay_entry b = t_entry(STATUS, BELAY_T_REG, 0644, t_put(before));
    const struct belay_entry a = t_entry(STATUS, BELAY_T_REG, 0644, t_put(after));
    tr_path(&r, STATUS, &b, &a, "modified");
    struct belay_entry e[1];
    e[0] = t_entry(STATES, BELAY_T_REG, 0644,
                   states != NULL ? t_put(states) : "0000000000000000000000000000000000000000000000000000000000000000");
    return tr_end(&r, e, entry ? 1 : 0);
}
#define INST(pkg, arch, autov) EV("dpkg_installed", "\"package\":\"" pkg "\",\"arch\":\"" arch "\",\"version\":\"1\"" autov, "installed " pkg ":" arch " 1")

TEST(auto_matches_package_and_architecture_exactly) {
    /* Another architecture's stanza is another package's. */
    ASSERT_EQ_STR(INST("libx", "amd64", ",\"auto\":false"),
                  one("", PKG("libx", "amd64", "1"), "Package: libx\nArchitecture: i386\nAuto-Installed: 1\n\n", true));
    ASSERT_EQ_STR(INST("libx", "amd64", ",\"auto\":false"),
                  one("", PKG("libx", "amd64", "1"), "Package: libxx\nArchitecture: amd64\nAuto-Installed: 1\n\n", true));
    /* A stanza without Architecture is the package without one, and no other. */
    ASSERT_EQ_STR(INST("libx", "amd64", ",\"auto\":false"),
                  one("", PKG("libx", "amd64", "1"), "Package: libx\nAuto-Installed: 1\n\n", true));
    ASSERT_EQ_STR(EV("dpkg_installed", "\"package\":\"old\",\"arch\":\"\",\"version\":\"1\",\"auto\":true", "installed old: 1"),
                  one("", "Package: old\nStatus: install ok installed\nVersion: 1\n\n", "Package: old\nAuto-Installed: 1\n\n", true));
    /* Two architectures of one package: each by its own stanza. */
    ASSERT_EQ_STR(INST("libc6", "amd64", ",\"auto\":false") INST("libc6", "i386", ",\"auto\":true"),
                  one("", PKG("libc6", "amd64", "1") PKG("libc6", "i386", "1"),
                      "Package: libc6\nArchitecture: i386\nAuto-Installed: 1\n\n", true));
    /* Field names in any case, as deb822 reads them; values trimmed. */
    ASSERT_EQ_STR(INST("libx", "amd64", ",\"auto\":true"),
                  one("", PKG("libx", "amd64", "1"), "package: libx\nARCHITECTURE:   amd64  \nauto-installed:\t1\n", true));
}

TEST(auto_is_false_for_a_stanza_that_says_0_or_nothing_and_the_first_stanza_counts) {
    ASSERT_EQ_STR(INST("libx", "amd64", ",\"auto\":false"),
                  one("", PKG("libx", "amd64", "1"), "Package: libx\nArchitecture: amd64\nAuto-Installed: 0\n\n", true));
    ASSERT_EQ_STR(INST("libx", "amd64", ",\"auto\":false"),
                  one("", PKG("libx", "amd64", "1"), "Package: libx\nArchitecture: amd64\n\n", true));
    ASSERT_EQ_STR(INST("libx", "amd64", ",\"auto\":false"),
                  one("", PKG("libx", "amd64", "1"),
                      "Package: libx\nArchitecture: amd64\nAuto-Installed: 0\n\nPackage: libx\nArchitecture: amd64\nAuto-Installed: 1\n\n", true));
    ASSERT_EQ_STR(INST("libx", "amd64", ",\"auto\":true"),
                  one("", PKG("libx", "amd64", "1"),
                      "Package: libx\nArchitecture: amd64\nAuto-Installed: 1\n\nPackage: libx\nArchitecture: amd64\nAuto-Installed: 0\n\n", true));
    /* An empty record is a record: nothing is marked. */
    ASSERT_EQ_STR(INST("libx", "amd64", ",\"auto\":false"), one("", PKG("libx", "amd64", "1"), "", true));
}

/* A record that cannot be read, or is not apt's, says nothing: absent. */
TEST(auto_is_absent_when_the_record_cannot_be_read_or_parsed) {
    ASSERT_EQ_STR(INST("libx", "amd64", ""), one("", PKG("libx", "amd64", "1"), NULL, true));
    ASSERT_EQ_STR(INST("libx", "amd64", ""), one("", PKG("libx", "amd64", "1"), NULL, false));
    ASSERT_EQ_STR(INST("libx", "amd64", ""),
                  one("", PKG("libx", "amd64", "1"), "Package: libx\nArchitecture: amd64\nAuto-Installed: 1\nthis is no field\n", true));
    ASSERT_EQ_STR(INST("libx", "amd64", ""),
                  one("", PKG("libx", "amd64", "1"), "Architecture: amd64\nAuto-Installed: 1\n\n", true));       /* no Package */
    ASSERT_EQ_STR(INST("libx", "amd64", ""),
                  one("", PKG("libx", "amd64", "1"), "Package: libx\nArchitecture: amd64\nAuto-Installed: yes\n\n", true));
    ASSERT_EQ_STR(INST("libx", "amd64", ""),
                  one("", PKG("libx", "amd64", "1"), " Package: libx\n", true));           /* continues nothing */
    /* Not a regular file, or one never read. */
    static struct t_run r;
    tr_begin(&r, BELAY_INTERP_DPKG);
    const struct belay_entry b = t_entry(STATUS, BELAY_T_REG, 0644, t_put(""));
    const struct belay_entry a = t_entry(STATUS, BELAY_T_REG, 0644, t_put(PKG("libx", "amd64", "1")));
    tr_path(&r, STATUS, &b, &a, "modified");
    struct belay_entry e = t_entry(STATES, BELAY_T_LNK, 0777, NULL);
    ASSERT_EQ_STR(INST("libx", "amd64", ""), tr_end(&r, &e, 1));
    tr_free(&r);
}

/* The record is asked for only when an event would carry auto. */
TEST(the_record_is_looked_up_only_for_an_event_that_carries_auto) {
    struct t_run r;
    tr_begin(&r, BELAY_INTERP_DPKG);
    const struct belay_entry b = t_entry(STATUS, BELAY_T_REG, 0644, t_put(PKG("gone", "amd64", "2")));
    const struct belay_entry a = t_entry(STATUS, BELAY_T_REG, 0644, t_put(""));
    tr_path(&r, STATUS, &b, &a, "modified");
    REQUIRE(r.it->prepare != NULL);
    r.lk.current = BELAY_INTERP_DPKG;
    ASSERT_EQ_INT(BELAY_INTERP_FINDINGS, r.it->prepare(r.state, &r.lk));
    ASSERT_EQ_INT(0, (int)lookup_wanted(&r.lk));
    tr_free(&r);
    tr_begin(&r, BELAY_INTERP_DPKG);
    tr_path(&r, STATUS, &a, &b, "modified");
    r.lk.current = BELAY_INTERP_DPKG;
    ASSERT_EQ_INT(BELAY_INTERP_FINDINGS, r.it->prepare(r.state, &r.lk));
    ASSERT_EQ_INT(1, (int)lookup_wanted(&r.lk));
    lookup_round_end(&r.lk);
    /* Asked once: a second round asks nothing. */
    ASSERT_EQ_INT(BELAY_INTERP_FINDINGS, r.it->prepare(r.state, &r.lk));
    ASSERT_EQ_INT(0, (int)lookup_wanted(&r.lk));
    tr_free(&r);
}

/* A status database inside the scope (a container's root) has its own
 * record beside it, and no other tree's. */
TEST(each_tree_has_its_own_record) {
    t_reset();
    t_file("a/" STATUS, "", 0644);
    t_file("b/" STATUS, "", 0644);
    t_file("c/" STATUS, "", 0644);
    t_file("a/" STATES, "Package: libx\nArchitecture: amd64\nAuto-Installed: 1\n\n", 0644);
    t_file("b/" STATES, "", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("a/" STATUS, PKG("libx", "amd64", "1"), 0644);
    t_file("b/" STATUS, PKG("libx", "amd64", "1"), 0644);
    t_file("c/" STATUS, PKG("libx", "amd64", "1"), 0644);
    REQUIRE(t_snap(2) == 0);
#define TREE(t, autov) "{\"event\":\"dpkg_installed\",\"interp\":\"dpkg\",\"package\":\"libx\",\"arch\":\"amd64\",\"version\":\"1\"" autov \
                       ",\"text\":\"installed libx:amd64 1\",\"paths\":[\"" t "/" STATUS "\"]}\n"
    ASSERT_EQ_STR(TREE("a", ",\"auto\":true") TREE("b", ",\"auto\":false") TREE("c", ""), t_events(1, 2));
}

/* `apt-mark auto` rewrites the record alone: no dpkg event (the pin gives
 * none), and the record's own line in the diff stands, with no finding. */
TEST(a_record_that_changed_alone_is_its_record_and_no_event) {
    t_reset();
    t_file(STATUS, PKG("nginx", "amd64", "1"), 0644);
    t_file(STATES, "", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(STATES, "Package: nginx\nArchitecture: amd64\nAuto-Installed: 1\n\n", 0644);
    REQUIRE(t_snap(2) == 0);
    const char *d = t_diff(1, 2);
    const char *rec = t_record(d, STATES);
    ASSERT_TRUE(strstr(rec, "\"outcome\":\"modified\"") != NULL);
    ASSERT_TRUE(strstr(rec, "\"findings\"") == NULL);
    ASSERT_TRUE(strstr(d, "{\"event\":") == NULL);
}

/* The record is written by the watched machine. */
TEST(a_hostile_record_is_read_or_refused_never_trusted) {
    /* A NUL byte, inside a value of a stanza otherwise whole: not apt's. */
    static struct t_run r;
    tr_begin(&r, BELAY_INTERP_DPKG);
    const struct belay_entry b = t_entry(STATUS, BELAY_T_REG, 0644, t_put(""));
    const struct belay_entry a = t_entry(STATUS, BELAY_T_REG, 0644, t_put(PKG("libx", "amd64", "1")));
    tr_path(&r, STATUS, &b, &a, "modified");
    struct belay_entry e = t_entry(STATES, BELAY_T_REG, 0644,
                                   t_put_n("Package: libx\nArchitecture: amd64\nDescription: a\0b\nAuto-Installed: 1\n", 69));
    ASSERT_EQ_STR(INST("libx", "amd64", ""), tr_end(&r, &e, 1));
    tr_free(&r);
    /* CRLF, and a last stanza without its newline. */
    ASSERT_EQ_STR(INST("libx", "amd64", ",\"auto\":true"),
                  one("", PKG("libx", "amd64", "1"), "Package: other\r\nAuto-Installed: 0\r\n\r\nPackage: libx\r\nArchitecture: amd64\r\nAuto-Installed: 1", true));
    /* A 70,000-byte value, invalid UTF-8, and 100,000 stanzas before the one asked. */
    static char big[8000000];
    size_t w = (size_t)snprintf(big, sizeof big, "Package: long\nDescription: ");
    memset(big + w, 'x', 70000);
    w += 70000;
    w += (size_t)snprintf(big + w, sizeof big - w, "\n\nPackage: bad\xff\xfe\nAuto-Installed: 1\n\n");
    for (int i = 0; i < 100000; i++)
        w += (size_t)snprintf(big + w, sizeof big - w, "Package: p%d\nArchitecture: amd64\nAuto-Installed: 1\n\n", i);
    snprintf(big + w, sizeof big - w, "Package: libx\nArchitecture: amd64\nAuto-Installed: 1\n\n");
    ASSERT_EQ_STR(INST("libx", "amd64", ",\"auto\":true"), one("", PKG("libx", "amd64", "1"), big, true));
    ASSERT_EQ_STR(EV("dpkg_installed", "\"package\":\"p99999\",\"arch\":\"amd64\",\"version\":\"1\",\"auto\":true", "installed p99999:amd64 1"),
                  one("", PKG("p99999", "amd64", "1"), big, true));
    one("", "", "", true);      /* frees the last run */
}

int main(void) {
    t_begin("sysdpkg");
    RUN(auto_is_what_apts_record_says_of_the_package_after);
    RUN(auto_comes_from_a_record_that_did_not_change_and_a_removal_has_none);
    RUN(auto_is_absent_without_apts_record);
    RUN(auto_matches_package_and_architecture_exactly);
    RUN(auto_is_false_for_a_stanza_that_says_0_or_nothing_and_the_first_stanza_counts);
    RUN(auto_is_absent_when_the_record_cannot_be_read_or_parsed);
    RUN(the_record_is_looked_up_only_for_an_event_that_carries_auto);
    RUN(each_tree_has_its_own_record);
    RUN(a_record_that_changed_alone_is_its_record_and_no_event);
    RUN(a_hostile_record_is_read_or_refused_never_trusted);
    free(g_text);
    t_end();
    return belay_test_report();
}
