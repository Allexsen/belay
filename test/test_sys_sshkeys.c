/*
 *  The sshkeys interpreter (test/expect/system-interpreters.md SK-1 to
 *  SK-3; finding-kinds.md, ssh_*). The two keys are real: made once with
 *  `ssh-keygen -t ed25519` and `ssh-keygen -t rsa -b 2048` (OpenSSH 9.6p1),
 *  their public lines pasted here, and the fingerprints expected are what
 *  `ssh-keygen -lf` printed for them -- for the plain lines and for the
 *  lines with a quoted `command=` holding `\"` and a comma and with
 *  `cert-authority`, which it read as the same keys (the pin's O3).
 */
#include "sys_test.h"

#define ED_B64 "AAAAC3NzaC1lZDI1NTE5AAAAID+XhYW3QNQL3yLnaxntF+2EPC2DlSefg63NQkxrgw/6"
#define RSA_B64 "AAAAB3NzaC1yc2EAAAADAQABAAABAQCnN8w5vxX/Oka8WcWQIoxFDfjcFZKLsE1QfnqP9HK8gnTWQji2L500a3Np3VmeMvojnn0t9T+B" \
                "Jxc259mzRxY8mqfGw2Zq8Q/YxdRzHuNCFprdBwU3FUywl8fCqsjlL1yvBnWU4ZGVkSImdcInozi0S7e+RqaosRXBnZVeGL2huE8YAns3" \
                "ILHHUXWMoDWdra4t3JxWB7+RfYNBNqRLmTgg/aIciH5PMAbP62NqSNC0eBj8mJJrPp7fslzz9y2nHXDrgQPefJ5S04A7FBDnmzxEBm6W" \
                "8T9EkoNaFoEFTUyjDXaN+Nebcqc8iJlHFGo09JuxLSw1cN4EhjqYBz48vBm1"
#define ED_FP "SHA256:1fRG1Rf5nSke2+R/GsepKAqKx9nu3Aq0c3xPJS+6wFk"
#define RSA_FP "SHA256:yO6PKHKsztzSGBkkcRVORzgftngDB07wQe4Yoy3BZP0"

#define ED_LINE "ssh-ed25519 " ED_B64 " probe@host\n"
#define CMD_LINE "command=\"echo \\\"a,b\\\"\",no-pty ssh-ed25519 " ED_B64 " c\n"
#define CA_LINE "cert-authority,principals=\"x\" ssh-rsa " RSA_B64 " ca key\n"

#define AK "home/u/.ssh/authorized_keys"

/* One event, as the diff writes it: `opts` the JSON of the options' elements. */
#define EV(kind, words, path, type, fp, comment, opts, sep) \
    "{\"event\":\"" kind "\",\"interp\":\"sshkeys\",\"path\":\"" path "\",\"type\":\"" type "\",\"fingerprint\":\"" fp \
    "\",\"comment\":\"" comment "\",\"options\":[" opts "],\"text\":\"" words " in " path ": " type " " fp sep comment \
    "\",\"paths\":[\"" path "\"]}\n"
#define E10(p) "{\"event\":\"could_not_interpret\",\"interp\":\"sshkeys\",\"text\":\"could not interpret\",\"paths\":[\"" p "\"]}\n"
#define CNI ",\"findings\":[{\"kind\":\"could_not_interpret\",\"text\":\"could not interpret\"}]"

static int count(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

/* SK-1: a key line is its type, the fingerprint of its decoded key, its
 * comment and its options as written; a line with cert-authority is a
 * certificate authority's. By line, in the file's order. */
TEST(key_lines_added_and_removed_are_events) {
    t_reset();
    t_file(AK, "# the operator's\n" ED_LINE, 0600);
    REQUIRE(t_snap(1) == 0);
    t_file(AK, "# the operator's\n" ED_LINE "\n" CA_LINE CMD_LINE, 0600);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EV("ssh_ca_added", "certificate authority added", AK, "ssh-rsa", RSA_FP, "ca key",
           "\"cert-authority\",\"principals=\\\"x\\\"\"", " ")
        EV("ssh_key_added", "key added", AK, "ssh-ed25519", ED_FP, "c",
           "\"command=\\\"echo \\\\\\\"a,b\\\\\\\"\\\"\",\"no-pty\"", " "),
        t_events(1, 2));
    /* The file removed: each of its key lines, in its order. */
    t_rm(AK);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(
        EV("ssh_key_removed", "key removed", AK, "ssh-ed25519", ED_FP, "probe@host", "", " ")
        EV("ssh_ca_removed", "certificate authority removed", AK, "ssh-rsa", RSA_FP, "ca key",
           "\"cert-authority\",\"principals=\\\"x\\\"\"", " ")
        EV("ssh_key_removed", "key removed", AK, "ssh-ed25519", ED_FP, "c",
           "\"command=\\\"echo \\\\\\\"a,b\\\\\\\"\\\"\",\"no-pty\"", " "),
        t_events(2, 3));
    /* authorized_keys2, in another home, a key without a comment. */
    t_file("root/.ssh/authorized_keys2", "ssh-rsa " RSA_B64 "\n", 0600);
    REQUIRE(t_snap(4) == 0);
    ASSERT_EQ_STR(EV("ssh_key_added", "key added", "root/.ssh/authorized_keys2", "ssh-rsa", RSA_FP, "", "", " "),
                  t_events(3, 4));
}

/* SI-3: identity is (type, fingerprint); a key whose options or comment
 * changed is one removed and one added, at its line, removed first. Lines
 * moved, comments and blank lines are no event. */
TEST(a_key_whose_options_or_comment_changed_is_removed_and_added) {
    t_reset();
    t_file(AK, ED_LINE "ssh-rsa " RSA_B64 " ops\n", 0600);
    REQUIRE(t_snap(1) == 0);
    t_file(AK, "no-pty ssh-ed25519 " ED_B64 " probe@host\nssh-rsa " RSA_B64 " ops team\n", 0600);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EV("ssh_key_removed", "key removed", AK, "ssh-ed25519", ED_FP, "probe@host", "", " ")
        EV("ssh_key_added", "key added", AK, "ssh-ed25519", ED_FP, "probe@host", "\"no-pty\"", " ")
        EV("ssh_key_removed", "key removed", AK, "ssh-rsa", RSA_FP, "ops", "", " ")
        EV("ssh_key_added", "key added", AK, "ssh-rsa", RSA_FP, "ops team", "", " "),
        t_events(1, 2));
    t_file(AK, "# moved\n\n  ssh-rsa   " RSA_B64 "\t ops team  \n\tno-pty\tssh-ed25519 " ED_B64 " probe@host\n", 0600);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR("", t_events(2, 3));
    /* The same line twice is two lines: one of them removed is one event. */
    t_file(AK, ED_LINE ED_LINE, 0600);
    REQUIRE(t_snap(4) == 0);
    t_file(AK, ED_LINE, 0600);
    REQUIRE(t_snap(5) == 0);
    ASSERT_EQ_INT(1, count(t_events(4, 5), "{\"event\":\"ssh_key_removed\""));
    ASSERT_EQ_INT(1, count(t_events(4, 5), "\n"));
}

/* sshd(8): options end at a blank outside double quotes, `\"` inside
 * quotes is a quote character, and they split at commas outside quotes;
 * cert-authority in any case. */
TEST(options_are_split_at_commas_outside_quotes) {
    t_reset();
    REQUIRE(t_snap(1) == 0);
    t_file(AK, "from=\"*.example.org,!bad.example.org\",command=\"/bin/sh -c \\\"x y\\\"\",Cert-Authority ssh-ed25519 " ED_B64 "\n", 0600);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EV("ssh_ca_added", "certificate authority added", AK, "ssh-ed25519", ED_FP, "",
           "\"from=\\\"*.example.org,!bad.example.org\\\"\",\"command=\\\"/bin/sh -c \\\\\\\"x y\\\\\\\"\\\"\",\"Cert-Authority\"", " "),
        t_events(1, 2));
    /* An option that only holds the word is no certificate authority. */
    t_file(AK, "environment=\"X=cert-authority\",no-cert-authority ssh-ed25519 " ED_B64 "\n", 0600);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_INT(1, count(t_events(2, 3), "{\"event\":\"ssh_key_added\""));
    ASSERT_EQ_INT(0, count(t_events(2, 3), "{\"event\":\"ssh_ca_added\""));
}

/* SK-1, SI-2: a line that does not parse makes the file could_not_interpret:
 * its record says so and stands, no key of it is an event, and another
 * file's events stand. */
TEST(a_line_that_does_not_parse_makes_the_file_could_not_interpret) {
    static const char *const BAD[] = {
        "ssh-ed25519x " ED_B64 " unknown type\n",
        "ssh-ed25519 " "AAAAC3NzaC1lZDI1NTE5AAAAID+XhYW3QNQL3yLnaxntF+2EPC2DlSefg63NQkxrgw/!" " bad base64\n",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID+XhYW3QNQL3yLnaxntF+2EPC2DlSefg63NQkxrgw c\n",   /* its padding cut */
        "ssh-rsa " ED_B64 " the key says ed25519\n",
        "ssh-ed25519 AAAA short\n",
        "command=\"never closed ssh-ed25519 " ED_B64 "\n",
        "no-pty " ED_B64 " no type\n",
        "ssh-ed25519\n",
        "no-pty\n",
    };
    for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        char text[2048];
        t_reset();
        t_file("root/.ssh/authorized_keys", ED_LINE, 0600);
        REQUIRE(t_snap(1) == 0);
        snprintf(text, sizeof text, ED_LINE "ssh-rsa " RSA_B64 " good\n%s", BAD[i]);
        t_file(AK, text, 0600);
        t_file("root/.ssh/authorized_keys", "", 0600);
        REQUIRE(t_snap(2) == 0);
        const char *d = t_diff(1, 2);
        if (strstr(t_record(d, AK), "\"outcome\":\"added\"") == NULL || strstr(t_record(d, AK), CNI "}") == NULL)
            BELAY_FAIL("case %zu: the record is %s", i, t_record(d, AK));
        ASSERT_EQ_STR(E10(AK) EV("ssh_key_removed", "key removed", "root/.ssh/authorized_keys", "ssh-ed25519", ED_FP,
                                 "probe@host", "", " "),
                      t_only_events(g_text));
    }
}

/* SI-2, by hand: what no capture of this binary writes is never silent; an
 * unknown outcome is read, its events provisional, its record given no
 * finding; what is not such a file is declined. */
TEST(what_cannot_be_read_is_said_and_what_is_not_a_key_file_is_declined) {
    struct t_run r;
    tr_begin(&r, BELAY_INTERP_SSHKEYS);
    struct belay_entry a = t_entry("a/.ssh/authorized_keys", BELAY_T_REG, 0600, NULL);
    a.sealed = true;
    ASSERT_EQ_STR(CNI, tr_path(&r, "a/.ssh/authorized_keys", NULL, &a, "added"));
    const struct belay_entry nc = t_entry("b/.ssh/authorized_keys", BELAY_T_REG, 0600, NULL);
    ASSERT_EQ_STR(CNI, tr_path(&r, "b/.ssh/authorized_keys", &nc, NULL, "removed"));
    const struct belay_entry gone = t_entry("c/.ssh/authorized_keys", BELAY_T_REG, 0600,
                                            "0000000000000000000000000000000000000000000000000000000000000000");
    const struct belay_entry ok = t_entry("c/.ssh/authorized_keys", BELAY_T_REG, 0600, t_put(ED_LINE));
    ASSERT_EQ_STR(CNI, tr_path(&r, "c/.ssh/authorized_keys", &gone, &ok, "modified"));
    const struct belay_entry lnk = t_entry("d/.ssh/authorized_keys", BELAY_T_LNK, 0777, NULL);
    ASSERT_EQ_STR(CNI, tr_path(&r, "d/.ssh/authorized_keys", &ok, &lnk, "type_changed"));
    ASSERT_EQ_STR("", tr_path(&r, "e/.ssh/authorized_keys", NULL, &ok, "unknown"));
    ASSERT_EQ_STR("", tr_path(&r, "f/.ssh/authorized_keys", NULL, &nc, "unknown"));
    /* declined */
    ASSERT_EQ_STR("", tr_path(&r, "g/.ssh/authorized_keys", &ok, &ok, "metadata_only"));
    ASSERT_EQ_INT(BELAY_INTERP_DECLINE, (int)r.last);
    ASSERT_EQ_STR("", tr_path(&r, "g/.ssh/authorized_keys2", &nc, &nc, "metadata_only"));     /* equal content is not read */
    ASSERT_EQ_INT(BELAY_INTERP_DECLINE, (int)r.last);
    const struct belay_entry dir = t_entry("h/.ssh/authorized_keys", BELAY_T_DIR, 0755, NULL);
    ASSERT_EQ_STR("", tr_path(&r, "h/.ssh/authorized_keys", NULL, &dir, "added"));
    ASSERT_EQ_INT(BELAY_INTERP_DECLINE, (int)r.last);
    const struct belay_entry junk = t_entry("x", BELAY_T_REG, 0644, t_put("not a key\n"));
    ASSERT_EQ_STR("", tr_path(&r, "i/xssh/authorized_keys", NULL, &junk, "added"));
    ASSERT_EQ_STR("", tr_path(&r, "i/.ssh/authorized_keys3", NULL, &junk, "added"));
    ASSERT_EQ_STR("", tr_path(&r, "i/.ssh/sub/authorized_keys", NULL, &junk, "added"));
    ASSERT_EQ_STR("", tr_path(&r, "authorized_keys", NULL, &junk, "added"));
    ASSERT_EQ_STR(
        E10("a/.ssh/authorized_keys") E10("b/.ssh/authorized_keys") E10("c/.ssh/authorized_keys") E10("d/.ssh/authorized_keys")
        "{\"event\":\"ssh_key_added\",\"interp\":\"sshkeys\",\"path\":\"e/.ssh/authorized_keys\",\"type\":\"ssh-ed25519\","
        "\"fingerprint\":\"" ED_FP "\",\"comment\":\"probe@host\",\"options\":[],"
        "\"text\":\"key added in e/.ssh/authorized_keys: ssh-ed25519 " ED_FP " probe@host\",\"provisional\":true,"
        "\"paths\":[\"e/.ssh/authorized_keys\"]}\n"
        "{\"event\":\"could_not_interpret\",\"interp\":\"sshkeys\",\"text\":\"could not interpret\",\"provisional\":true,"
        "\"paths\":[\"f/.ssh/authorized_keys\"]}\n",
        tr_end(&r, NULL, 0));
    tr_free(&r);
}

static struct belay_entry g_e;
static const char *one(struct t_run *r, const char *data, size_t n) {
    tr_begin(r, BELAY_INTERP_SSHKEYS);
    g_e = t_entry(AK, BELAY_T_REG, 0600, t_put_n(data, n));
    tr_path(r, AK, NULL, &g_e, "added");
    return tr_end(r, NULL, 0);
}

/* The file is written by the watched machine: NUL bytes, a very long line,
 * no final newline, CRLF, bytes that are not UTF-8, 100,000 lines. */
TEST(hostile_key_files_are_read_or_refused_never_trusted) {
    struct t_run r;
    /* a NUL byte: not interpreted */
    ASSERT_EQ_STR(E10(AK), one(&r, "ssh-ed25519 " ED_B64 " a\0b\n", sizeof("ssh-ed25519 " ED_B64 " a\0b\n") - 1));
    tr_free(&r);
    /* no final newline: the last line is a line */
    ASSERT_EQ_STR(EV("ssh_key_added", "key added", AK, "ssh-ed25519", ED_FP, "last", "", " "),
                  one(&r, "ssh-ed25519 " ED_B64 " last", sizeof("ssh-ed25519 " ED_B64 " last") - 1));
    tr_free(&r);
    /* CRLF: the CR is a byte of the comment, as written; without a comment it is a byte of the key, which then is none */
    ASSERT_EQ_STR(EV("ssh_key_added", "key added", AK, "ssh-ed25519", ED_FP, "c\\r", "", " "),
                  one(&r, "ssh-ed25519 " ED_B64 " c\r\n", sizeof("ssh-ed25519 " ED_B64 " c\r\n") - 1));
    tr_free(&r);
    ASSERT_EQ_STR(E10(AK), one(&r, "ssh-ed25519 " ED_B64 "\r\n", sizeof("ssh-ed25519 " ED_B64 "\r\n") - 1));
    tr_free(&r);
    /* a comment that is not UTF-8: that event is invalid, in its place (E9); the other stands */
    ASSERT_EQ_STR(
        "{\"event\":\"invalid_finding\",\"interp\":\"sshkeys\",\"text\":\"invalid finding\",\"paths\":[\"" AK "\"]}\n"
        EV("ssh_key_added", "key added", AK, "ssh-rsa", RSA_FP, "ok", "", " "),
        one(&r, "ssh-ed25519 " ED_B64 " \xff\xfe\nssh-rsa " RSA_B64 " ok\n",
            sizeof("ssh-ed25519 " ED_B64 " \xff\xfe\nssh-rsa " RSA_B64 " ok\n") - 1));
    tr_free(&r);
    /* a 70,000-byte line: as a comment it breaks only its event; as a key it is none; as options never closed, none */
    static char big[80000];
    size_t w = (size_t)snprintf(big, sizeof big, "ssh-ed25519 " ED_B64 " ");
    memset(big + w, 'c', 70000);
    big[w + 70000] = '\n';
    ASSERT_EQ_STR("{\"event\":\"invalid_finding\",\"interp\":\"sshkeys\",\"text\":\"invalid finding\",\"paths\":[\"" AK "\"]}\n",
                  one(&r, big, w + 70001));
    tr_free(&r);
    w = (size_t)snprintf(big, sizeof big, "ssh-ed25519 ");
    memset(big + w, 'A', 70000);
    big[w + 70000] = '\n';
    ASSERT_EQ_STR(E10(AK), one(&r, big, w + 70001));
    tr_free(&r);
    w = (size_t)snprintf(big, sizeof big, "command=\"");
    memset(big + w, ',', 70000);
    big[w + 70000] = '\n';
    ASSERT_EQ_STR(E10(AK), one(&r, big, w + 70001));
    tr_free(&r);
    /* 70,000 commas outside quotes: more options than a list holds -- that event is invalid */
    w = 0;
    memset(big, ',', 70000);
    w = 70000 + (size_t)snprintf(big + 70000, sizeof big - 70000, " ssh-ed25519 " ED_B64 "\n");
    ASSERT_EQ_STR("{\"event\":\"invalid_finding\",\"interp\":\"sshkeys\",\"text\":\"invalid finding\",\"paths\":[\"" AK "\"]}\n",
                  one(&r, big, w));
    tr_free(&r);
    /* 100,000 key lines are over the 4 MiB an interpreter reads: refused, said. 40,000 fit: each is an event. */
    const size_t ll = sizeof("ssh-ed25519 " ED_B64 " 000000\n") - 1;
    char *many = malloc(100000 * ll + 1);
    REQUIRE(many != NULL);
    for (unsigned i = 0; i < 100000; i++) snprintf(many + (size_t)i * ll, ll + 1, "ssh-ed25519 " ED_B64 " %06u\n", i % 1000000u);
    ASSERT_EQ_STR(E10(AK), one(&r, many, 100000 * ll));
    tr_free(&r);
    const char *ev = one(&r, many, 40000 * ll);
    ASSERT_EQ_INT(40000, count(ev, "{\"event\":\"ssh_key_added\""));
    ASSERT_EQ_INT(40000, count(ev, "\n"));
    ASSERT_TRUE(strstr(ev, "\"comment\":\"039999\"") != NULL);
    tr_free(&r);
    free(many);
}

int main(void) {
    t_begin("sshkeys");
    RUN(key_lines_added_and_removed_are_events);
    RUN(a_key_whose_options_or_comment_changed_is_removed_and_added);
    RUN(options_are_split_at_commas_outside_quotes);
    RUN(a_line_that_does_not_parse_makes_the_file_could_not_interpret);
    RUN(what_cannot_be_read_is_said_and_what_is_not_a_key_file_is_declined);
    RUN(hostile_key_files_are_read_or_refused_never_trusted);
    free(g_text);
    t_end();
    return belay_test_report();
}
