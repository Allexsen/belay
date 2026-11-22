/*
 *  The sudoers interpreter (test/expect/system-interpreters.md SS-1 to
 *  SS-5; finding-kinds.md, sudo_*). The fixtures are the shapes of the pin's
 *  "how established" cells: a forms file `visudo -c` accepts (`@includedir`
 *  and `#includedir`, `Defaults`, aliases, `(ALL) NOPASSWD: /bin/echo ...`,
 *  `(root) NOPASSWD: /bin/ls, PASSWD: /bin/cat`, a uid written `#1000`), and
 *  the four names of `sudoers.d` sudo was seen to read or not: `90-site`,
 *  `UPPER_ok`, `with.dot`, `backup~`. Files are written mode 0440, as
 *  sudoers is, captured with the real capture and compared with the real
 *  diff. Every expectation is written by hand from the pin.
 */
#include "sys_test.h"

#define EVT(kind, fields, text, path) \
    "{\"event\":\"" kind "\",\"interp\":\"sudoers\"," fields ",\"text\":\"" text "\",\"paths\":[\"" path "\"]}\n"
/* A line that is no plain user specification. `word`: added or removed. */
#define LINE(word, path, line) \
    EVT("sudo_line_" word, "\"path\":\"" path "\",\"line\":\"" line "\"", "sudoers line " word " in " path ": " line, path)
/* A user specification of the plain form; `tags` is the JSON list's body. */
#define RULE(word, path, who, hosts, runas, tags, commands, line) \
    EVT("sudo_rule_" word, "\"path\":\"" path "\",\"who\":\"" who "\",\"hosts\":\"" hosts "\",\"runas\":\"" runas \
        "\",\"tags\":[" tags "],\"commands\":\"" commands "\",\"line\":\"" line "\"", \
        "sudo rule " word " in " path ": " line, path)
#define NOT_READ(path, why) \
    EVT("sudoers_file_not_read_by_sudo", "\"path\":\"" path "\",\"why\":\"" why "\"", \
        path ": sudo does not read a file named like this (" why ")", path)
#define CNI(path) "{\"event\":\"could_not_interpret\",\"interp\":\"sudoers\",\"text\":\"could not interpret\",\"paths\":[\"" path "\"]}\n"
#define INVALID(path) "{\"event\":\"invalid_finding\",\"interp\":\"sudoers\",\"text\":\"invalid finding\",\"paths\":[\"" path "\"]}\n"
#define F_CNI ",\"findings\":[{\"kind\":\"could_not_interpret\",\"text\":\"could not interpret\"}]"

#define S "etc/sudoers"

/* SS-1, SS-2: the forms file. What is a user specification of the plain
 * form is a rule with its parts as written; everything else that is not a
 * comment or blank is a line as written. Events come in the order of the
 * lines, a removed line before an added one at the same place (SI-1). */
TEST(the_forms_file_gives_rules_and_lines_as_written) {
    t_reset();
    t_file(S, "# sudoers\n"
              "Defaults env_reset\n"
              "root ALL=(ALL:ALL) ALL\n"
              "@includedir /etc/sudoers.d\n", 0440);
    REQUIRE(t_snap(1) == 0);
    t_file(S, "# sudoers\n"
              "Defaults env_reset\n"
              "Defaults !authenticate\n"
              "User_Alias ADMINS = alice, bob\n"
              "Cmnd_Alias SVC = /bin/systemctl\n"
              "root ALL=(ALL:ALL) ALL\n"
              "alice ALL=(ALL) NOPASSWD: /bin/echo hi\n"
              "bob ALL=(root) NOPASSWD: /bin/ls, PASSWD: /bin/cat\n"
              "%sudo ALL=(ALL:ALL) ALL\n"
              "ADMINS ALL = SVC\n"
              "#1000 ALL=(ALL) ALL\n"
              "carol web1, web2 = NOPASSWD: SETENV: /usr/bin/rsync \\\n"
              "    --server\n"
              "root ALL=(ALL) ALL : LOCAL=(ALL) ALL\n"
              "#includedir /etc/sudoers.d\n", 0440);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        LINE("added", S, "Defaults !authenticate")
        LINE("removed", S, "@includedir /etc/sudoers.d")
        LINE("added", S, "User_Alias ADMINS = alice, bob")
        LINE("added", S, "Cmnd_Alias SVC = /bin/systemctl")
        RULE("added", S, "alice", "ALL", "ALL", "\"NOPASSWD\"", "/bin/echo hi", "alice ALL=(ALL) NOPASSWD: /bin/echo hi")
        RULE("added", S, "bob", "ALL", "root", "\"NOPASSWD\"", "/bin/ls, PASSWD: /bin/cat",
             "bob ALL=(root) NOPASSWD: /bin/ls, PASSWD: /bin/cat")
        RULE("added", S, "%sudo", "ALL", "ALL:ALL", "", "ALL", "%sudo ALL=(ALL:ALL) ALL")
        /* an alias name stays a name: nothing is expanded */
        RULE("added", S, "ADMINS", "ALL", "", "", "SVC", "ADMINS ALL = SVC")
        /* `#` and a digit is a uid, not a comment */
        RULE("added", S, "#1000", "ALL", "ALL", "", "ALL", "#1000 ALL=(ALL) ALL")
        /* two physical lines joined at the backslash: one logical line, at its first line's place */
        RULE("added", S, "carol", "web1, web2", "", "\"NOPASSWD\",\"SETENV\"", "/usr/bin/rsync     --server",
             "carol web1, web2 = NOPASSWD: SETENV: /usr/bin/rsync     --server")
        /* a second specification after `:` is not the plain form */
        LINE("added", S, "root ALL=(ALL) ALL : LOCAL=(ALL) ALL")
        LINE("added", S, "#includedir /etc/sudoers.d"),
        t_events(1, 2));
    /* The reverse diff says the reverse, each removed line at its place before. */
    ASSERT_EQ_STR(
        LINE("removed", S, "Defaults !authenticate")
        LINE("removed", S, "User_Alias ADMINS = alice, bob")
        LINE("added", S, "@includedir /etc/sudoers.d")
        LINE("removed", S, "Cmnd_Alias SVC = /bin/systemctl")
        RULE("removed", S, "alice", "ALL", "ALL", "\"NOPASSWD\"", "/bin/echo hi", "alice ALL=(ALL) NOPASSWD: /bin/echo hi")
        RULE("removed", S, "bob", "ALL", "root", "\"NOPASSWD\"", "/bin/ls, PASSWD: /bin/cat",
             "bob ALL=(root) NOPASSWD: /bin/ls, PASSWD: /bin/cat")
        RULE("removed", S, "%sudo", "ALL", "ALL:ALL", "", "ALL", "%sudo ALL=(ALL:ALL) ALL")
        RULE("removed", S, "ADMINS", "ALL", "", "", "SVC", "ADMINS ALL = SVC")
        RULE("removed", S, "#1000", "ALL", "ALL", "", "ALL", "#1000 ALL=(ALL) ALL")
        RULE("removed", S, "carol", "web1, web2", "", "\"NOPASSWD\",\"SETENV\"", "/usr/bin/rsync     --server",
             "carol web1, web2 = NOPASSWD: SETENV: /usr/bin/rsync     --server")
        LINE("removed", S, "root ALL=(ALL) ALL : LOCAL=(ALL) ALL")
        LINE("removed", S, "#includedir /etc/sudoers.d"),
        t_events(2, 1));
    /* The record of the file stands, and carries nothing of the interpreter's. */
    const char *rec = t_record(t_diff(1, 2), S);
    ASSERT_TRUE(strstr(rec, "\"outcome\":\"modified\"") != NULL);
    ASSERT_TRUE(strstr(rec, "\"findings\"") == NULL);
}

/* SS-1: a comment is a line whose first non-blank is `#` not followed by
 * `include`, `includedir` or a digit; a blank line is nothing. */
TEST(comments_and_blank_lines_are_nothing) {
    t_reset();
    t_file(S, "root ALL=(ALL) ALL\n", 0440);
    REQUIRE(t_snap(1) == 0);
    t_file(S, "# a comment\n"
              "\n"
              "   \t\n"
              "\t# indented\n"
              "#\n"
              "#-1 ALL=(ALL) ALL\n"
              "# include /etc/x\n"
              "#Include /etc/x\n"
              "root ALL=(ALL) ALL\n"
              "#include /etc/sudoers.local\n"
              "  #includedir /etc/more.d\n"
              "\t#0 ALL = ALL\n"
              "@include /etc/sudoers.site\n"
              "# a comment ends at its line's end, backslash or not \\\n"
              "eve ALL=(ALL) ALL\n", 0440);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        LINE("added", S, "#include /etc/sudoers.local")
        LINE("added", S, "#includedir /etc/more.d")
        RULE("added", S, "#0", "ALL", "", "", "ALL", "#0 ALL = ALL")
        LINE("added", S, "@include /etc/sudoers.site")
        /* never hidden behind a comment: the line after one stands by itself */
        RULE("added", S, "eve", "ALL", "ALL", "", "ALL", "eve ALL=(ALL) ALL"),
        t_events(1, 2));
}

/* SS-2, read conservatively: one `=` on the line, a runas only right after
 * it, tags only before the first command. A line that is not surely of the
 * plain form is given as written, never as a rule split wrongly. */
TEST(what_is_not_surely_the_plain_form_is_a_line) {
    t_reset();
    t_file(S, "", 0440);
    REQUIRE(t_snap(1) == 0);
    t_file(S, "a ALL=(ALL) /usr/bin/env FOO=bar /bin/true\n"            /* a second `=` */
              "b ALL=(ALL) /bin/echo \"x=y\"\n"                          /* `=` inside quotes is not one */
              "c ALL=(ALL) /bin/echo x\\=y\n"                            /* nor one escaped */
              "d ALL=(root) /bin/ls, (bob) /bin/cat\n"                   /* a second runas */
              "e ALL=(root /bin/ls\n"                                    /* a runas never closed */
              "f ALL=(root)\n"                                           /* no command */
              "g=ALL\n"                                                  /* no hosts */
              "h ALL=\n"                                                 /* nothing after `=` */
              "Defaults:alice !lecture\n"
              "Defaults@web1 log_output\n"
              "Defaults>root !set_logname\n"
              "Defaults!/bin/ls noexec\n"
              "Defaults env_keep += \"HOME\"\n"
              "Host_Alias WEB = web1, web2\n"
              "Runas_Alias OP = root, operator\n"
              "Cmd_Alias SH = /bin/sh\n"
              "i ALL=(ALL) NOPASSWD:NOEXEC: /bin/vi\n"                   /* tags written without a space */
              "j ALL = sha224:d06a2617c98d377c250edd470fd5e576327748d82915d6e33b5f8db1 /bin/ls\n"
              "k ALL=(ALL) CWD=/tmp /bin/pwd\n"                          /* an option with `=`: a second `=` */
              "l ALL = /bin/ls : ALL\n"                                  /* a colon in the commands, one `=` */
              "m ALL = /bin/date +%H\\:%M\n"
              "just words\n", 0440);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        LINE("added", S, "a ALL=(ALL) /usr/bin/env FOO=bar /bin/true")
        RULE("added", S, "b", "ALL", "ALL", "", "/bin/echo \\\"x=y\\\"", "b ALL=(ALL) /bin/echo \\\"x=y\\\"")
        RULE("added", S, "c", "ALL", "ALL", "", "/bin/echo x\\\\=y", "c ALL=(ALL) /bin/echo x\\\\=y")
        LINE("added", S, "d ALL=(root) /bin/ls, (bob) /bin/cat")
        LINE("added", S, "e ALL=(root /bin/ls")
        LINE("added", S, "f ALL=(root)")
        LINE("added", S, "g=ALL")
        LINE("added", S, "h ALL=")
        LINE("added", S, "Defaults:alice !lecture")
        LINE("added", S, "Defaults@web1 log_output")
        LINE("added", S, "Defaults>root !set_logname")
        LINE("added", S, "Defaults!/bin/ls noexec")
        LINE("added", S, "Defaults env_keep += \\\"HOME\\\"")
        LINE("added", S, "Host_Alias WEB = web1, web2")
        LINE("added", S, "Runas_Alias OP = root, operator")
        LINE("added", S, "Cmd_Alias SH = /bin/sh")
        RULE("added", S, "i", "ALL", "ALL", "\"NOPASSWD\",\"NOEXEC\"", "/bin/vi", "i ALL=(ALL) NOPASSWD:NOEXEC: /bin/vi")
        /* a digest is no tag (tags are upper case), and a colon that is no tag's is not the plain form */
        LINE("added", S, "j ALL = sha224:d06a2617c98d377c250edd470fd5e576327748d82915d6e33b5f8db1 /bin/ls")
        LINE("added", S, "k ALL=(ALL) CWD=/tmp /bin/pwd")
        LINE("added", S, "l ALL = /bin/ls : ALL")
        /* an escaped colon is the command's text */
        RULE("added", S, "m", "ALL", "", "", "/bin/date +%H\\\\:%M", "m ALL = /bin/date +%H\\\\:%M")
        LINE("added", S, "just words"),
        t_events(1, 2));
}

/* SI-3: a changed line is a removed one and an added one. Lines are
 * compared as written, trimmed, as a multiset: moving a line says nothing,
 * a second copy of a line is one line added. */
TEST(a_changed_line_is_one_removed_and_one_added) {
    t_reset();
    t_file(S, "Defaults env_reset\n"
              "alice ALL=(ALL) ALL\n"
              "bob ALL=(ALL) ALL\n", 0440);
    REQUIRE(t_snap(1) == 0);
    t_file(S, "bob ALL=(ALL) ALL\n"
              "  alice ALL=(ALL) NOPASSWD: ALL  \n"
              "Defaults env_reset\n"
              "bob ALL=(ALL) ALL\n", 0440);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        RULE("removed", S, "alice", "ALL", "ALL", "", "ALL", "alice ALL=(ALL) ALL")
        RULE("added", S, "alice", "ALL", "ALL", "\"NOPASSWD\"", "ALL", "alice ALL=(ALL) NOPASSWD: ALL")
        RULE("added", S, "bob", "ALL", "ALL", "", "ALL", "bob ALL=(ALL) ALL"),
        t_events(1, 2));
    /* Only reordered, re-indented and re-commented: no event. */
    t_file(S, "# moved\n"
              "\tbob ALL=(ALL) ALL\n"
              "bob ALL=(ALL) ALL\n"
              "Defaults env_reset\n"
              "alice ALL=(ALL) NOPASSWD: ALL\n", 0440);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR("", t_events(2, 3));
}

#define D "etc/sudoers.d/"

/* SS-3, SS-4: the name rule of sudoers.d, as measured: `90-site` and
 * `UPPER_ok` are read, `with.dot` and `backup~` are not. No rule from the
 * mode: a 0644 file gives no event of its own. The lines of a file sudo
 * does not read are events all the same: they are the file's text. */
TEST(the_name_rule_of_sudoers_d) {
    t_reset();
    t_file(S, "@includedir /etc/sudoers.d\n", 0440);
    REQUIRE(t_snap(1) == 0);
    t_file(D "90-site", "dave ALL=(ALL) ALL\n", 0644);
    t_file(D "UPPER_ok", "dave ALL=(ALL) ALL\n", 0440);
    t_file(D "with.dot", "dave ALL=(ALL) ALL\n", 0440);
    t_file(D "backup~", "dave ALL=(ALL) ALL\n", 0440);
    t_file(D "both.names~", "Defaults !authenticate\n", 0440);
    t_file(D "sub/deeper.conf", "dave ALL=(ALL) ALL\n", 0440);        /* not directly in sudoers.d: not sudoers' */
    REQUIRE(t_snap(2) == 0);
#define DAVE(word, name) RULE(word, D name, "dave", "ALL", "ALL", "", "ALL", "dave ALL=(ALL) ALL")
    ASSERT_EQ_STR(
        DAVE("added", "90-site")
        DAVE("added", "UPPER_ok")
        NOT_READ(D "backup~", "its name ends ~")
        DAVE("added", "backup~")
        NOT_READ(D "both.names~", "a . in its name")
        LINE("added", D "both.names~", "Defaults !authenticate")
        NOT_READ(D "with.dot", "a . in its name")
        DAVE("added", "with.dot"),
        t_events(1, 2));
    /* Changed: said again, with what changed. Only its mode changed: nothing
     * (SS-4). Removed: its lines, and no word on a name that is gone. */
    char p[700];
    t_file(D "with.dot", "dave ALL=(ALL) ALL\nerin ALL=(ALL) ALL\n", 0440);
    snprintf(p, sizeof p, "%s/root/" D "backup~", g_dir);
    REQUIRE(chmod(p, 0400) == 0);
    snprintf(p, sizeof p, "%s/root/" D "90-site", g_dir);
    REQUIRE(chmod(p, 0666) == 0);
    t_rm(D "both.names~");
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(
        LINE("removed", D "both.names~", "Defaults !authenticate")
        NOT_READ(D "with.dot", "a . in its name")
        RULE("added", D "with.dot", "erin", "ALL", "ALL", "", "ALL", "erin ALL=(ALL) ALL"),
        t_events(2, 3));
}

/* A sudoers file added or removed whole: every line of it. An empty one,
 * or one of comments only: nothing. */
TEST(a_file_added_or_removed_gives_its_lines) {
    t_reset();
    t_file("etc/hostname", "h\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(S, "Defaults env_reset\nroot ALL=(ALL:ALL) ALL", 0440);         /* no final newline */
    t_file(D "empty", "", 0440);
    t_file(D "comments", "# nothing here\n\n", 0440);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        LINE("added", S, "Defaults env_reset")
        RULE("added", S, "root", "ALL", "ALL:ALL", "", "ALL", "root ALL=(ALL:ALL) ALL"),
        t_events(1, 2));
    ASSERT_EQ_STR(
        LINE("removed", S, "Defaults env_reset")
        RULE("removed", S, "root", "ALL", "ALL:ALL", "", "ALL", "root ALL=(ALL:ALL) ALL"),
        t_events(2, 1));
}

/* A sudoers under another root (a container's tree in the scope) is read
 * the same; `path` is the path in the scope. */
TEST(a_sudoers_anywhere_in_the_scope_is_read) {
    t_reset();
    t_file("srv/img/etc/sudoers", "", 0440);
    REQUIRE(t_snap(1) == 0);
    t_file("srv/img/etc/sudoers", "root ALL=(ALL) ALL\n", 0440);
    t_file("srv/img/etc/sudoers.d/x.bak", "Defaults !authenticate\n", 0440);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        RULE("added", "srv/img/etc/sudoers", "root", "ALL", "ALL", "", "ALL", "root ALL=(ALL) ALL")
        NOT_READ("srv/img/etc/sudoers.d/x.bak", "a . in its name")
        LINE("added", "srv/img/etc/sudoers.d/x.bak", "Defaults !authenticate"),
        t_events(1, 2));
}

/* ---- by hand: what no capture of this binary produces ---- */

/* SI-2: a claimed file that is sealed against the claim, was not read, has
 * no kept copy, or is no regular file on a side cannot be interpreted: its
 * record says so and one event names it. Nothing is skipped silently. */
TEST(a_file_that_cannot_be_read_could_not_be_interpreted) {
    struct t_run r;
    const char *ok = t_put("root ALL=(ALL) ALL\n");
    struct belay_entry b = t_entry(S, BELAY_T_REG, 0440, ok), a = t_entry(S, BELAY_T_REG, 0440, NULL);

    tr_begin(&r, BELAY_INTERP_SUDOERS);
    a.sealed = true;                                            /* sealed: no copy, by rule */
    ASSERT_EQ_STR(F_CNI, tr_path(&r, S, &b, &a, "modified"));
    ASSERT_EQ_STR(CNI(S), tr_end(&r, NULL, 0));
    tr_free(&r);

    tr_begin(&r, BELAY_INTERP_SUDOERS);
    a = t_entry(S, BELAY_T_REG, 0440, NULL);                    /* no copy kept */
    ASSERT_EQ_STR(F_CNI, tr_path(&r, S, &b, &a, "modified"));
    ASSERT_EQ_STR(CNI(S), tr_end(&r, NULL, 0));
    tr_free(&r);

    tr_begin(&r, BELAY_INTERP_SUDOERS);                         /* a copy the store does not have, before */
    a = t_entry(S, BELAY_T_REG, 0440, ok);
    b = t_entry(S, BELAY_T_REG, 0440, "0000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_EQ_STR(F_CNI, tr_path(&r, S, &b, &a, "modified"));
    ASSERT_EQ_STR(CNI(S), tr_end(&r, NULL, 0));
    tr_free(&r);

    tr_begin(&r, BELAY_INTERP_SUDOERS);                         /* a file that became a link */
    b = t_entry(S, BELAY_T_REG, 0440, ok);
    a = t_entry(S, BELAY_T_LNK, 0777, NULL);
    ASSERT_EQ_STR(F_CNI, tr_path(&r, S, &b, &a, "type_changed"));
    ASSERT_EQ_STR(CNI(S), tr_end(&r, NULL, 0));
    tr_free(&r);

    tr_begin(&r, BELAY_INTERP_SUDOERS);                         /* a `meta` entry: statted, never read */
    a = t_entry(S, BELAY_T_REG, 0440, NULL);
    a.meta = true;
    ASSERT_EQ_STR(F_CNI, tr_path(&r, S, NULL, &a, "added"));
    ASSERT_EQ_STR(CNI(S), tr_end(&r, NULL, 0));
    tr_free(&r);

    /* The name rule does not need the content: said even so, after the
     * file's could_not_interpret. */
    tr_begin(&r, BELAY_INTERP_SUDOERS);
    a = t_entry(D "x.conf", BELAY_T_REG, 0440, NULL);
    ASSERT_EQ_STR(F_CNI, tr_path(&r, D "x.conf", NULL, &a, "added"));
    ASSERT_EQ_STR(CNI(D "x.conf") NOT_READ(D "x.conf", "a . in its name"), tr_end(&r, NULL, 0));
    tr_free(&r);
}

/* What is not a file on either side is not sudoers' to read (a directory
 * in sudoers.d), and a change of metadata alone says nothing (SS-4). */
TEST(directories_and_metadata_changes_are_declined) {
    struct t_run r;
    const char *ok = t_put("root ALL=(ALL) ALL\n");
    tr_begin(&r, BELAY_INTERP_SUDOERS);
    struct belay_entry d = t_entry(D "sub", BELAY_T_DIR, 0755, NULL);
    ASSERT_EQ_STR("", tr_path(&r, D "sub", NULL, &d, "added"));
    ASSERT_EQ_INT(BELAY_INTERP_DECLINE, r.last);
    struct belay_entry b = t_entry(D "with.dot", BELAY_T_REG, 0440, ok), a = t_entry(D "with.dot", BELAY_T_REG, 0644, ok);
    ASSERT_EQ_STR("", tr_path(&r, D "with.dot", &b, &a, "metadata_only"));
    ASSERT_EQ_INT(BELAY_INTERP_DECLINE, r.last);
    struct belay_entry deep = t_entry(D "sub/x", BELAY_T_REG, 0440, ok);
    ASSERT_EQ_STR("", tr_path(&r, D "sub/x", NULL, &deep, "added"));
    ASSERT_EQ_INT(BELAY_INTERP_DECLINE, r.last);
    ASSERT_EQ_STR("", tr_end(&r, NULL, 0));
    tr_free(&r);
}

/* E2, P8: a path whose outcome is unknown is read like any other; its
 * events are provisional and its record gets no finding -- not even
 * could_not_interpret when it cannot be read, which the event still says. */
TEST(an_unknown_path_gives_provisional_events_and_no_finding) {
    struct t_run r;
    tr_begin(&r, BELAY_INTERP_SUDOERS);
    struct belay_entry b = t_entry(S, BELAY_T_REG, 0440, t_put("root ALL=(ALL) ALL\n")),
                       a = t_entry(S, BELAY_T_REG, 0440, t_put("root ALL=(ALL) ALL\nDefaults !authenticate\n"));
    ASSERT_EQ_STR("", tr_path(&r, S, &b, &a, "unknown"));
    struct belay_entry x = t_entry(D "x~", BELAY_T_REG, 0440, NULL);
    ASSERT_EQ_STR("", tr_path(&r, D "x~", NULL, &x, "unknown"));
    ASSERT_EQ_STR(
        "{\"event\":\"sudo_line_added\",\"interp\":\"sudoers\",\"path\":\"etc/sudoers\",\"line\":\"Defaults !authenticate\","
        "\"text\":\"sudoers line added in etc/sudoers: Defaults !authenticate\",\"provisional\":true,\"paths\":[\"etc/sudoers\"]}\n"
        "{\"event\":\"could_not_interpret\",\"interp\":\"sudoers\",\"text\":\"could not interpret\",\"provisional\":true,"
        "\"paths\":[\"etc/sudoers.d/x~\"]}\n"
        "{\"event\":\"sudoers_file_not_read_by_sudo\",\"interp\":\"sudoers\",\"path\":\"etc/sudoers.d/x~\","
        "\"why\":\"its name ends ~\",\"text\":\"etc/sudoers.d/x~: sudo does not read a file named like this (its name ends ~)\","
        "\"provisional\":true,\"paths\":[\"etc/sudoers.d/x~\"]}\n",
        tr_end(&r, NULL, 0));
    tr_free(&r);
}

/* ---- hostile files: sudoers is written by the watched machine ---- */

static const char *hostile(const char *data, size_t n) {
    static struct t_run r;
    static bool live;
    if (live) tr_free(&r);
    tr_begin(&r, BELAY_INTERP_SUDOERS);
    live = data != NULL;
    if (data == NULL) { tr_free(&r); return ""; }
    const struct belay_entry a = t_entry(S, BELAY_T_REG, 0440, t_put_n(data, n));
    tr_path(&r, S, NULL, &a, "added");
    return tr_end(&r, NULL, 0);
}
#define HOSTILE(text) hostile(text, sizeof(text) - 1)

TEST(hostile_files_are_read_within_bounds_and_never_silently) {
    /* A NUL byte: no sudoers has one. The file is not interpreted. */
    ASSERT_EQ_STR(CNI(S), HOSTILE("root ALL=(ALL) ALL\n\0Defaults !authenticate\n"));
    /* CRLF: the CR is a byte of the line, as written. A line that ends
     * `\` CR is not continued. */
    ASSERT_EQ_STR(RULE("added", S, "root", "ALL", "ALL", "", "ALL\\r", "root ALL=(ALL) ALL\\r")
                  LINE("added", S, "Defaults a \\\\\\r")
                  LINE("added", S, "\\r"),
                  HOSTILE("root ALL=(ALL) ALL\r\nDefaults a \\\r\n\r\n"));
    /* No final newline, and a last line that ends in a backslash: what was joined. */
    ASSERT_EQ_STR(LINE("added", S, "Defaults env_reset"), HOSTILE("Defaults \\\nenv_reset\\"));
    ASSERT_EQ_STR("", HOSTILE("\\"));
    ASSERT_EQ_STR("", HOSTILE("  \\\n\t\\\n"));
    /* Bytes that are not UTF-8: that line's event is refused by the core
     * (E9), in its place; the others stand. */
    ASSERT_EQ_STR(LINE("added", S, "Defaults env_reset") INVALID(S)
                  RULE("added", S, "root", "ALL", "ALL", "", "ALL", "root ALL=(ALL) ALL"),
                  HOSTILE("Defaults env_reset\n\xff\xfe ALL=(ALL) ALL\nroot ALL=(ALL) ALL\n"));
    /* A 70,000-byte line: over a string field's bound, the same. */
    static char big[2600000];
    memset(big, 'x', 70000);
    memcpy(big, "u ALL=(ALL) ", 12);
    memcpy(big + 70000, "\nDefaults env_reset\n", 21);
    ASSERT_EQ_STR(INVALID(S) LINE("added", S, "Defaults env_reset"), hostile(big, 70020));
    /* A rule with more tags than a list holds (256): refused the same way. */
    size_t w = (size_t)snprintf(big, sizeof big, "t ALL = ");
    for (int i = 0; i < 257; i++) w += (size_t)snprintf(big + w, sizeof big - w, "A:");
    w += (size_t)snprintf(big + w, sizeof big - w, " /bin/ls\n");
    ASSERT_EQ_STR(INVALID(S), hostile(big, w));
    /* A file that is one endless continuation: one logical line, too long to state. */
    w = 0;
    for (int i = 0; i < 50000; i++) w += (size_t)snprintf(big + w, sizeof big - w, "a \\\n");
    ASSERT_EQ_STR(INVALID(S), hostile(big, w));
    /* 100,000 lines, each a rule: 65,536 event records, the last of them
     * and_more counting itself and the rest (E5). */
    w = 0;
    for (int i = 0; i < 100000; i++) w += (size_t)snprintf(big + w, sizeof big - w, "u%d ALL=(ALL) ALL\n", i);
    const char *out = hostile(big, w);
    size_t lines = 0;
    const char *last = out;
    for (const char *p = out; *p; p++)
        if (*p == '\n') { lines++; if (p[1]) last = p + 1; }
    ASSERT_EQ_INT(65536, (int)lines);
    ASSERT_EQ_STR("{\"event\":\"and_more\",\"interp\":\"sudoers\",\"n\":34465,\"text\":\"and 34465 more\",\"paths\":[]}\n", last);
    ASSERT_TRUE(strncmp(out, RULE("added", S, "u0", "ALL", "ALL", "", "ALL", "u0 ALL=(ALL) ALL"),
                        strlen(RULE("added", S, "u0", "ALL", "ALL", "", "ALL", "u0 ALL=(ALL) ALL"))) == 0);
    /* The same 100,000 lines on both sides, one changed: one line each way. */
    static struct t_run r;
    tr_begin(&r, BELAY_INTERP_SUDOERS);
    const struct belay_entry b = t_entry(S, BELAY_T_REG, 0440, t_put_n(big, w));
    char *at = strstr(big, "\nu77777 ALL=(ALL) ALL\n");
    REQUIRE(at != NULL);
    memcpy(at, "\nu77777 ALL=(ALL) NO:\n", 22);                      /* the same length: a tag and no command */
    const struct belay_entry a = t_entry(S, BELAY_T_REG, 0440, t_put_n(big, w));
    tr_path(&r, S, &b, &a, "modified");
    ASSERT_EQ_STR(RULE("removed", S, "u77777", "ALL", "ALL", "", "ALL", "u77777 ALL=(ALL) ALL")
                  LINE("added", S, "u77777 ALL=(ALL) NO:"),
                  tr_end(&r, NULL, 0));
    tr_free(&r);
    /* A file over the bound read (4 MiB) is not interpreted. */
    static char huge[4200000];
    memset(huge, '\n', sizeof huge);
    ASSERT_EQ_STR(CNI(S), hostile(huge, sizeof huge));
    hostile(NULL, 0);
}

int main(void) {
    t_begin("sudoers");
    RUN(the_forms_file_gives_rules_and_lines_as_written);
    RUN(comments_and_blank_lines_are_nothing);
    RUN(what_is_not_surely_the_plain_form_is_a_line);
    RUN(a_changed_line_is_one_removed_and_one_added);
    RUN(the_name_rule_of_sudoers_d);
    RUN(a_file_added_or_removed_gives_its_lines);
    RUN(a_sudoers_anywhere_in_the_scope_is_read);
    RUN(a_file_that_cannot_be_read_could_not_be_interpreted);
    RUN(directories_and_metadata_changes_are_declined);
    RUN(an_unknown_path_gives_provisional_events_and_no_finding);
    RUN(hostile_files_are_read_within_bounds_and_never_silently);
    free(g_text);
    t_end();
    return belay_test_report();
}
