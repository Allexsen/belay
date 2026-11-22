/*
 *  The accounts interpreter (test/expect/system-interpreters.md, SA-1 to
 *  SA-5; finding-kinds.md, user_* and group_*). The fixtures are lines as
 *  useradd and adduser were measured to write them (SA-2, SA-3):
 *  `siteuser:x:1002:1002::/home/siteuser:/bin/sh`, a `--system` account at
 *  uid 999, `svc2:x:109:118::/nonexistent:/usr/sbin/nologin`, the group
 *  lines `siteuser:x:1002:` and `sudo:x:27:ubuntu`, and login.defs's
 *  `UID_MIN 1000`. Every expectation is written by hand from the pins.
 */
#include "sys_test.h"

#define EV(kind, fields, text, path) \
    "{\"event\":\"" kind "\",\"interp\":\"accounts\"," fields ",\"text\":\"" text "\",\"paths\":[\"" path "\"]}\n"
#define E10(path) "{\"event\":\"could_not_interpret\",\"interp\":\"accounts\",\"text\":\"could not interpret\",\"paths\":[\"" path "\"]}\n"
#define CNI ",\"findings\":[{\"kind\":\"could_not_interpret\",\"text\":\"could not interpret\"}]"

#define ROOT "root:x:0:0:root:/root:/bin/bash\n"
#define UBUNTU "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
#define SITE "siteuser:x:1002:1002::/home/siteuser:/bin/sh\n"
#define DEFS "#\n# /etc/login.defs - Configuration control definitions for the login package.\n#\n" \
             "MAIL_DIR        /var/mail\nUID_MIN\t\t\t 1000\nUID_MAX\t\t\t60000\n#SYS_UID_MIN\t\t  100\n"

/* SA-3: useradd adds one line to passwd and one to group. E13: by path,
 * so the group's event first. uid_min is the UID_MIN of the same capture's
 * login.defs, a file that did not change and that nobody claims (SI-4). */
TEST(useradd_is_a_user_added_and_a_group_added) {
    t_reset();
    t_file("etc/passwd", ROOT UBUNTU, 0644);
    t_file("etc/group", "root:x:0:\nsudo:x:27:ubuntu\n", 0644);
    t_file("etc/login.defs", DEFS, 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/passwd", ROOT UBUNTU SITE, 0644);
    t_file("etc/group", "root:x:0:\nsudo:x:27:ubuntu\nsiteuser:x:1002:\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(EV("group_added", "\"name\":\"siteuser\",\"gid\":1002", "group siteuser added (gid 1002)", "etc/group")
                  EV("user_added", "\"name\":\"siteuser\",\"uid\":1002,\"gid\":1002,\"home\":\"/home/siteuser\","
                     "\"shell\":\"/bin/sh\",\"uid_min\":1000",
                     "user siteuser added: uid 1002, home /home/siteuser, shell /bin/sh", "etc/passwd"),
                  t_events(1, 2));
    /* And back: removed, the group before the user (by path). */
    ASSERT_EQ_STR(EV("group_removed", "\"name\":\"siteuser\",\"gid\":1002", "group siteuser removed (gid 1002)", "etc/group")
                  EV("user_removed", "\"name\":\"siteuser\",\"uid\":1002", "user siteuser removed (uid 1002)", "etc/passwd"),
                  t_events(2, 1));
    /* The records of the two files stand, with no finding of their own. */
    const char *d = t_diff(1, 2);
    ASSERT_TRUE(strstr(t_record(d, "etc/passwd"), "\"outcome\":\"modified\"") != NULL);
    ASSERT_TRUE(strstr(t_record(d, "etc/passwd"), "findings") == NULL);
}

/* SA-2: the event carries UID_MIN; belay does not say "system account".
 * A lookup that fails is said: null, never assumed. */
TEST(uid_min_is_login_defs_or_null) {
    static const struct { const char *defs; const char *want; } C[] = {
        { DEFS, "1000" },
        { "UID_MIN 500\n", "500" },
        { "  UID_MIN\t500  \n", "500" },                    /* blanks around it */
        { "UID_MIN 500", "500" },                           /* no final newline */
        { NULL, "null" },                                   /* no login.defs */
        { "UID_MAX 60000\n", "null" },                      /* no UID_MIN line */
        { "UID_MIN 1000\nUID_MIN 500\n", "null" },          /* two: not one number */
        { "UID_MIN abc\n", "null" },
        { "UID_MIN\n", "null" },
        { "UID_MIN 1000 2000\n", "null" },
        { "UID_MIN 99999999999\n", "null" },
        { "#UID_MIN 500\nUID_MIN 1000\n", "1000" },         /* a comment is no line of it */
        { "SYS_UID_MIN 100\nUID_MINIMUM 5\n", "null" },     /* other names */
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        t_reset();
        t_file("etc/passwd", ROOT, 0644);
        if (C[i].defs != NULL) t_file("etc/login.defs", C[i].defs, 0644);
        REQUIRE(t_snap(1) == 0);
        t_file("etc/passwd", ROOT "svc:x:999:999::/home/svc:/bin/sh\n", 0644);
        REQUIRE(t_snap(2) == 0);
        char want[600];
        snprintf(want, sizeof want, EV("user_added", "\"name\":\"svc\",\"uid\":999,\"gid\":999,\"home\":\"/home/svc\","
                                       "\"shell\":\"/bin/sh\",\"uid_min\":%s",
                                       "user svc added: uid 999, home /home/svc, shell /bin/sh", "etc/passwd"), C[i].want);
        const char *got = t_events(1, 2);
        if (strcmp(want, got) != 0) BELAY_FAIL("case %zu: want %s, got %s", i, want, got);
    }
    /* A login.defs that is a directory, or whose copy is not kept, is no answer. */
    t_reset();
    t_file("etc/passwd", ROOT, 0644);
    t_dir("etc/login.defs");
    REQUIRE(t_snap(1) == 0);
    t_file("etc/passwd", ROOT "svc2:x:109:118::/nonexistent:/usr/sbin/nologin\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(EV("user_added", "\"name\":\"svc2\",\"uid\":109,\"gid\":118,\"home\":\"/nonexistent\","
                     "\"shell\":\"/usr/sbin/nologin\",\"uid_min\":null",
                     "user svc2 added: uid 109, home /nonexistent, shell /usr/sbin/nologin", "etc/passwd"),
                  t_events(1, 2));
}

/* The login.defs is the one beside that passwd: a tree inside the scope
 * has its own. */
TEST(uid_min_is_read_beside_the_passwd) {
    t_reset();
    t_file("etc/passwd", ROOT, 0644);
    t_file("etc/login.defs", "UID_MIN 1000\n", 0644);
    t_file("srv/jail/etc/passwd", ROOT, 0644);
    t_file("srv/jail/etc/login.defs", "UID_MIN 200\n", 0644);
    t_file("srv/bare/etc/passwd", ROOT, 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/passwd", ROOT "a:x:1:1::/:/bin/sh\n", 0644);
    t_file("srv/jail/etc/passwd", ROOT "b:x:2:2::/:/bin/sh\n", 0644);
    t_file("srv/bare/etc/passwd", ROOT "c:x:3:3::/:/bin/sh\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(EV("user_added", "\"name\":\"a\",\"uid\":1,\"gid\":1,\"home\":\"/\",\"shell\":\"/bin/sh\",\"uid_min\":1000",
                     "user a added: uid 1, home /, shell /bin/sh", "etc/passwd")
                  EV("user_added", "\"name\":\"c\",\"uid\":3,\"gid\":3,\"home\":\"/\",\"shell\":\"/bin/sh\",\"uid_min\":null",
                     "user c added: uid 3, home /, shell /bin/sh", "srv/bare/etc/passwd")
                  EV("user_added", "\"name\":\"b\",\"uid\":2,\"gid\":2,\"home\":\"/\",\"shell\":\"/bin/sh\",\"uid_min\":200",
                     "user b added: uid 2, home /, shell /bin/sh", "srv/jail/etc/passwd"),
                  t_events(1, 2));
}

/* One event per differing field, in the order uid, gid, gecos, home,
 * shell; by the line's place after; a line that only moved says nothing.
 * SA-4: a change to uid 0 is this kind, no other. */
TEST(user_changed_once_per_field) {
    t_reset();
    t_file("etc/passwd", ROOT UBUNTU SITE, 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/passwd", "siteuser:x:0:0:Site User,,,:/srv/site:/bin/bash\n" ROOT
                         "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/usr/sbin/nologin\n", 0644);
    REQUIRE(t_snap(2) == 0);
#define CH(n, f, a, b) EV("user_changed", "\"name\":\"" n "\",\"field\":\"" f "\",\"from\":\"" a "\",\"to\":\"" b "\"", \
                          "user " n ": " f " " a " -> " b, "etc/passwd")
    ASSERT_EQ_STR(CH("siteuser", "uid", "1002", "0") CH("siteuser", "gid", "1002", "0")
                  CH("siteuser", "gecos", "", "Site User,,,") CH("siteuser", "home", "/home/siteuser", "/srv/site")
                  CH("siteuser", "shell", "/bin/sh", "/bin/bash")
                  CH("ubuntu", "shell", "/bin/bash", "/usr/sbin/nologin"),
                  t_events(1, 2));
    /* Removed before added at one place: line 2 before went, line 2 after came. */
    t_file("etc/passwd", ROOT "other:x:1001:1001::/home/other:/bin/sh\n" SITE, 0644);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(EV("user_removed", "\"name\":\"ubuntu\",\"uid\":1000", "user ubuntu removed (uid 1000)", "etc/passwd")
                  EV("user_added", "\"name\":\"other\",\"uid\":1001,\"gid\":1001,\"home\":\"/home/other\","
                     "\"shell\":\"/bin/sh\",\"uid_min\":null",
                     "user other added: uid 1001, home /home/other, shell /bin/sh", "etc/passwd"),
                  t_events(1, 3));
}

#define PW(n) EV("user_password_in_passwd", "\"name\":\"" n "\"", "user " n ": a password is set in passwd itself", "etc/passwd")
#define MARK "$6$MARKERsalt$MARKERHASHVALUE"

/* The second field: `x`, `*`, `!` say nothing; anything else is said, for
 * a new name or a field that differs from before's, and its value is in
 * no part of the diff. */
TEST(a_password_in_passwd_is_said_and_never_copied) {
    t_reset();
    t_file("etc/passwd", ROOT "a:x:1:1::/:/bin/sh\nb:*:2:2::/:/bin/sh\nc:" MARK ":3:3::/:/bin/sh\n"
                         "d:" MARK ":4:4::/:/bin/sh\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/passwd", ROOT "a:" MARK ":1:1::/:/bin/sh\n"            /* x -> a hash: said */
                         "b:!:2:2::/:/bin/sh\n"                         /* * -> !: nothing */
                         "c:" MARK "2:3:3::/:/bin/sh\n"                 /* another value: said */
                         "d:" MARK ":4:4::/:/bin/zsh\n"                 /* the same value: not said again */
                         "e:" MARK ":5:5::/:/bin/sh\n"                  /* a new name with one: said */
                         "f:x:6:6::/:/bin/sh\ng:*:7:7::/:/bin/sh\nh:!:8:8::/:/bin/sh\n", 0644);
    REQUIRE(t_snap(2) == 0);
    const char *d = t_diff(1, 2);
    ASSERT_TRUE(strstr(d, "MARKER") == NULL);
    char *ev = strdup(d);
    REQUIRE(ev != NULL);
#define ADD(n, u) EV("user_added", "\"name\":\"" n "\",\"uid\":" u ",\"gid\":" u ",\"home\":\"/\",\"shell\":\"/bin/sh\",\"uid_min\":null", \
                     "user " n " added: uid " u ", home /, shell /bin/sh", "etc/passwd")
    ASSERT_EQ_STR(PW("a") PW("c")
                  EV("user_changed", "\"name\":\"d\",\"field\":\"shell\",\"from\":\"/bin/sh\",\"to\":\"/bin/zsh\"",
                     "user d: shell /bin/sh -> /bin/zsh", "etc/passwd")
                  ADD("e", "5") PW("e") ADD("f", "6") ADD("g", "7") ADD("h", "8"),
                  t_only_events(ev));
    free(ev);
    /* Back: a's hash went back to x and says nothing; c's value differs again. */
#define RM(n, u) EV("user_removed", "\"name\":\"" n "\",\"uid\":" u, "user " n " removed (uid " u ")", "etc/passwd")
    ASSERT_EQ_STR(PW("c")
                  EV("user_changed", "\"name\":\"d\",\"field\":\"shell\",\"from\":\"/bin/zsh\",\"to\":\"/bin/sh\"",
                     "user d: shell /bin/zsh -> /bin/sh", "etc/passwd")
                  RM("e", "5") RM("f", "6") RM("g", "7") RM("h", "8"),
                  t_events(2, 1));
}

/* An empty second field: said, unless the same capture has an etc/shadow
 * beside the passwd (the pin's "empty-with-shadow"). */
TEST(an_empty_password_field_is_said_only_without_a_shadow) {
    t_reset();
    t_file("etc/passwd", ROOT, 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/passwd", ROOT "e::5:5::/:/bin/sh\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(ADD("e", "5") PW("e"), t_events(1, 2));
    t_file("etc/shadow", "root:*:19000:0:99999:7:::\n", 0640);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(ADD("e", "5"), t_events(1, 3));
    /* An existing name whose field became empty, with and without. */
    t_reset();
    t_file("etc/passwd", ROOT "e:x:5:5::/:/bin/sh\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/passwd", ROOT "e::5:5::/:/bin/sh\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(PW("e"), t_events(1, 2));
    t_file("etc/shadow", "root:*:19000:0:99999:7:::\n", 0640);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR("", t_events(1, 3));
}

#define GM(n, a, r, ta, tr) EV("group_members_changed", "\"name\":\"" n "\",\"added\":[" a "],\"removed\":[" r "]", \
                               "group " n ": added " ta "; removed " tr, "etc/group")

/* The fourth field as a set: order and repeats say nothing; the lists are
 * sorted bytewise and joined by ", " in the text. */
TEST(group_members_are_compared_as_a_set) {
    t_reset();
    t_file("etc/group", "root:x:0:\nsudo:x:27:ubuntu\nadm:x:4:syslog,ubuntu\ndocker:x:998:b,a\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/group", "root:x:0:\nsudo:x:27:ubuntu,siteuser\nadm:x:4:zed,ubuntu,alice\ndocker:x:998:a,b,a,\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(GM("sudo", "\"siteuser\"", "", "siteuser", "")
                  GM("adm", "\"alice\",\"zed\"", "\"syslog\"", "alice, zed", "syslog"),
                  t_events(1, 2));
    ASSERT_EQ_STR(GM("sudo", "", "\"siteuser\"", "", "siteuser")
                  GM("adm", "\"syslog\"", "\"alice\",\"zed\"", "syslog", "alice, zed"),
                  t_events(2, 1));
}

/* SI-3: a group line whose second or third field differs was removed and
 * another added; its members are compared all the same. */
TEST(a_group_whose_gid_or_password_field_differs_is_removed_and_added) {
    t_reset();
    t_file("etc/group", "root:x:0:\nsite:x:1002:\nops:x:50:a\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/group", "root:x:0:\nops:secret:50:a,b\nsite:x:2002:\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(EV("group_removed", "\"name\":\"site\",\"gid\":1002", "group site removed (gid 1002)", "etc/group")
                  EV("group_added", "\"name\":\"ops\",\"gid\":50", "group ops added (gid 50)", "etc/group")
                  GM("ops", "\"b\"", "", "b", "")
                  EV("group_removed", "\"name\":\"ops\",\"gid\":50", "group ops removed (gid 50)", "etc/group")
                  EV("group_added", "\"name\":\"site\",\"gid\":2002", "group site added (gid 2002)", "etc/group"),
                  t_events(1, 2));
    ASSERT_TRUE(strstr(g_text, "secret") == NULL);
}

/* SA-1: a line with another field count (a blank line and a comment are
 * such lines), one beginning + or -, or a uid or gid that is no number:
 * the file is not interpreted, no event is given from it, and its record
 * says so and stands. The other file's events stand. */
TEST(a_file_that_does_not_parse_is_could_not_interpret) {
    static const char *const BAD[] = {
        ROOT "siteuser:x:1002:1002:/home/siteuser:/bin/sh\n",          /* six fields */
        ROOT "siteuser:x:1002:1002::/home/siteuser:/bin/sh:extra\n",   /* eight */
        ROOT "\n" SITE,                                                 /* a blank line */
        ROOT "# a comment\n" SITE,
        ROOT "+::::::\n" SITE,                                          /* NIS */
        ROOT "+@netgroup::::::\n" SITE,
        ROOT "-baduser::::::\n" SITE,
        ROOT "+nis:x:1:1::/:/bin/sh\n",                                 /* a whole line, but for its sign */
        ROOT "-nis:x:1:1::/:/bin/sh\n",
        ROOT "siteuser:x:abc:1002::/home/siteuser:/bin/sh\n",
        ROOT "siteuser:x:1002:-1::/home/siteuser:/bin/sh\n",
        ROOT "siteuser:x::1002::/home/siteuser:/bin/sh\n",
        ROOT "siteuser:x:4294967296:1002::/home/siteuser:/bin/sh\n",
        ROOT "siteuser:x: 1002:1002::/home/siteuser:/bin/sh\n",
        ROOT ":x:1002:1002::/home/siteuser:/bin/sh\n",                  /* no name */
    };
    for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        t_reset();
        t_file("etc/passwd", ROOT, 0644);
        t_file("etc/group", "root:x:0:\n", 0644);
        REQUIRE(t_snap(1) == 0);
        t_file("etc/passwd", BAD[i], 0644);
        t_file("etc/group", "root:x:0:\nsiteuser:x:1002:\n", 0644);
        REQUIRE(t_snap(2) == 0);
        const char *d = t_diff(1, 2);
        if (strstr(t_record(d, "etc/passwd"), "\"outcome\":\"modified\"") == NULL ||
            strstr(t_record(d, "etc/passwd"), CNI "}") == NULL)
            BELAY_FAIL("case %zu: the record is %s", i, t_record(d, "etc/passwd"));
        const char *want = EV("group_added", "\"name\":\"siteuser\",\"gid\":1002", "group siteuser added (gid 1002)", "etc/group")
                           E10("etc/passwd");
        const char *got = t_only_events(g_text);
        if (strcmp(want, got) != 0) BELAY_FAIL("case %zu: got %s", i, got);
        /* The side before not parsing is the same: nothing can be compared. */
        got = t_events(2, 1);
        want = EV("group_removed", "\"name\":\"siteuser\",\"gid\":1002", "group siteuser removed (gid 1002)", "etc/group")
               E10("etc/passwd");
        if (strcmp(want, got) != 0) BELAY_FAIL("case %zu, reversed: got %s", i, got);
    }
    /* group: four fields, the same rules. */
    static const char *const BADG[] = { "root:x:0\n", "root:x:0::\n", "root:x:zero:\n", "\n", "+:::\n", "-x:::\n", ":x:0:\n",
                                        "+nis:x:5:\n", "-nis:x:5:a\n" };
    for (size_t i = 0; i < sizeof BADG / sizeof BADG[0]; i++) {
        t_reset();
        t_file("etc/group", "root:x:0:\n", 0644);
        REQUIRE(t_snap(1) == 0);
        t_file("etc/group", BADG[i], 0644);
        REQUIRE(t_snap(2) == 0);
        const char *got = t_events(1, 2);
        if (strcmp(E10("etc/group"), got) != 0) BELAY_FAIL("group case %zu: got %s", i, got);
    }
}

/* SA-1: two lines with one name: the first is the user, and the file is
 * also could_not_interpret. */
TEST(two_lines_with_one_name_the_first_is_the_user_and_the_file_is_said) {
    t_reset();
    t_file("etc/passwd", ROOT, 0644);
    t_file("etc/group", "root:x:0:\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/passwd", ROOT SITE "siteuser:x:0:0::/root:/bin/bash\n", 0644);
    t_file("etc/group", "root:x:0:\nsite:x:5:a\nsite:x:6:b\n", 0644);
    REQUIRE(t_snap(2) == 0);
    const char *d = t_diff(1, 2);
    ASSERT_TRUE(strstr(t_record(d, "etc/passwd"), CNI "}") != NULL);
    ASSERT_TRUE(strstr(t_record(d, "etc/group"), CNI "}") != NULL);
    ASSERT_EQ_STR(E10("etc/group")
                  EV("group_added", "\"name\":\"site\",\"gid\":5", "group site added (gid 5)", "etc/group")
                  E10("etc/passwd")
                  EV("user_added", "\"name\":\"siteuser\",\"uid\":1002,\"gid\":1002,\"home\":\"/home/siteuser\","
                     "\"shell\":\"/bin/sh\",\"uid_min\":null",
                     "user siteuser added: uid 1002, home /home/siteuser, shell /bin/sh", "etc/passwd"),
                  t_only_events(g_text));
    /* Twice before, once after: still the first of each side. */
    ASSERT_EQ_STR(E10("etc/group")
                  EV("group_removed", "\"name\":\"site\",\"gid\":5", "group site removed (gid 5)", "etc/group")
                  E10("etc/passwd")
                  EV("user_removed", "\"name\":\"siteuser\",\"uid\":1002", "user siteuser removed (uid 1002)", "etc/passwd"),
                  t_events(2, 1));
}

/* A file added whole, or removed: every line is one. An empty file has no line. */
TEST(a_new_or_removed_file_is_its_lines) {
    t_reset();
    t_file("etc/hostname", "h\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/passwd", ROOT, 0644);
    t_file("etc/group", "", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(EV("user_added", "\"name\":\"root\",\"uid\":0,\"gid\":0,\"home\":\"/root\",\"shell\":\"/bin/bash\",\"uid_min\":null",
                     "user root added: uid 0, home /root, shell /bin/bash", "etc/passwd"),
                  t_events(1, 2));
    ASSERT_EQ_STR(EV("user_removed", "\"name\":\"root\",\"uid\":0", "user root removed (uid 0)", "etc/passwd"), t_events(2, 1));
}

/* Only passwd and group directly in an etc; a change of mode alone is no
 * change of text. */
TEST(other_paths_and_metadata_say_nothing) {
    t_reset();
    t_file("etc/passwd", ROOT, 0644);
    t_file("etc/passwd.d/etc/group", "root:x:0:\n", 0644);
    t_file("etc/group/x", "y\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/passwd", ROOT, 0600);
    t_file("etc/group/x", "z\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR("", t_events(1, 2));
}

/* ---- by hand: what no capture of this binary writes ---- */

/* SI-2: sealed against the claim, no copy kept, a copy gone from the store,
 * or not a regular file: could_not_interpret, on the record and as an event. */
TEST(a_side_that_cannot_be_read_is_could_not_interpret) {
    const char *before = t_put(ROOT), *after = t_put(ROOT SITE);
    for (int c = 0; c < 5; c++) {
        struct t_run r;
        tr_begin(&r, BELAY_INTERP_ACCOUNTS);
        struct belay_entry b = t_entry("etc/passwd", BELAY_T_REG, 0644, before);
        struct belay_entry a = t_entry("etc/passwd", BELAY_T_REG, 0644, after);
        if (c == 0) { a.sealed = true; a.has_stored = false; }
        if (c == 1) a.has_stored = false;
        if (c == 2) snprintf(a.stored_hex, sizeof a.stored_hex, "%064d", 0);
        if (c == 3) a = t_entry("etc/passwd", BELAY_T_LNK, 0777, NULL);
        if (c == 4) { b.meta = true; b.has_stored = false; }
        const char *got = tr_path(&r, "etc/passwd", &b, &a, c == 3 ? "type_changed" : "modified");
        if (strcmp(CNI, got) != 0) BELAY_FAIL("case %d: findings %s", c, got);
        got = tr_end(&r, NULL, 0);
        if (strcmp(E10("etc/passwd"), got) != 0) BELAY_FAIL("case %d: events %s", c, got);
        tr_free(&r);
    }
}

/* P8, E2: a path whose outcome is unknown is read all the same; its record
 * gets no finding and its events are provisional. metadata_only: nothing. */
TEST(an_unknown_outcome_gives_provisional_events) {
    struct t_run r;
    tr_begin(&r, BELAY_INTERP_ACCOUNTS);
    const struct belay_entry b = t_entry("etc/passwd", BELAY_T_REG, 0644, t_put(ROOT));
    const struct belay_entry a = t_entry("etc/passwd", BELAY_T_REG, 0644, t_put(ROOT SITE));
    const struct belay_entry bad = t_entry("etc/group", BELAY_T_REG, 0644, t_put("not a group line\n"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/group", NULL, &bad, "unknown"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/passwd", &b, &a, "unknown"));
    const struct belay_entry defs = t_entry("etc/login.defs", BELAY_T_REG, 0644, t_put("UID_MIN 1000\n"));
    ASSERT_EQ_STR("{\"event\":\"could_not_interpret\",\"interp\":\"accounts\",\"text\":\"could not interpret\","
                  "\"provisional\":true,\"paths\":[\"etc/group\"]}\n"
                  "{\"event\":\"user_added\",\"interp\":\"accounts\",\"name\":\"siteuser\",\"uid\":1002,\"gid\":1002,"
                  "\"home\":\"/home/siteuser\",\"shell\":\"/bin/sh\",\"uid_min\":1000,"
                  "\"text\":\"user siteuser added: uid 1002, home /home/siteuser, shell /bin/sh\","
                  "\"provisional\":true,\"paths\":[\"etc/passwd\"]}\n",
                  tr_end(&r, &defs, 1));
    tr_free(&r);
    /* Every kind of the two files is provisional then. */
#define PROV(kind, fields, text, path) \
    "{\"event\":\"" kind "\",\"interp\":\"accounts\"," fields ",\"text\":\"" text "\",\"provisional\":true,\"paths\":[\"" path "\"]}\n"
    tr_begin(&r, BELAY_INTERP_ACCOUNTS);
    const struct belay_entry b2 = t_entry("etc/passwd", BELAY_T_REG, 0644, t_put(ROOT "a:x:1:1::/:/bin/sh\ngone:x:2:2::/:/bin/sh\n"));
    const struct belay_entry a2 = t_entry("etc/passwd", BELAY_T_REG, 0644, t_put(ROOT "a:hash:1:1::/:/bin/zsh\n"));
    const struct belay_entry gb = t_entry("etc/group", BELAY_T_REG, 0644, t_put("g:x:1:\nold:x:2:\n"));
    const struct belay_entry ga = t_entry("etc/group", BELAY_T_REG, 0644, t_put("g:x:1:m\nnew:x:3:\n"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/group", &gb, &ga, "unknown"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/passwd", &b2, &a2, "unknown"));
    ASSERT_EQ_STR(PROV("group_members_changed", "\"name\":\"g\",\"added\":[\"m\"],\"removed\":[]", "group g: added m; removed ", "etc/group")
                  PROV("group_removed", "\"name\":\"old\",\"gid\":2", "group old removed (gid 2)", "etc/group")
                  PROV("group_added", "\"name\":\"new\",\"gid\":3", "group new added (gid 3)", "etc/group")
                  PROV("user_changed", "\"name\":\"a\",\"field\":\"shell\",\"from\":\"/bin/sh\",\"to\":\"/bin/zsh\"",
                       "user a: shell /bin/sh -> /bin/zsh", "etc/passwd")
                  PROV("user_password_in_passwd", "\"name\":\"a\"", "user a: a password is set in passwd itself", "etc/passwd")
                  PROV("user_removed", "\"name\":\"gone\",\"uid\":2", "user gone removed (uid 2)", "etc/passwd"),
                  tr_end(&r, NULL, 0));
    tr_free(&r);
    tr_begin(&r, BELAY_INTERP_ACCOUNTS);
    ASSERT_EQ_STR("", tr_path(&r, "etc/passwd", &b, &a, "metadata_only"));
    ASSERT_EQ_INT(BELAY_INTERP_DECLINE, r.last);
    ASSERT_EQ_STR("", tr_end(&r, NULL, 0));
    tr_free(&r);
}

/* A login.defs without a kept copy, or sealed: uid_min is null. */
TEST(a_login_defs_that_cannot_be_read_is_null) {
    for (int c = 0; c < 3; c++) {
        struct t_run r;
        tr_begin(&r, BELAY_INTERP_ACCOUNTS);
        const struct belay_entry b = t_entry("etc/passwd", BELAY_T_REG, 0644, t_put(ROOT));
        const struct belay_entry a = t_entry("etc/passwd", BELAY_T_REG, 0644, t_put(ROOT SITE));
        tr_path(&r, "etc/passwd", &b, &a, "modified");
        struct belay_entry defs = t_entry("etc/login.defs", BELAY_T_REG, 0644, t_put("UID_MIN 1000\n"));
        if (c == 0) defs.has_stored = false;
        if (c == 1) snprintf(defs.stored_hex, sizeof defs.stored_hex, "%064d", 0);
        if (c == 2) defs = t_entry("etc/login.defs", BELAY_T_REG, 0644, t_put_n("UID_MIN 1000\n\0", 14));
        const char *got = tr_end(&r, &defs, 1);
        if (strstr(got, "\"uid_min\":null,") == NULL) BELAY_FAIL("case %d: %s", c, got);
        tr_free(&r);
    }
}

/* ---- hostile files (run under the sanitizers by check-san) ---- */

TEST(hostile_files_are_read_within_bounds) {
    struct t_run r;
    const struct belay_entry b = t_entry("etc/passwd", BELAY_T_REG, 0644, t_put(ROOT));
    /* A NUL byte: not a passwd. */
    tr_begin(&r, BELAY_INTERP_ACCOUNTS);
    struct belay_entry a = t_entry("etc/passwd", BELAY_T_REG, 0644, t_put_n(ROOT "a:x:1:1:\0:/:/bin/sh\n", 52));
    ASSERT_EQ_STR(CNI, tr_path(&r, "etc/passwd", &b, &a, "modified"));
    ASSERT_EQ_STR(E10("etc/passwd"), tr_end(&r, NULL, 0));
    tr_free(&r);
    /* No final newline, and CRLF: the CR is a byte of the last field. */
    tr_begin(&r, BELAY_INTERP_ACCOUNTS);
    a = t_entry("etc/passwd", BELAY_T_REG, 0644, t_put(ROOT "a:x:1:1::/:/bin/sh\r\nb:x:2:2::/:/bin/sh"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/passwd", &b, &a, "modified"));
    ASSERT_EQ_STR(EV("user_added", "\"name\":\"a\",\"uid\":1,\"gid\":1,\"home\":\"/\",\"shell\":\"/bin/sh\\r\",\"uid_min\":null",
                     "user a added: uid 1, home /, shell /bin/sh\\r", "etc/passwd")
                  EV("user_added", "\"name\":\"b\",\"uid\":2,\"gid\":2,\"home\":\"/\",\"shell\":\"/bin/sh\",\"uid_min\":null",
                     "user b added: uid 2, home /, shell /bin/sh", "etc/passwd"),
                  tr_end(&r, NULL, 0));
    tr_free(&r);
    /* A 70,000-byte home and a name that is not UTF-8: each is one invalid
     * event in its place (E9), the others stand. */
    static char big[80000];
    size_t w = (size_t)snprintf(big, sizeof big, ROOT "a:x:1:1::/:/bin/sh\nlong:x:2:2::/");
    memset(big + w, 'g', 70000);
    w += 70000;
    snprintf(big + w, sizeof big - w, ":/bin/sh\nbad\xff:x:3:3::/:/bin/sh\nz:x:4:4::/:/bin/sh\n");
    tr_begin(&r, BELAY_INTERP_ACCOUNTS);
    a = t_entry("etc/passwd", BELAY_T_REG, 0644, t_put(big));
    ASSERT_EQ_STR("", tr_path(&r, "etc/passwd", &b, &a, "modified"));
#define INV "{\"event\":\"invalid_finding\",\"interp\":\"accounts\",\"text\":\"invalid finding\",\"paths\":[\"etc/passwd\"]}\n"
    ASSERT_EQ_STR(ADD("a", "1") INV INV ADD("z", "4"), tr_end(&r, NULL, 0));
    tr_free(&r);
    /* 100,000 lines: 100,000 users added, of which 65,536 events are kept
     * and the last counts the rest (E5). */
    static char many[4000000];
    w = (size_t)snprintf(many, sizeof many, ROOT);
    for (int i = 0; i < 100000; i++) w += (size_t)snprintf(many + w, sizeof many - w, "u%d:x:%d:%d::/:/bin/sh\n", i, i + 1, i + 1);
    tr_begin(&r, BELAY_INTERP_ACCOUNTS);
    a = t_entry("etc/passwd", BELAY_T_REG, 0644, t_put(many));
    ASSERT_EQ_STR("", tr_path(&r, "etc/passwd", &b, &a, "modified"));
    const char *got = tr_end(&r, NULL, 0);
    size_t lines = 0;
    for (const char *p = got; (p = strchr(p, '\n')) != NULL; p++) lines++;
    ASSERT_EQ_INT(65536, (int)lines);
    ASSERT_TRUE(strstr(got, "{\"event\":\"user_added\",\"interp\":\"accounts\",\"name\":\"u0\",") == got);
    ASSERT_TRUE(strstr(got, "{\"event\":\"and_more\",\"interp\":\"accounts\",\"n\":34465,\"text\":\"and 34465 more\",\"paths\":[]}\n") != NULL);
    tr_free(&r);
    /* 100,000 members of one group, and a group line of 100,000 commas. */
    static char grp[1000000];
    w = (size_t)snprintf(grp, sizeof grp, "big:x:9:");
    for (int i = 0; i < 100000; i++) w += (size_t)snprintf(grp + w, sizeof grp - w, "m%d,", i);
    w += (size_t)snprintf(grp + w, sizeof grp - w, "\ncommas:x:10:");
    memset(grp + w, ',', 100000);
    w += 100000;
    grp[w++] = '\n';
    grp[w] = '\0';
    tr_begin(&r, BELAY_INTERP_ACCOUNTS);
    const struct belay_entry gb = t_entry("etc/group", BELAY_T_REG, 0644, t_put("big:x:9:\ncommas:x:10:x\n"));
    const struct belay_entry ga = t_entry("etc/group", BELAY_T_REG, 0644, t_put(grp));
    ASSERT_EQ_STR("", tr_path(&r, "etc/group", &gb, &ga, "modified"));
    /* big: a list past 256 elements is an invalid event (E9); commas: no name is a member. */
    ASSERT_EQ_STR("{\"event\":\"invalid_finding\",\"interp\":\"accounts\",\"text\":\"invalid finding\",\"paths\":[\"etc/group\"]}\n"
                  GM("commas", "", "\"x\"", "", "x"),
                  tr_end(&r, NULL, 0));
    tr_free(&r);
}

int main(void) {
    t_begin("accounts");
    RUN(useradd_is_a_user_added_and_a_group_added);
    RUN(uid_min_is_login_defs_or_null);
    RUN(uid_min_is_read_beside_the_passwd);
    RUN(user_changed_once_per_field);
    RUN(a_password_in_passwd_is_said_and_never_copied);
    RUN(an_empty_password_field_is_said_only_without_a_shadow);
    RUN(group_members_are_compared_as_a_set);
    RUN(a_group_whose_gid_or_password_field_differs_is_removed_and_added);
    RUN(a_file_that_does_not_parse_is_could_not_interpret);
    RUN(two_lines_with_one_name_the_first_is_the_user_and_the_file_is_said);
    RUN(a_new_or_removed_file_is_its_lines);
    RUN(other_paths_and_metadata_say_nothing);
    RUN(a_side_that_cannot_be_read_is_could_not_interpret);
    RUN(an_unknown_outcome_gives_provisional_events);
    RUN(a_login_defs_that_cannot_be_read_is_null);
    RUN(hostile_files_are_read_within_bounds);
    free(g_text);
    t_end();
    return belay_test_report();
}
