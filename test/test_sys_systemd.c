/*
 *  The systemd interpreter (test/expect/system-interpreters.md SY-1 to SY-4,
 *  SW-7; finding-kinds.md, unit_*, init_script_*, timer_file_*). The
 *  fixtures are what the pin's "how established" cells saw systemctl write:
 *  `enable` adds the one link `etc/systemd/system/multi-user.target.wants/
 *  nginx.service`, pointing at `/lib/systemd/system/nginx.service` on 22.04
 *  and `/usr/lib/systemd/system/nginx.service` on 24.04; `mask` adds
 *  `etc/systemd/system/nginx.service -> /dev/null`; enabling a timer adds
 *  `timers.target.wants/probe.timer`. Every expectation is written by hand.
 */
#include "sys_test.h"

#include "interp/inwords.h"

#include <sys/time.h>

#define EV(kind) "{\"event\":\"" kind "\",\"interp\":\"systemd\","
#define E10(p) "{\"event\":\"could_not_interpret\",\"interp\":\"systemd\",\"text\":\"could not interpret\",\"paths\":[\"" p "\"]}\n"
#define CNI ",\"findings\":[{\"kind\":\"could_not_interpret\",\"text\":\"could not interpret\"}]"

#define WANTS "etc/systemd/system/multi-user.target.wants"
#define UNIT  "[Unit]\nDescription=A high performance web server\n\n[Service]\nExecStart=/usr/sbin/nginx\n\n[Install]\nWantedBy=multi-user.target\n"
#define TIMER(cal) "[Unit]\nDescription=probe\n\n[Timer]\n" cal "\n[Install]\nWantedBy=timers.target\n"

static int count(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

/* A dpkg database that lists nothing: every owner asked is null. */
static void db(void) {
    t_file("var/lib/dpkg/diversions", "", 0644);
    t_dir("var/lib/dpkg/info");
}

/* SY-1, SI-5: enable is one link added, disable the link removed; the
 * owner is the package of the file the link's text names, found whichever
 * way the release's list spells the path. Never "enabled" (SY-3); what a
 * package install writes under var/lib/systemd is no event (SY-2). */
TEST(enable_and_disable_are_a_link_added_and_removed) {
    t_reset();
    t_file("var/lib/dpkg/diversions", "", 0644);
    t_file("var/lib/dpkg/info/nginx-common.list", "/lib/systemd/system/nginx.service\n", 0644);     /* 22.04 */
    t_file("usr/lib/systemd/system/nginx.service", UNIT, 0644);
    t_link("lib", "usr/lib");
    REQUIRE(t_snap(1) == 0);
    t_link(WANTS "/nginx.service", "/lib/systemd/system/nginx.service");
    t_file("var/lib/systemd/deb-systemd-helper-enabled/multi-user.target.wants/nginx.service", "", 0644);
    t_file("var/lib/systemd/deb-systemd-helper-enabled/nginx.service.dsh-also",
           "/etc/systemd/system/multi-user.target.wants/nginx.service\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EV("unit_linked") "\"unit\":\"nginx.service\",\"into\":\"multi-user.target\","
        "\"target\":\"/lib/systemd/system/nginx.service\",\"owner\":\"nginx-common\","
        "\"text\":\"nginx.service linked into multi-user.target\",\"paths\":[\"" WANTS "/nginx.service\"]}\n",
        t_events(1, 2));
    /* 24.04: the list and the link both say /usr/lib. The link's text
     * changed: one unlinked, one linked (SI-3), removed first; the old
     * text's file is still nginx-common's, by the list's other spelling. */
    t_file("var/lib/dpkg/info/nginx-common.list", "/usr/lib/systemd/system/nginx.service\n", 0644);
    t_link(WANTS "/nginx.service", "/usr/lib/systemd/system/nginx.service");
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(
        EV("unit_unlinked") "\"unit\":\"nginx.service\",\"into\":\"multi-user.target\","
        "\"target\":\"/lib/systemd/system/nginx.service\",\"owner\":\"nginx-common\","
        "\"text\":\"nginx.service unlinked from multi-user.target\",\"paths\":[\"" WANTS "/nginx.service\"]}\n"
        EV("unit_linked") "\"unit\":\"nginx.service\",\"into\":\"multi-user.target\","
        "\"target\":\"/usr/lib/systemd/system/nginx.service\",\"owner\":\"nginx-common\","
        "\"text\":\"nginx.service linked into multi-user.target\",\"paths\":[\"" WANTS "/nginx.service\"]}\n",
        t_events(2, 3));
    t_rm(WANTS "/nginx.service");
    REQUIRE(t_snap(4) == 0);
    ASSERT_EQ_STR(
        EV("unit_unlinked") "\"unit\":\"nginx.service\",\"into\":\"multi-user.target\","
        "\"target\":\"/usr/lib/systemd/system/nginx.service\",\"owner\":\"nginx-common\","
        "\"text\":\"nginx.service unlinked from multi-user.target\",\"paths\":[\"" WANTS "/nginx.service\"]}\n",
        t_events(3, 4));
    ASSERT_TRUE(strstr(t_events(1, 4), "enabled") == NULL);
}

/* A `.requires` directory is the same; a link's text read from its own
 * directory when it is relative; one that leaves the scope has no owner
 * asked; without a dpkg database no owner is given at all. A file that is
 * not a link in a .wants directory is nothing of systemd's. */
TEST(links_name_their_target_as_written_and_its_owner_where_it_can_be_told) {
    t_reset();
    t_file("var/lib/dpkg/diversions", "", 0644);
    t_file("var/lib/dpkg/info/site.list", "/etc/systemd/system/site.service\n", 0644);
    t_file("etc/systemd/system/site.service", UNIT, 0644);
    REQUIRE(t_snap(1) == 0);
    t_link("etc/systemd/system/sockets.target.requires/site.service", "../site.service");
    t_link("etc/systemd/system/sockets.target.wants/out.service", "../../../../../out.service");
    t_link("etc/systemd/system/sockets.target.wants/local.service", "/usr/local/lib/local.service");
    t_file("etc/systemd/system/sockets.target.wants/not-a-link.service", UNIT, 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EV("unit_linked") "\"unit\":\"site.service\",\"into\":\"sockets.target\",\"target\":\"../site.service\","
        "\"owner\":\"site\",\"text\":\"site.service linked into sockets.target\","
        "\"paths\":[\"etc/systemd/system/sockets.target.requires/site.service\"]}\n"
        EV("unit_linked") "\"unit\":\"local.service\",\"into\":\"sockets.target\",\"target\":\"/usr/local/lib/local.service\","
        "\"owner\":null,\"text\":\"local.service linked into sockets.target\","
        "\"paths\":[\"etc/systemd/system/sockets.target.wants/local.service\"]}\n"
        EV("unit_linked") "\"unit\":\"out.service\",\"into\":\"sockets.target\",\"target\":\"../../../../../out.service\","
        "\"text\":\"out.service linked into sockets.target\","
        "\"paths\":[\"etc/systemd/system/sockets.target.wants/out.service\"]}\n",
        t_events(1, 2));
    t_reset();
    REQUIRE(t_snap(1) == 0);
    t_link("usr/lib/systemd/system/sysinit.target.wants/x.service", "../x.service");
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EV("unit_linked") "\"unit\":\"x.service\",\"into\":\"sysinit.target\",\"target\":\"../x.service\","
        "\"text\":\"x.service linked into sysinit.target\","
        "\"paths\":[\"usr/lib/systemd/system/sysinit.target.wants/x.service\"]}\n",
        t_events(1, 2));
}

/* SY-1: mask is a link to /dev/null where the unit's name is, unmask its
 * removal; an empty file masks too. Only in etc: under usr/lib an empty
 * unit file is a unit file and a link is nothing. */
TEST(mask_and_unmask_are_a_link_to_dev_null_or_an_empty_file) {
    t_reset();
    db();
    t_file("etc/systemd/system/cups.service", UNIT, 0644);
    REQUIRE(t_snap(1) == 0);
    t_link("etc/systemd/system/nginx.service", "/dev/null");
    t_file("etc/systemd/system/cups.service", "", 0644);
    t_file("etc/systemd/user/new.socket", "", 0644);
    t_file("usr/lib/systemd/system/empty.service", "", 0644);
    t_link("usr/lib/systemd/system/gone.service", "/dev/null");
    t_link("etc/systemd/system/README", "/dev/null");
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EV("unit_file_removed") "\"path\":\"etc/systemd/system/cups.service\",\"owner\":null,"
        "\"text\":\"unit file etc/systemd/system/cups.service removed\",\"paths\":[\"etc/systemd/system/cups.service\"]}\n"
        EV("unit_masked") "\"unit\":\"cups.service\",\"text\":\"cups.service masked\",\"paths\":[\"etc/systemd/system/cups.service\"]}\n"
        EV("unit_masked") "\"unit\":\"nginx.service\",\"text\":\"nginx.service masked\",\"paths\":[\"etc/systemd/system/nginx.service\"]}\n"
        EV("unit_masked") "\"unit\":\"new.socket\",\"text\":\"new.socket masked\",\"paths\":[\"etc/systemd/user/new.socket\"]}\n"
        EV("unit_file_added") "\"path\":\"usr/lib/systemd/system/empty.service\",\"owner\":null,"
        "\"text\":\"unit file usr/lib/systemd/system/empty.service added\",\"paths\":[\"usr/lib/systemd/system/empty.service\"]}\n",
        t_events(1, 2));
    t_rm("etc/systemd/system/nginx.service");
    t_file("etc/systemd/system/cups.service", UNIT, 0644);
    t_link("etc/systemd/user/new.socket", "/dev/null");            /* masked either way: no event */
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(
        EV("unit_unmasked") "\"unit\":\"cups.service\",\"text\":\"cups.service unmasked\",\"paths\":[\"etc/systemd/system/cups.service\"]}\n"
        EV("unit_file_added") "\"path\":\"etc/systemd/system/cups.service\",\"owner\":null,"
        "\"text\":\"unit file etc/systemd/system/cups.service added\",\"paths\":[\"etc/systemd/system/cups.service\"]}\n"
        EV("unit_unmasked") "\"unit\":\"nginx.service\",\"text\":\"nginx.service unmasked\",\"paths\":[\"etc/systemd/system/nginx.service\"]}\n",
        t_events(2, 3));
}

/* A link in etc/systemd/system itself, not to /dev/null, is an alias: its
 * name and its text. A changed text is one removed and one added. */
TEST(a_link_in_the_directory_itself_is_an_alias) {
    t_reset();
    REQUIRE(t_snap(1) == 0);
    t_link("etc/systemd/system/dbus-org.freedesktop.timesync1.service", "/lib/systemd/system/systemd-timesyncd.service");
    REQUIRE(t_snap(2) == 0);
#define AL "etc/systemd/system/dbus-org.freedesktop.timesync1.service"
    ASSERT_EQ_STR(
        EV("unit_alias_added") "\"alias\":\"dbus-org.freedesktop.timesync1.service\","
        "\"target\":\"/lib/systemd/system/systemd-timesyncd.service\","
        "\"text\":\"dbus-org.freedesktop.timesync1.service is a link to /lib/systemd/system/systemd-timesyncd.service\","
        "\"paths\":[\"" AL "\"]}\n",
        t_events(1, 2));
    t_link(AL, "/etc/systemd/system/other.service");
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(
        EV("unit_alias_removed") "\"alias\":\"dbus-org.freedesktop.timesync1.service\","
        "\"target\":\"/lib/systemd/system/systemd-timesyncd.service\","
        "\"text\":\"dbus-org.freedesktop.timesync1.service is no longer a link to /lib/systemd/system/systemd-timesyncd.service\","
        "\"paths\":[\"" AL "\"]}\n"
        EV("unit_alias_added") "\"alias\":\"dbus-org.freedesktop.timesync1.service\","
        "\"target\":\"/etc/systemd/system/other.service\","
        "\"text\":\"dbus-org.freedesktop.timesync1.service is a link to /etc/systemd/system/other.service\","
        "\"paths\":[\"" AL "\"]}\n",
        t_events(2, 3));
    /* It becomes a mask: the alias is gone and the unit masked. */
    t_link(AL, "/dev/null");
    REQUIRE(t_snap(4) == 0);
    ASSERT_EQ_STR(
        EV("unit_alias_removed") "\"alias\":\"dbus-org.freedesktop.timesync1.service\","
        "\"target\":\"/etc/systemd/system/other.service\","
        "\"text\":\"dbus-org.freedesktop.timesync1.service is no longer a link to /etc/systemd/system/other.service\","
        "\"paths\":[\"" AL "\"]}\n"
        EV("unit_masked") "\"unit\":\"dbus-org.freedesktop.timesync1.service\","
        "\"text\":\"dbus-org.freedesktop.timesync1.service masked\",\"paths\":[\"" AL "\"]}\n",
        t_events(3, 4));
#undef AL
}

/* Unit files and drop-ins are named with their owner, never parsed; one
 * added in etc where a packaged one of its name is takes its place. */
TEST(unit_files_are_named_and_one_over_a_packaged_one_is_said) {
    t_reset();
    t_file("var/lib/dpkg/diversions", "", 0644);
    t_file("var/lib/dpkg/info/nginx-common.list", "/usr/lib/systemd/system/nginx.service\n", 0644);
    t_file("usr/lib/systemd/system/nginx.service", UNIT, 0644);
    t_file("usr/lib/systemd/user/agent.service", UNIT, 0644);
    t_file("lib/systemd/system/old.service", UNIT, 0644);          /* `lib` a directory here */
    REQUIRE(t_snap(1) == 0);
    t_file("etc/systemd/system/nginx.service", UNIT "# site\n", 0644);
    t_file("etc/systemd/system/old.service", UNIT, 0644);
    t_file("etc/systemd/system/site.service", UNIT, 0644);
    t_file("etc/systemd/system/nginx.service.d/override.conf", "[Service]\nLimitNOFILE=65536\n", 0644);
    t_file("etc/systemd/system/README", "not a unit\n", 0644);
    t_file("etc/systemd/system/notaunit.d/x.conf", "[Service]\n", 0644);
    t_file("etc/systemd/user/agent.service", UNIT, 0644);
    REQUIRE(t_snap(2) == 0);
#define FA(p, own) EV("unit_file_added") "\"path\":\"" p "\",\"owner\":" own ",\"text\":\"unit file " p " added\",\"paths\":[\"" p "\"]}\n"
#define OV(u, p, o) EV("unit_overrides_packaged") "\"unit\":\"" u "\",\"path\":\"" p "\",\"over\":\"" o "\"," \
                    "\"text\":\"" p " takes the place of " o "\",\"paths\":[\"" p "\"]}\n"
    ASSERT_EQ_STR(
        FA("etc/systemd/system/nginx.service", "null")
        OV("nginx.service", "etc/systemd/system/nginx.service", "usr/lib/systemd/system/nginx.service")
        FA("etc/systemd/system/nginx.service.d/override.conf", "null")
        FA("etc/systemd/system/old.service", "null")
        OV("old.service", "etc/systemd/system/old.service", "lib/systemd/system/old.service")
        FA("etc/systemd/system/site.service", "null")
        FA("etc/systemd/user/agent.service", "null")
        OV("agent.service", "etc/systemd/user/agent.service", "usr/lib/systemd/user/agent.service"),
        t_events(1, 2));
    t_file("usr/lib/systemd/system/nginx.service", UNIT "# changed\n", 0644);
    t_file("etc/systemd/system/nginx.service.d/override.conf", "[Service]\nLimitNOFILE=1024\n", 0644);
    t_file("etc/systemd/system/nginx.service", UNIT "# site, again\n", 0644);  /* changed, not added: no override said */
    t_rm("etc/systemd/system/site.service");
    char p[700];
    snprintf(p, sizeof p, "%s/root/etc/systemd/system/old.service", g_dir);
    REQUIRE(chmod(p, 0600) == 0);                                   /* the mode alone: nothing */
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(
        EV("unit_file_changed") "\"path\":\"etc/systemd/system/nginx.service\",\"owner\":null,"
        "\"text\":\"unit file etc/systemd/system/nginx.service changed\",\"paths\":[\"etc/systemd/system/nginx.service\"]}\n"
        EV("unit_file_changed") "\"path\":\"etc/systemd/system/nginx.service.d/override.conf\",\"owner\":null,"
        "\"text\":\"unit file etc/systemd/system/nginx.service.d/override.conf changed\","
        "\"paths\":[\"etc/systemd/system/nginx.service.d/override.conf\"]}\n"
        EV("unit_file_removed") "\"path\":\"etc/systemd/system/site.service\",\"owner\":null,"
        "\"text\":\"unit file etc/systemd/system/site.service removed\",\"paths\":[\"etc/systemd/system/site.service\"]}\n"
        EV("unit_file_changed") "\"path\":\"usr/lib/systemd/system/nginx.service\",\"owner\":\"nginx-common\","
        "\"text\":\"unit file usr/lib/systemd/system/nginx.service changed\",\"paths\":[\"usr/lib/systemd/system/nginx.service\"]}\n",
        t_events(2, 3));
#undef FA
#undef OV
}

#define PT "usr/lib/systemd/system/probe.timer"
#define TF(kind, word, cal, words) EV(kind) "\"path\":\"" PT "\",\"on_calendar\":[" cal "],\"owner\":null" words \
                                   ",\"text\":\"timer " PT " " word ": "

/* SY-1, SW-7: a .timer file is a unit file and a timer: its OnCalendar=
 * values as written, and words for the forms of the table alone. */
TEST(timer_files_carry_their_on_calendar_values_and_words) {
    t_reset();
    db();
    REQUIRE(t_snap(1) == 0);
    t_file(PT, TIMER("OnCalendar=*-*-* 03:17:00\n"), 0644);
    t_link("etc/systemd/system/timers.target.wants/probe.timer", "/usr/lib/systemd/system/probe.timer");
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EV("unit_linked") "\"unit\":\"probe.timer\",\"into\":\"timers.target\",\"target\":\"/usr/lib/systemd/system/probe.timer\","
        "\"owner\":null,\"text\":\"probe.timer linked into timers.target\","
        "\"paths\":[\"etc/systemd/system/timers.target.wants/probe.timer\"]}\n"
        EV("unit_file_added") "\"path\":\"" PT "\",\"owner\":null,\"text\":\"unit file " PT " added\",\"paths\":[\"" PT "\"]}\n"
        TF("timer_file_added", "added", "\"*-*-* 03:17:00\"", ",\"in_words\":\"at 03:17 every day (by systemd's)\"")
        "*-*-* 03:17:00\",\"paths\":[\"" PT "\"]}\n",
        t_events(1, 2));
    /* Another value: the timer removed and added (SI-3), besides the file changed. */
    t_file(PT, TIMER("OnCalendar=Mon,Thu *-*-* 03:17:00\n"), 0644);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(
        TF("timer_file_removed", "removed", "\"*-*-* 03:17:00\"", ",\"in_words\":\"at 03:17 every day (by systemd's)\"")
        "*-*-* 03:17:00\",\"paths\":[\"" PT "\"]}\n"
        EV("unit_file_changed") "\"path\":\"" PT "\",\"owner\":null,\"text\":\"unit file " PT " changed\",\"paths\":[\"" PT "\"]}\n"
        TF("timer_file_added", "added", "\"Mon,Thu *-*-* 03:17:00\"", ",\"in_words\":\"at 03:17 on Mon, Thu (by systemd's)\"")
        "Mon,Thu *-*-* 03:17:00\",\"paths\":[\"" PT "\"]}\n",
        t_events(2, 3));
    /* The same values, another line changed: the file changed, the timer is no event. */
    t_file(PT, "# a comment\n" TIMER("OnCalendar=Mon,Thu *-*-* 03:17:00\n"), 0644);
    REQUIRE(t_snap(4) == 0);
    ASSERT_EQ_STR(EV("unit_file_changed") "\"path\":\"" PT "\",\"owner\":null,\"text\":\"unit file " PT " changed\",\"paths\":[\"" PT "\"]}\n",
                  t_events(3, 4));
    /* Two values: both as written, in order, and no words. A value outside
     * [Timer], a comment, and a key that only begins like it are not values. */
    t_file(PT, "[Unit]\nOnCalendar=yearly\n[Timer]\n# OnCalendar=hourly\n;OnCalendar=hourly\nOnCalendarX=1\n"
               " OnCalendar = daily \nOnCalendar=Sat *-*-* 10:00:00\n[Install]\nOnCalendar=monthly\n", 0644);
    REQUIRE(t_snap(5) == 0);
    ASSERT_TRUE(strstr(t_events(4, 5),
        TF("timer_file_added", "added", "\"daily\",\"Sat *-*-* 10:00:00\"", "") "daily, Sat *-*-* 10:00:00\",") != NULL);
    /* An empty assignment forgets what was above it; another trigger beside
     * the one value: no words. Removed: with the values it had. */
    t_file(PT, "[Timer]\nOnCalendar=hourly\nOnCalendar=\nOnCalendar=weekly\nOnBootSec=5min\n", 0644);
    REQUIRE(t_snap(6) == 0);
    ASSERT_TRUE(strstr(t_events(5, 6), TF("timer_file_added", "added", "\"weekly\"", "") "weekly\",") != NULL);
    t_file(PT, "[Timer]\nOnCalendar=weekly\n", 0644);
    REQUIRE(t_snap(7) == 0);
    ASSERT_EQ_INT(0, count(t_events(6, 7), "timer_file"));          /* the values are the same: only the file changed */
    t_rm(PT);
    REQUIRE(t_snap(8) == 0);
    ASSERT_EQ_STR(
        EV("unit_file_removed") "\"path\":\"" PT "\",\"owner\":null,\"text\":\"unit file " PT " removed\",\"paths\":[\"" PT "\"]}\n"
        TF("timer_file_removed", "removed", "\"weekly\"", ",\"in_words\":\"at 00:00 on Mon (by systemd's)\"")
        "weekly\",\"paths\":[\"" PT "\"]}\n",
        t_events(7, 8));
    /* No OnCalendar at all: an empty list, and a line continued by a backslash is one value. */
    t_file(PT, "[Timer]\nOnBootSec=1h\n", 0644);
    t_file("etc/systemd/system/cont.timer", "[Timer]\nOnCalendar=Mon \\\n*-*-* 01:00:00\n", 0644);
    REQUIRE(t_snap(9) == 0);
    const char *ev = t_events(8, 9);
    ASSERT_TRUE(strstr(ev, TF("timer_file_added", "added", "", "") "\",\"paths\"") != NULL);
    ASSERT_TRUE(strstr(ev, "\"path\":\"etc/systemd/system/cont.timer\",\"on_calendar\":[\"Mon  *-*-* 01:00:00\"],\"owner\":null,\"text\"") != NULL);
}

/* SY-3a: a unit under a home's .config/systemd/user gives the same kinds,
 * its `unit` prefixed by that directory's path. */
TEST(a_home_s_units_are_prefixed_by_their_directory) {
    t_reset();
    REQUIRE(t_snap(1) == 0);
#define HD "home/u/.config/systemd/user"
    t_file(HD "/probe.service", UNIT, 0644);
    t_link(HD "/default.target.wants/probe.service", "/home/u/.config/systemd/user/probe.service");
    t_link(HD "/noisy.service", "/dev/null");
    t_link(HD "/alias.service", "probe.service");
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        EV("unit_alias_added") "\"alias\":\"" HD "/alias.service\",\"target\":\"probe.service\","
        "\"text\":\"" HD "/alias.service is a link to probe.service\",\"paths\":[\"" HD "/alias.service\"]}\n"
        EV("unit_linked") "\"unit\":\"" HD "/probe.service\",\"into\":\"default.target\","
        "\"target\":\"/home/u/.config/systemd/user/probe.service\","
        "\"text\":\"" HD "/probe.service linked into default.target\",\"paths\":[\"" HD "/default.target.wants/probe.service\"]}\n"
        EV("unit_masked") "\"unit\":\"" HD "/noisy.service\",\"text\":\"" HD "/noisy.service masked\",\"paths\":[\"" HD "/noisy.service\"]}\n"
        EV("unit_file_added") "\"path\":\"" HD "/probe.service\",\"text\":\"unit file " HD "/probe.service added\","
        "\"paths\":[\"" HD "/probe.service\"]}\n",
        t_events(1, 2));
#undef HD
}

/* SY-3b: rc.local and the files of init.d are named, never read, with
 * whether they are executable -- which is what rc-local.service asks. */
TEST(init_scripts_are_named_with_their_owner_and_execute_bit) {
    t_reset();
    t_file("var/lib/dpkg/diversions", "", 0644);
    t_file("var/lib/dpkg/info/nginx-common.list", "/etc/init.d/nginx\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/rc.local", "#!/bin/sh\n/usr/local/bin/beacon &\n", 0644);
    t_file("etc/init.d/nginx", "#!/bin/sh\n# \0 binary is fine: never read\n", 0755);
    t_dir("etc/init.d/sub");
    t_link("etc/rc2.d/S01nginx", "../init.d/nginx");               /* SY-3b: not an event */
    REQUIRE(t_snap(2) == 0);
#define IS(kind, word, p, own, x) EV(kind) "\"path\":\"" p "\",\"owner\":" own ",\"executable\":" x \
                                  ",\"text\":\"init script " p " " word "\",\"paths\":[\"" p "\"]}\n"
    ASSERT_EQ_STR(IS("init_script_added", "added", "etc/init.d/nginx", "\"nginx-common\"", "true")
                  IS("init_script_added", "added", "etc/rc.local", "null", "false"),
                  t_events(1, 2));
    char p[700];
    snprintf(p, sizeof p, "%s/root/etc/rc.local", g_dir);
    REQUIRE(chmod(p, 0755) == 0);                                   /* the mode alone: changed, now executable */
    t_file("etc/init.d/nginx", "#!/bin/sh\nexit 0\n", 0644);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(IS("init_script_changed", "changed", "etc/init.d/nginx", "\"nginx-common\"", "false")
                  IS("init_script_changed", "changed", "etc/rc.local", "null", "true"),
                  t_events(2, 3));
    /* Its times alone: nothing. */
    const struct timeval tv[2] = { { 1000000000, 0 }, { 1000000000, 0 } };
    REQUIRE(utimes(p, tv) == 0);
    REQUIRE(t_snap(4) == 0);
    ASSERT_EQ_STR("", t_events(3, 4));
    t_rm("etc/rc.local");
    t_rm("etc/init.d/nginx");
    t_link("etc/init.d/linked", "/usr/local/bin/x");
    REQUIRE(t_snap(5) == 0);
    ASSERT_EQ_STR(IS("init_script_added", "added", "etc/init.d/linked", "null", "false")
                  IS("init_script_removed", "removed", "etc/init.d/nginx", "\"nginx-common\"", "false")
                  IS("init_script_removed", "removed", "etc/rc.local", "null", "true"),
                  t_events(4, 5));
#undef IS
}

/* SI-2, by hand: a timer whose copy cannot be read is said and gives no
 * other event; an unknown outcome is read and its events provisional;
 * what is not systemd's to name is declined. */
TEST(what_cannot_be_read_is_said_and_what_is_not_systemd_s_is_declined) {
    struct t_run r;
    tr_begin(&r, BELAY_INTERP_SYSTEMD);
    struct belay_entry a = t_entry("etc/systemd/system/sealed.timer", BELAY_T_REG, 0600, NULL);
    a.sealed = true;
    a.size = 10;
    ASSERT_EQ_STR(CNI, tr_path(&r, "etc/systemd/system/sealed.timer", NULL, &a, "added"));
    struct belay_entry nc = t_entry("usr/lib/systemd/system/nocopy.timer", BELAY_T_REG, 0644, NULL);
    nc.size = 10;
    ASSERT_EQ_STR(CNI, tr_path(&r, "usr/lib/systemd/system/nocopy.timer", &nc, NULL, "removed"));
    struct belay_entry gone = t_entry("etc/systemd/system/gone.timer", BELAY_T_REG, 0644,
                                      "0000000000000000000000000000000000000000000000000000000000000000");
    gone.size = 10;
    ASSERT_EQ_STR(CNI, tr_path(&r, "etc/systemd/system/gone.timer", NULL, &gone, "added"));
    /* a link whose text could not be read */
    struct belay_entry lnk = t_entry("etc/systemd/system/a.target.wants/x.service", BELAY_T_LNK, 0777, NULL);
    lnk.unreadable = true;
    ASSERT_EQ_STR(CNI, tr_path(&r, "etc/systemd/system/a.target.wants/x.service", NULL, &lnk, "added"));
    struct belay_entry lnk2 = t_entry("etc/systemd/system/y.service", BELAY_T_LNK, 0777, NULL);
    lnk2.unreadable = true;
    ASSERT_EQ_STR(CNI, tr_path(&r, "etc/systemd/system/y.service", &lnk2, NULL, "removed"));
    /* sealed, though a copy is named: its bytes are given to no interpreter */
    struct belay_entry sc = t_entry("etc/systemd/system/sealed2.timer", BELAY_T_REG, 0600, t_put("[Timer]\nOnCalendar=daily\n"));
    sc.sealed = true;
    sc.size = 25;
    ASSERT_EQ_STR(CNI, tr_path(&r, "etc/systemd/system/sealed2.timer", NULL, &sc, "added"));
    /* unknown: no finding; the events provisional, the unreadable one too */
    struct belay_entry mk = t_entry("etc/systemd/system/m.service", BELAY_T_LNK, 0777, NULL);
    mk.has_link_target = true;
    mk.link_target_len = 9;
    memcpy(mk.link_target, "/dev/null", 9);
    ASSERT_EQ_STR("", tr_path(&r, "etc/systemd/system/m.service", NULL, &mk, "unknown"));
    struct belay_entry zero = mk;                 /* nine bytes that are not /dev/null: an alias */
    memcpy(zero.link_target, "/dev/zero", 9);
    ASSERT_EQ_STR("", tr_path(&r, "etc/systemd/system/z.service", &zero, NULL, "unknown"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/systemd/system/t.target.wants/m.service", &zero, NULL, "unknown"));
    struct belay_entry rc = t_entry("etc/rc.local", BELAY_T_REG, 0755, NULL);
    ASSERT_EQ_STR("", tr_path(&r, "etc/rc.local", NULL, &rc, "unknown"));
    struct belay_entry u1 = t_entry("etc/systemd/system/raced.timer", BELAY_T_REG, 0644, t_put("[Timer]\nOnCalendar=daily\n"));
    u1.size = 25;
    ASSERT_EQ_STR("", tr_path(&r, "etc/systemd/system/raced.timer", NULL, &u1, "unknown"));
    ASSERT_EQ_STR("", tr_path(&r, "usr/lib/systemd/system/raced2.timer", NULL, &nc, "unknown"));
    /* declined */
    struct belay_entry f = t_entry("x", BELAY_T_REG, 0644, t_put(UNIT));
    f.size = 100;
    const struct belay_entry dir = t_entry("x", BELAY_T_DIR, 0755, NULL);
    static const char *const NOT[] = {
        "etc/systemd/system/a.target.wants/deep/x.service", "etc/systemd/system/x.service.d/deep/y.conf",
        "etc/systemd/system/plain/x.service", "etc/systemd/system/x.txt", "usr/lib/systemd/system/x.servic",
        "etc/init.d/sub/x", "etc/systemd/system/a.wants.not/x.service",
    };
    for (size_t i = 0; i < sizeof NOT / sizeof NOT[0]; i++) {
        ASSERT_EQ_STR("", tr_path(&r, NOT[i], NULL, &f, "added"));
        ASSERT_EQ_INT(BELAY_INTERP_DECLINE, (int)r.last);
    }
    ASSERT_EQ_STR("", tr_path(&r, "etc/systemd/system/x.service", NULL, &dir, "added"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/init.d", NULL, &dir, "added"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/systemd/system/same.service", &f, &f, "metadata_only"));
    ASSERT_EQ_STR(
        EV("init_script_added") "\"path\":\"etc/rc.local\",\"executable\":true,\"text\":\"init script etc/rc.local added\","
        "\"provisional\":true,\"paths\":[\"etc/rc.local\"]}\n"
        E10("etc/systemd/system/a.target.wants/x.service") E10("etc/systemd/system/gone.timer")
        EV("unit_masked") "\"unit\":\"m.service\",\"text\":\"m.service masked\",\"provisional\":true,"
        "\"paths\":[\"etc/systemd/system/m.service\"]}\n"
        EV("unit_file_added") "\"path\":\"etc/systemd/system/raced.timer\",\"text\":\"unit file etc/systemd/system/raced.timer added\","
        "\"provisional\":true,\"paths\":[\"etc/systemd/system/raced.timer\"]}\n"
        EV("timer_file_added") "\"path\":\"etc/systemd/system/raced.timer\",\"on_calendar\":[\"daily\"],"
        "\"in_words\":\"at 00:00 every day (by systemd's)\",\"text\":\"timer etc/systemd/system/raced.timer added: daily\","
        "\"provisional\":true,\"paths\":[\"etc/systemd/system/raced.timer\"]}\n"
        E10("etc/systemd/system/sealed.timer") E10("etc/systemd/system/sealed2.timer")
        EV("unit_unlinked") "\"unit\":\"m.service\",\"into\":\"t.target\",\"target\":\"/dev/zero\","
        "\"text\":\"m.service unlinked from t.target\",\"provisional\":true,"
        "\"paths\":[\"etc/systemd/system/t.target.wants/m.service\"]}\n"
        E10("etc/systemd/system/y.service")
        EV("unit_alias_removed") "\"alias\":\"z.service\",\"target\":\"/dev/zero\","
        "\"text\":\"z.service is no longer a link to /dev/zero\",\"provisional\":true,"
        "\"paths\":[\"etc/systemd/system/z.service\"]}\n"
        E10("usr/lib/systemd/system/nocopy.timer")
        "{\"event\":\"could_not_interpret\",\"interp\":\"systemd\",\"text\":\"could not interpret\",\"provisional\":true,"
        "\"paths\":[\"usr/lib/systemd/system/raced2.timer\"]}\n",
        tr_end(&r, NULL, 0));
    tr_free(&r);
}

/* SW-7: the six spellings measured, and their form; nothing else. */
TEST(timer_words_are_given_for_the_forms_of_the_table_only) {
    static const struct { const char *v, *words; } T[] = {
        { "*-*-* 03:17:00", "at 03:17 every day (by systemd's)" },
        { "Mon,Thu *-*-* 03:17:00", "at 03:17 on Mon, Thu (by systemd's)" },
        { "Mon *-*-* 00:00:00", "at 00:00 on Mon (by systemd's)" },
        { "daily", "at 00:00 every day (by systemd's)" },
        { "weekly", "at 00:00 on Mon (by systemd's)" },
        { "hourly", "at minute 0 of every hour (by systemd's)" },
        { "Sat,Sun,Wed *-*-* 23:59:00", "at 23:59 on Sat, Sun, Wed (by systemd's)" },
    };
    char out[128];
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++) {
        out[0] = '\0';
        if (!inwords_timer(T[i].v, strlen(T[i].v), out, sizeof out)) BELAY_FAIL("\"%s\": no words", T[i].v);
        ASSERT_EQ_STR(T[i].words, out);
    }
    static const char *const NONE[] = {
        "", "monthly", "yearly", "minutely", "Daily", "*-*-* 03:17:30", "*-*-* 3:17:00", "*-*-* 24:00:00", "*-*-* 03:60:00",
        "*-*-* *:00:00", "*-*-01 03:17:00", "2026-*-* 03:17:00", "*-*-* 03:17", "*-*-*  03:17:00", " *-*-* 03:17:00",
        "*-*-* 03:17:00 UTC", "Mon..Fri *-*-* 03:17:00", "mon *-*-* 03:17:00", "Monday *-*-* 03:17:00", "Mon, Thu *-*-* 03:17:00",
        "Mon;Thu *-*-* 03:17:00", "Mon Thu *-*-* 03:17:00", "Mon,*-*-* 03:17:00", "Mon, *-*-* 03:17:00", ",Mon *-*-* 03:17:00", "Mon,Xyz *-*-* 03:17:00", "Mon 03:17:00", "03:17:00",
        "*-*-* 03:17:00\n", "dailyx", "hourl",
    };
    for (size_t i = 0; i < sizeof NONE / sizeof NONE[0]; i++)
        if (inwords_timer(NONE[i], strlen(NONE[i]), out, sizeof out)) BELAY_FAIL("\"%s\": words \"%s\"", NONE[i], out);
    /* words that do not fit are not cut */
    ASSERT_FALSE(inwords_timer("daily", 5, out, 20));
}

static struct belay_entry g_e;
static const char *one(struct t_run *r, const char *data, size_t n) {
    tr_begin(r, BELAY_INTERP_SYSTEMD);
    g_e = t_entry("etc/systemd/system/x.timer", BELAY_T_REG, 0644, t_put_n(data, n));
    g_e.size = n;
    tr_path(r, "etc/systemd/system/x.timer", NULL, &g_e, "added");
    return tr_end(r, NULL, 0);
}
#define XT(cal, rest) EV("unit_file_added") "\"path\":\"etc/systemd/system/x.timer\",\"text\":\"unit file etc/systemd/system/x.timer added\"," \
    "\"paths\":[\"etc/systemd/system/x.timer\"]}\n" \
    EV("timer_file_added") "\"path\":\"etc/systemd/system/x.timer\",\"on_calendar\":[" cal "]" rest

/* Unit files are written by the watched machine: NUL bytes, a very long
 * line, no final newline, CRLF, bytes that are not UTF-8, 100,000 lines,
 * a file that is one endless continuation. */
TEST(hostile_timers_are_read_or_refused_never_trusted) {
    struct t_run r;
    ASSERT_EQ_STR(E10("etc/systemd/system/x.timer"), one(&r, "[Timer]\nOnCalendar=dai\0ly\n", 26));
    tr_free(&r);
    /* 70,000 bytes of value: the timer event breaks its row (E9), the unit file's stands. */
    static char big[80000];
    size_t w = (size_t)snprintf(big, sizeof big, "[Timer]\nOnCalendar=");
    memset(big + w, 'x', 70000);
    w += 70000;
    ASSERT_EQ_STR(
        EV("unit_file_added") "\"path\":\"etc/systemd/system/x.timer\",\"text\":\"unit file etc/systemd/system/x.timer added\","
        "\"paths\":[\"etc/systemd/system/x.timer\"]}\n"
        "{\"event\":\"invalid_finding\",\"interp\":\"systemd\",\"text\":\"invalid finding\",\"paths\":[\"etc/systemd/system/x.timer\"]}\n",
        one(&r, big, w));                                          /* and no final newline */
    tr_free(&r);
    /* CRLF: systemd strips it with the other whitespace, and so the value has none. */
    ASSERT_EQ_STR(XT("\"daily\"", ",\"in_words\":\"at 00:00 every day (by systemd's)\","
                     "\"text\":\"timer etc/systemd/system/x.timer added: daily\",\"paths\":[\"etc/systemd/system/x.timer\"]}\n"),
                  one(&r, "[Timer]\r\nOnCalendar=daily\r\n", 27));
    tr_free(&r);
    /* no final newline */
    ASSERT_EQ_STR(XT("\"hourly\"", ",\"in_words\":\"at minute 0 of every hour (by systemd's)\","
                     "\"text\":\"timer etc/systemd/system/x.timer added: hourly\",\"paths\":[\"etc/systemd/system/x.timer\"]}\n"),
                  one(&r, "[Timer]\nOnCalendar=hourly", 25));
    tr_free(&r);
    /* not UTF-8: no string of an event may carry it (E9) */
    ASSERT_TRUE(strstr(one(&r, "[Timer]\nOnCalendar=\xff\xfe\n", 22), "{\"event\":\"invalid_finding\",\"interp\":\"systemd\"") != NULL);
    tr_free(&r);
    /* lines that are nothing: no `=`, an empty key, a section never closed */
    ASSERT_EQ_STR(XT("", ",\"text\":\"timer etc/systemd/system/x.timer added: \",\"paths\":[\"etc/systemd/system/x.timer\"]}\n"),
                  one(&r, "[Timer\nOnCalendar\n=daily\n[Timer]x\nOnCalendar=daily\n", 51));
    tr_free(&r);
    /* one endless continuation: one line, which is the section header and more -- no value */
    static char cont[300000];
    w = (size_t)snprintf(cont, sizeof cont, "[Timer]\\\n");
    for (int i = 0; i < 50000; i++) w += (size_t)snprintf(cont + w, sizeof cont - w, "a\\\n");
    ASSERT_EQ_STR(XT("", ",\"text\":\"timer etc/systemd/system/x.timer added: \",\"paths\":[\"etc/systemd/system/x.timer\"]}\n"),
                  one(&r, cont, w));
    tr_free(&r);
    /* 100,000 values: more than a list holds (256): the event breaks its row, said. */
    static char many[2000000];
    w = (size_t)snprintf(many, sizeof many, "[Timer]\n");
    for (int i = 0; i < 100000; i++) w += (size_t)snprintf(many + w, sizeof many - w, "OnCalendar=daily\n");
    ASSERT_TRUE(strstr(one(&r, many, w), "{\"event\":\"invalid_finding\",\"interp\":\"systemd\"") != NULL);
    tr_free(&r);
    /* 256 fit a list, but their text is over 1,024 bytes: said too (E9). 100 fit both. */
    w = (size_t)snprintf(many, sizeof many, "[Timer]\n");
    for (int i = 0; i < 256; i++) w += (size_t)snprintf(many + w, sizeof many - w, "OnCalendar=daily\n");
    ASSERT_TRUE(strstr(one(&r, many, w), "{\"event\":\"invalid_finding\",\"interp\":\"systemd\"") != NULL);
    tr_free(&r);
    w = (size_t)snprintf(many, sizeof many, "[Timer]\n");
    for (int i = 0; i < 100; i++) w += (size_t)snprintf(many + w, sizeof many - w, "OnCalendar=daily\n");
    ASSERT_EQ_INT(100, count(one(&r, many, w), "\"daily\""));          /* the list; and the text joins them */
    ASSERT_EQ_INT(99, count(r.out, "daily, "));
    tr_free(&r);
}

int main(void) {
    t_begin("systemd");
    g_events_not_of = "config";     /* the keys of these unit files are test_sys_config's (CF-6) */
    RUN(enable_and_disable_are_a_link_added_and_removed);
    RUN(links_name_their_target_as_written_and_its_owner_where_it_can_be_told);
    RUN(mask_and_unmask_are_a_link_to_dev_null_or_an_empty_file);
    RUN(a_link_in_the_directory_itself_is_an_alias);
    RUN(unit_files_are_named_and_one_over_a_packaged_one_is_said);
    RUN(timer_files_carry_their_on_calendar_values_and_words);
    RUN(a_home_s_units_are_prefixed_by_their_directory);
    RUN(init_scripts_are_named_with_their_owner_and_execute_bit);
    RUN(what_cannot_be_read_is_said_and_what_is_not_systemd_s_is_declined);
    RUN(timer_words_are_given_for_the_forms_of_the_table_only);
    RUN(hostile_timers_are_read_or_refused_never_trusted);
    free(g_text);
    t_end();
    return belay_test_report();
}
