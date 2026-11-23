/*
 *  The kernel record (test/expect/kernel-record.md): the recorder, its
 *  journal, the barrier, why a capture is a walk, the receipt's `kernel
 *  record` line, and `touched`.
 *
 *  Everything after the read of an event is tested here without privilege:
 *  BELAY_TEST_KREC names a file the recorder reads as its queue of events
 *  instead of a fanotify group (src/watch/recorder.c says the lines). The
 *  recorder is a real process, started and ended by `watch start` and
 *  `watch stop`; it is never signalled: it ends by its own stop file. The
 *  fanotify reader itself needs root and is tested by the last tests here,
 *  which skip otherwise.
 *
 *  BLAST RADIUS: as test_watch_system.c. Every command is given
 *  `--system-root DIR`, a tree under this test's temporary directory, and
 *  belay's state is under it too. Nothing of the machine is captured,
 *  marked or changed.
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/error.h"
#include "cli/cli.h"
#include "cli/state.h"
#include "watch/krec.h"
#include "watch/run.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char g_dir[256], g_tree[400], g_state[400], g_queue[400];
static char *g_out, *g_err;

static int belayv(const char *const *args) {
    char *argv[40] = { "belay" };
    int argc = 1;
    while (argc < 39 && args[argc - 1] != NULL) { argv[argc] = (char *)args[argc - 1]; argc++; }
    free(g_out);
    free(g_err);
    g_out = g_err = NULL;
    size_t on, en;
    FILE *out = open_memstream(&g_out, &on), *err = open_memstream(&g_err, &en);
    const int rc = cli_main(argc, argv, out, err);
    fclose(out);
    fclose(err);
    return rc;
}
#define belay(...) belayv((const char *const[]){ __VA_ARGS__, NULL })

static void sh(const char *fmt, ...) {
    char cmd[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    if (system(cmd) != 0) { /* the assertions say */ }
}

/* A shell test with $w the watch's directory in the state. */
static bool holds(const char *fmt, ...) {
    char body[4096], cmd[5000];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof body, fmt, ap);
    va_end(ap);
    snprintf(cmd, sizeof cmd, "w=$(ls -d '%s'/scopes/*/watch) && %s", g_state, body);
    return system(cmd) == 0;
}

/* The watch's directory, as a state the recorder's functions take. */
static struct state *watch_state(void) {
    static struct state st;
    char cmd[600], path[PATH_MAX] = "";
    snprintf(cmd, sizeof cmd, "ls -d '%s'/scopes/* 2>/dev/null", g_state);
    FILE *p = popen(cmd, "r");
    if (p != NULL) {
        if (fgets(path, sizeof path, p) == NULL) path[0] = '\0';
        pclose(p);
    }
    path[strcspn(path, "\n")] = '\0';
    if (st.dir_fd > 0) close(st.dir_fd);
    memset(&st, 0, sizeof st);
    snprintf(st.dir, sizeof st.dir, "%s", path);
    st.dir_fd = open(path, O_RDONLY | O_DIRECTORY);
    return &st;
}

/* The recorder a test left is ended, by its own stop file, before the tree goes. */
static void end_recorder(void) {
    struct state *st = watch_state();
    if (st->dir_fd != -1) krec_stop(st);
}

static void fresh(void) {
    end_recorder();
    sh("chmod -R u+rwx '%s' '%s' 2>/dev/null; rm -rf '%s' '%s' '%s' '%s.mountinfo'; mkdir -p '%s' '%s' && chmod 700 '%s' && chmod 755 '%s'",
       g_tree, g_state, g_tree, g_state, g_queue, g_queue, g_tree, g_state, g_state, g_tree);
    sh("cd '%s' && mkdir -p etc/sub usr/bin var/lib/dpkg/info root home/u proc && "
       "printf 'root:x:0:0:root:/root:/bin/sh\\nu:x:1000:1000::/home/u:/bin/sh\\n' > etc/passwd && "
       "printf 'root:x:0:\\n' > etc/group && printf 'one\\n' > etc/conf && printf 'two\\n' > etc/other && "
       "printf 'tool\\n' > usr/bin/tool && chmod 700 root && chmod 755 . etc usr var home home/u && : > '%s'",
       g_tree, g_queue);
    setenv("BELAY_TEST_KREC", g_queue, 1);
    watch_barrier_wait_ms = 5000;
    struct timespec ts = { 0, 30 * 1000000L };
    nanosleep(&ts, NULL);
}

static void queue(const char *lines) {
    FILE *f = fopen(g_queue, "a");
    if (f == NULL) return;
    fputs(lines, f);
    fclose(f);
}

static int sys(const char *cmd) { return belay("watch", cmd, "--system-root", g_tree); }
static int step(void) { return belay("watch", "step", "--system-root", g_tree, "--session", "s1"); }

/* The reason the last walk of the record gave (WS-3a's `walking (<reason>)`). */
static bool walked_because(const char *reason) {
    return holds("grep -h '\"t\":\"walk\"' \"$w\"/ledger-* | tail -1 | grep -q '\"walk\":\\[[0-9]*,\"%s\"\\]'", reason);
}

/* K1, WS-2, WS-R3: `watch start` starts one recorder, the receipt's line says
 * the record is on and whole, `watch stop` ends it; a new watch has a new
 * journal and another recorder. */
TEST(the_recorder_starts_with_the_watch_and_ends_with_it) {
    fresh();
    REQUIRE_MSG(sys("start") == 0, "%s%s", g_out, g_err);
    const char *line = strstr(g_out, "\nkernel record: on since 20");
    REQUIRE_MSG(line != NULL, "%s", g_out);
    ASSERT_TRUE(strstr(line, "Z, whole\n") != NULL && strstr(line, "Z, whole\n") < line + 60);
    ASSERT_TRUE(strstr(g_out, "no kernel record") == NULL);
    char id[17], again[17];
    ASSERT_TRUE(krec_alive(watch_state(), id));
    ASSERT_EQ_INT(16, (int)strlen(id));
    ASSERT_TRUE(holds("head -1 \"$w/journal.1\" | grep -q '^{\"seq\":1,\"time_ns\":[0-9]*,\"record\":\"start\",\"recorder\":\"%s\"'", id));
    REQUIRE_MSG(sys("stop") == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(strstr(g_out, "\nkernel record: on since 20") != NULL);
    ASSERT_FALSE(krec_alive(watch_state(), NULL));
    ASSERT_TRUE(holds("[ ! -e \"$w/recorder\" ] && [ ! -e \"$w/recorder.stop\" ]"));
    REQUIRE_MSG(sys("start") == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(krec_alive(watch_state(), again));
    ASSERT_TRUE(strcmp(id, again) != 0);
    ASSERT_TRUE(holds("head -1 \"$w/journal.1\" | grep -q '\"recorder\":\"%s\"'", again));
    REQUIRE(sys("stop") == 0);
}

/* K5, K7, checkpoint-v3 C3-6a: a capture creates and removes a barrier file
 * and waits for the recorder to journal it; the checkpoint records its seq;
 * a new segment begins after it; the events queued before it lie before it,
 * each a line with the object's dev and ino, its directory's and its name. */
TEST(a_capture_takes_its_barrier_in_the_journal) {
    fresh();
    REQUIRE(sys("start") == 0);
    ASSERT_EQ_INT(0, belay("log", "--system-root", g_tree, "--json"));
    ASSERT_TRUE(strstr(g_out, "\"journal_seq\":2,") != NULL);
    ASSERT_TRUE(holds("sed -n 2p \"$w/journal.1\" | grep -q '^{\"seq\":2,\"time_ns\":[0-9]*,\"record\":\"barrier\",\"name\":\"barrier\\.[0-9a-f]\\{16\\}\"}$' && "
                      "[ \"$(wc -l < \"$w/journal.1\" | tr -d ' ')\" = 2 ] && [ -f \"$w/journal.3\" ] && ! ls \"$w\" | grep -q '^barrier'"));
    sh("cd '%s' && printf 'new\\n' > etc/new && printf 'three\\n' > etc/conf", g_tree);
    queue("+ etc/new\nMW etc/new\nM etc/conf\n- etc/gone\n");
    REQUIRE_MSG(step() == 0, "%s%s", g_out, g_err);
    ASSERT_EQ_INT(0, belay("log", "--system-root", g_tree, "--json"));
    ASSERT_TRUE(strstr(g_out, "\"journal_seq\":7,") != NULL);
    ASSERT_TRUE(holds("ino=$(ls -di '%s/etc/new' | awk '{print $1}') && dino=$(ls -di '%s/etc' | awk '{print $1}') && "
                      "sed -n 1p \"$w/journal.3\" | grep -q \"^{\\\"seq\\\":3,\\\"time_ns\\\":[0-9]*,\\\"mask\\\":256,\\\"dev\\\":[0-9]*,\\\"ino\\\":$ino,"
                      "\\\"dir_dev\\\":[0-9]*,\\\"dir_ino\\\":$dino,\\\"name\\\":\\\"new\\\"}$\" && "
                      "sed -n 2p \"$w/journal.3\" | grep -q \"\\\"mask\\\":10,\\\"dev\\\":[0-9]*,\\\"ino\\\":$ino,\" && "
                      "sed -n 4p \"$w/journal.3\" | grep -q \"\\\"mask\\\":512,\\\"dev\\\":0,\\\"ino\\\":null,\\\"dir_dev\\\":[0-9]*,\\\"dir_ino\\\":$dino,\\\"name\\\":\\\"gone\\\"}$\" && "
                      "sed -n 5p \"$w/journal.3\" | grep -q '^{\"seq\":7,.*\"record\":\"barrier\"' && [ -f \"$w/journal.8\" ]",
                      g_tree, g_tree));
    REQUIRE(sys("stop") == 0);
}

/* K5: a name that is not UTF-8 is base64; a rename has both names. */
TEST(a_journal_line_carries_names_as_they_are) {
    fresh();
    REQUIRE(sys("start") == 0);
    sh("cd '%s' && mv etc/other etc/sub/moved && : > \"$(printf 'etc/b\\377d')\"", g_tree);
    queue("R etc/other\tetc/sub/moved\n+ etc/b\377d\n");
    REQUIRE_MSG(step() == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(holds("ino=$(ls -di '%s/etc/sub/moved' | awk '{print $1}') && to=$(ls -di '%s/etc/sub' | awk '{print $1}') && "
                      "sed -n 1p \"$w/journal.3\" | grep -q \"\\\"mask\\\":268435456,\\\"dev\\\":[0-9]*,\\\"ino\\\":$ino,.*\\\"name\\\":\\\"other\\\","
                      "\\\"to_dir_dev\\\":[0-9]*,\\\"to_dir_ino\\\":$to,\\\"to_name\\\":\\\"moved\\\"}$\" && "
                      "sed -n 2p \"$w/journal.3\" | grep -q '\"name_b64\":\"Yv9k\"}$'", g_tree, g_tree));
    REQUIRE(sys("stop") == 0);
}

/* K7, K10, K12, K17: why a capture is a walk, each said (WS-3a's reason). */
TEST(a_walk_says_why_it_is_one) {
    fresh();
    REQUIRE(sys("start") == 0);
    ASSERT_TRUE(walked_because("the first capture of the watch"));             /* K17 */
    queue("overflow\n");
    REQUIRE(step() == 0);
    ASSERT_TRUE(walked_because("the kernel dropped events"));                  /* K10 */
    queue("M etc/conf\nmounts_changed\n");
    REQUIRE(step() == 0);
    ASSERT_TRUE(walked_because("the mounts changed"));
    queue("U M\n");
    REQUIRE(step() == 0);
    ASSERT_TRUE(walked_because("an event did not resolve"));
    queue("X - etc/gone\nM etc/conf\n");                /* its directory resolved: that is enough (K10) */
    REQUIRE(step() == 0);
    ASSERT_FALSE(walked_because("an event did not resolve"));
    ASSERT_FALSE(walked_because("the kernel dropped events"));  /* an overflow two captures ago is not this one's */
    queue("overflow\n");                                /* K12: whatever the journal says */
    REQUIRE(sys("receipt") == 0);
    ASSERT_TRUE(walked_because("the end state rests on a walk"));
    ASSERT_TRUE(strstr(g_out, "\nend state: by a walk at ") != NULL);
    REQUIRE(sys("stop") == 0);
    ASSERT_TRUE(walked_because("the end state rests on a walk"));
}

/* K7: no barrier in time, and the capture is a walk that says so, with no
 * journal_seq. Here the queue is taken from the capture, so the create of
 * its barrier never reaches the recorder. */
TEST(a_recorder_that_does_not_answer_makes_a_walk) {
    fresh();
    REQUIRE(sys("start") == 0);
    unsetenv("BELAY_TEST_KREC");
    watch_barrier_wait_ms = 150;
    REQUIRE_MSG(step() == 0, "%s%s", g_out, g_err);
    setenv("BELAY_TEST_KREC", g_queue, 1);
    watch_barrier_wait_ms = 5000;
    ASSERT_TRUE(walked_because("the recorder did not answer"));
    ASSERT_EQ_INT(0, belay("log", "--system-root", g_tree, "--json"));
    const char *second = strstr(g_out, "\n{\"id\":2,");
    REQUIRE(second != NULL);
    ASSERT_TRUE(strstr(second, "\"journal_seq\":null,") != NULL);
    REQUIRE(step() == 0);                               /* and the one after has none to start from */
    ASSERT_TRUE(walked_because("the previous capture had no barrier"));
    REQUIRE(sys("stop") == 0);
}

/* K17, WS-R3: a recorder that is gone is started again at the next capture,
 * which is a walk; the receipt's line gives the gap. */
TEST(a_recorder_that_went_is_a_gap) {
    fresh();
    REQUIRE(sys("start") == 0);
    char id[17], again[17];
    REQUIRE(krec_alive(watch_state(), id));
    krec_stop(watch_state());                           /* its own stop file: no signal */
    REQUIRE(!krec_alive(watch_state(), NULL));
    REQUIRE_MSG(step() == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(walked_because("the recorder was restarted"));
    ASSERT_TRUE(krec_alive(watch_state(), again) && strcmp(id, again) != 0);
    REQUIRE(step() == 0);                               /* the next is an ordinary one again */
    ASSERT_FALSE(walked_because("the recorder was restarted"));
    REQUIRE(sys("stop") == 0);
    const char *line = strstr(g_out, "\nkernel record: on since 20");
    REQUIRE_MSG(line != NULL, "%s", g_out);
    const char *gap = strstr(line, "Z, with a gap from 20");
    ASSERT_TRUE(gap != NULL && gap < line + 60 && strstr(gap, "Z (the recorder was not running)\n") != NULL &&
                strstr(gap, " to 20") != NULL);
    ASSERT_TRUE(strstr(line, ", whole") == NULL || strstr(line, ", whole") > strchr(line + 1, '\n'));
}

/* K2a, K3, K4, K15, WS-R3: the filesystems under the roots. One that is
 * entered and not ext4 is walked every time and named; with no ext4 among
 * them the record is off, and says so; a filesystem that gives no event
 * for an inode flag is said. The mount table is the test's, beside its
 * queue, its mount points relative to the tree. */
TEST(the_line_names_what_is_walked_every_time_and_what_is_off) {
    fresh();
    sh("printf '%%s\\n' '1 0 8:1 / / rw - ext4 /dev/a rw' '2 1 8:2 / /etc rw - btrfs /dev/b rw' '3 1 0:5 / /proc rw - proc proc rw' "
       "'4 1 0:6 / /usr/bin rw - nfs4 host:/x rw' '5 1 8:9 / /nowhere/else rw - xfs /dev/c rw' '6 2 8:10 / /etc/sub rw - vfat /dev/d rw' > '%s.mountinfo'", g_queue);
    REQUIRE_MSG(sys("start") == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(strstr(g_out, "Z, whole; walked every time: etc (btrfs); walked every time: etc/sub (vfat)\n") != NULL);
    REQUIRE(sys("stop") == 0);
    fresh();
    sh("printf '%%s\\n' '1 0 8:1 / / rw - btrfs /dev/a rw' > '%s.mountinfo'", g_queue);
    REQUIRE_MSG(sys("start") == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(strstr(g_out, "\nkernel record: off: no ext4 filesystem under the roots: a change put back is not seen\n") != NULL);
    ASSERT_FALSE(krec_alive(watch_state(), NULL));
    REQUIRE(step() == 0);
    ASSERT_TRUE(walked_because("no kernel record"));
    REQUIRE(sys("stop") == 0);
    fresh();
    queue("iflags false\n");
    REQUIRE_MSG(sys("start") == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(strstr(g_out, "Z, whole; inode flags as of the last walk\n") != NULL);
    REQUIRE(sys("stop") == 0);
}

/* K5: the journal is read as hostile input. A line is the recorder's or it
 * is nothing; an interval with a line that is not, a seq missing or out of
 * order, or a segment gone, is not handed on as if it were whole. */
static int count_event(void *ctx, const struct kev *e) {
    (void)e;
    ++*(int *)ctx;
    return 0;
}

TEST(a_journal_that_is_not_the_recorder_s_is_not_read_as_one) {
    static struct kev e;
#define LINE(s) krec_parse(s, strlen(s), &e)
    ASSERT_EQ_INT(0, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":9}"));
    ASSERT_TRUE(e.kind == KEV_EVENT && e.seq == 3 && e.mask == KR_MODIFY && e.has_ino && e.dev == 7 && e.ino == 9 && !e.named);
    ASSERT_EQ_INT(0, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":512,\"dev\":0,\"ino\":null,\"dir_dev\":7,\"dir_ino\":2,\"name\":\"a\"}"));
    ASSERT_TRUE(!e.has_ino && e.named && e.has_dir && e.dir_ino == 2 && e.name_len == 1);
    ASSERT_EQ_INT(0, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":256,\"dev\":7,\"ino\":9,\"dir_dev\":7,\"dir_ino\":2,\"name_b64\":\"Yv9k\"}"));
    ASSERT_TRUE(e.name_len == 3 && memcmp(e.name, "b\377d", 3) == 0);
    ASSERT_EQ_INT(-1, LINE(""));
    ASSERT_EQ_INT(-1, LINE("[]"));
    ASSERT_EQ_INT(-1, LINE("{\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":9}"));                          /* no seq */
    ASSERT_EQ_INT(-1, LINE("{\"seq\":0,\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":9}"));
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":-9}"));
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":1.5}"));
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":2,\"dev\":7}"));                           /* no ino */
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":99999999999,\"dev\":7,\"ino\":9}"));
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":9,\"dir_dev\":7,\"dir_ino\":2}"));   /* no name */
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":9,\"dir_dev\":7,\"dir_ino\":2,\"name\":\"a/b\"}"));
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":9,\"dir_dev\":7,\"dir_ino\":2,\"name\":\"\"}"));
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":9,\"dir_dev\":7,\"dir_ino\":2,\"name_b64\":\"!!\"}"));
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":9,\"dir_dev\":7,\"dir_ino\":2,\"name\":\"a\",\"name_b64\":\"YQ==\"}"));
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"record\":\"start\",\"recorder\":\"zz\",\"iflags_events\":true}"));
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"record\":\"other\"}"));
    ASSERT_EQ_INT(-1, LINE("{\"seq\":3,\"time_ns\":5,\"mask\":268435456,\"dev\":7,\"ino\":9,\"to_dir_dev\":7,\"to_dir_ino\":2,\"to_name\":\"a\"}"));
    {
        char longname[700], line[900];
        memset(longname, 'a', 256);
        longname[256] = '\0';
        snprintf(line, sizeof line, "{\"seq\":3,\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":9,\"dir_dev\":7,\"dir_ino\":2,\"name\":\"%s\"}", longname);
        ASSERT_EQ_INT(-1, LINE(line));
        longname[255] = '\0';
        snprintf(line, sizeof line, "{\"seq\":3,\"time_ns\":5,\"mask\":2,\"dev\":7,\"ino\":9,\"dir_dev\":7,\"dir_ino\":2,\"name\":\"%s\"}", longname);
        ASSERT_EQ_INT(0, LINE(line));
    }
#undef LINE
    fresh();
    REQUIRE(sys("start") == 0);
    queue("M etc/conf\nM etc/other\n");
    REQUIRE(step() == 0);                               /* 1 start, 2 barrier | 3, 4 events, 5 barrier | ... */
    REQUIRE(sys("stop") == 0);
    struct state *st = watch_state();
    int n = 0;
    ASSERT_EQ_INT(0, krec_scan(st, 2, 5, count_event, &n));
    ASSERT_EQ_INT(3, n);
    ASSERT_EQ_INT(0, krec_scan(st, 0, 4, count_event, &n));
    ASSERT_EQ_INT(7, n);
    ASSERT_EQ_INT(1, krec_scan(st, 2, 400, count_event, &n));                   /* past its end */
    ASSERT_TRUE(holds("cp \"$w/journal.3\" \"$w/keep\" && sed -i.bak '2s/\"seq\":4/\"seq\":5/' \"$w/journal.3\" && rm \"$w/journal.3.bak\""));
    ASSERT_EQ_INT(1, krec_scan(st, 2, 5, NULL, NULL));                          /* a seq twice, one missing */
    ASSERT_TRUE(holds("{ sed -n 1p \"$w/keep\"; printf 'not a line\\n'; sed -n 3p \"$w/keep\"; } > \"$w/journal.3\""));
    ASSERT_EQ_INT(1, krec_scan(st, 2, 5, NULL, NULL));
    ASSERT_TRUE(holds("{ sed -n 1p \"$w/keep\"; head -c 20000 /dev/zero | tr '\\0' 'x'; printf '\\n'; sed -n 3p \"$w/keep\"; } > \"$w/journal.3\""));
    ASSERT_EQ_INT(1, krec_scan(st, 2, 5, NULL, NULL));                          /* a line longer than any */
    ASSERT_TRUE(holds("rm \"$w/journal.3\""));
    ASSERT_EQ_INT(1, krec_scan(st, 2, 5, NULL, NULL));                          /* a segment gone */
    ASSERT_EQ_INT(0, krec_scan(st, 0, 2, NULL, NULL));                          /* what is whole still reads */
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_krec_%d_%ld", (int)getpid(), (long)time(NULL));
    snprintf(g_tree, sizeof g_tree, "%s/tree", g_dir);
    snprintf(g_state, sizeof g_state, "%s/state", g_dir);
    snprintf(g_queue, sizeof g_queue, "%s/queue", g_dir);
    umask(022);
    mkdir(g_dir, 0700);
    setenv("BELAY_STATE_DIR", g_state, 1);
    RUN(the_recorder_starts_with_the_watch_and_ends_with_it);
    RUN(a_capture_takes_its_barrier_in_the_journal);
    RUN(a_journal_line_carries_names_as_they_are);
    RUN(a_walk_says_why_it_is_one);
    RUN(a_recorder_that_does_not_answer_makes_a_walk);
    RUN(a_recorder_that_went_is_a_gap);
    RUN(the_line_names_what_is_walked_every_time_and_what_is_off);
    RUN(a_journal_that_is_not_the_recorder_s_is_not_read_as_one);
    end_recorder();
    sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    free(g_out);
    free(g_err);
    return belay_test_report();
}
