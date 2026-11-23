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

/* K13, WS-R1: a file written between two checkpoints and now as it was is
 * `touched`: an event of the diff, and a line of the receipt's `put back`.
 * Not one that changed, not one only its attributes were touched on, not
 * one nothing wrote to; a file replaced by an equal one is. */
TEST(a_file_written_and_put_back_is_touched) {
    fresh();
    REQUIRE(sys("start") == 0);
    /* conf: written twice, as it was at the end. other: written and different.
     * passwd: an attribute event only. sub: untouched. group: replaced by an equal file.
     * tool: under a root whose files are not read (a `meta` file): never. */
    sh("cd '%s' && printf 'x\\n' > etc/conf && printf 'one\\n' > etc/conf && printf 'changed\\n' > etc/other && "
       "printf 'root:x:0:\\n' > etc/group.new && mv etc/group.new etc/group && printf 'y\\n' > usr/bin/tool && printf 'tool\\n' > usr/bin/tool", g_tree);
    queue("M etc/conf\nMW etc/conf\nM etc/other\nA etc/passwd\n+ etc/group\nM etc/group\nM usr/bin/tool\n");
    REQUIRE_MSG(step() == 0, "%s%s", g_out, g_err);
    ASSERT_EQ_INT(0, belay("diff", "--system-root", g_tree, "--since", "1", "--to", "2", "--json"));
    ASSERT_TRUE(strstr(g_out, "{\"event\":\"touched\",\"interp\":\"core\",\"text\":\"written and now as it was\",\"paths\":[\"etc/conf\"]}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"text\":\"written and now as it was\",\"paths\":[\"etc/group\"]}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"paths\":[\"etc/other\"]") == NULL && strstr(g_out, "\"paths\":[\"etc/passwd\"]") == NULL &&
                strstr(g_out, "\"paths\":[\"usr/bin/tool\"]") == NULL);
    ASSERT_TRUE(strstr(g_out, "\"touched\":") == NULL);                  /* the trailer speaks only when it cannot tell */
    ASSERT_TRUE(strstr(g_out, "\"events\":2,") != NULL);
    REQUIRE_MSG(sys("stop") == 0, "%s%s", g_out, g_err);
    const char *pb = strstr(g_out, "\nput back\n");
    REQUIRE_MSG(pb != NULL, "%s", g_out);
    ASSERT_TRUE(strstr(pb, "\n  etc/conf   written and now as it was\n") != NULL);
    ASSERT_TRUE(strstr(pb, "\n  etc/group   written and now as it was\n") != NULL);
    ASSERT_TRUE(strstr(pb, "etc/other   written") == NULL);
    const char *changes = strstr(g_out, "\nchanges\n");
    ASSERT_TRUE(changes == NULL || pb < changes);                       /* WS-R1's order */
}

/* K13: `touched` is said only where it can be told. A checkpoint without a
 * journal_seq, checkpoints of two recorders, a journal that lost events or
 * a segment: the trailer says `not available` and no event is given. A diff
 * outside a system watch says nothing of it. */
TEST(touched_is_not_available_where_the_journal_cannot_tell) {
    fresh();
    REQUIRE(sys("start") == 0);                                         /* 1 */
    sh("cd '%s' && printf 'x\\n' > etc/conf && printf 'one\\n' > etc/conf", g_tree);
    queue("M etc/conf\noverflow\n");
    REQUIRE(step() == 0);                                               /* 2: the kernel dropped events */
    ASSERT_EQ_INT(0, belay("diff", "--system-root", g_tree, "--since", "1", "--to", "2", "--json"));
    ASSERT_TRUE(strstr(g_out, "\"runtime\":0,\"touched\":\"not available\"}\n") != NULL || strstr(g_out, ",\"touched\":\"not available\"}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"event\":\"touched\"") == NULL);
    queue("M etc/conf\n");
    REQUIRE(step() == 0);                                               /* 3 */
    ASSERT_EQ_INT(0, belay("diff", "--system-root", g_tree, "--since", "2", "--to", "3", "--json"));
    ASSERT_TRUE(strstr(g_out, "\"paths\":[\"etc/conf\"]") != NULL && strstr(g_out, "\"touched\":") == NULL);
    krec_stop(watch_state());                                           /* another recorder from here */
    queue("M etc/conf\n");
    REQUIRE(step() == 0);                                               /* 4 */
    ASSERT_EQ_INT(0, belay("diff", "--system-root", g_tree, "--since", "3", "--to", "4", "--json"));
    ASSERT_TRUE(strstr(g_out, ",\"touched\":\"not available\"}\n") != NULL && strstr(g_out, "\"event\":\"touched\"") == NULL);
    queue("M etc/conf\n");
    REQUIRE(step() == 0);                                               /* 5 */
    queue("M etc/conf\n");
    REQUIRE(step() == 0);                                               /* 6 */
    ASSERT_EQ_INT(0, belay("diff", "--system-root", g_tree, "--since", "4", "--to", "6", "--json"));
    REQUIRE_MSG(strstr(g_out, "\"paths\":[\"etc/conf\"]") != NULL, "%s", g_out);
    /* the segment between 4 and 5 gone */
    ASSERT_TRUE(holds("f=$(ls \"$w\" | grep '^journal\\.' | sort -t. -k2 -n | tail -3 | head -1) && rm \"$w/$f\""));
    ASSERT_EQ_INT(0, belay("diff", "--system-root", g_tree, "--since", "4", "--to", "6", "--json"));
    ASSERT_TRUE(strstr(g_out, ",\"touched\":\"not available\"}\n") != NULL && strstr(g_out, "\"event\":\"touched\"") == NULL);
    REQUIRE(sys("stop") == 0);
    ASSERT_TRUE(strstr(g_out, "\nput back\n") == NULL);
    /* a scope that is no system watch's: the key is not there */
    char plain[500];
    snprintf(plain, sizeof plain, "%s/plain", g_dir);
    sh("rm -rf '%s' && mkdir -p '%s' && printf 'a\\n' > '%s/f'", plain, plain, plain);
    ASSERT_EQ_INT(0, belay("check", "--scope", plain));
    ASSERT_EQ_INT(0, belay("mark", "--scope", plain));
    ASSERT_EQ_INT(0, belay("diff", "--scope", plain, "--since", "1", "--to", "2", "--json"));
    ASSERT_TRUE(strstr(g_out, "\"touched\"") == NULL && strstr(g_out, "\"belay_diff_end\"") != NULL);
}

/* K5: prune removes the segments older than the oldest checkpoint left, and
 * `touched` between the checkpoints that stay is still told. */
TEST(prune_removes_the_segments_before_the_oldest_checkpoint) {
    fresh();
    REQUIRE(sys("start") == 0);
    for (int i = 0; i < 4; i++) {
        sh("cd '%s' && printf 'x\\n' > etc/conf && printf 'one\\n' > etc/conf && printf '%d\\n' > etc/other", g_tree, i);
        queue("M etc/conf\nM etc/other\n");
        REQUIRE(step() == 0);
    }
    ASSERT_TRUE(holds("[ -f \"$w/journal.1\" ] && [ \"$(ls \"$w\" | grep -c '^journal\\.')\" = 6 ]"));
    ASSERT_EQ_INT(0, belay("prune", "--system-root", g_tree, "--keep-last", "2"));
    ASSERT_TRUE(holds("[ ! -f \"$w/journal.1\" ] && [ \"$(ls \"$w\" | grep -c '^journal\\.')\" = 2 ]"));
    ASSERT_EQ_INT(0, belay("diff", "--system-root", g_tree, "--since", "4", "--to", "5", "--json"));
    ASSERT_TRUE(strstr(g_out, "\"paths\":[\"etc/conf\"]") != NULL && strstr(g_out, "\"touched\":") == NULL);
    REQUIRE(step() == 0);                               /* and the recorder goes on in its own segment */
    REQUIRE(sys("stop") == 0);
}

/* K1, K2, K5, K6, K7, K13 with the kernel's own events: the fanotify reader.
 * Needs root and a filesystem of its own to mark (BELAY_TEST_ROOT, ext4:
 * the tree and belay's state are both put on it, so the group marks that
 * filesystem and no other). Run by the `filesystems` CI job. */
TEST(the_fanotify_reader_journals_what_the_kernel_sends) {
#ifndef __linux__
    SKIP("fanotify is Linux's");
#else
    if (geteuid() != 0 || getenv("BELAY_TEST_ROOT") == NULL) SKIP("needs root and an ext4 filesystem of its own (BELAY_TEST_ROOT)");
    fresh();
    unsetenv("BELAY_TEST_KREC");
    REQUIRE_MSG(sys("start") == 0, "%s%s", g_out, g_err);
    REQUIRE_MSG(strstr(g_out, "\nkernel record: on since 20") != NULL, "%s", g_out);
    ASSERT_TRUE(krec_alive(watch_state(), NULL));
    ASSERT_EQ_INT(0, belay("log", "--system-root", g_tree, "--json"));
    ASSERT_TRUE(strstr(g_out, "\"journal_seq\":null") == NULL);         /* K7: the kernel's event for the barrier came */
    sh("cd '%s' && printf 'x\\n' > etc/conf && printf 'one\\n' > etc/conf && printf 'changed\\n' > etc/other && "
       "chmod 600 etc/passwd && printf 'n\\n' > etc/new && mv etc/new etc/sub/moved && rm etc/group", g_tree);
    REQUIRE_MSG(step() == 0, "%s%s", g_out, g_err);
    ASSERT_FALSE(walked_because("the recorder did not answer"));
    /* K5: a write carries the object's inode; a create and a rename their directory and names */
    ASSERT_TRUE(holds("ino=$(ls -di '%s/etc/conf' | awk '{print $1}') && cat \"$w\"/journal.* | grep \"\\\"ino\\\":$ino,\" | grep -q '\"mask\":[0-9]*[02468],' && "
                      "cat \"$w\"/journal.* | grep -q '\"name\":\"new\"' && cat \"$w\"/journal.* | grep -q '\"to_name\":\"moved\"}' && "
                      "cat \"$w\"/journal.* | grep -q '\"name\":\"group\"'", g_tree));
    ASSERT_TRUE(holds("! cat \"$w\"/journal.* | grep -q '\"name\":\"journal\\.'"));     /* K5: the ignore mark */
    ASSERT_EQ_INT(0, belay("diff", "--system-root", g_tree, "--since", "1", "--to", "2", "--json"));
    ASSERT_TRUE(strstr(g_out, "\"text\":\"written and now as it was\",\"paths\":[\"etc/conf\"]}\n") != NULL);
    ASSERT_TRUE(strstr(g_out, "\"paths\":[\"etc/other\"]") == NULL && strstr(g_out, "\"paths\":[\"etc/passwd\"]") == NULL);
    ASSERT_TRUE(strstr(g_out, "\"touched\":") == NULL);
    REQUIRE_MSG(sys("stop") == 0, "%s%s", g_out, g_err);
    ASSERT_TRUE(strstr(g_out, "\n  etc/conf   written and now as it was\n") != NULL);
    ASSERT_FALSE(krec_alive(watch_state(), NULL));
    setenv("BELAY_TEST_KREC", g_queue, 1);
#endif
}

/* K4: not root and no queue: the record is off and says why; everything else runs. */
TEST(not_root_the_record_is_off) {
    if (geteuid() == 0) SKIP("run as root: fanotify_init is not refused");
    fresh();
    unsetenv("BELAY_TEST_KREC");
    REQUIRE_MSG(sys("start") == 0, "%s%s", g_out, g_err);
    setenv("BELAY_TEST_KREC", g_queue, 1);
    ASSERT_TRUE(strstr(g_out, "\nkernel record: off: not root: a change put back is not seen\n") != NULL);
    ASSERT_FALSE(krec_alive(watch_state(), NULL));
    ASSERT_TRUE(holds("! ls \"$w\" | grep -q '^journal\\.'"));
    unsetenv("BELAY_TEST_KREC");
    REQUIRE(step() == 0);
    ASSERT_TRUE(walked_because("not root"));
    REQUIRE(sys("stop") == 0);
    setenv("BELAY_TEST_KREC", g_queue, 1);
    ASSERT_TRUE(strstr(g_out, "\nput back\n") == NULL);
}

int main(void) {
    const char *base = getenv("BELAY_TEST_ROOT");       /* a filesystem of the test's own, for the root test */
    snprintf(g_dir, sizeof g_dir, "%s/belay_krec_%d_%ld", base != NULL ? base : "/tmp", (int)getpid(), (long)time(NULL));
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
    RUN(a_file_written_and_put_back_is_touched);
    RUN(touched_is_not_available_where_the_journal_cannot_tell);
    RUN(prune_removes_the_segments_before_the_oldest_checkpoint);
    RUN(not_root_the_record_is_off);
    RUN(the_fanotify_reader_journals_what_the_kernel_sends);
    end_recorder();
    sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    free(g_out);
    free(g_err);
    return belay_test_report();
}
