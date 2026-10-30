/*
 *  The diff core (docs/spec/diff-v1.md), one test per rule of "How an
 *  outcome is decided", through the public belay_diff. Manifests are built
 *  by hand -- valid ones, which the reader accepts -- so each case is exactly
 *  the state it names. The broad check is the differential oracle
 *  (scripts/oracle/); these pin each rule down by name.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "belay/diff.h"
#include "belay/error.h"
#include "diff/classify.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define H64(c) c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c \
               c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c
#define HA H64("a")
#define HB H64("b")

/* ---- a manifest builder: valid lines in canonical field order ---- */

struct me {
    const char *path, *type;
    unsigned long long size, ino;
    long long mtime, ctime;
    unsigned mode;                       /* permission bits; type bits added */
    const char *sha;                     /* reg: NULL means unverified */
    const char *target;                  /* lnk */
    bool unstable, unreadable, mount, raced, xattrs_unknown;
    unsigned long long dev;              /* 0: 1 */
    bool has_iflags;
    unsigned long long iflags;
    const char *caps, *xattrs;           /* caps hex; xattrs array body */
    unsigned long long rdev;             /* blk, chr: 0 means 3 */
};

static char g_dir[256];
static char g_out[300];
static FILE *g_f;
static size_t g_n, g_unreadable, g_unstable, g_mounts, g_raced;

static void m_begin(const char *name, const char *scope, unsigned long long hash_max) {
    char p[400];
    snprintf(p, sizeof p, "%s/%s", g_dir, name);
    g_f = fopen(p, "wb");
    fprintf(g_f, "{\"belay_manifest\":1,\"created_ns\":1,\"scopes\":[\"%s\"],\"hash\":\"sha256\","
                 "\"hash_max_bytes\":%llu,\"store_max_bytes\":0}\n", scope, hash_max);
    g_n = g_unreadable = g_unstable = g_mounts = g_raced = 0;
}

static void m_entry(struct me e) {
    const bool reg = strcmp(e.type, "reg") == 0, dir = strcmp(e.type, "dir") == 0;
    const bool lnk = strcmp(e.type, "lnk") == 0;
    const bool chr = strcmp(e.type, "chr") == 0, blk = strcmp(e.type, "blk") == 0;
    const bool sock = strcmp(e.type, "sock") == 0;
    const unsigned tbits = reg ? 0100000 : dir ? 0040000 : lnk ? 0120000 : chr ? 0020000
                         : blk ? 0060000 : sock ? 0140000 : 0010000;
    if (lnk && e.target != NULL && !e.unreadable) e.size = strlen(e.target);
    fprintf(g_f, "{\"path\":\"%s\",\"type\":\"%s\",\"mode\":%u,\"uid\":1,\"gid\":1,\"size\":%llu,"
                 "\"mtime_ns\":%lld,\"ctime_ns\":%lld,\"ino\":%llu,\"dev\":%llu,\"nlink\":1",
            e.path, e.type, tbits | (e.mode ? e.mode : 0644), e.size, e.mtime ? e.mtime : 1,
            e.ctime ? e.ctime : 1, e.ino ? e.ino : 7, e.dev ? e.dev : 1);
    if (e.has_iflags) fprintf(g_f, ",\"iflags\":%llu", e.iflags);
    if (e.caps) fprintf(g_f, ",\"caps\":\"%s\"", e.caps);
    if (e.xattrs) fprintf(g_f, ",\"xattrs\":[%s]", e.xattrs);
    if (e.xattrs_unknown) fprintf(g_f, ",\"xattrs_unknown\":true");
    if (reg) fprintf(g_f, e.sha ? ",\"sha256\":\"%s\"" : ",\"unverified\":true", e.sha);
    if (e.unstable) fprintf(g_f, ",\"unstable\":true");
    if (chr || blk) fprintf(g_f, ",\"rdev\":%llu", e.rdev ? e.rdev : 3);
    if (lnk) fprintf(g_f, ",\"link_target\":\"%s\"", e.target ? e.target : "");
    if (e.mount) fprintf(g_f, ",\"mount\":true");
    if (e.unreadable) fprintf(g_f, ",\"unreadable\":true");
    if (e.raced) fprintf(g_f, ",\"raced\":true");
    fprintf(g_f, "}\n");
    g_n++;
    g_unreadable += e.unreadable;
    g_unstable += e.unstable;
    g_mounts += e.mount;
    g_raced += e.raced;
}

static void m_end(void) {
    fprintf(g_f, "{\"belay_manifest_end\":%zu,\"vanished\":0,\"unreadable\":%zu,\"unstable\":%zu,"
                 "\"mounts\":%zu,\"raced\":%zu}\n", g_n, g_unreadable, g_unstable, g_mounts,
            g_raced);
    fclose(g_f);
}

#define ROOT(...) m_entry((struct me){ .path = ".", .type = "dir", __VA_ARGS__ })
#define E(...)    m_entry((struct me){ __VA_ARGS__ })

/* ---- running a diff, reading its lines ---- */

static struct belay_diff_stats g_st;
static char g_text[1 << 16];

static int run(void) {
    char b[400], a[400];
    snprintf(b, sizeof b, "%s/before", g_dir);
    snprintf(a, sizeof a, "%s/after", g_dir);
    memset(&g_st, 0, sizeof g_st);
    g_text[0] = '\0';
    const int rc = belay_diff(b, a, g_out, &g_st);
    if (rc != 0) return rc;
    FILE *f = fopen(g_out, "rb");
    const size_t n = fread(g_text, 1, sizeof g_text - 1, f);
    g_text[n] = '\0';
    fclose(f);
    return 0;
}

/* The record line for `path`, or NULL. */
static const char *record(const char *path) {
    static char line[4096];
    char key[512];
    snprintf(key, sizeof key, "{\"path\":\"%s\",", path);
    const char *s = strstr(g_text, key);
    if (s == NULL) return NULL;
    const char *e = strchr(s, '\n');
    snprintf(line, sizeof line, "%.*s", (int)(e - s), s);
    return line;
}

static bool has(const char *path, const char *fragment) {
    const char *r = record(path);
    return r != NULL && strstr(r, fragment) != NULL;
}


/* ---- the rules ---- */

/* A2 (audit 2026-10): iflags recorded on one side only meant "not compared",
 * and the path read as unchanged. Absent means the flags could not be read:
 * unknown (pin: iflags, absent means unknown). */
TEST(iflags_on_one_side_only_is_unknown) {
    m_begin("before", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA, .has_iflags = true, .iflags = 16); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("f", "\"outcome\":\"unknown\""));
    ASSERT_TRUE(has("f", "\"unknown\":[\"iflags_unknown\"]"));
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA, .has_iflags = true, .iflags = 0); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("f", "\"outcome\":\"metadata_only\"") && has("f", "\"changed\":[\"iflags\"]"));
}

/* Item 1a (2026-10-30): an absent caps or xattrs means none only where the
 * attributes were read; against xattrs_unknown it is unknown, never "no
 * capabilities". */
TEST(caps_and_xattrs_against_unreadable_attributes_are_unknown) {
    m_begin("before", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA, .caps = "0100000200200000", .xattrs = "\"user.a=" HB "\""); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA, .xattrs_unknown = true); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("f", "\"outcome\":\"unknown\"") && has("f", "\"unknown\":[\"xattrs_unknown\"]"));
    ASSERT_FALSE(has("f", "\"caps\"") || has("f", "\"xattrs\""));
    /* read on both sides: a capability removed is a change */
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA, .xattrs = "\"user.a=" HB "\""); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("f", "\"outcome\":\"metadata_only\"") && has("f", "\"changed\":[\"caps\"]"));
    /* a mount root's are never read: against one they are not compared, which
     * shows where content proves a change and the changed fields are listed */
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 4, .mount = true); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("f", "\"outcome\":\"modified\"") && has("f", "\"changed\":[\"size\"]"));
}

/* Item 1b: dev is compared as the entry's relation to its scope root's
 * device. An entry moving onto another device is a real mount change. */
TEST(an_entry_moving_off_the_scope_roots_device_is_reported) {
    m_begin("before", "/s", 1000); ROOT(); E(.path = "d", .type = "dir"); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "d", .type = "dir", .dev = 2); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("d", "\"outcome\":\"metadata_only\"") && has("d", "\"changed\":[\"dev\"]"));
}

/* Item 1b: a remount renumbers every device (overlay, tmpfs, btrfs). Once
 * reported in the header, it is not a change of every entry; inode numbers
 * are not compared across it; content still compares by hash. */
TEST(a_remounted_scope_reports_once_and_still_compares_content) {
    m_begin("before", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA, .ino = 7);
    E(.path = "g", .type = "reg", .size = 3, .sha = HA, .ino = 8); m_end();
    m_begin("after", "/s", 1000); ROOT(.dev = 9); E(.path = "f", .type = "reg", .size = 3, .sha = HA, .ino = 70, .dev = 9);
    E(.path = "g", .type = "reg", .size = 3, .sha = HB, .ino = 80, .dev = 9); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(g_text, "\"scope_remounted\":true,\"identity_compared\":false}") != NULL);
    ASSERT_TRUE(record("f") == NULL);                    /* renumbered, nothing else */
    ASSERT_TRUE(has("g", "\"outcome\":\"modified\"") && has("g", "\"changed\":[\"sha256\"]"));
    ASSERT_TRUE(record(".") == NULL);
    /* No inode is compared across a remount, even one whose device number
     * held (a btrfs subvolume keeps its own): rule O3. */
    m_begin("before", "/s", 1000); ROOT(); E(.path = "v", .type = "reg", .size = 3, .sha = HA, .ino = 7, .dev = 5); m_end();
    m_begin("after", "/s", 1000); ROOT(.dev = 9); E(.path = "v", .type = "reg", .size = 3, .sha = HA, .ino = 8, .dev = 5); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(record("v") == NULL);
}

/* Item 1b: an inode number means something within one device only. */
TEST(inode_numbers_compare_only_within_one_device) {
    m_begin("before", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA, .ino = 7, .dev = 5); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA, .ino = 8, .dev = 6); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(record("f") == NULL);                    /* off the root's device on both sides */
    ASSERT_TRUE(strstr(g_text, "\"scope_remounted\":false,\"identity_compared\":true}") != NULL);
}

/* Item 1c: ttys and FIFOs stamp themselves when used, and a mount root's
 * times belong to the mounted filesystem: timestamps are not compared there,
 * while a chmod still is. */
TEST(node_and_mount_root_timestamps_are_not_compared) {
    m_begin("before", "/s", 1000); ROOT(); E(.path = "c", .type = "chr"); E(.path = "m", .type = "dir", .mount = true, .dev = 2);
    E(.path = "p", .type = "fifo"); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "c", .type = "chr", .mode = 0600, .mtime = 9, .ctime = 9);
    E(.path = "m", .type = "dir", .mount = true, .dev = 2, .mtime = 9, .ctime = 9); E(.path = "p", .type = "fifo", .mtime = 9, .ctime = 9); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(record("p") == NULL);
    ASSERT_TRUE(has("c", "\"outcome\":\"metadata_only\"") && has("c", "\"changed\":[\"mode\"]"));
    ASSERT_TRUE(has("m", "\"outcome\":\"unknown\""));
    ASSERT_FALSE(has("m", "mtime_ns") || has("m", "ctime_ns"));
    /* A file mount root whose content proves a change lists what differs:
     * its times are not among it. */
    m_begin("before", "/s", 1000); ROOT(); E(.path = "b", .type = "reg", .size = 3, .mount = true); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "b", .type = "reg", .size = 4, .mount = true, .mtime = 9, .ctime = 9); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("b", "\"outcome\":\"modified\"") && has("b", "\"changed\":[\"size\"]"));
}

TEST(identical_manifests_emit_no_record) {
    for (int side = 0; side < 2; side++) {
        m_begin(side ? "after" : "before", "/s", 1000);
        ROOT(.mode = 0755);
        E(.path = "a", .type = "reg", .size = 3, .sha = HA);
        E(.path = "l", .type = "lnk", .target = "a");
        m_end();
    }
    ASSERT_EQ_INT(0, run());
    ASSERT_EQ_INT(0, (int)g_st.records);
    ASSERT_EQ_INT(3, (int)g_st.unchanged);
    ASSERT_TRUE(strstr(g_text, "\"belay_diff_end\":0,\"unchanged\":3,") != NULL);
}

TEST(added_removed_and_modified_by_hash) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "gone", .type = "reg", .size = 3, .sha = HA);
    E(.path = "kept", .type = "reg", .size = 3, .sha = HA);
    m_end();
    m_begin("after", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "kept", .type = "reg", .size = 3, .sha = HB);
    E(.path = "new", .type = "reg", .size = 3, .sha = HA);
    m_end();
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("gone", "\"outcome\":\"removed\""));
    ASSERT_TRUE(has("new", "\"outcome\":\"added\""));
    ASSERT_TRUE(has("kept", "\"outcome\":\"modified\",\"type\":\"reg\",\"changed\":[\"sha256\"]"));
    ASSERT_EQ_INT(3, (int)g_st.records);
}

/* Q4: different hash limits. Unverified on one side and the same size:
 * absence of evidence, unknown. A different size is proof: modified. */
TEST(different_hash_limits_are_unknown_unless_size_proves_a_change) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "big", .type = "reg", .size = 500, .sha = HA);
    E(.path = "grew", .type = "reg", .size = 500, .sha = HA);
    m_end();
    m_begin("after", "/s", 100);
    ROOT(.mode = 0755);
    E(.path = "big", .type = "reg", .size = 500);
    E(.path = "grew", .type = "reg", .size = 600);
    m_end();
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("big", "\"outcome\":\"unknown\""));
    ASSERT_TRUE(has("big", "\"unknown\":[\"unverified\"]"));
    ASSERT_TRUE(has("grew", "\"outcome\":\"modified\""));
    ASSERT_TRUE(strstr(g_text, "\"before_hash_max_bytes\":1000,\"after_hash_max_bytes\":100") != NULL);
}

/* Q3: the same bytes under a new inode (rename-over) is metadata_only,
 * naming ino; a permission change too; a ctime-only change names ctime. */
TEST(new_inode_permissions_and_ctime_alone_are_metadata_only) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "c", .type = "reg", .size = 3, .sha = HA, .ctime = 5);
    E(.path = "i", .type = "reg", .size = 3, .sha = HA, .ino = 10);
    E(.path = "m", .type = "reg", .size = 3, .sha = HA, .mode = 0644);
    m_end();
    m_begin("after", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "c", .type = "reg", .size = 3, .sha = HA, .ctime = 6);
    E(.path = "i", .type = "reg", .size = 3, .sha = HA, .ino = 11);
    E(.path = "m", .type = "reg", .size = 3, .sha = HA, .mode = 0600);
    m_end();
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("i", "\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"ino\"]"));
    ASSERT_TRUE(has("m", "\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"mode\"]"));
    ASSERT_TRUE(has("c", "\"outcome\":\"metadata_only\",\"type\":\"reg\",\"changed\":[\"ctime_ns\"]"));
}

TEST(type_change_names_the_type_before) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "t", .type = "reg", .size = 3, .sha = HA);
    m_end();
    m_begin("after", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "t", .type = "dir", .mode = 0755);
    m_end();
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("t", "\"outcome\":\"type_changed\",\"type\":\"dir\",\"type_before\":\"reg\","
                         "\"changed\":[\"type\"]"));
}

/* Rule 1: raced on either side is unknown, even with a different hash --
 * its recorded fields may not be the state at the end of its walk. */
TEST(raced_is_unknown_even_when_a_field_differs) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "r", .type = "reg", .size = 3, .sha = HA);
    m_end();
    m_begin("after", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "r", .type = "reg", .size = 3, .sha = HB, .raced = true);
    m_end();
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("r", "\"outcome\":\"unknown\""));
    ASSERT_TRUE(has("r", "\"changed\":[\"sha256\"],\"unknown\":[\"raced\"]"));
}

/* Rule 3 and 4 with xattrs_unknown: metadata unknown unless content proves
 * a change. Never unchanged. */
TEST(unknown_attributes_never_read_as_unchanged) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "p", .type = "reg", .size = 3, .sha = HA);
    E(.path = "q", .type = "reg", .size = 3, .sha = HA);
    m_end();
    m_begin("after", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "p", .type = "reg", .size = 3, .sha = HA, .xattrs_unknown = true);
    E(.path = "q", .type = "reg", .size = 3, .sha = HB, .xattrs_unknown = true);
    m_end();
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("p", "\"outcome\":\"unknown\""));
    ASSERT_TRUE(has("p", "\"unknown\":[\"xattrs_unknown\"]"));
    ASSERT_TRUE(has("q", "\"outcome\":\"modified\""));
}

/* One-sided: the lacking side's nearest recorded ancestor decides. */
TEST(absence_below_an_incomplete_or_sealed_directory_is_unknown) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "clean", .type = "dir", .mode = 0755);
    E(.path = "sealed", .type = "dir", .mode = 0755, .unreadable = true);
    E(.path = "shaky", .type = "dir", .mode = 0755, .unstable = true);
    m_end();
    m_begin("after", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "clean", .type = "dir", .mode = 0755);
    E(.path = "clean/x", .type = "reg", .size = 1, .sha = HA);
    E(.path = "sealed", .type = "dir", .mode = 0755);
    E(.path = "sealed/x", .type = "reg", .size = 1, .sha = HA);
    E(.path = "shaky", .type = "dir", .mode = 0755);
    E(.path = "shaky/x", .type = "reg", .size = 1, .sha = HA);
    m_end();
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("clean/x", "\"outcome\":\"added\""));
    ASSERT_TRUE(has("sealed/x", "\"unknown\":[\"not_captured\"]"));
    ASSERT_TRUE(has("shaky/x", "\"unknown\":[\"listing_incomplete\"]"));
    ASSERT_TRUE(has("shaky", "\"outcome\":\"unknown\""));         /* its own unstable flag */
}

/* An orphan (an entry whose parent directory is not recorded) is refused by
 * the reader (decided 2026-10-30), so the diff never classifies one. */
TEST(a_manifest_with_an_orphan_is_refused_with_no_output) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    m_end();
    m_begin("after", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "o/y", .type = "reg", .size = 1, .sha = HA);
    m_end();
    unlink(g_out);
    ASSERT_EQ_INT(-1, run());
    ASSERT_TRUE(strstr(belay_err_msg(), "orphan") != NULL);
    ASSERT_TRUE(access(g_out, F_OK) != 0);
    belay_err_clear();
}

/* "." sorts after "!x": the root's kind must be known before its own line. */
TEST(names_sorting_before_the_root_see_its_flags) {
    m_begin("before", "/s", 1000);
    E(.path = "!early", .type = "reg", .size = 1, .sha = HA);
    ROOT(.mode = 0755);
    m_end();
    m_begin("after", "/s", 1000);
    ROOT(.mode = 0755, .unstable = true);
    m_end();
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("!early", "\"unknown\":[\"listing_incomplete\"]"));
}

TEST(manifests_of_different_scopes_are_refused_with_no_output) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    m_end();
    m_begin("after", "/other", 1000);
    ROOT(.mode = 0755);
    m_end();
    unlink(g_out);
    ASSERT_EQ_INT(-1, run());
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
    ASSERT_TRUE(access(g_out, F_OK) != 0);
    belay_err_clear();
}

/* An unreadable link's target is unknown (empty), not a target that
 * changed: compared only when neither side is unreadable. */
TEST(an_unreadable_links_unknown_target_is_not_a_change) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "l", .type = "lnk", .target = "t5");
    m_end();
    m_begin("after", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "l", .type = "lnk", .target = "", .size = 2, .unreadable = true);
    m_end();
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("l", "\"outcome\":\"unknown\""));
    ASSERT_TRUE(has("l", "\"unknown\":[\"unreadable\"]"));
}

/* xattrs_unknown suspends the caps and xattrs comparisons: a capability
 * "missing" on the side that could not read attributes is not a change. */
TEST(capabilities_are_not_compared_when_attributes_are_unknown) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "f", .type = "reg", .size = 3, .sha = HA);
    m_end();
    m_begin("after", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "f", .type = "reg", .size = 3, .sha = HA, .xattrs_unknown = true);
    m_end();
    /* before carries a capability: added by hand, after the builder's line */
    char p[400];
    snprintf(p, sizeof p, "%s/before", g_dir);
    FILE *f = fopen(p, "rb");
    static char buf[4096];
    const size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    fclose(f);
    char *at = strstr(buf, "\"nlink\":1,\"sha256\"");
    REQUIRE(at != NULL);
    f = fopen(p, "wb");
    fwrite(buf, 1, (size_t)(at - buf) + strlen("\"nlink\":1"), f);
    fputs(",\"caps\":\"0100000200200000\"", f);
    fputs(at + strlen("\"nlink\":1"), f);
    fclose(f);
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("f", "\"outcome\":\"unknown\""));
    ASSERT_FALSE(has("f", "\"caps\""));
}

/* The ancestry stack keeps an ancestor while the stream sits in its
 * "before range": "a!b" sorts after "a" but before "a/x", so "a" must still
 * be on the stack when "a/x", missing on that side, is asked about. */
TEST(an_ancestor_survives_siblings_that_sort_between_it_and_its_children) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "a", .type = "dir", .mode = 0755, .unstable = true);
    E(.path = "a!b", .type = "reg", .size = 1, .sha = HA);
    m_end();
    m_begin("after", "/s", 1000);
    ROOT(.mode = 0755);
    E(.path = "a", .type = "dir", .mode = 0755, .unstable = true);
    E(.path = "a!b", .type = "reg", .size = 1, .sha = HA);
    E(.path = "a/x", .type = "reg", .size = 1, .sha = HA);
    m_end();
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("a/x", "\"unknown\":[\"listing_incomplete\"]"));
}

/* Nothing lives below a non-directory: a path missing below a file is
 * known absent, even when an ancestor further up is unstable. */
TEST(absence_below_a_file_is_known) {
    m_begin("before", "/s", 1000);
    ROOT(.mode = 0755, .unstable = true);
    E(.path = "f", .type = "reg", .size = 1, .sha = HA);
    m_end();
    m_begin("after", "/s", 1000);                    /* f became a directory */
    ROOT(.mode = 0755, .unstable = true);
    E(.path = "f", .type = "dir");
    E(.path = "f/x", .type = "reg", .size = 1, .sha = HA);
    m_end();
    ASSERT_EQ_INT(0, run());
    ASSERT_TRUE(has("f/x", "\"outcome\":\"added\""));
}

/* The schema's promise, checked exhaustively: no combination of flags on
 * either side classifies as unchanged, for any entry type, even when every
 * compared field is equal. The six flags are listed here by hand, from the
 * spec (diff-v1, rules 1, 3 and 4), not read from DIFF_FIELDS: a flag the
 * table demoted would otherwise drop out of this test with it (audit 2026-10,
 * class 1). */
static void set_flag(struct belay_entry *e, enum entry_field f) {
    switch (f) {
    case F_RACED: e->raced = true; break;
    case F_UNSTABLE: e->unstable = true; break;
    case F_UNVERIFIED: e->unverified = true; break;
    case F_UNREADABLE: e->unreadable = true; break;
    case F_MOUNT: e->is_mount = true; break;
    case F_XATTRS_UNKNOWN: e->xattrs_unknown = true; break;
    case F_PATH: case F_TYPE: case F_MODE: case F_UID: case F_GID: case F_SIZE: case F_MTIME:
    case F_CTIME: case F_INO: case F_DEV: case F_NLINK: case F_IFLAGS: case F_CAPS: case F_XATTRS:
    case F_XATTRS_SHA256: case F_SHA256: case F_RDEV: case F_LINK_TARGET: case F_TARGET_OUTSIDE:
    case F_STORED: case F_COUNT:
        BELAY_FAIL("flag field %d has no setter here", (int)f);
        break;
    }
}

TEST(no_flag_combination_on_either_side_is_unchanged) {
    static const enum entry_field flags[] = { F_RACED, F_UNSTABLE, F_UNVERIFIED, F_UNREADABLE,
                                              F_MOUNT, F_XATTRS_UNKNOWN };
    const int nf = (int)(sizeof flags / sizeof flags[0]);
    const struct diff_ctx ctx = { 0, 0, false };
    static struct belay_entry base, b, a;
    int checked = 0;
    for (int t = 0; t < ENTRY_TYPE_COUNT; t++) {
        memset(&base, 0, sizeof base);
        base.type = (enum belay_entry_type)t;
        base.path[0] = 'x';
        base.path_len = 1;
        for (unsigned mask = 1; mask < (1u << (2 * nf)); mask++) {
            b = base;
            a = base;
            for (int i = 0; i < nf; i++) {
                if (mask & (1u << i)) set_flag(&b, flags[i]);
                if (mask & (1u << (nf + i))) set_flag(&a, flags[i]);
            }
            struct verdict v;
            REQUIRE(classify_both(&ctx, &b, &a, &v) == 0);
            REQUIRE_MSG(v.outcome != D_UNCHANGED, "type %d, flag mask %#x classified unchanged",
                        t, mask);
            REQUIRE_MSG(!(v.outcome == D_UNKNOWN && v.reasons == 0),
                        "type %d, flag mask %#x unknown with no reason", t, mask);
            checked++;
        }
    }
    ASSERT_TRUE(checked > 20000);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_diff_%d", (int)getpid());
    snprintf(g_out, sizeof g_out, "%s/diff.ndjson", g_dir);
    char cmd[400];
    snprintf(cmd, sizeof cmd, "mkdir -p '%s'", g_dir);
    if (system(cmd) != 0) return 1;
    RUN(identical_manifests_emit_no_record);
    RUN(iflags_on_one_side_only_is_unknown);
    RUN(caps_and_xattrs_against_unreadable_attributes_are_unknown);
    RUN(an_entry_moving_off_the_scope_roots_device_is_reported);
    RUN(a_remounted_scope_reports_once_and_still_compares_content);
    RUN(inode_numbers_compare_only_within_one_device);
    RUN(node_and_mount_root_timestamps_are_not_compared);
    RUN(added_removed_and_modified_by_hash);
    RUN(different_hash_limits_are_unknown_unless_size_proves_a_change);
    RUN(new_inode_permissions_and_ctime_alone_are_metadata_only);
    RUN(type_change_names_the_type_before);
    RUN(raced_is_unknown_even_when_a_field_differs);
    RUN(unknown_attributes_never_read_as_unchanged);
    RUN(absence_below_an_incomplete_or_sealed_directory_is_unknown);
    RUN(a_manifest_with_an_orphan_is_refused_with_no_output);
    RUN(names_sorting_before_the_root_see_its_flags);
    RUN(manifests_of_different_scopes_are_refused_with_no_output);
    RUN(an_unreadable_links_unknown_target_is_not_a_change);
    RUN(capabilities_are_not_compared_when_attributes_are_unknown);
    RUN(an_ancestor_survives_siblings_that_sort_between_it_and_its_children);
    RUN(absence_below_a_file_is_known);
    RUN(no_flag_combination_on_either_side_is_unchanged);
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
