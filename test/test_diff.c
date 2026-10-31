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
#include "belay/hash.h"
#include "diff/classify.h"
#include "diff/diff_run.h"
#include "schema/finding_schema.h"
#include "schema/entry.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
    const char *stored;                  /* reg: the stored copy's hash */
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
static size_t g_n, g_unreadable, g_unstable, g_mounts, g_raced, g_vanished;
static long long g_created = 1;           /* the next manifest's created_ns */

static void m_begin(const char *name, const char *scope, unsigned long long hash_max) {
    char p[400];
    snprintf(p, sizeof p, "%s/%s", g_dir, name);
    g_f = fopen(p, "wb");
    fprintf(g_f, "{\"belay_manifest\":1,\"created_ns\":%lld,\"scopes\":[\"%s\"],\"hash\":\"sha256\","
                 "\"hash_max_bytes\":%llu,\"store_max_bytes\":0}\n", g_created, scope, hash_max);
    g_created = 1;
    g_n = g_unreadable = g_unstable = g_mounts = g_raced = g_vanished = 0;
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
    if (e.stored) fprintf(g_f, ",\"stored\":\"%s\"", e.stored);
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
    fprintf(g_f, "{\"belay_manifest_end\":%zu,\"vanished\":%zu,\"unreadable\":%zu,\"unstable\":%zu,"
                 "\"mounts\":%zu,\"raced\":%zu}\n", g_n, g_vanished, g_unreadable, g_unstable,
            g_mounts, g_raced);
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
    const int rc = belay_diff(b, a, g_out, NULL, &g_st);
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

/* Pin PR #12 (review F6): a mount root's iflags, caps and xattrs are never
 * read (manifest rule 22), so they are not compared there. A directory that
 * becomes a mount root, or stops being one, is unknown for the reason mount
 * alone -- not iflags_unknown, which says something could not be read. */
TEST(a_mount_roots_unread_attributes_are_not_compared) {
    for (int way = 0; way < 2; way++) {
        m_begin(way ? "after" : "before", "/s", 1000); ROOT();
        E(.path = "m", .type = "dir", .has_iflags = true, .iflags = 16, .xattrs = "\"user.a=" HB "\"");
        m_end();
        m_begin(way ? "before" : "after", "/s", 1000); ROOT();
        E(.path = "m", .type = "dir", .mount = true, .dev = 2); m_end();
        REQUIRE(run() == 0);
        ASSERT_TRUE(has("m", "\"outcome\":\"unknown\",\"type\":\"dir\",\"changed\":[\"dev\"],"
                             "\"unknown\":[\"mount\"]}"));
    }
}

/* Pin O8 (decided 2026-10-31): a mounted regular file carries unverified
 * because it is never read (manifest rules 5 and 21), so on that side
 * `mount` is the reason; unverified on the other side keeps its own. */
TEST(a_mounted_file_is_unknown_for_mount_not_unverified) {
    for (int way = 0; way < 2; way++) {
        m_begin(way ? "after" : "before", "/s", 1000); ROOT();
        E(.path = "f", .type = "reg", .size = 3, .sha = HA, .has_iflags = true, .iflags = 16); m_end();
        m_begin(way ? "before" : "after", "/s", 1000); ROOT();
        E(.path = "f", .type = "reg", .size = 3, .mount = true, .dev = 2); m_end();
        REQUIRE(run() == 0);
        ASSERT_TRUE(has("f", "\"outcome\":\"unknown\",\"type\":\"reg\",\"changed\":[\"dev\"],"
                             "\"unknown\":[\"mount\"]}"));
    }
    /* the other side unverified for its own reason: larger than its hash limit */
    m_begin("before", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3000); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3000, .mount = true, .dev = 2); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("f", "\"unknown\":[\"unverified\",\"mount\"]}"));
}

/* Decided F2: a tree that changed while it was walked makes the whole result
 * provisional (manifest-v1, obligations on a consumer), and only the trailers
 * say so for `vanished`, which leaves no record. */
TEST(a_tree_that_changed_while_walked_makes_the_diff_provisional) {
    m_begin("before", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(g_text, "\"after_raced\":0,\"provisional\":false,") != NULL);
    ASSERT_FALSE(g_st.provisional);
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA);
    g_vanished = 1;                                   /* one entry gone mid-walk: no record */
    m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(record("f") == NULL);
    ASSERT_TRUE(strstr(g_text, "\"after_vanished\":1,") != NULL);
    ASSERT_TRUE(strstr(g_text, "\"provisional\":true,") != NULL);
    ASSERT_TRUE(g_st.provisional);
}

/* Decided F9: the output is never one of the inputs, however it is spelled;
 * compared by device and inode. The input is left as it was. */
TEST(the_output_is_never_an_input_however_spelled) {
    m_begin("before", "/s", 1000); ROOT(); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA); m_end();
    char dotted[400], viaink[400], b[400];
    snprintf(b, sizeof b, "%s/before", g_dir);
    snprintf(dotted, sizeof dotted, "%s/./before", g_dir);
    snprintf(viaink, sizeof viaink, "%s/to_before", g_dir);
    unlink(viaink);
    REQUIRE(symlink(b, viaink) == 0);
    struct stat st0, st1;
    REQUIRE(stat(b, &st0) == 0);
    const char *outs[] = { b, dotted, viaink };
    for (size_t i = 0; i < 3; i++) {
        char a[400];
        snprintf(a, sizeof a, "%s/after", g_dir);
        ASSERT_EQ_INT(-1, belay_diff(b, a, outs[i], NULL, NULL));
        ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
        belay_err_clear();
    }
    REQUIRE(stat(b, &st1) == 0);
    ASSERT_TRUE(st1.st_size == st0.st_size && st1.st_mtime == st0.st_mtime);
    unlink(viaink);
}

/* Audit L4: the trailer names what was compared -- each input's sha256, of
 * the bytes read (the header goes out before anything else is read). */
TEST(the_trailer_names_both_inputs_by_their_digest) {
    m_begin("before", "/s", 1000); ROOT(); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA); m_end();
    REQUIRE(run() == 0);
    const char *side[2] = { "before", "after" };
    for (int k = 0; k < 2; k++) {
        char p[400], want[128], hex[65];
        snprintf(p, sizeof p, "%s/%s", g_dir, side[k]);
        FILE *f = fopen(p, "rb");
        REQUIRE(f != NULL);
        struct belay_sha256 h;
        belay_sha256_init(&h);
        unsigned char buf[4096];
        for (size_t n; (n = fread(buf, 1, sizeof buf, f)) > 0; ) belay_sha256_update(&h, buf, n);
        fclose(f);
        uint8_t d[BELAY_SHA256_DIGEST_LEN];
        belay_sha256_final(&h, d);
        belay_hex_encode(hex, d, sizeof d);
        snprintf(want, sizeof want, "\"%s_sha256\":\"%s\"", side[k], hex);
        ASSERT_TRUE(strstr(g_text, want) != NULL);
    }
}

/* F3 / R11: an interpreter can only add to a record, and its failures stay
 * in its own output. Run through diff_run with a test interpreter in one
 * slot: the binary one, which every unclaimed path reaches, or pip's, which
 * claims "*.dist-info/RECORD". */
#define PIP_A "a-1.dist-info/RECORD"
#define PIP_B "b-1.dist-info/RECORD"
static int g_begun, g_ended, g_saw_modified;
static void *t_begin(void) { g_begun++; return &g_saw_modified; }
static enum belay_interp_result t_end(void *state, struct belay_events *ev) {
    (void)ev;
    g_ended += state == &g_saw_modified;
    return BELAY_INTERP_DECLINE;
}
static const struct belay_fv CU_MISSING[] = { { .s = "missing", .len = 7 }, { .s = "after", .len = 5 } };
static enum belay_interp_result t_error(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    (void)state; (void)in;
    belay_finding(out, FK_CONTENT_UNAVAILABLE, CU_MISSING, 2);       /* half-written */
    return BELAY_INTERP_ERROR;
}
static enum belay_interp_result t_invalid(void *state, const struct belay_interp_input *in,
                                          struct belay_findings *out) {
    (void)state; (void)in;
    const struct belay_fv bad[] = { { .s = "ok \xff\xfe", .len = 5 }, { .s = "after", .len = 5 } };
    belay_finding(out, FK_CONTENT_UNAVAILABLE, bad, 2);
    belay_finding(out, FK_CONTENT_UNAVAILABLE, CU_MISSING, 2);
    return BELAY_INTERP_FINDINGS;
}
static enum belay_interp_result t_verdict(void *state, const struct belay_interp_input *in,
                                          struct belay_findings *out) {
    if (state != NULL && strcmp(in->outcome, "modified") == 0) (*(int *)state)++;
    (void)out;
    return BELAY_INTERP_DECLINE;
}
static const struct belay_diff_opts *g_opts;    /* run_with's options; NULL: none */
static int run_in(enum belay_interp_id slot, const struct belay_interp *t) {
    const struct belay_interp *table[BELAY_INTERP_COUNT];
    for (int i = 0; i < BELAY_INTERP_COUNT; i++) table[i] = belay_interp_builtin((enum belay_interp_id)i);
    table[slot] = t;
    char b[400], a[400];
    snprintf(b, sizeof b, "%s/before", g_dir);
    snprintf(a, sizeof a, "%s/after", g_dir);
    g_text[0] = '\0';
    if (diff_run(b, a, g_out, g_opts, &g_st, table) != 0) return -1;
    FILE *f = fopen(g_out, "rb");
    const size_t n = fread(g_text, 1, sizeof g_text - 1, f);
    g_text[n] = '\0';
    fclose(f);
    return 0;
}
static int run_with(const struct belay_interp *t) { return run_in(BELAY_INTERP_BINARY, t); }

/* Two dist-info RECORDs, both modified. */
static void two_records(void) {
    for (int k = 0; k < 2; k++) {
        m_begin(k ? "after" : "before", "/s", 1000); ROOT();
        E(.path = "a-1.dist-info", .type = "dir", .mode = 0755, .ino = 8);
        E(.path = PIP_A, .type = "reg", .size = 3, .sha = k ? HB : HA);
        E(.path = "b-1.dist-info", .type = "dir", .mode = 0755, .ino = 9);
        E(.path = PIP_B, .type = "reg", .size = 3, .sha = k ? HB : HA); m_end();
    }
}

/* Review F8: findings are cleared before each path, so nothing an
 * interpreter added for one path reaches the next. */
static int g_calls;
static enum belay_interp_result t_stale(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    (void)state; (void)in;
    if (g_calls++ == 0) belay_finding(out, FK_CONTENT_UNAVAILABLE, CU_MISSING, 2);
    return BELAY_INTERP_FINDINGS;
}

TEST(one_paths_findings_never_reach_the_next) {
    two_records();
    g_calls = 0;
    const struct belay_interp t = { BELAY_INTERP_PIP, NULL, t_stale, NULL };
    REQUIRE(run_in(BELAY_INTERP_PIP, &t) == 0);
    ASSERT_TRUE(has(PIP_A, "\"findings\":[{\"kind\":\"content_unavailable\",\"reason\":\"missing\","
                           "\"side\":\"after\",\"text\":\"content unavailable (after): missing\"}]"));
    ASSERT_FALSE(has(PIP_B, "findings"));
}

/* diff-events E1, E2, E7: an end hook's events come after the last path
 * record and before the trailer, which counts them; belay_diff_end and
 * stats.records count path records only. */
static enum belay_interp_result t_claims(void *state, const struct belay_interp_input *in,
                                         struct belay_findings *out) {
    (void)state; (void)in; (void)out;
    return BELAY_INTERP_DECLINE;
}
static enum belay_interp_result t_end_event(void *state, struct belay_events *ev) {
    (void)state;
    if (ev == NULL) return BELAY_INTERP_DECLINE;
    const char *p[] = { PIP_B, PIP_A };
    const size_t l[] = { strlen(PIP_B), strlen(PIP_A) };
    const struct belay_fv v[] = { { .s = "a", .len = 1 }, { .s = "1", .len = 1 } };
    belay_event(ev, FK_PIP_INSTALLED, v, 2, p, l, 2);
    belay_event(ev, FK_PIP_REMOVED, v, 2, p, l, 1);
    return BELAY_INTERP_FINDINGS;
}

TEST(events_come_after_the_path_records_and_the_trailer_counts_them) {
    two_records();
    const struct belay_interp t = { BELAY_INTERP_PIP, NULL, t_claims, t_end_event };
    const int rc = run_in(BELAY_INTERP_PIP, &t);
    if (rc != 0) BELAY_FAIL("%s", belay_err_msg());
    REQUIRE(rc == 0);
    const char *last_path = strstr(g_text, "{\"path\":\"" PIP_B "\"");
    const char *e1 = strstr(g_text, "{\"event\":\"pip_installed\",\"interp\":\"pip\",\"name\":\"a\","
                                    "\"version\":\"1\",\"text\":\"installed a 1\",\"paths\":[\"" PIP_A "\",\""
                                    PIP_B "\"]}\n");
    const char *e2 = strstr(g_text, "{\"event\":\"pip_removed\"");
    const char *trailer = strstr(g_text, "{\"belay_diff_end\":2,");
    if (!(last_path != NULL && e1 != NULL && e2 != NULL && trailer != NULL)) BELAY_FAIL("%s", g_text);
    REQUIRE(last_path != NULL && e1 != NULL && e2 != NULL && trailer != NULL);
    ASSERT_TRUE(last_path < e1 && e1 < e2 && e2 < trailer);
    ASSERT_TRUE(strstr(trailer, ",\"events\":2,") != NULL);
    ASSERT_EQ_INT(2, (int)g_st.records);
    ASSERT_EQ_INT(2, (int)g_st.events);
}

TEST(a_diff_with_no_events_says_zero) {
    m_begin("before", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HB); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(strstr(g_text, ",\"events\":0,") != NULL);
    ASSERT_TRUE(strstr(g_text, "{\"event\"") == NULL);
    ASSERT_EQ_INT(0, (int)g_st.events);
}

/* E6: an end hook that fails has its events replaced by one
 * could_not_interpret naming every path it was given; the diff succeeds. */
static enum belay_interp_result t_end_fails(void *state, struct belay_events *ev) {
    t_end_event(state, ev);
    return BELAY_INTERP_ERROR;
}

TEST(a_failed_end_hook_is_one_event_naming_its_paths) {
    two_records();
    const struct belay_interp t = { BELAY_INTERP_PIP, NULL, t_claims, t_end_fails };
    REQUIRE(run_in(BELAY_INTERP_PIP, &t) == 0);
    ASSERT_TRUE(strstr(g_text, "{\"event\":\"could_not_interpret\",\"interp\":\"pip\",\"text\":"
                               "\"could not interpret\",\"paths\":[\"" PIP_A "\",\"" PIP_B "\"]}\n") != NULL);
    ASSERT_TRUE(strstr(g_text, "pip_installed") == NULL);
    ASSERT_EQ_INT(1, (int)g_st.events);
}

/* A diff that fails after begin still ends each interpreter, with no sink:
 * its state is freed, and nothing it adds can reach an output. */
static int g_null_ends;
static enum belay_interp_result t_end_null(void *state, struct belay_events *ev) {
    (void)state;
    g_null_ends += ev == NULL;
    return BELAY_INTERP_DECLINE;
}

TEST(a_failed_diff_ends_its_interpreters_without_a_sink) {
    m_begin("before", "/s", 1000); ROOT(.mode = 0755); m_end();
    m_begin("after", "/s", 1000); ROOT(.mode = 0755);
    E(.path = "o/y", .type = "reg", .size = 1, .sha = HA); m_end();       /* an orphan: refused */
    g_null_ends = 0;
    const struct belay_interp t = { BELAY_INTERP_PIP, NULL, t_claims, t_end_null };
    ASSERT_EQ_INT(-1, run_in(BELAY_INTERP_PIP, &t));
    ASSERT_EQ_INT(1, g_null_ends);
    belay_err_clear();
}

/* Review F4: different scopes are refused before any entry is read -- not
 * reported as whatever is wrong with an entry sorting before the root. */
TEST(different_scopes_are_refused_before_any_entry_is_read) {
    char b[400], a[400];
    snprintf(b, sizeof b, "%s/before", g_dir);
    snprintf(a, sizeof a, "%s/after", g_dir);
    FILE *f = fopen(b, "wb");
    REQUIRE(f != NULL);
    fputs("{\"belay_manifest\":1,\"created_ns\":1,\"scopes\":[\"/s\"],\"hash\":\"sha256\","
          "\"hash_max_bytes\":1000,\"store_max_bytes\":0}\n"
          "{\"path\":\"!a/b\",\"type\":\"reg\",\"mode\":33188,\"uid\":1,\"gid\":1,\"size\":3,"
          "\"mtime_ns\":1,\"ctime_ns\":1,\"ino\":7,\"dev\":1,\"nlink\":1,\"sha256\":\"" HA "\"}\n", f);
    fclose(f);
    m_begin("after", "/other", 1000); ROOT(); m_end();
    unlink(g_out);
    ASSERT_EQ_INT(-1, belay_diff(b, a, g_out, NULL, NULL));
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "different scopes") != NULL);
    belay_err_clear();
}

/* Review F3: once the output is in place, the diff has succeeded. A directory
 * that cannot be opened to sync it (write and search only) does not turn a
 * complete output into a reported failure. */
TEST(a_published_output_is_success_even_where_its_directory_cannot_be_synced) {
    m_begin("before", "/s", 1000); ROOT(); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA); m_end();
    char d[400], out[480], b[400], a[400];
    snprintf(d, sizeof d, "%s/drop", g_dir);
    snprintf(out, sizeof out, "%s/out.diff", d);
    snprintf(b, sizeof b, "%s/before", g_dir);
    snprintf(a, sizeof a, "%s/after", g_dir);
    mkdir(d, 0700);
    REQUIRE(chmod(d, 0300) == 0);
    const int rc = belay_diff(b, a, out, NULL, NULL);
    const char *why = rc == 0 ? "" : belay_err_msg();
    chmod(d, 0700);
    ASSERT_TRUE(rc == 0);
    if (rc != 0) BELAY_FAIL("refused: %s", why);
    belay_err_clear();
    ASSERT_TRUE(access(out, F_OK) == 0);
    unlink(out);
    rmdir(d);
}

TEST(an_interpreter_error_is_a_finding_never_a_failed_diff) {
    m_begin("before", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HB); m_end();
    const struct belay_interp t = { BELAY_INTERP_BINARY, NULL, t_error, NULL };
    REQUIRE(run_with(&t) == 0);
    ASSERT_TRUE(has("f", "\"outcome\":\"modified\""));
    ASSERT_TRUE(has("f", "\"findings\":[{\"kind\":\"could_not_interpret\",\"text\":\"could not interpret\"}]}"));
}

TEST(a_finding_that_is_not_utf8_is_replaced) {
    two_records();
    const struct belay_interp t = { BELAY_INTERP_PIP, NULL, t_invalid, NULL };
    REQUIRE(run_in(BELAY_INTERP_PIP, &t) == 0);
    ASSERT_TRUE(has(PIP_A, "\"findings\":[{\"kind\":\"invalid_finding\",\"text\":\"invalid finding\"},"
                           "{\"kind\":\"content_unavailable\",\"reason\":\"missing\",\"side\":\"after\","
                           "\"text\":\"content unavailable (after): missing\"}]}"));
    ASSERT_TRUE(strchr(g_text, '\xff') == NULL);
}

TEST(an_interpreter_sees_the_verdict_and_keeps_its_state_over_one_diff) {
    m_begin("before", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HA);
    E(.path = "g", .type = "reg", .size = 3, .sha = HA); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 3, .sha = HB);
    E(.path = "g", .type = "reg", .size = 4, .sha = HB); m_end();
    g_begun = g_ended = g_saw_modified = 0;
    const struct belay_interp t = { BELAY_INTERP_BINARY, t_begin, t_verdict, t_end };
    REQUIRE(run_with(&t) == 0);
    ASSERT_EQ_INT(1, g_begun);
    ASSERT_EQ_INT(1, g_ended);
    ASSERT_EQ_INT(2, g_saw_modified);
}

/* Decided 2026-10-31 (Q1): the store reaches an interpreter through
 * belay_diff's options -- content to read, checked against its name -- and
 * without a store an interpreter gets none. */
static int g_content_ok, g_content_none;
static char g_content_hex[65];
static enum belay_interp_result t_content(void *state, const struct belay_interp_input *in,
                                          struct belay_findings *out) {
    (void)state;
    (void)out;
    if (in->content == NULL) {
        g_content_none++;
        return BELAY_INTERP_DECLINE;
    }
    unsigned char *b = NULL;
    size_t n = 0;
    if (belay_content_get(in->content, g_content_hex, 4096, &b, &n) == 0 && n == 6 &&
        memcmp(b, "after\n", 6) == 0)
        g_content_ok++;
    free(b);
    return BELAY_INTERP_DECLINE;
}

TEST(the_store_reaches_an_interpreter_through_the_options) {
    char store[400], obj[600];
    snprintf(store, sizeof store, "%s/store", g_dir);
    {   /* store "after\n" under its real name */
        struct belay_sha256 h;
        uint8_t d[32];
        belay_sha256_init(&h);
        belay_sha256_update(&h, "after\n", 6);
        belay_sha256_final(&h, d);
        belay_hex_encode(g_content_hex, d, sizeof d);
        snprintf(obj, sizeof obj, "%s/%.2s", store, g_content_hex);
        mkdir(store, 0700);
        mkdir(obj, 0700);
        snprintf(obj, sizeof obj, "%s/%.2s/%s", store, g_content_hex, g_content_hex + 2);
        FILE *f = fopen(obj, "wb");
        REQUIRE(f != NULL);
        fputs("after\n", f);
        fclose(f);
    }
    m_begin("before", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 6, .sha = HA); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f", .type = "reg", .size = 6, .sha = HB); m_end();
    const struct belay_interp t = { BELAY_INTERP_BINARY, NULL, t_content, NULL };
    const struct belay_diff_opts o = { .store_dir = store };
    g_content_ok = g_content_none = 0;
    g_opts = &o;
    REQUIRE(run_with(&t) == 0);
    g_opts = NULL;
    ASSERT_EQ_INT(1, g_content_ok);
    ASSERT_EQ_INT(0, g_content_none);
    REQUIRE(run_with(&t) == 0);
    ASSERT_EQ_INT(1, g_content_none);
    const struct belay_diff_opts bad = { .store_dir = "/nonexistent/belay-store" };
    g_opts = &bad;
    ASSERT_EQ_INT(-1, run_with(&t));                    /* a store named but absent: refused */
    g_opts = NULL;
    belay_err_clear();
}

/* The built-ins end to end, through belay_diff: dispatch, an interpreter,
 * the emitter. `data` stored under its own name in `store`; *hex its name. */
static void store_put(const char *store, const char *data, char hex[65]) {
    struct belay_sha256 h;
    uint8_t d[32];
    char p[600];
    belay_sha256_init(&h);
    belay_sha256_update(&h, data, strlen(data));
    belay_sha256_final(&h, d);
    belay_hex_encode(hex, d, sizeof d);
    mkdir(store, 0700);
    snprintf(p, sizeof p, "%s/%.2s", store, hex);
    mkdir(p, 0700);
    snprintf(p, sizeof p, "%s/%.2s/%s", store, hex, hex + 2);
    FILE *f = fopen(p, "wb");
    if (f == NULL) return;
    fputs(data, f);
    fclose(f);
}

/* Q6: unclaimed and stored on both sides is text; its record says how. */
TEST(a_stored_text_file_is_explained_in_its_record) {
    char store[400], hb[65], ha[65];
    snprintf(store, sizeof store, "%s/store", g_dir);
    store_put(store, "a\nb\n", hb);
    store_put(store, "a\nc\nd\n", ha);
    m_begin("before", "/s", 1000); ROOT(); E(.path = "f.txt", .type = "reg", .size = 4, .sha = hb, .stored = hb);
    E(.path = "g", .type = "reg", .size = 4, .sha = HA); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "f.txt", .type = "reg", .size = 6, .sha = ha, .stored = ha);
    E(.path = "g", .type = "reg", .size = 5, .sha = HB); m_end();
    const struct belay_diff_opts o = { .store_dir = store };
    char b[400], a[400];
    snprintf(b, sizeof b, "%s/before", g_dir);
    snprintf(a, sizeof a, "%s/after", g_dir);
    REQUIRE(belay_diff(b, a, g_out, &o, &g_st) == 0);
    FILE *f = fopen(g_out, "rb");
    REQUIRE(f != NULL);
    g_text[fread(g_text, 1, sizeof g_text - 1, f)] = '\0';
    fclose(f);
    ASSERT_TRUE(has("f.txt", "\"findings\":[{\"kind\":\"text_changed\",\"lines_added\":2,"
                             "\"lines_deleted\":1,\"first_changed_line\":2,"
                             "\"text\":\"+2 -1 lines, first change at line 2\"}]}"));
    ASSERT_FALSE(has("g", "findings"));                       /* not stored: binary declines */
}

/* Decision 2026-10-31: a changed dpkg status, diffed with no store, says so
 * on its record and as an event: never "no packages changed". */
TEST(a_changed_dpkg_status_without_a_store_is_never_no_change) {
    m_begin("before", "/s", 1000); ROOT();
    E(.path = "var", .type = "dir", .mode = 0755, .ino = 2); E(.path = "var/lib", .type = "dir", .mode = 0755, .ino = 3);
    E(.path = "var/lib/dpkg", .type = "dir", .mode = 0755, .ino = 4);
    E(.path = "var/lib/dpkg/status", .type = "reg", .size = 9, .sha = HA, .stored = HA); m_end();
    m_begin("after", "/s", 1000); ROOT();
    E(.path = "var", .type = "dir", .mode = 0755, .ino = 2); E(.path = "var/lib", .type = "dir", .mode = 0755, .ino = 3);
    E(.path = "var/lib/dpkg", .type = "dir", .mode = 0755, .ino = 4);
    E(.path = "var/lib/dpkg/status", .type = "reg", .size = 9, .sha = HB, .stored = HB); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("var/lib/dpkg/status", "{\"kind\":\"content_unavailable\",\"reason\":\"no_store\","
                                           "\"side\":\"before\""));
    ASSERT_TRUE(strstr(g_text, "{\"event\":\"content_unavailable\",\"interp\":\"dpkg\",\"reason\":\"no_store\","
                               "\"side\":\"both\",\"text\":\"content unavailable (both): no_store\","
                               "\"paths\":[\"var/lib/dpkg/status\"]}\n{\"belay_diff_end\":1,") != NULL);
    ASSERT_TRUE(strstr(g_text, ",\"events\":1,") != NULL);
}

/* R6 (audit 2026-10): every fact a manifest's header and trailer carry is
 * checked by the reader, carried into the diff, or ignored for a stated
 * reason -- this table, written by hand, against the schema's keys both
 * ways, then each carried value against a diff of two manifests that differ
 * in all of them. (Entry fields are conserved by the field pin: test_pins.) */
static const struct { const char *line, *key, *fate, *why; } FACTS[] = {
    { "header", "belay_manifest", "checked", "the reader refuses any other version" },
    { "header", "created_ns", "carried", "before_created_ns, after_created_ns" },
    { "header", "scopes", "carried", "scopes; manifests of different scopes are refused" },
    { "header", "hash", "checked", "the reader refuses any algorithm but sha256" },
    { "header", "hash_max_bytes", "carried", "before_hash_max_bytes, after_hash_max_bytes" },
    { "header", "store_max_bytes", "ignored", "which copies a capture kept, nothing about the tree" },
    { "trailer", "belay_manifest_end", "checked", "the reader counts the entries against it" },
    { "trailer", "vanished", "carried", "before_vanished, after_vanished, provisional" },
    { "trailer", "unreadable", "ignored", "each such entry carries its flag, which is compared" },
    { "trailer", "unstable", "carried", "before_unstable, after_unstable, provisional" },
    { "trailer", "mounts", "ignored", "each mount point carries its flag, which is compared" },
    { "trailer", "raced", "carried", "before_raced, after_raced, provisional" },
};

static bool in_facts(const char *line, const char *key) {
    for (size_t i = 0; i < sizeof FACTS / sizeof FACTS[0]; i++)
        if (strcmp(FACTS[i].line, line) == 0 && strcmp(FACTS[i].key, key) == 0) return true;
    return false;
}

TEST(every_manifest_fact_is_checked_carried_or_ignored_for_a_reason) {
    for (int i = 0; i < H_COUNT; i++)
        if (!in_facts("header", HEADER_FIELDS[i].name))
            BELAY_FAIL("header key %s has no fate", HEADER_FIELDS[i].name);
    for (int i = 0; i < TR_COUNT; i++)
        if (!in_facts("trailer", TRAILER_FIELDS[i].name))
            BELAY_FAIL("trailer key %s has no fate", TRAILER_FIELDS[i].name);
    for (size_t i = 0; i < sizeof FACTS / sizeof FACTS[0]; i++) {
        bool known = false;
        for (int k = 0; k < H_COUNT; k++)
            known |= strcmp(FACTS[i].line, "header") == 0 && strcmp(HEADER_FIELDS[k].name, FACTS[i].key) == 0;
        for (int k = 0; k < TR_COUNT; k++)
            known |= strcmp(FACTS[i].line, "trailer") == 0 && strcmp(TRAILER_FIELDS[k].name, FACTS[i].key) == 0;
        if (!known) BELAY_FAIL("%s key %s is not in the format", FACTS[i].line, FACTS[i].key);
    }
    g_created = 111;
    m_begin("before", "/s", 1000); ROOT(); E(.path = "r", .type = "reg", .size = 3, .sha = HA, .raced = true);
    E(.path = "u", .type = "dir", .unstable = true); g_vanished = 3; m_end();
    g_created = 222;
    m_begin("after", "/s", 2000); ROOT(); E(.path = "r", .type = "reg", .size = 3, .sha = HA);
    E(.path = "u", .type = "dir"); g_vanished = 4; m_end();
    REQUIRE(run() == 0);
    static const char *const carried[] = {
        "\"scopes\":[\"/s\"]", "\"before_created_ns\":111", "\"after_created_ns\":222",
        "\"before_hash_max_bytes\":1000", "\"after_hash_max_bytes\":2000",
        "\"before_vanished\":3,\"before_unstable\":1,\"before_raced\":1,"
        "\"after_vanished\":4,\"after_unstable\":0,\"after_raced\":0,\"provisional\":true",
    };
    for (size_t i = 0; i < sizeof carried / sizeof carried[0]; i++)
        if (strstr(g_text, carried[i]) == NULL) BELAY_FAIL("not carried: %s", carried[i]);
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

/* Decided F5 (pin O5): a directory's own timestamps move with its listing,
 * which its children's records report. A directory whose only difference is
 * its timestamps is unchanged, not emitted, and counted in the trailer; any
 * other difference or flag still gets its record, without the timestamps. */
TEST(a_directorys_own_timestamps_are_counted_never_emitted) {
    m_begin("before", "/s", 1000); ROOT();
    E(.path = "a", .type = "dir"); E(.path = "c", .type = "dir"); E(.path = "f", .type = "fifo");
    E(.path = "m", .type = "dir"); E(.path = "p", .type = "dir"); E(.path = "q", .type = "dir");
    E(.path = "s", .type = "dir"); m_end();
    m_begin("after", "/s", 1000); ROOT();
    E(.path = "a", .type = "dir", .mtime = 9, .ctime = 9);       /* a name added in it */
    E(.path = "a/x", .type = "reg", .size = 3, .sha = HA);
    E(.path = "c", .type = "dir", .ctime = 9);                   /* ctime alone */
    E(.path = "f", .type = "fifo", .mtime = 9, .ctime = 9);      /* not a directory: not counted */
    E(.path = "m", .type = "dir", .mtime = 9);                   /* mtime alone */
    E(.path = "p", .type = "dir", .mode = 0700, .ctime = 9);     /* a chmod: its record */
    E(.path = "q", .type = "dir", .ctime = 9, .unstable = true); /* a flag: unknown */
    E(.path = "s", .type = "dir"); m_end();                      /* nothing differs */
    REQUIRE(run() == 0);
    ASSERT_TRUE(record("a") == NULL && record("c") == NULL && record("m") == NULL);
    ASSERT_TRUE(record("f") == NULL && record("s") == NULL);
    ASSERT_TRUE(has("a/x", "\"outcome\":\"added\""));
    ASSERT_TRUE(has("p", "\"outcome\":\"metadata_only\",\"type\":\"dir\",\"changed\":[\"mode\"]}"));
    ASSERT_TRUE(has("q", "\"outcome\":\"unknown\",\"type\":\"dir\",\"unknown\":[\"unstable\"]}"));
    ASSERT_TRUE(strstr(g_text, "\"unchanged\":6,\"added\":1,\"removed\":0,\"modified\":0,"
                               "\"type_changed\":0,\"metadata_only\":1,\"unknown\":1,"
                               "\"dir_timestamps_only\":3,") != NULL);
    ASSERT_EQ_INT(3, (int)g_st.dir_timestamps_only);
    ASSERT_EQ_INT(6, (int)g_st.unchanged);
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

/* Decided 2026-10-30: a raced type change is unknown (rule 1), but both types
 * are known, so its record keeps the type before, as a type_changed does. */
TEST(a_raced_type_change_names_the_type_before) {
    m_begin("before", "/s", 1000); ROOT(); E(.path = "x", .type = "reg", .size = 3, .sha = HA, .has_iflags = true, .iflags = 16); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "x", .type = "lnk", .target = "t", .raced = true); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("x", "\"outcome\":\"unknown\",\"type\":\"lnk\",\"type_before\":\"reg\","
                         "\"changed\":[\"type\"],\"unknown\":[\"raced\"]}"));
    /* raced on the other side, the same */
    m_begin("before", "/s", 1000); ROOT(); E(.path = "x", .type = "reg", .size = 3, .sha = HA, .raced = true); m_end();
    m_begin("after", "/s", 1000); ROOT(); E(.path = "x", .type = "lnk", .target = "t"); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("x", "\"type_before\":\"reg\""));
    /* a raced path whose type did not change has none */
    m_begin("after", "/s", 1000); ROOT(); E(.path = "x", .type = "reg", .size = 4, .sha = HB); m_end();
    REQUIRE(run() == 0);
    ASSERT_TRUE(has("x", "\"outcome\":\"unknown\"") && !has("x", "type_before"));
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

/* Review F5 (decided 2026-10-30): a non-directory that changed after it was
 * recorded may have become a directory holding the path, so a path missing
 * below it is unknown (raced), never a definite added or removed -- either
 * way round, and however deep. Below a file that did not race, the absence
 * is still known. */
static void raced_file_side(const char *name) {
    m_begin(name, "/s", 1000); ROOT();
    E(.path = "d", .type = "reg", .size = 3, .sha = HA, .raced = true);
    E(.path = "f", .type = "reg", .size = 3, .sha = HA); m_end();
}

static void tree_side(const char *name) {
    m_begin(name, "/s", 1000); ROOT();
    E(.path = "d", .type = "dir"); E(.path = "d/e", .type = "dir");
    E(.path = "d/e/x", .type = "reg", .size = 1, .sha = HA);
    E(.path = "f", .type = "dir"); E(.path = "f/x", .type = "reg", .size = 1, .sha = HA); m_end();
}

TEST(absence_below_a_raced_non_directory_is_unknown) {
    for (int way = 0; way < 2; way++) {
        raced_file_side(way ? "after" : "before");
        tree_side(way ? "before" : "after");
        REQUIRE(run() == 0);
        ASSERT_TRUE(has("d", "\"outcome\":\"unknown\""));
        ASSERT_TRUE(has("d/e", "\"outcome\":\"unknown\",\"type\":\"dir\",\"unknown\":[\"raced\"]}"));
        ASSERT_TRUE(has("d/e/x", "\"outcome\":\"unknown\",\"type\":\"reg\",\"unknown\":[\"raced\"]}"));
        ASSERT_TRUE(has("f/x", way ? "\"outcome\":\"removed\"" : "\"outcome\":\"added\""));
    }
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
    RUN(a_mount_roots_unread_attributes_are_not_compared);
    RUN(a_mounted_file_is_unknown_for_mount_not_unverified);
    RUN(added_removed_and_modified_by_hash);
    RUN(different_hash_limits_are_unknown_unless_size_proves_a_change);
    RUN(new_inode_permissions_and_ctime_alone_are_metadata_only);
    RUN(a_directorys_own_timestamps_are_counted_never_emitted);
    RUN(type_change_names_the_type_before);
    RUN(a_raced_type_change_names_the_type_before);
    RUN(raced_is_unknown_even_when_a_field_differs);
    RUN(unknown_attributes_never_read_as_unchanged);
    RUN(absence_below_an_incomplete_or_sealed_directory_is_unknown);
    RUN(a_manifest_with_an_orphan_is_refused_with_no_output);
    RUN(a_tree_that_changed_while_walked_makes_the_diff_provisional);
    RUN(the_output_is_never_an_input_however_spelled);
    RUN(the_trailer_names_both_inputs_by_their_digest);
    RUN(an_interpreter_error_is_a_finding_never_a_failed_diff);
    RUN(a_finding_that_is_not_utf8_is_replaced);
    RUN(an_interpreter_sees_the_verdict_and_keeps_its_state_over_one_diff);
    RUN(every_manifest_fact_is_checked_carried_or_ignored_for_a_reason);
    RUN(one_paths_findings_never_reach_the_next);
    RUN(events_come_after_the_path_records_and_the_trailer_counts_them);
    RUN(a_diff_with_no_events_says_zero);
    RUN(a_failed_end_hook_is_one_event_naming_its_paths);
    RUN(a_failed_diff_ends_its_interpreters_without_a_sink);
    RUN(a_stored_text_file_is_explained_in_its_record);
    RUN(a_changed_dpkg_status_without_a_store_is_never_no_change);
    RUN(the_store_reaches_an_interpreter_through_the_options);
    RUN(different_scopes_are_refused_before_any_entry_is_read);
    RUN(a_published_output_is_success_even_where_its_directory_cannot_be_synced);
    RUN(names_sorting_before_the_root_see_its_flags);
    RUN(manifests_of_different_scopes_are_refused_with_no_output);
    RUN(an_unreadable_links_unknown_target_is_not_a_change);
    RUN(capabilities_are_not_compared_when_attributes_are_unknown);
    RUN(an_ancestor_survives_siblings_that_sort_between_it_and_its_children);
    RUN(absence_below_a_file_is_known);
    RUN(absence_below_a_raced_non_directory_is_unknown);
    RUN(no_flag_combination_on_either_side_is_unchanged);
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
