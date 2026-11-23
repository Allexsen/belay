/*
 *  The previous checkpoint's index (test/expect/capture-scale.md SC-M1,
 *  SC-M3, SC-M3a, SC-M4; src/capture/previous.h): every entry of a manifest
 *  under every name, read back as the manifest's own line; an inode trusted
 *  under one name only; an index used for the manifest whose sha256 it
 *  names and for no other; a walk leaving the index of what it wrote; and
 *  nothing of it under TMPDIR or left behind.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "capture/capture.h"
#include "capture/fsops.h"
#include "capture/previous.h"
#include "capture/serialize.h"

#include "belay/error.h"
#include "belay/manifest.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[256], g_tree[300], g_index[300], g_m1[300], g_m2[300];

static void sh(const char *fmt, ...) {
    char cmd[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    if (system(cmd) != 0) { /* the assertions say */ }
}

/* A tree of every type a user can make: directories, files (one empty, one
 * with two names), a link, a FIFO. */
static void tree(void) {
    sh("rm -rf '%s' && mkdir -p '%s/d/e' '%s/empty' && cd '%s' && printf 'one\n' > a && printf 'two\n' > d/b && "
       "printf 'three\n' > d/e/c && : > zero && ln a d/a-again && ln -s ../a d/link && mkfifo d/fifo && "
       "printf 'x\n' > 'tab\there'", g_dir, g_tree, g_tree, g_tree);
    /* past the tick the files were made in: a capture begun within it trusts none of them later (the racy rule) */
    sh("sleep 0.05");
}

static FILE *tmp_here(void *ctx) {
    (void)ctx;
    char p[400];
    snprintf(p, sizeof p, "%s/anon.XXXXXX", g_dir);
    const int fd = mkstemp(p);
    if (fd == -1) return NULL;
    unlink(p);
    return fdopen(fd, "w+b");
}

static int capture(const char *out, const char *previous, const char *index_dir, struct belay_manifest_stats *st) {
    const struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20, .store_max_bytes = 4096, .previous = previous,
                                           .index_dir = index_dir };
    return capture_write(fsops_default(), out, g_tree, &o, st);
}

/* The index of `manifest`, as a capture of g_tree loads it. */
static int load(const char *manifest, const char *index_dir, struct prev_index **p, struct prev_info *info) {
    const struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20, .store_max_bytes = 4096, .index_dir = index_dir };
    char *real = realpath(g_tree, NULL);
    const char *why = NULL;
    const int rc = prev_load(fsops_default(), manifest, real, 0, &o, tmp_here, NULL, p, info, &why);
    free(real);
    if (rc == 1) printf("      not usable: %s\n", why);
    return rc;
}

/* The names in the index directory, sorted, space-separated. */
static const char *index_names(void) {
    static char out[2048];
    char cmd[700];
    snprintf(cmd, sizeof cmd, "ls -A '%s' 2>/dev/null | LC_ALL=C sort | tr '\\n' ' '", g_index);
    FILE *f = popen(cmd, "r");
    out[0] = '\0';
    if (f != NULL) {
        if (fgets(out, sizeof out, f) == NULL) out[0] = '\0';
        pclose(f);
    }
    return out;
}

static const char *names_of(const char *manifest) {
    static char want[200];
    char sha[65];
    if (prev_file_sha256(manifest, sha) != 0) return "?";
    snprintf(want, sizeof want, "%s.paths %s.recs ", sha, sha);
    return want;
}

/* SC-M3a: every entry of the manifest, of every type and under every name,
 * is in the index, and is read from it as the manifest's line has it; the
 * records are sorted by (dev, ino, sequence) and the paths lie in the
 * manifest's order. With the index kept in a directory, and without. */
TEST(the_index_holds_every_entry_as_the_manifest_has_it) {
    for (int kept = 0; kept < 2; kept++) {
        tree();
        REQUIRE_MSG(capture(g_m1, NULL, NULL, NULL) == 0, "%s", belay_err_msg());
        struct prev_index *p = NULL;
        struct prev_info info;
        REQUIRE_MSG(load(g_m1, kept ? g_index : NULL, &p, &info) == 0, "%s", belay_err_msg());
        ASSERT_TRUE(info.built);
        struct belay_manifest_reader *rd = NULL;
        REQUIRE(belay_manifest_open(g_m1, &rd) == 0);
        static struct belay_entry e;
        size_t n = 0, types = 0;
        uint64_t last_off = 0;
        int g;
        while ((g = belay_manifest_next(rd, &e)) == 1) {
            const struct prev_rec *r = prev_find_path(p, e.path, e.path_len);
            if (r == NULL) { BELAY_FAIL("no record for %s", e.path); continue; }
            char hex[65];
            prev_hex(r, hex);
            if (r->path_len != e.path_len || memcmp(prev_path(p, r), e.path, e.path_len) != 0 || r->type != (uint16_t)e.type ||
                r->mode != e.mode || r->uid != e.uid || r->gid != e.gid || r->size != e.size || r->mtime_ns != e.mtime_ns ||
                r->ctime_ns != e.ctime_ns || r->ino != e.ino || r->dev != e.dev || r->nlink != e.nlink ||
                (e.has_hash && strcmp(hex, e.sha256_hex) != 0))
                BELAY_FAIL("%s is not read back as the manifest has it", e.path);
            if (r->seq != n) BELAY_FAIL("%s is entry %zu, its record says %llu", e.path, n, (unsigned long long)r->seq);
            if (n > 0 && r->path_off <= last_off) BELAY_FAIL("the path of %s does not follow the one before it", e.path);
            last_off = r->path_off;
            types |= 1u << e.type;
            n++;
        }
        ASSERT_EQ_INT(0, g);
        belay_manifest_close(rd);
        ASSERT_EQ_INT((int)n, (int)prev_count(p));
        ASSERT_TRUE(n == 12);                                    /* the root and eleven below it */
        ASSERT_TRUE((types & (1u << BELAY_T_DIR)) && (types & (1u << BELAY_T_REG)) && (types & (1u << BELAY_T_LNK)) &&
                    (types & (1u << BELAY_T_FIFO)));
        for (size_t i = 1; i < prev_count(p); i++) {
            const struct prev_rec *a = prev_at(p, i - 1), *b = prev_at(p, i);
            const bool up = a->dev < b->dev || (a->dev == b->dev && (a->ino < b->ino || (a->ino == b->ino && a->seq < b->seq)));
            if (!up) BELAY_FAIL("record %zu does not sort after record %zu", i, i - 1);
        }
        ASSERT_TRUE(prev_find_path(p, "d/nothing", 9) == NULL && prev_find_path(p, "", 0) == NULL &&
                    prev_find_path(p, "zzz", 3) == NULL && prev_find_path(p, "d/", 2) == NULL);
        prev_free(p);
    }
}

/* SC-M4: the entry a file may be trusted by is the regular file's own, with
 * its hash; an inode with two names is trusted by neither; nothing that is
 * not a regular file is. */
TEST(an_inode_is_trusted_under_one_name_only) {
    tree();
    REQUIRE(capture(g_m1, NULL, NULL, NULL) == 0);
    struct prev_index *p = NULL;
    struct prev_info info;
    REQUIRE(load(g_m1, NULL, &p, &info) == 0);
    static const struct { const char *rel; bool trusted; } F[] = {
        { "d/b", true }, { "d/e/c", true }, { "zero", true }, { "tab\there", true },
        { "a", false }, { "d/a-again", false },                 /* one inode, two names */
        { "d", false }, { "d/link", false }, { "d/fifo", false }, { ".", false },
    };
    for (size_t i = 0; i < sizeof F / sizeof F[0]; i++) {
        char path[700];
        struct stat st;
        snprintf(path, sizeof path, "%s/%s", g_tree, F[i].rel);
        REQUIRE(lstat(path, &st) == 0);
        const struct prev_rec *r = prev_find(p, (uint64_t)st.st_dev, (uint64_t)st.st_ino);
        if ((r != NULL) != F[i].trusted) BELAY_FAIL("%s: %s", F[i].rel, r != NULL ? "a record to trust" : "none");
        if (r != NULL && !prev_trusted(r, &st, INT64_MAX)) BELAY_FAIL("%s: its record is not its stat", F[i].rel);
        if (r != NULL && prev_trusted(r, &st, r->ctime_ns)) BELAY_FAIL("%s: trusted at its own ctime", F[i].rel);
        if (r != NULL && (r->path_len != strlen(F[i].rel) || memcmp(prev_path(p, r), F[i].rel, r->path_len) != 0))
            BELAY_FAIL("%s: found under another path", F[i].rel);
    }
    ASSERT_EQ_INT(6, (int)info.files);                           /* the two names of one inode are files too */
    ASSERT_TRUE(prev_find(p, 0, 0) == NULL && prev_find(p, UINT64_MAX, UINT64_MAX) == NULL);
    prev_free(p);
    /* and so the capture: four files not read again, the pair read */
    struct belay_manifest_stats st;
    sh("sleep 0.05");
    REQUIRE(capture(g_m2, g_m1, NULL, &st) == 0);
    ASSERT_TRUE(st.prefilter);
    ASSERT_EQ_INT(4, (int)st.trusted);
}

/* V5-E7, V5-A2: an entry the manifest names racy is never trusted, and its
 * neighbours are. Racy lines are an event capture's, so the manifest is
 * written by hand. */
TEST(an_entry_named_racy_is_never_trusted) {
    sh("rm -rf '%s' && mkdir -p '%s'", g_dir, g_tree);
    char *real = realpath(g_tree, NULL);
    REQUIRE(real != NULL);
    FILE *f = fopen(g_m1, "wb");
    REQUIRE(f != NULL);
#define SHA "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define REG(p, ino) "{\"path\":\"" p "\",\"type\":\"reg\",\"mode\":33188,\"uid\":0,\"gid\":0,\"size\":0,\"mtime_ns\":1500000001," \
    "\"ctime_ns\":1500000001,\"ino\":" ino ",\"dev\":1,\"nlink\":1,\"sha256\":\"" SHA "\"}\n"
    fprintf(f, "{\"belay_manifest\":5,\"created_ns\":0,\"scopes\":[\"%s\"],\"hash\":\"sha256\",\"hash_max_bytes\":1048576,"
               "\"store_max_bytes\":4096,\"excluded\":[],\"walk_start_ns\":2000000000,\"source\":null,\"roots\":0,"
               "\"basis\":\"events\"}\n", real);
    fputs("{\"path\":\".\",\"type\":\"dir\",\"mode\":16877,\"uid\":0,\"gid\":0,\"size\":1,\"mtime_ns\":1500000001,"
          "\"ctime_ns\":1500000001,\"ino\":2,\"dev\":1,\"nlink\":2}\n" REG("a", "3") REG("b", "4") REG("c", "5")
          "{\"racy\":\"b\"}\n"
          "{\"belay_manifest_end\":4,\"vanished\":0,\"unreadable\":0,\"unstable\":0,\"mounts\":0,\"raced\":0,\"trusted\":0,"
          "\"reference\":\"none\",\"read_all\":\"check\",\"writer_open\":0,\"unguarded\":0,\"not_read\":0,\"meta\":0,"
          "\"sealed\":0,\"carried\":0,\"racy\":1}\n", f);
    fclose(f);
    free(real);
    for (int kept = 0; kept < 2; kept++) {
        struct prev_index *p = NULL;
        struct prev_info info;
        REQUIRE_MSG(load(g_m1, kept ? g_index : NULL, &p, &info) == 0, "%s", belay_err_msg());
        ASSERT_TRUE(prev_find(p, 1, 3) != NULL && prev_find(p, 1, 5) != NULL);
        ASSERT_TRUE(prev_find(p, 1, 4) == NULL);
        ASSERT_TRUE(prev_find_path(p, "b", 1) != NULL);         /* it is in the index all the same */
        prev_free(p);
    }
    /* and from the index as it was kept */
    struct prev_index *p = NULL;
    struct prev_info info;
    REQUIRE(load(g_m1, g_index, &p, &info) == 0);
    ASSERT_TRUE(!info.built && prev_find(p, 1, 4) == NULL && prev_find(p, 1, 3) != NULL);
    prev_free(p);
}

/* SC-M3a: an index names the sha256 of the manifest it stands for, and is
 * used only for that manifest; for any other it is made again, in its
 * place. A file that is not an index is made again too. */
TEST(an_index_is_used_only_for_the_manifest_it_names) {
    tree();
    REQUIRE(capture(g_m1, NULL, NULL, NULL) == 0);
    struct prev_index *p = NULL;
    struct prev_info info;
    REQUIRE(load(g_m1, g_index, &p, &info) == 0);
    ASSERT_TRUE(info.built);
    prev_free(p);
    ASSERT_EQ_STR(names_of(g_m1), index_names());
    REQUIRE(load(g_m1, g_index, &p, &info) == 0);
    ASSERT_TRUE(!info.built);                                   /* kept: not built again */
    ASSERT_EQ_INT(12, (int)prev_count(p));
    prev_free(p);
    char sha1[65];
    REQUIRE(prev_file_sha256(g_m1, sha1) == 0);
    sh("cp '%s/%s.recs' '%s/first.recs' && cp '%s/%s.paths' '%s/first.paths'", g_index, sha1, g_dir, g_index, sha1, g_dir);

    /* another manifest: its own index, and the other's is gone */
    sh("printf 'more\n' > '%s/new' && rm '%s/zero'", g_tree, g_tree);
    REQUIRE(capture(g_m2, NULL, NULL, NULL) == 0);
    REQUIRE(load(g_m2, g_index, &p, &info) == 0);
    ASSERT_TRUE(info.built);
    ASSERT_TRUE(prev_find_path(p, "new", 3) != NULL && prev_find_path(p, "zero", 4) == NULL);
    prev_free(p);
    ASSERT_EQ_STR(names_of(g_m2), index_names());
    ASSERT_TRUE(strcmp(names_of(g_m1), index_names()) != 0);

    /* what is there under the right name but is no index of it */
    static const char *const SPOIL[] = {
        ": > '%s/%s.recs'",                                                         /* empty */
        "printf 'x' >> '%s/%s.recs'",                                               /* a byte too long */
        "printf 'belayix0' | dd of='%s/%s.recs' conv=notrunc 2>/dev/null",          /* another version */
        "rm '%s/%s.paths'",
        "printf 'x' >> '%s/%s.paths'",
        "dd if=/dev/zero of='%s/%s.recs' bs=1 seek=60 count=8 conv=notrunc 2>/dev/null",    /* its sha256 is another's */
    };
    char sha[65];
    REQUIRE(prev_file_sha256(g_m2, sha) == 0);
    /* a whole index, of the first manifest, under the second's name: what it says it stands for decides */
    sh("cp '%s/first.recs' '%s/%s.recs' && cp '%s/first.paths' '%s/%s.paths'", g_dir, g_index, sha, g_dir, g_index, sha);
    REQUIRE_MSG(load(g_m2, g_index, &p, &info) == 0, "%s", belay_err_msg());
    ASSERT_TRUE(info.built);
    ASSERT_TRUE(prev_find_path(p, "new", 3) != NULL && prev_find_path(p, "zero", 4) == NULL);
    prev_free(p);
    for (size_t i = 0; i < sizeof SPOIL / sizeof SPOIL[0]; i++) {
        sh(SPOIL[i], g_index, sha);
        REQUIRE_MSG(load(g_m2, g_index, &p, &info) == 0, "%s", belay_err_msg());
        if (!info.built) BELAY_FAIL("used as it was after: %s", SPOIL[i]);
        ASSERT_TRUE(prev_find_path(p, "new", 3) != NULL);
        prev_free(p);
        ASSERT_EQ_STR(names_of(g_m2), index_names());
        REQUIRE(load(g_m2, g_index, &p, &info) == 0);
        ASSERT_TRUE(!info.built);
        prev_free(p);
    }
}

/* SC-M3: a walk leaves the index of the manifest it wrote, so the next
 * capture builds none; the index is a file of that directory and nothing
 * of it is made under TMPDIR; what a killed run left there is removed. */
TEST(a_walk_leaves_the_index_of_what_it_wrote) {
    tree();
    char *old = getenv("TMPDIR") != NULL ? strdup(getenv("TMPDIR")) : NULL;
    char gone[400];
    snprintf(gone, sizeof gone, "%s/no-such-directory", g_dir);
    setenv("TMPDIR", gone, 1);
    sh("mkdir -p '%s' && printf 'half' > '%s/tmp.999999999.recs' && printf 'old' > '%s/%064d.paths'", g_index, g_index, g_index, 0);
    struct belay_manifest_stats st;
    const int first = capture(g_m1, NULL, g_index, &st);
    char after_first[400];
    snprintf(after_first, sizeof after_first, "%s", index_names());
    sh("sleep 0.05");
    const int second = capture(g_m2, g_m1, g_index, &st);
    if (old != NULL) setenv("TMPDIR", old, 1); else unsetenv("TMPDIR");
    free(old);
    REQUIRE_MSG(first == 0 && second == 0, "%s", belay_err_msg());
    ASSERT_EQ_STR(names_of(g_m1), after_first);
    ASSERT_TRUE(st.prefilter);
    ASSERT_EQ_INT(4, (int)st.trusted);
    ASSERT_EQ_STR(names_of(g_m2), index_names());               /* the newest manifest's, and only it */
    struct prev_index *p = NULL;
    struct prev_info info;
    REQUIRE(load(g_m2, g_index, &p, &info) == 0);
    ASSERT_TRUE(!info.built);
    ASSERT_EQ_INT(12, (int)prev_count(p));
    prev_free(p);
    /* without a directory a capture leaves no index anywhere */
    sh("rm -rf '%s'", g_index);
    REQUIRE(capture(g_m1, g_m2, NULL, &st) == 0);
    ASSERT_TRUE(st.prefilter);
    ASSERT_EQ_STR("", index_names());
}

/* SC-M1: nothing about its size makes a previous manifest unusable. 60,000
 * entries written by hand (the old index stopped at 64 MiB; the bound
 * itself is make scale-test's): each inode found, the last path found. */
TEST(a_large_manifest_is_indexed_within_the_sort_budget) {
    sh("rm -rf '%s' && mkdir -p '%s'", g_dir, g_tree);
    char *real = realpath(g_tree, NULL);
    REQUIRE(real != NULL);
    FILE *f = fopen(g_m1, "wb");
    REQUIRE(f != NULL);
    fprintf(f, "{\"belay_manifest\":5,\"created_ns\":0,\"scopes\":[\"%s\"],\"hash\":\"sha256\",\"hash_max_bytes\":1048576,"
               "\"store_max_bytes\":4096,\"excluded\":[],\"walk_start_ns\":2000000000,\"source\":null,\"roots\":0,"
               "\"basis\":\"walk\"}\n", real);
    fputs("{\"path\":\".\",\"type\":\"dir\",\"mode\":16877,\"uid\":0,\"gid\":0,\"size\":1,\"mtime_ns\":1500000001,"
          "\"ctime_ns\":1500000001,\"ino\":2,\"dev\":1,\"nlink\":2}\n", f);
    const int N = 60000;
    for (int i = 0; i < N; i++)        /* inode numbers running against the paths' order */
        fprintf(f, "{\"path\":\"f%06d\",\"type\":\"reg\",\"mode\":33188,\"uid\":0,\"gid\":0,\"size\":%d,\"mtime_ns\":1500000001,"
                   "\"ctime_ns\":1500000001,\"ino\":%d,\"dev\":1,\"nlink\":1,\"sha256\":\"%064x\"}\n", i, i, 1000000 - i, i);
    fprintf(f, "{\"belay_manifest_end\":%d,\"vanished\":0,\"unreadable\":0,\"unstable\":0,\"mounts\":0,\"raced\":0,\"trusted\":0,"
               "\"reference\":\"none\",\"read_all\":\"check\",\"writer_open\":0,\"unguarded\":0,\"not_read\":0,\"meta\":0,"
               "\"sealed\":0,\"carried\":0,\"racy\":0}\n", N + 1);
    fclose(f);
    const struct belay_manifest_opts o = { .hash_max_bytes = 1u << 20, .store_max_bytes = 4096, .index_dir = g_index,
                                           .run_bytes = 256 * 1024 };      /* many runs, merged */
    struct prev_index *p = NULL;
    struct prev_info info;
    const char *why = NULL;
    REQUIRE_MSG(prev_load(fsops_default(), g_m1, real, 0, &o, tmp_here, NULL, &p, &info, &why) == 0, "%s", why ? why : belay_err_msg());
    free(real);
    ASSERT_EQ_INT(N + 1, (int)prev_count(p));
    ASSERT_EQ_INT(N, (int)info.files);
    for (int i = 0; i < N; i += 997) {
        const struct prev_rec *r = prev_find(p, 1, (uint64_t)(1000000 - i));
        char want[16], hex[65], sha[65];
        snprintf(want, sizeof want, "f%06d", i);
        snprintf(sha, sizeof sha, "%064x", i);
        if (r == NULL || r->size != (uint64_t)i || memcmp(prev_path(p, r), want, 7) != 0) { BELAY_FAIL("inode of %s", want); continue; }
        prev_hex(r, hex);
        ASSERT_EQ_STR(sha, hex);
        ASSERT_TRUE(prev_find_path(p, want, 7) == r);
    }
    ASSERT_TRUE(prev_find_path(p, "f059999", 7) != NULL && prev_find_path(p, "f060000", 7) == NULL);
    prev_free(p);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_previous_%d", (int)getpid());
    snprintf(g_tree, sizeof g_tree, "%s/tree", g_dir);
    snprintf(g_index, sizeof g_index, "%s/index", g_dir);
    snprintf(g_m1, sizeof g_m1, "%s/m1", g_dir);
    snprintf(g_m2, sizeof g_m2, "%s/m2", g_dir);
    RUN(the_index_holds_every_entry_as_the_manifest_has_it);
    RUN(an_inode_is_trusted_under_one_name_only);
    RUN(an_entry_named_racy_is_never_trusted);
    RUN(an_index_is_used_only_for_the_manifest_it_names);
    RUN(a_walk_leaves_the_index_of_what_it_wrote);
    RUN(a_large_manifest_is_indexed_within_the_sort_budget);
    sh("rm -rf '%s'", g_dir);
    return belay_test_report();
}
