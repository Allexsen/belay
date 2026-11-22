/*
 *  Lookups and ownership (test/expect/system-interpreters.md SI-4, SI-5)
 *  and the order of the interpreters' events (SI-1, diff-events E13).
 *  The dpkg fixtures are the shapes the pin's "how established" cell gives:
 *  `nginx-common.list` naming `/lib/systemd/system/nginx.service` (22.04)
 *  or `/usr/lib/systemd/system/nginx.service` (24.04), `coreutils.list`
 *  naming `/bin/cat`, and `diversions` with three lines a diversion.
 */
#include "sys_test.h"

#include "diff/diff_run.h"

#define INFO "var/lib/dpkg/info"

/* Entries of an after-manifest, in path order, with their copies. */
static struct belay_entry E[64];
static size_t NE;
static void e_reset(void) { NE = 0; }
static void e_dir(const char *path) { E[NE++] = t_entry(path, BELAY_T_DIR, 0755, NULL); }
static void e_file(const char *path, const char *text) { E[NE++] = t_entry(path, BELAY_T_REG, 0644, t_put(text)); }

static struct belay_content *g_c;

/* Asks `paths`, feeds E, and answers as "path=owner" lines: `-` for
 * absent, `null` for none. */
static const char *owners_answer(const char *const *paths, size_t n) {
    static char out[4096];
    struct owners *o = owners_new();
    size_t w = 0;
    out[0] = '\0';
    if (o == NULL) return "(no memory)";
    for (size_t i = 0; i < n; i++) owners_ask(o, paths[i], strlen(paths[i]));
    for (size_t i = 0; i < NE; i++) owners_feed(o, &E[i], g_c);
    owners_done(o);
    for (size_t i = 0; i < n; i++) {
        const char *pkg = "";
        size_t pl = 0;
        const enum belay_owned r = owners_get(o, paths[i], strlen(paths[i]), &pkg, &pl);
        w += (size_t)snprintf(out + w, sizeof out - w, "%s=%.*s\n", paths[i],
                              r == BELAY_OWNER_PACKAGE ? (int)pl : r == BELAY_OWNER_NONE ? 4 : 1,
                              r == BELAY_OWNER_PACKAGE ? pkg : r == BELAY_OWNER_NONE ? "null" : "-");
    }
    owners_free(o);
    return out;
}
#define ASK(...) owners_answer((const char *const[]){ __VA_ARGS__ }, sizeof((const char *const[]){ __VA_ARGS__ }) / sizeof(char *))

TEST(owner_is_the_package_whose_list_names_the_path) {
    e_reset();
    e_file("var/lib/dpkg/diversions", "");
    e_dir(INFO);
    e_file(INFO "/coreutils.list", "/.\n/usr\n/usr/bin\n/usr/bin/ls\n/usr/share/doc/coreutils/README\n");
    e_file(INFO "/nginx-common.list", "/.\n/etc/nginx\n/etc/nginx/nginx.conf\n");
    ASSERT_EQ_STR("etc/nginx/nginx.conf=nginx-common\nusr/bin/ls=coreutils\netc/cron.d/site=null\n",
                  ASK("etc/nginx/nginx.conf", "usr/bin/ls", "etc/cron.d/site"));
    /* A name that only begins like a listed one is not it, nor is a listed
     * path's prefix. */
    ASSERT_EQ_STR("usr/bin/l=null\nusr/bin/lsx=null\n", ASK("usr/bin/l", "usr/bin/lsx"));
}

/* SI-5: the top-level links rewritten each way. 22.04's lists say /lib and
 * /bin where the capture records usr/lib and usr/bin; and a path recorded
 * under lib (a directory there) is found in a list that says /usr/lib. */
TEST(owner_tries_the_top_level_links_both_ways) {
    e_reset();
    e_dir(INFO);
    e_file(INFO "/coreutils.list", "/bin/cat\n");
    e_file(INFO "/nginx-common.list", "/lib/systemd/system/nginx.service\n");
    ASSERT_EQ_STR("usr/lib/systemd/system/nginx.service=nginx-common\nusr/bin/cat=coreutils\n"
                  "lib/systemd/system/nginx.service=nginx-common\n",
                  ASK("usr/lib/systemd/system/nginx.service", "usr/bin/cat", "lib/systemd/system/nginx.service"));
    e_reset();
    e_dir(INFO);
    e_file(INFO "/libx.list", "/usr/lib64/libx.so\n/usr/libx32/a\n/usr/lib32/b\n/usr/sbin/c\n");
    e_file(INFO "/nginx-common.list", "/usr/lib/systemd/system/nginx.service\n");
    ASSERT_EQ_STR("lib/systemd/system/nginx.service=nginx-common\nlib64/libx.so=libx\nlibx32/a=libx\n"
                  "lib32/b=libx\nsbin/c=libx\n",
                  ASK("lib/systemd/system/nginx.service", "lib64/libx.so", "libx32/a", "lib32/b", "sbin/c"));
    /* Only those six names, and only at the top. */
    e_reset();
    e_dir(INFO);
    e_file(INFO "/p.list", "/share/x\n/usr/local/bin/y\n/opt/usr/bin/z\n");
    ASSERT_EQ_STR("usr/share/x=null\nlocal/bin/y=null\nopt/bin/z=null\n",
                  ASK("usr/share/x", "local/bin/y", "opt/bin/z"));
}

TEST(owner_is_absent_without_a_dpkg_database_and_null_with_one) {
    e_reset();
    e_file("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    ASSERT_EQ_STR("etc/cron.d/site=-\n", ASK("etc/cron.d/site"));
    /* The directory there, and no list: in no package. */
    e_reset();
    e_dir(INFO);
    ASSERT_EQ_STR("etc/cron.d/site=null\n", ASK("etc/cron.d/site"));
    /* A directory nothing was seen below is no database. */
    e_reset();
    e_dir(INFO);
    E[0].not_read = true;
    ASSERT_EQ_STR("etc/cron.d/site=-\n", ASK("etc/cron.d/site"));
    e_reset();
    e_dir(INFO);
    E[0].unreadable = true;
    ASSERT_EQ_STR("etc/cron.d/site=-\n", ASK("etc/cron.d/site"));
}

/* dpkg-divert(1): the file of every package but the diverting one is at
 * the second line's path; the first line's path is the diverting package's
 * own, when it has one. `:` is a local diversion: nobody's. */
TEST(owner_applies_diversions) {
    e_reset();
    e_file("var/lib/dpkg/diversions", "/usr/bin/foo\n/usr/bin/foo.distrib\npkgb\n"
                                      "/usr/bin/x\n/usr/bin/x.real\n:\n");
    e_dir(INFO);
    e_file(INFO "/pkga.list", "/usr/bin/foo\n");
    e_file(INFO "/pkgb.list", "/usr/bin/foo\n");
    e_file(INFO "/pkgc.list", "/usr/bin/x\n");
    ASSERT_EQ_STR("usr/bin/foo=pkgb\nusr/bin/foo.distrib=pkga\nusr/bin/x=null\nusr/bin/x.real=pkgc\n",
                  ASK("usr/bin/foo", "usr/bin/foo.distrib", "usr/bin/x", "usr/bin/x.real"));
    /* The diverting package's list may carry an architecture. */
    e_reset();
    e_file("var/lib/dpkg/diversions", "/usr/bin/foo\n/usr/bin/foo.distrib\npkgb\n");
    e_dir(INFO);
    e_file(INFO "/pkga:amd64.list", "/usr/bin/foo\n");
    e_file(INFO "/pkgb:amd64.list", "/usr/bin/foo\n");
    ASSERT_EQ_STR("usr/bin/foo=pkgb:amd64\nusr/bin/foo.distrib=pkga:amd64\n", ASK("usr/bin/foo", "usr/bin/foo.distrib"));
    /* A diversions file that is not three lines a diversion says nothing
     * that can be relied on: what no list names is not known to be nobody's. */
    e_reset();
    e_file("var/lib/dpkg/diversions", "/usr/bin/foo\n/usr/bin/foo.distrib\n");
    e_dir(INFO);
    e_file(INFO "/pkga.list", "/usr/bin/bar\n");
    ASSERT_EQ_STR("usr/bin/bar=pkga\nusr/bin/zed=-\n", ASK("usr/bin/bar", "usr/bin/zed"));
}

TEST(owner_of_a_path_several_lists_name_is_the_first_in_byte_order) {
    e_reset();
    e_dir(INFO);
    e_file(INFO "/libc6:amd64.list", "/usr/share/doc/libc6\n/usr/share/doc/libc6/copyright\n");
    e_file(INFO "/libc6:i386.list", "/usr/share/doc/libc6\n/usr/share/doc/libc6/copyright\n");
    ASSERT_EQ_STR("usr/share/doc/libc6/copyright=libc6:amd64\n", ASK("usr/share/doc/libc6/copyright"));
}

/* Never assumed: with a list that could not be read, a path no other list
 * names is not "in no package" -- nothing is known of it. */
TEST(owner_with_a_list_that_cannot_be_read_is_absent_unless_found) {
    e_reset();
    e_dir(INFO);
    e_file(INFO "/a.list", "/usr/bin/a\n");
    E[NE++] = t_entry(INFO "/b.list", BELAY_T_REG, 0644, NULL);               /* no copy kept */
    ASSERT_EQ_STR("usr/bin/a=a\nusr/bin/b=-\n", ASK("usr/bin/a", "usr/bin/b"));
    e_reset();
    e_dir(INFO);
    e_file(INFO "/a.list", "/usr/bin/a\n");
    E[NE++] = t_entry(INFO "/b.list", BELAY_T_REG, 0644,
                      "0000000000000000000000000000000000000000000000000000000000000000");  /* gone from the store */
    ASSERT_EQ_STR("usr/bin/a=a\nusr/bin/b=-\n", ASK("usr/bin/a", "usr/bin/b"));
    /* What is not a list is not read: md5sums, a directory, a list deeper. */
    e_reset();
    e_dir(INFO);
    e_file(INFO "/a.list", "/usr/bin/a\n");
    e_file(INFO "/a.md5sums", "/usr/bin/b\n");
    e_dir(INFO "/sub");
    e_file(INFO "/sub/c.list", "/usr/bin/b\n");
    E[NE++] = t_entry(INFO "/x.list", BELAY_T_LNK, 0777, NULL);                /* a link named like a list */
    ASSERT_EQ_STR("usr/bin/a=a\nusr/bin/b=-\n", ASK("usr/bin/a", "usr/bin/b"));
}

/* Lists are written by the watched machine: NUL bytes, CRLF, a last line
 * without its newline, a very long line, 100,000 lines. */
TEST(owner_reads_hostile_lists) {
    e_reset();
    e_dir(INFO);
    E[NE++] = t_entry(INFO "/a.list", BELAY_T_REG, 0644, t_put_n("/usr/bin/a\0b\n/usr/bin/c\n", 23));
    e_file(INFO "/b.list", "/usr/bin/crlf\r\n/usr/bin/last");
    ASSERT_EQ_STR("usr/bin/a=null\nusr/bin/c=a\nusr/bin/crlf=null\nusr/bin/last=b\n",
                  ASK("usr/bin/a", "usr/bin/c", "usr/bin/crlf", "usr/bin/last"));
    static char big[2300000];
    size_t w = 0;
    memset(big, 'x', 70000);
    big[0] = '/';
    w = 70000;
    big[w++] = '\n';
    for (int i = 0; i < 100000; i++) w += (size_t)snprintf(big + w, sizeof big - w, "/usr/share/f/%d\n", i);
    e_reset();
    e_dir(INFO);
    e_file(INFO "/big.list", big);
    ASSERT_EQ_STR("usr/share/f/99999=big\nusr/share/f/100000=null\n", ASK("usr/share/f/99999", "usr/share/f/100000"));
}

/* Bounded by what is asked: a path asked twice is one, and asking nothing
 * reads no list (a list without a copy would make every answer absent). */
TEST(owner_asks_are_a_set) {
    e_reset();
    e_dir(INFO);
    e_file(INFO "/a.list", "/usr/bin/a\n");
    ASSERT_EQ_STR("usr/bin/a=a\nusr/bin/a=a\n", ASK("usr/bin/a", "usr/bin/a"));
    struct owners *o = owners_new();
    REQUIRE(o != NULL);
    const char *pkg;
    size_t pl;
    owners_done(o);
    ASSERT_EQ_INT(BELAY_OWNER_ABSENT, owners_get(o, "usr/bin/never-asked", 19, &pkg, &pl));
    owners_free(o);
}

/* ---- through the diff: a test interpreter in pip's place ---- */

struct probe { struct belay_lookup *lk; int round; char defs[64], target[128]; int below; bool link_seen; };
static struct probe P;

static void *p_begin(void) { memset(&P, 0, sizeof P); return &P; }
static enum belay_interp_result p_explain(void *s, const struct belay_interp_input *in, struct belay_findings *out) {
    (void)s; (void)in; (void)out;
    return BELAY_INTERP_DECLINE;
}
static int p_defs(void *ctx, const struct belay_entry *e) {
    struct probe *p = ctx;
    unsigned char *buf;
    size_t len;
    if (!e->has_stored || belay_content_get(belay_lookup_content(p->lk), e->stored_hex, 4096, &buf, &len) != 0) return 0;
    snprintf(p->defs, sizeof p->defs, "%.*s", (int)(len && buf[len - 1] == '\n' ? len - 1 : len), (const char *)buf);
    free(buf);
    return 0;
}
static int p_link(void *ctx, const struct belay_entry *e) {
    struct probe *p = ctx;
    p->link_seen = true;
    if (e->type == BELAY_T_LNK) snprintf(p->target, sizeof p->target, "%.*s", (int)e->link_target_len, e->link_target);
    return 0;
}
static int p_count(void *ctx, const struct belay_entry *e) { (void)e; ((struct probe *)ctx)->below++; return 0; }
static enum belay_interp_result p_prepare(void *s, struct belay_lookup *lk) {
    struct probe *p = s;
    p->lk = lk;
    p->round++;
    if (p->round == 1) {
        /* A path nobody claims, one that did not change, and one not there. */
        if (belay_lookup_want(lk, "etc/login.defs", 14, false, p_defs, p) ||
            belay_lookup_want(lk, "etc/ssl/certs/a.pem", 19, false, p_link, p) ||
            belay_lookup_want(lk, "etc/absent", 10, false, p_count, p) ||
            belay_lookup_want(lk, "etc/cron.d", 10, true, p_count, p))
            return BELAY_INTERP_ERROR;
    } else if (p->round == 2 && p->target[0]) {
        /* A second round, from what the first found: the link's target. */
        if (belay_owner_ask(lk, p->target + 1, strlen(p->target + 1)) || belay_owner_ask(lk, "etc/login.defs", 14))
            return BELAY_INTERP_ERROR;
    }
    return BELAY_INTERP_FINDINGS;
}
static enum belay_interp_result p_end(void *s, struct belay_events *ev) {
    struct probe *p = s;
    if (ev == NULL) return BELAY_INTERP_FINDINGS;
    const char *pkg = "?", *path = "etc/login.defs";
    size_t pl = 1, pathl = 14;
    char below[32];
    const enum belay_owned o = belay_owner_of(p->lk, p->target + 1, strlen(p->target + 1), &pkg, &pl);
    const enum belay_owned o2 = belay_owner_of(p->lk, "etc/login.defs", 14, NULL, NULL);
    snprintf(below, sizeof below, "%d/%d/%d", p->below, p->round, (int)o2);
    const struct belay_fv v[] = { { .s = p->defs, .len = strlen(p->defs) },
                                  { .s = o == BELAY_OWNER_PACKAGE ? pkg : below, .len = o == BELAY_OWNER_PACKAGE ? pl : 1 } };
    const struct belay_fv v2[] = { { .s = p->target, .len = strlen(p->target) }, { .s = below, .len = strlen(below) } };
    belay_event(ev, FK_PIP_INSTALLED, v, 2, &path, &pathl, 1, 0);
    belay_event(ev, FK_PIP_REMOVED, v2, 2, &path, &pathl, 1, 0);
    return BELAY_INTERP_FINDINGS;
}

static const char *probe_diff(void) {
    char ma[400], mb[400], d[400], store[400];
    snprintf(ma, sizeof ma, "%s/m1", g_dir);
    snprintf(mb, sizeof mb, "%s/m2", g_dir);
    snprintf(d, sizeof d, "%s/d", g_dir);
    snprintf(store, sizeof store, "%s/store", g_dir);
    const struct belay_interp t = { BELAY_INTERP_PIP, p_begin, p_explain, p_end, p_prepare };
    const struct belay_interp *table[BELAY_INTERP_COUNT];
    for (int i = 0; i < BELAY_INTERP_COUNT; i++) table[i] = belay_interp_builtin((enum belay_interp_id)i);
    table[BELAY_INTERP_PIP] = &t;
    const struct belay_diff_opts o = { .store_dir = store };
    free(g_text);
    g_text = NULL;
    if (diff_run(ma, mb, d, &o, NULL, table) != 0) {
        BELAY_FAIL("diff: %s", belay_err_msg());
        belay_err_clear();
        return "";
    }
    g_text = t_slurp(d);
    return g_text ? g_text : "";
}

/* SI-4: at its end an interpreter reads the entry and the kept copy of a
 * path of the after-manifest it does not claim and that did not change;
 * what it learns there it may ask about in a further round; and the
 * owner asked is answered from the same manifest's dpkg database. */
TEST(an_interpreter_reads_paths_it_was_not_given_and_asks_their_owner) {
    t_reset();
    t_file("etc/login.defs", "UID_MIN 1000\n", 0644);
    t_link("etc/ssl/certs/a.pem", "/usr/share/ca-certificates/mozilla/a.crt");
    t_file("etc/cron.d/one", "x\n", 0644);
    t_file("etc/cron.d/two", "x\n", 0644);
    t_file("etc/cron.daily/not-below-cron.d", "x\n", 0755);
    t_file("usr/share/ca-certificates/mozilla/a.crt", "cert\n", 0644);
    t_file("var/lib/dpkg/diversions", "", 0644);
    t_file(INFO "/ca-certificates.list", "/usr/share/ca-certificates/mozilla/a.crt\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/motd", "changed\n", 0644);
    REQUIRE(t_snap(2) == 0);
    const char *d = probe_diff();
    ASSERT_TRUE(strstr(d, "{\"event\":\"pip_installed\",\"interp\":\"pip\",\"name\":\"UID_MIN 1000\","
                          "\"version\":\"ca-certificates\",\"text\":\"installed UID_MIN 1000 ca-certificates\","
                          "\"paths\":[\"etc/login.defs\"]}\n") != NULL);
    /* The directory's two entries were delivered, the absent path was not;
     * the hook ran twice (its second round asked for no entry); login.defs is in no
     * package (BELAY_OWNER_NONE is 1). */
    ASSERT_TRUE(strstr(d, "\"name\":\"/usr/share/ca-certificates/mozilla/a.crt\",\"version\":\"2/2/1\"") != NULL);
    ASSERT_TRUE(P.link_seen);
    /* The diff is whole: its trailer follows the events and names both manifests. */
    ASSERT_TRUE(strstr(d, "\"events\":2") != NULL);
    ASSERT_TRUE(strstr(d, "\"after_sha256\":\"") != NULL);
}

static enum belay_interp_result p_prepare_fails(void *s, struct belay_lookup *lk) {
    (void)s; (void)lk;
    return BELAY_INTERP_ERROR;
}
static enum belay_interp_result p_claims(void *s, const struct belay_interp_input *in, struct belay_findings *out) {
    (void)s; (void)in; (void)out;
    return BELAY_INTERP_FINDINGS;
}

/* A prepare hook that fails is an end hook that fails (E6): one
 * could_not_interpret naming what the interpreter was given, and the diff
 * stands. */
TEST(a_failed_prepare_is_one_could_not_interpret_and_the_diff_stands) {
    t_reset();
    t_file("lib/x-1.0.dist-info/RECORD", "a,,\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("lib/x-1.0.dist-info/RECORD", "b,,\n", 0644);
    REQUIRE(t_snap(2) == 0);
    char ma[400], mb[400], d[400];
    snprintf(ma, sizeof ma, "%s/m1", g_dir);
    snprintf(mb, sizeof mb, "%s/m2", g_dir);
    snprintf(d, sizeof d, "%s/d", g_dir);
    const struct belay_interp t = { BELAY_INTERP_PIP, p_begin, p_claims, p_end, p_prepare_fails };
    const struct belay_interp *table[BELAY_INTERP_COUNT];
    for (int i = 0; i < BELAY_INTERP_COUNT; i++) table[i] = belay_interp_builtin((enum belay_interp_id)i);
    table[BELAY_INTERP_PIP] = &t;
    REQUIRE(diff_run(ma, mb, d, NULL, NULL, table) == 0);
    free(g_text);
    g_text = t_slurp(d);
    REQUIRE(g_text != NULL);
    ASSERT_EQ_STR("{\"event\":\"could_not_interpret\",\"interp\":\"pip\",\"text\":\"could not interpret\","
                  "\"paths\":[\"lib/x-1.0.dist-info/RECORD\"]}\n", t_only_events(g_text));
}

/* The lookups read the manifest the diff read: one rewritten in place
 * between the two reads (a digit of a time, the JSON still whole) fails the
 * diff, and no output is left. */
static enum belay_interp_result p_prepare_rewrites(void *s, struct belay_lookup *lk) {
    struct probe *p = s;
    if (p->round++ > 0) return BELAY_INTERP_FINDINGS;
    char mb[400];
    snprintf(mb, sizeof mb, "%s/m2", g_dir);
    char *text = t_slurp(mb);
    char *at = text != NULL ? strstr(text, "\"mtime_ns\":") : NULL;
    if (at != NULL) {
        at += 11;
        *at = *at == '1' ? '2' : '1';
        FILE *f = fopen(mb, "r+b");
        if (f != NULL) {
            fseek(f, (long)(at - text), SEEK_SET);
            fputc(*at, f);
            fclose(f);
        }
    }
    free(text);
    return belay_lookup_want(lk, "etc/motd", 8, false, p_count, p) ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
}

TEST(a_manifest_rewritten_between_the_diff_and_a_lookup_fails_the_diff) {
    t_reset();
    t_file("etc/motd", "one\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file("etc/motd", "two\n", 0644);
    REQUIRE(t_snap(2) == 0);
    char ma[400], mb[400], d[400];
    snprintf(ma, sizeof ma, "%s/m1", g_dir);
    snprintf(mb, sizeof mb, "%s/m2", g_dir);
    snprintf(d, sizeof d, "%s/d", g_dir);
    unlink(d);
    const struct belay_interp t = { BELAY_INTERP_PIP, p_begin, p_explain, p_end, p_prepare_rewrites };
    const struct belay_interp *table[BELAY_INTERP_COUNT];
    for (int i = 0; i < BELAY_INTERP_COUNT; i++) table[i] = belay_interp_builtin((enum belay_interp_id)i);
    table[BELAY_INTERP_PIP] = &t;
    ASSERT_EQ_INT(-1, diff_run(ma, mb, d, NULL, NULL, table));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    belay_err_clear();
    ASSERT_EQ_INT(-1, access(d, F_OK));
}

/* SI-1, E13: text, pip, dpkg, accounts, sudoers, cron, systemd, sshkeys,
 * trust, (config), git -- whatever order the events were added in. */
TEST(events_are_written_in_the_amended_order) {
    static const enum belay_interp_id ADD[] = { BELAY_INTERP_GIT, BELAY_INTERP_TRUST, BELAY_INTERP_SSHKEYS,
        BELAY_INTERP_SYSTEMD, BELAY_INTERP_CRON, BELAY_INTERP_SUDOERS, BELAY_INTERP_ACCOUNTS, BELAY_INTERP_DPKG,
        BELAY_INTERP_PIP, BELAY_INTERP_TEXT };
    struct belay_events ev;
    events_init(&ev);
    const char *p = "x";
    const size_t pl = 1;
    for (size_t i = 0; i < sizeof ADD / sizeof ADD[0]; i++) {
        ev.interp = ADD[i];
        ASSERT_EQ_INT(0, belay_event_not_interpreted(&ev, &p, &pl, 1, 0));
    }
    char *out = NULL;
    size_t n;
    FILE *m = open_memstream(&out, &n);
    REQUIRE(m != NULL);
    ASSERT_EQ_INT(0, events_write(&ev, m));
    fclose(m);
    char got[256] = "";
    for (const char *l = out; l != NULL && *l; l = strchr(l, '\n') + 1) {
        const char *q = strstr(l, "\"interp\":\"") + 10;
        snprintf(got + strlen(got), sizeof got - strlen(got), "%.*s ", (int)strcspn(q, "\""), q);
    }
    ASSERT_EQ_STR("text pip dpkg accounts sudoers cron systemd sshkeys trust git ", got);
    free(out);
    events_free(&ev);
}

int main(void) {
    t_begin("lookup");
    char store[400];
    snprintf(store, sizeof store, "%s/store", g_dir);
    mkdir(store, 0700);
    if (belay_content_open(store, &g_c) != 0) return 2;
    RUN(owner_is_the_package_whose_list_names_the_path);
    RUN(owner_tries_the_top_level_links_both_ways);
    RUN(owner_is_absent_without_a_dpkg_database_and_null_with_one);
    RUN(owner_applies_diversions);
    RUN(owner_of_a_path_several_lists_name_is_the_first_in_byte_order);
    RUN(owner_with_a_list_that_cannot_be_read_is_absent_unless_found);
    RUN(owner_reads_hostile_lists);
    RUN(owner_asks_are_a_set);
    belay_content_close(g_c);
    RUN(an_interpreter_reads_paths_it_was_not_given_and_asks_their_owner);
    RUN(a_failed_prepare_is_one_could_not_interpret_and_the_diff_stands);
    RUN(a_manifest_rewritten_between_the_diff_and_a_lookup_fails_the_diff);
    RUN(events_are_written_in_the_amended_order);
    free(g_text);
    t_end();
    return belay_test_report();
}
