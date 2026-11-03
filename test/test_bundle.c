/*
 *  The baseline bundle and the package lines against their pin
 *  (test/expect/baseline-bundle.md), through `belay baseline export` run
 *  in-process: every at_reset a database row can have, dpkg's MD5 checked
 *  in the read that hashes the file (decision 158), a bundle read back
 *  byte for byte, one whose bytes are not the digest given never parsed
 *  (B-R2), every row of B-R3 refused, export's refusals (B-R4, PS-C2) and
 *  the 4 GiB hash limit a spec brings (PS-C3, decision 159).
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include "cli/cli.h"
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/interp.h"
#include "belay/manifest.h"
#include "policy/bundle.h"
#include "policy/pkgdb.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[256], g_scope[400], g_state[400], g_out_path[400];
static char *g_out, *g_err;

static int belay(const char *a0, ...) {
    char *argv[32] = { "belay", (char *)a0 };
    int argc = 2;
    va_list ap;
    va_start(ap, a0);
    const char *a;
    while (argc < 31 && (a = va_arg(ap, const char *)) != NULL) argv[argc++] = (char *)a;
    va_end(ap);
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

static void sh(const char *fmt, ...) {
    char cmd[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    if (system(cmd) != 0) { /* the assertions say */ }
}

static void sha_of(const void *b, size_t n, char hex[65]) {
    struct belay_sha256 h;
    uint8_t d[32];
    belay_sha256_init(&h);
    belay_sha256_update(&h, b, n);
    belay_sha256_final(&h, d);
    belay_hex_encode(hex, d, 32);
}

/* A scope with a dpkg root and a pip site-packages, as the fixture for
 * every row: a file tampered with, one gone, a conffile, a RECORD row
 * climbing to bin/, one with no hash, one escaping the scope. */
static void fixture(void) {
    sh("rm -rf '%s' && mkdir -p '%s/var/lib/dpkg/info' '%s/usr/bin' '%s/etc' '%s/bin' "
       "'%s/lib/site-packages/foo-1.0.dist-info' '%s/lib/site-packages/foo' '%s' && chmod 700 '%s'",
       g_dir, g_scope, g_scope, g_scope, g_scope, g_scope, g_scope, g_state, g_state);
    sh("cd '%s' && printf 'hello\\n' > usr/bin/hello && printf 'cfg\\n' > etc/hello.conf && "
       "m=$(python3 -c \"import hashlib;print(hashlib.md5(open('usr/bin/hello','rb').read()).hexdigest())\") && "
       "c=$(python3 -c \"import hashlib;print(hashlib.md5(open('etc/hello.conf','rb').read()).hexdigest())\") && "
       "printf 'Package: hello\\nStatus: install ok installed\\nArchitecture: amd64\\nVersion: 2.10-3\\n"
       "Conffiles:\\n /etc/hello.conf %%s\\n /etc/gone.conf newconffile\\nDescription: x\\n more\\n\\n' $c > var/lib/dpkg/status && "
       "printf '%%s  usr/bin/hello\\n%%s  usr/bin/gone\\n%%s  ../../outside\\n%%s  zzz/last\\n' $m $m $m $m > var/lib/dpkg/info/hello.md5sums && "
       "printf 'x = 1\\n' > lib/site-packages/foo/__init__.py && cp lib/site-packages/foo/__init__.py bin/foo && "
       "h=$(python3 -c \"import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256(b'x = 1\\\\n').digest()).rstrip(b'=').decode())\") && "
       "printf 'foo/__init__.py,sha256=%%s,6\\nfoo-1.0.dist-info/RECORD,,\\n../../bin/foo,sha256=%%s,6\\n../../../../escape,,\\n' $h $h "
       "> lib/site-packages/foo-1.0.dist-info/RECORD && printf 'tampered\\n' > usr/bin/hello", g_scope);
}

static int export_(const char *json) {
    setenv("BELAY_STATE_DIR", g_state, 1);
    return json ? belay("baseline", "export", "--scope", g_scope, "--out", g_out_path, "--json", NULL)
                : belay("baseline", "export", "--scope", g_scope, "--out", g_out_path, NULL);
}

static char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    fseek(f, 0, SEEK_END);
    const long l = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)l + 1);
    *n = fread(b, 1, (size_t)l, f);
    b[*n] = '\0';
    fclose(f);
    return b;
}

static char g_line[4096];
static const char *line_of(const struct pkg_line *x) {
    snprintf(g_line, sizeof g_line, "%s %s %s %.*s%s %s", pkg_db_name(x->db), x->package, x->version,
             (int)x->path_len, x->path, x->conffile ? " (conffile)" : "", pkg_at_reset_name(x->at_reset));
    return g_line;
}

/* bundle_read into a fresh work directory. */
static int read_back(const char *path, const char *want, struct bundle *b) {
    char work[512], man[600], store[600];
    snprintf(work, sizeof work, "%s/work", g_dir);
    sh("rm -rf '%s' && mkdir -p '%s'", work, work);
    snprintf(man, sizeof man, "%s/manifest.ndjson", work);
    snprintf(store, sizeof store, "%s/store", work);
    return bundle_read(path, want, work, man, store, b);
}

TEST(export_lists_every_database_row_with_what_it_said_at_reset) {
    fixture();
    REQUIRE_MSG(export_(NULL) == EXIT_DONE, "%s", g_err);
    ASSERT_TRUE(strstr(g_out, "packages: 8 files listed by their databases, 2 outside the scope (never checked)") != NULL);
    ASSERT_TRUE(strstr(g_out, "baseline integrity: 5 files not as their database says") != NULL);
    /* the sha256 printed is the file's, as sha256sum says (B-R1) */
    size_t n;
    char *b = slurp(g_out_path, &n), hex[65], want[80];
    REQUIRE(b != NULL);
    sha_of(b, n, hex);
    snprintf(want, sizeof want, "sha256 %s\n", hex);
    ASSERT_TRUE(strstr(g_out, want) != NULL);
    free(b);
    struct bundle bd;
    REQUIRE_MSG(read_back(g_out_path, hex, &bd) == 0, "%s", belay_err_msg());
    ASSERT_EQ_INT(8, (int)bd.packages.n);
    ASSERT_EQ_INT(2, (int)bd.packages.outside_scope);
    /* sorted by db, package, path (B-6); each at_reset (B-P6) */
    ASSERT_EQ_STR("dpkg hello:amd64 2.10-3 etc/gone.conf (conffile) missing", line_of(&bd.packages.v[0]));
    ASSERT_EQ_STR("dpkg hello:amd64 2.10-3 etc/hello.conf (conffile) match", line_of(&bd.packages.v[1]));
    ASSERT_EQ_STR("dpkg hello:amd64 2.10-3 usr/bin/gone missing", line_of(&bd.packages.v[2]));
    ASSERT_EQ_STR("dpkg hello:amd64 2.10-3 usr/bin/hello mismatch", line_of(&bd.packages.v[3]));
    ASSERT_EQ_STR("dpkg hello:amd64 2.10-3 zzz/last missing", line_of(&bd.packages.v[4]));   /* past every entry */
    ASSERT_EQ_STR("pip foo 1.0 bin/foo match", line_of(&bd.packages.v[5]));
    ASSERT_EQ_STR("pip foo 1.0 lib/site-packages/foo-1.0.dist-info/RECORD no_hash", line_of(&bd.packages.v[6]));
    ASSERT_EQ_STR("pip foo 1.0 lib/site-packages/foo/__init__.py match", line_of(&bd.packages.v[7]));
    bundle_free(&bd);
    /* --json: one line, the findings in the packages member's order */
    sh("rm -f '%s'", g_out_path);
    REQUIRE(export_("json") == EXIT_DONE);
    ASSERT_TRUE(strstr(g_out, "\"baseline_integrity\":[{\"db\":\"dpkg\",\"package\":\"hello:amd64\",\"version\":\"2.10-3\","
                              "\"path\":\"etc/gone.conf\",\"at_reset\":\"missing\"},") != NULL);
    ASSERT_TRUE(strchr(g_out, '\n') == g_out + strlen(g_out) - 1);
}

/* dpkg's hash is checked in the read that hashes the file, and that hash
 * must be the manifest's: a file changed after its capture fails the
 * export rather than vouch for bytes it never recorded (decision 158). */
TEST(a_file_changed_after_its_capture_fails_the_export) {
    fixture();
    REQUIRE_MSG(export_(NULL) == EXIT_DONE, "%s", g_err);
    char man[700];
    snprintf(man, sizeof man, "%s/m.ndjson", g_dir);
    struct belay_manifest_opts o = { .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT,
                                     .store_max_bytes = BELAY_STORE_MAX_BYTES_DEFAULT };
    char store[700];
    snprintf(store, sizeof store, "%s/st", g_dir);
    o.store_dir = store;
    REQUIRE(belay_manifest_write(man, g_scope, &o, NULL) == 0);
    struct pkg_list l;
    REQUIRE_MSG(pkgdb_list(man, store, &l) == 0, "%s", belay_err_msg());
    ASSERT_EQ_INT(0, pkgdb_check(man, g_scope, &l));
    sh("printf 'other\\n' > '%s/usr/bin/hello'", g_scope);         /* after the capture */
    ASSERT_EQ_INT(-1, pkgdb_check(man, g_scope, &l));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    ASSERT_TRUE(strstr(belay_err_msg(), "usr/bin/hello: not the bytes the capture recorded") != NULL);
    pkgdb_free(&l);
}

TEST(a_bundle_reads_back_what_was_written) {
    fixture();
    REQUIRE(export_(NULL) == EXIT_DONE);
    size_t n;
    char *b = slurp(g_out_path, &n), hex[65];
    sha_of(b, n, hex);
    free(b);
    struct bundle bd;
    REQUIRE_MSG(read_back(g_out_path, hex, &bd) == 0, "%s", belay_err_msg());
    char man[600];
    snprintf(man, sizeof man, "%s/work/manifest.ndjson", g_dir);
    char *m = slurp(man, &n), mh[65];
    REQUIRE(m != NULL);
    sha_of(m, n, mh);
    free(m);
    ASSERT_EQ_STR(bd.manifest_sha256, mh);                       /* B-4 */
    char real[PATH_MAX];
    REQUIRE(realpath(g_scope, real) != NULL);              /* macOS: /tmp is /private/tmp */
    ASSERT_EQ_STR(real, bd.meta.scope);
    ASSERT_EQ_INT(BELAY_HASH_MAX_BYTES_DEFAULT, (int)bd.meta.hash_max_bytes);
    ASSERT_FALSE(bd.meta.has_protect);
    /* every copy the manifest names is in the store, and verifies (B-5) */
    struct belay_manifest_reader *r;
    REQUIRE(belay_manifest_open(man, &r) == 0);
    static struct belay_entry e;
    char store[600];
    snprintf(store, sizeof store, "%s/work/store", g_dir);
    struct belay_content *c;
    REQUIRE(belay_content_open(store, &c) == 0);
    int copies = 0;
    while (belay_manifest_next(r, &e) == 1) {
        if (!e.has_stored) continue;
        unsigned char *buf;
        size_t len;
        ASSERT_EQ_INT(0, belay_content_get(c, e.stored_hex, 1 << 20, &buf, &len));
        free(buf);
        copies++;
    }
    belay_manifest_close(r);
    belay_content_close(c);
    ASSERT_TRUE(copies >= 6);
    bundle_free(&bd);
}

/* B-R2: bytes that are not the digest given are never parsed: nothing of
 * them kept, refused as INVALID (exit 3 in verify). */
TEST(a_bundle_whose_bytes_are_not_the_digest_given_is_never_parsed) {
    fixture();
    REQUIRE(export_(NULL) == EXIT_DONE);
    struct bundle bd;
    ASSERT_EQ_INT(-1, read_back(g_out_path, "0000000000000000000000000000000000000000000000000000000000000000", &bd));
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
    char p[700];
    snprintf(p, sizeof p, "%s/work/manifest.ndjson", g_dir);
    ASSERT_EQ_INT(-1, access(p, F_OK));
    snprintf(p, sizeof p, "%s/work/bundle", g_dir);
    ASSERT_EQ_INT(-1, access(p, F_OK));
    ASSERT_EQ_INT(-1, read_back(g_out_path, "ABC", &bd));        /* not 64 lowercase hex */
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
}

/* ---- B-R3: a bundle with the right digest that breaks a row ---- */

struct member { char *hdr; size_t hl; char *body; size_t bl; };

/* The members of a bundle (header line without its newline, body). */
static size_t split(char *b, size_t n, struct member *m, size_t max) {
    size_t k = 0, i = 0;
    while (i < n && k < max) {
        char *nl = memchr(b + i, '\n', n - i);
        m[k].hdr = b + i;
        m[k].hl = (size_t)(nl - (b + i));
        const char *s = strstr(m[k].hdr, "\"size\":");
        const size_t sz = s != NULL && s < nl ? strtoull(s + 7, NULL, 10) : 0;
        m[k].body = nl + 1;
        m[k].bl = sz;
        i = (size_t)(nl + 1 - b) + sz;
        k++;
    }
    return k;
}

/* Writes the members back, each header's size and sha256 recomputed from
 * its body unless `keep_hdr`; returns the file's digest. */
static void join(const char *path, struct member *m, size_t k, bool keep_hdr, char hex[65]) {
    FILE *f = fopen(path, "wb");
    for (size_t i = 0; i < k; i++) {
        char h[70000];
        snprintf(h, sizeof h, "%.*s", (int)m[i].hl, m[i].hdr);
        char *s = strstr(h, "\"size\":"), *x = strstr(h, "\"sha256\":\"");
        if (!keep_hdr && s != NULL) {
            static char rest[70000];
            char *e = s + 7;
            while (*e >= '0' && *e <= '9') e++;
            snprintf(rest, sizeof rest, "%s", e);
            snprintf(s, sizeof h - (size_t)(s - h), "\"size\":%zu%s", m[i].bl, rest);
            x = strstr(h, "\"sha256\":\"");
        }
        if (!keep_hdr && x != NULL && strstr(h, "\"member\"") != NULL) {
            char d[65];
            sha_of(m[i].body, m[i].bl, d);
            memcpy(x + 10, d, 64);
        }
        fprintf(f, "%s\n", h);
        fwrite(m[i].body, 1, m[i].bl, f);
    }
    fclose(f);
    size_t n;
    char *b = slurp(path, &n);
    sha_of(b, n, hex);
    free(b);
}

static char *g_bundle;
static size_t g_bundle_n;

static const char *verdict(const char *what, struct member *m, size_t k, bool keep_hdr) {
    char path[600], hex[65];
    snprintf(path, sizeof path, "%s/mutant", g_dir);
    join(path, m, k, keep_hdr, hex);
    struct bundle bd;
    const int rc = read_back(path, hex, &bd);
    if (rc == 0) bundle_free(&bd);
    snprintf(g_line, sizeof g_line, "%s: %s", what,
             rc == 0 ? "read" : belay_err_code() == BELAY_ERR_CORRUPT ? "corrupt" : belay_err_msg());
    return g_line;
}

#define CORRUPT_(what, m, k, keep) do { char w_[512]; snprintf(w_, sizeof w_, "%s: corrupt", what); \
                                        ASSERT_EQ_STR(w_, verdict(what, m, k, keep)); } while (0)

static size_t fresh_members(struct member *m, size_t max) {
    free(g_bundle);
    g_bundle = slurp(g_out_path, &g_bundle_n);
    return split(g_bundle, g_bundle_n, m, max);
}

TEST(every_row_refuses_what_it_does_not_allow) {
    fixture();
    REQUIRE(export_(NULL) == EXIT_DONE);
    static struct member m[64], t[64];
    size_t k = fresh_members(m, 64);
    REQUIRE(k >= 6);                            /* bundle, manifest, copies, packages, end */
    { char w_[64]; snprintf(w_, sizeof w_, "as written: read"); ASSERT_EQ_STR(w_, verdict("as written", m, k, false)); }
    const size_t P = k - 2, C = 2;             /* the packages member; the first copy */

    char h[70000], body[200000];
    /* B-3: another version; keys out of order; a key more */
    memcpy(t, m, k * sizeof *t);
    snprintf(h, sizeof h, "%.*s", (int)m[0].hl, m[0].hdr);
    *strstr(h, "\"belay_bundle\":1") = '\0';
    static char h2[140100];
    snprintf(h2, sizeof h2, "%s\"belay_bundle\":2%s", h, strstr(m[0].hdr, "\"belay_bundle\":1") + 16);
    h2[strchr(h2, '\n') != NULL ? (size_t)(strchr(h2, '\n') - h2) : strlen(h2)] = '\0';
    t[0].hdr = h2;
    t[0].hl = strlen(h2);
    CORRUPT_("belay_bundle 2", t, k, false);
    /* every key there, two swapped: "created_ns" before "size" */
    static char h3[70000];
    {
        const char *sz = strstr(m[0].hdr, "\"size\":0,"), *cr = strstr(m[0].hdr, "\"created_ns\":");
        const char *cre = strchr(cr, ',');
        snprintf(h3, sizeof h3, "%.*s%.*s,\"size\":0%.*s", (int)(sz - m[0].hdr), m[0].hdr, (int)(cre - cr), cr,
                 (int)(m[0].hl - (size_t)(cre - m[0].hdr)), cre);
    }
    t[0].hdr = h3;
    t[0].hl = strlen(h3);
    CORRUPT_("keys out of order", t, k, false);
    memcpy(t, m, k * sizeof *t);
    snprintf(h, sizeof h, "%.*s,\"why\":1}", (int)m[0].hl - 1, m[0].hdr);
    t[0].hdr = h;
    t[0].hl = strlen(h);
    CORRUPT_("a key more", t, k, false);

    /* B-2: an unknown member; members out of order; one missing */
    memcpy(t, m, k * sizeof *t);
    snprintf(h, sizeof h, "%.*s", (int)m[P].hl, m[P].hdr);
    memcpy(strstr(h, "packages"), "pakkages", 8);
    t[P].hdr = h;
    CORRUPT_("an unknown member", t, k, false);
    memcpy(t, m, k * sizeof *t);
    t[1] = m[C];
    t[C] = m[1];
    CORRUPT_("a copy before the manifest", t, k, false);
    memcpy(t, m, k * sizeof *t);
    memmove(&t[P], &t[P + 1], sizeof *t);
    CORRUPT_("no packages member", t, k - 1, false);

    /* B-5: a copy whose bytes do not hash to its key (header kept); copies
     * out of order; a copy dropped (the manifest names it); one added */
    memcpy(t, m, k * sizeof *t);
    memcpy(body, m[C].body, m[C].bl);
    body[0] ^= 1;
    t[C].body = body;
    CORRUPT_("a copy's bytes not its key", t, k, true);
    if (P - C >= 2) {
        memcpy(t, m, k * sizeof *t);
        t[C] = m[C + 1];
        t[C + 1] = m[C];
        CORRUPT_("copies out of order", t, k, true);
    }
    memcpy(t, m, k * sizeof *t);
    memmove(&t[C], &t[C + 1], (k - C - 1) * sizeof *t);
    snprintf(h, sizeof h, "{\"member\":\"end\",\"size\":0,\"members\":%zu}", k - 2);
    t[k - 2].hdr = h;
    t[k - 2].hl = strlen(h);
    CORRUPT_("a copy the manifest names, dropped", t, k - 1, true);
    memcpy(t, m, k * sizeof *t);
    memmove(&t[C + 1], &t[C], (k - C) * sizeof *t);
    static char extra[] = "planted\n", eh[200];
    char ex[65];
    sha_of(extra, 8, ex);
    snprintf(eh, sizeof eh, "{\"member\":\"copy\",\"size\":8,\"sha256\":\"%s\"}", ex);
    t[C] = (struct member){ eh, strlen(eh), extra, 8 };
    /* keep ascending order: put it where it sorts */
    for (size_t i = C; i + 1 < P + 1 && memcmp(strstr(t[i].hdr, "sha256") + 9, strstr(t[i + 1].hdr, "sha256") + 9, 64) > 0; i++) {
        struct member s = t[i];
        t[i] = t[i + 1];
        t[i + 1] = s;
    }
    snprintf(h, sizeof h, "{\"member\":\"end\",\"size\":0,\"members\":%zu}", k);
    t[k].hdr = h;
    t[k].hl = strlen(h);
    CORRUPT_("a copy no entry names", t, k + 1, true);

    /* B-4: the manifest's bytes not its sha256 (header kept) */
    memcpy(t, m, k * sizeof *t);
    char *mb = malloc(m[1].bl);
    memcpy(mb, m[1].body, m[1].bl);
    char *mt = memmem(mb, m[1].bl, "\"mtime_ns\":1", 12);   /* still a manifest a reader accepts */
    REQUIRE(mt != NULL);
    mt[11] = '2';
    t[1].body = mb;
    CORRUPT_("the manifest's bytes not its sha256", t, k, true);
    free(mb);

    /* B-6: package lines unsorted, repeated, of another db, an at_reset
     * unknown, a conffile on pip, a key more (headers recomputed) */
    const char *lines = m[P].body;
    const size_t ll = m[P].bl;
    const char *first_nl = memchr(lines, '\n', ll);
    const size_t l1 = (size_t)(first_nl - lines) + 1;
    struct { const char *what; const char *from, *to; int how; } cases[] = {
        { "package lines unsorted", NULL, NULL, 1 },
        { "a package line repeated", NULL, NULL, 2 },
        { "a db unknown", "\"db\":\"dpkg\"", "\"db\":\"rpms\"", 0 },
        { "an at_reset unknown", "\"at_reset\":\"missing\"", "\"at_reset\":\"lost!!!\"", 0 },
        { "a key more", "\"at_reset\":", "\"x\":1,\"at_reset\":", 0 },
        { "a conffile on pip", "\"db\":\"pip\",\"package\":\"foo\",\"version\":\"1.0\",\"path\":\"bin/foo\"",
          "\"db\":\"pip\",\"package\":\"foo\",\"version\":\"1.0\",\"path\":\"bin/foo\",\"conffile\":true", 0 },
    };
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        memcpy(t, m, k * sizeof *t);
        size_t bl = 0;
        if (cases[c].how == 1) {                /* the first line moved last */
            memcpy(body, lines + l1, ll - l1);
            memcpy(body + ll - l1, lines, l1);
            bl = ll;
        } else if (cases[c].how == 2) {         /* the first line twice */
            memcpy(body, lines, l1);
            memcpy(body + l1, lines, ll);
            bl = ll + l1;
        } else {
            const char *at = memmem(lines, ll, cases[c].from, strlen(cases[c].from));
            REQUIRE_MSG(at != NULL, "%s", cases[c].what);
            const size_t pre = (size_t)(at - lines);
            memcpy(body, lines, pre);
            memcpy(body + pre, cases[c].to, strlen(cases[c].to));
            memcpy(body + pre + strlen(cases[c].to), at + strlen(cases[c].from), ll - pre - strlen(cases[c].from));
            bl = ll - strlen(cases[c].from) + strlen(cases[c].to);
        }
        t[P].body = body;
        t[P].bl = bl;
        CORRUPT_(cases[c].what, t, k, false);
    }

    /* B-7: members miscounted; bytes after the end; the end missing */
    memcpy(t, m, k * sizeof *t);
    snprintf(h, sizeof h, "{\"member\":\"end\",\"size\":0,\"members\":%zu}", k);
    t[k - 1].hdr = h;
    t[k - 1].hl = strlen(h);
    CORRUPT_("members miscounted", t, k, false);
    memcpy(t, m, k * sizeof *t);
    static char trail[] = "x";
    t[k] = (struct member){ trail, 1, trail, 0 };
    CORRUPT_("a byte after the end", t, k + 1, true);
    CORRUPT_("no end", m, k - 1, true);
}

/* ---- export's refusals and its hash limit ---- */

TEST(export_refuses_what_its_rows_do_not_allow) {
    fixture();
    setenv("BELAY_STATE_DIR", g_state, 1);
    char inside[600], spec[600], bad[600];
    snprintf(inside, sizeof inside, "%s/b.bundle", g_scope);
    ASSERT_EQ_INT(EXIT_REFUSED, belay("baseline", "export", "--scope", g_scope, "--out", inside, NULL));   /* B-R4 */
    ASSERT_TRUE(strstr(g_err, "is inside the scope") != NULL);
    ASSERT_EQ_INT(-1, access(inside, F_OK));
    ASSERT_EQ_INT(EXIT_USAGE, belay("baseline", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(EXIT_USAGE, belay("baseline", "export", "--scope", g_scope, NULL));
    ASSERT_EQ_INT(EXIT_USAGE, belay("baseline", "export", "--scope", g_scope, "--out", g_out_path, "--out", g_out_path, NULL));
    /* a spec refused: exit 2 (PS-R2) */
    snprintf(bad, sizeof bad, "%s/bad.json", g_dir);
    sh("printf '{\"belay_protect\":1,\"protect\":[],\"frozen_package\":true}' > '%s'", bad);
    ASSERT_EQ_INT(EXIT_USAGE, belay("baseline", "export", "--scope", g_scope, "--out", g_out_path, "--protect", bad, NULL));
    ASSERT_TRUE(strstr(g_err, "protect spec: a key unknown or given twice") != NULL);
    /* an exclude covering a protected pattern: exit 3 (PS-C2) */
    snprintf(spec, sizeof spec, "%s/spec.json", g_dir);
    sh("printf '{\"belay_protect\":1,\"protect\":[{\"path\":\"etc/**\",\"mode\":[\"no_write\"]}]}' > '%s'", spec);
    ASSERT_EQ_INT(EXIT_DONE, belay("exclude", "--scope", g_scope, "--add", "etc", NULL));
    ASSERT_EQ_INT(EXIT_REFUSED, belay("baseline", "export", "--scope", g_scope, "--out", g_out_path, "--protect", spec, NULL));
    ASSERT_TRUE(strstr(g_err, "etc is excluded") != NULL && strstr(g_err, "etc/**") != NULL);
    ASSERT_EQ_INT(-1, access(g_out_path, F_OK));
    ASSERT_EQ_INT(EXIT_DONE, belay("exclude", "--scope", g_scope, "--remove", "etc", NULL));
    /* belay's state directory in the scope, under a protected pattern */
    char st[600];
    snprintf(st, sizeof st, "%s/state", g_scope);
    sh("mkdir -p '%s' && chmod 700 '%s'", st, st);
    setenv("BELAY_STATE_DIR", st, 1);
    sh("printf '{\"belay_protect\":1,\"protect\":[{\"path\":\"**/x\",\"mode\":[\"no_create\"]}]}' > '%s'", spec);
    ASSERT_EQ_INT(EXIT_REFUSED, belay("baseline", "export", "--scope", g_scope, "--out", g_out_path, "--protect", spec, NULL));
    ASSERT_TRUE(strstr(g_err, "is belay's state directory") != NULL);
    setenv("BELAY_STATE_DIR", g_state, 1);
}

/* PS-C3, decision 159: with a spec, every file within 4 GiB is hashed. A
 * sparse file of 65 MiB is past the default 64 MiB. */
TEST(a_spec_raises_the_hash_limit_to_4_gib) {
    fixture();
    setenv("BELAY_STATE_DIR", g_state, 1);
    char big[600];
    snprintf(big, sizeof big, "%s/big", g_scope);
    const int bfd = open(big, O_WRONLY | O_CREAT | O_TRUNC, 0644);      /* sparse: no `truncate` on macOS */
    REQUIRE(bfd >= 0 && ftruncate(bfd, 65 << 20) == 0);
    close(bfd);
    char spec[600];
    snprintf(spec, sizeof spec, "%s/spec.json", g_dir);
    sh("printf '{\"belay_protect\":1,\"protect\":[{\"path\":\"big\",\"mode\":[\"no_write\"]}]}' > '%s'", spec);
    for (int with = 0; with < 2; with++) {
        sh("rm -f '%s'", g_out_path);
        const int rc = with ? belay("baseline", "export", "--scope", g_scope, "--out", g_out_path, "--protect", spec, NULL)
                            : belay("baseline", "export", "--scope", g_scope, "--out", g_out_path, NULL);
        REQUIRE_MSG(rc == EXIT_DONE, "%s", g_err);
        size_t n;
        char *b = slurp(g_out_path, &n);
        REQUIRE(b != NULL);
        ASSERT_TRUE(strstr(b, with ? "\"hash_max_bytes\":4294967296" : "\"hash_max_bytes\":67108864") != NULL);
        const char *e = strstr(b, "{\"path\":\"big\"");
        REQUIRE(e != NULL);
        const char *eol = strchr(e, '\n');
        const bool hashed = memmem(e, (size_t)(eol - e), "\"sha256\":", 9) != NULL;
        ASSERT_EQ_INT(with, hashed);
        free(b);
    }
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_bundle_%d", (int)getpid());
    snprintf(g_scope, sizeof g_scope, "%s/scope", g_dir);
    snprintf(g_state, sizeof g_state, "%s/state", g_dir);
    snprintf(g_out_path, sizeof g_out_path, "%s/out.bundle", g_dir);
    RUN(export_lists_every_database_row_with_what_it_said_at_reset);
    RUN(a_file_changed_after_its_capture_fails_the_export);
    RUN(a_bundle_reads_back_what_was_written);
    RUN(a_bundle_whose_bytes_are_not_the_digest_given_is_never_parsed);
    RUN(every_row_refuses_what_it_does_not_allow);
    RUN(export_refuses_what_its_rows_do_not_allow);
    RUN(a_spec_raises_the_hash_limit_to_4_gib);
    sh("chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'", g_dir, g_dir);
    free(g_out);
    free(g_err);
    free(g_bundle);
    return belay_test_report();
}
