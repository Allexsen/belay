/*
 *  Stored copies read back for interpreters (belay/interp.h, content): the
 *  contract before any interpreter uses it. Read-only, verified against the
 *  name, bounded. Fixtures under /tmp (§0.4d).
 */
#define _GNU_SOURCE

#include "belay_test.h"
#include "belay/interp.h"
#include "belay/store.h"
#include "belay/hash.h"
#include "belay/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

static char g_dir[256];

static void sha_hex(const char *data, size_t n, char out[65]) {
    struct belay_sha256 c;
    uint8_t d[32];
    belay_sha256_init(&c);
    belay_sha256_update(&c, data, n);
    belay_sha256_final(&c, d);
    belay_hex_encode(out, d, sizeof d);
}

/* A fresh store holding `data`; its name in hex. */
static void stored(const char *data, char hex[65]) {
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* the assertions say */ }
    struct belay_store *s = NULL;
    sha_hex(data, strlen(data), hex);
    if (belay_store_open(g_dir, &s) != 0) return;
    struct belay_store_tx tx;
    if (belay_store_begin(s, &tx) == 0 && belay_store_write(&tx, data, strlen(data)) == 0)
        belay_store_commit(&tx, hex);
    belay_store_sync(s);
    belay_store_close(s);
}

static void obj(const char *hex, char *p, size_t n) { snprintf(p, n, "%s/%.2s/%s", g_dir, hex, hex + 2); }

TEST(an_object_is_read_whole_and_checked) {
    char hex[65];
    stored("line one\nline two\n", hex);
    struct belay_content *c = NULL;
    REQUIRE(belay_content_open(g_dir, &c) == 0);
    unsigned char *b = NULL;
    size_t n = 0;
    ASSERT_EQ_INT(0, belay_content_get(c, hex, 1024, &b, &n));
    ASSERT_EQ_INT(18, (int)n);
    ASSERT_TRUE(memcmp(b, "line one\nline two\n", 18) == 0 && b[18] == '\0');
    free(b);
    belay_content_close(c);
}

TEST(every_wrong_object_is_an_error_never_content) {
    char hex[65], p[600], missing[65];
    stored("the real bytes\n", hex);
    struct belay_content *c = NULL;
    REQUIRE(belay_content_open(g_dir, &c) == 0);
    unsigned char *b = NULL;
    size_t n = 0;
    ASSERT_EQ_INT(-1, belay_content_get(c, hex, 4, &b, &n));             /* over max */
    ASSERT_EQ_INT(BELAY_ERR_RANGE, belay_err_code());
    ASSERT_TRUE(b == NULL);
    belay_err_clear();
    obj(hex, p, sizeof p);
    REQUIRE(truncate(p, 3) == 0);                                        /* cut short */
    ASSERT_EQ_INT(-1, belay_content_get(c, hex, 1024, &b, &n));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    belay_err_clear();
    REQUIRE(unlink(p) == 0 && symlink("/etc/hostname", p) == 0);         /* a planted link */
    ASSERT_EQ_INT(-1, belay_content_get(c, hex, 1024, &b, &n));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    belay_err_clear();
    sha_hex("never stored", 12, missing);                                /* absent */
    ASSERT_EQ_INT(-1, belay_content_get(c, missing, 1024, &b, &n));
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, belay_err_code());
    belay_err_clear();
    ASSERT_EQ_INT(-1, belay_content_get(c, "../../etc/passwd", 1024, &b, &n));
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
    belay_err_clear();
    char upper[65];
    memcpy(upper, hex, 65);
    upper[0] = 'A';
    ASSERT_EQ_INT(-1, belay_content_get(c, upper, 1024, &b, &n));
    ASSERT_EQ_INT(BELAY_ERR_INVALID, belay_err_code());
    belay_err_clear();
    belay_content_close(c);
}

/* Review 2026-10-31, findings 1 and 6: an object that is not a regular file
 * -- a FIFO (opening one with no writer blocks), a socket (ENXIO), a
 * directory, a prefix that is a file -- is corrupt, at once. Each get runs in
 * a child under a 5-second alarm, so a hang is a failed assertion here, not
 * a hung test. */
static int get_code_in_child(const struct belay_content *c, const char *hex) {
    const pid_t pid = fork();
    if (pid == 0) {
        alarm(5);
        unsigned char *b = NULL;
        size_t n = 0;
        const int rc = belay_content_get(c, hex, 1024, &b, &n);
        _exit(rc == 0 ? 100 : belay_err_code());
    }
    int ws;
    if (waitpid(pid, &ws, 0) != pid) return -1;
    return WIFEXITED(ws) ? WEXITSTATUS(ws) : 200 + (WIFSIGNALED(ws) ? WTERMSIG(ws) : 0);
}

TEST(an_object_that_is_not_a_regular_file_is_corrupt_at_once) {
    char hex[65], p[600], d[600];
    stored("bytes\n", hex);
    struct belay_content *c = NULL;
    REQUIRE(belay_content_open(g_dir, &c) == 0);
    obj(hex, p, sizeof p);
    REQUIRE(unlink(p) == 0 && mkfifo(p, 0600) == 0);                    /* a FIFO, no writer */
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, get_code_in_child(c, hex));
    REQUIRE(unlink(p) == 0);
    {
        const int sk = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un a = { .sun_family = AF_UNIX };
        REQUIRE(sk != -1 && strlen(p) < sizeof a.sun_path);
        snprintf(a.sun_path, sizeof a.sun_path, "%s", p);
        REQUIRE(bind(sk, (struct sockaddr *)&a, sizeof a) == 0);         /* a socket */
        ASSERT_EQ_INT(BELAY_ERR_CORRUPT, get_code_in_child(c, hex));
        close(sk);
        REQUIRE(unlink(p) == 0);
    }
    REQUIRE(mkdir(p, 0700) == 0);                                        /* a directory */
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, get_code_in_child(c, hex));
    REQUIRE(rmdir(p) == 0);
    snprintf(d, sizeof d, "%s/%.2s", g_dir, hex);                        /* the prefix a file */
    char cmd[1300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s' && touch '%s'", d, d);
    REQUIRE(system(cmd) == 0);
    ASSERT_EQ_INT(BELAY_ERR_CORRUPT, get_code_in_child(c, hex));
    belay_content_close(c);
}

/* Opening never creates the store, and refuses a symlink in its place. */
TEST(the_store_is_opened_read_only) {
    char cmd[400], link[300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* the assertions say */ }
    struct belay_content *c = NULL;
    ASSERT_EQ_INT(-1, belay_content_open(g_dir, &c));
    belay_err_clear();
    struct stat st;
    ASSERT_TRUE(stat(g_dir, &st) != 0);                                  /* not created */
    REQUIRE(mkdir(g_dir, 0700) == 0);
    snprintf(link, sizeof link, "%s.link", g_dir);
    unlink(link);
    REQUIRE(symlink(g_dir, link) == 0);
    ASSERT_EQ_INT(-1, belay_content_open(link, &c));
    belay_err_clear();
    unlink(link);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/belay_content_%d", (int)getpid());
    RUN(an_object_is_read_whole_and_checked);
    RUN(every_wrong_object_is_an_error_never_content);
    RUN(an_object_that_is_not_a_regular_file_is_corrupt_at_once);
    RUN(the_store_is_opened_read_only);
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    return belay_test_report();
}
