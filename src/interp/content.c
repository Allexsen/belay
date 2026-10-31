/*
 *  Stored copies, read back (belay/interp.h). Read-only: nothing here creates,
 *  writes or follows a symlink; every object is checked against its name.
 */
#define _GNU_SOURCE
#include "belay/interp.h"
#include "belay/error.h"
#include "belay/hash.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct belay_content { int dfd; };

int belay_content_open(const char *store_dir, struct belay_content **out) {
    *out = NULL;
    const int dfd = open(store_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "content: cannot open the store %s", store_dir);
        return -1;
    }
    struct belay_content *c = malloc(sizeof *c);
    if (c == NULL) {
        close(dfd);
        belay_err_set(BELAY_ERR_NOMEM, 0, "content: out of memory");
        return -1;
    }
    c->dfd = dfd;
    *out = c;
    return 0;
}

void belay_content_close(struct belay_content *c) {
    if (c == NULL) return;
    close(c->dfd);
    free(c);
}

static bool lower_hex64(const char *h) {
    if (h == NULL) return false;
    for (int i = 0; i < 64; i++)
        if (!((h[i] >= '0' && h[i] <= '9') || (h[i] >= 'a' && h[i] <= 'f'))) return false;
    return h[64] == '\0';
}

int belay_content_get(const struct belay_content *c, const char *hex, size_t max,
                      unsigned char **buf, size_t *len) {
    *buf = NULL;
    *len = 0;
    if (c == NULL || !lower_hex64(hex)) {
        belay_err_set(BELAY_ERR_INVALID, 0, "content: not an object name");
        return -1;
    }
    const char prefix[3] = { hex[0], hex[1], '\0' };
    const int pfd = openat(c->dfd, prefix, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    const int fd = pfd == -1 ? -1 : openat(pfd, hex + 2, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    const int e = errno;
    if (pfd != -1) close(pfd);
    if (fd == -1) {
        if (e == ENOENT || e == ELOOP || e == ENOTDIR)
            belay_err_set(BELAY_ERR_CORRUPT, 0, "content: object %s is missing", hex);
        else
            belay_err_set(BELAY_ERR_IO, e, "content: cannot open object %s", hex);
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)) {
        close(fd);
        belay_err_set(BELAY_ERR_CORRUPT, 0, "content: object %s is not a regular file", hex);
        return -1;
    }
    if ((uint64_t)st.st_size > max) {
        close(fd);
        belay_err_set(BELAY_ERR_RANGE, 0, "content: object %s is larger than %zu bytes", hex, max);
        return -1;
    }
    unsigned char *b = malloc((size_t)st.st_size + 1);
    if (b == NULL) {
        close(fd);
        belay_err_set(BELAY_ERR_NOMEM, 0, "content: out of memory");
        return -1;
    }
    /* Read to the end, never past max: the file may have grown since fstat. */
    size_t n = 0;
    for (;;) {
        if (n == (size_t)st.st_size) {
            unsigned char extra;
            const ssize_t r = read(fd, &extra, 1);
            if (r == 0) break;
            if (r < 0 && errno == EINTR) continue;
            free(b);
            close(fd);
            belay_err_set(BELAY_ERR_CORRUPT, 0, "content: object %s changed while read", hex);
            return -1;
        }
        const ssize_t r = read(fd, b + n, (size_t)st.st_size - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) {
            const int re = errno;
            free(b);
            close(fd);
            if (r == 0) belay_err_set(BELAY_ERR_CORRUPT, 0, "content: object %s changed while read", hex);
            else belay_err_set(BELAY_ERR_IO, re, "content: cannot read object %s", hex);
            return -1;
        }
        n += (size_t)r;
    }
    close(fd);
    struct belay_sha256 h;
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    char got[65];
    belay_sha256_init(&h);
    belay_sha256_update(&h, b, n);
    belay_sha256_final(&h, d);
    belay_hex_encode(got, d, sizeof d);
    if (memcmp(got, hex, 64) != 0) {
        free(b);
        belay_err_set(BELAY_ERR_CORRUPT, 0, "content: object %s has content hashing to %s", hex, got);
        return -1;
    }
    b[n] = '\0';
    *buf = b;
    *len = n;
    return 0;
}
