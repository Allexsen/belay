/*
 *  Content store. BLAST RADIUS -- see belay/store.h.
 *
 *  Every operation is relative to `dfd`, the store directory opened once with
 *  O_DIRECTORY|O_NOFOLLOW. No path string is resolved after open.
 */
#define _GNU_SOURCE

#include "belay/store.h"
#include "belay/error.h"
#include "belay/hash.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct belay_store {
    int dfd;
    unsigned long counter;
};

/* Exactly 64 lowercase hex characters. Checked before `hex` is ever used to
 * build a name, so it cannot carry "/", "..", or a NUL. */
static bool valid_hex(const char *hex) {
    if (hex == NULL) return false;
    for (int i = 0; i < 64; i++) {
        const char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return hex[64] == '\0';
}

int belay_store_open(const char *dir, struct belay_store **out) {
    if (dir == NULL || out == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "store_open: null argument");
        return -1;
    }
    *out = NULL;

    if (mkdir(dir, 0700) == -1 && errno != EEXIST) {
        belay_err_set(BELAY_ERR_IO, errno, "store: cannot create %s", dir);
        return -1;
    }
    /* O_NOFOLLOW on the final component: a store directory replaced by a
     * symlink would otherwise redirect every write elsewhere. */
    const int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "store: cannot open %s%s", dir,
                      errno == ELOOP ? " (it is a symlink)" : "");
        return -1;
    }

    /* An existing store must be ours and writable only by us. Otherwise
     * another user could plant objects that dedup would keep; verify-on-read
     * would still catch them, but nothing should be able to put them there. */
    struct stat st;
    if (fstat(dfd, &st) == -1) {
        belay_err_set(BELAY_ERR_IO, errno, "store: cannot stat %s", dir);
        close(dfd);
        return -1;
    }
    if (st.st_uid != geteuid() || (st.st_mode & 022) != 0) {
        belay_err_set(BELAY_ERR_INVALID, 0,
                      "store: %s must be owned by this user and not group/other-writable "
                      "(mode %03o)", dir, (unsigned)(st.st_mode & 0777));
        close(dfd);
        return -1;
    }

    struct belay_store *s = calloc(1, sizeof *s);
    if (s == NULL) {
        close(dfd);
        belay_err_set(BELAY_ERR_NOMEM, 0, "store: out of memory");
        return -1;
    }
    s->dfd = dfd;
    *out = s;
    return 0;
}

void belay_store_close(struct belay_store *s) {
    if (s == NULL) return;
    close(s->dfd);
    free(s);
}

int belay_store_begin(struct belay_store *s, struct belay_store_tx *tx) {
    memset(tx, 0, sizeof *tx);
    tx->fd = -1;
    if (s == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "store_begin: null store");
        return -1;
    }
    tx->s = s;

    /* O_EXCL + O_NOFOLLOW: never reuse or follow anything already at the
     * name. Retry on collision with another process using the same name. */
    for (int attempt = 0; attempt < 100; attempt++) {
        snprintf(tx->tmp, sizeof tx->tmp, ".tmp-%ld-%lu", (long)getpid(), s->counter++);
        tx->fd = openat(s->dfd, tx->tmp,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (tx->fd != -1) {
            tx->live = true;
            return 0;
        }
        if (errno != EEXIST) break;
    }
    belay_err_set(BELAY_ERR_IO, errno, "store: cannot create a staging file");
    return -1;
}

int belay_store_write(struct belay_store_tx *tx, const void *buf, size_t n) {
    if (tx == NULL || !tx->live) {
        belay_err_set(BELAY_ERR_INVALID, 0, "store_write: no open transaction");
        return -1;
    }
    const unsigned char *p = buf;
    while (n > 0) {
        const ssize_t w = write(tx->fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            belay_err_set(BELAY_ERR_IO, errno, "store: write failed");
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

void belay_store_abort(struct belay_store_tx *tx) {
    if (tx == NULL || !tx->live) return;
    close(tx->fd);
    unlinkat(tx->s->dfd, tx->tmp, 0);
    tx->fd = -1;
    tx->live = false;
}

/* Opens (creating if needed) the fan-out directory for `hex`. */
static int open_prefix(struct belay_store *s, const char *hex) {
    const char prefix[3] = { hex[0], hex[1], '\0' };
    if (mkdirat(s->dfd, prefix, 0700) == -1 && errno != EEXIST) {
        belay_err_set(BELAY_ERR_IO, errno, "store: cannot create %s/", prefix);
        return -1;
    }
    const int pfd = openat(s->dfd, prefix, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (pfd == -1)
        belay_err_set(BELAY_ERR_IO, errno, "store: cannot open %s/%s", prefix,
                      errno == ELOOP || errno == ENOTDIR ? " (not a directory)" : "");
    return pfd;
}

int belay_store_commit(struct belay_store_tx *tx, const char *hex) {
    if (tx == NULL || !tx->live) {
        belay_err_set(BELAY_ERR_INVALID, 0, "store_commit: no open transaction");
        return -1;
    }
    if (!valid_hex(hex)) {
        belay_store_abort(tx);
        belay_err_set(BELAY_ERR_INVALID, 0, "store: object name is not a sha256 hex digest");
        return -1;
    }

    if (close(tx->fd) == -1) {
        tx->fd = -1;
        const int e = errno;
        unlinkat(tx->s->dfd, tx->tmp, 0);
        tx->live = false;
        belay_err_set(BELAY_ERR_IO, e, "store: close failed");
        return -1;
    }
    tx->fd = -1;

    const int pfd = open_prefix(tx->s, hex);
    if (pfd == -1) {
        unlinkat(tx->s->dfd, tx->tmp, 0);
        tx->live = false;
        return -1;
    }

    int rc = 0;
    struct stat st;
    if (fstatat(pfd, hex + 2, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISREG(st.st_mode)) {
            /* Dedup: keep the existing object, never rewrite it. Its content
             * is not trusted here -- verify-on-read is what checks it. */
            unlinkat(tx->s->dfd, tx->tmp, 0);
        } else {
            /* A symlink or directory at an object's name was put there by
             * something other than belay. Refuse rather than replace: a
             * rename would silently move a planted symlink out of the way. */
            unlinkat(tx->s->dfd, tx->tmp, 0);
            belay_err_set(BELAY_ERR_CORRUPT, 0,
                          "store: %.2s/%s exists and is not a regular file", hex, hex + 2);
            rc = -1;
        }
    } else if (errno == ENOENT) {
        if (renameat(tx->s->dfd, tx->tmp, pfd, hex + 2) == -1) {
            const int e = errno;
            unlinkat(tx->s->dfd, tx->tmp, 0);
            belay_err_set(BELAY_ERR_IO, e, "store: cannot publish object");
            rc = -1;
        }
    } else {
        const int e = errno;
        unlinkat(tx->s->dfd, tx->tmp, 0);
        belay_err_set(BELAY_ERR_IO, e, "store: cannot stat object");
        rc = -1;
    }

    close(pfd);
    tx->live = false;
    return rc;
}

int belay_store_verify(struct belay_store *s, const char *hex) {
    if (s == NULL || !valid_hex(hex)) {
        belay_err_set(BELAY_ERR_INVALID, 0, "store_verify: bad argument");
        return -1;
    }
    const char prefix[3] = { hex[0], hex[1], '\0' };
    const int pfd = openat(s->dfd, prefix, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (pfd == -1) {
        if (errno == ENOENT) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "store: object %s is missing", hex);
            return 0;
        }
        belay_err_set(BELAY_ERR_IO, errno, "store: cannot open %s/", prefix);
        return -1;
    }
    const int fd = openat(pfd, hex + 2, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    close(pfd);
    if (fd == -1) {
        if (errno == ENOENT || errno == ELOOP) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "store: object %s is %s", hex,
                          errno == ENOENT ? "missing" : "a symlink");
            return 0;
        }
        belay_err_set(BELAY_ERR_IO, errno, "store: cannot open object %s", hex);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)) {
        close(fd);
        belay_err_set(BELAY_ERR_CORRUPT, 0, "store: object %s is not a regular file", hex);
        return 0;
    }

    struct belay_sha256 c;
    belay_sha256_init(&c);
    unsigned char buf[65536];
    for (;;) {
        const ssize_t n = read(fd, buf, sizeof buf);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            belay_err_set(BELAY_ERR_IO, errno, "store: read failed");
            close(fd);
            return -1;
        }
        belay_sha256_update(&c, buf, (size_t)n);
    }
    close(fd);

    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    char got[BELAY_SHA256_HEX_LEN + 1];
    belay_sha256_final(&c, d);
    belay_hex_encode(got, d, sizeof d);
    if (strcmp(got, hex) != 0) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "store: object %s has content hashing to %s", hex, got);
        return 0;
    }
    return 1;
}
