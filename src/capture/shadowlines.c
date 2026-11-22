/*
 *  The per-line digests of shadow and gshadow (capture_internal.h;
 *  system-interpreters.md SA-6). What is kept of a line is its first field
 *  and a keyed digest: the bytes after the first `:` pass through the hash
 *  and nowhere else.
 */
#define _GNU_SOURCE
#include "capture_internal.h"

#include "belay/hash.h"
#include "belay/json.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *const NAMES[2] = { "etc/gshadow", "etc/shadow" };

struct cap_lines {
    struct { char *p; size_t len, cap; bool kept, dropped; } file[2];
    int cur;                            /* the file being read; -1: none */
    uint8_t key[BELAY_SEALING_KEY_BYTES];
    struct belay_sha256 h;              /* the inner hash of the line being read */
    bool in_line;                       /* a byte of the current line was seen */
    bool in_name;                       /* its first `:` was not */
    char name[CAP_LINES_NAME_MAX];
    size_t name_len;
};

struct cap_lines *cap_lines_new(void) {
    struct cap_lines *l = calloc(1, sizeof *l);
    if (l != NULL) l->cur = -1;
    return l;
}

void cap_lines_free(struct cap_lines *l) {
    if (l == NULL) return;
    free(l->file[0].p);
    free(l->file[1].p);
    cap_wipe(l, sizeof *l);
    free(l);
}

int cap_lines_which(const char *rel, size_t len) {
    for (int i = 0; i < 2; i++)
        if (len == strlen(NAMES[i]) && memcmp(rel, NAMES[i], len) == 0) return i;
    return -1;
}

static void drop(struct cap_lines *l) {
    free(l->file[l->cur].p);
    l->file[l->cur].p = NULL;
    l->file[l->cur].len = l->file[l->cur].cap = 0;
    l->file[l->cur].dropped = true;
}

static void line_start(struct cap_lines *l) {
    uint8_t pad[64];
    memset(pad, 0x36, sizeof pad);
    for (size_t i = 0; i < BELAY_SEALING_KEY_BYTES; i++) pad[i] ^= l->key[i];
    belay_sha256_init(&l->h);
    belay_sha256_update(&l->h, pad, sizeof pad);
    cap_wipe(pad, sizeof pad);
    l->in_line = true;
    l->in_name = true;
    l->name_len = 0;
}

/* The line ended: its record, appended to the file's. */
static void line_end(struct cap_lines *l) {
    uint8_t pad[64], d[BELAY_SHA256_DIGEST_LEN];
    char hex[2 * BELAY_SHA256_DIGEST_LEN + 1], esc[6 * CAP_LINES_NAME_MAX + 8], rec[6 * CAP_LINES_NAME_MAX + 256];
    belay_sha256_final(&l->h, d);
    memset(pad, 0x5c, sizeof pad);
    for (size_t i = 0; i < BELAY_SEALING_KEY_BYTES; i++) pad[i] ^= l->key[i];
    belay_sha256_init(&l->h);
    belay_sha256_update(&l->h, pad, sizeof pad);
    belay_sha256_update(&l->h, d, sizeof d);
    belay_sha256_final(&l->h, d);
    cap_wipe(pad, sizeof pad);
    belay_hex_encode(hex, d, sizeof d);
    l->in_line = false;
    if (l->file[l->cur].dropped) return;
    const bool utf8 = belay_utf8_valid(l->name, l->name_len) && memchr(l->name, '\0', l->name_len) == NULL;
    if ((utf8 ? belay_json_escape(esc, sizeof esc, l->name, l->name_len)
              : belay_base64_encode(esc, sizeof esc, l->name, l->name_len)) == -1) {
        drop(l);
        return;
    }
    const int n = snprintf(rec, sizeof rec, "{\"file\":\"%s\",\"%s\":\"%s\",\"hmac\":\"%s\"}\n", NAMES[l->cur],
                           utf8 ? "name" : "name_b64", esc, hex);
    if (n < 0 || (size_t)n >= sizeof rec || l->file[l->cur].len + (size_t)n > CAP_LINES_MAX) { drop(l); return; }
    if (l->file[l->cur].len + (size_t)n > l->file[l->cur].cap) {
        size_t c = l->file[l->cur].cap ? l->file[l->cur].cap : 4096;
        while (c < l->file[l->cur].len + (size_t)n) c *= 2;
        char *q = realloc(l->file[l->cur].p, c);
        if (q == NULL) { drop(l); return; }
        l->file[l->cur].p = q;
        l->file[l->cur].cap = c;
    }
    memcpy(l->file[l->cur].p + l->file[l->cur].len, rec, (size_t)n);
    l->file[l->cur].len += (size_t)n;
}

void cap_lines_begin(struct cap_lines *l, int which, const uint8_t key[BELAY_SEALING_KEY_BYTES]) {
    l->cur = which;
    memcpy(l->key, key, BELAY_SEALING_KEY_BYTES);
    free(l->file[which].p);
    memset(&l->file[which], 0, sizeof l->file[which]);
    l->in_line = false;
}

void cap_lines_feed(struct cap_lines *l, const unsigned char *buf, size_t n) {
    if (l->cur < 0) return;
    size_t i = 0;
    while (i < n) {
        if (buf[i] == '\n') {
            if (l->in_line) line_end(l);        /* an empty line is no entry */
            i++;
            continue;
        }
        if (!l->in_line) line_start(l);
        size_t j = i;
        while (j < n && buf[j] != '\n') j++;
        belay_sha256_update(&l->h, buf + i, j - i);
        for (size_t k = i; k < j && l->in_name; k++) {
            if (buf[k] == ':') l->in_name = false;
            else if (l->name_len == CAP_LINES_NAME_MAX) { l->in_name = false; if (!l->file[l->cur].dropped) drop(l); }
            else l->name[l->name_len++] = (char)buf[k];
        }
        i = j;
    }
}

void cap_lines_end(struct cap_lines *l, bool keep) {
    if (l->cur < 0) return;
    if (l->in_line) line_end(l);                /* a last line without its newline */
    if (!keep && !l->file[l->cur].dropped) drop(l);
    l->file[l->cur].kept = !l->file[l->cur].dropped;
    l->cur = -1;
    l->name_len = 0;
    cap_wipe(l->name, sizeof l->name);
}

static bool write_all(int fd, const char *p, size_t n) {
    while (n > 0) {
        const ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w;
        n -= (size_t)w;
    }
    return true;
}

int cap_lines_write(struct cap_lines *l, const char *path, const char *key_id, char hex[65]) {
    hex[0] = '\0';
    if (!l->file[0].kept && !l->file[1].kept) {
        if (unlink(path) == -1 && errno != ENOENT) return -1;
        return 0;
    }
    char tmp[PATH_MAX + 32], head[160];
    if ((size_t)snprintf(tmp, sizeof tmp, "%s.tmp.XXXXXX", path) >= sizeof tmp) { errno = ENAMETOOLONG; return -1; }
    const int hn = snprintf(head, sizeof head, "{\"belay_shadow_lines\":1,\"sealed_key\":\"%s\",\"files\":[%s%s%s]}\n", key_id,
                            l->file[0].kept ? "\"etc/gshadow\"" : "", l->file[0].kept && l->file[1].kept ? "," : "",
                            l->file[1].kept ? "\"etc/shadow\"" : "");
    const int fd = mkstemp(tmp);                /* mode 600 */
    if (fd == -1) return -1;
    struct belay_sha256 h;
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_init(&h);
    belay_sha256_update(&h, head, (size_t)hn);
    bool ok = fchmod(fd, 0600) == 0 && write_all(fd, head, (size_t)hn);
    for (int i = 0; i < 2 && ok; i++) {
        if (!l->file[i].kept) continue;
        belay_sha256_update(&h, l->file[i].p, l->file[i].len);
        ok = write_all(fd, l->file[i].p, l->file[i].len);
    }
    ok = ok && fsync(fd) == 0;
    int err = errno;
    close(fd);
    if (ok && rename(tmp, path) != 0) { ok = false; err = errno; }
    if (!ok) {
        unlink(tmp);
        errno = err;
        return -1;
    }
    belay_sha256_final(&h, d);
    belay_hex_encode(hex, d, sizeof d);
    return 0;
}
