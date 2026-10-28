/*
 *  Capturing one entry: its stat and mount boundary, a regular file's content
 *  (hashed, and stored when kept), a symlink's target, a directory's open
 *  handle, and extended metadata. Every finding goes through outcome_apply.
 */
#define _GNU_SOURCE
#include "capture_internal.h"

#include "belay/error.h"
#include "belay/hash.h"
#include "belay/interp.h"
#include "belay/path.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The schema's type for these mode bits. A type the format does not know
 * (none on Linux; a whiteout on macOS) falls through to chr, as before;
 * its mode bits then disagree with chr, so the writer's check of the entry
 * fails the capture. */
static enum belay_entry_type type_of(mode_t m) {
    for (int t = 0; t < ENTRY_TYPE_COUNT; t++)
        if (((uint32_t)m & ENTRY_IFMT) == ENTRY_TYPES[t].ifmt) return (enum belay_entry_type)t;
    return BELAY_T_CHR;
}

/* Hashes by fd: no path is re-resolved, so there is no window between the
 * open and the read. */
/* Hashes by fd, and when `tx` is non-NULL stages the same bytes into the
 * store in the same pass: what is stored is exactly what was hashed. `*binary`
 * reports a NUL within the first SNIFF_BYTES. */
static int hash_fd(const struct fsops *ops, int fd, unsigned char *buf, char hex_out[65],
                   uint64_t *nread, struct belay_store_tx *tx, bool *binary) {
    struct belay_sha256 c;
    belay_sha256_init(&c);
    *nread = 0;
    *binary = false;
    for (;;) {
        const ssize_t n = ops->read(ops->ctx, fd, buf, READ_CHUNK);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            belay_err_set(BELAY_ERR_IO, errno, "hash: read failed");
            return -2;                      /* the file's problem, not belay's */
        }
        if (*nread < SNIFF_BYTES) {
            const size_t span = (size_t)n < SNIFF_BYTES - *nread ? (size_t)n
                                                                 : (size_t)(SNIFF_BYTES - *nread);
            if (memchr(buf, '\0', span) != NULL) *binary = true;
        }
        belay_sha256_update(&c, buf, (size_t)n);
        if (tx != NULL && belay_store_write(tx, buf, (size_t)n) == -1) return -1;
        *nread += (uint64_t)n;
    }
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    belay_sha256_final(&c, d);
    belay_hex_encode(hex_out, d, sizeof d);
    return 0;
}

void cap_fill_from_stat(struct belay_entry *e, const struct stat *st) {
    e->type     = type_of(st->st_mode);
    e->mode     = (uint32_t)st->st_mode;
    e->uid      = (uint32_t)st->st_uid;
    e->gid      = (uint32_t)st->st_gid;
    e->size     = (uint64_t)st->st_size;
    e->ino      = (uint64_t)st->st_ino;
    e->dev      = (uint64_t)st->st_dev;
    e->nlink    = (uint64_t)st->st_nlink;
    const struct ident id = ident_of_stat(st);
    e->mtime_ns = id.mtime_ns;
    e->ctime_ns = id.ctime_ns;
    if (e->type == BELAY_T_BLK || e->type == BELAY_T_CHR) {
        e->has_rdev = true;
        e->rdev = (uint64_t)st->st_rdev;
    }
}

/* ------------------------------------------------------------------------ */
/* Extended metadata: xattrs, ACLs, file capabilities, inode flags          */
/* ------------------------------------------------------------------------ */

/*
 *  `setcap` on a binary and `chattr +i` on a grader file used to change
 *  nothing recorded but ctime (decided 2026-10-26, W6). The entry's
 *  attributes are reached through its open fd (regular files, directories),
 *  or on Linux through the /proc/self/fd path of an O_PATH|O_NOFOLLOW fd,
 *  which acts on the entry itself -- a symlink, never its target (verified:
 *  the target's user.* attribute is not seen through the link). Nothing is
 *  resolved from a path string, so containment holds as for the walk.
 */

/* Names written as themselves: printable ASCII without '"', '\\' or '=',
 * not starting "x:". Anything else is written "x:" + hex, so every name has
 * exactly one spelling and none needs JSON escaping. */
static bool plain_xattr_name(const char *n, size_t l) {
    if (l == 0 || (l >= 2 && n[0] == 'x' && n[1] == ':')) return false;
    for (size_t i = 0; i < l; i++) {
        const unsigned char c = (unsigned char)n[i];
        if (c < 0x21 || c > 0x7e || c == '"' || c == '\\' || c == '=') return false;
    }
    return true;
}

static int name_cmp(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);   /* bytewise */
}

/* The canonical "xattrs" array body goes to the digest always, and to the
 * entry while it fits; larger sets are recorded by digest alone. */
struct xout { struct belay_sha256 h; char *buf; size_t len, cap; bool fits; size_t n; };
static void xo_put(struct xout *o, const char *s, size_t l) {
    belay_sha256_update(&o->h, s, l);
    if (o->fits && o->len + l < o->cap) {
        memcpy(o->buf + o->len, s, l);
        o->len += l;
    } else {
        o->fits = false;
    }
}

/* Reads the extras of wc->e. `fd` is the entry's open fd, or -1 to reach it
 * from parent `pfd` + `name` (checked against `st`, the recorded stat). Any
 * failure other than "no xattrs on this filesystem" records xattrs_unknown:
 * an absent field must never stand for "could not read". 0, or -1 if fatal. */
int cap_read_extras(struct walk_ctx *wc, int fd, int pfd, const char *name,
                       const struct stat *st) {
    struct belay_entry *e = &wc->e;
    const struct fsops *ops = wc->ops;
    wc->extras_done = true;
    uint64_t flags;
    if (ops->inode_flags(ops->ctx, fd, st, &flags) == 0) {
        e->has_iflags = true;
        e->iflags = flags;
    }
    struct xsrc x = { .fd = fd, .path = NULL, .own = -1 };
    if (fd == -1 && ops->xattr_source_open(ops->ctx, pfd, name, st, &x) == -1) {
        if (cap_fatal_errno(errno)) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: cannot reach %s for its attributes", name);
            ops->xattr_source_close(ops->ctx, &x);
            return -1;
        }
        goto unknown;
    }
    {
        const ssize_t ln = ops->xattr_list(ops->ctx, &x, wc->xlist, XLIST_CAP);
        if (ln < 0) {
            if (errno == ENOTSUP || errno == EOPNOTSUPP) goto done;   /* none here */
            goto unknown;
        }
        size_t n = 0;
        for (ssize_t i = 0; i < ln; ) {
            const char *nm = wc->xlist + i;
            const size_t l = strnlen(nm, (size_t)(ln - i));
            if (l > 0) wc->xnames[n++] = nm;
            i += (ssize_t)l + 1;
        }
        qsort(wc->xnames, n, sizeof *wc->xnames, name_cmp);

        struct xout o = { .buf = e->xattrs, .cap = sizeof e->xattrs, .fits = true };
        belay_sha256_init(&o.h);
        for (size_t i = 0; i < n; i++) {
            const char *nm = wc->xnames[i];
            const ssize_t vl = ops->xattr_get(ops->ctx, &x, nm, wc->readbuf, READ_CHUNK);
            if (vl < 0) goto unknown;                /* removed meanwhile, or denied */
            if (strcmp(nm, "security.capability") == 0) {
                if ((size_t)vl * 2 >= sizeof e->caps_hex) goto unknown;
                belay_hex_encode(e->caps_hex, wc->readbuf, (size_t)vl);
                e->has_caps = true;
                continue;
            }
            struct belay_sha256 vh;
            uint8_t d[BELAY_SHA256_DIGEST_LEN];
            belay_sha256_init(&vh);
            belay_sha256_update(&vh, wc->readbuf, (size_t)vl);
            belay_sha256_final(&vh, d);
            char el[2 * NAME_BYTES + 3 * BELAY_SHA256_DIGEST_LEN + 16];
            size_t w = 0;
            if (o.n > 0) el[w++] = ',';
            el[w++] = '"';
            const size_t nl = strlen(nm);
            if (nl > NAME_BYTES) goto unknown;
            if (plain_xattr_name(nm, nl)) {
                memcpy(el + w, nm, nl);
                w += nl;
            } else {
                el[w++] = 'x';
                el[w++] = ':';
                belay_hex_encode(el + w, (const uint8_t *)nm, nl);
                w += 2 * nl;
            }
            el[w++] = '=';
            belay_hex_encode(el + w, d, sizeof d);
            w += 2 * sizeof d;
            el[w++] = '"';
            xo_put(&o, el, w);
            o.n++;
        }
        if (o.n > 0) {
            uint8_t d[BELAY_SHA256_DIGEST_LEN];
            belay_sha256_final(&o.h, d);
            belay_hex_encode(e->xattrs_sha256_hex, d, sizeof d);
            e->has_xattrs = true;
            e->xattrs_inline = o.fits && o.len <= BELAY_XATTRS_INLINE_MAX;
            e->xattrs_len = e->xattrs_inline ? o.len : 0;
            e->xattrs[e->xattrs_len] = '\0';
        }
    }
    goto done;
unknown:
    outcome_apply(e, FACET_EXTRAS, OUT_DENIED, &wc->tally);
done:
    ops->xattr_source_close(ops->ctx, &x);
    return 0;
}

/*
 *  lstat, plus whether the entry is a mount root. On Linux, statx's
 *  STATX_ATTR_MOUNT_ROOT reports every mount root, bind mounts from the same
 *  filesystem included (st_dev alone missed those -- verified). *mount_known
 *  says whether it could answer; when not, the caller falls back to st_dev.
 *  AT_NO_AUTOMOUNT: walking a scope must not trigger autofs mounts (fstatat
 *  implies it since Linux 4.14; statx does not).
 *
 *  An error here is one entry's property (EIO, or EACCES/EPERM from an LSM or
 *  a FUSE server) and is handled by the caller like any other. Whether statx
 *  is usable at all was settled once, on the scope root.
 */
int cap_stat_entry(const struct walk_ctx *wc, int dfd, const char *name, struct stat *st,
                      bool *mount_root, bool *mount_known) {
    *mount_root = *mount_known = false;
    if (wc->statx_ok)
        return wc->ops->stat_mount(wc->ops->ctx, dfd, name, st, mount_root, mount_known);
    return wc->ops->fstatat(wc->ops->ctx, dfd, name, st, AT_SYMLINK_NOFOLLOW);
}

/*
 *  Whether an entry stat'ed by cap_stat_entry is a capture boundary: the
 *  root of another mount, of ANY type -- recorded, never read or descended.
 *  Where statx can say whether this is a mount root, its answer is used
 *  alone: st_dev is only a proxy, and a wrong one both ways -- a btrfs
 *  subvolume is a directory with its own st_dev but no mount, and on
 *  overlayfs (xino off) every non-directory carries its layer's device.
 *  Without statx (kernels before 5.8, or statx blocked), st_dev decides for
 *  every type, except non-directories of an overlayfs scope.
 *  (Directories-only everywhere hashed a file bind-mounted from another
 *  filesystem as a local file -- verified.) The walk and the end-of-walk
 *  validator both decide by this, so the validator never enters a mount the
 *  walk would not have.
 */
bool cap_crossed(const struct walk_ctx *wc, const struct stat *st, bool mount_root,
                 bool mount_known) {
    if (mount_known) return mount_root;
    return (uint64_t)st->st_dev != wc->root_dev && (S_ISDIR(st->st_mode) || !wc->scope_overlay);
}

/* Errors that are belay's own resource exhaustion rather than a property of
 * one entry: these stay fatal, loudly. Everything else about one entry is
 * recorded on that entry and the walk goes on. */
bool cap_fatal_errno(int err) {
    return err == EMFILE || err == ENFILE || err == ENOMEM;
}

/*
 *  Symlink. readlinkat reads the link itself, never its target. The link is
 *  re-stat'ed afterwards: the target read must belong to the link whose
 *  metadata was recorded (same inode, unchanged ctime, size equal to the
 *  target's length), or a swapped link would record one link's target with
 *  another's metadata.
 */
int cap_read_link(int pfd, const char *name, const struct stat *st, const char *rel,
                     struct walk_ctx *wc) {
    struct belay_entry *e = &wc->e;
    /* Buffer of PATH_CAP: a target of exactly PATH_CAP-1 (4095, the most
     * Linux allows) fits with its NUL. A full buffer means truncation. */
    const ssize_t n = wc->ops->readlinkat(wc->ops->ctx, pfd, name, e->link_target,
                                          sizeof e->link_target);
    if (n < 0) {
        if (errno == ENOENT) return V_VANISHED;
        if (errno == EINVAL) return V_RACED;           /* no longer a symlink */
        if (cap_fatal_errno(errno)) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: readlinkat %s", rel);
            return -1;
        }
        return V_UNREADABLE;                           /* EIO and friends */
    }
    if ((size_t)n >= sizeof e->link_target) return V_UNREADABLE;
    /* No real symlink has an empty target (symlink(2) refuses one), but a
     * FUSE or network filesystem can present it. Recorded as such it would be
     * read back as "unknown" without the unreadable flag that says so. */
    if (n == 0) return V_UNREADABLE;
    e->link_target[n] = '\0';
    e->link_target_len = (size_t)n;
    e->has_link_target = true;

    struct stat again;
    bool mr, mk;
    if (cap_stat_entry(wc, pfd, name, &again, &mr, &mk) == -1) {
        if (errno == ENOENT) return V_VANISHED;
        if (cap_fatal_errno(errno)) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: stat %s", rel);
            return -1;
        }
        return V_RACED;
    }
    if (!cons_link_read(st, &again, (size_t)n)) return V_RACED;

    /* Advisory only (§5.1.1): computed lexically, never used to decide. */
    e->target_outside_scope = belay_link_target_outside(wc->scope, e->path, e->path_len,
                                                        e->link_target, e->link_target_len);
    return V_OK;
}

/*
 *  Regular file. Hashes by fd and, when content is kept, stages the copy in
 *  the same read. The (size, sha256) pair must describe one real state of the
 *  file, so the fd is checked against the fstatat (inode, size, mtime, ctime)
 *  before reading and against itself after; any mismatch records no hash.
 */
int cap_read_file(int pfd, const char *name, const struct stat *st, const char *rel,
                     size_t rel_len, struct walk_ctx *wc) {
    struct belay_entry *e = &wc->e;

    /* O_NOFOLLOW closes the swap window; O_NONBLOCK stops a FIFO swapped in
     * from blocking the open forever. */
    const int fd = wc->ops->openat(wc->ops->ctx, pfd, name,
                                   O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd == -1) {
        if (errno == ENOENT) return V_VANISHED;
        if (cap_fatal_errno(errno)) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: openat %s", rel);
            return -1;
        }
        /* EACCES, EPERM, ELOOP (swapped for a link), EAGAIN (a lease),
         * ETXTBSY, EIO...: one entry's property, recorded on it. */
        outcome_apply(e, FACET_CONTENT, OUT_DENIED, &wc->tally);
        return V_OK;
    }

    struct stat before, after;
    if (wc->ops->fstat(wc->ops->ctx, fd, &before) == -1) {
        close(fd);
        outcome_apply(e, FACET_CONTENT, OUT_DENIED, &wc->tally);
        return V_OK;
    }
    const bool same = cons_file_opened(st, &before);
    if (!same) {
        outcome_apply(e, FACET_CONTENT, OUT_CHANGED, &wc->tally);
        close(fd);
        return V_OK;
    }
    if (cap_read_extras(wc, fd, pfd, name, st) == -1) {
        close(fd);
        return -1;
    }
    if (e->size > wc->opts->hash_max_bytes) {
        outcome_apply(e, FACET_CONTENT, OUT_TOO_LARGE, &wc->tally);
        close(fd);
        return V_OK;
    }

    /* What must be kept: an interpreter's claim overrides the size threshold
     * (stored whatever its size) or forbids storing (hash only); unclaimed
     * files are kept if small and text. */
    struct belay_claim claim = { BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT };
    if (wc->store != NULL) {
        const size_t sep = wc->scope_len > 1 ? 1 : 0;
        if (wc->scope_len + sep + rel_len < PATH_MAX * 2) {
            if (sep) wc->abs[wc->scope_len] = '/';
            memcpy(wc->abs + wc->scope_len + sep, rel, rel_len);
            belay_interp_classify(wc->abs, wc->scope_len + sep + rel_len, &claim);
        }
    }
    const bool want = wc->store != NULL && claim.keep != BELAY_KEEP_HASH &&
                      (claim.keep == BELAY_KEEP_STORE || e->size <= wc->opts->store_max_bytes);

    struct belay_store_tx tx;
    if (want && belay_store_begin(wc->store, &tx) == -1) {
        close(fd);
        return -1;
    }

    uint64_t nread = 0;
    bool binary = false;
    const int h = hash_fd(wc->ops, fd, wc->readbuf, e->sha256_hex, &nread, want ? &tx : NULL, &binary);
    if (h != 0) {
        if (want) belay_store_abort(&tx);
        close(fd);
        if (h == -2) {
            /* The file could not be read (EIO and friends): record it. */
            belay_err_clear();
            outcome_apply(e, FACET_CONTENT, OUT_DENIED, &wc->tally);
            return V_OK;
        }
        return -1;                                      /* store write failed */
    }
    if (wc->ops->fstat(wc->ops->ctx, fd, &after) == -1) {
        if (want) belay_store_abort(&tx);
        close(fd);
        outcome_apply(e, FACET_CONTENT, OUT_DENIED, &wc->tally);
        return V_OK;
    }
    close(fd);

    const bool stable = cons_file_read(&before, &after, nread);
    if (!stable) {
        /* The bytes read -- and any staged copy -- match no state of the file. */
        if (want) belay_store_abort(&tx);
        outcome_apply(e, FACET_CONTENT, OUT_CHANGED, &wc->tally);
        return V_OK;
    }

    e->has_hash = true;
    /* Unclaimed binary content is not kept: the text interpreter could not
     * use it. Claimed content is kept whatever it is. */
    if (want && !(claim.keep == BELAY_KEEP_DEFAULT && binary)) {
        if (belay_store_commit(&tx, e->sha256_hex) == -1) return -1;
        e->has_stored = true;
        memcpy(e->stored_hex, e->sha256_hex, sizeof e->stored_hex);
    } else if (want) {
        belay_store_abort(&tx);
    }
    return V_OK;
}

/*
 *  Directory. Opened, and checked, BEFORE its entry is emitted, so whatever
 *  goes wrong is recorded on the entry itself. Any condition that keeps belay
 *  from capturing the contents is a flag on this one entry ("contents
 *  unknown"), never a failure of the whole check.
 */
int cap_open_dir(int pfd, const char *name, const struct stat *st, const char *rel,
                    size_t rel_len, int depth, struct walk_ctx *wc, int *out_fd) {
    struct belay_entry *e = &wc->e;
    *out_fd = -1;

    if (depth >= MAX_DEPTH || rel_len > PATH_CAP - 2 - NAME_BYTES) {
        outcome_apply(e, FACET_LISTING, OUT_DENIED, &wc->tally);
        return V_OK;
    }

    const int cfd = wc->ops->openat(wc->ops->ctx, pfd, name,
                                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cfd == -1) {
        if (cap_fatal_errno(errno)) {
            belay_err_set(BELAY_ERR_IO, errno, "manifest: openat dir %s", rel);
            return -1;
        }
        /* ENOENT (gone), ELOOP/ENOTDIR (swapped), EACCES/EPERM: the subtree is
         * absent, and unflagged it would read as an empty directory. */
        outcome_apply(e, FACET_LISTING, errno == ENOENT ? OUT_GONE : OUT_DENIED, &wc->tally);
        return V_OK;
    }

    struct stat cs, probe;
    const enum outcome opened = wc->ops->fstat(wc->ops->ctx, cfd, &cs) == -1
                              ? OUT_DENIED : cons_dir_opened(st, &cs);
    if (opened == OUT_DENIED ||
        /* Readable but not searchable (r without x): its names can be listed
         * but none of them can be stat'ed. */
        wc->ops->fstatat(wc->ops->ctx, cfd, ".", &probe, AT_SYMLINK_NOFOLLOW) == -1) {
        close(cfd);
        outcome_apply(e, FACET_LISTING, OUT_DENIED, &wc->tally);
        return V_OK;
    }
    if (opened == OUT_CHANGED) outcome_apply(e, FACET_LISTING, OUT_CHANGED, &wc->tally);
    if (cap_read_extras(wc, cfd, pfd, name, st) == -1) {
        close(cfd);
        return -1;
    }
    (void)rel;
    *out_fd = cfd;
    return V_OK;
}

int cap_emit(struct walk_ctx *wc, const struct belay_entry *e) {
    const size_t n = entry_pack(e, wc->pack, ENTRY_PACK_MAX);
    if (n == 0) {
        belay_err_set(BELAY_ERR_RANGE, 0, "manifest: entry exceeds %u bytes", ENTRY_PACK_MAX);
        return -1;
    }
    return runs_add(wc->runs, e->path, (uint32_t)e->path_len, wc->pack, (uint32_t)n);
}
