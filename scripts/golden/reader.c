/*
 *  Golden reader: prints, for each manifest given, ACCEPT or the reader's
 *  error message, plus every entry's decoded fields -- so two revisions of the
 *  reader can be compared on accept/reject, message and decoding.
 *  Public API only.
 */
#include "belay/manifest.h"
#include "belay/error.h"

#include <stdio.h>

static int show(const struct belay_entry *e, void *c) {
    (void)c;
    printf("  %.*s|%d|%u|%u|%u|%llu|%lld|%lld|%llu|%llu|%llu|%s%s|%s|%d%d%d%d%d%d%d|%.*s|%s|"
           "%d:%llu|%s|%s|%s|%d\n",
           (int)e->path_len, e->path, (int)e->type, e->mode, e->uid, e->gid,
           (unsigned long long)e->size, (long long)e->mtime_ns, (long long)e->ctime_ns,
           (unsigned long long)e->ino, (unsigned long long)e->dev, (unsigned long long)e->nlink,
           e->has_hash ? "h:" : "", e->has_hash ? e->sha256_hex : "",
           e->has_stored ? e->stored_hex : "",
           e->unverified, e->unstable, e->unreadable, e->is_mount, e->raced,
           e->target_outside_scope, e->has_rdev,
           (int)e->link_target_len, e->has_link_target ? e->link_target : "",
           e->has_caps ? e->caps_hex : "",
           e->has_iflags, (unsigned long long)e->iflags,
           e->has_xattrs ? e->xattrs_sha256_hex : "",
           e->xattrs_inline ? e->xattrs : "", e->xattrs_unknown ? "U" : "",
           (int)e->rdev);
    return 0;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        printf("== %s\n", argv[i]);
        const int r = belay_manifest_read(argv[i], show, NULL);
        printf("-> %s\n", r == 0 ? "ACCEPT" : belay_err_msg());
        belay_err_clear();
    }
    return 0;
}
