/*
 *  The files installed packages list, with the hash each database gives
 *  (test/expect/baseline-bundle.md, package lines): dpkg's
 *  info/<package>.md5sums and its status's Conffiles (MD5), pip's RECORD
 *  (sha256). Read from a manifest's stored copies -- never from the tree --
 *  and checked against the files as they are at reset (B-P6, decision
 *  158): dpkg's MD5 in the same read as the file's sha256, which must be
 *  the manifest's; pip's sha256 against the manifest's own, no read.
 */
#ifndef BELAY_POLICY_PKGDB_H
#define BELAY_POLICY_PKGDB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PKGDB_COPY_MAX (256u << 20)     /* bytes of one database file read */

enum pkg_db { PKG_DPKG, PKG_PIP };

/* B-P6's values, in their order. */
enum pkg_at_reset {
    AT_MATCH, AT_MISMATCH, AT_MISSING, AT_NOT_A_FILE, AT_UNVERIFIED, AT_NO_HASH, AT_UNSET
};
const char *pkg_at_reset_name(enum pkg_at_reset a);
const char *pkg_db_name(enum pkg_db d);

struct pkg_line {
    enum pkg_db db;
    char *package, *version;    /* NUL-terminated, owned */
    char *path;                 /* relative to the scope, path_len bytes (owned, NUL after) */
    size_t path_len;
    bool conffile;
    enum pkg_at_reset at_reset;
    char expected[65];          /* the database's hash, lowercase hex (MD5: 32 digits); "" none */
};

struct pkg_list {
    struct pkg_line *v;
    size_t n, cap;
    uint64_t outside_scope;     /* listed files outside the scope: counted, never checked (B-6) */
};

/* The files the package databases in the manifest list, from the stored
 * copies in `store_dir`; each line's at_reset AT_UNSET. Sorted by db,
 * package, path bytes. 0, or -1 with belay_err: CORRUPT when a database
 * file has no stored copy, or a copy cannot be parsed; NOMEM, IO. */
int pkgdb_list(const char *manifest, const char *store_dir, struct pkg_list *out);

/* Fills each line's at_reset from the manifest and, for dpkg, the files
 * under `scope` (read without following a symlink, below the scope only).
 * 0, or -1 with belay_err: CORRUPT when a file's bytes are not the
 * manifest's (it changed after the capture: the export is not one state),
 * IO. */
int pkgdb_check(const char *manifest, const char *scope, struct pkg_list *l);

void pkgdb_free(struct pkg_list *l);

/* Adds a line (copies the strings). 0, or -1 (NOMEM). For the reader. */
int pkgdb_add(struct pkg_list *l, enum pkg_db db, const char *package, const char *version,
              const char *path, size_t path_len, bool conffile, enum pkg_at_reset at);

/* Sorts by db, package, path bytes (B-6). */
void pkgdb_sort(struct pkg_list *l);

#endif
