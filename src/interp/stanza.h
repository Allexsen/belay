/*
 *  dpkg's status database (deb822 control format, deb-control(5)): the
 *  stanzas, and of each the four fields the dpkg interpreter reads. A
 *  streaming pass over one buffer, no allocation, no recursion; the file is
 *  written by the watched process, so every bound is checked.
 */
#ifndef BELAY_INTERP_STANZA_H
#define BELAY_INTERP_STANZA_H

#include <stddef.h>

#define STANZA_VALUE_MAX 1024u      /* bytes of a field read (first line) */
#define STANZA_MAX       262144u    /* stanzas in one file */

struct stanza_pkg {
    const char *package, *arch, *version, *status;   /* into the buffer; NULL when absent */
    size_t package_len, arch_len, version_len, status_len;
    size_t line;                                     /* the stanza's first line, 1-based */
};

typedef int (*stanza_fn)(const struct stanza_pkg *p, void *ctx);

/* Calls `fn` for each stanza, in file order. 0; -1 with belay_err CORRUPT
 * (naming the line) when a line is neither a field, a continuation nor
 * blank, a stanza has no Package, a field read exceeds STANZA_VALUE_MAX, or there
 * are more than STANZA_MAX stanzas; or fn's non-zero return, at once. Field
 * names compare case-insensitively; values are trimmed of blanks; a field
 * given twice keeps its first value. */
int stanza_each(const char *buf, size_t len, stanza_fn fn, void *ctx);

#endif
