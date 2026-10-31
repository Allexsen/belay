/*
 *  pip's RECORD (PEP 376, the wheel spec): CSV rows of path, hash, size, as
 *  Python's csv module writes them -- fields quoted with '"' when they need
 *  it, '""' inside a quoted field, rows ended by "\n" or "\r\n". A streaming
 *  pass, no allocation; written by the watched process, so bounded.
 */
#ifndef BELAY_INTERP_RECORD_CSV_H
#define BELAY_INTERP_RECORD_CSV_H

#include <stddef.h>

#define RECORD_FIELD_MAX 4096u      /* bytes of one field, unquoted */

struct record_row {
    const char *path, *hash, *size;   /* NUL-terminated, valid until fn returns */
    size_t path_len, hash_len, size_len;
    size_t line;                      /* where the row starts, 1-based */
};

typedef int (*record_fn)(const struct record_row *r, void *ctx);

/* Calls `fn` for each row, in file order; blank lines are skipped. 0; -1
 * with belay_err CORRUPT (naming the line) for a row that is not three
 * fields, an unterminated quote, a quote inside an unquoted field, or a
 * field over RECORD_FIELD_MAX; or fn's non-zero return, at once. */
int record_each(const char *buf, size_t len, record_fn fn, void *ctx);

#endif
