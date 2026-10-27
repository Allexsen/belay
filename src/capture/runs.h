/*
 *  A bounded-memory sorted store of records: (key, value) byte strings,
 *  iterated in strictly increasing key order (memcmp, shorter first), as many
 *  times as needed. It knows nothing about manifests.
 *
 *  Records go into an in-memory arena of `budget` bytes. A full arena is
 *  sorted and spilled to an anonymous temporary file. Runs are kept by level:
 *  FANIN runs at one level merge into one run at the next, so each byte is
 *  rewritten about log16(runs) times and open descriptors stay bounded. Peak
 *  memory is roughly the budget plus FANIN merge cursors, whatever the number
 *  of records. (Earlier designs held every entry in RAM, then re-merged one
 *  ever-growing run at every cascade: independent review defects 4 and 6.)
 *
 *  Keys are unique by construction; an equal pair met while iterating is an
 *  error ("listed one name twice"), never a tie to break.
 */
#ifndef BELAY_CAPTURE_RUNS_H
#define BELAY_CAPTURE_RUNS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct runs;

/* Anonymous temporary files come from the caller (the platform adapter). */
typedef FILE *(*runs_tmpfile_fn)(void *ctx);

/* budget: arena bytes (raised to hold one maximal record); max_key, max_val:
 * the largest key and value that will be added. */
struct runs *runs_new(size_t budget, uint32_t max_key, uint32_t max_val,
                      runs_tmpfile_fn tmp, void *tmp_ctx);
void runs_free(struct runs *r);

int runs_add(struct runs *r, const void *key, uint32_t klen, const void *val, uint32_t vlen);

/* Ends adding. Then iterate: runs_rewind, and runs_next until it returns 0
 * (1 = a record, -1 = error). Pointers stay valid until the next call. */
int runs_seal(struct runs *r);
int runs_rewind(struct runs *r);
int runs_next(struct runs *r, const unsigned char **key, uint32_t *klen,
              const unsigned char **val, uint32_t *vlen);

size_t runs_count(const struct runs *r);

#endif
