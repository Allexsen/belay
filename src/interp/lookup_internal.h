/*
 *  The core's side of lookups (belay/interp.h, "Lookup"; system-
 *  interpreters.md SI-4, SI-5): what interpreters asked for in a round, the
 *  delivery of the after-manifest's entries to them, and the ownership of
 *  the paths they asked about.
 */
#ifndef BELAY_INTERP_LOOKUP_INTERNAL_H
#define BELAY_INTERP_LOOKUP_INTERNAL_H

#include "belay/interp.h"

struct owners;

struct lk_want { char *path; size_t len; bool below; belay_lookup_fn fn; void *ctx; int interp; };

struct belay_lookup {
    const struct belay_content *content;
    const char *shadow_lines[2];    /* belay_diff_opts': before, after */
    struct lk_want *w;          /* this round's, sorted by path before a pass */
    size_t n, cap;
    bool sorted;
    struct owners *owners;      /* NULL until a path's owner is asked */
    bool owners_done;           /* the ownership pass was made */
    bool failed;                /* memory: the diff fails */
    int current;                /* whose prepare hook is asking */
    bool hook_failed[BELAY_INTERP_COUNT];   /* an fn of its returned -1: its events are E6's */
};

void lookup_init(struct belay_lookup *lk, const struct belay_content *content);
void lookup_free(struct belay_lookup *lk);
/* The number of entries asked for since the last lookup_round_end. */
size_t lookup_wanted(const struct belay_lookup *lk);
/* One entry of the after-manifest, in its order: delivered to whoever asked
 * for it. An fn that fails marks its interpreter (hook_failed) and is asked
 * no more. */
void lookup_feed(struct belay_lookup *lk, const struct belay_entry *e);
void lookup_round_end(struct belay_lookup *lk);
/* Whether a path's owner was asked and the ownership pass is still to be
 * made; the pass: every entry through lookup_owner_feed, then _done. */
bool lookup_owner_pending(const struct belay_lookup *lk);
int  lookup_owner_feed(struct belay_lookup *lk, const struct belay_entry *e);
void lookup_owner_done(struct belay_lookup *lk);

/*
 *  Ownership (SI-5), on its own: paths asked, then the entries of a
 *  manifest fed in its order (only `var/lib/dpkg/diversions`, the
 *  directory `var/lib/dpkg/info` and its `*.list` files are looked at;
 *  each list's stored copy is read once and matched line by line against
 *  what was asked), then the answers. Memory: the paths asked and one list
 *  at a time.
 */
struct owners *owners_new(void);
void owners_free(struct owners *o);
int  owners_ask(struct owners *o, const char *path, size_t len);         /* 0, -1 (memory) */
int  owners_feed(struct owners *o, const struct belay_entry *e, const struct belay_content *c);
void owners_done(struct owners *o);
enum belay_owned owners_get(const struct owners *o, const char *path, size_t len,
                            const char **pkg, size_t *pkg_len);

/* The owners of `n` paths by the manifest at `manifest` and the store at
 * `store_dir` (NULL: none), for a caller outside a diff (the receipt's
 * folding, SD-3): one pass. 0 with *out (owners_get answers; the caller
 * frees it), or -1 with belay_err. */
int owners_of_manifest(const char *manifest, const char *store_dir, const char *const *paths,
                       const size_t *lens, size_t n, struct owners **out);

#endif
