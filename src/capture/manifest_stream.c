/*
 *  Rules over the sequence of entries (manifest_stream.h).
 */
#include "manifest_stream.h"
#include "manifest_lex.h"

#include "belay/error.h"

#include <string.h>

/*
 *  Where an entry may be, by the roots (manifest-v5 V5-E3, V5-E4, V5-E5, V5-2;
 *  its addendum V5-A4): what a capture writes, and nothing else.
 *    - No roots: a whole scope, as version 4: none of the four flags.
 *    - Under a root (the longest listed path that is the entry's or above
 *      it): the root was found; no `partial`; `meta` only where the root is
 *      metadata, `sealed` only where it is content.
 *    - Outside every root: the directory it is in is partial, and it is a
 *      directory, or a link directly under the scope root or on the way to a
 *      root; never `meta` or `sealed`.
 *  `parent_partial`: the recorded parent carries `partial` (the scope root's
 *  own is checked when the trailer is read: it may sort after its children).
 *  No memory: the roots are the header's, looked up by binary search.
 */
static int zone_check(const struct belay_manifest_header *h, const struct belay_entry *e, bool top, bool parent_partial) {
    if (h->n_roots == 0 || h->roots == NULL) {
        if (e->partial || e->not_read || e->meta || e->sealed)
            return lex_corrupt("partial, not_read, meta or sealed in a capture of a whole scope (no roots)");
        return 0;
    }
    if (e->path_len == 1 && e->path[0] == '.') return 0;
    const struct belay_root *root = NULL;
    for (size_t k = e->path_len; k > 0 && root == NULL; ) {
        size_t lo = 0, hi = h->n_roots;
        while (lo < hi) {
            const size_t mid = lo + (hi - lo) / 2;
            const char *r = h->roots[mid].path;
            const size_t rl = strlen(r), m = rl < k ? rl : k;
            int c = memcmp(r, e->path, m);
            if (c == 0) c = (rl > k) - (rl < k);
            if (c == 0) { root = &h->roots[mid]; break; }
            if (c < 0) lo = mid + 1;
            else hi = mid;
        }
        do k--; while (k > 0 && e->path[k] != '/');     /* the next shorter prefix */
    }
    if (root != NULL) {
        if (!root->found) return lex_corrupt("an entry at or below a root that was not found");
        if (e->partial) return lex_corrupt("partial on a directory under a root");
        if (e->meta && root->cls != BELAY_ROOT_METADATA) return lex_corrupt("meta under a content root");
        if (e->sealed && root->cls != BELAY_ROOT_CONTENT) return lex_corrupt("sealed under a metadata root");
        return 0;
    }
    const bool recorded = e->type == BELAY_T_DIR ||
                          (e->type == BELAY_T_LNK && (top || belay_manifest_root_below(h, e->path, e->path_len)));
    if (!recorded || (!top && !parent_partial) || e->meta || e->sealed)
        return lex_corrupt("an entry outside every root that a partial directory does not record");
    return 0;
}

int stream_entry(struct stream *s, const struct belay_manifest_header *h, const struct belay_entry *e) {
    /* Strictly increasing raw-path order: the comparator merges two
     * manifests and would mis-pair out-of-order or duplicated entries. */
    size_t common = 0;          /* length of the prefix shared with prev */
    if (s->have_prev) {
        const size_t n = s->prev_len < e->path_len ? s->prev_len : e->path_len;
        while (common < n && s->prev[common] == e->path[common]) common++;
        const bool greater = common < n
            ? (unsigned char)s->prev[common] < (unsigned char)e->path[common]
            : s->prev_len < e->path_len;
        if (!greater)
            return lex_corrupt(common == n && s->prev_len == e->path_len ? "duplicate path"
                                                                      : "entries out of order");
    }
    memcpy(s->prev, e->path, e->path_len);
    s->prev_len = e->path_len;
    s->have_prev = true;

    /* Nothing below a directory that was not descended -- the writer never
     * emits such an entry, and one appearing would contradict the flag that
     * tells the comparator "contents unknown". A sealed prefix longer than
     * the shared one is behind us for good. One of exactly the shared length
     * is a prefix of this path: the byte after it decides -- '/' is an entry
     * below it, above '/' is past its range, below '/' (as in "d!x") is
     * neither. Shorter ones are untouched: this path agrees with prev there. */
    while (s->n_sealed > 0 && s->sealed[s->n_sealed - 1] > common) s->n_sealed--;
    if (s->n_sealed > 0 && s->sealed[s->n_sealed - 1] == common) {
        const unsigned char next = (unsigned char)e->path[common];
        if (next == '/')
            return lex_corrupt(s->sealed_by_rule[s->n_sealed - 1] ? "entry below a not_read directory"
                                                                  : "entry below an unreadable or mounted directory");
        if (next > '/') s->n_sealed--;
    }
    /* The parent: popped as the sealed stack is, then it must be the recorded
     * directory of exactly the parent's length. Names with no '/' have the
     * root as parent, which the trailer checks (it may sort after them). */
    while (s->n_dirs > 0 && s->dirs[s->n_dirs - 1] > common) s->n_dirs--;
    if (s->n_dirs > 0 && s->dirs[s->n_dirs - 1] == common && (unsigned char)e->path[common] > '/')
        s->n_dirs--;
    size_t plen = e->path_len;
    while (plen > 0 && e->path[plen - 1] != '/') plen--;
    if (plen > 0) {
        size_t i = s->n_dirs;
        while (i > 0 && s->dirs[i - 1] > plen - 1) i--;
        if (i == 0 || s->dirs[i - 1] != plen - 1)
            return lex_corrupt("orphan: the parent directory is not recorded");
        if (zone_check(h, e, false, s->dir_partial[i - 1]) == -1) return -1;
    } else if (zone_check(h, e, true, false) == -1) {
        return -1;
    }

    /* "." is not a prefix of the paths below it; an unreadable root is
     * checked at the trailer instead (it must be the only entry). */
    if (e->type == BELAY_T_DIR && !(e->path_len == 1 && e->path[0] == '.')) {
        if (s->n_dirs == SEALED_MAX)            /* unreachable: see SEALED_MAX */
            return lex_corrupt("too many nested directories");
        s->dir_partial[s->n_dirs] = e->partial;
        s->dirs[s->n_dirs++] = e->path_len;
        if (e->unreadable || e->is_mount || e->not_read) {
            if (s->n_sealed == SEALED_MAX)      /* unreachable: see SEALED_MAX */
                return lex_corrupt("too many nested sealed directories");
            s->sealed_by_rule[s->n_sealed] = e->not_read;
            s->sealed[s->n_sealed++] = e->path_len;
        }
    }

    if (e->path_len == 1 && e->path[0] == '.') {
        if (e->type != BELAY_T_DIR) return lex_corrupt("scope root is not a directory");
        if (e->is_mount) return lex_corrupt("scope root flagged as a mount");
        s->have_root = true;
        s->root_partial = e->partial;
        s->root_sealed = e->unreadable || e->not_read;
        /* A not_read root was not entered either (V5-E2). */
        s->root_unreadable = e->unreadable || e->not_read;
    }
    s->n_entries++;
    if (e->unreadable) s->n_unreadable++;
    if (e->unstable)   s->n_unstable++;
    if (e->is_mount)   s->n_mounts++;
    if (e->raced)    s->n_raced++;
    if (e->writer_open) s->n_writer_open++;
    if (e->not_read) s->n_not_read++;
    if (e->meta) s->n_meta++;
    if (e->sealed) s->n_sealed_flag++;
    if (e->type == BELAY_T_DIR && (e->unreadable || e->is_mount || e->not_read)) s->n_sealing++;
    return 0;
}

int stream_end(const struct stream *s, const struct belay_manifest_header *h, const uint64_t v[TR_COUNT],
               const struct belay_manifest_stats *t) {
    /* V5-E3: with roots the scope root is on the way to them, unless it could not be listed at all. */
    if (h->n_roots > 0 && s->have_root && !s->root_partial && !s->root_sealed)
        return lex_corrupt("a capture of roots whose scope root is not partial");
    const size_t writer_open = t->writer_open;
    if (t->racy_listed != s->n_racy) {              /* manifest-v5-addendum V5-A2 */
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: trailer says %zu racy, read %zu", t->racy_listed, s->n_racy);
        return -1;
    }
    if (t->not_read != s->n_not_read || t->meta != s->n_meta || t->sealed != s->n_sealed_flag) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: trailer says %zu not_read / %zu meta / %zu sealed, "
                      "read %zu / %zu / %zu", t->not_read, t->meta, t->sealed, s->n_not_read, s->n_meta,
                      s->n_sealed_flag);
        return -1;
    }
    if (writer_open != s->n_writer_open) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "manifest: trailer says %zu writer_open, read %zu",
                      writer_open, s->n_writer_open);
        return -1;
    }
    if (v[TR_ENTRIES] != s->n_entries || v[TR_UNREADABLE] != s->n_unreadable || v[TR_UNSTABLE] != s->n_unstable ||
        v[TR_MOUNTS] != s->n_mounts || v[TR_RACED] != s->n_raced) {
        belay_err_set(BELAY_ERR_CORRUPT, 0,
                      "manifest: trailer says %llu entries / %llu unreadable / %llu unstable / "
                      "%llu mounts / %llu raced, read %zu / %zu / %zu / %zu / %zu",
                      (unsigned long long)v[TR_ENTRIES], (unsigned long long)v[TR_UNREADABLE],
                      (unsigned long long)v[TR_UNSTABLE], (unsigned long long)v[TR_MOUNTS],
                      (unsigned long long)v[TR_RACED], s->n_entries, s->n_unreadable,
                      s->n_unstable, s->n_mounts, s->n_raced);
        return -1;
    }
    if (!s->have_root) return lex_corrupt("no entry for the scope root \".\"");
    /* An unreadable root was not walked, so it is the only entry. Checked here
     * rather than per entry because names sorting before "." (such as "!x")
     * are read before the root itself. */
    if (s->root_unreadable && s->n_entries != 1)
        return lex_corrupt("entries recorded under an unreadable scope root");
    return 0;
}
