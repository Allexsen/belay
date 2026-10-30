/*
 *  Rules over the sequence of entries (manifest_stream.h).
 */
#include "manifest_stream.h"
#include "manifest_lex.h"

#include "belay/error.h"

#include <string.h>

int stream_entry(struct stream *s, const struct belay_entry *e) {
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
        if (next == '/') return lex_corrupt("entry below an unreadable or mounted directory");
        if (next > '/') s->n_sealed--;
    }
    /* "." is not a prefix of the paths below it; an unreadable root is
     * checked at the trailer instead (it must be the only entry). */
    if (e->type == BELAY_T_DIR && (e->unreadable || e->is_mount) &&
        !(e->path_len == 1 && e->path[0] == '.')) {
        if (s->n_sealed == SEALED_MAX)          /* unreachable: see SEALED_MAX */
            return lex_corrupt("too many nested sealed directories");
        s->sealed[s->n_sealed++] = e->path_len;
    }

    if (e->path_len == 1 && e->path[0] == '.') {
        if (e->type != BELAY_T_DIR) return lex_corrupt("scope root is not a directory");
        if (e->is_mount) return lex_corrupt("scope root flagged as a mount");
        s->have_root = true;
        s->root_unreadable = e->unreadable;
    }
    s->n_entries++;
    if (e->unreadable) s->n_unreadable++;
    if (e->unstable)   s->n_unstable++;
    if (e->is_mount)   s->n_mounts++;
    if (e->raced)    s->n_raced++;
    return 0;
}

int stream_end(const struct stream *s, const uint64_t v[TR_COUNT]) {
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
