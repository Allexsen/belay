/*
 *  For a path one manifest lacks: what that manifest's nearest recorded
 *  ancestor says about it -- sealed (an unreadable or mount directory:
 *  nothing below was captured), incomplete (an unstable directory: its
 *  listing may miss names), or nothing (the absence is known).
 *
 *  Fed every entry of one side in path order. It keeps the recorded entries
 *  that are byte-prefixes of where the stream is -- each a prefix of the
 *  next, so a stack of lengths over one path buffer, bounded by the longest
 *  path whatever the manifest's size. It never looks a parent up, so an
 *  entry whose parent is missing (an orphan) needs no special case. The
 *  scope root "." is not a byte-prefix of anything and sorts after "!x", so
 *  its kind is given up front.
 */
#ifndef BELAY_DIFF_ANCESTRY_H
#define BELAY_DIFF_ANCESTRY_H

#include "belay/manifest.h"

#include <stddef.h>

/* ANC_UNSET (0) is no answer at all; classify fails on it (audit 2026-10, R1). */
enum anc { ANC_UNSET, ANC_NONE, ANC_INCOMPLETE, ANC_SEALED };

#define ANC_PATH_MAX 4096

struct ancestry {
    enum anc root;
    char   path[ANC_PATH_MAX];  /* the last entry pushed; every stacked entry is a prefix */
    size_t len[ANC_PATH_MAX + 1];
    unsigned char kind[ANC_PATH_MAX + 1];
    size_t n;
};

/* What an entry, as an ancestor, says about paths below it. */
enum anc ancestry_kind(const struct belay_entry *e);

void ancestry_init(struct ancestry *a, enum anc root);

/* The next entry of this side, in path order. */
void ancestry_feed(struct ancestry *a, const struct belay_entry *e);

/* The nearest recorded ancestor's kind for `path`, which this side lacks and
 * which sorts after every entry fed so far. */
enum anc ancestry_of(struct ancestry *a, const char *path, size_t len);

#endif
