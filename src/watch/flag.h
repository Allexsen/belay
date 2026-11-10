/*
 *  What `belay watch` flags, and why (test/expect/watch-v1.md: FL, FK, BR,
 *  DT). One diff record in, a kind, a level and the words that name it out.
 *  It knows nothing of lines, calls or agents.
 */
#ifndef BELAY_WATCH_FLAG_H
#define BELAY_WATCH_FLAG_H

#include <stdbool.h>
#include <stddef.h>

#include "cli/receipt.h"
#include "util/jsonr.h"

/* FK-1 to FK-12, in the order flags are named. */
enum wkind {
    WK_DONTTOUCH, WK_GIT, WK_AGENT, WK_PRIVILEGE, WK_LOAD, WK_PKG, WK_CI, WK_CRED,
    WK_SYMLINK, WK_HISTORY, WK_UNREAD, WK_COVERAGE, WK_COUNT
};
const char *wkind_name(enum wkind k);

/* limits of a built-in row (BR-L1 to BR-L6) */
#define BR_FILE     1u      /* not a directory */
#define BR_DEPS     2u      /* not in a dependency */
#define BR_NEWDIR   4u      /* not in a new directory */
#define BR_NOTE_MOD 8u      /* noted when modified */
#define BR_NOTE     16u     /* noted */

struct brow { enum wkind kind; const char *label, *pattern; unsigned limits; const char *except; };
extern const struct brow flag_rows[];
extern const size_t flag_n_rows;

/* ---- .belay-donttouch (DT-1 to DT-4) ---- */

#define DT_FILE_MAX     65536u
#define DT_PATTERNS_MAX 256u
#define DT_GLOBSTARS    4u

struct dtlist { char **pat; size_t *len; size_t n; };

/* The file's bytes into a list. 0; or -1 with `why` (at least 96 bytes)
 * saying which line is not a pattern, or which limit was passed. An empty
 * buffer is an empty list. */
int  dtlist_parse(const char *buf, size_t len, struct dtlist *out, char *why, size_t cap);
void dtlist_free(struct dtlist *l);

/* ---- flagging ---- */

struct flagctx {
    const struct dtlist *lists[2];  /* the list in force, and in the step that changes it the new one too (DT-5); NULL: none */
    receipt_mode_fn mode;           /* both manifests' fields, for FK-4 */
    void *mode_ctx;
    /* directories added in this step (BR-L3), kept as records arrive */
    char **newdirs;
    size_t n_newdirs, cap_newdirs;
};

struct wflag {
    enum wkind kind;
    bool note;          /* FL-2: named, no red circle */
    char *text;         /* how the line names it (LN-3); malloc'd */
};

/* One path record of a diff. 1 with *out when it is flagged or noted, 0
 * when it is neither, -1 (memory). Records must be given in the diff's
 * order. *word is the record's outcome as the lines say it (LN-3). */
int flag_record(struct flagctx *x, const struct jval *r, const char *path, size_t len, struct wflag *out,
                const char **word);

/* An event record: 1 with *out for git_history_rewritten (FK-10), else 0; -1 (memory). */
int flag_event(const struct jval *e, struct wflag *out);

void flagctx_free(struct flagctx *x);

/* For `belay watch patterns`: whether a row applies to an entry, by its
 * pattern, exception and the limits that do not depend on a change
 * (BR-L1, BR-L2, BR-L4); and which list a current entry falls under --
 * true with its kind, the reason shown and whether a modification of it
 * would only be noted. */
bool flag_row_applies(const struct brow *r, const char *path, size_t len, bool dir);
/* How many entries a user's pattern matches is counted with this: the
 * dialect's match, the watched directory itself (".") having no component. */
unsigned flag_user_match(const char *pat, size_t plen, const char *path, size_t len);
bool flag_path(const struct flagctx *x, const char *path, size_t len, bool dir, enum wkind *kind, const char **reason,
               bool *note);

/* `len` bytes of a path as a line shows them (LN-7): escaped as the receipt
 * does, cut in the middle past 80 characters. malloc'd; NULL: no memory. */
char *flag_shown(const char *path, size_t len);

/* Whether a path belay did not read matters to a list (CV-3): it matches a
 * row or a pattern, lies below a match, or -- for one whose first component
 * is not `**` -- is an ancestor of something it could match. Limits ignored. */
bool flag_covers(const struct dtlist *list, const char *path, size_t len);

#endif
