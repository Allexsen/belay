/*
 *  Interpreter dispatch (M1 step 4.1).
 *
 *  Decides, from a path alone, which interpreter owns a regular file and what
 *  the capture side must keep for it. Pure: no filesystem access, so not on
 *  the blast-radius list.
 *
 *  Why capture needs this before any interpreter exists: an interpreter can
 *  only explain a change if the BEFORE content was kept. dpkg's status file,
 *  pip's RECORD and git's refs must therefore be stored at check time
 *  regardless of the size threshold, or the later diff has nothing to compare
 *  against (decision 2026-10-20). Some claimed files are only hashed: git's
 *  index can be hundreds of MB, and M1's git scope needs only to know it
 *  changed.
 *
 *  Matching is on the ABSOLUTE path (scope root + relative path), so
 *  "/var/lib/dpkg/status" is recognised whether the scope is "/", "/var" or a
 *  container root. Patterns are fnmatch(3) without FNM_PATHNAME, so "*" spans
 *  "/". Matching is bytewise: belay never calls setlocale.
 */
#ifndef BELAY_INTERP_H
#define BELAY_INTERP_H

#include <stddef.h>
#include <stdint.h>

enum belay_interp_id {
    BELAY_INTERP_BINARY = 0,    /* fallback: size + hash; claims nothing */
    BELAY_INTERP_TEXT,          /* unified diff for stored small text files */
    BELAY_INTERP_PIP,
    BELAY_INTERP_DPKG,
    BELAY_INTERP_GIT,
    BELAY_INTERP_COUNT
};

enum belay_keep {
    BELAY_KEEP_DEFAULT = 0,     /* store only if under the size threshold and text */
    BELAY_KEEP_HASH,            /* claimed, hash only, never stored */
    BELAY_KEEP_STORE            /* claimed, always stored whatever its size */
};

struct belay_claim {
    enum belay_interp_id interp;
    enum belay_keep keep;
};

/* Classifies `abs_path` (`len` bytes, need not be NUL-terminated). Never
 * fails: an unclaimed path gets {BINARY, KEEP_DEFAULT}. */
void belay_interp_classify(const char *abs_path, size_t len, struct belay_claim *out);

const char *belay_interp_name(enum belay_interp_id id);

/*
 *  Explaining a change (diff.v1, "Interpreters"). For a path whose outcome
 *  is not unchanged, the interpreter that claims it receives the path, both
 *  entries and the core's verdict, and returns findings -- short strings,
 *  emitted as the record's "findings" -- or declines. Findings are
 *  annotations only: nothing here can set or change the outcome, so an
 *  interpreter cannot hide a change. Its failures degrade to its own output
 *  (R11): an error is the finding "could not interpret", a finding that is
 *  not valid UTF-8 is replaced by "invalid finding", and neither stops the
 *  diff. In this version every interpreter declines; Phase 4 adds pip, dpkg,
 *  git and text.
 */
#define BELAY_FINDINGS_MAX   16
#define BELAY_FINDING_BYTES  256

struct belay_findings {
    size_t n;
    char item[BELAY_FINDINGS_MAX][BELAY_FINDING_BYTES];
};

/* Appends one finding, truncated to BELAY_FINDING_BYTES - 1 bytes on a
 * character boundary, never inside a UTF-8 sequence. 0, or -1 when
 * BELAY_FINDINGS_MAX are already recorded. */
int belay_findings_add(struct belay_findings *f, const char *text);

struct belay_entry;
struct belay_content;                   /* stored copies by hash: no store reaches the diff yet */
struct belay_interp_input {
    const char *path;                   /* relative to the scope */
    size_t path_len;
    const struct belay_entry *before;   /* NULL: added */
    const struct belay_entry *after;    /* NULL: removed */
    const char *outcome;                /* the core's verdict, read-only: a diff.v1 outcome */
    uint32_t changed;                   /* the fields that differ: bit i is the manifest's
                                           field i (its key order) */
    const struct belay_content *content;  /* NULL in this version */
};

enum belay_interp_result { BELAY_INTERP_FINDINGS, BELAY_INTERP_DECLINE, BELAY_INTERP_ERROR };

/* One interpreter. Over one diff: begin once before the first path (its
 * state, or NULL), explain for each path it claims (`out` cleared first),
 * end once after the last -- also when the diff fails. Any may be NULL. */
struct belay_interp {
    enum belay_interp_id id;
    void *(*begin)(void);
    enum belay_interp_result (*explain)(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out);
    void (*end)(void *state);
};

/* The built-in interpreter for `id`. */
const struct belay_interp *belay_interp_builtin(enum belay_interp_id id);

#endif /* BELAY_INTERP_H */
