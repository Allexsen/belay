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

#include <stdbool.h>
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
    BELAY_KEEP_STORE,           /* claimed, always stored whatever its size */
    BELAY_KEEP_STORE_BOUNDED    /* claimed, stored within the store limit, text or not */
};

struct belay_claim {
    enum belay_interp_id interp;
    enum belay_keep keep;
};

/* Classifies `abs_path` (`len` bytes, need not be NUL-terminated). Never
 * fails: an unclaimed path gets {BINARY, KEEP_DEFAULT}. */
void belay_interp_classify(const char *abs_path, size_t len, struct belay_claim *out);

const char *belay_interp_name(enum belay_interp_id id);

struct belay_entry;

/* The interpreter that explains a path in a diff, from its claim and its two
 * entries (NULL where absent): the claim's, or TEXT for an unclaimed path
 * that is stored on every side it exists on (decision 2026-10-31, Q6). */
enum belay_interp_id belay_interp_dispatch(const struct belay_claim *claim,
                                           const struct belay_entry *before,
                                           const struct belay_entry *after);

/*
 *  Explaining a change (diff.v1, "Interpreters"; pins test/expect/finding-
 *  kinds.md and diff-events.md). For a path whose outcome is not unchanged,
 *  the interpreter that claims it receives the path, both entries, the
 *  core's verdict and the stored content, and adds structured findings
 *  about that path; facts about a package are event records, added by its
 *  end hook once every path has been seen. Findings are annotations only:
 *  nothing here can set or change an outcome. An interpreter gives each
 *  finding's kind and field values; the core checks them against the kind's
 *  row (a finding that breaks it becomes invalid_finding) and renders the
 *  text from the kind's template. Failures degrade to the interpreter's own
 *  output (R11): an error is the finding could_not_interpret.
 */

/* One field value, in the kind's field order: `s`/`len` for a string,
 * `i` for an int, `b` for a bool. */
struct belay_fv { const char *s; size_t len; uint64_t i; bool b; };

struct belay_findings;          /* one path's findings, kept by the core */
struct belay_events;            /* one interpreter's events over one diff */

/* Is s/len a string field's value the core accepts (at most 1,024 bytes,
 * UTF-8, no NUL)? An interpreter that must not emit what would be replaced
 * checks with this, the core's own rule. */
bool belay_finding_string_ok(const char *s, size_t len);

/* Adds a finding of `kind` (enum finding_kind, src/schema/finding_schema.h)
 * to the path being explained. Past 4,096 on one record they are counted
 * into one final and_more. 0, or -1 (out of memory: the diff fails). */
int belay_finding(struct belay_findings *f, int kind, const struct belay_fv *v, size_t n);

/* Adds an event of `kind` listing `npaths` paths (relative to the scope;
 * sorted and deduplicated by the core). One that breaks its kind's row is
 * replaced, in its place, by an invalid_finding event naming its paths (E9);
 * one naming no path fails the end hook (E6). Past 65,536 for one
 * interpreter they are counted into one final and_more. `flags`:
 * BELAY_EVENT_PROVISIONAL when a path it was derived from has the outcome
 * unknown (E2). 0, or -1 (out of memory). */
#define BELAY_EVENT_PROVISIONAL 1u
int belay_event(struct belay_events *ev, int kind, const struct belay_fv *v, size_t n,
                const char *const *paths, const size_t *path_lens, size_t npaths, unsigned flags);

/* E10: one could_not_interpret event naming files the interpreter claims and
 * cannot interpret; its other events stand. 0, or -1 (out of memory). */
int belay_event_not_interpreted(struct belay_events *ev, const char *const *paths,
                                const size_t *path_lens, size_t npaths, unsigned flags);

/*
 *  Stored copies, read back for an interpreter (decision 2026-10-31, Q1:
 *  the store reaches the diff through belay_diff's options). The store is
 *  opened read-only and never created; every object read is hashed and must
 *  match its name, so a stale, planted or truncated copy is an error, never
 *  content.
 */
struct belay_content;

/* 0, or -1 with belay_err when `store_dir` cannot be opened as a directory
 * (a symlink in its last component included). */
int  belay_content_open(const char *store_dir, struct belay_content **out);
void belay_content_close(struct belay_content *c);

/* Object `sha256_hex`, read whole when it is at most `max` bytes. 0 with
 * *buf (malloc'd, NUL after the last byte; the caller frees it) and *len; or
 * -1 with belay_err: CORRUPT when it is absent (errno ENOENT), not a regular
 * file, or does not hash to its name; RANGE when it is larger than `max`; INVALID when
 * `sha256_hex` is not 64 lowercase hex digits; IO, NOMEM. */
int  belay_content_get(const struct belay_content *c, const char *sha256_hex, size_t max,
                       unsigned char **buf, size_t *len);
struct belay_interp_input {
    const char *path;                   /* relative to the scope */
    size_t path_len;
    const char *abs_path;               /* scope + "/" + path: what dispatch matched */
    size_t abs_len;
    const struct belay_entry *before;   /* NULL: added */
    const struct belay_entry *after;    /* NULL: removed */
    const char *outcome;                /* the core's verdict, read-only: a diff.v1 outcome */
    uint32_t changed;                   /* the fields that differ: bit i is the manifest's
                                           field i (its key order) */
    const struct belay_content *content;  /* NULL when the diff has no store */
};

enum belay_interp_result { BELAY_INTERP_FINDINGS, BELAY_INTERP_DECLINE, BELAY_INTERP_ERROR };

/* One interpreter. Over one diff: begin once before the first path (its
 * state, or NULL), explain for each path it claims (`out` empty at first),
 * end once after the last -- with `ev` to add its events to after a diff
 * that read every path, NULL when the diff failed and only the state is to
 * be freed. An end that returns BELAY_INTERP_ERROR has its events replaced
 * by one could_not_interpret event naming the paths it was given (diff-
 * events E6). Any may be NULL. */
struct belay_interp {
    enum belay_interp_id id;
    void *(*begin)(void);
    enum belay_interp_result (*explain)(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out);
    enum belay_interp_result (*end)(void *state, struct belay_events *ev);
};

/* The built-in interpreter for `id`. */
const struct belay_interp *belay_interp_builtin(enum belay_interp_id id);

#endif /* BELAY_INTERP_H */
