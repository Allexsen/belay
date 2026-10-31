/*
 *  belay's state directory (NOTES/phase5-structure.md §2; decisions Q1, Q3,
 *  Q6, Q8): one directory per scope under the state root, holding one
 *  content store shared by its checkpoints, the checkpoints in order, and a
 *  lock. Nothing in it is ever deleted (Q1: no retention policy yet).
 *
 *    <root>/scopes/<16 hex of sha256(scope)>/
 *        scope                   the scope's resolved path
 *        store/                  content copies, shared (Q1)
 *        lock                    flock(2): one writer at a time
 *        checkpoints/<n>/manifest.ndjson
 *        checkpoints/<n>/meta.json   written last: a checkpoint exists once it does
 *
 *  The root: $BELAY_STATE_DIR, else $XDG_STATE_HOME/belay, else
 *  $HOME/.local/state/belay.
 */
#ifndef BELAY_CLI_STATE_H
#define BELAY_CLI_STATE_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The scope as resolved once (§5.1.1): its path and its identity. */
struct scope {
    char path[PATH_MAX];
    uint64_t dev, ino;
};

/* Test hook: called between realpath() and the open that checks it, so a
 * test can swap a component in the window. NULL in the binary. */
extern void (*scope_resolve_hook)(const char *resolved);

/* Resolves `arg` once: lexical checks, realpath(), then the result opened
 * one component at a time from "/" with O_NOFOLLOW -- a component swapped
 * for a symlink after realpath() is refused, never followed. 0; -1 with
 * belay_err: INVALID (not a directory, changed during resolution), IO
 * (missing, unreadable). */
int scope_resolve(const char *arg, struct scope *out);

struct state {
    char root[PATH_MAX];        /* the state root */
    char dir[PATH_MAX + 64];    /* the scope's directory */
    char store[PATH_MAX + 128];
    struct scope scope;
    uint64_t root_dev, root_ino;   /* the state root's identity: excluded from walks (Q6) */
    int lock_fd;
};

/* Opens (creating when `create`) the state for a resolved scope, and takes
 * its lock when `create`. 0; -1 with belay_err. state_close always. */
int state_open(const struct scope *sc, bool create, struct state *st);
void state_close(struct state *st);

struct checkpoint {
    long id;
    char kind[8];               /* "check", "mark", "diff" */
    int64_t created_ns;
    uint64_t entries, raced, unstable, vanished, excluded;
    bool provisional;
    bool full;                  /* every file read (no prefilter) */
    char full_reason[160];      /* why a mark read every file */
    uint64_t trusted, racy;
};

/* The checkpoints that exist (meta.json written), ascending by id; *n of
 * them in a malloc'd array the caller frees. 0, or -1. */
int state_list(const struct state *st, struct checkpoint **out, size_t *n);

/* The path of checkpoint `id`'s manifest into buf. */
void state_manifest(const struct state *st, long id, char *buf, size_t cap);

/* How a capture runs. */
struct capture_req {
    const char *kind;           /* "check", "mark", "diff" */
    bool prefilter;             /* mark and diff: against the latest checkpoint */
    bool force_full;            /* --full */
    long full_every;            /* a full mark every N marks (Q8); 0: never */
};

/* Captures the scope into a new checkpoint. 0 with *out; -1 with belay_err. */
int state_capture(struct state *st, const struct capture_req *req, struct checkpoint *out);

#endif
