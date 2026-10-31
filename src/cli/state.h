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
 *  $HOME/.local/state/belay. It must be owned by the user belay runs as and
 *  writable by no one else; everything under it is opened from directory
 *  descriptors without following symlinks, and files are created O_EXCL
 *  (review 2026-10-31, Phase 5, 1 and 2). A scope that is the root or
 *  inside it is refused (9).
 */
#ifndef BELAY_CLI_STATE_H
#define BELAY_CLI_STATE_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* The scope as resolved once (§5.1.1): its path and its identity. */
struct scope {
    char path[PATH_MAX];
    uint64_t dev, ino;
};

/* Test hook: called between realpath() and the open that checks it, so a
 * test can swap a component in the window. NULL in the binary. */
extern void (*scope_resolve_hook)(const char *resolved);
/* Test hook: called after the scope was resolved and just before the walk
 * opens it again. NULL in the binary. */
extern void (*state_capture_hook)(const char *scope);

/* Resolves `arg` once: realpath(), then the result opened
 * one component at a time from "/" with O_NOFOLLOW (O_PATH or O_SEARCH
 * where there is one: search permission is enough) -- a component swapped
 * for a symlink after realpath() is refused, never followed. 0; -1 with
 * belay_err: INVALID (missing, not a directory, unreadable, changed during
 * resolution), IO (anything else), RANGE (too long). */
int scope_resolve(const char *arg, struct scope *out);

struct state {
    char root[PATH_MAX];        /* the state root */
    char dir[PATH_MAX + 64];    /* the scope's directory */
    char store[PATH_MAX + 128];
    struct scope scope;
    uint64_t root_dev, root_ino;   /* the state root's identity: excluded from walks (Q6) */
    int dir_fd, cp_fd;          /* the scope's directory and checkpoints/; -1: none yet (log, no create) */
    int lock_fd;
};

/* Opens (creating when `create`) the state for a resolved scope, and takes
 * its lock when `create` -- before anything in the scope's directory is
 * written (review 2026-10-31, Phase 5, 3); when another belay holds it, one
 * line on `note` says belay is waiting. 0; -1 with belay_err: INVALID
 * (refused: the root is another user's or writable by others, the scope is
 * the root or inside it), CORRUPT (the directory is another scope's, a
 * symlink or not what belay wrote), IO. state_close always. */
int state_open(const struct scope *sc, bool create, struct state *st, FILE *note);
void state_close(struct state *st);

/* A checkpoint id from its decimal text: digits only, no leading zero, at
 * most STATE_ID_DIGITS of them. The id, or 0 when `s` is not one. */
#define STATE_ID_DIGITS 9
long state_id_parse(const char *s);

struct checkpoint {
    long id;
    char kind[8];               /* "check", "mark", "diff" */
    int64_t created_ns;
    uint64_t entries, raced, unstable, vanished, excluded;
    bool provisional;
    bool full;                  /* every file read (no prefilter) */
    char full_reason[160];      /* why a mark read every file */
    uint64_t trusted, racy;
    int64_t walk_start_ns;      /* when its walk began, on the scope's clock; 0: unknown (previous.h) */
    bool walk_start_reference;  /* prefiltered against the previous walk's start, not its newest ctime */
};

/* How a checkpoint's prefilter was referenced: "none" (every file read),
 * "walk_start" or "newest_ctime" (the previous walk's start was not known:
 * belay's state is on another filesystem than the scope). */
const char *state_reference(const struct checkpoint *c);

/* Checkpoint `id`'s manifest, opened from the directory fds without
 * following a link or waiting on a FIFO: 0 when it is a regular file; -1
 * with belay_err (CORRUPT) otherwise. Before its path is handed on. */
int state_check_manifest(const struct state *st, long id);

/* The checkpoints that exist (meta.json written), ascending by id; *n of
 * them in a malloc'd array the caller frees. A directory without meta.json
 * is a capture that never finished and is skipped; a meta.json that is not
 * a regular file, is too large, or does not parse is CORRUPT -- never
 * skipped in silence, never waited on. 0, or -1. */
int state_list(const struct state *st, struct checkpoint **out, size_t *n);

/* `s` as one JSON member into buf: "key":"..." when it is UTF-8, else
 * "key_b64":"..." in base64, as the manifest does for paths. 0, or -1 when
 * it does not fit. */
int state_json_member(char *buf, size_t cap, const char *key, const char *s);

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
