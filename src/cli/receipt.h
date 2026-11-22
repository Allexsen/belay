/*
 *  The receipt: diff.v1 rendered for a person (NOTES/phase5-structure.md §5;
 *  decisions §14.7, Q4 of Phase 4). It decides nothing the diff did not:
 *  events first, then every privilege change (caps, setuid, setgid,
 *  sticky, and the inode-flag changes test/expect/inode-flags.md counts)
 *  -- never folded, never filtered -- then the other
 *  records by path; each record at most RECEIPT_FINDINGS findings, then
 *  "and N more"; flagged entries named on their own lines, no global
 *  "provisional" banner. With a classifier (git's view of the repository,
 *  2026-11-04) the other records go tracked first, then untracked -- the
 *  only ones RECEIPT_FOLD cuts -- then what git ignores, one line per
 *  top-level directory; a repository's own .git folds to one line, what
 *  git reports there staying unless git's events say it (as the dogfood
 *  receipt does), moves that left a ref in place counted. --all folds
 *  nothing. Every string from the diff is printed escaped:
 *  control bytes, C1 controls, invisible format and bidi characters and
 *  bytes that are not UTF-8 as \xNN, a
 *  backslash as \\ -- a path cannot forge a line, a heading or a terminal
 *  sequence (review 2026-10-31, Phase 5, 7).
 */
#ifndef BELAY_CLI_RECEIPT_H
#define BELAY_CLI_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define RECEIPT_FINDINGS 15     /* per record, then "and N more" */
#define RECEIPT_FOLD     50     /* events or other records shown, then "and N more" (unless all) */

/* What the receipt needs of a path on one side that diff.v1 does not carry
 * yet (pin PR #24): its mode, and whether it has file capabilities. */
struct receipt_meta {
    uint32_t mode;
    bool has_caps;
    bool has_iflags;            /* its inode flags were read (inode-flags IF-8) */
    uint64_t iflags;
    bool sealed;                /* manifest v5: its hash is keyed, its content not kept */
};

/* A path's metadata on a side (0 before, 1 after): 0 and *m, or -1 when the
 * side does not record the path. Records arrive in path order, so a lookup
 * may move forward only. `path` is the bytes, base64 already decoded. */
typedef int (*receipt_mode_fn)(void *ctx, int side, const char *path, size_t len, struct receipt_meta *m);

/* What git says of n paths (gitclass.h's GC_ values in out): 0, or -1 when
 * it cannot say. */
typedef int (*receipt_class_fn)(void *ctx, const char *const *paths, const size_t *lens, const bool *dir, size_t n,
                                unsigned char *out);

/* Which package's file list names each of n paths, by the dpkg database of a
 * side's manifest (0 before, 1 after; system-interpreters.md SI-5): owner[i]
 * a malloc'd name the receipt frees (`nginx-common`, `libc6:amd64`), or NULL
 * for none or not known. 0, or -1 when it cannot say. */
typedef int (*receipt_owner_fn)(void *ctx, int side, const char *const *paths, const size_t *lens, size_t n,
                                char **owner);

/* How many of a diff's paths the receipt asks owners of (BELAY_OWNER_ASKS);
 * the rest are listed as they are, and one line says so. A variable for
 * the tests. */
extern size_t receipt_owner_asks;

/* What the receipt asks of the after manifest for systemd's events
 * (system-interpreters.md SY-3a, SY-4), in one read of it. `timers`: file
 * names of timers (`probe.timer`); linked[i]: whether a symbolic link of
 * that name stands in some directory named `<x>.wants` or `<x>.requires`.
 * `homes`: home directories relative to the scope (`home/u`); linger[i]: 1
 * when `var/lib/systemd/linger/<name>` is recorded for the one user whose
 * home that is by the kept `etc/passwd`, 0 when it is not, -1 when it
 * cannot be told (no copy of passwd, no user or several with that home,
 * the linger directory not recorded). */
#define RECEIPT_SYSTEM_ASKS 4096        /* timers, and homes, asked about; past it nothing is said of the rest */
struct receipt_system {
    const char *const *timers;
    size_t n_timers;
    bool *linked;
    const char *const *homes;
    size_t n_homes;
    int *linger;
};
/* 0, or -1 when it cannot say. */
typedef int (*receipt_system_fn)(void *ctx, struct receipt_system *q);

/* A system watch's receipt (watch-system.md WS-R1 to WS-R6): the events,
 * runtime records and records in sections, in this order, each only when
 * it has something. setuid takes the privilege changes; secret, trust and
 * firewall the records `section` gives them; a record an event names is
 * that event's; the rest are `changes`, up to 20. */
enum receipt_sec { RS_INSTALLED, RS_SERVICES, RS_RUNNING, RS_LISTENING, RS_USER, RS_CRON, RS_SUDO, RS_SSH, RS_SETUID,
                   RS_SECRET, RS_TRUST, RS_FIREWALL, RS_INIT, RS_CONFIG, RS_COUNT };
#define RECEIPT_CHANGES 20
/* RS_SECRET, RS_TRUST or RS_FIREWALL for a record's path; -1: none of them. */
typedef int (*receipt_section_fn)(void *ctx, const char *path, size_t len, bool dir);
struct receipt_sections {
    const char *head;           /* printed first, as it is: could not read, kernel record, end state */
    const char *roots;          /* WS-10: "+a, -b", the first line of changes; NULL: the roots did not change */
    const char *put_back;       /* the put back section's lines; NULL: it has none */
    const char *tail;           /* printed last, as it is: not compared, not read */
    receipt_section_fn section;
    void *section_ctx;
    const char *const *meta;    /* the metadata roots: the records folded into packages, counted per root */
    size_t n_meta;
};

struct receipt_opts {
    const char *from, *to;      /* how the two sides are named in the heading */
    bool all;                   /* nothing folded */
    receipt_mode_fn mode;       /* NULL: setuid/setgid/sticky and caps on added or removed files cannot be told */
    void *mode_ctx;
    receipt_class_fn classify;  /* NULL, or -1 from it: changes in path order, as before (2026-11-04) */
    void *class_ctx;
    const char *class_note;     /* said once when paths were classified: they were, as the repository is now */
    receipt_owner_fn owner;     /* NULL, or -1 from it: no record folds into a package's line (SD-3) */
    void *owner_ctx;
    receipt_system_fn system;   /* NULL, or -1 from it: `not linked into any target` and `lingering` are not said */
    void *system_ctx;
    const struct receipt_sections *sections;    /* NULL: a diff's receipt, as before */
};

/* Reads diff.v1 from `diff`, writes the receipt to `out`. 0; -1 with
 * belay_err (a line that is not diff.v1, memory, write). */
int receipt_render(FILE *diff, FILE *out, const struct receipt_opts *o);

/* `s` written to `f` escaped as the receipt escapes paths: for any text
 * belay prints that came from the filesystem or its own state (a scope, a
 * reason read back, an error naming a path). */
void receipt_fputs(FILE *f, const char *s);

/* For `belay watch`, which names what it flags as the receipt would:
 * `len` bytes escaped as the receipt escapes a path (malloc'd; NULL: no
 * memory); a diff record's path as bytes (0, or -1); and what makes a
 * record a privilege change, in the privilege section's words (malloc'd),
 * or NULL when it is none. */
struct jval;
char *receipt_escaped(const char *s, size_t len);
int   receipt_record_path(const struct jval *r, char *buf, size_t cap, size_t *len);
char *receipt_privilege_words(const struct jval *r, const char *path, size_t len, receipt_mode_fn mode, void *ctx);

#endif
