/*
 *  The protect spec (test/expect/protect-spec.md): what a task declares
 *  about its scope -- paths that must stay as they were, the bytes a file
 *  must hold, packages frozen, where its executables live. It comes from
 *  the task package, never from the environment judged (BELAY_DESIGN §6, 4).
 *
 *  Read strictly (PS-R2): a key this reader does not know, a key given
 *  twice, a value of another type or outside its row refuses the whole
 *  spec, so a misspelt key never silently drops a protection.
 */
#ifndef BELAY_POLICY_PROTECT_H
#define BELAY_POLICY_PROTECT_H

#include <stdbool.h>
#include <stddef.h>

#define PROTECT_SPEC_MAX    (1u << 20)  /* bytes of the file (PS-R1) */
#define PROTECT_RULES_MAX   4096u       /* PS-2 */
#define PROTECT_PATTERN_MAX 4096u       /* bytes of a pattern (PS-P1) */
#define PROTECT_DIRS_MAX    256u        /* PS-7 */
#define PROTECT_HASH_MAX_BYTES (4ull << 30)  /* a capture's hash limit with a spec (PS-C3, decision 159) */

/* A rule's modes (PS-4): a bit each. */
enum { PROTECT_NO_WRITE = 1u, PROTECT_NO_DELETE = 2u, PROTECT_NO_CREATE = 4u };

struct protect_rule {
    char    *path;                  /* the pattern, NUL-terminated; path_len bytes */
    size_t   path_len;
    unsigned modes;                 /* PROTECT_NO_* */
    bool     has_sha256;            /* expected_sha256 given (PS-5) */
    char     sha256[65];
};

struct protect_spec {
    struct protect_rule *rules;     /* in the spec's order: a flag names the first that matches */
    size_t   n_rules;
    bool     frozen_packages;       /* PS-6 */
    bool     has_path_dirs;         /* given: replaces the default (PS-7) */
    char   **path_dirs;             /* patterns, NUL-terminated */
    size_t   n_path_dirs;
    char     sha256[65];            /* of the bytes as read (PS-R3) */
};

/* Parses a spec from `len` bytes. 0, or -1 with belay_err INVALID naming
 * what was refused (and *out left empty). */
int protect_parse(const char *buf, size_t len, struct protect_spec *out);

/* Reads the file at `path` (at most PROTECT_SPEC_MAX bytes) and parses it.
 * 0, or -1 with belay_err set: IO when it cannot be read, INVALID when it
 * is refused. */
int protect_load(const char *path, struct protect_spec *out);

void protect_free(struct protect_spec *s);

/* Whether `p` (n bytes) is a pattern PS-P1 allows. */
bool protect_pattern_valid(const char *p, size_t n);

/* Whether the path (relative to the scope, n bytes) matches the pattern
 * (PS-P2 to PS-P4). */
bool protect_match(const char *pat, size_t plen, const char *path, size_t n);

/* Whether some path at or below `dir` (relative to the scope) could match
 * the pattern: an exclusion there covers it (PS-C2). */
bool protect_covers(const char *pat, size_t plen, const char *dir, size_t n);

#endif
