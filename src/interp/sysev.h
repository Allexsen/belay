/*
 *  What the system interpreters share (test/expect/system-interpreters.md):
 *  reading the two sides of a claimed file or saying it cannot be
 *  interpreted (SI-2), comparing its lines as multisets (SI-3), and keeping
 *  the events of one diff until the end hook writes them in the pinned
 *  order (SI-1, diff-events E13) with the owner of each filled in (SI-5).
 *  The state is bounded: at most EVENTS_PER_INTERP events and SYS_STATE_MAX
 *  bytes, whatever the files hold (E5).
 */
#ifndef BELAY_INTERP_SYSEV_H
#define BELAY_INTERP_SYSEV_H

#include "belay/interp.h"
#include "schema/finding_schema.h"

#include <stdint.h>

#define SYS_FILE_MAX  (4u * 1024u * 1024u)      /* bytes of one side read; larger: not interpreted */
#define SYS_STATE_MAX (64u * 1024u * 1024u)     /* bytes of one interpreter's per-diff state */

/* ---- the two sides of a claimed file ---- */

struct sysfile { unsigned char *buf[2]; size_t len[2]; bool have[2]; };   /* [0] before, [1] after */

/* Whether the path's outcome is `unknown`: it is read all the same and its
 * events are provisional (E2), and its record gets no finding (P8). */
bool sys_prov(const struct belay_interp_input *in);

/* The kept copies of the sides the path exists on. false when it cannot be
 * interpreted: a side that is there is not a regular file, is sealed or was
 * not read, has no copy that can be read whole within SYS_FILE_MAX, or
 * holds a NUL byte (none of the formats read here has one). */
bool sys_read(const struct belay_interp_input *in, struct sysfile *f);
void sys_free(struct sysfile *f);

/* ---- lines ---- */

struct sysline {
    const char *s; size_t n;    /* the line, without its newline; a CR is a byte of it */
    uint32_t line;              /* 1-based */
    bool only;                  /* sys_lines_diff: on this side only */
    uint32_t aux;               /* the caller's */
};

/* The lines of a buffer: malloc'd, *n of them (the caller frees). A last
 * line without its newline is a line; an empty buffer has none. NULL with
 * *n 0 when there are none, or (with *oom) when memory ran out. */
struct sysline *sys_lines(const char *buf, size_t len, size_t *n, bool *oom);

/* Marks `only` on each line of `a` that `b` does not have, and the reverse,
 * as multisets of bytes: of equal lines, the earliest pair off. 0, or -1
 * (memory). */
int sys_lines_diff(struct sysline *a, size_t na, struct sysline *b, size_t nb);

/* ---- small things every parser needs ---- */

static inline bool sys_blank(char c) { return c == ' ' || c == '\t'; }
/* [*s, *e) without leading and trailing spaces and tabs. */
void sys_trim(const char **s, const char **e);
/* Whether the `n` bytes at `s` end with the string `tail`. */
bool sys_ends(const char *s, size_t n, const char *tail);
/* The last component of a path, and the length of what precedes it
 * (with its slash; 0 when there is none). */
const char *sys_base(const char *path, size_t len, size_t *base_len, size_t *dir_len);
/* A decimal number that fits 32 bits, nothing else in [s, s+n). */
bool sys_u32(const char *s, size_t n, uint32_t *out);

/* ---- the events of one diff ---- */

enum { SYS_REMOVED = 0, SYS_ADDED = 1 };

struct sysev {
    int kind;                   /* 0: could_not_interpret (E10) */
    const char *path;           /* the first of its paths: the order's key */
    size_t path_len;
    uint32_t line;              /* its line's place; 0: of the file as a whole */
    uint8_t rank;               /* SYS_REMOVED before SYS_ADDED */
    bool prov;
    bool drop;                  /* decided at the end not to be one (a lookup said so) */
    struct belay_fv v[FINDING_FIELDS_MAX];
    size_t n;
    int owner_field;            /* the index in v of `owner`, filled at the end; -1: none */
    const char *owner_path;     /* the path whose owner is asked */
    size_t owner_len;
    const char *path2;          /* a second path the event was derived from, or NULL */
    size_t path2_len;
    uint32_t aux;               /* the interpreter's own */
    size_t seq;
};

struct sysevs;

struct sysevs *sysevs_new(void);
void sysevs_free(struct sysevs *s);
/* The state passed its bound or memory ran out: the end hook fails (E6). */
bool sysevs_failed(const struct sysevs *s);
/* `n` bytes kept for the diff (NUL after them), or NULL (then failed). */
const char *sysevs_dup(struct sysevs *s, const char *p, size_t n);

/* Adds an event: its values -- strings and list elements -- are copied.
 * The event, for what is only known later (`owner`, a value a lookup
 * gives, `drop`); or NULL: past EVENTS_PER_INTERP it is only counted (E5),
 * and on failure the state is failed. */
struct sysev *sysevs_add(struct sysevs *s, int kind, const char *path, size_t path_len, uint32_t line,
                         int rank, bool prov, const struct belay_fv *v, size_t n);
/* E10: `path` could not be interpreted. */
void sysevs_not_interpreted(struct sysevs *s, const char *path, size_t path_len, bool prov);
/* The same, and what explain returns for it: the record carries
 * could_not_interpret too, unless its outcome is unknown (P8). */
enum belay_interp_result sys_cannot(struct sysevs *s, const struct belay_interp_input *in);
/* Sets where `e`'s owner goes and whose it is; asked by sysevs_ask_owners. */
void sysevs_owner(struct sysevs *s, struct sysev *e, int field, const char *path, size_t len);

size_t sysevs_count(const struct sysevs *s);
struct sysev *sysevs_at(struct sysevs *s, size_t i);

/* In a prepare hook: asks the owner of every event that has one to fill.
 * Once is enough; asking again asks nothing. 0, or -1. */
int sysevs_ask_owners(struct sysevs *s, struct belay_lookup *lk);
/* In the end hook: the events in E13's order, each owner filled from `lk`
 * (NULL: every owner absent). */
enum belay_interp_result sysevs_emit(struct sysevs *s, struct belay_events *ev, const struct belay_lookup *lk);

#endif
