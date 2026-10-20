/*
 *  Error reporting for the portable core.
 *
 *  Convention, decided once (M1 phase 0.2):
 *
 *    - Functions that can fail return `int`: 0 on success, -1 on failure.
 *      This matches the POSIX calls underneath and the existing session-engine
 *      code, so one rule covers the whole codebase.
 *    - On failure the function sets a thread-local error describing what went
 *      wrong, retrievable with belay_err_msg() / belay_err_code().
 *    - Functions returning a pointer return NULL on failure, same error rules.
 *
 *  Why thread-local rather than an out-parameter: the alternative threads an
 *  error object through every signature, including deep recursive walks, which
 *  is a large amount of plumbing for a program whose failure mode is almost
 *  always "report and stop". errno already set the precedent, and this is the
 *  same shape without the global-variable hazard.
 *
 *  The child-side protocol in src/session/childerr.h does NOT apply here:
 *  that one exists because a forked child must report across a pipe before
 *  _exit(). The portable core has no fork and no pipe.
 */
#ifndef BELAY_ERROR_H
#define BELAY_ERROR_H

enum belay_err_code {
    BELAY_OK = 0,
    BELAY_ERR_IO,           /* a syscall failed; errno was captured */
    BELAY_ERR_INVALID,      /* caller passed something malformed */
    BELAY_ERR_RANGE,        /* value or buffer out of bounds */
    BELAY_ERR_UNSUPPORTED,  /* valid request, not supported here */
    BELAY_ERR_CORRUPT,      /* on-disk data failed validation */
    BELAY_ERR_NOMEM
};

/* Records an error. `sys_errno` is the captured errno, or 0 when not from a
 * syscall. Format string is printf-style. */
void belay_err_set(enum belay_err_code code, int sys_errno, const char *fmt, ...);

/* Clears any recorded error. */
void belay_err_clear(void);

/* The last recorded error. Message is never NULL; it is "" when none. */
enum belay_err_code belay_err_code(void);
int                 belay_err_errno(void);
const char         *belay_err_msg(void);

#endif /* BELAY_ERROR_H */
