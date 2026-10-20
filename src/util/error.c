#include "belay/error.h"

#include <stdarg.h>
#include <stdio.h>

/*
 *  C11 _Thread_local. The portable core is single-threaded today, but a
 *  process-global here would be a latent bug the moment anything threads, and
 *  the cost is zero.
 */
#define BELAY_ERR_MSG_MAX 512

static _Thread_local enum belay_err_code err_code = BELAY_OK;
static _Thread_local int                 err_errno;
static _Thread_local char                err_msg[BELAY_ERR_MSG_MAX];

void belay_err_set(enum belay_err_code code, int sys_errno, const char *fmt, ...) {
    err_code  = code;
    err_errno = sys_errno;

    if (fmt == NULL) {
        err_msg[0] = '\0';
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    /* vsnprintf always NUL-terminates within the buffer; truncation of a
     * diagnostic string is acceptable and is not itself an error. */
    vsnprintf(err_msg, sizeof err_msg, fmt, ap);
    va_end(ap);
}

void belay_err_clear(void) {
    err_code   = BELAY_OK;
    err_errno  = 0;
    err_msg[0] = '\0';
}

enum belay_err_code belay_err_code(void) { return err_code; }
int                 belay_err_errno(void) { return err_errno; }
const char         *belay_err_msg(void) { return err_msg; }
