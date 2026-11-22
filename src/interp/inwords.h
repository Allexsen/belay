/*
 *  Schedules in words (test/expect/system-interpreters.md SI-6, the table
 *  SW-1 to SW-8): only the forms the table lists, each with one reading;
 *  every other form has no words.
 */
#ifndef BELAY_INTERP_INWORDS_H
#define BELAY_INTERP_INWORDS_H

#include <stdbool.h>
#include <stddef.h>

/* The words for a cron schedule -- its five fields joined by single
 * spaces, or its `@word` -- into out (NUL-terminated), ending ` (by cron's
 * clock)`. false: the form is not one of SW-1 to SW-6, or does not fit. */
bool inwords_cron(const char *schedule, size_t n, char *out, size_t cap);

/* The words for a timer's one `OnCalendar=` value, as written (SW-7): `daily`,
 * `weekly`, `hourly`, `*-*-* HH:MM:00`, or that after a list of weekdays
 * (`Mon,Thu *-*-* HH:MM:00`), ending ` (by systemd's)`. false: any other
 * spelling, or it does not fit. */
bool inwords_timer(const char *value, size_t n, char *out, size_t cap);

#endif
