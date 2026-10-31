/*
 *  Version orderings for the package interpreters: Debian's (dpkg's own
 *  algorithm, `dpkg --compare-versions`) and PEP 440's (pip). Pure, bounded,
 *  no allocation: versions come from files the watched process writes.
 */
#ifndef BELAY_INTERP_VERSIONS_H
#define BELAY_INTERP_VERSIONS_H

#include <stddef.h>

/* <0, 0, >0 as `a` sorts before, with or after `b`. Every byte string is
 * comparable: dpkg compares what it finds. */
int debver_cmp(const char *a, size_t al, const char *b, size_t bl);

/* 0 with *cmp <0, 0, >0; or -1 when either is not a PEP 440 version (the
 * public grammar, case-insensitive, with an optional +local), or is longer
 * than 255 bytes or has more than 32 release or local parts. */
int pep440_cmp(const char *a, size_t al, const char *b, size_t bl, int *cmp);

#endif
