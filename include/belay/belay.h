/*
 *  libbelay public API.
 *
 *  BELAY_DESIGN.md §4.2 contract 1: this header is a public, semver'd
 *  interface. The closed side consumes it and must never need core internals.
 *  Nothing here may depend on a Linux-only type or header: the portable core
 *  (capture/A, diff/, interp/) builds on macOS too (§9.1).
 *
 *  Empty for now. Declarations land as M1 phases complete.
 */
#ifndef BELAY_BELAY_H
#define BELAY_BELAY_H

#define BELAY_VERSION_MAJOR 0
#define BELAY_VERSION_MINOR 0
#define BELAY_VERSION_PATCH 0

#endif /* BELAY_BELAY_H */
