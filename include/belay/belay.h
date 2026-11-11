/*
 *  libbelay's version. The API is in the sibling headers (manifest.h,
 *  diff.h, interp.h, store.h, ...): a public interface, semver'd from the
 *  first release, which a consumer outside this repository must be able to
 *  use without core internals. Nothing in them may depend on a Linux-only
 *  type or header: the portable core (capture, diff, interp) builds on macOS
 *  too. The binary reports this version (belay --version) as it is when
 *  built from a clean tree at the tag v<this version> -- a release -- and
 *  with git's description after it otherwise, 0.1.0-alpha.2+95-ga2054b3, or
 *  +unknown without git (scripts/version.sh).
 */
#ifndef BELAY_BELAY_H
#define BELAY_BELAY_H

#define BELAY_VERSION_MAJOR 0
#define BELAY_VERSION_MINOR 1
#define BELAY_VERSION_PATCH 0
#define BELAY_VERSION_STRING "0.1.0-alpha.8"

#endif /* BELAY_BELAY_H */
