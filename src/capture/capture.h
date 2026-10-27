/*
 *  Capture's internal entry point: belay_manifest_write with an explicit
 *  platform adapter. Tests pass a decorated adapter to fire a race, or a
 *  failure, at an exact point (see fsops.h).
 */
#ifndef BELAY_CAPTURE_CAPTURE_H
#define BELAY_CAPTURE_CAPTURE_H

#include "belay/manifest.h"
#include "fsops.h"

int capture_write(const struct fsops *ops, const char *out_path, const char *scope,
                  const struct belay_manifest_opts *opts, struct belay_manifest_stats *stats);

#endif
