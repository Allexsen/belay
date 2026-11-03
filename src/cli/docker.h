/*
 *  `--docker CONTAINER` (test/expect/host-reader.md, "The command line" and
 *  "The mount"): the container found with `docker inspect`, its overlay
 *  mount read from its first process's mount table, every check the pin
 *  names made, and the union of its layers opened. Linux only; elsewhere
 *  each call refuses.
 */
#ifndef BELAY_CLI_DOCKER_H
#define BELAY_CLI_DOCKER_H

#include "belay/manifest.h"
#include "capture/union.h"

#include <stdbool.h>
#include <stdio.h>

struct docker_info {
    char id[65];                /* the container's full id */
    char image[72];             /* "sha256:" and its image's id */
    long pid;                   /* its first process */
    bool paused;
};

/* Inspects `name` (H-C2), checks its state (H-C4: paused when `need_paused`,
 * else running or paused), its capabilities (H-C6, H-C7: a warning on `warn`
 * for CAP_LINUX_IMMUTABLE, H-C9), and its mount (H-M1..H-M5), and opens the
 * union of its layers. 0, or -1 with belay_err (BELAY_ERR_INVALID when
 * refused, the reason said). */
int docker_open(const char *name, bool need_paused, struct docker_info *d, struct union_fs **u, FILE *warn);

/* Captures the scope `path` of the container `name` into `manifest`
 * through the union, `source` set (manifest-v3 V3-2): 0, or -1 with
 * belay_err -- a refusal met during the capture (BELAY_ERR_INVALID) or a
 * container that changed (H-C5) leaves no manifest. */
int docker_capture(const char *name, const char *path, bool need_paused, const char *manifest,
                   struct belay_manifest_opts *o, struct belay_manifest_stats *s, FILE *warn);

/* H-C5: inspects `name` again after the read: 0 when it is the same
 * container, the same first process, and (when `need_paused`) still
 * paused; -1 with belay_err otherwise. */
int docker_still(const char *name, const struct docker_info *d, bool need_paused);

#endif
