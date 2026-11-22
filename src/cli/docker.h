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

/* A system capture of a container (watch-system WS-1): its roots resolved
 * in its `/` through the union, its homes from its own etc/passwd, put in
 * the options and kept in `roots` (the caller frees them); then `runtime`,
 * when not NULL, reads its runtime record (runtime-v1 RT-12) before H-C5's
 * second look, so both are of the container that look finds. */
struct docker_system {
    struct belay_system_roots *roots;
    int (*runtime)(void *ctx, const struct docker_info *d);
    void *ctx;
};

/* Captures the scope `path` of the container `name` into `manifest`
 * through the union, `source` set (manifest-v3 V3-2): 0, or -1 with
 * belay_err -- a refusal met during the capture (BELAY_ERR_INVALID) or a
 * container that changed (H-C5) leaves no manifest. `sys` NULL: a scope's
 * capture; else the system's, `path` "/". */
int docker_capture(const char *name, const char *path, bool need_paused, const char *manifest,
                   struct belay_manifest_opts *o, struct belay_manifest_stats *s, FILE *warn,
                   const struct docker_system *sys);

/* WS-1, WS-8a: the roots of the container's `/` as they are now, for
 * `watch patterns --system --docker`. 0, or -1 with belay_err. */
int docker_system_roots(const char *name, struct belay_system_roots *out);

/* The container's source as manifest v3's header writes it, into `out`. */
void docker_source_json(const struct docker_info *d, char *out, size_t cap);

/*
 *  The tests' container. When `docker_test_open` is set, docker_open and
 *  docker_still ask it in place of `docker inspect`, the root check and the
 *  first process's status and mount table: it fills `d` and opens the union
 *  of directories it made (test/test_docker_system.c). `docker_proc` is
 *  where the container's processes are read (RT-12): "/proc", or the tests'
 *  tree shaped like it. belay itself never sets either.
 */
extern int (*docker_test_open)(const char *name, struct docker_info *d, struct union_fs **u);
extern const char *docker_proc;

/* H-C5: inspects `name` again after the read: 0 when it is the same
 * container, the same first process, and (when `need_paused`) still
 * paused; -1 with belay_err otherwise. */
int docker_still(const char *name, const struct docker_info *d, bool need_paused);

#endif
