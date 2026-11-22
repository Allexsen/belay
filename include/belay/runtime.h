/*
 *  The runtime record, version 1 (test/expect/runtime-v1.md): what is
 *  listening and which services have processes, as a proc file system says
 *  at the moment of a capture. Read by belay itself: no program of the
 *  watched machine is run.
 */
#ifndef BELAY_RUNTIME_H
#define BELAY_RUNTIME_H

#include <stddef.h>

struct belay_runtime_opts {
    /* The proc file system: `/proc`, or a tree shaped like it. */
    const char *proc_root;
    /* RT-12: the process whose `net/` and `ns/net` are read; 0: the proc
     * root's own `net/` and `self/ns/net` (the namespace belay runs in). */
    long net_pid;
    /* The header's `source`, as JSON (manifest v3's object); NULL: `null`. */
    const char *source_json;
    /* RT-8, RT-9: whether to read as root -- the holders are read only then.
     * -1: whether geteuid() is 0 (what the CLI passes); 0 or 1: as given. */
    int root;
};

struct belay_runtime_stats {
    size_t listeners, services, holders_unknown;    /* the trailer (RT-4) */
    char sha256[65];                                /* of the file written */
};

/*
 *  Writes the record to `out_path` (mode 600, through a temporary name
 *  beside it). 1 with *stats; 0 when there is no `net` directory to read
 *  under the proc root (no proc file system: macOS, or a root without
 *  one): nothing is written; -1 with belay_err and no file.
 */
int belay_runtime_capture(const struct belay_runtime_opts *opts, const char *out_path,
                          struct belay_runtime_stats *stats);

#endif
