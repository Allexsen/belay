/*
 *  The policy pass (test/expect/policy-v1.md): what the changes since the
 *  baseline mean against a task's expectations, written as policy.v1 beside
 *  diff.v1, never inside it (decision 145). It reads the diff verify ran,
 *  the two manifests (an unchanged path has no record, and an added file's
 *  mode is only there), the stored copies, the bundle's package lines and
 *  the protect spec; it decides nothing about what changed -- that is the
 *  diff's -- only what each change means.
 */
#ifndef BELAY_POLICY_POLICY_H
#define BELAY_POLICY_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "policy/bundle.h"
#include "policy/protect.h"

struct policy_in {
    const char *before, *after;         /* the manifests: the bundle's, verify's */
    const char *diff;                   /* diff.v1 between them */
    const char *store;                  /* both sides' copies */
    const char *scope;                  /* resolved: the tree, read for dpkg's MD5s after */
    bool tree_is_after;                 /* the tree is still the after state (not --to) */
    const struct bundle *bundle;
    const char *bundle_sha256;
    const struct protect_spec *spec;    /* NULL: none */
};

struct policy_stats { size_t violations, signals; };

/* Writes policy.v1 to `out`. 0, or -1 with belay_err (CORRUPT: the diff or
 * a manifest is not what it should be; IO, NOMEM). */
int policy_run(const struct policy_in *in, FILE *out, struct policy_stats *st);

#endif
