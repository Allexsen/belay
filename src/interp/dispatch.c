#include "belay/interp.h"

#include "belay/manifest.h"

#include <fnmatch.h>
#include <string.h>

/*
 *  One row per claim. First match wins, so more specific rows come first
 *  (git's index, hash-only, before nothing else could catch it -- the order
 *  only matters where two patterns overlap, and none do today).
 *
 *  Each row is a decision about what a later diff will need:
 *    dpkg  status: which packages are installed, at which version.
 *          The per-package md5sums files: hashes M2's integrity check
 *          verifies against -- they must be the BASELINE copies (§6).
 *          The per-package list files: which package owns which path.
 *    pip   RECORD: installed files and their hashes; METADATA: name/version.
 *    git   HEAD, packed-refs and everything under refs: ref moves. Hooks:
 *          executable code, so the content is kept. index: changed or not.
 *          logs: the reflog, which operation moved a ref.
 */
struct rule {
    const char *pattern;
    enum belay_interp_id interp;
    enum belay_keep keep;
};

static const struct rule rules[] = {
    { "*/var/lib/dpkg/status",            BELAY_INTERP_DPKG, BELAY_KEEP_STORE },
    { "*/var/lib/dpkg/info/*.md5sums",    BELAY_INTERP_DPKG, BELAY_KEEP_STORE },
    { "*/var/lib/dpkg/info/*.list",       BELAY_INTERP_DPKG, BELAY_KEEP_STORE },

    { "*.dist-info/RECORD",               BELAY_INTERP_PIP,  BELAY_KEEP_STORE },
    { "*.dist-info/METADATA",             BELAY_INTERP_PIP,  BELAY_KEEP_STORE },

    { "*/.git/index",                     BELAY_INTERP_GIT,  BELAY_KEEP_HASH  },
    { "*/.git/HEAD",                      BELAY_INTERP_GIT,  BELAY_KEEP_STORE },
    { "*/.git/packed-refs",               BELAY_INTERP_GIT,  BELAY_KEEP_STORE },
    { "*/.git/refs/*",                    BELAY_INTERP_GIT,  BELAY_KEEP_STORE },
    { "*/.git/hooks/*",                   BELAY_INTERP_GIT,  BELAY_KEEP_STORE },
    /* The reflog: which operation moved each ref (decision 2026-10-31, Q3).
     * Written by the watched process, so evidence, not proof. Stored within
     * the store limit only: a long-lived reflog grows without bound. */
    { "*/.git/logs/HEAD",                 BELAY_INTERP_GIT,  BELAY_KEEP_STORE_BOUNDED },
    { "*/.git/logs/refs/*",               BELAY_INTERP_GIT,  BELAY_KEEP_STORE_BOUNDED },

    /*
     *  The system interpreters (test/expect/system-interpreters.md). What
     *  they parse is kept whatever its mode: KEEP_STORE is the claim that
     *  takes a file others cannot read out of the sealing rule (manifest-v5
     *  V5-E5: sudoers is 0440, a crontab and authorized_keys 0600). What
     *  they only name -- the scripts of the cron directories and of init.d,
     *  the trust store's files -- is kept as any file is (small text), and
     *  sealed like any file when others cannot read it. `*` spans `/`:
     *  each interpreter checks the depth it means.
     */
    { "*/var/lib/apt/extended_states",    BELAY_INTERP_DPKG,     BELAY_KEEP_STORE },   /* SD-1 */

    { "*/etc/passwd",                     BELAY_INTERP_ACCOUNTS, BELAY_KEEP_STORE },
    { "*/etc/group",                      BELAY_INTERP_ACCOUNTS, BELAY_KEEP_STORE },

    { "*/etc/sudoers",                    BELAY_INTERP_SUDOERS,  BELAY_KEEP_STORE },
    { "*/etc/sudoers.d/*",                BELAY_INTERP_SUDOERS,  BELAY_KEEP_STORE },

    { "*/etc/crontab",                    BELAY_INTERP_CRON,     BELAY_KEEP_STORE },
    { "*/etc/cron.d/*",                   BELAY_INTERP_CRON,     BELAY_KEEP_STORE },
    { "*/var/spool/cron/crontabs/*",      BELAY_INTERP_CRON,     BELAY_KEEP_STORE },
    { "*/etc/cron.hourly/*",              BELAY_INTERP_CRON,     BELAY_KEEP_DEFAULT },
    { "*/etc/cron.daily/*",               BELAY_INTERP_CRON,     BELAY_KEEP_DEFAULT },
    { "*/etc/cron.weekly/*",              BELAY_INTERP_CRON,     BELAY_KEEP_DEFAULT },
    { "*/etc/cron.monthly/*",             BELAY_INTERP_CRON,     BELAY_KEEP_DEFAULT },

    /* The lib/systemd patterns match usr/lib/systemd too. */
    { "*/etc/systemd/system/*",           BELAY_INTERP_SYSTEMD,  BELAY_KEEP_STORE },
    { "*/etc/systemd/user/*",             BELAY_INTERP_SYSTEMD,  BELAY_KEEP_STORE },
    { "*/lib/systemd/system/*",           BELAY_INTERP_SYSTEMD,  BELAY_KEEP_STORE },
    { "*/lib/systemd/user/*",             BELAY_INTERP_SYSTEMD,  BELAY_KEEP_STORE },
    { "*/.config/systemd/user/*",         BELAY_INTERP_SYSTEMD,  BELAY_KEEP_STORE },
    { "*/etc/rc.local",                   BELAY_INTERP_SYSTEMD,  BELAY_KEEP_DEFAULT },
    { "*/etc/init.d/*",                   BELAY_INTERP_SYSTEMD,  BELAY_KEEP_DEFAULT },

    { "*/.ssh/authorized_keys",           BELAY_INTERP_SSHKEYS,  BELAY_KEEP_STORE },
    { "*/.ssh/authorized_keys2",          BELAY_INTERP_SSHKEYS,  BELAY_KEEP_STORE },

    { "*/etc/ssl/certs/*",                BELAY_INTERP_TRUST,    BELAY_KEEP_DEFAULT },
    { "*/usr/local/share/ca-certificates/*", BELAY_INTERP_TRUST, BELAY_KEEP_DEFAULT },
};

/* diff-events E13. `config` will stand between trust and git. */
const enum belay_interp_id BELAY_INTERP_ORDER[BELAY_INTERP_ORDER_COUNT] = {
    BELAY_INTERP_TEXT, BELAY_INTERP_PIP, BELAY_INTERP_DPKG, BELAY_INTERP_ACCOUNTS, BELAY_INTERP_SUDOERS,
    BELAY_INTERP_CRON, BELAY_INTERP_SYSTEMD, BELAY_INTERP_SSHKEYS, BELAY_INTERP_TRUST, BELAY_INTERP_GIT,
};

void belay_interp_classify(const char *abs_path, size_t len, struct belay_claim *out) {
    out->interp = BELAY_INTERP_BINARY;
    out->keep = BELAY_KEEP_DEFAULT;

    /* fnmatch needs a C string. Paths are bounded by the manifest's 4096-byte
     * cap plus the scope; anything longer is simply unclaimed. */
    char buf[8192];
    if (len >= sizeof buf || memchr(abs_path, '\0', len) != NULL) return;
    memcpy(buf, abs_path, len);
    buf[len] = '\0';

    for (size_t i = 0; i < sizeof rules / sizeof rules[0]; i++) {
        if (fnmatch(rules[i].pattern, buf, 0) == 0) {
            out->interp = rules[i].interp;
            out->keep = rules[i].keep;
            return;
        }
    }
}

enum belay_interp_id belay_interp_dispatch(const struct belay_claim *claim,
                                           const struct belay_entry *before,
                                           const struct belay_entry *after) {
    if (claim->interp != BELAY_INTERP_BINARY) return claim->interp;
    if ((before == NULL && after == NULL) || (before != NULL && !before->has_stored) ||
        (after != NULL && !after->has_stored))
        return BELAY_INTERP_BINARY;
    return BELAY_INTERP_TEXT;
}

const char *belay_interp_name(enum belay_interp_id id) {
    switch (id) {
    case BELAY_INTERP_BINARY: return "binary";
    case BELAY_INTERP_TEXT:   return "text";
    case BELAY_INTERP_PIP:    return "pip";
    case BELAY_INTERP_DPKG:   return "dpkg";
    case BELAY_INTERP_GIT:    return "git";
    case BELAY_INTERP_ACCOUNTS: return "accounts";
    case BELAY_INTERP_SUDOERS:  return "sudoers";
    case BELAY_INTERP_CRON:     return "cron";
    case BELAY_INTERP_SYSTEMD:  return "systemd";
    case BELAY_INTERP_SSHKEYS:  return "sshkeys";
    case BELAY_INTERP_TRUST:    return "trust";
    case BELAY_INTERP_COUNT:  break;
    }
    return "unknown";
}
