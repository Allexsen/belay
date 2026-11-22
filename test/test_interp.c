/*
 *  Interpreter dispatch. Pure classification, so every case is a path in and
 *  a claim out. The near-misses matter as much as the hits: a false claim
 *  stores content needlessly, a missed claim loses the baseline an
 *  interpreter needs.
 */
#include "belay_test.h"
#include "belay/interp.h"
#include "belay/manifest.h"

#include <string.h>

static struct belay_claim cls(const char *p) {
    struct belay_claim c;
    belay_interp_classify(p, strlen(p), &c);
    return c;
}

#define EXPECT(path, I, K)                                                   \
    do {                                                                     \
        struct belay_claim _c = cls(path);                                   \
        if (_c.interp != (I) || _c.keep != (K))                              \
            BELAY_FAIL("%s: got %s/%d", path, belay_interp_name(_c.interp),  \
                       (int)_c.keep);                                        \
    } while (0)

TEST(dpkg_claims_status_and_baseline_databases) {
    EXPECT("/var/lib/dpkg/status", BELAY_INTERP_DPKG, BELAY_KEEP_STORE);
    EXPECT("/var/lib/dpkg/info/bash.md5sums", BELAY_INTERP_DPKG, BELAY_KEEP_STORE);
    EXPECT("/var/lib/dpkg/info/libc6:amd64.list", BELAY_INTERP_DPKG, BELAY_KEEP_STORE);
    /* A container root or a host reader's rootfs path. */
    EXPECT("/var/lib/docker/overlay2/ab12/diff/var/lib/dpkg/status",
           BELAY_INTERP_DPKG, BELAY_KEEP_STORE);
}

TEST(dpkg_near_misses_are_not_claimed) {
    EXPECT("/var/lib/dpkg/status-old", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/var/lib/dpkg/status.bak", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/var/lib/dpkg/info/bash.postinst", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/home/u/notes/var/lib/dpkg", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
}

TEST(pip_claims_dist_info_records) {
    EXPECT("/usr/lib/python3/dist-packages/numpy-2.1.0.dist-info/RECORD",
           BELAY_INTERP_PIP, BELAY_KEEP_STORE);
    EXPECT("/home/u/.venv/lib/python3.12/site-packages/requests-2.32.3.dist-info/METADATA",
           BELAY_INTERP_PIP, BELAY_KEEP_STORE);
    EXPECT("/x/numpy-2.1.0.dist-info/INSTALLER", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/x/numpy-2.1.0.dist-info/RECORD.jws", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
}

TEST(git_claims_refs_hooks_and_hashes_the_index) {
    EXPECT("/repo/.git/HEAD", BELAY_INTERP_GIT, BELAY_KEEP_STORE);
    EXPECT("/repo/.git/packed-refs", BELAY_INTERP_GIT, BELAY_KEEP_STORE);
    EXPECT("/repo/.git/refs/heads/main", BELAY_INTERP_GIT, BELAY_KEEP_STORE);
    EXPECT("/repo/.git/refs/remotes/origin/feature/x", BELAY_INTERP_GIT, BELAY_KEEP_STORE);
    EXPECT("/repo/.git/hooks/pre-commit", BELAY_INTERP_GIT, BELAY_KEEP_STORE);
    /* The index can be hundreds of MB; M1 only needs to know it changed. */
    EXPECT("/repo/.git/index", BELAY_INTERP_GIT, BELAY_KEEP_HASH);
}

/* Decided 2026-10-31 (Q3): the reflog is claimed, stored only up to a bound
 * (it grows without one) -- 16 MiB from 2026-11-01 (6); other logs are not
 * reflogs. */
TEST(git_claims_the_reflog_within_the_store_limit) {
    EXPECT("/repo/.git/logs/HEAD", BELAY_INTERP_GIT, BELAY_KEEP_STORE_BOUNDED);
    EXPECT("/repo/.git/logs/refs/heads/main", BELAY_INTERP_GIT, BELAY_KEEP_STORE_BOUNDED);
    EXPECT("/repo/.git/logs/refs/remotes/origin/x", BELAY_INTERP_GIT, BELAY_KEEP_STORE_BOUNDED);
    EXPECT("/repo/.git/logs/HEAD.lock", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/repo/logs/HEAD", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
}

/* Objects and packs are explicitly out of M1's git scope (no zlib), so they
 * must not be claimed -- claiming them would store every pack. */
TEST(git_objects_and_packs_are_not_claimed) {
    EXPECT("/repo/.git/objects/pack/pack-abc.pack", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/repo/.git/objects/ab/cdef0123", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/repo/.git/config", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/repo/src/.githooks/pre-commit", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
}

TEST(unclaimed_and_hostile_inputs_fall_back_to_binary) {
    EXPECT("/home/u/src/main.c", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);

    /* An embedded NUL must not truncate the path into a claimed one. */
    const char tricky[] = "/var/lib/dpkg/status\0.not-really";
    struct belay_claim c;
    belay_interp_classify(tricky, sizeof tricky - 1, &c);
    ASSERT_EQ_INT(BELAY_INTERP_BINARY, c.interp);

    /* Over-long input is unclaimed, never read past. */
    static char big[9000];
    memset(big, 'a', sizeof big);
    belay_interp_classify(big, sizeof big, &c);
    ASSERT_EQ_INT(BELAY_INTERP_BINARY, c.interp);
}

TEST(names_are_stable) {
    ASSERT_EQ_STR("pip", belay_interp_name(BELAY_INTERP_PIP));
    ASSERT_EQ_STR("dpkg", belay_interp_name(BELAY_INTERP_DPKG));
    ASSERT_EQ_STR("git", belay_interp_name(BELAY_INTERP_GIT));
    ASSERT_EQ_STR("binary", belay_interp_name(BELAY_INTERP_BINARY));
    ASSERT_EQ_STR("unknown", belay_interp_name(BELAY_INTERP_COUNT));
}

/* The string findings these replaced (reviews F2, F3, F9: a cut inside a
 * UTF-8 sequence, a write past the cap, bad text made valid by a cut) have no
 * counterpart: a structured finding is never cut -- one over its bound is
 * invalid_finding (test_findings). */

/* Decided 2026-10-31 (Q6, reconciled with Q2): an unclaimed path is TEXT when
 * it is stored on every side it exists on; a claim always wins. */
TEST(text_is_an_unclaimed_path_stored_on_every_side_it_exists_on) {
    struct belay_entry s = { 0 }, u = { 0 };
    s.has_stored = true;
    const struct belay_claim none = { BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT };
    const struct belay_claim pip = { BELAY_INTERP_PIP, BELAY_KEEP_STORE };
    ASSERT_EQ_INT(BELAY_INTERP_TEXT, belay_interp_dispatch(&none, &s, &s));
    ASSERT_EQ_INT(BELAY_INTERP_TEXT, belay_interp_dispatch(&none, NULL, &s));    /* added */
    ASSERT_EQ_INT(BELAY_INTERP_TEXT, belay_interp_dispatch(&none, &s, NULL));    /* removed */
    ASSERT_EQ_INT(BELAY_INTERP_BINARY, belay_interp_dispatch(&none, &s, &u));
    ASSERT_EQ_INT(BELAY_INTERP_BINARY, belay_interp_dispatch(&none, &u, &s));
    ASSERT_EQ_INT(BELAY_INTERP_BINARY, belay_interp_dispatch(&none, NULL, &u));
    ASSERT_EQ_INT(BELAY_INTERP_BINARY, belay_interp_dispatch(&none, NULL, NULL));
    ASSERT_EQ_INT(BELAY_INTERP_PIP, belay_interp_dispatch(&pip, &u, &u));
    ASSERT_EQ_INT(BELAY_INTERP_PIP, belay_interp_dispatch(&pip, &s, &s));
}

/* system-interpreters.md: what each of the six claims, and how it is kept.
 * KEEP_STORE is what keeps a file others cannot read out of the sealing
 * rule (manifest-v5 V5-E5): sudoers, crontabs, authorized_keys, units. */
TEST(system_interpreters_claim_their_files) {
    EXPECT("/etc/passwd", BELAY_INTERP_ACCOUNTS, BELAY_KEEP_STORE);
    EXPECT("/etc/group", BELAY_INTERP_ACCOUNTS, BELAY_KEEP_STORE);
    EXPECT("/srv/root/etc/passwd", BELAY_INTERP_ACCOUNTS, BELAY_KEEP_STORE);
    EXPECT("/etc/sudoers", BELAY_INTERP_SUDOERS, BELAY_KEEP_STORE);
    EXPECT("/etc/sudoers.d/90-site", BELAY_INTERP_SUDOERS, BELAY_KEEP_STORE);
    EXPECT("/etc/crontab", BELAY_INTERP_CRON, BELAY_KEEP_STORE);
    EXPECT("/etc/cron.d/ok-name", BELAY_INTERP_CRON, BELAY_KEEP_STORE);
    EXPECT("/var/spool/cron/crontabs/siteuser", BELAY_INTERP_CRON, BELAY_KEEP_STORE);
    EXPECT("/etc/cron.hourly/x", BELAY_INTERP_CRON, BELAY_KEEP_DEFAULT);
    EXPECT("/etc/cron.daily/logrotate", BELAY_INTERP_CRON, BELAY_KEEP_DEFAULT);
    EXPECT("/etc/cron.weekly/x", BELAY_INTERP_CRON, BELAY_KEEP_DEFAULT);
    EXPECT("/etc/cron.monthly/x", BELAY_INTERP_CRON, BELAY_KEEP_DEFAULT);
    EXPECT("/etc/systemd/system/multi-user.target.wants/nginx.service", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    EXPECT("/etc/systemd/system/nginx.service", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    EXPECT("/etc/systemd/user/x.service", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    EXPECT("/usr/lib/systemd/system/nginx.service", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    EXPECT("/usr/lib/systemd/user/x.timer", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    EXPECT("/lib/systemd/system/nginx.service.d/override.conf", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    EXPECT("/home/u/.config/systemd/user/probe.timer", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    EXPECT("/etc/rc.local", BELAY_INTERP_SYSTEMD, BELAY_KEEP_DEFAULT);
    EXPECT("/etc/init.d/nginx", BELAY_INTERP_SYSTEMD, BELAY_KEEP_DEFAULT);
    EXPECT("/var/lib/apt/extended_states", BELAY_INTERP_DPKG, BELAY_KEEP_STORE);
    EXPECT("/home/u/.ssh/authorized_keys", BELAY_INTERP_SSHKEYS, BELAY_KEEP_STORE);
    EXPECT("/root/.ssh/authorized_keys2", BELAY_INTERP_SSHKEYS, BELAY_KEEP_STORE);
    EXPECT("/etc/ssl/certs/probe-ca.pem", BELAY_INTERP_TRUST, BELAY_KEEP_DEFAULT);
    EXPECT("/usr/local/share/ca-certificates/probe-ca.crt", BELAY_INTERP_TRUST, BELAY_KEEP_DEFAULT);
    /* Near misses stay unclaimed. `shadow` is nobody's: it is sealed, and
     * its lines reach the accounts interpreter another way (SA-6). */
    EXPECT("/etc/passwd-", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/etc/shadow", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/etc/gshadow", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/etc/sudoers.dist", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/etc/cron.deny", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/home/u/.ssh/authorized_keys.bak", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/home/u/.ssh/id_ed25519", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/etc/rc.local.bak", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/etc/rc2.d/S01nginx", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/var/lib/systemd/deb-systemd-helper-enabled/multi-user.target.wants/nginx.service",
           BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    EXPECT("/run/systemd/system/x.service", BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);
    ASSERT_EQ_STR("accounts", belay_interp_name(BELAY_INTERP_ACCOUNTS));
    ASSERT_EQ_STR("sudoers", belay_interp_name(BELAY_INTERP_SUDOERS));
    ASSERT_EQ_STR("cron", belay_interp_name(BELAY_INTERP_CRON));
    ASSERT_EQ_STR("systemd", belay_interp_name(BELAY_INTERP_SYSTEMD));
    ASSERT_EQ_STR("sshkeys", belay_interp_name(BELAY_INTERP_SSHKEYS));
    ASSERT_EQ_STR("trust", belay_interp_name(BELAY_INTERP_TRUST));
}

/* system-config.md "Grammars": config's second claim, beside the path's own
 * interpreter (CF-6). What only config claims is kept up to the size it
 * keys (CF-4) and sealed as any file is (KEEP_STORE_KEYED); a unit file
 * keeps systemd's claim. */
#define CONFIG(path, I, K)                                                   \
    do {                                                                     \
        EXPECT(path, I, K);                                                  \
        ASSERT_TRUE(belay_interp_config_claims(path, strlen(path)));         \
    } while (0)
#define NOT_CONFIG(path)                                                     \
    do {                                                                     \
        EXPECT(path, BELAY_INTERP_BINARY, BELAY_KEEP_DEFAULT);               \
        ASSERT_TRUE(!belay_interp_config_claims(path, strlen(path)));        \
    } while (0)
TEST(config_claims_its_files_beside_their_interpreter) {
    const enum belay_interp_id B = BELAY_INTERP_BINARY;
    const enum belay_keep K = BELAY_KEEP_STORE_KEYED;
    CONFIG("/etc/nginx/nginx.conf", B, K);
    CONFIG("/etc/nginx/conf.d/site.conf", B, K);
    CONFIG("/etc/nginx/sites-available/default", B, K);
    CONFIG("/etc/nginx/sites-enabled/default", B, K);
    CONFIG("/etc/nginx/modules-enabled/50-mod-stream.conf", B, K);
    CONFIG("/etc/nginx/snippets/fastcgi-php.conf", B, K);
    CONFIG("/etc/ssh/sshd_config", B, K);
    CONFIG("/etc/ssh/sshd_config.d/50-cloud-init.conf", B, K);
    CONFIG("/etc/systemd/journald.conf", B, K);
    CONFIG("/etc/systemd/system.conf.d/limits.conf", B, K);
    CONFIG("/etc/sysctl.conf", B, K);
    CONFIG("/etc/sysctl.d/99-site.conf", B, K);
    CONFIG("/etc/login.defs", B, K);
    CONFIG("/srv/root/etc/login.defs", B, K);
    CONFIG("/etc/systemd/system/nginx.service", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    CONFIG("/etc/systemd/system/nginx.service.d/override.conf", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    CONFIG("/usr/lib/systemd/system/probe.timer", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    CONFIG("/lib/systemd/user/x.service.d/a", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    CONFIG("/home/u/.config/systemd/user/probe.service", BELAY_INTERP_SYSTEMD, BELAY_KEEP_STORE);
    /* Near misses, and what is not keyed by design (CF-X1, CF-X2). */
    NOT_CONFIG("/etc/nginx/nginx.conf.bak");
    NOT_CONFIG("/etc/nginx/conf.d/site.conf.bak");
    NOT_CONFIG("/etc/nginx/conf.d/.conf");
    NOT_CONFIG("/etc/nginx/sites-enabled/a/b");
    NOT_CONFIG("/etc/nginx/mime.types");
    NOT_CONFIG("/etc/ssh/ssh_config");
    NOT_CONFIG("/etc/ssh/sshd_config.d/notes.txt");
    NOT_CONFIG("/etc/ssh/sshd_config.bak");
    NOT_CONFIG("/etc/systemd/a/journald.conf");
    NOT_CONFIG("/etc/systemd/journald.conf.d/x.txt");
    NOT_CONFIG("/etc/systemd/.conf.d/x.conf");
    NOT_CONFIG("/etc/systemd/x/y.conf.d/z.conf");
    NOT_CONFIG("/etc/sysctl.d/99-site.txt");
    NOT_CONFIG("/etc/sysctl.d/a/99.conf");
    NOT_CONFIG("/etc/default/grub");
    NOT_CONFIG("/etc/environment");
    NOT_CONFIG("/etc/fstab");
    NOT_CONFIG("/etc/login.defs.orig");
    ASSERT_TRUE(!belay_interp_config_claims("/etc/systemd/system/multi-user.target.wants/nginx.service", 57));
    ASSERT_TRUE(!belay_interp_config_claims("/etc/init.d/nginx", 17));
    ASSERT_EQ_STR("config", belay_interp_name(BELAY_INTERP_CONFIG));
}

int main(void) {
    RUN(dpkg_claims_status_and_baseline_databases);
    RUN(dpkg_near_misses_are_not_claimed);
    RUN(pip_claims_dist_info_records);
    RUN(git_claims_refs_hooks_and_hashes_the_index);
    RUN(git_claims_the_reflog_within_the_store_limit);
    RUN(git_objects_and_packs_are_not_claimed);
    RUN(unclaimed_and_hostile_inputs_fall_back_to_binary);
    RUN(names_are_stable);
    RUN(text_is_an_unclaimed_path_stored_on_every_side_it_exists_on);
    RUN(system_interpreters_claim_their_files);
    RUN(config_claims_its_files_beside_their_interpreter);
    return belay_test_report();
}
