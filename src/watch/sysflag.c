#define _GNU_SOURCE
#include "watch/sysflag.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "belay/error.h"
#include "belay/interp.h"
#include "belay/manifest.h"
#include "interp/config.h"
#include "interp/lookup_internal.h"
#include "util/pattern.h"

/* ---- the lists (watch-system.md, in its order) ---- */

const struct sysrow sysflag_rows[] = {
    { "WS-F5", WK_AUTH, "pam", "etc/pam.d", NULL },
    { "WS-F5", WK_AUTH, "pam", "etc/security", NULL },
    { "WS-F5", WK_LOAD, "loader", "etc/ld.so.preload", NULL },
    { "WS-F5", WK_LOAD, "loader", "etc/ld.so.conf", NULL },
    { "WS-F5", WK_LOAD, "loader", "etc/ld.so.conf.d", NULL },
    { "WS-F5", WK_AUTH, "name service", "etc/nsswitch.conf", NULL },
    { "WS-F5", WK_SUDO, "doas", "etc/doas.conf", NULL },
    { "WS-F5", WK_AUTH, "polkit", "etc/polkit-1", NULL },
    { "WS-F5", WK_AUTH, "polkit", "usr/local/share/polkit-1", NULL },
    { "WS-F5", WK_AUTH, "userdb", "etc/userdb", NULL },
    { "WS-F6", WK_SSH, "ssh", "etc/ssh", "etc/ssh/ssh_known_hosts" },
    { "WS-F7", WK_PKG, "package source", "etc/apt/sources.list", NULL },
    { "WS-F7", WK_PKG, "package source", "etc/apt/sources.list.d", NULL },
    { "WS-F7", WK_PKG, "package source", "etc/apt/trusted.gpg", NULL },
    { "WS-F7", WK_PKG, "package source", "etc/apt/trusted.gpg.d", NULL },
    { "WS-F7", WK_PKG, "package source", "etc/apt/keyrings", NULL },
    { "WS-F7", WK_PKG, "package source", "etc/apt/apt.conf.d", NULL },
    { "WS-F7", WK_PKG, "package source", "etc/apt/preferences", NULL },
    { "WS-F7", WK_PKG, "package source", "etc/apt/preferences.d", NULL },
    { "WS-F8", WK_LOAD, "shell startup file", "etc/profile", NULL },
    { "WS-F8", WK_LOAD, "shell startup file", "etc/profile.d", NULL },
    { "WS-F8", WK_LOAD, "shell startup file", "etc/environment", NULL },
    { "WS-F8", WK_LOAD, "shell startup file", "etc/bash.bashrc", NULL },
    { "WS-F8", WK_LOAD, "shell startup file", "etc/zsh", NULL },
    { "WS-F9", WK_LOAD, "kernel module", "etc/modules", NULL },
    { "WS-F9", WK_LOAD, "kernel module", "etc/modules-load.d", NULL },
    { "WS-F9", WK_LOAD, "kernel module", "etc/modprobe.d", NULL },
    { "WS-F9", WK_LOAD, "device rule", "etc/udev/rules.d", NULL },
    { "WS-F9", WK_LOAD, "kernel setting", "etc/sysctl.conf", NULL },
    { "WS-F9", WK_LOAD, "kernel setting", "etc/sysctl.d", NULL },
    { "WS-F14", WK_TRUST, "trust store", "etc/ca-certificates.conf", NULL },
    { "WS-F14", WK_TRUST, "trust store", "etc/ca-certificates", NULL },
    { "WS-F15", WK_FIREWALL, "firewall", "etc/nftables.conf", NULL },
    { "WS-F15", WK_FIREWALL, "firewall", "etc/nftables.d", NULL },
    { "WS-F15", WK_FIREWALL, "firewall", "etc/ufw", NULL },
    { "WS-F15", WK_FIREWALL, "firewall", "etc/default/ufw", NULL },
    { "WS-F15", WK_FIREWALL, "firewall", "etc/iptables", NULL },
    { "WS-F15", WK_FIREWALL, "firewall", "etc/sysconfig/iptables*", NULL },
    { "WS-F15", WK_FIREWALL, "firewall", "etc/firewalld", NULL },
};
const size_t sysflag_n_rows = sizeof sysflag_rows / sizeof sysflag_rows[0];

const char *const sysflag_event_rows[][2] = {
    { "WS-F1", "sudo_rule_added, sudo_rule_removed, sudo_line_added, sudo_line_removed" },
    { "WS-F2", "ssh_key_added, ssh_ca_added" },
    { "WS-F3", "user_added with uid 0; user_changed of uid, gid, home or shell; user_password_in_passwd; password_entry_changed" },
    { "WS-F4", "group_members_changed adding a member to sudo, admin, wheel, root, adm, shadow, disk, docker, lxd" },
    { "WS-F6", "a config event of grammar sshd" },
    { "WS-F8", "a shell startup file of WS-6 in any home" },
    { "WS-F10", "unit_overrides_packaged; config_key_added or _changed of Exec*, User, Environment, EnvironmentFile in a drop-in or override of a packaged unit" },
    { "WS-F11", "a privilege change: setuid, setgid, a capability, a device node, world-writable" },
    { "WS-F12", "a sealed entry added, removed or changed outside root and the homes" },
    { "WS-F13", "listener_opened below port 1024 held by an executable in no package" },
    { "WS-F14", "trust_anchor_added in no package" },
    { "WS-F16", "a unit event under a home's .config/systemd/user" },
    { "WS-F17", "could_not_interpret of accounts, sudoers, sshkeys, of config on a file of grammar sshd, or on a unit under a home's .config/systemd/user" },
    { "WS-N1", "noted: user_added, group_added, password_entry_added, other group_members_changed" },
    { "WS-N2", "noted: cron_job_added, cron_script_added, timer_file_added, unit_linked, unit_file_added, unit_masked, init_script_added, init_script_changed, trust_anchor_added in a package" },
    { "WS-N3", "noted: service_started, service_stopped, service_restarted, other listener_opened, listener_closed" },
    { "WS-N4", "noted: dpkg events" },
};
const size_t sysflag_n_event_rows = sizeof sysflag_event_rows / sizeof sysflag_event_rows[0];

const char *const sysflag_home_files[] = { ".profile", ".bash_profile", ".bash_login", ".bashrc", ".bash_logout",
                                           ".zshenv", ".zprofile", ".zshrc", ".zlogin", ".cshrc", ".login",
                                           ".config/fish/config.fish" };
const size_t sysflag_n_home_files = sizeof sysflag_home_files / sizeof sysflag_home_files[0];

static const char *const PRIV_GROUPS[] = { "sudo", "admin", "wheel", "root", "adm", "shadow", "disk", "docker", "lxd" };

const struct sysrow *sysflag_row_of(const char *path, size_t len) {
    for (size_t i = 0; i < sysflag_n_rows; i++) {
        const struct sysrow *r = &sysflag_rows[i];
        if (pattern_match(r->pattern, strlen(r->pattern), path, len, PATTERN_DOTS | PATTERN_NOCASE) == 0) continue;
        if (r->except != NULL && pattern_match(r->except, strlen(r->except), path, len, PATTERN_DOTS) != 0) continue;
        return r;
    }
    return NULL;
}

/* ---- a set of byte strings ---- */

struct sset { char **v; size_t *len; size_t n, cap; bool sorted; };

static int sset_add(struct sset *s, const char *p, size_t len) {
    if (s->n == s->cap) {
        const size_t c = s->cap ? s->cap * 2 : 64;
        char **v = realloc(s->v, c * sizeof *v);
        if (v == NULL) return -1;
        s->v = v;
        size_t *l = realloc(s->len, c * sizeof *l);
        if (l == NULL) return -1;
        s->len = l;
        s->cap = c;
    }
    if ((s->v[s->n] = malloc(len + 1)) == NULL) return -1;
    memcpy(s->v[s->n], p, len);
    s->v[s->n][len] = '\0';
    s->len[s->n++] = len;
    s->sorted = false;
    return 0;
}

static int bytes_cmp(const char *a, size_t al, const char *b, size_t bl) {
    const int c = memcmp(a, b, al < bl ? al : bl);
    return c != 0 ? c : al < bl ? -1 : al > bl;
}

static struct sset *sort_of;
static int by_bytes(const void *a, const void *b) {
    const size_t i = *(const size_t *)a, j = *(const size_t *)b;
    return bytes_cmp(sort_of->v[i], sort_of->len[i], sort_of->v[j], sort_of->len[j]);
}

static int sset_sort(struct sset *s) {
    if (s->sorted || s->n < 2) { s->sorted = true; return 0; }
    size_t *ix = malloc(s->n * sizeof *ix);
    char **v = malloc(s->n * sizeof *v);
    size_t *l = malloc(s->n * sizeof *l);
    if (ix == NULL || v == NULL || l == NULL) { free(ix); free(v); free(l); return -1; }
    for (size_t i = 0; i < s->n; i++) ix[i] = i;
    sort_of = s;
    qsort(ix, s->n, sizeof *ix, by_bytes);
    size_t w = 0;
    for (size_t i = 0; i < s->n; i++) {
        const size_t k = ix[i];
        if (w > 0 && bytes_cmp(v[w - 1], l[w - 1], s->v[k], s->len[k]) == 0) { free(s->v[k]); continue; }
        v[w] = s->v[k];
        l[w++] = s->len[k];
    }
    free(ix);
    free(s->v);
    free(s->len);
    s->v = v;
    s->len = l;
    s->n = w;
    s->cap = s->n;
    s->sorted = true;
    return 0;
}

static bool sset_has(const struct sset *s, const char *p, size_t len) {
    size_t lo = 0, hi = s->n;
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2;
        const int c = bytes_cmp(s->v[mid], s->len[mid], p, len);
        if (c == 0) return true;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

static void sset_free(struct sset *s) {
    for (size_t i = 0; i < s->n; i++) free(s->v[i]);
    free(s->v);
    free(s->len);
    memset(s, 0, sizeof *s);
}

/* ---- the context of one diff ---- */

enum { PKG_INSTALLED, PKG_UPGRADED, PKG_DOWNGRADED, PKG_REMOVED };

struct sx {
    const char *diff;
    receipt_mode_fn mode;
    void *mode_ctx;
    struct sset homes, meta;    /* from the two manifests' roots */
    struct sset pkgs, pkgs_installed;   /* `name` and `name:arch` of the diff's dpkg events; of those installed */
    bool removed;               /* a package whose files are the before manifest's */
    struct sset asks;           /* paths whose owner is asked */
    struct owners *own[2];      /* by the before and the after manifest; NULL: not asked */
    struct sset taken;          /* paths a flagged, noted or counted event names */
};

static int nomem(void) {
    belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
    return -1;
}

static bool at_or_under(const char *path, size_t len, const char *dir, size_t dl) {
    return len >= dl && memcmp(path, dir, dl) == 0 && (len == dl || path[dl] == '/');
}

static bool under_home(const struct sx *x, const char *path, size_t len) {
    if (at_or_under(path, len, "root", 4)) return true;
    for (size_t i = 0; i < x->homes.n; i++)
        if (at_or_under(path, len, x->homes.v[i], x->homes.len[i])) return true;
    return false;
}

static bool startup_file(const struct sx *x, const char *path, size_t len) {
    for (size_t i = 0; i < x->homes.n; i++) {
        const size_t hl = x->homes.len[i];
        if (len <= hl + 1 || memcmp(path, x->homes.v[i], hl) != 0 || path[hl] != '/') continue;
        for (size_t k = 0; k < sysflag_n_home_files; k++)
            if (strlen(sysflag_home_files[k]) == len - hl - 1 && memcmp(path + hl + 1, sysflag_home_files[k], len - hl - 1) == 0)
                return true;
    }
    return false;
}

static bool in_user_units(const struct sx *x, const char *path, size_t len) {
    static const char U[] = "/.config/systemd/user/";
    for (size_t i = 0; i < x->homes.n; i++) {
        const size_t hl = x->homes.len[i];
        if (len > hl + sizeof U - 1 && memcmp(path, x->homes.v[i], hl) == 0 && memcmp(path + hl, U, sizeof U - 1) == 0)
            return true;
    }
    return false;
}

static const char *meta_root_of(const struct sx *x, const char *path, size_t len, size_t *rl) {
    for (size_t i = 0; i < x->meta.n; i++)
        if (at_or_under(path, len, x->meta.v[i], x->meta.len[i])) { *rl = x->meta.len[i]; return x->meta.v[i]; }
    return NULL;
}

/* The roots of a header into the homes (what precedes `/.ssh`) and the metadata roots. */
static int roots_into(struct sx *x, const struct belay_manifest_header *h) {
    for (size_t i = 0; i < h->n_roots; i++) {
        const char *p = h->roots[i].path;
        const size_t n = strlen(p);
        if (h->roots[i].cls == BELAY_ROOT_METADATA && sset_add(&x->meta, p, n) == -1) return -1;
        if (n > 5 && memcmp(p + n - 5, "/.ssh", 5) == 0 && sset_add(&x->homes, p, n - 5) == -1) return -1;
    }
    return 0;
}

/* An executable as a path of the scope: the leading `/` off, and a
 * deleted one's ` (deleted)` (runtime-v1 RT-11). 0 when it is none. */
static size_t exe_path(const char *exe, const char **p) {
    if (exe == NULL || exe[0] != '/' || exe[1] == '\0') return 0;
    size_t n = strlen(exe + 1);
    if (n > 10 && memcmp(exe + 1 + n - 10, " (deleted)", 10) == 0) n -= 10;
    *p = exe + 1;
    return n;
}

/* A drop-in or override of a unit, by its path (WS-F10): the packaged
 * files that unit would have, into `out` (up to four). The number. */
static size_t packaged_of(const char *path, size_t len, char out[4][600]) {
    static const char *const DIRS[] = { "etc/systemd/system/", "etc/systemd/user/" };
    for (int d = 0; d < 2; d++) {
        const size_t dl = strlen(DIRS[d]);
        if (len <= dl || memcmp(path, DIRS[d], dl) != 0) continue;
        const char *u = path + dl;
        const char *sl = memchr(u, '/', len - dl);
        size_t ul;
        if (sl != NULL) {                       /* <unit>.d/<file> */
            ul = (size_t)(sl - u);
            if (ul < 3 || memcmp(u + ul - 2, ".d", 2) != 0 || memchr(sl + 1, '/', len - dl - ul - 1) != NULL) return 0;
            ul -= 2;
        } else {
            ul = len - dl;
        }
        if (ul == 0 || ul > 400) return 0;
        const char *kind = d == 0 ? "system" : "user";
        size_t n = 0;
        snprintf(out[n++], 600, "usr/lib/systemd/%s/%.*s", kind, (int)ul, u);
        snprintf(out[n++], 600, "lib/systemd/%s/%.*s", kind, (int)ul, u);
        const char *at = memchr(u, '@', ul), *dot = NULL;   /* the last `.`: memrchr is not on macOS */
        for (size_t k = ul; k > 0; k--) if (u[k - 1] == '.') { dot = u + k - 1; break; }
        if (at != NULL && dot != NULL && dot > at + 1) {      /* a template's instance: its template */
            snprintf(out[n++], 600, "usr/lib/systemd/%s/%.*s%.*s", kind, (int)(at - u + 1), u, (int)(ul - (size_t)(dot - u)), dot);
            snprintf(out[n++], 600, "lib/systemd/%s/%.*s%.*s", kind, (int)(at - u + 1), u, (int)(ul - (size_t)(dot - u)), dot);
        }
        return n;
    }
    return 0;
}

/* Whose `path` is by a side's lists: ABSENT when that side was not asked. */
static enum belay_owned owned(const struct sx *x, int side, const char *path, size_t len, const char **pkg, size_t *pl) {
    if (x->own[side] == NULL) return BELAY_OWNER_ABSENT;
    return owners_get(x->own[side], path, len, pkg, pl);
}

static bool pkg_in(const struct sset *s, const char *pkg, size_t pl) { return sset_has(s, pkg, pl); }

/* ---- pass 1: what to ask ---- */

static int collect(struct sx *x, FILE *in) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    static char path[4096];
    struct sset meta_paths = { 0 };
    while (rc == 0 && (n = getline(&line, &cap, in)) > 0) {
        struct jval v;
        if (jsonr_parse(line, (size_t)n, &v) == -1) { belay_err_clear(); continue; }
        if (v.t != J_OBJ) { jsonr_free(&v); continue; }
        if (jget(&v, "event") != NULL) {
            const char *k = jstr(&v, "event"), *interp = jstr(&v, "interp");
            if (strcmp(interp, "dpkg") == 0) {
                const int kind = !strcmp(k, "dpkg_installed") ? PKG_INSTALLED : !strcmp(k, "dpkg_upgraded") ? PKG_UPGRADED
                               : !strcmp(k, "dpkg_downgraded") ? PKG_DOWNGRADED : !strcmp(k, "dpkg_removed") ? PKG_REMOVED : -1;
                if (kind >= 0) {
                    const char *p = jstr(&v, "package"), *a = jstr(&v, "arch");
                    char both[600];
                    snprintf(both, sizeof both, "%s:%s", p, a);
                    if (sset_add(&x->pkgs, p, strlen(p)) == -1 || sset_add(&x->pkgs, both, strlen(both)) == -1) rc = -1;
                    if (kind == PKG_INSTALLED &&
                        (sset_add(&x->pkgs_installed, p, strlen(p)) == -1 || sset_add(&x->pkgs_installed, both, strlen(both)) == -1))
                        rc = -1;
                    x->removed |= kind != PKG_INSTALLED;
                }
            } else if (strcmp(interp, "config") == 0 && strcmp(jstr(&v, "grammar"), "ini") == 0) {
                char pk[4][600];
                const char *p = jstr(&v, "path");
                const size_t np = packaged_of(p, strlen(p), pk);
                for (size_t i = 0; i < np && rc == 0; i++) rc = sset_add(&x->asks, pk[i], strlen(pk[i]));
            }
        } else if (jget(&v, "runtime") != NULL) {
            const char *p;
            size_t pl;
            const struct jval *h = jget(&v, "holders");
            for (size_t i = 0; h != NULL && h->t == J_ARR && i < h->n && rc == 0; i++)
                if ((pl = exe_path(jstr(&h->kids[i], "exe"), &p)) > 0) rc = sset_add(&x->asks, p, pl);
            if (rc == 0 && (pl = exe_path(jstr(&v, "exe"), &p)) > 0) rc = sset_add(&x->asks, p, pl);
        } else if (jget(&v, "outcome") != NULL) {
            size_t len, rl;
            if (receipt_record_path(&v, path, sizeof path, &len) == 0 && meta_root_of(x, path, len, &rl) != NULL &&
                meta_paths.n < BELAY_OWNER_ASKS)
                rc = sset_add(&meta_paths, path, len);
            belay_err_clear();
        }
        jsonr_free(&v);
    }
    free(line);
    if (rc == 0 && ferror(in)) { belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", x->diff); rc = -1; }
    else if (rc == -1) nomem();
    /* the records under metadata roots are asked about only when a package of the diff may own them */
    for (size_t i = 0; rc == 0 && x->pkgs.n > 0 && i < meta_paths.n; i++)
        if (sset_add(&x->asks, meta_paths.v[i], meta_paths.len[i]) == -1) rc = nomem();
    sset_free(&meta_paths);
    if (rc == 0 && (sset_sort(&x->asks) == -1 || sset_sort(&x->pkgs) == -1 || sset_sort(&x->pkgs_installed) == -1 ||
                    sset_sort(&x->homes) == -1 || sset_sort(&x->meta) == -1))
        rc = nomem();
    return rc;
}

/* ---- naming ---- */

/* An event's or a runtime record's text as a line names it: escaped as the
 * receipt escapes, and past TEXT_SHOWN characters cut at its end -- the
 * middle of a key or a rule is what says which (LN-7 cuts paths). */
#define TEXT_SHOWN 160
static char *text_shown(const char *text) {
    char *e = receipt_escaped(text, strlen(text));
    if (e == NULL) return NULL;
    size_t chars = 0, at = 0;
    for (size_t i = 0; e[i] != '\0'; i++) {
        if (((unsigned char)e[i] & 0xC0) == 0x80) continue;
        if (chars++ == TEXT_SHOWN) { at = i; break; }
    }
    if (at == 0) return e;
    char *out = malloc(at + 4);
    if (out != NULL) {
        memcpy(out, e, at);
        memcpy(out + at, "\xe2\x80\xa6", 4);
    }
    free(e);
    return out;
}

static int say(struct wflag *f, enum wkind kind, bool note, bool own, const char *text, const char *reason) {
    char *shown = text_shown(text);
    if (shown == NULL) return nomem();
    const size_t cap = strlen(shown) + (reason != NULL ? strlen(reason) : 0) + 24;
    f->text = malloc(cap);
    if (f->text == NULL) { free(shown); return nomem(); }
    if (own) snprintf(f->text, cap, "%s, in no package", shown);
    else if (reason != NULL) snprintf(f->text, cap, "%s (%s)", shown, reason);
    else snprintf(f->text, cap, "%s", shown);
    free(shown);
    f->kind = kind;
    f->note = note || own;
    f->own = own;
    return 0;
}

static int add_flag(struct wstep *s, const struct wflag *f) {
    struct wflag *q = realloc(s->flags, (s->n_flags + 1) * sizeof *q);
    if (q == NULL) return nomem();
    s->flags = q;
    s->flags[s->n_flags++] = *f;
    return 0;
}

/* ---- pass 2: events and runtime records ---- */

enum { SF_NONE, SF_FLAG, SF_NOTE, SF_BYINST };

static bool in_list(const char *s, const char *const *l, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(s, l[i]) == 0) return true;
    return false;
}

static bool nonempty(const struct jval *v) {
    return v != NULL && ((v->t == J_ARR && v->n > 0) || (v->t == J_STR && v->s_len > 0));
}

/* WS-N5: an event of N2 or N3 by its owner. */
static int by_owner(const struct sx *x, const struct jval *owner, bool *own) {
    *own = false;
    if (owner != NULL && owner->t == J_NULL) { *own = true; return SF_NOTE; }
    if (owner != NULL && owner->t == J_STR && pkg_in(&x->pkgs_installed, owner->s, owner->s_len)) return SF_BYINST;
    return SF_NOTE;
}

static bool any_path(const struct jval *e, bool (*fn)(const struct sx *, const char *, size_t), const struct sx *x) {
    const struct jval *ps = jget(e, "paths");
    for (size_t i = 0; ps != NULL && ps->t == J_ARR && i < ps->n; i++)
        if (ps->kids[i].t == J_STR && fn(x, ps->kids[i].s, ps->kids[i].s_len)) return true;
    const char *p = jstr(e, "path");
    return p[0] != '\0' && fn(x, p, strlen(p));
}

/* A file of sshd's grammar (WS-F6), by its scope-relative path. */
static bool sshd_file(const struct sx *x, const char *path, size_t len) {
    (void)x;
    char abs[4096];
    if (len + 2 > sizeof abs) return false;
    abs[0] = '/';
    memcpy(abs + 1, path, len);
    abs[len + 1] = '\0';
    return config_grammar(abs, len + 1) == CONFIG_SSHD;
}

/* WS-F17: a could_not_interpret on a file whose events WS-F1, F2, F3, F6,
 * F16 flag. */
static int not_interpreted(const struct sx *x, const struct jval *e, const char *interp, enum wkind *kind) {
    if (any_path(e, in_user_units, x)) { *kind = WK_SERVICE; return SF_FLAG; }
    if (!strcmp(interp, "sudoers")) { *kind = WK_SUDO; return SF_FLAG; }
    if (!strcmp(interp, "sshkeys")) { *kind = WK_SSH; return SF_FLAG; }
    if (!strcmp(interp, "accounts")) { *kind = WK_ACCOUNT; return SF_FLAG; }
    if (!strcmp(interp, "config") && any_path(e, sshd_file, x)) { *kind = WK_SSH; return SF_FLAG; }
    return SF_NONE;
}

/* The text of a could_not_interpret as the receipt says it: with its first
 * path. NULL: no memory. */
static char *not_interpreted_text(const struct jval *e) {
    const struct jval *ps = jget(e, "paths");
    const char *t = jstr(e, "text"), *p = ps != NULL && ps->t == J_ARR && ps->n && ps->kids[0].t == J_STR ? ps->kids[0].s : NULL;
    const size_t cap = strlen(t) + (p != NULL ? strlen(p) : 0) + 16;
    char *out = malloc(cap);
    if (out == NULL) return NULL;
    if (p != NULL) snprintf(out, cap, "%s: %s%s", t, p, ps->n > 1 ? " and others" : "");
    else snprintf(out, cap, "%s", t);
    return out;
}

static int event_class(const struct sx *x, const struct jval *e, enum wkind *kind, bool *own) {
    const char *k = jstr(e, "event"), *interp = jstr(e, "interp");
    *own = false;
    if (!strcmp(k, "could_not_interpret")) return not_interpreted(x, e, interp, kind);
    const bool config = strcmp(interp, "config") == 0 && strncmp(k, "config_", 7) == 0;
    /* WS-F16: a unit event under a home's user units */
    static const char *const UNIT_EV[] = { "unit_file_added", "unit_file_changed", "timer_file_added", "unit_linked" };
    if ((config || (strcmp(interp, "systemd") == 0 && in_list(k, UNIT_EV, 4))) && any_path(e, in_user_units, x)) {
        *kind = WK_SERVICE;
        return SF_FLAG;
    }
    static const char *const SUDO[] = { "sudo_rule_added", "sudo_rule_removed", "sudo_line_added", "sudo_line_removed" };
    if (in_list(k, SUDO, 4)) { *kind = WK_SUDO; return SF_FLAG; }                                 /* F1 */
    if (!strcmp(k, "ssh_key_added") || !strcmp(k, "ssh_ca_added")) { *kind = WK_SSH; return SF_FLAG; }  /* F2 */
    *kind = WK_ACCOUNT;
    if (!strcmp(k, "user_added")) {                                                                /* F3, N1 */
        const struct jval *u = jget(e, "uid");
        return u != NULL && u->t == J_NUM && u->integer && u->i == 0 ? SF_FLAG : SF_NOTE;
    }
    if (!strcmp(k, "user_changed")) {
        static const char *const F[] = { "uid", "gid", "home", "shell" };
        return in_list(jstr(e, "field"), F, 4) ? SF_FLAG : SF_NONE;
    }
    if (!strcmp(k, "user_password_in_passwd") || !strcmp(k, "password_entry_changed")) return SF_FLAG;
    if (!strcmp(k, "group_members_changed"))                                                       /* F4, N1 */
        return in_list(jstr(e, "name"), PRIV_GROUPS, sizeof PRIV_GROUPS / sizeof PRIV_GROUPS[0]) && nonempty(jget(e, "added"))
             ? SF_FLAG : SF_NOTE;
    if (!strcmp(k, "group_added") || !strcmp(k, "password_entry_added")) return SF_NOTE;
    if (config && strcmp(jstr(e, "grammar"), "sshd") == 0) { *kind = WK_SSH; return SF_FLAG; }     /* F6 */
    *kind = WK_SERVICE;
    if (!strcmp(k, "unit_overrides_packaged")) return SF_FLAG;                                     /* F10 */
    if (config && (!strcmp(k, "config_key_added") || !strcmp(k, "config_key_changed")) &&
        strcmp(jstr(e, "grammar"), "ini") == 0) {
        const char *key = jstr(e, "key");
        if (strncmp(key, "Exec", 4) == 0 || !strcmp(key, "User") || !strcmp(key, "Environment") ||
            !strcmp(key, "EnvironmentFile")) {
            char pk[4][600];
            const char *p = jstr(e, "path");
            const size_t np = packaged_of(p, strlen(p), pk);
            for (size_t i = 0; i < np; i++) {
                const char *pkg;
                size_t pl;
                if (owned(x, 1, pk[i], strlen(pk[i]), &pkg, &pl) == BELAY_OWNER_PACKAGE) return SF_FLAG;
            }
        }
        return SF_NONE;
    }
    if (!strcmp(k, "trust_anchor_added")) {                                                        /* F14, N2 */
        *kind = WK_TRUST;
        const struct jval *o = jget(e, "owner");
        if (o != NULL && o->t == J_NULL) return SF_FLAG;
        return by_owner(x, o, own);
    }
    static const char *const SCHED[] = { "cron_job_added", "cron_script_added", "timer_file_added" };
    static const char *const SERV[] = { "unit_linked", "unit_file_added", "unit_masked", "init_script_added",
                                        "init_script_changed" };
    if (in_list(k, SCHED, 3)) { *kind = WK_SCHEDULE; return by_owner(x, jget(e, "owner"), own); }   /* N2 */
    if (in_list(k, SERV, 5)) { *kind = WK_SERVICE; return by_owner(x, jget(e, "owner"), own); }
    if (strcmp(interp, "dpkg") == 0) { *kind = WK_DPKG; return SF_NOTE; }                        /* N4 */
    return SF_NONE;
}

/* The owner of a runtime record's executables (WS-F13, WS-N5): any in no
 * package; else installed here when one is. */
static void exe_owners(const struct sx *x, const struct jval *r, bool *none, bool *installed) {
    *none = *installed = false;
    const char *one[1] = { jstr(r, "exe") };
    const struct jval *h = jget(r, "holders");
    const size_t n = h != NULL && h->t == J_ARR ? h->n : 1;
    for (size_t i = 0; i < n; i++) {
        const char *p, *pkg;
        size_t pl, kl;
        const size_t len = exe_path(h != NULL && h->t == J_ARR ? jstr(&h->kids[i], "exe") : one[0], &p);
        if (len == 0) continue;
        const enum belay_owned o = owned(x, 1, p, len, &pkg, &kl);
        if (o == BELAY_OWNER_NONE) *none = true;
        else if (o == BELAY_OWNER_PACKAGE && pkg_in(&x->pkgs_installed, pkg, kl)) *installed = true;
        (void)pl;
    }
}

static int runtime_class(const struct sx *x, const struct jval *r, enum wkind *kind, bool *own, const char **word) {
    const char *k = jstr(r, "runtime");
    *own = false;
    const bool opened = !strcmp(k, "listener_opened"), closed = !strcmp(k, "listener_closed");
    const bool service = !strcmp(k, "service_started") || !strcmp(k, "service_stopped") || !strcmp(k, "service_restarted");
    if (!opened && !closed && !service) return -1;      /* not a change: `incomplete`, a kind not known */
    *word = opened || !strcmp(k, "service_started") ? "added" : closed || !strcmp(k, "service_stopped") ? "removed" : "modified";
    *kind = service ? WK_SERVICE : WK_LISTEN;
    const struct jval *cr = jget(r, "client_range");
    if (opened && cr != NULL && cr->t == J_BOOL && cr->b) return SF_NONE;          /* N3: in the count only */
    bool none, installed;
    exe_owners(x, r, &none, &installed);
    const struct jval *port = jget(r, "port");
    if (opened && none && port != NULL && port->t == J_NUM && port->integer && port->i < 1024) return SF_FLAG;  /* F13 */
    if (none) { *own = true; return SF_NOTE; }
    return installed ? SF_BYINST : SF_NOTE;
}

static int taken_add(struct sx *x, const struct jval *e) {
    const struct jval *ps = jget(e, "paths");
    for (size_t i = 0; ps != NULL && ps->t == J_ARR && i < ps->n; i++)
        if (ps->kids[i].t == J_STR && sset_add(&x->taken, ps->kids[i].s, ps->kids[i].s_len) == -1) return nomem();
    return 0;
}

static int pass_events(struct sx *x, FILE *in, struct wstep *s) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, in)) > 0) {
        struct jval v;
        if (jsonr_parse(line, (size_t)n, &v) == -1) { belay_err_clear(); continue; }
        if (v.t != J_OBJ) { jsonr_free(&v); continue; }
        enum wkind kind = WK_SERVICE;
        bool own = false;
        struct wflag f = { 0 };
        if (jget(&v, "event") != NULL) {
            const int c = event_class(x, &v, &kind, &own);
            if (c != SF_NONE && taken_add(x, &v) == -1) rc = -1;
            else if (c == SF_BYINST) s->by_installed++;
            else if (c == SF_FLAG || c == SF_NOTE) {
                const bool cni = strcmp(jstr(&v, "event"), "could_not_interpret") == 0;     /* F17 */
                char *t = cni ? not_interpreted_text(&v) : NULL;
                if (cni && t == NULL) rc = nomem();
                else if (say(&f, kind, c == SF_NOTE, own, cni ? t : jstr(&v, "text"), own ? NULL : wkind_name(kind)) == -1 ||
                         add_flag(s, &f) == -1) { free(f.text); rc = -1; }
                free(t);
            }
        } else if (jget(&v, "runtime") != NULL) {
            const char *word = "added";
            const int c = runtime_class(x, &v, &kind, &own, &word);
            if (c >= 0) s->changes++;
            if (c == SF_NONE) s->counts[watch_outcome_index(word)]++;
            else if (c == SF_BYINST) s->by_installed++;
            else if (c == SF_FLAG || c == SF_NOTE) {
                if (say(&f, kind, c == SF_NOTE, own, jstr(&v, "text"), own ? NULL : wkind_name(kind)) == -1 ||
                    add_flag(s, &f) == -1) { free(f.text); rc = -1; }
            }
        }
        jsonr_free(&v);
    }
    free(line);
    if (rc == 0 && ferror(in)) { belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", x->diff); rc = -1; }
    if (rc == 0 && sset_sort(&x->taken) == -1) rc = nomem();
    return rc;
}

/* ---- pass 3: the path records ---- */

static const char *word_of(const char *outcome) {
    if (!strcmp(outcome, "added")) return "added";
    if (!strcmp(outcome, "removed")) return "removed";
    if (!strcmp(outcome, "modified")) return "modified";
    if (!strcmp(outcome, "type_changed")) return "type changed";
    if (!strcmp(outcome, "metadata_only")) return "metadata changed";
    return "not compared";
}

static int named(struct wstep *s, enum wkind kind, const char *path, size_t len, const char *word, const char *reason) {
    char *shown = flag_shown(path, len);
    if (shown == NULL) return nomem();
    const size_t cap = strlen(shown) + strlen(word) + (reason != NULL ? strlen(reason) : 0) + 8;
    struct wflag f = { .kind = kind, .text = malloc(cap) };
    if (f.text == NULL) { free(shown); return nomem(); }
    if (reason != NULL) snprintf(f.text, cap, "%s %s (%s)", shown, word, reason);
    else snprintf(f.text, cap, "%s %s", shown, word);
    free(shown);
    if (add_flag(s, &f) == -1) { free(f.text); return -1; }
    return 0;
}

static bool sealed_side(const struct sx *x, const char *path, size_t len) {
    struct receipt_meta m;
    if (x->mode == NULL) return false;
    for (int side = 0; side < 2; side++) {
        memset(&m, 0, sizeof m);
        if (x->mode(x->mode_ctx, side, path, len, &m) == 0 && m.sealed) return true;
    }
    return false;
}

/* WS-L1: a record under a metadata root that a package of the diff owns. */
static bool of_a_package(const struct sx *x, const char *path, size_t len) {
    for (int side = 1; side >= 0; side--) {
        const char *pkg;
        size_t pl;
        if (owned(x, side, path, len, &pkg, &pl) == BELAY_OWNER_PACKAGE && pkg_in(&x->pkgs, pkg, pl)) return true;
    }
    return false;
}

static int quiet_top(struct wstep *s, const char *path, size_t len) {
    const char *sl = memchr(path, '/', len);
    const size_t tl = sl != NULL ? (size_t)(sl - path) : len;
    const size_t have = strlen(s->quiet_under);
    for (const char *c = s->quiet_under; *c != '\0';) {        /* each once */
        const size_t n = strcspn(c, ",");
        if (n == tl && memcmp(c, path, tl) == 0) return 0;
        c += n;
        while (*c == ',' || *c == ' ') c++;
    }
    if (have + tl + 3 < sizeof s->quiet_under)
        snprintf(s->quiet_under + have, sizeof s->quiet_under - have, "%s%.*s", have ? ", " : "", (int)tl, path);
    return 0;
}

static int pass_records(struct sx *x, FILE *in, struct wstep *s) {
    char *line = NULL;
    size_t cap = 0, unflagged = 0, run = 0, best_n = 0;
    char top[256] = "", best[256] = "";
    ssize_t n;
    int rc = 0;
    static char path[4096];
    while (rc == 0 && (n = getline(&line, &cap, in)) > 0) {
        struct jval v;
        if (jsonr_parse(line, (size_t)n, &v) == -1) { belay_err_clear(); continue; }
        if (v.t != J_OBJ || jget(&v, "outcome") == NULL || jget(&v, "belay_diff") != NULL) { jsonr_free(&v); continue; }
        size_t len, rl;
        if (receipt_record_path(&v, path, sizeof path, &len) == -1) {
            jsonr_free(&v);
            belay_err_set(BELAY_ERR_CORRUPT, 0, "%s holds a record with no path", x->diff);
            rc = -1;
            break;
        }
        s->changes++;
        const char *outcome = jstr(&v, "outcome"), *word = word_of(outcome);
        if (sset_has(&x->taken, path, len)) { jsonr_free(&v); continue; }          /* the event's */
        char *priv = receipt_privilege_words(&v, path, len, x->mode, x->mode_ctx);    /* F11 */
        const struct sysrow *row = sysflag_row_of(path, len);
        const bool unknown = strcmp(outcome, "unknown") == 0;
        if (priv != NULL) {
            rc = named(s, WK_PRIVILEGE, path, len, priv, "privilege");
            free(priv);
        } else if (row != NULL || startup_file(x, path, len)) {                  /* F5 to F9, F14, F15 */
            const enum wkind kind = row != NULL ? row->kind : WK_LOAD;
            const char *label = row != NULL ? row->label : "shell startup file";
            if (unknown) {                                                       /* FK-11 */
                const struct jval *u = jget(&v, "unknown");
                char reason[160];
                snprintf(reason, sizeof reason, "could not be read: %.120s",
                         u != NULL && u->t == J_ARR && u->n > 0 && u->kids[0].t == J_STR ? u->kids[0].s : "unknown");
                rc = named(s, WK_UNREAD, path, len, word, reason);
            } else {
                rc = named(s, kind, path, len, word, label);
            }
        } else if (strcmp(outcome, "metadata_only") != 0 && !under_home(x, path, len) && strcmp(jstr(&v, "type"), "dir") != 0 &&
                   sealed_side(x, path, len)) {                                  /* its metadata alone: counted */
            rc = named(s, WK_SECRET, path, len, !strcmp(outcome, "modified") ? "changed" : word, "secret");   /* F12 */
        } else {
            s->counts[watch_outcome_index(word)]++;
            const bool quiet = at_or_under(path, len, "var", 3) || (meta_root_of(x, path, len, &rl) != NULL && of_a_package(x, path, len));
            if (quiet) {                                                         /* WS-L1 */
                s->quiet++;
                quiet_top(s, path, len);
            } else if (unflagged < 3) {                                          /* named when three or fewer (LN-5) */
                char *shown = flag_shown(path, len);
                const size_t nc = (shown != NULL ? strlen(shown) : 0) + 24;
                char *nm = shown != NULL ? malloc(nc) : NULL;
                if (nm == NULL) { free(shown); rc = nomem(); }
                else {
                    snprintf(nm, nc, "%s %s", shown, word);
                    free(shown);
                    s->names[s->n_names++] = nm;
                }
            }
            if (!quiet) unflagged++;
            const char *sl = memchr(path, '/', len);                             /* LN-6 */
            const size_t tl = sl != NULL ? (size_t)(sl - path) : 0;
            if (tl > 0 && tl < sizeof top && strlen(top) == tl && memcmp(top, path, tl) == 0) run++;
            else {
                run = tl > 0 && tl < sizeof top ? 1 : 0;
                memcpy(top, path, tl < sizeof top ? tl : 0);
                top[tl < sizeof top ? tl : 0] = '\0';
            }
            if (run > best_n) { best_n = run; memcpy(best, top, sizeof best); }
        }
        jsonr_free(&v);
    }
    free(line);
    if (rc == 0 && ferror(in)) { belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", x->diff); rc = -1; }
    if (rc == 0 && unflagged > 3) {
        for (size_t i = 0; i < s->n_names; i++) free(s->names[i]);
        s->n_names = 0;
    }
    if (rc == 0 && best_n > 0) {
        s->under = flag_shown(best, strlen(best));
        s->n_under = best_n;
        if (s->under == NULL) rc = nomem();
    }
    return rc;
}

static int header_of(const char *path, struct belay_manifest_reader **r) {
    return belay_manifest_open(path, r);      /* the root lines follow the header (V5-A1) */
}

int sysflag_step(const char *diff, const char *before, const char *after, const char *store, receipt_mode_fn mode,
                 void *mode_ctx, struct wstep *s) {
    struct sx x = { .diff = diff, .mode = mode, .mode_ctx = mode_ctx };
    struct belay_manifest_reader *r[2] = { NULL, NULL };
    int rc = -1;
    FILE *in = NULL;
    if (header_of(before, &r[0]) == -1 || header_of(after, &r[1]) == -1) goto out;
    if (roots_into(&x, belay_manifest_header(r[0])) == -1 || roots_into(&x, belay_manifest_header(r[1])) == -1) {
        nomem();
        goto out;
    }
    if (sysflag_roots_changed(belay_manifest_header(r[0]), belay_manifest_header(r[1]), &s->roots) == -1) goto out;
    if ((in = fopen(diff, "r")) == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", diff);
        goto out;
    }
    if (collect(&x, in) == -1) goto out;
    if (x.asks.n > 0) {
        if (owners_of_manifest(after, store, (const char *const *)x.asks.v, x.asks.len, x.asks.n, &x.own[1]) == -1) goto out;
        if (x.removed && owners_of_manifest(before, store, (const char *const *)x.asks.v, x.asks.len, x.asks.n, &x.own[0]) == -1)
            goto out;
    }
    rewind(in);
    if (pass_events(&x, in, s) == -1) goto out;
    rewind(in);
    if (pass_records(&x, in, s) == -1) goto out;
    rc = 0;
out:
    if (in != NULL) fclose(in);
    belay_manifest_close(r[0]);
    belay_manifest_close(r[1]);
    owners_free(x.own[0]);
    owners_free(x.own[1]);
    sset_free(&x.homes);
    sset_free(&x.meta);
    sset_free(&x.pkgs);
    sset_free(&x.pkgs_installed);
    sset_free(&x.asks);
    sset_free(&x.taken);
    return rc;
}

int sysflag_roots_changed(const struct belay_manifest_header *before, const struct belay_manifest_header *after,
                          char **out) {
    *out = NULL;
    struct wsb b = { 0 };
    for (int side = 1; side >= 0; side--) {
        const struct belay_manifest_header *mine = side ? after : before, *other = side ? before : after;
        for (size_t i = 0; i < mine->n_roots; i++) {
            bool both = false;
            for (size_t j = 0; j < other->n_roots && !both; j++)
                both = strcmp(mine->roots[i].path, other->roots[j].path) == 0 && mine->roots[i].cls == other->roots[j].cls;
            if (both) continue;
            char *e = receipt_escaped(mine->roots[i].path, strlen(mine->roots[i].path));
            wsb_f(&b, "%s%c%s", b.n ? ", " : "", side ? '+' : '-', e != NULL ? e : "?");
            b.bad |= e == NULL;
            free(e);
        }
    }
    if (b.bad) { free(b.p); return nomem(); }
    *out = b.p;
    return 0;
}
