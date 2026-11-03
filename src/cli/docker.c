/*
 *  `--docker`: see docker.h. Each rule cites its row of
 *  test/expect/host-reader.md; each fact about Docker or the kernel was
 *  probed before the pin stated it (decision 184; the pin says where).
 */
#define _GNU_SOURCE
#include "cli/docker.h"

#include "belay/error.h"
#include "capture/capture.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__

extern char **environ;

#define CAP_LINUX_IMMUTABLE_BIT 9
#define CAP_SYS_ADMIN_BIT 21
#define CONTAINERD_SNAPSHOTS "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/"

static int refuse(const char *fmt, const char *a, const char *b) {
    belay_err_set(BELAY_ERR_INVALID, 0, fmt, a, b);
    return -1;
}

/* `docker inspect --type container --format F name`: its output (at most
 * cap - 1 bytes, NUL-terminated), or -1 with belay_err. */
static int inspect(const char *name, const char *format, char *out, size_t cap) {
    int po[2], pe[2];
    if (pipe2(po, O_CLOEXEC) != 0) return refuse("--docker: %s%s", strerror(errno), "");
    if (pipe2(pe, O_CLOEXEC) != 0) {
        close(po[0]);
        close(po[1]);
        return refuse("--docker: %s%s", strerror(errno), "");
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, po[1], 1);
    posix_spawn_file_actions_adddup2(&fa, pe[1], 2);
    char *argv[] = { "docker", "inspect", "--type", "container", "--format", (char *)format, (char *)name, NULL };
    pid_t pid;
    const int sr = posix_spawnp(&pid, "docker", &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(po[1]);
    close(pe[1]);
    if (sr != 0) {
        close(po[0]);
        close(pe[0]);
        return refuse("--docker: cannot run docker (%s)%s", strerror(sr), "");
    }
    size_t n = 0;
    ssize_t r;
    while ((r = read(po[0], out + n, cap - 1 - n)) > 0 && n + (size_t)r < cap - 1) n += (size_t)r;
    if (r > 0) n += (size_t)r;
    out[n] = '\0';
    char e[512];
    const ssize_t el = read(pe[0], e, sizeof e - 1);
    e[el > 0 ? el : 0] = '\0';
    close(po[0]);
    close(pe[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) == -1 && errno == EINTR) {}
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        char *nl = strchr(e, '\n');
        if (nl != NULL) *nl = '\0';
        return refuse("--docker %s: docker inspect: %s", name, e[0] ? e : "failed");
    }
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = '\0';
    return 0;
}

static bool hex64(const char *s) {
    if (strlen(s) != 64) return false;
    for (int i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

#define FMT "{{.Id}}|{{.Image}}|{{.State.Status}}|{{.State.Paused}}|{{.State.Pid}}|{{.GraphDriver.Name}}|" \
            "{{json .GraphDriver.Data}}"

struct inspected {
    struct docker_info d;
    char status[32], driver[64];
    char data[16384];                   /* GraphDriver.Data as JSON, or "null" */
};

static int inspect_all(const char *name, struct inspected *x) {
    static char out[20000];
    if (inspect(name, FMT, out, sizeof out) == -1) return -1;
    char *f[7];
    char *p = out;
    for (int i = 0; i < 6; i++) {
        char *bar = strchr(p, '|');
        if (bar == NULL) return refuse("--docker %s: docker inspect said what belay cannot read%s", name, "");
        *bar = '\0';
        f[i] = p;
        p = bar + 1;
    }
    f[6] = p;
    memset(x, 0, sizeof *x);
    if (!hex64(f[0]) || strncmp(f[1], "sha256:", 7) != 0 || !hex64(f[1] + 7))
        return refuse("--docker %s: an id or image id that is not 64 hex digits (%s)", name, f[0]);
    snprintf(x->d.id, sizeof x->d.id, "%s", f[0]);
    snprintf(x->d.image, sizeof x->d.image, "%s", f[1]);
    snprintf(x->status, sizeof x->status, "%s", f[2]);
    x->d.paused = strcmp(f[3], "true") == 0;
    char *end;
    x->d.pid = strtol(f[4], &end, 10);
    if (*end != '\0' || x->d.pid < 0) return refuse("--docker %s: a pid belay cannot read (%s)", name, f[4]);
    snprintf(x->driver, sizeof x->driver, "%s", f[5]);
    snprintf(x->data, sizeof x->data, "%s", f[6]);
    return 0;
}

/* GraphDriver.Data's string `key` (a layer list: no escapes in it, H-M3). */
static bool data_str(const char *json, const char *key, char *out, size_t cap) {
    char k[64];
    snprintf(k, sizeof k, "\"%s\":\"", key);
    const char *s = strstr(json, k);
    if (s == NULL) return false;
    s += strlen(k);
    const char *e = strchr(s, '"');
    if (e == NULL || (size_t)(e - s) >= cap || memchr(s, '\\', (size_t)(e - s)) != NULL) return false;
    memcpy(out, s, (size_t)(e - s));
    out[e - s] = '\0';
    return true;
}

/* A /proc file of the container's first process, whole (cap - 1 bytes at most). */
static int proc_file(long pid, const char *what, char *out, size_t cap) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%ld/%s", pid, what);
    const int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return -1;
    size_t n = 0;
    ssize_t r;
    while (n < cap - 1 && (r = read(fd, out + n, cap - 1 - n)) > 0) n += (size_t)r;
    close(fd);
    out[n] = '\0';
    return 0;
}

/* H-C6, H-C9: the first process's bounding set. */
static int caps(const struct docker_info *d, const char *name, FILE *warn) {
    static char status[16384];
    if (proc_file(d->pid, "status", status, sizeof status) == -1)
        return refuse("--docker %s: its first process is not on this host (Docker Desktop, or a remote daemon?)%s",
                      name, "");
    const char *b = strstr(status, "\nCapBnd:");
    if (b == NULL) return refuse("--docker %s: no capability bounding set in its status%s", name, "");
    const unsigned long long bnd = strtoull(b + 8, NULL, 16);
    if (bnd & (1ull << CAP_SYS_ADMIN_BIT))
        return refuse("--docker %s: the container can gain CAP_SYS_ADMIN (privileged, or the capability added): "
                      "it can mount over a path inside itself, so its writes would not reach the layers the host "
                      "reads -- refused (host-reader H-C6)%s", name, "");
    if ((bnd & (1ull << CAP_LINUX_IMMUTABLE_BIT)) && warn != NULL)
        fprintf(warn, "belay: warning: the container %s can set immutable and append-only flags "
                      "(CAP_LINUX_IMMUTABLE): on the files Docker bind-mounts from the host (/etc/hostname, "
                      "/etc/hosts, /etc/resolv.conf) that sets them on the host's own files, and `docker rm` "
                      "then fails (host-reader H-C9)\n", name);
    return 0;
}

/* A mountinfo field, its \NNN escapes decoded (H-M5). */
static void unescape(char *s) {
    char *w = s;
    for (char *r = s; *r != '\0';) {
        if (r[0] == '\\' && r[1] >= '0' && r[1] <= '7' && r[2] >= '0' && r[2] <= '7' && r[3] >= '0' && r[3] <= '7') {
            *w++ = (char)((r[1] - '0') * 64 + (r[2] - '0') * 8 + (r[3] - '0'));
            r += 4;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

static bool layer_chars(const char *p) {
    if (p[0] != '/') return false;
    for (; *p != '\0'; p++)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '/' ||
              *p == '.' || *p == '_' || *p == '-'))
            return false;
    return true;
}

static bool module_on(const char *param) {
    char p[128], v[8] = "";
    snprintf(p, sizeof p, "/sys/module/overlay/parameters/%s", param);
    FILE *f = fopen(p, "re");
    if (f == NULL) return false;
    const bool ok = fgets(v, sizeof v, f) != NULL;
    fclose(f);
    return ok && v[0] == 'Y';
}

/* H-M2: the super options belay accepts; the rest refused by name. */
static int options(const char *name, char *opts, char **lower, char **upper) {
    bool named_index = false, named_meta = false, named_nfs = false;
    *lower = *upper = NULL;
    char *save = NULL;
    for (char *o = strtok_r(opts, ",", &save); o != NULL; o = strtok_r(NULL, ",", &save)) {
        if (strncmp(o, "lowerdir=", 9) == 0) *lower = o + 9;
        else if (strncmp(o, "upperdir=", 9) == 0) *upper = o + 9;
        else if (strncmp(o, "workdir=", 8) == 0 || !strcmp(o, "rw") || !strcmp(o, "ro") || !strcmp(o, "nouserxattr") ||
                 !strncmp(o, "uuid=", 5) || !strncmp(o, "xino=", 5) || !strncmp(o, "redirect_dir=", 13) ||
                 !strcmp(o, "volatile") || !strcmp(o, "default_permissions"))
            continue;
        else if (!strcmp(o, "index=off")) named_index = true;
        else if (!strcmp(o, "metacopy=off")) named_meta = true;
        else if (!strcmp(o, "nfs_export=off")) named_nfs = true;
        else return refuse("--docker %s: the overlay option %s, which belay does not handle (host-reader H-M2)", name, o);
    }
    if (!named_index && module_on("index")) return refuse("--docker %s: the overlay's index is on (the module's default)%s", name, "");
    if (!named_meta && module_on("metacopy")) return refuse("--docker %s: the overlay's metacopy is on (the module's default)%s", name, "");
    if (!named_nfs && module_on("nfs_export")) return refuse("--docker %s: the overlay's nfs_export is on (the module's default)%s", name, "");
    if (*lower == NULL || *upper == NULL) return refuse("--docker %s: the root overlay has no %s", name, *lower ? "upperdir" : "lowerdir");
    if (strstr(*lower, "::") != NULL) return refuse("--docker %s: a data-only lower layer (host-reader H-M2)%s", name, "");
    return 0;
}

/* H-M3: overlay2's layers are the daemon's own; the containerd store's lie
 * where its snapshotter keeps them. */
static int layers_are_the_daemons(const char *name, const struct inspected *x, char **paths, size_t n) {
    if (strcmp(x->driver, "overlay2") == 0) {
        static char gl[16384], gu[4096];
        if (!data_str(x->data, "LowerDir", gl, sizeof gl) || !data_str(x->data, "UpperDir", gu, sizeof gu))
            return refuse("--docker %s: overlay2 does not name the container's layers%s", name, "");
        if (strcmp(paths[0], gu) != 0) return refuse("--docker %s: the mounted upper layer is not the daemon's (%s)", name, paths[0]);
        char *save = NULL;
        size_t i = 1;
        for (char *l = strtok_r(gl, ":", &save); l != NULL; l = strtok_r(NULL, ":", &save), i++)
            if (i >= n || strcmp(paths[i], l) != 0)
                return refuse("--docker %s: the mounted lower layers are not the daemon's (%s)", name, l);
        if (i != n) return refuse("--docker %s: the mount has more lower layers than the daemon names%s", name, "");
        return 0;
    }
    if (strcmp(x->driver, "overlayfs") == 0 && strcmp(x->data, "null") == 0) {
        for (size_t i = 0; i < n; i++) {
            const size_t pl = strlen(CONTAINERD_SNAPSHOTS);
            const char *p = paths[i];
            if (strncmp(p, CONTAINERD_SNAPSHOTS, pl) != 0) goto bad;
            p += pl;
            if (*p < '0' || *p > '9') goto bad;
            while (*p >= '0' && *p <= '9') p++;
            if (strcmp(p, "/fs") != 0) goto bad;
            continue;
        bad:
            return refuse("--docker %s: a layer outside the containerd snapshotter (%s)", name, paths[i]);
        }
        return 0;
    }
    return refuse("--docker %s: an image store belay does not read (%s)", name, x->driver);
}

int docker_open(const char *name, bool need_paused, struct docker_info *d, struct union_fs **u, FILE *warn) {
    *u = NULL;
    if (geteuid() != 0) return refuse("--docker %s: reading a container's layers needs root on the host (host-reader H-C7)%s", name, "");
    static struct inspected x;
    if (inspect_all(name, &x) == -1) return -1;
    *d = x.d;
    if (need_paused && !x.d.paused)
        return refuse("--docker %s: not paused (%s): baseline export and verify read a paused container (docker pause; "
                      "host-reader H-C4)", name, x.status);
    if (!x.d.paused && strcmp(x.status, "running") != 0)
        return refuse("--docker %s: %s, not running or paused: it has no mount to read (host-reader H-C4)", name, x.status);
    if (x.d.pid <= 0) return refuse("--docker %s: no first process%s", name, "");
    if (caps(d, name, warn) == -1) return -1;

    /* H-M1: exactly one mount at "/", an overlay */
    static char mi[1 << 20];
    if (proc_file(x.d.pid, "mountinfo", mi, sizeof mi) == -1)
        return refuse("--docker %s: cannot read its first process's mount table%s", name, "");
    char *root_opts = NULL, *mounts[1024];
    size_t nm = 0, roots = 0;
    char *save = NULL;
    for (char *line = strtok_r(mi, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        char *sep = strstr(line, " - ");
        if (sep == NULL) continue;
        *sep = '\0';
        char *fields[6] = { 0 }, *s2 = NULL;
        int nf = 0;
        for (char *t = strtok_r(line, " ", &s2); t != NULL && nf < 6; t = strtok_r(NULL, " ", &s2)) fields[nf++] = t;
        char *rest = sep + 3, *s3 = NULL;
        char *fstype = strtok_r(rest, " ", &s3), *src = strtok_r(NULL, " ", &s3), *super = strtok_r(NULL, " ", &s3);
        (void)src;
        if (nf < 5 || fstype == NULL || super == NULL) continue;
        unescape(fields[4]);
        if (strcmp(fields[4], "/") == 0) {
            roots++;
            if (strcmp(fstype, "overlay") == 0) root_opts = super;
        } else if (nm < sizeof mounts / sizeof *mounts) {
            mounts[nm++] = fields[4];
        }
    }
    if (roots != 1 || root_opts == NULL)
        return refuse("--docker %s: its root is not one overlay mount (host-reader H-M1)%s", name, "");
    char *lower, *upper;
    if (options(name, root_opts, &lower, &upper) == -1) return -1;

    /* H-M3, H-M4: the layers, upper first, each resolved and checked */
    char *raw[UNION_LAYERS_MAX + 1], *paths[UNION_LAYERS_MAX + 1];
    size_t n = 0;
    raw[n++] = upper;
    char *s4 = NULL;
    for (char *l = strtok_r(lower, ":", &s4); l != NULL; l = strtok_r(NULL, ":", &s4)) {
        if (n > UNION_LAYERS_MAX) return refuse("--docker %s: more than %s layers", name, "128");
        raw[n++] = l;
    }
    int fds[UNION_LAYERS_MAX + 1];
    dev_t dev = 0;
    size_t opened = 0;
    int rc = -1;
    for (size_t i = 0; i < n; i++) paths[i] = NULL;
    for (size_t i = 0; i < n; i++) {
        if (!layer_chars(raw[i])) { refuse("--docker %s: a layer path belay does not read (%s; host-reader H-M3)", name, raw[i]); goto out; }
        paths[i] = realpath(raw[i], NULL);
        if (paths[i] == NULL) { refuse("--docker %s: cannot resolve the layer %s", name, raw[i]); goto out; }
    }
    if (layers_are_the_daemons(name, &x, paths, n) == -1) goto out;
    for (; opened < n; opened++) {
        fds[opened] = open(paths[opened], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat st;
        if (fds[opened] == -1 || fstat(fds[opened], &st) != 0) {
            if (fds[opened] != -1) close(fds[opened]);
            refuse("--docker %s: cannot open the layer %s", name, paths[opened]);
            goto out;
        }
        if (opened == 0) dev = st.st_dev;
        else if (st.st_dev != dev) {
            close(fds[opened]);
            refuse("--docker %s: its layers are on more than one filesystem (host-reader H-M4)%s", name, "");
            goto out;
        }
    }
    const char *mp[1024];
    for (size_t i = 0; i < nm; i++) mp[i] = mounts[i];
    *u = union_new(fsops_default(), fds, n, "trusted.overlay.", mp, nm);
    opened = 0;                         /* the union holds them now, or closed them */
    rc = *u == NULL ? -1 : 0;
out:
    for (size_t i = 0; i < opened; i++) close(fds[i]);
    for (size_t i = 0; i < n; i++) free(paths[i]);
    return rc;
}

int docker_still(const char *name, const struct docker_info *d, bool need_paused) {
    static struct inspected x;
    if (inspect_all(name, &x) == -1) return -1;
    if (strcmp(x.d.id, d->id) != 0 || x.d.pid != d->pid || (need_paused && !x.d.paused)) {
        belay_err_set(BELAY_ERR_IO, 0, "--docker %s: the container changed while it was read (%s); nothing kept "
                      "(host-reader H-C5)", name, need_paused && !x.d.paused ? "no longer paused" : "another process");
        return -1;
    }
    return 0;
}

int docker_capture(const char *name, const char *path, bool need_paused, const char *manifest,
                   struct belay_manifest_opts *o, struct belay_manifest_stats *s, FILE *warn) {
    static struct docker_info d;
    struct union_fs *u;
    if (docker_open(name, need_paused, &d, &u, warn) == -1) return -1;
    char canon[PATH_MAX];
    const int root = union_open_scope(u, path, canon, sizeof canon);
    if (root == -1) {
        union_free(u);
        return -1;
    }
    o->source_docker = d.id;
    o->source_image = d.image;
    o->exclude = false;                 /* belay's state is on the host, never in the container */
    o->exclude_rel = NULL;
    int w = capture_write_root(union_ops(u), manifest, canon, root, o, s);
    if (w == 0 && union_refused(u)[0] != '\0') {
        belay_err_set(BELAY_ERR_INVALID, 0, "--docker %s: %s; nothing kept (host-reader)", name, union_refused(u));
        w = -1;
    }
    union_free(u);
    if (w == 0 && docker_still(name, &d, need_paused) == -1) w = -1;
    if (w == -1) unlink(manifest);
    return w;
}

#else

int docker_capture(const char *name, const char *path, bool need_paused, const char *manifest,
                   struct belay_manifest_opts *o, struct belay_manifest_stats *s, FILE *warn) {
    (void)path; (void)need_paused; (void)manifest; (void)o; (void)s; (void)warn;
    belay_err_set(BELAY_ERR_INVALID, 0, "--docker %s: the host reader is Linux only (host-reader H-C1)", name);
    return -1;
}

int docker_open(const char *name, bool need_paused, struct docker_info *d, struct union_fs **u, FILE *warn) {
    (void)need_paused; (void)d; (void)warn;
    *u = NULL;
    belay_err_set(BELAY_ERR_INVALID, 0, "--docker %s: the host reader is Linux only (host-reader H-C1)", name);
    return -1;
}

int docker_still(const char *name, const struct docker_info *d, bool need_paused) {
    (void)d; (void)need_paused;
    belay_err_set(BELAY_ERR_INVALID, 0, "--docker %s: the host reader is Linux only", name);
    return -1;
}

#endif
