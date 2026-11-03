/*
 *  belay's union in the union model's output format (scripts/union-model/,
 *  by its separate author): the same command line as model.py, the merged
 *  view captured through belay's union (src/capture/union.c) and printed one
 *  JSON line per entry, sorted by path bytes -- or one refusal line, its pin
 *  row taken from belay's message. `layer` and `layer_path` come from the
 *  entry's identity: the layer file with its (dev, ino), found by walking
 *  every layer (H-U7: an entry's identity is its layer file's). xattr values
 *  are printed as the sha256 of their bytes, as a manifest keeps them;
 *  scripts/union/agree.py hashes the model's to match.
 *
 *    driver [--prefix P] [--mount M]... [--content] [--explain] [--] SCOPE LAYER...
 */
#define _GNU_SOURCE
#include "belay/error.h"
#include "belay/json.h"
#include "belay/manifest.h"
#include "capture/capture.h"
#include "capture/union.h"

#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/fs.h>
#endif

struct where { dev_t dev; ino_t ino; int layer; char *path; };
static struct where *g_w;
static size_t g_nw, g_cw;
static int g_layer;
static const char *g_base;

static int note(const char *p, const struct stat *st, int flag, struct FTW *f) {
    (void)flag;
    (void)f;
    if (g_nw == g_cw) {
        g_cw = g_cw ? 2 * g_cw : 1024;
        g_w = realloc(g_w, g_cw * sizeof *g_w);
        if (g_w == NULL) return 1;
    }
    const size_t bl = strlen(g_base);
    g_w[g_nw++] = (struct where){ st->st_dev, st->st_ino, g_layer, strdup(p[bl] ? p + bl : "/") };
    return 0;
}

/* "key":"value", or "key_b64":"<base64>" when the bytes are not UTF-8 */
static void js(const char *s, size_t n);
static void field(const char *key, const char *s, size_t n) {
    if (belay_utf8_valid(s, n)) {
        printf("\"%s\":", key);
        js(s, n);
    } else {
        static char b[16384];
        belay_base64_encode(b, sizeof b, s, n);
        printf("\"%s_b64\":\"%s\"", key, b);
    }
}

static void js(const char *s, size_t n) {
    putchar('"');
    for (size_t i = 0; i < n; i++) {
        const unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') printf("\\%c", c);
        else if (c < 0x20) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}

struct out { char *line; char path[4200]; };
static struct out *g_o;
static size_t g_no;
static int g_content;

static const char *tname(int t) {
    switch (t) {
    case BELAY_T_REG: return "reg";
    case BELAY_T_DIR: return "dir";
    case BELAY_T_LNK: return "lnk";
    case BELAY_T_FIFO: return "fifo";
    case BELAY_T_SOCK: return "sock";
    case BELAY_T_BLK: return "blk";
    case BELAY_T_CHR: return "chr";
    default: return "?";
    }
}

static int entry(const struct belay_entry *e, void *ctx) {
    (void)ctx;
    const char *type = tname((int)e->type);
    char *buf;
    size_t len;
    FILE *f = open_memstream(&buf, &len);
    FILE *keep = stdout;
    stdout = f;
    putchar('{');
    field("path", e->path, e->path_len);
    const struct where *w = NULL;
    for (size_t i = 0; i < g_nw && w == NULL; i++)
        if (g_w[i].dev == (dev_t)e->dev && g_w[i].ino == (ino_t)e->ino) w = &g_w[i];
    printf(",\"type\":\"%s\",\"layer\":%d,", type, w ? w->layer : -1);
    field("layer_path", w ? w->path : "?", strlen(w ? w->path : "?"));
    printf(",\"mode\":%u,\"uid\":%llu,\"gid\":%llu", (unsigned)(e->mode & 07777), (unsigned long long)e->uid,
           (unsigned long long)e->gid);
    if (strcmp(type, "reg") == 0) printf(",\"size\":%llu", (unsigned long long)e->size);
    if (strcmp(type, "lnk") == 0) {
        putchar(',');
        field("target", e->link_target, e->link_target_len);
    }
    /* the manifest's body: "name=<sha256>",... -> {"name": "<sha256>", ...} */
    fputs(",\"xattrs\":{", stdout);
    for (size_t k = 0, first = 1; e->has_xattrs && e->xattrs_inline && k < e->xattrs_len;) {
        if (e->xattrs[k] != '"') { k++; continue; }
        size_t q = k + 1;
        while (q < e->xattrs_len && !(e->xattrs[q] == '"' && e->xattrs[q - 1] != '\\')) q++;
        const char *el = e->xattrs + k + 1, *eq = memrchr(el, '=', q - k - 1);
        if (eq != NULL) {
            printf("%s\"%.*s\":\"%.*s\"", first ? "" : ",", (int)(eq - el), el, (int)(e->xattrs + q - eq - 1), eq + 1);
            first = 0;
        }
        k = q + 1;
    }
    putchar('}');
    uint64_t fl = e->has_iflags ? e->iflags : 0;
    printf(",\"protattr\":\"%s%s\"", (fl & FS_IMMUTABLE_FL) ? "i" : "", (fl & FS_APPEND_FL) ? "a" : "");
    printf(",\"mount\":%s", e->is_mount ? "true" : "false");
    if (g_content && strcmp(type, "reg") == 0 && e->has_hash) printf(",\"sha256\":\"%s\"", e->sha256_hex);
    putchar('}');
    stdout = keep;
    fclose(f);
    g_o = realloc(g_o, (g_no + 1) * sizeof *g_o);
    g_o[g_no].line = buf;
    snprintf(g_o[g_no].path, sizeof g_o[g_no].path, "%.*s", (int)e->path_len, e->path);
    g_no++;
    return 0;
}

static int by_path(const void *a, const void *b) {
    return strcmp(((const struct out *)a)->path, ((const struct out *)b)->path);
}

static int refused(const char *msg) {
    const char *r = strstr(msg, "H-");
    char row[8] = "?";
    if (r != NULL) sscanf(r, "%7[A-Z0-9-]", row);
    printf("{\"refused\":\"%s\",\"why\":", row);
    js(msg, strlen(msg));
    puts("}");
    return 1;
}

int main(int argc, char **argv) {
    const char *prefix = "trusted.overlay.", *mounts[256];
    size_t nm = 0;
    int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--prefix") && i + 1 < argc) prefix = argv[++i];
        else if (!strcmp(argv[i], "--mount") && i + 1 < argc && nm < 256) mounts[nm++] = argv[++i];
        else if (!strcmp(argv[i], "--content")) g_content = 1;
        else if (!strcmp(argv[i], "--explain")) continue;
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else break;
    }
    if (argc - i < 2) {
        fprintf(stderr, "usage: driver [--prefix P] [--mount M]... [--content] SCOPE LAYER...\n");
        return 2;
    }
    const char *scope = argv[i++];
    int fds[UNION_LAYERS_MAX];
    size_t n = 0;
    for (; i < argc && n < UNION_LAYERS_MAX; i++, n++) {
        fds[n] = open(argv[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fds[n] == -1) { perror(argv[i]); return 2; }
        g_layer = (int)n;
        g_base = argv[i];
        nftw(argv[i], note, 64, FTW_PHYS);
    }
    struct union_fs *u = union_new(fsops_default(), fds, n, prefix, mounts, nm);
    if (u == NULL) { fprintf(stderr, "%s\n", belay_err_msg()); return 2; }
    char canon[4096];
    const int root = union_open_scope(u, scope, canon, sizeof canon);
    if (root == -1) return refused(belay_err_msg());
    char tmp[] = "/tmp/belay-union-driver-XXXXXX";
    const int t = mkstemp(tmp);
    if (t == -1) return 2;
    close(t);
    struct belay_manifest_opts o = { .hash_max_bytes = BELAY_HASH_MAX_BYTES_DEFAULT };
    const int w = capture_write_root(union_ops(u), tmp, canon, root, &o, NULL);
    const char *why = union_refused(u);
    if (why[0] != '\0') {
        unlink(tmp);
        return refused(why);
    }
    union_free(u);
    if (w != 0) { fprintf(stderr, "capture: %s\n", belay_err_msg()); unlink(tmp); return 2; }
    if (belay_manifest_read(tmp, entry, NULL) != 0) { fprintf(stderr, "read: %s\n", belay_err_msg()); unlink(tmp); return 2; }
    unlink(tmp);
    qsort(g_o, g_no, sizeof *g_o, by_path);
    for (size_t k = 0; k < g_no; k++) puts(g_o[k].line);
    return 0;
}
