/*
 *  The trust store's interpreter (test/expect/system-interpreters.md TS-1
 *  to TS-3; finding-kinds.md, trust_anchor_*): a symbolic link or regular
 *  file directly under `etc/ssl/certs` whose name ends `.pem` or `.crt`,
 *  added or removed -- the `<hash>.N` links beside it and the bundle
 *  `ca-certificates.crt` are not anchors, and the files of
 *  `usr/local/share/ca-certificates` are claimed only so that they are
 *  kept. A link whose text changed, or a file whose content did, is one
 *  removed and one added (SI-3).
 *
 *  `target` is where the chain of links ends by the after-manifest,
 *  followed one link a lookup round (SI-4): a link's text from the tree's
 *  root when absolute, from the link's directory otherwise, `..` never
 *  above the tree's root, as the kernel resolves it. Where the manifest
 *  has no entry for the path named, or after TRUST_HOPS links, the target
 *  is the last path named. `owner` is the target's (SI-5). `subject` and
 *  `fingerprint` are read from the target's kept copy when it holds exactly
 *  one certificate (TS-2); nothing is validated, and other programs' trust
 *  stores are not seen (TS-3).
 */
#include "builtins.h"
#include "stored.h"
#include "sysev.h"
#include "x509name.h"

#include "belay/manifest.h"

#include <stdlib.h>
#include <string.h>

#define TRUST_HOPS 8

struct trust;

struct anchor {
    struct trust *t;
    struct sysev *e;
    char *target;               /* the last path named, relative to the scope */
    char *next;                 /* the path the chain goes on to, still to be looked up; NULL: ended */
    size_t prefix_len;          /* of the tree's root in the paths: what precedes `etc/ssl/certs` */
    int hops;
    bool wanted;                /* asked for this round, not delivered yet */
    bool cert;                  /* fp is set */
    char fp[X509_FP_LEN + 1];
    char *subject;              /* NULL: not written */
};

struct trust {
    struct sysevs *s;
    struct anchor **a;
    size_t n, cap;
    struct belay_lookup *lk;
    bool owners_asked, failed;
};

static void *begin(void) {
    struct trust *t = calloc(1, sizeof *t);
    if (t != NULL && (t->s = sysevs_new()) == NULL) { free(t); t = NULL; }
    return t;
}

static char *dup_n(const char *s, size_t n) {
    char *p = malloc(n + 1);
    if (p == NULL) return NULL;
    if (n) memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

/* The path a link at `link` (a path relative to the scope, in the tree
 * whose root is its first prefix_len bytes) names by its text: malloc'd, or
 * NULL when it names the tree's root itself, is too long for a manifest's
 * path, or memory ran out (*oom). */
static char *resolve(const char *link, size_t prefix_len, const char *text, size_t text_len, bool *oom) {
    char buf[2 * 4096 + 2];
    const size_t root = prefix_len ? prefix_len - 1 : 0;       /* the root's path, without its slash */
    size_t w;
    size_t link_len = strlen(link), dir = link_len;
    while (dir > root && link[dir - 1] != '/') dir--;
    if (dir > root) dir--;                                      /* the link's directory, without its slash */
    if (link_len > 4096 || text_len > 4096) return NULL;
    w = text_len && text[0] == '/' ? root : dir;
    memcpy(buf, link, w);
    const char *p = text, *e = text + text_len;
    while (p < e) {
        const char *c = p;
        while (p < e && *p != '/') p++;
        const size_t n = (size_t)(p - c);
        if (p < e) p++;
        if (n == 0 || (n == 1 && c[0] == '.')) continue;
        if (n == 2 && c[0] == '.' && c[1] == '.') {
            while (w > root && buf[w - 1] != '/') w--;
            if (w > root) w--;
            continue;
        }
        if (w + 1 + n > 4096) return NULL;
        if (w > 0) buf[w++] = '/';
        memcpy(buf + w, c, n);
        w += n;
    }
    if (w == root) return NULL;
    char *out = dup_n(buf, w);
    if (out == NULL) *oom = true;
    return out;
}

/* What a certificate file says, into the anchor. */
static void read_cert(struct anchor *a, const unsigned char *buf, size_t len) {
    char subject[X509_SUBJECT_MAX + 1];
    size_t sl = 0;
    if (!x509_pem_one((const char *)buf, len, a->fp, subject, &sl)) return;
    a->cert = true;
    if (sl != (size_t)-1 && (a->subject = dup_n(subject, sl)) == NULL) a->t->failed = true;
}

/* The chain goes on from a link entry at `path`. */
static void follow(struct anchor *a, const char *path, const struct belay_entry *e) {
    bool oom = false;
    if (e->unreadable || !e->has_link_target || e->link_target_len == 0 ||
        memchr(e->link_target, '\0', e->link_target_len) != NULL)
        return;                                 /* a text that could not be read reliably names nothing */
    a->next = resolve(path, a->prefix_len, e->link_target, e->link_target_len, &oom);
    if (oom) a->t->failed = true;
}

static int hop_seen(void *ctx, const struct belay_entry *e) {
    struct anchor *a = ctx;
    if (!a->wanted) return 0;
    a->wanted = false;
    free(a->target);
    a->target = a->next;                        /* the manifest has it: the last path named */
    a->next = NULL;
    if (e->type == BELAY_T_LNK) {
        follow(a, a->target, e);
    } else if (e->type == BELAY_T_REG) {
        unsigned char *buf = NULL;
        size_t len = 0;
        if (stored_read_entry(belay_lookup_content(a->t->lk), e, SYS_FILE_MAX, &buf, &len) == SW_OK) read_cert(a, buf, len);
        free(buf);
    }
    return a->t->failed ? -1 : 0;
}

/* One event of an anchor, from the entry of the side it is on. */
static void anchor(struct trust *t, const struct belay_interp_input *in, enum side side, size_t prefix_len) {
    const struct belay_entry *e = side_entry(in, side);
    const struct belay_fv v[] = { { .s = in->path, .len = in->path_len }, { .s = in->path, .len = in->path_len },
                                  { .absent = true }, { .absent = true }, { .absent = true } };
    struct sysev *ev = sysevs_add(t->s, side == SIDE_BEFORE ? FK_TRUST_ANCHOR_REMOVED : FK_TRUST_ANCHOR_ADDED, in->path,
                                  in->path_len, 0, side == SIDE_BEFORE ? SYS_REMOVED : SYS_ADDED, sys_prov(in), v, 5);
    if (ev == NULL) return;                     /* past the bound: counted (E5) */
    if (t->n == t->cap) {
        const size_t c = t->cap ? 2 * t->cap : 16;
        struct anchor **q = realloc(t->a, c * sizeof *q);
        if (q == NULL) { t->failed = true; return; }
        t->a = q;
        t->cap = c;
    }
    struct anchor *a = calloc(1, sizeof *a);
    if (a == NULL) { t->failed = true; return; }
    t->a[t->n++] = a;
    a->t = t;
    a->e = ev;
    a->prefix_len = prefix_len;
    if ((a->target = dup_n(in->path, in->path_len)) == NULL) { t->failed = true; return; }
    if (e->type == BELAY_T_LNK) {
        follow(a, a->target, e);
    } else {
        unsigned char *buf = NULL;
        size_t len = 0;
        if (!e->sealed && !e->meta && stored_read(in, side, SYS_FILE_MAX, &buf, &len) == SW_OK) read_cert(a, buf, len);
        free(buf);
    }
}

static bool there(const struct belay_entry *e) { return e != NULL && (e->type == BELAY_T_LNK || e->type == BELAY_T_REG); }

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct trust *t = state;
    static const char DIR[] = "/etc/ssl/certs";
    (void)out;                                  /* what is reported are events: the record stands as it is */
    if (t == NULL) return BELAY_INTERP_ERROR;
    size_t bl, dl;
    const char *base = sys_base(in->abs_path, in->abs_len, &bl, &dl);
    if (bl == 0 || dl == 0 || !sys_ends(in->abs_path, dl - 1, DIR)) return BELAY_INTERP_DECLINE;
    if (!sys_ends(base, bl, ".pem") && !sys_ends(base, bl, ".crt")) return BELAY_INTERP_DECLINE;
    if (bl == 19 && memcmp(base, "ca-certificates.crt", 19) == 0) return BELAY_INTERP_DECLINE;     /* the bundle */
    if (strcmp(in->outcome, "metadata_only") == 0 || in->path_len < sizeof DIR + bl - 1) return BELAY_INTERP_DECLINE;
    const size_t prefix_len = in->path_len - (sizeof DIR - 1 + bl);     /* `etc/ssl/certs/<name>` after it */
    if (there(in->before)) anchor(t, in, SIDE_BEFORE, prefix_len);
    if (there(in->after)) anchor(t, in, SIDE_AFTER, prefix_len);
    return t->failed || sysevs_failed(t->s) ? BELAY_INTERP_ERROR : BELAY_INTERP_DECLINE;
}

static enum belay_interp_result prepare(void *state, struct belay_lookup *lk) {
    struct trust *t = state;
    if (t == NULL) return BELAY_INTERP_ERROR;
    t->lk = lk;
    bool asked = false;
    for (size_t i = 0; i < t->n; i++) {
        struct anchor *a = t->a[i];
        if (a->next == NULL) continue;
        if (a->wanted || a->hops == TRUST_HOPS) {       /* the manifest lacks it, or the chain is too long: */
            free(a->target);                            /* the last path named */
            a->target = a->next;
            a->next = NULL;
            a->wanted = false;
            continue;
        }
        if (belay_lookup_want(lk, a->next, strlen(a->next), false, hop_seen, a) == -1) return BELAY_INTERP_ERROR;
        a->wanted = true;
        a->hops++;
        asked = true;
    }
    if (asked || t->owners_asked) return t->failed ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    t->owners_asked = true;                             /* every chain has ended: whose is each target */
    for (size_t i = 0; i < t->n; i++) sysevs_owner(t->s, t->a[i]->e, 4, t->a[i]->target, strlen(t->a[i]->target));
    if (sysevs_failed(t->s) || sysevs_ask_owners(t->s, lk) == -1) return BELAY_INTERP_ERROR;
    return t->failed ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
}

static enum belay_interp_result end(void *state, struct belay_events *ev) {
    struct trust *t = state;
    if (t == NULL) return BELAY_INTERP_ERROR;
    enum belay_interp_result r = t->failed ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    if (ev != NULL && r == BELAY_INTERP_FINDINGS) {
        for (size_t i = 0; i < t->n; i++) {
            struct anchor *a = t->a[i];
            const size_t tl = strlen(a->target);
            a->e->v[1] = (struct belay_fv){ .s = sysevs_dup(t->s, a->target, tl), .len = tl };
            if (a->cert) a->e->v[3] = (struct belay_fv){ .s = sysevs_dup(t->s, a->fp, X509_FP_LEN), .len = X509_FP_LEN };
            if (a->cert && a->subject != NULL) {
                const size_t sl = strlen(a->subject);
                a->e->v[2] = (struct belay_fv){ .s = sysevs_dup(t->s, a->subject, sl), .len = sl };
            }
        }
        r = sysevs_emit(t->s, ev, t->lk);
    }
    for (size_t i = 0; i < t->n; i++) {
        free(t->a[i]->target);
        free(t->a[i]->next);
        free(t->a[i]->subject);
        free(t->a[i]);
    }
    free(t->a);
    sysevs_free(t->s);
    free(t);
    return r;
}

const struct belay_interp INTERP_TRUST = { BELAY_INTERP_TRUST, begin, explain, end, prepare };
