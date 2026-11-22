/*
 *  The sshkeys interpreter (test/expect/system-interpreters.md SK-1 to
 *  SK-3; finding-kinds.md, ssh_*): the key lines of an `authorized_keys` or
 *  `authorized_keys2` directly in a directory `.ssh`, added and removed. An
 *  event names the file and the key: never whose login it opens (SK-2:
 *  `AuthorizedKeysFile` and `StrictModes` are sshd's).
 *
 *  A line (sshd(8), AUTHORIZED_KEYS FILE FORMAT): blank, or a comment (`#`
 *  first); else optional options, a key type, the key in base64, and the
 *  rest as a comment. The first field is the key type when it is one of the
 *  names below; otherwise it is the options -- ended by a blank outside
 *  double quotes, `\"` inside quotes being a quote character -- and the
 *  next field must be a key type. The key must decode and must begin with
 *  its own type's name, length-prefixed, as ssh-keygen checks. A line that
 *  is none of this makes the file could_not_interpret (SI-2): no event is
 *  given from a file that was not read whole.
 *
 *  Lines are compared as multisets of (type, fingerprint, options,
 *  comment): a key whose options or comment changed is one removed and one
 *  added (SI-3); a key moved in its file is no event.
 */
#include "builtins.h"
#include "sysev.h"

#include "belay/error.h"
#include "belay/hash.h"
#include "belay/json.h"
#include "belay/manifest.h"

#include <stdlib.h>
#include <string.h>

#define FP_LEN (7 + 43)         /* "SHA256:" and 32 bytes in base64 without its padding */

struct sshkeys { struct sysevs *s; bool failed; };

static void *begin(void) {
    struct sshkeys *k = calloc(1, sizeof *k);
    if (k != NULL && (k->s = sysevs_new()) == NULL) { free(k); k = NULL; }
    return k;
}

static const char *const TYPES[] = {
    "ssh-ed25519", "ssh-rsa", "ssh-dss",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com", "ssh-dss-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
};

static bool is_type(const char *s, size_t n) {
    for (size_t i = 0; i < sizeof TYPES / sizeof TYPES[0]; i++)
        if (strlen(TYPES[i]) == n && memcmp(TYPES[i], s, n) == 0) return true;
    return false;
}

struct str { const char *s; size_t n; };

struct key {
    struct str type, opts, comment;     /* into the file's buffer; opts as written, empty when none */
    char fp[FP_LEN + 1];
    uint32_t line;
};

/* The end of the field at s: the first blank, or e. */
static const char *field_end(const char *s, const char *e) {
    while (s < e && !sys_blank(*s)) s++;
    return s;
}

/* The end of an options field at s: the first blank outside double quotes.
 * NULL when a quote is left open. */
static const char *opts_end(const char *s, const char *e) {
    bool quoted = false;
    for (; s < e; s++) {
        if (quoted && *s == '\\' && s + 1 < e && s[1] == '"') { s++; continue; }
        if (*s == '"') quoted = !quoted;
        else if (!quoted && sys_blank(*s)) break;
    }
    return quoted ? NULL : s;
}

/* The fingerprint of the key in base64 at [b, b+n), which must decode and
 * begin with the length-prefixed name `type`. false: not a key of the type. */
static bool fingerprint(const char *b, size_t n, struct str type, char fp[FP_LEN + 1], bool *oom) {
    if (n == 0 || n % 4 != 0) return false;
    char *in = malloc(n + 1);
    unsigned char *blob = malloc(3 * (n / 4) + 1);
    bool ok = false;
    size_t bl = 0;
    if (in == NULL || blob == NULL) { *oom = true; goto done; }
    memcpy(in, b, n);
    in[n] = '\0';
    if (belay_base64_decode(blob, 3 * (n / 4) + 1, &bl, in) != 0) { belay_err_clear(); goto done; }
    if (bl < 4 + type.n) goto done;
    const size_t tl = ((size_t)blob[0] << 24) | ((size_t)blob[1] << 16) | ((size_t)blob[2] << 8) | blob[3];
    if (tl != type.n || memcmp(blob + 4, type.s, tl) != 0) goto done;
    struct belay_sha256 c;
    uint8_t d[32];
    char b64[48];
    belay_sha256_init(&c);
    belay_sha256_update(&c, blob, bl);
    belay_sha256_final(&c, d);
    if (belay_base64_encode(b64, sizeof b64, d, sizeof d) != 0) { belay_err_clear(); goto done; }
    memcpy(fp, "SHA256:", 7);
    memcpy(fp + 7, b64, 43);            /* 44 characters, the last one padding */
    fp[FP_LEN] = '\0';
    ok = true;
done:
    free(in);
    free(blob);
    return ok;
}

/* One line into *k. 1: a key; 0: blank or a comment; -1: it does not parse. */
static int parse_line(const struct sysline *l, struct key *k, bool *oom) {
    const char *s = l->s, *e = l->s + l->n;
    sys_trim(&s, &e);
    if (s == e || *s == '#') return 0;
    memset(k, 0, sizeof *k);
    k->line = l->line;
    k->opts = (struct str){ s, 0 };
    const char *fe = field_end(s, e);
    if (!is_type(s, (size_t)(fe - s))) {        /* not a key type: the options */
        const char *oe = opts_end(s, e);
        if (oe == NULL || oe == s) return -1;
        k->opts = (struct str){ s, (size_t)(oe - s) };
        s = oe;
        while (s < e && sys_blank(*s)) s++;
        fe = field_end(s, e);
        if (!is_type(s, (size_t)(fe - s))) return -1;
    }
    k->type = (struct str){ s, (size_t)(fe - s) };
    s = fe;
    while (s < e && sys_blank(*s)) s++;
    fe = field_end(s, e);
    if (!fingerprint(s, (size_t)(fe - s), k->type, k->fp, oom)) return -1;
    s = fe;
    while (s < e && sys_blank(*s)) s++;
    k->comment = (struct str){ s, (size_t)(e - s) };
    return 1;
}

struct kside { struct sysline *lines; struct key *k; struct sysline *keys; char *buf; size_t n; };

static void side_free(struct kside *sd) {
    free(sd->lines);
    free(sd->k);
    free(sd->keys);
    free(sd->buf);
    memset(sd, 0, sizeof *sd);
}

/* A side's key lines, and for each the bytes it is compared by. 0; 1: a
 * line does not parse; -1: memory. */
static int parse(const char *buf, size_t len, struct kside *sd) {
    size_t nl = 0, total = 0;
    bool oom = false;
    memset(sd, 0, sizeof *sd);
    sd->lines = sys_lines(buf, len, &nl, &oom);
    if (oom) return -1;
    if (nl == 0) return 0;
    sd->k = calloc(nl, sizeof *sd->k);
    sd->keys = calloc(nl, sizeof *sd->keys);
    if (sd->k == NULL || sd->keys == NULL) return -1;
    for (size_t i = 0; i < nl; i++) {
        const int r = parse_line(&sd->lines[i], &sd->k[sd->n], &oom);
        if (oom) return -1;
        if (r == -1) return 1;
        if (r == 1) {
            const struct key *k = &sd->k[sd->n++];
            total += k->type.n + FP_LEN + k->opts.n + k->comment.n + 3;
        }
    }
    if (sd->n == 0) return 0;
    if ((sd->buf = malloc(total)) == NULL) return -1;
    char *w = sd->buf;
    for (size_t i = 0; i < sd->n; i++) {
        const struct key *k = &sd->k[i];
        /* No field holds a newline: the four cannot run into one another. */
        const struct str part[4] = { k->type, { k->fp, FP_LEN }, k->opts, k->comment };
        sd->keys[i] = (struct sysline){ .s = w, .line = k->line };
        for (int p = 0; p < 4; p++) {
            if (p) *w++ = '\n';
            if (part[p].n) memcpy(w, part[p].s, part[p].n);
            w += part[p].n;
        }
        sd->keys[i].n = (size_t)(w - sd->keys[i].s);
    }
    return 0;
}

static bool is_ca(const char *s, size_t n) {
    static const char CA[] = "cert-authority";
    if (n != sizeof CA - 1) return false;
    for (size_t i = 0; i < n; i++)
        if ((s[i] | 0x20) != CA[i] && s[i] != CA[i]) return false;
    return true;
}

/* The event of one key line: its options split at commas outside double
 * quotes, each as written. */
static void key_event(struct sshkeys *x, const struct belay_interp_input *in, const struct key *k, int rank) {
    size_t cap = 1, n = 0;
    for (size_t i = 0; i < k->opts.n; i++) cap += k->opts.s[i] == ',';
    struct belay_fv *opt = calloc(cap, sizeof *opt);
    if (opt == NULL) { x->failed = true; return; }
    bool ca = false, quoted = false;
    const char *s = k->opts.s, *e = s + k->opts.n, *from = s;
    for (const char *p = s; k->opts.n && p <= e; p++) {
        if (p < e && quoted && *p == '\\' && p + 1 < e && p[1] == '"') { p++; continue; }
        if (p < e && *p == '"') { quoted = !quoted; continue; }
        if (p == e || (!quoted && *p == ',')) {
            opt[n++] = (struct belay_fv){ .s = from, .len = (size_t)(p - from) };
            ca |= is_ca(from, (size_t)(p - from));
            from = p + 1;
        }
    }
    const int kind = rank == SYS_REMOVED ? (ca ? FK_SSH_CA_REMOVED : FK_SSH_KEY_REMOVED)
                                         : (ca ? FK_SSH_CA_ADDED : FK_SSH_KEY_ADDED);
    const struct belay_fv v[] = { { .s = in->path, .len = in->path_len }, { .s = k->type.s, .len = k->type.n },
                                  { .s = k->fp, .len = FP_LEN }, { .s = k->comment.s, .len = k->comment.n },
                                  { .list = opt, .nlist = n } };
    sysevs_add(x->s, kind, in->path, in->path_len, k->line, rank, sys_prov(in), v, 5);
    free(opt);
}

static bool ours(const struct belay_interp_input *in) {
    size_t bl, dl;
    const char *base = sys_base(in->abs_path, in->abs_len, &bl, &dl);
    if (!((bl == 15 && memcmp(base, "authorized_keys", 15) == 0) || (bl == 16 && memcmp(base, "authorized_keys2", 16) == 0)))
        return false;
    return dl > 0 && sys_ends(in->abs_path, dl - 1, "/.ssh");
}

static enum belay_interp_result explain(void *state, const struct belay_interp_input *in,
                                        struct belay_findings *out) {
    struct sshkeys *x = state;
    (void)out;                                  /* what is reported are events: the record stands as it is */
    if (x == NULL) return BELAY_INTERP_ERROR;
    if (!ours(in) || strcmp(in->outcome, "metadata_only") == 0) return BELAY_INTERP_DECLINE;
    /* A directory named like the file holds no key; one that became a file,
     * or the reverse, is read by sys_read, which refuses it (SI-2). */
    if ((in->before == NULL || in->before->type == BELAY_T_DIR) && (in->after == NULL || in->after->type == BELAY_T_DIR))
        return BELAY_INTERP_DECLINE;
    struct sysfile f;
    if (!sys_read(in, &f)) return sys_cannot(x->s, in);
    struct kside sd[2];
    memset(sd, 0, sizeof sd);
    int rc = 0;
    for (int k = 0; k < 2 && rc == 0; k++)
        if (f.have[k]) rc = parse((const char *)f.buf[k], f.len[k], &sd[k]);
    enum belay_interp_result r = BELAY_INTERP_DECLINE;
    if (rc == 1) {
        r = sys_cannot(x->s, in);
    } else if (rc == -1 || sys_lines_diff(sd[0].keys, sd[0].n, sd[1].keys, sd[1].n) == -1) {
        x->failed = true;
    } else {
        for (int k = 0; k < 2; k++)
            for (size_t i = 0; i < sd[k].n; i++)
                if (sd[k].keys[i].only) key_event(x, in, &sd[k].k[i], k == 0 ? SYS_REMOVED : SYS_ADDED);
    }
    side_free(&sd[0]);
    side_free(&sd[1]);
    sys_free(&f);
    return x->failed || sysevs_failed(x->s) ? BELAY_INTERP_ERROR : r;
}

static enum belay_interp_result end(void *state, struct belay_events *ev) {
    struct sshkeys *x = state;
    if (x == NULL) return BELAY_INTERP_ERROR;
    enum belay_interp_result r = x->failed ? BELAY_INTERP_ERROR : BELAY_INTERP_FINDINGS;
    if (ev != NULL && r == BELAY_INTERP_FINDINGS) r = sysevs_emit(x->s, ev, NULL);
    sysevs_free(x->s);
    free(x);
    return r;
}
const struct belay_interp INTERP_SSHKEYS = { BELAY_INTERP_SSHKEYS, begin, explain, end, NULL };
