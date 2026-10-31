/*
 *  Findings and events (belay/interp.h, src/schema/finding_schema.c): each
 *  checked against its kind's row and serialized when it is added, its text
 *  rendered from the kind's template. Nothing an interpreter passes can
 *  reach the output unchecked.
 */
#include "findings_internal.h"

#include "belay/error.h"
#include "belay/json.h"
#include "schema/finding_schema.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

static const char *const INTERP_NAMES[BELAY_INTERP_COUNT] = { "binary", "text", "pip", "dpkg", "git" };

static int sb_put(struct sbuf *b, const void *p, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t c = b->cap ? b->cap : 256;
        while (c < b->len + n + 1) c *= 2;
        char *q = realloc(b->p, c);
        if (q == NULL) {
            belay_err_set(BELAY_ERR_NOMEM, 0, "findings: out of memory");
            return -1;
        }
        b->p = q;
        b->cap = c;
    }
    memcpy(b->p + b->len, p, n);
    b->len += n;
    b->p[b->len] = '\0';
    return 0;
}
static int sb_str(struct sbuf *b, const char *s) { return sb_put(b, s, strlen(s)); }

/* A JSON string: "..." with the bytes escaped. */
static int sb_json(struct sbuf *b, const char *s, size_t n) {
    char esc[6 * FINDING_STRING_MAX + 8];
    if (n > FINDING_STRING_MAX || belay_json_escape(esc, sizeof esc, s, n) == -1) return -1;
    return sb_str(b, "\"") || sb_str(b, esc) || sb_str(b, "\"") ? -1 : 0;
}

bool belay_finding_string_ok(const char *s, size_t len) {
    if (s == NULL) return len == 0;
    return len <= FINDING_STRING_MAX && memchr(s, '\0', len) == NULL && belay_utf8_valid(s, len);
}

/* Is (kind, values) a valid finding for `interp` at `level`? Renders its
 * text into text[] when it is. */
static bool valid(int kind, int interp, unsigned level, const struct belay_fv *v, size_t n,
                  char *text, size_t *text_len) {
    if (kind <= FK_UNSET || kind >= FK_COUNT) return false;
    const struct finding_kind_def *d = &FINDING_KINDS[kind];
    if (d->name == NULL || !(d->levels & level) || !(d->interps & (1u << interp))) return false;
    if (n != finding_nfields((enum finding_kind)kind)) return false;
    for (size_t k = 0; k < n; k++)
        if (d->field[k].type == FT_STRING && !belay_finding_string_ok(v[k].s, v[k].len)) return false;
    size_t w = 0;
    for (const char *t = d->text; *t; ) {
        const char *open = strchr(t, '{');
        const size_t lit = open ? (size_t)(open - t) : strlen(t);
        if (w + lit > FINDING_STRING_MAX) return false;
        memcpy(text + w, t, lit);
        w += lit;
        if (open == NULL) break;
        const char *close = strchr(open, '}');
        size_t k = 0;
        while (k < n && (strlen(d->field[k].name) != (size_t)(close - open - 1) ||
                         memcmp(d->field[k].name, open + 1, (size_t)(close - open - 1)) != 0))
            k++;
        if (k == n) return false;                        /* a template naming no field: a bug */
        char num[32];
        const char *val = num;
        size_t vl;
        if (d->field[k].type == FT_STRING) { val = v[k].s ? v[k].s : ""; vl = v[k].len; }
        else if (d->field[k].type == FT_INT) vl = (size_t)snprintf(num, sizeof num, "%" PRIu64, v[k].i);
        else vl = (size_t)snprintf(num, sizeof num, "%s", v[k].b ? "true" : "false");
        if (w + vl > FINDING_STRING_MAX) return false;
        memcpy(text + w, val, vl);
        w += vl;
        t = close + 1;
    }
    *text_len = w;
    return true;
}

/* `"name":value` for each field, then `"text":"..."`. */
static int put_fields(struct sbuf *b, int kind, const struct belay_fv *v, size_t n,
                      const char *text, size_t text_len) {
    const struct finding_kind_def *d = &FINDING_KINDS[kind];
    for (size_t k = 0; k < n; k++) {
        char num[32];
        if (sb_str(b, ",\"") || sb_str(b, d->field[k].name) || sb_str(b, "\":")) return -1;
        if (d->field[k].type == FT_STRING) {
            if (sb_json(b, v[k].s ? v[k].s : "", v[k].len)) return -1;
        } else {
            if (d->field[k].type == FT_INT) snprintf(num, sizeof num, "%" PRIu64, v[k].i);
            else snprintf(num, sizeof num, "%s", v[k].b ? "true" : "false");
            if (sb_str(b, num)) return -1;
        }
    }
    return sb_str(b, ",\"text\":") || sb_json(b, text, text_len) ? -1 : 0;
}

/* ---- path findings ---- */

void findings_reset(struct belay_findings *f, int interp) {
    f->interp = interp;
    f->objs.len = f->last = 0;
    if (f->objs.p) f->objs.p[0] = '\0';
    f->n = f->extra = 0;
    f->oom = false;
}

bool findings_oom(const struct belay_findings *f) { return f->oom; }

void findings_free(struct belay_findings *f) { free(f->objs.p); memset(f, 0, sizeof *f); }

/* At most FINDINGS_PER_RECORD in all: past it, the last kept one gives way
 * to and_more, which counts it with the rest. */
size_t findings_count(const struct belay_findings *f) { return f->n; }

int belay_finding(struct belay_findings *f, int kind, const struct belay_fv *v, size_t n) {
    if (f->oom) return -1;
    if (f->n == FINDINGS_PER_RECORD) { f->extra++; return 0; }
    char text[FINDING_STRING_MAX + 1];
    size_t tl;
    if (!valid(kind, f->interp, LV_PATH, v, n, text, &tl)) {
        kind = FK_INVALID_FINDING;
        n = 0;
        tl = strlen(FINDING_KINDS[kind].text);
        memcpy(text, FINDING_KINDS[kind].text, tl);
    }
    const size_t at = f->objs.len;
    if ((f->n && sb_str(&f->objs, ",")) || sb_str(&f->objs, "{\"kind\":\"") ||
        sb_str(&f->objs, FINDING_KINDS[kind].name) || sb_str(&f->objs, "\"") ||
        put_fields(&f->objs, kind, v, n, text, tl) || sb_str(&f->objs, "}")) {
        f->oom = true;
        return -1;
    }
    f->last = at;
    f->n++;
    return 0;
}

int findings_write(const struct belay_findings *f, FILE *out) {
    if (f->n == 0) return 0;
    const size_t keep = f->extra ? f->last : f->objs.len;
    if (fputs(",\"findings\":[", out) == EOF || fwrite(f->objs.p, 1, keep, out) != keep)
        return -1;
    if (f->extra && fprintf(out, ",{\"kind\":\"and_more\",\"n\":%zu,\"text\":\"and %zu more\"}",
                            f->extra + 1, f->extra + 1) < 0)
        return -1;
    return fputs("]", out) == EOF ? -1 : 0;
}

/* ---- events ---- */

void events_init(struct belay_events *ev) { memset(ev, 0, sizeof *ev); }

void events_free(struct belay_events *ev) {
    for (int i = 0; i < BELAY_INTERP_COUNT; i++) {
        free(ev->per[i].recs.p);
        free(ev->per[i].claimed.p);
    }
    memset(ev, 0, sizeof *ev);
}

int events_claim(struct belay_events *ev, int interp, const char *path, size_t len) {
    struct ev_per *p = &ev->per[interp];
    if (sb_put(&p->claimed, &len, sizeof len) || sb_put(&p->claimed, path, len)) return -1;
    p->nclaimed++;
    return 0;
}

struct pth { const char *p; size_t n; };
static int pth_cmp(const void *a, const void *b) {
    const struct pth *x = a, *y = b;
    const int c = memcmp(x->p, y->p, x->n < y->n ? x->n : y->n);
    return c ? c : (x->n > y->n) - (x->n < y->n);
}

/* `"paths":[...]`, or `"paths_b64":[...]` when any is not UTF-8 (E3). */
static int put_paths(struct sbuf *b, struct pth *ps, size_t n) {
    qsort(ps, n, sizeof *ps, pth_cmp);
    bool b64 = false;
    for (size_t i = 0; i < n; i++) b64 |= !belay_utf8_valid(ps[i].p, ps[i].n);
    if (sb_str(b, b64 ? ",\"paths_b64\":[" : ",\"paths\":[")) return -1;
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        if (i > 0 && pth_cmp(&ps[i], &ps[i - 1]) == 0) continue;     /* each once */
        if (w++ && sb_str(b, ",")) return -1;
        if (b64) {
            char enc[4 * 4096 / 3 + 8];
            if (ps[i].n > 4096 || belay_base64_encode(enc, sizeof enc, ps[i].p, ps[i].n) == -1 ||
                sb_str(b, "\"") || sb_str(b, enc) || sb_str(b, "\""))
                return -1;
        } else {
            char esc[6 * 4096 + 8];
            if (ps[i].n > 4096 || belay_json_escape(esc, sizeof esc, ps[i].p, ps[i].n) == -1 ||
                sb_str(b, "\"") || sb_str(b, esc) || sb_str(b, "\""))
                return -1;
        }
    }
    return sb_str(b, "]");
}

static int add_event(struct ev_per *p, int interp, int kind, const struct belay_fv *v, size_t n,
                     struct pth *ps, size_t np, const char *text, size_t tl) {
    struct sbuf *b = &p->recs;
    p->last = b->len;
    if (sb_str(b, "{\"event\":\"") || sb_str(b, FINDING_KINDS[kind].name) ||
        sb_str(b, "\",\"interp\":\"") || sb_str(b, INTERP_NAMES[interp]) || sb_str(b, "\"") ||
        put_fields(b, kind, v, n, text, tl) || put_paths(b, ps, np) || sb_str(b, "}\n"))
        return -1;
    p->n++;
    return 0;
}

int belay_event(struct belay_events *ev, int kind, const struct belay_fv *v, size_t n,
                const char *const *paths, const size_t *path_lens, size_t npaths) {
    struct ev_per *p = &ev->per[ev->interp];
    if (p->oom) return -1;
    char text[FINDING_STRING_MAX + 1];
    size_t tl;
    bool paths_ok = npaths > 0;
    for (size_t i = 0; i < npaths && paths_ok; i++)
        paths_ok = paths[i] != NULL && path_lens[i] > 0 && path_lens[i] <= 4096;
    if (!paths_ok || !valid(kind, ev->interp, LV_EVENT, v, n, text, &tl)) {
        p->broken = true;                     /* an interpreter bug: E6, said, not hidden */
        return 0;
    }
    if (p->n == EVENTS_PER_INTERP) { p->extra++; return 0; }
    struct pth *ps = malloc(npaths * sizeof *ps);
    if (ps == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "events: out of memory");
        p->oom = true;
        return -1;
    }
    for (size_t i = 0; i < npaths; i++) ps[i] = (struct pth){ paths[i], path_lens[i] };
    const int r = add_event(p, ev->interp, kind, v, n, ps, npaths, text, tl);
    free(ps);
    if (r == -1) p->oom = true;
    return r;
}

bool events_oom(const struct belay_events *ev, int interp) { return ev->per[interp].oom; }
bool events_broken(const struct belay_events *ev, int interp) { return ev->per[interp].broken; }

int events_failed(struct belay_events *ev, int interp) {
    struct ev_per *p = &ev->per[interp];
    p->recs.len = p->last = 0;
    p->n = p->extra = 0;
    if (p->nclaimed == 0) return 0;
    struct pth *ps = malloc(p->nclaimed * sizeof *ps);
    if (ps == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "events: out of memory");
        return -1;
    }
    size_t off = 0;
    for (size_t i = 0; i < p->nclaimed; i++) {
        memcpy(&ps[i].n, p->claimed.p + off, sizeof ps[i].n);
        ps[i].p = p->claimed.p + off + sizeof ps[i].n;
        off += sizeof ps[i].n + ps[i].n;
    }
    const char *t = FINDING_KINDS[FK_COULD_NOT_INTERPRET].text;
    const int r = add_event(p, interp, FK_COULD_NOT_INTERPRET, NULL, 0, ps, p->nclaimed, t, strlen(t));
    free(ps);
    return r;
}

size_t events_count(const struct belay_events *ev) {
    size_t c = 0;
    for (int i = 0; i < BELAY_INTERP_COUNT; i++) c += ev->per[i].n;
    return c;
}

int events_write(const struct belay_events *ev, FILE *out) {
    static const int ORDER[] = { BELAY_INTERP_TEXT, BELAY_INTERP_PIP, BELAY_INTERP_DPKG,
                                 BELAY_INTERP_GIT };                      /* E4 */
    for (size_t k = 0; k < sizeof ORDER / sizeof ORDER[0]; k++) {
        const struct ev_per *p = &ev->per[ORDER[k]];
        const size_t keep = p->extra ? p->last : p->recs.len;     /* E5, as findings */
        if (keep && fwrite(p->recs.p, 1, keep, out) != keep) return -1;
        if (p->extra && fprintf(out, "{\"event\":\"and_more\",\"interp\":\"%s\",\"n\":%zu,"
                                     "\"text\":\"and %zu more\",\"paths\":[]}\n",
                                INTERP_NAMES[ORDER[k]], p->extra + 1, p->extra + 1) < 0)
            return -1;
    }
    return 0;
}
