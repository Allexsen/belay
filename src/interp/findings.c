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
    bool partial = false;
    for (size_t k = 0; k < n; k++) {
        if (v[k].absent) {                       /* only where the kind allows it */
            if (!d->field[k].optional) return false;
            partial = true;
            continue;
        }
        if (d->field[k].type == FT_STRING && !belay_finding_string_ok(v[k].s, v[k].len)) return false;
        if (d->field[k].type == FT_BYTES &&
            (v[k].len > FINDING_BYTES_MAX || (v[k].s == NULL && v[k].len) ||
             (v[k].len && memchr(v[k].s, '\0', v[k].len) != NULL)))
            return false;
    }
    const char *tmpl = partial ? d->text_partial : d->text;
    if (tmpl == NULL) tmpl = d->text;            /* no second template: absent fields unnamed */
    size_t w = 0;
    for (const char *t = tmpl; *t; ) {
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
        if (k == n || v[k].absent || d->field[k].type == FT_BYTES)
            return false;                                /* naming no field, or one not there: a bug */
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
        if (v[k].absent) continue;
        if (d->field[k].type == FT_BYTES) {          /* "<name>" or "<name>_b64" */
            static char enc[6 * FINDING_BYTES_MAX + 8];
            const char *p = v[k].s ? v[k].s : "";
            const bool utf8 = belay_utf8_valid(p, v[k].len);
            if (sb_str(b, ",\"") || sb_str(b, d->field[k].name) || sb_str(b, utf8 ? "\":\"" : "_b64\":\""))
                return -1;
            if ((utf8 ? belay_json_escape(enc, sizeof enc, p, v[k].len)
                      : belay_base64_encode(enc, sizeof enc, p, v[k].len)) == -1 ||
                sb_str(b, enc) || sb_str(b, "\""))
                return -1;
            continue;
        }
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

int findings_core(struct belay_findings *f, int kind) {
    if (f->oom) return -1;
    if (f->n == FINDINGS_PER_RECORD) { f->extra++; return 0; }
    const char *t = FINDING_KINDS[kind].text;
    const size_t at = f->objs.len;
    if ((f->n && sb_str(&f->objs, ",")) || sb_str(&f->objs, "{\"kind\":\"") ||
        sb_str(&f->objs, FINDING_KINDS[kind].name) || sb_str(&f->objs, "\"") ||
        put_fields(&f->objs, kind, NULL, 0, t, strlen(t)) || sb_str(&f->objs, "}")) {
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

/* E6 names at most E6_PATHS of them; the diff gives paths in its own
 * (bytewise) order, so the first kept are the first claimed, and the rest
 * are only counted: bounded however many there are (decision P4). */
int events_claim(struct belay_events *ev, int interp, const char *path, size_t len) {
    struct ev_per *p = &ev->per[interp];
    if (p->nclaimed == E6_PATHS) { p->claims_over++; return 0; }
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
    if (n > 1) qsort(ps, n, sizeof *ps, pth_cmp);
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

/* One event line: kind, interp, fields, text, provisional (E2), paths, and
 * paths_truncated when E6 cut its list. */
static int add_event(struct ev_per *p, int interp, int kind, const struct belay_fv *v, size_t n,
                     const char *text, size_t tl, bool provisional, struct pth *ps, size_t np,
                     size_t truncated) {
    struct sbuf *b = &p->recs;
    p->last = b->len;
    char num[48];
    snprintf(num, sizeof num, ",\"paths_truncated\":%zu", truncated);
    if (sb_str(b, "{\"event\":\"") || sb_str(b, FINDING_KINDS[kind].name) ||
        sb_str(b, "\",\"interp\":\"") || sb_str(b, INTERP_NAMES[interp]) || sb_str(b, "\"") ||
        put_fields(b, kind, v, n, text, tl) || (provisional && sb_str(b, ",\"provisional\":true")) ||
        put_paths(b, ps, np) || (truncated && sb_str(b, num)) || sb_str(b, "}\n"))
        return -1;
    p->n++;
    return 0;
}

/* Paths an event may name: at least one, each a manifest path's length. */
static bool paths_ok(const char *const *paths, const size_t *lens, size_t n) {
    if (n == 0 || paths == NULL || lens == NULL) return false;
    for (size_t i = 0; i < n; i++)
        if (paths[i] == NULL || lens[i] == 0 || lens[i] > 4096) return false;
    return true;
}

/* Adds an event the core has checked, its text rendered; counted past E5. */
static int put_event(struct belay_events *ev, int kind, const struct belay_fv *v, size_t n,
                     const char *text, size_t tl, bool provisional,
                     const char *const *paths, const size_t *path_lens, size_t npaths) {
    struct ev_per *p = &ev->per[ev->interp];
    if (p->n == EVENTS_PER_INTERP) { p->extra++; return 0; }
    struct pth *ps = malloc(npaths * sizeof *ps);
    if (ps == NULL) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "events: out of memory");
        p->oom = true;
        return -1;
    }
    for (size_t i = 0; i < npaths; i++) ps[i] = (struct pth){ paths[i], path_lens[i] };
    const int r = add_event(p, ev->interp, kind, v, n, text, tl, provisional, ps, npaths, 0);
    free(ps);
    if (r == -1) p->oom = true;
    return r;
}

int belay_event(struct belay_events *ev, int kind, const struct belay_fv *v, size_t n,
                const char *const *paths, const size_t *path_lens, size_t npaths, unsigned flags) {
    struct ev_per *p = &ev->per[ev->interp];
    if (p->oom) return -1;
    if (!paths_ok(paths, path_lens, npaths)) {
        p->broken = true;                     /* nothing to name: E6, said, not hidden */
        return 0;
    }
    char text[FINDING_STRING_MAX + 1];
    size_t tl;
    const bool prov = (flags & BELAY_EVENT_PROVISIONAL) != 0;
    if (!valid(kind, ev->interp, LV_EVENT, v, n, text, &tl)) {     /* E9: that event only */
        const char *t = FINDING_KINDS[FK_INVALID_FINDING].text;
        return put_event(ev, FK_INVALID_FINDING, NULL, 0, t, strlen(t), prov, paths, path_lens, npaths);
    }
    return put_event(ev, kind, v, n, text, tl, prov, paths, path_lens, npaths);
}

int belay_event_not_interpreted(struct belay_events *ev, const char *const *paths,
                                const size_t *path_lens, size_t npaths, unsigned flags) {
    struct ev_per *p = &ev->per[ev->interp];
    if (p->oom) return -1;
    if (!paths_ok(paths, path_lens, npaths)) {
        p->broken = true;
        return 0;
    }
    const char *t = FINDING_KINDS[FK_COULD_NOT_INTERPRET].text;
    return put_event(ev, FK_COULD_NOT_INTERPRET, NULL, 0, t, strlen(t),
                     (flags & BELAY_EVENT_PROVISIONAL) != 0, paths, path_lens, npaths);
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
    const int r = add_event(p, interp, FK_COULD_NOT_INTERPRET, NULL, 0, t, strlen(t), false, ps,
                            p->nclaimed, p->claims_over);
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
