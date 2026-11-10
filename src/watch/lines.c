#define _GNU_SOURCE
#include "watch/lines.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RED "\xf0\x9f\x94\xb4"          /* U+1F534 */
#define DOT " \xc2\xb7 "                /* " · " */

const char *const watch_outcome_word[WATCH_OUTCOMES] = {
    "added", "removed", "modified", "type changed", "metadata changed", "not compared",
};

int watch_outcome_index(const char *word) {
    for (int i = 0; i < WATCH_OUTCOMES; i++)
        if (strcmp(watch_outcome_word[i], word) == 0) return i;
    return WATCH_OUTCOMES - 1;
}

void wsb_f(struct wsb *b, const char *fmt, ...) {
    if (b->bad) return;
    va_list a;
    for (;;) {
        va_start(a, fmt);
        const int k = vsnprintf(b->p ? b->p + b->n : NULL, b->p ? b->cap - b->n : 0, fmt, a);
        va_end(a);
        if (k < 0) { b->bad = true; return; }
        if (b->p && (size_t)k < b->cap - b->n) { b->n += (size_t)k; return; }
        const size_t c = (b->cap + (size_t)k + 64) * 2;
        char *q = realloc(b->p, c);
        if (q == NULL) { b->bad = true; return; }
        b->p = q;
        b->cap = c;
    }
}

void wstep_free(struct wstep *s) {
    for (size_t i = 0; i < s->n_calls; i++) free(s->calls[i]);
    free(s->calls);
    for (size_t i = 0; i < s->n_flags; i++) free(s->flags[i].text);
    free(s->flags);
    for (size_t i = 0; i < s->n_names; i++) free(s->names[i]);
    free(s->under);
    for (size_t i = 0; i < s->n_trouble; i++) free(s->trouble[i]);
    free(s->trouble);
    memset(s, 0, sizeof *s);
}

int wstep_add_trouble(struct wstep *s, const char *fmt, ...) {
    char buf[1024];
    va_list a;
    va_start(a, fmt);
    vsnprintf(buf, sizeof buf, fmt, a);
    va_end(a);
    char **q = realloc(s->trouble, (s->n_trouble + 1) * sizeof *q);
    if (q == NULL) return -1;
    s->trouble = q;
    if ((s->trouble[s->n_trouble] = strdup(buf)) == NULL) return -1;
    s->n_trouble++;
    return 0;
}

/* ---- naming at most three (LN-4) ---- */

/* Flags of one level from `n` steps: at most `room` named into `out`, one
 * of each kind before a second of any, kinds in FK's order; the rest are
 * counted into rest[]. The number named. */
static size_t choose(const struct wstep *steps, size_t n, bool note, size_t room, const struct wflag **out,
                     uint64_t rest[WK_COUNT], uint64_t *total) {
    size_t have[WK_COUNT] = { 0 }, taken[WK_COUNT] = { 0 }, named = 0;
    memset(rest, 0, WK_COUNT * sizeof rest[0]);
    *total = 0;
    for (size_t s = 0; s < n; s++) {
        for (size_t i = 0; i < steps[s].n_flags; i++)
            if (steps[s].flags[i].note == note) have[steps[s].flags[i].kind]++;
        for (int k = 0; k < WK_COUNT; k++) rest[k] += note ? steps[s].cut_note[k] : steps[s].cut_flag[k];
    }
    for (int k = 0; k < WK_COUNT; k++) *total += have[k] + rest[k];
    for (size_t round = 0; named < room; round++) {
        bool any = false;
        for (int k = 0; k < WK_COUNT && named < room; k++) {
            if (have[k] <= round) continue;
            any = true;
            size_t seen = 0;            /* the round-th flag of this kind, in the steps' order */
            for (size_t s = 0; s < n && taken[k] == round; s++)
                for (size_t i = 0; i < steps[s].n_flags; i++) {
                    const struct wflag *f = &steps[s].flags[i];
                    if (f->note != note || (int)f->kind != k) continue;
                    if (seen++ == round) { out[named++] = f; taken[k]++; break; }
                }
        }
        if (!any) break;
    }
    for (int k = 0; k < WK_COUNT; k++) rest[k] += have[k] - taken[k];
    return named;
}

static void more(struct wsb *out, const char *what, const uint64_t rest[WK_COUNT]) {
    uint64_t n = 0;
    for (int k = 0; k < WK_COUNT; k++) n += rest[k];
    if (n == 0) return;
    wsb_f(out, "; and %llu more %s: ", (unsigned long long)n, what);
    bool first = true;
    for (int k = 0; k < WK_COUNT; k++) {
        if (rest[k] == 0) continue;
        wsb_f(out, "%s%llu %s", first ? "" : ", ", (unsigned long long)rest[k], wkind_name((enum wkind)k));
        first = false;
    }
}

/* The flagged, then the noted, of `n` steps as LN-4 names them. What was
 * written: flagged and noted totals in *nf and *nn. */
static void named(struct wsb *out, const struct wstep *steps, size_t n, bool flags, bool notes, uint64_t *nf,
                  uint64_t *nn) {
    const struct wflag *pick[3];
    uint64_t rest_f[WK_COUNT], rest_n[WK_COUNT];
    size_t k = 0;
    *nf = *nn = 0;
    if (flags) k = choose(steps, n, false, 3, pick, rest_f, nf);
    else memset(rest_f, 0, sizeof rest_f);
    if (notes) k += choose(steps, n, true, 3 - k, pick + k, rest_n, nn);
    else memset(rest_n, 0, sizeof rest_n);
    for (size_t i = 0; i < k; i++) wsb_f(out, "%s%s", i ? "; " : "", pick[i]->text);
    more(out, "flagged", rest_f);
    more(out, "noted", rest_n);
}

static void counts(struct wsb *out, const struct wstep *s, uint64_t u) {
    bool first = true;
    for (int i = 0; i < WATCH_OUTCOMES; i++) {
        if (s->counts[i] == 0) continue;
        wsb_f(out, "%s%llu %s", first ? "" : ", ", (unsigned long long)s->counts[i], watch_outcome_word[i]);
        first = false;
    }
    if (u > 3 && s->under != NULL && s->n_under * 2 > u)
        wsb_f(out, " (%llu under %s/)", (unsigned long long)s->n_under, s->under);
}

void lines_step(struct wsb *out, const struct wstep *s) {
    for (size_t i = 0; i < s->n_trouble; i++) wsb_f(out, "belay: " RED " %s\n", s->trouble[i]);
    uint64_t nf = 0, nn = 0, u = 0;
    for (int i = 0; i < WATCH_OUTCOMES; i++) u += s->counts[i];
    bool red = false;
    for (size_t i = 0; i < s->n_flags; i++) red |= !s->flags[i].note;
    for (int k = 0; k < WK_COUNT; k++) red |= s->cut_flag[k] > 0;
    bool any = s->n_flags > 0;
    for (int k = 0; k < WK_COUNT; k++) any |= s->cut_flag[k] > 0 || s->cut_note[k] > 0;
    if (!any && u == 0) return;                                             /* LN-1 */
    wsb_f(out, "belay: %s%s", red ? RED " " : "", s->n_calls == 0 ? "outside tool calls: " : "");
    if (any) {
        named(out, s, 1, true, true, &nf, &nn);
        if (u > 0) {
            wsb_f(out, DOT "%llu more: ", (unsigned long long)u);
            counts(out, s, u);
        }
    } else {
        wsb_f(out, "%llu change%s: ", (unsigned long long)u, u == 1 ? "" : "s");
        if (u <= 3 && s->n_names == u)
            for (size_t i = 0; i < s->n_names; i++) wsb_f(out, "%s%s", i ? "; " : "", s->names[i]);
        else counts(out, s, u);
    }
    wsb_f(out, "\n");
}

void lines_summary(struct wsb *out, const struct wstep *steps, size_t n, const char *session,
                   const char *const *standing, const char *gone, const struct wwords *w) {
    /* troubles: each text once, in order */
    size_t n_trouble = 0;
    for (size_t s = 0; s < n; s++)
        for (size_t i = 0; i < steps[s].n_trouble; i++) {
            bool seen = false;
            for (size_t p = 0; p <= s && !seen; p++)
                for (size_t j = 0; j < (p == s ? i : steps[p].n_trouble) && !seen; j++)
                    seen = strcmp(steps[p].trouble[j], steps[s].trouble[i]) == 0;
            for (size_t j = 0; standing != NULL && standing[j] != NULL && !seen; j++)
                seen = strcmp(standing[j], steps[s].trouble[i]) == 0;
            if (seen) continue;
            wsb_f(out, "belay: " RED " %s\n", steps[s].trouble[i]);
            n_trouble++;
        }
    for (size_t j = 0; standing != NULL && standing[j] != NULL; j++) {
        wsb_f(out, "belay: " RED " %s\n", standing[j]);
        n_trouble++;
    }
    uint64_t nf = 0, nn = 0, total = 0, in_calls = 0, outside = 0;
    struct wsb line = { 0 };
    named(&line, steps, n, true, false, &nf, &nn);
    if (nf > 0) wsb_f(out, "belay: " RED " %llu flagged: %s\n", (unsigned long long)nf, line.p ? line.p : "");
    line.n = 0;
    if (line.p) line.p[0] = '\0';
    named(&line, steps, n, false, true, &nf, &nn);
    if (nn > 0) wsb_f(out, "belay: %llu noted: %s\n", (unsigned long long)nn, line.p ? line.p : "");
    out->bad |= line.bad;
    free(line.p);
    /* totals (SM-3, SM-4): the sum of the steps' counts */
    size_t n_calls = 0;
    bool others = false;
    for (size_t s = 0; s < n; s++) {
        total += steps[s].changes;
        if (steps[s].changes > 0 && strcmp(steps[s].session, session) != 0) others = true;
        if (steps[s].n_calls == 0) { outside += steps[s].changes; continue; }
        in_calls += steps[s].changes;
        if (steps[s].changes == 0) continue;
        for (size_t i = 0; i < steps[s].n_calls; i++) {         /* each call once */
            bool seen = false;
            for (size_t p = 0; p <= s && !seen; p++) {
                if (steps[p].changes == 0) continue;
                for (size_t j = 0; j < (p == s ? i : steps[p].n_calls) && !seen; j++)
                    seen = strcmp(steps[p].calls[j], steps[s].calls[i]) == 0;
            }
            if (!seen) n_calls++;
        }
    }
    if (total == 0) {
        if (n_trouble == 0) wsb_f(out, "belay: nothing changed %s", w->span);
        else return;                    /* "could not record" is said; "nothing changed" would not be known */
    } else {
        wsb_f(out, "belay: %llu changed %s", (unsigned long long)total, w->span);
        if (outside == 0)
            wsb_f(out, " in %zu %s%s", n_calls, w->call, n_calls == 1 ? "" : "s");
        else if (in_calls == 0)
            wsb_f(out, " outside %ss", w->call);
        else
            wsb_f(out, ": %llu in %zu %s%s, %llu outside %ss", (unsigned long long)in_calls, n_calls, w->call,
                  n_calls == 1 ? "" : "s", (unsigned long long)outside, w->call);
    }
    if (others) wsb_f(out, " (with another session's steps)");
    if (gone != NULL) wsb_f(out, " (the record before %s is gone)", gone);
    wsb_f(out, "%s\n", total == 0 ? "" : w->tail);
}
