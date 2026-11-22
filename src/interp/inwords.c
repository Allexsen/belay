/*
 *  Schedules in words (system-interpreters.md SI-6, SW-1 to SW-6, SW-8).
 *  Only a form with one reading has words: a step is put in words only when
 *  it divides its field's span -- a step of 7 minutes runs at 0, 7, ..., 56
 *  and then at 0 again, which "every 7 minutes" would misstate -- and
 *  anything the table does not list has none. The @words are crontab(5)'s
 *  expansions. Times are cron's own clock's: the words say so.
 */
#include "inwords.h"

#include <stdio.h>
#include <string.h>

struct fld { const char *s; size_t n; };

static bool star(struct fld f) { return f.n == 1 && f.s[0] == '*'; }

/* One or two digits, within [lo, hi]. */
static bool num(const char *s, size_t n, int lo, int hi, int *out) {
    if (n < 1 || n > 2) return false;
    int v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10 + (s[i] - '0');
    }
    if (v < lo || v > hi) return false;
    *out = v;
    return true;
}

/* A star, a slash and N, N a divisor of `span` below it. */
static bool step(struct fld f, int span, int *out) {
    int n;
    if (f.n < 3 || f.s[0] != '*' || f.s[1] != '/' || !num(f.s + 2, f.n - 2, 1, span - 1, &n) || span % n != 0)
        return false;
    *out = n;
    return true;
}

static const char *const DAY[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

static char lower(char c) { return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c; }

/* A weekday: 0 to 7 (0 and 7 Sunday) or its first three letters, any case. */
static bool weekday(const char *s, size_t n, int *out) {
    int v;
    if (n == 1 && num(s, 1, 0, 7, &v)) { *out = v % 7; return true; }
    if (n != 3) return false;
    for (int d = 0; d < 7; d++)
        if (lower(s[0]) == lower(DAY[d][0]) && lower(s[1]) == DAY[d][1] && lower(s[2]) == DAY[d][2]) {
            *out = d;
            return true;
        }
    return false;
}

/* `D[,D...]` into "Mon, Thu", in the order written. */
static bool weekdays(struct fld f, char *out, size_t cap) {
    size_t w = 0, at = 0;
    if (f.n == 0) return false;
    for (;;) {
        size_t e = at;
        while (e < f.n && f.s[e] != ',') e++;
        int d;
        if (!weekday(f.s + at, e - at, &d) || w + 6 > cap) return false;
        w += (size_t)snprintf(out + w, cap - w, "%s%s", w ? ", " : "", DAY[d]);
        if (e == f.n) return true;
        at = e + 1;
        if (at == f.n) return false;            /* a list ending in a comma */
    }
}

static const char *ordinal(int n) {
    if (n % 100 >= 11 && n % 100 <= 13) return "th";
    return n % 10 == 1 ? "st" : n % 10 == 2 ? "nd" : n % 10 == 3 ? "rd" : "th";
}

static bool words(const char *s, size_t n, char *buf, size_t cap) {
    static const struct { const char *word, *is; } AT[] = {
        { "@hourly", "at minute 0 of every hour" }, { "@daily", "at 00:00 every day" },
        { "@midnight", "at 00:00 every day" }, { "@weekly", "at 00:00 on Sun" },
        { "@monthly", "at 00:00 on day 1 of every month" }, { "@yearly", "at 00:00 on day 1 of month 1" },
        { "@annually", "at 00:00 on day 1 of month 1" }, { "@reboot", "at startup" },
    };
    if (n > 0 && s[0] == '@') {                                 /* SW-6 */
        for (size_t i = 0; i < sizeof AT / sizeof AT[0]; i++)
            if (strlen(AT[i].word) == n && memcmp(AT[i].word, s, n) == 0)
                return (size_t)snprintf(buf, cap, "%s", AT[i].is) < cap;
        return false;
    }
    struct fld f[5];
    size_t at = 0;
    for (int k = 0; k < 5; k++) {                               /* five fields, one space between */
        size_t e = at;
        while (e < n && s[e] != ' ') e++;
        if (e == at || (k < 4) != (e < n)) return false;
        f[k] = (struct fld){ s + at, e - at };
        at = e + 1;
    }
    int m, h, d, st;
    if (!star(f[3])) return false;                              /* no form names a month */
    if (step(f[0], 60, &st))                                    /* SW-1 */
        return star(f[1]) && star(f[2]) && star(f[4]) && (size_t)snprintf(buf, cap, "every %d minutes", st) < cap;
    if (!num(f[0].s, f[0].n, 0, 59, &m)) return false;
    if (step(f[1], 24, &st))                                    /* SW-2 */
        return star(f[2]) && star(f[4]) &&
               (size_t)snprintf(buf, cap, "at minute %d of every %d%s hour", m, st, ordinal(st)) < cap;
    if (!num(f[1].s, f[1].n, 0, 23, &h)) return false;
    if (star(f[2]) && star(f[4]))                               /* SW-3 */
        return (size_t)snprintf(buf, cap, "at %02d:%02d every day", h, m) < cap;
    if (star(f[2])) {                                           /* SW-4 */
        char days[64];
        return weekdays(f[4], days, sizeof days) && (size_t)snprintf(buf, cap, "at %02d:%02d on %s", h, m, days) < cap;
    }
    if (star(f[4]) && num(f[2].s, f[2].n, 1, 31, &d))           /* SW-5 */
        return (size_t)snprintf(buf, cap, "at %02d:%02d on day %d of every month", h, m, d) < cap;
    return false;
}

bool inwords_cron(const char *schedule, size_t n, char *out, size_t cap) {
    char buf[160];
    if (schedule == NULL || out == NULL || !words(schedule, n, buf, sizeof buf)) return false;
    return (size_t)snprintf(out, cap, "%s (by cron's clock)", buf) < cap;
}
