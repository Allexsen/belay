#define _GNU_SOURCE
#include "watch/run.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "belay/diff.h"
#include "belay/error.h"
#include "belay/hash.h"
#include "belay/manifest.h"
#include "cli/cli.h"
#include "cli/cli_internal.h"
#include "cli/delta.h"
#include "cli/receipt.h"
#include "cli/state.h"
#include "watch/ledger.h"

#define RED "\xf0\x9f\x94\xb4"
#define NS_PER_DAY (86400LL * 1000000000LL)

void (*watch_stage_hook)(const char *stage) = NULL;
int64_t (*watch_clock)(void) = NULL;
long watch_second_ms = WATCH_SECOND_S * 1000;
bool watch_withhold_go = false;

static int64_t now_ns(void) {
    if (watch_clock != NULL) return watch_clock();
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void hhmm(int64_t ns, char out[6]) {
    const time_t t = (time_t)(ns / 1000000000LL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, 6, "%H:%M", &tm);
}

bool watch_too_wide(const char *resolved) {
    if (strcmp(resolved, "/") == 0) return true;
    const char *home = getenv("HOME");
    char real[PATH_MAX];
    if (home == NULL || home[0] != '/' || realpath(home, real) == NULL) return false;
    const size_t n = strlen(resolved);
    return strncmp(real, resolved, n) == 0 && (real[n] == '\0' || real[n] == '/');
}

/* ---- the pipe between the worker and the supervisor ---- */

/* worker -> supervisor: a tag, a length, the bytes.
 *   S  a stage reached           C  may I commit? (then the worker waits for one byte)
 *   O  the lines                 X  done: the exit status as one byte */
static int msg(int fd, char tag, const char *p, size_t n) {
    char head[5] = { tag, (char)(n >> 24), (char)(n >> 16), (char)(n >> 8), (char)n };
    size_t w = 0;
    while (w < sizeof head) {
        const ssize_t k = write(fd, head + w, sizeof head - w);
        if (k == -1 && errno == EINTR) continue;
        if (k <= 0) return -1;
        w += (size_t)k;
    }
    w = 0;
    while (w < n) {
        const ssize_t k = write(fd, p + w, n - w);
        if (k == -1 && errno == EINTR) continue;
        if (k <= 0) return -1;
        w += (size_t)k;
    }
    return 0;
}

/* ---- the worker ---- */

struct pending {
    char type[8];               /* "step", "mark", "close" */
    struct wstep *step;         /* for a step */
    char *section;              /* its section of the receipt, or NULL */
    size_t section_len;
    char mark[WATCH_ID_MAX + 1];        /* for a mark: its name */
    struct wstate snap;         /* the state after it */
};

struct wctx {
    const struct wreq *q;
    int to_sup, from_sup;
    struct state st;
    struct ledger l;
    int64_t now;
    bool readonly;              /* `belay watch summary`: no lock is held, nothing is written */
    struct pending *pend;       /* WATCH_OPS_MAX of them */
    size_t n_pend;
    size_t written;             /* how many of them are on disk: past the first, the event cannot be undone */
    bool dirty;                 /* the state changed since the last pending line */
    struct wsb out;
    size_t dropped;             /* calls and markers of sessions that ended without saying so (TL-15) */
    const char *stage;
};

static void stage(struct wctx *x, const char *name) {
    x->stage = name;
    msg(x->to_sup, 'S', name, strlen(name));
    if (watch_stage_hook != NULL) watch_stage_hook(name);
}

/* belay_err as text for a line, escaped as the receipt escapes; cleared. */
static void err_text(char *buf, size_t cap) {
    char *e = receipt_escaped(belay_err_msg(), strlen(belay_err_msg()));
    snprintf(buf, cap, "%s", e != NULL ? e : "out of memory");
    free(e);
    belay_err_clear();
}

static struct wcall *open_find(struct wstate *s, const char *id) {
    for (size_t i = 0; i < s->n_open; i++)
        if (strcmp(s->open[i].id, id) == 0) return &s->open[i];
    return NULL;
}

static void open_remove(struct wstate *s, size_t i) {
    memmove(&s->open[i], &s->open[i + 1], (s->n_open - i - 1) * sizeof s->open[0]);
    s->n_open--;
}

/* TM-4: the calls and markers of a session that has fired nothing for a
 * day are dropped: it died. The session firing now is alive, whatever its
 * calls' age: its own are kept, and their day starts again from this event
 * (review of #132, 4: a turn longer than a day lost its marker). */
static void drop_stale(struct wctx *x) {
    struct wstate *s = &x->l.st;
    const char *me = x->q->session;
    for (size_t i = s->n_open; i-- > 0;) {
        if (strcmp(s->open[i].session, me) == 0) {
            if (s->open[i].ns != x->now) { s->open[i].ns = x->now; x->dirty = true; }
        } else if (x->now - s->open[i].ns > NS_PER_DAY) {
            open_remove(s, i);
            x->dropped++;
            x->dirty = true;
        }
    }
    for (size_t i = s->n_marks; i-- > 0;) {
        if (strcmp(s->marks[i].session, me) == 0) {
            if (s->marks[i].seen_ns != x->now) { s->marks[i].seen_ns = x->now; x->dirty = true; }
        } else if (x->now - s->marks[i].seen_ns > NS_PER_DAY) {
            memmove(&s->marks[i], &s->marks[i + 1], (s->n_marks - i - 1) * sizeof s->marks[0]);
            s->n_marks--;
            x->dirty = true;
        }
    }
}

static struct wkill *kill_of(struct wstate *s, const char *session, bool make) {
    for (size_t i = 0; i < s->n_kills; i++)
        if (strcmp(s->kills[i].session, session) == 0) return &s->kills[i];
    if (!make) return NULL;
    if (s->n_kills == W_KILL_MAX) {             /* the oldest goes */
        memmove(&s->kills[0], &s->kills[1], (W_KILL_MAX - 1) * sizeof s->kills[0]);
        s->n_kills--;
    }
    struct wkill *k = &s->kills[s->n_kills++];
    snprintf(k->session, sizeof k->session, "%s", session);
    k->n = 0;
    return k;
}

/* ---- .belay-donttouch as the checkpoint holds it (DT-1) ---- */

enum { DT_NONE, DT_OK, DT_UNREADABLE, DT_TOO_LARGE };

/* The file's stored copy at checkpoint `id`: DT_OK with its bytes
 * (malloc'd), DT_NONE when the checkpoint has no such file, DT_UNREADABLE
 * with `why`. -1 with belay_err when the manifest cannot be read. */
static int donttouch_read(const struct state *st, long id, char **bytes, size_t *len, char *why, size_t cap) {
    struct manifest_file mf;
    struct belay_manifest_reader *r = NULL;
    if (manifest_acquire(st, id, &mf) == -1) return -1;
    if (belay_manifest_open(mf.path, &r) == -1) {
        manifest_release(&mf);
        return -1;
    }
    int rc = DT_NONE;
    const struct belay_manifest_header *h = belay_manifest_header(r);
    for (size_t i = 0; i < h->n_excluded; i++)
        if (h->excluded[i].path_len == 16 && memcmp(h->excluded[i].path, ".belay-donttouch", 16) == 0) {
            snprintf(why, cap, "it is excluded");
            rc = DT_UNREADABLE;
        }
    static struct belay_entry e;
    int got;
    while (rc == DT_NONE && (got = belay_manifest_next(r, &e)) == 1) {
        const int c = memcmp(e.path, ".belay-donttouch", e.path_len < 16 ? e.path_len : 16);
        if (c > 0 || (c == 0 && e.path_len > 16)) {
            /* past it in path order -- unless it is one of its own children, which a file has none of */
            if (!(c == 0 && e.path[16] == '/')) break;
            continue;
        }
        if (c < 0 || e.path_len != 16) continue;
        if (e.type != BELAY_T_REG) {
            snprintf(why, cap, "it is not a regular file");
            rc = DT_UNREADABLE;
        } else if (e.size > DT_FILE_MAX) {      /* DT-4: a limit passed is an invalid file, not an unreadable one */
            snprintf(why, cap, "the file is over %u bytes", DT_FILE_MAX);
            rc = DT_TOO_LARGE;
        } else if (!e.has_stored) {
            snprintf(why, cap, e.writer_open ? "a writer has it open" : "no stored copy");
            rc = DT_UNREADABLE;
        } else {
            char rel[96];
            snprintf(rel, sizeof rel, "store/%.2s/%s", e.stored_hex, e.stored_hex + 2);
            const int fd = openat(st->dir_fd, rel, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
            struct stat fs;
            char *p = NULL;
            size_t n = 0;
            if (fd != -1 && fstat(fd, &fs) == 0 && S_ISREG(fs.st_mode) && fs.st_size <= (off_t)DT_FILE_MAX &&
                (p = malloc((size_t)fs.st_size + 1)) != NULL) {
                while (n < (size_t)fs.st_size) {
                    const ssize_t k = read(fd, p + n, (size_t)fs.st_size - n);
                    if (k == -1 && errno == EINTR) continue;
                    if (k <= 0) break;
                    n += (size_t)k;
                }
            }
            if (fd != -1) close(fd);
            struct belay_sha256 c2;
            uint8_t d[BELAY_SHA256_DIGEST_LEN];
            char hex[65] = "";
            if (p != NULL) {
                belay_sha256_init(&c2);
                belay_sha256_update(&c2, p, n);
                belay_sha256_final(&c2, d);
                belay_hex_encode(hex, d, sizeof d);
            }
            if (p == NULL || strcmp(hex, e.stored_hex) != 0) {
                free(p);
                snprintf(why, cap, "its stored copy cannot be read");
                rc = DT_UNREADABLE;
            } else if (memchr(p, '\0', n) != NULL) {
                free(p);
                snprintf(why, cap, "it holds a NUL byte");
                rc = DT_UNREADABLE;
            } else {
                p[n] = '\0';
                *bytes = p;
                *len = n;
                rc = DT_OK;
            }
        }
        break;
    }
    belay_manifest_close(r);
    manifest_release(&mf);
    belay_err_clear();
    return rc;
}

/* The list in force by the ledger's state into *list; false when there is
 * none (or its file is gone, which is said by the caller). */
static bool list_in_force(const struct ledger *l, struct dtlist *list) {
    memset(list, 0, sizeof *list);
    if (l->st.list[0] == '\0') return false;
    size_t n;
    char *b = ledger_list_read(l, l->st.list, &n), why[96];
    if (b == NULL) return false;
    const bool ok = dtlist_parse(b, n, list, why, sizeof why) == 0;
    free(b);
    return ok;
}

/* DT-5 and DT-6 for the checkpoint a step has just written: *fresh is the
 * new list where a valid file differs from the list in force (both apply
 * in this step), or the list in force could not be read back; the state takes the new list, or keeps the old one and
 * the trouble. 0, or -1 with belay_err. */
static int donttouch_step(struct wctx *x, long id, struct wstep *s, bool have_old, struct dtlist *fresh, bool *have_fresh) {
    char *bytes = NULL, why[96] = "", trouble[200] = "";
    size_t len = 0;
    struct wstate *st = &x->l.st;
    *have_fresh = false;
    const int r = donttouch_read(&x->st, id, &bytes, &len, why, sizeof why);
    if (r == -1) return -1;
    const char *tail = st->list[0] != '\0' ? "the previous list stays in force" : "no list is in force";
    if (r == DT_NONE) {
        st->list[0] = '\0';
    } else if (r == DT_TOO_LARGE) {
        snprintf(trouble, sizeof trouble, ".belay-donttouch: %s; %s", why, tail);
    } else if (r == DT_UNREADABLE) {
        snprintf(trouble, sizeof trouble, "could not read .belay-donttouch: %s; %s", why, tail);
    } else {
        char hex[65], bad[96];
        if (dtlist_parse(bytes, len, fresh, bad, sizeof bad) == -1) {
            snprintf(trouble, sizeof trouble, ".belay-donttouch: %s; %s", bad, tail);
        } else if (ledger_list_write(&x->l, bytes, len, hex) == -1) {
            dtlist_free(fresh);
            free(bytes);
            return -1;
        } else if (strcmp(hex, st->list) != 0 || !have_old) {       /* new, or its kept copy was gone */
            *have_fresh = true;
            snprintf(st->list, sizeof st->list, "%s", hex);
        } else {
            dtlist_free(fresh);
        }
    }
    free(bytes);
    /* said in the step where it arises or changes; while it lasts, in every summary */
    if (trouble[0] != '\0' && strcmp(trouble, st->list_trouble) != 0 && wstep_add_trouble(s, "%s", trouble) == -1) {
        belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
        return -1;
    }
    snprintf(st->list_trouble, sizeof st->list_trouble, "%s", trouble);
    return 0;
}

/* ---- a step ---- */

static int add_flag(struct wstep *s, const struct wflag *f) {
    struct wflag *q = realloc(s->flags, (s->n_flags + 1) * sizeof *q);
    if (q == NULL) return -1;
    s->flags = q;
    s->flags[s->n_flags++] = *f;
    return 0;
}

static int nomem(void) {
    belay_err_set(BELAY_ERR_NOMEM, 0, "out of memory");
    return -1;
}

/* The diff at `d` read once: every record flagged, noted or counted into
 * the step; a change of what is read flagged too (CV-1). */
static int match_diff(struct wctx *x, const char *d, struct flagctx *fx, struct wstep *s) {
    FILE *in = fopen(d, "r");
    if (in == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", d);
        return -1;
    }
    (void)x;
    char *line = NULL, top[256] = "", best[256] = "";
    size_t cap = 0, run = 0, best_n = 0, unflagged = 0;
    ssize_t n;
    int rc = 0;
    static char path[4096];
    while (rc == 0 && (n = getline(&line, &cap, in)) > 0) {
        struct jval v;
        if (jsonr_parse(line, (size_t)n, &v) == -1 || v.t != J_OBJ) {
            if (belay_err_code() == BELAY_OK) belay_err_set(BELAY_ERR_CORRUPT, 0, "%s is not a diff belay wrote", d);
            rc = -1;
            break;
        }
        struct wflag f = { 0 };
        if (jget(&v, "belay_diff") != NULL) {
            /* CV-1: the two manifests' excluded sets differ */
            const struct jval *b = jget(&v, "before_excluded"), *a = jget(&v, "after_excluded");
            for (int side = 0; side < 2 && rc == 0; side++) {
                const struct jval *mine = side ? a : b, *other = side ? b : a;
                for (size_t i = 0; mine != NULL && mine->t == J_ARR && i < mine->n && rc == 0; i++) {
                    const char *p = jstr(&mine->kids[i], "path");
                    bool both = false;
                    for (size_t j = 0; other != NULL && other->t == J_ARR && j < other->n; j++)
                        both |= strcmp(jstr(&other->kids[j], "path"), p) == 0;
                    if (both || other == NULL || other->t != J_ARR) continue;
                    char *shown = flag_shown(p, strlen(p));
                    const size_t tc = (shown != NULL ? strlen(shown) : 0) + 48;
                    f.text = shown != NULL ? malloc(tc) : NULL;
                    if (f.text == NULL) { free(shown); rc = nomem(); break; }
                    snprintf(f.text, tc, "%s %s (coverage)", shown, side ? "is no longer read" : "is read again");
                    free(shown);
                    f.kind = WK_COVERAGE;
                    f.note = false;
                    if (add_flag(s, &f) == -1) { free(f.text); rc = nomem(); }
                }
            }
        } else if (jget(&v, "event") != NULL) {
            const int r = flag_event(&v, &f);
            if (r == -1 || (r == 1 && add_flag(s, &f) == -1)) { free(r == 1 ? f.text : NULL); rc = nomem(); }
        } else if (jget(&v, "outcome") != NULL) {
            size_t len;
            const char *word;
            if (receipt_record_path(&v, path, sizeof path, &len) == -1) {
                belay_err_set(BELAY_ERR_CORRUPT, 0, "%s holds a record with no path", d);
                rc = -1;
            } else {
                s->changes++;
                const int r = flag_record(fx, &v, path, len, &f, &word);
                if (r == -1 || (r == 1 && add_flag(s, &f) == -1)) {
                    free(r == 1 ? f.text : NULL);
                    rc = nomem();
                } else if (r == 0) {
                    s->counts[watch_outcome_index(word)]++;
                    if (unflagged < 3) {                    /* named when three or fewer (LN-5) */
                        char *shown = flag_shown(path, len);
                        const size_t nc = (shown != NULL ? strlen(shown) : 0) + 24;
                        char *name = shown != NULL ? malloc(nc) : NULL;
                        if (name == NULL) { free(shown); rc = nomem(); }
                        else {
                            snprintf(name, nc, "%s %s", shown, word);
                            free(shown);
                            s->names[s->n_names++] = name;
                        }
                    }
                    unflagged++;
                    /* entries under one top-level directory arrive together (LN-6) */
                    const char *sl = memchr(path, '/', len);
                    const size_t tl = sl != NULL ? (size_t)(sl - path) : 0;
                    if (tl > 0 && tl < sizeof top && strlen(top) == tl && memcmp(top, path, tl) == 0) {
                        run++;
                    } else {
                        run = tl > 0 && tl < sizeof top ? 1 : 0;
                        memcpy(top, path, tl < sizeof top ? tl : 0);
                        top[tl < sizeof top ? tl : 0] = '\0';
                    }
                    if (run > best_n) { best_n = run; memcpy(best, top, sizeof best); }
                }
            }
        }
        jsonr_free(&v);
    }
    if (rc == 0 && ferror(in)) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", d);
        rc = -1;
    }
    free(line);
    fclose(in);
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

/* The step's section of the receipt: a heading, then `belay diff --all`. */
static int render_section(struct wctx *x, const struct wstep *s, const char *a, const char *b, const char *d,
                          char **text, size_t *len) {
    struct cli_modes m = { 0 };
    FILE *in = fopen(d, "r"), *mem = open_memstream(text, len);
    int rc = -1;
    if (in == NULL || mem == NULL) {
        belay_err_set(BELAY_ERR_IO, errno, "cannot read %s", d);
        goto out;
    }
    if (belay_manifest_open(a, &m.side[0].r) == -1 || belay_manifest_open(b, &m.side[1].r) == -1) goto out;
    for (int sd = 0; sd < 2; sd++) m.side[sd].got = belay_manifest_next(m.side[sd].r, &m.side[sd].e);
    char when[32], la[48], lb[48];
    const time_t t = (time_t)(s->ns / 1000000000LL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%SZ", &tm);
    fprintf(mem, "==== %s  session %s  ", when, s->session);
    if (s->n_calls == 0) fputs("outside tool calls", mem);
    for (size_t i = 0; i < s->n_calls; i++) fprintf(mem, "%s%s", i ? ", " : "call ", s->calls[i]);
    fputs("\n", mem);
    snprintf(la, sizeof la, "checkpoint %ld", s->from);
    snprintf(lb, sizeof lb, "checkpoint %ld", s->to);
    const struct receipt_opts ro = { la, lb, true, cli_mode_of, &m, x->st.scope.docker[0] ? NULL : cli_classify,
                                     x->st.scope.path, NULL };
    if (receipt_render(in, mem, &ro) == -1) goto out;
    cli_not_compared(mem, belay_manifest_header(m.side[0].r), belay_manifest_header(m.side[1].r), NULL);
    fputs("\n", mem);
    rc = 0;
out:
    if (in != NULL) fclose(in);
    if (mem != NULL && fclose(mem) != 0 && rc == 0) rc = nomem();
    belay_manifest_close(m.side[0].r);
    belay_manifest_close(m.side[1].r);
    if (rc == -1) { free(*text); *text = NULL; }
    return rc;
}

static struct pending *pend(struct wctx *x, const char *type) {
    struct pending *p = &x->pend[x->n_pend++];
    memset(p, 0, sizeof *p);
    snprintf(p->type, sizeof p->type, "%s", type);
    return p;
}

static int do_step(struct wctx *x, const struct wop *op) {
    const struct wreq *q = x->q;
    struct wstate *st = &x->l.st;
    struct wstep *s = calloc(1, sizeof *s);
    if (s == NULL) return nomem();
    struct pending *p = pend(x, "step");
    p->step = s;
    snprintf(s->session, sizeof s->session, "%s", q->session);
    s->ns = x->now;
    /* the calls open at any time in the interval: those open now */
    if (st->n_open > 0 && (s->calls = calloc(st->n_open, sizeof *s->calls)) == NULL) return nomem();
    for (size_t i = 0; i < st->n_open; i++) {
        if ((s->calls[i] = strdup(st->open[i].id)) == NULL) return nomem();
        s->n_calls++;
    }
    if (x->l.unfinished && wstep_add_trouble(s, "the previous step did not finish") == -1) return nomem();
    if (x->dropped > 0 &&
        wstep_add_trouble(s, "%zu call%s of a session that ended without saying so %s closed", x->dropped,
                          x->dropped == 1 ? "" : "s", x->dropped == 1 ? "was" : "were") == -1)
        return nomem();
    x->dropped = 0;
    /* an attempt, so a step that does not finish is known to have begun */
    if (ledger_append(&x->l, "attempt", q->session, x->now, "", NULL) == -1) return -1;

    stage(x, "capturing");
    /* the cursor's checkpoint, looked for before the capture: once it is
     * gone its id is free, and the capture below could take it */
    const long cursor = st->cursor;
    bool have = false;
    if (cursor != 0) {
        struct checkpoint *list = NULL;
        size_t n = 0;
        if (state_list(&x->st, &list, &n) == -1) return -1;
        for (size_t i = 0; i < n; i++)
            if (list[i].id == cursor) have = list[i].created_ns == st->cursor_ns;
        free(list);
        have = have && state_check_manifest(&x->st, cursor) == 0;
        belay_err_clear();
    }
    const struct capture_req req = { "mark", true, false, 50, 0, false, true };
    struct checkpoint c;
    if (state_capture(&x->st, &req, &c) == -1) return -1;
    s->to = c.id;
    char at[6];
    hhmm(x->now, at);
    struct dtlist old = { 0 }, fresh = { 0 };
    bool have_old = list_in_force(&x->l, &old), have_fresh = false;
    int rc = -1;
    struct manifest_file mf_a = { .temporary = false }, mf_b = { .temporary = false };
    if (donttouch_step(x, c.id, s, have_old, &fresh, &have_fresh) == -1) goto out;
    if (!have) {
        /* nothing to diff against: a first step, or the record was interrupted */
        const int tr = cursor != 0 ? wstep_add_trouble(s, "the record was interrupted: resuming from checkpoint %ld (%s)", c.id, at)
                     : x->l.unreadable ? wstep_add_trouble(s, "the record was interrupted: nothing before %s is accounted for", at)
                     : q->first_ok ? 0
                     : wstep_add_trouble(s, "recording starts here: nothing before %s is accounted for", at);
        if (tr == -1) { nomem(); goto out; }
    } else {
        s->from = cursor;
        char d[PATH_MAX + 200];
        snprintf(d, sizeof d, "%s/checkpoints/%ld/diff-from-%ld.ndjson", x->st.dir, c.id, cursor);
        if (manifest_acquire(&x->st, cursor, &mf_a) == -1 || manifest_acquire(&x->st, c.id, &mf_b) == -1) goto out;
        const struct belay_diff_opts dopts = { .store_dir = x->st.store };
        struct belay_diff_stats ds;
        if (belay_diff(mf_a.path, mf_b.path, d, &dopts, &ds) == -1) goto out;
        stage(x, "matching");
        struct cli_modes m = { 0 };
        struct flagctx fx = { .lists = { have_old ? &old : NULL, have_fresh ? &fresh : NULL }, .mode = cli_mode_of, .mode_ctx = &m };
        int mr = -1;
        if (belay_manifest_open(mf_a.path, &m.side[0].r) == 0 && belay_manifest_open(mf_b.path, &m.side[1].r) == 0) {
            for (int sd = 0; sd < 2; sd++) m.side[sd].got = belay_manifest_next(m.side[sd].r, &m.side[sd].e);
            mr = match_diff(x, d, &fx, s);
        }
        belay_manifest_close(m.side[0].r);
        belay_manifest_close(m.side[1].r);
        flagctx_free(&fx);
        if (mr == -1) goto out;
        if (s->changes > 0 || s->n_flags > 0) {
            stage(x, "rendering");
            if (render_section(x, s, mf_a.path, mf_b.path, d, &p->section, &p->section_len) == -1) goto out;
        }
    }
    /* the step is made: what it leaves in the state */
    st->cursor = c.id;
    st->cursor_ns = c.created_ns;
    struct wkill *k = kill_of(st, q->session, false);
    if (k != NULL) k->n = 0;
    if (op->how == WSTEP_FINISH) {
        for (size_t i = 0; i < st->n_open; i++)
            if (strcmp(st->open[i].id, op->arg) == 0) { open_remove(st, i); break; }
    } else if (op->how == WSTEP_BEGIN && open_find(st, op->arg) == NULL) {
        if (st->n_open == W_OPEN_MAX) {         /* the oldest is closed, and said at the next step */
            open_remove(st, 0);
            x->dropped++;
        }
        struct wcall *call = &st->open[st->n_open++];
        memset(call, 0, sizeof *call);
        snprintf(call->id, sizeof call->id, "%s", op->arg);
        snprintf(call->session, sizeof call->session, "%s", q->session);
        snprintf(call->agent, sizeof call->agent, "%s", q->agent != NULL ? q->agent : "");
        call->ns = x->now;
    }
    p->snap = *st;
    x->dirty = false;
    rc = 0;
out:
    manifest_release(&mf_a);
    manifest_release(&mf_b);
    if (have_old) dtlist_free(&old);
    if (have_fresh) dtlist_free(&fresh);
    return rc;
}

/* ---- a summary ---- */

struct span { struct wstep *steps; size_t n, cap; bool bad; };

static int span_line(void *ctx, const struct jval *line, const char *type) {
    struct span *sp = ctx;
    const bool step = strcmp(type, "step") == 0, trouble = strcmp(type, "trouble") == 0;
    if (!step && !trouble) return 0;
    if (sp->n == sp->cap) {
        const size_t c = sp->cap ? sp->cap * 2 : 32;
        struct wstep *q = realloc(sp->steps, c * sizeof *q);
        if (q == NULL) { sp->bad = true; return 1; }
        sp->steps = q;
        sp->cap = c;
    }
    struct wstep *s = &sp->steps[sp->n];
    if (step) {
        if (ledger_step(line, s) == 0) sp->n++;
        return 0;
    }
    memset(s, 0, sizeof *s);
    snprintf(s->session, sizeof s->session, "%.*s", WATCH_ID_MAX, jstr(line, "session"));
    if (wstep_add_trouble(s, "%s", jstr(line, "trouble")) == -1) { sp->bad = true; return 1; }
    sp->n++;
    return 0;
}

/* What the newest checkpoint did not read, for CV-2 and CV-3: excludes from
 * the manifest's header; mounts and unreadable directories from its entries. */
static int coverage(struct wctx *x, struct wsb *told, char **standing, size_t max, size_t *n_standing) {
    const long id = x->l.st.cursor;
    if (id == 0 || state_checkpoint_exists(&x->st, id) != 1) { belay_err_clear(); return 0; }
    struct manifest_file mf;
    struct belay_manifest_reader *r = NULL;
    if (manifest_acquire(&x->st, id, &mf) == -1) return -1;
    if (belay_manifest_open(mf.path, &r) == -1) { manifest_release(&mf); return -1; }
    struct dtlist list;
    const bool have = list_in_force(&x->l, &list);
    const struct belay_manifest_header *h = belay_manifest_header(r);
    size_t named = 0;
    #define NOT_READ(p, pl, why) do { \
        char *shown_ = flag_shown((p), (pl)); \
        if (shown_ != NULL) { \
            if (named < 8) wsb_f(told, "%s%s (%s)", named ? ", " : "", shown_, (why)); \
            named++; \
            if (flag_covers(have ? &list : NULL, (p), (pl)) && *n_standing < max) { \
                const size_t c_ = strlen(shown_) + 96; \
                if ((standing[*n_standing] = malloc(c_)) != NULL) \
                    snprintf(standing[(*n_standing)++], c_, "not reading %s (%s), where the list would flag a change", shown_, (why)); \
            } \
            free(shown_); \
        } \
    } while (0)
    for (size_t i = 0; i < h->n_excluded; i++)
        if (h->excluded[i].reason == BELAY_EXCLUDE_USER) NOT_READ(h->excluded[i].path, h->excluded[i].path_len, "excluded");
    static struct belay_entry e;
    while (belay_manifest_next(r, &e) == 1) {
        if (e.is_mount && e.path_len > 0) NOT_READ(e.path, e.path_len, "a mount");
        else if (e.unreadable && e.type == BELAY_T_DIR) NOT_READ(e.path, e.path_len, "unreadable");
    }
    #undef NOT_READ
    if (named > 8) wsb_f(told, ", and %zu more", named - 8);
    if (have) dtlist_free(&list);
    belay_manifest_close(r);
    manifest_release(&mf);
    belay_err_clear();
    return 0;
}

static int do_summary(struct wctx *x, const char *name) {
    const struct wstate *st = &x->l.st;
    const struct wmark *mk = NULL;
    for (size_t i = 0; i < st->n_marks; i++)
        if (strcmp(st->marks[i].session, x->q->session) == 0 && strcmp(st->marks[i].name, name) == 0) mk = &st->marks[i];
    char (*days)[11];
    size_t n_days;
    if (ledger_days(&x->l, &days, &n_days) == -1) return -1;
    struct span sp = { 0 };
    const char *gone = NULL;
    char gone_day[11];
    int rc = 0;
    bool from_found = false;
    for (size_t i = 0; i < n_days && rc == 0; i++) {
        /* with no marker of that name: the newest day, whole */
        const int c = mk != NULL ? strcmp(days[i], mk->day) : (i + 1 == n_days ? 0 : -1);
        if (c < 0) continue;
        if (c == 0) from_found = true;
        rc = ledger_read(&x->l, days[i], c == 0 && mk != NULL ? mk->off : 0, span_line, &sp);
    }
    if (mk != NULL && !from_found) {            /* SM-5: its day was pruned */
        memcpy(gone_day, mk->day, 11);
        gone = gone_day;
    }
    free(days);
    if (rc == 1 || sp.bad) rc = nomem();
    char *standing[8] = { 0 };
    size_t n_standing = 0;
    struct wsb told = { 0 };
    if (rc == 0 && st->list_trouble[0] != '\0' && (standing[n_standing++] = strdup(st->list_trouble)) == NULL) rc = nomem();
    if (rc == 0) rc = coverage(x, &told, standing, 7, &n_standing);
    if (rc == 0) {
        /* CV-2: once per session, what is not read, in a line that is not flagged */
        bool was_told = false;
        for (size_t i = 0; i < st->n_told; i++) was_told |= strcmp(st->told[i], x->q->session) == 0;
        if (!was_told && told.n > 0 && !told.bad) {
            wsb_f(&x->out, "belay: not reading: %s\n", told.p);
            struct wstate *w = &x->l.st;
            if (w->n_told == W_TOLD_MAX) {
                memmove(w->told[0], w->told[1], (W_TOLD_MAX - 1) * sizeof w->told[0]);
                w->n_told--;
            }
            snprintf(w->told[w->n_told++], WATCH_ID_MAX + 1, "%s", x->q->session);
            if (!x->readonly && ledger_append(&x->l, "close", x->q->session, x->now, "", NULL) == -1) rc = -1;
        }
    }
    if (rc == 0) lines_summary(&x->out, sp.steps, sp.n, x->q->session, (const char *const *)standing, gone, &x->q->words);
    for (size_t i = 0; i < sp.n; i++) wstep_free(&sp.steps[i]);
    free(sp.steps);
    for (size_t i = 0; i < n_standing; i++) free(standing[i]);
    free(told.p);
    return rc;
}

int watch_summary(const struct wreq *q, const char *name, struct wsb *out) {
    static struct wctx x;
    memset(&x, 0, sizeof x);
    x.q = q;
    x.readonly = true;
    x.now = now_ns();
    x.st.dir_fd = x.st.cp_fd = x.st.lock_fd = -1;
    x.l.dfd = -1;
    struct scope sc;
    int rc = -1;
    if (scope_resolve(q->scope, &sc) == 0 && state_open(&sc, false, &x.st, NULL) == 0 && ledger_open(&x.st, false, &x.l) == 0)
        rc = do_summary(&x, name);
    if (rc == 0) wsb_f(out, "%s", x.out.p != NULL ? x.out.p : "");
    out->bad |= x.out.bad;
    free(x.out.p);
    ledger_close(&x.l);
    state_close(&x.st);
    return rc;
}

/* ---- the worker's run ---- */

static int commit(struct wctx *x) {
    struct ledger *l = &x->l;
    for (size_t i = 0; i < x->n_pend; i++) {
        struct pending *p = &x->pend[i];
        if (p->step != NULL) {
            if (p->section != NULL && ledger_section_write(l, p->step, p->section, p->section_len) == -1) return -1;
            l->st = p->snap;
            if (ledger_append_step(l, p->step) == -1) return -1;
            x->written = i + 1;
            continue;
        }
        if (p->mark[0] != '\0') {
            /* the marker points at its own line: where the next line of its day starts now */
            char day[11], name[32];
            struct stat fs;
            ledger_day(l, x->now, day);
            snprintf(name, sizeof name, "ledger-%s.ndjson", day);
            const long off = fstatat(l->dfd, name, &fs, AT_SYMLINK_NOFOLLOW) == 0 ? (long)fs.st_size : 0;
            for (size_t j = i; j < x->n_pend; j++) {    /* in its own snapshot and every later one */
                struct wstate *s = &x->pend[j].snap;
                for (size_t m = 0; m < s->n_marks; m++)
                    if (strcmp(s->marks[m].session, x->q->session) == 0 && strcmp(s->marks[m].name, p->mark) == 0 &&
                        s->marks[m].ns == x->now) {
                        memcpy(s->marks[m].day, day, 11);
                        s->marks[m].off = off;
                    }
            }
        }
        l->st = p->snap;
        char body[160] = "";
        if (p->mark[0] != '\0') snprintf(body, sizeof body, "\"name\":\"%s\",", p->mark);
        if (ledger_append(l, p->type, x->q->session, x->now, body, NULL) == -1) return -1;
        x->written = i + 1;
    }
    return 0;
}

static int work(struct wctx *x) {
    const struct wreq *q = x->q;
    bool summary = false;
    for (size_t i = 0; i < q->n_ops; i++) summary |= q->ops[i].op == WOP_SUMMARY;
    drop_stale(x);
    for (size_t i = 0; i < q->n_ops; i++) {
        const struct wop *op = &q->ops[i];
        struct wstate *st = &x->l.st;
        switch (op->op) {
        case WOP_STEP:
            if (do_step(x, op) == -1) return -1;
            break;
        case WOP_CLOSE:                         /* ids, separated by a space: one that is not open is nothing */
            for (const char *id = op->arg; *id != '\0';) {
                const size_t n = strcspn(id, " ");
                for (size_t k = 0; k < st->n_open; k++)
                    if (strlen(st->open[k].id) == n && memcmp(st->open[k].id, id, n) == 0) {
                        open_remove(st, k);
                        x->dirty = true;
                        break;
                    }
                id += n + (id[n] == ' ');
            }
            break;
        case WOP_CLOSE_SESSION:
        case WOP_CLOSE_AGENT:
            for (size_t k = st->n_open; k-- > 0;)
                if (strcmp(st->open[k].session, q->session) == 0 &&
                    (op->op == WOP_CLOSE_SESSION || strcmp(st->open[k].agent, op->arg) == 0)) {
                    open_remove(st, k);
                    x->dirty = true;
                }
            break;
        case WOP_MARK: {
            size_t at = st->n_marks;
            for (size_t k = 0; k < st->n_marks; k++)
                if (strcmp(st->marks[k].session, q->session) == 0 && strcmp(st->marks[k].name, op->arg) == 0) at = k;
            if (at == st->n_marks) {
                if (st->n_marks == W_MARK_MAX) {
                    memmove(&st->marks[0], &st->marks[1], (W_MARK_MAX - 1) * sizeof st->marks[0]);
                    st->n_marks--;
                    at--;
                }
                st->n_marks++;
            }
            struct wmark *m = &st->marks[at];
            memset(m, 0, sizeof *m);
            snprintf(m->session, sizeof m->session, "%s", q->session);
            snprintf(m->name, sizeof m->name, "%s", op->arg);
            memcpy(m->day, "1970-01-01", 11);           /* set when its line is written */
            m->ns = x->now;
            m->seen_ns = x->now;
            struct pending *p = pend(x, "mark");
            snprintf(p->mark, sizeof p->mark, "%s", op->arg);
            p->snap = *st;
            x->dirty = false;
            break;
        }
        case WOP_FORGET:
            for (size_t k = st->n_marks; k-- > 0;)
                if (strcmp(st->marks[k].session, q->session) == 0) {
                    memmove(&st->marks[k], &st->marks[k + 1], (st->n_marks - k - 1) * sizeof st->marks[0]);
                    st->n_marks--;
                    x->dirty = true;
                }
            for (size_t k = st->n_kills; k-- > 0;)
                if (strcmp(st->kills[k].session, q->session) == 0) {
                    memmove(&st->kills[k], &st->kills[k + 1], (st->n_kills - k - 1) * sizeof st->kills[0]);
                    st->n_kills--;
                    x->dirty = true;
                }
            for (size_t k = st->n_told; k-- > 0;)
                if (strcmp(st->told[k], q->session) == 0) {
                    memmove(st->told[k], st->told[k + 1], (st->n_told - k - 1) * sizeof st->told[0]);
                    st->n_told--;
                    x->dirty = true;
                }
            break;
        case WOP_SUMMARY:
            break;
        }
    }
    if (x->dirty) {                             /* closes and the like after the last line: a line of their own */
        struct pending *p = pend(x, "close");
        p->snap = x->l.st;
    }
    if (x->n_pend > 0) {
        /* commit is asked for, not announced: "go" or a kill, never both (TM-2) */
        if (watch_stage_hook != NULL) watch_stage_hook("committing");
        char go = 0;
        if (msg(x->to_sup, 'C', "", 0) == -1) _exit(4);
        ssize_t k;
        while ((k = read(x->from_sup, &go, 1)) == -1 && errno == EINTR) {}
        if (k != 1 || go != 'g') _exit(4);      /* the supervisor is gone or said no: nothing is written */
        stage(x, "writing the record");
        if (commit(x) == -1) return -1;
    }
    for (size_t i = 0; i < x->n_pend; i++)
        if (x->pend[i].step != NULL) lines_step(&x->out, x->pend[i].step);
    for (size_t i = 0; summary && i < q->n_ops; i++)
        if (q->ops[i].op == WOP_SUMMARY && do_summary(x, q->ops[i].arg) == -1) return -1;
    return 0;
}

/* The worker: everything that touches belay's state. Never returns. */
static void worker(const struct wreq *q, int to_sup, int from_sup) {
    static struct wctx x;
    memset(&x, 0, sizeof x);
    x.q = q;
    x.to_sup = to_sup;
    x.from_sup = from_sup;
    x.now = now_ns();
    x.st.dir_fd = x.st.cp_fd = x.st.lock_fd = -1;
    x.l.dfd = -1;
    int status = 0;
    char why[1024];
    stage(&x, "waiting for the lock");
    struct scope sc;
    if (scope_resolve(q->scope, &sc) == -1) {
        err_text(why, sizeof why);
        wsb_f(&x.out, "belay: " RED " could not record: %s\n", why);
        status = 3;
        goto done;
    }
    if (watch_too_wide(sc.path)) {
        char *shown = flag_shown(sc.path, strlen(sc.path));
        wsb_f(&x.out, "belay: " RED " not watching %s: too wide\n", shown != NULL ? shown : "it");
        free(shown);
        status = 3;
        goto done;
    }
    /* back-off (TM-3): read without the lock, and nothing is written */
    bool captures = false;
    for (size_t i = 0; i < q->n_ops; i++) captures |= q->ops[i].op == WOP_STEP;
    if (captures) {
        struct state ro;
        ro.dir_fd = ro.cp_fd = ro.lock_fd = -1;
        if (state_open(&sc, false, &ro, NULL) == 0) {
            struct ledger rl;
            if (ledger_open(&ro, false, &rl) == 0) {
                const struct wkill *k = kill_of(&rl.st, q->session, false);
                if (k != NULL && k->n >= WATCH_BACKOFF) {
                    wsb_f(&x.out, "belay: " RED " not recording: capturing this directory takes longer than %ld s\n", q->deadline_s);
                    status = 4;
                }
                ledger_close(&rl);
            }
        }
        state_close(&ro);
        belay_err_clear();
        if (status != 0) goto done;
    }
    if (state_open(&sc, true, &x.st, NULL) == -1 || ledger_open(&x.st, true, &x.l) == -1) {
        const bool refused = belay_err_code() == BELAY_ERR_INVALID;
        err_text(why, sizeof why);
        wsb_f(&x.out, "belay: " RED " could not record: %s\n", why);
        status = refused ? 3 : 4;
        goto done;
    }
    x.pend = calloc(WATCH_OPS_MAX + 1, sizeof *x.pend);
    static struct wstate found;
    found = x.l.st;
    if (x.pend == NULL || work(&x) == -1) {
        if (x.pend == NULL) nomem();
        err_text(why, sizeof why);
        struct wsb body = { 0 };
        char text[1100];
        x.out.n = 0;
        if (x.out.p != NULL) x.out.p[0] = '\0';
        if (x.written == 0) {
            /* nothing of it is on disk: the event leaves the state as it found it */
            x.l.st = found;
            snprintf(text, sizeof text, "could not record: %s", why);
        } else {
            /* A line of it is on disk, and the cursor with it. What is written
             * stands: the state is that line's, the step is shown, and it is
             * not said to be lost -- or the next step would record it again
             * (review of #132, 1). */
            x.l.st = x.pend[x.written - 1].snap;
            for (size_t i = 0; i < x.written; i++)
                if (x.pend[i].step != NULL) lines_step(&x.out, x.pend[i].step);
            snprintf(text, sizeof text, "this step is recorded; what came after it failed: %s", why);
        }
        /* kept in the record too, so the summary repeats it */
        wsb_f(&body, "\"trouble\":");
        wsb_json(&body, text);
        wsb_f(&body, ",");
        if (!body.bad && x.l.dfd != -1) ledger_append(&x.l, "trouble", q->session, x.now, body.p, NULL);
        free(body.p);
        belay_err_clear();
        wsb_f(&x.out, "belay: " RED " %s\n", text);
        status = 4;
    }
done:
    if (x.out.bad) {
        static const char oom[] = "belay: " RED " could not record: out of memory\n";
        msg(to_sup, 'O', oom, sizeof oom - 1);
        status = 4;
    } else {
        msg(to_sup, 'O', x.out.p != NULL ? x.out.p : "", x.out.n);
    }
    const char st = (char)status;
    msg(to_sup, 'X', &st, 1);
    ledger_close(&x.l);
    state_close(&x.st);
    _exit(0);
}

/* ---- the supervisor ---- */

/* What the worker has sent so far. */
struct sup { char stage[40]; bool commit, done; int status; struct wsb lines; char *in; size_t have, cap; bool bad; };

/* Reads what there is. 1: more may come; 0: the pipe is closed (or memory ran out). */
static int drain(int fd, struct sup *s) {
    char tmp[4096];
    const ssize_t k = read(fd, tmp, sizeof tmp);
    if (k == -1 && (errno == EINTR || errno == EAGAIN)) return 1;
    if (k <= 0) return 0;
    if (s->have + (size_t)k > s->cap) {
        const size_t c = (s->have + (size_t)k) * 2;
        char *q = realloc(s->in, c);
        if (q == NULL) { s->bad = true; return 0; }
        s->in = q;
        s->cap = c;
    }
    memcpy(s->in + s->have, tmp, (size_t)k);
    s->have += (size_t)k;
    size_t at = 0;
    while (s->have - at >= 5) {
        const unsigned char *h = (const unsigned char *)s->in + at;
        const size_t n = ((size_t)h[1] << 24) | ((size_t)h[2] << 16) | ((size_t)h[3] << 8) | (size_t)h[4];
        if (s->have - at - 5 < n) break;
        const char *body = s->in + at + 5;
        if (h[0] == 'S') snprintf(s->stage, sizeof s->stage, "%.*s", (int)n, body);
        else if (h[0] == 'C') s->commit = true;
        else if (h[0] == 'O') wsb_f(&s->lines, "%.*s", (int)n, body);
        else if (h[0] == 'X' && n == 1) { s->done = true; s->status = body[0]; }
        at += 5 + n;
    }
    memmove(s->in, s->in + at, s->have - at);
    s->have -= at;
    return 1;
}

static long ms_since(const struct timespec *t0) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)((t.tv_sec - t0->tv_sec) * 1000 + (t.tv_nsec - t0->tv_nsec) / 1000000);
}

/* After a kill the lock is free: the kill is put in the record, with the
 * session's count for the back-off, so the summary repeats it. Never waits
 * long for the lock, and says nothing when it cannot. */
static void record_kill(const struct wreq *q, const char *text) {
    struct scope sc;
    struct state st;
    struct ledger l;
    st.dir_fd = st.cp_fd = st.lock_fd = -1;
    state_lock_wait_ms = 500;
    if (scope_resolve(q->scope, &sc) == 0 && state_open(&sc, true, &st, NULL) == 0) {
        if (ledger_open(&st, true, &l) == 0) {
            kill_of(&l.st, q->session, true)->n++;
            struct wsb body = { 0 };
            wsb_f(&body, "\"trouble\":");
            wsb_json(&body, text);
            wsb_f(&body, ",");
            if (!body.bad) ledger_append(&l, "trouble", q->session, now_ns(), body.p, NULL);
            free(body.p);
            ledger_close(&l);
        }
    }
    state_close(&st);
    state_lock_wait_ms = -1;
    belay_err_clear();
}

int watch_run(const struct wreq *q, struct wsb *out) {
    int up[2], down[2];
    if (pipe(up) == -1) {
        wsb_f(out, "belay: " RED " could not record: %s\n", strerror(errno));
        return 4;
    }
    if (pipe(down) == -1) {
        close(up[0]);
        close(up[1]);
        wsb_f(out, "belay: " RED " could not record: %s\n", strerror(errno));
        return 4;
    }
    fflush(NULL);
    const pid_t pid = fork();
    if (pid == -1) {
        wsb_f(out, "belay: " RED " could not record: %s\n", strerror(errno));
        close(up[0]); close(up[1]); close(down[0]); close(down[1]);
        return 4;
    }
    if (pid == 0) {
        close(up[0]);
        close(down[1]);
        signal(SIGPIPE, SIG_IGN);
        worker(q, up[1], down[0]);
        _exit(4);
    }
    close(up[1]);
    close(down[0]);
    void (*old)(int) = signal(SIGPIPE, SIG_IGN);
    struct sup s;
    memset(&s, 0, sizeof s);
    snprintf(s.stage, sizeof s.stage, "starting");
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    const long deadline = q->deadline_s * 1000, second = deadline + watch_second_ms;
    bool went = false, open = true;
    int rc = 4;
    for (;;) {
        if (s.commit && !went && !watch_withhold_go) {
            went = true;
            if (write(down[1], "g", 1) != 1) open = false;
        }
        if (s.done || !open) break;
        const long left = (went ? second : deadline) - ms_since(&t0);
        if (left <= 0) break;
        struct pollfd pf = { up[0], POLLIN, 0 };
        const int pr = poll(&pf, 1, left > 1000 ? 1000 : (int)left);
        if (pr > 0) open = drain(up[0], &s) == 1;
    }
    if (s.done) {
        /* the worker's own lines, whatever they say */
        wsb_f(out, "%s", s.lines.p != NULL ? s.lines.p : "");
        rc = s.status;
        waitpid(pid, NULL, 0);
    } else if (!open) {
        waitpid(pid, NULL, 0);
        wsb_f(out, "belay: " RED " belay stopped unexpectedly while %s\n", s.stage);
    } else if (went) {
        /* told to go, and no word by the second limit: not killed, a write may be half done */
        wsb_f(out, "belay: " RED " could not confirm the record\n");
    } else {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        char text[160];
        if (strcmp(s.stage, "waiting for the lock") == 0 || strcmp(s.stage, "starting") == 0) {
            snprintf(text, sizeof text, "could not record: another belay holds this directory's lock");
        } else {
            snprintf(text, sizeof text, "could not record in %ld s: %s", q->deadline_s, s.stage);
            record_kill(q, text);
        }
        wsb_f(out, "belay: " RED " %s\n", text);
    }
    out->bad |= s.lines.bad;
    free(s.lines.p);
    free(s.in);
    close(up[0]);
    close(down[1]);
    signal(SIGPIPE, old);
    return rc;
}
