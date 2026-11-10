/*
 *  belay hook claude-code EVENT: the Claude Code adapter, and the only
 *  place that knows Claude Code (NOTES/watch-structure.md section 3). It
 *  reads the hook's JSON from standard input, maps the event to the
 *  operations of `belay watch`, and writes the hook's JSON reply.
 *
 *  Its exit status is 0 whatever happens: a hook that fails must not stop a
 *  tool call or a session. What went wrong is a line, never silence.
 *
 *  Facts about Claude Code used here were probed on 2.1.322 (2026-11-10):
 *    - SessionStart has `source`; "startup" is a fresh session.
 *    - PreToolUse and PostToolUse carry the same `tool_use_id`; a subagent's
 *      carry the parent's `session_id` and an `agent_id`.
 *    - PostToolBatch lists every call of its batch in `tool_calls`; a call
 *      the harness blocked gets nothing else.
 *    - a call the user denies or interrupts fires only its PreToolUse.
 *    - UserPromptSubmit also fires when a background command ends, with a
 *      prompt that begins "<task-notification>", and while a call is open.
 */
#define _GNU_SOURCE
#include "cli.h"
#include "cli_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "belay/error.h"
#include "belay/json.h"
#include "watch/ledger.h"
#include "watch/run.h"
#include "watch/watch_cmd.h"

#define RED "\xf0\x9f\x94\xb4"
#define INPUT_MAX ((size_t)256 << 20)

/* ---- the hook's input: the top level of one JSON object ---- */

struct hin {
    char session[WATCH_ID_MAX + 1], call[WATCH_ID_MAX + 1], agent[WATCH_ID_MAX + 1], source[32], command[64];
    char cwd[PATH_MAX];
    bool notification;          /* the prompt begins "<task-notification>" */
    struct wsb calls;           /* tool_calls[].tool_use_id, separated by a space */
};

static const char *ws(const char *p, const char *e) {
    while (p < e && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

/* A JSON string at p (its opening quote) decoded into buf, at most cap - 1
 * bytes kept; the byte after its closing quote, or NULL when it is not one.
 * \uXXXX is kept as '?': no id or path belay reads here has one. */
static const char *string(const char *p, const char *e, char *buf, size_t cap) {
    if (p >= e || *p != '"') return NULL;
    size_t w = 0;
    for (p++; p < e && *p != '"'; p++) {
        char c = *p;
        if ((unsigned char)c < 0x20) return NULL;
        if (c == '\\') {
            if (++p >= e) return NULL;
            switch (*p) {
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'u':
                if (e - p < 5) return NULL;
                p += 4;
                c = '?';
                break;
            case '"': case '\\': case '/': c = *p; break;
            default: return NULL;
            }
        }
        if (buf != NULL && w + 1 < cap) buf[w++] = c;
    }
    if (p >= e) return NULL;
    if (buf != NULL && cap > 0) buf[w] = '\0';
    return p + 1;
}

/* The byte after the JSON value at p, whatever it is and however deep; NULL
 * when it is not one. No recursion: brackets are counted. */
static const char *skip(const char *p, const char *e) {
    p = ws(p, e);
    if (p >= e) return NULL;
    if (*p == '"') return string(p, e, NULL, 0);
    if (*p != '{' && *p != '[') {
        const char *q = p;
        while (q < e && *q != ',' && *q != '}' && *q != ']' && *q != ' ' && *q != '\n' && *q != '\t' && *q != '\r') q++;
        return q > p ? q : NULL;
    }
    size_t depth = 0;
    while (p < e) {
        if (*p == '"') {
            if ((p = string(p, e, NULL, 0)) == NULL) return NULL;
            continue;
        }
        if (*p == '{' || *p == '[') depth++;
        else if ((*p == '}' || *p == ']') && --depth == 0) return p + 1;
        p++;
    }
    return NULL;
}

/* The members of the object at p: fn(ctx, key, value start) for each. The
 * byte after the object, or NULL. */
typedef void (*member_fn)(void *ctx, const char *key, const char *val, const char *e);
static const char *object(const char *p, const char *e, member_fn fn, void *ctx) {
    p = ws(p, e);
    if (p >= e || *p != '{') return NULL;
    p = ws(p + 1, e);
    if (p < e && *p == '}') return p + 1;
    for (;;) {
        char key[64];
        if ((p = string(ws(p, e), e, key, sizeof key)) == NULL) return NULL;
        p = ws(p, e);
        if (p >= e || *p != ':') return NULL;
        const char *val = ws(p + 1, e);
        fn(ctx, key, val, e);
        if ((p = skip(val, e)) == NULL) return NULL;
        p = ws(p, e);
        if (p < e && *p == ',') { p++; continue; }
        return p < e && *p == '}' ? p + 1 : NULL;
    }
}

static void call_member(void *ctx, const char *key, const char *val, const char *e) {
    struct hin *h = ctx;
    char id[WATCH_ID_MAX + 2];
    if (strcmp(key, "tool_use_id") == 0 && string(val, e, id, sizeof id) != NULL && ledger_id_valid(id))
        wsb_f(&h->calls, "%s%s", h->calls.n ? " " : "", id);
}

static void top_member(void *ctx, const char *key, const char *val, const char *e) {
    struct hin *h = ctx;
    char prompt[32];
    if (strcmp(key, "session_id") == 0) string(val, e, h->session, sizeof h->session);
    else if (strcmp(key, "tool_use_id") == 0) string(val, e, h->call, sizeof h->call);
    else if (strcmp(key, "agent_id") == 0) string(val, e, h->agent, sizeof h->agent);
    else if (strcmp(key, "source") == 0) string(val, e, h->source, sizeof h->source);
    else if (strcmp(key, "command_name") == 0) string(val, e, h->command, sizeof h->command);
    else if (strcmp(key, "cwd") == 0) string(val, e, h->cwd, sizeof h->cwd);
    else if (strcmp(key, "prompt") == 0 && string(val, e, prompt, sizeof prompt) != NULL)
        h->notification = strncmp(prompt, "<task-notification>", 19) == 0;
    else if (strcmp(key, "tool_calls") == 0 && val < e && *val == '[') {
        const char *p = ws(val + 1, e);
        while (p != NULL && p < e && *p != ']') {
            const char *q = *p == '{' ? object(p, e, call_member, h) : skip(p, e);
            p = q != NULL ? ws(q, e) : NULL;
            if (p != NULL && p < e && *p == ',') p = ws(p + 1, e);
        }
    }
}

int hook_claude_parse(const char *buf, size_t len, struct hook_claude_in *out) {
    static struct hin h;
    memset(&h, 0, sizeof h);
    memset(out, 0, sizeof *out);
    const char *end = object(buf, buf + len, top_member, &h);
    if (end == NULL || h.calls.bad) {
        free(h.calls.p);
        return -1;
    }
    snprintf(out->session, sizeof out->session, "%s", h.session);
    snprintf(out->call, sizeof out->call, "%s", h.call);
    snprintf(out->agent, sizeof out->agent, "%s", h.agent);
    snprintf(out->source, sizeof out->source, "%s", h.source);
    snprintf(out->command, sizeof out->command, "%s", h.command);
    snprintf(out->cwd, sizeof out->cwd, "%s", h.cwd);
    out->notification = h.notification;
    out->calls = h.calls.p;         /* the caller frees it */
    return 0;
}

/* ---- the reply ---- */

static void reply_message(FILE *out, const char *lines) {
    size_t n = strlen(lines);
    while (n > 0 && lines[n - 1] == '\n') n--;
    if (n == 0) return;
    char *esc = malloc(6 * n + 1);
    if (esc == NULL || belay_json_escape(esc, 6 * n + 1, lines, n) == -1) {
        belay_err_clear();
        fputs("{\"systemMessage\":\"belay: " RED " could not record: out of memory\"}\n", out);
    } else {
        fprintf(out, "{\"systemMessage\":\"%s\"}\n", esc);
    }
    free(esc);
}

static void reply_block(FILE *out, const char *text) {
    const size_t n = strlen(text);
    char *esc = malloc(6 * n + 1);
    if (esc != NULL && belay_json_escape(esc, 6 * n + 1, text, n) == 0)
        fprintf(out, "{\"decision\":\"block\",\"reason\":\"%s\",\"hookSpecificOutput\":{\"hookEventName\":"
                     "\"UserPromptExpansion\",\"suppressOriginalPrompt\":true}}\n", esc);
    belay_err_clear();
    free(esc);
}

/* ---- the daily prune (state-retention-watch WR-10, WR-12) ---- */

/* The record's directory for housekeeping files, opened without a lock; -1
 * when there is no record. */
static int watch_dir(const char *scope) {
    struct scope sc;
    struct state st;
    st.dir_fd = st.cp_fd = st.lock_fd = -1;
    int fd = -1;
    if (scope_resolve(scope, &sc) == 0 && state_open(&sc, false, &st, NULL) == 0 && st.dir_fd != -1)
        fd = openat(st.dir_fd, "watch", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    state_close(&st);
    belay_err_clear();
    return fd;
}

/* What the last prune said when it failed, as a line; then forgotten. */
static void prune_said(int dfd, struct wsb *lines) {
    const int fd = openat(dfd, "prune.log", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd == -1) return;
    char buf[400];
    const ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    unlinkat(dfd, "prune.log", 0);
    if (n <= 0) return;
    buf[n] = '\0';
    buf[strcspn(buf, "\n")] = '\0';
    char *esc = receipt_escaped(buf, strlen(buf));
    wsb_f(lines, "belay: " RED " the last prune failed: %s\n", esc != NULL ? esc : "");
    free(esc);
}

/* Once a day at most: `belay prune --keep-days 7 --watch-only`, detached. */
static void prune_daily(const char *scope, int dfd) {
    struct stat fs;
    const time_t now = time(NULL);
    if (fstatat(dfd, "pruned", &fs, AT_SYMLINK_NOFOLLOW) == 0 && now - fs.st_mtime < 86400) return;
    const int stamp = openat(dfd, "pruned", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (stamp == -1) return;
    futimens(stamp, NULL);
    close(stamp);
    fflush(NULL);
    const pid_t pid = fork();
    if (pid != 0) {
        if (pid > 0) waitpid(pid, NULL, 0);     /* the child below, which leaves at once */
        return;
    }
    if (fork() != 0) _exit(0);                  /* the grandchild is no one's to wait for */
    setsid();
    const int log = openat(dfd, "prune.log", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    const int null = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (log == -1 || null == -1) _exit(0);
    dup2(null, 0);
    dup2(null, 1);
    dup2(null, 2);
    FILE *sink = fdopen(null, "w"), *errs = fdopen(log, "w");
    if (sink == NULL || errs == NULL) _exit(0);
    char *argv[] = { "belay", "prune", "--scope", (char *)scope, "--keep-days", "7", "--watch-only", NULL };
    const int rc = cli_main(7, argv, sink, errs);
    if (rc != 0 && ftell(errs) == 0) fprintf(errs, "belay: prune exited %d\n", rc);
    fflush(errs);
    if (rc == 0) unlinkat(dfd, "prune.log", 0);
    _exit(0);
}

/* ---- /belay:receipt ---- */

/* `code --reuse-window FILE`, waited for a few seconds. true when it ran and exited 0. */
static bool open_in_editor(const char *file) {
    fflush(NULL);
    const pid_t pid = fork();
    if (pid == -1) return false;
    if (pid == 0) {
        const int null = open("/dev/null", O_RDWR);
        if (null != -1) { dup2(null, 0); dup2(null, 1); dup2(null, 2); }
        execlp("code", "code", "--reuse-window", file, (char *)NULL);
        _exit(127);
    }
    for (int i = 0; i < 100; i++) {
        int status;
        const pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (r == -1) return false;
        nanosleep(&(struct timespec){ 0, 100 * 1000000L }, NULL);
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return false;
}

static void receipt_event(const char *scope, FILE *out) {
    struct wsb text = { 0 }, r = { 0 };
    size_t n_steps = 0;
    char file[PATH_MAX + 120];
    const char *entry = getenv("CLAUDE_CODE_ENTRYPOINT");
    if (watch_receipt(scope, &text, &n_steps) == -1 || text.bad) {
        belay_err_clear();
        wsb_f(&r, "belay could not read its record of this directory.");
    } else if (n_steps == 0) {
        wsb_f(&r, "belay has no receipt for this directory yet: nothing has changed in it.");
    } else if (entry != NULL && strcmp(entry, "claude-vscode") == 0 &&
               watch_receipt_file(scope, &text, file, sizeof file) == 0 && open_in_editor(file)) {
        wsb_f(&r, "belay's full receipt is open in an editor tab: %s", file);
    } else {
        belay_err_clear();
        size_t lines = 0;
        const char *p = text.p;
        while (*p != '\0' && lines < 400) {
            const char *nl = strchr(p, '\n');
            const size_t n = nl != NULL ? (size_t)(nl - p) + 1 : strlen(p);
            wsb_f(&r, "%.*s", (int)n, p);
            p += n;
            lines++;
        }
        if (*p != '\0') wsb_f(&r, "... the rest: belay watch receipt --scope .\n");
    }
    if (!r.bad && r.p != NULL) reply_block(out, r.p);
    free(text.p);
    free(r.p);
}

/* ---- the events ---- */

static char *read_all(FILE *in, size_t *len) {
    size_t cap = 65536, n = 0;
    char *buf = malloc(cap);
    while (buf != NULL) {
        const size_t k = fread(buf + n, 1, cap - n, in);
        n += k;
        if (k == 0) break;
        if (n == cap) {
            if (cap >= INPUT_MAX) { free(buf); return NULL; }
            char *q = realloc(buf, cap * 2);
            if (q == NULL) { free(buf); return NULL; }
            buf = q;
            cap *= 2;
        }
    }
    *len = n;
    return buf;
}

int hook_claude(const char *event, const char *scope_arg, FILE *in, FILE *out) {
    static const char *const EVENTS[] = { "start", "pre", "post", "batch", "prompt", "stop", "subagent-stop", "end", "receipt" };
    bool known = false;
    for (size_t i = 0; i < sizeof EVENTS / sizeof EVENTS[0]; i++) known |= strcmp(event, EVENTS[i]) == 0;
    if (!known) return 0;
    size_t len = 0;
    char *buf = read_all(in, &len);
    static struct hook_claude_in h;
    if (buf == NULL || hook_claude_parse(buf, len, &h) == -1) {
        free(buf);
        reply_message(out, "belay: " RED " could not record: the hook's input could not be read");
        return 0;
    }
    free(buf);
    const char *env = getenv("CLAUDE_PROJECT_DIR");
    const char *scope = scope_arg != NULL ? scope_arg : env != NULL && env[0] == '/' ? env : h.cwd;
    struct wsb lines = { 0 };
    if (!strcmp(event, "receipt")) {
        if (strcmp(h.command, "belay:receipt") == 0) receipt_event(scope, out);    /* this command and no other */
        goto done;
    }
    if (!ledger_id_valid(h.session) || scope[0] == '\0') {
        reply_message(out, "belay: " RED " could not record: the hook's input names no session or directory");
        goto done;
    }
    /* too wide a directory is said at a session's start, and nowhere else (TL-14) */
    struct scope sc;
    if (scope_resolve(scope, &sc) == 0 && watch_too_wide(sc.path)) {
        if (!strcmp(event, "start")) {
            char *shown = flag_shown(sc.path, strlen(sc.path));
            wsb_f(&lines, "belay: " RED " not watching %s: too wide\n", shown != NULL ? shown : "this directory");
            free(shown);
            reply_message(out, lines.bad || lines.p == NULL ? "" : lines.p);
        }
        goto done;
    }
    belay_err_clear();
    struct wreq q = { .scope = scope, .session = h.session, .agent = "", .deadline_s = WATCH_DEADLINE_S,
                      .words = { "tool call", "this turn", " \xc2\xb7 full receipt: /belay:receipt" } };
    const bool call = ledger_id_valid(h.call), agent = ledger_id_valid(h.agent);
    if (agent) q.agent = h.agent;
    if (!strcmp(event, "start")) {
        q.first_ok = strcmp(h.source, "startup") == 0;
        q.ops[q.n_ops++] = (struct wop){ WOP_STEP, NULL, WSTEP_PLAIN };
    } else if (!strcmp(event, "pre")) {
        q.ops[q.n_ops++] = (struct wop){ WOP_STEP, call ? h.call : NULL, call ? WSTEP_BEGIN : WSTEP_PLAIN };
    } else if (!strcmp(event, "post")) {
        q.ops[q.n_ops++] = (struct wop){ WOP_STEP, call ? h.call : NULL, call ? WSTEP_FINISH : WSTEP_PLAIN };
    } else if (!strcmp(event, "batch")) {
        if (h.calls == NULL || h.calls[0] == '\0') goto done;
        q.ops[q.n_ops++] = (struct wop){ WOP_CLOSE, h.calls, 0 };
    } else if (!strcmp(event, "prompt")) {
        /* closes nothing: a message typed while a call runs fires this with the call open */
        q.ops[q.n_ops++] = (struct wop){ WOP_STEP, NULL, WSTEP_PLAIN };
        if (!h.notification) q.ops[q.n_ops++] = (struct wop){ WOP_MARK, "prompt", 0 };
    } else if (!strcmp(event, "stop")) {
        /* a denied or interrupted call fires nothing of its own: the main thread's are closed here */
        q.ops[q.n_ops++] = (struct wop){ WOP_CLOSE_AGENT, "", 0 };
        q.ops[q.n_ops++] = (struct wop){ WOP_STEP, NULL, WSTEP_PLAIN };
        q.ops[q.n_ops++] = (struct wop){ WOP_SUMMARY, "prompt", 0 };
    } else if (!strcmp(event, "subagent-stop")) {
        if (agent) q.ops[q.n_ops++] = (struct wop){ WOP_CLOSE_AGENT, h.agent, 0 };
        q.ops[q.n_ops++] = (struct wop){ WOP_STEP, NULL, WSTEP_PLAIN };
    } else {    /* end */
        q.ops[q.n_ops++] = (struct wop){ WOP_CLOSE_SESSION, NULL, 0 };
        q.ops[q.n_ops++] = (struct wop){ WOP_STEP, NULL, WSTEP_PLAIN };
        q.ops[q.n_ops++] = (struct wop){ WOP_FORGET, NULL, 0 };
    }
    watch_run(&q, &lines);
    if (!strcmp(event, "stop")) {
        const int dfd = watch_dir(scope);
        if (dfd != -1) {
            prune_said(dfd, &lines);
            prune_daily(scope, dfd);
            close(dfd);
        }
    }
    if (strcmp(event, "end") != 0)              /* at a session's end nothing can be shown */
        reply_message(out, lines.bad ? "belay: " RED " could not record: out of memory" : lines.p != NULL ? lines.p : "");
done:
    free(lines.p);
    free(h.calls);
    return 0;
}

int cmd_hook(int argc, char **argv, FILE *out, FILE *err) {
    (void)err;
    /* exit status 0 for any arguments, before anything else is looked at */
    if (argc < 4 || strcmp(argv[2], "claude-code") != 0) return 0;
    const char *scope = NULL;
    for (int i = 4; i + 1 < argc; i++)
        if (!strcmp(argv[i], "--scope")) scope = argv[i + 1];
    hook_claude(argv[3], scope, stdin, out);
    return 0;
}
