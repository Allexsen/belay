#define _GNU_SOURCE
#include "watch/flag.h"

#include <stdlib.h>
#include <string.h>

#include "belay/json.h"
#include "util/pattern.h"

static const char *const KIND[WK_COUNT] = {
    "don't-touch", "git hooks and config", "agent rules", "privilege", "loads on its own", "package source",
    "CI", "credentials", "replaced by a symlink", "history", "could not be read", "coverage",
};
const char *wkind_name(enum wkind k) { return (unsigned)k < WK_COUNT ? KIND[k] : "?"; }

/* The built-in list: test/expect/watch-v1.md, BR-1 on, in the pin's order.
 * A test reads the pin and compares it with this table, row by row. */
const struct brow flag_rows[] = {
    { WK_GIT, "git hook", "**/.git/hooks", BR_FILE, NULL },
    { WK_GIT, "git hook", "**/.git/hooks/*", BR_FILE, "**/*.sample" },
    { WK_GIT, "git hook", "**/.git/modules/**/hooks/*", BR_FILE, "**/*.sample" },
    { WK_GIT, "git config", "**/.git/config", BR_FILE | BR_NEWDIR | BR_NOTE_MOD, NULL },
    { WK_GIT, "git config", "**/.git/config.worktree", BR_FILE | BR_NEWDIR | BR_NOTE_MOD, NULL },
    { WK_GIT, "git config", "**/.git/worktrees/*/config.worktree", BR_FILE | BR_NEWDIR | BR_NOTE_MOD, NULL },
    { WK_GIT, "git config", "**/.git/modules/**/config", BR_FILE | BR_NEWDIR | BR_NOTE_MOD, NULL },
    { WK_GIT, "git exclude list", "**/.git/info/exclude", BR_FILE | BR_NEWDIR, NULL },
    { WK_GIT, "git attributes", "**/.git/info/attributes", BR_FILE | BR_NEWDIR, NULL },
    { WK_GIT, "git submodules", "**/.gitmodules", BR_FILE, NULL },
    { WK_GIT, "git hook manager", "**/.husky", BR_DEPS, NULL },
    { WK_GIT, "git hook manager", "**/.pre-commit-config.yaml", BR_FILE | BR_DEPS, NULL },
    { WK_GIT, "git hook manager", "**/lefthook.yml", BR_FILE | BR_DEPS, NULL },
    { WK_GIT, "git hook manager", "**/lefthook.yaml", BR_FILE | BR_DEPS, NULL },
    { WK_GIT, "git hook manager", "**/.lefthook.yml", BR_FILE | BR_DEPS, NULL },
    { WK_GIT, "git hook manager", "**/.lefthook.yaml", BR_FILE | BR_DEPS, NULL },
    { WK_GIT, "git config", "**/.gitconfig", BR_FILE | BR_DEPS, NULL },
    { WK_GIT, "git config", "**/.config/git", BR_DEPS, NULL },
    { WK_AGENT, "agent permissions", ".claude/settings.local.json", BR_FILE | BR_NOTE, NULL },
    { WK_AGENT, "agent rules", ".claude/*", 0, ".claude/worktrees", ".claude/.cc-writes" },
    { WK_AGENT, "agent rules", "**/CLAUDE.md", BR_FILE | BR_DEPS, NULL },
    { WK_AGENT, "agent rules", "**/CLAUDE.local.md", BR_FILE | BR_DEPS, NULL },
    { WK_AGENT, "agent rules", "**/AGENTS.md", BR_FILE | BR_DEPS, NULL },
    { WK_AGENT, "agent rules", ".mcp.json", BR_FILE, NULL },
    { WK_AGENT, "agent rules", ".cursor", 0, NULL },
    { WK_AGENT, "agent rules", ".cursorrules", BR_FILE, NULL },
    { WK_AGENT, "agent rules", ".github/copilot-instructions.md", BR_FILE, NULL },
    { WK_AGENT, "agent rules", ".claude.json", BR_FILE, NULL },
    { WK_AGENT, "search config", ".ripgreprc", BR_FILE, NULL },
    { WK_LOAD, "runs on entering the directory", "**/.envrc", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "editor runs it", "**/.vscode/tasks.json", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "editor settings", "**/.vscode/settings.json", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "editor runs it", "**/.vscode/launch.json", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "container setup", "**/.devcontainer", BR_DEPS, NULL },
    { WK_LOAD, "container setup", "**/.devcontainer.json", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "runs at every Python start", "**/site-packages/*.pth", BR_FILE, NULL },
    { WK_LOAD, "runs at every Python start", "**/site-packages/sitecustomize.py", BR_FILE, NULL },
    { WK_LOAD, "runs at every install", "**/.pnpmfile.cjs", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "shell startup file", "**/.bashrc", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "shell startup file", "**/.bash_profile", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "shell startup file", "**/.zshrc", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "shell startup file", "**/.zprofile", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "shell startup file", "**/.profile", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "shell startup file", "**/.zshenv", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "shell startup file", "**/.zlogin", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "shell startup file", "**/.zlogout", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "shell startup file", "**/.bash_login", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "shell startup file", "**/.bash_aliases", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "shell startup file", "**/.bash_logout", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "runs at every Node start", "**/.pnp.cjs", BR_FILE | BR_DEPS | BR_NOTE_MOD, NULL },
    { WK_LOAD, "runs at every Node start", "**/.pnp.loader.mjs", BR_FILE | BR_DEPS | BR_NOTE_MOD, NULL },
    { WK_LOAD, "bun config", "**/bunfig.toml", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "bun config", "**/.bunfig.toml", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "build setup", "**/.bazelrc", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "type checker config", "**/pyrightconfig.json", BR_FILE | BR_DEPS, NULL },
    { WK_LOAD, "build setup", "**/.mvn", BR_DEPS, NULL },
    { WK_LOAD, "runs at every yarn start", "**/.yarn/releases", BR_DEPS, NULL },
    { WK_LOAD, "runs at every yarn start", "**/.yarn/plugins", BR_DEPS, NULL },
    { WK_PKG, "package source", "**/.npmrc", BR_FILE | BR_DEPS, NULL },
    { WK_PKG, "package source", "**/.yarnrc", BR_FILE | BR_DEPS, NULL },
    { WK_PKG, "package source", "**/.yarnrc.yml", BR_FILE | BR_DEPS, NULL },
    { WK_PKG, "package source", "**/pip.conf", BR_FILE | BR_DEPS, NULL },
    { WK_PKG, "package source", "**/.cargo/config.toml", BR_FILE | BR_DEPS, NULL },
    { WK_PKG, "package source", "**/.cargo/config", BR_FILE | BR_DEPS, NULL },
    { WK_PKG, "build tool source", "**/.bazelversion", BR_FILE | BR_DEPS, NULL },
    { WK_PKG, "build tool source", "**/.bazeliskrc", BR_FILE | BR_DEPS, NULL },
    { WK_PKG, "build tool source", "**/gradle-wrapper.properties", BR_FILE | BR_DEPS, NULL },
    { WK_PKG, "build tool source", "**/maven-wrapper.properties", BR_FILE | BR_DEPS, NULL },
    { WK_CI, "CI", ".github/workflows", 0, NULL },
    { WK_CI, "CI", ".github/actions", 0, NULL },
    { WK_CI, "CI", ".github/CODEOWNERS", BR_FILE, NULL },
    { WK_CI, "CI", "CODEOWNERS", BR_FILE, NULL },
    { WK_CI, "CI", "docs/CODEOWNERS", BR_FILE, NULL },
    { WK_CI, "CI", ".github/dependabot.yml", BR_FILE, NULL },
    { WK_CI, "CI", ".github/dependabot.yaml", BR_FILE, NULL },
    { WK_CI, "CI", ".gitlab-ci.yml", BR_FILE, NULL },
    { WK_CI, "CI", ".circleci", 0, NULL },
    { WK_CI, "CI", "Jenkinsfile", BR_FILE, NULL },
    { WK_CI, "CI", "azure-pipelines.yml", BR_FILE, NULL },
    { WK_CI, "CI", ".travis.yml", BR_FILE, NULL },
    { WK_CRED, "credentials", "**/.env", BR_FILE | BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/.env.*", BR_FILE | BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/*.pem", BR_FILE | BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/*.key", BR_FILE | BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/*.p12", BR_FILE | BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/*.pfx", BR_FILE | BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/id_rsa*", BR_FILE | BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/id_ed25519*", BR_FILE | BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/id_ecdsa*", BR_FILE | BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/.ssh", BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/.aws", BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/.netrc", BR_FILE | BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/.git-credentials", BR_FILE | BR_DEPS, NULL },
    { WK_CRED, "credentials", "**/.kube/config", BR_FILE | BR_DEPS, NULL },
};
const size_t flag_n_rows = sizeof flag_rows / sizeof flag_rows[0];

/* ---- .belay-donttouch ---- */

void dtlist_free(struct dtlist *l) {
    for (size_t i = 0; i < l->n; i++) free(l->pat[i]);
    free(l->pat);
    free(l->len);
    memset(l, 0, sizeof *l);
}

int dtlist_parse(const char *buf, size_t len, struct dtlist *out, char *why, size_t cap) {
    memset(out, 0, sizeof *out);
    if (len > DT_FILE_MAX) {
        snprintf(why, cap, "the file is over %u bytes", DT_FILE_MAX);
        return -1;
    }
    size_t line = 0, i = 0;
    while (i < len) {
        const char *nl = memchr(buf + i, '\n', len - i);
        const size_t e = nl != NULL ? (size_t)(nl - buf) : len;
        const char *p = buf + i;
        const size_t n = e - i;
        i = e + 1;
        line++;
        if (n == 0 || p[0] == '#') continue;
        /* DT-4's limits on one pattern are limits passed, not a line that is no pattern */
        if (n > PATTERN_MAX || (pattern_valid(p, n) && pattern_globstars(p, n) > DT_GLOBSTARS)) {
            if (n > PATTERN_MAX) snprintf(why, cap, "a pattern of more than %u bytes (line %zu)", PATTERN_MAX, line);
            else snprintf(why, cap, "more than %u `**` in a pattern (line %zu)", DT_GLOBSTARS, line);
            dtlist_free(out);
            return -1;
        }
        bool ok = pattern_valid(p, n) && p[0] != '!';
        for (size_t k = 0; ok && k < n; k++) {
            const unsigned char c = (unsigned char)p[k];
            if (c < 0x20 || c == 0x7f || c == '?' || c == '[' || c == '\\') ok = false;
        }
        if (!ok) {
            snprintf(why, cap, "line %zu is not a pattern", line);
            dtlist_free(out);
            return -1;
        }
        if (out->n == DT_PATTERNS_MAX) {
            snprintf(why, cap, "more than %u patterns", DT_PATTERNS_MAX);
            dtlist_free(out);
            return -1;
        }
        char **q = realloc(out->pat, (out->n + 1) * sizeof *q);
        if (q != NULL) out->pat = q;
        size_t *ql = q != NULL ? realloc(out->len, (out->n + 1) * sizeof *ql) : NULL;
        if (ql != NULL) out->len = ql;
        char *copy = ql != NULL ? malloc(n + 1) : NULL;
        if (copy == NULL) {
            snprintf(why, cap, "out of memory");
            dtlist_free(out);
            return -1;
        }
        memcpy(copy, p, n);
        copy[n] = '\0';
        out->pat[out->n] = copy;
        out->len[out->n++] = n;
    }
    return 0;
}

/* ---- naming ---- */

/* The number of bytes of the UTF-8 character at s (escaped text is valid). */
static size_t chr(const char *s) {
    const unsigned char c = (unsigned char)*s;
    return c < 0x80 ? 1 : c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
}

char *flag_shown(const char *path, size_t len) {
    char *e = receipt_escaped(path, len);
    if (e == NULL) return NULL;
    size_t chars = 0;
    for (const char *p = e; *p != '\0'; p += chr(p)) chars++;
    if (chars <= 80) return e;
    /* 39 characters, the ellipsis, the last 40 */
    const char *head = e, *tail = e;
    for (size_t k = 0; k < 39; k++) head += chr(head);
    for (size_t k = 0; k < chars - 40; k++) tail += chr(tail);
    const size_t hl = (size_t)(head - e), tl = strlen(tail);
    char *out = malloc(hl + 3 + tl + 1);
    if (out != NULL) {
        memcpy(out, e, hl);
        memcpy(out + hl, "\xe2\x80\xa6", 3);
        memcpy(out + hl + 3, tail, tl + 1);
    }
    free(e);
    return out;
}

static const char *word_of(const char *outcome) {
    if (!strcmp(outcome, "added")) return "added";
    if (!strcmp(outcome, "removed")) return "removed";
    if (!strcmp(outcome, "modified")) return "modified";
    if (!strcmp(outcome, "type_changed")) return "type changed";
    if (!strcmp(outcome, "metadata_only")) return "metadata changed";
    return "not compared";
}

static int named(struct wflag *out, enum wkind kind, bool note, const char *path, size_t len, const char *middle,
                 const char *reason) {
    char *shown = flag_shown(path, len);
    if (shown == NULL) return -1;
    const size_t cap = strlen(shown) + strlen(middle) + (reason != NULL ? strlen(reason) : 0) + 8;
    out->text = malloc(cap);
    if (out->text == NULL) {
        free(shown);
        return -1;
    }
    if (reason != NULL) snprintf(out->text, cap, "%s %s (%s)", shown, middle, reason);
    else snprintf(out->text, cap, "%s %s", shown, middle);
    free(shown);
    out->kind = kind;
    out->note = note;
    return 1;
}

/* ---- the lists ---- */

/* The watched directory itself is the entry "."; its path has no component
 * (WD-3), so only a pattern of nothing but `**` matches it. */
static unsigned match(const char *pat, size_t plen, const char *path, size_t len, unsigned sw) {
    if (len == 1 && path[0] == '.') len = 0;
    return pattern_match(pat, plen, path, len, sw);
}

/* BR-L2: at or below a directory of that name; a file of that name is no dependency. */
static bool in_dependency(const char *path, size_t len, bool dir) {
    const unsigned want = PATTERN_ABOVE | (dir ? PATTERN_SELF : 0u);
    return (match("**/node_modules", 15, path, len, PATTERN_DOTS) & want) != 0 ||
           (match("**/site-packages", 16, path, len, PATTERN_DOTS) & want) != 0;
}

static bool is_newdir(const struct flagctx *x, const char *path, size_t len) {
    size_t dl = len;
    while (dl > 0 && path[dl - 1] != '/') dl--;
    if (dl == 0) return false;
    dl--;
    for (size_t i = x->n_newdirs; i-- > 0;)        /* the parent is among the latest: records come in path order */
        if (strlen(x->newdirs[i]) == dl && memcmp(x->newdirs[i], path, dl) == 0) return true;
    return false;
}

bool flag_row_applies(const struct brow *r, const char *path, size_t len, bool dir) {
    const unsigned m = match(r->pattern, strlen(r->pattern), path, len, PATTERN_DOTS | PATTERN_NOCASE);
    if (r->limits & BR_FILE ? !((m & PATTERN_SELF) && !dir) : m == 0) return false;
    if (r->except != NULL && match(r->except, strlen(r->except), path, len, PATTERN_DOTS) != 0) return false;
    if (r->except2 != NULL && match(r->except2, strlen(r->except2), path, len, PATTERN_DOTS) != 0) return false;
    return !((r->limits & BR_DEPS) && in_dependency(path, len, dir));
}

/* The first built-in row that applies to the entry, or NULL. */
static const struct brow *row_of(const struct flagctx *x, const char *path, size_t len, bool dir, bool added) {
    for (size_t i = 0; i < flag_n_rows; i++) {
        const struct brow *r = &flag_rows[i];
        if (!flag_row_applies(r, path, len, dir)) continue;
        if ((r->limits & BR_NEWDIR) && added && is_newdir(x, path, len)) continue;
        return r;
    }
    return NULL;
}

static bool user_match(const struct flagctx *x, const char *path, size_t len) {
    if (len == 16 && memcmp(path, ".belay-donttouch", 16) == 0) return true;
    for (int l = 0; l < 2; l++)
        for (size_t i = 0; x->lists[l] != NULL && i < x->lists[l]->n; i++)
            if (match(x->lists[l]->pat[i], x->lists[l]->len[i], path, len, PATTERN_DOTS) != 0) return true;
    return false;
}

unsigned flag_user_match(const char *pat, size_t plen, const char *path, size_t len) {
    return match(pat, plen, path, len, PATTERN_DOTS);
}

bool flag_path(const struct flagctx *x, const char *path, size_t len, bool dir, enum wkind *kind, const char **reason,
               bool *note) {
    if (user_match(x, path, len)) {
        *kind = WK_DONTTOUCH;
        *reason = "don't-touch";
        *note = false;
        return true;
    }
    const struct brow *r = row_of(x, path, len, dir, false);
    if (r == NULL) return false;
    *kind = r->kind;
    *reason = r->label;
    *note = (r->limits & (BR_NOTE | BR_NOTE_MOD)) != 0;
    return true;
}

int flag_record(struct flagctx *x, const struct jval *r, const char *path, size_t len, struct wflag *out,
                const char **word) {
    const char *outcome = jstr(r, "outcome"), *type = jstr(r, "type");
    const bool dir = strcmp(type, "dir") == 0, added = strcmp(outcome, "added") == 0;
    const bool unknown = strcmp(outcome, "unknown") == 0;
    *word = word_of(outcome);
    out->text = NULL;
    /* an added directory is remembered before its children arrive (BR-L3) */
    if (added && dir) {
        if (x->n_newdirs == x->cap_newdirs) {
            const size_t c = x->cap_newdirs ? x->cap_newdirs * 2 : 64;
            char **q = realloc(x->newdirs, c * sizeof *q);
            if (q == NULL) return -1;
            x->newdirs = q;
            x->cap_newdirs = c;
        }
        if ((x->newdirs[x->n_newdirs] = strndup(path, len)) == NULL) return -1;
        x->n_newdirs++;
    }
    const bool user = user_match(x, path, len);
    const struct brow *row = user ? NULL : row_of(x, path, len, dir, added);
    if (unknown && (user || row != NULL)) {             /* FK-11 */
        const struct jval *u = jget(r, "unknown");
        char reason[160];
        snprintf(reason, sizeof reason, "could not be read: %.120s",
                 u != NULL && u->t == J_ARR && u->n > 0 && u->kids[0].t == J_STR ? u->kids[0].s : "unknown");
        return named(out, WK_UNREAD, false, path, len, *word, reason);
    }
    if (user) return named(out, WK_DONTTOUCH, false, path, len, *word, "don't-touch");
    if (row != NULL && (row->kind == WK_GIT || row->kind == WK_AGENT)) {
        const bool note = (row->limits & BR_NOTE) || ((row->limits & BR_NOTE_MOD) && strcmp(outcome, "modified") == 0);
        return named(out, row->kind, note, path, len, *word, row->label);
    }
    char *priv = receipt_privilege_words(r, path, len, x->mode, x->mode_ctx);        /* FK-4 */
    if (priv != NULL) {
        const int rc = named(out, WK_PRIVILEGE, false, path, len, priv, "privilege");
        free(priv);
        return rc;
    }
    if (row != NULL) {
        const bool note = (row->limits & BR_NOTE) || ((row->limits & BR_NOTE_MOD) && strcmp(outcome, "modified") == 0);
        return named(out, row->kind, note, path, len, *word, row->label);
    }
    /* FK-9: it was not a symlink and is one now */
    if (strcmp(outcome, "type_changed") == 0 && strcmp(type, "lnk") == 0 && strcmp(jstr(r, "type_before"), "lnk") != 0)
        return named(out, WK_SYMLINK, false, path, len, "replaced by a symlink", NULL);
    return 0;
}

int flag_event(const struct jval *e, struct wflag *out) {
    if (strcmp(jstr(e, "event"), "git_history_rewritten") != 0) return 0;
    const char *text = jstr(e, "text");
    /* the event's text, its commit ids cut to seven characters (LN-3) */
    const size_t n = strlen(text);
    char *t = malloc(n + 16), *esc;
    if (t == NULL) return -1;
    size_t w = 0;
    for (size_t i = 0; i < n;) {
        size_t h = 0;
        while (i + h < n && ((text[i + h] >= '0' && text[i + h] <= '9') || (text[i + h] >= 'a' && text[i + h] <= 'f'))) h++;
        const bool id = (h == 40 || h == 64) && (i == 0 || text[i - 1] == ' ');
        const size_t take = id ? 7 : h > 0 ? h : 1;
        memcpy(t + w, text + i, take);
        w += take;
        i += id ? h : take;
    }
    esc = receipt_escaped(t, w);
    free(t);
    if (esc == NULL) return -1;
    const size_t cap = strlen(esc) + 16;
    out->text = malloc(cap);
    if (out->text != NULL) snprintf(out->text, cap, "%s (history)", esc);
    free(esc);
    if (out->text == NULL) return -1;
    out->kind = WK_HISTORY;
    out->note = false;
    return 1;
}

void flagctx_free(struct flagctx *x) {
    for (size_t i = 0; i < x->n_newdirs; i++) free(x->newdirs[i]);
    free(x->newdirs);
    x->newdirs = NULL;
    x->n_newdirs = x->cap_newdirs = 0;
}

bool flag_covers(const struct dtlist *list, const char *path, size_t len) {
    for (size_t i = 0; i < flag_n_rows; i++) {
        const char *p = flag_rows[i].pattern;
        const size_t pl = strlen(p);
        if (pattern_match(p, pl, path, len, PATTERN_DOTS | PATTERN_NOCASE) != 0) return true;
        if (strncmp(p, "**/", 3) != 0 && pattern_covers(p, pl, path, len, PATTERN_DOTS | PATTERN_NOCASE)) return true;
    }
    for (size_t i = 0; list != NULL && i < list->n; i++) {
        if (pattern_match(list->pat[i], list->len[i], path, len, PATTERN_DOTS) != 0) return true;
        const bool star = list->len[i] >= 2 && list->pat[i][0] == '*' && list->pat[i][1] == '*' &&
                          (list->len[i] == 2 || list->pat[i][2] == '/');
        if (!star && pattern_covers(list->pat[i], list->len[i], path, len, PATTERN_DOTS)) return true;
    }
    return len == 16 && memcmp(path, ".belay-donttouch", 16) == 0;
}
