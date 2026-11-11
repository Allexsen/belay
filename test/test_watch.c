/*
 *  `belay watch` against its pin (test/expect/watch-v1.md), without a
 *  state directory: the built-in rows as the pin's table has them, what a
 *  record is flagged or noted as, .belay-donttouch's reader, and the lines.
 *  The commands, the record and the supervisor are test_watch_cli.c's.
 *  Each case is a table row printed as text, so a failure names it.
 */
#define _GNU_SOURCE
#include "belay_test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "util/jsonr.h"
#include "util/pattern.h"
#include "watch/flag.h"
#include "watch/lines.h"
#include "watch/watch.h"

#define PIN "test/expect/watch-v1.md"
#define RED "\xf0\x9f\x94\xb4"

/* ---- the rows ---- */

static const char *limits_text(const struct brow *r, char *buf, size_t cap) {
    static const struct { unsigned bit; const char *text; } L[] = {
        { BR_FILE, "not a directory" }, { BR_DEPS, "not in a dependency" }, { BR_NEWDIR, "not in a new directory" },
        { BR_NOTE_MOD, "noted when modified" }, { BR_NOTE, "noted" },
    };
    size_t w = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < sizeof L / sizeof L[0]; i++)
        if (r->limits & L[i].bit) w += (size_t)snprintf(buf + w, cap - w, "%s%s", w ? "; " : "", L[i].text);
    if (r->except != NULL) w += (size_t)snprintf(buf + w, cap - w, "%sexcept `%s`", w ? "; " : "", r->except);
    if (w == 0) snprintf(buf, cap, "--");
    return buf;
}

/* The pin's table, "| BR-n | kind | label | `pattern` | limits | probed |",
 * row by row against the code's. */
TEST(the_built_in_rows_are_the_pins) {
    FILE *f = fopen(PIN, "r");
    REQUIRE(f != NULL);
    char line[4096];
    size_t n = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        int id;
        char kind[64], label[64], pattern[128], limits[256];
        if (sscanf(line, "| BR-%d | %63[^|]| %63[^|]| `%127[^`]` | %255[^|]|", &id, kind, label, pattern, limits) != 5) continue;
        for (char *s = kind + strlen(kind); s > kind && s[-1] == ' ';) *--s = '\0';
        for (char *s = label + strlen(label); s > label && s[-1] == ' ';) *--s = '\0';
        for (char *s = limits + strlen(limits); s > limits && s[-1] == ' ';) *--s = '\0';
        n++;
        char want[600], got[600], lim[256];
        snprintf(want, sizeof want, "BR-%d | %s | %s | %s | %s", id, kind, label, pattern, limits);
        if ((size_t)id == n && n <= flag_n_rows) {
            const struct brow *r = &flag_rows[n - 1];
            snprintf(got, sizeof got, "BR-%zu | %s | %s | %s | %s", n, wkind_name(r->kind), r->label, r->pattern,
                     limits_text(r, lim, sizeof lim));
        } else {
            snprintf(got, sizeof got, "BR-%zu: the code has no such row, or the pin's ids are not 1, 2, 3...", n);
        }
        ASSERT_EQ_STR(want, got);
    }
    fclose(f);
    ASSERT_EQ_INT((int)flag_n_rows, (int)n);
    ASSERT_TRUE(n >= 60);
}

/* BR-P1: what makes CV-3 computable. */
TEST(no_row_starts_with_a_wildcard_component_that_is_not_a_globstar_and_goes_on) {
    for (size_t i = 0; i < flag_n_rows; i++) {
        const char *p = flag_rows[i].pattern, *sl = strchr(p, '/');
        const size_t first = sl != NULL ? (size_t)(sl - p) : strlen(p);
        const bool star = memchr(p, '*', first) != NULL, globstar = first == 2 && p[0] == '*' && p[1] == '*';
        char got[200];
        snprintf(got, sizeof got, "%s: %s", p, star && !globstar && sl != NULL ? "a wildcard first component, and more" : "fine");
        char want[200];
        snprintf(want, sizeof want, "%s: fine", p);
        ASSERT_EQ_STR(want, got);
    }
}

/* ---- flagging ---- */

static uint32_t g_mode[2];      /* what the mode lookup answers for each side; 0: the entry is not there */

static int mode_stub(void *ctx, int side, const char *path, size_t len, struct receipt_meta *m) {
    (void)ctx; (void)path; (void)len;
    if (g_mode[side] == 0) return -1;
    memset(m, 0, sizeof *m);
    m->mode = g_mode[side];
    return 0;
}

/* One record through flag_record: "kind|flag or note|text", or "none". */
static const char *flagged(struct flagctx *x, const char *path, const char *outcome, const char *type, const char *extra) {
    static char got[1024], json[1024];
    snprintf(json, sizeof json, "{\"path\":\"%s\",\"outcome\":\"%s\",\"type\":\"%s\"%s}", path, outcome, type, extra);
    struct jval v;
    if (jsonr_parse(json, strlen(json), &v) == -1) return "the test's record does not parse";
    struct wflag f = { 0 };
    const char *word;
    const int r = flag_record(x, &v, path, strlen(path), &f, &word);
    if (r == 1) snprintf(got, sizeof got, "%s|%s|%s", wkind_name(f.kind), f.note ? "note" : "flag", f.text);
    else snprintf(got, sizeof got, r == 0 ? "none (%s)" : "error", word);
    free(f.text);
    jsonr_free(&v);
    return got;
}

struct fcase { const char *path, *outcome, *type, *extra, *want; };

static void cases(struct flagctx *x, const struct fcase *t, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char want[1200], got[1200];
        snprintf(want, sizeof want, "%s %s %s: %s", t[i].path, t[i].outcome, t[i].type, t[i].want);
        snprintf(got, sizeof got, "%s %s %s: %s", t[i].path, t[i].outcome, t[i].type,
                 flagged(x, t[i].path, t[i].outcome, t[i].type, t[i].extra != NULL ? t[i].extra : ""));
        ASSERT_EQ_STR(want, got);
    }
}

TEST(a_row_flags_as_its_limits_say) {
    struct flagctx x = { .mode = mode_stub };
    g_mode[0] = g_mode[1] = 0;
    static const struct fcase t[] = {
        /* git: hooks, and BR-L1 (the directory itself is no flag), BR-L4 (samples) */
        { "old/.git/hooks/pre-push", "added", "reg", NULL, "git hooks and config|flag|old/.git/hooks/pre-push added (git hook)" },
        { "old/.git/hooks/pre-push.sample", "modified", "reg", NULL, "none (modified)" },
        { "old/.git/hooks", "type_changed", "lnk", ",\"type_before\":\"dir\"", "git hooks and config|flag|old/.git/hooks type changed (git hook)" },
        { "old/.git/modules/a/b/hooks/pre-commit", "added", "reg", NULL, "git hooks and config|flag|old/.git/modules/a/b/hooks/pre-commit added (git hook)" },
        /* BR-L5: a modified config is noted, anything else flagged */
        { "old/.git/config", "modified", "reg", NULL, "git hooks and config|note|old/.git/config modified (git config)" },
        { "old/.git/config", "removed", "reg", NULL, "git hooks and config|flag|old/.git/config removed (git config)" },
        { "old/.git/config", "added", "reg", NULL, "git hooks and config|flag|old/.git/config added (git config)" },
        { "old/.git/config", "metadata_only", "reg", NULL, "git hooks and config|flag|old/.git/config metadata changed (git config)" },
        { "old/.git/modules/s/config", "modified", "reg", NULL, "git hooks and config|note|old/.git/modules/s/config modified (git config)" },
        /* BR-L3: a new repository's own files */
        { "new/.git", "added", "dir", NULL, "none (added)" },
        { "new/.git/config", "added", "reg", NULL, "none (added)" },
        { "new/.git/hooks", "added", "dir", NULL, "none (added)" },
        { "new/.git/hooks/pre-push", "added", "reg", NULL, "git hooks and config|flag|new/.git/hooks/pre-push added (git hook)" },
        { "new/.git/info", "added", "dir", NULL, "none (added)" },
        { "new/.git/info/exclude", "added", "reg", NULL, "none (added)" },
        { "old/.git/info/exclude", "added", "reg", NULL, "git hooks and config|flag|old/.git/info/exclude added (git exclude list)" },
        /* hook managers, and BR-L2 */
        { ".husky", "added", "dir", NULL, "git hooks and config|flag|.husky added (git hook manager)" },
        { ".husky/_/pre-commit", "added", "reg", NULL, "git hooks and config|flag|.husky/_/pre-commit added (git hook manager)" },
        { "a/Lefthook.YML", "modified", "reg", NULL, "git hooks and config|flag|a/Lefthook.YML modified (git hook manager)" },
        { "node_modules/p/.pre-commit-config.yaml", "added", "reg", NULL, "none (added)" },
        /* the agent's rules: BR-17, BR-18, BR-P3, the exception, case */
        { ".claude", "added", "dir", NULL, "none (added)" },
        { ".claude/settings.local.json", "added", "reg", NULL, "agent rules|note|.claude/settings.local.json added (agent permissions)" },
        { ".claude/settings.local.json", "modified", "reg", NULL, "agent rules|note|.claude/settings.local.json modified (agent permissions)" },
        { ".claude/settings.json", "modified", "reg", NULL, "agent rules|flag|.claude/settings.json modified (agent rules)" },
        { ".claude/skills/a/SKILL.md", "added", "reg", NULL, "agent rules|flag|.claude/skills/a/SKILL.md added (agent rules)" },
        { ".claude/worktrees", "added", "dir", NULL, "none (added)" },
        { ".claude/worktrees/w/src/x.c", "modified", "reg", NULL, "none (modified)" },
        { "sub/.claude/settings.json", "modified", "reg", NULL, "none (modified)" },
        { "docs/claude.MD", "modified", "reg", NULL, "agent rules|flag|docs/claude.MD modified (agent rules)" },
        { "node_modules/p/AGENTS.md", "added", "reg", NULL, "none (added)" },
        { ".mcp.json", "added", "reg", NULL, "agent rules|flag|.mcp.json added (agent rules)" },
        { "sub/.mcp.json", "added", "reg", NULL, "none (added)" },
        /* loads on its own */
        { ".venv/lib/python3.12/site-packages/evil.pth", "added", "reg", NULL, "loads on its own|flag|.venv/lib/python3.12/site-packages/evil.pth added (runs at every Python start)" },
        { "evil.pth", "added", "reg", NULL, "none (added)" },
        { "tools/.envrc", "added", "reg", NULL, "loads on its own|flag|tools/.envrc added (runs on entering the directory)" },
        { ".devcontainer/devcontainer.json", "modified", "reg", NULL, "loads on its own|flag|.devcontainer/devcontainer.json modified (container setup)" },
        /* package source, CI, credentials */
        { "packages/a/.npmrc", "added", "reg", NULL, "package source|flag|packages/a/.npmrc added (package source)" },
        { "node_modules/dep/.npmrc", "added", "reg", NULL, "none (added)" },
        { ".github/workflows/ci.yml", "modified", "reg", NULL, "CI|flag|.github/workflows/ci.yml modified (CI)" },
        { "vendor/x/.github/workflows/ci.yml", "added", "reg", NULL, "none (added)" },
        { "node_modules/p/.travis.yml", "added", "reg", NULL, "none (added)" },
        { ".env", "added", "reg", NULL, "credentials|flag|.env added (credentials)" },
        { ".env", "added", "dir", NULL, "none (added)" },
        /* BR-L2 is for a directory of that name: a file called so is no dependency */
        { ".ssh/site-packages", "added", "reg", NULL, "credentials|flag|.ssh/site-packages added (credentials)" },
        { ".ssh/node_modules/key", "added", "reg", NULL, "none (added)" },
        /* the watched directory itself has no name a wildcard could match */
        { ".", "metadata_only", "dir", ",\"changed\":[\"mode\"]", "none (metadata changed)" },
        { ".env/lib/x.py", "added", "reg", NULL, "none (added)" },
        { "deploy/prod.pem", "added", "reg", NULL, "credentials|flag|deploy/prod.pem added (credentials)" },
        { ".venv/lib/python3.12/site-packages/certifi/cacert.pem", "added", "reg", NULL, "none (added)" },
        /* FK-9: replaced by a symlink; a new or retargeted one is not */
        { "bin/tool", "type_changed", "lnk", ",\"type_before\":\"reg\"", "replaced by a symlink|flag|bin/tool replaced by a symlink" },
        { "bin/link", "added", "lnk", NULL, "none (added)" },
        { "bin/link", "modified", "lnk", ",\"changed\":[\"link_target\"]", "none (modified)" },
        { "bin/dir", "type_changed", "dir", ",\"type_before\":\"lnk\"", "none (type changed)" },
        /* FK-11: could not be read, on a path a list covers; elsewhere it is counted */
        { ".env", "unknown", "reg", ",\"unknown\":[\"unreadable\",\"x\"]", "could not be read|flag|.env not compared (could not be read: unreadable)" },
        { "old/.git/config", "unknown", "reg", ",\"unknown\":[\"raced\"]", "could not be read|flag|old/.git/config not compared (could not be read: raced)" },
        { "src/a.c", "unknown", "reg", ",\"unknown\":[\"raced\"]", "none (not compared)" },
        { "src/a.c", "metadata_only", "reg", ",\"changed\":[\"mtime_ns\"]", "none (metadata changed)" },
    };
    cases(&x, t, sizeof t / sizeof t[0]);
    flagctx_free(&x);
}

TEST(a_privilege_change_is_flagged_after_git_and_agent_rows_and_before_the_rest) {
    struct flagctx x = { .mode = mode_stub };
    g_mode[0] = S_IFREG | 0755;
    g_mode[1] = S_IFREG | 04755;
    static const struct fcase t[] = {
        { "bin/tool", "metadata_only", "reg", ",\"changed\":[\"mode\"]", "privilege|flag|bin/tool setuid added (mode 0755 -> 4755) (privilege)" },
        /* FK-2 and FK-3 come first: the entry is flagged once, by the first kind */
        { ".git/hooks/pre-push", "metadata_only", "reg", ",\"changed\":[\"mode\"]", "git hooks and config|flag|.git/hooks/pre-push metadata changed (git hook)" },
        { ".claude/x", "metadata_only", "reg", ",\"changed\":[\"mode\"]", "agent rules|flag|.claude/x metadata changed (agent rules)" },
        /* FK-4 before FK-5 to FK-8 */
        { ".env", "metadata_only", "reg", ",\"changed\":[\"mode\"]", "privilege|flag|.env setuid added (mode 0755 -> 4755) (privilege)" },
        { ".npmrc", "metadata_only", "reg", ",\"changed\":[\"mode\"]", "privilege|flag|.npmrc setuid added (mode 0755 -> 4755) (privilege)" },
    };
    cases(&x, t, sizeof t / sizeof t[0]);
    g_mode[0] = 0;                              /* added setuid */
    static const struct fcase u[] = {
        { "bin/new", "added", "reg", NULL, "privilege|flag|bin/new setuid added (new, mode 4755) (privilege)" },
    };
    cases(&x, u, 1);
    g_mode[0] = g_mode[1] = S_IFREG | 0644;     /* no privilege bit moved */
    static const struct fcase v[] = {
        { "bin/tool", "metadata_only", "reg", ",\"changed\":[\"mode\"]", "none (metadata changed)" },
    };
    cases(&x, v, 1);
    flagctx_free(&x);
}

TEST(a_users_pattern_flags_whatever_it_matches_and_first) {
    struct dtlist old, fresh;
    char why[96];
    const char *a = "migrations\n# a comment\n\n**/*.lock\n.git/config\n", *b = "docs/api\n";
    REQUIRE(dtlist_parse(a, strlen(a), &old, why, sizeof why) == 0);
    REQUIRE(dtlist_parse(b, strlen(b), &fresh, why, sizeof why) == 0);
    ASSERT_EQ_INT(3, (int)old.n);
    struct flagctx x = { .lists = { &old, &fresh }, .mode = mode_stub };
    g_mode[0] = g_mode[1] = 0;
    static const struct fcase t[] = {
        { "migrations", "added", "dir", NULL, "don't-touch|flag|migrations added (don't-touch)" },
        { "migrations/0001.py", "modified", "reg", NULL, "don't-touch|flag|migrations/0001.py modified (don't-touch)" },
        { "x/migrations/0001.py", "modified", "reg", NULL, "none (modified)" },                     /* WD-3: from the top */
        { "a/b/yarn.lock", "removed", "reg", NULL, "don't-touch|flag|a/b/yarn.lock removed (don't-touch)" },
        { ".hidden/x.lock", "added", "reg", NULL, "don't-touch|flag|.hidden/x.lock added (don't-touch)" },  /* WD-1: dot-names */
        { "Migrations/1.py", "modified", "reg", NULL, "none (modified)" },                           /* WD-4: case-sensitive */
        /* FL-3: a user's pattern always flags, where the row would only note */
        { ".git/config", "modified", "reg", NULL, "don't-touch|flag|.git/config modified (don't-touch)" },
        /* DT-5: in the step that changes the list, the new one applies too */
        { "docs/api/v1.md", "modified", "reg", NULL, "don't-touch|flag|docs/api/v1.md modified (don't-touch)" },
        /* the list itself, whatever is in it */
        { ".belay-donttouch", "modified", "reg", NULL, "don't-touch|flag|.belay-donttouch modified (don't-touch)" },
        { ".belay-donttouch", "removed", "reg", NULL, "don't-touch|flag|.belay-donttouch removed (don't-touch)" },
        { "sub/.belay-donttouch", "added", "reg", NULL, "none (added)" },
        { ".", "metadata_only", "dir", ",\"changed\":[\"mode\"]", "none (metadata changed)" },    /* no pattern of a name matches the top */
        { "migrations/x", "unknown", "reg", ",\"unknown\":[\"hash_limit\"]", "could not be read|flag|migrations/x not compared (could not be read: hash_limit)" },
    };
    cases(&x, t, sizeof t / sizeof t[0]);
    flagctx_free(&x);
    dtlist_free(&old);
    dtlist_free(&fresh);
    /* the watched directory itself is the entry ".": patterns that would match that as a name do not */
    const char *dots = ".*\n*\n*.\n**/.*\n";
    REQUIRE(dtlist_parse(dots, strlen(dots), &old, why, sizeof why) == 0);
    struct flagctx y = { .lists = { &old, NULL }, .mode = mode_stub };
    static const struct fcase top[] = {
        { ".", "metadata_only", "dir", ",\"changed\":[\"mode\"]", "none (metadata changed)" },
        { ".env", "added", "dir", NULL, "don't-touch|flag|.env added (don't-touch)" },
    };
    cases(&y, top, 2);
    flagctx_free(&y);
    dtlist_free(&old);
    const char *all = "**\n";                             /* a pattern of nothing but `**` does: it has no component to match */
    REQUIRE(dtlist_parse(all, strlen(all), &old, why, sizeof why) == 0);
    struct flagctx z = { .lists = { &old, NULL }, .mode = mode_stub };
    static const struct fcase star[] = {
        { ".", "metadata_only", "dir", ",\"changed\":[\"mode\"]", "don't-touch|flag|. metadata changed (don't-touch)" },
    };
    cases(&z, star, 1);
    flagctx_free(&z);
    dtlist_free(&old);
}

TEST(a_dont_touch_file_is_read_as_dt_2_to_dt_4_say) {
    static const struct { const char *text, *want; } t[] = {
        { "", "0 patterns" },
        { "# only a comment\n\n", "0 patterns" },
        { "a\nb/c\n**/x\n", "3 patterns" },
        { "a", "1 patterns" },                                  /* no newline at the end */
        { "a\r\nb\r\n", "line 1 is not a pattern" },            /* a CRLF file */
        { "ok\n/abs\n", "line 2 is not a pattern" },
        { "ok\ntrailing/\n", "line 2 is not a pattern" },
        { "a//b\n", "line 1 is not a pattern" },
        { "a/./b\n", "line 1 is not a pattern" },
        { "../up\n", "line 1 is not a pattern" },
        { "# c\n\nwh?t\n", "line 3 is not a pattern" },
        { "a[bc]\n", "line 1 is not a pattern" },
        { "a\\b\n", "line 1 is not a pattern" },
        { "!negated\n", "line 1 is not a pattern" },
        { "a\tb\n", "line 1 is not a pattern" },
        { "**/a/**/b/**/c/**\n", "1 patterns" },                /* four `**` */
        { "**/a/**/b/**/c/**/d/**\n", "more than 4 `**` in a pattern (line 1)" },  /* five: a limit passed */
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        struct dtlist l;
        char why[96], got[160], want[160];
        if (dtlist_parse(t[i].text, strlen(t[i].text), &l, why, sizeof why) == 0) {
            snprintf(got, sizeof got, "[%s]: %zu patterns", t[i].text, l.n);
            dtlist_free(&l);
        } else {
            snprintf(got, sizeof got, "[%s]: %s", t[i].text, why);
        }
        snprintf(want, sizeof want, "[%s]: %s", t[i].text, t[i].want);
        ASSERT_EQ_STR(want, got);
    }
}

TEST(a_dont_touch_file_is_bounded) {
    struct dtlist l;
    char why[96];
    /* 256 patterns are read, 257 are not */
    char *buf = malloc(70000);
    REQUIRE(buf != NULL);
    size_t w = 0;
    for (int i = 0; i < 256; i++) w += (size_t)sprintf(buf + w, "p%d\n", i);
    ASSERT_EQ_INT(0, dtlist_parse(buf, w, &l, why, sizeof why));
    ASSERT_EQ_INT(256, (int)l.n);
    dtlist_free(&l);
    w += (size_t)sprintf(buf + w, "one-more\n");
    ASSERT_EQ_INT(-1, dtlist_parse(buf, w, &l, why, sizeof why));
    ASSERT_EQ_STR("more than 256 patterns", why);
    /* the file: 65,536 bytes are read, one more is not */
    memset(buf, '\n', 65537);
    ASSERT_EQ_INT(0, dtlist_parse(buf, 65536, &l, why, sizeof why));
    dtlist_free(&l);
    ASSERT_EQ_INT(-1, dtlist_parse(buf, 65537, &l, why, sizeof why));
    ASSERT_EQ_STR("the file is over 65536 bytes", why);
    /* a pattern: 4,096 bytes, not 4,097 */
    memset(buf, 'a', 4097);
    buf[4096] = '\n';
    ASSERT_EQ_INT(0, dtlist_parse(buf, 4097, &l, why, sizeof why));
    dtlist_free(&l);
    buf[4097] = '\n';
    buf[4096] = 'a';
    ASSERT_EQ_INT(-1, dtlist_parse(buf, 4098, &l, why, sizeof why));
    ASSERT_EQ_STR("a pattern of more than 4096 bytes (line 1)", why);
    free(buf);
}

TEST(a_history_event_is_flagged_with_its_ids_cut_to_seven) {
    const char *j = "{\"event\":\"git_history_rewritten\",\"interp\":\"git\",\"repo\":\".git\",\"branch\":\"feature\","
                    "\"text\":\"feature rewritten by commit (amend): c38c0d43ec8880c676b95d565a2b70eaeb801dd7 -> "
                    "e4876502e107f0997cd0ffd817d309baf8d0ddc5\",\"paths\":[]}";
    struct jval v;
    REQUIRE(jsonr_parse(j, strlen(j), &v) == 0);
    struct wflag f = { 0 };
    ASSERT_EQ_INT(1, flag_event(&v, &f));
    ASSERT_EQ_STR("feature rewritten by commit (amend): c38c0d4 -> e487650 (history)", f.text);
    ASSERT_EQ_INT(WK_HISTORY, (int)f.kind);
    ASSERT_FALSE(f.note);
    free(f.text);
    jsonr_free(&v);
    const char *other = "{\"event\":\"pip_installed\",\"interp\":\"pip\",\"text\":\"installed x 1\",\"paths\":[]}";
    REQUIRE(jsonr_parse(other, strlen(other), &v) == 0);
    ASSERT_EQ_INT(0, flag_event(&v, &f));
    jsonr_free(&v);
}

TEST(a_path_is_shown_escaped_and_cut_in_its_middle_past_80_characters) {
    char *s = flag_shown("a\x1b[31m\nb", 8);
    REQUIRE(s != NULL);
    ASSERT_EQ_STR("a\\x1b[31m\\x0ab", s);
    free(s);
    s = flag_shown("rlo\xe2\x80\xae" "exe.txt", 13);        /* a bidirectional override */
    REQUIRE(s != NULL);
    ASSERT_EQ_STR("rlo\\xe2\\x80\\xae" "exe.txt", s);
    free(s);
    char p80[81], p81[82];
    memset(p80, 'x', 80);
    p80[80] = '\0';
    memset(p81, 'y', 81);
    p81[81] = '\0';
    memcpy(p81, "START", 5);
    memcpy(p81 + 76, "FINAL", 5);
    s = flag_shown(p80, 80);
    REQUIRE(s != NULL);
    ASSERT_EQ_STR(p80, s);
    free(s);
    s = flag_shown(p81, 81);
    REQUIRE(s != NULL);
    ASSERT_EQ_INT(39 + 3 + 40, (int)strlen(s));
    ASSERT_TRUE(strncmp(s, "START", 5) == 0);
    ASSERT_TRUE(strcmp(s + strlen(s) - 5, "FINAL") == 0);
    ASSERT_TRUE(strstr(s, "\xe2\x80\xa6") == s + 39);
    free(s);
    /* characters, not bytes: 80 two-byte letters are not cut */
    char wide[161];
    for (int i = 0; i < 80; i++) memcpy(wide + 2 * i, "\xc3\xa9", 2);
    wide[160] = '\0';
    s = flag_shown(wide, 160);
    REQUIRE(s != NULL);
    ASSERT_EQ_STR(wide, s);
    free(s);
}

/* CV-3: what makes an unread path an alarm. Limits are ignored. */
TEST(an_unread_path_matters_where_a_list_could_flag_below_it) {
    struct dtlist l;
    char why[96];
    const char *text = "services/api/migrations\n**/secrets\n";
    REQUIRE(dtlist_parse(text, strlen(text), &l, why, sizeof why) == 0);
    static const struct { const char *path; bool with_list, want; } t[] = {
        { "node_modules", false, false },               /* the ordinary exclude is no alarm */
        { "build", false, false },
        { ".claude", false, true },                     /* an ancestor of what the agent rows matches */
        { ".claude/worktrees", false, true },           /* below a row's match: the exception is ignored */
        { ".github", false, true },                     /* an ancestor of `.github/workflows` */
        { ".github/workflows", false, true },
        { ".env", false, true },
        { "vendor/x/.git", false, false },              /* `**` rows count only on a match, and `.git` is none */
        { "vendor/x/.git/hooks", false, true },
        { "services", true, true },                     /* an ancestor of the user's pattern */
        { "services/api/migrations/old", true, true },
        { "services/web", true, false },
        { "x/secrets", true, true },
        { "x", true, false },                           /* `**` patterns count only on a match */
        { "services", false, false },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char want[160], got[160];
        snprintf(want, sizeof want, "%s (%s): %s", t[i].path, t[i].with_list ? "with the list" : "rows only", t[i].want ? "matters" : "does not");
        snprintf(got, sizeof got, "%s (%s): %s", t[i].path, t[i].with_list ? "with the list" : "rows only",
                 flag_covers(t[i].with_list ? &l : NULL, t[i].path, strlen(t[i].path)) ? "matters" : "does not");
        ASSERT_EQ_STR(want, got);
    }
    dtlist_free(&l);
}

/* ---- the lines ---- */

static struct wflag fl(enum wkind k, bool note, const char *text) { return (struct wflag){ k, note, (char *)text }; }

static const char *step_line(const struct wstep *s) {
    static char got[4096];
    struct wsb b = { 0 };
    lines_step(&b, s);
    snprintf(got, sizeof got, "%s", b.p != NULL ? b.p : "");
    free(b.p);
    return got;
}

/* The pin's examples, each from the step that gives it. */
TEST(a_steps_line_is_the_pins) {
    char *call[] = { "c1" };
    struct wstep s = { .calls = call, .n_calls = 1, .changes = 1, .counts = { [2] = 1 }, .names = { "a.txt modified" }, .n_names = 1 };
    ASSERT_EQ_STR("belay: 1 change: a.txt modified\n", step_line(&s));

    s = (struct wstep){ .changes = 2, .counts = { 1, 1 }, .names = { "b.txt added", "c.txt removed" }, .n_names = 2 };
    ASSERT_EQ_STR("belay: outside tool calls: 2 changes: b.txt added; c.txt removed\n", step_line(&s));

    s = (struct wstep){ .calls = call, .n_calls = 1, .changes = 714, .counts = { 714 }, .under = "node_modules", .n_under = 713 };
    ASSERT_EQ_STR("belay: 714 changes: 714 added (713 under node_modules/)\n", step_line(&s));

    struct wflag hook[] = { fl(WK_GIT, false, ".git/hooks/pre-push added (git hook)") };
    s = (struct wstep){ .calls = call, .n_calls = 1, .changes = 8, .flags = hook, .n_flags = 1, .counts = { 7 },
                        .under = "node_modules", .n_under = 5 };
    ASSERT_EQ_STR("belay: " RED " .git/hooks/pre-push added (git hook) \xc2\xb7 7 more: 7 added (5 under node_modules/)\n", step_line(&s));

    struct wflag note[] = { fl(WK_GIT, true, ".git/config modified (git config)") };
    s = (struct wstep){ .calls = call, .n_calls = 1, .changes = 8, .flags = note, .n_flags = 1, .counts = { 3, 0, 4 } };
    ASSERT_EQ_STR("belay: .git/config modified (git config) \xc2\xb7 7 more: 3 added, 4 modified\n", step_line(&s));

    struct wflag both[] = { fl(WK_GIT, true, ".git/config modified (git config)"), fl(WK_GIT, false, ".gitmodules added (git submodules)") };
    s = (struct wstep){ .calls = call, .n_calls = 1, .changes = 260, .flags = both, .n_flags = 2, .counts = { 258 },
                        .under = "vendor", .n_under = 254 };
    ASSERT_EQ_STR("belay: " RED " .gitmodules added (git submodules); .git/config modified (git config) \xc2\xb7 258 more: 258 added (254 under vendor/)\n",
                  step_line(&s));

    /* three named, one of each kind first; the rest counted by kind */
    struct wflag many[24];
    size_t n = 0;
    many[n++] = fl(WK_GIT, false, ".husky/_/a added (git hook manager)");
    many[n++] = fl(WK_GIT, false, ".husky/pre-commit added (git hook manager)");
    many[n++] = fl(WK_CRED, false, ".env added (credentials)");
    many[n++] = fl(WK_DONTTOUCH, false, "migrations/0001.py modified (don't-touch)");
    for (int i = 0; i < 18; i++) many[n++] = fl(WK_GIT, false, "x");
    s = (struct wstep){ .calls = call, .n_calls = 1, .changes = 23, .flags = many, .n_flags = n, .counts = { 0, 0, 1 }, .names = { "z modified" }, .n_names = 1 };
    ASSERT_EQ_STR("belay: " RED " migrations/0001.py modified (don't-touch); .husky/_/a added (git hook manager); .env added (credentials)"
                  "; and 19 more flagged: 19 git hooks and config \xc2\xb7 1 more: 1 modified\n", step_line(&s));

    char *trouble[] = { "could not record in 45 s: capturing" };
    s = (struct wstep){ .trouble = trouble, .n_trouble = 1 };
    ASSERT_EQ_STR("belay: " RED " could not record in 45 s: capturing\n", step_line(&s));

    s = (struct wstep){ .calls = call, .n_calls = 1 };                         /* LN-1 */
    ASSERT_EQ_STR("", step_line(&s));
}

TEST(a_steps_line_counts_every_entry_once) {
    char *call[] = { "c1" };
    /* four not flagged: counted, not named, and no directory holds more than half */
    struct wstep s = { .calls = call, .n_calls = 1, .changes = 4, .counts = { 1, 1, 1, 0, 1 }, .under = "src", .n_under = 2 };
    ASSERT_EQ_STR("belay: 4 changes: 1 added, 1 removed, 1 modified, 1 metadata changed\n", step_line(&s));
    /* exactly half is not "more than half" */
    s = (struct wstep){ .calls = call, .n_calls = 1, .changes = 6, .counts = { 6 }, .under = "src", .n_under = 3 };
    ASSERT_EQ_STR("belay: 6 changes: 6 added\n", step_line(&s));
    s.n_under = 4;
    ASSERT_EQ_STR("belay: 6 changes: 6 added (4 under src/)\n", step_line(&s));
    /* flags cut from the line's record are still counted (LN-8) */
    struct wflag one[] = { fl(WK_CRED, false, ".env added (credentials)") };
    s = (struct wstep){ .calls = call, .n_calls = 1, .changes = 12, .flags = one, .n_flags = 1, .cut_flag = { [WK_CRED] = 9 }, .cut_note = { [WK_GIT] = 2 } };
    ASSERT_EQ_STR("belay: " RED " .env added (credentials); and 9 more flagged: 9 credentials; and 2 more noted: 2 git hooks and config\n", step_line(&s));
    /* notes fill what the flags leave of the three places */
    struct wflag mix[] = { fl(WK_AGENT, true, "n1"), fl(WK_GIT, true, "n2"), fl(WK_CI, false, "f1"), fl(WK_GIT, true, "n3") };
    s = (struct wstep){ .calls = call, .n_calls = 1, .changes = 4, .flags = mix, .n_flags = 4 };
    ASSERT_EQ_STR("belay: " RED " f1; n2; n1; and 1 more noted: 1 git hooks and config\n", step_line(&s));
    /* notes alone: no red circle */
    struct wflag notes[] = { fl(WK_AGENT, true, ".claude/settings.local.json added (agent permissions)") };
    s = (struct wstep){ .changes = 1, .flags = notes, .n_flags = 1 };
    ASSERT_EQ_STR("belay: outside tool calls: .claude/settings.local.json added (agent permissions)\n", step_line(&s));
}

static const char *summary(const struct wstep *steps, size_t n, const char *const *standing, const char *gone) {
    static char got[4096];
    struct wsb b = { 0 };
    const struct wwords w = { "tool call", "this turn", " \xc2\xb7 full receipt: /belay:receipt" };
    lines_summary(&b, steps, n, "me", standing, gone, &w);
    snprintf(got, sizeof got, "%s", b.p != NULL ? b.p : "");
    free(b.p);
    return got;
}

TEST(a_summary_is_the_pins) {
    char *c1[] = { "c1" }, *c2[] = { "c2" }, *c3[] = { "c3" }, *c12[] = { "c1", "c2" };
    ASSERT_EQ_STR("belay: nothing changed this turn\n", summary(NULL, 0, NULL, NULL));

    struct wflag hook[] = { fl(WK_GIT, false, ".git/hooks/pre-push added (git hook)") };
    struct wflag note[] = { fl(WK_GIT, true, ".git/config modified (git config)") };
    struct wstep one[] = { { .session = "me", .calls = c1, .n_calls = 1, .changes = 8, .flags = hook, .n_flags = 1 } };
    ASSERT_EQ_STR("belay: " RED " 1 flagged: .git/hooks/pre-push added (git hook)\n"
                  "belay: 8 changed this turn in 1 tool call \xc2\xb7 full receipt: /belay:receipt\n", summary(one, 1, NULL, NULL));

    /* SM-4: a sum of the steps' counts; SM-3: calls counted once each, and only those that changed something */
    struct wstep many[] = {
        { .session = "me", .calls = c1, .n_calls = 1, .changes = 10, .flags = note, .n_flags = 1 },
        { .session = "me", .calls = c12, .n_calls = 2, .changes = 30 },
        { .session = "me", .calls = c3, .n_calls = 1, .changes = 0 },      /* a call that changed nothing is not counted */
        { .session = "me", .changes = 2 },
        { .session = "me", .calls = c1, .n_calls = 1, .changes = 0 },
    };
    ASSERT_EQ_STR("belay: 1 noted: .git/config modified (git config)\n"
                  "belay: 42 changed this turn: 40 in 2 tool calls, 2 outside tool calls \xc2\xb7 full receipt: /belay:receipt\n",
                  summary(many, 5, NULL, NULL));

    struct wstep outside[] = { { .session = "me", .changes = 3 } };
    ASSERT_EQ_STR("belay: 3 changed this turn outside tool calls \xc2\xb7 full receipt: /belay:receipt\n", summary(outside, 1, NULL, NULL));

    /* SM-5 */
    struct wstep theirs[] = { { .session = "me", .calls = c1, .n_calls = 1, .changes = 1 }, { .session = "other", .calls = c2, .n_calls = 1, .changes = 4 } };
    ASSERT_EQ_STR("belay: 5 changed this turn in 2 tool calls (with another session's steps) \xc2\xb7 full receipt: /belay:receipt\n",
                  summary(theirs, 2, NULL, NULL));
    ASSERT_EQ_STR("belay: 8 changed this turn in 1 tool call (the record before 2026-11-03 is gone) \xc2\xb7 full receipt: /belay:receipt\n",
                  summary(one + 0, 1, NULL, "2026-11-03") + strlen("belay: " RED " 1 flagged: .git/hooks/pre-push added (git hook)\n"));
}

TEST(a_summary_repeats_what_could_not_be_kept_and_never_says_nothing_changed_then) {
    char *t1[] = { "could not record in 45 s: capturing" }, *t2[] = { "could not record in 45 s: capturing", "the previous step did not finish" };
    struct wstep steps[] = {
        { .session = "me", .trouble = t1, .n_trouble = 1 },
        { .session = "me", .trouble = t2, .n_trouble = 2 },
    };
    /* each once; and with nothing recorded as changed, no line claims that nothing changed */
    ASSERT_EQ_STR("belay: " RED " could not record in 45 s: capturing\nbelay: " RED " the previous step did not finish\n",
                  summary(steps, 2, NULL, NULL));
    const char *standing[] = { ".belay-donttouch: line 2 is not a pattern; the previous list stays in force", NULL };
    char *c1[] = { "c1" };
    struct wstep ok[] = { { .session = "me", .calls = c1, .n_calls = 1, .changes = 1 } };
    ASSERT_EQ_STR("belay: " RED " .belay-donttouch: line 2 is not a pattern; the previous list stays in force\n"
                  "belay: 1 changed this turn in 1 tool call \xc2\xb7 full receipt: /belay:receipt\n", summary(ok, 1, standing, NULL));
}

int main(void) {
    RUN(the_built_in_rows_are_the_pins);
    RUN(no_row_starts_with_a_wildcard_component_that_is_not_a_globstar_and_goes_on);
    RUN(a_row_flags_as_its_limits_say);
    RUN(a_privilege_change_is_flagged_after_git_and_agent_rows_and_before_the_rest);
    RUN(a_users_pattern_flags_whatever_it_matches_and_first);
    RUN(a_dont_touch_file_is_read_as_dt_2_to_dt_4_say);
    RUN(a_dont_touch_file_is_bounded);
    RUN(a_history_event_is_flagged_with_its_ids_cut_to_seven);
    RUN(a_path_is_shown_escaped_and_cut_in_its_middle_past_80_characters);
    RUN(an_unread_path_matters_where_a_list_could_flag_below_it);
    RUN(a_steps_line_is_the_pins);
    RUN(a_steps_line_counts_every_entry_once);
    RUN(a_summary_is_the_pins);
    RUN(a_summary_repeats_what_could_not_be_kept_and_never_says_nothing_changed_then);
    return belay_test_report();
}
