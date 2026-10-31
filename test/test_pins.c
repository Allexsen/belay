/*
 *  The code against the pins (audit 2026-10, R2, R12): test/expect/ holds
 *  hand-written expectations, approved by the author and written from the
 *  spec's prose, never from the code or its generated tables.
 *
 *  - diff-fields.md: every row against DIFF_FIELDS, in both directions; then,
 *    for every (field, type) cell, a pair differing in that field alone must
 *    classify as the pin's words say -- the outcome for each word is spelled
 *    out here by hand, from the spec's rules, never read from the code.
 *  - manifest-v1.md: the frozen format's keys, order, kinds, types and rule
 *    count against the schema tables, in both directions; and the file itself
 *    never changes (a new format version gets a new file).
 *
 *  The pins are read at run time from test/expect/ relative to the working
 *  directory (make runs the tests from the repository root).
 */
#include "belay_test.h"
#include "belay/hash.h"
#include "schema/entry.h"
#include "schema/diff_schema.h"
#include "schema/finding_schema.h"
#include "belay/interp.h"
#include "diff/classify.h"

#define DIFF_PIN   "test/expect/diff-fields.md"
#define FORMAT_PIN "test/expect/manifest-v1.md"
#define KINDS_PIN  "test/expect/finding-kinds.md"
#define EVENTS_PIN "test/expect/diff-events.md"

/* sha256 of test/expect/manifest-v1.md as approved (PR #10, 2026-10-30). The
 * file is immutable: a new format version gets a new file. */
#define FORMAT_PIN_SHA256 "58a88cb34c5f9dff2ece818fc9c96198478fd648aeb70471be85c6e992bb7c9a"

/* ---- reading the pins: markdown tables ----------------------------------- */

#define MAX_ROWS 96
#define MAX_COLS 8
struct table { int n; char cell[MAX_ROWS][MAX_COLS][1024]; int cols[MAX_ROWS]; };

static void trim(char *s) {
    char *p = s;
    while (*p == ' ') p++;
    memmove(s, p, strlen(p) + 1);
    size_t l = strlen(s);
    while (l > 0 && (s[l - 1] == ' ' || s[l - 1] == '\n' || s[l - 1] == '\r')) s[--l] = '\0';
}

/* The rows of the table whose header row starts with `| first |`. */
static int read_table(const char *path, const char *first, struct table *t) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    char line[8192], head[64];
    snprintf(head, sizeof head, "| %s |", first);
    int in = 0;
    t->n = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        if (!in) {
            if (strncmp(line, head, strlen(head)) == 0) in = 1;   /* header row */
            continue;
        }
        if (in == 1) { in = 2; continue; }                          /* |---| row */
        if (line[0] != '|') break;
        if (t->n == MAX_ROWS) break;
        /* split on '|' not preceded by '\' */
        int c = 0;
        char *p = line + 1, *start = p;
        for (; *p && c < MAX_COLS; p++) {
            if (*p == '|' && p[-1] != '\\') {
                *p = '\0';
                snprintf(t->cell[t->n][c], sizeof t->cell[t->n][c], "%.1023s", start);
                trim(t->cell[t->n][c]);
                c++;
                start = p + 1;
            }
        }
        t->cols[t->n] = c;
        t->n++;
    }
    fclose(f);
    return in ? t->n : -1;
}

static void unescape_pipes(char *s) {
    char *w = s;
    for (char *r = s; *r; r++) {
        if (r[0] == '\\' && r[1] == '|') continue;
        *w++ = *r;
    }
    *w = '\0';
}

static int type_named(const char *s) {
    for (int t = 0; t < ENTRY_TYPE_COUNT; t++)
        if (strcmp(ENTRY_TYPES[t].name, s) == 0) return t;
    return -1;
}

/* "all", "reg, lnk", "all but reg" -> a TBIT mask; 0 when unparsable. */
static unsigned types_of(const char *s) {
    unsigned all = 0, m = 0;
    for (int t = 0; t < ENTRY_TYPE_COUNT; t++) all |= TBIT(t);
    if (strcmp(s, "all") == 0) return all;
    const int but = strncmp(s, "all but ", 8) == 0;
    char buf[256];
    snprintf(buf, sizeof buf, "%s", but ? s + 8 : s);
    for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
        trim(tok);
        const int t = type_named(tok);
        if (t < 0) return 0;
        m |= TBIT(t);
    }
    return but ? all & ~m : m;
}

/* The pin's words for a class -- the vocabulary of diff-fields.md. */
struct cls_word { const char *word; enum change_class cls; enum unknown_scope scope; };
static const struct cls_word CLASS_WORDS[] = {
    { "key", CC_KEY, US_NONE }, { "type", CC_TYPE, US_NONE }, { "content", CC_CONTENT, US_NONE },
    { "metadata", CC_METADATA, US_NONE }, { "identity", CC_IDENTITY, US_NONE },
    { "identity: device relation", CC_DEVICE, US_NONE },
    { "identity: within one device", CC_INODE, US_NONE }, { "ctime", CC_CTIME, US_NONE },
    { "flag: content unknown", CC_FLAG, US_CONTENT }, { "flag: metadata unknown", CC_FLAG, US_METADATA },
    { "flag: everything unknown", CC_FLAG, US_ALL }, { "not compared", CC_INFO, US_NONE },
};
struct abs_word { const char *word; enum absent_means am; };
static const struct abs_word ABSENT_WORDS[] = {
    { "required", AM_REQUIRED }, { "flag", AM_FLAG }, { "none", AM_NONE },
    { "none if read", AM_NONE_IF_READ }, { "unknown", AM_UNKNOWN },
    { "with unverified", AM_WITH_UNVERIFIED }, { "only on its types", AM_ONLY_ON_TYPES },
    { "n/a", AM_NA },
};

static int field_named(const char *s) {
    for (int f = 0; f < F_COUNT; f++)
        if (strcmp(ENTRY_FIELDS[f].name, s) == 0) return f;
    return -1;
}

/* ---- diff-fields.md against DIFF_FIELDS ---------------------------------- */

struct pin_row { int set; enum change_class cls; enum unknown_scope scope; unsigned types;
                 enum mount_roots mr; enum absent_means am; };
static struct pin_row PIN[F_COUNT];

static int load_diff_pin(void) {
    static struct table t;
    if (read_table(DIFF_PIN, "field", &t) < 0) return -1;
    memset(PIN, 0, sizeof PIN);
    for (int i = 0; i < t.n; i++) {
        if (t.cols[i] < 5) return -1;
        const int f = field_named(t.cell[i][0]);
        if (f < 0) { printf("      pin names an unknown field: %s\n", t.cell[i][0]); return -1; }
        struct pin_row *r = &PIN[f];
        r->set++;
        for (size_t w = 0; w < sizeof CLASS_WORDS / sizeof CLASS_WORDS[0]; w++)
            if (strcmp(CLASS_WORDS[w].word, t.cell[i][1]) == 0) { r->cls = CLASS_WORDS[w].cls; r->scope = CLASS_WORDS[w].scope; }
        r->types = types_of(t.cell[i][2]);
        r->mr = strcmp(t.cell[i][3], "compared") == 0 ? MR_COMPARED
              : strcmp(t.cell[i][3], "not compared") == 0 ? MR_NOT_COMPARED : MR_UNSET;
        for (size_t w = 0; w < sizeof ABSENT_WORDS / sizeof ABSENT_WORDS[0]; w++)
            if (strcmp(ABSENT_WORDS[w].word, t.cell[i][4]) == 0) r->am = ABSENT_WORDS[w].am;
        if (strncmp(t.cell[i][4], "n/a", 3) == 0) r->am = AM_NA;
        if (strncmp(t.cell[i][4], "only on its types", 17) == 0) r->am = AM_ONLY_ON_TYPES;
        if (strncmp(t.cell[i][4], "with unverified", 15) == 0) r->am = AM_WITH_UNVERIFIED;
    }
    return 0;
}

TEST(diff_fields_pin_and_table_agree_both_ways) {
    REQUIRE_MSG(load_diff_pin() == 0, "cannot read %s (run from the repository root)", DIFF_PIN);
    for (int f = 0; f < F_COUNT; f++) {
        const struct pin_row *p = &PIN[f];
        const struct field_change *c = &DIFF_FIELDS[f];
        const char *n = ENTRY_FIELDS[f].name;
        if (p->set != 1) { BELAY_FAIL("%s: %d pin rows, want 1", n, p->set); continue; }
        if (p->cls == CC_UNSET) BELAY_FAIL("%s: the pin's class word is not in the vocabulary", n);
        if (p->cls != c->cls) BELAY_FAIL("%s: class %d in the pin, %d in the code", n, p->cls, c->cls);
        if (p->cls == CC_FLAG && p->scope != c->unknown)
            BELAY_FAIL("%s: unknown scope %d in the pin, %d in the code", n, p->scope, c->unknown);
        if (p->cls == CC_FLAG && (c->reason < DR_FIRST || strcmp(DIFF_REASONS[c->reason].name, n) != 0))
            BELAY_FAIL("%s: a flag's reason is its own name", n);
        if (p->types == 0) BELAY_FAIL("%s: the pin's types are unreadable", n);
        if (p->types != c->types) BELAY_FAIL("%s: types %#x in the pin, %#x in the code", n, p->types, c->types);
        if (p->mr != c->mount_roots) BELAY_FAIL("%s: on mount roots %d in the pin, %d in the code", n, p->mr, c->mount_roots);
        if (p->am == AM_UNSET) BELAY_FAIL("%s: the pin's absent-means word is not in the vocabulary", n);
        if (p->am != c->absent) BELAY_FAIL("%s: absent means %d in the pin, %d in the code", n, p->am, c->absent);
    }
}

/* ---- every (field, type) cell behaves as the pin says --------------------- */

static void base_entry(struct belay_entry *e, int t) {
    memset(e, 0, sizeof *e);
    e->path[0] = 'x';
    e->path_len = 1;
    e->type = (enum belay_entry_type)t;
    e->mode = ENTRY_TYPES[t].ifmt | 0644;
    e->uid = 1; e->gid = 1; e->size = 1; e->mtime_ns = 10; e->ctime_ns = 10;
    e->ino = 5; e->dev = 1; e->nlink = 1;
    if (t == BELAY_T_REG) { e->has_hash = true; memset(e->sha256_hex, 'a', 64); }
    if (t == BELAY_T_LNK) { e->has_link_target = true; e->link_target[0] = 't'; e->link_target_len = 1; }
    if (t == BELAY_T_BLK || t == BELAY_T_CHR) { e->has_rdev = true; e->rdev = 3; }
}

/* Makes field `f` of `a` differ from `b`'s; false when the field has no
 * value to differ in (flags, the key, derived fields). */
static bool vary(struct belay_entry *a, int f) {
    switch ((enum entry_field)f) {
    case F_MODE:   a->mode ^= 0100; return true;
    case F_UID:    a->uid++; return true;
    case F_GID:    a->gid++; return true;
    case F_SIZE:   a->size++; return true;
    case F_MTIME:  a->mtime_ns++; return true;
    case F_CTIME:  a->ctime_ns++; return true;
    case F_INO:    a->ino++; return true;
    case F_DEV:    a->dev = 2; return true;            /* off the scope root's device */
    case F_NLINK:  a->nlink++; return true;
    case F_IFLAGS: a->has_iflags = true; a->iflags = 16; return true;   /* paired below */
    case F_CAPS:   a->has_caps = true; snprintf(a->caps_hex, sizeof a->caps_hex, "01"); return true;
    case F_XATTRS: a->has_xattrs = a->xattrs_inline = true; memset(a->xattrs_sha256_hex, 'b', 64); return true;
    case F_SHA256: if (!a->has_hash) return false; a->sha256_hex[0] = 'c'; return true;
    case F_RDEV:   if (!a->has_rdev) return false; a->rdev++; return true;
    case F_LINK_TARGET: if (!a->has_link_target) return false; a->link_target[0] = 'u'; return true;
    case F_PATH: case F_TYPE: case F_XATTRS_SHA256: case F_XATTRS_UNKNOWN: case F_UNVERIFIED:
    case F_UNSTABLE: case F_TARGET_OUTSIDE: case F_STORED: case F_MOUNT: case F_UNREADABLE:
    case F_RACED: case F_COUNT:
        return false;
    }
    return false;
}

/* For each pinned class word, the outcome of a pair differing in that field
 * alone, on an entry the field applies to -- the spec's rules 3 to 5. */
static enum diff_outcome expected(enum change_class cls) {
    switch (cls) {
    case CC_CONTENT: return D_MODIFIED;
    case CC_METADATA: case CC_IDENTITY: case CC_DEVICE: case CC_INODE: case CC_CTIME:
        return D_METADATA_ONLY;
    case CC_UNSET: case CC_KEY: case CC_TYPE: case CC_FLAG: case CC_INFO:
        return D_UNDECIDED;
    }
    return D_UNDECIDED;
}

TEST(every_field_type_cell_classifies_as_its_pin_says) {
    REQUIRE(load_diff_pin() == 0);
    const struct diff_ctx ctx = { 1, 1, false };
    int cells = 0;
    for (int f = 0; f < F_COUNT; f++) {
        const struct pin_row *p = &PIN[f];
        for (int t = 0; t < ENTRY_TYPE_COUNT; t++) {
            struct belay_entry b, a;
            base_entry(&b, t);
            base_entry(&a, t);
            if (f == F_IFLAGS) { b.has_iflags = true; b.iflags = 0; }   /* both have it */
            if (!vary(&a, f)) continue;
            struct verdict v;
            REQUIRE(classify_both(&ctx, &b, &a, &v) == 0);
            const enum diff_outcome want = (p->types & TBIT(t)) ? expected(p->cls) : D_UNCHANGED;
            if (want == D_UNDECIDED) continue;
            cells++;
            if (v.outcome != want)
                BELAY_FAIL("%s on %s: outcome %s, the pin says %s", ENTRY_FIELDS[f].name,
                           ENTRY_TYPES[t].name, DIFF_OUTCOMES[v.outcome].name, DIFF_OUTCOMES[want].name);
            const uint32_t want_changed = want == D_UNCHANGED ? 0 : FBIT(f);
            if (v.changed != want_changed)
                BELAY_FAIL("%s on %s: changed %#x, want %#x", ENTRY_FIELDS[f].name,
                           ENTRY_TYPES[t].name, v.changed, want_changed);
        }
    }
    ASSERT_TRUE(cells > 60);
}

/* On a mount root, a field the pin marks "not compared" never appears in
 * `changed`, and one it marks "compared" does (the mount flag makes the
 * outcome unknown either way: rule 3). */
TEST(mount_root_cells_follow_the_pin) {
    REQUIRE(load_diff_pin() == 0);
    const struct diff_ctx ctx = { 1, 1, false };
    for (int f = 0; f < F_COUNT; f++) {
        const struct pin_row *p = &PIN[f];
        for (int t = 0; t < ENTRY_TYPE_COUNT; t++) {
            if (!(p->types & TBIT(t)) || expected(p->cls) == D_UNDECIDED) continue;
            struct belay_entry b, a;
            base_entry(&b, t);
            base_entry(&a, t);
            b.is_mount = a.is_mount = true;
            if (t == BELAY_T_REG) { b.has_hash = a.has_hash = false; b.unverified = a.unverified = true; }
            if (f == F_IFLAGS) { b.has_iflags = true; b.iflags = 0; }
            if (!vary(&a, f)) continue;
            struct verdict v;
            REQUIRE(classify_both(&ctx, &b, &a, &v) == 0);
            const bool listed = (v.changed & FBIT(f)) != 0;
            if (p->mr == MR_NOT_COMPARED && listed)
                BELAY_FAIL("%s on a %s mount root: compared, the pin says not", ENTRY_FIELDS[f].name, ENTRY_TYPES[t].name);
            if (p->mr == MR_COMPARED && !listed)
                BELAY_FAIL("%s on a %s mount root: not compared, the pin says compared", ENTRY_FIELDS[f].name, ENTRY_TYPES[t].name);
        }
    }
}

/* Absence on one side, by the pin's absent-means words. */
TEST(one_sided_fields_follow_the_pin) {
    REQUIRE(load_diff_pin() == 0);
    const struct diff_ctx ctx = { 1, 1, false };
    for (int f = 0; f < F_COUNT; f++) {
        const struct pin_row *p = &PIN[f];
        if (p->am != AM_UNKNOWN && p->am != AM_NONE_IF_READ) continue;
        if (expected(p->cls) == D_UNDECIDED) continue;
        struct belay_entry b, a;
        base_entry(&b, BELAY_T_REG);
        base_entry(&a, BELAY_T_REG);
        REQUIRE(vary(&a, f));                       /* present after, absent before */
        if (f == F_IFLAGS) { b.has_iflags = false; }
        struct verdict v;
        REQUIRE(classify_both(&ctx, &b, &a, &v) == 0);
        if (p->am == AM_UNKNOWN) {
            if (v.outcome != D_UNKNOWN)
                BELAY_FAIL("%s on one side: %s, the pin says unknown", ENTRY_FIELDS[f].name, DIFF_OUTCOMES[v.outcome].name);
        } else {
            /* none if read: read on both sides, absence is none -- a change */
            if (v.outcome != D_METADATA_ONLY || !(v.changed & FBIT(f)))
                BELAY_FAIL("%s on one side, read: %s, the pin says a change", ENTRY_FIELDS[f].name, DIFF_OUTCOMES[v.outcome].name);
            /* not read on one side: unknown, never "none" */
            b.xattrs_unknown = true;
            REQUIRE(classify_both(&ctx, &b, &a, &v) == 0);
            if (v.outcome != D_UNKNOWN || (v.changed & FBIT(f)))
                BELAY_FAIL("%s against xattrs_unknown: %s, the pin says unknown", ENTRY_FIELDS[f].name, DIFF_OUTCOMES[v.outcome].name);
        }
    }
}

/* ---- manifest-v1.md: the frozen format ----------------------------------- */

TEST(the_frozen_format_file_never_changes) {
    FILE *f = fopen(FORMAT_PIN, "rb");
    REQUIRE_MSG(f != NULL, "cannot read %s", FORMAT_PIN);
    struct belay_sha256 c;
    belay_sha256_init(&c);
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) belay_sha256_update(&c, buf, n);
    fclose(f);
    uint8_t d[BELAY_SHA256_DIGEST_LEN];
    char hex[65];
    belay_sha256_final(&c, d);
    belay_hex_encode(hex, d, sizeof d);
    /* A failure here means the frozen format's pin was edited. Do not update
     * the digest: a new format version gets a new file. */
    ASSERT_EQ_STR(FORMAT_PIN_SHA256, hex);
}

static void check_line_keys(struct table *t, const char *line, const char *const *names,
                            const char *const *alts, const char *const *kinds, int n) {
    int pos = 0;
    for (int i = 0; i < t->n; i++) {
        if (strcmp(t->cell[i][0], line) != 0) continue;
        char key[256];
        snprintf(key, sizeof key, "%s", t->cell[i][2]);
        unescape_pipes(key);
        char want[256];
        if (pos < n) {
            snprintf(want, sizeof want, "%s%s%s", names[pos], alts[pos] ? "|" : "", alts[pos] ? alts[pos] : "");
            if (strcmp(want, key) != 0)
                BELAY_FAIL("%s key %d: %s in the pin, %s in the code", line, pos + 1, key, want);
            if (strcmp(kinds[pos], t->cell[i][3]) != 0)
                BELAY_FAIL("%s key %s: kind %s in the pin, %s in the code", line, key, t->cell[i][3], kinds[pos]);
        }
        pos++;
    }
    if (pos != n) BELAY_FAIL("%s: %d keys in the pin, %d in the code", line, pos, n);
}

TEST(frozen_format_keys_types_and_rules_match_the_schema) {
    static struct table t;
    REQUIRE_MSG(read_table(FORMAT_PIN, "line", &t) > 0, "cannot read the keys table of %s", FORMAT_PIN);
    const char *hn[H_COUNT], *ha[H_COUNT], *hk[H_COUNT];
    for (int i = 0; i < H_COUNT; i++) { hn[i] = HEADER_FIELDS[i].name; ha[i] = HEADER_FIELDS[i].alt; hk[i] = HEADER_FIELDS[i].kind; }
    check_line_keys(&t, "header", hn, ha, hk, H_COUNT);
    const char *en[F_COUNT], *ea[F_COUNT], *ek[F_COUNT];
    for (int i = 0; i < F_COUNT; i++) { en[i] = ENTRY_FIELDS[i].name; ea[i] = ENTRY_FIELDS[i].alt; ek[i] = ENTRY_FIELDS[i].kind; }
    check_line_keys(&t, "entry", en, ea, ek, F_COUNT);
    for (int i = 0, pos = 0; i < t.n; i++) {
        if (strcmp(t.cell[i][0], "entry") != 0) continue;
        const bool req = strncmp(t.cell[i][4], "required", 8) == 0;
        if (pos < F_COUNT && req != ENTRY_FIELDS[pos].required)
            BELAY_FAIL("entry key %s: required %d in the pin, %d in the code", ENTRY_FIELDS[pos].name, req, ENTRY_FIELDS[pos].required);
        pos++;
    }
    const char *tn[TR_COUNT], *ta[TR_COUNT], *tk[TR_COUNT];
    for (int i = 0; i < TR_COUNT; i++) { tn[i] = TRAILER_FIELDS[i].name; ta[i] = TRAILER_FIELDS[i].alt; tk[i] = TRAILER_FIELDS[i].kind; }
    check_line_keys(&t, "trailer", tn, ta, tk, TR_COUNT);

    static struct table ty;
    REQUIRE(read_table(FORMAT_PIN, "type", &ty) > 0);
    ASSERT_EQ_INT(ENTRY_TYPE_COUNT, ty.n);
    for (int i = 0; i < ty.n; i++) {
        const int tt = type_named(ty.cell[i][0]);
        if (tt < 0) { BELAY_FAIL("type %s is not in the code", ty.cell[i][0]); continue; }
        if (strtoul(ty.cell[i][1], NULL, 8) != ENTRY_TYPES[tt].ifmt)
            BELAY_FAIL("type %s: mode bits %s in the pin, %06o in the code", ty.cell[i][0], ty.cell[i][1], ENTRY_TYPES[tt].ifmt);
    }

    static struct table r;
    REQUIRE(read_table(FORMAT_PIN, "rule", &r) > 0);
    int entry_rules = 0, header_rules = 0;
    for (int i = 0; i < r.n; i++) {
        if (strncmp(r.cell[i][0], "header", 6) == 0) { header_rules++; continue; }
        const int k = atoi(r.cell[i][0]);
        entry_rules++;
        if (k < 1 || (size_t)k > ENTRY_RULE_COUNT) { BELAY_FAIL("rule %s is not in the code", r.cell[i][0]); continue; }
        /* "present exactly on `blk` and `chr`": such a rule is checked on every
         * entry, and its types are the ones its statement names. */
        unsigned want = types_of(r.cell[i][1]);
        const char *exactly = strstr(r.cell[i][2], "present exactly on");
        if (exactly != NULL) {
            want = 0;
            for (const char *q = strchr(exactly, '`'); q != NULL; q = strchr(q + 1, '`')) {
                const char *e = strchr(q + 1, '`');
                if (e == NULL) break;
                char name[32];
                snprintf(name, sizeof name, "%.*s", (int)(e - q - 1), q + 1);
                const int tt = type_named(name);
                if (tt >= 0) want |= TBIT(tt);
                q = e;
            }
        }
        if (want != ENTRY_RULES[k - 1].types)
            BELAY_FAIL("rule %d applies to %#x in the pin, %#x in the code", k, want, ENTRY_RULES[k - 1].types);
    }
    ASSERT_EQ_INT((int)ENTRY_RULE_COUNT, entry_rules);
    ASSERT_EQ_INT((int)ENTRY_HEADER_RULE_COUNT, header_rules);
}

/* ---- finding-kinds.md against FINDING_KINDS ------------------------------ */

/* "`text`" -> "text" in place. */
static void unquote(char *s) {
    size_t l = strlen(s);
    if (l >= 2 && s[0] == '`' && s[l - 1] == '`') { memmove(s, s + 1, l - 2); s[l - 2] = '\0'; }
}

/* "text, pip" or "any" -> an interpreter mask; 0 when a name is unknown. */
static unsigned interps_of(const char *s) {
    if (strcmp(s, "core") == 0) return IN_CORE;
    char buf[256];
    unsigned m = 0;
    snprintf(buf, sizeof buf, "%s", s);
    for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
        trim(tok);
        int id = 0;
        while (id < BELAY_INTERP_COUNT && strcmp(belay_interp_name((enum belay_interp_id)id), tok)) id++;
        if (id == BELAY_INTERP_COUNT) return 0;
        m |= 1u << id;
    }
    return m;
}

/* "name: int, other: string" -> the schema's field list, written back the
 * same way, so the two compare as strings. */
static void fields_of(const struct finding_kind_def *d, char *out, size_t cap) {
    static const char *const T[] = { [FT_INT] = "int", [FT_STRING] = "string", [FT_BOOL] = "bool" };
    size_t w = 0;
    out[0] = '\0';
    for (int k = 0; k < FINDING_FIELDS_MAX && d->field[k].name; k++)
        w += (size_t)snprintf(out + w, cap - w, "%s%s: %s", k ? ", " : "", d->field[k].name,
                              d->field[k].type < FT_UNSET || d->field[k].type > FT_BOOL ||
                              d->field[k].type == FT_UNSET ? "?" : T[d->field[k].type]);
    if (w == 0) snprintf(out, cap, "--");
}

/* Pin 2026-10-31 (#18): every kind the pin lists is the schema's, with the
 * same interpreters, levels, fields in order and template; and the schema
 * has no kind the pin does not list. */
TEST(finding_kinds_pin_and_schema_agree_both_ways) {
    static struct table t;
    REQUIRE(read_table(KINDS_PIN, "kind", &t) > 0);
    int seen[FK_COUNT] = { 0 };
    for (int i = 0; i < t.n; i++) {
        if (t.cols[i] < 5) { BELAY_FAIL("row %d: %d cells", i, t.cols[i]); continue; }
        int k = FK_UNSET + 1;
        while (k < FK_COUNT && strcmp(FINDING_KINDS[k].name, t.cell[i][0]) != 0) k++;
        if (k == FK_COUNT) { BELAY_FAIL("the pin lists %s; the schema has no such kind", t.cell[i][0]); continue; }
        seen[k]++;
        const struct finding_kind_def *d = &FINDING_KINDS[k];
        if (interps_of(t.cell[i][1]) != d->interps)
            BELAY_FAIL("%s: interpreters %s, schema mask %#x", d->name, t.cell[i][1], d->interps);
        const unsigned lv = strcmp(t.cell[i][2], "path") == 0 ? LV_PATH
                          : strcmp(t.cell[i][2], "event") == 0 ? LV_EVENT
                          : strcmp(t.cell[i][2], "path, event") == 0 ? (LV_PATH | LV_EVENT) : 0;
        if (lv != d->levels) BELAY_FAIL("%s: level %s, schema %u", d->name, t.cell[i][2], d->levels);
        char f[256];
        fields_of(d, f, sizeof f);
        if (strcmp(f, t.cell[i][3]) != 0) BELAY_FAIL("%s: fields \"%s\", schema \"%s\"", d->name, t.cell[i][3], f);
        unquote(t.cell[i][4]);
        if (strcmp(d->text, t.cell[i][4]) != 0)
            BELAY_FAIL("%s: text \"%s\", schema \"%s\"", d->name, t.cell[i][4], d->text);
    }
    for (int k = FK_UNSET + 1; k < FK_COUNT; k++)
        if (seen[k] != 1) BELAY_FAIL("%s: listed %d times by the pin", FINDING_KINDS[k].name, seen[k]);
}

/* Pin 2026-10-31 (#19): the event rules the spec is generated from are the
 * pin's, word for word, and no more. */
TEST(event_rules_pin_and_schema_agree_both_ways) {
    static struct table t;
    REQUIRE(read_table(EVENTS_PIN, "rule", &t) > 0);
    ASSERT_EQ_INT(EVENT_RULE_COUNT, t.n);
    for (int i = 0; i < t.n && i < EVENT_RULE_COUNT; i++) {
        if (strcmp(EVENT_RULES[i].id, t.cell[i][0]) != 0)
            BELAY_FAIL("row %d: pin %s, schema %s", i, t.cell[i][0], EVENT_RULES[i].id);
        if (strcmp(EVENT_RULES[i].statement, t.cell[i][1]) != 0)
            BELAY_FAIL("%s: the statement differs", t.cell[i][0]);
    }
}

int main(void) {
    RUN(diff_fields_pin_and_table_agree_both_ways);
    RUN(finding_kinds_pin_and_schema_agree_both_ways);
    RUN(event_rules_pin_and_schema_agree_both_ways);
    RUN(every_field_type_cell_classifies_as_its_pin_says);
    RUN(mount_root_cells_follow_the_pin);
    RUN(one_sided_fields_follow_the_pin);
    RUN(the_frozen_format_file_never_changes);
    RUN(frozen_format_keys_types_and_rules_match_the_schema);
    return belay_test_report();
}
