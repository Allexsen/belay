/*
 *  Generates the specs' tables from the schemas (src/schema/entry.c,
 *  diff_schema.c), so the documentation cannot drift from the code:
 *
 *    gen_schema spec <file>   <file> with each generated block replaced
 *                             (docs/spec/manifest-v1.md, docs/spec/diff-v1.md)
 *
 *  Output goes to stdout. `make gen` writes it in place; `make gen-check`
 *  (part of `make check`) fails when a committed one is stale. Documentation
 *  only: no check derives its expectations from it (audit 2026-10, R2) --
 *  the fuzz invariants it used to generate are hand-written from the pin.
 */
#include "schema/entry.h"
#include "schema/diff_schema.h"
#include "schema/finding_schema.h"
#include "belay/interp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BEGIN_MARK "<!-- BEGIN GENERATED: "
#define END_MARK   "<!-- END GENERATED: "
#define MARK_TAIL  " -->"
#define WIDTH      100

/* ------------------------------------------------------------------------ */
/* Shared                                                                    */
/* ------------------------------------------------------------------------ */

static void type_names(char *out, size_t cap, unsigned mask, const char *sep) {
    size_t n = 0;
    out[0] = '\0';
    if (mask == T_ALL) {
        snprintf(out, cap, "all");
        return;
    }
    for (int t = 0; t < ENTRY_TYPE_COUNT; t++) {
        if (!(mask & TBIT(t))) continue;
        n += (size_t)snprintf(out + n, cap - n, "%s%s", n ? sep : "", ENTRY_TYPES[t].name);
        if (n >= cap) abort();
    }
}

/* ------------------------------------------------------------------------ */
/* Spec                                                                      */
/* ------------------------------------------------------------------------ */

/* Writes `text` after `first`, wrapped at WIDTH, continuation lines indented
 * by `indent` spaces. */
static void wrap(const char *first, const char *text, int indent) {
    int col = printf("%s", first);
    const char *p = text;
    while (*p) {
        const char *sp = strchr(p, ' ');
        const int len = sp ? (int)(sp - p) : (int)strlen(p);
        if (col + 1 + len > WIDTH && col > indent) {
            col = printf("\n%*s", indent, "") - 1;
        } else if (p != text) {
            col += printf(" ");
        }
        col += printf("%.*s", len, p);
        p += len;
        while (*p == ' ') p++;
    }
    printf("\n");
}

/* On which types a field may appear, as far as the single-field rules say
 * (FORBID, PRESENT_IFF); combinations are the numbered rules' business. */
static unsigned allowed_on(int f) {
    unsigned on = T_ALL;
    for (size_t i = 0; i < ENTRY_RULE_COUNT; i++) {
        const struct entry_rule *r = &ENTRY_RULES[i];
        if (!(r->a & FBIT(f))) continue;
        if (r->kind == R_FORBID) on &= ~r->types;
        if (r->kind == R_PRESENT_IFF) on &= r->types;
    }
    return on;
}

static unsigned required_on(int f) {
    if (ENTRY_FIELDS[f].required) return T_ALL;
    for (size_t i = 0; i < ENTRY_RULE_COUNT; i++) {
        const struct entry_rule *r = &ENTRY_RULES[i];
        if (r->kind == R_PRESENT_IFF && r->a == FBIT(f)) return r->types;
    }
    return 0;
}

/* Which types carry field `f`, in words, from the rules. */
static void carried_by(char *out, size_t cap, int f) {
    const unsigned on = allowed_on(f), req = required_on(f);
    char ty[128];
    if (req == T_ALL) {
        snprintf(out, cap, "every entry");
    } else if (req != 0) {
        if (on & ~req) abort();     /* required on some types, optional on others: say how */
        type_names(ty, sizeof ty, req, "`, `");
        snprintf(out, cap, "every `%s`", ty);
    } else if (on == T_ALL) {
        snprintf(out, cap, "any type");
    } else {
        type_names(ty, sizeof ty, on, "`, `");
        snprintf(out, cap, "`%s`", ty);
    }
}

static void entries_block(void) {
    printf("| field | kind | carried by | meaning |\n|---|---|---|---|\n");
    for (int f = 0; f < F_COUNT; f++) {
        const struct entry_field_def *d = &ENTRY_FIELDS[f];
        char by[160];
        if (strchr(d->description, '|') != NULL || strchr(d->description, '\n') != NULL)
            abort();                /* would break the table row */
        carried_by(by, sizeof by, f);
        printf("| `%s`%s%s%s | %s | %s | %s |\n", d->name, d->alt ? " / `" : "",
               d->alt ? d->alt : "", d->alt ? "`" : "", d->kind, by, d->description);
    }
}

/* A header or trailer table: field, kind, meaning. */
static void line_table(const struct line_field_def *d, size_t n) {
    printf("| field | kind | meaning |\n|---|---|---|\n");
    for (size_t i = 0; i < n; i++) {
        if (strchr(d[i].description, '|') != NULL) abort();
        printf("| `%s`%s%s%s | %s | %s |\n", d[i].name, d[i].alt ? " / `" : "",
               d[i].alt ? d[i].alt : "", d[i].alt ? "`" : "", d[i].kind, d[i].description);
    }
}
static void header_block(void) { line_table(HEADER_FIELDS, H_COUNT); }
static void trailer_block(void) { line_table(TRAILER_FIELDS, TR_COUNT); }

/* "`a`, `b`|`b_b64`, ..." for a header or trailer key order. */
static void line_order(char *buf, size_t cap, const struct line_field_def *d, size_t n) {
    size_t w = 0;
    for (size_t i = 0; i < n; i++)
        w += (size_t)snprintf(buf + w, cap - w, "%s`%s`%s%s%s", i ? ", " : "", d[i].name,
                              d[i].alt ? "|`" : "", d[i].alt ? d[i].alt : "", d[i].alt ? "`" : "");
    snprintf(buf + w, cap - w, ".");
}

static void schema_block(void) {
    char buf[1024];
    size_t n = 0;

    for (int f = 0; f < F_COUNT; f++) {
        const struct entry_field_def *d = &ENTRY_FIELDS[f];
        n += (size_t)snprintf(buf + n, sizeof buf - n, "%s`%s`%s%s%s", f ? ", " : "", d->name,
                              d->alt ? "|`" : "", d->alt ? d->alt : "", d->alt ? "`" : "");
    }
    n += (size_t)snprintf(buf + n, sizeof buf - n, ".");
    wrap("- ", "**Entry fields appear in one fixed order**, optional ones omitted, never "
         "reordered (`a`|`b`: one spelling or the other, never both):", 2);
    wrap("  ", buf, 2);
    line_order(buf, sizeof buf, HEADER_FIELDS, H_COUNT);
    wrap("- ", "**Header fields, in order:**", 2);
    wrap("  ", buf, 2);
    line_order(buf, sizeof buf, TRAILER_FIELDS, TR_COUNT);
    wrap("- ", "**Trailer fields, in order:**", 2);
    wrap("  ", buf, 2);

    n = 0;
    for (int t = 0; t < ENTRY_TYPE_COUNT; t++)
        n += (size_t)snprintf(buf + n, sizeof buf - n, "%s`%s` %06o", t ? ", " : "",
                              ENTRY_TYPES[t].name, ENTRY_TYPES[t].ifmt);
    n += (size_t)snprintf(buf + n, sizeof buf - n, ".");
    wrap("- ", "**`type` is one of these, and `mode`'s type bits (`S_IFMT`, octal) match it:**", 2);
    wrap("  ", buf, 2);

    printf("- **Types, fields and flags agree** -- exactly the combinations the writer produces.\n"
           "  A reader applies these rules in this order and reports the first one violated:\n\n");
    for (size_t i = 0; i < ENTRY_RULE_COUNT; i++) {
        char lead[32];
        snprintf(lead, sizeof lead, "  %zu. ", i + 1);
        wrap(lead, ENTRY_RULES[i].doc, (int)strlen(lead));
    }
    printf("- **What the header determines, holds**, checked after the rules above:\n\n");
    for (size_t i = 0; i < ENTRY_HEADER_RULE_COUNT; i++) {
        char lead[32];
        snprintf(lead, sizeof lead, "  %zu. ", i + 1);
        wrap(lead, ENTRY_HEADER_RULES[i].doc, (int)strlen(lead));
    }
}

/* ---- diff.v1 (src/schema/diff_schema.c) ---- */

static void names_table(const struct diff_name_def *d, size_t first, size_t n) {
    printf("| name | meaning |\n|---|---|\n");
    for (size_t i = first; i < n; i++) {
        if (strchr(d[i].description, '|') != NULL) abort();
        printf("| `%s` | %s |\n", d[i].name, d[i].description);
    }
}
static void diff_outcomes_block(void) { names_table(DIFF_OUTCOMES, D_FIRST, D_OUTCOME_COUNT); }
static void diff_reasons_block(void) { names_table(DIFF_REASONS, DR_FIRST, DR_COUNT); }
static void diff_header_block(void) { line_table(DIFF_HEADER_FIELDS, DH_COUNT); }
static void diff_record_block(void) { line_table(DIFF_RECORD_FIELDS, DF_COUNT); }
static void diff_trailer_block(void) {
    struct line_field_def t[1 + D_OUTCOME_COUNT + DT_COUNT];
    char doc[D_OUTCOME_COUNT][96];
    size_t n = 0;
    t[n++] = DIFF_TRAILER_END;
    for (size_t i = D_FIRST; i < D_OUTCOME_COUNT; i++) {
        snprintf(doc[i], sizeof doc[i], "Paths whose outcome is `%s`.", DIFF_OUTCOMES[i].name);
        t[n++] = (struct line_field_def){ DIFF_OUTCOMES[i].name, NULL, "int", doc[i] };
    }
    for (size_t i = 0; i < DT_COUNT; i++) t[n++] = DIFF_TRAILER_FIELDS[i];
    line_table(t, n);
}

static const char *const CLASS_NAMES[] = {
    [CC_UNSET] = NULL,                  /* refused before anything is generated */
    [CC_KEY] = "key", [CC_TYPE] = "type", [CC_CONTENT] = "content", [CC_METADATA] = "metadata",
    [CC_IDENTITY] = "identity", [CC_DEVICE] = "identity: device relation",
    [CC_INODE] = "identity: within one device", [CC_CTIME] = "ctime", [CC_FLAG] = "flag",
    [CC_INFO] = "not compared",
};
static const char *const MOUNT_NAMES[] = {
    [MR_UNSET] = NULL, [MR_COMPARED] = "compared", [MR_NOT_COMPARED] = "not compared",
};
static const char *const ABSENT_NAMES[] = {
    [AM_UNSET] = NULL, [AM_REQUIRED] = "required", [AM_FLAG] = "flag", [AM_NONE] = "none",
    [AM_NONE_IF_READ] = "none if read", [AM_UNKNOWN] = "unknown",
    [AM_WITH_UNVERIFIED] = "with unverified", [AM_ONLY_ON_TYPES] = "only on its types",
    [AM_NA] = "n/a",
};
static const char *const SCOPE_NAMES[] = {
    [US_UNSET] = NULL, [US_NONE] = "", [US_CONTENT] = "content", [US_METADATA] = "metadata",
    [US_ALL] = "everything",
};
static void diff_fields_block(void) {
    printf("| field | class | for types | on mount roots | absent means | makes unknown | why |\n"
           "|---|---|---|---|---|---|---|\n");
    for (int f = 0; f < F_COUNT; f++) {
        const struct field_change *c = &DIFF_FIELDS[f];
        char ty[128];
        type_names(ty, sizeof ty, c->types, ", ");
        if (strchr(c->why, '|') != NULL) abort();
        printf("| `%s` | %s | %s | %s | %s | %s | %s |\n", ENTRY_FIELDS[f].name,
               CLASS_NAMES[c->cls],
               c->cls == CC_FLAG || c->cls == CC_INFO || c->cls == CC_KEY ? "" : ty,
               MOUNT_NAMES[c->mount_roots], ABSENT_NAMES[c->absent], SCOPE_NAMES[c->unknown],
               c->why);
    }
}

/* ---- findings and events (src/schema/finding_schema.c) ---- */

static void diff_findings_block(void) {
    static const char *const T[] = { [FT_UNSET] = NULL, [FT_INT] = "int", [FT_STRING] = "string",
                                     [FT_BOOL] = "bool" };
    printf("| kind | interpreter | level | fields | text | meaning |\n|---|---|---|---|---|---|\n");
    for (int k = FK_UNSET + 1; k < FK_COUNT; k++) {
        const struct finding_kind_def *d = &FINDING_KINDS[k];
        char in[128] = "", fl[256] = "";
        size_t w = 0;
        if (d->interps == IN_ANY) snprintf(in, sizeof in, "any");
        else
            for (int i = 0; i < BELAY_INTERP_COUNT; i++)
                if (d->interps & (1u << i))
                    w += (size_t)snprintf(in + w, sizeof in - w, "%s%s", w ? ", " : "",
                                          belay_interp_name((enum belay_interp_id)i));
        w = 0;
        for (int f = 0; f < FINDING_FIELDS_MAX && d->field[f].name; f++) {
            if (T[d->field[f].type] == NULL) abort();
            w += (size_t)snprintf(fl + w, sizeof fl - w, "%s%s: %s", w ? ", " : "", d->field[f].name,
                                  T[d->field[f].type]);
        }
        if (strchr(d->meaning, '|') != NULL || strchr(d->text, '|') != NULL) abort();
        printf("| `%s` | %s | %s | %s | `%s` | %s |\n", d->name, in,
               d->levels == (LV_PATH | LV_EVENT) ? "path, event" : d->levels == LV_EVENT ? "event" : "path",
               w ? fl : "--", d->text, d->meaning);
    }
}

static void diff_events_block(void) {
    printf("| rule | statement |\n|---|---|\n");
    for (int i = 0; i < EVENT_RULE_COUNT; i++) {
        if (strchr(EVENT_RULES[i].statement, '|') != NULL) abort();
        printf("| %s | %s |\n", EVENT_RULES[i].id, EVENT_RULES[i].statement);
    }
}

/* Every generated block, and the spec file it belongs in: each file must
 * hold each of its blocks exactly once. */
static const struct {
    const char *name;
    const char *file;           /* basename of the spec */
    const char *source;
    void (*emit)(void);
} BLOCKS[] = {
    { "entries", "manifest-v1.md", "src/schema/entry.c", entries_block },
    { "header", "manifest-v1.md", "src/schema/entry.c", header_block },
    { "trailer", "manifest-v1.md", "src/schema/entry.c", trailer_block },
    { "schema", "manifest-v1.md", "src/schema/entry.c", schema_block },
    { "diff-header", "diff-v1.md", "src/schema/diff_schema.c", diff_header_block },
    { "diff-record", "diff-v1.md", "src/schema/diff_schema.c", diff_record_block },
    { "diff-trailer", "diff-v1.md", "src/schema/diff_schema.c", diff_trailer_block },
    { "diff-outcomes", "diff-v1.md", "src/schema/diff_schema.c", diff_outcomes_block },
    { "diff-reasons", "diff-v1.md", "src/schema/diff_schema.c", diff_reasons_block },
    { "diff-fields", "diff-v1.md", "src/schema/diff_schema.c", diff_fields_block },
    { "diff-findings", "diff-v1.md", "src/schema/finding_schema.c", diff_findings_block },
    { "diff-events", "diff-v1.md", "src/schema/finding_schema.c", diff_events_block },
};
#define NBLOCKS (sizeof BLOCKS / sizeof BLOCKS[0])

/* The block a marker line names, or -1. */
static int marker(const char *line, const char *mark) {
    if (strncmp(line, mark, strlen(mark)) != 0) return -1;
    const char *name = line + strlen(mark);
    for (size_t i = 0; i < NBLOCKS; i++) {
        const size_t len = strlen(BLOCKS[i].name);
        if (strncmp(name, BLOCKS[i].name, len) == 0 &&
            strncmp(name + len, MARK_TAIL, strlen(MARK_TAIL)) == 0)
            return (int)i;
    }
    return -1;
}

/* Copies `path` to stdout with every block regenerated. Each block must
 * appear exactly once, so a lost marker is an error, not a silent no-op. */
static int spec(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) { perror(path); return 1; }
    char line[4096];
    int inside = -1, seen[NBLOCKS] = { 0 }, bad = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        int b;
        if (inside == -1 && (b = marker(line, BEGIN_MARK)) != -1) {
            fputs(line, stdout);
            printf("<!-- From %s by tools/gen_schema.c. Edit there, then `make gen`. -->\n\n",
                   BLOCKS[b].source);
            BLOCKS[b].emit();
            seen[b]++;
            inside = b;
        } else if (inside != -1) {
            if (marker(line, END_MARK) == inside) {
                fputs(line, stdout);
                inside = -1;
            }
        } else {
            fputs(line, stdout);
        }
    }
    fclose(f);
    if (inside != -1) {
        fprintf(stderr, "%s: block \"%s\" has no end marker\n", path, BLOCKS[inside].name);
        return 1;
    }
    const char *base = strrchr(path, '/') ? strrchr(path, '/') + 1 : path;
    for (size_t i = 0; i < NBLOCKS; i++) {
        const int want = strcmp(BLOCKS[i].file, base) == 0;
        if (seen[i] != want) {
            fprintf(stderr, "%s: block \"%s\" appears %d times, want %d\n", path,
                    BLOCKS[i].name, seen[i], want);
            bad = 1;
        }
    }
    return bad;
}

/* Every cell of every table explicit (audit 2026-10, R1): a missing row or a
 * short one compiles to zeros, and zero is a sentinel nothing may generate
 * from. Checked here independently of test/test_schema.c. */
static int tables_complete(void) {
    int bad = 0;
#define REFUSE(...) do { fprintf(stderr, "gen_schema: " __VA_ARGS__); fputc('\n', stderr); bad = 1; } while (0)
    for (int f = 0; f < F_COUNT; f++) {
        const struct entry_field_def *d = &ENTRY_FIELDS[f];
        if (d->name == NULL || d->kind == NULL || d->description == NULL)
            REFUSE("ENTRY_FIELDS[%d] is incomplete", f);
        const struct field_change *c = &DIFF_FIELDS[f];
        const char *n = d->name ? d->name : "?";
        if (c->cls == CC_UNSET) REFUSE("DIFF_FIELDS[%s]: class unset", n);
        if (c->unknown == US_UNSET) REFUSE("DIFF_FIELDS[%s]: unknown scope unset", n);
        if (c->reason == DR_UNSET) REFUSE("DIFF_FIELDS[%s]: reason unset", n);
        if (c->why == NULL) REFUSE("DIFF_FIELDS[%s]: no description", n);
        if (c->mount_roots == MR_UNSET) REFUSE("DIFF_FIELDS[%s]: mount-root cell unset", n);
        if (c->absent == AM_UNSET) REFUSE("DIFF_FIELDS[%s]: absent-means cell unset", n);
        if (c->cls == CC_FLAG && (c->unknown == US_NONE || c->reason < DR_FIRST))
            REFUSE("DIFF_FIELDS[%s]: a flag needs a scope and a reason", n);
        if (c->cls != CC_FLAG && (c->unknown != US_NONE || c->reason != DR_NONE))
            REFUSE("DIFF_FIELDS[%s]: only a flag has a scope and a reason", n);
        if (c->types == 0) REFUSE("DIFF_FIELDS[%s]: no types", n);
    }
    for (size_t i = 0; i < ENTRY_RULE_COUNT; i++) {
        const struct entry_rule *r = &ENTRY_RULES[i];
        if (r->kind == R_UNSET) REFUSE("ENTRY_RULES[%zu]: kind unset", i);
        if (r->types == 0) REFUSE("ENTRY_RULES[%zu]: applies to no type", i);
        if (r->kind == R_CHECK ? r->check == NULL : r->a == 0) REFUSE("ENTRY_RULES[%zu]: empty", i);
        if (r->msg == NULL || r->doc == NULL) REFUSE("ENTRY_RULES[%zu]: no message or doc", i);
        if ((r->kind == R_EXACTLY_ONE || r->kind == R_PRESENT_IFF) && r->msg2 == NULL)
            REFUSE("ENTRY_RULES[%zu]: no second message", i);
    }
    for (int i = D_FIRST; i < D_OUTCOME_COUNT; i++)
        if (DIFF_OUTCOMES[i].name == NULL || DIFF_OUTCOMES[i].description == NULL)
            REFUSE("DIFF_OUTCOMES[%d] is incomplete", i);
    for (int i = DR_FIRST; i < DR_COUNT; i++)
        if (DIFF_REASONS[i].name == NULL || DIFF_REASONS[i].description == NULL)
            REFUSE("DIFF_REASONS[%d] is incomplete", i);
    for (int i = 0; i < H_COUNT; i++)
        if (HEADER_FIELDS[i].name == NULL) REFUSE("HEADER_FIELDS[%d] is incomplete", i);
    for (int i = 0; i < TR_COUNT; i++)
        if (TRAILER_FIELDS[i].name == NULL) REFUSE("TRAILER_FIELDS[%d] is incomplete", i);
#undef REFUSE
    return !bad;
}

int main(int argc, char **argv) {
    if (!tables_complete()) return 1;
    if (argc == 3 && strcmp(argv[1], "spec") == 0) return spec(argv[2]);
    fprintf(stderr, "usage: gen_schema spec <file>\n");
    return 2;
}
