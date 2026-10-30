/*
 *  Generates, from the entry schema (src/schema/entry.c), the two artifacts
 *  that would otherwise restate it by hand:
 *
 *    gen_schema spec <file>   <file> with each generated block replaced
 *                             (docs/spec/manifest-v1.md): "entries", the
 *                             Entries table; "schema", the field order, the
 *                             types and the rules
 *    gen_schema fuzz          the fuzz target's schema invariants, as
 *                             straight-line checks (test/fuzz/fuzz_invariants.gen.h)
 *
 *  Output goes to stdout. `make gen` writes it in place; `make gen-check`
 *  (part of `make check`) fails when a committed artifact is stale.
 */
#include "schema/entry.h"
#include "schema/diff_schema.h"

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

static void field_names(char *out, size_t cap, uint32_t mask, const char *sep) {
    size_t n = 0;
    out[0] = '\0';
    for (int f = 0; f < F_COUNT; f++) {
        if (!(mask & FBIT(f))) continue;
        n += (size_t)snprintf(out + n, cap - n, "%s%s", n ? sep : "", ENTRY_FIELDS[f].name);
        if (n >= cap) abort();
    }
}

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

static void names_table(const struct diff_name_def *d, size_t n) {
    printf("| name | meaning |\n|---|---|\n");
    for (size_t i = 0; i < n; i++) {
        if (strchr(d[i].description, '|') != NULL) abort();
        printf("| `%s` | %s |\n", d[i].name, d[i].description);
    }
}
static void diff_outcomes_block(void) { names_table(DIFF_OUTCOMES, D_OUTCOME_COUNT); }
static void diff_reasons_block(void) { names_table(DIFF_REASONS, DR_COUNT); }
static void diff_header_block(void) { line_table(DIFF_HEADER_FIELDS, DH_COUNT); }
static void diff_record_block(void) { line_table(DIFF_RECORD_FIELDS, DF_COUNT); }
static void diff_trailer_block(void) {
    struct line_field_def t[1 + D_OUTCOME_COUNT];
    char doc[D_OUTCOME_COUNT][96];
    t[0] = DIFF_TRAILER_END;
    for (size_t i = 0; i < D_OUTCOME_COUNT; i++) {
        snprintf(doc[i], sizeof doc[i], "Paths whose outcome is `%s`.", DIFF_OUTCOMES[i].name);
        t[1 + i] = (struct line_field_def){ DIFF_OUTCOMES[i].name, NULL, "int", doc[i] };
    }
    line_table(t, 1 + D_OUTCOME_COUNT);
}

static const char *const CLASS_NAMES[] = {
    [CC_KEY] = "key", [CC_TYPE] = "type", [CC_CONTENT] = "content", [CC_METADATA] = "metadata",
    [CC_IDENTITY] = "identity", [CC_CTIME] = "ctime", [CC_FLAG] = "flag", [CC_INFO] = "not compared",
};
static const char *const SCOPE_NAMES[] = {
    [US_NONE] = "", [US_CONTENT] = "content", [US_METADATA] = "metadata", [US_ALL] = "everything",
};
static void diff_fields_block(void) {
    printf("| field | class | for types | makes unknown | why |\n|---|---|---|---|---|\n");
    for (int f = 0; f < F_COUNT; f++) {
        const struct field_change *c = &DIFF_FIELDS[f];
        char ty[128];
        type_names(ty, sizeof ty, c->types, ", ");
        if (strchr(c->why, '|') != NULL) abort();
        printf("| `%s` | %s | %s | %s | %s |\n", ENTRY_FIELDS[f].name, CLASS_NAMES[c->cls],
               c->cls == CC_FLAG || c->cls == CC_INFO || c->cls == CC_KEY ? "" : ty,
               SCOPE_NAMES[c->unknown], c->why);
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

/* ------------------------------------------------------------------------ */
/* Fuzz invariants                                                           */
/* ------------------------------------------------------------------------ */

static int fuzz(void) {
    char a[512], b[512], ty[128];
    printf("/* GENERATED from src/schema/entry.c by tools/gen_schema.c. Do not edit:\n"
           " * change the schema, then `make gen`. */\n"
           "#ifndef BELAY_FUZZ_INVARIANTS_GEN_H\n"
           "#define BELAY_FUZZ_INVARIANTS_GEN_H\n\n"
           "#include \"schema/entry.h\"\n\n"
           "#include <stdlib.h>\n\n"
           "/* Aborts unless `e`, as the reader delivered it under header `h`, obeys\n"
           " * every schema rule. Fields present are recomputed from the decoded entry\n"
           " * (entry_present), not from the keys the reader saw; each rule is\n"
           " * expanded here rather than interpreted by entry.c's rule engine. */\n"
           "static void schema_invariants(const struct belay_manifest_header *h,\n"
           "                              const struct belay_entry *e) {\n"
           "    if (F_COUNT != %d || ENTRY_RULE_COUNT != %zu || ENTRY_HEADER_RULE_COUNT != %zu)\n"
           "        abort();                /* the schema changed: `make gen` */\n"
           "    if ((unsigned)e->type >= ENTRY_TYPE_COUNT) abort();\n"
           "    const uint32_t p = entry_present(e);\n"
           "    const unsigned t = TBIT(e->type);\n",
           F_COUNT, ENTRY_RULE_COUNT, ENTRY_HEADER_RULE_COUNT);
    for (size_t i = 0; i < ENTRY_RULE_COUNT; i++) {
        const struct entry_rule *r = &ENTRY_RULES[i];
        field_names(a, sizeof a, r->a, ", ");
        field_names(b, sizeof b, r->b, ", ");
        type_names(ty, sizeof ty, r->types, ", ");
        if (strstr(r->doc, "*/") != NULL) abort();
        printf("\n    /* %zu. %s */\n", i + 1, r->doc);
        const char *on = "(t & 0x%02xu)";
        char applies[32];
        snprintf(applies, sizeof applies, on, r->types);
        switch (r->kind) {
        case R_FORBID:
            printf("    if (%s && (p & 0x%07xu)) abort();  /* on %s: never %s */\n",
                   applies, r->a, ty, a);
            break;
        case R_IMPLIES:
            printf("    if (%s && (p & 0x%07xu) && !(p & 0x%07xu)) abort();  /* on %s: %s needs %s */\n",
                   applies, r->a, r->b, ty, a, b);
            break;
        case R_EXCLUSIVE:
            printf("    if (%s && __builtin_popcount(p & 0x%07xu) > 1) abort();  /* on %s: at most one of %s */\n",
                   applies, r->a, ty, a);
            break;
        case R_EXACTLY_ONE:
            printf("    if (%s && __builtin_popcount(p & 0x%07xu) != 1) abort();  /* on %s: exactly one of %s */\n",
                   applies, r->a, ty, a);
            break;
        case R_EXCLUDES:
            printf("    if (%s && (p & 0x%07xu) && (p & 0x%07xu)) abort();  /* on %s: %s excludes %s */\n",
                   applies, r->a, r->b, ty, a, b);
            break;
        case R_PRESENT_IFF:
            printf("    if (!%s != !(p & 0x%07xu)) abort();  /* %s exactly on %s */\n",
                   applies, r->a, a, ty);
            break;
        case R_CHECK:
            printf("    if (%s && ENTRY_RULES[%zu].check(e)) abort();  /* on %s */\n",
                   applies, i, ty);
            break;
        }
    }
    for (size_t i = 0; i < ENTRY_HEADER_RULE_COUNT; i++) {
        printf("\n    /* Header rule %zu (spec: \"What the header determines, holds\"). */\n"
               "    if (ENTRY_HEADER_RULES[%zu].check(h, e) != NULL) abort();\n", i + 1, i);
    }
    printf("}\n\n#endif\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "spec") == 0) return spec(argv[2]);
    if (argc == 2 && strcmp(argv[1], "fuzz") == 0) return fuzz();
    fprintf(stderr, "usage: gen_schema spec <file> | gen_schema fuzz\n");
    return 2;
}
