/*
 *  Generates, from the entry schema (src/capture/entry.c), the two artifacts
 *  that would otherwise restate it by hand:
 *
 *    gen_schema spec <file>   <file> with the block between the markers
 *                             replaced by the field order, the field/type
 *                             table and the rules (docs/spec/manifest-v1.md)
 *    gen_schema fuzz          the fuzz target's schema invariants, as
 *                             straight-line checks (test/fuzz/fuzz_invariants.gen.h)
 *
 *  Output goes to stdout. `make gen` writes it in place; `make gen-check`
 *  (part of `make check`) fails when a committed artifact is stale.
 */
#include "capture/entry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BEGIN_MARK "<!-- BEGIN GENERATED: schema -->"
#define END_MARK   "<!-- END GENERATED: schema -->"
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

static void spec_block(void) {
    char buf[1024];
    size_t n = 0;

    printf("%s\n", BEGIN_MARK);
    printf("<!-- From src/capture/entry.c by tools/gen_schema.c. Edit there, then `make gen`. -->\n\n");

    for (int f = 0; f < F_COUNT; f++) {
        const struct entry_field_def *d = &ENTRY_FIELDS[f];
        n += (size_t)snprintf(buf + n, sizeof buf - n, "%s`%s`%s%s%s", f ? ", " : "", d->name,
                              d->alt ? "|`" : "", d->alt ? d->alt : "", d->alt ? "`" : "");
    }
    n += (size_t)snprintf(buf + n, sizeof buf - n, ".");
    wrap("- ", "**Entry fields appear in one fixed order**, optional ones omitted, never "
         "reordered (`a`|`b`: one spelling or the other, never both):", 2);
    wrap("  ", buf, 2);

    printf("- **Which type carries which field.** `●` on every entry of that type, `○` may "
           "appear\n  (subject to the rules below), blank never:\n\n");
    printf("  | field | kind |");
    for (int t = 0; t < ENTRY_TYPE_COUNT; t++) printf(" `%s` |", ENTRY_TYPES[t].name);
    printf(" meaning |\n  |---|---|");
    for (int t = 0; t < ENTRY_TYPE_COUNT; t++) printf(":-:|");
    printf("---|\n");
    for (int f = 0; f < F_COUNT; f++) {
        const struct entry_field_def *d = &ENTRY_FIELDS[f];
        const unsigned on = allowed_on(f), req = required_on(f);
        printf("  | `%s`%s%s%s | %s |", d->name, d->alt ? " / `" : "", d->alt ? d->alt : "",
               d->alt ? "`" : "", d->kind);
        for (int t = 0; t < ENTRY_TYPE_COUNT; t++)
            printf(" %s |", (req & TBIT(t)) ? "●" : (on & TBIT(t)) ? "○" : "");
        printf(" %s |\n", d->doc);
    }
    n = 0;
    for (int t = 0; t < ENTRY_TYPE_COUNT; t++)
        n += (size_t)snprintf(buf + n, sizeof buf - n, "%s`%s` %06o", t ? ", " : "",
                              ENTRY_TYPES[t].name, ENTRY_TYPES[t].ifmt);
    n += (size_t)snprintf(buf + n, sizeof buf - n, ".");
    printf("\n");
    wrap("  ", "`type`, and the type bits of `mode` (`S_IFMT`, octal) that go with it:", 2);
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
    printf("%s\n", END_MARK);
}

static int spec(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) { perror(path); return 1; }
    char line[4096];
    int state = 0;              /* 0 before, 1 inside, 2 after the block */
    while (fgets(line, sizeof line, f) != NULL) {
        if (state == 0 && strncmp(line, BEGIN_MARK, strlen(BEGIN_MARK)) == 0) {
            spec_block();
            state = 1;
        } else if (state == 1) {
            if (strncmp(line, END_MARK, strlen(END_MARK)) == 0) state = 2;
        } else {
            fputs(line, stdout);
        }
    }
    fclose(f);
    if (state != 2) {
        fprintf(stderr, "%s: no complete %s ... %s block\n", path, BEGIN_MARK, END_MARK);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Fuzz invariants                                                           */
/* ------------------------------------------------------------------------ */

static int fuzz(void) {
    char a[512], b[512], ty[128];
    printf("/* GENERATED from src/capture/entry.c by tools/gen_schema.c. Do not edit:\n"
           " * change the schema, then `make gen`. */\n"
           "#ifndef BELAY_FUZZ_INVARIANTS_GEN_H\n"
           "#define BELAY_FUZZ_INVARIANTS_GEN_H\n\n"
           "#include \"capture/entry.h\"\n\n"
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
