/*
 *  Every cell of every schema table is explicit (audit 2026-10, R1).
 *
 *  A missing row, or a short designated one ([F_X] = { CC_FLAG, T_ALL }),
 *  compiles silently to zeros -- -Wmissing-field-initializers does not cover
 *  designated initializers -- and zero is a sentinel in every enum column
 *  here, so these tests find it. They are written independently of
 *  tools/gen_schema.c, which refuses the same tables on its own.
 */
#include "belay_test.h"
#include "schema/entry.h"
#include "schema/diff_schema.h"
#include "capture/outcome.h"
#include "diff/ancestry.h"

/* Zero is "missing" in each of these enums; reordering one would turn a
 * missing cell back into a real value. */
TEST(zero_is_the_missing_value_in_every_enum) {
    ASSERT_EQ_INT(0, CC_UNSET);
    ASSERT_EQ_INT(0, US_UNSET);
    ASSERT_EQ_INT(0, DR_UNSET);
    ASSERT_EQ_INT(0, D_UNDECIDED);
    ASSERT_EQ_INT(0, ANC_UNSET);
    ASSERT_EQ_INT(0, R_UNSET);
    ASSERT_TRUE(D_FIRST > D_UNDECIDED);
    ASSERT_TRUE(DR_FIRST > DR_NONE && DR_NONE > DR_UNSET);
}

TEST(every_entry_field_row_is_complete) {
    for (int f = 0; f < F_COUNT; f++) {
        const struct entry_field_def *d = &ENTRY_FIELDS[f];
        ASSERT_TRUE(d->name != NULL);
        ASSERT_TRUE(d->description != NULL);
        ASSERT_TRUE(d->kind != NULL && (strcmp(d->kind, "string") == 0 || strcmp(d->kind, "int") == 0 ||
                                        strcmp(d->kind, "bool") == 0 || strcmp(d->kind, "array") == 0));
    }
    for (int t = 0; t < ENTRY_TYPE_COUNT; t++) {
        ASSERT_TRUE(ENTRY_TYPES[t].name != NULL);
        ASSERT_TRUE(ENTRY_TYPES[t].ifmt != 0);
    }
}

TEST(every_entry_rule_row_is_complete) {
    for (size_t i = 0; i < ENTRY_RULE_COUNT; i++) {
        const struct entry_rule *r = &ENTRY_RULES[i];
        if (r->kind == R_UNSET) BELAY_FAIL("rule %zu: kind unset", i + 1);
        if (r->types == 0) BELAY_FAIL("rule %zu: applies to no type", i + 1);
        if (r->kind == R_CHECK ? r->check == NULL : r->a == 0) BELAY_FAIL("rule %zu: empty", i + 1);
        if (r->msg == NULL || r->doc == NULL) BELAY_FAIL("rule %zu: no message or doc", i + 1);
        if ((r->kind == R_EXACTLY_ONE || r->kind == R_PRESENT_IFF) && r->msg2 == NULL)
            BELAY_FAIL("rule %zu: no second message", i + 1);
    }
    for (size_t i = 0; i < ENTRY_HEADER_RULE_COUNT; i++) {
        ASSERT_TRUE(ENTRY_HEADER_RULES[i].check != NULL);
        ASSERT_TRUE(ENTRY_HEADER_RULES[i].doc != NULL);
    }
}

TEST(every_header_and_trailer_row_is_complete) {
    for (int i = 0; i < H_COUNT; i++) ASSERT_TRUE(HEADER_FIELDS[i].name != NULL && HEADER_FIELDS[i].kind != NULL);
    for (int i = 0; i < TR_COUNT; i++) ASSERT_TRUE(TRAILER_FIELDS[i].name != NULL && TRAILER_FIELDS[i].kind != NULL);
    for (int i = 0; i < DH_COUNT; i++) ASSERT_TRUE(DIFF_HEADER_FIELDS[i].name != NULL);
    for (int i = 0; i < DF_COUNT; i++) ASSERT_TRUE(DIFF_RECORD_FIELDS[i].name != NULL);
    ASSERT_TRUE(DIFF_TRAILER_END.name != NULL);
}

TEST(every_diff_field_cell_is_set) {
    for (int f = 0; f < F_COUNT; f++) {
        const struct field_change *c = &DIFF_FIELDS[f];
        const char *n = ENTRY_FIELDS[f].name;
        if (c->cls == CC_UNSET) BELAY_FAIL("%s: class unset", n);
        if (c->unknown == US_UNSET) BELAY_FAIL("%s: unknown scope unset", n);
        if (c->reason == DR_UNSET) BELAY_FAIL("%s: reason unset", n);
        if (c->why == NULL) BELAY_FAIL("%s: no description", n);
        if (c->types == 0) BELAY_FAIL("%s: no types", n);
        if (c->cls == CC_FLAG && (c->unknown == US_NONE || c->reason < DR_FIRST))
            BELAY_FAIL("%s: a flag needs a scope and a reason", n);
        if (c->cls != CC_FLAG && (c->unknown != US_NONE || c->reason != DR_NONE))
            BELAY_FAIL("%s: only a flag has a scope and a reason", n);
    }
}

TEST(every_outcome_and_reason_has_a_name) {
    ASSERT_TRUE(DIFF_OUTCOMES[D_UNDECIDED].name == NULL);        /* never written */
    for (int i = D_FIRST; i < D_OUTCOME_COUNT; i++)
        ASSERT_TRUE(DIFF_OUTCOMES[i].name != NULL && DIFF_OUTCOMES[i].description != NULL);
    ASSERT_TRUE(DIFF_REASONS[DR_UNSET].name == NULL && DIFF_REASONS[DR_NONE].name == NULL);
    for (int i = DR_FIRST; i < DR_COUNT; i++)
        ASSERT_TRUE(DIFF_REASONS[i].name != NULL && DIFF_REASONS[i].description != NULL);
}

/* Every cell is either defined or explicitly nothing; the cells the capture
 * applies (enumerated from every outcome_apply call, audit 2026-10) are
 * defined, so none of them can record nothing by accident. */
TEST(every_effect_cell_the_capture_applies_is_defined) {
    for (int f = 0; f < FACET_N; f++)
        for (int o = 0; o < OUT_N; o++) {
            const unsigned x = OUTCOME_EFFECT[f][o];
            if (x != 0 && !(x & EFF_DEFINED)) BELAY_FAIL("cell [%d][%d] has effects but is not defined", f, o);
        }
    static const int used[][2] = {
        { FACET_CONTENT, OUT_CHANGED }, { FACET_CONTENT, OUT_DENIED }, { FACET_CONTENT, OUT_TOO_LARGE },
        { FACET_LISTING, OUT_CHANGED }, { FACET_LISTING, OUT_DENIED }, { FACET_LISTING, OUT_GONE },
        { FACET_TARGET, OUT_DENIED }, { FACET_TARGET, OUT_CHANGED },
        { FACET_ENTRY, OUT_GONE }, { FACET_ENTRY, OUT_BOUNDARY }, { FACET_ENTRY, OUT_CHANGED },
        { FACET_EXTRAS, OUT_DENIED },
    };
    for (size_t i = 0; i < sizeof used / sizeof used[0]; i++)
        if (!(OUTCOME_EFFECT[used[i][0]][used[i][1]] & EFF_DEFINED))
            BELAY_FAIL("cell [%d][%d] is applied by capture but not defined", used[i][0], used[i][1]);
    for (int f = 0; f < FACET_N; f++) ASSERT_TRUE(OUTCOME_EFFECT[f][OUT_OK] & EFF_DEFINED);
}

/* Applying a cell nothing defines is counted, never silently ignored. */
TEST(an_undefined_effect_is_counted_not_ignored) {
    struct walk_tally t = { 0, 0 };
    struct belay_entry e;
    memset(&e, 0, sizeof e);
    outcome_apply(&e, FACET_EXTRAS, OUT_BOUNDARY, &t);      /* no such combination */
    ASSERT_EQ_INT(1, (int)t.invalid);
    outcome_apply(&e, FACET_LISTING, OUT_CHANGED, &t);
    ASSERT_EQ_INT(1, (int)t.invalid);
    ASSERT_TRUE(e.unstable);
}

int main(void) {
    RUN(zero_is_the_missing_value_in_every_enum);
    RUN(every_entry_field_row_is_complete);
    RUN(every_entry_rule_row_is_complete);
    RUN(every_header_and_trailer_row_is_complete);
    RUN(every_diff_field_cell_is_set);
    RUN(every_outcome_and_reason_has_a_name);
    RUN(every_effect_cell_the_capture_applies_is_defined);
    RUN(an_undefined_effect_is_counted_not_ignored);
    return belay_test_report();
}
