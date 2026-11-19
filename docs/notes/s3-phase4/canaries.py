# S3, Phase 4: a canary per finding kind and per rule of the findings core.
# Each: the edit, the test binary, the named test that must FAIL on an assertion.
I = 'test_interpreters'; F = 'test_findings'; D = 'test_diff'; P = 'test_pins'; T = 'test_interp'
C = lambda id, f, old, new, b, t: dict(id=id, edits=[(f, old, new)], bin=b, test=t)
CANARIES = [
 # ---- the findings core ----
 C('K1 interp mask', 'src/interp/findings.c', "!(d->interps & (1u << interp))", "false", F, 'a_finding_that_breaks_its_row_is_invalid_finding'),
 C('K2 level', 'src/interp/findings.c', "!(d->levels & level)", "false", F, 'a_finding_that_breaks_its_row_is_invalid_finding'),
 C('K3 field count', 'src/interp/findings.c', "if (n != finding_nfields((enum finding_kind)kind)) return false;", "if (n > finding_nfields((enum finding_kind)kind)) return false;", F, 'a_finding_that_breaks_its_row_is_invalid_finding'),
 C('K4 string bound', 'src/interp/findings.c', "return len <= FINDING_STRING_MAX && memchr", "return len < FINDING_STRING_MAX && memchr", F, 'a_finding_that_breaks_its_row_is_invalid_finding'),
 C('K5 NUL', 'src/interp/findings.c', "memchr(s, '\\0', len) == NULL && belay_utf8_valid", "belay_utf8_valid", F, 'a_finding_that_breaks_its_row_is_invalid_finding'),
 C('K6 text bound', 'src/interp/findings.c', "if (w + vl > FINDING_STRING_MAX) return false;", "", F, 'a_finding_that_breaks_its_row_is_invalid_finding'),
 C('K6b text bound off by one', 'src/interp/findings.c', "if (w + vl > FINDING_STRING_MAX) return false;", "if (w + vl >= FINDING_STRING_MAX) return false;", F, 'a_finding_that_breaks_its_row_is_invalid_finding'),
 C('K7 4096 cap', 'src/interp/findings.c', "if (f->n == FINDINGS_PER_RECORD) { f->extra++; return 0; }", "if (f->n == FINDINGS_PER_RECORD + 1) { f->extra++; return 0; }", F, 'past_4096_findings_the_last_is_and_more'),
 C('K8 and_more n', 'src/interp/findings.c', "f->extra + 1, f->extra + 1) < 0)", "f->extra, f->extra) < 0)", F, 'past_4096_findings_the_last_is_and_more'),
 C('K9 events cap n', 'src/interp/findings.c', "INTERP_NAMES[ORDER[k]], p->extra + 1, p->extra + 1) < 0)", "INTERP_NAMES[ORDER[k]], p->extra, p->extra) < 0)", F, 'past_65536_events_the_last_is_and_more'),
 C('K10 paths dedup', 'src/interp/findings.c', "if (i > 0 && pth_cmp(&ps[i], &ps[i - 1]) == 0) continue;", "", F, 'an_event_lists_its_paths_sorted_and_once'),
 C('K11 paths sorted', 'src/interp/findings.c', "    qsort(ps, n, sizeof *ps, pth_cmp);\n", "", F, 'an_event_lists_its_paths_sorted_and_once'),
 C('K12 paths_b64', 'src/interp/findings.c', "b64 |= !belay_utf8_valid", "b64 &= !belay_utf8_valid", F, 'an_event_with_a_non_utf8_path_lists_them_all_in_base64'),
 C('K13 E4 order', 'src/interp/findings.c', "{ BELAY_INTERP_TEXT, BELAY_INTERP_PIP, BELAY_INTERP_DPKG,", "{ BELAY_INTERP_TEXT, BELAY_INTERP_DPKG, BELAY_INTERP_PIP,", F, 'events_are_written_by_interpreter_in_the_pinned_order'),
 C('K14 E6 keeps events', 'src/interp/findings.c', "    p->recs.len = p->last = 0;\n    p->n = p->extra = 0;\n    if (p->nclaimed == 0) return 0;", "    if (p->nclaimed == 0) return 0;", F, 'an_invalid_event_fails_its_interpreter'),
 C('K15 event needs paths', 'src/interp/findings.c', "    bool paths_ok = npaths > 0;", "    bool paths_ok = true;", F, 'an_invalid_event_fails_its_interpreter'),
 C('K16 decline drops findings', 'src/diff/diff.c', "    if (r == BELAY_INTERP_FINDINGS) return 0;\n    findings_reset(&x->findings, id);\n    if (r == BELAY_INTERP_DECLINE) return 0;", "    if (r != BELAY_INTERP_ERROR) return 0;\n    findings_reset(&x->findings, id);", D, 'a_declining_interpreter_adds_nothing'),
 C('K17 error keeps findings', 'src/diff/diff.c', "    if (r == BELAY_INTERP_FINDINGS) return 0;\n    findings_reset(&x->findings, id);", "    if (r == BELAY_INTERP_FINDINGS) return 0;", D, 'an_interpreter_error_is_a_finding_never_a_failed_diff'),
 C('K18 failed end kept', 'src/diff/diff.c', "if ((r == BELAY_INTERP_ERROR || events_broken(&x->events, i)) &&", "if ((events_broken(&x->events, i)) &&", D, 'a_failed_end_hook_is_one_event_naming_its_paths'),
 C('K19 trailer events', 'src/diff/emit.c', "    em->events = events_count(ev);", "    em->events = 0;", D, 'events_come_after_the_path_records_and_the_trailer_counts_them'),
 C('K20 TEXT dispatch', 'src/interp/dispatch.c', "(after != NULL && !after->has_stored))", "false)", T, 'text_is_an_unclaimed_path_stored_on_every_side_it_exists_on'),
 C('K21 pin text', 'src/schema/finding_schema.c', '"hook {hook} added"', '"hook {hook} added!"', P, 'finding_kinds_pin_and_schema_agree_both_ways'),
 C('K22 pin rule', 'src/schema/finding_schema.c', '"has none." },', '"has none" },', P, 'event_rules_pin_and_schema_agree_both_ways'),
 # ---- content_unavailable ----
 C('U1 missing vs corrupt', 'src/interp/stored.c', "return err == ENOENT ? SW_MISSING : SW_CORRUPT;", "return SW_CORRUPT;", I, 'text_says_why_a_copy_cannot_be_read'),
 C('U2 too_large', 'src/interp/stored.c', "if (code == BELAY_ERR_RANGE) return SW_TOO_LARGE;", "if (code == BELAY_ERR_RANGE) return SW_CORRUPT;", I, 'text_says_a_copy_over_its_bound_is_too_large'),
 C('U3 no stored field', 'src/interp/stored.c', "if (e == NULL || !e->has_stored) return SW_MISSING;", "if (e == NULL) return SW_MISSING;", I, 'git_reflog_without_a_copy_is_content_unavailable'),
 C('U4 pip side', 'src/interp/pip.c', 'sides == 1u << SIDE_AFTER ? "after" : "both";', 'sides == 1u << SIDE_AFTER ? "after" : "before";', I, 'pip_record_that_cannot_be_read_is_said_on_the_path_and_as_an_event'),
 C('U5 dpkg event', 'src/interp/dpkg.c', "        if (unavailable_events(d, ev) == -1) r = BELAY_INTERP_ERROR;\n", "", I, 'dpkg_status_that_cannot_be_read_is_never_no_change'),
 C('U6 pip event', 'src/interp/pip.c', "            if (unavailable_events(p, ev) == -1) r = BELAY_INTERP_ERROR;\n", "", I, 'pip_record_that_cannot_be_read_is_said_on_the_path_and_as_an_event'),
 C('U7 dpkg side', 'src/interp/dpkg.c', 'sides == 1u << SIDE_BEFORE ? "before" : sides', 'sides == 1u << SIDE_BEFORE ? "after" : sides', I, 'dpkg_status_that_cannot_be_read_is_never_no_change'),
 # ---- text ----
 C('T1 text_changed fields', 'src/interp/text.c', "{ { .i = d.added }, { .i = d.deleted }, { .i = d.first_changed } }", "{ { .i = d.deleted }, { .i = d.added }, { .i = d.first_changed } }", I, 'text_counts_lines_by_their_longest_common_subsequence'),
 C('T2 text_rewritten', 'src/interp/text.c', "} else if (d.counted) {", "} else if (true) {", I, 'text_past_2000_lines_of_difference_is_rewritten'),
 C('T3 text_added/removed', 'src/interp/text.c', "in->before ? FK_TEXT_REMOVED : FK_TEXT_ADDED", "in->before ? FK_TEXT_ADDED : FK_TEXT_REMOVED", I, 'text_added_and_removed_give_their_line_count'),
 # ---- pip ----
 C('P1 upgraded/downgraded', 'src/interp/pip.c', ": cmp < 0 ? FK_PIP_UPGRADED : FK_PIP_DOWNGRADED;", ": cmp > 0 ? FK_PIP_UPGRADED : FK_PIP_DOWNGRADED;", I, 'pip_installs_removals_and_version_changes_are_events'),
 C('P2 version_changed', 'src/interp/pip.c', "add->version_len, &cmp) == -1 || cmp == 0", "add->version_len, &cmp) == -1", I, 'pip_installs_removals_and_version_changes_are_events'),
 C('P3 installed/removed', 'src/interp/pip.c', "p->d[k].change == C_ADDED ? FK_PIP_INSTALLED : FK_PIP_REMOVED", "p->d[k].change == C_ADDED ? FK_PIP_REMOVED : FK_PIP_INSTALLED", I, 'pip_installs_removals_and_version_changes_are_events'),
 C('P4 PEP 503 case', 'src/interp/pip.c', "out[w++] = c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;", "out[w++] = c;", I, 'pip_pairs_within_one_directory_by_normalized_name'),
 C('P5 reinstalled size', 'src/interp/pip.c', "memcmp(x->hash, y->hash, x->hl) != 0 || x->sl != y->sl ||", "memcmp(x->hash, y->hash, x->hl) != 0 || false ||", I, 'pip_reinstall_counts_files_by_record_row'),
 C('P6 ambiguous', 'src/interp/pip.c', "r = BELAY_INTERP_ERROR;     /* several of one name on a side: no kind says it */", "(void)0;", I, 'pip_what_cannot_be_named_or_paired_fails_the_end_hook'),
 C('P7 directory key', 'src/interp/pip.c', "    if (c == 0) c = str_cmp(x->key, x->key_len, y->key, y->key_len);\n    if (c == 0) c = (int)x->change", "    if (c == 0) c = (int)x->change", I, 'pip_pairs_within_one_directory_by_normalized_name'),
 # ---- dpkg ----
 C('D1 installed word', 'src/interp/dpkg.c', "if (word == 2) return", "if (word == 1) return", I, 'dpkg_status_deltas_are_events_in_package_order'),
 C('D2 up/downgraded', 'src/interp/dpkg.c', "c < 0 ? FK_DPKG_UPGRADED : FK_DPKG_DOWNGRADED", "c > 0 ? FK_DPKG_UPGRADED : FK_DPKG_DOWNGRADED", I, 'dpkg_status_deltas_are_events_in_package_order'),
 C('D3 state_changed covered', 'src/interp/dpkg.c', "if (bi == ai && str_cmp(sx, sy) != 0", "if (str_cmp(sx, sy) != 0", I, 'dpkg_status_deltas_are_events_in_package_order'),
 C('D4 installed/removed', 'src/interp/dpkg.c', "if (!bi && ai && pend(d, FK_DPKG_INSTALLED", "if (!bi && ai && pend(d, FK_DPKG_REMOVED", I, 'dpkg_status_deltas_are_events_in_package_order'),
 C('D5 arch in key', 'src/interp/dpkg.c', "    const int c = str_cmp(x->package, y->package);\n    return c ? c : str_cmp(x->arch, y->arch);", "    return str_cmp(x->package, y->package);", I, 'dpkg_status_deltas_are_events_in_package_order'),
 C('D6 parse failure E6', 'src/interp/dpkg.c', "    if (r == BELAY_INTERP_ERROR) d->failed = true;\n    return r;", "    return r;", I, 'dpkg_status_that_cannot_be_parsed_fails_the_end_hook'),
 # ---- git ----
 C('G1 head from/to', 'src/interp/git.c', "            const struct belay_fv v[] = { FV(from, fl), FV(to, tl) };", "            const struct belay_fv v[] = { FV(to, tl), FV(from, fl) };", I, 'git_head_names_the_symbolic_ref_or_the_commit'),
 C('G2 ref created', 'src/interp/git.c', "if (belay_finding(out, FK_GIT_REF_CREATED, v, 2) == -1) r = BELAY_INTERP_ERROR;\n        } else if (!reg(in, SIDE_AFTER))", "if (belay_finding(out, FK_GIT_REF_DELETED, v, 2) == -1) r = BELAY_INTERP_ERROR;\n        } else if (!reg(in, SIDE_AFTER))", I, 'git_loose_refs_are_created_deleted_and_moved'),
 C('G3 packed moved', 'src/interp/git.c', "if (a->ol != b->ol || memcmp(a->oid, b->oid, a->ol) != 0) {", "if (a->ol != b->ol) {", I, 'git_packed_refs_are_compared_ref_by_ref'),
 C('G4 hook exec', 'src/interp/git.c', "} else if (executable(in->before) != executable(in->after)) {", "} else if (false) {", I, 'git_hooks_are_added_removed_changed_or_made_executable'),
 C('G5 index metadata', 'src/interp/git.c', "if (!content || (!reg(in, SIDE_BEFORE) && !reg(in, SIDE_AFTER))) return BELAY_INTERP_DECLINE;", "if ((!reg(in, SIDE_BEFORE) && !reg(in, SIDE_AFTER))) return BELAY_INTERP_DECLINE;", I, 'git_index_is_changed_and_nothing_more'),
 C('G6 commit (initial)', 'src/interp/git.c', '(e->operation_len == 16 && memcmp(e->operation, "commit (initial)", 16) == 0))', 'false)', I, 'git_reflog_entries_appended_and_the_moves_that_are_not_commits'),
 C('G7 fast-forward', 'src/interp/git.c', "if (memcmp(e->message + i, FF, sizeof FF - 1) == 0) return true;", "(void)0;", I, 'git_reflog_entries_appended_and_the_moves_that_are_not_commits'),
 C('G8 prefix ends a line', 'src/interp/git.c', " || (bl && a[bl - 1] != '\\n')) {", ") {", I, 'git_reflog_that_is_not_appended_to_is_rewritten'),
 C('G9 prefix compared', 'src/interp/git.c', "(bl && memcmp(s.buf[0], a, bl) != 0) ||", "", I, 'git_reflog_that_is_not_appended_to_is_rewritten'),
 C('G10 reflog removed', 'src/interp/git.c', "    if (!reg(in, SIDE_AFTER)) {                 /* every entry removed */", "    if (false) {", I, 'git_reflog_that_is_not_appended_to_is_rewritten'),
]
Ct, Cp, Cv = 'test_content', 'test_parsers', 'test_versions'
CANARIES += [
 # ---- the review's and the reference's fixes ----
 C('R1 non-regular object opened', 'src/interp/content.c', "        else if (!S_ISREG(st.st_mode)) e = EFTYPE_NOT_REG;\n        else if ((fd = openat(pfd, hex + 2, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)) == -1) e = errno;", "        else if ((fd = openat(pfd, hex + 2, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) == -1) e = errno;", Ct, 'an_object_that_is_not_a_regular_file_is_corrupt_at_once'),
 C('R2 reflog directory', 'src/interp/git.c', "    if (!reg(in, SIDE_BEFORE) && !reg(in, SIDE_AFTER)) return BELAY_INTERP_DECLINE;  /* a directory */\n", "", I, 'git_paths_that_are_not_files_are_absent'),
 C('R3 equal ref values', 'src/interp/git.c', " ||\n                   (reg(in, SIDE_BEFORE) && reg(in, SIDE_AFTER) && fl == tl && memcmp(from, to, fl) == 0)) {", ") {", I, 'git_a_ref_rewritten_to_the_same_value_says_nothing'),
 C('R4 dpkg event fit', 'src/interp/dpkg.c', "    if (!belay_event_fits(ev, e->kind, v, n)) return -1;\n", "", I, 'dpkg_an_event_whose_text_would_not_fit_fails_the_end_hook'),
 C('R5 RECORD rows', 'src/interp/pip.c', "    if (r->n == PIP_RECORD_ROWS) return 2;                  /* over the bound: stop */\n", "", I, 'pip_a_record_past_its_row_bound_is_too_large'),
 C('R6 text lines', 'src/interp/text.c', "        if (w == SW_OK && line_count((const char *)buf[s], len[s]) > TEXT_LINES) w = SW_TOO_LARGE;\n", "", I, 'text_past_its_line_bound_is_too_large'),
 C('R7 folded simple field', 'src/interp/stanza.c', "            if (simple) {", "            if (false) {", Cp, 'a_malformed_dpkg_status_is_an_error'),
 C('R8 RECORD UTF-8', 'src/interp/pip.c', "    if (!belay_utf8_valid((const char *)buf, len)) {       /* RECORD is UTF-8 text (PEP 376) */", "    if (false) {", I, 'pip_what_cannot_be_named_or_paired_fails_the_end_hook'),
 C('R9 PEP 440 trailing separator', 'src/interp/versions.c', "            if (!take_num(s, n, &m, &v->pre)) v->pre = 0;     /* \"2a.\" is 2a0 (Appendix B) */", "            if (!take_num(s, n, &m, &v->pre)) { v->pre = 0; m = k; }", Cv, 'pep440_versions_sort_as_the_pep_shows'),
 C('R10 non-file hook', 'src/interp/git.c', "    if (!b && !a) return BELAY_INTERP_DECLINE;          /* a directory, a link: no hook file */\n    if (!b) {", "    if (in->before == NULL) {", I, 'git_paths_that_are_not_files_are_absent'),
 C('R11 index directory', 'src/interp/git.c', "if (!content || (!reg(in, SIDE_BEFORE) && !reg(in, SIDE_AFTER))) return BELAY_INTERP_DECLINE;", "if (!content) return BELAY_INTERP_DECLINE;", I, 'git_paths_that_are_not_files_are_absent'),
]
