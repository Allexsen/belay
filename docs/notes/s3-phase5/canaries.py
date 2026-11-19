M = 'test_mark'; L = 'test_cli'; R = 'test_receipt'
C = lambda id, f, old, new, b, t: dict(id=id, edits=[(f, old, new)], bin=b, test=t)
D = 'mark_agrees_with_check_on_every_change'
D1 = 'mark_agrees_with_check_on_one_second_timestamps'
CANARIES = [
 # ---- the prefilter's rule, clause by clause ----
 C('M1 size', 'src/capture/previous.c', "r->mode == s.mode && r->size == s.size &&", "r->mode == s.mode &&", M, D),
 C('M2 mtime', 'src/capture/previous.c', "r->mtime_ns == s.mtime_ns && r->ctime_ns == s.ctime_ns", "r->ctime_ns == s.ctime_ns", M, D1),
 C('M3 ctime', 'src/capture/previous.c', "r->mtime_ns == s.mtime_ns && r->ctime_ns == s.ctime_ns", "r->mtime_ns == s.mtime_ns", M, D),
 C('M4 reference point', 'src/capture/previous.c', " && r->ctime_ns < reference_ns;", ";", M, D1),
 C('M5 inode', 'src/capture/previous.c', "return r->dev == s.dev && r->ino == s.ino && r->mode == s.mode", "return r->dev == s.dev && r->mode == s.mode", M, D),
 C('M6 mode', 'src/capture/previous.c', "r->ino == s.ino && r->mode == s.mode && r->size == s.size", "r->ino == s.ino && r->size == s.size", M, D),
 C('M7 manifest ctime as R', 'src/capture/previous.c', "        info->reference_ns = info->manifest_ctime_ns;       /* git's index rule (Q2) */", "        (void)0;", M, 'an_unchanged_file_is_trusted_and_a_racy_one_read'),
 C('M8 other limits used', 'src/capture/previous.c', "    if (h->hash_max_bytes != opts->hash_max_bytes || h->store_max_bytes != opts->store_max_bytes) {", "    if (0) {", M, 'an_unusable_previous_manifest_means_a_full_walk'),
 C('M9 exclusion', 'src/capture/walk.c', "        if (wc->opts->exclude && S_ISDIR(st.st_mode)", "        if (0 && S_ISDIR(st.st_mode)", M, 'an_excluded_directory_is_not_recorded'),
 C('M10 excluded name listed', 'src/capture/walk.c', "        if (v == VISIT_RECORDED || v == VISIT_EXCLUDED)", "        if (v == VISIT_RECORDED)", M, 'an_excluded_directory_is_not_recorded'),
 C('M11 root identity', 'src/capture/manifest_write.c', "    if (opts->expect_root && ((uint64_t)rst.st_dev != opts->root_dev", "    if (0 && ((uint64_t)rst.st_dev != opts->root_dev", M, 'a_root_that_is_not_the_one_resolved_is_refused'),
 C('M12 trusted file not opened', 'src/capture/capture.c', "            wc->trusted++;\n            close(fd);\n            return V_OK;", "            wc->trusted++;\n            close(fd);\n            e->has_iflags = false;\n            return V_OK;", M, D),
 # ---- the CLI ----
 C('L1 O_NOFOLLOW', 'src/cli/state.c', "O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);\n        const int e = errno;", "O_RDONLY | O_DIRECTORY | O_CLOEXEC);\n        const int e = errno;", L, 'a_component_swapped_after_resolution_is_refused'),
 C('L2 not a directory', 'src/cli/state.c', "    if (stat(real, &st) == -1 || !S_ISDIR(st.st_mode)) {", "    if (stat(real, &st) == -1) {", L, 'a_scope_that_cannot_be_resolved_is_refused_exit_3'),
 C('L3 refused is 3', 'src/cli/cli.c', "    if (refusal || code == BELAY_ERR_INVALID) return EXIT_REFUSED;", "    if (refusal) return EXIT_REFUSED;", L, 'a_scope_that_cannot_be_resolved_is_refused_exit_3'),
 C('L4 exit-code opt-in', 'src/cli/cli.c', "    if (o->exit_code && ds.records > 0) rc = EXIT_CHANGES;", "    if (ds.records > 0) rc = EXIT_CHANGES;", L, 'diff_keeps_its_capture_and_exit_code_is_opt_in'),
 C('L5 exit-code works', 'src/cli/cli.c', "    if (o->exit_code && ds.records > 0) rc = EXIT_CHANGES;", "    (void)ds;", L, 'diff_keeps_its_capture_and_exit_code_is_opt_in'),
 C('L6 Q8 backwards', 'src/cli/state.c', "               s.newest_ctime_ns < s.previous_newest_ns) {", "               0) {", L, 'mark_says_when_it_reads_every_file'),
 C('L7 full every', 'src/cli/state.c', "        else if (req->full_every > 0 && since_full + 1 >= req->full_every)", "        else if (0)", L, 'mark_says_when_it_reads_every_file'),
 C('L8 --full', 'src/cli/state.c', "        if (req->force_full) snprintf(c.full_reason", "        if (0) snprintf(c.full_reason", L, 'mark_says_when_it_reads_every_file'),
 C('L9 exclusion said', 'src/cli/cli.c', "    if (c->excluded) fprintf(out, \"  not recorded", "    if (0) fprintf(out, \"  not recorded", L, 'the_state_directory_inside_the_scope_is_excluded_and_said'),
 C('L10 exclusion wired', 'src/cli/state.c', "        .exclude = st->root_ino != 0,", "        .exclude = false,", L, 'the_state_directory_inside_the_scope_is_excluded_and_said'),
 C('L11 diff capture kept', 'src/cli/cli.c', "        const struct capture_req req = { \"diff\", true, false, o->full_every };", "        const struct capture_req req = { \"mark\", true, false, o->full_every };", L, 'diff_keeps_its_capture_and_exit_code_is_opt_in'),
 C('L12 usage before stdout', 'src/cli/cli.c', "    if (o->scope == NULL) return usage(err, \"--scope DIR is required\");", "    if (o->scope == NULL) return EXIT_DONE;", L, 'usage_errors_exit_2'),
 C('L13 session gone', 'src/cli/cli.c', "    const bool known = !strcmp(cmd, \"check\")", "    const bool known = !strcmp(cmd, \"run\") || !strcmp(cmd, \"check\")", L, 'the_session_engine_is_not_a_command'),
 # ---- the receipt ----
 C('R1 privilege never folds', 'src/cli/receipt.c', "    return keep(is_priv ? priv : other, b.p, !is_priv, o->all);", "    return keep(is_priv ? priv : other, b.p, true, o->all);", R, 'long_sections_fold_but_privilege_never_does'),
 C('R2 setuid', 'src/cli/receipt.c', "((m0 ^ m1) & 07000) != 0) {", "((m0 ^ m1) & 06000) == 07000) {", R, 'a_receipt_puts_events_then_privilege_then_changes'),
 C('R3 caps', 'src/cli/receipt.c', "    if (has(ch, \"caps\")) sbf(b,", "    if (0) sbf(b,", R, 'a_receipt_puts_events_then_privilege_then_changes'),
 C('R4 iflags', 'src/cli/receipt.c', "    if (has(ch, \"iflags\")) sbf(b,", "    if (0) sbf(b,", R, 'long_sections_fold_but_privilege_never_does'),
 C('R5 15 findings', 'src/cli/receipt.c', "i < f->n && i < RECEIPT_FINDINGS; i++)", "i < f->n; i++)", R, 'a_receipt_puts_events_then_privilege_then_changes'),
 C('R6 fold at 50', 'src/cli/receipt.c', "    if (fold && !all && l->n >= RECEIPT_FOLD) {", "    if (0) {", R, 'long_sections_fold_but_privilege_never_does'),
 C('R7 events first', 'src/cli/receipt.c', '{ "packages and files explained", &ev }, { "privilege", &priv }, { "changes", &other },', '{ "privilege", &priv }, { "packages and files explained", &ev }, { "changes", &other },', R, 'a_receipt_puts_events_then_privilege_then_changes'),
 C('R8 truncated refused', 'src/cli/receipt.c', "    if (!have_trailer) {", "    if (0) {", R, 'a_truncated_or_malformed_diff_renders_nothing'),
 C('R9 provisional named', 'src/cli/receipt.c', "    if (pv != NULL && pv->t == J_BOOL && pv->b) sbf(&b,", "    if (0) sbf(&b,", R, 'a_receipt_puts_events_then_privilege_then_changes'),
 C('R10 unknown named', 'src/cli/receipt.c', "        sbf(&b, \"   unknown: \");", "        sbf(&b, \"   \");", R, 'a_receipt_puts_events_then_privilege_then_changes'),
]
