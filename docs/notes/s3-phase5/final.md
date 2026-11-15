# S3 (Phase 5), 2026-10-31

First run (e3b2210): 28 of 35 killed. Survivors: M3, L3, L13 -> tests added (fc commit 'the cases Phase 5's S3 run showed no test held'), each then KILLED:

| M3 ctime | KILLED | test/test_mark.c:264: expected true: a != NULL && b != NULL && strcmp(a, b) == 0 |
| L3 refused is 3 | KILLED | test/test_cli.c:183: rc: want 3, got 4 |
| L13 session gone | KILLED | test/test_cli.c:93: expected true: strstr(g_err, "unknown command run") != NULL |

Equivalent (not killable by any test, kept as defence in depth): M1 size, M2 mtime, M5 inode, M6 mode -- every change to one of them moves ctime, which the rule checks (M3, killed), and mode is recorded from the fresh stat whether or not the file is trusted.

## First run, all 35

| M1 size | NOT KILLED (baseline ok) |  |
| M2 mtime | NOT KILLED (baseline ok) |  |
| M3 ctime | NOT KILLED (baseline ok) |  |
| M4 reference point | KILLED | test/test_mark.c:193: step 22 (round 1000000000 ns): mark and check differ |
| M5 inode | NOT KILLED (baseline ok) |  |
| M6 mode | NOT KILLED (baseline ok) |  |
| M7 manifest ctime as R | KILLED | test/test_mark.c:228: (int)st.trusted: want 12, got 11 |
| M8 other limits used | KILLED | test/test_mark.c:253: expected false: st.prefilter |
| M9 exclusion | KILLED | test/test_mark.c:293: (int)st.excluded: want 1, got 0 |
| M10 excluded name listed | KILLED | test/test_mark.c:292: required: capture_write(&g_ops, out, g_tree, &o, &st) == 0 |
| M11 root identity | KILLED | test/test_mark.c:311: capture_write(&g_ops, out, g_tree, &o, NULL): want -1, got 0 |
| M12 trusted file not opened | KILLED | test/test_mark.c:193: step 1 (round 0 ns): mark and check differ |
| L1 O_NOFOLLOW | KILLED | test/test_cli.c:164: rc: want 3, got 0 |
| L2 not a directory | KILLED | test/test_cli.c:105: expected true: strstr(g_err, "not a directory") != NULL |
| L3 refused is 3 | NOT KILLED (baseline ok) |  |
| L4 exit-code opt-in | KILLED | test/test_cli.c:198: belay("diff", "--scope", g_scope, "--since", "1", NULL): want 0, got 1 |
| L5 exit-code works | KILLED | test/test_cli.c:200: belay("diff", "--scope", g_scope, "--since", "1", "--exit-code", NULL): want 1, got 0 |
| L6 Q8 backwards | KILLED | test/test_cli.c:226: expected true: strstr(g_out, "ctime went backwards") != NULL |
| L7 full every | KILLED | test/test_cli.c:220: expected true: strstr(g_out, "\"full_reason\":\"every 2 marks\"") != NULL |
| L8 --full | KILLED | test/test_cli.c:216: expected true: strstr(g_out, "\"full_reason\":\"asked for (--full)\"") != NULL |
| L9 exclusion said | KILLED | test/test_cli.c:179: expected true: strstr(g_out, "not recorded: belay's own state directory") != NULL |
| L10 exclusion wired | KILLED | test/test_cli.c:179: expected true: strstr(g_out, "not recorded: belay's own state directory") != NULL |
| L11 diff capture kept | KILLED | test/test_cli.c:202: expected true: strstr(g_out, "check 1") != NULL && strstr(g_out, "diff 4") != NULL |
| L12 usage before stdout | KILLED | test/test_cli.c:63: belay("check", NULL): want 2, got 3 |
| L13 session gone | NOT KILLED (baseline ok) |  |
| R1 privilege never folds | KILLED | test/test_receipt.c:102: expected true: strstr(g_text, "  ~ p59   inode flags changed\n") != NULL |
| R2 setuid | KILLED | test/test_receipt.c:86: g_text: want "belay diff  /w  checkpoint 3 -> checkpoint 4 |
| R3 caps | KILLED | test/test_receipt.c:86: g_text: want "belay diff  /w  checkpoint 3 -> checkpoint 4 |
| R4 iflags | KILLED | test/test_receipt.c:102: expected true: strstr(g_text, "  ~ p59   inode flags changed\n") != NULL |
| R5 15 findings | KILLED | test/test_receipt.c:86: g_text: want "belay diff  /w  checkpoint 3 -> checkpoint 4 |
| R6 fold at 50 | KILLED | test/test_receipt.c:103: expected true: strstr(g_text, "  A q49\n") != NULL && strstr(g_text, "  A q50\n") ==  |
| R7 events first | KILLED | test/test_receipt.c:86: g_text: want "belay diff  /w  checkpoint 3 -> checkpoint 4 |
| R8 truncated refused | KILLED | test/test_receipt.c:117: render(HEAD "{\"path\":\"a\",\"outcome\":\"added\",\"type\":\"reg\"}\n", false): want |
| R9 provisional named | KILLED | test/test_receipt.c:86: g_text: want "belay diff  /w  checkpoint 3 -> checkpoint 4 |
| R10 unknown named | KILLED | test/test_receipt.c:86: g_text: want "belay diff  /w  checkpoint 3 -> checkpoint 4 |
