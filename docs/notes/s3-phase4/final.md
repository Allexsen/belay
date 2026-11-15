# S3 (Phase 4) final run at 26fe30f, 2026-10-31

| canary | result | the failing assertion |
|---|---|---|
| K1 interp mask | KILLED | test/test_findings.c:96: another interpreter's kind: ,"findings":[{"kind":"text_added","lines":0,"text":"0 lin |
| K2 level | KILLED | test/test_findings.c:96: an event kind on a path: ,"findings":[{"kind":"pip_installed","name":"missing","versi |
| K3 field count | KILLED | test/test_findings.c:105: written(&g): want ","findings":[{"kind":"invalid_finding","text":"invalid finding"}] |
| K4 string bound | NOT KILLED (baseline ok) |  |
| K5 NUL | KILLED | test/test_findings.c:96: a NUL inside: ,"findings":[{"kind":"content_unavailable","reason":"a\u0000b","side":" |
| K6 text bound | NOT KILLED (baseline ok) |  |
| K6b text bound off by one | KILLED | test/test_findings.c:121: expected true: strstr(written(&g), "\"kind\":\"git_head_changed\"") != NULL |
| K7 4096 cap | KILLED | test/test_findings.c:155: (int)n: want 4096, got 4097 |
| K8 and_more n | KILLED | test/test_findings.c:158: expected true: l > sizeof tail && strcmp(w + l - (sizeof tail - 1), tail) == 0 |
| K9 events cap n | KILLED | test/test_findings.c:269: expected true: strstr(w, "{\"event\":\"and_more\",\"interp\":\"pip\",\"n\":5,\"text\ |
| K10 paths dedup | KILLED | test/test_findings.c:179: ev_written(&e): want "{"event":"pip_installed","interp":"pip","name":"numpy","versio |
| K11 paths sorted | KILLED | test/test_findings.c:179: ev_written(&e): want "{"event":"pip_installed","interp":"pip","name":"numpy","versio |
| K12 paths_b64 | KILLED | test/test_findings.c:193: expected true: strstr(ev_written(&e), ",\"paths_b64\":[\"YQ==\",\"/w==\"]}\n") != NU |
| K13 E4 order | KILLED | test/test_findings.c:211: expected true: pip != NULL && dpkg != NULL && cu != NULL && pip < dpkg && dpkg < cu |
| K14 E6 keeps events | KILLED | test/test_findings.c:239: a path-level kind: {"event":"pip_installed","interp":"pip","name":"numpy","version": |
| K15 event needs paths | KILLED | test/test_findings.c:235: no paths: not marked broken |
| K16 decline drops findings | KILLED | test/test_diff.c:444: expected false: has(PIP_A, "findings") |
| K17 error keeps findings | KILLED | test/test_diff.c:583: expected true: has("f", "\"findings\":[{\"kind\":\"could_not_interpret\",\"text\":\"coul |
| K18 failed end kept | KILLED | test/test_diff.c:506: expected true: strstr(g_text, "{\"event\":\"could_not_interpret\",\"interp\":\"pip\",\"t |
| K19 trailer events | KILLED | test/test_diff.c:481: expected true: strstr(trailer, ",\"events\":2,") != NULL |
| K20 TEXT dispatch | KILLED | test/test_interp.c:121: belay_interp_dispatch(&none, &s, &u): want 0, got 1 |
| K21 pin text | KILLED | test/test_pins.c:497: git_hook_added: text "hook {hook} added", schema "hook {hook} added!" |
| K22 pin rule | KILLED | test/test_pins.c:513: E1 placement: the statement differs |
| U1 missing vs corrupt | KILLED | test/test_interpreters.c:238: r_path(&r, "/s/f", &b, &gone, "modified"): want ","findings":[{"kind":"content_u |
| U2 too_large | KILLED | test/test_interpreters.c:258: r_path(&r, "/s/huge", NULL, &a, "added"): want ","findings":[{"kind":"content_un |
| U3 no stored field | KILLED | test/test_interpreters.c:420: r_path(&r, "/s/r/.git/logs/HEAD", &b, &a, "modified"): want ","findings":[{"kind |
| U4 pip side | KILLED | test/test_interpreters.c:579: r_end(&r): want "{"event":"content_unavailable","interp":"pip","reason":"no_stor |
| U5 dpkg event | KILLED | test/test_interpreters.c:803: r_end(&r): want "{"event":"content_unavailable","interp":"dpkg","reason":"no_sto |
| U6 pip event | KILLED | test/test_interpreters.c:579: r_end(&r): want "{"event":"content_unavailable","interp":"pip","reason":"no_stor |
| U7 dpkg side | KILLED | test/test_interpreters.c:812: r_end(&r): want "{"event":"content_unavailable","interp":"dpkg","reason":"no_sto |
| T1 text_changed fields | KILLED | test/test_interpreters.c:160: r_path(&r, "/s/notes.txt", &b, &a, "modified"): want ","findings":[{"kind":"text |
| T2 text_rewritten | KILLED | test/test_interpreters.c:198: r_path(&r, "/s/big", &b, &a, "modified"): want ","findings":[{"kind":"text_rewri |
| T3 text_added/removed | KILLED | test/test_interpreters.c:180: r_path(&r, "/s/new", NULL, &a, "added"): want ","findings":[{"kind":"text_added" |
| P1 upgraded/downgraded | KILLED | test/test_interpreters.c:488: r_end(&r): want "{"event":"pip_downgraded","interp":"pip","name":"django","from" |
| P2 version_changed | KILLED | test/test_interpreters.c:488: r_end(&r): want "{"event":"pip_downgraded","interp":"pip","name":"django","from" |
| P3 installed/removed | KILLED | test/test_interpreters.c:488: r_end(&r): want "{"event":"pip_downgraded","interp":"pip","name":"django","from" |
| P4 PEP 503 case | KILLED | test/test_interpreters.c:488: r_end(&r): want "{"event":"pip_downgraded","interp":"pip","name":"django","from" |
| P5 reinstalled size | KILLED | test/test_interpreters.c:548: r_end(&r): want "{"event":"pip_reinstalled","interp":"pip","name":"six","version |
| P6 ambiguous | KILLED | test/test_interpreters.c:625: expected true: strncmp(r_end(&r), "{\"event\":\"could_not_interpret\"", 30) == 0 |
| P7 directory key | KILLED | test/test_interpreters.c:516: r_end(&r): want "{"event":"pip_installed","interp":"pip","name":"foo","version": |
| D1 installed word | KILLED | test/test_interpreters.c:749: r_end(&r): want "{"event":"dpkg_state_changed","interp":"dpkg","package":"bash", |
| D2 up/downgraded | KILLED | test/test_interpreters.c:749: r_end(&r): want "{"event":"dpkg_state_changed","interp":"dpkg","package":"bash", |
| D3 state_changed covered | KILLED | test/test_interpreters.c:749: r_end(&r): want "{"event":"dpkg_state_changed","interp":"dpkg","package":"bash", |
| D4 installed/removed | KILLED | test/test_interpreters.c:749: r_end(&r): want "{"event":"dpkg_state_changed","interp":"dpkg","package":"bash", |
| D5 arch in key | KILLED | test/test_interpreters.c:749: r_end(&r): want "{"event":"dpkg_state_changed","interp":"dpkg","package":"bash", |
| D6 parse failure E6 | KILLED | test/test_interpreters.c:838: r_end(&r): want "{"event":"could_not_interpret","interp":"dpkg","text":"could no |
| G1 head from/to | KILLED | test/test_interpreters.c:277: r_path(&r, "/s/repo/.git/HEAD", &b, &a, "modified"): want ","findings":[{"kind": |
| G2 ref created | KILLED | test/test_interpreters.c:290: r_path(&r, "/s/r/.git/refs/heads/x", NULL, &x, "added"): want ","findings":[{"ki |
| G3 packed moved | KILLED | test/test_interpreters.c:313: r_path(&r, "/s/r/.git/packed-refs", &b, &a, "modified"): want ","findings":[{"ki |
| G4 hook exec | KILLED | test/test_interpreters.c:336: r_path(&r, "/s/r/.git/hooks/post-checkout", &n, &x, "metadata_only"): want ","fi |
| G6 commit (initial) | KILLED | test/test_interpreters.c:379: r_path(&r, "/s/r/.git/logs/refs/heads/x", NULL, &b, "added"): want ","findings": |
| G7 fast-forward | KILLED | test/test_interpreters.c:369: r_path(&r, "/s/r/.git/logs/HEAD", &b, &a, "modified"): want ","findings":[{"kind |
| G8 prefix ends a line | KILLED | test/test_interpreters.c:408: r_path(&r, "/s/r/.git/logs/refs/heads/main", &c1, &c2, "modified"): want ","find |
| G9 prefix compared | KILLED | test/test_interpreters.c:401: r_path(&r, "/s/r/.git/logs/refs/heads/main", &b, &e, "modified"): want ","findin |
| G10 reflog removed | KILLED | test/test_interpreters.c:411: r_path(&r, "/s/r/.git/logs/refs/heads/main", &none, NULL, "removed"): want ","fi |
| R1 non-regular object opened | KILLED | test/test_content.c:127: get_code_in_child(c, hex): want 5, got 214 |
| R2 reflog directory | KILLED | test/test_interpreters.c:445: r_path(&r, "/s/r/.git/logs/refs/heads/feature", NULL, &d, "added"): want "", got |
| R3 equal ref values | KILLED | test/test_interpreters.c:463: r_path(&r, "/s/r/.git/refs/heads/main", &a, &b, "modified"): want "", got ","fin |
| R4 dpkg event fit | KILLED | test/test_interpreters.c:900: r.it->end(r.state, &r.ev): want 2, got 0 |
| R5 RECORD rows | KILLED | test/test_interpreters.c:641: r_path(&r, REC("six-1.16.0"), &b, &a, "modified"): want ","findings":[{"kind":"c |
| R6 text lines | KILLED | test/test_interpreters.c:662: r_path(&r, "/s/lines", NULL, &a, "added"): want ","findings":[{"kind":"content_u |
| R7 folded simple field | KILLED | test/test_parsers.c:90: accepted: Package: a |
| R8 RECORD UTF-8 | KILLED | test/test_interpreters.c:616: r_path(&r, REC("six-1.16.0"), &rb, &ra, "modified"): want ","findings":[{"kind": |
| R9 PEP 440 trailing separator | KILLED | test/test_versions.c:69: 2a. and 2a0 should be equal |
| R10 non-file hook | KILLED | test/test_interpreters.c:447: r_path(&r, "/s/r/.git/hooks/pre-push.d", NULL, &d, "added"): want "", got ","fin |
| R11 index directory | KILLED | test/test_interpreters.c:450: r_path(&r, "/s/r/.git/index", NULL, &d, "added"): want "", got ","findings":[{"k |
| G5 index metadata | KILLED | test/test_interpreters.c:349: r_path(&r, "/s/r/.git/index", &e, &e, "metadata_only"): want "", got ","findings |
