# PR #33 (user excludes), independent review, verbatim

Reviewer: a fresh agent with no implementation context, 2026-11-02 (decision row 100: blast radius).
Scope: `git diff 0071887..caf9076 -- src docs`.
Relayed verbatim; dispositions appended after it.

---

REVIEW: PR #33, user excludes (commits 3dd4a4b, 0313586, caf9076; reviewed as `git diff 0071887..caf9076 -- src docs`)

I worked in a detached worktree of origin/main (3f266b3) and built it with `make -j8`. Every run of bin/belay used a fresh 0700 BELAY_STATE_DIR under the scratchpad, and every scope was a scratch tree. The worktree and scratch data are now removed. The main checkout was not modified; it now shows branch m1/one-sided, which I did not cause.

`make -j8 check`: exit 0. Summed over the suites: 440 run, 0 failed, 0 skipped.

Overall: none of the boundary checks below found a way to reach outside the scope, to exclude the scope root, or to drop paths without saying so in the text output. The defects are in what is reported around an exclude.

======================================================================
ESTABLISHED DEFECTS (most severe first)
======================================================================

D1. MEDIUM. Across an exclude, the pip and dpkg interpreters report "installed" or "removed" events, provisional, for packages that did not change.
- Where: src/diff/diff.c:197-204 maps an excluded path to ANC_SEALED, which gives `unknown`/`not_captured`. src/interp/pip.c:264-266 ("An unknown RECORD still pairs ... (P7)") and src/interp/dpkg.c:223-224 ("An unknown outcome is read too") then build events from those unknown records.
- Contradicts: docs/cli.md says "A diff across an exclude reports what one side holds there as `unknown`, `not_captured`, never as removed or added." The records keep that promise; the events break it in substance.
- How established: scope sc5 holds venv/lib/python3.12/site-packages/foo-1.0.dist-info/{METADATA,RECORD} and foo/__init__.py. The commands were `belay exclude --scope sc5 --add venv`, `belay mark` (checkpoint 1), `belay exclude --remove venv`, `belay diff --scope sc5 --since 1`. Output:
    9 unknown    events: 1
    packages and files explained
      pip   installed foo 1.0 (provisional: a path it came from is unknown)
  and in --json:
    {"event":"pip_installed","interp":"pip","name":"foo","version":"1.0","text":"installed foo 1.0","provisional":true,...}
- Reverse direction (exclude venv/lib added after checkpoint 2): "pip   removed foo 1.0 (provisional ...)".
- dpkg (var/lib/dpkg/status with bash and zsh; mark; then `exclude --add var/lib/dpkg`; diff): "dpkg  removed bash: 5.2 (provisional ...)" and "dpkg  removed zsh: 5.9 (provisional ...)".
- Nothing was installed or removed; only the exclude list changed.
- Class: interpreters treat every `unknown` reason alike. The same would apply to not_captured under a mount or an unreadable directory (inferred from the code, not run). git declines unknown (src/interp/git.c:334), so it is not affected.
- Severity: an agent or RL consumer of events sees package installs and removals that did not happen. The `provisional` flag is the only signal, and it does not say "excluded".

D2. MEDIUM. `diff --json` says nothing about excluded paths in some cases.
- Case 1: when both sides excluded a path. That path appears in no record, as the spec intends, and also on no line of stdout or stderr.
- Case 2: with `--to`, the excludes of neither side are named anywhere.
- Case 3: with `--since` to now, only the new capture's excludes are named (on stderr, src/cli/cli.c:410). The before side's are not.
- The "not compared" list exists only in the text receipt (src/cli/cli.c:422-443). The diff.v1 header and trailer have no field for it.
- How established: checkpoints 6 and 8 both excluded node_modules. `belay diff --scope sc1 --since 6 --to 8 --json >o.json 2>e.txt` gave exit 0. stdout was only the header and a trailer with "unchanged":7 and no records. e.txt was empty. The text receipt for the same pair does say "not compared / node_modules   excluded for this scope".
- `check --json` and `mark --json` give only a count ("excluded":1), not the paths.
- Severity: the machine interface reports a clean, apparently complete diff with a blind spot it does not name. That conflicts with the commit title ("named everywhere") and the never-silent rule. The receipt and the manifest header do name it.

D3. LOW. A NUL byte in a hand-edited `excludes` file silently drops every line after it.
- Where: src/cli/state.c, state_excludes_read. The loop `for (line = buf; *line != '\0'; ...)` stops at the first NUL, even though read_small read further.
- How established: `printf 'node_modules\n\0src\n' > .../excludes`, then `belay exclude --scope sc1` printed only "node_modules" (exit 0), and `belay check` excluded only node_modules. "src" was silently ignored.
- Every other malformed file is refused: blank lines, no final newline, a NUL inside a line, "/etc", "../x" all give exit 4 ("holds a line that is not an exclude" or "is not a file belay wrote").
- The failure walks more, not less, so nothing is hidden. But the file is accepted when it should be refused, against the module's own strictness.

D4. LOW. A CRLF line in a hand-edited `excludes` file is accepted, and the exclude then matches nothing.
- How established: `printf 'node_modules\r\n'` gave a list showing "node_modules\x0d" (exit 0). `check` then recorded node_modules: 10 entries, no "not recorded" line.
- The user believes node_modules is excluded. It is walked, which is the safe direction.
- Fix: state_exclude_valid could refuse control bytes, or at least '\r'.

D5. LOW. `--remove` with duplicate lines in the file removes one copy and reports success.
- Where: in cmd_exclude (src/cli/cli.c), the loop `for (...) if (!strcmp(...)) at = i;` keeps only the last match.
- How established: with the file 'node_modules\nsrc\nnode_modules\n', `belay exclude --scope sc1 --remove node_modules` exited 0 and printed "node_modules\nsrc". The path is still excluded.
- Duplicates can only come from hand edits; the printed list does show it.

D6. LOW. Two related CLI cases succeed silently.
- `--add x --add y` adds only y (exit 0). The parser at src/cli/cli.c:126-133 lets the last value win; the same class already applies to `--scope`, `--since` and `--to`.
- `--remove nothere` exits 0 with no note that the path was not in the list.

======================================================================
SUSPICIONS (labelled; not established)
======================================================================

S1 (suspected, from reading the code; not run). At src/capture/walk.c:72-90 the check for belay's state directory, by device and inode, runs before cap_crossed. If that directory is reachable at more than one path inside the scope (a bind mount), each path takes a slot. With 31 user excludes, one extra appearance makes the capture fail with "manifest: more than 32 excluded entries". That fails loudly, not silently, but the message is misleading. I could not set up a bind mount: under `unshare -rm`, belay refused /tmp, which belongs to uid 65534 inside the namespace.

S2 (observed; a cosmetic suspicion). The first `mark` after adding an exclude that covers the most recently changed files reads every file. Its stated reason is "every file read (ctime went backwards: newest ... below the previous ...)". That is safe, but the reason misleads: an exclude changed, ctime did not go backwards. Seen on scope sc6.

S3 (from reading the code). The exclude match in the walk calls strlen on each of up to 31 excludes for every entry visited (walk.c:75-76). At worst that is about 127 KB of strlen per entry. Computing the lengths once would remove it.

======================================================================
CHECKED AND SOUND (how)
======================================================================

1. The scope root cannot be excluded. `.`, the empty string, `/`, the scope's absolute path and `./` are all refused with exit 2 ("an exclude is a path relative to the scope, without '.', '..' or empty parts"). So are `./src`, `src/`, `src//x`, `src/./x` and a path containing a newline.

2. Symlinks (scope sc2, with ld -> d, lo -> ../outside, and a dangling link):
   - `--add lo` excludes the link itself. The header records lo's own inode (84314, checked with stat), not its target's (84310).
   - `ld/sub` and `lo/o` have no effect: the walk never descends links, so they match nothing. The configured but unmatched paths are not listed, as manifest-v2 says.
   - d/sub/s is recorded normally. Nothing outside the scope is reachable.
   - The walk matches on its own relative path built from directory handles (walk.c:75), so an exclude cannot name anything outside the scope.

3. Paths outside the scope: `/abs`, `..`, `../x`, `a/../../b` and `src/..` are refused, both from the CLI and from a hand-edited file. `%2e%2e` is accepted as a literal file name, which is correct: there is no decoding.

4. `..` as any component is refused (state_exclude_valid checks each component).

5. The state directory inside the scope:
   - It is excluded with reason state_dir.
   - A user exclude naming it (`.bstate`) still shows as state_dir, once.
   - With the state directory under a user-excluded `var`, the header shows `var (user)`. After the exclude is removed, it shows `var/bst (belay's own state directory)`. The diff then lists both under "not compared", and var is unknown/not_captured.
   - 31 user excludes plus the state directory: the capture works and names all 32. A 32nd user exclude is refused ("at most 31 excludes", exit 2).

6. Silently empty captures: excluding everything leaves only the root recorded, and each exclude is named in the output. No silent drop was found.
   - Non-UTF-8 names (`n\xffu`, written as path_b64 "bv91") and escape bytes (`e\x1b[31mred`, written as \u001b in JSON, shown as \x1b in text) match and round-trip through mark, the header and diff.
   - A 4095-byte exclude is accepted; 4096 bytes is refused.
   - Running `exclude --add` during a `mark --full` of about 10,000 entries: the exclude waited on the lock ("waiting for another belay working on ...") and then applied. The capture was consistent.
   - The file is written by tmp + fsync + rename (write_whole). It is read with O_NOFOLLOW, as a regular file only, with a size limit.

7. Diff across an exclude and prefix siblings:
   - Exclude `a` on the before side only; then delete a.b and a-/y, add a0, and add a/new. Results: a, a/x and a/new are unknown/not_captured; a-/y is D, a.b is D, a0 is A.
   - Exclude node_modules after a mark; modify node_modules2/z and a.b/q. Those two are reported M, and node_modules/** is unknown.
   - excluded_covers (diff.c:170-178) and the new check in manifest_read.c both require an exact match or a '/' right after the prefix.
   - The receipt and the manifest name every excluded path in text mode. For JSON see D2.

8. manifest_read now refuses an entry at or below an excluded path. That is consistent with the writer: the walk returns VISIT_EXCLUDED before recording anything at that path or below it. The new unit test passes.

======================================================================
TEST GAPS
======================================================================

- No tests for events across an exclude (pip or dpkg; D1).
- No test that `diff --json` names excludes, or that it does not (D2).
- No tests for a hand-edited excludes file with NUL, CRLF or duplicate lines (D3-D5). The one existing hand-edit test covers '/abs' only.
- No CLI tests for a symlink exclude, an exclude through a symlink, or prefix siblings (`a` vs `a.b` / `a-` / `a0`).
- No tests for the state directory under a user exclude, or for 31 user excludes plus the state directory at once.
- No test for running `exclude` while a capture is in progress.

Also noted: in cli.c the old comment "What a capture must say on every capture ..." now sits stacked above the new comment for excluded_notes, so it no longer sits above the function it describes (capture_notes). This is cosmetic.

---

## Dispositions (implementer, appended)

Each fix has a test that fails with it reverted (scratchpad/canary/c11.json): 8 canaries, 8 KILLED.

- **D1 -- not fixed here: a pin change.** Pin diff-events.md E2 (decision P7) makes an event from
  an `unknown` path provisional, whatever the reason. Deriving no event from a path unknown only
  for `not_captured` (excluded, or below an unreadable directory or a mount) changes diff.v1:
  opened as a pin PR, as a table, for the author's OK (with the oracle's and the reference's
  authors after it).
- **D2 -- fixed (CLI); a format question opened.** `diff --json` names every path either side did
  not walk, on stderr ("belay: not compared: PATH (excluded for this scope)"), with `--to` too;
  checkpoint JSON gains `excluded_paths` (schema updated). Tests:
  `json_output_names_every_excluded_path`, `diff_says_what_its_capture_left_out`. Whether diff.v1's
  header should carry the excluded paths is in the same pin PR as D1.
- **D3 -- fixed.** A NUL in `excludes` is corrupt state (exit 4).
- **D4 -- fixed.** An exclude has no control byte (CR, ...): refused by `--add`, corrupt in the file.
- **D5 -- fixed.** A line twice in `excludes` is corrupt state.
- **D6 -- fixed.** An option given twice is a usage error (`--add`, and `--scope`, `--since`, `--to`
  -- the same class); `--remove` of a path not excluded says so, exit 2.
- **S1 -- recorded.** The state directory reachable at two paths would take two slots; a capture
  then fails loudly with a misleading count. Not reproduced (needs a bind mount); left.
- **S2 -- fixed.** A path excluded now no longer counts toward the previous newest ctime, so adding
  an exclude over the newest files is not "ctime went backwards" (same test).
- **S3 -- fixed.** Exclude lengths computed once per walk.
- Cosmetic: the comment above capture_notes restored.
- Test gaps closed: a symlink exclude (the link itself) and prefix siblings
  (`an_exclude_is_exact_on_links_and_prefixes`). Left: concurrent `exclude` during a capture (the
  reviewer verified it by hand: the lock serialises them).

