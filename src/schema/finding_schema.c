#include "finding_schema.h"

#include "belay/interp.h"

#define IN(i) (1u << (i))
#define I_TEXT IN(BELAY_INTERP_TEXT)
#define I_PIP  IN(BELAY_INTERP_PIP)
#define I_DPKG IN(BELAY_INTERP_DPKG)
#define I_GIT  IN(BELAY_INTERP_GIT)
#define S(n) { n, FT_STRING }
#define N(n) { n, FT_INT }
#define B(n) { n, FT_BOOL }
#define BO(n) { n, FT_BOOL, true }
#define NO(n) { n, FT_INT, true }
#define SO(n) { n, FT_STRING, true }
#define BY(n) { n, FT_BYTES }

const struct finding_kind_def FINDING_KINDS[FK_COUNT] = {
    [FK_COULD_NOT_INTERPRET] = { "could_not_interpret", IN_CORE, LV_PATH | LV_EVENT, { { 0 } },
        "could not interpret", "The interpreter failed on this path (R11), nothing else from it "
        "here; or, as an event, on the paths it names (E6, E10)." },
    [FK_INVALID_FINDING] = { "invalid_finding", IN_CORE, LV_PATH | LV_EVENT, { { 0 } }, "invalid finding",
        "A finding that broke the rules, replaced; or, as an event, an event that did (E9)." },
    [FK_AND_MORE] = { "and_more", IN_CORE, LV_PATH | LV_EVENT, { N("n") }, "and {n} more",
        "In the last place of a record past 4,096 findings, or of an interpreter's events past "
        "65,536: the findings or events from that place on, counted." },
    [FK_CONTENT_UNAVAILABLE] = { "content_unavailable", I_TEXT | I_PIP | I_DPKG | I_GIT,
        LV_PATH | LV_EVENT, { S("reason"), S("side") }, "content unavailable ({side}): {reason}",
        "The stored copy of a claimed path, on a side where it exists, cannot be read: reason "
        "`no_store`, `missing`, `too_large` or `corrupt`; side `before`, `after` (or, for an event, "
        "`both`). Never a silent decline." },
    [FK_TEXT_CHANGED] = { "text_changed", I_TEXT, LV_PATH,
        { N("lines_added"), N("lines_deleted"), N("first_changed_line") },
        "+{lines_added} -{lines_deleted} lines, first change at line {first_changed_line}",
        "Stored on both sides: lines by the longest common subsequence of lines; the first line "
        "past the common prefix, 1-based, in before." },
    [FK_TEXT_REWRITTEN] = { "text_rewritten", I_TEXT, LV_PATH,
        { N("lines_before"), N("lines_after"), N("first_changed_line") },
        "rewritten: {lines_before} lines before, {lines_after} after, first change at line "
        "{first_changed_line}",
        "As text_changed, past 2,000 lines of edit distance: not counted." },
    [FK_TEXT_ADDED] = { "text_added", I_TEXT, LV_PATH, { N("lines") }, "{lines} lines",
        "Added, stored." },
    [FK_TEXT_REMOVED] = { "text_removed", I_TEXT, LV_PATH, { N("lines") }, "{lines} lines",
        "Removed, stored before." },
    [FK_PIP_INSTALLED] = { "pip_installed", I_PIP, LV_EVENT, { S("name"), S("version") },
        "installed {name} {version}", "A dist-info whose RECORD is added, none removed of that name." },
    [FK_PIP_REMOVED] = { "pip_removed", I_PIP, LV_EVENT, { S("name"), S("version") },
        "removed {name} {version}", "A dist-info whose RECORD is removed, none added of that name." },
    [FK_PIP_UPGRADED] = { "pip_upgraded", I_PIP, LV_EVENT, { S("name"), S("from"), S("to") },
        "upgraded {name} {from} -> {to}", "One removed and one added of a name; to higher (PEP 440)." },
    [FK_PIP_DOWNGRADED] = { "pip_downgraded", I_PIP, LV_EVENT, { S("name"), S("from"), S("to") },
        "downgraded {name} {from} -> {to}", "The same; to lower." },
    [FK_PIP_VERSION_CHANGED] = { "pip_version_changed", I_PIP, LV_EVENT,
        { S("name"), S("from"), S("to") }, "{name} {from} -> {to}",
        "The same; equal by PEP 440, or not a PEP 440 version." },
    [FK_PIP_REINSTALLED] = { "pip_reinstalled", I_PIP, LV_EVENT,
        { S("name"), S("version"), NO("files_added"), NO("files_removed"), NO("files_changed") },
        "reinstalled {name} {version}: +{files_added} -{files_removed} ~{files_changed} files",
        "The same dist-info on both sides, its RECORD changed; unknown on both sides, provisional and "
        "not counted.",
        "reinstalled {name} {version} (files not counted)" },
    [FK_DPKG_INSTALLED] = { "dpkg_installed", I_DPKG, LV_EVENT,
        { S("package"), S("arch"), S("version") }, "installed {package}:{arch} {version}",
        "`installed` after and not before." },
    [FK_DPKG_REMOVED] = { "dpkg_removed", I_DPKG, LV_EVENT, { S("package"), S("arch"), S("version") },
        "removed {package}:{arch} {version}", "`installed` before and not after." },
    [FK_DPKG_UPGRADED] = { "dpkg_upgraded", I_DPKG, LV_EVENT,
        { S("package"), S("arch"), S("from"), S("to") }, "upgraded {package}:{arch} {from} -> {to}",
        "`installed` on both sides; to higher (Debian version comparison)." },
    [FK_DPKG_DOWNGRADED] = { "dpkg_downgraded", I_DPKG, LV_EVENT,
        { S("package"), S("arch"), S("from"), S("to") }, "downgraded {package}:{arch} {from} -> {to}",
        "The same; to lower." },
    [FK_DPKG_STATE_CHANGED] = { "dpkg_state_changed", I_DPKG, LV_EVENT,
        { S("package"), S("arch"), S("from"), S("to") }, "{package}:{arch} {from} -> {to}",
        "The Status field differs, no installed or removed event covering it." },
    [FK_GIT_HEAD_CHANGED] = { "git_head_changed", I_GIT, LV_PATH, { S("from"), S("to") },
        "HEAD {from} -> {to}", "`.git/HEAD`: the symbolic ref, or the commit it names." },
    [FK_GIT_REF_CREATED] = { "git_ref_created", I_GIT, LV_PATH, { S("ref"), S("to") },
        "created {ref} at {to}", "A ref appeared." },
    [FK_GIT_REF_DELETED] = { "git_ref_deleted", I_GIT, LV_PATH, { S("ref"), S("from") },
        "deleted {ref} (was {from})", "A ref went away." },
    [FK_GIT_REF_MOVED] = { "git_ref_moved", I_GIT, LV_PATH, { S("ref"), S("from"), S("to") },
        "{ref} {from} -> {to}", "A ref names another commit." },
    [FK_GIT_HOOK_ADDED] = { "git_hook_added", I_GIT, LV_PATH, { S("hook"), BO("executable"), BY("target") },
        "hook {hook} added", "" },
    [FK_GIT_HOOK_REMOVED] = { "git_hook_removed", I_GIT, LV_PATH, { S("hook"), BY("target") }, "hook {hook} removed",
        "" },
    [FK_GIT_HOOK_CHANGED] = { "git_hook_changed", I_GIT, LV_PATH, { S("hook"), BO("executable"), BY("target") },
        "hook {hook} changed", "Its content changed." },
    [FK_GIT_HOOK_EXECUTABLE_CHANGED] = { "git_hook_executable_changed", I_GIT, LV_PATH,
        { S("hook"), B("executable") }, "hook {hook} executable: {executable}",
        "Only its executable bit changed." },
    [FK_GIT_INDEX_CHANGED] = { "git_index_changed", I_GIT, LV_PATH, { { 0 } }, "index changed",
        "`.git/index` (hashed, never stored)." },
    [FK_GIT_REFLOG_APPENDED] = { "git_reflog_appended", I_GIT, LV_PATH, { S("ref"), N("entries") },
        "{ref}: {entries} reflog entries", "Entries appended to the ref's reflog." },
    [FK_GIT_REFLOG_MOVE] = { "git_reflog_move", I_GIT, LV_PATH,
        { S("ref"), S("from"), S("to"), S("operation") }, "{ref} {from} -> {to} by {operation}",
        "An appended entry that is not a plain commit or a fast-forward. The reflog is written by "
        "the watched process: evidence, not proof." },
    [FK_GIT_REFLOG_REWRITTEN] = { "git_reflog_rewritten", I_GIT, LV_PATH, { S("ref") },
        "{ref}: reflog rewritten", "The reflog before is not a prefix of the reflog after." },
    [FK_GIT_HEAD_SWITCHED] = { "git_head_switched", I_GIT, LV_EVENT, { S("repo"), S("from"), S("to") },
        "HEAD {from} -> {to}",
        "`HEAD` names another branch, or became or stopped being detached: from and to are the branch "
        "or, detached, the commit (diff-events E12)." },
    [FK_GIT_BRANCH_CREATED] = { "git_branch_created", I_GIT, LV_EVENT, { S("repo"), S("branch"), S("at") },
        "branch {branch} created at {at}", "A branch absent before, by evidence (E12), exists after." },
    [FK_GIT_BRANCH_DELETED] = { "git_branch_deleted", I_GIT, LV_EVENT, { S("repo"), S("branch"), S("was") },
        "branch {branch} deleted (was {was})", "A branch that existed before exists no more (E12)." },
    [FK_GIT_BRANCH_RENAMED] = { "git_branch_renamed", I_GIT, LV_EVENT,
        { S("repo"), S("from"), S("to"), S("at") }, "branch {from} renamed to {to}",
        "In place of a deletion and a creation at the same commit, by the new branch's reflog. From "
        "the reflog: evidence, not proof." },
    [FK_GIT_COMMITS_ADDED] = { "git_commits_added", I_GIT, LV_EVENT,
        { S("repo"), S("branch"), NO("count"), S("to") }, "commits added to {branch}: {count}, now at {to}",
        "The branch moved forward by commits, fast-forwards or merges alone (E12); count, when every "
        "entry is one commit. From the reflog: evidence, not proof.",
        "commits added to {branch}, now at {to}" },
    [FK_GIT_HISTORY_REWRITTEN] = { "git_history_rewritten", I_GIT, LV_EVENT,
        { S("repo"), S("branch"), S("how"), S("from"), S("to") }, "{branch} rewritten by {how}: {from} -> {to}",
        "A reset, an amend, a rebase or a forced update (E12). From the reflog: evidence, not proof." },
    [FK_GIT_BRANCH_MOVED] = { "git_branch_moved", I_GIT, LV_EVENT,
        { S("repo"), S("branch"), SO("from"), S("to") }, "{branch} {from} -> {to}",
        "The branch names another commit, its reflog not saying how; from absent when its value "
        "before cannot be told (E12).",
        "{branch} now at {to}" },
};

size_t finding_nfields(enum finding_kind k) {
    size_t n = 0;
    while (n < FINDING_FIELDS_MAX && FINDING_KINDS[k].field[n].name != NULL) n++;
    return n;
}

/* diff-events.md, rule by rule: the spec's table is generated from here and
 * test_pins compares both ways, word for word. */
const struct event_rule EVENT_RULES[EVENT_RULE_COUNT] = {
    { "E1 placement",
        "Event records come after the last path record and before the trailer. A diff with none "
        "has none." },
    { "E2 shape",
        "`{\"event\": \"<kind>\", \"interp\": \"<interpreter>\", <the kind's fields, in "
        "finding-kinds.md's order>, \"text\": \"<its template>\", \"provisional\": true, \"paths\": "
        "[...]}`. The kind is an `event`-level kind of finding-kinds.md. `provisional` is "
        "present, and `true`, exactly when a path the event was derived from has the outcome "
        "`unknown` (decision P7): the event may not hold." },
    { "E3 paths",
        "The paths it was derived from, relative to the scope as in path records, sorted "
        "bytewise, each once, at least one (except `and_more`). `paths_b64` instead -- every "
        "element base64 -- when any is not valid UTF-8." },
    { "E4 order",
        "By interpreter, in the order text, pip, dpkg, git; within one, as the interpreter "
        "defines it in finding-kinds.md's terms: pip by normalized name, then kind; dpkg by "
        "Package, then Architecture, then kind; git by repository, then `HEAD` before every "
        "branch, then branch, then kind (decision 126). The same inputs give the same bytes." },
    { "E5 bound",
        "At most 65,536 event records per interpreter per diff: past that, the 65,536th is "
        "`{\"event\": \"and_more\", \"interp\": ..., \"n\": <that one and the rest>, \"text\": \"and {n} "
        "more\", \"paths\": []}`. An interpreter's per-diff state is bounded to match." },
    { "E6 failure",
        "An interpreter whose end hook fails emits `{\"event\": \"could_not_interpret\", \"interp\": "
        "..., \"text\": \"could not interpret\", \"paths\": [...], \"paths_truncated\": <n>}` and no "
        "other event: `paths` the first 1,024 of the paths it had claimed (bytewise; never a path "
        "E11 withholds), "
        "`paths_truncated` the number of the rest, present only when not 0 (decision P4). The "
        "diff does not fail." },
    { "E7 trailer",
        "The trailer gains `events`: the number of event records. `belay_diff_end` still counts "
        "path records only." },
    { "E8 forward",
        "A consumer ignores an event kind it does not know, as it ignores an unknown finding kind "
        "or field." },
    { "E9 invalid",
        "An event an interpreter adds that breaks its kind's row -- a kind not its own, not "
        "event-level, or the core's; a field missing, extra, or not a string field's value; text "
        "over 1,024 bytes -- is replaced, in its place, by `{\"event\": \"invalid_finding\", "
        "\"interp\": ..., \"text\": \"invalid finding\", \"paths\": [<its paths>]}`; the interpreter's "
        "other events stand (decisions P1, P5)." },
    { "E10 a file not interpreted",
        "A file an interpreter claims and cannot interpret gives one `{\"event\": "
        "\"could_not_interpret\", \"interp\": ..., \"text\": \"could not interpret\", \"paths\": [<the "
        "files>]}`; the interpreter's other events stand (the class of decision P1). pip: a "
        "dist-info that cannot be named, or a RECORD it must read that cannot be parsed -- that "
        "RECORD's path record carries `could_not_interpret` too, unless its outcome is `unknown`, "
        "and nothing more is read from it; a name with RECORDs added and removed other than one "
        "of each -- one event naming them, their path records carrying nothing (the pairing is "
        "known only once every path record is written). dpkg: a status that cannot be parsed -- "
        "its path record carries `could_not_interpret` too, unless its outcome is `unknown`." },
    { "E11 not captured",
        "A path whose outcome is `unknown` with `not_captured` as its only reason -- the side "
        "that lacks it excluded it, or it lies below an `unreadable` directory or a mount there "
        "(diff-v1, \"Present on one side only\") -- derives no event: that side was not looked "
        "at, so nothing was installed or removed there. Its path record stands. Any other "
        "`unknown` path still derives provisional events (E2). No interpreter is given it, so no "
        "event of the core's names it either: no `could_not_interpret` (E10) nor "
        "`content_unavailable` for it, and a failed end hook's event (E6) never lists it. "
        "(Decision 2026-11-02: approved, from the review of #33, D1; the core's events spelled "
        "out, decision 118.)" },
    { "E12 git events",
        "git's end hook derives repository-level events from the paths of this diff it explained "
        "-- loose refs, `packed-refs`, `HEAD`, reflogs -- per repository (a directory named "
        "`.git`; `repo` its path in the scope). A branch is a ref `refs/heads/<branch>`, named "
        "without `refs/heads/`. Its value on a side: its loose ref there; else its line in "
        "`packed-refs` when `packed-refs` is a path of this diff; else, before only, the old id "
        "of the first entry its reflog gained in this diff (all zeros: absent). One event per "
        "branch whose existence or commit differs: absent before by that evidence and present "
        "after, `git_branch_created`; present after with no evidence of before, "
        "`git_branch_moved` with no `from`; its loose ref removed and `packed-refs` without it (a "
        "path of this diff, or not -- git removes a branch from both), `git_branch_deleted`; a "
        "deletion and a creation at the same commit whose new reflog says `Branch: renamed`, one "
        "`git_branch_renamed`. A branch on both sides at different commits is decided by the "
        "entries its reflog gained in this diff, when they lead from its value before to its "
        "value after (each entry's old id the previous one's new, the first's old the value "
        "before, the last's new the value after): any `reset`, `commit (amend)`, operation "
        "containing `rebase`, message starting `branch: Reset to`, or message containing "
        "`forced-update` -- `git_history_rewritten`; else only commits (`commit`, `commit "
        "(merge)`, `cherry-pick`, `revert`, `am`) and fast-forwards or merges (a message "
        "containing `Fast-forward`; an operation starting with `merge` or `pull`) -- "
        "`git_commits_added`; else, or with no such entries, `git_branch_moved`. `HEAD` naming "
        "another branch, or detaching or attaching: `git_head_switched`; `HEAD` detached on both "
        "sides at different commits is the branch `HEAD`, decided by `logs/HEAD` as above. "
        "Remote-tracking refs and tags derive no event (their path findings stand). A path whose "
        "outcome is `unknown` adds no finding to its record (P8) but is read like any other where "
        "its copy can be read, as dpkg reads a status (a `raced` file's bytes were true when "
        "read, and may be no longer): every event derived from it is provisional (E2), so a "
        "branch whose ref raced is never silent. What git cannot read reduces what is claimed, "
        "never the fact the refs give: a reflog it cannot read is no evidence -- the move still "
        "comes from the refs, as `git_branch_moved`, without a how; a ref or `packed-refs` that "
        "cannot be read on a side gives no value there -- before, the reflog's evidence may still "
        "give one, and without one the event is `git_branch_moved` with no `from` (a branch only "
        "in `packed-refs` too); after, the branch derives no event. The record of a path git "
        "cannot read whose outcome is not `unknown` carries `content_unavailable`, and one "
        "`content_unavailable` event per reason names those paths (provisional when one of them "
        "is `unknown`). `paths`: every ref, `packed-refs` and `HEAD` path whose value the event "
        "uses, and a reflog only when its entries were used -- giving the value before or "
        "evidence of absence before, a rename, or how the branch moved (entries that lead from "
        "before to after but say not how are not used). The reflog is written by the watched "
        "process (diff-v1, git): the kinds that rest on it say so. (Decisions 126, 132: approved "
        "2026-11-02, events from an `unknown` path provisional rather than dropped; 137: what "
        "cannot be read, and `paths`, worded -- refs are proof, the reflog is evidence.)" },
};
