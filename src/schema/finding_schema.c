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

const struct finding_kind_def FINDING_KINDS[FK_COUNT] = {
    [FK_COULD_NOT_INTERPRET] = { "could_not_interpret", IN_ANY, LV_PATH, { { 0 } },
        "could not interpret", "The interpreter failed on this path (R11); nothing else from it here." },
    [FK_INVALID_FINDING] = { "invalid_finding", IN_ANY, LV_PATH, { { 0 } }, "invalid finding",
        "A finding that broke the rules, replaced." },
    [FK_AND_MORE] = { "and_more", IN_ANY, LV_PATH, { N("n") }, "and {n} more",
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
        { S("name"), S("version"), N("files_added"), N("files_removed"), N("files_changed") },
        "reinstalled {name} {version}: +{files_added} -{files_removed} ~{files_changed} files",
        "The same dist-info on both sides, its RECORD changed." },
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
    [FK_GIT_HOOK_ADDED] = { "git_hook_added", I_GIT, LV_PATH, { S("hook"), B("executable") },
        "hook {hook} added", "" },
    [FK_GIT_HOOK_REMOVED] = { "git_hook_removed", I_GIT, LV_PATH, { S("hook") }, "hook {hook} removed",
        "" },
    [FK_GIT_HOOK_CHANGED] = { "git_hook_changed", I_GIT, LV_PATH, { S("hook"), B("executable") },
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
        "finding-kinds.md's order>, \"text\": \"<its template>\", \"paths\": [...]}`. The kind is an "
        "`event`-level kind of finding-kinds.md, or `and_more`." },
    { "E3 paths",
        "The paths it was derived from, relative to the scope as in path records, sorted "
        "bytewise, each once, at least one (except `and_more`). `paths_b64` instead -- every "
        "element base64 -- when any is not valid UTF-8." },
    { "E4 order",
        "By interpreter, in the order text, pip, dpkg, git; within one, as the interpreter "
        "defines it in finding-kinds.md's terms: pip by normalized name, then kind; dpkg by "
        "Package, then Architecture, then kind. The same inputs give the same bytes." },
    { "E5 bound",
        "At most 65,536 event records per interpreter per diff; past that, one final `{\"event\": "
        "\"and_more\", \"interp\": ..., \"n\": <the rest>, \"text\": \"and {n} more\", \"paths\": []}`. An "
        "interpreter's per-diff state is bounded to match." },
    { "E6 failure",
        "An interpreter that fails in its end hook emits `{\"event\": \"could_not_interpret\", "
        "\"interp\": ..., \"text\": \"could not interpret\", \"paths\": [...]}` with the paths it had "
        "claimed, and no other event. The diff does not fail." },
    { "E7 trailer",
        "The trailer gains `events`: the number of event records. `belay_diff_end` still counts "
        "path records only." },
    { "E8 forward",
        "A consumer ignores an event kind it does not know, as it ignores an unknown finding kind "
        "or field." },
};
