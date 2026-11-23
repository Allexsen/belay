#include "finding_schema.h"

#include "belay/interp.h"

#define IN(i) (1u << (i))
#define I_TEXT IN(BELAY_INTERP_TEXT)
#define I_PIP  IN(BELAY_INTERP_PIP)
#define I_DPKG IN(BELAY_INTERP_DPKG)
#define I_GIT  IN(BELAY_INTERP_GIT)
#define I_ACCOUNTS IN(BELAY_INTERP_ACCOUNTS)
#define I_SUDOERS  IN(BELAY_INTERP_SUDOERS)
#define I_CRON     IN(BELAY_INTERP_CRON)
#define I_SYSTEMD  IN(BELAY_INTERP_SYSTEMD)
#define I_SSHKEYS  IN(BELAY_INTERP_SSHKEYS)
#define I_TRUST    IN(BELAY_INTERP_TRUST)
#define I_CONFIG   IN(BELAY_INTERP_CONFIG)
#define S(n) { n, FT_STRING }
#define N(n) { n, FT_INT }
#define B(n) { n, FT_BOOL }
#define BO(n) { n, FT_BOOL, true }
#define NO(n) { n, FT_INT, true }
#define SO(n) { n, FT_STRING, true }
#define BY(n) { n, FT_BYTES }
#define L(n) { n, FT_LIST }
#define NN(n) { n, FT_INT, false, true }            /* int/null */
#define SNO(n) { n, FT_STRING, true, true }         /* string/null? */

const struct finding_kind_def FINDING_KINDS[FK_COUNT] = {
    [FK_COULD_NOT_INTERPRET] = { "could_not_interpret", IN_CORE, LV_PATH | LV_EVENT, { { 0 } },
        "could not interpret", "The interpreter failed on this path (R11), nothing else from it "
        "here; or, as an event, on the paths it names (E6, E10)." },
    [FK_INVALID_FINDING] = { "invalid_finding", IN_CORE, LV_PATH | LV_EVENT, { { 0 } }, "invalid finding",
        "A finding that broke the rules, replaced; or, as an event, an event that did (E9)." },
    [FK_AND_MORE] = { "and_more", IN_CORE, LV_PATH | LV_EVENT, { N("n") }, "and {n} more",
        "In the last place of a record past 4,096 findings, or of an interpreter's events past "
        "65,536: the findings or events from that place on, counted." },
    [FK_TOUCHED] = { "touched", IN_CORE, LV_EVENT, { { 0 } }, "written and now as it was",
        "A regular file read on both sides, its size and sha256 equal, whose inode the kernel record's "
        "journal has a write for between the two checkpoints (kernel-record K13). Only in a diff of "
        "two checkpoints of one system watch, taken under one recorder; no count of writes." },
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
        { S("package"), S("arch"), S("version"), BO("auto") }, "installed {package}:{arch} {version}",
        "`installed` after and not before."
        " auto: `true` when the after-manifest's `var/lib/apt/extended_states` has a stanza for this "
        "Package and Architecture with `Auto-Installed: 1`; `false` when it has none or it says `0`; "
        "absent when that file is not in the scope or cannot be read (SD-1)." },
    [FK_DPKG_REMOVED] = { "dpkg_removed", I_DPKG, LV_EVENT, { S("package"), S("arch"), S("version") },
        "removed {package}:{arch} {version}", "`installed` before and not after." },
    [FK_DPKG_UPGRADED] = { "dpkg_upgraded", I_DPKG, LV_EVENT,
        { S("package"), S("arch"), S("from"), S("to"), BO("auto") }, "upgraded {package}:{arch} {from} -> {to}",
        "`installed` on both sides; to higher (Debian version comparison)."
        " auto: `true` when the after-manifest's `var/lib/apt/extended_states` has a stanza for this "
        "Package and Architecture with `Auto-Installed: 1`; `false` when it has none or it says `0`; "
        "absent when that file is not in the scope or cannot be read (SD-1)." },
    [FK_DPKG_DOWNGRADED] = { "dpkg_downgraded", I_DPKG, LV_EVENT,
        { S("package"), S("arch"), S("from"), S("to"), BO("auto") }, "downgraded {package}:{arch} {from} -> {to}",
        "The same; to lower."
        " auto: `true` when the after-manifest's `var/lib/apt/extended_states` has a stanza for this "
        "Package and Architecture with `Auto-Installed: 1`; `false` when it has none or it says `0`; "
        "absent when that file is not in the scope or cannot be read (SD-1)." },
    [FK_DPKG_STATE_CHANGED] = { "dpkg_state_changed", I_DPKG, LV_EVENT,
        { S("package"), S("arch"), S("from"), S("to"), BO("auto") }, "{package}:{arch} {from} -> {to}",
        "The Status field differs, no installed or removed event covering it."
        " auto: `true` when the after-manifest's `var/lib/apt/extended_states` has a stanza for this "
        "Package and Architecture with `Auto-Installed: 1`; `false` when it has none or it says `0`; "
        "absent when that file is not in the scope or cannot be read (SD-1)." },
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
    [FK_GIT_REFLOG_LINES_IGNORED] = { "git_reflog_lines_ignored", I_GIT, LV_PATH, { S("ref"), N("lines") },
        "{ref}: {lines} lines git ignores",
        "Lines the reflog gained in this diff that git does not read as entries: blank, or not in the form "
        "of one (diff-events E12). git skips them silently; the count is evidence worth showing." },
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
    [FK_USER_ADDED] = { "user_added", I_ACCOUNTS, LV_EVENT,
        { S("name"), N("uid"), N("gid"), S("home"), S("shell"), NN("uid_min") },
        "user {name} added: uid {uid}, home {home}, shell {shell}",
        "A name in `passwd` after and not before (SA-1). uid_min: the `UID_MIN` of the "
        "`etc/login.defs` beside that `passwd` in the after-manifest, when it has exactly one "
        "`UID_MIN` line and its value is a decimal number; null otherwise -- not there, not kept, "
        "or not one number (SA-2, SI-4)." },
    [FK_USER_REMOVED] = { "user_removed", I_ACCOUNTS, LV_EVENT,
        { S("name"), N("uid") },
        "user {name} removed (uid {uid})",
        "A name in `passwd` before and not after." },
    [FK_USER_CHANGED] = { "user_changed", I_ACCOUNTS, LV_EVENT,
        { S("name"), S("field"), S("from"), S("to") },
        "user {name}: {field} {from} -> {to}",
        "A name on both sides: one event per differing field of `uid`, `gid`, `gecos`, `home`, "
        "`shell`, in that order, the values as written. A second name with uid 0 is no kind of "
        "its own (SA-4)." },
    [FK_USER_PASSWORD_IN_PASSWD] = { "user_password_in_passwd", I_ACCOUNTS, LV_EVENT,
        { S("name") },
        "user {name}: a password is set in passwd itself",
        "The second field after is none of `x`, `*`, `!`, and not empty where the after-manifest "
        "has an `etc/shadow` beside that `passwd`; and the name is new, or its second field "
        "before was one of those or another value. The value is never copied." },
    [FK_GROUP_ADDED] = { "group_added", I_ACCOUNTS, LV_EVENT,
        { S("name"), N("gid") },
        "group {name} added (gid {gid})",
        "A name in `group` after and not before; or (SI-3) a name on both sides whose second or "
        "third field differs: its line was removed and another added." },
    [FK_GROUP_REMOVED] = { "group_removed", I_ACCOUNTS, LV_EVENT,
        { S("name"), N("gid") },
        "group {name} removed (gid {gid})",
        "The reverse." },
    [FK_GROUP_MEMBERS_CHANGED] = { "group_members_changed", I_ACCOUNTS, LV_EVENT,
        { S("name"), L("added"), L("removed") },
        "group {name}: added {added}; removed {removed}",
        "A name on both sides whose fourth field differs as a set of names: those only after, "
        "those only before, each sorted bytewise." },
    [FK_PASSWORD_ENTRY_ADDED] = { "password_entry_added", I_ACCOUNTS, LV_EVENT,
        { S("file"), S("name") },
        "password database: entry added for {name}",
        "A line of `shadow` or `gshadow` (`file`: its path), by its first field, whose keyed "
        "digest is in the after capture's per-line digests and not in the before's (SA-6). Only "
        "when both captures kept digests under one sealing key." },
    [FK_PASSWORD_ENTRY_REMOVED] = { "password_entry_removed", I_ACCOUNTS, LV_EVENT,
        { S("file"), S("name") },
        "password database: entry removed for {name}",
        "The reverse." },
    [FK_PASSWORD_ENTRY_CHANGED] = { "password_entry_changed", I_ACCOUNTS, LV_EVENT,
        { S("file"), S("name") },
        "password database: entry changed for {name}",
        "A first field on both sides whose line's keyed digest differs. No other part of the line "
        "is known to belay." },
    [FK_SUDO_RULE_ADDED] = { "sudo_rule_added", I_SUDOERS, LV_EVENT,
        { S("path"), S("who"), S("hosts"), S("runas"), L("tags"), S("commands"), S("line") },
        "sudo rule added in {path}: {line}",
        "A logical line (SS-1) after and not before that is a user specification of the plain "
        "form (SS-2): `who`, `hosts`, `commands` the text between its marks, trimmed; `runas` the "
        "text inside `(...)`, empty when none is written; `tags` the `NAME:` words before the "
        "first command, without the colon; `line` the logical line, its physical lines joined, "
        "trimmed. Nothing is expanded, and nothing is said of what anyone may run (SS-5)." },
    [FK_SUDO_RULE_REMOVED] = { "sudo_rule_removed", I_SUDOERS, LV_EVENT,
        { S("path"), S("who"), S("hosts"), S("runas"), L("tags"), S("commands"), S("line") },
        "sudo rule removed in {path}: {line}",
        "The reverse." },
    [FK_SUDO_LINE_ADDED] = { "sudo_line_added", I_SUDOERS, LV_EVENT,
        { S("path"), S("line") },
        "sudoers line added in {path}: {line}",
        "Any other logical line that is not a comment or blank: an alias, `Defaults`, `@include`, "
        "`@includedir`, `#include`, `#includedir`, and a user specification SS-2 does not cover." },
    [FK_SUDO_LINE_REMOVED] = { "sudo_line_removed", I_SUDOERS, LV_EVENT,
        { S("path"), S("line") },
        "sudoers line removed in {path}: {line}",
        "The reverse." },
    [FK_SUDOERS_FILE_NOT_READ_BY_SUDO] = { "sudoers_file_not_read_by_sudo", I_SUDOERS, LV_EVENT,
        { S("path"), S("why") },
        "{path}: sudo does not read a file named like this ({why})",
        "A file directly in `etc/sudoers.d`, added or changed in this diff, whose name contains "
        "`.` (why: `a . in its name`) or ends `~` (why: `its name ends ~`) (SS-3). Its lines are "
        "events all the same. No rule from the mode (SS-4)." },
    [FK_CRON_JOB_ADDED] = { "cron_job_added", I_CRON, LV_EVENT,
        { S("path"), S("schedule"), S("user"), S("command"), L("env"), SNO("owner"), SO("in_words") },
        "cron job added in {path}: {schedule} {user} {command}",
        "A job line (SC-1) after and not before: `schedule` its five fields joined by one space, "
        "or its `@word`; `user` the sixth field in `etc/crontab` and `etc/cron.d/*`, the file's "
        "name in `crontabs/*`; `command` the rest of the line as written; `env` the `SHELL`, "
        "`PATH`, `MAILTO`, `CRON_TZ` lines in force above it in its file, as written. in_words: "
        "only for the forms of SW-1 to SW-6, absent otherwise (SW-8). owner: the package that "
        "owns the file (SI-5); null: in no package; absent: no dpkg database in the "
        "after-manifest, or one that could not be read whole." },
    [FK_CRON_JOB_REMOVED] = { "cron_job_removed", I_CRON, LV_EVENT,
        { S("path"), S("schedule"), S("user"), S("command"), L("env"), SNO("owner"), SO("in_words") },
        "cron job removed in {path}: {schedule} {user} {command}",
        "The reverse; `owner` by the after-manifest all the same." },
    [FK_CRON_ENV_CHANGED] = { "cron_env_changed", I_CRON, LV_EVENT,
        { S("path"), S("name"), S("from"), S("to") },
        "{path}: {name} {from} -> {to}",
        "A `NAME=value` line added, removed or changed: a name with one such line on each side "
        "whose values differ is one event; otherwise one event per line added (from empty) and "
        "per line removed (to empty)." },
    [FK_CRON_SCRIPT_ADDED] = { "cron_script_added", I_CRON, LV_EVENT,
        { S("path"), SNO("owner") },
        "{path} added",
        "A file directly in `etc/cron.hourly`, `cron.daily`, `cron.weekly` or `cron.monthly`; "
        "never read for meaning, and no schedule is claimed for it (SC-5). owner: the package "
        "that owns it (SI-5); null: in no package; absent: no dpkg database in the "
        "after-manifest, or one that could not be read whole." },
    [FK_CRON_SCRIPT_REMOVED] = { "cron_script_removed", I_CRON, LV_EVENT,
        { S("path"), SNO("owner") },
        "{path} removed",
        "The same, removed." },
    [FK_CRON_SCRIPT_CHANGED] = { "cron_script_changed", I_CRON, LV_EVENT,
        { S("path"), SNO("owner") },
        "{path} changed",
        "The same: its content, or its mode." },
    [FK_CRON_FILE_NOT_RUN] = { "cron_file_not_run", I_CRON, LV_EVENT,
        { S("path"), S("why") },
        "{path}: cron does not run a file like this ({why})",
        "Only where the after-manifest's dpkg database has the package `cron` installed (SC-2). A "
        "file of `etc/cron.d` added or changed in this diff whose name has a character outside "
        "`A-Za-z0-9_-` (why: `name`) or that group or others may write (why: `mode`) (SC-3); a "
        "file of the four directories whose name has such a character (why: `name`) or that has "
        "no execute bit (why: `not executable`) (SC-4)." },
    [FK_UNIT_LINKED] = { "unit_linked", I_SYSTEMD, LV_EVENT,
        { S("unit"), S("into"), S("target"), SNO("owner") },
        "{unit} linked into {into}",
        "A symbolic link added in a directory named `<x>.wants` or `<x>.requires` under a "
        "directory systemd reads units from: `unit` the link's name, `into` `<x>`, `target` the "
        "link's text. Under a home's `.config/systemd/user`, `unit` is prefixed by that "
        "directory's path (SY-3a). Never `enabled` (SY-3). owner: the package that owns the file "
        "the link's text names, read from the link's directory (SI-5); null: in no package; "
        "absent: no dpkg database in the after-manifest, or one that could not be read whole." },
    [FK_UNIT_UNLINKED] = { "unit_unlinked", I_SYSTEMD, LV_EVENT,
        { S("unit"), S("into"), S("target"), SNO("owner") },
        "{unit} unlinked from {into}",
        "The same, removed." },
    [FK_UNIT_MASKED] = { "unit_masked", I_SYSTEMD, LV_EVENT,
        { S("unit") },
        "{unit} masked",
        "A unit name directly in `etc/systemd/system` or `etc/systemd/user` (or a home's "
        "`.config/systemd/user`) that became a symbolic link to `/dev/null` or an empty file." },
    [FK_UNIT_UNMASKED] = { "unit_unmasked", I_SYSTEMD, LV_EVENT,
        { S("unit") },
        "{unit} unmasked",
        "One that stopped being that." },
    [FK_UNIT_FILE_ADDED] = { "unit_file_added", I_SYSTEMD, LV_EVENT,
        { S("path"), SNO("owner") },
        "unit file {path} added",
        "A regular file with a unit suffix (`.service`, `.socket`, `.device`, `.mount`, "
        "`.automount`, `.swap`, `.target`, `.path`, `.timer`, `.slice`, `.scope`), or a file "
        "under a `<unit>.d` directory. An empty one in `etc/systemd` is `unit_masked` instead. "
        "owner: the package that owns it (SI-5); null: in no package; absent: no dpkg database in "
        "the after-manifest, or one that could not be read whole." },
    [FK_UNIT_FILE_REMOVED] = { "unit_file_removed", I_SYSTEMD, LV_EVENT,
        { S("path"), SNO("owner") },
        "unit file {path} removed",
        "The same, removed." },
    [FK_UNIT_FILE_CHANGED] = { "unit_file_changed", I_SYSTEMD, LV_EVENT,
        { S("path"), SNO("owner") },
        "unit file {path} changed",
        "The same, its content changed." },
    [FK_UNIT_OVERRIDES_PACKAGED] = { "unit_overrides_packaged", I_SYSTEMD, LV_EVENT,
        { S("unit"), S("path"), S("over") },
        "{path} takes the place of {over}",
        "A unit file added under `etc/systemd/system` (or `etc/systemd/user`) while the "
        "after-manifest has one of that name under `usr/lib/systemd/system` (`.../user`), or "
        "under `lib/systemd/...`: `over` is that path." },
    [FK_UNIT_ALIAS_ADDED] = { "unit_alias_added", I_SYSTEMD, LV_EVENT,
        { S("alias"), S("target") },
        "{alias} is a link to {target}",
        "A symbolic link added directly in `etc/systemd/system` or `etc/systemd/user` (or a "
        "home's `.config/systemd/user`), not to `/dev/null`: `target` its text." },
    [FK_UNIT_ALIAS_REMOVED] = { "unit_alias_removed", I_SYSTEMD, LV_EVENT,
        { S("alias"), S("target") },
        "{alias} is no longer a link to {target}",
        "The same, removed." },
    [FK_INIT_SCRIPT_ADDED] = { "init_script_added", I_SYSTEMD, LV_EVENT,
        { S("path"), SNO("owner"), B("executable") },
        "init script {path} added",
        "`etc/rc.local` or a file directly in `etc/init.d`; never read for meaning. executable: "
        "whether any execute bit is set (SY-3b). owner: the package that owns it (SI-5); null: in "
        "no package; absent: no dpkg database in the after-manifest, or one that could not be "
        "read whole." },
    [FK_INIT_SCRIPT_REMOVED] = { "init_script_removed", I_SYSTEMD, LV_EVENT,
        { S("path"), SNO("owner"), B("executable") },
        "init script {path} removed",
        "The same, removed; executable: as it was." },
    [FK_INIT_SCRIPT_CHANGED] = { "init_script_changed", I_SYSTEMD, LV_EVENT,
        { S("path"), SNO("owner"), B("executable") },
        "init script {path} changed",
        "The same: its content, or its mode; executable: as it is after." },
    [FK_TIMER_FILE_ADDED] = { "timer_file_added", I_SYSTEMD, LV_EVENT,
        { S("path"), L("on_calendar"), SNO("owner"), SO("in_words") },
        "timer {path} added: {on_calendar}",
        "A `.timer` unit file added (it is a `unit_file_added` too): `on_calendar` its "
        "`OnCalendar=` values as written, in order, or empty. in_words: SW-7, absent otherwise. A "
        "changed timer whose `OnCalendar=` values differ is one removed and one added (SI-3). "
        "owner: the package that owns it (SI-5); null: in no package; absent: no dpkg database in "
        "the after-manifest, or one that could not be read whole." },
    [FK_TIMER_FILE_REMOVED] = { "timer_file_removed", I_SYSTEMD, LV_EVENT,
        { S("path"), L("on_calendar"), SNO("owner"), SO("in_words") },
        "timer {path} removed: {on_calendar}",
        "The same, removed." },
    [FK_SSH_KEY_ADDED] = { "ssh_key_added", I_SSHKEYS, LV_EVENT,
        { S("path"), S("type"), S("fingerprint"), S("comment"), L("options") },
        "key added in {path}: {type} {fingerprint} {comment}",
        "A key line (SK-1) of an `authorized_keys` or `authorized_keys2` whose `(type, "
        "fingerprint)` is in the file after and not before, or whose options or comment differ "
        "(SI-3: one removed, one added). fingerprint: `SHA256:` and the unpadded base64 of the "
        "sha256 of the decoded key. options: as written, split at commas outside double quotes. "
        "The event names the file, not whose login it opens (SK-2)." },
    [FK_SSH_KEY_REMOVED] = { "ssh_key_removed", I_SSHKEYS, LV_EVENT,
        { S("path"), S("type"), S("fingerprint"), S("comment"), L("options") },
        "key removed in {path}: {type} {fingerprint} {comment}",
        "The reverse." },
    [FK_SSH_CA_ADDED] = { "ssh_ca_added", I_SSHKEYS, LV_EVENT,
        { S("path"), S("type"), S("fingerprint"), S("comment"), L("options") },
        "certificate authority added in {path}: {type} {fingerprint} {comment}",
        "The same, for a key line whose options include `cert-authority`." },
    [FK_SSH_CA_REMOVED] = { "ssh_ca_removed", I_SSHKEYS, LV_EVENT,
        { S("path"), S("type"), S("fingerprint"), S("comment"), L("options") },
        "certificate authority removed in {path}: {type} {fingerprint} {comment}",
        "The reverse." },
    [FK_TRUST_ANCHOR_ADDED] = { "trust_anchor_added", I_TRUST, LV_EVENT,
        { S("path"), S("target"), SO("subject"), SO("fingerprint"), SNO("owner") },
        "certificate added to the trust store: {subject} ({path})",
        "A symbolic link or regular file added directly under `etc/ssl/certs` whose name ends "
        "`.pem` or `.crt`, the bundle `ca-certificates.crt` aside (TS-1). target: the path, "
        "relative to the scope, where the chain of links ends by the after-manifest (the path "
        "itself for a regular file; where the chain leaves what the manifest records, the last "
        "path it names). subject, fingerprint: from the PEM when the target's content is kept and "
        "holds exactly one certificate; `subject` as `openssl x509 -noout -subject` prints it "
        "after `subject=`, `fingerprint` the sha256 of the DER in uppercase hex pairs joined by "
        "`:`; else both absent (TS-2). Not validated. owner: the package that owns the target "
        "(SI-5); null: in no package; absent: no dpkg database in the after-manifest, or one that "
        "could not be read whole.",
        "certificate added to the trust store: {path}" },
    [FK_TRUST_ANCHOR_REMOVED] = { "trust_anchor_removed", I_TRUST, LV_EVENT,
        { S("path"), S("target"), SO("subject"), SO("fingerprint"), SNO("owner") },
        "certificate removed from the trust store: {subject} ({path})",
        "The same, removed: target, subject and fingerprint by the entries the diff was given and "
        "the after-manifest; absent where they cannot be told.",
        "certificate removed from the trust store: {path}" },
    [FK_CONFIG_KEY_ADDED] = { "config_key_added", I_CONFIG, LV_EVENT,
        { S("path"), S("grammar"), L("context"), S("key"), S("value") },
        "{path}: {context} › {key} added: {value}",
        "A value of `key` in `context` that the file has after and not before, unless the key has "
        "one value there on each side (CF-2). grammar: `nginx`, `sshd`, `ini`, `keyvalue` or "
        "`namevalue`, by the file's path (system-config.md CF-N to CF-L). context: the enclosing "
        "block headers, outermost first, or the section name, as written; empty at the top level. "
        "key: as written; `sshd` keywords are compared without regard to ASCII case. value: the "
        "rest of the directive as written, each run of whitespace made one space (CF-1); of an "
        "opaque `nginx` block, whose key is its header, the sha256 of the text between its braces. "
        "The values of a key in a context are a set. A symbolic link is no file of its path: its "
        "target's file is keyed where it is. The text of one file, never the setting in force." },
    [FK_CONFIG_KEY_REMOVED] = { "config_key_removed", I_CONFIG, LV_EVENT,
        { S("path"), S("grammar"), L("context"), S("key"), S("value") },
        "{path}: {context} › {key} removed: {value}",
        "The reverse." },
    [FK_CONFIG_KEY_CHANGED] = { "config_key_changed", I_CONFIG, LV_EVENT,
        { S("path"), S("grammar"), L("context"), S("key"), S("from"), S("to") },
        "{path}: {context} › {key} {from} -> {to}",
        "The key has exactly one value in that context on each side and they differ (CF-2); key "
        "as written after. A repeated key is never reported as changed." },
    [FK_CONFIG_NOT_KEYED] = { "config_not_keyed", I_CONFIG, LV_EVENT,
        { S("path"), S("grammar"), S("why") },
        "{path}: shown as lines ({why})",
        "The file's keys are not compared, on a side or both; the text interpreter's line "
        "findings stand (CF-6). why: `too large` (a side over 1 MiB or of more than 65,536 "
        "triples: CF-4), else `does not parse` (CF-4), else `a block header is not unique` (two "
        "blocks at one level, or two sections, with the same header text on a side: CF-3)." },
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
        "git's end hook derives repository-level events from the paths of this diff it explained -- "
        "loose refs, `packed-refs`, `HEAD`, reflogs -- per repository (a directory named `.git`; "
        "`repo` its path in the scope). A branch is a ref `refs/heads/<branch>`, named without "
        "`refs/heads/`. Its value on a side: its loose ref there; else its line in `packed-refs` "
        "when `packed-refs` is a path of this diff; else, before only, the old id of the first entry "
        "its reflog gained in this diff (all zeros: absent). One event per branch whose existence or "
        "commit differs: absent before by that evidence and present after, `git_branch_created`; "
        "present after with no evidence of before, `git_branch_moved` with no `from`; its loose ref "
        "removed and `packed-refs` without it (a path of this diff, or not -- git removes a branch "
        "from both), `git_branch_deleted`; a deletion and a creation at the same commit whose new "
        "reflog says `Branch: renamed`, one `git_branch_renamed`. A branch on both sides at "
        "different commits is decided by the entries its reflog gained in this diff, when they lead "
        "from its value before to its value after (each entry's old id the previous one's new, the "
        "first's old the value before, the last's new the value after): any `reset`, `commit "
        "(amend)`, operation containing `rebase`, message starting `branch: Reset to`, or message "
        "containing `forced-update` -- `git_history_rewritten`; else only commits (`commit`, `commit "
        "(merge)`, `cherry-pick`, `revert`, `am`) and fast-forwards or merges (a message containing "
        "`Fast-forward`; an operation starting with `merge` or `pull`) -- `git_commits_added`; else, "
        "or with no such entries, `git_branch_moved`. `HEAD` naming another branch, or detaching or "
        "attaching: `git_head_switched`; `HEAD` detached on both sides at different commits is the "
        "branch `HEAD`, decided by `logs/HEAD` as above. Remote-tracking refs and tags derive no "
        "event (their path findings stand). A path whose outcome is `unknown` adds no finding to its "
        "record (P8) but is read like any other where its copy can be read, as dpkg reads a status "
        "(a `raced` file's bytes were true when read, and may be no longer): every event derived "
        "from it is provisional (E2), so a branch whose ref raced is never silent. What git cannot "
        "read reduces what is claimed, never the fact the refs give: a reflog it cannot read is no "
        "evidence -- the move still comes from the refs, as `git_branch_moved`, without a how; a ref "
        "or `packed-refs` that cannot be read on a side gives no value there -- before, the reflog's "
        "evidence may still give one, and without one the event is `git_branch_moved` with no `from` "
        "(a branch only in `packed-refs` too); after, the branch derives no event. A side git cannot "
        "parse counts as one it cannot read (and is a `could_not_interpret` event, E10); parsing a "
        "reflog is parsing only the entries it gained in this diff -- those after before's bytes "
        "when they are a prefix of after's ending at a line's end, and none otherwise (diff-v1, git: "
        "`git_reflog_rewritten`) -- never its older entries. A reflog's line is an entry when git "
        "reads it as one: `<old> <new> <identity>> <time> <zone>` and the message -- the ids 40 or "
        "64 hex digits of either case, the identity up to the first `>` with a space after it, the "
        "time a number other than 0 as `strtoumax` reads it, the zone `+` or `-` and four digits, "
        "the message after one tab when there is one; every other line, a blank one included, git "
        "skips, and so does belay, counting the lines the reflog gained in this diff that git skips "
        "in `git_reflog_lines_ignored` (decision 202). A reflog's last line without its newline is "
        "no entry, and not counted: git does not read it as one. A loose ref's or `HEAD`'s value is "
        "read as git reads it: `ref:`, any spaces or tabs, then the name to the line's end, trailing "
        "whitespace cut; or an object id of either case at the start, followed by the end or by "
        "whitespace, whatever follows ignored -- a value git calls a broken ref is one git cannot "
        "parse (E10). An id read in either case is written lowercased, as git prints it (decision "
        "213). A branch whose loose ref is symbolic (`ref: refs/heads/<other>`) on a side is an "
        "alias of its target there, as git lists it (`alias -> main`), not a branch of its own: it "
        "derives no event, its path finding stands, and the target's events are the target's own "
        "(decision 213). A last line without its newline is read, as git reads it; a `packed-refs` "
        "that ends without a newline is one git refuses, so a side git cannot parse (E10). A branch "
        "removed whose value before cannot be told derives no event (`git_branch_deleted` needs "
        "`was`), and `HEAD` that cannot be read on a side derives none. The record of a path git "
        "cannot read whose outcome is not `unknown` carries `content_unavailable`, and one "
        "`content_unavailable` event per reason names those paths (provisional when one of them is "
        "`unknown`). `paths`: every ref, `packed-refs` and `HEAD` path whose value the event uses, "
        "and a reflog only when its entries were used -- giving the value before or evidence of "
        "absence before, a rename, or how the branch moved (entries that lead from before to after "
        "but say not how are not used). The reflog is written by the watched process (diff-v1, git): "
        "the kinds that rest on it say so. (Decisions 126, 132: approved 2026-11-02, events from an "
        "`unknown` path provisional rather than dropped; 137: what cannot be read, and `paths`, "
        "worded -- refs are proof, the reflog is evidence; 141: a side not parsed, a removal not "
        "dated, HEAD not read; 144: a reflog parsed by the entries it gained; 160, 183: a reflog's "
        "unterminated last line no entry; 183: a ref's and HEAD's read, an unterminated packed-refs "
        "refused -- as git does; 202: the reflog lines git skips skipped and counted, refs read as "
        "git reads them; 213: ids lowercased, a symbolic loose branch an alias.)" },
    { "E13 order, amended",
        "By interpreter, in the order text, pip, dpkg, accounts, sudoers, cron, systemd, sshkeys, "
        "trust, config, git: this list supersedes E4's (system-interpreters.md SI-1). Within pip, "
        "dpkg and git, as E4 says. Within each of accounts, sudoers, cron, systemd, sshkeys, trust "
        "and config: by path (the first of the event's `paths`), then by the line's place in the "
        "file (a removed line's place before, an added line's after; an event of the file as a "
        "whole before every line's), removed before added, then by kind in finding-kinds.md's "
        "order. The same inputs give the same bytes." },
};
