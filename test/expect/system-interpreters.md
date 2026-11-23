# Pin: the system interpreters

**Status.** Approved by the author, 2026-11-19, after two independent reviews. The code follows in later
PRs: until a row's code has merged, nothing in it is implemented, and `docs/cli.md` says only what is.
Rows marked **owed** state what a run must show before the code resting on them merges.

**Evidence.** "Measured" means run on GitHub-hosted Ubuntu 24.04 (kernel 7.0) and 22.04 (kernel 6.8)
runners, 2026-11-18 and 19. The file names and section labels given (`events.txt` E1, `facts.txt` P4,
`owed.txt` U1, `round-3`, ...) are those runs' outputs, kept in the project's notes, not in this repository.

**What this is.** What belay reads in `passwd`, `group`, sudoers, cron, systemd's directories,
apt's record and `authorized_keys`, and the events it states. **An event states the text of a
file. It never states an effect**: not what sudo would answer, not what systemd will start.
"Measured" is `out-ubuntu-24.04/facts.txt` and
`out-ubuntu-22.04/facts.txt` (sudo 1.9.15p5 and 1.9.9; Debian's cron; systemd 255 and 249).

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## Common rules

| id | rule |
|---|---|
| SI-1 | diff-events E4's order becomes: text, pip, dpkg, accounts, sudoers, cron, systemd, sshkeys, trust, config, git. Within each of the new ones: by path, then by the line's place in the file, removed before added. |
| SI-2 | A claimed file that is unreadable, `sealed` against the claim, or does not parse gives `could_not_interpret` (E10) naming it; its record in the diff stands. Nothing is skipped silently. |
| SI-3 | A changed line is a removed one and an added one, unless a kind below says otherwise. |
| SI-4 | **Lookup.** At its end hook an interpreter may read the entry, and the stored copy if kept, of a path of the after-manifest it does not claim. Used for: `etc/login.defs` (accounts), the dpkg database (ownership). A lookup that fails is said in the event (`uid_min: null`, `owner` absent), never assumed. |
| SI-5 | **Ownership.** `owner` on an event is a package name or `null`: whether any `var/lib/dpkg/info/*.list` of the after-manifest lists the path, after applying `var/lib/dpkg/diversions`, and trying the path both as recorded and with the top-level links (`bin`, `sbin`, `lib`, `lib32`, `lib64`, `libx32` into `usr`) rewritten each way. The lists are streamed once per diff against the set of paths asked about. No dpkg database in the scope: `owner` is absent. The receipt's words for `null`: `in no package`. |
| SI-6 | `in_words` (a string) on cron and timer events only for the forms of the table at the end. Absent otherwise. |

| rows | how established |
|---|---|
| SI-5 | measured: the same unit's link points at `/lib/systemd/system/nginx.service` on 22.04 and `/usr/lib/systemd/system/nginx.service` on 24.04. Measured (`owed-*/owed.txt`, O2): `nginx-common.list` says `/lib/systemd/system/nginx.service` on 22.04 and `/usr/lib/systemd/system/nginx.service` on 24.04, `coreutils.list` says `/bin/cat` on 22.04, and 528 lists on 24.04 still have paths under `/bin`, `/sbin` or `/lib`; `diversions` is three lines per diversion: the path, where it was moved, the package. |

## accounts

Claims `etc/passwd`, `etc/group`. Receives, from the capture, the per-line digests of `etc/shadow` and `etc/gshadow` (SA-6).

| kind | fields | text | when |
|---|---|---|---|
| `user_added` | name, uid, gid, home, shell, uid_min | `user {name} added: uid {uid}, home {home}, shell {shell}` | a name in `passwd` after and not before |
| `user_removed` | name, uid | `user {name} removed (uid {uid})` | the reverse |
| `user_changed` | name, field, from, to | `user {name}: {field} {from} -> {to}` | once per differing field of `uid`, `gid`, `gecos`, `home`, `shell` |
| `user_password_in_passwd` | name | `user {name}: a password is set in passwd itself` | the second field after is none of `x`, `*`, `!`, empty-with-shadow; its value is never copied |
| `group_added`, `group_removed` | name, gid | `group {name} added (gid {gid})` | by name |
| `group_members_changed` | name, added, removed | `group {name}: added {added}; removed {removed}` | the fourth field as a set |
| `password_entry_added`, `_removed`, `_changed` | file, name | `{file}: password entry {added} for {name}` | a line of `shadow` or `gshadow`, by its first field, whose keyed digest appeared, went or differs |

| id | rule | how established |
|---|---|---|
| SA-1 | A line is seven `:`-separated fields (`group`: four). A line with another count, or beginning `+` or `-`, makes the file `could_not_interpret`. Two lines with one name: the first is the user, the file is also `could_not_interpret`. | from the file formats; not run |
| SA-2 | `uid_min` is the `UID_MIN` of the after-manifest's `etc/login.defs` (config's `namevalue` reading), or null. The receipt says `below UID_MIN {n}` when uid is lower. belay does not say "system account". | measured: `UID_MIN 1000` on both; `useradd --system` gave uid 999 and 997, `adduser --system` 109 and 118, `useradd -m` 1002 |
| SA-3 | What the tools were seen to write: `useradd` adds one line to `passwd` and one to `group`, and rewrites `shadow`, `gshadow` and the `-` backups. | measured (P4) |
| SA-4 | A second name with uid 0, or a `user_changed` to uid 0, is not a separate kind: the flag list reads the fields. | design |
| SA-5 | Accounts that are not lines of `passwd` (sssd, `etc/userdb`, NIS) are not seen. | from knowledge |
| SA-6 | **Per-line digests.** For `etc/shadow` and `etc/gshadow` the capture computes, per line, HMAC-SHA256 under the sealing key of the whole line, and keeps `{name, digest}` in the checkpoint (`shadow.lines`, mode 600). The name is the line's first field. No other part of a line is written anywhere. **The author's OK is asked for this row specifically: it is one step past "never stored".** Without it: `password database changed`, and no names. | design |

## sudoers

Claims `etc/sudoers`, `etc/sudoers.d/*` (kept, though mode 0440: manifest-v5 V5-E5).

| kind | fields | text | when |
|---|---|---|---|
| `sudo_rule_added`, `sudo_rule_removed` | path, who, hosts, runas, tags, commands, line | `sudo rule {added} in {path}: {line}` | a logical line that is a user specification of the plain form (SS-2) |
| `sudo_line_added`, `sudo_line_removed` | path, line | `sudoers line {added} in {path}: {line}` | any other logical line that is not a comment or blank: aliases, `Defaults`, `@include`, `@includedir`, `#include`, `#includedir`, and a user specification SS-2 does not cover |
| `sudoers_file_not_read_by_sudo` | path, why | `{path}: sudo does not read a file named like this ({why})` | a file in `etc/sudoers.d` whose name contains `.` or ends `~` |

| id | rule | how established |
|---|---|---|
| SS-1 | A logical line: physical lines joined at a trailing `\`. A comment is a line whose first non-blank is `#` not followed by `include`, `includedir`, or a digit (a uid). | measured: `@includedir /etc/sudoers.d` is how both releases include; `visudo -c` accepted `#includedir` and `@includedir` lines in `forms` |
| SS-2 | The plain form: `WHO HOSTS = [(RUNAS)] [TAG: ...] COMMANDS` on one logical line, one `=`, no `:`-separated second specification. `who`, `hosts`, `runas`, `commands` are the text between those marks, trimmed; `tags` the list of `NAME:` before the first command. Nothing is expanded: an alias name stays a name. | measured: `visudo -c` parsed all of `forms`; `sudo -l` shows `(ALL) NOPASSWD: /bin/echo ...`, `(root) NOPASSWD: /bin/ls, PASSWD: /bin/cat`, and the alias expanded by sudo, not by belay |
| SS-3 | The name rule of `sudoers.d`. | measured, both versions: of `90-site`, `UPPER_ok`, `with.dot`, `backup~`, the first two are in `sudo -l -U`, the last two are not |
| SS-4 | **No rule from the mode.** | measured, both versions: a mode-0644 file's rule is in `sudo -l -U`, though `visudo -c` prints `bad permissions, should be mode 0440` |
| SS-5 | belay never states what a user may run. | the review's F35: host lists, later rules, `Defaults !authenticate`, aliases all decide it |

## cron

Claims `etc/crontab`, `etc/cron.d/*`, `var/spool/cron/crontabs/*` (kept, though mode 600), and the files of `etc/cron.hourly`, `cron.daily`, `cron.weekly`, `cron.monthly`.

| kind | fields | text | when |
|---|---|---|---|
| `cron_job_added`, `cron_job_removed` | path, schedule, user, command, env, owner, in_words | `cron job {added} in {path}: {schedule} {user} {command}` | a line that is a job (SC-1) |
| `cron_env_changed` | path, name, from, to | `{path}: {name} {from} -> {to}` | one `NAME=value` line of a name on each side, its value changed |
| `cron_env_added`, `cron_env_removed` | path, name, value | `{path}: {name} {added}: {value}` | otherwise a `NAME=value` line added or removed (measured: `SHELL  -> /bin/sh` read as a change) |
| `cron_script_added`, `_removed`, `_changed` | path, owner | `{path} {added}` | a file of the four directories; never read for meaning |
| `cron_file_not_run` | path, why | `{path}: cron does not run a file like this ({why})` | SC-3, SC-4 |

| id | rule | how established |
|---|---|---|
| SC-1 | A job line: five schedule fields or one `@word`, then in `etc/crontab` and `etc/cron.d/*` a user, then the command to the end of the line, as written (`%` included). In `crontabs/<name>` there is no user field: `user` is the file's name. `env` is the `SHELL`, `PATH`, `MAILTO`, `CRON_TZ` lines above the job in its file, as written. | measured: the spool file is `crontabs/siteuser`, mode 600, owner the user, with three `#` header lines crontab adds; `etc/crontab`'s lines have the user field |
| SC-2 | The validity rules (SC-3, SC-4) are stated only when the dpkg database of the same capture has package `cron` installed. Otherwise jobs are listed and no `cron_file_not_run` is given. | measured on that package only |
| SC-3 | `etc/cron.d`: a name with a character outside `A-Za-z0-9_-` (`why: name`), or a file writable by group or others (`why: mode`). | measured: `ok-name` and `UPPER_1` ran within 130 s; `has.dot` and `tilde~` did not; `mode666` logged `INSECURE MODE (group/other writable)` |
| SC-4 | The four directories: a name with a character outside `A-Za-z0-9_-` (`why: name`) and a file without an execute bit (`why: not executable`). | measured, both releases (`owed-*/owed.txt`, O1): of `ok-name`, `UPPER_1`, `under_score`, `has.dot`, `tilde~` and a mode-644 file, `run-parts --test` lists the first three |
| SC-5 | Whether and when the four directories run is the text of `etc/crontab` and anacron's; belay lists the scripts and claims no schedule for them. | measured: both releases' `etc/crontab` run them through `run-parts` unless anacron is installed |
| SC-6 | Other cron implementations (cronie, systemd-cron, busybox) read these files by other rules; under SC-2 nothing about validity is said for them. | from knowledge |

## systemd

Claims `etc/systemd/system/**`, `etc/systemd/user/**`, `usr/lib/systemd/system/**`, `usr/lib/systemd/user/**` (and `lib/systemd/...` where `lib` is a directory), `**/.config/systemd/user/**` in the homes watch-system.md names, and `etc/rc.local`, `etc/init.d/*`.

| kind | fields | text | when |
|---|---|---|---|
| `unit_linked`, `unit_unlinked` | unit, into, target, owner | `{unit} linked into {into}` | a symlink added or removed in a directory named `<x>.wants` or `<x>.requires`; `into` is `<x>`, `target` the link's text |
| `unit_masked`, `unit_unmasked` | unit | `{unit} masked` | a unit name in `etc/systemd/*/` that became, or stopped being, a symlink to `/dev/null` or an empty file |
| `unit_file_added`, `_removed`, `_changed` | path, owner | `unit file {path} {added}` | a regular file with a unit suffix, or a file under `<unit>.d/`; its keys are config's (system-config.md) |
| `unit_overrides_packaged` | unit, path, over | `{path} takes the place of {over}` | a unit file added under `etc/systemd/system` while `usr/lib/systemd/system` (or `lib/...`) has one of that name |
| `unit_alias_added`, `_removed` | alias, target | `{alias} is a link to {target}` | a symlink in `etc/systemd/*/` itself, not to `/dev/null` |
| `init_script_added`, `_removed`, `_changed` | path, owner, executable | `init script {path} {added}` | `etc/rc.local` or a file of `etc/init.d`; never read for meaning. With `owner: null` the receipt gives it a line of its own. |
| `timer_file_added`, `_removed` | path, on_calendar, owner, in_words | `timer {path} {added}: {on_calendar}` | a `.timer` unit file; `on_calendar` its `OnCalendar=` values as written, or `[]` |

| id | rule | how established |
|---|---|---|
| SY-1 | What `systemctl` was seen to write: `enable` adds one link `etc/systemd/system/multi-user.target.wants/nginx.service`; `disable` removes it; `mask` adds `etc/systemd/system/nginx.service -> /dev/null`; `unmask` removes it; enabling a timer adds `timers.target.wants/probe.timer`. | measured (P5c), both releases |
| SY-2 | What a package install was seen to write beside the link: `var/lib/systemd/deb-systemd-helper-enabled/multi-user.target.wants/nginx.service` and `.../nginx.service.dsh-also`. They are under a metadata root and are not events. | measured (P5b) |
| SY-3 | The receipt says `linked into multi-user.target`. belay never says `enabled at boot`: units from `/run/systemd`, generators, presets, `Wants=` inside other units and conditions are systemd's, and `/run` is not read. | the review's F38 |
| SY-3a | A unit under a home's `.config/systemd/user` gives the same kinds, its `unit` prefixed by the path of that directory. Whether it runs depends on the user's manager and on lingering (`var/lib/systemd/linger/<name>`, an entry of a metadata root): the receipt says `lingering: yes` or `no` from that entry and nothing more. | from knowledge; **probe owed**: `loginctl enable-linger` writes that file |
| SY-3b | `etc/rc?.d/*` links are not events: the receipt counts those added and removed in one line. Whether `rc.local` runs is `rc-local.service`'s condition (the file being executable), which is why the event carries `executable`. | **probe owed**: `systemctl cat rc-local.service` on both releases |
| SY-4 | A timer file without a `unit_linked` for it in the same diff or a link in the after-manifest is shown as `not linked into any target`. | design, from SY-1 |

## dpkg: the `auto` field

| id | rule | how established |
|---|---|---|
| SD-1 | The dpkg interpreter also claims `var/lib/apt/extended_states`. `dpkg_installed`, `dpkg_upgraded`, `dpkg_downgraded` and `dpkg_state_changed` gain `auto`, last: `true` when the after copy has a stanza for the event's `Package` and `Architecture` with `Auto-Installed: 1`; `false` when it has none or the stanza says `0`; absent when the file is not in the scope or cannot be read. | measured, both releases: after `apt-get install nginx`, `nginx` has no stanza and `apt-mark showmanual` lists it; `nginx-common` has `Auto-Installed: 1`; `apt-mark auto` adds the stanza, `apt-mark manual` removes it; of 971 and 1,117 stanzas, none says `0` |
| SD-2 | The receipt's words: `not marked automatic by apt` and `marked automatic`. Not "asked for". | apt's meaning, not belay's |
| SD-3 | **Folding.** In the receipt, a record whose path a package of this diff's dpkg events owns (SI-5) is counted in that package's line and listed only by `--all`. The `installed` line names the packages with `auto: false`, counts the rest, and names the three with the most records. | measured: 4,874 added lines for one install (`round-1`) |

## The trust store

Part of the `accounts`-style family, interpreter `trust`; in E4's order after sshkeys. Claims `etc/ssl/certs/*`, `usr/local/share/ca-certificates/**`.

| kind | fields | text | when |
|---|---|---|---|
| `trust_anchor_added`, `trust_anchor_removed` | path, target, subject, fingerprint, owner | `certificate {added} to the trust store: {subject} ({path})` | TS-1 |

| id | rule | how established |
|---|---|---|
| TS-1 | An anchor is a symbolic link or regular file added (or removed) directly under `etc/ssl/certs` whose name ends `.pem` or `.crt`; the `<hash>.N` links beside it and the bundle `ca-certificates.crt` are not anchors. `target` is where the link chain ends; `owner` is that file's owner (SI-5), or the entry's own when it is a regular file. | measured, both releases (`owed-*/owed.txt`, T1): a certificate put in `usr/local/share/ca-certificates` and `update-ca-certificates` add exactly `etc/ssl/certs/probe-ca.pem -> /usr/local/share/ca-certificates/probe-ca.crt` and `etc/ssl/certs/a1c079ef.0 -> probe-ca.pem`, and rewrite the bundle; a packaged anchor's link ends at `/usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt`, which `ca-certificates` owns, while no package owns the link or the bundle |
| TS-2 | `subject` and `fingerprint` (sha256 of the DER) are read from the PEM when the target's content is kept and holds exactly one certificate; otherwise absent. belay does not validate the certificate. | **probe owed**: against `openssl x509 -noout -subject -fingerprint -sha256` |
| TS-3 | Not seen: trust stores of other programs (Java's `cacerts`, NSS databases, a browser's), and `SSL_CERT_FILE` in someone's environment. | from knowledge |

## sshkeys

Claims `**/.ssh/authorized_keys` and `authorized_keys2` (kept, though usually mode 600).

| kind | fields | text | when |
|---|---|---|---|
| `ssh_key_added`, `ssh_key_removed` | path, type, fingerprint, comment, options | `key {added} in {path}: {type} {fingerprint} {comment}` | a key line; identity is `(type, fingerprint)` |
| `ssh_ca_added`, `ssh_ca_removed` | path, type, fingerprint, comment, options | `certificate authority {added} in {path}: ...` | a key line whose options include `cert-authority` |

| id | rule | how established |
|---|---|---|
| SK-1 | A line: optional options, key type, base64 key, optional comment. Options are split at commas outside double quotes, `\"` inside quotes. `fingerprint` is `SHA256:` and the unpadded base64 of the sha256 of the decoded key. A line that does not parse makes the file `could_not_interpret`. | measured (`owed-*/owed.txt`, O3): for an ed25519 and an RSA key, with a quoted `command=` holding `\"` and a comma, and a `cert-authority` line, `ssh-keygen -lf` reads all three lines and its `SHA256:` value equals the one computed as this row says. Owed: sshd's own acceptance of the quoting |
| SK-2 | The event names the file. belay does not say whose login it opens: `AuthorizedKeysFile` and `StrictModes` decide that in sshd. | the review's F41 |
| SK-3 | The files are found because `<home>/.ssh` of every `passwd` line is a content root (watch-system.md). A key file elsewhere is not seen. | design |

## `in_words`

| id | form | words | how established |
|---|---|---|---|
| SW-1 | `*/N * * * *` | `every N minutes` | **probe owed**, all rows: each form run under cron or checked with `systemd-analyze calendar`, on a fixture |
| SW-2 | `M */N * * *` | `at minute M of every Nth hour` | |
| SW-3 | `M H * * *` | `at HH:MM every day` | |
| SW-4 | `M H * * D[,D...]` with numeric or three-letter weekdays | `at HH:MM on Mon, Thu` | |
| SW-5 | `M H N * *` | `at HH:MM on day N of every month` | |
| SW-6 | `@hourly`, `@daily`, `@midnight`, `@weekly`, `@monthly`, `@yearly`, `@annually`, `@reboot` | the word's expansion in crontab(5) | |
| SW-7 | a timer with exactly one `OnCalendar=` of the form `*-*-* HH:MM:SS` or `Day *-*-* HH:MM:SS` | as SW-3, SW-4 | measured, both releases (`owed-*/owed.txt`, O4): `*-*-* 03:17:00`, `Mon,Thu *-*-* 03:17:00` and `Mon *-*-* 00:00:00` normalize to themselves; `daily`, `weekly`, `hourly` normalize to `*-*-* 00:00:00`, `Mon *-*-* 00:00:00`, `*-*-* *:00:00`. A timer's `in_words` is given for those six spellings |
| SW-8 | Absent when the file sets `CRON_TZ` or `TZ`, when a field has a range, a step with a start, or a list other than SW-4's, and for every other form. The words end `(by cron's clock)` or `(by systemd's)`. | | design |
