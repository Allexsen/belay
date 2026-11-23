# Pin: `belay watch --system`

**Status.** Approved by the author, 2026-11-19, after two independent reviews. The code follows in later
PRs: until a row's code has merged, nothing in it is implemented, and `docs/cli.md` says only what is.
Rows marked **owed** state what a run must show before the code resting on them merges. The flag list's measurement (WS-M) is owed: it needs the build.

**Evidence.** "Measured" means run on GitHub-hosted Ubuntu 24.04 (kernel 7.0) and 22.04 (kernel 6.8)
runners, 2026-11-18 and 19. The file names and section labels given (`events.txt` E1, `facts.txt` P4,
`owed.txt` U1, `round-3`, ...) are those runs' outputs, kept in the project's notes, not in this repository.

**What this is.** `belay watch` over a whole machine: the roots it reads, the flag list that fits a
system, the lines and the receipt. `watch-v1.md` stays as it is for a project directory; this pin
says only what differs with `--system`.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## Commands

| id | rule |
|---|---|
| WS-1 | `--system` takes the place of `--scope` on `watch start\|step\|receipt\|stop\|summary\|patterns` and on `check`, `mark`, `diff`, `log`, `manifest`, `prune`: the scope is `/`, read by the roots below. `--scope /` without it stays refused (`not watching /: too wide`). With `--docker C` the scope is the container's `/`. |
| WS-2 | `watch start` takes the first capture, starts the recorder when it can (kernel-record.md), and prints the two opening lines of the receipt. `watch stop` prints the receipt and ends the recorder. A second `start` on a running watch is refused. |
| WS-3 | watch-v1's time limit (TM-1, 45 s) holds for `step`. `start`, `receipt` and `stop` have none and print one progress line to standard error every 10 s. |
| WS-3a | A `step` whose capture must be a walk hands the walk, and all that follows it (the diff, the matching, the step's record), to a worker process of its own session (`setsid`), which holds the state's lock and outlives the step and the adapter's hook; the recorder goes on reading meanwhile. The step waits for it up to the limit. Finished in time: the step's line, as usual. Not finished, the walk or what follows it: the step prints `walking (<reason>): not finished in 45 s; what changed will be in the next line` and exits 0, and the worker records the step itself when it ends. The next `step` or `receipt` prints that step's line from the record, `since <time of the checkpoint before it>`, and diffs nothing again. Nothing is lost and nothing is said twice: the walk becomes a checkpoint when it ends, and each change lies between exactly two consecutive checkpoints. This amends watch-v1 TM-1 and TM-3 for `--system` only: there the worker is not killed at the limit, and no back-off stops a system watch's steps. The watch's state records the step not yet shown, set under the lock, so two steps at once cannot both show it; other belay commands on the scope wait for the lock as any two do today. Measured on a 22.04 runner: the diff of two walks took 40 to 57 s, so a step that diffed a late walk again within the limit was killed at `matching`, and three such kills stopped the watch (TM-3). |
| WS-3b | A `step` that finds a walk still running prints `walk in progress since <time> (<reason>)` and exits 0, without starting another. A `step` that finds a finished walk not yet reported prints its line first (`since <time>`), then does its own capture; if that is again a walk that does not finish, the `walking` line follows (two lines from one step: watch-v1 LN-1 is amended for `--system` to allow it). So on a machine where every capture is a walk longer than the limit, a flagged change is reported one step late, and the receipt's `kernel record` line says so (WS-3c). `receipt` and `stop` wait for a running walk and then take their own. A worker that died leaves a lock nobody holds: the next command says `the last walk did not finish` and starts one. |
| WS-3c | The receipt's `kernel record` line counts the steps that had no line of their own for this reason: `; 2 steps reported late (walks of 61 s, 74 s)`. |
| WS-4 | Not root: everything runs; the receipt opens as WS-R2 says. `--docker` needs root, as today. |
| WS-5 | `baseline export`, `verify` and `--protect` with `--system`: refused (manifest-v5 V5-R4). |
| WS-5a | Whether a scope is a system watch is a property of its state, not of one command line. A capturing command (`check`, `mark`, `diff` to now) given `--scope` for a scope whose state holds a checkpoint with roots is refused, exit 3, naming `--system`; so is `--system` for a scope whose latest checkpoint has none. Nothing is captured and nothing is stored. `--scope /` is refused for these commands as it is for `watch` (WS-1). Run on the step-2 build by an independent reviewer: after system captures of a tree, `mark --scope` on the same tree took a whole-scope capture into the same state and stored four files the system captures had sealed. |

## The roots

| id | class | paths | how established |
|---|---|---|---|
| WS-6 | content | `etc`; `usr/local`; `root`; `var/spool/cron`; `var/lib/dpkg`; `var/lib/apt/extended_states`; `usr/lib/systemd`; `lib/systemd` when `lib` is a directory; `boot/grub/grub.cfg`; and for the sixth field `<home>` of every line of `etc/passwd` as it is when the capture starts, where they exist: `<home>/.ssh`, `<home>/.config/systemd/user`, and the files (each listed in the manifest's `roots` whether found or not) `.profile`, `.bash_profile`, `.bash_login`, `.bashrc`, `.bash_logout`, `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`, `.cshrc`, `.login`, `.config/fish/config.fish` | the files the interpreters claim, and where the probe's task left its marks (`round-1`); the homes: the review's F41 |
| WS-7 | metadata | `usr`, `var`, `opt`, `srv`, `boot`; `bin`, `sbin`, `lib`, `lib32`, `lib64`, `libx32` when directories | measured: `usr` 41 GB and 765,077 entries, `opt` 9.1 GB on the runner image; a first capture of all content there took 17 to 90 minutes |
| WS-8 | not read | every other child of `/`, and under the roots: `var/log`, `var/cache`, `var/tmp`, `var/lib/docker`, `var/lib/containerd`, `var/lib/snapd`, `var/snap`; each home directory outside the paths WS-6 names: its other files are not recorded at all, its other directories as `not_read` (manifest-v5 V5-E3) | measured: idle writes under `var/lib/waagent`, `var/lib/containerd`, `var/log` in every probe log |
| WS-8a | | A home is used only when it is an absolute path other than `/`, every component of it is a real directory (no symbolic link), it is on a filesystem the capture enters, and it does not lie in a not-read directory of WS-8. `watch patterns --system` lists the homes left out, each with the reason (`/nonexistent: not there`, `/run/sshd: under run, not read`). | measured: `svc2:x:109:118::/nonexistent` (`facts.txt` P4) |
| WS-9 | | A longer root wins over a shorter. `watch patterns --system` prints the resolved roots with their classes and entry counts, then the not-read directories, then the flag list. | |
| WS-10 | | The resolved roots are in each manifest's header. When they differ from the previous capture's, the step's line and the receipt say `roots changed: +var/lib/postgresql/.ssh`. | manifest-v5 V5-D6 |

## What is flagged, and what is noted

Rows are matched against events and paths as watch-v1's are (WD-1 to WD-4). No `*.pem`, `*.key` rows.

| id | flagged 🔴 | reads |
|---|---|---|
| WS-F1 | every `sudo_rule_added`, `sudo_rule_removed`, `sudo_line_added`, `sudo_line_removed` | events |
| WS-F2 | `ssh_key_added`, `ssh_ca_added` | events |
| WS-F3 | `user_added` with uid 0; `user_changed` of `uid`, `gid`, `home` or `shell`; `user_password_in_passwd`; `password_entry_changed` | events |
| WS-F4 | `group_members_changed` with a member added to `sudo`, `admin`, `wheel`, `root`, `adm`, `shadow`, `disk`, `docker`, `lxd` | events |
| WS-F5 | any change under `etc/pam.d`, `etc/security`; `etc/ld.so.preload`, `etc/ld.so.conf`, `etc/ld.so.conf.d`; `etc/nsswitch.conf`; `etc/doas.conf`; `etc/polkit-1`, `usr/local/share/polkit-1`; `etc/userdb` | paths |
| WS-F6 | any config event for grammar `sshd`; any change under `etc/ssh` but `ssh_known_hosts` | events, paths |
| WS-F7 | any change under `etc/apt/sources.list`, `sources.list.d`, `trusted.gpg`, `trusted.gpg.d`, `keyrings`, `apt.conf.d`, `preferences`, `preferences.d` | paths |
| WS-F8 | `etc/profile`, `etc/profile.d`, `etc/environment`, `etc/bash.bashrc`, `etc/zsh`, and every shell startup file WS-6 names, in any home | paths |
| WS-F9 | `etc/modules`, `etc/modules-load.d`, `etc/modprobe.d`, `etc/udev/rules.d`, `etc/sysctl.conf`, `etc/sysctl.d` | paths |
| WS-F10 | `unit_overrides_packaged`; a `config_key_added` or `_changed` whose key begins `Exec` or is `User`, `Environment`, `EnvironmentFile`, in a drop-in or override of a unit whose packaged file has an owner | events |
| WS-F11 | privilege changes as watch-v1 flags them: setuid, setgid, a capability, a device node, world-writable, added or changed, in any root | policy's `privilege_changed` |
| WS-F12 | a `sealed` entry added, removed or changed outside `root` and the homes, said without content: `🔴 secret  etc/wireguard/wg0.conf changed`. Sealed entries under `root` and the homes (a shell history, a cache) are counted in `changes` and never flagged by this row; the rows that name paths there (keys, startup files, user units) still apply. | manifest flags |
| WS-F13 | `listener_opened` on a port below 1024 whose holder's `exe` has `owner: null` | runtime |
| WS-F14 | `trust_anchor_added` with `owner: null` (system-interpreters.md, the trust store); any change to `etc/ca-certificates.conf` or under `etc/ca-certificates` | events, paths |
| WS-F15 | any change under `etc/nftables.conf`, `etc/nftables.d`, `etc/ufw`, `etc/default/ufw`, `etc/iptables`, `etc/sysconfig/iptables*`, `etc/firewalld`. These are the rules as files; the ruleset loaded in the kernel is not read. | paths |
| WS-F16 | a unit event (`unit_file_added`, `unit_linked`, a config event) under a home's `.config/systemd/user` | events |
| WS-F17 | `could_not_interpret` of the `accounts`, `sudoers` or `sshkeys` interpreter; of `config` on a file of grammar `sshd`; of any interpreter on a unit file under a home's `.config/systemd/user`. These are the files whose events WS-F1, F2, F3, F6, F16 flag: one that can no longer be interpreted is not a count. Said as the event's own text with its first path, as the receipt says it: `🔴 could not interpret: etc/sudoers (sudo)`. In the receipt it is in the section of its interpreter's events (`user`, `sudo`, `ssh`, `config`; systemd's: `services`). | events |

| id | noted (no circle) |
|---|---|
| WS-N1 | `user_added`, `group_added`, `password_entry_added`, other `group_members_changed` |
| WS-N2 | `cron_job_added`, `cron_script_added`, `timer_file_added`, `unit_linked`, `unit_file_added`, `unit_masked`, `init_script_added`, `init_script_changed`, `trust_anchor_added` with an owner |
| WS-N3 | `service_started`, `service_stopped`, `service_restarted`, other `listener_opened`, `listener_closed`. A UDP listener with `client_range` never makes a line of its own in a step: the step's count includes it, and the receipt lists those open at the end on one line (runtime-v1 RT-6). |
| WS-N4 | dpkg events |
| WS-N5 | An event of WS-N2 or WS-N3 whose `owner` is `null` is printed on a line of its own ending `, in no package`. One whose owner is a package installed in this diff is counted in a line (`and 6 others by packages installed here`). |

## The lines

| id | rule |
|---|---|
| WS-L1 | A step's line is watch-v1's (LN-1 to LN-3): flagged events first, then noted ones, then a count of everything else. Records under metadata roots owned by a package of the diff, and any record under `var` with no event, never make a line by themselves: they are in the count. A step with only those prints `N entries changed under usr, var` and no more. |
| WS-L2 | A step with nothing prints nothing (LN-1). Under a kernel record that is a step with an empty dirty set and no runtime change. |

## The receipt

| id | rule |
|---|---|
| WS-R1 | Sections, in this order, each only when it has something: `could not read`; `kernel record`; `end state`; `installed`; `services`; `running`; `listening`; `user`; `cron`; `sudo`; `ssh`; `setuid`; `secret`; `trust`; `firewall`; `init`; `config`; `put back`; `changes`; `not compared`; `not read`. The first three and the last two are always there. |
| WS-R2 | `could not read` lists every entry with `unreadable`, once, by path, up to 20 and then a count; `nothing` when none. Not root, it is followed by `not root: no sudoers, no user crontabs, no other users' keys, no holders of ports, no kernel record`, each part only if true of this run. |
| WS-R3 | `kernel record` is one of: `on since <time>, whole`, followed by `; walked every time: <path> (<type>)` for each entered filesystem not on kernel-record K2a's list; `on since <time>, with a gap from <time> to <time> (<reason>)`; `off: <the kernel's message or "not root">: a change put back is not seen`. With `iflags_events` false it adds `; inode flags as of the last walk`. |
| WS-R4 | `end state` is `by a walk at <time>` (kernel-record K12). |
| WS-R5 | `changes` lists records no section and no package took, up to 20, then `N more (--all lists them)`; then per metadata root a count of the records folded into packages. `not compared` names the metadata roots; `not read` names the not-read directories. |
| WS-R6 | Every section line is an event's or a runtime record's text (system-interpreters.md, runtime-v1.md, system-config.md). The receipt adds no words of its own about what a change means. |

## Measured (owed, WS-M)

As watch-v1's list was measured over 47 steps: on a fresh Ubuntu 24.04 and 22.04 VM, the probe's
task; `apt-get upgrade`; a user added and removed; a service restarted; logrotate run; a
certificate renewed with a local CA; ten idle steps. Counted: flagged lines, noted lines, steps
that print nothing. A row that fires on an ordinary step is brought to the author before merge.
