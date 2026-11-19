# Pin: the runtime record, version 1

**Status.** Approved by the author, 2026-11-19, after two independent reviews. The code follows in later
PRs: until a row's code has merged, nothing in it is implemented, and `docs/cli.md` says only what is.
Rows marked **owed** state what a run must show before the code resting on them merges.

**Evidence.** "Measured" means run on GitHub-hosted Ubuntu 24.04 (kernel 7.0) and 22.04 (kernel 6.8)
runners, 2026-11-18 and 19. The file names and section labels given (`events.txt` E1, `facts.txt` P4,
`owed.txt` U1, `round-3`, ...) are those runs' outputs, kept in the project's notes, not in this repository.

**What this is.** What is listening and which services have processes, as `/proc` says at the
moment of a capture. Taken by belay itself: no program of the watched machine is run. Measured
against `ss -ltnup` and `systemctl` on Ubuntu 24.04 and 22.04:
`out-*/facts.txt`, section P6.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## The file

`runtime.ndjson` beside the checkpoint's manifest; its sha256 is the checkpoint's `runtime_sha256`
(checkpoint-v3). Pruned with the checkpoint. Never in a bundle. Written only for a scope with
`roots` (a system watch).

| id | line | keys, in order | rule |
|---|---|---|---|
| RT-1 | header | `belay_runtime: 1`, `netns`, `root`, `source` | `netns`: the inode of the network namespace read. `root`: whether belay was root. `source`: null, or the container as in manifest v3's header. |
| RT-2 | listener | `listener`, `proto`, `addr`, `port`, `client_range` (UDP only, when true), `holders` | One per socket. `listener` is `tcp`, `udp` or `unix`; `proto` `4`, `6` or null. Sorted by `listener`, `port`, `addr`. |
| RT-3 | service | `service`, `processes`, `exe`, `started_ns` | One per cgroup with processes whose last path component ends `.service`. `exe` and `started_ns` are the oldest process's. Sorted by `service`. |
| RT-4 | trailer | `listeners`, `services`, `holders_unknown` | Counts; `holders_unknown` the listeners whose holders could not be read. |

## Rules

| id | rule | how established |
|---|---|---|
| RT-5 | TCP: the lines of `/proc/net/tcp` and `tcp6` in state `0A`. | measured: the six lines equal `ss`'s six `LISTEN` rows, on 24.04 and on 22.04 |
| RT-6 | UDP: every line of `/proc/net/udp` and `udp6` whose remote address and port are zero (an unconnected socket). A connected socket is a client's and is not listed. The listener line gains `client_range: true` when its port lies within `/proc/sys/net/ipv4/ip_local_port_range`: such a socket may be a server (WireGuard's 51820) or a program that sends without connecting, and `/proc` does not say which. Nothing is dropped; the receipt prints those on a line of their own, `udp in the client port range: 51820 (no process holds it), 40000 held by socat`. | measured, both releases (`owed-*/owed.txt`, U1): a connected client shows its remote address and state `01`, and is the only socket `ss` calls `ESTAB`; WireGuard's 51820 is unconnected with no holder; an unconnected server on 40000 and an unconnected `sendto` client on 33473 look the same; over 60 idle seconds the only unconnected sockets in the range were those. `udp6` has the same columns and shows WireGuard's and an IPv6 server's sockets (`recheck-*/recheck.txt`, U1) |
| RT-7 | unix: the lines of `/proc/net/unix` whose flags have the listening bit (`00010000`) and whose path does not begin `@`. `addr` is the path, `port` null. | measured (`owed-*/owed.txt`, U2): those lines are the `LISTEN` rows of `ss -xl`; compared whole on both releases, 36 paths each way and none on one side only, 36 of socket type stream and 2 seqpacket (`recheck-*/recheck.txt`, U2; the script is `recheck-first-run.sh`) |
| RT-8 | `holders`: as root, every process with a descriptor that is this socket (the `socket:[inode]` of `/proc/<pid>/fd/*` equal to the line's inode), each as `{"exe": <readlink of /proc/<pid>/exe, as read>, "cgroup": <the path of its cgroup v2 line, as read>}`, each distinct pair once, sorted. | measured: port 80's inode is held by the five nginx processes, `exe=/usr/sbin/nginx`, `cgroup=/system.slice/nginx.service` |
| RT-9 | Not root: `holders` is null and `holders_unknown` counts it. | measured: `/proc/1/fd`: `Permission denied`; the ports themselves are readable |
| RT-10 | A socket no process holds: `holders` is `[]`. The receipt says `no process holds it`. | from knowledge (kernel listeners), not run |
| RT-11 | `exe` is never resolved or cleaned: a deleted executable reads `... (deleted)`, a container's is a path in the container. | from knowledge, not run |
| RT-12 | With `--docker`: `/proc/<pid>/net/*` of the container's first process, and the processes whose cgroup is the container's. No `service` lines unless the container has such cgroups. When the container's network namespace is the host's, no listener lines, and the header's `netns` says `host`. | measured: `/proc/5887/net/tcp` shows the container's port 80; its cgroup `/system.slice/docker-<id>.scope` matches 5 of 5 processes |
| RT-13 | One network namespace per record. Others are not read. | design |

## The diff: a `runtime` section of diff.v1

Runtime changes are not interpreter events: an event must list a path (diff-events E3).

| id | rule |
|---|---|
| RT-D1 | When both checkpoints have a runtime record, the diff has `runtime` records after the events and before the trailer: `{"runtime": <kind>, <fields>, "text": ...}`. The trailer gains `runtime`: their count. A consumer ignores a kind it does not know. |
| RT-D2 | `listener_opened`, `listener_closed`: `{listener, proto, addr, port, client_range, holders}` (`client_range` as in RT-2); the key is `(listener, proto, addr, port)`. Text: `opened: tcp 0.0.0.0:80 held by nginx.service`: the unit is the last `.service` component of a holder's cgroup; without one, the `exe`; `held by systemd` when the only holder is pid 1's cgroup (`init.scope`). |
| RT-D3 | `service_started`, `service_stopped`: a `service` line on one side only. `service_restarted`: on both sides with a different `started_ns`. Fields `{service, processes, exe}`. |
| RT-D4 | A listener held by systemd is additionally given `matches`: the names of the `.socket` unit files in the after-manifest whose text has a `ListenStream=` ending in that port. Empty when none; never guessed from the port number. |
| RT-D5 | One side without a runtime record, or `holders_unknown` not 0 on a side: the section is still given, and its first record is `{"runtime": "incomplete", "why": ...}`. |

| rows | how established |
|---|---|
| RT-D2 | measured: on 24.04 port 22 is held by `systemd`, pid 1; on 22.04 by `sshd` |
| RT-D3 | measured, both releases (`owed-*/owed.txt`, U3): the oldest process's start time is the same after `systemctl reload nginx` and later after `restart` |
