# Pin: the host reader (`--docker`)

**What this is.** How belay captures a Docker container's filesystem from the host, reading the
container's overlay layers directly (capture engine B, BELAY_DESIGN §5.1-B; decision 187: "read the
container's overlay mount from /proc/<pid>/mountinfo first ... refuse unsupported overlay features
loudly; `--docker CONTAINER`: yes"). It writes a manifest v3 with a `source` (manifest-v3.md), the
same entries the walker writes for the same tree, read without entering the container. What the
union of the layers is, beyond the rows below, is what the kernel's overlayfs documentation
(`Documentation/filesystems/overlayfs.rst`) says; the union resolver's separate author models it
from that document. Written by hand; approved by the author 2026-11-03 (decision 199).

**How the outside facts were established** (decision 184). Probes on GitHub's `ubuntu-24.04`
runners, Docker 28.0.4, both image stores (overlay2, and the containerd store with its overlayfs
snapshotter), kernel 7.0.0-1017-azure (draft PRs #71 and #73, closed after reading); and an
overlay mounted in a user namespace on Linux 6.18. Each row below that rests on one says so:
*(probed)*.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

## The command line

| id | rule |
|---|---|
| H-C1 | `--docker CONTAINER` is accepted by `check`, `mark`, `diff`, `log`, `exclude`, `baseline export` and `verify`. With it the command captures the container's filesystem by the host reader; without it, nothing changes. On a platform other than Linux it is refused (exit 3). |
| H-C2 | `CONTAINER` is a name or an id, as `docker inspect` takes it. belay runs the `docker` program found on `PATH`, as `docker inspect`, before the read and again after it, and uses `Id`, `Image`, `State.Status`, `State.Paused`, `State.Pid` and `GraphDriver` *(probed)*. |
| H-C3 | `--scope PATH` is a path inside the container: absolute, looked up in the union (below), component by component, by belay itself, never by the host. A symbolic link on the way is followed inside the container's root: an absolute target from that root, `..` at the root staying there, at most 40 links (more: refused). The scope must be a directory of the union, and not the mount point of another mount (H-M5): a volume or a bind mount is refused, with its host source named when the mount table gives it, for the caller to capture that as a scope of its own, without `--docker`. |
| H-C4 | `baseline export` and `verify` require the container paused (`State.Paused` true): the protocol's freeze (step 2), which the reader can check, so it does. `check`, `mark`, `diff` and `log` take it paused or running. Any other state is refused: a stopped container has no mount to read (`State.Pid` 0) *(probed: paused gives `Status` "paused", `Paused` true, `Running` true, the same `Pid`, its mount table and layers readable; stopped gives `Pid` 0)*. |
| H-C5 | After the read, belay inspects the container again: a different `Id` or `Pid`, or for `baseline export` and `verify` a container no longer paused, fails the capture (exit 4), and nothing is kept. |
| H-C6 | A container is refused when anything grants it `CAP_SYS_ADMIN`: `--privileged`, or the capability in its first process's bounding set (`CapBnd` in `/proc/<pid>/status`), which is what any process there can gain. Such a container can mount over a path inside itself, so its writes never reach the layer files the host reads: the scope would show the layers while the container sees something else (decision 199). A test runs exactly that escape -- a privileged container mounts a tmpfs over a directory of its scope and writes below it; the layers do not have the write, and belay refuses the container *(probed: `--privileged`, `--cap-add SYS_ADMIN` and `--cap-add ALL` each set the bit, and `--user 1000 --cap-add SYS_ADMIN` too, though that first process's effective set is empty)*. |
| H-C9 | A container whose bounding set holds `CAP_LINUX_IMMUTABLE` is captured, with a warning on standard error: it can set the immutable and append-only flags on the files Docker bind-mounts from the host (`/etc/hostname`, `/etc/hosts`, `/etc/resolv.conf`), which sets them on the host's own files, and `docker rm` then fails *(probed: `chattr +i /etc/hostname` inside such a container, then `docker rm`: `unlinkat .../hostname: operation not permitted`)*. The warning decides nothing; it is not in any JSON output. |
| H-C7 | Reading the layers needs root on the host; without it, refused. A container whose `State.Pid` is not a process on this host (Docker Desktop's VM, a remote daemon) is refused. |
| H-C8 | A container's checkpoints and excludes are kept on the host, in belay's state directory, by container id and scope path, as a local scope's are by its path; `log --docker C --scope P` lists them. belay never writes in a layer, and never pauses, unpauses or stops a container: the orchestrator does. |

## The mount

| id | rule |
|---|---|
| H-M1 | The mount table is `/proc/<State.Pid>/mountinfo`. Exactly one mount has the mount point `/`, and its type is `overlay`; otherwise refused *(probed: one, on both stores)*. |
| H-M2 | Of its super options (the last field), `lowerdir` (colon-separated, topmost first), `upperdir` and `workdir` name the layers *(probed)*. Of the rest, belay accepts `rw`, `ro`, `nouserxattr`, `uuid=`*, `xino=`*, `redirect_dir=`*, `index=off`, `metacopy=off`, `nfs_export=off`, `volatile` and `default_permissions`. Any other option is refused by name: `userxattr` (rootless: after M3), `index=on`, `metacopy=on`, `nfs_export=on`, `verity=`*, a data-only layer (`::` in `lowerdir`), and any belay does not know. When the options name none of `index`, `metacopy` and `nfs_export`, the overlay module's default decides (`/sys/module/overlay/parameters/<name>`): `Y` is refused *(probed: options `rw,nouserxattr`; defaults `index=N`, `metacopy=N`, `nfs_export=N`, `redirect_dir=Y`)*. |
| H-M3 | Each layer path is absolute and made only of `A-Z a-z 0-9 / . _ -`; anything else is refused (no escape sequence is decoded in a layer path). Resolved (the overlay2 store names its lower layers by links under `l/`), they must be the daemon's: with the overlay2 store (`GraphDriver.Name` `overlay2`), the upper and the lower layers are exactly `GraphDriver.Data`'s `UpperDir` and `LowerDir`, in order; with the containerd store (`GraphDriver.Data` null, `Name` `overlayfs`), each is a directory `/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<digits>/fs`. Otherwise refused *(probed)*. |
| H-M4 | Every layer directory is on one filesystem (one `st_dev`); otherwise refused: in a manifest a directory's `dev` differing from the scope root's means a mount boundary (manifest-v1, `dev`). |
| H-M5 | Every other mount whose mount point (field 5, its `\NNN` octal escapes decoded) lies below the scope is a mount root: its entry is the union's entry at that path, marked `mount`, with nothing below it captured (manifest-v1) -- volumes, bind mounts, tmpfs, the files Docker binds (`/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`) *(probed: each is listed, a space as `\040`)*. A mount point the union does not hold is refused. |

## The union

| id | rule |
|---|---|
| H-U1 | The layers, topmost first: the upper directory, then the lower ones in `lowerdir`'s order. A path's entry comes from the topmost layer that holds it, unless a layer above hides it *(probed: `lowerdir=l1:l2` shows `l1`'s file)*. |
| H-U2 | A character device with device number 0:0 is a whiteout: the path is absent, in that layer and every one below; it is not an entry *(probed: a deleted file, and the old name of a renamed file or directory)*. |
| H-U3 | A directory with the xattr `trusted.overlay.opaque` = `y` is opaque: its children come from it and the layers above it, none from below. Any other value is refused *(probed: a directory deleted and made again)*. |
| H-U4 | A directory present in several layers, none of them hidden, has as children the union of theirs; its own metadata is the topmost one's. |
| H-U5 | A directory with `trusted.overlay.redirect` was renamed: in the layers below its own, its content is looked up at the redirect's path instead of its own -- from the overlay's root when the value starts with `/`, otherwise a name in the same parent -- and a lower directory's redirect is followed in turn, as the kernel's documentation describes *(probed: a rename in place gives `"ssl"`; across directories `"/etc/profile.d"`, `"/lib/apk/db"`)*. A redirect on anything but a directory, or naming a path no layer below holds as a directory, is refused. |
| H-U6 | The xattrs under `trusted.overlay.` are the overlay's own, not the file's: none is in an entry's `xattrs` *(probed: the merged view shows none)*. belay acts on `opaque`, `redirect` and `protattr`, and ignores `origin`, `impure` and `uuid` *(probed: the ones Docker's layers carry)*. Any other is refused, by name. |
| H-U7 | An entry's `dev`, `ino`, `nlink` and every other stat field are those of the layer file that supplies it, read on the host. A walk inside the container sees otherwise: the overlay's device, and a copied-up file keeps its lower inode number *(probed)*. Here a copy-up -- any write, a `chmod`, a `touch` -- shows as the file replaced, with its content the same when it is: it was rewritten into the upper layer *(probed: a mode-only change copies the whole file up)*. |
| H-U8 | An entry's `iflags` are the layer file's, with those `trusted.overlay.protattr` names added: `i` immutable, `a` append-only. Inside a container, `chattr +i` and `chattr +a` set that xattr on the upper file and not the flag, and the merged view shows the flag *(probed)*. |
| H-U9 | `walk_start_ns` (manifest-v2 V2-3) is the ctime of a file belay creates in its state directory when that directory is on the layers' filesystem; otherwise `0`, the clock unknown. |
| H-U10 | Containment, as the walker's (BELAY_DESIGN §5.1.1): each layer directory is opened once and held; every path below it is opened relative to it, never following a link. |

## Not covered (refused, or outside the scope, never silent)

The content of volumes and bind mounts (mount roots, H-M5); tmpfs; rootless Docker, `userxattr` and
fuse-overlayfs; podman and other runtimes (its mount table would serve, its inspect differs);
Docker Desktop and remote daemons (H-C7); stopped containers (H-C4).
