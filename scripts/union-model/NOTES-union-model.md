# The union model: readings

The union-resolver model (`model.py`) is written from two sources only: Linux's
`Documentation/filesystems/overlayfs.rst` (fetched 2026-11-03 from torvalds/linux master) and
the pin `test/expect/host-reader.md` (rows H-U1..H-U10, H-C3 and H-M5). It never reads belay's
code. Below are its readings, U1..U24: each says what the pin and the documentation say, what
the model does, and how that was established: **kernel** (`run.sh` compares it with a real
overlay), **probe** (tried by hand on Linux 6.18.33.2-microsoft-standard-WSL2, in `unshare -rm`),
**hand** (a case in `hand.py` with the outcome written down in advance), or **reading** (the
model's own reading, not checked against anything). **OPEN** marks a reading the pin leaves
open, for the author to decide.

After them: K1..K9, the kernel's behaviour that neither the documentation nor the pin led the
model to expect; and what `run.sh` cannot check, with the reason.

## The files

| file | what |
|---|---|
| `model.py` | the model. `model.py [--prefix P] [--mount M]... SCOPE LAYER...` (layers topmost first) |
| `gen.py` | random layer sets, seeded (`--seed N --out DIR`), run in `unshare -r` (whiteouts) |
| `kwalk.py` | mounts a set as a real overlay (`userxattr`), chroots into it, walks the scope |
| `compare.py` | `compare_outputs()`: **the hook** for belay's driver (its output in the model's format against the model's); `kernel_diffs()`: the model against `kwalk.py` |
| `hand.py` | 18 hand cases: the redirects the kernel cannot be asked here (U19), and the readings below |
| `check.py` | the loop: gen, model, kwalk, compare, for COUNT seeds |
| `run.sh` | `run.sh [COUNT [SEED]]`: the hand cases, then COUNT generated sets (default 300) |

## The runs

`run.sh 300 1` (2026-11-03, Linux 6.18.33.2-microsoft-standard-WSL2): the 18 hand cases pass,
15 of them also agreeing with the kernel (8 in full, 7 around their redirects; the other 3 are
refusals the kernel does not make); of the 300 generated
sets, none disagrees. 177 were listed: 3663 entries compared field by field with the kernel's
view, 381 entries behind a followed redirect not compared (33 sets). 123 were refused: 60 with
the kernel agreeing (H-C3 37: ELOOP 11, ENOENT 15, ENOTDIR 4, a mount 7; H-M5 23), 40 planted
refusals of the right row (H-U3 11, H-U5 15, H-U6 8, H-U8 6), and 23 random redirects whose
target did not survive (H-U5, not judged). The same check over 3000 further sets (seeds
10000-12999): 37246 entries compared, 1087 sets refused, no disagreement -- after one fix to
the *comparison*: in 4 sets the scope's path met a mount point and then also failed in the
kernel's own resolution (ELOOP or ENOENT further on); the model refuses at the mount point first
(U18), which the walker confirms, and the comparison had asked for the kernel's later errno.
Merged directories there: 9232, every one `nlink` 1 (K4).

## The lookup

**U1. Topmost first, a missing name is no stop, a whiteout is.** A path's entry is the first
layer file found going down from the upper layer; a layer without the name is passed over;
a whiteout (character device 0:0, H-U2) ends the search: the path is absent from that layer
down, though a layer above it may make it again. Pin H-U1, H-U2; documentation "whiteouts and
opaque directories". **kernel**, **hand**.

**U2. A directory over a lower non-directory.** The non-directory is hidden, and the search
ends there: a directory further down, below the non-directory, is *not* merged. The
documentation: "If both actual lookups find directories, both are stored and a merged directory
is formed, otherwise only one is stored: the upper if it exists". The pin does not say. The
model: the directory stands alone (with whatever merged above the non-directory). **kernel**
(hand case "a directory over a file over a directory", and in the random sets).

**U3. A non-directory over a lower directory.** The non-directory is the entry; the directory
and everything below it are hidden ("non-directories are always opaque"). **kernel**, **hand**.

**U4. A relative redirect** names a directory in the same parent -- the parent *as it is in
each lower layer*: when the parent itself was reached through a redirect, its lower directory
sits at another path, and the name is looked up there. The documentation only describes the
absolute form ("set to the path of the original location from the root of the overlay"); the
relative one comes from the pin (*probed*: a rename in place gives `"ssl"`). **hand** only (U19).

**U5. An absolute redirect.** In every layer below the one that carries it, the path is looked
up from that layer's root, component by component, each component as a lookup of its own: a
whiteout or a non-directory on the way ends the search (nothing below that layer either); a
directory on the way that is opaque ends it for the layers below (that layer's own directory is
still found) -- unless a later component on the way carries an absolute redirect of its own,
which starts again from the root. Once an absolute redirect is met, the layers below are
searched from their roots, no longer through the parent's directories. The documentation says
"from the root of the overlay" and nothing about the walk; the pin says "as the kernel's
documentation describes", which it does not. This walk is the model's reading of what a path
"from the root" means layer by layer, and it matches my understanding of the kernel's own
lookup; it is **hand** only (U19). **OPEN** in its details (an opaque directory part way along
the redirect's path; a redirect part way along it).

**U6. "Naming a path no layer below holds as a directory" (H-U5) is judged after the lookup:**
a directory carrying a redirect must have at least one directory merged below it -- the
redirect's target must survive the search (U5), not merely exist in some layer: a target that a
middle layer whites out, or a file, or one behind an opaque directory, is refused. So a
redirect in the bottom layer is always refused (nothing is below it; the kernel ignores it).
**hand**. **OPEN**: the bottom-layer case, and "holds" as "the lookup finds" rather than "some
layer has a directory at that path".

**U7. A chain.** A lower directory reached through a redirect may carry a redirect of its own;
it is followed in turn, its value read where that directory is: a relative one in its own
parent in that layer, an absolute one from the root (pin H-U5 "followed in turn"; the
documentation's NFS-export section: "a middle layer directory may have a 'redirect' to lower
directory"). **hand** (three-layer chain; relative inside absolute).

**U8. The root.** The roots of all layers always merge. An `opaque` or `redirect` on a layer's
root is not consulted: nothing looks the root up. The pin's H-U3 read literally would make an
opaque upper root hide every lower layer; the kernel does not (K5). The model follows the
kernel. **kernel** (an opaque root on a random layer in about 7% of the sets), **probe**.
**OPEN** (the pin's literal reading differs).

**U9. An opaque directory's redirect is moot**: nothing below an opaque directory is looked up,
so its redirect is not followed and its target not checked (its value is still checked, U10).
Not something the kernel makes: a rename gives a redirect only to a directory that has a lower
one, which an opaque directory does not. **kernel** (hand case: the kernel, which follows no
redirect here, reads none on an opaque directory either and agrees in full), **reading**.

## What is refused, and where

**U10. A bad redirect (H-U5).** Refused: an empty value; a NUL; a relative value containing
`/`; an absolute value with an empty component (`/a//b`, `/a/`, `/`); any `.` or `..`
component. The pin says only "a bad redirect" and "on anything but a directory". **reading**,
**OPEN** (the list).

**U11. Unknown overlay xattrs (H-U6).** Any name under the prefix other than `opaque`,
`redirect`, `protattr`, `origin`, `impure`, `uuid` -- compared exactly, case-sensitively. That
includes three the documentation defines: `whiteout` (its alternative form of a whiteout),
`metacopy`, and an *escaped* name `overlay.overlay.X` (nesting: the kernel shows it as the
file's own `overlay.X`, K9). The pin refuses all of them by name. **probe** for what the kernel
does; the model refuses as the pin says (planted in the random sets).

**U12. `opaque=x` is refused (H-U3: "any other value").** The documentation defines it: a
directory holding xattr-form whiteouts, honoured in a lower layer (K7). With U11 the model
refuses that whole form of whiteout. **probe** (the kernel honours it); refused per the pin.

**U13. `opaque` on a non-directory is refused (H-U3)**, as `redirect` on one is (H-U5, the pin
says so). The pin speaks of "a directory with" the xattr; on a file the kernel never reads it.
**OPEN**.

**U14. Only what the union reads is judged.** The refusals of U10-U13 and U15 apply to every
layer file the union's lookups read: each layer directory merged into an entry at or below the
scope, the entries on the scope's path and on the mount points' paths, and the directories
walked through under an absolute redirect. A file hidden without being read -- a lower file
under an upper file, a lower non-directory under a directory -- is not judged: a bad xattr
there refuses nothing. **OPEN** (the pin does not say how far the refusals reach).

**U15. `protattr` (H-U8): the upper layer's only; a bad value refused.** The kernel honours
`protattr` on the upper layer's file only and ignores it on a lower layer's (K6); the pin says
"the layer file's [flags], with those `trusted.overlay.protattr` names added", without saying
which layer. The model's `protattr` is the upper file's value, `""` for an entry a lower layer
supplies. A value that is empty or holds anything but `i` and `a` is refused under H-U8 wherever
it is read (the kernel ignores it with a warning, K6). The field is the letters as stored
(`ai`, `ii` possible); they compare as a set with the kernel's flags. **kernel** (upper honoured,
lower not, on reg and dir), **probe** (bad value). **OPEN**: which layer; and refusing a bad value.

## The scope and the mounts

**U16. The scope (H-C3).** Resolved component by component in the union. A link is followed
(the last component's too), absolute from the container's root, relative from the link's
directory; `..` goes to the parent of where the walk stands, at the root it stays there; every
link followed counts, the 41st is refused. A non-directory followed by anything -- a name, `.`
or `..` -- is refused (the kernel: ENOTDIR); so is an empty link target (ENOENT), and a scope
that does not exist or is not a directory. **kernel** (chains of 1-3 and of 39, 40 and 41 links,
some through `..` above the root, with `/a`, `/..`, `/.` after them; refusals matched to the
kernel's ELOOP, ENOENT and ENOTDIR from `chdir` in a chroot of the merged view).

**U17. A mount point the union holds (H-M5).** A mount point's path (canonical, as mountinfo
gives it) is looked up from the root without following links: every component above it a
directory of the union, itself present, of any type. A link on the way, or a missing component,
is refused. Only mount points below the resolved scope are looked at. **kernel** (lstat of each
component in the merged view).

**U18. Mounts within mounts, and a scope within a mount.** A mount point below another mount
point (both below the scope) is not looked up: nothing below the outer one is read. A scope
whose resolution looks a name up inside a mount point -- the scope inside a volume, or a link
in one -- is refused under H-C3, as a scope that *is* a mount point is: the container would find
those names in the mount, not in the layers. `..` out of a mount point looks nothing up and is
allowed. The first such lookup refuses, before any later failure of the same path. **kernel** (the walker detects a lookup inside a mount point the same way, from the
merged view), **hand**. **OPEN** (the pin names only the scope being a mount point).

## What the kernel check covers

**U19. Redirects cannot be checked against the kernel here.** An unprivileged overlay needs
`userxattr`, and with it the kernel follows no redirect (K1): a lookup that meets one fails with
EPERM. So `kwalk.py`'s view differs from the model's wherever a redirect is followed. `run.sh`
compares those sets *around* the redirects (U20) and pins the redirect readings (U4-U7, U9)
with the hand cases instead.

**U20. "Behind a redirect".** With `--explain` the model marks an entry `tainted` when its
lookup, or its parent's, followed a redirect, and the scope `scope_tainted` when its resolution
did. The comparison skips tainted entries, and every EPERM the kernel gives must be at a
tainted entry, at the scope when it is tainted, at a mount point the kernel cannot reach for
the same reason, or at a directory whose listing failed because a child is tainted (K2). Every
other entry is compared in full.

**U21. Modes the generator does not make.** Directories keep `u+rwx` and files `u+r`: the
model runs as the layers' unprivileged owner here, where belay reads them as root. Other bits
vary (setuid, setgid, sticky, group and other bits).

## The format

**U22. The output** (pinned by the brief; the readings are where it left a choice):
`path` relative to the scope (`.` its root), as `path_b64` when not valid UTF-8 (manifest-v1's
rule; likewise `layer_path_b64`, `target_b64`); lines sorted by the raw bytes of the path
(memcmp: `.` sorts by its byte, after `-x` and before `a`); `layer_path` absolute inside its
layer (`/` for its root); `xattrs` an object of name to lowercase hex value, the overlay's own
removed (only those under the given prefix: with `trusted.overlay.`, a `user.overlay.*` xattr is
the file's own); `size` on `reg` only; `target` on `lnk` only; `protattr` always, `""` when none;
`mount` always, `true` or `false`; a refusal is a single line `{"refused", "why"}` and exit 1.
`--content` adds `sha256` (reg), `--explain` adds `tainted`, `members` and, on `.`, `scope` and
`scope_tainted`; neither belongs to the format, and `compare_outputs()` ignores them.

## Where the pin is open on the stat fields

**U23. `nlink` of a merged directory.** The pin (H-U7): every stat field is the layer file's,
read on the host -- so a merged directory has its topmost member's `nlink`. Inside the
container the kernel reports `1` for every merged directory, and the real count for one that
is not merged (K4). The model does not output `nlink`; the reading is that belay records the
layer file's, as H-U7 says. But the pin's preface promises "the same entries the walker writes
for the same tree": for `nlink` of merged directories (as for `dev` and `ino`, which H-U7
already names) they differ. **kernel** (the 300-set run: 918 merged directories, every one
`nlink` 1; 1416 unmerged, 2 to 7). **OPEN**.

**U24. How far "its own metadata is the topmost one's" (H-U4) reaches.** All of it: mode,
owner, xattrs, the inode flags (with the upper file's `protattr`, U15), times, size -- every
stat field of the topmost member, none of the lower ones'. The documentation: "Only the lists
of names from directories are merged. Other content such as metadata and extended attributes
are reported for the upper directory only." The exceptions are the kernel's own, not the
layers': `nlink` (U23), `dev` and `ino` (H-U7). **kernel** for mode, uid, gid, xattrs and the
`i`/`a` flags (times and directory sizes are not compared).

## What the kernel did that I did not expect

**K1. `userxattr` turns redirects off, and then a redirect is an error.** The documentation's
"User xattr" section says only that the prefix changes. Mounting with
`userxattr,redirect_dir=follow` (or `=on`) fails: dmesg `overlayfs: conflicting options:
userxattr,redirect_dir=follow`. Without the option the mount shows `redirect_dir=nofollow`,
although this machine's module defaults are `redirect_dir=N`, `redirect_always_follow=Y`. A lookup
of a directory with a redirect, when a lower directory is found under the redirect's target, fails
with EPERM: dmesg `refusing to follow redirect for (/new)`. *How:* probe (mount options, `ls`,
dmesg, `/proc/self/mountinfo`).

**K2. A redirected child can make its parent unlistable.** Under K1, listing a directory can
fail with EPERM because one of its children carries a redirect: the listing itself looks the
names up (seen on the root, which K8 marks `impure`). Not every such parent fails. *How:* a
generated set (seed 1083: `readdir` of the scope root EPERM; its child `cR` redirected);
`compare.py` accepts this EPERM only where a child of that directory is tainted (U20).

**K3. Whiteouts are listed in a directory that is not merged.** In a directory only one layer
holds (a new upper directory, or one only a lower layer has), a whiteout comes back from
`readdir` -- `ls` shows `c?????????` -- but `lstat` of the name fails with ENOENT. The
documentation does say "Readdir on directories that are not merged is simply handled by the
underlying directory", but not that whiteouts show through. In merged directories they do not.
For belay: a walker inside the container sees a name it cannot stat (manifest-v1 makes such a
directory `unstable`), where the host reader, by H-U2, sees nothing at all. *How:* probe (`ls -la`
in the merged view), and `run.sh` (63 such names in the 300-set run).

**K4. A merged directory's `nlink` is 1** (U23). *How:* probe (`stat -c %h`), `run.sh`.

**K5. The root's `opaque` is ignored** (U8): an upper root with `opaque=y` still shows every
lower layer's root files. *How:* probe, `run.sh`.

**K6. `protattr` is read from the upper layer only, and a bad one is ignored.** `lsattr` in the
merged view: an upper file with `protattr=i` shows `i`; a lower file with `protattr=i` shows
nothing; an upper file with `protattr=iz` shows nothing, dmesg `incompatible overlay.protattr
format (u/pbad, len=2)`. Neither the documentation (which does not mention `protattr`) nor
the pin says so. *How:* probe, `run.sh` (FS_IOC_GETFLAGS on reg and dir).

**K7. `opaque` values.** `opaque=n` on a lower directory is ignored (the directory merges as if
no xattr were there); `opaque=x` on a lower directory with a zero-size file carrying
`overlay.whiteout` hides that name below, as the documentation says. The pin refuses both (U12).
*How:* probe.

**K8. Mounting writes into the upper layer.** After a mount and a walk, the upper root carries
`user.overlay.uuid` and `user.overlay.impure="y"`, and each merged upper directory
`user.overlay.origin=""`; `uuid=on` appears among the mount's options. The model therefore runs
before `kwalk.py` mounts the set. (These are the names H-U6 ignores.) *How:* probe (`getfattr`
on the upper layer after the walk).

**K9. Escaped and unknown overlay xattrs in the merged view.** A lower file's
`user.overlay.overlay.foo` shows as `user.overlay.foo`; its `user.overlay.weird` does not show at
all. The first is the documentation's nesting rule; both are refused by the pin (U11). *How:*
probe (`getfattr -m -` in the merged view).

## What run.sh cannot check, and why

- **Redirects** (U4-U7): the kernel follows none under `userxattr` (K1), and an overlay that
  follows them needs `trusted.*` xattrs, i.e. CAP_SYS_ADMIN in the initial namespace, which this
  user does not have (sudo asks for a password). They are pinned by the hand cases, and the
  random sets with redirects are compared around them (U20). The user is in the `docker` group,
  so a privileged container could mount a `trusted.overlay.` set; that is root on the host, and
  was not done without the author's say-so.
- **The `trusted.overlay.` prefix**: the same reason. The model's code is the same for both
  prefixes; only the string differs.
- **Devices** other than whiteouts: `mknod` of any other character or block device fails with
  EPERM in a user namespace, so `chr` and `blk` entries never occur.
- **Owners**: one uid and one gid are mapped (no `newuidmap` here), so every file is the
  namespace's 0; an unmapped owner (shown as 65534) is not exercised. The mapping itself is
  compared.
- **The layer files' own `i`/`a` flags**: setting them needs CAP_LINUX_IMMUTABLE on the host;
  only the `protattr` path is checked.
- **The refusals of H-U3, H-U5, H-U6 and H-U8**: the kernel refuses nothing (K5-K7, K9); the check
  is that the model refuses each planted case with the planted row. A random set's H-U5 refusal
  (a generated redirect whose target did not survive, U6) is counted, not judged.
- **`dev`, `ino`, `nlink`, times**: by H-U7 they are the layer file's, which the merged view
  does not show (K4); the model does not output them.
- **Mounts** are given to the model and the walker as paths; nothing is mounted at them.
