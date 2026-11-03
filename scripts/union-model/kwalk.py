#!/usr/bin/env python3
"""The kernel's side: mount a generated layer set as a real overlay and walk the merged view.

    unshare -rm kwalk.py CASE.json

Must run in a new user and mount namespace (`unshare -rm`): it mounts the layers with
`userxattr` (the overlay's xattrs are then `user.overlay.*`), chroots into the merged view
so that the scope's links resolve inside the container's root (H-C3), and walks it.

Output: a header line, then one line per entry in the model's format, minus what only the
layers know (`layer`, `layer_path`, `protattr`), plus:
    `iflags`: the `i`/`a` of FS_IOC_GETFLAGS (reg and dir), to set beside the model's protattr;
    `nlink`; `sha256` for reg.
A name readdir lists but lstat cannot find is a line {"ghost": path}; any other error a line
{"path": ..., "error": "EPERM"}. The header: {"mounted": options} or {"mount_error": text};
then {"scope": resolved} or {"scope_error": errno name}; and the namespace's id maps, and
which mount points are paths of the merged view.
"""

import errno
import fcntl
import hashlib
import json
import os
import stat
import struct
import subprocess
import sys

sys.dont_write_bytecode = True     # nothing left beside the scripts
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from model import put_bytes, type_of  # noqa: E402  (format helpers only)

FS_IOC_GETFLAGS = 0x80086601
FS_IMMUTABLE_FL = 0x10
FS_APPEND_FL = 0x20


def idmap(path):
    with open(path) as f:
        return [list(map(int, line.split())) for line in f if line.strip()]


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")


def held(m):
    """The mount point is a path of the merged view: each component above it a real
    directory (no link followed), itself present."""
    comps = [c for c in m.split(b"/") if c]
    p = b""
    for k, c in enumerate(comps):
        p += b"/" + c
        try:
            st = os.lstat(p)
        except OSError as e:
            return errno.errorcode.get(e.errno, False) if e.errno == errno.EPERM else False
        if k < len(comps) - 1 and not stat.S_ISDIR(st.st_mode):
            return False
    return True


def through_mount(scope, mounts):
    """Does resolving the scope look a name up inside a mount point? (The container would
    find it in that mount, not in the overlay: H-C3.)"""
    mset = {tuple(c for c in m.split(b"/") if c) for m in mounts}
    stack, todo, links = [], scope.split(b"/"), 0
    while todo:
        c = todo.pop(0)
        if c in (b"", b"."):
            continue
        if c == b"..":
            if stack:
                stack.pop()
            continue
        if stack and tuple(stack) in mset:
            return True
        p = b"/" + b"/".join(stack + [c])
        try:
            st = os.lstat(p)
        except OSError:
            return False
        if stat.S_ISLNK(st.st_mode):
            links += 1
            if links > 40:
                return False
            t = os.readlink(p)
            if t.startswith(b"/"):
                stack = []
            todo = t.split(b"/") + todo
            continue
        stack.append(c)
    return False


def iflags(path, kind):
    if kind not in ("reg", "dir"):
        return None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        buf = bytearray(8)
        fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf)
        v = struct.unpack("<i", bytes(buf[:4]))[0]
    finally:
        os.close(fd)
    return ("i" if v & FS_IMMUTABLE_FL else "") + ("a" if v & FS_APPEND_FL else "")


def sha(path):
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        for blk in iter(lambda: f.read(1 << 16), b""):
            h.update(blk)
    return h.hexdigest()


def record(rel, path, st, is_mount):
    r = {}
    put_bytes(r, "path", rel)
    kind = type_of(st)
    r["type"] = kind
    r["mode"] = st.st_mode & 0o7777
    r["uid"] = st.st_uid
    r["gid"] = st.st_gid
    if kind == "reg":
        r["size"] = st.st_size
    if kind == "lnk":
        put_bytes(r, "target", os.readlink(path))
    if is_mount:
        r["xattrs"] = {}        # a mount root: its stat fields only, as the walker's (H-M5)
    else:
        names = os.listxattr(path, follow_symlinks=False)
        r["xattrs"] = {k: os.getxattr(path, k, follow_symlinks=False).hex()
                       for k in sorted(names)}
    r["mount"] = is_mount
    r["nlink"] = st.st_nlink
    f = None if is_mount else iflags(path, kind)
    if f is not None:
        r["iflags"] = f
    if kind == "reg" and not is_mount:
        r["sha256"] = sha(path)
    return r


def main():
    with open(sys.argv[1]) as f:
        case = json.load(f)
    if case["prefix"] != "user.overlay.":
        sys.exit("kwalk: the kernel check runs with userxattr only")
    upper, lowers = case["layers"][0], case["layers"][1:]
    opts = "userxattr,lowerdir=%s,upperdir=%s,workdir=%s" % (":".join(lowers), upper, case["work"])
    p = subprocess.run(["mount", "-t", "overlay", "overlay", "-o", opts, case["mnt"]],
                       capture_output=True, text=True)
    if p.returncode != 0:
        emit({"mount_error": p.stderr.strip()})
        return
    hdr = {"mounted": opts, "uid_map": idmap("/proc/self/uid_map"),
           "gid_map": idmap("/proc/self/gid_map")}
    os.chroot(case["mnt"])
    os.chdir("/")
    mounts = [os.fsencode(m) for m in case["mounts"]]
    hdr["mounts_held"] = {os.fsdecode(m): held(m) for m in mounts}
    hdr["scope_through_mount"] = through_mount(os.fsencode(case["scope"]), mounts)
    try:
        os.chdir(os.fsencode(case["scope"]))
    except OSError as e:
        hdr["scope_error"] = errno.errorcode.get(e.errno, str(e.errno))
        emit(hdr)
        return
    scope = os.getcwdb()
    hdr["scope"] = os.fsdecode(scope)
    emit(hdr)
    mset = set(mounts)

    def abs_of(rel):
        return (scope.rstrip(b"/") + b"/" + rel) if rel != b"." else scope

    todo = [b"."]
    while todo:
        rel = todo.pop()
        try:
            st = os.lstat(rel)
        except OSError as e:
            if e.errno == errno.ENOENT:
                emit({"ghost": os.fsdecode(rel)})
            else:
                emit({"path": os.fsdecode(rel), "error": errno.errorcode.get(e.errno, "?")})
            continue
        is_mount = rel != b"." and abs_of(rel) in mset
        try:
            emit(record(rel, rel, st, is_mount))
        except OSError as e:
            emit({"path": os.fsdecode(rel), "error": errno.errorcode.get(e.errno, "?")})
            continue
        if stat.S_ISDIR(st.st_mode) and not is_mount:
            try:
                names = os.listdir(rel)
            except OSError as e:
                emit({"path": os.fsdecode(rel), "error": errno.errorcode.get(e.errno, "?"),
                      "in": "readdir"})
                continue
            for n in names:
                todo.append(n if rel == b"." else rel + b"/" + n)


if __name__ == "__main__":
    main()
