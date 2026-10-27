#!/usr/bin/env python3
"""Deterministic fixture trees for golden manifest comparisons.

Usage: make_fixtures.py <dir>

Creates <dir>/main (the general tree), <dir>/root_unsearchable (a scope root
that can be listed but not searched) and, where /dev/shm is tmpfs with user
xattrs, a large-xattr fixture under <dir>/shm_link -> /dev/shm/... . Every
capture path that can be reproduced without privileges is represented once.
"""
import os
import socket
import stat
import subprocess
import sys


def write(path, data=b"", mode=None):
    with open(path, "wb") as f:
        f.write(data)
    if mode is not None:
        os.chmod(path, mode)


def try_xattr(path, name, value, follow=True):
    try:
        os.setxattr(path, name, value, follow_symlinks=follow)
        return True
    except (OSError, AttributeError):
        return False


def main_tree(root):
    os.makedirs(root)
    j = lambda *p: os.path.join(root, *p)

    # Regular files: empty, text, binary, over hash_max (4096 in the driver's
    # small-limit run), over store_max (1024), exactly at the limits.
    write(j("empty"))
    write(j("text.txt"), b"hello\n")
    write(j("binary.bin"), b"\x00\x01\x02binary")
    write(j("big.txt"), b"a" * 5000)
    write(j("mid.txt"), b"m" * 2000)
    write(j("at_hash_limit.txt"), b"h" * 4096)
    write(j("at_store_limit.txt"), b"s" * 1024)
    write(j("mode0755.sh"), b"#!/bin/sh\n", 0o755)

    # Names: non-ASCII, non-UTF-8, JSON escapes, sort-order traps.
    write(j("café.txt"), b"c")
    write(os.path.join(root.encode(), b"bad\xffname"), b"b")
    write(j('quote"back\\slash'), b"q")
    write(j("new\nline"), b"n")
    write(j("-dash"), b"d")
    os.makedirs(j("d"))
    write(j("d", "child"), b"x")
    write(j("d!x"), b"between d and d/")
    write(j("d.y"), b"also between")
    write(j("d0"), b"after d/")
    os.makedirs(j("empty_dir"))

    # Symlinks: relative inside, absolute outside, relative escape,
    # dangling, long target, to a directory.
    os.symlink("text.txt", j("link_rel"))
    os.symlink("/etc", j("link_abs_out"))
    os.symlink("../../outside", j("link_escape"))
    os.symlink("no_such_target", j("link_dangling"))
    os.symlink("x" * 4000, j("link_long"))
    os.symlink("d", j("link_dir"))
    os.symlink("café.txt", j("link_utf8"))
    os.symlink(b"bad\xfetarget", os.path.join(root.encode(), b"link_non_utf8"))

    # Hard links, FIFO, socket.
    write(j("hard_a"), b"shared")
    os.link(j("hard_a"), j("hard_b"))
    os.mkfifo(j("fifo"))
    s = socket.socket(socket.AF_UNIX)
    try:
        s.bind(j("sock"))
    finally:
        s.close()

    # Unreadable: file, directory (with contents), readable-not-searchable.
    write(j("unreadable_file"), b"secret", 0o000)
    os.makedirs(j("locked", "inner"))
    write(j("locked", "inner", "f"), b"f")
    os.chmod(j("locked"), 0o000)
    os.makedirs(j("r_only"))
    write(j("r_only", "f"), b"f")
    os.chmod(j("r_only"), 0o444)

    # Depth limit: 130 nested directories (the walk opens 128 levels).
    p = j("deep")
    for i in range(130):
        p = os.path.join(p, "n")
    os.makedirs(p)
    write(os.path.join(p, "leaf"), b"leaf")

    # Interpreter-claimed paths (stored regardless of size, or hash only).
    os.makedirs(j("var", "lib", "dpkg", "info"))
    write(j("var", "lib", "dpkg", "status"), b"Package: x\n" * 300)
    write(j("var", "lib", "dpkg", "info", "x.list"), b"/usr/bin/x\n")
    write(j("var", "lib", "dpkg", "info", "x.md5sums"), b"0" * 32 + b"  usr/bin/x\n")
    dist = j("usr", "lib", "python3", "dist-packages", "x-1.0.dist-info")
    os.makedirs(dist)
    write(os.path.join(dist, "RECORD"), b"x.py,sha256=abc,1\n" * 200)
    write(os.path.join(dist, "METADATA"), b"Name: x\n")
    for d in ("refs/heads", "hooks", "objects/ab"):
        os.makedirs(j(".git", d))
    write(j(".git", "HEAD"), b"ref: refs/heads/main\n")
    write(j(".git", "refs", "heads", "main"), b"0" * 40 + b"\n")
    write(j(".git", "hooks", "pre-commit"), b"#!/bin/sh\nexit 0\n", 0o755)
    write(j(".git", "index"), b"DIRC" + b"\x00" * 3000)
    write(j(".git", "objects", "ab", "cdef"), b"x\x9c" + b"\x00" * 100)

    # Extended metadata, where the filesystem has it.
    try_xattr(j("text.txt"), "user.alpha", b"1")
    try_xattr(j("text.txt"), "user.wé", b"2")
    try_xattr(j("d"), "user.dir", b"dirval")
    try_xattr(j("empty"), "user.empty", b"")
    subprocess.run(["chattr", "+d", j("mid.txt")], stderr=subprocess.DEVNULL, check=False)

    # Volume: enough records to spill with the minimum run budget.
    for a in range(30):
        os.makedirs(j("many", "g%02d" % a))
        for b in range(100):
            write(j("many", "g%02d" % a, "%sf%03d" % ("F" if b % 3 == 0 else "", b)), b"%d" % b)


def root_unsearchable(root):
    os.makedirs(root)
    write(os.path.join(root, "f"), b"f")
    os.chmod(root, 0o644)


def shm_tree(root):
    os.makedirs(root)
    f = os.path.join(root, "many_xattrs")
    write(f, b"x")
    ok = all(try_xattr(f, "user.a-fairly-long-attribute-name-number-%03d" % i, b"v")
             for i in range(100))
    write(os.path.join(root, "few"), b"y")
    try_xattr(os.path.join(root, "few"), "user.one", b"1")
    return ok


def main():
    base = sys.argv[1]
    main_tree(os.path.join(base, "main"))
    root_unsearchable(os.path.join(base, "root_unsearchable"))
    if os.path.isdir("/dev/shm"):
        shm = "/dev/shm/belay_golden_%d" % os.getpid()
        if shm_tree(shm):
            with open(os.path.join(base, "shm_path"), "w") as f:
                f.write(shm)


if __name__ == "__main__":
    main()
