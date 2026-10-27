#!/usr/bin/env python3
"""Deterministic mutation corpus for reader-equivalence checks.

Usage: mutate.py <outdir> <manifest>...

For every input manifest, writes the original plus variants that drop,
duplicate, swap, add or corrupt fields, flags, lines and trailer counts.
Two revisions of the reader must accept and reject exactly the same files,
with the same messages and the same decoded entries.
"""
import os
import random
import re
import sys

FLAGS = ["unverified", "unstable", "unreadable", "mount", "raced", "target_outside_scope",
         "xattrs_unknown"]
FIELD = re.compile(rb'"([a-z_0-9]+)":("(?:[^"\\]|\\.)*"|\[[^\]]*\]|-?[0-9]+|true|false|null)')


def split_fields(line):
    body = line.strip()[1:-1]
    return [m.group(0) for m in FIELD.finditer(body)]


def join_fields(fields):
    return b"{" + b",".join(fields) + b"}"


def variants(lines, rnd):
    body = list(range(1, len(lines) - 1))
    for _ in range(300):
        i = rnd.choice(body) if body else 0
        f = split_fields(lines[i])
        kind = rnd.randrange(14)
        new = list(f)
        if kind == 0 and f:
            new.pop(rnd.randrange(len(f)))
        elif kind == 1 and f:
            new.insert(rnd.randrange(len(f) + 1), rnd.choice(f))
        elif kind == 2 and len(f) > 1:
            k = rnd.randrange(len(f) - 1)
            new[k], new[k + 1] = new[k + 1], new[k]
        elif kind == 3:
            new.append(b'"%s":true' % rnd.choice(FLAGS).encode())
        elif kind == 4:
            new.insert(rnd.randrange(len(f) + 1), b'"%s":true' % rnd.choice(FLAGS).encode())
        elif kind == 5:
            new = [x.replace(b":true", b": true") if rnd.random() < .5 else x for x in f]
        elif kind == 6:
            new = [re.sub(rb'"type":"[a-z]+"', b'"type":"%s"' % rnd.choice(
                [b"reg", b"dir", b"lnk", b"fifo", b"sock", b"blk", b"chr", b"xyz"]), x) for x in f]
        elif kind == 7:
            new = [re.sub(rb'([0-9a-f]{64})', lambda m: m.group(1)[:-1] + b"g", x) for x in f]
        elif kind == 8:
            new.append(b'"zz_unknown":1')
        elif kind == 9 and f:
            new.insert(rnd.randrange(len(f)), b'"zz_unknown":1')
        elif kind == 10:
            new = [re.sub(rb':([0-9]+)', lambda m: b":" + str(int(m.group(1)) + 1).encode(), x, count=1)
                   if rnd.random() < .3 else x for x in f]
        elif kind == 11:
            yield ("trunc", lines[:i] + [lines[i][: rnd.randrange(1, len(lines[i]))]])
            continue
        elif kind == 12 and len(lines) > 3:
            yield ("dropline", lines[:i] + lines[i + 1:])
            continue
        elif kind == 13:
            yield ("dupline", lines[:i + 1] + [lines[i]] + lines[i + 1:])
            continue
        yield ("k%d" % kind, lines[:i] + [join_fields(new)] + lines[i + 1:])
    t = lines[-1]
    for key in (b"belay_manifest_end", b"vanished", b"unreadable", b"unstable", b"mounts", b"raced"):
        yield ("trailer_" + key.decode(),
               lines[:-1] + [re.sub(rb'"%s":([0-9]+)' % key,
                                    lambda m: b'"%s":%d' % (key, int(m.group(1)) + 1), t)])


# Every state an unprivileged quiet-tree fixture cannot produce: devices,
# raced and unstable entries, mounts, unknown xattrs, capabilities, digest-form
# xattr sets, base64 paths and targets, the empty "unknown" link target.
H = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SEED = [
    '{"belay_manifest":1,"created_ns":0,"scopes":["/s"],"hash":"sha256","hash_max_bytes":67108864,"store_max_bytes":65536}',
    '{"path":".","type":"dir","mode":16877,"uid":1,"gid":1,"size":1,"mtime_ns":1,"ctime_ns":1,"ino":1,"dev":1,"nlink":2,"iflags":0,"unstable":true}',
    '{"path":"blk","type":"blk","mode":24992,"uid":0,"gid":0,"size":0,"mtime_ns":1,"ctime_ns":1,"ino":2,"dev":1,"nlink":1,"rdev":2049}',
    '{"path":"chr","type":"chr","mode":8630,"uid":0,"gid":0,"size":0,"mtime_ns":1,"ctime_ns":1,"ino":3,"dev":1,"nlink":1,"rdev":259,"raced":true}',
    '{"path":"d","type":"dir","mode":16877,"uid":1,"gid":1,"size":1,"mtime_ns":1,"ctime_ns":1,"ino":4,"dev":1,"nlink":2,"xattrs":["user.a=' + H + '","x:757365722e77c3a9=' + H + '"],"unstable":true}',
    '{"path":"d/f","type":"reg","mode":33261,"uid":1,"gid":1,"size":0,"mtime_ns":1,"ctime_ns":1,"ino":5,"dev":1,"nlink":1,"caps":"0100000200200000","xattrs_sha256":"' + H + '","sha256":"' + H + '","stored":"' + H + '","raced":true}',
    '{"path":"lnk","type":"lnk","mode":41471,"uid":1,"gid":1,"size":7,"mtime_ns":1,"ctime_ns":1,"ino":6,"dev":1,"nlink":1,"link_target":"","unreadable":true}',
    '{"path":"lnk2","type":"lnk","mode":41471,"uid":1,"gid":1,"size":4,"mtime_ns":1,"ctime_ns":1,"ino":7,"dev":1,"nlink":1,"link_target":"/etc","target_outside_scope":true}',
    '{"path":"lnk3","type":"lnk","mode":41471,"uid":1,"gid":1,"size":2,"mtime_ns":1,"ctime_ns":1,"ino":8,"dev":1,"nlink":1,"link_target_b64":"//4=","xattrs_unknown":true}',
    '{"path":"m","type":"dir","mode":16877,"uid":1,"gid":1,"size":1,"mtime_ns":1,"ctime_ns":1,"ino":9,"dev":2,"nlink":2,"mount":true,"raced":true}',
    '{"path":"p","type":"fifo","mode":4516,"uid":1,"gid":1,"size":0,"mtime_ns":1,"ctime_ns":1,"ino":10,"dev":1,"nlink":1}',
    '{"path":"q","type":"reg","mode":33188,"uid":1,"gid":1,"size":9,"mtime_ns":1,"ctime_ns":1,"ino":11,"dev":1,"nlink":1,"unverified":true,"unstable":true,"raced":true}',
    '{"path":"r","type":"reg","mode":33188,"uid":1,"gid":1,"size":9,"mtime_ns":1,"ctime_ns":1,"ino":12,"dev":1,"nlink":1,"unverified":true,"unreadable":true}',
    '{"path":"s","type":"sock","mode":49645,"uid":1,"gid":1,"size":0,"mtime_ns":1,"ctime_ns":1,"ino":13,"dev":1,"nlink":1,"mount":true}',
    '{"path":"u","type":"dir","mode":16877,"uid":1,"gid":1,"size":1,"mtime_ns":1,"ctime_ns":1,"ino":14,"dev":1,"nlink":2,"unreadable":true}',
    '{"path_b64":"/w==","type":"reg","mode":33188,"uid":1,"gid":1,"size":0,"mtime_ns":-5,"ctime_ns":1,"ino":15,"dev":1,"nlink":1,"sha256":"' + H + '"}',
    '{"belay_manifest_end":15,"vanished":3,"unreadable":3,"unstable":3,"mounts":2,"raced":4}',
]


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    rnd = random.Random(20261027)
    n = 0
    seed = os.path.join(out, "seed", "seed.ndjson")
    os.makedirs(os.path.dirname(seed), exist_ok=True)
    open(seed, "w").write("\n".join(SEED) + "\n")
    for path in [seed] + sys.argv[2:]:
        lines = open(path, "rb").read().split(b"\n")[:-1]
        stem = os.path.basename(os.path.dirname(path)) + "_" + os.path.basename(path)
        open(os.path.join(out, "%05d_orig_%s" % (n, stem)), "wb").write(b"\n".join(lines) + b"\n")
        n += 1
        for tag, ls in variants(lines, rnd):
            open(os.path.join(out, "%05d_%s_%s" % (n, tag, stem)), "wb").write(b"\n".join(ls) + b"\n")
            n += 1
    print(n, "files")


if __name__ == "__main__":
    main()
