#!/usr/bin/env python3
"""Random overlay layer sets for the union model, seeded and reproducible.

    gen.py --seed N --out DIR [--prefix user.overlay.]

Run it inside a user namespace (`unshare -r`): a whiteout is a character device 0:0, which
an unprivileged mknod makes only there. Writes DIR/l0 (the upper layer) .. DIR/l<n-1>, an
empty work directory DIR/w and mount point DIR/m, and DIR/case.json:

    {"seed", "layers": [...], "prefix", "scope", "mounts": [...],
     "expect": ROW or null, "inject": what was planted, "features": [...]}

`expect` names the pin row the model must refuse with when the set was built to be refused;
null when it was not (a random set can still be refused: run.sh checks those otherwise).

Names come from a small alphabet so that layers collide on the same paths: a file over a
directory, a directory over a file, a whiteout over either, entries hidden and made again.
"""

import argparse
import json
import os
import random
import socket
import stat

NAMES = [b"a", b"b", b"c", b"d", b"e"]
RARE = [b"sp ace", "été".encode(), b"\xff\xfe", b"-x", b".h", b"a.b", b"n\nl"]
MAXDEPTH = 3


class Layer:
    def __init__(self, root, idx):
        self.root = root
        self.idx = idx
        self.kind = {}          # path tuple -> "reg" | "dir" | "lnk" | "fifo" | "sock" | "wh"

    def full(self, path):
        return self.root + b"".join(b"/" + c for c in path)

    def ensure_dirs(self, path, rnd):
        """Make the parents of `path` in this layer; False when one is not a directory."""
        for k in range(1, len(path)):
            p = path[:k]
            kd = self.kind.get(p)
            if kd is None:
                os.mkdir(self.full(p))
                os.chmod(self.full(p), dir_mode(rnd))
                self.kind[p] = "dir"
            elif kd != "dir":
                return False
        return True


def dir_mode(rnd):
    # The owner keeps rwx: the model reads the layers as their unprivileged owner (U21).
    return 0o700 | rnd.choice([0, 0o055, 0o005, 0o050, 0o077, 0o1000 | 0o077, 0o2000 | 0o055])


def file_mode(rnd):
    return 0o400 | rnd.choice([0, 0o200, 0o244, 0o044, 0o311, 0o4000 | 0o155,
                               0o2000 | 0o244, 0o1000 | 0o200, 0o6000 | 0o355])


def rand_name(rnd):
    return rnd.choice(RARE) if rnd.random() < 0.06 else rnd.choice(NAMES)


def rand_path(rnd, depth=None):
    d = depth or rnd.randint(1, MAXDEPTH)
    return tuple(rand_name(rnd) for _ in range(d))


def setx(path, name, value):
    os.setxattr(path, name, value, follow_symlinks=False)


class Gen:
    def __init__(self, seed, out, prefix):
        self.rnd = random.Random(seed)
        self.seed = seed
        self.out = os.fsencode(out)
        self.prefix = prefix
        self.features = set()
        self.inject = None
        self.expect = None
        self.scope = b"/"
        self.mounts = []

    def P(self, name):
        return self.prefix + name

    # -- the random content of one layer -----------------------------------------------

    def make(self, L, path, kind, below):
        rnd = self.rnd
        if path in L.kind or not L.ensure_dirs(path, rnd):
            return False
        f = L.full(path)
        if kind == "reg":
            data = bytes(rnd.getrandbits(8) for _ in range(rnd.choice([0, 1, 7, 100, 3000])))
            with open(f, "wb") as fh:
                fh.write(data)
            os.chmod(f, file_mode(rnd))
        elif kind == "dir":
            os.mkdir(f)
            os.chmod(f, dir_mode(rnd))
        elif kind == "lnk":
            os.symlink(self.rand_target(path), f)
        elif kind == "fifo":
            os.mkfifo(f, 0o600 | rnd.choice([0, 0o044, 0o066]))
        elif kind == "sock":
            parent = L.full(path[:-1])
            cwd = os.open(".", os.O_RDONLY)
            try:
                os.chdir(parent)       # a socket path must fit sockaddr_un: bind a short name
                s = socket.socket(socket.AF_UNIX)
                s.bind(path[-1])
                s.close()
            finally:
                os.fchdir(cwd)
                os.close(cwd)
        elif kind == "wh":
            os.mknod(f, 0o600 | stat.S_IFCHR, os.makedev(0, 0))
            self.features.add("whiteout")
        L.kind[path] = kind
        if kind in ("reg", "dir") and rnd.random() < 0.25:
            for k in range(rnd.randint(1, 3)):
                val = bytes(rnd.getrandbits(8) for _ in range(rnd.choice([0, 1, 5, 40])))
                setx(f, "user.t%d" % k, val)
            self.features.add("xattr")
        if kind in ("reg", "dir") and rnd.random() < 0.06:
            setx(f, self.P("protattr"), rnd.choice([b"i", b"a", b"ia", b"ai", b"ii"]))
            self.features.add("protattr-l0" if L.idx == 0 else "protattr-lower")
        if kind == "dir" and below and rnd.random() < 0.15:
            setx(f, self.P("opaque"), b"y")
            self.features.add("opaque")
        return True

    def rand_target(self, path):
        rnd = self.rnd
        r = rnd.random()
        if r < 0.3:
            return rand_name(rnd)
        if r < 0.5:
            return b"../" * rnd.randint(1, 4) + b"/".join(rand_path(rnd))
        if r < 0.85:
            return b"/" + b"/".join(rand_path(rnd))
        return rnd.choice([b"/", b".", b"..", b"nowhere/x", b"/a/../b", b"//a//b/"])

    def layer_ops(self, L, layers, nops, redirects):
        rnd = self.rnd
        below = [M for M in layers if M.idx > L.idx]
        for _ in range(nops):
            r = rnd.random()
            if redirects and below and r < 0.12:
                self.redirect(L, below)
                continue
            if below and r < 0.30:
                # Hide something a layer below holds, often to make it again further up.
                cands = [p for M in below for p in M.kind if M.kind[p] != "wh"]
                if cands:
                    self.make(L, rnd.choice(cands), "wh", below)
                    continue
            if below and r < 0.45:
                # Something at a path a layer below holds, of a random kind.
                cands = [p for M in below for p in M.kind]
                if cands:
                    self.make(L, rnd.choice(cands), rnd.choice(["reg", "dir", "dir", "lnk"]), below)
                    continue
            kind = rnd.choices(["reg", "dir", "lnk", "fifo", "sock"], [40, 30, 15, 3, 2])[0]
            self.make(L, rand_path(rnd), kind, below)

    def redirect(self, L, below):
        """A directory renamed in L: a directory at a new path whose redirect names one a
        layer below holds, relative (a rename in place) or absolute; often with a whiteout at
        the old path, as a rename leaves; sometimes in a middle layer, so that a redirect
        leads to another (a chain)."""
        rnd = self.rnd
        cands = [(M, p) for M in below for p in M.kind if M.kind[p] == "dir"]
        if not cands:
            return
        M, old = rnd.choice(cands)
        relative = rnd.random() < 0.4
        if relative:
            new = old[:-1] + (rand_name(rnd) + b"r",)
        else:
            new = rand_path(rnd)[:-1] + (rand_name(rnd) + b"R",)
        if new[:len(old)] == old or old[:len(new)] == new:
            return
        if not self.make(L, new, "dir", below):
            return
        value = old[-1] if relative else b"/" + b"/".join(old)
        setx(L.full(new), self.P("redirect"), value)
        self.features.add("redirect-rel" if relative else "redirect-abs")
        if L.idx > 0:
            self.features.add("redirect-middle")
        if rnd.random() < 0.5:
            self.make(L, old, "wh", below)

    # -- the set -----------------------------------------------------------------------

    def build(self):
        rnd = self.rnd
        n = rnd.randint(2, 5)
        layers = []
        for i in range(n):
            root = self.out + b"/l%d" % i
            os.mkdir(root)
            layers.append(Layer(root, i))
        os.mkdir(self.out + b"/w")
        os.mkdir(self.out + b"/m")
        r = rnd.random()
        inject = r < 0.18
        redirects = not inject and rnd.random() < 0.35
        for L in reversed(layers):
            self.layer_ops(L, layers, rnd.randint(4, 40), redirects)
        # The roots: an opaque root changes nothing (U8); a root's own xattrs show.
        if rnd.random() < 0.1:
            setx(rnd.choice(layers).root, self.P("opaque"), b"y")
            self.features.add("opaque-root")
        if rnd.random() < 0.1:
            setx(layers[0].root, "user.root", b"r")
        if inject:
            self.plant(layers)
        else:
            self.pick_scope(layers)
            self.pick_mounts(layers)
        return layers

    def pick_scope(self, layers):
        rnd = self.rnd
        r = rnd.random()
        if r < 0.7:
            return
        dirs = [p for L in layers for p in L.kind if L.kind[p] == "dir"]
        top = [p for p in layers[0].kind if layers[0].kind[p] == "dir"]
        if top and rnd.random() < 0.7:
            dirs = top          # the upper layer's directories are always paths of the union
        if r < 0.82 and dirs:
            self.scope = b"/" + b"/".join(rnd.choice(dirs))
            self.features.add("scope-dir")
            return
        # A scope reached by links (H-C3), sometimes through `..` above the root.
        L = layers[0]
        target = b"/" + b"/".join(rnd.choice(dirs)) if dirs else b"/"
        if rnd.random() < 0.3:
            target = b"../../.." + target
        hops = rnd.choice([1, 2, 3, 39, 40, 41])
        if not L.ensure_dirs((b"zl", b"x"), rnd):
            return
        for k in range(hops):
            nxt = b"s%d" % (k + 1) if k + 1 < hops else target
            os.symlink(nxt, L.full((b"zl", b"s%d" % k)))
            L.kind[(b"zl", b"s%d" % k)] = "lnk"
        tail = rnd.choice([b"", b"", b"/a", b"/..", b"/."])
        self.scope = b"/zl/s0" + tail
        self.features.add("scope-link-%d" % hops)

    def pick_mounts(self, layers):
        rnd = self.rnd
        if rnd.random() > 0.2:
            return
        paths = [p for L in layers for p in L.kind]
        for _ in range(rnd.randint(1, 3)):
            if paths and rnd.random() < 0.85:
                m = rnd.choice(paths)
            else:
                m = rand_path(rnd)
            self.mounts.append(b"/" + b"/".join(m))
        self.features.add("mounts")

    def plant(self, layers):
        """One thing a pin row refuses, where the union must read it (scope `/`)."""
        rnd = self.rnd
        n = len(layers)
        up = layers[0]
        low = layers[rnd.randint(1, n - 1)]
        z = (b"zz",)

        def updir():
            os.mkdir(up.full(z))
            up.kind[z] = "dir"

        def lowdir(attr=None, value=None):
            os.mkdir(low.full(z))
            low.kind[z] = "dir"
            if attr:
                setx(low.full(z), self.P(attr), value)

        cases = [
            ("H-U3", "opaque n on an upper dir"),
            ("H-U3", "opaque x on a lower dir merged under an upper one"),
            ("H-U3", "opaque y on a regular file"),
            ("H-U5", "redirect on a regular file"),
            ("H-U5", "malformed redirect"),
            ("H-U5", "redirect to a path nothing below holds"),
            ("H-U5", "redirect on a bottom-layer dir"),
            ("H-U5", "redirect to a lower regular file"),
            ("H-U6", "unknown overlay xattr upper"),
            ("H-U6", "unknown overlay xattr on a lower merged dir"),
            ("H-U8", "malformed protattr"),
            ("H-C3", "scope over 40 links"),
            ("H-C3", "scope a regular file"),
            ("H-C3", "scope missing"),
            ("H-C3", "scope a mount point"),
            ("H-C3", "scope inside a mount"),
            ("H-M5", "mount point the union does not hold"),
            ("H-M5", "mount point below a link"),
        ]
        row, what = rnd.choice(cases)
        self.expect, self.inject = row, what
        f = up.full(z)
        if what == "opaque n on an upper dir":
            updir()
            setx(f, self.P("opaque"), rnd.choice([b"n", b"", b"yes", b"Y"]))
        elif what.startswith("opaque x"):
            updir()
            lowdir("opaque", b"x")
        elif what == "opaque y on a regular file":
            open(f, "wb").close()
            setx(f, self.P("opaque"), b"y")
        elif what == "redirect on a regular file":
            open(f, "wb").close()
            setx(f, self.P("redirect"), b"/a")
        elif what == "malformed redirect":
            updir()
            setx(f, self.P("redirect"),
                 rnd.choice([b"a/b", b"/a//b", b"/a/", b"", b"..", b"/a/../b", b"/", b"."]))
        elif what == "redirect to a path nothing below holds":
            updir()
            setx(f, self.P("redirect"), rnd.choice([b"/no-such-q", b"no-such-r"]))
        elif what == "redirect on a bottom-layer dir":
            low = layers[-1]
            lowdir("redirect", b"/a")
        elif what == "redirect to a lower regular file":
            updir()
            setx(f, self.P("redirect"), b"/zf")
            open(low.full((b"zf",)), "wb").close()
            low.kind[(b"zf",)] = "reg"
            os.mknod(up.full((b"zf",)), 0o600 | stat.S_IFCHR, os.makedev(0, 0))
        elif what == "unknown overlay xattr upper":
            open(f, "wb").close()
            setx(f, self.P(rnd.choice(["whiteout", "metacopy", "overlay.opaque", "nlink",
                                       "upper", "Opaque"])), b"y")
        elif what == "unknown overlay xattr on a lower merged dir":
            updir()
            lowdir(rnd.choice(["whiteout", "metacopy", "overlay.x"]), b"")
        elif what == "malformed protattr":
            open(f, "wb").close()
            setx(f, self.P("protattr"), rnd.choice([b"x", b"", b"i ", b"I", b"iax"]))
        elif what == "scope over 40 links":
            updir()
            for k in range(41):
                os.symlink(b"s%d" % (k + 1) if k < 40 else b"/", up.full(z + (b"s%d" % k,)))
            self.scope = b"/zz/s0"
        elif what == "scope a regular file":
            open(f, "wb").close()
            self.scope = rnd.choice([b"/zz", b"/zz/", b"/zz/x"])
        elif what == "scope missing":
            self.scope = b"/zz-none/x"
        elif what == "scope a mount point":
            updir()
            self.scope = b"/zz"
            self.mounts = [b"/zz"]
        elif what == "scope inside a mount":
            updir()
            os.mkdir(up.full(z + (b"in",)))
            self.scope = b"/zz/in"
            self.mounts = [b"/zz"]
        elif what == "mount point the union does not hold":
            self.mounts = [b"/zz-none"]
        elif what == "mount point below a link":
            updir()
            os.mkdir(up.full(z + (b"d",)))
            os.mkdir(up.full(z + (b"d", b"x")))
            os.symlink(b"zz/d", up.full((b"zy",)))
            self.mounts = [b"/zy/x"]
        self.features.add("inject")

    def write_case(self, layers):
        case = {
            "seed": self.seed,
            "layers": [os.fsdecode(L.root) for L in layers],
            "work": os.fsdecode(self.out + b"/w"),
            "mnt": os.fsdecode(self.out + b"/m"),
            "prefix": self.prefix,
            "scope": os.fsdecode(self.scope),
            "mounts": [os.fsdecode(m) for m in self.mounts],
            "expect": self.expect,
            "inject": self.inject,
            "features": sorted(self.features),
        }
        with open(self.out + b"/case.json", "w") as f:
            json.dump(case, f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--prefix", default="user.overlay.")
    a = ap.parse_args()
    os.umask(0)
    os.makedirs(a.out, exist_ok=False)
    g = Gen(a.seed, a.out, a.prefix)
    layers = g.build()
    g.write_case(layers)


if __name__ == "__main__":
    main()
