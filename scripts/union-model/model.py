#!/usr/bin/env python3
"""The union-resolver model: a container's filesystem as read from its overlay layers.

An independent model, written from Linux's Documentation/filesystems/overlayfs.rst and
the pin test/expect/host-reader.md (rows H-U1..H-U10, H-C3, H-M5). It never looks at
belay's code. Every choice the pin leaves open is a numbered reading in
NOTES-union-model.md (U1, U2, ...); the code cites them.

    model.py [options] SCOPE LAYER... [--mount PATH]...

LAYER: the layer directories, topmost first (upper, then the lowers in lowerdir's order).
SCOPE: an absolute path inside the container.

Output (stdout): one JSON line per entry of the merged view at and below the scope,
sorted by the bytes of `path` -- or one line {"refused": ROW, "why": TEXT}.
Exit status: 0 for a listing, 1 for a refusal, 2 for a usage error.
"""

import argparse
import base64
import errno
import hashlib
import json
import os
import stat
import sys

# The overlay's own xattrs the pin names (H-U6): acted on, and ignored.
ACTED = ("opaque", "redirect", "protattr")
IGNORED = ("origin", "impure", "uuid")
MAXLINKS = 40  # H-C3


class Refused(Exception):
    def __init__(self, row, why):
        super().__init__(row, why)
        self.row = row
        self.why = why


def show(b):
    """Bytes as text for a refusal message (never parsed back)."""
    return b.decode("utf-8", "backslashreplace")


def put_bytes(obj, key, b):
    """manifest-v1's rule: `key` for valid UTF-8, `key_b64` otherwise (U22)."""
    try:
        obj[key] = b.decode("utf-8")
    except UnicodeDecodeError:
        obj[key + "_b64"] = base64.b64encode(b).decode("ascii")


TYPES = (
    (stat.S_ISREG, "reg"), (stat.S_ISDIR, "dir"), (stat.S_ISLNK, "lnk"),
    (stat.S_ISCHR, "chr"), (stat.S_ISBLK, "blk"), (stat.S_ISFIFO, "fifo"),
    (stat.S_ISSOCK, "sock"),
)


def type_of(st):
    for test, name in TYPES:
        if test(st.st_mode):
            return name
    raise Refused("H-U1", "a layer file of unknown type")


class LayerFile:
    """One file of one layer, as read on the host: its lstat and its xattrs."""

    __slots__ = ("layer", "path", "st", "xattrs")

    def __init__(self, layer, path, st, xattrs):
        self.layer = layer      # index, 0 = topmost
        self.path = path        # bytes, absolute inside the layer ("/" for its root)
        self.st = st
        self.xattrs = xattrs    # name (str) -> value (bytes)

    @property
    def is_dir(self):
        return stat.S_ISDIR(self.st.st_mode)

    def is_whiteout(self):
        # H-U2: a character device 0:0. (The xattr form of a whiteout is refused by H-U6, U12.)
        return stat.S_ISCHR(self.st.st_mode) and self.st.st_rdev == 0


class Entry:
    """A path of the merged view: the layer files that make it, topmost first."""

    __slots__ = ("members", "tainted")

    def __init__(self, members, tainted):
        self.members = members  # [LayerFile]; one for a non-directory, the merged stack for a dir
        self.tainted = tainted  # a redirect was followed to reach it (U20; for run.sh only)

    @property
    def top(self):
        return self.members[0]


class Union:
    def __init__(self, layers, prefix):
        self.roots = [os.fsencode(os.path.realpath(d)) for d in layers]
        self.n = len(self.roots)
        self.prefix = prefix
        self.cache = {}

    # -- reading one layer -------------------------------------------------------------

    def read(self, layer, path):
        """The layer file at `path` (whose parent is known to be a real directory of that
        layer, so no link is ever followed: H-U10), or None when there is none."""
        key = (layer, path)
        if key in self.cache:
            return self.cache[key]
        full = self.roots[layer] + path
        try:
            st = os.lstat(full)
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.ENAMETOOLONG):
                self.cache[key] = None
                return None
            raise
        xattrs = {}
        if not stat.S_ISCHR(st.st_mode) or st.st_rdev != 0:
            for name in os.listxattr(full, follow_symlinks=False):
                xattrs[name] = os.getxattr(full, name, follow_symlinks=False)
        lf = LayerFile(layer, path, st, xattrs)
        self.cache[key] = lf
        return lf

    def ovl(self, lf, name):
        return lf.xattrs.get(self.prefix + name)

    def validate(self, lf):
        """The refusals that a layer file's own overlay xattrs call for (U11-U14)."""
        where = "%s in layer %d" % (show(lf.path), lf.layer)
        for name in sorted(lf.xattrs):
            if not name.startswith(self.prefix):
                continue
            rest = name[len(self.prefix):]
            if rest not in ACTED and rest not in IGNORED:
                raise Refused("H-U6", "unknown overlay xattr %s on %s" % (name, where))
        op = self.ovl(lf, "opaque")
        if op is not None:
            if not lf.is_dir:
                raise Refused("H-U3", "an opaque xattr on a non-directory, %s" % where)
            if op != b"y":
                raise Refused("H-U3", "opaque value %r on %s" % (op, where))
        red = self.ovl(lf, "redirect")
        if red is not None:
            if not lf.is_dir:
                raise Refused("H-U5", "a redirect on a non-directory, %s" % where)
            if not redirect_ok(red):
                raise Refused("H-U5", "a malformed redirect %r on %s" % (red, where))
        pa = self.ovl(lf, "protattr")
        if pa is not None and (pa == b"" or pa.strip(b"ia") != b""):
            raise Refused("H-U8", "protattr value %r on %s" % (pa, where))

    def listdir(self, lf):
        return os.listdir(self.roots[lf.layer] + lf.path)

    # -- the lookup (H-U1..H-U5) ---------------------------------------------------------

    def root(self):
        """The root: every layer's root directory, merged. A root's opaque and redirect are
        never consulted (U8): nothing names the root by looking it up."""
        members = []
        for i in range(self.n):
            lf = self.read(i, b"/")
            if lf is None or not lf.is_dir:
                raise Refused("H-U1", "layer %d's root is not a directory" % i)
            self.validate(lf)
            members.append(lf)
        return Entry(members, False)

    def child(self, parent, name):
        """The entry `name` in the directory entry `parent`, or None (U1-U7)."""
        st = _Lookup(name)
        found = []
        # In the layers the parent is made of, the name is looked up in the parent's
        # directory of that layer (which, under the parent's own redirects, can sit at
        # another path). Once an absolute redirect is met, every layer below it is
        # searched from its root instead (U5).
        queue = [(m.layer, m.path) for m in parent.members]
        pos = 0
        from_root = False
        while pos < len(queue) and not st.stop:
            layer, base = queue[pos]
            pos += 1
            lf = self.lookup_layer(layer, base, st)
            if lf is None:
                continue
            found.append((lf, st.redirected_here))
            if st.stop:
                break
            if st.absolute and not from_root:
                from_root = True
                queue = [(i, b"/") for i in range(layer + 1, self.n)]
                pos = 0
        if not found:
            return None
        members = [lf for lf, _ in found]
        # H-U5: a redirect must name something a layer below holds as a directory: some
        # member must come after the one that carries it (U6).
        for k, (lf, redirected) in enumerate(found):
            if redirected and k == len(found) - 1:
                raise Refused("H-U5", "the redirect %r on %s in layer %d names no directory a "
                              "layer below holds" % (self.ovl(lf, "redirect"), show(lf.path),
                                                     lf.layer))
        return Entry(members, parent.tainted or st.tainted)

    def lookup_layer(self, layer, base, st):
        """Look the current name up in one layer: a single name inside `base`, or an absolute
        path walked from the layer's root, component by component (U5)."""
        st.redirected_here = False
        if not st.name.startswith(b"/"):
            return self.lookup_single(layer, join(base, st.name), st, True, b"")
        comps = st.name[1:].split(b"/")
        path = b""
        for k, comp in enumerate(comps):
            last_el = k == len(comps) - 1
            post = b"".join(b"/" + c for c in comps[k + 1:])
            path = path + b"/" + comp
            lf = self.lookup_single(layer, path, st, last_el, post)
            if lf is None or last_el:
                return lf
        raise AssertionError("unreachable")

    def lookup_single(self, layer, path, st, last_el, post):
        lf = self.read(layer, path)
        if lf is None:
            return None                                     # nothing here: look below (H-U1)
        if lf.is_whiteout():
            st.stop = True                                  # H-U2
            return None
        if not lf.is_dir:
            if st.is_dir or not last_el:
                st.stop = True                              # a non-dir below a dir: hidden (U2)
                return None
            self.validate(lf)
            st.stop = True                                  # non-directories hide all below (U3)
            return lf
        # Only the layer files the union is made of are judged (U14).
        self.validate(lf)
        if last_el:
            st.is_dir = True
        if layer == self.n - 1:
            # The bottom layer: nothing is below it. Its redirect is checked by the caller
            # (U6), its opaque changes nothing.
            if last_el and self.ovl(lf, "redirect") is not None and self.ovl(lf, "opaque") is None:
                st.redirected_here = True
            return lf
        if self.ovl(lf, "opaque") == b"y":
            st.stop = True                                  # H-U3; its redirect is moot (U9)
            return lf
        red = self.ovl(lf, "redirect")
        if red is not None:                                 # H-U5
            st.tainted = True
            if last_el:
                st.redirected_here = True
            if red.startswith(b"/"):
                st.name = red + post
                st.absolute = True
                st.stop = False                             # U5: from the root again
            else:
                head = st.name[:len(st.name) - len(post) - len(path.rsplit(b"/", 1)[1])]
                st.name = head + red + post
        return lf


class _Lookup:
    """The state of one name's lookup down the layers."""

    __slots__ = ("name", "stop", "is_dir", "absolute", "tainted", "redirected_here")

    def __init__(self, name):
        self.name = name            # a single name, or an absolute path after a redirect
        self.stop = False
        self.is_dir = False
        self.absolute = False
        self.tainted = False
        self.redirected_here = False


def join(base, name):
    return (base if base != b"/" else b"") + b"/" + name


def redirect_ok(v):
    """U10: an absolute path of non-empty components, or a single name; never `.`/`..`."""
    if v == b"" or b"\0" in v:
        return False
    comps = v[1:].split(b"/") if v.startswith(b"/") else [v]
    if not v.startswith(b"/") and b"/" in v:
        return False
    return all(c not in (b"", b".", b"..") for c in comps)


def norm_abs(p, what):
    if not p.startswith(b"/"):
        raise ValueError("%s %s is not absolute" % (what, show(p)))
    comps = [c for c in p.split(b"/") if c != b""]
    if any(c in (b".", b"..") for c in comps):
        raise ValueError("%s %s is not canonical" % (what, show(p)))
    return comps


def is_below(path, top):
    """`path` strictly below `top` (component lists)."""
    return len(path) > len(top) and path[:len(top)] == top


class Model:
    def __init__(self, layers, prefix, scope, mounts):
        self.u = Union(layers, prefix)
        self.scope = scope
        self.mounts = [tuple(m) for m in mounts]
        self.scope_tainted = False      # a redirect followed on the way to the scope (U20)

    def resolve_scope(self):
        """H-C3: component by component in the union; links followed inside the
        container's root, absolute from it, `..` at the root staying there, 40 at most."""
        u = self.u
        root = u.root()
        chain = [((), root)]                 # (components, entry) from the root down
        todo = [c for c in self.scope.split(b"/")]
        links = 0
        while todo:
            c = todo.pop(0)
            if c == b"":
                continue
            comps, ent = chain[-1]
            if not ent.top.is_dir:      # `file/..` and `file/.` too, as the kernel's walk (U16)
                raise Refused("H-C3", "the scope's path goes through a non-directory, /%s"
                              % show(b"/".join(comps)))
            if c == b".":
                continue
            if c == b"..":
                if len(chain) > 1:
                    chain.pop()
                continue
            if comps and comps in self.mounts:
                raise Refused("H-C3", "the scope's path enters another mount, /%s"
                              % show(b"/".join(comps)))
            nxt = u.child(ent, c)
            if nxt is None:
                raise Refused("H-C3", "the scope's path does not exist: no /%s"
                              % show(b"/".join(comps + (c,))))
            self.scope_tainted |= nxt.tainted
            if stat.S_ISLNK(nxt.top.st.st_mode):
                links += 1
                if links > MAXLINKS:
                    raise Refused("H-C3", "more than %d links resolving the scope" % MAXLINKS)
                target = os.readlink(u.roots[nxt.top.layer] + nxt.top.path)
                if target == b"":
                    raise Refused("H-C3", "an empty link on the scope's path")
                if target.startswith(b"/"):
                    chain = chain[:1]
                todo = target.split(b"/") + todo
                continue
            chain.append((comps + (c,), nxt))
        comps, ent = chain[-1]
        if not ent.top.is_dir:
            raise Refused("H-C3", "the scope is not a directory")
        if comps in self.mounts:
            raise Refused("H-C3", "the scope is the mount point of another mount, /%s"
                          % show(b"/".join(comps)))
        return comps, ent

    def check_mounts(self, scope_comps):
        """H-M5: each mount point below the scope must be a path the union holds -- every
        component above it a directory, not a link (U17)."""
        u = self.u
        below = [m for m in self.mounts if is_below(m, scope_comps)]
        for m in sorted(below):
            if any(is_below(m, o) for o in below):
                continue            # inside another mount: never reached (U18)
            ent = u.root()
            for k, c in enumerate(m):
                if not ent.top.is_dir:
                    ent = None
                    break
                ent = u.child(ent, c)
                if ent is None:
                    break
            if ent is None:
                raise Refused("H-M5", "the mount point /%s is not a path of the union"
                              % show(b"/".join(m)))
        return set(below)

    def walk(self, content=False, explain=False):
        u = self.u
        scope_comps, scope_ent = self.resolve_scope()
        mounts = self.check_mounts(scope_comps)
        out = []
        todo = [((), scope_ent)]
        while todo:
            rel, ent = todo.pop()
            is_mount = bool(rel) and (scope_comps + rel) in mounts
            out.append((b"/".join(rel) if rel else b".", ent, is_mount))
            if not ent.top.is_dir or is_mount:
                continue
            names = set()
            for m in ent.members:
                names.update(u.listdir(m))
            for name in sorted(names):
                ch = u.child(ent, name)
                if ch is not None:
                    todo.append((rel + (name,), ch))
        out.sort(key=lambda t: t[0])
        recs = [self.record(p, e, mnt, content, explain) for p, e, mnt in out]
        if explain:
            for r in recs:
                if r.get("path") == ".":
                    r["scope"] = "/" + b"/".join(scope_comps).decode("utf-8", "surrogateescape")
                    r["scope_tainted"] = self.scope_tainted
        return recs

    def record(self, path, ent, is_mount, content, explain):
        u = self.u
        top = ent.top
        st = top.st
        full = u.roots[top.layer] + top.path
        r = {}
        put_bytes(r, "path", path)
        r["type"] = type_of(st)
        r["layer"] = top.layer
        put_bytes(r, "layer_path", top.path)
        r["mode"] = st.st_mode & 0o7777
        r["uid"] = st.st_uid
        r["gid"] = st.st_gid
        if r["type"] == "reg":
            r["size"] = st.st_size
        if r["type"] == "lnk":
            put_bytes(r, "target", os.readlink(full))
        # A mount point's entry is its stat fields (and a link's target) only: no xattrs, no
        # protattr, no content (H-M5, decision 212; U25).
        r["xattrs"] = {} if is_mount else {k: v.hex() for k, v in sorted(top.xattrs.items())
                                           if not k.startswith(u.prefix)}
        # H-U8 as the kernel honours it: the upper layer's protattr only (U15).
        pa = u.ovl(top, "protattr") if top.layer == 0 and not is_mount else None
        r["protattr"] = pa.decode("ascii") if pa is not None else ""
        r["mount"] = is_mount
        if content and r["type"] == "reg" and not is_mount:
            h = hashlib.sha256()
            with open(full, "rb") as f:
                for blk in iter(lambda: f.read(1 << 16), b""):
                    h.update(blk)
            r["sha256"] = h.hexdigest()
        if explain:
            r["tainted"] = ent.tainted
            r["members"] = [[m.layer, show(m.path)] for m in ent.members]
        return r


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--prefix", default="trusted.overlay.",
                    help="the overlay's xattr prefix: trusted.overlay. (Docker) or user.overlay.")
    ap.add_argument("--mount", action="append", default=[],
                    help="a mount point inside the container (absolute); repeatable")
    ap.add_argument("--content", action="store_true", help="add sha256 to reg entries")
    ap.add_argument("--explain", action="store_true",
                    help="add `tainted` and `members` (for run.sh, not the format)")
    ap.add_argument("scope")
    ap.add_argument("layers", nargs="+", help="layer directories, topmost first")
    a = ap.parse_args(argv)
    if a.prefix not in ("trusted.overlay.", "user.overlay."):
        ap.error("prefix must be trusted.overlay. or user.overlay.")
    scope = os.fsencode(a.scope)
    try:
        if not scope.startswith(b"/"):
            raise ValueError("the scope must be absolute")
        mounts = [norm_abs(os.fsencode(m), "mount point") for m in a.mount]
    except ValueError as e:
        ap.error(str(e))
    if any(m == [] for m in mounts):
        ap.error("/ is the overlay itself, not another mount")
    if len(a.layers) < 2:
        ap.error("an overlay has an upper layer and at least one lower one")
    model = Model(a.layers, a.prefix, scope, mounts)
    try:
        recs = model.walk(a.content, a.explain)
    except Refused as r:
        sys.stdout.write(json.dumps({"refused": r.row, "why": r.why}) + "\n")
        return 1
    w = sys.stdout.write
    for r in recs:
        w(json.dumps(r, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
