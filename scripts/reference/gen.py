#!/usr/bin/env python3
"""Deterministic corpus for the dpkg, pip and git reference (scripts/reference/).

A case is two trees, before and after, written as two manifest files (v1,
or v2 -- docs/spec/manifest-v2.md -- when a side excludes something or the
case asks for it) plus a store: copies at <store>/<first two hex of sha256>/<other 62>
(diff-v1, "Content"). Required cells are built by construction, one builder
each; random cases come from a seeded random.Random. Nothing here retries.

Each case says which modes it runs in ("store": belay_diff given the store;
"nostore": given none) and, per mode, the cells it was built to hit. git's
repositories are built by hand for E12's cells (cell_git_events, and
cell_git_unread for what git cannot read) and, in the
random cases, from a simulated history (random_git).
"""

import base64
import csv
import hashlib
import io
import json
import os
import random
import zlib

import ref

SCOPE = b"/srv/belay-ref"
DEV = 2049
HASH_MAX = 1 << 30          # header hash_max_bytes: every claimed copy here is hashable
UNVERIFIED_SIZE = (1 << 31) + 7
BIG = {"pip": [ref.PIP_BOUND + 1, ref.PIP_BOUND + 2],
       "dpkg": [ref.DPKG_BOUND + 1, ref.DPKG_BOUND + 2]}


# ---------------------------------------------------------------- entries

def reg(content=None, store="ok", big=None, gen=0, raced=False, mode=0o100644,
        unverified=False, mount=False):
    """A regular file. store: ok | none (no `stored` field) | absent (named,
    not in the store) | corrupt (the object holds other bytes) | symlink (a
    symlink to a good copy sits at the object's name). big: a sparse, zero
    copy of that size instead of `content`. unverified: no hash, no copy,
    larger than hash_max_bytes. mount: a mounted file (a bind mount), never
    read -- `unverified`, no hash or copy, its size that of `content`, on
    another device (manifest-v1, `mount`)."""
    return {"type": "reg", "content": content, "store": store, "big": big, "gen": gen,
            "raced": raced, "mode": mode, "unverified": unverified or mount, "mount": mount}


def unreadable_dir():
    """A directory belay could not list: nothing below it on that side, so a
    path that is there on the other side is unknown."""
    return {"type": "dir", "unreadable": True}


def unstable_dir():
    """A directory whose listing is not its listing at the end of the walk:
    a path missing below it on that side is unknown (listing_incomplete)."""
    return {"type": "dir", "unstable": True}


def mount_dir():
    """The root of another mount: never descended, nothing below it on that
    side (manifest-v1, `mount`)."""
    return {"type": "dir", "mount": True}


def lnk(target, gen=0):
    return {"type": "lnk", "target": target, "gen": gen, "mode": 0o120777, "raced": False}


class Case:
    def __init__(self, name, modes=("store",)):
        self.name = name
        self.before = {}
        self.after = {}
        self.modes = list(modes)
        self.tags = {m: set() for m in ("store", "nostore")}
        # manifest v2's `excluded`, per side: path -> reason; a side that
        # excludes anything is written as v2, and so is one named in `v2`
        self.excluded = {"before": {}, "after": {}}
        self.v2 = set()

    def tag(self, cell, mode=None):
        for m in ([mode] if mode else self.modes):
            self.tags[m].add(cell)

    def both(self, path, e):
        self.before[path] = e
        self.after[path] = e

    def put(self, side, path, e):
        (self.before if side == "before" else self.after)[path] = e

    def exclude(self, side, path, reason=b"user"):
        self.excluded[side][path] = reason

    def hide(self, side, path, how):
        """Makes `path` not captured on `side`, or its listing incomplete:
        how is unreadable | mount | excluded (everything at or below it
        dropped on that side) or unstable (everything below it dropped)."""
        tree = self.before if side == "before" else self.after
        for p in list(tree):
            if p == path or p.startswith(path + b"/"):
                del tree[p]
        for x in list(self.excluded[side]):
            if x == path or x.startswith(path + b"/"):
                del self.excluded[side][x]
        if how == "excluded":
            self.exclude(side, path)
        else:
            tree[path] = {"unreadable": unreadable_dir, "mount": mount_dir,
                          "unstable": unstable_dir}[how]()


# ---------------------------------------------------------------- writing

_zero_digests = {}


def zero_digest(n, cache_file):
    if n in _zero_digests:
        return _zero_digests[n]
    try:
        with open(cache_file) as f:
            _zero_digests.update({int(k): v for k, v in json.load(f).items()})
    except (OSError, ValueError):
        pass
    if n not in _zero_digests:
        h = hashlib.sha256()
        chunk = bytes(1 << 20)
        left = n
        while left:
            k = min(left, len(chunk))
            h.update(chunk[:k])
            left -= k
        _zero_digests[n] = h.hexdigest()
        tmp = cache_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump({str(k): v for k, v in _zero_digests.items()}, f)
        os.replace(tmp, cache_file)
    return _zero_digests[n]


def crc(*parts):
    return zlib.crc32(b"\0".join(p if isinstance(p, bytes) else str(p).encode() for p in parts))


def jkey(k, v):
    if isinstance(v, bool):
        assert v
        return b'"' + k.encode() + b'":true'
    if isinstance(v, int):
        return b'"' + k.encode() + b'":' + str(v).encode()
    return b'"' + k.encode() + b'":' + ref.jstr(v)


def path_field(p):
    if ref.utf8_ok(p):
        return jkey("path", p)
    return jkey("path_b64", base64.b64encode(p))


def complete(tree, excluded=()):
    """Adds every missing parent directory, and the root -- an excluded
    path's parents too: its name still counts in its parent's listing."""
    out = dict(tree)
    for p in list(tree) + list(excluded):
        parts = p.split(b"/")
        for i in range(1, len(parts)):
            d = b"/".join(parts[:i])
            out.setdefault(d, {"type": "dir"})
    out.setdefault(b".", {"type": "dir"})
    for x in excluded:
        # manifest-v2: "A reader rejects a manifest that records an entry at
        # or below one of its excluded paths."
        assert not any(p == x or p.startswith(x + b"/") for p in out), x
    return out


def entry_line(p, e, digest_of):
    t = e["type"]
    kv = [path_field(p), jkey("type", t)]
    if t == "dir":
        ino = 100 + crc(b"dir", p) % 1000000
        kv += [jkey("mode", 0o40755), jkey("uid", 0), jkey("gid", 0), jkey("size", 4096),
               jkey("mtime_ns", 1750000000000000000), jkey("ctime_ns", 1750000000000000000),
               jkey("ino", ino), jkey("dev", DEV + 1 if e.get("mount") else DEV),
               jkey("nlink", 2)]
        # manifest-v1's key order: ... unstable ... mount, unreadable
        for flag in ("unstable", "mount", "unreadable"):
            if e.get(flag):
                kv.append(jkey(flag, True))
        return b"{" + b",".join(kv) + b"}"
    if t == "lnk":
        size = len(e["target"])
        seed = crc(b"lnk", p, e["target"], e["gen"])
    else:
        if e.get("mount"):
            size = len(e["content"])
            sha = None
        elif e["unverified"]:
            size = UNVERIFIED_SIZE
            sha = None
        elif e["big"] is not None:
            size = e["big"]
            sha = digest_of(e)
        else:
            size = len(e["content"])
            sha = digest_of(e)
        seed = crc(b"reg", p, sha or b"", e["gen"])
    t_ns = 1760000000000000000 + (seed % 1000000) * 1000
    kv += [jkey("mode", e["mode"]), jkey("uid", 0), jkey("gid", 0), jkey("size", size),
           jkey("mtime_ns", t_ns), jkey("ctime_ns", t_ns), jkey("ino", 5000 + seed % 100000000),
           jkey("dev", DEV + 1 if e.get("mount") else DEV), jkey("nlink", 1)]
    if t == "reg":
        if sha is None:
            kv.append(jkey("unverified", True))
        else:
            kv.append(jkey("sha256", sha))
            if e["store"] != "none":
                kv.append(jkey("stored", sha))
    else:
        kv.append(jkey("link_target", e["target"]))
    if e.get("mount"):
        kv.append(jkey("mount", True))
    if e.get("raced"):
        kv.append(jkey("raced", True))
    return b"{" + b",".join(kv) + b"}"


def write_manifest(fn, tree, created_ns, digest_of, version=1, excluded=None):
    """excluded: {path: reason} (v2 only; manifest-v2.md V2-2)."""
    excluded = excluded or {}
    assert version == 2 or not excluded
    t = complete(tree, excluded)
    head = (b'{"belay_manifest":%d,"created_ns":%d,"scopes":[%s],"hash":"sha256",'
            b'"hash_max_bytes":%d,"store_max_bytes":65536'
            % (version, created_ns, ref.jstr(SCOPE), HASH_MAX))
    if version == 2:
        # V2-2: sorted by path bytes, each {"path", "reason", "dev", "ino"}
        xs = [b"{" + b",".join([path_field(x), jkey("reason", excluded[x]), jkey("dev", DEV),
                                jkey("ino", 900000 + crc(b"excluded", x) % 100000)]) + b"}"
              for x in sorted(excluded)]
        head += b',"excluded":[' + b",".join(xs) + b'],"walk_start_ns":%d' % (created_ns - 10**9)
    lines = [head + b"}"]
    for p in sorted(t):
        lines.append(entry_line(p, t[p], digest_of))

    def count(flag):
        return sum(1 for e in t.values() if e.get(flag))
    trailer = (b'{"belay_manifest_end":%d,"vanished":0,"unreadable":%d,"unstable":%d,'
               b'"mounts":%d,"raced":%d'
               % (len(t), count("unreadable"), count("unstable"), count("mount"), count("raced")))
    if version == 2:
        # V2-4..6: a full walk -- read_all "check", reference "none", trusted 0
        trailer += b',"trusted":0,"reference":"none","read_all":"check"'
    lines.append(trailer + b"}")
    with open(fn, "wb") as f:
        f.write(b"\n".join(lines) + b"\n")


def write_case(case, d, cache_file):
    """Writes before.ndjson, after.ndjson and store/ under `d`."""
    os.makedirs(d)
    store = os.path.join(d, "store")
    elsewhere = os.path.join(d, "elsewhere")
    os.makedirs(store)
    os.makedirs(elsewhere)

    def digest_of(e):
        if e["big"] is not None:
            return zero_digest(e["big"], cache_file)
        return hashlib.sha256(e["content"]).hexdigest()

    # One state per object: the first entry to name it decides (entries
    # visited in path order, before then after).
    states = {}
    for tree in (case.before, case.after):
        for p in sorted(tree):
            e = tree[p]
            if e["type"] != "reg" or e["unverified"]:
                continue
            states.setdefault(digest_of(e), e)
    for sha, e in sorted(states.items()):
        s = e["store"]
        if s in ("none", "absent"):
            continue
        fan = os.path.join(store, sha[:2])
        os.makedirs(fan, exist_ok=True)
        obj = os.path.join(fan, sha[2:])
        target = obj
        if s == "symlink":
            target = os.path.join(elsewhere, sha)
            os.symlink(target, obj)
        if e["big"] is not None:
            with open(target, "wb") as f:
                f.truncate(e["big"] + (1 if s == "corrupt" else 0))
        else:
            with open(target, "wb") as f:
                f.write(e["content"] + (b"#corrupt" if s == "corrupt" else b""))
    for side, tree, t in (("before", case.before, 1761000000000000000),
                          ("after", case.after, 1761000600000000000)):
        x = case.excluded[side]
        write_manifest(os.path.join(d, side + ".ndjson"), tree, t, digest_of,
                       2 if (x or side in case.v2) else 1, x)


# ---------------------------------------------------------------- dpkg content

PKGS = [b"libc6", b"bash", b"coreutils", b"python3.12", b"libssl3", b"zlib1g", b"tzdata",
        b"g++-13", b"libstdc++6", b"x11-common", b"apt", b"dpkg", b"libgcc-s1", b"perl-base"]
ARCHES = [b"amd64", b"i386", b"arm64", b"all"]
DEB_VERSIONS = [b"1.0-1", b"1.0-2", b"1:1.0-1", b"2.36-9+deb12u4", b"2.36-9+deb12u10",
                b"1.0~rc1-1", b"1.0+dfsg-1", b"0.9.8zh-1", b"10.0", b"9.99", b"1.2.3",
                b"1.2.3a", b"1.2.3~bpo1", b"2:0.1", b"1.0-1ubuntu1", b"1.0-1ubuntu1.1",
                b"3.0.0~alpha2-1", b"1.0.0", b"1.10-1", b"1.9-1", b"7.4p1-1~"]
INSTALLED = [b"install ok installed", b"hold ok installed", b"deinstall ok installed"]
NOT_INSTALLED = [b"deinstall ok config-files", b"purge ok not-installed", b"install ok unpacked",
                 b"install ok half-configured", b"install reinstreq half-installed",
                 b"install ok triggers-pending"]


def stanza(pkg, version, status=b"install ok installed", arch=b"amd64", nonce=0,
           desc_lines=1, conffiles=False, raw_fields=None):
    """One status stanza, fields in dpkg's order; arch b"" omits Architecture.
    raw_fields: a list of (name, value) replacing the generated ones."""
    if raw_fields is not None:
        lines = [n + b": " + v if v else n + b":" for n, v in raw_fields]
        return b"\n".join(lines) + b"\n"
    lines = [b"Package: " + pkg, b"Status: " + status, b"Priority: optional",
             b"Section: libs", b"Installed-Size: %d" % (100 + nonce % 9000),
             b"Maintainer: Reference Maintainers <ref-%d@example.org>" % nonce]
    if arch:
        lines.append(b"Architecture: " + arch)
    lines += [b"Multi-Arch: same", b"Version: " + version,
              b"Depends: libc6 (>= 2.34),\n libgcc-s1 (>= 3.0)"]
    lines.append(b"Description: the package " + pkg)
    for i in range(desc_lines):
        lines.append(b" line %d of the long description, nonce %d" % (i, nonce))
        if i % 2:
            lines.append(b" .")
    if conffiles:
        lines.append(b"Conffiles:\n /etc/" + pkg + b".conf 0123456789abcdef0123456789abcdef")
    return b"\n".join(lines) + b"\n"


def status_bytes(stanzas, sep=b"\n"):
    return b"".join(s + sep for s in stanzas)


SHORT_STATUS = [b"install ok", b"installed", b"hold installed", b""]


def rand_deb_version(rng, near=None):
    """A valid Debian version: from the pool, near another one, or random."""
    r = rng.random()
    if near is not None and r < 0.5:
        return near + rng.choice([b"~1", b"+b1", b"1", b"a", b".0", b"~", b"-1", b"+"])
    if r < 0.6:
        return rng.choice(DEB_VERSIONS)
    up = rng.choice("0123456789") + "".join(rng.choice("0123456789abzAZ.+~")
                                            for _ in range(rng.randrange(0, 6)))
    v = up
    if rng.random() < 0.6:
        if rng.random() < 0.2:
            v += "-" + rng.choice("0123456789") + "a"
        v += "-" + "".join(rng.choice("0123456789abz.+~") for _ in range(rng.randrange(1, 4)))
    if rng.random() < 0.2:
        v = str(rng.randrange(0, 3)) + ":" + v
    return v.encode()


def rand_status(rng):
    r = rng.random()
    if r < 0.65:
        return rng.choice(INSTALLED)
    if r < 0.93:
        return rng.choice(NOT_INSTALLED)
    return rng.choice(SHORT_STATUS)


def rand_stanza(rng):
    return {"pkg": rng.choice(PKGS), "arch": rng.choice(ARCHES + [b""]),
            "ver": rand_deb_version(rng), "status": rand_status(rng),
            "nonce": rng.randrange(1 << 30), "desc": rng.randrange(0, 4),
            "conf": rng.random() < 0.3}


def rand_stanzas(rng, n):
    """n stanzas; a key repeated now and then (the first counts)."""
    out = []
    used = set()
    for _ in range(n):
        st = rand_stanza(rng)
        if (st["pkg"], st["arch"]) in used and rng.random() < 0.85:
            continue
        used.add((st["pkg"], st["arch"]))
        out.append(st)
    return out


def render_db(db):
    return status_bytes([stanza(s["pkg"], s["ver"], s["status"], s["arch"], s["nonce"], s["desc"],
                                s["conf"]) for s in db])


def mutate_db(rng, db):
    db = [dict(s) for s in db]
    for _ in range(rng.randrange(1, 7)):
        op = rng.randrange(6)
        if op == 0 and db:                     # removed: stanza dropped or state changed
            i = rng.randrange(len(db))
            if rng.random() < 0.5:
                del db[i]
            else:
                db[i]["status"] = rng.choice(NOT_INSTALLED)
        elif op == 1:                          # installed, somewhere in the file
            db.insert(rng.randrange(len(db) + 1), rand_stanza(rng))
        elif op in (2, 3) and db:              # a new version
            st = db[rng.randrange(len(db))]
            st["ver"] = rand_deb_version(rng, near=st["ver"])
        elif op == 4 and db:                   # a state change
            db[rng.randrange(len(db))]["status"] = rand_status(rng)
        elif op == 5 and db:                   # nothing a package says (description)
            db[rng.randrange(len(db))]["nonce"] = rng.randrange(1 << 30)
    return db


# ---------------------------------------------------------------- pip content

SITES = [b"usr/lib/python3/dist-packages", b"usr/local/lib/python3.12/site-packages",
         b"venv/lib/python3.12/site-packages"]
NAMES = [b"requests", b"Flask_SQLAlchemy", b"zope.interface", b"PyYAML", b"typing_extensions",
         b"numpy", b"six", b"attrs", b"Jinja2", b"setuptools", b"wheel", b"charset_normalizer",
         "Ünicode_pkg".encode()]
PIP_VERSIONS = [b"1.0", b"1.0.0", b"1.0.1", b"2.31.0", b"1.0a1", b"1.0b2", b"1.0rc1",
                b"1.0.post1", b"1.0.dev3", b"1!0.5", b"2.0+local.1", b"0.9", b"v1.0", b"1.0_beta",
                b"2013x", b"abc", b"1.0.x", b"1.0-1", b"10.2", b"1.0.0a1"]


def rand_pep440(rng):
    """A version as a dist-info name might carry it: from the pool, built
    from PEP 440's parts in their alternative spellings, or not PEP 440."""
    if rng.random() < 0.3:
        return rng.choice(PIP_VERSIONS)
    s = rng.choice(["", "", "", "", "v", "V"])
    if rng.random() < 0.1:
        s += "%d!" % rng.randrange(0, 3)
    s += ".".join(str(rng.choice([0, 0, 1, 2, 10])) for _ in range(rng.randrange(1, 4)))
    sep = lambda: rng.choice(["", "", ".", "-", "_"])
    if rng.random() < 0.3:
        s += sep() + rng.choice(["a", "b", "c", "rc", "alpha", "beta", "pre", "preview", "A", "RC"])
        n = rng.choice(["", "0", "1", "2", "10"])
        # A separator after the letter only before a number: whether "1.0a."
        # is PEP 440 is a question of its own (probe.pip.pep440_trailing_separator).
        s += (sep() + n) if n else ""
    if rng.random() < 0.2:
        s += rng.choice(["-1", "-2", ".post1", "post", "_post2", ".rev1", "r3", "-r", ".POST0"])
    if rng.random() < 0.15:
        s += rng.choice([".dev0", "dev", "-dev1", "_dev2", ".DEV3"])
    if rng.random() < 0.1:
        s += "+" + rng.choice(["abc", "1", "abc.5", "5.abc", "ubuntu-1", "x_y", "ABC"])
    if rng.random() < 0.05:
        s += rng.choice(["x", "..", "-foo", "+", "!"])
    return s.encode()


def respell(rng, name):
    """Another spelling of a name that PEP 503 normalizes the same, often."""
    f = rng.randrange(5)
    if f == 0:
        return name.lower()
    if f == 1:
        return name.upper()
    if f == 2:
        return name.replace(b"_", b".").replace(b"-", b"_")
    if f == 3:
        return name.replace(b"_", b"__").replace(b".", b"._")
    return name


def b64hash(rng):
    return b"sha256=" + base64.urlsafe_b64encode(rng.randbytes(32)).rstrip(b"=")


def record_bytes(rows, term="\r\n"):
    s = io.StringIO()
    w = csv.writer(s, lineterminator=term)
    for r in rows:
        w.writerow([x.decode("utf-8") if isinstance(x, bytes) else x for x in r])
    return s.getvalue().encode("utf-8")


def rand_rows(rng, name, version, n=None):
    di = name + b"-" + version + b".dist-info"
    pkg = name.lower().replace(b".", b"_")
    rows = []
    for i in range(rng.randrange(1, 7) if n is None else n):
        fn = pkg + b"/mod%d.py" % rng.randrange(1000)
        if rng.random() < 0.05:
            fn = pkg + b"/odd, \"quoted\" %d.py" % i
        rows.append([fn, b64hash(rng), str(rng.randrange(1, 100000))])
    rows += [[di + b"/METADATA", b64hash(rng), str(rng.randrange(100, 9000))],
             [di + b"/WHEEL", b64hash(rng), "92"], [di + b"/RECORD", "", ""]]
    return rows


def mutate_rows(rng, rows):
    rows = [list(r) for r in rows]
    for _ in range(rng.randrange(1, 4)):
        op = rng.randrange(5)
        body = [r for r in rows if r[1]]
        if op == 0:
            rows.insert(0, [b"extra/new%d.py" % rng.randrange(10000), b64hash(rng), "17"])
        elif op == 1 and body:
            rows.remove(rng.choice(body))
        elif op == 2 and body:
            rng.choice(body)[1] = b64hash(rng)
        elif op == 3 and body:
            rng.choice(body)[2] = str(rng.randrange(1, 100000))
        elif op == 4 and body:
            r = rng.choice(body)
            rows.append([r[0], b64hash(rng), "1"])     # listed twice: the first row counts
    return rows


def join(*parts):
    return b"/".join(p for p in parts if p)


def dist(site, name, version):
    di = join(site, name + b"-" + version + b".dist-info")
    return di + b"/RECORD", di + b"/METADATA"


def put_dist(case, side, site, name, version, rows, gen=0, store="ok", term="\r\n",
             raced=False, raw=None):
    """A dist-info on one side. raced: its RECORD raced (outcome unknown).
    raw: the RECORD's bytes instead of `rows` rendered."""
    rec, meta = dist(site, name, version)
    data = raw if raw is not None else record_bytes(rows, term)
    case.put(side, rec, reg(data, store=store, gen=gen, raced=raced))
    case.put(side, meta, reg(b"Metadata-Version: 2.1\nName: " + name + b"\nVersion: " + version
                             + b"\n", gen=gen))
    if name:
        case.put(side, join(site, name.lower().replace(b".", b"_"), b"__init__.py"),
                 reg(b"# " + name + b" " + version + b"\n", store="none", gen=gen))


def both_dist(case, site, name, version, rows):
    rec, meta = dist(site, name, version)
    case.both(rec, reg(record_bytes(rows)))
    case.both(meta, reg(b"Name: " + name + b"\n"))


# ---------------------------------------------------------------- random cases

def random_case(rng, i):
    c = Case("random-%04d" % i, modes=("store", "nostore"))
    store_choices = ["ok"] * 12 + ["none", "absent", "corrupt", "symlink"]

    # dpkg: one or two roots
    roots = [b""] + ([b"chroot/bookworm/"] if rng.random() < 0.4 else [])
    if rng.random() < 0.05:
        roots.append(b"chroot/\xfe/")
    def odd(data):
        """Now and then, a status E9 or E10 applies to: a line that is no
        field (E10), a stanza with a NUL or non-UTF-8 value, or one whose
        event text is over 1,024 bytes (E9)."""
        r = rng.random()
        if r < 0.03:
            return data + b"not a field\n"
        if r < 0.05:
            return data + b"\n" + stanza(b"odd-" + rng.choice(PKGS), rng.choice([b"1\0", b"1\xff"]),
                                         rng.choice(INSTALLED + NOT_INSTALLED))
        if r < 0.07:
            return data + b"\n" + stanza(b"x" * rng.choice([600, 1025]), b"1." + b"0" * 500,
                                         rng.choice(INSTALLED))
        return data

    for root in roots:
        sp = root + b"var/lib/dpkg/status"
        db = rand_stanzas(rng, rng.randrange(0, 14))
        r = rng.random()
        if r < 0.1:
            c.put("before", sp, reg(odd(render_db(db)), store=rng.choice(store_choices),
                                    raced=rng.random() < 0.1))
        elif r < 0.2:
            c.put("after", sp, reg(odd(render_db(db)), store=rng.choice(store_choices),
                                   raced=rng.random() < 0.1))
        elif r < 0.25:
            c.both(sp, reg(render_db(db)))
        elif r < 0.28:
            c.put("before", sp, reg(render_db(db), store=rng.choice(store_choices)))
            c.put("after", sp, lnk(b"status-new"))
        else:
            c.put("before", sp, reg(render_db(db), store=rng.choice(store_choices)))
            c.put("after", sp, reg(odd(render_db(mutate_db(rng, db))), gen=1,
                                    store=rng.choice(store_choices),
                                    raced=rng.random() < 0.08))
        if rng.random() < 0.3:
            c.put("after", root + b"var/lib/dpkg/info/" + rng.choice(PKGS) + b".list",
                  reg(b"/usr/share/doc\n", gen=2))
        if rng.random() < 0.2:
            c.put("before", root + b"var/lib/dpkg/info/" + rng.choice(PKGS) + b".md5sums",
                  reg(b"0123456789abcdef0123456789abcdef  usr/bin/x\n"))

    # pip: a few distributions per site
    sites = rng.sample(SITES, rng.randrange(1, 3))
    if rng.random() < 0.05:
        sites.append(b"opt/\xfflib/site-packages")
    for site in sites:
        for name in rng.sample(NAMES, rng.randrange(1, 5)):
            v1, v2 = rand_pep440(rng), rand_pep440(rng)
            rows = rand_rows(rng, name, v1)
            term = rng.choice(["\r\n", "\n"])
            op = rng.randrange(12)
            st = rng.choice(store_choices)
            # P7: a RECORD that raced is unknown and still pairs
            rc = rng.random() < 0.1
            if op == 0:
                put_dist(c, "after", site, name, v1, rows, store=st, term=term, raced=rc)
            elif op == 1:
                put_dist(c, "before", site, name, v1, rows, store=st, term=term, raced=rc)
            elif op == 2 and v1 != v2:
                put_dist(c, "before", site, name, v1, rows, store=st, term=term,
                         raced=rng.random() < 0.1)
                spell = respell(rng, name)
                put_dist(c, "after", site, spell, v2, rand_rows(rng, spell, v2), gen=1,
                         store=rng.choice(store_choices), term=term, raced=rc)
                if rng.random() < 0.15:        # E10: a name added twice, removed once
                    spell2 = respell(rng, name)
                    v3 = rand_pep440(rng)
                    if (spell2, v3) != (spell, v2):
                        put_dist(c, "after", site, spell2, v3, rand_rows(rng, spell2, v3),
                                 gen=2, term=term)
            elif op == 3:
                put_dist(c, "before", site, name, v1, rows, store=st, term=term)
                after_rows = mutate_rows(rng, rows)
                raw = None
                if rng.random() < 0.05:        # E10: a row of other than three fields
                    raw = record_bytes(after_rows, term) + rng.choice(
                        [b"x.py,sha256=X\n", b"x.py,h,1,extra\n", b"\xff,,\n"])
                put_dist(c, "after", site, name, v1, after_rows, gen=1,
                         store=rng.choice(store_choices), term=term, raced=rc, raw=raw)
            elif op == 9:                      # E10: a dist-info that cannot be named
                side = rng.choice(["before", "after"])
                bad = rng.choice([name, name + b"-", b"-" + v1])
                c.put(side, join(site, bad + b".dist-info", b"RECORD"),
                      reg(record_bytes(rows, term), store=st, raced=rc))
            elif op == 4:                      # METADATA alone changes
                rec, meta = dist(site, name, v1)
                c.both(rec, reg(record_bytes(rows, term)))
                c.put("before", meta, reg(b"Name: " + name + b"\n"))
                c.put("after", meta, reg(b"Name: " + name + b"\nSummary: x\n", gen=1))
            elif op == 5:                      # a RECORD that raced: unknown on both
                rec, meta = dist(site, name, v1)   # sides, an uncounted reinstall
                if rng.random() < 0.2:         # ... or, unnamable, could_not_interpret
                    rec = join(site, rng.choice([name, name + b"-", b"-" + v1]) + b".dist-info",
                               b"RECORD")
                c.put("before", rec, reg(record_bytes(rows, term), store=st))
                c.put("after", rec, reg(record_bytes(mutate_rows(rng, rows), term), gen=1,
                                        raced=True, store=rng.choice(store_choices)))
            elif op == 6 and rng.random() < 0.3:   # RECORD replaced by a symlink
                rec, meta = dist(site, name, v1)
                c.put("before", rec, reg(record_bytes(rows, term), store=st))
                c.put("after", rec, lnk(b"RECORD.real"))
            elif op == 6:                      # mode only: metadata_only, nothing
                rec, meta = dist(site, name, v1)
                c.put("before", rec, reg(record_bytes(rows, term)))
                c.put("after", rec, reg(record_bytes(rows, term), mode=0o100600, gen=1))
            else:
                both_dist(c, site, name, v1, rows)
    # E11 and E2 mixed: now and then a directory one side could not look
    # into (unreadable, a mount, excluded: not_captured) or whose listing is
    # incomplete there (unstable: listing_incomplete), or a status excluded
    # alone; then the RECORDs and statuses on the other side below it are
    # unknown, and only those not captured derive nothing.
    if rng.random() < 0.3:
        hidden = {"before": [], "after": []}
        for _ in range(rng.randrange(1, 4)):
            side = rng.choice(["before", "after"])
            records = list(c.before) + list(c.after)
            dirs = (list(sites) + [r + b"var/lib/dpkg" for r in roots]
                    + [r.rstrip(b"/") for r in roots if r]
                    + sorted({p.rsplit(b"/", 1)[0] for p in records
                              if p.endswith(b".dist-info/RECORD")}))
            files = [r + b"var/lib/dpkg/status" for r in roots]
            if rng.random() < 0.15:
                path, how = rng.choice(files), "excluded"
            else:
                path = rng.choice(dirs)
                how = rng.choice(["unreadable", "mount", "excluded", "unstable"])
            # one hidden path never below another on its side
            if any(path == h or path.startswith(h + b"/") or h.startswith(path + b"/")
                   for h in hidden[side]):
                continue
            hidden[side].append(path)
            c.hide(side, path, how)
    for side in ("before", "after"):
        if rng.random() < 0.3:
            c.v2.add(side)
    if rng.random() < 0.4:
        random_reflog(rng, c)
    if rng.random() < 0.5:
        random_git(rng, c)
    c.tag("random")
    return c


# ---------------------------------------------------------------- git reflogs

REFLOG_HEAD = b"proj/.git/logs/HEAD"
REFLOG_MAIN = b"proj/.git/logs/refs/heads/main"
# operation: message; True when it is no git_reflog_move (a plain commit or a
# fast-forward)
REFLOG_MSGS = [(b"commit: fix the parser", True), (b"commit (initial): start", True),
               (b"merge topic: Fast-forward", True), (b"pull: Fast-forward", True),
               (b"checkout: moving from main to topic", False),
               (b"reset: moving to HEAD~1", False), (b"commit (amend): fix", False),
               (b"rebase (finish): returning to refs/heads/main", False),
               (b"branch: Created from HEAD", False), (b"cherry-pick: a fix", False),
               (b"merge topic: Merge made by the 'ort' strategy.", False)]


def oid(rng):
    return rng.randbytes(20).hex().encode()


def reflog_entry(old, new, msg, t):
    return (old + b" " + new + b" Ref Erence <ref@example.org> %d +0000\t" % (1761000000 + t)
            + msg + b"\n")


def rand_reflog(rng, n, last=None, t=0):
    """n entries continuing from `last` (an object id, or the zero id)."""
    old = last or b"0" * 40
    out = []
    for i in range(n):
        new = oid(rng)
        out.append(reflog_entry(old, new, rng.choice(REFLOG_MSGS)[0], t + i))
        old = new
    return b"".join(out), old


def reflog_of_size(size):
    """Plain commits, `size` bytes exactly; the entries it holds."""
    head = reflog_entry(b"0" * 40, b"1" * 40, b"commit: ", 0)
    body_len = len(head)
    n = size // body_len
    out = [reflog_entry(b"%040x" % i, b"%040x" % (i + 1), b"commit: ", i) for i in range(n - 1)]
    used = sum(len(x) for x in out)
    last = reflog_entry(b"%040x" % n, b"%040x" % (n + 1), b"commit: ", n)
    last = last[:-1] + b"x" * (size - used - len(last)) + b"\n"
    data = b"".join(out) + last
    assert len(data) == size
    return data, n


REFLOG_BIG = ref.REFLOG_BOUND + 1


def cell_git_reflog():
    out = []
    rng = random.Random(4242)
    L, M = REFLOG_HEAD, REFLOG_MAIN
    B = ref.REFLOG_BOUND
    small = lambda n=3: rand_reflog(rng, n)

    c = Case("git-reflog-appended")
    before, last = small(3)
    more = (reflog_entry(last, oid(rng), b"commit: x", 9) + reflog_entry(b"a" * 40, b"b" * 40,
            b"reset: moving to HEAD~1", 10) + reflog_entry(b"b" * 40, b"c" * 40,
            b"pull: Fast-forward", 11) + reflog_entry(b"c" * 40, b"d" * 40,
            b"checkout: moving from main to topic", 12))
    c.put("before", L, reg(before))
    c.put("after", L, reg(before + more, gen=1))
    c.put("before", M, reg(before))
    c.put("after", M, reg(before + reflog_entry(last, b"e" * 40, b"commit (amend): y", 13), gen=1))
    c.tag("git.reflog_appended")
    c.tag("git.reflog_move")
    c.tag("git.ref_name_refs")
    out.append(c)

    c = Case("git-reflog-rewritten")
    before, _ = small(4)
    c.put("before", L, reg(before))
    c.put("after", L, reg(before[:len(before) // 2] + b"\n" + small(2)[0], gen=1))
    # a prefix that ends inside a line of after
    c.put("before", M, reg(before[:-1]))
    c.put("after", M, reg(before + small(1)[0], gen=1))
    c.tag("git.reflog_rewritten")
    out.append(c)

    c = Case("git-reflog-added-removed")
    c.put("after", L, reg(small(5)[0]))
    # removed, no copy and over the bound: no copy is needed
    c.put("before", M, reg(None, big=REFLOG_BIG, store="none"))
    c.tag("git.reflog_added")
    c.tag("git.reflog_removed_no_copy")
    out.append(c)

    # read in full up to 16 MiB, whatever store_max_bytes (65,536 here) says
    c = Case("git-reflog-read-at-bound")
    data, _ = reflog_of_size(B)
    c.put("after", L, reg(data))
    before, last = rand_reflog(rng, 2000)
    c.put("before", M, reg(before))
    c.put("after", M, reg(before + rand_reflog(rng, 1500, last)[0], gen=1))
    c.tag("git.reflog_read_at_bound")
    c.tag("git.reflog_over_store_max_bytes")
    out.append(c)

    def cu(name, side, bad, mode="store"):
        """One reflog, modified: `bad` on `side`, a small stored copy on the
        other (a removed reflog needs no copy; an added one is random's)."""
        c = Case(name, modes=(mode,))
        good = reg(small(2)[0], gen=7)
        c.put("before", L, bad(0) if side in ("before", "both") else good)
        c.put("after", L, bad(1) if side in ("after", "both") else good)
        return c

    variants = {
        # recorded without a copy, larger than the bound: too_large
        "too_large_nostored": lambda w: reg(None, big=B + 1 + w, store="none", gen=w),
        "too_large_unverified": lambda w: reg(None, unverified=True, gen=w),
        # a copy larger than the bound: too_large, as for any interpreter
        "too_large_stored": lambda w: reg(None, big=B + 3 + w, gen=w),
        # no copy, at or under the bound: still missing
        "missing_nostored_at_bound": lambda w: reg(None, big=B - w, store="none", gen=w),
        "missing_nostored": lambda w: reg(small(2)[0], store="none", gen=w),
        "missing_absent": lambda w: reg(small(2)[0], store="absent", gen=w),
        "corrupt_content": lambda w: reg(small(2)[0], store="corrupt", gen=w),
    }
    for v, bad in variants.items():
        for side in ("before", "after", "both"):
            if v == "too_large_unverified" and side == "both":
                continue                # unverified on both sides: unknown
            c = cu("cu-git-%s-%s" % (v, side), side, bad)
            c.tag("cu.git.%s.%s" % (v, side))
            out.append(c)

    # no store: the no-copy reasons come before no_store
    c = cu("cu-git-too_large-before-no_store", "before", variants["too_large_nostored"],
           mode="nostore")
    c.tag("cu.git.too_large_before_no_store")
    out.append(c)
    c = cu("cu-git-missing-before-no_store", "before", variants["missing_nostored_at_bound"],
           mode="nostore")
    c.tag("cu.git.missing_before_no_store")
    out.append(c)
    return out


def random_reflog(rng, c):
    """Now and then, a reflog: appended, rewritten, added, removed; its copy
    on a side kept or not, the side's size under, at or over the bound."""
    p = rng.choice([REFLOG_HEAD, REFLOG_MAIN, b".git/logs/HEAD",
                    b"proj/sub/.git/logs/refs/remotes/origin/main"])
    store = lambda: rng.choice(["ok"] * 6 + ["none", "absent", "corrupt", "symlink"])
    B = ref.REFLOG_BOUND
    big = lambda w: reg(None, big=rng.choice([B - 1, B, B + 1, B + 9]), store="none", gen=w)
    rc = lambda: rng.random() < 0.05
    before, last = rand_reflog(rng, rng.randrange(1, 6))
    op = rng.randrange(8)
    if op == 0:                                  # appended
        c.put("before", p, reg(before, store=store(), raced=rc()))
        c.put("after", p, reg(before + rand_reflog(rng, rng.randrange(1, 9), last, 50)[0],
                              store=store(), gen=1, raced=rc()))
    elif op == 1:                                # rewritten
        c.put("before", p, reg(before, store=store()))
        c.put("after", p, reg(rand_reflog(rng, rng.randrange(1, 4))[0], store=store(), gen=1))
    elif op == 2:                                # added
        c.put("after", p, reg(before, store=store()))
    elif op == 3:                                # removed
        c.put("before", p, big(0) if rng.random() < 0.3 else reg(before, store=store()))
    elif op == 4:                                # one side big without a copy
        side = rng.choice(["before", "after"])
        c.put(side, p, big(0))
        c.put("after" if side == "before" else "before", p, reg(before, store=store(), gen=1))
    elif op == 5:                                # added, unverified
        c.put("after", p, reg(None, unverified=True))
    elif op == 6:                                # mode only: metadata_only, nothing
        c.put("before", p, reg(before))
        c.put("after", p, reg(before, mode=0o100600, gen=1))
    else:                                        # both big without a copy
        c.put("before", p, big(0))
        c.put("after", p, big(1))


# ---------------------------------------------------------------- git events (E12)

ZERO = b"0" * 40


def goid(label):
    """A deterministic object id for a label."""
    return hashlib.sha1(b"belay-ref " + (label if isinstance(label, bytes) else label.encode())
                        ).hexdigest().encode()


def glog(entries, t=0):
    """A reflog of (old, new, message) entries."""
    return b"".join(reflog_entry(o, n, m, t + i) for i, (o, n, m) in enumerate(entries))


def gpacked(refs, header=True, peeled=None):
    """packed-refs: refs a list of (refname, id) in the order given; peeled:
    {refname: id} written as `^id` after that ref's line."""
    out = [b"# pack-refs with: peeled fully-peeled sorted \n"] if header else []
    for name, oid in refs:
        out.append(oid + b" " + name + b"\n")
        if peeled and name in peeled:
            out.append(b"^" + peeled[name] + b"\n")
    return b"".join(out)


class GitRepo:
    """Files of one repository in a case: `root` is the work tree, its
    repository `root/.git` (E12's `repo`)."""

    def __init__(self, case, root=b"proj"):
        self.c = case
        self.repo = join(root, b".git")

    def p(self, rest):
        return self.repo + b"/" + rest

    def put(self, side, rest, data, **kw):
        kw.setdefault("gen", 1 if side == "after" else 0)
        self.c.put(side, self.p(rest), reg(data, **kw))

    def both(self, rest, data):
        self.c.both(self.p(rest), reg(data))

    def head(self, side, branch=None, oid=None, **kw):
        self.put(side, b"HEAD", (b"ref: refs/heads/" + branch + b"\n") if branch else oid + b"\n",
                 **kw)

    def ref(self, side, name, oid, **kw):
        """A loose ref: name is a branch, or a full name starting refs/."""
        full = name if name.startswith(b"refs/") else b"refs/heads/" + name
        self.put(side, full, oid + b"\n", **kw)

    def log(self, side, name, entries, **kw):
        """A reflog: name HEAD, a branch, or a full name starting refs/."""
        rest = b"logs/HEAD" if name == b"HEAD" else b"logs/" + (
            name if name.startswith(b"refs/") else b"refs/heads/" + name)
        self.put(side, rest, glog(entries), **kw)

    def packed(self, side, refs, **kw):
        self.put(side, b"packed-refs", gpacked([(n if n.startswith(b"refs/") else
                                                  b"refs/heads/" + n, o) for n, o in refs]), **kw)

    def unchanged(self, branch=b"main", oid=None, head=True):
        """A repository's unchanged files: HEAD on `branch`, its loose ref."""
        oid = oid or goid(b"unchanged " + self.repo + branch)
        if head:
            self.both(b"HEAD", b"ref: refs/heads/" + branch + b"\n")
        self.both(b"refs/heads/" + branch, oid + b"\n")
        self.both(b"logs/refs/heads/" + branch, glog([(ZERO, oid, b"commit (initial): start")]))
        return oid


def cell_git_events():
    """Required cells for git's repository-level events (diff-events E12),
    one builder each; run.py's check names what each must show."""
    out = []
    X, Y, Z, W, V, U = (goid(c) for c in "XYZWVU")

    # ---- created: absent before by the reflog's zeros
    c = Case("git-e12-created-reflog-zeros", modes=BOTH)
    g = GitRepo(c)
    m = g.unchanged()
    g.ref("after", b"topic", m)
    g.log("after", b"topic", [(ZERO, m, b"branch: Created from HEAD")])
    c.tag("git.e12.created.reflog_zeros", "store")
    c.tag("git.e12.nostore_cu_only", "nostore")
    out.append(c)

    # ---- created: absent before by packed-refs (a path of this diff); a
    # branch created as a packed line alone
    c = Case("git-e12-created-packed-absence")
    g = GitRepo(c)
    g.unchanged()
    g.packed("before", [(b"refs/tags/v1", X)])
    g.packed("after", [(b"refs/heads/rel", Z), (b"refs/tags/v1", X), (b"refs/tags/v2", Y)])
    g.ref("after", b"feat", W)
    c.tag("git.e12.created.packed_absence")
    c.tag("git.e12.created.packed_line")
    out.append(c)

    # ---- moved with no `from`: present after, no evidence of before
    c = Case("git-e12-moved-no-from")
    g = GitRepo(c, b"a")
    g.unchanged()
    g.ref("after", b"feat", W)
    # ... and a reflog rewritten: it gained nothing, so no before either, and
    # it is not listed ("a reflog only when its entries were used")
    g = GitRepo(c, b"b")
    g.unchanged()
    g.ref("after", b"feat", W)
    g.log("before", b"feat", [(ZERO, X, b"branch: Created from HEAD")])
    g.log("after", b"feat", [(ZERO, Y, b"branch: Created from HEAD"), (Y, W, b"commit: w")])
    # ... and before from the reflog's first gained entry (the branch was
    # packed and unchanged; a commit wrote its loose ref)
    g = GitRepo(c, b"c")
    g.unchanged()
    g.both(b"packed-refs", gpacked([(b"refs/heads/feat", X)]))
    g.ref("after", b"feat", Y)
    g.log("before", b"feat", [(ZERO, X, b"branch: Created from HEAD")])
    g.log("after", b"feat", [(ZERO, X, b"branch: Created from HEAD"), (X, Y, b"commit: y")])
    # ... and before from the reflog whose entries then do not lead to after:
    # moved from that value, the reflog listed -- its entries gave the `from`
    # (ref.reflog_before's READING)
    g = GitRepo(c, b"d")
    g.unchanged()
    g.ref("after", b"feat", Y)
    g.log("before", b"feat", [(ZERO, X, b"branch: Created from HEAD")])
    g.log("after", b"feat", [(ZERO, X, b"branch: Created from HEAD"), (X, V, b"commit: v")])
    c.tag("git.e12.moved.no_from")
    c.tag("git.e12.moved.no_from_reflog_rewritten")
    c.tag("git.e12.before_from_reflog")
    c.tag("git.e12.before_from_reflog_not_chaining")
    out.append(c)

    # ---- deleted
    c = Case("git-e12-deleted")
    g = GitRepo(c, b"a")            # loose removed, packed-refs not a path
    g.unchanged()
    g.ref("before", b"old", X)
    g.log("before", b"old", [(ZERO, X, b"branch: Created from HEAD")])
    g = GitRepo(c, b"b")            # loose removed, its packed line too
    g.unchanged()
    g.ref("before", b"old", X)
    g.packed("before", [(b"old", V), (b"refs/tags/v1", Y)])
    g.packed("after", [(b"refs/tags/v1", Y)])
    g = GitRepo(c, b"c")            # a packed branch deleted, no loose ref
    g.unchanged()
    g.packed("before", [(b"gone", X), (b"refs/tags/v1", Y)])
    g.packed("after", [(b"refs/tags/v1", Y)])
    g = GitRepo(c, b"d")            # pack-refs: the loose ref moves into packed-refs
    g.unchanged()
    g.ref("before", b"kept", X)
    g.packed("before", [(b"refs/tags/v1", Y)])
    g.packed("after", [(b"kept", X), (b"refs/tags/v1", Y)])
    c.tag("git.e12.deleted.loose")
    c.tag("git.e12.deleted.loose_and_packed")
    c.tag("git.e12.deleted.packed_only")
    c.tag("git.e12.pack_refs_nothing")
    out.append(c)

    # ---- renamed, ordered by `from`; HEAD follows the rename
    c = Case("git-e12-renamed")
    g = GitRepo(c)
    g.head("before", b"a-old")
    g.head("after", b"z-new")
    g.ref("before", b"a-old", X)
    g.ref("after", b"z-new", X)
    born = [(ZERO, Y, b"branch: Created from HEAD"), (Y, X, b"commit: x")]
    g.log("before", b"a-old", born)
    g.log("after", b"z-new", born + [(X, X, b"Branch: renamed refs/heads/a-old to refs/heads/z-new")])
    g.ref("before", b"m", Y)
    g.ref("after", b"m", Z)
    g.log("before", b"m", [(ZERO, Y, b"branch: Created from HEAD")])
    g.log("after", b"m", [(ZERO, Y, b"branch: Created from HEAD"), (Y, Z, b"commit: z")])
    c.tag("git.e12.renamed")
    out.append(c)

    # ---- a deletion and a creation at one commit, no rename said
    c = Case("git-e12-same-commit-not-renamed")
    g = GitRepo(c)
    g.unchanged()
    g.ref("before", b"one", X)
    g.ref("after", b"two", X)
    g.log("before", b"one", [(ZERO, X, b"branch: Created from HEAD")])
    g.log("after", b"two", [(ZERO, X, b"branch: Created from HEAD")])
    c.tag("git.e12.same_commit_not_renamed")
    out.append(c)

    # ---- commits added, counted and not
    def moved(g, br, frm, to, entries, before_entries=None):
        g.ref("before", br, frm)
        g.ref("after", br, to)
        old = before_entries if before_entries is not None else [(ZERO, frm, b"branch: Created")]
        g.log("before", br, old)
        g.log("after", br, old + entries)

    c = Case("git-e12-commits-added")
    g = GitRepo(c)
    g.unchanged()
    a, b2, d, e = goid("ca"), goid("cb"), goid("cd"), goid("ce")
    moved(g, b"counted", X, Z, [(X, a, b"commit: a"), (a, b2, b"cherry-pick: b"),
                                (b2, d, b"revert: \"b\""), (d, e, b"am: e"),
                                (e, Z, b"commit (merge): Merge branch 'x'")])
    moved(g, b"ff", X, Y, [(X, a, b"commit: a"), (a, Y, b"merge topic: Fast-forward")])
    moved(g, b"merge", X, Y, [(X, Y, b"merge topic: Merge made by the 'ort' strategy.")])
    moved(g, b"pull", X, Y, [(X, a, b"pull: Fast-forward"), (a, Y, b"pull origin main: Merge made")])
    c.tag("git.e12.commits_added.counted")
    c.tag("git.e12.commits_added.uncounted")
    out.append(c)

    # ---- each rewrite trigger; `how` each operation once, in order
    c = Case("git-e12-rewritten")
    g = GitRepo(c)
    g.unchanged()
    a, b2, d = goid("ra"), goid("rb"), goid("rd")
    triggers = {
        b"r-reset": [(X, Y, b"reset: moving to HEAD~1")],
        b"r-amend": [(X, Y, b"commit (amend): fix")],
        b"r-rebase": [(X, Y, b"rebase (finish): refs/heads/r-rebase onto " + Z)],
        b"r-rebase-i": [(X, a, b"commit: a"), (a, Y, b"rebase -i (finish): refs/heads/r-rebase-i onto " + Z)],
        b"r-pull-rebase": [(X, Y, b"pull --rebase (finish): refs/heads/r-pull-rebase onto " + Z)],
        b"r-branch-reset": [(X, Y, b"branch: Reset to " + Y)],
        b"r-forced": [(X, Y, b"update by push: forced-update")],
        b"r-mixed": [(X, a, b"commit: a"), (a, b2, b"reset: moving to HEAD~1"),
                     (b2, d, b"commit (amend): b"), (d, Y, b"reset: moving to " + Y)],
    }
    for br, entries in triggers.items():
        moved(g, br, X, Y, entries)
    c.tag("git.e12.rewritten.reset")
    c.tag("git.e12.rewritten.amend")
    c.tag("git.e12.rewritten.rebase")
    c.tag("git.e12.rewritten.branch_reset")
    c.tag("git.e12.rewritten.forced_update")
    c.tag("git.e12.rewritten.how_each_once")
    out.append(c)

    # ---- moved: entries that do not lead from before to after, another
    # operation, no reflog, a reflog rewritten
    c = Case("git-e12-moved")
    g = GitRepo(c)
    g.unchanged()
    a = goid("na")
    moved(g, b"n-first", X, Y, [(W, Y, b"commit: y")])
    moved(g, b"n-gap", X, Y, [(X, a, b"commit: a"), (W, Y, b"commit: y")])
    moved(g, b"n-last", X, Y, [(X, a, b"commit: a")])
    moved(g, b"n-other", X, Y, [(X, a, b"commit: a"), (a, Y, b"checkout: moving from a to b")])
    g.ref("before", b"n-none", X)
    g.ref("after", b"n-none", Y)
    g.ref("before", b"n-rewritten", X)
    g.ref("after", b"n-rewritten", Y)
    g.log("before", b"n-rewritten", [(ZERO, X, b"branch: Created"), (X, X, b"commit: q")])
    g.log("after", b"n-rewritten", [(ZERO, X, b"branch: Created"), (X, Y, b"commit: y")])
    c.tag("git.e12.not_chaining.first")
    c.tag("git.e12.not_chaining.gap")
    c.tag("git.e12.not_chaining.last")
    c.tag("git.e12.other_operation")
    c.tag("git.e12.moved.no_reflog")
    c.tag("git.e12.moved.reflog_rewritten")
    out.append(c)

    # ---- HEAD: switched, detached, attached; the detached branch HEAD
    c = Case("git-e12-head")
    g = GitRepo(c, b"h1")           # switched; a branch named below `HEAD`
    g.head("before", b"main")       # bytewise still comes after it
    g.head("after", b"topic")
    g.ref("after", b"A", X)
    g.log("after", b"A", [(ZERO, X, b"branch: Created from HEAD")])
    g = GitRepo(c, b"h2")
    g.head("before", b"main")
    g.head("after", oid=X)
    g = GitRepo(c, b"h3")
    g.head("before", oid=X)
    g.head("after", b"main")
    g = GitRepo(c, b"h4")
    g.head("before", oid=X)
    g.head("after", oid=Y)
    g.log("before", b"HEAD", [(ZERO, X, b"commit (initial): x")])
    g.log("after", b"HEAD", [(ZERO, X, b"commit (initial): x"), (X, Y, b"commit: y")])
    g = GitRepo(c, b"h5")
    g.head("before", oid=X)
    g.head("after", oid=Y)
    g.log("before", b"HEAD", [(ZERO, X, b"commit (initial): x")])
    g.log("after", b"HEAD", [(ZERO, X, b"commit (initial): x"),
                             (X, Y, b"checkout: moving from " + X + b" to " + Y)])
    g = GitRepo(c, b"h6")
    g.head("before", oid=X)
    g.head("after", oid=Y)
    g.log("before", b"HEAD", [(ZERO, X, b"commit (initial): x")])
    g.log("after", b"HEAD", [(ZERO, X, b"commit (initial): x"), (X, Y, b"reset: moving to " + Y)])
    g = GitRepo(c, b"h7")
    g.head("before", oid=X)
    g.head("after", oid=Y)
    c.tag("git.e12.head.switch")
    c.tag("git.e12.head.detach")
    c.tag("git.e12.head.attach")
    c.tag("git.e12.head.detached_commits")
    c.tag("git.e12.head.detached_moved")
    c.tag("git.e12.head.detached_rewritten")
    c.tag("git.e12.head.detached_no_reflog")
    c.tag("git.e12.order.head_first")
    out.append(c)

    # ---- a repository made: HEAD added switches nothing; main created
    c = Case("git-e12-new-repo")
    g = GitRepo(c)
    g.head("after", b"main")
    g.ref("after", b"main", X)
    g.log("after", b"main", [(ZERO, X, b"commit (initial): start")])
    g.log("after", b"HEAD", [(ZERO, X, b"commit (initial): start")])
    c.tag("git.e12.head.added_no_switch")
    out.append(c)

    # ---- `git checkout -b topic` and a commit on it
    c = Case("git-e12-checkout-b")
    g = GitRepo(c)
    g.head("before", b"main")
    g.head("after", b"topic")
    g.both(b"refs/heads/main", X + b"\n")
    g.ref("after", b"topic", Y)
    g.log("after", b"topic", [(ZERO, X, b"branch: Created from HEAD"), (X, Y, b"commit: y")])
    hl = [(ZERO, X, b"commit (initial): x")]
    g.log("before", b"HEAD", hl)
    g.log("after", b"HEAD", hl + [(X, X, b"checkout: moving from main to topic"),
                                  (X, Y, b"commit: y")])
    c.tag("git.e12.checkout_b")
    out.append(c)

    # ---- nested repositories, ordered by repo; branch names bytewise
    c = Case("git-e12-nested")
    for root in (b"proj", b"a/vendor/lib", b"a", b"", b"a-b"):
        g = GitRepo(c, root)
        g.unchanged(oid=X)
        for br in (b"z", b"a/b", b"a-b"):
            g.ref("after", br, Y)
            g.log("after", br, [(ZERO, Y, b"branch: Created from HEAD")])
    c.tag("git.e12.nested")
    c.tag("git.e12.branch_order")
    out.append(c)

    # ---- an unknown ref, read where its copy can be: provisional
    c = Case("git-e12-unknown-with-copy", modes=BOTH)
    g = GitRepo(c)
    g.unchanged()
    g.ref("before", b"main2", X)
    g.ref("after", b"main2", Y, raced=True)
    g.log("before", b"main2", [(ZERO, X, b"branch: Created")])
    g.log("after", b"main2", [(ZERO, X, b"branch: Created"), (X, Y, b"commit: y")])
    g.ref("before", b"dev", X)                       # its reflog raced
    g.ref("after", b"dev", Z)
    g.log("before", b"dev", [(ZERO, X, b"branch: Created")])
    g.log("after", b"dev", [(ZERO, X, b"branch: Created"), (X, Z, b"reset: moving to " + Z)],
          raced=True)
    g.ref("before", b"plain", X)                     # nothing unknown: not provisional
    g.ref("after", b"plain", W)
    c.tag("git.e12.unknown.with_copy", "store")
    c.tag("git.e12.unknown.reflog", "store")
    c.tag("git.e12.unknown.no_store", "nostore")
    out.append(c)

    c = Case("git-e12-unknown-no-copy")
    g = GitRepo(c)
    g.unchanged()
    g.ref("before", b"main2", X)
    g.ref("after", b"main2", Y, raced=True, store="none")
    g.ref("before", b"plain", X)
    g.ref("after", b"plain", W)
    c.tag("git.e12.unknown.no_copy")
    out.append(c)

    # ---- refs that cannot be parsed: could_not_interpret (E10), and "A side
    # git cannot parse counts as one it cannot read" (decision 141): per
    # side, as a side not read (decision 137); the rest stand
    c = Case("git-e12-unparseable")
    g = GitRepo(c, b"r")            # parsed before, not after: no event
    g.unchanged()
    g.ref("before", b"bad", X)
    g.put("after", b"refs/heads/bad", b"not an object id\n")
    g.ref("before", b"good", X)
    g.ref("after", b"good", Y)
    g = GitRepo(c, b"p")            # packed-refs parsed before, not after
    g.unchanged()
    g.packed("before", [(b"refs/heads/dated-by-packed", X), (b"refs/heads/only-before", X),
                        (b"refs/tags/v1", X)])
    g.put("after", b"packed-refs", gpacked([(b"refs/tags/v1", X)]) + b"this is no ref line\n")
    g.ref("after", b"needs-packed", Y)              # absent before by packed-refs: created
    g.ref("after", b"dated-by-packed", Y)           # before from packed-refs: moved, `from`
    g.ref("before", b"needs-after", X)              # its after is packed-refs': no event
    # (`only-before`, only in packed-refs, parsed before only: no value
    # after, no event)
    g.ref("before", b"loose-both", X)               # both sides loose: stands
    g.ref("after", b"loose-both", Y)
    g = GitRepo(c, b"q")            # HEAD parsed before, not after: none
    g.head("before", b"main")
    g.put("after", b"HEAD", b"\xff\xfe not a HEAD\n")
    g.both(b"refs/heads/main", X + b"\n")
    g = GitRepo(c, b"q2")           # HEAD not parsed before, detached after: none
    g.put("before", b"HEAD", b"not a HEAD before\n")
    g.head("after", oid=Y)
    g.both(b"refs/heads/main", X + b"\n")
    # a loose ref that cannot be parsed before only: no value before, no
    # reflog -- "now at", and its E10 event
    g = GitRepo(c, b"s")
    g.unchanged()
    g.put("before", b"refs/heads/bad-before", b"not an object id either\n")
    g.ref("after", b"bad-before", Y)
    # ... and its outcome unknown (raced after): read where its copy can be,
    # both events provisional, its record no finding
    g = GitRepo(c, b"u")
    g.unchanged()
    g.put("before", b"refs/heads/raced", b"no id, and raced after\n")
    g.ref("after", b"raced", Z, raced=True)
    c.tag("git.e12.unparseable_ref")
    c.tag("git.e12.unparseable_packed")
    c.tag("git.e12.unparseable_head")
    c.tag("git.e12.unparseable_head_before")
    c.tag("git.e12.unparseable_ref_before")
    c.tag("git.e12.unparseable_ref_before_unknown")
    out.append(c)

    # ---- tags and remote-tracking refs derive nothing (path findings stand)
    c = Case("git-e12-tags-remotes")
    g = GitRepo(c)
    g.unchanged()
    g.ref("after", b"refs/tags/v2", Y)
    g.ref("before", b"refs/tags/v0", W)
    g.ref("before", b"refs/remotes/origin/main", X)
    g.ref("after", b"refs/remotes/origin/main", Y)
    g.log("before", b"refs/remotes/origin/main", [(ZERO, X, b"fetch: storing head")])
    g.log("after", b"refs/remotes/origin/main", [(ZERO, X, b"fetch: storing head"),
                                                  (X, Y, b"fetch: forced-update")])
    g.put("before", b"packed-refs", gpacked([(b"refs/remotes/origin/dev", X),
                                            (b"refs/tags/v1", Z)], peeled={b"refs/tags/v1": X}))
    g.put("after", b"packed-refs", gpacked([(b"refs/remotes/origin/dev", Y), (b"refs/tags/v1", W),
                                           (b"refs/tags/v3", U)], peeled={b"refs/tags/v1": Y}))
    c.tag("git.e12.tags_remotes_nothing")
    out.append(c)

    # ---- what git cannot read reduces the claim, never the fact (decision
    # 137): "a ref or `packed-refs` that cannot be read on a side gives no
    # value there"
    c = Case("git-e12-cu")
    g = GitRepo(c, b"r")
    g.unchanged()
    # its before cannot be read (bytes no other entry has: one state per
    # object), no reflog: moved, no `from`
    g.ref("before", b"lost", goid("lost"), store="absent")
    g.ref("after", b"lost", Y)
    g.ref("before", b"fine", X)
    g.ref("after", b"fine", Y)
    g = GitRepo(c, b"p")
    g.unchanged()
    g.packed("before", [(b"refs/tags/v1", X)])
    g.packed("after", [(b"refs/tags/v1", Y)], store="corrupt")
    g.ref("after", b"needs-packed", Y)              # packed-refs before, read: created
    g.ref("before", b"loose-both", X)               # does not need it: stands
    g.ref("after", b"loose-both", Y)
    c.tag("git.e12.cu.ref")
    c.tag("git.e12.cu.packed")
    out.append(c)

    # ... and a reflog it cannot read to say how a branch moved: "no
    # evidence -- the move still comes from the refs, as `git_branch_moved`,
    # without a how"
    c = Case("git-e12-cu-reflog")
    g = GitRepo(c)
    g.unchanged()
    moved(g, b"dev", X, Y, [(X, Y, b"commit: y")])
    c.before[g.p(b"logs/refs/heads/dev")]["store"] = "corrupt"
    c.tag("git.e12.cu.reflog_classify")
    out.append(c)

    # ---- E11: refs not captured on one side derive nothing
    c = Case("git-e12-e11", modes=BOTH)
    g = GitRepo(c)
    g.unchanged()
    g.ref("after", b"hidden", X)
    g.log("after", b"hidden", [(ZERO, X, b"branch: Created from HEAD")])
    c.hide("before", g.p(b"refs/heads"), "unreadable")
    c.hide("before", g.p(b"logs"), "unreadable")
    g2 = GitRepo(c, b"other")
    g2.unchanged()
    g2.ref("after", b"seen", Y)
    g2.log("after", b"seen", [(ZERO, Y, b"branch: Created from HEAD")])
    c.tag("git.e12.e11", "store")
    c.tag("git.e12.e11_nostore", "nostore")
    out.append(c)

    # ---- E9: a branch whose name is not UTF-8
    c = Case("git-e12-e9-not-utf8", modes=BOTH)
    g = GitRepo(c)
    g.unchanged()
    g.ref("after", b"caf\xe9", X)
    g.log("after", b"caf\xe9", [(ZERO, X, b"branch: Created from HEAD")])
    g.ref("after", b"ok", Y)
    g.log("after", b"ok", [(ZERO, Y, b"branch: Created from HEAD")])
    c.tag("git.e12.e9_branch_not_utf8", "store")
    c.tag("git.e12.e9_nostore", "nostore")
    out.append(c)

    # ---- a tag and a remote-tracking ref that cannot be parsed: E10 (diff-v1,
    # "pip, dpkg and git emit one `could_not_interpret` event naming it") is
    # about any file git claims; they derive no event otherwise
    c = Case("git-e12-unparseable-tag-remote")
    g = GitRepo(c)
    g.unchanged()
    g.ref("before", b"refs/tags/v1", X)
    g.put("after", b"refs/tags/v1", b"no tag here\n")
    g.ref("before", b"refs/remotes/origin/main", X)
    g.put("after", b"refs/remotes/origin/main", b"no remote here\n")
    g.ref("before", b"dev", X)
    g.ref("after", b"dev", Y)
    c.tag("git.e12.unparseable_tag_remote")
    out.append(c)

    # ---- copies git cannot read that it derives no event from: a tag, a
    # remote-tracking ref and its reflog (Content: "git names only the paths
    # it derives events from"), and a removed reflog ("a reflog removed needs
    # no copy"): their records say so, no event names them
    c = Case("git-e12-cu-not-named", modes=BOTH)
    g = GitRepo(c)
    g.unchanged()
    g.ref("before", b"refs/tags/v1", goid("t-before"), store="absent")
    g.ref("after", b"refs/tags/v1", goid("t-after"))
    g.ref("before", b"refs/remotes/origin/main", goid("r-before"))
    g.ref("after", b"refs/remotes/origin/main", goid("r-after"), store="corrupt")
    g.log("before", b"refs/remotes/origin/main", [(ZERO, goid("r-before"), b"fetch: x")])
    g.log("after", b"refs/remotes/origin/main", [(ZERO, goid("r-before"), b"fetch: x"),
                                                  (goid("r-before"), goid("r-after"), b"fetch: y")],
          store="none")
    g.ref("before", b"gone", goid("gone"))
    g.log("before", b"gone", [(ZERO, goid("gone"), b"branch: Created from HEAD")], store="absent")
    c.tag("git.e12.cu_not_named", "store")
    c.tag("git.e12.cu_not_named_nostore", "nostore")
    out.append(c)

    # ---- a loose ref replaced by a directory: `a` deleted, `a/b` appears
    c = Case("git-e12-ref-type-changed")
    g = GitRepo(c)
    g.unchanged()
    g.ref("before", b"a", X)
    g.ref("after", b"a/b", Y)
    c.tag("git.e12.ref_type_changed")
    out.append(c)
    return out


def cell_git_unread():
    """Required cells for what git cannot read (E12, decision 137): "What git
    cannot read reduces what is claimed, never the fact the refs give". Each
    copy that cannot be read holds bytes no other entry has (one state per
    object)."""
    out = []
    X, Y, Z, W, V = (goid(c) for c in "XYZWV")

    # ---- a loose ref that cannot be read before
    c = Case("git-e12-unread-ref")
    g = GitRepo(c, b"a")            # the reflog's evidence dates it
    g.unchanged()
    g.ref("before", b"dated", goid("unread a"), store="absent")
    g.ref("after", b"dated", Y)
    g.log("before", b"dated", [(ZERO, X, b"branch: Created from HEAD")])
    g.log("after", b"dated", [(ZERO, X, b"branch: Created from HEAD"), (X, Y, b"commit: y")])
    g = GitRepo(c, b"b")            # its reflog starts from zeros: never absent
    g.unchanged()
    g.ref("before", b"zeros", goid("unread b"), store="corrupt")
    g.ref("after", b"zeros", Y)
    g.log("after", b"zeros", [(ZERO, Y, b"branch: Created from HEAD")])
    g = GitRepo(c, b"c")            # removed after, no evidence: no event
    g.unchanged()
    g.ref("before", b"gone", goid("unread c"), store="absent")
    c.tag("git.e12.unread.ref_before_dated")
    c.tag("git.e12.unread.ref_before_reflog_zeros")
    c.tag("git.e12.unread.ref_before_removed")
    out.append(c)

    # ---- packed-refs that cannot be read before, read after
    c = Case("git-e12-unread-packed-before")
    g = GitRepo(c)
    g.unchanged()
    g.put("before", b"packed-refs", gpacked([(b"refs/heads/kept", X), (b"refs/heads/old-packed", X),
                                            (b"refs/tags/v1", goid("unread packed"))]),
          store="absent")
    # `kept`, only in packed-refs, read after only: moved, no `from` ("a
    # branch only in `packed-refs` too"); `old-packed`, in the side not read,
    # is named by nothing
    g.packed("after", [(b"kept", X), (b"later", Z), (b"refs/tags/v1", X)])
    g.ref("after", b"new-dated", Y)                 # the reflog's zeros: created
    g.log("after", b"new-dated", [(ZERO, Y, b"branch: Created from HEAD")])
    g.ref("after", b"moved-dated", Y)               # the reflog's old id: dated
    g.log("before", b"moved-dated", [(ZERO, X, b"branch: Created from HEAD")])
    g.log("after", b"moved-dated", [(ZERO, X, b"branch: Created from HEAD"), (X, Y, b"commit: y")])
    g.ref("after", b"undated", W)                   # no evidence: moved, no `from`
    g.ref("before", b"later", X)                    # loose before, packed after: read
    g.ref("before", b"gone", X)                     # loose before, not packed after: deleted
    c.tag("git.e12.unread.packed_before_only_packed")
    c.tag("git.e12.unread.packed_before_reflog_absent")
    c.tag("git.e12.unread.packed_before_reflog_value")
    c.tag("git.e12.unread.packed_before_no_evidence")
    c.tag("git.e12.unread.packed_after_side_used")
    out.append(c)

    # ---- packed-refs read before, that cannot be read after
    c = Case("git-e12-unread-packed-after")
    g = GitRepo(c)
    g.unchanged()
    g.packed("before", [(b"only-before", X), (b"dated-by-packed", X), (b"refs/tags/v1", X)])
    g.put("after", b"packed-refs", gpacked([(b"refs/tags/v1", goid("unread packed after"))]),
          store="corrupt")
    g.ref("before", b"needs-after", X)              # its after is packed-refs': no event
    # (`only-before`, only in packed-refs, read before only: no value after,
    # no event)
    g.ref("after", b"dated-by-packed", Y)           # before from packed-refs, read
    g.ref("after", b"created", Y)                   # absent before by packed-refs, read
    c.tag("git.e12.unread.packed_after_no_event")
    c.tag("git.e12.unread.packed_before_side_used")
    out.append(c)

    # ---- a rename whose deletion takes its absence after from packed-refs,
    # which cannot be read before: the event uses that value
    c = Case("git-e12-unread-packed-renamed")
    g = GitRepo(c)
    g.unchanged()
    born = [(ZERO, X, b"branch: Created from HEAD")]
    g.ref("before", b"old", X)
    g.ref("after", b"new", X)
    g.log("before", b"old", born)
    g.log("after", b"new", born + [(X, X, b"Branch: renamed refs/heads/old to refs/heads/new")])
    g.put("before", b"packed-refs", gpacked([(b"refs/tags/v1", goid("unread packed renamed"))]),
          store="absent")
    g.packed("after", [(b"refs/tags/v1", Z)])
    c.tag("git.e12.unread.packed_before_renamed")
    out.append(c)

    # ---- a reflog that cannot be read is no evidence
    c = Case("git-e12-unread-reflog")
    g = GitRepo(c, b"a")            # it alone would date the branch
    g.unchanged()
    g.ref("after", b"alone", Y)
    g.log("before", b"alone", [(ZERO, goid("unread log a"), b"branch: Created from HEAD")],
          store="corrupt")
    g.log("after", b"alone", [(ZERO, goid("unread log a"), b"branch: Created from HEAD"),
                              (goid("unread log a"), Y, b"commit: y")])
    g = GitRepo(c, b"b")            # it would say a rename: created and deleted stand
    g.unchanged()
    g.packed("before", [(b"refs/tags/v1", X)])
    g.packed("after", [(b"refs/tags/v1", X), (b"refs/tags/v2", Y)])
    g.ref("before", b"old", X)
    g.ref("after", b"new", X)
    g.log("before", b"old", [(ZERO, X, b"branch: Created from HEAD")])
    g.log("after", b"new", [(ZERO, X, b"branch: Created from HEAD"),
                            (X, X, b"Branch: renamed refs/heads/old to refs/heads/new")],
          store="absent")
    g = GitRepo(c, b"h")            # HEAD detached: the branch `HEAD`, without a how
    g.head("before", oid=X)
    g.head("after", oid=Y)
    g.log("before", b"HEAD", [(ZERO, X, b"commit (initial): x")])
    g.log("after", b"HEAD", [(ZERO, X, b"commit (initial): x"), (X, Y, b"reset: moving to y")],
          store="corrupt")
    c.tag("git.e12.unread.reflog_would_date")
    c.tag("git.e12.unread.reflog_rename_untold")
    c.tag("git.e12.unread.reflog_head_detached")
    out.append(c)

    # ---- HEAD that cannot be read on a side: neither a switch nor the
    # branch `HEAD` can be told (ref.git_events' READING)
    c = Case("git-e12-unread-head")
    g = GitRepo(c, b"a")
    g.put("before", b"HEAD", b"ref: refs/heads/unread-a\n", store="absent")
    g.head("after", b"topic")
    g.both(b"refs/heads/main", X + b"\n")
    g = GitRepo(c, b"b")
    g.head("before", b"main")
    g.put("after", b"HEAD", b"ref: refs/heads/unread-b\n", store="corrupt")
    g.both(b"refs/heads/main", X + b"\n")
    g = GitRepo(c, b"c")
    g.put("before", b"HEAD", goid("unread head c") + b"\n", store="absent")
    g.head("after", oid=Y)
    g.both(b"refs/heads/main", X + b"\n")
    c.tag("git.e12.unread.head")
    out.append(c)

    # ---- a file that cannot be read on one side and cannot be parsed on the
    # other: its record says what could not be read. A branch ref, HEAD or
    # packed-refs is read on the side it can be (E12's value there), so E10
    # names it; a tag or remote-tracking ref is not (nothing needs that
    # side: ref.git_read's READING), so no E10 event -- nor for one whose
    # outcome is unknown (raced), which nothing needs either
    c = Case("git-e12-unread-and-unparseable")
    g = GitRepo(c)
    g.unchanged()
    g.ref("before", b"bad", goid("unread bad"), store="absent")
    g.put("after", b"refs/heads/bad", b"garbage, not an id\n")
    g.ref("before", b"good", X)
    g.ref("after", b"good", Y)
    g.ref("before", b"refs/tags/t", goid("unread tag"), store="absent")
    g.put("after", b"refs/tags/t", b"no tag here\n")
    g.put("before", b"refs/remotes/origin/main", b"no remote here\n")
    g.ref("after", b"refs/remotes/origin/main", goid("unread remote"), store="corrupt")
    g.put("after", b"refs/tags/raced", b"a raced tag, no id\n", raced=True)
    g.ref("before", b"refs/remotes/origin/raced", X)
    g.put("after", b"refs/remotes/origin/raced", b"a raced remote, no id\n", raced=True)
    g = GitRepo(c, b"h")
    g.put("before", b"HEAD", b"ref: refs/heads/unread-h\n", store="absent")
    g.put("after", b"HEAD", b"no HEAD here\n")
    g.both(b"refs/heads/main", X + b"\n")
    g = GitRepo(c, b"k")
    g.unchanged()
    g.put("before", b"packed-refs", b"no packed line\n")
    g.packed("after", [(b"refs/tags/k", goid("unread packed k"))], store="corrupt")
    g.ref("after", b"nb", Y)                        # no value before: moved, no `from`
    c.tag("git.e12.unread.and_unparseable")
    c.tag("git.e12.unread.and_unparseable_tag_remote")
    out.append(c)
    return out


def cell_git_unparsed():
    """Required cells for a side git cannot parse (E12, decision 141): "A
    side git cannot parse counts as one it cannot read (and is a
    `could_not_interpret` event, E10). A branch removed whose value before
    cannot be told derives no event (`git_branch_deleted` needs `was`)" --
    the cells of cell_git_unread, a side not parsed in place of one not
    read, and removals with no value before."""
    out = []
    X, Y, Z, W = (goid(c) for c in "XYZW")

    # ---- a loose ref that cannot be parsed before
    c = Case("git-e12-unparsed-ref")
    g = GitRepo(c, b"a")            # the reflog's evidence dates it
    g.unchanged()
    g.put("before", b"refs/heads/dated", b"no id: dated\n")
    g.ref("after", b"dated", Y)
    g.log("before", b"dated", [(ZERO, X, b"branch: Created from HEAD")])
    g.log("after", b"dated", [(ZERO, X, b"branch: Created from HEAD"), (X, Y, b"commit: y")])
    g = GitRepo(c, b"b")            # its reflog starts from zeros: never absent
    g.unchanged()
    g.put("before", b"refs/heads/zeros", b"no id: zeros\n")
    g.ref("after", b"zeros", Y)
    g.log("after", b"zeros", [(ZERO, Y, b"branch: Created from HEAD")])
    g = GitRepo(c, b"c")            # removed after, no evidence: no event
    g.unchanged()
    g.put("before", b"refs/heads/gone", b"no id: gone\n")
    c.tag("git.e12.unparsed.ref_before_dated")
    c.tag("git.e12.unparsed.ref_before_reflog_zeros")
    c.tag("git.e12.unparsed.ref_before_removed")
    out.append(c)

    # ---- a loose ref removed whose before cannot be told, a line of
    # packed-refs (read on both sides) under it before: the loose ref is the
    # value there (ref.branch_value's READING), so no `was` -- no event
    c = Case("git-e12-removed-loose-hides-packed")
    g = GitRepo(c, b"d")            # its before not parsed
    g.unchanged()
    g.packed("before", [(b"hid", X), (b"refs/tags/v1", X)])
    g.packed("after", [(b"refs/tags/v1", Y)])
    g.put("before", b"refs/heads/hid", b"no id: hid\n")
    g = GitRepo(c, b"e")            # its before not read
    g.unchanged()
    g.packed("before", [(b"hid", X), (b"refs/tags/v1", X)])
    g.packed("after", [(b"refs/tags/v1", Z)])
    g.ref("before", b"hid", goid("unread hid e"), store="absent")
    c.tag("git.e12.removed.loose_hides_packed_unparsed")
    c.tag("git.e12.removed.loose_hides_packed_unread")
    out.append(c)

    # ---- packed-refs that cannot be parsed before, parsed after
    c = Case("git-e12-unparsed-packed-before")
    g = GitRepo(c)
    g.unchanged()
    g.put("before", b"packed-refs",
          gpacked([(b"refs/heads/kept", X), (b"refs/heads/old-packed", X), (b"refs/heads/po", W),
                   (b"refs/tags/v1", X)]) + b"no ref line before\n")
    # `kept`, only in packed-refs, parsed after only: moved, no `from`; `old-
    # packed`, only in the side not parsed, is named by nothing
    g.packed("after", [(b"kept", X), (b"later", Z), (b"refs/tags/v1", X)])
    g.ref("after", b"new-dated", Y)                 # the reflog's zeros: created
    g.log("after", b"new-dated", [(ZERO, Y, b"branch: Created from HEAD")])
    g.ref("after", b"moved-dated", Y)               # the reflog's old id: dated
    g.log("before", b"moved-dated", [(ZERO, X, b"branch: Created from HEAD")])
    g.log("after", b"moved-dated", [(ZERO, X, b"branch: Created from HEAD"), (X, Y, b"commit: y")])
    g.ref("after", b"undated", W)                   # no evidence: moved, no `from`
    g.ref("before", b"later", X)                    # loose before, packed after: parsed
    g.ref("before", b"gone", X)                     # loose before, not packed after: deleted
    # `po`, only in the packed-refs not parsed, its reflog removed (git
    # removes it with the branch): removed, no value before -- no event
    g.log("before", b"po", [(ZERO, W, b"branch: Created from HEAD")])
    c.tag("git.e12.unparsed.packed_before")
    c.tag("git.e12.unparsed.packed_before_removed")
    out.append(c)
    return out


NOT_AN_ENTRY = b"this line is not a reflog entry\n"


def cell_git_reflog_gained():
    """Required cells for which entries of a reflog git parses (E12, decision
    144): "parsing a reflog is parsing only the entries it gained in this
    diff -- those after before's bytes when they are a prefix of after's
    ending at a line's end, and none otherwise (diff-v1, git:
    `git_reflog_rewritten`) -- never its older entries". Older entries not
    git's: the events come from the gained ones alone. A reflog not a
    prefix, after's entries not git's, or a before ending inside a line of
    after: it gained none, so nothing is parsed -- `git_reflog_rewritten`,
    no E10 event, no evidence. A gained entry not git's: "A side git cannot parse
    counts as one it cannot read (and is a `could_not_interpret` event,
    E10)" -- the reflog is no evidence, the cells of git-e12-unread-reflog
    with a reflog not parsed in place of one not read."""
    out = []
    X, Y = goid("X"), goid("Y")
    born = (ZERO, X, b"branch: Created from HEAD")

    # ---- older entries not git's, gained ones git's
    c = Case("git-e12-reflog-old-not-gits")
    g = GitRepo(c, b"a")            # how it moved: from the gained entry
    g.unchanged()
    g.ref("before", b"feat", X)
    g.ref("after", b"feat", Y)
    old = NOT_AN_ENTRY + glog([born])
    g.put("before", b"logs/refs/heads/feat", old)
    g.put("after", b"logs/refs/heads/feat", old + glog([(X, Y, b"commit: y")], 5))
    g = GitRepo(c, b"b")            # its value before: the first gained entry's old id
    g.unchanged()
    g.ref("after", b"dated", Y)
    old = glog([born]) + NOT_AN_ENTRY
    g.put("before", b"logs/refs/heads/dated", old)
    g.put("after", b"logs/refs/heads/dated", old + glog([(X, Y, b"commit: y")], 5))
    g = GitRepo(c, b"h")            # HEAD detached: the branch `HEAD`, rewritten
    g.head("before", oid=X)
    g.head("after", oid=Y)
    g.put("before", b"logs/HEAD", NOT_AN_ENTRY)
    g.put("after", b"logs/HEAD", NOT_AN_ENTRY + glog([(X, Y, b"reset: moving to y")], 5))
    c.tag("git.e12.reflog_gained.old_not_gits")
    c.tag("git.e12.reflog_gained.old_not_gits_dates")
    c.tag("git.e12.reflog_gained.old_not_gits_head")
    out.append(c)

    # ---- not a prefix ending at a line's end, after's entries not git's:
    # it gained none, so none is parsed -- rewritten, no E10 event, and no
    # evidence
    c = Case("git-e12-reflog-not-prefix-not-gits")
    g = GitRepo(c, b"r")            # no entry of after git's: moved, no how
    g.unchanged()
    g.ref("before", b"feat", X)
    g.ref("after", b"feat", Y)
    g.log("before", b"feat", [born])
    g.put("after", b"logs/refs/heads/feat", NOT_AN_ENTRY + NOT_AN_ENTRY)
    g = GitRepo(c, b"s")            # after's first line not git's, its next one
    g.unchanged()                   # would date the branch: no value before
    g.ref("after", b"dated", Y)
    g.log("before", b"dated", [born])
    g.put("after", b"logs/refs/heads/dated", NOT_AN_ENTRY + glog([(X, Y, b"commit: y")], 5))
    # ... and before a prefix of after's ending inside a line of it ("ending
    # at a line's end, and none otherwise"; diff-v1: "A line is the bytes up
    # to and including a newline"): it gained none either
    full = glog([born, (X, Y, b"commit: y")])
    g = GitRepo(c, b"t")            # before ends mid-entry: after's rest is no entry
    g.unchanged()
    g.ref("after", b"dated", Y)
    g.put("before", b"logs/refs/heads/dated", full[:len(glog([born])) + 50])
    g.put("after", b"logs/refs/heads/dated", full)
    g = GitRepo(c, b"u")            # before ends just short of a newline: after's
    g.unchanged()                   # next entry would date the branch
    g.ref("after", b"dated", Y)
    g.put("before", b"logs/refs/heads/dated", glog([born])[:-1])
    g.put("after", b"logs/refs/heads/dated", full)
    c.tag("git.e12.reflog_gained.not_prefix_not_gits")
    c.tag("git.e12.reflog_gained.not_prefix_no_evidence")
    c.tag("git.e12.reflog_gained.inside_a_line")
    out.append(c)

    # ---- gained entries not git's: no evidence, and its E10 event
    c = Case("git-e12-unparsed-reflog")
    g = GitRepo(c, b"a")            # its first gained entry would date the branch
    g.unchanged()
    g.ref("after", b"alone", Y)
    g.log("before", b"alone", [born])
    g.put("after", b"logs/refs/heads/alone",
          glog([born, (X, Y, b"commit: y")]) + NOT_AN_ENTRY)
    g = GitRepo(c, b"b")            # it would say a rename: created and deleted stand
    g.unchanged()
    g.packed("before", [(b"refs/tags/v1", X)])
    g.packed("after", [(b"refs/tags/v1", X), (b"refs/tags/v2", Y)])
    g.ref("before", b"old", X)
    g.ref("after", b"new", X)
    g.log("before", b"old", [born])
    g.put("after", b"logs/refs/heads/new",
          glog([born, (X, X, b"Branch: renamed refs/heads/old to refs/heads/new")])
          + NOT_AN_ENTRY)
    g = GitRepo(c, b"c")            # every gained entry not git's: moved, no how
    g.unchanged()
    g.ref("before", b"feat", X)
    g.ref("after", b"feat", Y)
    g.log("before", b"feat", [born])
    g.put("after", b"logs/refs/heads/feat", glog([born]) + NOT_AN_ENTRY + NOT_AN_ENTRY)
    g = GitRepo(c, b"h")            # HEAD detached: the branch `HEAD`, without a how
    g.head("before", oid=X)
    g.head("after", oid=Y)
    g.log("before", b"HEAD", [(ZERO, X, b"commit (initial): x")])
    g.put("after", b"logs/HEAD",
          glog([(ZERO, X, b"commit (initial): x"), (X, Y, b"reset: moving to y")]) + NOT_AN_ENTRY)
    c.tag("git.e12.unparsed.reflog_gained")
    c.tag("git.e12.unparsed.reflog_would_date")
    c.tag("git.e12.unparsed.reflog_rename_untold")
    c.tag("git.e12.unparsed.reflog_head_detached")
    out.append(c)
    return out


def random_git(rng, c):
    """A repository's history, simulated: a few operations before, more
    after, each written as git writes it (loose refs, packed-refs, HEAD,
    reflogs); now and then a copy lost, a file raced, a ref, HEAD or
    packed-refs garbled on a side, a reflog entry dropped, or a reflog line
    not git's -- among its older entries, or gained."""
    root = rng.choice([b"", b"proj", b"proj/vendor/lib", b"w"])
    repo = join(root, b".git")
    st = {"loose": {}, "packed": {}, "logs": {}, "head": ("sym", b"main"), "t": 0}
    n = [0]

    def new():
        n[0] += 1
        return rng.randbytes(20).hex().encode()

    def value(ref):
        return st["loose"].get(ref, st["packed"].get(ref))

    def cur():
        h = st["head"]
        return value(b"refs/heads/" + h[1]) if h[0] == "sym" else h[1]

    def log(ref, old, nw, msg):
        st["logs"].setdefault(ref, []).append((old, nw, msg, st["t"]))
        st["t"] += 1

    def set_branch(br, nw, msg, head_too=True):
        ref = b"refs/heads/" + br
        old = value(ref) or ZERO
        st["loose"][ref] = nw
        log(ref, old, nw, msg)
        if head_too and st["head"] == ("sym", br):
            log(b"HEAD", old, nw, msg)

    def branches():
        return sorted({r[len(b"refs/heads/"):] for r in list(st["loose"]) + list(st["packed"])
                       if r.startswith(b"refs/heads/")})

    first = new()
    set_branch(b"main", first, b"commit (initial): start")
    names = [b"main", b"dev", b"topic", b"feature/x", b"fix-1", b"rel"]

    def step():
        h = st["head"]
        op = rng.randrange(17)
        brs = branches()
        if op in (0, 1, 2):                                  # a commit
            msg = rng.choice([b"commit: c", b"commit: c", b"commit (merge): m", b"cherry-pick: p",
                              b"revert: r", b"am: a", b"commit (amend): fix"])
            nw = new()
            if h[0] == "sym":
                set_branch(h[1], nw, msg)
            else:
                log(b"HEAD", h[1], nw, msg)
                st["head"] = ("oid", nw)
        elif op == 3 and h[0] == "sym":                      # reset
            nw = new() if rng.random() < 0.5 else first
            set_branch(h[1], nw, b"reset: moving to " + nw[:7])
        elif op == 4 and h[0] == "sym":                      # a merge
            nw = new()
            set_branch(h[1], nw, rng.choice([b"merge dev: Fast-forward", b"pull: Fast-forward",
                                             b"merge dev: Merge made by the 'ort' strategy."]))
        elif op == 5 and h[0] == "sym":                      # a rebase
            nw = new()
            ref = b"refs/heads/" + h[1]
            old = value(ref)
            st["loose"][ref] = nw
            log(ref, old, nw, b"rebase (finish): " + ref + b" onto " + first)
            log(b"HEAD", old, first, b"rebase (start): checkout " + first[:7])
            log(b"HEAD", first, nw, b"rebase (pick): p")
            log(b"HEAD", nw, nw, b"rebase (finish): returning to " + ref)
        elif op == 6 and brs:                                # checkout
            br = rng.choice(brs)
            frm = cur()
            to = value(b"refs/heads/" + br)
            log(b"HEAD", frm, to, b"checkout: moving from " + (h[1] if h[0] == "sym" else h[1][:7])
                + b" to " + br)
            st["head"] = ("sym", br)
        elif op == 7:                                        # checkout -b
            br = rng.choice(names)
            if value(b"refs/heads/" + br) is None:
                at = cur()
                ref = b"refs/heads/" + br
                st["loose"][ref] = at
                log(ref, ZERO, at, b"branch: Created from HEAD")
                log(b"HEAD", at, at, b"checkout: moving from x to " + br)
                st["head"] = ("sym", br)
        elif op == 8:                                        # branch, no checkout
            br = rng.choice(names)
            ref = b"refs/heads/" + br
            if value(ref) is None:
                at = cur()
                st["loose"][ref] = at
                log(ref, ZERO, at, b"branch: Created from " + rng.choice([b"HEAD", b"main"]))
        elif op == 9 and len(brs) > 1:                       # branch -d
            br = rng.choice([b for b in brs if st["head"] != ("sym", b)])
            ref = b"refs/heads/" + br
            st["loose"].pop(ref, None)
            st["packed"].pop(ref, None)
            st["logs"].pop(ref, None)
        elif op == 10 and brs:                               # branch -m
            br = rng.choice(brs)
            to = rng.choice(names)
            if value(b"refs/heads/" + to) is None:
                old, ref = b"refs/heads/" + br, b"refs/heads/" + to
                v = value(old)
                st["loose"].pop(old, None)
                st["packed"].pop(old, None)
                st["loose"][ref] = v
                st["logs"][ref] = st["logs"].pop(old, [])
                log(ref, v, v, b"Branch: renamed " + old + b" to " + ref)
                if st["head"] == ("sym", br):
                    st["head"] = ("sym", to)
        elif op == 11 and brs:                               # branch -f
            br = rng.choice([b for b in brs if st["head"] != ("sym", b)] or [None])
            if br:
                nw = rng.choice([first, new()])
                set_branch(br, nw, b"branch: Reset to " + nw[:7], head_too=False)
        elif op == 12:                                       # detach
            at = cur()
            log(b"HEAD", at, at, b"checkout: moving from x to " + at)
            st["head"] = ("oid", at)
        elif op == 13:                                       # pack-refs --all
            st["packed"].update(st["loose"])
            st["loose"] = {}
        elif op == 14:                                       # fetch
            ref = b"refs/remotes/origin/main"
            nw = new()
            old = value(ref) or ZERO
            st["loose"][ref] = nw
            log(ref, old, nw, rng.choice([b"fetch: fast-forward", b"fetch: forced-update"]))
        elif op == 15:                                       # a tag
            st["loose"][b"refs/tags/v%d" % rng.randrange(4)] = new()
        elif op == 16 and h[0] == "sym":                     # push --force-like
            set_branch(h[1], new(), b"update by push: forced-update")

    def files():
        out = {}
        h = st["head"]
        out[b"HEAD"] = (b"ref: refs/heads/" + h[1] if h[0] == "sym" else h[1]) + b"\n"
        for ref, v in st["loose"].items():
            out[ref] = v + b"\n"
        if st["packed"] or rng.random() < 0.2:
            out[b"packed-refs"] = gpacked(sorted(st["packed"].items()))
        for ref, es in st["logs"].items():
            if es:
                out[b"logs/" + ref] = b"".join(reflog_entry(o, nw, m, t) for o, nw, m, t in es)
        return out

    for _ in range(rng.randrange(1, 6)):
        step()
    bf = files()
    for _ in range(rng.randrange(1, 7)):
        step()
    af = files()
    # older entries not git's, on both sides: never parsed (E12, decision 144)
    for rest in sorted(set(bf) & set(af)):
        if (rest.startswith(b"logs/") and bf[rest] != af[rest]
                and af[rest].startswith(bf[rest]) and rng.random() < 0.08):
            bf[rest] = NOT_AN_ENTRY + bf[rest]
            af[rest] = NOT_AN_ENTRY + af[rest]
    store_choices = ["ok"] * 14 + ["none", "absent", "corrupt"]
    for side, fs in (("before", bf), ("after", af)):
        for rest, data in fs.items():
            other = af if side == "before" else bf
            same = other.get(rest) == data
            r = rng.random()
            if not same and rest.startswith(b"logs/") and side == "after" and r < 0.04:
                lines = data.split(b"\n")[:-1]     # an entry dropped: no longer a chain
                if len(lines) > 2:
                    del lines[-2]
                    data = b"\n".join(lines) + b"\n"
            elif not same and rest.startswith(b"logs/") and side == "after" and r < 0.08:
                data += NOT_AN_ENTRY            # an entry gained, not git's
            elif not same and rest.startswith(b"refs/") and r < 0.02:
                data = b"garbled\n"
            elif not same and rest == b"HEAD" and r < 0.03:
                data = b"garbled HEAD\n"
            elif not same and rest == b"packed-refs" and r < 0.06:
                data += b"garbled, no ref line\n"
            c.put(side, repo + b"/" + rest,
                  reg(data, gen=0 if same else (1 if side == "after" else 0),
                      store="ok" if same else rng.choice(store_choices),
                      raced=(not same) and rng.random() < 0.04))


# ---------------------------------------------------------------- required cells

def base_db():
    return [stanza(b"base-files", b"12.4+deb12u5"), stanza(b"bash", b"5.2.15-2+b2")]


def cell_dpkg_simple():
    out = []
    sp = b"var/lib/dpkg/status"

    c = Case("dpkg-installed")
    c.put("before", sp, reg(status_bytes(base_db())))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"7.88.1-10+deb12u5",
                                                             nonce=1, conffiles=True)]), gen=1))
    c.tag("dpkg.installed")
    out.append(c)

    c = Case("dpkg-removed")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"7.88.1-10")])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"7.88.1-10",
                                                             b"deinstall ok config-files")]), gen=1))
    c.tag("dpkg.removed")
    out.append(c)

    c = Case("dpkg-upgraded")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"7.88.1-10")])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"7.88.1-10+deb12u5")]), gen=1))
    c.tag("dpkg.upgraded")
    out.append(c)

    c = Case("dpkg-downgraded")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1:7.0-1")])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"8.0~rc1-1")]), gen=1))
    c.tag("dpkg.downgraded")
    out.append(c)

    c = Case("dpkg-state-changed-alone")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"7.88.1-10")])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"7.88.1-10",
                                                             b"hold ok installed")]), gen=1))
    c.tag("dpkg.state_changed.alone")
    out.append(c)

    c = Case("dpkg-state-changed-not-installed")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"7.88.1-10",
                                                              b"deinstall ok config-files")])))
    c.put("after", sp, reg(status_bytes(base_db()), gen=1))
    c.tag("dpkg.state_changed.alone")
    out.append(c)

    c = Case("dpkg-state-changed-with-upgrade")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"7.88.1-10")])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"7.88.1-11",
                                                             b"hold ok installed")]), gen=1))
    c.tag("dpkg.state_changed.with_upgrade")
    out.append(c)

    c = Case("dpkg-empty-arch")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"noarch", b"1.0", arch=b"")])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"noarch", b"2.0", arch=b"")]), gen=1))
    c.tag("dpkg.empty_arch")
    out.append(c)

    c = Case("dpkg-key-repeated")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.0-1"),
                                                      stanza(b"curl", b"9.0-1", nonce=5)])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"2.0-1"),
                                                     stanza(b"curl", b"0.5-1", nonce=5)]), gen=1))
    c.tag("dpkg.key_repeated_first_wins")
    out.append(c)

    c = Case("dpkg-multi-arch")
    c.put("before", sp, reg(status_bytes(base_db() + [
        stanza(b"libssl3", b"3.0.11-1", arch=b"amd64"),
        stanza(b"libssl3", b"3.0.11-1", arch=b"i386")])))
    c.put("after", sp, reg(status_bytes(base_db() + [
        stanza(b"libssl3", b"3.0.13-1", arch=b"amd64"),
        stanza(b"libssl3", b"3.0.11-1", b"deinstall ok config-files", arch=b"i386"),
        stanza(b"libssl3", b"3.0.13-1", arch=b"arm64")]), gen=1))
    c.tag("dpkg.multi_arch")
    out.append(c)

    c = Case("dpkg-status-added")
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"7.88.1-10", arch=b"")])))
    c.tag("dpkg.status_added_all_installed")
    out.append(c)

    c = Case("dpkg-status-removed")
    c.put("before", sp, reg(status_bytes(base_db() + [
        stanza(b"curl", b"7.88.1-10", b"deinstall ok config-files")])))
    c.tag("dpkg.status_removed")
    out.append(c)

    c = Case("dpkg-status-short")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.0", b"install installed"),
                                                      stanza(b"wget", b"1.0")])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.0"),
                                                     stanza(b"wget", b"1.0", b"installed")]), gen=1))
    c.tag("dpkg.status_short")
    out.append(c)

    c = Case("dpkg-continuation")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.0-1", desc_lines=6,
                                                             conffiles=True)])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.1-1", desc_lines=3,
                                                            conffiles=True, nonce=3)]), gen=1))
    c.tag("dpkg.continuation_multiline")
    out.append(c)

    c = Case("dpkg-two-status-files")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.0-1")])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.1-1")]), gen=1))
    sp2 = b"chroot/bookworm/var/lib/dpkg/status"
    c.put("before", sp2, reg(status_bytes(base_db() + [stanza(b"curl", b"2.0-1", nonce=7)])))
    c.put("after", sp2, reg(status_bytes(base_db() + [stanza(b"curl", b"1.9-1", nonce=7),
                                                      stanza(b"apt", b"2.6.1")]), gen=1))
    c.tag("dpkg.two_status_files")
    out.append(c)
    return out


def cell_pip_simple():
    out = []
    S, S2 = SITES[0], SITES[2]
    rng = random.Random(4242)

    def rows(n, v):
        return rand_rows(rng, n, v)

    c = Case("pip-installed")
    put_dist(c, "after", S, b"requests", b"2.31.0", rows(b"requests", b"2.31.0"))
    c.tag("pip.installed")
    out.append(c)

    c = Case("pip-removed")
    put_dist(c, "before", S, b"requests", b"2.31.0", rows(b"requests", b"2.31.0"))
    c.tag("pip.removed")
    out.append(c)

    c = Case("pip-upgraded")
    put_dist(c, "before", S, b"requests", b"2.9.0", rows(b"requests", b"2.9.0"))
    put_dist(c, "after", S, b"requests", b"2.31.0", rows(b"requests", b"2.31.0"), gen=1)
    c.tag("pip.upgraded")
    out.append(c)

    c = Case("pip-downgraded")
    put_dist(c, "before", S, b"numpy", b"2.0.0", rows(b"numpy", b"2.0.0"))
    put_dist(c, "after", S, b"numpy", b"2.0.0rc1", rows(b"numpy", b"2.0.0rc1"), gen=1)
    c.tag("pip.downgraded")
    out.append(c)

    c = Case("pip-version-changed-equal")
    put_dist(c, "before", S, b"six", b"1.16", rows(b"six", b"1.16"))
    put_dist(c, "after", S, b"six", b"1.16.0", rows(b"six", b"1.16.0"), gen=1)
    put_dist(c, "before", S, b"attrs", b"1.0alpha1", rows(b"attrs", b"1.0alpha1"))
    put_dist(c, "after", S, b"attrs", b"1.0.0a1", rows(b"attrs", b"1.0.0a1"), gen=1)
    c.tag("pip.version_changed.pep440_equal")
    out.append(c)

    c = Case("pip-version-changed-non-pep440")
    put_dist(c, "before", S, b"tzdata", b"2013x", rows(b"tzdata", b"2013x"))
    put_dist(c, "after", S, b"tzdata", b"2024.1", rows(b"tzdata", b"2024.1"), gen=1)
    put_dist(c, "before", S, b"wheel", b"0.41", rows(b"wheel", b"0.41"))
    put_dist(c, "after", S, b"wheel", b"latest", rows(b"wheel", b"latest"), gen=1)
    c.tag("pip.version_changed.non_pep440")
    out.append(c)

    base = rows(b"attrs", b"23.1.0")
    body = [r for r in base if r[1]]

    def reinst(name, after_rows, cell, term="\r\n"):
        c = Case(name)
        put_dist(c, "before", S, b"attrs", b"23.1.0", base, term=term)
        put_dist(c, "after", S, b"attrs", b"23.1.0", after_rows, gen=1, term=term)
        c.tag(cell)
        out.append(c)

    reinst("pip-reinstalled-added", base + [["attrs/new.py", "sha256=AAAA", "3"],
                                            ["attrs/new2.py", "sha256=BBBB", "4"]],
           "pip.reinstalled.files_added")
    reinst("pip-reinstalled-removed", [r for r in base if r is not body[0]],
           "pip.reinstalled.files_removed")
    reinst("pip-reinstalled-hash", [[r[0], "sha256=CHANGED", r[2]] if r is body[0] else r
                                    for r in base], "pip.reinstalled.changed_hash", term="\n")
    reinst("pip-reinstalled-size", [[r[0], r[1], "999999"] if r is body[0] else r for r in base],
           "pip.reinstalled.changed_size")
    reinst("pip-reinstalled-twice-first-same",
           base + [[body[0][0], "sha256=SECOND", "1"]], "pip.reinstalled.path_listed_twice")
    reinst("pip-reinstalled-twice-first-differs",
           [[body[0][0], "sha256=FIRST", "1"]] + base, "pip.reinstalled.path_listed_twice")
    c = Case("pip-reinstalled-twice-in-before")
    put_dist(c, "before", S, b"attrs", b"23.1.0", base + [[body[0][0], "sha256=SECOND", "1"]])
    put_dist(c, "after", S, b"attrs", b"23.1.0", base + [["attrs/z.py", "sha256=Z", "1"]], gen=1)
    c.tag("pip.reinstalled.path_listed_twice")
    out.append(c)

    c = Case("pip-different-dirs")
    put_dist(c, "before", S, b"six", b"1.15.0", rows(b"six", b"1.15.0"))
    put_dist(c, "after", S2, b"six", b"1.16.0", rows(b"six", b"1.16.0"))
    c.tag("pip.diff_dirs_not_paired")
    out.append(c)

    c = Case("pip-normalized-pair")
    put_dist(c, "before", S, b"Flask_SQLAlchemy", b"3.0.0", rows(b"Flask_SQLAlchemy", b"3.0.0"))
    put_dist(c, "after", S, b"flask.sqlalchemy", b"3.1.1", rows(b"flask.sqlalchemy", b"3.1.1"),
             gen=1)
    put_dist(c, "before", S, b"Zope__Interface", b"6.0", rows(b"Zope__Interface", b"6.0"))
    put_dist(c, "after", S, b"zope._.interface", b"5.0", rows(b"zope._.interface", b"5.0"), gen=1)
    c.tag("pip.normalize_equal_paired")
    out.append(c)

    c = Case("pip-name-split")
    put_dist(c, "after", S, b"typing", b"extensions-4.8.0", rows(b"typing", b"extensions-4.8.0"))
    put_dist(c, "before", S, b"foo", b"1.0-1", rows(b"foo", b"1.0-1"))
    put_dist(c, "after", S, b"foo", b"1.0-2", rows(b"foo", b"1.0-2"), gen=1)
    c.tag("pip.name_split_first_dash")
    out.append(c)

    # Several added (or removed) of one name in one directory: name, kind and
    # directory tie, so "then the paths it lists" orders them. Path order
    # (SIX < Six < six, bytewise) differs from version order here.
    c = Case("pip-events-tie-by-paths", modes=("store", "nostore"))
    for n, v in [(b"six", b"1.0"), (b"Six", b"3.0"), (b"SIX", b"2.0")]:
        put_dist(c, "after", S, n, v, rows(n, v))
    for n, v in [(b"attrs", b"2.0"), (b"Attrs", b"1.0")]:
        put_dist(c, "before", S, n, v, rows(n, v))
    c.tag("pip.events_tie_by_paths")
    out.append(c)

    c = Case("pip-metadata-only")
    rec, meta = dist(S, b"six", b"1.16.0")
    c.both(rec, reg(record_bytes(rows(b"six", b"1.16.0"))))
    c.put("before", meta, reg(b"Name: six\nVersion: 1.16.0\n"))
    c.put("after", meta, reg(b"Name: six\nVersion: 1.16.0\nSummary: changed\n", gen=1))
    rec2, meta2 = dist(S, b"attrs", b"23.1.0")
    c.both(rec2, reg(record_bytes(rows(b"attrs", b"23.1.0"))))
    c.put("before", meta2, reg(b"Name: attrs\n", store="none"))
    c.put("after", meta2, reg(b"Name: attrs\nX: 1\n", store="absent", gen=1))
    c.put("after", dist(S, b"newpkg", b"1.0")[1], reg(b"Name: newpkg\n", store="corrupt"))
    c.tag("pip.metadata_changes_nothing")
    out.append(c)

    c = Case("pip-event-order")
    put_dist(c, "after", S, b"zzz", b"1.0", rows(b"zzz", b"1.0"))
    put_dist(c, "before", S, b"aaa", b"1.0", rows(b"aaa", b"1.0"))
    put_dist(c, "after", S2, b"AAA", b"2.0", rows(b"AAA", b"2.0"))
    put_dist(c, "before", S2, b"aaa", b"3.0", rows(b"aaa", b"3.0"))
    put_dist(c, "before", S, b"Mmm", b"1.0", rows(b"Mmm", b"1.0"))
    put_dist(c, "after", S, b"mmm", b"0.9", rows(b"mmm", b"0.9"), gen=1)
    put_dist(c, "before", SITES[1], b"aaa", b"1.0", rows(b"aaa", b"1.0"))
    put_dist(c, "after", SITES[1], b"aaa", b"1.0", rows(b"aaa", b"1.0"), gen=1)
    put_dist(c, "after", SITES[1], b"a_b", b"1.0", rows(b"a_b", b"1.0"))
    c.tag("pip.events_order")
    out.append(c)
    return out


BOTH = ("store", "nostore")


def cell_pip_e10():
    """E10 for pip: a file not interpreted is one could_not_interpret event
    naming it; the other events stand. Naming and pairing read no content, so
    those run with and without a store."""
    out = []
    S = SITES[0]
    rng = random.Random(77)
    for label, name, version in [("no-dash", b"nodash", None), ("empty-name", b"", b"1.0"),
                                 ("empty-version", b"foo", b""),
                                 ("bad-utf8-name", b"f\xffo", b"1.0"),
                                 ("long-name", b"n" * 1025, b"1.0")]:
        c = Case("pip-e10-unnameable-" + label, modes=BOTH)
        if version is None:
            di = S + b"/" + name + b".dist-info"
            c.put("after", di + b"/RECORD", reg(b"x,,\n"))
        else:
            put_dist(c, "after", S, name, version, rand_rows(rng, b"x", b"1"))
        put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
        put_dist(c, "before", S, b"attrs", b"1.0", rand_rows(rng, b"attrs", b"1.0"))
        put_dist(c, "after", S, b"attrs", b"2.0", rand_rows(rng, b"attrs", b"2.0"), gen=1)
        c.tag("pip.E10.unnameable")
        out.append(c)
    c = Case("pip-e10-ambiguous", modes=BOTH)
    put_dist(c, "before", S, b"six", b"1.15.0", rand_rows(rng, b"six", b"1.15.0"))
    put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
    put_dist(c, "after", S, b"Six", b"1.17.0", rand_rows(rng, b"Six", b"1.17.0"))
    put_dist(c, "after", S, b"attrs", b"1.0", rand_rows(rng, b"attrs", b"1.0"))
    put_dist(c, "before", S, b"zzz", b"1.0", rand_rows(rng, b"zzz", b"1.0"))
    c.tag("pip.E10.ambiguous")
    out.append(c)
    c = Case("pip-e10-ambiguous-2r1a", modes=BOTH)
    put_dist(c, "before", S, b"six", b"1.15.0", rand_rows(rng, b"six", b"1.15.0"))
    put_dist(c, "before", S, b"SIX", b"1.14.0", rand_rows(rng, b"SIX", b"1.14.0"))
    put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
    put_dist(c, "after", S, b"Six", b"1.14.0", rand_rows(rng, b"Six", b"1.14.0"))
    put_dist(c, "after", S, b"zzz", b"1.0", rand_rows(rng, b"zzz", b"1.0"))
    c.tag("pip.E10.ambiguous")
    out.append(c)
    # An unparseable RECORD: only a reinstall reads one, so with a store.
    c = Case("pip-e10-unparseable-record")
    r = rand_rows(rng, b"six", b"1.16.0")
    put_dist(c, "before", S, b"six", b"1.16.0", r)
    put_dist(c, "after", S, b"six", b"1.16.0", None, gen=1,
             raw=record_bytes(r) + b"six/short.py,sha256=X\n")
    r2 = rand_rows(rng, b"attrs", b"23.1.0")
    put_dist(c, "before", S, b"attrs", b"23.1.0", r2)
    put_dist(c, "after", S, b"attrs", b"23.1.0", mutate_rows(rng, r2), gen=1)
    put_dist(c, "after", S, b"requests", b"2.31.0", rand_rows(rng, b"requests", b"2.31.0"))
    c.tag("pip.E10.unparseable_record")
    out.append(c)
    return out


def cell_dpkg_e9_e10():
    """E9: an event that breaks its row is one invalid_finding event in its
    place, the others intact. E10: a status that cannot be parsed is one
    could_not_interpret event naming it, another root's events intact. Both
    read content: with a store."""
    out = []
    sp = b"var/lib/dpkg/status"

    c = Case("dpkg-e9-oversized-text")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"aaa", b"1.0"),
                                                      stanza(b"zzz", b"1.0")])))
    c.put("after", sp, reg(status_bytes(base_db() + [
        stanza(b"aaa", b"2.0"), stanza(b"m" * 600, b"1." + b"0" * 500)]), gen=1))
    c.tag("dpkg.E9.oversized_text")
    out.append(c)

    c = Case("dpkg-e9-nul-value")
    c.put("before", sp, reg(status_bytes(base_db() + [
        stanza(b"aaa", b"1.0"), stanza(b"zzz", b"1.0", b"hold ok installed")])))
    c.put("after", sp, reg(status_bytes(base_db() + [
        stanza(b"aaa", b"2.0"), stanza(b"mmm", b"1.0\0rc1"), stanza(b"zzz", b"1.0")]), gen=1))
    c.tag("dpkg.E9.nul_value")
    out.append(c)

    c = Case("dpkg-e9-non-utf8-value")
    c.put("before", sp, reg(status_bytes(base_db() + [
        stanza(b"aaa", b"1.0"), stanza(b"ccc", b"1.0"), stanza(b"zzz", b"1.0")])))
    c.put("after", sp, reg(status_bytes(base_db() + [
        stanza(b"aaa", b"2.0"), stanza(b"ccc", b"1.0", b"hold\xff ok installed"),
        stanza(b"pk\xe9", b"1.0")]), gen=1))
    c.tag("dpkg.E9.non_utf8_value")
    out.append(c)

    c = Case("dpkg-e10-unparseable-status")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.0-1")])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.1-1")])
                           + b"garbage line\n", gen=1))
    sp2 = b"chroot/bookworm/var/lib/dpkg/status"
    c.put("before", sp2, reg(status_bytes(base_db() + [stanza(b"curl", b"1.0-1", nonce=2)])))
    c.put("after", sp2, reg(status_bytes(base_db() + [stanza(b"curl", b"1.1-1", nonce=2),
                                                      stanza(b"apt", b"2.6.1")]), gen=1))
    c.tag("dpkg.E10.unparseable_status")
    out.append(c)
    return out


def cell_p7():
    """P7: an event derived from a path whose outcome is unknown is
    provisional; an unknown path carries no path finding."""
    out = []
    S, S2 = SITES[0], SITES[2]
    rng = random.Random(707)
    sp = b"var/lib/dpkg/status"
    sp2 = b"chroot/bookworm/var/lib/dpkg/status"

    c = Case("pip-p7-unknown-pairs", modes=BOTH)
    put_dist(c, "before", S, b"six", b"1.15.0", rand_rows(rng, b"six", b"1.15.0"))
    put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"), raced=True)
    put_dist(c, "before", S, b"attrs", b"2.0", rand_rows(rng, b"attrs", b"2.0"), raced=True)
    put_dist(c, "after", S, b"attrs", b"1.0", rand_rows(rng, b"attrs", b"1.0"))
    put_dist(c, "after", S, b"requests", b"2.31.0", rand_rows(rng, b"requests", b"2.31.0"))
    c.tag("pip.P7.unknown_pairs")
    out.append(c)

    c = Case("pip-p7-unknown-unpaired", modes=BOTH)
    put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"), raced=True)
    put_dist(c, "before", S, b"attrs", b"1.0", rand_rows(rng, b"attrs", b"1.0"), raced=True)
    # unknown because the directory's listing is incomplete on the side that
    # lacks it (listing_incomplete). Under an unreadable directory it would
    # be not_captured, and derive nothing (E11: cell_e11).
    put_dist(c, "before", S2, b"numpy", b"2.0", rand_rows(rng, b"numpy", b"2.0"))
    c.put("after", S2, unstable_dir())
    put_dist(c, "before", S, b"wheel", b"0.41", rand_rows(rng, b"wheel", b"0.41"))
    c.tag("pip.P7.unknown_unpaired")
    out.append(c)

    c = Case("pip-p7-unknown-both-sides", modes=BOTH)
    r = rand_rows(rng, b"six", b"1.16.0")
    put_dist(c, "before", S, b"six", b"1.16.0", r)
    put_dist(c, "after", S, b"six", b"1.16.0", mutate_rows(rng, r), gen=1, raced=True)
    put_dist(c, "after", S, b"requests", b"2.31.0", rand_rows(rng, b"requests", b"2.31.0"))
    c.tag("pip.P7.unknown_both_sides")
    out.append(c)

    # the same, its dist-info unnamable: one provisional could_not_interpret
    # (E10), no record finding (its outcome is unknown), nothing read
    c = Case("pip-p7-unknown-unnameable-both-sides", modes=BOTH)
    c.put("before", S + b"/nodash.dist-info/RECORD", reg(b"x,,\n"))
    c.put("after", S + b"/nodash.dist-info/RECORD", reg(b"x,,\ny,,\n", raced=True, gen=1))
    put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
    c.tag("pip.P7.unknown_unnameable_both_sides")
    out.append(c)

    c = Case("dpkg-p7-unknown-status", modes=BOTH)
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.0-1")])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"2.0-1"),
                                                     stanza(b"apt", b"2.6.1")]),
                           gen=1, raced=True))
    c.put("before", sp2, reg(status_bytes([stanza(b"x", b"1.0")])))
    c.put("after", sp2, reg(status_bytes([stanza(b"x", b"1.1")]), gen=1))
    c.tag("dpkg.P7.unknown_status_readable", "store")
    c.tag("dpkg.P7.unknown_and_proven_no_store", "nostore")
    out.append(c)

    c = Case("dpkg-p7-unknown-status-alone", modes=BOTH)
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.0-1")]), raced=True))
    c.tag("dpkg.P7.unknown_status_readable", "store")
    c.tag("dpkg.P7.unknown_status_no_store", "nostore")
    out.append(c)

    # unknown through a directory whose listing is incomplete on the side that
    # lacks it (listing_incomplete): the after side's status, read. (Below an
    # unreadable directory it is not_captured: E11, cell_e11.)
    c = Case("dpkg-p7-unknown-unstable-dir", modes=BOTH)
    c.put("before", b"chroot/sid", unstable_dir())
    c.put("after", b"chroot/sid/" + sp, reg(status_bytes(base_db())))
    c.tag("dpkg.P7.unknown_status_readable", "store")
    c.tag("dpkg.P7.unknown_status_no_store", "nostore")
    out.append(c)
    return out


def cell_e11():
    """E11: a path unknown only as not_captured -- the side that lacks it
    excluded it (or a path above it), or it lies below a directory that side
    records as unreadable or a mount -- derives no event: it is no pair
    partner, is never named, and no copy of it is needed. Its record stands.
    Any other unknown path still derives provisional events (E2, P7).
    The pin spells out the core's events (decision 118): "No interpreter is
    given it, so no event of the core's names it either: no
    `could_not_interpret` (E10) nor `content_unavailable` for it, and a
    failed end hook's event (E6) never lists it." E10 and content_unavailable
    are built below (pip-e11-unnameable, dpkg-e11-unparseable, the
    store="absent" sides and every nostore pair); E6 is not (see ref.py)."""
    out = []
    S, S2, S3 = SITES
    rng = random.Random(1111)
    sp = b"var/lib/dpkg/status"

    def rows(n, v):
        return rand_rows(rng, n, v)

    # ---- pip
    for how in ("unreadable", "mount"):
        c = Case("pip-e11-below-" + how, modes=BOTH)
        # added below a directory the before side could not look into
        both_dist(c, S2, b"numpy", b"2.0", rows(b"numpy", b"2.0"))
        put_dist(c, "after", S2, b"scipy", b"1.13.0", rows(b"scipy", b"1.13.0"))
        put_dist(c, "after", S2, b"numpy", b"2.1", rows(b"numpy", b"2.1"))
        c.hide("before", S2, how)
        # removed below one the after side could not look into
        put_dist(c, "before", S3, b"wheel", b"0.41", rows(b"wheel", b"0.41"))
        c.hide("after", S3, how)
        # and a known install beside them
        put_dist(c, "after", S, b"requests", b"2.31.0", rows(b"requests", b"2.31.0"))
        c.tag("pip.E11.below_" + how)
        out.append(c)

    c = Case("pip-e11-excluded", modes=BOTH)
    # a path above it excluded on the before side
    put_dist(c, "after", S2, b"numpy", b"2.1", rows(b"numpy", b"2.1"))
    c.exclude("before", S2)
    # the RECORD itself excluded on the after side (its METADATA removed)
    put_dist(c, "before", S3, b"wheel", b"0.41", rows(b"wheel", b"0.41"))
    c.exclude("after", dist(S3, b"wheel", b"0.41")[0])
    put_dist(c, "after", S, b"requests", b"2.31.0", rows(b"requests", b"2.31.0"))
    c.tag("pip.E11.excluded_above")
    c.tag("pip.E11.excluded_path")
    out.append(c)

    # a not_captured RECORD is no pair partner: the other one stands alone
    c = Case("pip-e11-not-a-partner", modes=BOTH)
    put_dist(c, "before", S, b"six", b"1.15.0", rows(b"six", b"1.15.0"))
    put_dist(c, "after", S, b"six", b"1.16.0", rows(b"six", b"1.16.0"))
    c.exclude("before", S + b"/six-1.16.0.dist-info")
    put_dist(c, "before", S, b"attrs", b"1.0", rows(b"attrs", b"1.0"))
    c.hide("after", S + b"/attrs-1.0.dist-info", "mount")
    put_dist(c, "after", S, b"attrs", b"2.0", rows(b"attrs", b"2.0"))
    c.tag("pip.E11.not_a_partner")
    out.append(c)

    # two added and one removed under one key, one of the added not
    # captured: a pair of one each, not E10's ambiguity
    c = Case("pip-e11-not-in-ambiguity", modes=BOTH)
    put_dist(c, "before", S, b"six", b"1.15.0", rows(b"six", b"1.15.0"))
    put_dist(c, "after", S, b"six", b"1.16.0", rows(b"six", b"1.16.0"))
    put_dist(c, "after", S, b"Six", b"1.17.0", rows(b"Six", b"1.17.0"))
    c.exclude("before", S + b"/Six-1.17.0.dist-info")
    c.tag("pip.E11.not_in_ambiguity")
    out.append(c)

    # a dist-info that cannot be named, not captured: never named, so no
    # could_not_interpret (E10) either -- E11: "no `could_not_interpret`
    # (E10) nor `content_unavailable` for it" (its before side has no copy)
    c = Case("pip-e11-unnameable", modes=BOTH)
    c.put("after", S2 + b"/nodash.dist-info/RECORD", reg(b"x,,\n"))
    c.put("before", S2, mount_dir())
    c.put("before", S3 + b"/-1.0.dist-info/RECORD", reg(b"y,,\n", store="absent"))
    c.exclude("after", S3 + b"/-1.0.dist-info")
    put_dist(c, "after", S, b"requests", b"2.31.0", rows(b"requests", b"2.31.0"))
    c.tag("pip.E11.unnameable")
    out.append(c)

    # not_captured beside unknown for other reasons, in one diff: those stay
    # provisional (E2) -- a RECORD that raced, one under an unstable
    # directory, one raced on both sides
    c = Case("pip-e11-with-raced", modes=BOTH)
    put_dist(c, "after", S2, b"numpy", b"2.1", rows(b"numpy", b"2.1"))
    c.hide("before", S2, "unreadable")
    put_dist(c, "after", S, b"six", b"1.16.0", rows(b"six", b"1.16.0"), raced=True)
    r = rows(b"attrs", b"2.0")
    put_dist(c, "before", S, b"attrs", b"2.0", r)
    put_dist(c, "after", S, b"attrs", b"2.0", mutate_rows(rng, r), gen=1, raced=True)
    put_dist(c, "before", S3, b"wheel", b"0.41", rows(b"wheel", b"0.41"))
    c.hide("after", S3, "unstable")
    c.tag("pip.E11.with_raced")
    out.append(c)

    # the first rule that applies decides: a RECORD that raced, below a
    # directory unreadable on the side that lacks it, is not_captured
    c = Case("pip-e11-first-rule-decides", modes=BOTH)
    put_dist(c, "after", S2, b"numpy", b"2.1", rows(b"numpy", b"2.1"), raced=True)
    c.hide("before", S2, "unreadable")
    put_dist(c, "before", S3, b"wheel", b"0.41", rows(b"wheel", b"0.41"), raced=True)
    c.hide("after", S3, "excluded")
    c.tag("pip.E11.first_rule_decides")
    out.append(c)

    # both sides excluded the same path: in no record, named only in the
    # header (V2-R7); a v1 manifest against a v2 one
    c = Case("pip-e11-excluded-both-sides", modes=BOTH)
    c.exclude("before", S2)
    c.exclude("after", S2)
    put_dist(c, "after", S, b"requests", b"2.31.0", rows(b"requests", b"2.31.0"))
    c.tag("pip.E11.excluded_both_sides")
    out.append(c)
    c = Case("pip-e11-v1-against-v2", modes=BOTH)
    put_dist(c, "before", S2, b"numpy", b"2.0", rows(b"numpy", b"2.0"))
    c.put("after", S2, unreadable_dir())
    put_dist(c, "after", S3, b"wheel", b"0.41", rows(b"wheel", b"0.41"))
    c.exclude("before", S3)
    put_dist(c, "after", S, b"requests", b"2.31.0", rows(b"requests", b"2.31.0"))
    c.tag("pip.E11.v1_against_v2")
    out.append(c)

    # ---- dpkg
    for how in ("unreadable", "mount"):
        c = Case("dpkg-e11-below-" + how, modes=BOTH)
        c.put("after", b"chroot/sid/" + sp, reg(status_bytes(base_db())))
        c.hide("before", b"chroot/sid", how)
        c.put("before", b"chroot/buster/" + sp, reg(status_bytes(base_db()), store="absent"))
        c.put("before", b"chroot/buster/var/lib/dpkg/info/bash.list", reg(b"/bin/bash\n"))
        c.hide("after", b"chroot/buster/var/lib/dpkg", how)
        c.tag("dpkg.E11.below_" + how)
        out.append(c)

    c = Case("dpkg-e11-excluded", modes=BOTH)
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.0-1")])))
    c.exclude("after", b"var/lib/dpkg")
    c.put("after", b"x/" + sp, reg(status_bytes([stanza(b"y", b"1.0")])))
    c.exclude("before", b"x/" + sp)
    c.put("before", b"x/var/lib/dpkg/available", reg(b""))
    c.put("after", b"x/var/lib/dpkg/available", reg(b""))
    c.tag("dpkg.E11.excluded_above")
    c.tag("dpkg.E11.excluded_path")
    out.append(c)

    # a status that cannot be parsed, not captured on the side that lacks
    # it, is never parsed: E11, "no `could_not_interpret` (E10) ... for it".
    # Beside it, a captured one that cannot be parsed still gives E10's
    # could_not_interpret, naming it alone.
    c = Case("dpkg-e11-unparseable", modes=BOTH)
    bad = status_bytes(base_db()) + b"garbage line\n"
    c.put("after", b"chroot/sid/" + sp, reg(bad))
    c.hide("before", b"chroot/sid", "unreadable")
    c.put("before", b"chroot/old/" + sp, reg(bad))
    c.hide("after", b"chroot/old", "excluded")
    c.put("before", sp, reg(status_bytes(base_db())))
    c.put("after", sp, reg(bad, gen=1))
    c.tag("dpkg.E11.unparseable", "store")
    c.tag("dpkg.E11.unparseable_no_store", "nostore")
    out.append(c)

    # beside a status that raced: its events stay provisional; without a
    # store, one provisional content_unavailable naming it alone
    c = Case("dpkg-e11-with-raced", modes=BOTH)
    c.put("after", b"chroot/sid/" + sp, reg(status_bytes(base_db())))
    c.hide("before", b"chroot/sid", "unreadable")
    c.put("before", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"1.0-1")])))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"curl", b"2.0-1")]),
                           gen=1, raced=True))
    c.put("before", b"chroot/old/" + sp, reg(status_bytes(base_db())))
    c.hide("after", b"chroot/old/var", "unstable")
    c.tag("dpkg.E11.with_raced")
    out.append(c)

    # READING: a file mounted on one side of a path present on both is
    # unknown with the reason `mount` (its flag's), not `not_captured`:
    # E11 does not apply, and its events stay provisional (E2)
    c = Case("probe-e11-mounted-file", modes=BOTH)
    r = rows(b"six", b"1.16.0")
    rec = dist(S, b"six", b"1.16.0")[0]
    put_dist(c, "before", S, b"six", b"1.16.0", r)
    put_dist(c, "after", S, b"six", b"1.16.0", r)
    c.put("after", rec, reg(record_bytes(r), mount=True))
    c.tag("probe.pip.mounted_record_not_e11")
    out.append(c)
    c = Case("probe-e11-mounted-status", modes=BOTH)
    c.put("before", sp, reg(status_bytes(base_db())))
    c.put("after", sp, reg(status_bytes(base_db()), mount=True))
    c.tag("probe.dpkg.mounted_status_not_e11")
    out.append(c)
    return out


def cell_order():
    """Events with no name first, in the Kinds table's order (could_not_interpret
    by path, then content_unavailable by reason), then the named ones."""
    out = []
    rng = random.Random(4711)

    c = Case("order-dpkg-no-name-first")
    good = status_bytes(base_db())
    for root in (b"z/", b"a/"):
        c.put("before", root + b"var/lib/dpkg/status", reg(good))
        c.put("after", root + b"var/lib/dpkg/status", reg(good + b"garbage " + root + b"\n",
                                                         gen=1))
    # (other bytes than the others': one store state per object)
    c.put("before", b"b/var/lib/dpkg/status", reg(good + b"\n\n\n", store="corrupt"))
    c.put("after", b"b/var/lib/dpkg/status", reg(good + b"\n", gen=1))
    c.put("before", b"m/var/lib/dpkg/status", reg(good))
    c.put("after", b"m/var/lib/dpkg/status", reg(good + b"\n\n", store="absent", gen=1))
    c.put("before", b"var/lib/dpkg/status", reg(status_bytes([stanza(b"aaa", b"1.0")])))
    c.put("after", b"var/lib/dpkg/status", reg(status_bytes([stanza(b"aaa", b"2.0"),
                                                             stanza(b"bbb", b"1.0")]), gen=1))
    c.tag("order.dpkg.no_name_first")
    out.append(c)

    c = Case("order-pip-no-name-first")
    S0, S1, S2 = SITES
    r = rand_rows(rng, b"six", b"1.0")
    put_dist(c, "before", S0, b"six", b"1.0", r)
    put_dist(c, "after", S0, b"six", b"1.0", None, gen=1,
             raw=record_bytes(r) + b"six/short.py,sha256=X\n")
    c.put("after", S2 + b"/nodash.dist-info/RECORD", reg(b"x,,\n"))
    r = rand_rows(rng, b"attrs", b"1.0")
    put_dist(c, "before", S1, b"attrs", b"1.0", r)
    put_dist(c, "after", S1, b"attrs", b"1.0", mutate_rows(rng, r), gen=1, store="absent")
    put_dist(c, "before", S0, b"aaa", b"1.0", rand_rows(rng, b"aaa", b"1.0"))
    put_dist(c, "after", S0, b"aaa", b"2.0", rand_rows(rng, b"aaa", b"2.0"))
    put_dist(c, "after", S0, b"AAA", b"3.0", rand_rows(rng, b"AAA", b"3.0"))
    put_dist(c, "after", S0, b"a-b", b"1.0", rand_rows(rng, b"a-b", b"1.0"))
    put_dist(c, "after", S0, b"zzz", b"1.0", rand_rows(rng, b"zzz", b"1.0"))
    c.tag("order.pip.no_name_first")
    out.append(c)
    return out


# content_unavailable: variant -> how one side of an entry is made unreadable
CU_VARIANTS = ["missing_nostored", "missing_absent", "missing_unverified", "corrupt_content",
               "corrupt_symlink", "too_large"]


def bad_reg(interp, variant, content, which, gen):
    if variant == "missing_nostored":
        return reg(content, store="none", gen=gen)
    if variant == "missing_absent":
        return reg(content, store="absent", gen=gen)
    if variant == "missing_unverified":
        return reg(content, unverified=True, gen=gen)
    if variant == "corrupt_content":
        return reg(content, store="corrupt", gen=gen)
    if variant == "corrupt_symlink":
        return reg(content, store="symlink", gen=gen)
    if variant == "too_large":
        return reg(None, big=BIG[interp][which], gen=gen)
    if variant == "too_large_rows":            # pip: small, but past 262,144 rows
        return reg(b"w%d,,\n" % which + b"x,,\n" * ref.PIP_ROWS, gen=gen)
    raise ValueError(variant)


def cell_content_unavailable():
    out = []
    sp = b"var/lib/dpkg/status"
    sp2 = b"chroot/bookworm/var/lib/dpkg/status"
    S = SITES[0]
    rng = random.Random(99)

    def dpkg_case(name, mode, variant, side):
        c = Case(name, modes=(mode,))

        def bad(content, which, gen):
            if variant == "no_store":
                return reg(content, gen=gen)
            return bad_reg("dpkg", variant, content, which, gen)

        if side in ("before", "both"):         # a status removed
            c.put("before", sp, bad(status_bytes(base_db()), 0, 0))
        if side in ("after", "both"):          # a status added
            c.put("after", sp2, bad(status_bytes(base_db() + [stanza(b"x", b"1")]), 1, 1))
        if variant != "no_store":
            # a status that reads fine, whose events still come
            c.put("before", b"other/var/lib/dpkg/status",
                  reg(status_bytes([stanza(b"y", b"1.0")])))
            c.put("after", b"other/var/lib/dpkg/status",
                  reg(status_bytes([stanza(b"y", b"2.0")]), gen=1))
        return c

    def pip_case(name, mode, variant, side):
        c = Case(name, modes=(mode,))

        def bad(content, which, gen):
            if variant == "no_store":
                return reg(content, gen=gen)
            return bad_reg("pip", variant, content, which, gen)

        r1 = rand_rows(rng, b"six", b"1.16.0")
        r2 = rand_rows(rng, b"attrs", b"23.1.0")
        rec1 = dist(S, b"six", b"1.16.0")[0]
        rec2 = dist(S, b"attrs", b"23.1.0")[0]
        if side in ("before", "both"):
            c.put("before", rec1, bad(record_bytes(r1), 0, 0))
            c.put("after", rec1, reg(record_bytes(mutate_rows(rng, r1)), gen=1))
        if side in ("after", "both") and variant != "no_store":
            c.put("before", rec2, reg(record_bytes(r2)))
            c.put("after", rec2, bad(record_bytes(mutate_rows(rng, r2)), 1, 1))
        put_dist(c, "after", S, b"requests", b"2.31.0", rand_rows(rng, b"requests", b"2.31.0"))
        return c

    for side in ("before", "after", "both"):
        c = dpkg_case("cu-dpkg-no_store-" + side, "nostore", "no_store", side)
        c.tag("cu.dpkg.no_store." + side)
        out.append(c)
        for v in CU_VARIANTS:
            c = dpkg_case("cu-dpkg-%s-%s" % (v, side), "store", v, side)
            c.tag("cu.dpkg.%s.%s" % (v, side))
            out.append(c)
    c = pip_case("cu-pip-no_store-both", "nostore", "no_store", "both")
    c.tag("cu.pip.no_store.both")
    out.append(c)
    for side in ("before", "after", "both"):
        for v in CU_VARIANTS + ["too_large_rows"]:
            c = pip_case("cu-pip-%s-%s" % (v, side), "store", v, side)
            c.tag("cu.pip.%s.%s" % (v, side))
            out.append(c)

    # one path unavailable on both sides
    c = Case("cu-dpkg-one-path-both-sides")
    c.put("before", sp, reg(status_bytes(base_db()), store="absent"))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"x", b"1")]), store="absent", gen=1))
    c.tag("cu.dpkg.one_path_both_sides")
    out.append(c)
    c = Case("cu-pip-one-path-two-reasons")
    r = rand_rows(rng, b"six", b"1")
    rec = dist(S, b"six", b"1")[0]
    c.put("before", rec, reg(record_bytes(r), store="corrupt"))
    c.put("after", rec, reg(record_bytes(mutate_rows(rng, r)), store="none", gen=1))
    c.tag("cu.pip.one_path_two_reasons")
    out.append(c)
    return out


def cell_paths_b64():
    out = []
    rng = random.Random(5)
    c = Case("paths-b64", modes=("store", "nostore"))
    site = b"opt/\xfflib/site-packages"
    put_dist(c, "after", site, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
    root = b"chroot/\xfe/"
    c.put("after", root + b"var/lib/dpkg/status", reg(status_bytes(base_db())))
    c.tag("paths_b64")
    out.append(c)
    return out


# ---------------------------------------------------------------- probes
# Not demanded by the task; each one tests a reading the prose leaves open or
# an edge the formats allow. They are gated like the required cells.

def cell_probes():
    out = []
    sp = b"var/lib/dpkg/status"
    S = SITES[0]
    rng = random.Random(31337)

    def dpkg_pair(name, before, after, cell, modes=("store",)):
        c = Case(name, modes=modes)
        c.put("before", sp, reg(before))
        c.put("after", sp, reg(after, gen=1))
        c.tag(cell)
        out.append(c)

    dpkg_pair("probe-dpkg-equal-versions",
              status_bytes([stanza(b"a", b"1.0"), stanza(b"b", b"1.0-1"), stanza(b"c", b"1.0")]),
              status_bytes([stanza(b"a", b"1.00"), stanza(b"b", b"0:1.0-1"),
                            stanza(b"c", b"1.0-0")]),
              "probe.dpkg.versions_equal_by_ordering")
    dpkg_pair("probe-dpkg-field-case",
              status_bytes([stanza(None, None, raw_fields=[
                  (b"package", b"lc"), (b"STATUS", b"install ok installed"),
                  (b"architecture", b"amd64"), (b"version", b"1.0")])]),
              status_bytes([stanza(None, None, raw_fields=[
                  (b"package", b"lc"), (b"STATUS", b"install ok installed"),
                  (b"architecture", b"amd64"), (b"version", b"2.0")])]),
              "probe.dpkg.field_name_case")
    dpkg_pair("probe-dpkg-status-blanks",
              status_bytes([stanza(b"a", b"1.0", b"install  ok\tinstalled"),
                            stanza(b"b", b"1.0")]),
              status_bytes([stanza(b"a", b"1.0", b"install ok installed"),
                            stanza(b"b", b"1.0", b"hold\tok  installed")]),
              "probe.dpkg.status_inner_blanks")
    dpkg_pair("probe-dpkg-trailing-blanks",
              status_bytes([stanza(None, None, raw_fields=[
                  (b"Package", b"a  "), (b"Status", b"install ok installed \t"),
                  (b"Version", b"1.0 ")])]),
              status_bytes([stanza(None, None, raw_fields=[
                  (b"Package", b"a"), (b"Status", b"install ok installed"),
                  (b"Version", b"\t1.1")])]),
              "probe.dpkg.value_surrounding_blanks")
    dpkg_pair("probe-dpkg-blank-lines",
              status_bytes([stanza(b"a", b"1.0"), stanza(b"b", b"1.0")], sep=b"\n\n\n"),
              b"\n\n" + status_bytes([stanza(b"a", b"1.1"), stanza(b"b", b"1.0")], sep=b"\n\n"),
              "probe.dpkg.several_blank_lines")
    dpkg_pair("probe-dpkg-no-final-newline",
              status_bytes([stanza(b"a", b"1.0")])[:-2],
              status_bytes([stanza(b"a", b"1.1")])[:-2],
              "probe.dpkg.no_final_newline")
    dpkg_pair("probe-dpkg-json-escapes",
              status_bytes([stanza(b"q\"uote", b"1.0", arch=b"x\\y")]),
              status_bytes([stanza(b"q\"uote", b"1.0", b"install ok\tunpacked", arch=b"x\\y")]),
              "probe.dpkg.json_escapes")
    dpkg_pair("probe-dpkg-e10-no-colon",
              status_bytes(base_db()),
              status_bytes(base_db()) + b"garbage line\n",
              "probe.dpkg.E10_line_not_a_field")
    dpkg_pair("probe-dpkg-e9-bad-utf8-version",
              status_bytes(base_db()),
              status_bytes(base_db() + [stanza(b"bad", b"1.0\xff")]),
              "probe.dpkg.E9_value_not_string")
    dpkg_pair("probe-dpkg-e9-value-over-1024",
              status_bytes(base_db()),
              status_bytes(base_db() + [stanza(b"p" * 1025, b"1.0"), stanza(b"q", b"1.0")]),
              "probe.dpkg.E9_value_over_1024")
    dpkg_pair("probe-dpkg-e9-version-over-1024",
              status_bytes(base_db()),
              status_bytes(base_db() + [stanza(b"p", b"1." + b"0" * 1023), stanza(b"q", b"1.0")]),
              "probe.dpkg.E9_version_over_1024")
    # a value over 1,024 bytes in a stanza no event carries: READING, no
    # event is affected, so nothing breaks (the status parses)
    dpkg_pair("probe-dpkg-long-value-without-event",
              status_bytes(base_db() + [stanza(b"p" * 1025, b"1.0", b"purge ok not-installed")]),
              status_bytes(base_db() + [stanza(b"p" * 1025, b"1.0", b"purge ok not-installed",
                                               nonce=4), stanza(b"q", b"1.0")]),
              "probe.dpkg.long_value_without_event")
    dpkg_pair("probe-dpkg-bad-utf8-no-event",
              status_bytes(base_db() + [stanza(b"bad", b"1.0\xff", b"purge ok not-installed")]),
              status_bytes(base_db() + [stanza(b"bad", b"1.0\xff", b"purge ok not-installed",
                                               nonce=9)]),
              "probe.dpkg.bad_value_without_event")
    dpkg_pair("probe-dpkg-continuation-in-version",
              status_bytes([stanza(b"a", b"1.0")]),
              status_bytes([stanza(None, None, raw_fields=[
                  (b"Package", b"a"), (b"Status", b"install ok installed"),
                  (b"Version", b"1.1\n .5")])]),
              "probe.dpkg.continuation_in_read_field")

    c = Case("probe-dpkg-partial-modified")
    c.put("before", sp, reg(status_bytes(base_db()), store="absent"))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"x", b"1")]), gen=1))
    c.tag("probe.dpkg.one_side_unavailable_modified")
    out.append(c)

    c = Case("probe-no-store-and-no-copy", modes=("nostore",))
    c.put("before", sp, reg(status_bytes(base_db()), store="none"))
    c.put("after", b"x/" + sp, reg(status_bytes(base_db()), unverified=True))
    r = rand_rows(rng, b"six", b"1")
    rec = dist(S, b"six", b"1")[0]
    c.put("before", rec, reg(record_bytes(r), store="none"))
    c.put("after", rec, reg(record_bytes(mutate_rows(rng, r)), gen=1))
    c.tag("probe.no_store_with_entry_recording_no_copy")
    out.append(c)

    c = Case("probe-dpkg-symlinked-status", modes=("store", "nostore"))
    c.put("before", sp, reg(status_bytes(base_db())))
    c.put("after", sp, lnk(b"status-new"))
    c.tag("probe.dpkg.status_type_changed")
    out.append(c)

    c = Case("probe-dpkg-info-files", modes=("store", "nostore"))
    c.put("after", b"var/lib/dpkg/info/curl.list", reg(b"/usr/bin/curl\n"))
    c.put("before", b"var/lib/dpkg/info/wget.md5sums", reg(b"0" * 32 + b"  usr/bin/wget\n"))
    c.put("after", b"var/lib/dpkg/info/apt.list", reg(b"/usr/bin/apt\n", store="none"))
    c.tag("probe.dpkg.info_files_no_findings")
    out.append(c)

    c = Case("probe-dpkg-e10-names-the-file")
    c.put("after", b"var/lib/dpkg/info/curl.list", reg(b"/usr/bin/curl\n"))
    c.put("before", sp, reg(status_bytes(base_db())))
    c.put("after", sp, reg(status_bytes(base_db()) + b"no colon\n", gen=1))
    c.put("before", b"x/var/lib/dpkg/status", reg(status_bytes(base_db())))
    c.put("after", b"x/var/lib/dpkg/status", reg(status_bytes(base_db()), raced=True, gen=1))
    c.tag("probe.dpkg.E10_names_the_file")
    out.append(c)

    # P7 x E9 / E10: an unknown status's broken event or unparseable content
    c = Case("probe-dpkg-unknown-e9")
    c.put("before", sp, reg(status_bytes(base_db())))
    c.put("after", sp, reg(status_bytes(base_db() + [stanza(b"m" * 600, b"1." + b"0" * 500),
                                                     stanza(b"n", b"1")]), gen=1, raced=True))
    c.tag("probe.dpkg.unknown_E9_provisional")
    out.append(c)
    c = Case("probe-dpkg-unknown-e10")
    c.put("before", sp, reg(status_bytes(base_db())))
    c.put("after", sp, reg(status_bytes(base_db()) + b"no colon\n", gen=1, raced=True))
    c.put("before", b"x/" + sp, reg(status_bytes([stanza(b"y", b"1.0")])))
    c.put("after", b"x/" + sp, reg(status_bytes([stanza(b"y", b"2.0")]), gen=1))
    c.tag("probe.dpkg.unknown_E10_provisional")
    out.append(c)

    # pip
    c = Case("probe-pip-two-installs-one-key")
    put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
    put_dist(c, "after", S, b"Six", b"1.17.0", rand_rows(rng, b"Six", b"1.17.0"))
    c.tag("probe.pip.two_added_none_removed")
    out.append(c)

    c = Case("probe-pip-reinstall-and-install")
    r = rand_rows(rng, b"six", b"1.16.0")
    put_dist(c, "before", S, b"six", b"1.16.0", r)
    put_dist(c, "after", S, b"six", b"1.16.0", mutate_rows(rng, r), gen=1)
    put_dist(c, "after", S, b"six", b"1.17.0", rand_rows(rng, b"six", b"1.17.0"))
    c.tag("probe.pip.reinstall_beside_install")
    out.append(c)

    c = Case("probe-pip-csv-quoting")
    r = [["six/a,b.py", "sha256=A", "1"], ['six/q"q.py', "sha256=B", "2"],
         ["six/nl\nname.py", "sha256=C", "3"], ["six/ sp.py", "sha256=D", "4"]]
    put_dist(c, "before", S, b"six", b"1.16.0", r, term="\n")
    put_dist(c, "after", S, b"six", b"1.16.0",
             [["six/a,b.py", "sha256=A2", "1"], ['six/q"q.py', "sha256=B", "2"],
              ["six/nl\nname.py", "sha256=C", "4"], ["six/new,\"x\".py", "sha256=E", "5"]],
             gen=1, term="\r\n")
    c.tag("probe.pip.csv_quoting")
    out.append(c)

    c = Case("probe-pip-e10-short-row")
    r = rand_rows(rng, b"six", b"1.16.0")
    put_dist(c, "before", S, b"six", b"1.16.0", r)
    rec = dist(S, b"six", b"1.16.0")[0]
    c.put("after", rec, reg(record_bytes(r) + b"six/short.py,sha256=X\n", gen=1))
    c.tag("probe.pip.E10_row_of_two_fields")
    out.append(c)

    c = Case("probe-pip-e10-long-row")
    put_dist(c, "before", S, b"six", b"1.16.0", r)
    c.put("after", rec, reg(record_bytes(r) + b"six/long.py,sha256=X,1,extra\n", gen=1))
    c.tag("probe.pip.E10_row_of_four_fields")
    out.append(c)

    c = Case("probe-pip-e10-not-utf8")
    put_dist(c, "before", S, b"six", b"1.16.0", r)
    c.put("after", rec, reg(record_bytes(r) + b"six/\xff.py,sha256=X,1\n", gen=1))
    c.tag("probe.pip.E10_record_not_utf8")
    out.append(c)

    # P7 x E10: an unknown RECORD whose dist-info cannot be named, on one
    # side: named, so one provisional could_not_interpret. (On both sides it
    # is now the required cell pip.P7.unknown_unnameable_both_sides.)
    c = Case("probe-pip-unknown-unnameable-one-side", modes=BOTH)
    c.put("after", S + b"/nodash.dist-info/RECORD", reg(b"x,,\n", raced=True))
    put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
    c.tag("probe.pip.unknown_unnameable_one_side")
    out.append(c)
    # P7 x E10: an ambiguous name one of whose RECORDs is unknown
    c = Case("probe-pip-ambiguous-with-unknown", modes=BOTH)
    put_dist(c, "before", S, b"six", b"1.15.0", rand_rows(rng, b"six", b"1.15.0"))
    put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
    put_dist(c, "after", S, b"Six", b"1.17.0", rand_rows(rng, b"Six", b"1.17.0"), raced=True)
    c.tag("probe.pip.ambiguous_with_unknown")
    out.append(c)
    # E9 for pip: names and versions within 1,024 bytes, the text over it
    c = Case("probe-pip-e9-text-over-1024", modes=BOTH)
    long_name, v1, v2 = b"p" * 500, b"1." + b"0" * 300, b"2." + b"0" * 300
    put_dist(c, "before", S, long_name, v1, rand_rows(rng, b"p", v1))
    put_dist(c, "after", S, long_name, v2, rand_rows(rng, b"p", v2), gen=1)
    put_dist(c, "after", S, b"aaa", b"1.0", rand_rows(rng, b"aaa", b"1.0"))
    put_dist(c, "after", S, b"zzz", b"1.0", rand_rows(rng, b"zzz", b"1.0"))
    c.tag("probe.pip.E9_text_over_1024")
    out.append(c)
    # A dist-info that cannot be named, modified in place, a copy unavailable.
    # spec (E10): "nothing more is read from it" -- could_not_interpret on
    # its record and one event, no content_unavailable.
    c = Case("probe-pip-unnameable-unavailable")
    c.put("before", S + b"/nodash.dist-info/RECORD", reg(b"x,,\n"))
    c.put("after", S + b"/nodash.dist-info/RECORD", reg(b"x,,\ny,,\n", store="absent", gen=1))
    c.tag("probe.pip.unnameable_content_unavailable")
    out.append(c)

    c = Case("probe-pip-blank-line")
    put_dist(c, "before", S, b"six", b"1.16.0", r)
    c.put("after", rec, reg(record_bytes(r) + b"\nsix/x.py,sha256=X,1\n", gen=1))
    c.tag("probe.pip.blank_line_in_record")
    out.append(c)

    c = Case("probe-pip-root-dist-info")
    put_dist(c, "after", b"", b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
    c.tag("probe.pip.dist_info_at_scope_root")
    out.append(c)

    c = Case("probe-pip-pep440-edges")
    pairs = [(b"aa", b"1.0", b"1.0+local"), (b"bb", b"1.0.dev1", b"1.0a1"),
             (b"cc", b"1.0.post1", b"1.0-1"), (b"dd", b"1!0.1", b"9.9"),
             (b"ee", b"1.0rc1", b"1.0c1"), (b"ff", b"1.0+abc.5", b"1.0+abc.10"),
             (b"gg", b"1.0+5", b"1.0+abc"), (b"hh", b"V1.0", b"1.0"),
             (b"ii", b"1.0.0.0", b"1"), (b"jj", b"1.0a1.post2.dev3", b"1.0a1.post2"),
             (b"kk", b"1.0pre", b"1.0rc0"), (b"ll", b"1.0-r1", b"1.0.post1"),
             (b"mm", b"1.0+ABC", b"1.0+abc")]
    for n, v1, v2 in pairs:
        put_dist(c, "before", S, n, v1, rand_rows(rng, n, v1))
        put_dist(c, "after", S, n, v2, rand_rows(rng, n, v2), gen=1)
    c.tag("probe.pip.pep440_edges")
    out.append(c)

    c = Case("probe-pip-pep440-trailing-separator")
    for n, v1, v2 in [(b"aa", b"1.0", b"2a."), (b"bb", b"1.0", b"1.0.post."),
                      (b"cc", b"1.0", b"1.0rc--1"), (b"dd", b"1.0", b"1.0.dev-")]:
        put_dist(c, "before", S, n, v1, rand_rows(rng, n, v1))
        put_dist(c, "after", S, n, v2, rand_rows(rng, n, v2), gen=1)
    c.tag("probe.pip.pep440_trailing_separator")
    out.append(c)

    c = Case("probe-dpkg-e5-bound")
    many = status_bytes([b"Package: p%05d\nStatus: install ok installed\nVersion: 1\n" % i
                         for i in range(ref.EVENT_BOUND + 4)])
    c.put("after", sp, reg(many))
    c.tag("probe.dpkg.E5_bound")
    out.append(c)

    c = Case("probe-pip-at-bound")
    rows = []
    size = 0
    i = 0
    while True:
        row = "six/m%07d.py,sha256=%s,%d\n" % (i, "A" * 60, i)
        if size + len(row) > ref.PIP_BOUND - 200:
            break
        rows.append(row)
        size += len(row)
        i += 1
    head = "".join(rows).encode()
    pad = ref.PIP_BOUND - len(head) - len(b",sha256=Z,1\n")
    before = head + b"p" * pad + b",sha256=Z,1\n"
    after = head + b"p" * pad + b",sha256=Y,1\n"
    assert len(before) == ref.PIP_BOUND == len(after)
    rec = dist(S, b"six", b"1.16.0")[0]
    c.put("before", rec, reg(before))
    c.put("after", rec, reg(after, gen=1))
    assert i < ref.PIP_ROWS
    c.tag("probe.pip.record_at_bound")
    out.append(c)

    c = Case("probe-pip-rows-at-bound")
    rows = b"".join(b"r%06d,h,1\n" % i for i in range(ref.PIP_ROWS))
    rec = dist(S, b"six", b"1.16.0")[0]
    c.put("before", rec, reg(rows))
    c.put("after", rec, reg(rows.replace(b"r000007,h,1", b"r000007,g,1"), gen=1))
    c.tag("probe.pip.record_rows_at_bound")
    out.append(c)

    dpkg_pair("probe-dpkg-text-over-1024",
              status_bytes(base_db()),
              status_bytes(base_db() + [stanza(b"p" * 600, b"1." + b"0" * 500)]),
              "probe.dpkg.E9_event_text_over_1024")
    dpkg_pair("probe-dpkg-template-in-value",
              status_bytes(base_db() + [stanza(b"p{arch}q", b"1.0", arch=b"{version}")]),
              status_bytes(base_db() + [stanza(b"p{arch}q", b"2.0", arch=b"{version}")]),
              "probe.dpkg.template_text_in_value")

    c = Case("probe-dpkg-md5sums-elsewhere")
    c.put("after", b"etc/foo.md5sums", reg(b"0" * 32 + b"  x\n"))
    c.put("after", b"var/lib/dpkg/info/curl.md5sums", reg(b"0" * 32 + b"  y\n"))
    c.put("before", sp, reg(status_bytes(base_db())))
    c.put("after", sp, reg(status_bytes(base_db()) + b"no colon\n", gen=1))
    c.tag("probe.dpkg.md5sums_outside_info")
    out.append(c)
    return out


def required_cases():
    return (cell_dpkg_simple() + cell_pip_simple() + cell_pip_e10() + cell_dpkg_e9_e10()
            + cell_p7() + cell_e11() + cell_order() + cell_content_unavailable() + cell_paths_b64()
            + cell_git_reflog() + cell_git_events() + cell_git_unread() + cell_git_unparsed()
            + cell_git_reflog_gained() + cell_probes())


def all_cases(n, seed):
    rng = random.Random(seed)
    return required_cases() + [random_case(rng, i) for i in range(n)]
