#!/usr/bin/env python3
"""Deterministic corpus for the dpkg/pip reference (scripts/reference/).

A case is two trees, before and after, written as two manifest-v1 files plus
a store: copies at <store>/<first two hex of sha256>/<other 62>
(diff-v1, "Content"). Required cells are built by construction, one builder
each; random cases come from a seeded random.Random. Nothing here retries.

Each case says which modes it runs in ("store": belay_diff given the store;
"nostore": given none) and, per mode, the cells it was built to hit.
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
        unverified=False):
    """A regular file. store: ok | none (no `stored` field) | absent (named,
    not in the store) | corrupt (the object holds other bytes) | symlink (a
    symlink to a good copy sits at the object's name). big: a sparse, zero
    copy of that size instead of `content`. unverified: no hash, no copy,
    larger than hash_max_bytes."""
    return {"type": "reg", "content": content, "store": store, "big": big, "gen": gen,
            "raced": raced, "mode": mode, "unverified": unverified}


def lnk(target, gen=0):
    return {"type": "lnk", "target": target, "gen": gen, "mode": 0o120777, "raced": False}


class Case:
    def __init__(self, name, modes=("store",)):
        self.name = name
        self.before = {}
        self.after = {}
        self.modes = list(modes)
        self.tags = {m: set() for m in ("store", "nostore")}

    def tag(self, cell, mode=None):
        for m in ([mode] if mode else self.modes):
            self.tags[m].add(cell)

    def both(self, path, e):
        self.before[path] = e
        self.after[path] = e

    def put(self, side, path, e):
        (self.before if side == "before" else self.after)[path] = e


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


def complete(tree):
    """Adds every missing parent directory, and the root."""
    out = dict(tree)
    for p in list(tree):
        parts = p.split(b"/")
        for i in range(1, len(parts)):
            d = b"/".join(parts[:i])
            out.setdefault(d, {"type": "dir"})
    out.setdefault(b".", {"type": "dir"})
    return out


def entry_line(p, e, digest_of):
    t = e["type"]
    kv = [path_field(p), jkey("type", t)]
    if t == "dir":
        ino = 100 + crc(b"dir", p) % 1000000
        kv += [jkey("mode", 0o40755), jkey("uid", 0), jkey("gid", 0), jkey("size", 4096),
               jkey("mtime_ns", 1750000000000000000), jkey("ctime_ns", 1750000000000000000),
               jkey("ino", ino), jkey("dev", DEV), jkey("nlink", 2)]
        return b"{" + b",".join(kv) + b"}"
    if t == "lnk":
        size = len(e["target"])
        seed = crc(b"lnk", p, e["target"], e["gen"])
    else:
        if e["unverified"]:
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
           jkey("dev", DEV), jkey("nlink", 1)]
    if t == "reg":
        if sha is None:
            kv.append(jkey("unverified", True))
        else:
            kv.append(jkey("sha256", sha))
            if e["store"] != "none":
                kv.append(jkey("stored", sha))
    else:
        kv.append(jkey("link_target", e["target"]))
    if e.get("raced"):
        kv.append(jkey("raced", True))
    return b"{" + b",".join(kv) + b"}"


def write_manifest(fn, tree, created_ns, digest_of):
    t = complete(tree)
    lines = [b'{"belay_manifest":1,"created_ns":%d,"scopes":[%s],"hash":"sha256",'
             b'"hash_max_bytes":%d,"store_max_bytes":65536}' % (created_ns, ref.jstr(SCOPE), HASH_MAX)]
    for p in sorted(t):
        lines.append(entry_line(p, t[p], digest_of))
    raced = sum(1 for e in t.values() if e.get("raced"))
    lines.append(b'{"belay_manifest_end":%d,"vanished":0,"unreadable":0,"unstable":0,'
                 b'"mounts":0,"raced":%d}' % (len(t), raced))
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
    write_manifest(os.path.join(d, "before.ndjson"), case.before, 1761000000000000000, digest_of)
    write_manifest(os.path.join(d, "after.ndjson"), case.after, 1761000600000000000, digest_of)


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


def put_dist(case, side, site, name, version, rows, gen=0, store="ok", term="\r\n"):
    rec, meta = dist(site, name, version)
    case.put(side, rec, reg(record_bytes(rows, term), store=store, gen=gen))
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
    for root in roots:
        sp = root + b"var/lib/dpkg/status"
        db = rand_stanzas(rng, rng.randrange(0, 14))
        r = rng.random()
        if r < 0.1:
            c.put("before", sp, reg(render_db(db), store=rng.choice(store_choices)))
        elif r < 0.2:
            c.put("after", sp, reg(render_db(db), store=rng.choice(store_choices)))
        elif r < 0.25:
            c.both(sp, reg(render_db(db)))
        elif r < 0.28:
            c.put("before", sp, reg(render_db(db), store=rng.choice(store_choices)))
            c.put("after", sp, lnk(b"status-new"))
        else:
            c.put("before", sp, reg(render_db(db), store=rng.choice(store_choices)))
            c.put("after", sp, reg(render_db(mutate_db(rng, db)), gen=1,
                                    store=rng.choice(store_choices),
                                    raced=rng.random() < 0.03))
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
            op = rng.randrange(9)
            st = rng.choice(store_choices)
            if op == 0:
                put_dist(c, "after", site, name, v1, rows, store=st, term=term)
            elif op == 1:
                put_dist(c, "before", site, name, v1, rows, store=st, term=term)
            elif op == 2 and v1 != v2:
                put_dist(c, "before", site, name, v1, rows, store=st, term=term)
                spell = respell(rng, name)
                put_dist(c, "after", site, spell, v2, rand_rows(rng, spell, v2), gen=1,
                         store=rng.choice(store_choices), term=term)
            elif op == 3:
                put_dist(c, "before", site, name, v1, rows, store=st, term=term)
                put_dist(c, "after", site, name, v1, mutate_rows(rng, rows), gen=1,
                         store=rng.choice(store_choices), term=term)
            elif op == 4:                      # METADATA alone changes
                rec, meta = dist(site, name, v1)
                c.both(rec, reg(record_bytes(rows, term)))
                c.put("before", meta, reg(b"Name: " + name + b"\n"))
                c.put("after", meta, reg(b"Name: " + name + b"\nSummary: x\n", gen=1))
            elif op == 5:                      # a RECORD that raced: unknown, nothing
                rec, meta = dist(site, name, v1)
                c.put("before", rec, reg(record_bytes(rows, term)))
                c.put("after", rec, reg(record_bytes(mutate_rows(rng, rows), term), gen=1,
                                        raced=True))
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
    c.tag("random")
    return c


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


def cell_pip_e6():
    out = []
    S = SITES[0]
    rng = random.Random(77)
    for label, name, version in [("no-dash", b"nodash", None), ("empty-name", b"", b"1.0"),
                                 ("empty-version", b"foo", b""),
                                 ("bad-utf8-name", b"f\xffo", b"1.0")]:
        c = Case("pip-e6-unnameable-" + label)
        if version is None:
            di = S + b"/" + name + b".dist-info"
            c.put("after", di + b"/RECORD", reg(b"x,,\n"))
        else:
            put_dist(c, "after", S, name, version, rand_rows(rng, b"x", b"1"))
        put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
        c.tag("pip.E6.unnameable")
        out.append(c)
    c = Case("pip-e6-ambiguous")
    put_dist(c, "before", S, b"six", b"1.15.0", rand_rows(rng, b"six", b"1.15.0"))
    put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
    put_dist(c, "after", S, b"Six", b"1.17.0", rand_rows(rng, b"Six", b"1.17.0"))
    put_dist(c, "after", S, b"attrs", b"1.0", rand_rows(rng, b"attrs", b"1.0"))
    c.tag("pip.E6.ambiguous")
    out.append(c)
    c = Case("pip-e6-ambiguous-2r1a")
    put_dist(c, "before", S, b"six", b"1.15.0", rand_rows(rng, b"six", b"1.15.0"))
    put_dist(c, "before", S, b"SIX", b"1.14.0", rand_rows(rng, b"SIX", b"1.14.0"))
    put_dist(c, "after", S, b"six", b"1.16.0", rand_rows(rng, b"six", b"1.16.0"))
    c.tag("pip.E6.ambiguous")
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
    dpkg_pair("probe-dpkg-e6-no-colon",
              status_bytes(base_db()),
              status_bytes(base_db()) + b"garbage line\n",
              "probe.dpkg.E6_line_not_a_field")
    dpkg_pair("probe-dpkg-e6-bad-utf8-version",
              status_bytes(base_db()),
              status_bytes(base_db() + [stanza(b"bad", b"1.0\xff")]),
              "probe.dpkg.E6_value_not_string")
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

    c = Case("probe-dpkg-e6-paths")
    c.put("after", b"var/lib/dpkg/info/curl.list", reg(b"/usr/bin/curl\n"))
    c.put("before", sp, reg(status_bytes(base_db())))
    c.put("after", sp, reg(status_bytes(base_db()) + b"no colon\n", gen=1))
    c.put("before", b"x/var/lib/dpkg/status", reg(status_bytes(base_db())))
    c.put("after", b"x/var/lib/dpkg/status", reg(status_bytes(base_db()), raced=True, gen=1))
    c.tag("probe.dpkg.E6_paths_given")
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

    c = Case("probe-pip-e6-short-row")
    r = rand_rows(rng, b"six", b"1.16.0")
    put_dist(c, "before", S, b"six", b"1.16.0", r)
    rec = dist(S, b"six", b"1.16.0")[0]
    c.put("after", rec, reg(record_bytes(r) + b"six/short.py,sha256=X\n", gen=1))
    c.tag("probe.pip.E6_row_of_two_fields")
    out.append(c)

    c = Case("probe-pip-e6-not-utf8")
    put_dist(c, "before", S, b"six", b"1.16.0", r)
    c.put("after", rec, reg(record_bytes(r) + b"six/\xff.py,sha256=X,1\n", gen=1))
    c.tag("probe.pip.E6_record_not_utf8")
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
              "probe.dpkg.E6_event_text_over_1024")
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
    return (cell_dpkg_simple() + cell_pip_simple() + cell_pip_e6() + cell_content_unavailable()
            + cell_paths_b64() + cell_probes())


def all_cases(n, seed):
    rng = random.Random(seed)
    return required_cases() + [random_case(rng, i) for i in range(n)]
