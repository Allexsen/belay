#!/usr/bin/env python3
"""An independent reference for diff.v1's dpkg and pip interpreters.

Written from docs/spec/diff-v1.md ("Interpreters", "What each interpreter
reports", the Kinds table and the event rules), docs/spec/manifest-v1.md, the
pins test/expect/finding-kinds.md and test/expect/diff-events.md, and the
formats' own documentation: deb-control(5) and Debian Policy 5.6.12 for the
status database, PEP 376 / "Recording installed projects" for RECORD (rows as
Python's csv module reads them), PEP 503 for names and PEP 440 for versions
(implemented here from the PEP; no third-party package).

Given two manifests and a store directory (or none), it gives, for every path
the diff reports (outcome not `unchanged`), the outcome as this file reads
the rules, and for each path dpkg or pip claims the exact bytes of its
`findings` array (None when absent); then the pip and dpkg event records, in
order, byte for byte. Standard library only.

Where the prose is silent this file says so in a comment starting READING:
those are the readings implemented, listed again in the harness's report.
"""

import base64
import csv
import fnmatch
import hashlib
import io
import json
import os
import re
import stat

PIP_BOUND = 64 << 20        # spec: pip RECORD, 64 MiB
DPKG_BOUND = 256 << 20      # spec: dpkg status, 256 MiB
EVENT_BOUND = 65536         # E5
STRING_MAX = 1024           # a string field's value, and a finding's text

# The Kinds table, in its order (E4 sorts "kind" by it).
KINDS = [
    "could_not_interpret", "invalid_finding", "and_more", "content_unavailable",
    "text_changed", "text_rewritten", "text_added", "text_removed",
    "pip_installed", "pip_removed", "pip_upgraded", "pip_downgraded",
    "pip_version_changed", "pip_reinstalled",
    "dpkg_installed", "dpkg_removed", "dpkg_upgraded", "dpkg_downgraded",
    "dpkg_state_changed",
]
KIND_INDEX = {k: i for i, k in enumerate(KINDS)}

# fields, template
KIND_ROWS = {
    "could_not_interpret": ([], "could not interpret"),
    "and_more": (["n"], "and {n} more"),
    "content_unavailable": (["reason", "side"], "content unavailable ({side}): {reason}"),
    "pip_installed": (["name", "version"], "installed {name} {version}"),
    "pip_removed": (["name", "version"], "removed {name} {version}"),
    "pip_upgraded": (["name", "from", "to"], "upgraded {name} {from} -> {to}"),
    "pip_downgraded": (["name", "from", "to"], "downgraded {name} {from} -> {to}"),
    "pip_version_changed": (["name", "from", "to"], "{name} {from} -> {to}"),
    "pip_reinstalled": (["name", "version", "files_added", "files_removed", "files_changed"],
                        "reinstalled {name} {version}: +{files_added} -{files_removed} "
                        "~{files_changed} files"),
    "dpkg_installed": (["package", "arch", "version"], "installed {package}:{arch} {version}"),
    "dpkg_removed": (["package", "arch", "version"], "removed {package}:{arch} {version}"),
    "dpkg_upgraded": (["package", "arch", "from", "to"],
                      "upgraded {package}:{arch} {from} -> {to}"),
    "dpkg_downgraded": (["package", "arch", "from", "to"],
                        "downgraded {package}:{arch} {from} -> {to}"),
    "dpkg_state_changed": (["package", "arch", "from", "to"], "{package}:{arch} {from} -> {to}"),
}

# READING: the order of content_unavailable events of different reasons is not
# stated; they are ordered as the spec lists the reasons.
REASONS = ["no_store", "missing", "too_large", "corrupt"]

# Claims (diff-v1 "Which interpreter"): fnmatch on the absolute path, '*'
# spanning '/'. READING: the info/ patterns are taken as
# */var/lib/dpkg/info/*.list and */var/lib/dpkg/info/*.md5sums.
DPKG_STATUS = b"*/var/lib/dpkg/status"
DPKG_PATTERNS = [DPKG_STATUS, b"*/var/lib/dpkg/info/*.list", b"*/var/lib/dpkg/info/*.md5sums"]
PIP_RECORD = b"*.dist-info/RECORD"
PIP_PATTERNS = [PIP_RECORD, b"*.dist-info/METADATA"]


class InterpFailure(Exception):
    """The end hook fails (E6)."""


# ---------------------------------------------------------------- JSON

def utf8_ok(b):
    try:
        b.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return False
    return True


_SHORT = {0x22: b'\\"', 0x5C: b"\\\\", 0x08: b"\\b", 0x0C: b"\\f", 0x0A: b"\\n",
          0x0D: b"\\r", 0x09: b"\\t"}


def jstr(b):
    """A JSON string of valid UTF-8 bytes, as belay and the manifest write one:
    the short escapes where they exist, \\u00xx (lowercase) for other control
    bytes, every other byte as itself."""
    if isinstance(b, str):
        b = b.encode("utf-8")
    out = bytearray(b'"')
    for c in b:
        if c in _SHORT:
            out += _SHORT[c]
        elif c < 0x20:
            out += b"\\u%04x" % c
        else:
            out.append(c)
    out += b'"'
    return bytes(out)


def string_ok(b):
    """A string field's value: UTF-8, at most 1,024 bytes, no NUL."""
    return len(b) <= STRING_MAX and b"\0" not in b and utf8_ok(b)


def render(kind, values):
    fields, template = KIND_ROWS[kind]
    text = template
    for f in fields:
        v = values[f]
        text = text.replace("{" + f + "}", str(v) if isinstance(v, int) else v.decode("utf-8"))
    return text.encode("utf-8")


def fields_json(kind, values):
    fields, _ = KIND_ROWS[kind]
    parts = []
    for f in fields:
        v = values[f]
        parts.append(jstr(f) + b":" + (str(v).encode() if isinstance(v, int) else jstr(v)))
    return parts


def finding_json(kind, values):
    parts = [b'"kind":' + jstr(kind)] + fields_json(kind, values)
    parts.append(b'"text":' + jstr(render(kind, values)))
    return b"{" + b",".join(parts) + b"}"


def event_json(kind, interp, values, paths):
    parts = [b'"event":' + jstr(kind), b'"interp":' + jstr(interp)]
    parts += fields_json(kind, values)
    parts.append(b'"text":' + jstr(render(kind, values)))
    ps = sorted(set(paths))
    if all(utf8_ok(p) for p in ps):
        parts.append(b'"paths":[' + b",".join(jstr(p) for p in ps) + b"]")
    else:
        parts.append(b'"paths_b64":[' + b",".join(jstr(base64.b64encode(p)) for p in ps) + b"]")
    return b"{" + b",".join(parts) + b"}"


# ---------------------------------------------------------------- manifests

def entry_path(o):
    if "path" in o:
        return o["path"].encode("utf-8")
    return base64.b64decode(o["path_b64"], validate=True)


def read_manifest(fn):
    with open(fn, "rb") as f:
        lines = f.read().split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    header = json.loads(lines[0])
    if "scopes" in header:
        scope = header["scopes"][0].encode("utf-8")
    else:
        scope = base64.b64decode(header["scopes_b64"][0])
    entries = {}
    for line in lines[1:-1]:
        o = json.loads(line)
        entries[entry_path(o)] = o
    return scope, entries


def nearest_ancestor(entries, path):
    p = path
    while True:
        i = p.rfind(b"/")
        if i < 0:
            return entries.get(b".")
        p = p[:i]
        if p in entries:
            return entries[p]


def outcome(b, a, bents, aents, root_dev_b, root_dev_a):
    """The core's verdict for one path (diff-v1, "How an outcome is decided"),
    for the entries the corpus generates (no xattrs, caps or iflags)."""
    if b is None or a is None:
        has, lacking_entries = (a, bents) if b is None else (b, aents)
        anc = nearest_ancestor(lacking_entries, entry_path(has))
        if anc is not None:
            if anc["type"] == "dir" and (anc.get("unreadable") or anc.get("mount")):
                return "unknown"
            if anc["type"] == "dir" and anc.get("unstable"):
                return "unknown"
            if anc["type"] != "dir" and anc.get("raced"):
                return "unknown"
        if has.get("raced"):
            return "unknown"
        return "added" if b is None else "removed"
    if b.get("raced") or a.get("raced"):
        return "unknown"
    if b["type"] != a["type"]:
        return "type_changed"
    t = b["type"]
    proof = False
    if t in ("reg", "lnk") and b["size"] != a["size"]:
        proof = True
    if t == "reg" and "sha256" in b and "sha256" in a and b["sha256"] != a["sha256"]:
        proof = True
    if t == "lnk" and not b.get("unreadable") and not a.get("unreadable"):
        if b.get("link_target", b.get("link_target_b64")) != a.get("link_target", a.get("link_target_b64")):
            proof = True
    if t in ("blk", "chr") and b.get("rdev") != a.get("rdev"):
        proof = True
    if proof:
        return "modified"
    for side in (b, a):
        for fl in ("unverified", "unstable", "unreadable", "mount"):
            if side.get(fl):
                return "unknown"
    meta = ["mode", "uid", "gid"]
    if t in ("reg", "lnk") and not (b.get("mount") or a.get("mount")):
        meta.append("mtime_ns")
    if t != "dir":
        meta.append("nlink")
    if any(b[k] != a[k] for k in meta):
        return "metadata_only"
    if (b["dev"] == root_dev_b) != (a["dev"] == root_dev_a):
        return "metadata_only"
    if b["dev"] == a["dev"] and root_dev_b == root_dev_a and b["ino"] != a["ino"]:
        return "metadata_only"
    if t in ("reg", "lnk") and b["ctime_ns"] != a["ctime_ns"]:
        return "metadata_only"
    return "unchanged"


def claim(scope, path):
    absp = scope + b"/" + path
    for p in DPKG_PATTERNS:
        if fnmatch.fnmatchcase(absp, p):
            return "dpkg"
    for p in PIP_PATTERNS:
        if fnmatch.fnmatchcase(absp, p):
            return "pip"
    return None


# ---------------------------------------------------------------- content

def fetch(store, entry, bound):
    """(reason, None) or (None, bytes): the stored copy of one side."""
    if store is None:
        # READING: with no store every needed copy is `no_store`, even one
        # whose entry records no `stored` copy.
        return "no_store", None
    s = entry.get("stored")
    if not s:
        return "missing", None
    p = os.path.join(store, s[:2], s[2:])
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return "missing", None
    if not stat.S_ISREG(st.st_mode):
        return "corrupt", None
    if st.st_size > bound:
        return "too_large", None
    with open(p, "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != s:
        return "corrupt", None
    return None, data


def is_reg(e):
    return e is not None and e["type"] == "reg"


PROVEN = ("added", "removed", "modified", "type_changed")


def needed_copies(store, b, a, bound, need_before, need_after):
    """Reads the sides needed; returns (findings, unavailable list of
    (side, reason), contents dict)."""
    findings = []
    unavailable = []
    contents = {}
    for side, e, need in (("before", b, need_before), ("after", a, need_after)):
        if not need:
            continue
        reason, data = fetch(store, e, bound)
        if reason:
            # READING: one finding per side, before's first.
            findings.append(finding_json("content_unavailable",
                                         {"reason": reason.encode(), "side": side.encode()}))
            unavailable.append((side, reason))
        else:
            contents[side] = data
    return findings, unavailable, contents


def unavailable_events(interp, unav):
    """One content_unavailable event per reason: side before/after when every
    (path, side) of that reason shares it, else both."""
    out = []
    for reason in REASONS:
        items = [(p, s) for (p, s, r) in unav if r == reason]
        if not items:
            continue
        sides = {s for _, s in items}
        side = sides.pop() if len(sides) == 1 else "both"
        out.append(((-1, KIND_INDEX["content_unavailable"], REASONS.index(reason)),
                    event_json("content_unavailable", interp,
                               {"reason": reason.encode(), "side": side.encode()},
                               [p for p, _ in items])))
    return out


def bound_events(interp, events):
    """E5. "At most 65,536 event records per interpreter" and (diff-v1,
    Interpreters) "past that, the last place is one and_more counting the
    rest": the and_more is the 65,536th record."""
    if len(events) <= EVENT_BOUND:
        return events
    keep = EVENT_BOUND - 1
    return events[:keep] + [event_json("and_more", interp, {"n": len(events) - keep}, [])]


# ---------------------------------------------------------------- dpkg

def deb_order(c):
    if c is None:
        return 0
    if 0x30 <= c <= 0x39:
        return 0
    if 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A:
        return c
    if c == 0x7E:   # ~
        return -1
    return c + 256


def verrevcmp(a, b):
    """Debian Policy 5.6.12: alternating non-digit and digit parts."""
    i = j = 0
    la, lb = len(a), len(b)

    def isdig(s, k):
        return k < len(s) and 0x30 <= s[k] <= 0x39

    while i < la or j < lb:
        first_diff = 0
        while (i < la and not isdig(a, i)) or (j < lb and not isdig(b, j)):
            ac = deb_order(a[i] if i < la else None)
            bc = deb_order(b[j] if j < lb else None)
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < la and a[i] == 0x30:
            i += 1
        while j < lb and b[j] == 0x30:
            j += 1
        while isdig(a, i) and isdig(b, j):
            if not first_diff:
                first_diff = a[i] - b[j]
            i += 1
            j += 1
        if isdig(a, i):
            return 1
        if isdig(b, j):
            return -1
        if first_diff:
            return first_diff
    return 0


def deb_split(v):
    epoch = 0
    rest = v
    c = v.find(b":")
    if c >= 0:
        epoch = int(v[:c]) if v[:c] else 0
        rest = v[c + 1:]
    h = rest.rfind(b"-")
    if h >= 0:
        return epoch, rest[:h], rest[h + 1:]
    return epoch, rest, b""


def deb_compare(x, y):
    ex, ux, rx = deb_split(x)
    ey, uy, ry = deb_split(y)
    if ex != ey:
        return -1 if ex < ey else 1
    r = verrevcmp(ux, uy)
    if r:
        return r
    return verrevcmp(rx, ry)


def parse_status(data):
    """deb-control(5) stanzas: {lowercased field name: value}, values with
    surrounding blanks stripped; continuation lines (starting with a space or
    tab) extend the field before them. Raises InterpFailure on a line that is
    neither."""
    stanzas = []
    cur = None
    last = None
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for line in lines:
        if line == b"":
            if cur is not None:
                stanzas.append(cur)
            cur = None
            last = None
            continue
        if line[:1] in (b" ", b"\t"):
            if cur is None or last is None:
                raise InterpFailure("continuation line with no field")
            cur[last] = cur[last] + b"\n" + line
            continue
        c = line.find(b":")
        if c <= 0:
            raise InterpFailure("not a field: %r" % line[:40])
        name = line[:c].lower()
        if cur is None:
            cur = {}
        if name in cur:
            # READING: a field repeated in one stanza; deb822 forbids it.
            # Never generated.
            raise InterpFailure("field repeated")
        cur[name] = line[c + 1:].strip(b" \t")
        last = name
    if cur is not None:
        stanzas.append(cur)
    for st in stanzas:
        for f in (b"package", b"architecture", b"version", b"status"):
            if b"\n" in st.get(f, b""):
                # Debian Policy 5.1: these are simple fields, whose folding is
                # not permitted (and dpkg rejects a version with a blank).
                raise InterpFailure("simple field %r folded" % f)
    db = {}
    for st in stanzas:
        key = (st.get(b"package", b""), st.get(b"architecture", b""))
        if key not in db:          # the first stanza of a key is kept
            db[key] = st
    return db


def deb_installed(st):
    if st is None:
        return False
    words = [w for w in re.split(rb"[ \t]+", st.get(b"status", b"")) if w]
    return len(words) >= 3 and words[2] == b"installed"


def dpkg_events_for(path, before, after):
    """Events of one status path, as (sort key, kind, values)."""
    bdb = parse_status(before) if before is not None else {}
    adb = parse_status(after) if after is not None else {}
    out = []
    for key in set(bdb) | set(adb):
        b = bdb.get(key)
        a = adb.get(key)
        bi = deb_installed(b)
        ai = deb_installed(a)
        pkg, arch = key
        evs = []
        covered = False
        if ai and not bi:
            evs.append(("dpkg_installed", {"package": pkg, "arch": arch,
                                           "version": a.get(b"version", b"")}))
            covered = True
        elif bi and not ai:
            evs.append(("dpkg_removed", {"package": pkg, "arch": arch,
                                         "version": b.get(b"version", b"")}))
            covered = True
        elif bi and ai:
            vb = b.get(b"version", b"")
            va = a.get(b"version", b"")
            c = deb_compare(vb, va)
            if c < 0:
                evs.append(("dpkg_upgraded", {"package": pkg, "arch": arch, "from": vb, "to": va}))
            elif c > 0:
                evs.append(("dpkg_downgraded", {"package": pkg, "arch": arch, "from": vb, "to": va}))
        sb = b.get(b"status", b"") if b is not None else b""
        sa = a.get(b"status", b"") if a is not None else b""
        if sb != sa and not covered:
            evs.append(("dpkg_state_changed", {"package": pkg, "arch": arch, "from": sb, "to": sa}))
        for kind, vals in evs:
            for v in vals.values():
                if not string_ok(v):
                    raise InterpFailure("value not a string field's value")
            out.append(((pkg, arch, KIND_INDEX[kind], path), kind, vals))
    return out


# ---------------------------------------------------------------- pip

_PEP440 = re.compile(r"""
    ^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""", re.VERBOSE | re.IGNORECASE | re.ASCII)


def pep440_key(v):
    """PEP 440's ordering as a sortable key, or None when `v` is not a PEP 440
    version."""
    m = _PEP440.match(v)
    if not m:
        return None
    epoch = int(m.group("epoch") or 0)
    release = [int(x) for x in m.group("release").split(".")]
    while release and release[-1] == 0:
        release.pop()
    pre = None
    if m.group("pre_l"):
        l = m.group("pre_l").lower()
        l = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}.get(l, l)
        pre = (l, int(m.group("pre_n") or 0))
    post = None
    if m.group("post_n1") is not None:
        post = int(m.group("post_n1"))
    elif m.group("post_l"):
        post = int(m.group("post_n2") or 0)
    dev = int(m.group("dev_n") or 0) if m.group("dev_l") else None
    local = None
    if m.group("local") is not None:
        local = tuple((1, int(s), "") if s.isdigit() else (0, 0, s.lower())
                      for s in re.split(r"[-_.]", m.group("local")))
    if pre is None and post is None and dev is not None:
        pre_k = (0,)
    elif pre is None:
        pre_k = (2,)
    else:
        pre_k = (1,) + pre
    post_k = (0,) if post is None else (1, post)
    dev_k = (2,) if dev is None else (1, dev)
    local_k = (0,) if local is None else (1, local)
    return (epoch, tuple(release), pre_k, post_k, dev_k, local_k)


def pep503(name):
    return re.sub(rb"[-_.]+", b"-", name.lower())


def dist_info(path):
    """(directory holding the dist-info, name, version) of a RECORD path."""
    parent = path[:path.rfind(b"/")] if b"/" in path else b""
    i = parent.rfind(b"/")
    holder, base = (parent[:i], parent[i + 1:]) if i >= 0 else (b"", parent)
    stem = base[:-len(b".dist-info")]
    d = stem.find(b"-")
    if d < 0:
        raise InterpFailure("dist-info name has no '-'")
    name, version = stem[:d], stem[d + 1:]
    if not name or not version or not string_ok(name) or not string_ok(version):
        raise InterpFailure("dist-info cannot be named")
    return holder, name, version


def record_rows(data):
    """RECORD's rows by path, the first row of a path kept: {path: (hash, size)}.
    READING: content that is not UTF-8, a csv error, or a row of fewer than
    three fields is a RECORD that cannot be parsed; never generated except
    by the probes that say so."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise InterpFailure("RECORD not UTF-8")
    rows = {}
    try:
        for row in csv.reader(io.StringIO(text, newline="")):
            if not row:
                continue
            if len(row) < 3:
                raise InterpFailure("RECORD row of %d fields" % len(row))
            if row[0] not in rows:
                rows[row[0]] = (row[1], row[2])
    except csv.Error as e:
        raise InterpFailure("RECORD csv: %s" % e)
    return rows


# ---------------------------------------------------------------- the diff

class Result:
    def __init__(self):
        self.outcomes = {}      # path -> outcome, every path not unchanged
        self.claims = {}        # path -> "pip" | "dpkg" for those
        self.findings = {}      # path -> bytes of the findings array, or None
        self.events = []        # event lines (bytes), pip's then dpkg's
        self.failed = {}        # interp -> reason of an E6 failure


def interpret(before_fn, after_fn, store):
    scope_b, bents = read_manifest(before_fn)
    scope_a, aents = read_manifest(after_fn)
    assert scope_b == scope_a, "the corpus never pairs manifests of different scopes"
    scope = scope_b
    root_dev_b = bents[b"."]["dev"]
    root_dev_a = aents[b"."]["dev"]
    res = Result()

    given = {"pip": [], "dpkg": []}
    unav = {"pip": [], "dpkg": []}      # (path, side, reason)
    dpkg_jobs = []                      # (path, before bytes|None, after bytes|None)
    pip_pairs = {}                      # (holder, normalized) -> {"A": [...], "R": [...]}
    pip_reinst = []                     # (path, before bytes, after bytes)
    pip_names = []                      # RECORD paths to name

    for path in sorted(set(bents) | set(aents)):
        b = bents.get(path)
        a = aents.get(path)
        oc = outcome(b, a, bents, aents, root_dev_b, root_dev_a)
        if oc == "unchanged":
            continue
        res.outcomes[path] = oc
        who = claim(scope, path)
        if who is None:
            continue
        res.claims[path] = who
        given[who].append(path)
        findings = []
        absp = scope + b"/" + path
        # "A side on which the path is not a regular file counts as absent";
        # only a proven change of content is described.
        breg = is_reg(b)
        areg = is_reg(a)
        if oc in PROVEN and who == "dpkg" and fnmatch.fnmatchcase(absp, DPKG_STATUS) \
                and (breg or areg):
            findings, u, contents = needed_copies(store, b, a, DPKG_BOUND, breg, areg)
            unav["dpkg"] += [(path, s, r) for s, r in u]
            if not u:
                dpkg_jobs.append((path, contents.get("before"), contents.get("after")))
            # READING: a status one of whose needed sides cannot be read gives
            # no package events (only content_unavailable); its readable side
            # is not parsed.
        elif oc in PROVEN and who == "pip" and fnmatch.fnmatchcase(absp, PIP_RECORD) \
                and (breg or areg):
            pip_names.append(path)
            if breg and areg:
                findings, u, contents = needed_copies(store, b, a, PIP_BOUND, True, True)
                unav["pip"] += [(path, s, r) for s, r in u]
                if not u:
                    pip_reinst.append((path, contents["before"], contents["after"]))
            else:
                pip_pairs.setdefault(path, "A" if areg else "R")
        res.findings[path] = (b"[" + b",".join(findings) + b"]") if findings else None

    # ---- pip end hook
    pip_events = []
    try:
        named = {}
        for path in pip_names:
            named[path] = dist_info(path)
        keys = {}
        for path, side in pip_pairs.items():
            holder, name, version = named[path]
            k = keys.setdefault((holder, pep503(name)), {"A": [], "R": []})
            k[side].append(path)
        for (holder, norm), k in keys.items():
            A, R = sorted(k["A"]), sorted(k["R"])
            if A and R and len(A) + len(R) > 2:
                raise InterpFailure("more than one RECORD added and removed for one key")
            if len(A) == 1 and len(R) == 1:
                _, name, to = named[A[0]]
                _, _, frm = named[R[0]]
                kb = pep440_key(frm.decode("utf-8"))
                ka = pep440_key(to.decode("utf-8"))
                if kb is None or ka is None or kb == ka:
                    kind = "pip_version_changed"
                elif ka > kb:
                    kind = "pip_upgraded"
                else:
                    kind = "pip_downgraded"
                pip_events.append(((0, norm, KIND_INDEX[kind], holder, A[0]),
                                   event_json(kind, "pip", {"name": name, "from": frm, "to": to},
                                              [A[0], R[0]])))
                continue
            for p in A:
                _, name, version = named[p]
                pip_events.append(((0, norm, KIND_INDEX["pip_installed"], holder, p),
                                   event_json("pip_installed", "pip",
                                              {"name": name, "version": version}, [p])))
            for p in R:
                _, name, version = named[p]
                pip_events.append(((0, norm, KIND_INDEX["pip_removed"], holder, p),
                                   event_json("pip_removed", "pip",
                                              {"name": name, "version": version}, [p])))
        for path, before, after in pip_reinst:
            holder, name, version = named[path]
            rb = record_rows(before)
            ra = record_rows(after)
            added = sum(1 for p in ra if p not in rb)
            removed = sum(1 for p in rb if p not in ra)
            changed = sum(1 for p in ra if p in rb and ra[p] != rb[p])
            pip_events.append(((0, pep503(name), KIND_INDEX["pip_reinstalled"], holder, path),
                               event_json("pip_reinstalled", "pip",
                                          {"name": name, "version": version,
                                           "files_added": added, "files_removed": removed,
                                           "files_changed": changed}, [path])))
        pip_events += unavailable_events("pip", unav["pip"])
        # READING: past name, kind and directory, events are ordered by the
        # first path they list.
        pip_events = [e for _, e in sorted(pip_events, key=lambda x: x[0])]
    except InterpFailure as e:
        res.failed["pip"] = str(e)
        pip_events = [event_json("could_not_interpret", "pip", {}, given["pip"])]

    # ---- dpkg end hook
    dpkg_events = []
    try:
        evs = []
        for path, before, after in dpkg_jobs:
            evs += dpkg_events_for(path, before, after)
        evs.sort(key=lambda x: x[0])
        dpkg_events = [e for _, e in sorted(unavailable_events("dpkg", unav["dpkg"]))]
        dpkg_events += [event_json(kind, "dpkg", vals, [k[3]]) for k, kind, vals in evs]
    except InterpFailure as e:
        res.failed["dpkg"] = str(e)
        dpkg_events = [event_json("could_not_interpret", "dpkg", {}, given["dpkg"])]

    res.events = bound_events("pip", pip_events) + bound_events("dpkg", dpkg_events)
    return res


if __name__ == "__main__":
    import sys
    if len(sys.argv) not in (3, 4):
        sys.exit("usage: ref.py before.ndjson after.ndjson [store]")
    r = interpret(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None)
    for p, f in sorted(r.findings.items()):
        if f is not None:
            print(p, f.decode())
    for e in r.events:
        print(e.decode())
