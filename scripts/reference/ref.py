#!/usr/bin/env python3
"""An independent reference for diff.v1's dpkg and pip interpreters, and
git's refs, reflogs and repository-level events.

Written from docs/spec/diff-v1.md ("Interpreters", "What each interpreter
reports", the Kinds table and the event rules, "Present on one side only"),
docs/spec/manifest-v1.md, docs/spec/manifest-v2.md (its `excluded`), the
pins test/expect/finding-kinds.md, test/expect/diff-events.md (E12 for git's
events) and test/expect/manifest-v2.md, and the
formats' own documentation: deb-control(5) and Debian Policy 5.6.12 for the
status database, PEP 376 / "Recording installed projects" for RECORD (rows as
Python's csv module reads them), PEP 503 for names and PEP 440 for versions
(implemented here from the PEP; no third-party package), and git's own file
formats for a loose ref, `HEAD`, `packed-refs` and a reflog.

Given two manifests and a store directory (or none), it gives, for every path
the diff reports (outcome not `unchanged`), the outcome as this file reads
the rules, and for each path dpkg, pip or git claims the exact bytes of its
`findings` array (None when absent); then the pip, dpkg and git event
records, in order, byte for byte. Of git, `HEAD`, `packed-refs`, the loose
refs and the reflogs are modelled ("What each interpreter reports", git;
E12); its hooks and index are not claimed here. Standard library only.

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

PIP_BOUND = 16 << 20        # spec: pip RECORD, 16 MiB ...
PIP_ROWS = 262144           # ... and 262,144 rows
DPKG_BOUND = 256 << 20      # spec: dpkg status, 256 MiB
GIT_REF_BOUND = 64 << 10   # spec: git, `HEAD`, a loose ref, 64 KiB
GIT_PACKED_BOUND = 64 << 20  # spec: git, `packed-refs`, 64 MiB
# spec (bounds table): git, a reflog, "16 MiB: a capture keeps a reflog up to
# this whatever `store_max_bytes` says, and a side recorded without a copy
# because it is larger is `content_unavailable`, reason `too_large`". The
# same 16 MiB bounds the copy read.
REFLOG_BOUND = 16 << 20
FINDINGS_MAX = 4096         # "A record carries at most 4,096 findings"
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
    "git_head_changed", "git_ref_created", "git_ref_deleted", "git_ref_moved",
    # git's hook and index kinds are not modelled; the rest keep the table's
    # order.
    "git_reflog_appended", "git_reflog_move", "git_reflog_rewritten",
    "git_head_switched", "git_branch_created", "git_branch_deleted", "git_branch_renamed",
    "git_commits_added", "git_history_rewritten", "git_branch_moved",
]
KIND_INDEX = {k: i for i, k in enumerate(KINDS)}

# fields, template
KIND_ROWS = {
    "could_not_interpret": ([], "could not interpret"),
    "invalid_finding": ([], "invalid finding"),
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
    "git_reflog_appended": (["ref", "entries"], "{ref}: {entries} reflog entries"),
    "git_reflog_move": (["ref", "from", "to", "operation"], "{ref} {from} -> {to} by {operation}"),
    "git_reflog_rewritten": (["ref"], "{ref}: reflog rewritten"),
    "git_head_changed": (["from", "to"], "HEAD {from} -> {to}"),
    "git_ref_created": (["ref", "to"], "created {ref} at {to}"),
    "git_ref_deleted": (["ref", "from"], "deleted {ref} (was {from})"),
    "git_ref_moved": (["ref", "from", "to"], "{ref} {from} -> {to}"),
    "git_head_switched": (["repo", "from", "to"], "HEAD {from} -> {to}"),
    "git_branch_created": (["repo", "branch", "at"], "branch {branch} created at {at}"),
    "git_branch_deleted": (["repo", "branch", "was"], "branch {branch} deleted (was {was})"),
    "git_branch_renamed": (["repo", "from", "to", "at"], "branch {from} renamed to {to}"),
    "git_commits_added": (["repo", "branch", "count", "to"],
                          "commits added to {branch}: {count}, now at {to}"),
    "git_history_rewritten": (["repo", "branch", "how", "from", "to"],
                              "{branch} rewritten by {how}: {from} -> {to}"),
    "git_branch_moved": (["repo", "branch", "from", "to"], "{branch} {from} -> {to}"),
}

# The optional fields (`?`) and the second template a kind gives, used when
# any of them is absent (finding-kinds.md, "The object"). An absent field is
# one missing from the values; it never appears in the object.
OPTIONAL = {
    "pip_reinstalled": (["files_added", "files_removed", "files_changed"],
                        "reinstalled {name} {version} (files not counted)"),
    "git_commits_added": (["count"], "commits added to {branch}, now at {to}"),
    "git_branch_moved": (["from"], "{branch} now at {to}"),
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
# git claims "`*/.git/HEAD`, `*/.git/packed-refs`, `*/.git/refs/*`,
# `*/.git/hooks/*`, `*/.git/index` and the reflogs `*/.git/logs/HEAD` and
# `*/.git/logs/refs/*`"; hooks and the index are not modelled (the corpus
# builds none, and they are not claimed here, so their records are not
# compared). READING: no path the corpus builds is claimed by two
# interpreters, so the order of these checks is not tested.
GIT_PATTERNS = [b"*/.git/HEAD", b"*/.git/packed-refs", b"*/.git/refs/*",
                b"*/.git/logs/HEAD", b"*/.git/logs/refs/*"]


class InterpFailure(Exception):
    """A file the interpreter claims cannot be interpreted (E10)."""


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
    """The template with each {field} replaced by its value, in one pass: a
    value that itself holds "{...}" is not replaced again."""
    fields, template = KIND_ROWS[kind]
    if any(f not in values for f in fields):
        optional, template = OPTIONAL[kind]
        assert all(f in values or f in optional for f in fields)

    def one(m):
        v = values[m.group(1)]
        return str(v) if isinstance(v, int) else v.decode("utf-8")
    return re.sub(r"\{([a-z_]+)\}", one, template).encode("utf-8")


def fields_json(kind, values):
    fields, _ = KIND_ROWS[kind]
    parts = []
    for f in fields:
        if f not in values:
            continue                    # an optional field, absent
        v = values[f]
        parts.append(jstr(f) + b":" + (str(v).encode() if isinstance(v, int) else jstr(v)))
    return parts


def finding_json(kind, values):
    parts = [b'"kind":' + jstr(kind)] + fields_json(kind, values)
    parts.append(b'"text":' + jstr(render(kind, values)))
    return b"{" + b",".join(parts) + b"}"


def event_json(kind, interp, values, paths, provisional=False):
    """E2: provisional (after text, before paths) when a path the event was
    derived from has the outcome unknown."""
    parts = [b'"event":' + jstr(kind), b'"interp":' + jstr(interp)]
    parts += fields_json(kind, values)
    parts.append(b'"text":' + jstr(render(kind, values)))
    if provisional:
        parts.append(b'"provisional":true')
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
    """(scope, entries by path, excluded): excluded is None for a v1
    manifest, else its header's `excluded` array as parsed (manifest-v2.md,
    V2-2), in its order."""
    with open(fn, "rb") as f:
        lines = f.read().split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    header = json.loads(lines[0])
    if "scopes" in header:
        scope = header["scopes"][0].encode("utf-8")
    else:
        scope = base64.b64decode(header["scopes_b64"][0])
    excluded = header["excluded"] if header["belay_manifest"] == 2 else None
    entries = {}
    for line in lines[1:-1]:
        o = json.loads(line)
        entries[entry_path(o)] = o
    return scope, entries, excluded


def excluded_paths(excluded):
    return [entry_path(x) for x in (excluded or [])]


def under(path, top):
    """path is top, or below it."""
    return path == top or path.startswith(top + b"/")


def nearest_ancestor(entries, path):
    p = path
    while True:
        i = p.rfind(b"/")
        if i < 0:
            return entries.get(b".")
        p = p[:i]
        if p in entries:
            return entries[p]


def outcome(b, a, bents, aents, root_dev_b, root_dev_a, bexcl=(), aexcl=()):
    """The core's verdict for one path (diff-v1, "How an outcome is decided"),
    for the entries the corpus generates (no xattrs, caps or iflags), as
    (outcome, reason): the reason is the one-sided case's one reason when
    the outcome is unknown there, else None.

    READING: `not_captured` comes only from "Present on one side only" (its
    first two rules). On a path present on both sides an unknown outcome's
    reasons are its flags' ("the reasons of every flag on either side"):
    `mount` is named as its own reason, and no flag is said to give
    `not_captured`, so a two-sided path is never E11's."""
    if b is None or a is None:
        has, lacking_entries, lacking_excl = (a, bents, bexcl) if b is None else (b, aents, aexcl)
        p = entry_path(has)
        # "The first of these that applies decides:"
        # 1. the lacking side excluded the path, or a path above it
        if any(under(p, x) for x in lacking_excl):
            return "unknown", "not_captured"
        anc = nearest_ancestor(lacking_entries, p)
        if anc is not None:
            # 2. that ancestor a directory carrying unreadable or mount
            if anc["type"] == "dir" and (anc.get("unreadable") or anc.get("mount")):
                return "unknown", "not_captured"
            # 3. a directory carrying unstable
            if anc["type"] == "dir" and anc.get("unstable"):
                return "unknown", "listing_incomplete"
            # 4. not a directory, carrying raced
            if anc["type"] != "dir" and anc.get("raced"):
                return "unknown", "raced"
        # 5. the absence known; raced on the side that has it
        if has.get("raced"):
            return "unknown", "raced"
        return ("added" if b is None else "removed"), None
    return two_sided(b, a, root_dev_b, root_dev_a), None


def two_sided(b, a, root_dev_b, root_dev_a):
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
    for p in GIT_PATTERNS:
        if fnmatch.fnmatchcase(absp, p):
            return "git"
    return None


# ---------------------------------------------------------------- content

def record_row_count(data):
    """RECORD's rows, for its bound. READING: the rows csv.reader yields
    that are not empty (a blank line is no row); content that is not UTF-8
    has no count here (it cannot be parsed, which record_rows says)."""
    try:
        text = data.decode("utf-8")
        return sum(1 for r in csv.reader(io.StringIO(text, newline="")) if r)
    except (UnicodeDecodeError, csv.Error):
        return 0


def fetch(store, entry, bound, rows_max=None, nocopy_too_large=False):
    """(reason, None) or (None, bytes): the stored copy of one side.
    nocopy_too_large: a reflog, kept by a capture up to `bound` whatever
    store_max_bytes says."""
    s = entry.get("stored")
    # spec: "`missing` covers a path whose entry records no `stored` copy (a
    # reflog over its 16 MiB bound excepted: `too_large`) as well as a copy
    # the store lacks, and is given before `no_store` when both apply".
    # READING: the reflog's too_large, which stands in that clause for
    # `missing`, is given before `no_store` too: like `missing` it is known
    # from the manifest alone. "Over" is strictly larger than the bound, the
    # entry's `size` its size (an unverified entry included: it has a size
    # and no copy).
    if not s:
        if nocopy_too_large and entry["size"] > bound:
            return "too_large", None
        return "missing", None
    if store is None:
        return "no_store", None
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
    if rows_max is not None and record_row_count(data) > rows_max:
        return "too_large", None
    return None, data


def is_reg(e):
    return e is not None and e["type"] == "reg"


PROVEN = ("added", "removed", "modified", "type_changed")


def needed_copies(store, b, a, bound, need_before, need_after, rows_max=None,
                  nocopy_too_large=False):
    """Reads the sides needed; returns (findings, unavailable list of
    (side, reason), contents dict)."""
    findings = []
    unavailable = []
    contents = {}
    for side, e, need in (("before", b, need_before), ("after", a, need_after)):
        if not need:
            continue
        reason, data = fetch(store, e, bound, rows_max, nocopy_too_large)
        if reason:
            # spec: before's finding first, then after's.
            findings.append(finding_json("content_unavailable",
                                         {"reason": reason.encode(), "side": side.encode()}))
            unavailable.append((side, reason))
        else:
            contents[side] = data
    return findings, unavailable, contents


def unavailable_events(interp, unav, unknown):
    """One content_unavailable event per reason: side before/after when every
    (path, side) of that reason shares it, else both. They have no name: key
    (-1, its kind, the reason's place)."""
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
                               [p for p, _ in items],
                               any(p in unknown for p, _ in items))))
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
            out.append(((0, pkg, arch, KIND_INDEX[kind], path), kind, vals, [path]))
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


def nameable(path):
    try:
        dist_info(path)
    except InterpFailure:
        return False
    return True


def record_rows(data):
    """RECORD's rows by path, the first row of a path kept: {path: (hash, size)}.
    spec: content that is not UTF-8, or a row of other than three fields,
    cannot be parsed. READING: a csv error is one too."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise InterpFailure("RECORD not UTF-8")
    rows = {}
    try:
        for row in csv.reader(io.StringIO(text, newline="")):
            if not row:
                continue
            if len(row) != 3:
                raise InterpFailure("RECORD row of %d fields" % len(row))
            if row[0] not in rows:
                rows[row[0]] = (row[1], row[2])
    except csv.Error as e:
        raise InterpFailure("RECORD csv: %s" % e)
    return rows


# ---------------------------------------------------------------- git: paths

def git_fits(rest):
    """The part after a `.git/` that one of git's claims takes."""
    return (rest in (b"HEAD", b"packed-refs", b"index", b"logs/HEAD")
            or (rest.startswith(b"refs/") and len(rest) > 5)
            or (rest.startswith(b"hooks/") and len(rest) > 6)
            or (rest.startswith(b"logs/refs/") and len(rest) > 10))


def git_place(scope, path):
    """(repo, rest). spec: "A path is placed by the part after its `.git/`
    (the last one that fits)"; E12: "per repository (a directory named
    `.git`; `repo` its path in the scope)". READING: `repo` is the path of
    that directory itself (`proj/.git`; `.git` at the scope's root), not the
    work tree holding it: the pin calls the repository "a directory named
    `.git`" and `repo` "its path"."""
    absp = scope + b"/" + path
    starts = [i for i in range(len(absp)) if absp.startswith(b"/.git/", i)]
    for i in reversed(starts):
        rest = absp[i + len(b"/.git/"):]
        if git_fits(rest):
            return absp[len(scope) + 1:i + len(b"/.git")], rest
    raise AssertionError("not git's: %r" % path)


def git_role(rest):
    if rest == b"HEAD":
        return "HEAD"
    if rest == b"packed-refs":
        return "packed"
    if rest.startswith(b"refs/"):
        return "ref"
    if rest == b"logs/HEAD" or rest.startswith(b"logs/refs/"):
        return "reflog"
    return None                         # hooks, index: not modelled


_HEX = frozenset(b"0123456789abcdef")


def is_oid(v):
    return len(v) == 40 and all(c in _HEX for c in v)


def is_zero(v):
    return v != b"" and v.strip(b"0") == b""


def parse_ref_value(data):
    """("oid", id) or ("sym", name). READING: git's loose-ref format, not
    spelled out by the spec: an object id (40 lowercase hex digits) and one
    newline, or `ref: <name>` and one newline (HEAD's symbolic form; the
    spec: "the symbolic ref's name or the object id"). Anything else cannot
    be parsed. The corpus writes only those two forms, and content that is
    plainly neither."""
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise InterpFailure("ref: not one line")
    v = data[:-1]
    if v.startswith(b"ref: ") and len(v) > 5:
        return ("sym", v[5:])
    if is_oid(v):
        return ("oid", v)
    raise InterpFailure("ref: neither an id nor `ref: `")


def parse_packed(data):
    """{refname: id}, a ref listed twice keeping its first line (spec: "first"
    is in file order). READING: git's packed-refs format: a line starting
    `#` is its header, a line starting `^` the peeled id of the ref before
    it; every other line is `<id> <refname>`. Anything else cannot be
    parsed. Only refs are lines here: a header or peeled line is no ref."""
    out = {}
    if data == b"":
        return out
    if not data.endswith(b"\n"):
        raise InterpFailure("packed-refs: no final newline")
    for line in data[:-1].split(b"\n"):
        if line.startswith(b"#"):
            continue
        if line.startswith(b"^"):
            if not is_oid(line[1:]):
                raise InterpFailure("packed-refs: bad peeled line")
            continue
        oid, sp, name = line.partition(b" ")
        if not sp or not is_oid(oid) or not name:
            raise InterpFailure("packed-refs: bad line")
        out.setdefault(name, oid)
    return out


def ref_display(v):
    """spec (HEAD): "the symbolic ref's name or the object id"."""
    return v[1]


def lines_of(data):
    """READING: a reflog's entries are lines as text's are: "the bytes up to
    and including a newline, or the bytes after the last newline"."""
    out = data.split(b"\n")
    if out[-1] == b"":
        out.pop()
    return out


def appended(before, after):
    """The entries after before's bytes when they are "a prefix of after's
    ending at a line's end (an absent before is empty)"; None otherwise."""
    bb = before or b""
    if after.startswith(bb) and (bb == b"" or bb.endswith(b"\n") or bb == after):
        return lines_of(after[len(bb):])
    return None


def reflog_entry_fields(line):
    """(old, new, message). READING: an entry is "<old> <new> <ident>\t<message>";
    old and new are its first two space-separated words. The corpus writes
    only such entries."""
    head, _, msg = line.partition(b"\t")
    words = head.split(b" ")
    return words[0], (words[1] if len(words) > 1 else b""), msg


def operation(msg):
    """spec: "its operation being the message before its first `:`".
    READING: a message with no `:` is all operation (never built)."""
    return msg.split(b":", 1)[0]


def checked(kind, values):
    """A path finding as the core checks it: one that breaks its row (a
    string value not UTF-8, over 1,024 bytes or holding a NUL; text over
    1,024 bytes) is invalid_finding."""
    for v in values.values():
        if isinstance(v, bytes) and not string_ok(v):
            return finding_json("invalid_finding", {})
    if len(render(kind, values)) > STRING_MAX:
        return finding_json("invalid_finding", {})
    return finding_json(kind, values)


def reflog_findings(ref, before, after):
    """before: bytes, or None when absent ("an absent before is empty");
    after: bytes, or None when the reflog was removed (no copy needed)."""
    if after is None:
        return [checked("git_reflog_rewritten", {"ref": ref})]
    new = appended(before, after)
    if new is None:
        return [checked("git_reflog_rewritten", {"ref": ref})]
    out = [checked("git_reflog_appended", {"ref": ref, "entries": len(new)})]
    for line in new:
        old, nw, msg = reflog_entry_fields(line)
        op = operation(msg)
        if op in (b"commit", b"commit (initial)") or b"Fast-forward" in msg:
            continue
        out.append(checked("git_reflog_move", {"ref": ref, "from": old, "to": nw,
                                               "operation": op}))
    # READING: appended first, then each move in entry order. The corpus
    # stays under 4,096 findings (and_more is not modelled here).
    assert len(out) <= FINDINGS_MAX
    return out


class GitPath:
    """One path git is given (its outcome proven or unknown) and what was read
    of it, side by side: E12, "a ref or `packed-refs` that cannot be read on
    a side gives no value there"."""

    def __init__(self, path, repo, rest, role, oc, b, a):
        self.path, self.repo, self.rest, self.role, self.oc = path, repo, rest, role, oc
        self.unknown = oc == "unknown"
        self.reg = {"before": is_reg(b), "after": is_reg(a)}
        self.b, self.a = b, a
        self.unav = []          # (side, reason)
        self.cu_findings = []
        self.contents = {}
        self.parsed = {}        # side -> parsed value (HEAD, ref, packed)
        self.cni = False        # could not be interpreted: E10, the file as a whole
        self.unread = set()     # sides it needs whose copy could not be read
        self.unparsed = set()   # sides read that could not be parsed (decision 141)
        self.record_unav = []   # the unavailable sides its record names
        self.gained = None      # reflog: [(old, new, msg)] when appended, else None


def git_read(store, g):
    """Reads the sides git needs. spec: a removed reflog needs no copy ("or
    when the reflog was removed (no copy needed)"; Content: "a reflog removed
    needs no copy"); every other path is read where it is a regular file.
    E12: an unknown path "is read like any other where its copy can be
    read".

    A side that can be read is read and parsed even when the other cannot,
    for a path E12 derives events from: E12 (decision 137), "a ref or
    `packed-refs` that cannot be read on a side gives no value there" --
    there, not on the other side.

    READING: a tag or remote-tracking ref is read for its record alone --
    E12 derives no event from it ("Remote-tracking refs and tags derive no
    event"). So it is not interpreted, and no E10 event names it, when its
    record needs nothing of it: when a side it needs cannot be read (the
    record, which would compare the two sides, carries its
    content_unavailable findings only), or when its outcome is `unknown`
    (its record carries no finding: "to a path whose outcome is `unknown`
    ... it adds none", and "pip, dpkg and git still derive events from an
    `unknown` path" -- none from this one). As an unknown RECORD on both
    sides is not read (pip).

    A side that cannot be parsed: E12 (decision 141), "A side git cannot
    parse counts as one it cannot read (and is a `could_not_interpret`
    event, E10)". So each side read is parsed alone, and one that cannot be
    parsed gives no value there only, as a side not read gives none (E12,
    "a ref or `packed-refs` that cannot be read on a side gives no value
    there -- before, the reflog's evidence may still give one, and without
    one the event is `git_branch_moved` with no `from` ...; after, the
    branch derives no event"): the other side's value stands. The file is
    still one git failed on: diff-v1, "that path's record carries
    `could_not_interpret` (R11) unless its outcome is `unknown`, ... and
    pip, dpkg and git emit one `could_not_interpret` event naming it (E10)"
    -- one event per file, whichever sides failed. READING: it counts as not
    read for its value only, not for "The record of a path git cannot read
    ... carries `content_unavailable`": the parenthesis says what it is
    instead ("and is a `could_not_interpret` event"), and no reason of
    `content_unavailable`'s (`no_store`, `missing`, `too_large`, `corrupt`)
    names a copy that was read. READING: diff-v1's "nothing more is read
    from it" is taken as nothing more read from the side that failed -- E12,
    the later and narrower rule, uses the other side's value. A reflog is
    never unparseable here (reflog_entry_fields; the corpus writes only such
    entries), so "a reflog it cannot read is no evidence" is reached only by
    a copy not read."""
    if g.role == "reflog":
        need_b = g.reg["before"] and g.reg["after"]
        need_a = g.reg["after"]
        bound = REFLOG_BOUND
    else:
        need_b, need_a = g.reg["before"], g.reg["after"]
        bound = GIT_PACKED_BOUND if g.role == "packed" else GIT_REF_BOUND
    g.cu_findings, g.unav, g.contents = needed_copies(
        store, g.b, g.a, bound, need_b, need_a, nocopy_too_large=g.role == "reflog")
    g.unread = {sd for sd, _ in g.unav}
    removed_log = g.role == "reflog" and not g.reg["after"]
    g.record_unav = [] if removed_log else g.unav
    if removed_log:
        g.cu_findings = []
        g.gained = []           # removed: it gained nothing
        return
    if not e12_path(g) and (g.unav or g.unknown):
        return
    for side, data in sorted(g.contents.items()):
        try:
            if g.role in ("HEAD", "ref"):
                g.parsed[side] = parse_ref_value(data)
            elif g.role == "packed":
                g.parsed[side] = parse_packed(data)
        except InterpFailure:
            g.cni = True                # E10: the file, once
            g.unparsed.add(side)        # "counts as one it cannot read": that side
    if g.role == "reflog" and not g.unread:
        new = appended(g.contents.get("before"), g.contents["after"])
        g.gained = None if new is None else [reflog_entry_fields(x) for x in new]


def gives(g, side):
    """Does this ref, packed-refs or HEAD give a value on `side`? It is a
    file there, its copy there was read, and parsed: E12, "A side git cannot
    parse counts as one it cannot read"."""
    return g.reg[side] and side not in g.unread and side not in g.unparsed


def git_path_findings(g):
    """The record's findings for a path whose content is proven changed."""
    if g.record_unav:
        # READING (as before for a reflog): a path a needed side of which
        # cannot be read carries its content_unavailable findings only --
        # no path finding can be told from one side. Its other side is
        # still read for E12's value there, and if it cannot be parsed the
        # E10 event names the file (git_read).
        return g.cu_findings
    if g.cni:
        return [finding_json("could_not_interpret", {})]
    if g.role == "reflog":
        if not g.reg["after"]:
            return reflog_findings(reflog_name(g.rest), None, None)
        return reflog_findings(reflog_name(g.rest), g.contents.get("before"),
                               g.contents["after"])
    if g.role == "HEAD":
        frm = ref_display(g.parsed["before"]) if "before" in g.parsed else b""
        to = ref_display(g.parsed["after"]) if "after" in g.parsed else b""
        return [] if frm == to else [checked("git_head_changed", {"from": frm, "to": to})]
    if g.role == "ref":
        return ref_findings(g.rest, g.parsed.get("before"), g.parsed.get("after"))
    # packed-refs: "a line of `packed-refs` (in ref order)"
    bp, ap = g.parsed.get("before", {}), g.parsed.get("after", {})
    out = []
    for name in sorted(set(bp) | set(ap)):
        out += ref_findings(name, ("oid", bp[name]) if name in bp else None,
                            ("oid", ap[name]) if name in ap else None)
    assert len(out) <= FINDINGS_MAX
    return out


def ref_findings(name, before, after):
    if before is None and after is None:
        return []
    if before is None:
        return [checked("git_ref_created", {"ref": name, "to": ref_display(after)})]
    if after is None:
        return [checked("git_ref_deleted", {"ref": name, "from": ref_display(before)})]
    if ref_display(before) == ref_display(after):
        return []                   # "only when the value differs"
    return [checked("git_ref_moved", {"ref": name, "from": ref_display(before),
                                      "to": ref_display(after)})]


def reflog_name(rest):
    """spec: "`logs/HEAD` is ref `HEAD`, `logs/refs/...` is `refs/...`"."""
    return b"HEAD" if rest == b"logs/HEAD" else rest[len(b"logs/"):]


# ---------------------------------------------------------------- git: E12

ABSENT, UNKNOWN = "absent", "unknown"
COMMIT_OPS = (b"commit", b"commit (merge)", b"cherry-pick", b"revert", b"am")


def is_rewrite(op, msg):
    """E12: "any `reset`, `commit (amend)`, operation containing `rebase`,
    message starting `branch: Reset to`, or message containing
    `forced-update`". READING: `reset` and `commit (amend)` are operations,
    compared whole."""
    return (op in (b"reset", b"commit (amend)") or b"rebase" in op
            or msg.startswith(b"branch: Reset to") or b"forced-update" in msg)


def is_ff_or_merge(op, msg):
    """E12: "fast-forwards or merges (a message containing `Fast-forward`; an
    operation starting with `merge` or `pull`)"."""
    return b"Fast-forward" in msg or op.startswith(b"merge") or op.startswith(b"pull")


def chains(frm, to, gained):
    """E12: "each entry's old id the previous one's new, the first's old the
    value before, the last's new the value after"."""
    return gained[0][0] == frm and gained[-1][1] == to and all(
        gained[i][0] == gained[i - 1][1] for i in range(1, len(gained)))


def classify(repo, branch, frm, to, gained):
    """E12: a branch on both sides at different commits, "decided by the
    entries its reflog gained in this diff, when they lead from its value
    before to its value after". (kind, values)."""
    moved = ("git_branch_moved", {"repo": repo, "branch": branch, "from": frm, "to": to})
    if not gained:
        return moved                    # "with no such entries"
    if not chains(frm, to, gained):
        return moved
    ops = [(operation(m), m) for _, _, m in gained]
    how = []
    for op, m in ops:
        if is_rewrite(op, m) and op not in how:
            how.append(op)              # "each once, in order"
    if how:
        return ("git_history_rewritten", {"repo": repo, "branch": branch,
                                          "how": b", ".join(how), "from": frm, "to": to})
    if all(op in COMMIT_OPS or is_ff_or_merge(op, m) for op, m in ops):
        vals = {"repo": repo, "branch": branch, "to": to}
        if all(op in COMMIT_OPS for op, _ in ops):
            vals["count"] = len(ops)    # "present only when every entry is one of those"
        return ("git_commits_added", vals)
    return moved                        # "another operation"


class Repo:
    def __init__(self, repo):
        self.repo = repo
        self.head = None
        self.hlog = None
        self.packed = None
        self.loose = {}     # branch -> GitPath (refs/heads/<branch>)
        self.rlog = {}      # branch -> GitPath (logs/refs/heads/<branch>)


def reflog_unusable(G):
    """A reflog git cannot read: a side it needs could not be read (a removed
    one needs none). E12: "a reflog it cannot read is no evidence"."""
    return G is not None and G.reg["after"] and bool(G.unread)


def reflog_before(G, loose_there):
    """E12, before only: "the old id of the first entry its reflog gained in
    this diff (all zeros: absent)" -- (value, paths), the reflog listed when
    its entries gave the value: "a reflog only when its entries were used --
    giving the value before or evidence of absence before, ...", whether or
    not they then lead to the value after.

    READING (the text leaves it open): a loose ref that was a file before
    and could not be read -- or parsed, which "counts as one it cannot
    read" (decision 141) -- is never absent by its reflog. Its existence there
    is a fact the refs give (the manifest records the file), and "What git
    cannot read reduces what is claimed, never the fact the refs give":
    zeros, there, are evidence against a fact, so they give no value, and
    the reflog is not listed (its entries were not used). An old id that is
    not zeros still dates it ("before, the reflog's evidence may still give
    one")."""
    if G is None or reflog_unusable(G) or not G.gained:
        return UNKNOWN, set()           # no evidence: "a reflog it cannot read is no evidence"
    old = G.gained[0][0]
    if is_zero(old):
        return (UNKNOWN, set()) if loose_there else (ABSENT, {G.path})
    return old, {G.path}


def branch_value(side, ref, L, P, G):
    """E12: "Its value on a side: its loose ref there; else its line in
    `packed-refs` when `packed-refs` is a path of this diff; else, before
    only, the old id of the first entry its reflog gained in this diff (all
    zeros: absent)"; and for a deletion, "its loose ref removed and
    `packed-refs` without it (a path of this diff, or not -- git removes a
    branch from both)". (value, the paths whose value it uses): `paths`,
    "every ref, `packed-refs` and `HEAD` path whose value the event uses".

    What cannot be read (decision 137): "a ref or `packed-refs` that cannot
    be read on a side gives no value there -- before, the reflog's evidence
    may still give one, and without one the event is `git_branch_moved`
    with no `from` (a branch only in `packed-refs` too); after, the branch
    derives no event". Before, that is UNKNOWN ("no evidence of before");
    after, UNKNOWN too, which derives nothing. And (decision 141) "A side
    git cannot parse counts as one it cannot read": gives() is false on it.

    READING: "its loose ref there" is the loose ref as git sees it -- a path
    of this diff ("git sees only the paths that changed"). A loose ref that
    is a file on a side and gives no value there is still the branch's ref
    there: before, the reflog may date it, never packed-refs (whose line it
    hides); after, nothing. A symbolic loose branch ref names no commit and
    gives no value (the corpus never builds one)."""
    if L is not None and L.reg[side]:
        if gives(L, side) and L.parsed[side][0] == "oid":
            return L.parsed[side][1], {L.path}
        return reflog_before(G, True) if side == "before" else (UNKNOWN, set())
    if P is not None:
        if not P.reg[side]:
            return ABSENT, {P.path}
        if gives(P, side):
            v = P.parsed[side].get(ref)
            return (ABSENT if v is None else v), {P.path}
        return reflog_before(G, False) if side == "before" else (UNKNOWN, set())
    if side == "after":
        if L is not None and L.reg["before"]:
            return ABSENT, {L.path}     # removed, packed-refs not a path
        return UNKNOWN, set()
    return reflog_before(G, False)


def is_id(v):
    return v not in (ABSENT, UNKNOWN)


def packed_names(P):
    """The branches packed-refs names, on every side it gives a value: read
    and parsed on one side only, that side is used -- E12, "without one the
    event is `git_branch_moved` with no `from` (a branch only in
    `packed-refs` too)"; "A side git cannot parse counts as one it cannot
    read". A side not read or not parsed names none."""
    out = set()
    if P is None:
        return out
    for side, refs in P.parsed.items():
        for ref in refs:
            if ref.startswith(b"refs/heads/") and len(ref) > len(b"refs/heads/"):
                out.add(ref[len(b"refs/heads/"):])
    return out


def classified(repo, branch, frm, to, G, paths):
    """classify() with the branch's reflog G (or None), adding it to paths
    when its entries say "how the branch moved" -- they lead from before to
    after and give git_commits_added or git_history_rewritten. E12: "(entries
    that lead from before to after but say not how are not used)"; "a reflog
    it cannot read is no evidence -- the move still comes from the refs, as
    `git_branch_moved`, without a how"."""
    gained = None if G is None or reflog_unusable(G) else G.gained
    kind, vals = classify(repo, branch, frm, to, gained)
    if kind != "git_branch_moved":
        paths.add(G.path)               # classify says how only from chaining entries
    return kind, vals


def git_events(gpaths):
    """E12, per repository: [(key, kind, values, paths)]. Key: (0, repo, 0 for
    HEAD else 1, branch, the kind's place, paths) -- E4: "by repository, then
    `HEAD` before every branch, then branch, then kind"."""
    repos = {}
    for g in gpaths:
        r = repos.setdefault(g.repo, Repo(g.repo))
        if not (g.reg["before"] or g.reg["after"]):
            continue                    # no side a file: no ref
        if g.role == "HEAD":
            r.head = g
        elif g.role == "packed":
            r.packed = g
        elif g.role == "ref" and g.rest.startswith(b"refs/heads/"):
            r.loose[g.rest[len(b"refs/heads/"):]] = g
        elif g.role == "reflog" and g.rest == b"logs/HEAD":
            r.hlog = g
        elif g.role == "reflog" and g.rest.startswith(b"logs/refs/heads/"):
            r.rlog[g.rest[len(b"logs/refs/heads/"):]] = g
        # tags, remote-tracking refs and their reflogs: "derive no event"
    out = []

    def emit(repo, head, branch, kind, vals, paths):
        out.append(((0, repo, 0 if head else 1, branch, KIND_INDEX[kind], tuple(sorted(paths))),
                    kind, vals, sorted(paths)))

    for repo, r in sorted(repos.items()):
        # ---- HEAD
        H = r.head
        if H is not None and gives(H, "before") and gives(H, "after"):
            # E12 (decision 141): "`HEAD` that cannot be read on a side
            # derives none" -- nor one that cannot be parsed there ("A side
            # git cannot parse counts as one it cannot read"): neither
            # git_head_switched nor the branch `HEAD`.
            # READING: git_head_switched needs HEAD on both sides: its from and
            # to are "the branch (`main`) or, detached, the commit", with no
            # empty value (git_head_changed's "empty on a side where it is
            # absent" is not repeated for it), so a HEAD added or removed
            # (a repository made or deleted) switches nothing.
            hb, ha = H.parsed["before"], H.parsed["after"]

            def shown(v):
                if v[0] == "sym":
                    # READING: HEAD naming a ref outside refs/heads/ is shown
                    # by its full name (never built).
                    n = v[1]
                    return n[len(b"refs/heads/"):] if n.startswith(b"refs/heads/") else n
                return v[1]
            if hb[0] == "oid" and ha[0] == "oid":
                if hb[1] != ha[1]:
                    # "`HEAD` detached on both sides at different commits is
                    # the branch `HEAD`, decided by `logs/HEAD` as above"
                    paths = {H.path}
                    c = classified(repo, b"HEAD", hb[1], ha[1], r.hlog, paths)
                    emit(repo, True, b"HEAD", c[0], c[1], paths)
            elif shown(hb) != shown(ha) or hb[0] != ha[0]:
                emit(repo, True, b"", "git_head_switched",
                     {"repo": repo, "from": shown(hb), "to": shown(ha)}, {H.path})

        # ---- branches
        P = r.packed
        names = set(r.loose) | set(r.rlog) | packed_names(P)
        created, deleted = {}, {}
        for br in sorted(names):
            ref = b"refs/heads/" + br
            L, G = r.loose.get(br), r.rlog.get(br)
            B, pb = branch_value("before", ref, L, P, G)
            A, pa = branch_value("after", ref, L, P, G)
            paths = pb | pa
            # E12 (decision 141): "A branch removed whose value before cannot
            # be told derives no event (`git_branch_deleted` needs `was`)" --
            # a loose ref there not read or not parsed, gone after, its reflog
            # no evidence; or a branch only in a packed-refs not read or not
            # parsed before, its reflog removed. What could not be read or
            # parsed is said by the record and by the content_unavailable or
            # could_not_interpret event.
            if B == ABSENT and is_id(A):
                created[br] = (A, paths)
            elif B == UNKNOWN and is_id(A):
                # "present after with no evidence of before, `git_branch_moved`
                # with no `from`"
                emit(repo, False, br, "git_branch_moved", {"repo": repo, "branch": br, "to": A},
                     paths)
            elif is_id(B) and A == ABSENT:
                deleted[br] = (B, paths)
            elif is_id(B) and is_id(A) and B != A:
                c = classified(repo, br, B, A, G, paths)
                emit(repo, False, br, c[0], c[1], paths)
        # "a deletion and a creation at the same commit whose new reflog says
        # `Branch: renamed`, one `git_branch_renamed`": the new branch's
        # reflog of this diff, an entry it gained whose message is
        # `Branch: renamed refs/heads/{from} to refs/heads/{to}`.
        # READING: the event takes the place of the deletion: it is ordered
        # by `from` (the branch renamed; E4's "then branch"), and it lists
        # the paths of both and the new reflog, its entries used "as evidence
        # ... of a rename". A reflog that says none adds nothing to the
        # creation's paths; one git cannot read "is no evidence": the
        # creation and the deletion stand.
        renamed_from = set()
        for to in sorted(created):
            at, cpaths = created[to]
            G = r.rlog.get(to)
            partners = [d for d in sorted(deleted) if deleted[d][0] == at and d not in renamed_from]
            said = set() if G is None or reflog_unusable(G) else {
                m for _, _, m in (G.gained or [])}
            match = [d for d in partners
                     if b"Branch: renamed refs/heads/" + d + b" to refs/heads/" + to in said]
            if match:
                d = match[0]
                renamed_from.add(d)
                emit(repo, False, d, "git_branch_renamed",
                     {"repo": repo, "from": d, "to": to, "at": at},
                     cpaths | {G.path} | deleted[d][1])
            else:
                emit(repo, False, to, "git_branch_created",
                     {"repo": repo, "branch": to, "at": at}, cpaths)
        for d in sorted(deleted):
            if d not in renamed_from:
                was, dpaths = deleted[d]
                emit(repo, False, d, "git_branch_deleted",
                     {"repo": repo, "branch": d, "was": was}, dpaths)
    return out


E12_RESTS = (b"HEAD", b"packed-refs", b"logs/HEAD")


def e12_path(g):
    """A path E12 derives events from (its paths list's kinds)."""
    return (g.rest in E12_RESTS or g.rest.startswith(b"refs/heads/")
            or g.rest.startswith(b"logs/refs/heads/"))


# ---------------------------------------------------------------- the diff

class Result:
    def __init__(self):
        self.outcomes = {}      # path -> outcome, every path not unchanged
        self.claims = {}        # path -> "pip" | "dpkg" | "git" for those
        self.findings = {}      # path -> bytes of the findings array, or None
        self.events = []        # event lines (bytes), pip's, dpkg's, then git's
        self.not_captured = set()   # paths unknown only as not_captured (E11)
        self.excluded = (None, None)    # each manifest's `excluded` (None: v1)


def row_ok(kind, vals):
    """E9: every string value a string field's value, the text at most 1,024
    bytes (an int is never out of its row here)."""
    for v in vals.values():
        if isinstance(v, bytes) and not string_ok(v):
            return False
    return len(render(kind, vals)) <= STRING_MAX


def end_events(interp, named, cni_files, unav, unknown):
    """One interpreter's events in order. named: (key, kind, values, paths),
    key starting with 0; an event that breaks its row becomes invalid_finding
    in its place (E9). cni_files: the files not interpreted, one
    could_not_interpret each (E10). The events with no name first, in the
    Kinds table's order -- could_not_interpret by path, then
    content_unavailable by reason."""
    lines = []
    for key, kind, vals, paths in named:
        prov = any(p in unknown for p in paths)
        if kind != "could_not_interpret" and not row_ok(kind, vals):
            kind, vals = "invalid_finding", {}
        lines.append((key, event_json(kind, interp, vals, paths, prov)))
    for p in cni_files:
        lines.append(((-1, KIND_INDEX["could_not_interpret"], p),
                      event_json("could_not_interpret", interp, {}, [p], p in unknown)))
    lines += unavailable_events(interp, unav, unknown)
    return [e for _, e in sorted(lines, key=lambda x: x[0])]



def interpret(before_fn, after_fn, store):
    scope_b, bents, bexcl = read_manifest(before_fn)
    scope_a, aents, aexcl = read_manifest(after_fn)
    assert scope_b == scope_a, "the corpus never pairs manifests of different scopes"
    scope = scope_b
    root_dev_b = bents[b"."]["dev"]
    root_dev_a = aents[b"."]["dev"]
    res = Result()
    res.excluded = (bexcl, aexcl)
    bx, ax = excluded_paths(bexcl), excluded_paths(aexcl)

    unknown = set()                     # claimed paths whose outcome is unknown
    unav = {"pip": [], "dpkg": []}      # (path, side, reason)
    dpkg_jobs = []                      # (path, before bytes|None, after bytes|None)
    pip_pairs = {}                      # RECORD path -> "A" (added) | "R" (removed)
    pip_reinst = []                     # (path, before bytes, after bytes)
    pip_uncounted = []                  # RECORDs unknown on both sides
    pip_names = []                      # RECORD paths to name
    git_paths = []                      # GitPath, in path order

    for path in sorted(set(bents) | set(aents)):
        b = bents.get(path)
        a = aents.get(path)
        oc, reason = outcome(b, a, bents, aents, root_dev_b, root_dev_a, bx, ax)
        if oc == "unchanged":
            continue
        res.outcomes[path] = oc
        who = claim(scope, path)
        if who is None:
            continue
        res.claims[path] = who
        if oc == "unknown" and reason == "not_captured":
            # E11: "A path whose outcome is `unknown` with `not_captured` as
            # its only reason ... derives no event"; diff-v1: "none from a
            # path `unknown` only as `not_captured`, which no interpreter is
            # given". So it is no pair partner and is never read. The pin
            # says the rest outright (decision 118): "No interpreter is given
            # it, so no event of the core's names it either: no
            # `could_not_interpret` (E10) nor `content_unavailable` for it,
            # and a failed end hook's event (E6) never lists it." Hence it is
            # never named nor parsed (no E10), no copy of it is needed (no
            # content_unavailable), and it is in no interpreter's claimed
            # paths (E6: "never a path E11 withholds"). Its record stands,
            # with no finding (its outcome is unknown).
            res.not_captured.add(path)
            res.findings[path] = None
            continue
        if oc == "unknown":
            unknown.add(path)
        findings = []
        absp = scope + b"/" + path
        # "A side on which the path is not a regular file counts as absent".
        # Findings only on a proven change of content; pip and dpkg still
        # derive (provisional) events from an unknown path (P7).
        breg = is_reg(b)
        areg = is_reg(a)
        read = oc in PROVEN or oc == "unknown"
        if read and who == "dpkg" and fnmatch.fnmatchcase(absp, DPKG_STATUS) and (breg or areg):
            findings, u, contents = needed_copies(store, b, a, DPKG_BOUND, breg, areg)
            unav["dpkg"] += [(path, s, r) for s, r in u]
            if not u:
                dpkg_jobs.append((path, contents.get("before"), contents.get("after")))
            # READING: a status one of whose needed sides cannot be read gives
            # no package events (only content_unavailable); its readable side
            # is not parsed.
        elif read and who == "pip" and fnmatch.fnmatchcase(absp, PIP_RECORD) and (breg or areg):
            if breg and areg:
                # spec: an unknown RECORD present on both sides "is a
                # provisional pip_reinstalled whose rows are not compared:
                # its three counts are absent" -- so its copies are not read
                # (no content_unavailable). It is named like any other: one
                # that cannot be named is E10's could_not_interpret
                # (provisional; no record finding, its outcome unknown).
                # spec (E10): a dist-info that cannot be named -- "nothing
                # more is read from it", so no content_unavailable either.
                if oc == "unknown":
                    pip_names.append(path)
                    pip_uncounted.append(path)
                elif nameable(path):
                    pip_names.append(path)
                    findings, u, contents = needed_copies(store, b, a, PIP_BOUND, True, True,
                                                         PIP_ROWS)
                    unav["pip"] += [(path, s, r) for s, r in u]
                    if not u:
                        pip_reinst.append((path, contents["before"], contents["after"]))
                else:
                    pip_names.append(path)      # fails to be named below: E10
            else:
                pip_names.append(path)
                pip_pairs[path] = "A" if areg else "R"
        elif who == "git":
            # git's paths are read once every path is seen (its end hook
            # needs them all): the record's findings are set below. A path
            # regular on neither side (a directory under refs/) is a ref on
            # neither: "not a regular file counts as absent". READING: a
            # metadata_only path (content proven unchanged) is neither read
            # nor used: "An interpreter adds findings only to a path whose
            # content is proven changed", and E12's "the record of one whose
            # outcome is not `unknown` carries `content_unavailable`" could
            # not hold for one. The corpus builds none but reflogs.
            if read and (breg or areg):
                repo, rest = git_place(scope, path)
                role = git_role(rest)
                if role is not None:
                    git_paths.append(GitPath(path, repo, rest, role, oc, b, a))
        if oc == "unknown":
            findings = []           # no path finding on an unknown path
        res.findings[path] = (b"[" + b",".join(findings) + b"]") if findings else None

    not_interpreted = set()             # paths whose record carries could_not_interpret

    # ---- pip end hook
    cni_pip = set()                     # files not interpreted, no name (E10)
    pip_events = []                     # (key, kind, values, paths)
    named = {}
    for path in pip_names:
        try:
            named[path] = dist_info(path)
        except InterpFailure:
            cni_pip.add(path)
    keys = {}
    for path, side in pip_pairs.items():
        if path not in named:
            continue
        holder, name, version = named[path]
        k = keys.setdefault((holder, pep503(name)), {"A": [], "R": []})
        k[side].append(path)
    for (holder, norm), k in keys.items():
        A, R = sorted(k["A"]), sorted(k["R"])
        if A and R and len(A) + len(R) > 2:
            # E10: one could_not_interpret event naming them, "in that name's
            # place"; "their records carry nothing, as the pairing is known
            # only once every path record is written". READING: placed as the
            # kind could_not_interpret of that name, then by directory.
            ps = A + R
            pip_events.append(((0, norm, KIND_INDEX["could_not_interpret"], holder,
                                tuple(sorted(ps))), "could_not_interpret", {}, ps))
            continue
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
            pip_events.append(((0, norm, KIND_INDEX[kind], holder, tuple(sorted((A[0], R[0])))),
                               kind, {"name": name, "from": frm, "to": to}, [A[0], R[0]]))
            continue
        for p in A:
            _, name, version = named[p]
            pip_events.append(((0, norm, KIND_INDEX["pip_installed"], holder, (p,)), "pip_installed",
                               {"name": name, "version": version}, [p]))
        for p in R:
            _, name, version = named[p]
            pip_events.append(((0, norm, KIND_INDEX["pip_removed"], holder, (p,)), "pip_removed",
                               {"name": name, "version": version}, [p]))
    for path, before, after in pip_reinst:
        try:
            rb = record_rows(before)
            ra = record_rows(after)
        except InterpFailure:
            cni_pip.add(path)
            continue
        if path not in named:
            continue
        holder, name, version = named[path]
        added = sum(1 for p in ra if p not in rb)
        removed = sum(1 for p in rb if p not in ra)
        changed = sum(1 for p in ra if p in rb and ra[p] != rb[p])
        pip_events.append(((0, pep503(name), KIND_INDEX["pip_reinstalled"], holder, (path,)),
                           "pip_reinstalled",
                           {"name": name, "version": version, "files_added": added,
                            "files_removed": removed, "files_changed": changed}, [path]))
    for path in pip_uncounted:
        if path not in named:
            continue                    # could_not_interpret (E10), above
        holder, name, version = named[path]
        pip_events.append(((0, pep503(name), KIND_INDEX["pip_reinstalled"], holder, (path,)),
                           "pip_reinstalled", {"name": name, "version": version}, [path]))
    # spec: past name, kind and directory, "then the paths it lists"
    # (sorted bytewise, compared in order).
    pip_lines = end_events("pip", pip_events, cni_pip, unav["pip"], unknown)
    not_interpreted |= cni_pip

    # ---- dpkg end hook
    cni_dpkg = set()
    evs = []
    for path, before, after in dpkg_jobs:
        try:
            evs += dpkg_events_for(path, before, after)
        except InterpFailure:
            cni_dpkg.add(path)
    dpkg_lines = end_events("dpkg", evs, cni_dpkg, unav["dpkg"], unknown)
    not_interpreted |= cni_dpkg

    for p in not_interpreted:
        # "has its findings there replaced by could_not_interpret" -- unless
        # the path is unknown, which carries no path finding.
        if p not in unknown:
            res.findings[p] = b"[" + finding_json("could_not_interpret", {}) + b"]"

    # ---- git: its paths, then its end hook (E12)
    cni_git = set()
    unav_git = []
    for g in git_paths:
        git_read(store, g)
        # E12: "The record of a path git cannot read whose outcome is not
        # `unknown` carries `content_unavailable`, and one
        # `content_unavailable` event per reason names those paths
        # (provisional when one of them is `unknown`)"; diff-v1, Content:
        # "git names only the paths it derives events from (HEAD, branches,
        # `packed-refs`, their reflogs), and a reflog removed needs no copy".
        # A tag's or remote-tracking ref's record still carries its
        # content_unavailable findings.
        if e12_path(g):
            unav_git += [(g.path, sd, rs) for sd, rs in g.unav]
        if g.cni:
            # E10: "A file an interpreter claims and cannot interpret gives one
            # `could_not_interpret` event"; diff-v1: "pip, dpkg and git emit one
            # `could_not_interpret` event naming it (E10)" -- any file git
            # claims, a tag's or a remote-tracking ref's included.
            cni_git.add(g.path)
        if not g.unknown:
            fs = git_path_findings(g)
            res.findings[g.path] = (b"[" + b",".join(fs) + b"]") if fs else None
    git_lines = end_events("git", git_events(git_paths), cni_git, unav_git, unknown)

    # E6 (per-diff state over 64 MiB, memory, an event naming no path) is not
    # modelled: the corpus never builds it (see the report's questions).
    # diff-v1: the end hook fails "only when the interpreter's per-diff state
    # would exceed 64 MiB or memory runs out" -- neither reachable from the
    # driver's inputs at the corpus's sizes. Were it modelled, its paths
    # would be those "given to it (every path it claims whose outcome is not
    # `unchanged`; none `unknown` only as `not_captured`, which it is never
    # given: E11)": the claimed paths outside res.not_captured.
    res.events = (bound_events("pip", pip_lines) + bound_events("dpkg", dpkg_lines)
                  + bound_events("git", git_lines))
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
