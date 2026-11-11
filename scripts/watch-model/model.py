#!/usr/bin/env python3
"""watch-model: an independent model of one part of test/expect/watch-v1.md.

The question it answers: which list does a current entry of a watched directory fall under, and
at what level. Written from the pin's words alone (WD-1 to WD-4, FK's order of kinds, BR-L1,
BR-L2, BR-L4, BR-L5, BR-L6, the BR table, DT-1 to DT-4); no matcher was read or copied. The
built-in rows and the order of kinds are parsed out of the pin's own tables at run time.

Out of scope: BR-L3 (not in a new directory) depends on a change between two steps, not on a
current entry, so it is parsed and ignored. FK-4, FK-9 to FK-12 likewise are about changes.

Readings taken where the pin leaves a choice are marked "READING n" and listed in READINGS.

Paths and patterns are bytes. A tree is a dict {path bytes: type}, type one of 'd' (directory),
'f' (regular file), 'l' (symlink).
"""

import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PIN = os.path.join(REPO, "test", "expect", "watch-v1.md")

DONTTOUCH = b".belay-donttouch"
DONTTOUCH_KIND = "don't-touch"
DEPENDENCY_NAMES = (b"node_modules", b"site-packages")

MAX_FILE = 64 * 1024
MAX_PATTERNS = 256
MAX_PATTERN_BYTES = 4096
MAX_DOUBLE_STARS = 4

READINGS = {
    1: "BR-L1: a row with 'not a directory' never covers below a match; it applies only to an "
       "entry that itself matches and is not a directory. A symlink is not a directory.",
    2: "BR-L2: the names node_modules and site-packages are compared as bytes (case-sensitive), "
       "although the row itself is matched case-insensitively (WD-4 speaks of the row only).",
    3: "BR-L2: 'at or below a directory named': tested on the entry's own path; the entry itself "
       "counts as 'at' only when it is a directory.",
    4: "BR-L4: the exception is matched against the whole path from the top, case-sensitively, "
       "with WD-2 ('or lies below its match'), so `proj.sample/.git/hooks/pre-commit` is excepted.",
    5: "First row wins among the rows that APPLY: a row its limit switches off does not stop a "
       "later row (`.env/key.pem` is credentials by BR-57; `.claude/worktrees/x/CLAUDE.md` is "
       "agent rules by BR-19).",
    6: "FK-1: `.belay-donttouch` at the top is don't-touch whatever its type and whether or not "
       "its content is valid; nothing below it (were it a directory) is covered by that clause.",
    7: "DT-2: no trimming. A blank line is an empty line; a line of spaces is a pattern; `#` is a "
       "comment only as the line's first byte.",
    8: "DT-3: a comment line is not a pattern and is not validated (a control byte other than "
       "NUL in a comment does not make the file invalid). A NUL is not a reading: DT-3 as "
       "amended says a file holding one anywhere, a comment included, cannot be read.",
    9: "DT-3: 'a control byte other than NUL' is 0x01-0x1f and 0x7f; bytes >= 0x80 are ordinary.",
    10: "DT-4: 'at most four `**`' counts components that are exactly `**`; `a**b` is two `*` "
        "inside a component and counts for nothing.",
    11: "DT-4: 256 counts patterns, not lines; comments and blank lines are free. Every DT-4 "
        "overrun (also a pattern past 4,096 bytes, although PS-P1 has that bound too) is 'the "
        "limit passed', not 'line N is not a pattern'.",
    12: "DT-1/DT-6: a `.belay-donttouch` that is not a regular file has no stored copy, so it "
        "'cannot be read'; the list in force is then empty.",
    13: "BR-L5 for a current entry: level 'note' (the interface's rule: note for 'noted' and "
        "'noted when modified').",
    14: "A pattern's lines are split on LF only; a final line needs no LF.",
    16: "DT-3/DT-4: a file that both holds a NUL and passes a limit of DT-4 (or has an invalid "
        "line) cannot be read: with no stored copy there is nothing to measure or to number. "
        "The pin does not order the two; no scenario rests on it.",
    15: "The watched directory itself is an entry (belay lists it as `.`; taken after the first "
        "run, the pin does not say). Its path relative to the top has no component, so by PS-P2 "
        "only a pattern whose every component is `**` matches it; `*`, `.*` and `*.` do not: `.` "
        "is not a name it has. A pattern that matches a directory below covers nothing above.",
}


# --------------------------------------------------------------------------- the pin's tables

class Row(object):
    __slots__ = ("id", "num", "kind", "label", "pattern", "limits_text", "not_dir", "not_dep",
                 "not_new_dir", "excepts", "noted_modified", "noted", "comps", "fcomps",
                 "except_comps")

    def note(self):
        return self.noted or self.noted_modified


def _cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == "`" and s[-1] == "`":
        return s[1:-1]
    return s


def parse_pin(text=None):
    """(rows, kinds): the BR rows in the table's order, and FK's kinds in FK's order."""
    if text is None:
        with open(PIN, "r", encoding="utf-8") as f:
            text = f.read()
    rows, kinds = [], []
    for line in text.split("\n"):
        m = re.match(r"^\| (BR|FK)-(\d+) \|", line)
        if not m:
            continue
        c = _cells(line)
        if m.group(1) == "FK":
            kinds.append(c[1])
            continue
        if len(c) != 6:
            raise ValueError("BR row with %d cells: %s" % (len(c), line))
        r = Row()
        r.id, r.num, r.kind, r.label = c[0], int(m.group(2)), c[1], c[2]
        r.pattern = _unquote(c[3])
        r.limits_text = c[4]
        r.not_dir = r.not_dep = r.not_new_dir = r.noted_modified = r.noted = False
        r.excepts = []
        if c[4] != "--":
            for lim in [x.strip() for x in c[4].split(";")]:
                if lim == "not a directory":
                    r.not_dir = True
                elif lim == "not in a dependency":
                    r.not_dep = True
                elif lim == "not in a new directory":
                    r.not_new_dir = True
                elif lim == "noted when modified":
                    r.noted_modified = True
                elif lim == "noted":
                    r.noted = True
                elif lim.startswith("except "):
                    r.excepts.append(_unquote(lim[len("except "):]))
                else:
                    raise ValueError("%s: unknown limit %r" % (r.id, lim))
        r.comps = split(r.pattern.encode())
        r.fcomps = fold(r.comps)
        r.except_comps = [split(e.encode()) for e in r.excepts]
        rows.append(r)
    if not rows or not kinds:
        raise ValueError("the pin's BR or FK table was not found")
    return rows, kinds


# --------------------------------------------------------------------------- WD-1: the dialect

def split(path):
    return tuple(path.split(b"/"))


def fold(comps):
    """ASCII case folding (bytes.lower() folds A-Z only)."""
    return tuple(c.lower() for c in comps)


def comp_match(pat, name):
    """`*` is any run of bytes, none included, within one component. Nothing else is special."""
    parts = pat.split(b"*")
    if len(parts) == 1:
        return pat == name
    first, last = parts[0], parts[-1]
    if len(name) < len(first) + len(last):
        return False
    if not name.startswith(first) or not name.endswith(last):
        return False
    pos, end = len(first), len(name) - len(last)
    for mid in parts[1:-1]:
        i = name.find(mid, pos, end)
        if i < 0:
            return False
        pos = i + len(mid)
    return True


def match(pcomps, ncomps):
    """The whole path against the whole pattern. `**` is any number of whole components, none
    included. Names that start with a dot are matched like any other (WD-1: PS-P4 is off)."""
    memo = {}

    def go(i, j):
        k = (i, j)
        if k in memo:
            return memo[k]
        if i == len(pcomps):
            r = j == len(ncomps)
        elif pcomps[i] == b"**":
            r = any(go(i + 1, x) for x in range(j, len(ncomps) + 1))
        else:
            r = j < len(ncomps) and comp_match(pcomps[i], ncomps[j]) and go(i + 1, j + 1)
        memo[k] = r
        return r

    return go(0, 0)


def covers(pcomps, ncomps):
    """WD-2: the pattern matches the path, or a directory above it."""
    return any(match(pcomps, ncomps[:k]) for k in range(1, len(ncomps) + 1))


# --------------------------------------------------------------------------- the built-in list

def in_dependency(ncomps, etype):
    """BR-L2: at or below a directory named node_modules or site-packages (READING 2, 3)."""
    for c in ncomps[:-1]:
        if c in DEPENDENCY_NAMES:
            return True
    return ncomps[-1] in DEPENDENCY_NAMES and etype == "d"


def row_applies(row, ncomps, etype, ignore=()):
    """Does this row, by itself, apply to this current entry (BR-L1, BR-L2, BR-L4)?
    `ignore` names limits to leave out ('L1', 'L2', 'L4'): run.py's gate uses it to tell
    which limit switched a row off."""
    if row.not_dep and "L2" not in ignore and in_dependency(ncomps, etype):
        return False
    if "L4" not in ignore:
        for ex in row.except_comps:
            if covers(ex, ncomps):
                return False
    f = fold(ncomps)
    if row.not_dir:
        return (etype != "d" or "L1" in ignore) and match(row.fcomps, f)
    return covers(row.fcomps, f)


class Model(object):
    def __init__(self, text=None):
        self.rows, self.kinds = parse_pin(text)
        self.row_kinds = []
        for r in self.rows:
            if r.kind not in self.kinds:
                raise ValueError("%s: kind %r is not in FK" % (r.id, r.kind))
            if r.kind not in self.row_kinds:
                self.row_kinds.append(r.kind)
        self.kind_order = [k for k in self.kinds if k in self.row_kinds]

    def winning_row(self, path, etype):
        """The first kind in FK's order with a row that applies; within it the first row."""
        ncomps = split(path)
        for kind in self.kind_order:
            for r in self.rows:
                if r.kind == kind and row_applies(r, ncomps, etype):
                    return r
        return None

    def classify(self, path, etype, user):
        """(kind, level, reason, row id or None) for a covered entry, else None.
        `user` is the list in force: a list of pattern bytes."""
        ncomps = split(path)
        if path == DONTTOUCH or any(covers(split(u), ncomps) for u in user):
            return (DONTTOUCH_KIND, "flag", DONTTOUCH_KIND, None)
        r = self.winning_row(path, etype)
        if r is None:
            return None
        return (r.kind, "note" if r.note() else "flag", r.label, r.id)

    def row_count(self, row, tree):
        return sum(1 for p, t in tree.items() if row_applies(row, split(p), t))

    @staticmethod
    def user_count(pattern, tree):
        """Entries of the tree the pattern covers, and the top itself when it matches that."""
        pc = split(pattern)
        return sum(1 for p in tree if covers(pc, split(p))) + (1 if match(pc, ()) else 0)

    @staticmethod
    def classify_top(user):
        """The watched directory itself (READING 15): its relative path has no components, so
        only a pattern made of `**` alone matches it. No row can (each has a literal name)."""
        if any(match(split(u), ()) for u in user):
            return (DONTTOUCH_KIND, "flag", DONTTOUCH_KIND, None)
        return None


# --------------------------------------------------------------------------- .belay-donttouch

def pattern_error(line):
    """DT-3: why a line is not a pattern, or None."""
    for b in line:                    # a NUL never comes here: parse_donttouch has said so
        if b < 0x20 or b == 0x7f:
            return "a control byte"
    if line.startswith(b"/"):
        return "a leading /"
    if line.endswith(b"/"):
        return "a trailing /"
    if line.startswith(b"!"):
        return "a leading !"
    for ch in (b"?", b"[", b"\\"):
        if ch in line:
            return "%s" % ch.decode()
    for c in line.split(b"/"):
        if c == b"":
            return "an empty component"
        if c in (b".", b".."):
            return "a . or .. component"
    return None


def parse_donttouch(data):
    """('ok', [patterns]) | ('line', N, why) | ('limit', what) | ('unreadable', why).
    `data` is the file's bytes."""
    if b"\x00" in data:              # DT-3: not text, no stored copy, no line number (READING 16)
        return ("unreadable", "no stored copy: a NUL byte")
    if len(data) > MAX_FILE:
        return ("limit", "file over 64 KiB")
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    pats = []
    for n, line in enumerate(lines, 1):
        if line == b"" or line.startswith(b"#"):
            continue
        why = pattern_error(line)
        if why:
            return ("line", n, why)
        if len(line) > MAX_PATTERN_BYTES:
            return ("limit", "pattern over 4,096 bytes")
        if sum(1 for c in line.split(b"/") if c == b"**") > MAX_DOUBLE_STARS:
            return ("limit", "more than four **")
        pats.append(line)
        if len(pats) > MAX_PATTERNS:
            return ("limit", "more than 256 patterns")
    return ("ok", pats)


def list_in_force(tree, content):
    """On a first step. (status, patterns): status is ('none',), ('ok',), ('line', N, why),
    ('limit', what) or ('unreadable',). `content` is the file's bytes when it is a regular file."""
    t = tree.get(DONTTOUCH)
    if t is None:
        return (("none",), [])
    if t != "f":
        return (("unreadable",), [])
    res = parse_donttouch(content)
    if res[0] == "ok":
        return (("ok",), res[1])
    if res[0] == "unreadable":
        return (("unreadable",), [])
    return (res, [])
