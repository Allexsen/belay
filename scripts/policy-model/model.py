"""policy-model: an independent model of policy.v1, from the pins alone (decision 150, Q9).

Written only from test/expect/policy-v1.md, protect-spec.md and baseline-bundle.md, diff.v1's
pins (diff-fields.md, diff-values.md, finding-kinds.md, diff-events.md), the manifest pins,
docs/spec prose outside its generated blocks, and docs/cli.md -- never from belay's code, the
oracle, the reference, or a generated table. Where it and belay disagree, one of them misreads a
pin, or the pin reads two ways: the harness (run.py) prints both lines.

Its input is what the generator built and changed, measured by the harness with lstat(2) and
read(2) (never taken from belay's output): the scope as it stood when the bundle was exported
and when verify captured it. From that it derives, as the pins say: the manifest each capture
records (as far as policy.v1 reads one), the diff.v1 records (outcome, changed, unknown), the
interpreters' findings and events policy.v1 rests on, the bundle's package lines, and then
export's and verify's output and exit codes.

AMBIGUITIES -- where a pin reads more than one way: the reading chosen, and why. One the
author has since pinned says SETTLED, with its decision and the words it now reads.

P1  `changed` and ctime_ns. diff-values.md's first example gives a chmod
    `"changed":["mode","ctime_ns"]`; diff-v1 ("`ctime_ns` only under rule 5"), diff-fields.md
    (ctime "compared only when nothing else differs") and policy-v1's own example
    (`["size","mtime_ns","sha256"]` for a write, which moves ctime too) name ctime_ns only when
    nothing else differs. Chosen: the three.

P2  SETTLED (decision 176). The order of `unknown` reasons: policy-v1 now reads "in the order
    `unverified`, `unstable`, `unreadable`, `raced`, `mount`, `xattrs_unknown`,
    `iflags_unknown`, `not_captured`, `listing_incomplete`" -- this model's reading.

P3  SETTLED (decision 163). privilege_changed `iflags`, read as written at first (every added
    file `none -> 0`, on ext4 `none -> 524288`). The row now reads: "For a file added or
    removed, `iflags` only when they hold the immutable or append-only flag (Linux
    `FS_IMMUTABLE_FL`, `FS_APPEND_FL`; ...)". Modelled: an entry on one side only gives an
    iflags record only when that side's flags hold 0x10 or 0x20 (`none -> 16`); an entry on both
    sides gives one whenever the two values differ, `none` where one is not recorded (so a file
    that becomes unreadable is `0 -> none`). See P32.

P4  privilege_changed "any file": any entry type, directories included (setgid and sticky
    matter most on directories).

P5  protected_path_unverifiable's `rule`, "the first that matches it": the first rule in the
    spec whose pattern matches the path, whatever its modes, even when only a later rule's
    side makes the path unverifiable.

P6  "On a side its modes read" (PS-M5): no_write reads before, and after when the path is
    there too ("matched before, on both sides"); no_delete reads before; no_create reads after,
    whenever the path is there (unchanged included); expected_sha256 reads after.

P7  expected_sha256 against an after entry that is a regular file without a hash
    (`unverified`): no protected_hash_mismatch -- none of its `why` fits; PS-M5 says it, as
    protected_path_unverifiable. Several rules giving a hash for one path: the first whose hash
    does not hold.

P8  tampered_installed_package and a file listed without a hash: P-T6 says such files are
    "never checked", so they give none (a pip RECORD's own row included) -- SETTLED as this
    model read it, with one exception pinned by decision 186: "A `.pyc` its RECORD lists without
    a hash is judged too ... one modified or of another type while its source did not change
    ... is `tampered_installed_package`; one rewritten while its source changed (recompiled), or
    removed, is not" (see P36-P38). A listed file whose outcome is `added` (missing at reset) or
    `metadata_only` gives none: no `why` fits. Which packages are judged is SETTLED (decision
    173): those no event names, "or one whose event is a reinstall at the same version
    (`pip_reinstalled`) ... frozen or not".

P9  tampered `why`, in this order: `removed`; `type changed`; `cannot be verified` (outcome
    `unknown`, or the after entry `unverified`); else `other bytes`.

P10 package_changed: only the package kinds (pip_*, dpkg_*); the core's events under pip or
    dpkg (could_not_interpret, content_unavailable, invalid_finding, and_more) name no package.
    `package`: pip, the event's `name`; dpkg, `<package>:<arch>` as the bundle names it (B-P2).
    A bundle line's package is "named by an event" when, for pip, the PEP 503-normalised names
    are equal, for dpkg, `<package>:<arch>` is.

P11 SETTLED (decision 176). `self_consistent`: "present exactly when frozen_packages is
    false"; "for a package with no database after (`pip_removed`, `dpkg_removed`) `true`" --
    this model's revised reading. Still this model's: pip, every RECORD row after that has a
    sha256 and lies in the scope names a regular file after with that sha256; dpkg, every
    md5sums row after names a regular file after with that MD5; Conffiles left out (admins edit
    them, decision 148).

P12 "Test file" (decision 175 narrowed it; the words are policy-v1's paragraph above the flag
    table). Read: no component of the path (its name included) is one of the build output or
    documentation names; and some component (its name included, any entry type, so a directory
    `tests` is one) is `test`, `tests`, `__tests__` or `spec`, or the name matches one of the
    language patterns, case-sensitively, `*` any run of bytes, none included (`_test.py` is
    `*_test.py`), with no dot rule (it is not a protect pattern). See P34.

P13 tests_weakened. "Held": a side's copy is held when its entry is stored, or is a regular file
    of size 0 (its content is known); a side where the path is absent or not a regular file
    counts 0 and is held. An `assert` statement is a line whose stripped text starts with
    `assert` followed by a space, tab or `(`; `self.assert*(`, `pytest.raises(`,
    `pytest.approx(` and `np.testing.assert_*(` are counted where they occur; a test is a line
    whose stripped text starts with `def test_` or `async def test_`. A marker is an added line
    (after's lines outside a longest common subsequence with before's) whose stripped text
    starts with one of the six markers. "Emptied": a regular file of size 0 after that was not
    empty before. Checked on paths whose outcome is added, removed, modified, type_changed or
    unknown. A side a capture did not look at (the path `unknown` only as not_captured: excluded,
    or below an unreadable directory or a mount) is not held and is not "absent": nothing is
    counted from it (diff-events E11's reasoning: "that side was not looked at"). The same holds
    for pytest_config_changed's copies.

P14 edits_ci_config, "below": strictly below `.github/workflows` and `.circleci` (the
    directories themselves are not configuration); the five names anywhere in the tree.

P15 pytest_config_changed. `section`: the header as written, brackets included (`[pytest]`,
    `[tool:pytest]`, `[tool.pytest.ini_options]`), or `pytest.ini`. A header is a line starting
    with `[` (its trailing blanks dropped); a `[tool.pytest...]` table is `[tool.pytest]` or one
    starting `[tool.pytest.`. An absent side's text is empty. One record per path (the kind has
    a `path`): the first differing section, after's order first.

P16 git_hook_changed for `executable changed`: that finding has no `target`; the hook is a
    regular file, so `target` is empty, as for a file.

P17 git_history_rewritten. `repo`: the `.git` directory's path in the scope (E12: "a directory
    named `.git`; `repo` its path in the scope"), for the reflog finding too. `branch` from a
    `git_reflog_rewritten` finding: its `ref` as written (`refs/heads/main`, `HEAD`).

P18 new_executable_on_path. "A file whose execute bits were added": a regular file on both sides
    with any execute bit set after and clear before. "Another type replaced by either": a type
    change to a symlink, or to a regular file with an execute bit. A venv's `bin` is one beside
    a regular file `pyvenv.cfg` in the after manifest.

P19 SETTLED (decision 174). A `bytes` value in `text`: P-F2 now reads "a `bytes` field as it is
    when it is UTF-8, else as the receipt writes it (docs/cli.md): each byte not in a valid UTF-8
    sequence as `\\xNN` (lowercase hex), a backslash doubled" -- this model's reading. See P33
    for the 1,024-byte cut the same row adds.

P20 The pin fixes keys, their order and their values, not the bytes of a line: lines are
    compared as JSON objects with their key order (run.py), not byte for byte.

P21 packages_no_hash: the bundle's package lines whose at_reset is `no_hash` (the baseline's
    databases), as P-T5 takes the bundle's outside_scope.

P22 The bundle's package lines: dpkg's installed stanzas only (third word of Status
    `installed`); md5sums at `info/<package>:<arch>.md5sums`, else `info/<package>.md5sums`;
    pip's `version` from the dist-info directory's name (as the pip interpreter takes it);
    `no_hash` decided before the manifest is consulted; a RECORD hash other than sha256 is
    `no_hash`.

P23 verify without `--baseline-sha256`: exit 3, as B-R2 says ("refuses a bundle without it ...
    (exit 3)"), though docs/cli.md calls a missing argument usage (2).

P24 A spec verify refuses (PS-R2) whose digest also differs from the bundle's: 2, refused before
    its digest is compared ("nothing is judged").

P25 What a manifest records of a file belay cannot open (mode 000, not root): `unverified` and
    `unreadable`, no `iflags` (no descriptor to ask through), its attributes read by path. The
    rows that would say so are generated (manifest-v1's entries table).

P26 PS-C2 and the dot rule: `**` never takes a dot-name, so an excluded `.cache` does not cover
    `**/x.py`.

P27 A spec number with a fraction or an exponent (`1.0`, `1e0`) is not an `int`: refused.

P28 A rule's `mode` given as `[]` with no `expected_sha256` is "a rule with neither a mode nor
    expected_sha256": refused.

P29 One-sided `iflags` (rule 4) adds the reason iflags_unknown to an `unknown` record whenever
    the types are the same and neither side is a mount root, even when another metadata field
    differs.

P30 A bundle exported with a spec, and verify given none: refused (exit 3) -- "the protections
    are the same at both ends" (PS-R3); the reverse too (a spec whose digest is not the null the
    bundle records).

P31 SETTLED (decision 174). Which paths verify's capture leaves out: baseline-bundle B-R5 now
    reads "exactly what the bundle's manifest's header lists as user excludes -- never the
    scope's configured excludes ...; with `--to`, the checkpoint's own" (`after_excludes`).

P32 New with decision 163. "For a file added or removed": an entry present in one manifest only,
    whatever its outcome -- `added` and `removed`, and also `unknown` one-sided (not_captured
    beside an exclusion, raced). The rule reads the manifests themselves, and its reason --
    "the flags a filesystem sets on every new file ... are no privilege" -- holds as much for a
    path one side did not capture; read otherwise, every not-captured file would be `0 -> none`.

P33 New with decision 174. "`text` is at most 1,024 bytes: a longer one is cut at a character and
    ends `...`": the whole text, `...` (three ASCII dots) included, is at most 1,024 bytes -- the
    longest prefix of whole UTF-8 characters within 1,021 bytes, then `...`. The cut is applied
    to every kind's text; the fields keep their full values.

P35 New with decision 174. The cut and P-F2's escaping together: "cut at a character" is read as
    a character of the text as filled, so a `\\xNN` written for a byte not UTF-8 may itself be
    cut (`...\\xf...`); the pin does not say to keep an escape whole.

P34 New with decision 175. The test-file rule's "a path none of whose components is a build output
    directory ... or documentation" excludes the path whatever the type of the component (a file
    named `build` included), and "either is or lies below a test directory (a component ...)"
    counts any component, the last included, as P12 did. `.build` is the only dot-name among them;
    `*.test.<ext>` and `*.spec.<ext>` take only the six extensions listed.

P36 New with decision 186. The `.pyc` judged is one "modified or of another type": its outcome
    `modified` (why `other bytes`, or `cannot be verified` when unverified after, as P9) or
    `type_changed` (why `type changed`). One whose outcome is `unknown`, `metadata_only`,
    `removed` or `added` is not judged: the exception names only the two, and a file "listed
    without a hash: never checked" stays so outside it.

P37 New with decision 186. The forms: in a directory `__pycache__`, `<name>.<tag>.pyc` and
    `<name>.<tag>.opt-<n>.pyc`, `<name>` the file name up to its first `.` (a module name holds
    none), `<tag>` the rest, non-empty, `<n>` decimal digits; the source is `<name>.py` in the
    directory above `__pycache__`. Any other `<dir>/<name>.pyc` is the legacy form, its source
    `<dir>/<name>.py`. "Its source did not change" is "with no record in the diff", read as
    written: a source absent on both sides has none, so a sourceless `.pyc` is judged.

P38 New with decision 186. packages_no_hash still counts every line without a hash, `.pyc`
    included: the row's subject is "Files a database lists without a hash", and "never checked
    -- a `.pyc` aside" says what becomes of them, not what is counted.
"""

import base64
import csv
import difflib
import hashlib
import io
import json
import re

HASH_BOUND_SPEC = 4294967296          # PS-C3, decision 159
HASH_DEFAULT = 64 * 1024 * 1024        # docs/cli.md: check's hash limit
STORE_MAX = 65536                      # manifest-v1's example store_max_bytes
REFLOG_MAX = 16 * 1024 * 1024          # diff-v1, git's reflog bound

KINDS = (
    "protected_path_written", "protected_path_deleted", "protected_path_created",
    "protected_hash_mismatch", "protected_path_unverifiable", "package_changed",
    "tampered_installed_package", "conffile_changed", "touches_tests", "tests_weakened",
    "edits_ci_config", "pytest_config_changed", "conftest_changed",
    "python_startup_hook_changed", "git_hook_changed", "git_history_rewritten",
    "new_executable_on_path", "privilege_changed", "writes_outside_workdir",
)
KIND_INDEX = {k: i for i, k in enumerate(KINDS)}
NOT_EMITTED = [{"flag": "writes_outside_workdir", "why": "needs a scope wider than the workdir"}]

ENTRY_FLAGS = ("unverified", "unstable", "unreadable", "raced", "mount")            # P2
REASON_ORDER = ENTRY_FLAGS + ("xattrs_unknown", "iflags_unknown", "not_captured",
                              "listing_incomplete")
FIELD_ORDER = ("mode", "uid", "gid", "size", "mtime_ns", "ctime_ns", "ino", "dev", "nlink",
               "iflags", "caps", "xattrs", "sha256", "rdev", "link_target")


class Refused(Exception):
    """A refusal: exit code and why (the model's words, never compared)."""

    def __init__(self, code, why):
        super().__init__(why)
        self.code = code
        self.why = why


# ---------------------------------------------------------------------------------------------
# Encoding

def enc(obj):
    """A line as the manifest's canonical encoding writes it (and policy.v1's example)."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def is_utf8(b):
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def b64(b):
    return base64.b64encode(b).decode("ascii")


def put_bytes(d, name, b):
    """A `bytes` field: `<name>` when UTF-8, else `<name>_b64` (finding-kinds.md)."""
    if is_utf8(b):
        d[name] = b.decode("utf-8")
    else:
        d[name + "_b64"] = b64(b)


def show(b):
    """A `bytes` value in a `text` (P19)."""
    if is_utf8(b):
        return b.decode("utf-8")
    s = b.decode("utf-8", errors="surrogateescape")
    return "".join("\\x%02x" % (ord(c) - 0xDC00) if 0xDC80 <= ord(c) <= 0xDCFF
                   else "\\\\" if c == "\\" else c for c in s)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------------------------------------
# The protect spec (protect-spec.md)

SPEC_KEYS = ("belay_protect", "protect", "frozen_packages", "path_dirs")
RULE_KEYS = ("path", "mode", "expected_sha256")
MODES = ("no_write", "no_delete", "no_create")
JSON_WS = " \t\n\r"


class Rule:
    def __init__(self, pattern, modes, expected):
        self.pattern = pattern                     # str, as given
        self.comps = pattern.encode("utf-8").split(b"/")
        self.modes = modes
        self.expected = expected


class Spec:
    def __init__(self, rules, frozen, path_dirs, digest):
        self.rules = rules
        self.frozen = frozen
        self.path_dirs = path_dirs                 # None (the default) or [components]
        self.digest = digest


def _pattern(s, what):
    """PS-P1."""
    try:
        b = s.encode("utf-8")
    except UnicodeEncodeError:
        raise Refused(2, what + ": not UTF-8")
    if len(b) > 4096:
        raise Refused(2, what + ": over 4,096 bytes")
    for c in b.split(b"/"):
        if c in (b"", b".", b".."):
            raise Refused(2, what + ": an empty, . or .. component, or a leading or trailing /")
    return b.split(b"/")


def parse_spec(raw):
    """PS-R1, PS-R2: the spec, or Refused(2)."""
    if len(raw) > 1 << 20:
        raise Refused(2, "over 1 MiB")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused(2, "not UTF-8")

    def pairs(ps):
        keys = [k for k, _ in ps]
        if len(set(keys)) != len(keys):
            raise Refused(2, "a key given twice")
        return dict(ps)

    def constant(c):
        raise Refused(2, "not JSON: " + c)

    body = text.lstrip(JSON_WS)
    try:
        obj, end = json.JSONDecoder(object_pairs_hook=pairs, parse_constant=constant).raw_decode(body)
    except ValueError:
        raise Refused(2, "not one JSON object")
    if body[end:].strip(JSON_WS):
        raise Refused(2, "something after the object")
    if type(obj) is not dict:
        raise Refused(2, "not an object")
    for k in obj:
        if k not in SPEC_KEYS:
            raise Refused(2, "unknown key " + k)
    if "belay_protect" not in obj or type(obj["belay_protect"]) is not int or obj["belay_protect"] != 1:
        raise Refused(2, "belay_protect is not 1")
    if "protect" not in obj or type(obj["protect"]) is not list:
        raise Refused(2, "protect is not an array")
    if len(obj["protect"]) > 4096:
        raise Refused(2, "over 4,096 rules")
    rules = []
    for r in obj["protect"]:
        if type(r) is not dict:
            raise Refused(2, "a rule is not an object")
        for k in r:
            if k not in RULE_KEYS:
                raise Refused(2, "unknown rule key " + k)
        if "path" not in r or type(r["path"]) is not str:
            raise Refused(2, "a rule without a string path")
        _pattern(r["path"], "path")
        modes = r.get("mode", [])
        if type(modes) is not list:
            raise Refused(2, "mode is not an array")
        for m in modes:
            if type(m) is not str or m not in MODES:
                raise Refused(2, "an unknown mode")
        if len(set(modes)) != len(modes):
            raise Refused(2, "a mode given twice")
        expected = None
        if "expected_sha256" in r:
            expected = r["expected_sha256"]
            if type(expected) is not str or not re.fullmatch("[0-9a-f]{64}", expected):
                raise Refused(2, "expected_sha256 is not 64 lowercase hex digits")
            if "*" in r["path"]:
                raise Refused(2, "expected_sha256 in a rule whose pattern has a *")
        if not modes and expected is None:                                           # P28
            raise Refused(2, "a rule with neither a mode nor expected_sha256")
        rules.append(Rule(r["path"], tuple(modes), expected))
    frozen = obj.get("frozen_packages", False)
    if type(frozen) is not bool:
        raise Refused(2, "frozen_packages is not a bool")
    path_dirs = None
    if "path_dirs" in obj:
        pd = obj["path_dirs"]
        if type(pd) is not list or len(pd) > 256:
            raise Refused(2, "path_dirs is not an array of at most 256")
        path_dirs = []
        for s in pd:
            if type(s) is not str:
                raise Refused(2, "a path_dirs element is not a string")
            path_dirs.append(_pattern(s, "path_dirs"))
    return Spec(rules, frozen, path_dirs, sha256(raw))


# ---------------------------------------------------------------------------------------------
# Patterns (PS-P1..P4) and what an exclusion covers (PS-C2)

def comp_match(pc, c):
    """One pattern component against one path component (PS-P3, PS-P4)."""
    if c.startswith(b".") and not pc.startswith(b"."):
        return False
    if b"*" not in pc:
        return pc == c
    parts = pc.split(b"*")
    if not c.startswith(parts[0]):
        return False
    pos = len(parts[0])
    for mid in parts[1:-1]:
        i = c.find(mid, pos)
        if i < 0:
            return False
        pos = i + len(mid)
    return len(c) - pos >= len(parts[-1]) and c.endswith(parts[-1])


def pat_match(pcs, path):
    """A pattern (components) against a path (bytes, relative); the root `.` never matches."""
    if path == b".":
        return False
    cs = path.split(b"/")
    memo = {}

    def m(i, j):
        key = (i, j)
        if key in memo:
            return memo[key]
        if i == len(pcs):
            r = j == len(cs)
        elif pcs[i] == b"**":
            r = m(i + 1, j) or (j < len(cs) and not cs[j].startswith(b".") and m(i, j + 1))
        else:
            r = j < len(cs) and comp_match(pcs[i], cs[j]) and m(i + 1, j + 1)
        memo[key] = r
        return r

    return m(0, 0)


def covers(pcs, excluded):
    """PS-C2: some path at or below `excluded` could match the pattern (P26)."""
    states = {0}
    for c in excluded.split(b"/"):
        new = set()
        todo = list(states)
        seen = set()
        while todo:
            i = todo.pop()
            if i in seen:
                continue
            seen.add(i)
            if i < len(pcs) and pcs[i] == b"**":
                todo.append(i + 1)
                if not c.startswith(b"."):
                    new.add(i)
            elif i < len(pcs) and comp_match(pcs[i], c):
                new.add(i + 1)
        states = new
        if not states:
            return False
    return True


# ---------------------------------------------------------------------------------------------
# The manifest a capture records, as far as policy.v1 reads it

def _parent(p):
    return p.rsplit(b"/", 1)[0] if b"/" in p else b"."


def _name(p):
    return p.rsplit(b"/", 1)[-1]


def git_place(p):
    """(repo, rest components) for a path under a `.git` directory, else None."""
    cs = p.split(b"/")
    for i in range(len(cs) - 2, -1, -1):
        if cs[i] == b".git":
            return b"/".join(cs[: i + 1]), cs[i + 1:]
    return None


def is_record(p):
    cs = p.split(b"/")
    return len(cs) >= 2 and cs[-1] == b"RECORD" and cs[-2].endswith(b".dist-info")


def is_status(p):
    return p == b"var/lib/dpkg/status" or p.endswith(b"/var/lib/dpkg/status")


def claimed_for_copy(p, size):
    """Files an interpreter needs (diff-v1, "Which interpreter"), stored whatever their size."""
    cs = p.split(b"/")
    if len(cs) >= 2 and cs[-2].endswith(b".dist-info") and cs[-1] in (b"RECORD", b"METADATA"):
        return True
    if is_status(p):
        return True
    if p.endswith(b".md5sums") or p.endswith(b".list"):
        par = _parent(p)
        if par == b"var/lib/dpkg/info" or par.endswith(b"/var/lib/dpkg/info"):
            return True
    g = git_place(p)
    if g is not None:
        rest = g[1]
        if rest in ([b"HEAD"], [b"packed-refs"]) or (rest and rest[0] == b"refs"):
            return True
        if rest and rest[0] == b"logs":
            return size <= REFLOG_MAX
    return False


def is_text(data):
    return b"\0" not in data and is_utf8(data)


def view(raw, hash_max):
    """The manifest entries a capture with this hash bound records (manifest-v1, PS-C3).

    `raw`: path -> what the harness measured: type, mode, uid, gid, size, mtime_ns, ctime_ns,
    ino, dev, nlink, iflags, caps, xattrs, xattrs_unknown, readable, data (the bytes, for a
    regular file it could read within its read limit), link_target, rdev.
    """
    out = {}
    for p, r in raw.items():
        e = dict(r)
        for f in ENTRY_FLAGS:
            e[f] = False
        e["sha256"] = None
        e["stored"] = False
        if r["type"] == "reg":
            if not r["readable"]:
                e["unverified"] = e["unreadable"] = True          # P25
                e["data"] = None
            elif r["size"] > hash_max:
                e["unverified"] = True
            else:
                if r["data"] is None:
                    raise AssertionError("no bytes measured for a file within the hash bound: %r" % p)
                e["sha256"] = sha256(r["data"])
                e["stored"] = claimed_for_copy(p, r["size"]) or (
                    r["size"] <= STORE_MAX and is_text(r["data"]))
        elif r["type"] == "dir" and not r["readable"]:
            e["unreadable"] = True
        elif r["type"] == "lnk" and r["link_target"] is None:
            e["unreadable"] = True
        out[p] = e
    return out


def held(e):
    """A regular file's content, when a copy of it is held (P13), else None."""
    if e is None or e["type"] != "reg":
        return None
    if e["stored"] or (e["size"] == 0 and e["sha256"] is not None):
        return e["data"]
    return None


def side_bytes(e):
    """A side's content for counting: absent or not a regular file is b'' (held); else the copy
    or None when not held."""
    if e is None or e["type"] != "reg":
        return b""
    return held(e)


# ---------------------------------------------------------------------------------------------
# The diff (diff-fields.md, diff-v1 "How an outcome is decided")

class Side:
    def __init__(self, entries, root_dev, excluded):
        self.entries = entries
        self.root_dev = root_dev
        self.excluded = excluded             # [{"path": bytes, "reason", "dev", "ino"}]


def _reasons(rs):
    return [r for r in REASON_ORDER if r in rs]


def _flag_reasons(e):
    rs = set()
    for f in ENTRY_FLAGS:
        if e[f] and not (f == "unverified" and e["mount"]):
            rs.add(f)
    if e.get("xattrs_unknown"):
        rs.add("xattrs_unknown")
    return rs


def _one_sided(p, have, lacking):
    """diff-v1, "Present on one side only"."""
    for x in lacking.excluded:
        xp = x["path"]
        if p == xp or p.startswith(xp + b"/"):
            return "unknown", ["not_captured"]
    q = p
    anc = None
    while b"/" in q:
        q = _parent(q)
        if q in lacking.entries:
            anc = lacking.entries[q]
            break
    if anc is None:
        anc = lacking.entries.get(b".")
    if anc is not None:
        if anc["type"] == "dir" and (anc["unreadable"] or anc["mount"]):
            return "unknown", ["not_captured"]
        if anc["type"] == "dir" and anc["unstable"]:
            return "unknown", ["listing_incomplete"]
        if anc["type"] != "dir" and anc["raced"]:
            return "unknown", ["raced"]
    if have["raced"]:
        return "unknown", ["raced"]
    return None, None


def _both(b, a, bs, as_, identity):
    t = a["type"]
    mount = b["mount"] or a["mount"]
    raced = b["raced"] or a["raced"]
    if b["type"] != t:
        rec = {"outcome": "type_changed", "type": t, "type_before": b["type"], "changed": ["type"]}
        if raced:
            rec["outcome"] = "unknown"
            rec["unknown"] = _reasons(_flag_reasons(b) | _flag_reasons(a))
        return rec
    differs = {}
    differs["mode"] = b["mode"] != a["mode"]
    differs["uid"] = b["uid"] != a["uid"]
    differs["gid"] = b["gid"] != a["gid"]
    differs["size"] = t in ("reg", "lnk") and b["size"] != a["size"]
    differs["mtime_ns"] = t in ("reg", "lnk") and not mount and b["mtime_ns"] != a["mtime_ns"]
    differs["ino"] = identity and b["dev"] == a["dev"] and b["ino"] != a["ino"]
    differs["dev"] = (b["dev"] == bs.root_dev) != (a["dev"] == as_.root_dev)
    differs["nlink"] = t != "dir" and b["nlink"] != a["nlink"]
    differs["iflags"] = (not mount and b["iflags"] is not None and a["iflags"] is not None
                         and b["iflags"] != a["iflags"])
    attrs_read = not mount and not b.get("xattrs_unknown") and not a.get("xattrs_unknown")
    differs["caps"] = attrs_read and b.get("caps") != a.get("caps")
    differs["xattrs"] = attrs_read and b.get("xattrs") != a.get("xattrs")
    differs["sha256"] = (t == "reg" and b["sha256"] is not None and a["sha256"] is not None
                         and b["sha256"] != a["sha256"])
    differs["rdev"] = t in ("blk", "chr") and b.get("rdev") != a.get("rdev")
    differs["link_target"] = (t == "lnk" and not b["unreadable"] and not a["unreadable"]
                              and b["link_target"] != a["link_target"])
    content = differs["size"] or differs["sha256"] or differs["rdev"] or differs["link_target"]
    content_flag = any(e[f] for e in (b, a) for f in ("unverified", "unstable", "unreadable", "mount"))
    metadata = any(differs[f] for f in ("mode", "uid", "gid", "mtime_ns", "ino", "dev", "nlink",
                                        "iflags", "caps", "xattrs"))
    iflags_one_sided = not mount and (b["iflags"] is None) != (a["iflags"] is None)
    xu = b.get("xattrs_unknown") or a.get("xattrs_unknown")
    changed = [f for f in FIELD_ORDER if f != "ctime_ns" and differs.get(f)]
    ctime_only = (t in ("reg", "lnk") and not mount and b["ctime_ns"] != a["ctime_ns"])
    if raced:
        outcome = "unknown"
    elif content:
        outcome = "modified"
    elif content_flag:
        outcome = "unknown"
    elif metadata:
        outcome = "metadata_only"
    elif xu or iflags_one_sided:
        outcome = "unknown"
    elif ctime_only:
        outcome = "metadata_only"
        changed = ["ctime_ns"]                                                       # P1
    else:
        return None
    rec = {"outcome": outcome, "type": t}
    if changed:
        rec["changed"] = changed
    if outcome == "unknown":
        rs = _flag_reasons(b) | _flag_reasons(a)
        if iflags_one_sided:                                                         # P29
            rs.add("iflags_unknown")
        rec["unknown"] = _reasons(rs)
    return rec


def diff(bs, as_):
    """path -> record, for every path whose outcome is not unchanged."""
    identity = bs.entries.get(b".", {}).get("dev") == as_.entries.get(b".", {}).get("dev")
    recs = {}
    for p in sorted(set(bs.entries) | set(as_.entries)):
        b = bs.entries.get(p)
        a = as_.entries.get(p)
        if b is not None and a is not None:
            rec = _both(b, a, bs, as_, identity)
        elif a is not None:
            o, why = _one_sided(p, a, bs)
            rec = {"outcome": o or "added", "type": a["type"]}
            if why:
                rec["unknown"] = why
        else:
            o, why = _one_sided(p, b, as_)
            rec = {"outcome": o or "removed", "type": b["type"]}
            if why:
                rec["unknown"] = why
        if rec is not None:
            recs[p] = rec
    return recs


def content_changed(rec):
    return rec is not None and rec["outcome"] in ("added", "removed", "modified", "type_changed")


def not_captured_only(rec):
    return rec is not None and rec["outcome"] == "unknown" and rec.get("unknown") == ["not_captured"]


# ---------------------------------------------------------------------------------------------
# Versions: PEP 440 (pip) and Debian (dpkg)

_PEP440 = re.compile(r"""^\s*v?(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|beta|preview|pre|a|b|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$""", re.X | re.I)


def pep440_key(v):
    m = _PEP440.match(v)
    if not m:
        return None
    rel = [int(x) for x in m.group("release").split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    inf = (float("inf"),)
    if m.group("pre"):
        lab = m.group("pre_l").lower()
        lab = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}.get(lab, lab)
        pre = ({"a": 0, "b": 1, "rc": 2}[lab], int(m.group("pre_n") or 0))
    elif m.group("dev") and not m.group("post"):
        pre = (-1,)
    else:
        pre = inf
    if m.group("post"):
        post = (int(m.group("post_n1") or m.group("post_n2") or 0),)
    else:
        post = (-1,)
    dev = (int(m.group("dev_n") or 0),) if m.group("dev") else inf
    local = m.group("local") or ""
    return (int(m.group("epoch") or 0), tuple(rel), pre, post, dev, local)


def _deb_order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _deb_part(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        diff_ = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _deb_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _deb_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return ac - bc
            i += 1 if i < len(a) and not a[i].isdigit() else 0
            j += 1 if j < len(b) and not b[j].isdigit() else 0
            if ac == 0 and bc == 0:
                break
        ni = i
        while ni < len(a) and a[ni].isdigit():
            ni += 1
        nj = j
        while nj < len(b) and b[nj].isdigit():
            nj += 1
        diff_ = int(a[i:ni] or "0") - int(b[j:nj] or "0")
        if diff_:
            return diff_
        i, j = ni, nj
    return 0


def deb_cmp(x, y):
    def split(v):
        epoch = 0
        if ":" in v:
            e, v = v.split(":", 1)
            epoch = int(e or "0")
        if "-" in v:
            up, rev = v.rsplit("-", 1)
        else:
            up, rev = v, "0"
        return epoch, up, rev
    ex, ux, rx = split(x)
    ey, uy, ry = split(y)
    if ex != ey:
        return ex - ey
    return _deb_part(ux, uy) or _deb_part(rx, ry)


# ---------------------------------------------------------------------------------------------
# Package databases: dpkg's status and md5sums, pip's RECORD

def parse_status(data):
    """(Package, Architecture) -> stanza fields (first stanza of a key kept), or None if it
    cannot be parsed."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    pkgs = {}
    order = []
    for block in re.split(r"\n\s*\n", text):
        fields = {}
        last = None
        for line in block.split("\n"):
            if not line.strip():
                continue
            if line[0] in " \t":
                if last is None or last in ("Package", "Architecture", "Version", "Status"):
                    return None
                fields[last] += "\n" + line
                continue
            if ":" not in line:
                return None
            k, v = line.split(":", 1)
            last = k
            fields[k] = v.strip()
        if "Package" not in fields:
            continue
        key = (fields["Package"], fields.get("Architecture", ""))
        if key not in pkgs:
            pkgs[key] = fields
            order.append(key)
    return pkgs


def installed(stanza):
    if stanza is None:
        return False
    words = stanza.get("Status", "").split()
    return len(words) >= 3 and words[2] == "installed"


def conffiles(stanza):
    out = []
    for line in stanza.get("Conffiles", "").split("\n"):
        w = line.split()
        if len(w) >= 2 and w[0].startswith("/"):
            out.append((w[0].lstrip("/").encode("utf-8"), w[1]))
    return out


def md5sums_rows(data):
    out = []
    for line in data.split(b"\n"):
        if not line.strip():
            continue
        m = re.match(rb"^([0-9a-fA-F]{32}) +(.*)$", line)
        if m:
            out.append((m.group(2).lstrip(b"/"), m.group(1).decode().lower()))
    return out


def dpkg_root(status_path):
    return status_path[: -len(b"var/lib/dpkg/status")]       # b"" or b"x/"


def md5sums_path(status_path, pkg, arch):
    info = dpkg_root(status_path) + b"var/lib/dpkg/info/"
    return [info + ("%s:%s.md5sums" % (pkg, arch)).encode(), info + ("%s.md5sums" % pkg).encode()]


def record_rows(data):
    """RECORD rows (path, hash, size), the first row of a path kept; None if not parseable."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    rows = []
    seen = set()
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        if len(row) != 3:
            return None
        if row[0] in seen:
            continue
        seen.add(row[0])
        rows.append(tuple(row))
    return rows


def record_hex(h):
    """A RECORD hash as sha256 hex, or None (no hash, or not sha256: P22)."""
    if not h.startswith("sha256="):
        return None
    v = h[len("sha256="):]
    try:
        return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)).hex()
    except (ValueError, base64.binascii.Error):
        return None


def resolve_lexically(parent, rel, scope):
    """B-P4: a database path, relative to the scope, or None when outside it."""
    if rel.startswith("/"):
        if rel == scope or rel.startswith(scope.rstrip("/") + "/"):
            rel = rel[len(scope.rstrip("/")) + 1:]
            parent = b""
        else:
            return None
    comps = [c for c in parent.split(b"/") if c and c != b"."] if parent not in (b"", b".") else []
    for c in rel.encode("utf-8").split(b"/"):
        if c in (b"", b"."):
            continue
        if c == b"..":
            if not comps:
                return None
            comps.pop()
        else:
            comps.append(c)
    if not comps:
        return None
    return b"/".join(comps)


def distinfo(record_path):
    """(directory holding it, name, version) from `<dir>/<name>-<version>.dist-info/RECORD`."""
    d = _parent(record_path)
    base = _name(d)[: -len(b".dist-info")].decode("utf-8", errors="replace")
    holder = _parent(d)
    if "-" not in base:
        return holder, None, None
    name, version = base.split("-", 1)
    if not name or not version:
        return holder, None, None
    return holder, name, version


def pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def bundle_packages(B, scope):
    """B-6: the packages member's lines (as dicts, in order) and outside_scope."""
    lines = []
    outside = 0
    for p in sorted(B):
        e = B[p]
        if e["type"] != "reg":
            continue
        if is_status(p) and e["data"] is not None:
            pkgs = parse_status(e["data"]) or {}
            root = dpkg_root(p)
            for (pkg, arch), st in pkgs.items():
                if not installed(st):                                                # P22
                    continue
                name = "%s:%s" % (pkg, arch)
                version = st.get("Version", "")
                rows = []
                for mp in md5sums_path(p, pkg, arch):
                    m = B.get(mp)
                    if m is not None and m["type"] == "reg" and m["data"] is not None:
                        rows = md5sums_rows(m["data"])
                        break
                for rel, md5 in rows:
                    lines.append(_dpkg_line(B, name, version, root + rel, md5, False))
                for rel, md5 in conffiles(st):
                    lines.append(_dpkg_line(B, name, version, root + rel, md5, True))
        elif is_record(p) and e["data"] is not None:
            holder, name, version = distinfo(p)
            rows = record_rows(e["data"])
            if name is None or rows is None:
                continue
            for path, h, _size in rows:
                rp = resolve_lexically(holder, path, scope)
                if rp is None:
                    outside += 1
                    continue
                lines.append(_pip_line(B, name, version, rp, h))
    lines.sort(key=lambda l: (l["db"].encode(), l["package"].encode(), l["_path"]))
    return lines, outside


def _at_reset(B, path, check):
    f = B.get(path)
    if f is None:
        return "missing"
    if f["type"] != "reg":
        return "not_a_file"
    if f["sha256"] is None:
        return "unverified"
    return "match" if check(f) else "mismatch"


def _dpkg_line(B, package, version, path, md5, conffile):
    at = _at_reset(B, path, lambda f: hashlib.md5(f["data"]).hexdigest() == md5)
    line = {"db": "dpkg", "package": package, "version": version}
    put_bytes(line, "path", path)
    if conffile:
        line["conffile"] = True
    line["at_reset"] = at
    line["_path"] = path
    return line


def _pip_line(B, package, version, path, h):
    hx = record_hex(h)
    at = "no_hash" if hx is None else _at_reset(B, path, lambda f: f["sha256"] == hx)   # P22
    line = {"db": "pip", "package": package, "version": version}
    put_bytes(line, "path", path)
    line["at_reset"] = at
    line["_path"] = path
    return line


def packages_member(lines):
    return b"".join(enc({k: v for k, v in l.items() if k != "_path"}).encode("utf-8") + b"\n"
                    for l in lines)


# ---------------------------------------------------------------------------------------------
# Interpreters: the events and findings policy.v1 rests on

class Event:
    def __init__(self, interp, kind, fields, text, paths, provisional):
        self.interp = interp
        self.kind = kind
        self.fields = fields
        self.text = text
        self.paths = sorted(set(paths))
        self.provisional = provisional


def pip_events(recs, B, A):
    groups = {}
    for p, rec in recs.items():
        if not is_record(p) or not_captured_only(rec):
            continue
        b, a = B.get(p), A.get(p)
        breg = b is not None and b["type"] == "reg"
        areg = a is not None and a["type"] == "reg"
        holder, name, version = distinfo(p)
        if name is None:
            continue                                        # could_not_interpret: no package
        g = groups.setdefault((holder, pep503(name)), {"added": [], "removed": [], "inplace": []})
        if breg and areg:
            if rec["outcome"] in ("modified", "unknown"):
                g["inplace"].append((p, name, version))
        elif areg:
            g["added"].append((p, name, version))
        elif breg:
            g["removed"].append((p, name, version))
    events = []
    for (holder, norm), g in groups.items():
        prov = lambda ps: any(recs[x]["outcome"] == "unknown" for x in ps)
        ad, rm = g["added"], g["removed"]
        if ad and not rm:
            for p, n, v in ad:
                events.append(Event("pip", "pip_installed", {"name": n, "version": v},
                                    "installed %s %s" % (n, v), [p], prov([p])))
        elif rm and not ad:
            for p, n, v in rm:
                events.append(Event("pip", "pip_removed", {"name": n, "version": v},
                                    "removed %s %s" % (n, v), [p], prov([p])))
        elif len(ad) == 1 and len(rm) == 1:
            (pa, na, va), (pr, _nr, vr) = ad[0], rm[0]
            ka, kr = pep440_key(va), pep440_key(vr)
            if ka is None or kr is None or ka == kr:
                kind, text = "pip_version_changed", "%s %s -> %s" % (na, vr, va)
            elif ka > kr:
                kind, text = "pip_upgraded", "upgraded %s %s -> %s" % (na, vr, va)
            else:
                kind, text = "pip_downgraded", "downgraded %s %s -> %s" % (na, vr, va)
            events.append(Event("pip", kind, {"name": na, "from": vr, "to": va}, text,
                                [pa, pr], prov([pa, pr])))
        for p, n, v in g["inplace"]:
            if recs[p]["outcome"] == "unknown":
                events.append(Event("pip", "pip_reinstalled", {"name": n, "version": v},
                                    "reinstalled %s %s (files not counted)" % (n, v), [p], True))
                continue
            rb = record_rows(held(B[p]) or b"")
            ra = record_rows(held(A[p]) or b"")
            if rb is None or ra is None:
                continue
            db = {r[0]: r for r in rb}
            da = {r[0]: r for r in ra}
            fa = len([x for x in da if x not in db])
            fr = len([x for x in db if x not in da])
            fc = len([x for x in da if x in db and da[x][1:] != db[x][1:]])
            events.append(Event("pip", "pip_reinstalled",
                                {"name": n, "version": v, "files_added": fa, "files_removed": fr,
                                 "files_changed": fc},
                                "reinstalled %s %s: +%d -%d ~%d files" % (n, v, fa, fr, fc),
                                [p], False))
    return events


def dpkg_events(recs, B, A):
    events = []
    for p, rec in recs.items():
        if not is_status(p) or not_captured_only(rec):
            continue
        if not (content_changed(rec) or rec["outcome"] == "unknown"):
            continue
        b, a = B.get(p), A.get(p)
        sb = parse_status(side_bytes(b) or b"") if side_bytes(b) is not None else None
        sa = parse_status(side_bytes(a) or b"") if side_bytes(a) is not None else None
        if sb is None or sa is None:
            continue
        prov = rec["outcome"] == "unknown"
        for key in sorted(set(sb) | set(sa)):
            pkg, arch = key
            x, y = sb.get(key), sa.get(key)
            ib, ia = installed(x), installed(y)
            covered = False
            if ia and not ib:
                v = y.get("Version", "")
                events.append(Event("dpkg", "dpkg_installed", {"package": pkg, "arch": arch, "version": v},
                                    "installed %s:%s %s" % (pkg, arch, v), [p], prov))
                covered = True
            elif ib and not ia:
                v = x.get("Version", "")
                events.append(Event("dpkg", "dpkg_removed", {"package": pkg, "arch": arch, "version": v},
                                    "removed %s:%s %s" % (pkg, arch, v), [p], prov))
                covered = True
            elif ib and ia:
                vf, vt = x.get("Version", ""), y.get("Version", "")
                c = deb_cmp(vt, vf) if vf != vt else 0
                if c > 0:
                    events.append(Event("dpkg", "dpkg_upgraded", {"package": pkg, "arch": arch, "from": vf, "to": vt},
                                        "upgraded %s:%s %s -> %s" % (pkg, arch, vf, vt), [p], prov))
                elif c < 0:
                    events.append(Event("dpkg", "dpkg_downgraded", {"package": pkg, "arch": arch, "from": vf, "to": vt},
                                        "downgraded %s:%s %s -> %s" % (pkg, arch, vf, vt), [p], prov))
            stf = x.get("Status", "") if x else ""
            stt = y.get("Status", "") if y else ""
            if stf != stt and not covered:
                events.append(Event("dpkg", "dpkg_state_changed", {"package": pkg, "arch": arch, "from": stf, "to": stt},
                                    "%s:%s %s -> %s" % (pkg, arch, stf, stt), [p], prov))
    return events


def git_hook_findings(recs, B, A):
    """path -> (kind, fields) for `.git/hooks/<name>` (finding-kinds.md, diff-v1 git)."""
    out = {}
    for p, rec in recs.items():
        g = git_place(p)
        if g is None or len(g[1]) != 2 or g[1][0] != b"hooks":
            continue
        hook = g[1][1].decode("utf-8", errors="replace")
        b, a = B.get(p), A.get(p)
        bh = b is not None and b["type"] in ("reg", "lnk")
        ah = a is not None and a["type"] in ("reg", "lnk")

        def tgt(e):
            return e["link_target"] or b"" if e["type"] == "lnk" else b""

        def exe(e):
            return bool(e["mode"] & 0o100) if e["type"] == "reg" else None
        o = rec["outcome"]
        if o == "added" and ah:
            out[p] = ("added", exe(a), tgt(a))
        elif o == "removed" and bh:
            out[p] = ("removed", None, tgt(b))
        elif o in ("modified", "type_changed") and bh and ah:
            out[p] = ("changed", exe(a), tgt(a))
        elif o == "type_changed" and ah:
            out[p] = ("added", exe(a), tgt(a))
        elif o == "type_changed" and bh:
            out[p] = ("removed", None, tgt(b))
        elif o == "metadata_only" and b["type"] == "reg" and a["type"] == "reg" \
                and (b["mode"] & 0o100) != (a["mode"] & 0o100):
            out[p] = ("executable changed", bool(a["mode"] & 0o100), b"")              # P16
    return out


def reflog_entries(data):
    out = []
    for line in data.split(b"\n"):
        if not line:
            continue
        head, _, msg = line.partition(b"\t")
        w = head.split(b" ")
        if len(w) < 2:
            continue
        msg = msg.decode("utf-8", errors="replace")
        out.append((w[0].decode(), w[1].decode(), msg.split(":", 1)[0], msg))
    return out


def reflog_gained(b, a):
    """The entries a reflog gained (bytes past before's when a prefix ending at a line's end),
    or None when rewritten."""
    if b and not a.startswith(b):
        return None
    if b and not b.endswith(b"\n"):
        return None
    return a[len(b):]


def git_reflog_rewritten(recs, B, A):
    """reflog path -> (repo, ref) for git_reflog_rewritten findings."""
    out = {}
    for p, rec in recs.items():
        g = git_place(p)
        if g is None or not g[1] or g[1][0] != b"logs" or not content_changed(rec):
            continue
        ref = b"/".join(g[1][1:]).decode("utf-8", errors="replace")
        b, a = B.get(p), A.get(p)
        if rec["outcome"] == "removed":
            out[p] = (g[0], ref)
            continue
        bb, ab = side_bytes(b), side_bytes(a)
        if bb is None or ab is None:
            continue
        if reflog_gained(bb, ab) is None:
            out[p] = (g[0], ref)
    return out


def _rewrites(op, msg):
    return (op == "reset" or op == "commit (amend)" or "rebase" in op
            or msg.startswith("branch: Reset to") or "forced-update" in msg)


def git_events(recs, B, A):
    """git_history_rewritten events (E12) for loose branch refs; the other E12 kinds give no
    flag and are not modelled."""
    events = []
    for p, rec in sorted(recs.items()):
        g = git_place(p)
        if g is None or len(g[1]) < 3 or g[1][:2] != [b"refs", b"heads"]:
            continue
        repo, rest = g
        branch = b"/".join(rest[2:])
        b, a = B.get(p), A.get(p)
        if b is None or a is None or b["type"] != "reg" or a["type"] != "reg":
            continue
        vb, va = held(b), held(a)
        if vb is None or va is None:
            continue
        vb, va = vb.strip().decode(), va.strip().decode()
        if vb == va:
            continue
        log = repo + b"/logs/refs/heads/" + branch
        lrec = recs.get(log)
        if lrec is None or not content_changed(lrec) and lrec["outcome"] != "unknown":
            continue
        lb, la = side_bytes(B.get(log)), side_bytes(A.get(log))
        if lb is None or la is None:
            continue
        gained = reflog_gained(lb, la)
        if gained is None:
            continue
        ents = reflog_entries(gained)
        if not ents:
            continue
        leads = ents[0][0] == vb and ents[-1][1] == va and all(
            ents[i][0] == ents[i - 1][1] for i in range(1, len(ents)))
        if not leads:
            continue
        hows = []
        for _o, _n, op, msg in ents:
            if _rewrites(op, msg) and op not in hows:
                hows.append(op)
        if not hows:
            continue
        paths = [p, log]
        events.append(Event("git", "git_history_rewritten",
                            {"repo": repo.decode(), "branch": branch.decode(), "how": ", ".join(hows),
                             "from": vb, "to": va},
                            "%s rewritten by %s: %s -> %s" % (branch.decode(), ", ".join(hows), vb, va),
                            paths, any(recs[x]["outcome"] == "unknown" for x in paths)))
    return events


# ---------------------------------------------------------------------------------------------
# Test files, Python counts, pytest configuration, CI, PATH

TEST_DIRS = (b"test", b"tests", b"spec", b"__tests__")
NOT_TEST_DIRS = (b"build", b"dist", b"out", b"target", b"_build", b".build", b"obj", b"node_modules",
                 b"__pycache__", b"docs", b"doc")                                    # decision 175
_JS = (b"js", b"jsx", b"ts", b"tsx", b"mjs", b"cjs")
TEST_NAMES = ((b"test_*.py", b"*_test.py")                                           # Python
              + tuple(b"*.test." + e for e in _JS) + tuple(b"*.spec." + e for e in _JS)
              + (b"*_test.go",                                                         # Go
                 b"*Test.java", b"*Tests.java", b"*Test.kt", b"*Tests.kt",             # Java, Kotlin
                 b"*_spec.rb", b"*_test.rb",                                           # Ruby
                 b"test_*.c", b"*_test.c", b"test_*.cc", b"*_test.cc", b"test_*.cpp", b"*_test.cpp"))


def fn_glob(pat, name):
    parts = pat.split(b"*")
    if not name.startswith(parts[0]):
        return False
    pos = len(parts[0])
    for mid in parts[1:-1]:
        i = name.find(mid, pos)
        if i < 0:
            return False
        pos = i + len(mid)
    return len(name) - pos >= len(parts[-1]) and name.endswith(parts[-1])


def is_test_file(p):
    """policy-v1, "Test file" (decision 175; P12, P34)."""
    if p == b".":
        return False
    cs = p.split(b"/")
    if any(c in NOT_TEST_DIRS for c in cs):
        return False
    if any(c in TEST_DIRS for c in cs):
        return True
    return any(fn_glob(pat, cs[-1]) for pat in TEST_NAMES)


def is_counted(p):
    n = _name(p)
    return is_test_file(p) and n.endswith(b".py") and n != b"conftest.py"


def lines_of(data):
    """diff-v1, text: a line is the bytes up to and including a newline, or after the last."""
    out = []
    start = 0
    while start < len(data):
        i = data.find(b"\n", start)
        if i < 0:
            out.append(data[start:])
            break
        out.append(data[start:i + 1])
        start = i + 1
    return out


_SELF_ASSERT = re.compile(rb"self\.assert[A-Za-z0-9_]*\(")
_NP_ASSERT = re.compile(rb"np\.testing\.assert_[A-Za-z0-9_]*\(")
MARKERS = (b"@pytest.mark.skip", b"@pytest.mark.skipif", b"@pytest.mark.xfail", b"@unittest.skip",
           b"pytest.skip(", b"pytest.xfail(")


def count_python(data):
    a = t = 0
    for ln in lines_of(data):
        s = ln.strip()
        if re.match(rb"assert[ \t(]", s):
            a += 1
        a += len(_SELF_ASSERT.findall(ln)) + ln.count(b"pytest.raises(") + ln.count(b"pytest.approx(")
        a += len(_NP_ASSERT.findall(ln))
        if s.startswith(b"def test_") or s.startswith(b"async def test_"):
            t += 1
    return a, t


def added_lines(before, after):
    x, y = lines_of(before), lines_of(after)
    n, m = len(x), len(y)
    if n * m > 4000000:
        from collections import Counter
        c = Counter(x)
        out = []
        for ln in y:
            if c[ln]:
                c[ln] -= 1
            else:
                out.append(ln)
        return out
    L = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            L[i][j] = L[i + 1][j + 1] + 1 if x[i] == y[j] else max(L[i + 1][j], L[i][j + 1])
    i = j = 0
    out = []
    while i < n and j < m:
        if x[i] == y[j]:
            i += 1
            j += 1
        elif L[i + 1][j] >= L[i][j + 1]:
            i += 1
        else:
            out.append(y[j])
            j += 1
    out.extend(y[j:])
    return out


def markers_added(before, after):
    out = []
    for ln in added_lines(before, after):
        s = ln.strip()
        if any(s.startswith(mk) for mk in MARKERS):
            out.append(s.decode("utf-8", errors="replace"))
    return out


PYTEST_FILES = {b"pytest.ini", b"tox.ini", b"setup.cfg", b"pyproject.toml"}


def _wanted(name, header):
    if name == b"tox.ini":
        return header == b"[pytest]"
    if name == b"setup.cfg":
        return header == b"[tool:pytest]"
    if name == b"pyproject.toml":
        return header == b"[tool.pytest]" or header.startswith(b"[tool.pytest.")
    return False


def pytest_sections(name, data):
    """header -> its lines (header to next header), in file order."""
    out = {}
    cur = None
    for ln in lines_of(data):
        if ln.startswith(b"["):
            h = ln.rstrip()
            cur = h if _wanted(name, h) else None
            if cur is not None:
                out.setdefault(cur, b"")
        if cur is not None:
            out[cur] += ln
    return out


def pytest_change(p, b_data, a_data):
    """(section) of the first differing pytest section, or None (P15)."""
    name = _name(p)
    if name == b"pytest.ini":
        return "pytest.ini" if b_data != a_data else None
    sb, sa = pytest_sections(name, b_data), pytest_sections(name, a_data)
    for h in list(sa) + [h for h in sb if h not in sa]:
        if sb.get(h, b"") != sa.get(h, b""):
            return h.decode("utf-8", errors="replace")
    return None


CI_NAMES = (b".gitlab-ci.yml", b"Jenkinsfile", b"azure-pipelines.yml", b".travis.yml")


def is_ci(p):
    cs = p.split(b"/")
    for i in range(len(cs) - 2):
        if cs[i] == b".github" and cs[i + 1] == b"workflows":
            return True
    for i in range(len(cs) - 1):
        if cs[i] == b".circleci":
            return True
    return cs[-1] in CI_NAMES


DEFAULT_PATH_DIRS = (b"bin", b"sbin", b"usr/bin", b"usr/sbin", b"usr/local/bin", b"usr/local/sbin")


def in_path_dir(p, A, spec):
    if b"/" not in p:
        return False
    parent = _parent(p)
    if spec is not None and spec.path_dirs is not None:
        return any(pat_match(pcs, parent) for pcs in spec.path_dirs)
    if parent in DEFAULT_PATH_DIRS:
        return True
    if _name(parent) == b"bin":
        cfg = (parent[:-3] if b"/" in parent else b"") + b"pyvenv.cfg"
        e = A.get(cfg)
        return e is not None and e["type"] == "reg"
    return False


STARTUP_NAMES = (b"sitecustomize.py", b"usercustomize.py")


def is_startup_hook(p):
    if b"/" not in p:
        return False
    n = _name(p)
    if not (n.endswith(b".pth") or n in STARTUP_NAMES):
        return False
    return _name(_parent(p)) in (b"site-packages", b"dist-packages")


def record_paths_after(A, scope):
    out = set()
    for p, e in A.items():
        if not is_record(p):
            continue
        rows = record_rows(held(e) or b"") if held(e) is not None else None
        if not rows:
            continue
        holder, _n, _v = distinfo(p)
        for path, _h, _s in rows:
            rp = resolve_lexically(holder, path, scope)
            if rp is not None:
                out.add(rp)
    return out


# ---------------------------------------------------------------------------------------------
# policy.v1

class Flag:
    def __init__(self, kind, level, fields, text, paths, provisional=False):
        self.kind = kind
        self.level = level
        self.fields = fields          # [(key, value)]: bytes values are `bytes` fields
        self.text = cut(text)
        self.paths = sorted(set(paths))
        self.provisional = provisional

    def obj(self):
        o = {"flag": self.kind, "level": self.level}
        for k, v in self.fields:
            if v is None:
                continue
            if isinstance(v, bytes):
                put_bytes(o, k, v)
            else:
                o[k] = v
        o["text"] = self.text
        if self.provisional:
            o["provisional"] = True
        if all(is_utf8(p) for p in self.paths):
            o["paths"] = [p.decode("utf-8") for p in self.paths]
        else:
            o["paths_b64"] = [b64(p) for p in self.paths]
        return o

    def sort_key(self):
        return (0 if self.level == "violation" else 1, KIND_INDEX[self.kind],
                self.paths[0] if self.paths else b"", self.text.encode("utf-8"))


def cut(text):
    """P-F2: "`text` is at most 1,024 bytes: a longer one is cut at a character and ends `...`"
    (P33)."""
    if len(text.encode("utf-8")) <= 1024:
        return text
    out = []
    n = 0
    for c in text:
        k = len(c.encode("utf-8"))
        if n + k > 1021:
            break
        out.append(c)
        n += k
    return "".join(out) + "..."


def joined(xs):
    return ", ".join(xs) if xs else "none"


def protected_flags(spec, recs, B, A):
    flags = []
    if spec is None:
        return flags
    for p in sorted(set(B) | set(A)):
        rec = recs.get(p)
        outcome = rec["outcome"] if rec else "unchanged"
        unknown = outcome == "unknown"
        b, a = B.get(p), A.get(p)
        matching = [r for r in spec.rules if pat_match(r.comps, p)]
        if not matching:
            continue
        prov = unknown
        # PS-M1 no_write
        for r in matching:
            if "no_write" not in r.modes:
                continue
            if b is not None and a is not None:
                hit = outcome in ("modified", "type_changed") or (
                    outcome == "metadata_only"
                    and set(rec["changed"]) & {"mode", "uid", "gid", "iflags", "caps", "xattrs"})
                if hit:
                    flags.append(Flag("protected_path_written", "violation",
                                      [("path", p), ("rule", r.pattern), ("outcome", outcome),
                                       ("changed", rec.get("changed"))],
                                      "%s: protected by %s (no_write), %s" % (show(p), r.pattern, outcome),
                                      [p], prov))
            break
        # PS-M2 no_delete
        for r in matching:
            if "no_delete" in r.modes:
                if b is not None and outcome == "removed":
                    flags.append(Flag("protected_path_deleted", "violation", [("path", p), ("rule", r.pattern)],
                                      "%s: protected by %s (no_delete), removed" % (show(p), r.pattern),
                                      [p], prov))
                break
        # PS-M3 no_create
        for r in matching:
            if "no_create" in r.modes:
                if a is not None and outcome == "added":
                    flags.append(Flag("protected_path_created", "violation", [("path", p), ("rule", r.pattern)],
                                      "%s: created where %s forbids it (no_create)" % (show(p), r.pattern),
                                      [p], prov))
                break
        # PS-M5 fail closed (P5, P6)
        hit_sides = set()
        for r in matching:
            sides = set()
            if ("no_write" in r.modes or "no_delete" in r.modes) and b is not None:
                sides.add("before")
                if "no_write" in r.modes and a is not None:
                    sides.add("after")
            if ("no_create" in r.modes or r.expected is not None) and a is not None:
                sides.add("after")
            hit_sides |= sides
        if hit_sides:
            ents = [e for s, e in (("before", b), ("after", a)) if s in hit_sides]
            flagged = [f for f in ENTRY_FLAGS if any(e[f] for e in ents)]
            if unknown or flagged:
                reasons = rec["unknown"] if unknown else flagged
                r = matching[0]
                flags.append(Flag("protected_path_unverifiable", "violation",
                                  [("path", p), ("rule", r.pattern), ("reasons", reasons)],
                                  "%s: protected by %s, cannot be verified: %s" % (show(p), r.pattern, joined(reasons)),
                                  [p], False))
    # PS-M4 expected_sha256 (P7)
    done = set()
    for r in spec.rules:
        if r.expected is None:
            continue
        p = r.pattern.encode("utf-8")
        if p in done:
            continue
        a = A.get(p)
        rec = recs.get(p)
        why = actual = None
        if a is None:
            why = "absent"
        elif a["type"] != "reg":
            why = "not a regular file"
        elif a["sha256"] is not None and a["sha256"] != r.expected:
            why, actual = "other bytes", a["sha256"]
        if why is None:
            continue
        done.add(p)
        flags.append(Flag("protected_hash_mismatch", "violation",
                          [("path", p), ("expected", r.expected), ("why", why), ("actual", actual)],
                          "%s: %s, expected sha256 %s" % (show(p), why, r.expected), [p],
                          rec is not None and rec["outcome"] == "unknown"))
    return flags


def package_flags(ctx, recs, B, A, events):
    flags = []
    frozen = ctx["frozen"]
    level = "violation" if frozen else "signal"
    named_pip = set()
    named_dpkg = set()
    for ev in events:
        if ev.interp not in ("pip", "dpkg") or not ev.kind.startswith(ev.interp + "_"):
            continue                                                                  # P10
        if ev.interp == "pip":
            package = ev.fields["name"]
            if ev.kind != "pip_reinstalled":                                          # decision 173
                named_pip.add(pep503(package))
        else:
            package = "%s:%s" % (ev.fields["package"], ev.fields["arch"])
            named_dpkg.add(package)
        fields = [("db", ev.interp), ("package", package), ("event", ev.kind), ("change", ev.text)]
        if not frozen:
            fields.append(("self_consistent", self_consistent(ev, recs, A, ctx["scope"])))
        flags.append(Flag("package_changed", level, fields, "%s: %s" % (ev.interp, ev.text),
                          ev.paths, ev.provisional))
    for line in ctx["bundle_lines"]:
        p = line["_path"]
        rec = recs.get(p)
        if line.get("conffile"):
            if rec is not None and rec["outcome"] in ("modified", "removed", "type_changed"):
                flags.append(Flag("conffile_changed", "signal",
                                  [("package", line["package"]), ("path", p), ("outcome", rec["outcome"])],
                                  "%s: conffile %s %s" % (line["package"], show(p), rec["outcome"]),
                                  [p], False))
            continue
        if line["at_reset"] == "no_hash":                                              # P8
            src = pyc_source(p)                                                       # decision 186
            if src is None or rec is None or rec["outcome"] not in ("modified", "type_changed"):
                continue                                                              # P36
            if src in recs:                                       # the source changed: recompiled
                continue
        if line["db"] == "pip" and pep503(line["package"]) in named_pip:
            continue
        if line["db"] == "dpkg" and line["package"] in named_dpkg:
            continue
        if rec is None:
            continue
        o = rec["outcome"]
        a = A.get(p)
        if o == "removed":
            why = "removed"
        elif o == "type_changed":
            why = "type changed"
        elif o == "unknown" or (a is not None and a["unverified"] and o == "modified"):
            why = "cannot be verified"
        elif o == "modified":
            why = "other bytes"
        else:
            continue
        flags.append(Flag("tampered_installed_package", level,
                          [("db", line["db"]), ("package", line["package"]), ("path", p), ("why", why),
                           ("at_reset", line["at_reset"])],
                          "%s: installed file %s %s" % (line["package"], show(p), why),
                          [p], o == "unknown"))
    return flags


def pyc_source(p):
    """The source of a `.pyc` (decision 186; P37), or None when `p` is not one."""
    if not p.endswith(b".pyc"):
        return None
    d = _parent(p)
    base = _name(p)[:-len(b".pyc")]
    if d != b"." and _name(d) == b"__pycache__":
        stem = re.sub(rb"\.opt-[0-9]+$", b"", base)
        name, dot, tag = stem.partition(b".")
        if name and dot and tag:
            top = _parent(d)
            return (b"" if top == b"." else top + b"/") + name + b".py"
    if not base:
        return None
    return (b"" if d == b"." else d + b"/") + base + b".py"


def self_consistent(ev, recs, A, scope):
    """P11: whether every file the package's database after lists matches it."""
    if ev.kind in ("pip_removed", "dpkg_removed"):
        return True
    if ev.interp == "pip":
        rp = [x for x in ev.paths if A.get(x) is not None]
        if not rp:
            return True
        rec_path = rp[0]
        data = held(A[rec_path])
        rows = record_rows(data) if data is not None else None
        if rows is None:
            return False
        holder, _n, _v = distinfo(rec_path)
        for path, h, _s in rows:
            hx = record_hex(h)
            if hx is None:
                continue
            q = resolve_lexically(holder, path, scope)
            if q is None:
                continue
            e = A.get(q)
            if e is None or e["type"] != "reg" or e["sha256"] != hx:
                return False
        return True
    status = ev.paths[0]
    st = parse_status(side_bytes(A.get(status)) or b"") or {}
    stanza = st.get((ev.fields["package"], ev.fields["arch"]))
    if stanza is None:
        return True
    rows = []
    for mp in md5sums_path(status, ev.fields["package"], ev.fields["arch"]):
        m = A.get(mp)
        if m is not None and m["type"] == "reg" and m["data"] is not None:
            rows = md5sums_rows(m["data"])
            break
    root = dpkg_root(status)
    for rel, md5 in rows:
        e = A.get(root + rel)
        if e is None or e["type"] != "reg" or e["data"] is None or hashlib.md5(e["data"]).hexdigest() != md5:
            return False
    return True


def other_flags(ctx, recs, B, A, events):
    spec = ctx["spec"]
    flags = []
    rec_after = record_paths_after(A, ctx["scope"])
    hooks = git_hook_findings(recs, B, A)
    for p, rec in sorted(recs.items()):
        o = rec["outcome"]
        prov = o == "unknown"
        b, a = B.get(p), A.get(p)
        name = _name(p)
        nc = not_captured_only(rec)           # a side not looked at is not held, never "absent" (P13)

        def copy_of(e):
            return None if nc and e is None else side_bytes(e)
        if is_test_file(p) and o in ("added", "removed", "modified", "type_changed"):
            flags.append(Flag("touches_tests", "signal", [("path", p), ("outcome", o)],
                              "%s: test file %s" % (show(p), o), [p], prov))
        if is_counted(p) and o in ("added", "removed", "modified", "type_changed", "unknown"):
            xb, xa = copy_of(b), copy_of(a)
            if xb is not None and xa is not None:
                ab, tb = count_python(xb)
                aa, ta = count_python(xa)
                mk = markers_added(xb, xa)
                emptied = (a is not None and a["type"] == "reg" and a["size"] == 0
                           and b is not None and b["type"] == "reg" and b["size"] > 0)
                if o == "removed" or emptied or aa < ab or ta < tb or mk:
                    flags.append(Flag("tests_weakened", "signal",
                                      [("path", p), ("language", "python"), ("assertions_before", ab),
                                       ("assertions_after", aa), ("tests_before", tb), ("tests_after", ta),
                                       ("markers_added", mk)],
                                      "%s: assertions %d -> %d, tests %d -> %d, markers added: %s"
                                      % (show(p), ab, aa, tb, ta, joined(mk)), [p], prov))
        if is_ci(p):
            flags.append(Flag("edits_ci_config", "signal", [("path", p), ("outcome", o)],
                              "%s: CI configuration %s" % (show(p), o), [p], prov))
        if name in PYTEST_FILES:
            xb, xa = copy_of(b), copy_of(a)
            if xb is not None and xa is not None:
                sec = pytest_change(p, xb, xa)
                if sec is not None:
                    flags.append(Flag("pytest_config_changed", "signal",
                                      [("path", p), ("section", sec), ("outcome", o)],
                                      "%s: pytest configuration %s %s" % (show(p), sec, o), [p], prov))
        if name == b"conftest.py":
            flags.append(Flag("conftest_changed", "signal", [("path", p), ("outcome", o)],
                              "%s: conftest.py %s, code pytest runs" % (show(p), o), [p], prov))
        if is_startup_hook(p) and o in ("added", "modified") and p not in rec_after:
            flags.append(Flag("python_startup_hook_changed", "signal", [("path", p), ("outcome", o)],
                              "%s: runs at every Python start, %s" % (show(p), o), [p], prov))
        if p in hooks:
            change, exe, target = hooks[p]
            hook = _name(p).decode("utf-8", errors="replace")
            flags.append(Flag("git_hook_changed", "signal",
                              [("path", p), ("hook", hook), ("change", change), ("executable", exe),
                               ("target", target)],
                              "%s: git hook %s %s" % (show(p), hook, change), [p], False))
        if a is not None and in_path_dir(p, A, spec):
            new_x = False
            if o in ("added", "type_changed"):
                new_x = a["type"] == "lnk" or (a["type"] == "reg" and a["mode"] & 0o111)
            elif b is not None and b["type"] == "reg" and a["type"] == "reg":
                new_x = bool(a["mode"] & 0o111 & ~b["mode"])
            if new_x:
                flags.append(Flag("new_executable_on_path", "signal",
                                  [("path", p), ("outcome", o), ("mode", a["mode"])],
                                  "%s: executable on PATH, %s" % (show(p), o), [p], prov))
        flags.extend(privilege(p, b, a, prov))
    for p, (repo, ref) in sorted(git_reflog_rewritten(recs, B, A).items()):
        flags.append(Flag("git_history_rewritten", "signal",
                          [("repo", repo.decode("utf-8", errors="replace")), ("branch", ref)],
                          "%s in %s: reflog rewritten" % (ref, show(repo)), [p], False))
    for ev in events:
        if ev.kind == "git_history_rewritten":
            f = ev.fields
            flags.append(Flag("git_history_rewritten", "signal",
                              [("repo", f["repo"]), ("branch", f["branch"]), ("how", f["how"])],
                              "%s in %s: history rewritten by %s" % (f["branch"], f["repo"], f["how"]),
                              ev.paths, ev.provisional))
    return flags


LOCKING_IFLAGS = 0x10 | 0x20          # Linux FS_IMMUTABLE_FL, FS_APPEND_FL


def privilege(p, b, a, prov):
    out = []

    def bits(e, m):
        return "on" if e is not None and e["mode"] & m else "off"
    for what, m in (("setuid", 0o4000), ("setgid", 0o2000), ("sticky", 0o1000)):
        x, y = bits(b, m), bits(a, m)
        if x != y:
            out.append((what, x, y))
    cb = b.get("caps") if b is not None else None
    ca = a.get("caps") if a is not None else None
    if cb != ca:
        out.append(("caps", cb or "none", ca or "none"))
    ib = b.get("iflags") if b is not None else None
    ia = a.get("iflags") if a is not None else None
    if (b is None) != (a is None):                                                      # P32
        report = bool(((ib if b is not None else ia) or 0) & LOCKING_IFLAGS)              # decision 163
    else:
        report = ib != ia
    if report:
        out.append(("iflags", "none" if ib is None else str(ib), "none" if ia is None else str(ia)))
    return [Flag("privilege_changed", "signal",
                 [("path", p), ("what", w), ("before", x), ("after", y)],
                 "%s: %s %s -> %s" % (show(p), w, x, y), [p], prov) for w, x, y in out]


def excluded_json(xs):
    out = []
    for x in xs:
        o = {}
        put_bytes(o, "path", x["path"])
        o["reason"] = x["reason"]
        o["dev"] = x["dev"]
        o["ino"] = x["ino"]
        out.append(o)
    return out


def verify_lines(ctx):
    """policy.v1's lines for one verify.

    ctx: scope (str), bundle_sha256, spec (Spec or None), before/after (Side), bundle_lines,
    outside_scope, before_sha256, after_sha256, walk_counts (six ints).
    """
    spec = ctx["spec"]
    ctx["frozen"] = spec.frozen if spec else False
    bs, as_ = ctx["before"], ctx["after"]
    B, A = bs.entries, as_.entries
    recs = diff(bs, as_)
    events = pip_events(recs, B, A) + dpkg_events(recs, B, A) + git_events(recs, B, A)
    flags = protected_flags(spec, recs, B, A)
    flags += package_flags(ctx, recs, B, A, events)
    flags += other_flags(ctx, recs, B, A, events)
    flags.sort(key=Flag.sort_key)
    hdr = {"belay_policy": 1}
    scope_b = ctx["scope"].encode("utf-8", errors="surrogateescape")
    if is_utf8(scope_b):
        hdr["scopes"] = [ctx["scope"]]
    else:
        hdr["scopes_b64"] = [b64(scope_b)]
    hdr["baseline_sha256"] = ctx["bundle_sha256"]
    hdr["protect_sha256"] = spec.digest if spec else None
    hdr["frozen_packages"] = ctx["frozen"]
    hdr["before_excluded"] = excluded_json(bs.excluded)
    hdr["after_excluded"] = excluded_json(as_.excluded)
    hdr["not_emitted"] = NOT_EMITTED
    hdr["tests_counted"] = ["python"]
    lines = [hdr] + [f.obj() for f in flags]
    tr = {"belay_policy_end": len(flags),
          "violations": sum(1 for f in flags if f.level == "violation"),
          "signals": sum(1 for f in flags if f.level == "signal")}
    for k in KINDS:
        tr[k] = sum(1 for f in flags if f.kind == k)
    tr["unknown"] = sum(1 for r in recs.values() if r["outcome"] == "unknown")
    tr["packages_outside_scope"] = ctx["outside_scope"]
    tr["packages_no_hash"] = sum(1 for l in ctx["bundle_lines"] if l["at_reset"] == "no_hash")     # P21
    tr["provisional"] = any(ctx.get("walk_counts", (0,) * 6))
    tr["before_sha256"] = ctx["before_sha256"]
    tr["after_sha256"] = ctx["after_sha256"]
    lines.append(tr)
    return lines, flags, recs, events


def after_excludes(bundle_excluded, configured, to):
    """P31: the paths verify's capture leaves out -- the bundle manifest's excludes; with `--to`,
    the checkpoint's own (the scope's configured ones when it was taken)."""
    if to is not None:
        return list(configured)
    return [x["path"] for x in bundle_excluded if x["reason"] == "user"]


def verify_exit(flags, exit_code_flag):
    """policy-v1, "The command's exit code"."""
    if exit_code_flag and any(f.level == "violation" for f in flags):
        return 1
    return 0


# ---------------------------------------------------------------------------------------------
# export and verify, end to end (refusals included)

def inside(path, scope):
    return path == scope or path.startswith(scope.rstrip("/") + "/")


def export_expect(scope, out_real, spec_raw, excluded, B_raw):
    """(exit, result): result is {hash_max, protect_sha256, lines, outside, integrity} on 0."""
    spec = None
    if spec_raw is not None:
        try:
            spec = parse_spec(spec_raw)
        except Refused as r:
            return r.code, r.why
    if inside(out_real, scope):
        return 3, "--out inside the scope"
    if spec is not None:
        for x in excluded:
            for r in spec.rules:
                if covers(r.comps, x["path"]):
                    return 3, "an exclusion covers %s" % r.pattern
    hash_max = HASH_BOUND_SPEC if spec is not None else HASH_DEFAULT
    B = view(B_raw, hash_max)
    lines, outside = bundle_packages(B, scope)
    integrity = []
    for l in lines:
        if l["at_reset"] != "match":
            o = {"db": l["db"], "package": l["package"], "version": l["version"]}
            put_bytes(o, "path", l["_path"])
            o["at_reset"] = l["at_reset"]
            integrity.append(o)
    return 0, {"hash_max": hash_max, "protect_sha256": spec.digest if spec else None,
               "spec": spec, "B": B, "lines": lines, "outside": outside,
               "integrity": integrity}


def verify_refusal(exported, spec_raw, digest_given, digest_true, excluded_after, to_trusted):
    """The refusal verify must give before judging, or None (policy-v1's exit codes)."""
    spec = None
    if spec_raw is not None:
        try:
            spec = parse_spec(spec_raw)
        except Refused as r:
            return r.code                                                             # P24
    if digest_given is None:
        return 3                                                                      # P23
    if digest_given != digest_true:
        return 3
    if (spec.digest if spec else None) != exported["protect_sha256"]:
        return 3                                                                      # P30
    if spec is not None:
        for x in excluded_after:
            for r in spec.rules:
                if covers(r.comps, x["path"]):
                    return 3
        if to_trusted:
            return 3
    return None


# ---------------------------------------------------------------------------------------------
# The bundle as export writes it (baseline-bundle.md B-1..B-7), checked against what the model
# expects of it: the layout and the package lines exactly; the manifest only as B-4 describes it.

HEADER_KEYS = {
    "bundle": (["belay_bundle", "size", "created_ns", "belay_version", "scopes", "hash_max_bytes",
                "protect_sha256"],
               ["belay_bundle", "size", "created_ns", "belay_version", "scopes_b64", "hash_max_bytes",
                "protect_sha256"]),
    "manifest": (["member", "size", "sha256"],),
    "copy": (["member", "size", "sha256"],),
    "packages": (["member", "size", "sha256", "outside_scope"],),
    "end": (["member", "size", "members"],),
}


def check_bundle(data, exp, scope):
    """Problems found (strings); sets exp["manifest_sha256"] from the manifest member."""
    problems = []
    members = []
    pos = 0
    exp["manifest_sha256"] = None
    while pos < len(data):
        nl = data.find(b"\n", pos)
        if nl < 0:
            problems.append("B-1: a header line without its newline at byte %d" % pos)
            break
        line = data[pos:nl + 1]
        if len(line) > 65536:
            problems.append("B-1: a header line over 65,536 bytes")
        try:
            hdr = json.loads(line)
        except ValueError:
            problems.append("B-1: a header line that is not JSON at byte %d" % pos)
            break
        if not isinstance(hdr, dict):
            problems.append("B-1: a header line that is not an object")
            break
        if (enc(hdr) + "\n").encode("utf-8") != line:
            problems.append("B-1: a header line not in the canonical encoding: %r" % line[:200])
        size = hdr.get("size")
        if type(size) is not int or size < 0:
            problems.append("B-1: no size")
            break
        content = data[nl + 1:nl + 1 + size]
        if len(content) != size:
            problems.append("B-1: content shorter than its size")
        kind = "bundle" if "belay_bundle" in hdr else hdr.get("member")
        members.append((kind, hdr, content))
        pos = nl + 1 + size
        if kind == "end":
            break
    if pos < len(data):
        problems.append("B-1: %d bytes after end" % (len(data) - pos))
    kinds = [k for k, _h, _c in members]
    want = ["bundle", "manifest"] + ["copy"] * kinds.count("copy") + ["packages", "end"]
    if kinds != want:
        problems.append("B-2: members %s, not %s" % (kinds, want))
    for kind, hdr, content in members:
        if kind not in HEADER_KEYS or list(hdr) not in [list(x) for x in HEADER_KEYS[kind]]:
            problems.append("B-3..B-7: %s's keys %s" % (kind, list(hdr)))
        if kind not in ("bundle", "end") and hdr.get("sha256") != sha256(content):
            problems.append("%s: sha256 is not its content's digest" % kind)
    by = {}
    for kind, hdr, content in members:
        by.setdefault(kind, []).append((hdr, content))
    if "bundle" in by:
        h = by["bundle"][0][0]
        scope_b = scope.encode("utf-8", errors="surrogateescape")
        want_scopes = [scope] if is_utf8(scope_b) else [b64(scope_b)]
        if h.get("belay_bundle") != 1 or h.get("size") != 0:
            problems.append("B-3: belay_bundle %r, size %r" % (h.get("belay_bundle"), h.get("size")))
        if h.get("scopes", h.get("scopes_b64")) != want_scopes:
            problems.append("B-3: scopes %r, not %r" % (h.get("scopes", h.get("scopes_b64")), want_scopes))
        if h.get("hash_max_bytes") != exp["hash_max"]:
            problems.append("B-3: hash_max_bytes %r, not %r" % (h.get("hash_max_bytes"), exp["hash_max"]))
        if h.get("protect_sha256") != exp["protect_sha256"]:
            problems.append("B-3: protect_sha256 %r, not %r" % (h.get("protect_sha256"), exp["protect_sha256"]))
        if type(h.get("created_ns")) is not int or type(h.get("belay_version")) is not str:
            problems.append("B-3: created_ns or belay_version of the wrong type")
    stored = set()
    if "manifest" in by:
        content = by["manifest"][0][1]
        exp["manifest_sha256"] = sha256(content)
        mlines = content.rstrip(b"\n").split(b"\n")
        try:
            mh = json.loads(mlines[0])
            mt = json.loads(mlines[-1])
            for ln in mlines[1:-1]:
                e = json.loads(ln)
                if "stored" in e:
                    stored.add(e["stored"])
        except ValueError:
            problems.append("B-4: the manifest is not NDJSON")
            mh, mt = {}, {}
        if mh.get("belay_manifest") != 2:
            problems.append("B-4: not manifest v2")
        if mh.get("hash_max_bytes") != exp["hash_max"]:
            problems.append("B-4/PS-C3: the manifest's hash_max_bytes %r, not %r" % (mh.get("hash_max_bytes"), exp["hash_max"]))
        if mt.get("trusted") != 0 or mt.get("read_all") != "check":
            problems.append("B-4: the manifest's trailer trusted %r, read_all %r" % (mt.get("trusted"), mt.get("read_all")))
        if "bundle" in by and mh.get("scopes", mh.get("scopes_b64")) != by["bundle"][0][0].get(
                "scopes", by["bundle"][0][0].get("scopes_b64")):
            problems.append("B-3: the bundle's scopes are not the manifest's")
    keys = [h.get("sha256") for h, _c in by.get("copy", [])]
    if keys != sorted(set(keys)):
        problems.append("B-2: copies not in ascending sha256 order, or repeated")
    if set(keys) != stored:
        problems.append("B-5: copies %d, stored keys %d, differ by %d" % (len(keys), len(stored), len(set(keys) ^ stored)))
    if "packages" in by:
        h, content = by["packages"][0]
        want_content = packages_member(exp["lines"])
        if content != want_content:
            got = content.decode("utf-8", errors="replace").split("\n")
            wl = want_content.decode("utf-8", errors="replace").split("\n")
            for d in difflib.unified_diff(wl, got, "model", "belay", lineterm="", n=0):
                problems.append("B-6 packages: " + d)
        if h.get("outside_scope") != exp["outside"]:
            problems.append("B-6: outside_scope %r, not %r" % (h.get("outside_scope"), exp["outside"]))
    if "end" in by:
        h = by["end"][0][0]
        if h.get("size") != 0 or h.get("members") != len(members) - 1:
            problems.append("B-7: end's members %r, not %d" % (h.get("members"), len(members) - 1))
    return problems
