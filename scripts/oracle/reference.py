#!/usr/bin/env python3
"""A naive reference comparator for diff.v1, written from the prose and the pins.

Its only sources:
  - docs/spec/diff-v1.md, PROSE ONLY: the "Shape" example (header, record and
    trailer keys, checked at run time against the lists below) and the
    sentence after it ("`before` is the first manifest given and `after` the
    second, whatever their `created_ns` say"), the "### Trailer" paragraph,
    "How an outcome is decided" (one-sided paths, rules 1-6), "Devices and
    identity", "Timestamps that move on use", "A directory's own timestamps",
    the `type_before` sentence, the `changed` / `unknown` paragraph and "An
    absent record means `unchanged`";
  - docs/spec/manifest-v1.md, PROSE ONLY: "Encoding" (the canonical string)
    and, under "Field rules a reader MUST enforce", what `xattrs_sha256` is;
  - test/expect/diff-fields.md, READ AT RUN TIME: for each field its
    `compared as`, `for types`, `on mount roots` and `absent means`, and the
    outcome rules O1-O8 (the text of O2, O5, O6, O7 and O8 checked at
    start-up where this file relies on it);
  - test/expect/manifest-v1.md, read at run time for the entry types;
  - docs/spec/diff-v1.md "Interpreters" and "What each interpreter reports",
    PROSE ONLY, with test/expect/finding-kinds.md (the kinds, read at run
    time) and test/expect/diff-events.md (E1-E8): the findings a record
    carries and the event records, in the oracle's setting -- mostly a diff
    given no store, so every stored copy an interpreter needs is
    `content_unavailable`. What would need text, pip or dpkg content
    (text_changed, a RECORD's rows, a status file's stanzas) is not
    modelled: no pair's store holds such a copy (read_copy() asserts it);
  - git's content, from a store the pair gives the diff ("Content": the
    store's layout, a copy hashed against its name): diff-v1's "**git.**"
    paragraph (HEAD, loose refs, packed-refs, reflogs) and the paragraph
    after it, with test/expect/diff-events.md E4 (git's order) and E12
    (repository-level events: a branch's value on each side, created,
    deleted, renamed, commits added, history rewritten, moved, HEAD
    switched, `unknown` paths read and their events provisional, one
    `content_unavailable` event per reason) and finding-kinds.md's seven git
    event kinds (decisions 126, 132), each sentence relied on checked at
    start-up. git's file formats are git's own (git_explain());
  - test/expect/manifest-v1-addendum.md A4 (a link target is at most 4,095
    bytes), which finding-kinds.md cites as a `bytes` field's bound;
  - test/expect/diff-values.md, READ AT RUN TIME (V1-V6 and its field table,
    the words record_values() relies on checked at start-up), with
    test/expect/manifest-v1.md's Keys table (a key's spellings, `a|b`): the
    `before` and `after` objects of a record;
  - docs/spec/diff-v1.md "## Shape", PROSE ONLY, for V5's "stated in
    diff-v1": no line has a fixed length bound;
  - test/expect/manifest-v2.md V2-R4: `before_manifest_version` and
    `after_manifest_version`, each manifest's `belay_manifest`; nothing else
    depends on the version (the entries are v1's, and of the keys v2 adds
    only `excluded` is read: V2-R6);
  - test/expect/manifest-v2.md V2-R7, READ AT RUN TIME (its words checked at
    start-up): the header ends with `before_excluded` and `after_excluded`,
    after `after_manifest_version`, each manifest's `excluded` as its header
    writes it, `null` for a v1 manifest; they decide nothing;
  - docs/spec/diff-v1.md "Present on one side only", its first bullet: a
    path the side lacking it excluded, or below one (checked at start-up,
    with the list's order), with test/expect/manifest-v2.md V2-2 (what an
    `excluded` element holds);
  - test/expect/diff-events.md E11 and the prose's "Event records" and "What
    each interpreter reports" (checked at start-up): a path `unknown` only
    as `not_captured` derives no event -- the core's `could_not_interpret`
    and `content_unavailable` included, and E6's list never names it
    (decision 118);
Never the generated blocks of the spec, never src/ or include/: every check
that quotes a spec reads it through spec_prose(), which withholds them
(decision 119); a check that quotes a pin reads that pin.

Ambiguities this file resolves one way (questions for the author) are
marked "ambiguity I<n>" where they are decided (VA<n> for diff-values.md,
G<n> for git's events, E12; G1 and G4 are settled by the prose, which now
says "pip, dpkg and git emit one `could_not_interpret` event naming it
(E10)" and "git names only the paths it derives events from (HEAD,
branches, `packed-refs`, their reflogs), and a reflog removed needs no
copy"):
  G2 `repo` is the path of the directory named `.git` (`.git` at the root);
  G3 a reflog that is not a prefix of its after gained no entries;
  G5 a ref or packed-refs that cannot be parsed ("nothing more is read
     from it") gives no value on any side it is on, as one that cannot be
     read gives none on that side (E12, decision 137): before, the
     reflog's evidence or no `from`; after, no event;
  G6 a rename takes its `from`'s place in E4's "then branch";
  G7, G8 are settled by E12 (decision 137): "a reflog only when its
     entries were used -- giving the value before or evidence of absence
     before, a rename, or how the branch moved (entries that lead from
     before to after but say not how are not used)"; packed-refs is named
     where its line or its absence gave a value, never where it gave none
     ("every ref, `packed-refs` and `HEAD` path whose value the event
     uses"), and a removed reflog gives nothing;
  G9 a packed-refs absent on a side, being a path of this diff, is
     "packed-refs without it" there;
  G10 a loose ref there before and not read is not absent by its reflog's
     zeros: that it was there is "the fact the refs give" -- no value
     before, so `git_branch_moved` with no `from`;
  G11 a loose ref removed whose value before is not told derives no
     event: `git_branch_deleted` needs `was`, and the "`git_branch_moved`
     with no `from`" a `to`;
  G12 HEAD not read on a side derives no event (git_head_switched's
     `from` and `to` are required; HEAD is a branch only when detached on
     both sides).

Deliberately naive: both manifests in memory as dictionaries, the union of
their paths sorted, ancestors found by walking a path's prefixes.

    reference.py <before> <after>   prints the expected diff, one JSON line each

What the prose leaves to generated tables:
  - the order of the reasons in `unknown` ("in the order of the reasons
    table") is NOT predicted here: compare.py compares the reasons as a set,
    plus one global order that every record must respect;
  - the order of the outcome counts in the trailer ("in the order of the
    outcomes table") is the one the "Shape" example shows;
  - the order of a record's keys after `path`, `outcome` and `type` (the
    record table is generated): compare.py does not check it -- except
    where a pin states it in words: `before` and `after` "after `changed`
    and before `unknown`" (diff-values V1, V6).
"""
import base64, collections, hashlib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
FIELDS_PIN = os.path.join(REPO, 'test', 'expect', 'diff-fields.md')
MANIFEST_PIN = os.path.join(REPO, 'test', 'expect', 'manifest-v1.md')
SPEC = os.path.join(REPO, 'docs', 'spec', 'diff-v1.md')
# Where a generated block was (spec_prose()): no quote can match across it.
WITHHELD = '\n<!-- a generated block, withheld from the oracle -->\n'


def spec_prose(path):
    """A spec's text with every generated block removed (decision 119): the
    oracle quotes prose only, so a sentence that someday appeared only in a
    generated table fails its check. A block runs from a line `<!-- BEGIN
    GENERATED: <name> -->` to the line `<!-- END GENERATED: <name> -->`;
    each becomes WITHHELD. An END without its BEGIN, a BEGIN inside a block
    or never ended, or names that differ stop the oracle rather than keep or
    drop text silently. Pins (test/expect/) have no generated blocks and are
    read whole."""
    out, inside = [], None
    for n, line in enumerate(open(path, encoding='utf-8').read().split('\n'), 1):
        m = re.fullmatch(r'\s*<!-- (BEGIN|END) GENERATED(?::\s*(\S+))?\s*-->\s*', line)
        if m is None and 'GENERATED' in line and '<!--' in line:
            raise SystemExit('spec: %s:%d: a GENERATED marker spec_prose() does not read: %r'
                             % (path, n, line))
        if m is None:
            if inside is None:
                out.append(line)
        elif m.group(1) == 'BEGIN':
            if inside is not None:
                raise SystemExit('spec: %s:%d: BEGIN GENERATED inside %r' % (path, n, inside))
            inside = m.group(2) or ''
            out.append(WITHHELD)
        else:
            if inside != (m.group(2) or ''):
                raise SystemExit('spec: %s:%d: END GENERATED %r closes %r'
                                 % (path, n, m.group(2), inside))
            inside = None
    if inside is not None:
        raise SystemExit('spec: %s: BEGIN GENERATED %r is never ended' % (path, inside))
    return '\n'.join(out)

# The header's and the trailer's keys, in order. The header's from the "Shape"
# example (its first line); `scopes` is spelled `scopes_b64` when the scope
# is not UTF-8 (ambiguity A9). Then V2-R7's two (test/expect/manifest-v2.md):
# "`before_excluded` and `after_excluded`, after `after_manifest_version`".
# The example predates V2-R7 and does not show them (ambiguity X2: the pin,
# approved later and explicit about the place, is followed; the example is
# accepted with them or without them, so it may be brought up to date).
HEADER_KEYS_SHAPE = ['belay_diff', 'scopes', 'before_created_ns', 'after_created_ns',
                     'before_hash_max_bytes', 'after_hash_max_bytes', 'scope_remounted',
                     'identity_compared', 'before_manifest_version', 'after_manifest_version']
EXCLUDED_KEYS = ['before_excluded', 'after_excluded']
HEADER_KEYS = HEADER_KEYS_SHAPE + EXCLUDED_KEYS
# The trailer's from the "### Trailer" paragraph: "`belay_diff_end` is the
# number of records written. Then come one count per outcome, named as the
# outcome, ... `unchanged` included" (in the example's order) ...
OUTCOMES = ['unchanged', 'added', 'removed', 'modified', 'type_changed', 'metadata_only',
            'unknown']
# ... "`dir_timestamps_only` counts the directories among `unchanged` whose own
# timestamps differ (see "A directory's own timestamps")" ...
DIR_TIMESTAMPS_ONLY = 'dir_timestamps_only'
# ... "`before_vanished`, `before_unstable` and `before_raced` are the first
# manifest's `vanished`, `unstable` and `raced` counts, and `after_vanished`,
# `after_unstable` and `after_raced` the second's. `provisional` is `true`
# exactly when any of those six is not 0 ... Last, `before_sha256` and
# `after_sha256` are the sha256 of each manifest file's bytes, all of them".
INPUT_COUNTS = ['vanished', 'unstable', 'raced']
# ... "and `events` the event records (`belay_diff_end` counts path records
# only)" ...
EVENTS = 'events'
TRAILER_KEYS = (['belay_diff_end'] + OUTCOMES + [DIR_TIMESTAMPS_ONLY, EVENTS]
                + ['before_' + c for c in INPUT_COUNTS] + ['after_' + c for c in INPUT_COUNTS]
                + ['provisional', 'before_sha256', 'after_sha256'])
# One-sided reasons, from "Present on one side only".
NOT_CAPTURED, LISTING_INCOMPLETE, RACED = 'not_captured', 'listing_incomplete', 'raced'
# docs/spec/diff-v1.md, "Present on one side only": its rules are ordered,
# and the first is what a path the side lacking it excluded means for the
# diff (manifest-v2.md's "Readers" points there). one_sided() takes them in
# that order. Tied to the spec's words at start-up (excluded_rule()): the
# order sentence, the exclusion bullet, and the start of the bullet after it
# -- so the exclusion is still the first.
EXCLUDED_RULE = ('The first of these that applies decides: '
                 '- The side that lacks it excluded the path, or a path above it (manifest '
                 'v2\'s `excluded`, `manifest-v2.md`): `unknown`, reason `not_captured`. That '
                 'manifest did not look there, so its absence says nothing -- never `added` or '
                 '`removed`. A path both manifests excluded is in neither, and in no record: '
                 'the header\'s `before_excluded` and `after_excluded` name it '
                 '(`manifest-v2.md`, V2-R7). '
                 '- That ancestor is a directory carrying `unreadable` or `mount`')


def excluded_rule():
    text = ' '.join(spec_prose(SPEC).split())
    if EXCLUDED_RULE not in text:
        raise SystemExit('reference: docs/spec/diff-v1.md no longer says %r; review '
                         'one_sided() first' % EXCLUDED_RULE)


excluded_rule()


def shape_example_keys():
    """The keys of the first (header) and last (trailer) line of the example
    under "## Shape" in docs/spec/diff-v1.md -- prose, not a generated block."""
    text = spec_prose(SPEC)
    m = re.search(r'^## Shape\n.*?^```json\n(.*?)^```', text, re.S | re.M)
    if not m:
        raise SystemExit('spec: no example under "## Shape" in %s' % SPEC)
    lines = m.group(1).splitlines()
    keys = lambda line: [k for k, _ in json.loads(line, object_pairs_hook=list)]
    return keys(lines[0]), keys(lines[-1])


_shape_header, _shape_trailer = shape_example_keys()
if _shape_header not in (HEADER_KEYS_SHAPE, HEADER_KEYS) or _shape_trailer != TRAILER_KEYS:
    raise SystemExit('spec: the "Shape" example\'s header or trailer keys are not the ones '
                     'reference.py writes: %r' % (shape_example_keys(),))

# test/expect/manifest-v2.md V2-R7, the words diff()'s header and
# header_excluded() rely on: the two
# keys and their place, the value (the manifest's own `excluded`, written as
# its header writes it; `null` for v1), and that they decide nothing. V2-R4
# still says the versions are "at the end of the header"; V2-R7, approved
# later, puts these two after them (ambiguity X3: V2-R7 is followed).
MANIFEST_V2_PIN = os.path.join(REPO, 'test', 'expect', 'manifest-v2.md')
V2_R7 = ['The diff header carries what each manifest left out: `before_excluded` and '
         '`after_excluded`, after `after_manifest_version`, each that manifest\'s `excluded` '
         'array as its header writes it',
         '`[]` when none), and `null` for a v1 manifest, which does not say what it left out',
         'Like V2-R4 they decide nothing',
         'a path both sides excluded is in no record and only here']


def v2_r7():
    """Called once the table reader is defined (below)."""
    rows = [split_row(l) for l in open(MANIFEST_V2_PIN, encoding='utf-8').read().splitlines()
            if l.startswith('| V2-R7 |')]
    if len(rows) != 1 or len(rows[0]) != 2:
        raise SystemExit('pin: manifest-v2.md has no one V2-R7 row')
    for w in V2_R7:
        if w not in rows[0][1]:
            raise SystemExit('pin: manifest-v2.md V2-R7 no longer says what reference.py '
                             'assumes: %r' % w)

# ---------------------------------------------------------------------------
# The pins, parsed at run time.


def split_row(line):
    """Cells of one markdown table row; `\\|` is a literal bar."""
    cells, cur, i, s = [], '', 0, line.strip()
    assert s.startswith('|') and s.endswith('|'), line
    s = s[1:-1]
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s) and s[i + 1] == '|':
            cur += '|'
            i += 2
            continue
        if s[i] == '|':
            cells.append(cur.strip())
            cur = ''
        else:
            cur += s[i]
        i += 1
    cells.append(cur.strip())
    return cells


def md_table(text, first_header):
    """Rows (as dicts) of the table whose header row's first cell is `first_header`."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith('|') and split_row(line)[0] == first_header:
            head = split_row(line)
            rows = []
            for l2 in lines[i + 2:]:
                if not l2.startswith('|'):
                    break
                cells = split_row(l2)
                assert len(cells) == len(head), l2
                rows.append(dict(zip(head, cells)))
            return rows
    raise SystemExit('pin: no table starting with %r' % first_header)


def entry_types():
    rows = md_table(open(MANIFEST_PIN, encoding='utf-8').read(), 'type')
    return [r['type'] for r in rows]


TYPES = entry_types()

# `compared as` vocabulary (diff-fields.md, "Columns").
KEY, TYPE, CONTENT, METADATA, IDENTITY, DEVREL, INO, CTIME, FLAG, NOTCMP = (
    'key', 'type', 'content', 'metadata', 'identity', 'identity: device relation',
    'identity: within one device', 'ctime', 'flag', 'not compared')
COMPARED_CLASSES = (CONTENT, METADATA, IDENTITY, DEVREL, INO)
# `absent means` vocabulary.
ABSENT = {'required', 'unknown', 'none if read', 'none', 'with unverified',
          'only on its types', 'n/a', 'flag'}


class Field:
    def __init__(self, row):
        self.name = row['field']
        ca = row['compared as']
        m = re.fullmatch(r'flag: (content|metadata|everything) unknown', ca)
        if m:
            self.cls, self.scope = FLAG, m.group(1)
        elif ca in (KEY, TYPE, CONTENT, METADATA, IDENTITY, DEVREL, INO, CTIME, NOTCMP):
            self.cls, self.scope = ca, None
        else:
            raise SystemExit('pin: unknown `compared as` %r for %s' % (ca, self.name))
        ft = row['for types']
        self.types = None if ft == 'all' else frozenset(t.strip() for t in ft.split(','))
        if self.types is not None and not self.types <= set(TYPES):
            raise SystemExit('pin: unknown type in %r for %s' % (ft, self.name))
        omr = row['on mount roots']
        if omr not in ('compared', 'not compared'):
            raise SystemExit('pin: unknown `on mount roots` %r for %s' % (omr, self.name))
        self.on_mount_roots = omr == 'compared'
        self.absent = row['absent means']
        if self.absent not in ABSENT:
            raise SystemExit('pin: unknown `absent means` %r for %s' % (self.absent, self.name))
        self.source = row['source']
        # A field that is "not compared" itself but is another field's
        # spelling ("compared as `xattrs`", in its source column).
        m = re.search(r'compared as `([a-z0-9_]+)`', self.source)
        self.spelling_of = m.group(1) if (m and self.cls == NOTCMP) else None

    def applies(self, t):
        return self.types is None or t in self.types


def load_fields():
    rows = md_table(open(FIELDS_PIN, encoding='utf-8').read(), 'field')
    fields = collections.OrderedDict((r['field'], Field(r)) for r in rows)
    rules = {r['rule']: r['statement'] for r in
             md_table(open(FIELDS_PIN, encoding='utf-8').read(), 'rule')}
    # The few places where this file relies on a field by name, each tied to
    # the text that justifies it; a pin change that breaks one stops the run.
    need = {
        'path': lambda f: f.cls == KEY,
        'type': lambda f: f.cls == TYPE,
        'dev': lambda f: f.cls == DEVREL,
        'mount': lambda f: f.cls == FLAG,          # "an entry carrying `mount`" = a mount root
        'unreadable': lambda f: f.cls == FLAG,
        'link_target': lambda f: 'neither side is `unreadable`' in f.source,
        'xattrs_sha256': lambda f: f.spelling_of == 'xattrs',
    }
    for name, ok in need.items():
        if name not in fields or not ok(fields[name]):
            raise SystemExit('pin: row %r no longer says what reference.py assumes' % name)
    for r in ('O1', 'O2', 'O3', 'O4', 'O5', 'O6', 'O7', 'O8'):
        if r not in rules:
            raise SystemExit('pin: outcome rule %s missing' % r)
    # The words of each rule that both_sides() relies on.
    said = {
        # O2: "With `xattrs_unknown` on either side, or on a mount root (never
        # read), they are not compared" -- whatever the `on mount roots`
        # column says for caps and xattrs (one version of the pin said
        # `compared`).
        'O2': ['on a mount root'],
        # O6: one-sided `iflags` is `unknown`, but across a type change it is
        # `type_changed` (the type-change branch comes before any field).
        'O6': ['present on one side only', '`unknown` (reason `iflags_unknown`)',
               'unless the type differs, which gives `type_changed`'],
        # O7: across a type change, the reasons of a raced `unknown` are the
        # flags' alone (that branch returns flag_reasons(), no field's).
        'O7': ['Across a type change no field is compared', '`changed` is `["type"]`',
               "its reasons are those of the flags on either side, never a field's"],
        # O8, in flag_reasons(): `unverified` on a mount side gives no reason,
        # on the other side it gives its own.
        'O8': ['`unverified` on a side that also carries `mount` adds no reason',
               '`unverified` on the other side still gives its own'],
    }
    for r, words in said.items():
        for w in words:
            if w not in rules[r]:
                raise SystemExit('pin: %s no longer says what reference.py assumes: %r'
                                 % (r, w))
    return fields, rules


def prose_unknown_carveout():
    """docs/spec/diff-v1.md, the `unknown` sentence after "`changed`, for a
    path present on both sides": "the reasons of every flag on either side --
    except `unverified` on a side that also carries `mount` ...". Pin O8 says
    the same; the prose is checked too, so that neither can drop it alone."""
    text = ' '.join(spec_prose(SPEC).split())
    want = ('`unknown`, for an `unknown` outcome: the reasons of every flag on either side -- '
            'except `unverified` on a side that also carries `mount`')
    if want not in text:
        raise SystemExit('spec: the `unknown` sentence no longer carves out `unverified` beside '
                         '`mount` (pin O8), which reference.py assumes')


def o5_timestamps(fields, rules):
    """The fields O5 names ("A directory whose `ctime_ns` or `mtime_ns`
    differs ..."): a directory's own timestamps, which the trailer counts.
    O5 holds only while the table compares none of them on a directory."""
    st = rules['O5']
    names = [f for f in fields if '`%s`' % f in st]
    if 'directory' not in st or not names or any(fields[f].applies('dir') for f in names):
        raise SystemExit('pin: O5 no longer says what reference.py assumes: %r' % st)
    return names


FIELDS, RULES = load_fields()
v2_r7()
prose_unknown_carveout()
DIR_TIMESTAMPS = o5_timestamps(FIELDS, RULES)
FIELD_ORDER = list(FIELDS)          # `changed` lists fields in this order (the
                                    # manifest's key order; the prose example's
                                    # ["size","mtime_ns","sha256"] follows it)
FLAGS = [f for f, s in FIELDS.items() if s.cls == FLAG]
SPELLINGS = collections.defaultdict(list)   # field -> its other spellings
for _f, _s in FIELDS.items():
    if _s.spelling_of:
        SPELLINGS[_s.spelling_of].append(_f)
if dict(SPELLINGS) != {'xattrs': ['xattrs_sha256']}:     # the one digest formula: as_digest
    raise SystemExit('pin: a spelling reference.py has no formula for: %r' % dict(SPELLINGS))

# ---------------------------------------------------------------------------
# Manifests.


def b64(s):
    return base64.b64decode(s.encode('ascii'), validate=True)


def trailer_of(path):
    """The manifest's own trailer, and the sha256 of the file: "of each
    manifest file's bytes, all of them" ("### Trailer")."""
    with open(path, 'rb') as f:
        raw = f.read()
    return json.loads(raw.rstrip(b'\n').split(b'\n')[-1].decode('utf-8')), hashlib.sha256(raw).hexdigest()


def excluded(header):
    """A manifest's `excluded` (manifest-v2.md, V2-2), {path bytes: element}:
    each element's `path` or `path_b64`, as an entry's; {} for a version 1
    manifest, which has none."""
    out = {}
    for d in header.get('excluded', []):
        out[b64(d['path_b64']) if 'path_b64' in d else d['path'].encode('utf-8')] = d
    return out


def header_excluded(path):
    """V2-R7: the value of the diff header's `before_excluded` or
    `after_excluded` for the manifest at path -- "that manifest's `excluded`
    array as its header writes it" (its objects as [(key, value)], in the
    header's order: path or path_b64, reason, dev, ino), "and `null` for a v1
    manifest" (None). Also (header line bytes, the array's bytes), so that
    compare.py can check the diff writes those very bytes."""
    with open(path, 'rb') as f:
        line = f.readline().rstrip(b'\n')
    h = json.loads(line.decode('utf-8'), object_pairs_hook=list)
    d = dict(h)
    if d['belay_manifest'] == 1:
        if 'excluded' in d:
            raise ValueError('%s: a version 1 header with `excluded`' % path)
        return None, line, None
    v = d['excluded']
    raw = b'"excluded":' + canonical(v)
    if raw not in line:
        raise ValueError('%s: `excluded` not written canonically' % path)
    return v, line, canonical(v)


def covering(excl, p):
    """The path of `excl` that p is at or below, or None."""
    if p in excl:
        return p
    for i in range(len(p) - 1, 0, -1):
        if p[i:i + 1] == b'/' and p[:i] in excl:
            return p[:i]
    return None


def load(path, raw=None):
    """(header, scope bytes, {path bytes: entry}). An entry's `path` and
    `link_target` are bytes whichever spelling the manifest used. With `raw`
    (a dict), raw[path bytes] is also the entry exactly as the manifest
    wrote it: its keys (`link_target_b64`, `xattrs_sha256`) and values, for
    the values a record carries (diff-values V1, V3)."""
    with open(path, 'rb') as f:
        lines = f.read().split(b'\n')
    if lines and lines[-1] == b'':
        lines.pop()
    objs = [json.loads(l.decode('utf-8')) for l in lines]
    header, body = objs[0], objs[1:-1]
    if 'belay_manifest' not in header or 'belay_manifest_end' not in objs[-1]:
        raise ValueError('%s: not a manifest' % path)
    entries = {}
    for d in body:
        e = dict(d)
        if raw is not None:
            raw[b64(d['path_b64']) if 'path_b64' in d else d['path'].encode('utf-8')] = d
        e['path'] = b64(e.pop('path_b64')) if 'path_b64' in e else e['path'].encode('utf-8')
        if 'link_target_b64' in e:
            e['link_target'] = b64(e.pop('link_target_b64'))
        elif 'link_target' in e:
            e['link_target'] = e['link_target'].encode('utf-8')
        entries[e['path']] = e
    scope = (b64(header['scopes_b64'][0]) if 'scopes_b64' in header
             else header['scopes'][0].encode('utf-8'))
    return header, scope, entries


# ---------------------------------------------------------------------------
# One path present on one side only ("Present on one side only").


def nearest_ancestor(entries, p):
    """The deepest entry whose path, followed by '/', begins p; else the root."""
    for i in range(len(p) - 1, 0, -1):
        if p[i:i + 1] == b'/' and p[:i] in entries:
            return entries[p[:i]]
    return entries[b'.']


def one_sided(p, present, lacking_entries, added, lacking_excluded):
    """The bullets of "Present on one side only", in their order: "The first
    of these that applies decides". The first: "The side that lacks it
    excluded the path, or a path above it (manifest v2's `excluded`,
    `manifest-v2.md`): `unknown`, reason `not_captured`" -- before the side
    that lacks the path is looked at for an `unstable` ancestor directory
    (listing_incomplete) and before `raced` on the side that has it. (This
    was ambiguity X1, decided here the same way before the spec stated it.)
    A path that one side excluded can lack no other way: nothing at or below
    it is recorded there."""
    trace = ['one-sided']
    if covering(lacking_excluded, p) is not None:
        return 'unknown', [NOT_CAPTURED], trace + ['excluded']
    anc = nearest_ancestor(lacking_entries, p)
    if anc['type'] == 'dir' and (anc.get('unreadable') or anc.get('mount')):
        return 'unknown', [NOT_CAPTURED], trace + [
            'not_captured', 'not_captured:' + ('unreadable' if anc.get('unreadable') else 'mount')]
    if anc['type'] == 'dir' and anc.get('unstable'):
        return 'unknown', [LISTING_INCOMPLETE], trace + ['listing_incomplete']
    # "It is not a directory and carries `raced`: `unknown`, reason `raced`.
    # It changed after it was recorded, and may have become a directory
    # holding this path before that walk ended."
    if anc['type'] != 'dir' and anc.get(RACED):
        return 'unknown', [RACED], trace + ['raced-ancestor']
    if present.get(RACED):
        return 'unknown', [RACED], trace + ['raced-one-sided']
    return ('added' if added else 'removed'), [], trace + ['known-absence']


# ---------------------------------------------------------------------------
# One path present on both sides ("Present on both sides", rules 1-6).


def value(e, f):
    """A field's value; a field with another spelling (xattrs / xattrs_sha256)
    is (spelling, value). None when absent."""
    if f in SPELLINGS:
        if f in e:
            return (f, tuple(e[f]) if isinstance(e[f], list) else e[f])
        for alt in SPELLINGS[f]:
            if alt in e:
                return (alt, e[alt])
        return None
    return e.get(f)


def canonical_string(s):
    """The bytes a writer emits for the JSON string s, quotes included:
    manifest-v1.md "Encoding" -- `string := '"' ( byte >= 0x20 other than '"'
    and '\\' | escape )* '"'`, `escape := \\" | \\\\ | \\b | \\f | \\n | \\r |
    \\t | \\u00XX` (\\u00XX only for a control byte with no short form,
    lowercase hex). The encoding is canonical, so these are the bytes."""
    short = {'"': b'\\"', '\\': b'\\\\', '\b': b'\\b', '\f': b'\\f', '\n': b'\\n',
             '\r': b'\\r', '\t': b'\\t'}
    out = []
    for c in s:
        if c in short:
            out.append(short[c])
        elif ord(c) < 0x20:
            out.append(b'\\u%04x' % ord(c))
        else:
            out.append(c.encode('utf-8'))
    return b'"' + b''.join(out) + b'"'


def xattrs_digest(items):
    """manifest-v1.md, "Field rules a reader MUST enforce": "`xattrs_sha256`
    is the sha256 of the bytes `xattrs` would hold between its brackets,
    exactly as a writer emits them -- each element in its double quotes, in
    order, joined by `,` with no space". Spelled as the format spells every
    sha256, lowercase hex (ambiguity: the sentence does not say)."""
    return hashlib.sha256(b','.join(canonical_string(x) for x in items)).hexdigest()


def as_digest(v):
    """A set's digest from its (spelling, value): computed when inline."""
    return xattrs_digest(v[1]) if v[0] == 'xattrs' else v[1]


def values_differ(f, vb, va):
    """A set spelled inline on one side and by its digest on the other
    (xattrs / xattrs_sha256, "compared as `xattrs`" in the pin) compares by
    the digest: "so a set recorded inline in one manifest and by digest in
    another compares equal" (manifest-v1.md, the rule xattrs_digest quotes)."""
    if f in SPELLINGS and vb is not None and va is not None and vb[0] != va[0]:
        return as_digest(vb) != as_digest(va)
    return vb != va


UNVERIFIED, MOUNT = 'unverified', 'mount'


def flag_reasons(b, a, trace):
    """The reasons of the flags on either side, in the pin's field order
    (compare.py compares them as a set, the order apart): "the reasons of every flag on either side --
    except `unverified` on a side that also carries `mount`, since a mounted
    regular file is never read and `mount` is that reason" (diff-v1.md, the
    `unknown` sentence); pin O8: "`unverified` on a side that also carries
    `mount` adds no reason ... `unverified` on the other side still gives its
    own". Across a type change too: O7's "those of the flags on either side"
    are these."""
    def gives(side, f):
        return bool(side.get(f)) and not (f == UNVERIFIED and side.get(MOUNT))
    for side, other in ((b, a), (a, b)):
        if side.get(UNVERIFIED) and side.get(MOUNT):
            trace.append('O8' if not other.get(UNVERIFIED) or other.get(MOUNT)
                         else 'O8-other-side-gives-unverified')
    return [f for f in FLAGS if gives(b, f) or gives(a, f)]


def both_sides(b, a, ctx):
    """(outcome, changed, unknown reasons, trace)."""
    trace = []
    flags = [f for f in FLAGS if b.get(f) or a.get(f)]
    scopes = {FIELDS[f].scope for f in flags}       # what the flags make unknown
    flag_why = flag_reasons(b, a, trace)            # the reasons they give (O8)
    # Either side ("on an entry that is a mount root on either side",
    # "Timestamps that move on use"; for timestamps, ambiguity A2).
    mount_root = bool(b.get('mount') or a.get('mount'))
    if mount_root:
        trace.append('mount-root')
    # caps/xattrs "were read on both sides": no metadata-unknown flag on
    # either side and neither side a mount root (O2, checked in load_fields;
    # prose `changed` paragraph).
    read_both = not mount_root and 'metadata' not in scopes

    # Fields whose absence means "could not be read" (`absent means: unknown`),
    # present on one side only: unknown under rule 4 (`iflags_unknown`) --
    # where the field is compared at all: by type, and on a mount root only
    # when the pin's `on mount roots` column says `compared`.
    def one_sided_unknown(types):
        out = []
        for f, s in FIELDS.items():
            if s.absent == 'unknown' and all(s.applies(t) for t in types) and \
                    (f in b) != (f in a):
                if mount_root and not s.on_mount_roots:
                    trace.append('not-on-mount-root:' + f)
                    continue
                out.append(f)
        return out

    if b['type'] != a['type']:                                   # rule 2 (after rule 1)
        trace.append('type')
        if 'everything' in scopes:                               # rule 1
            # "...and, when the types are the same, of every field unknown
            # under rule 4": across a type change no field is compared --
            # O7: "its reasons are those of the flags on either side, never a
            # field's (no `iflags_unknown`)"; which flags give one: O8.
            return 'unknown', ['type'], flag_why, trace + ['rule1']
        # O6: one-sided `iflags` "unless the type differs, which gives
        # `type_changed`" -- no field is looked at here.
        return 'type_changed', ['type'], [], trace + ['rule2']

    t = a['type']
    changed, proof, meta = [], False, False
    unk_fields = one_sided_unknown({t})
    if unk_fields:
        trace.append('iflags-one-sided' if unk_fields == ['iflags'] else 'one-sided-unknown')
    for f, s in FIELDS.items():
        if s.cls not in COMPARED_CLASSES:
            continue
        vb, va = value(b, f), value(a, f)
        raw_differs = vb != va or (s.cls == DEVREL and b['dev'] != a['dev'])
        if not s.applies(t):
            if raw_differs:
                trace.append('not-for-type:' + f)
            continue
        if mount_root and not s.on_mount_roots:
            if raw_differs:
                trace.append('not-on-mount-root:' + f)
            continue
        if s.absent == 'unknown':
            if vb is None or va is None:
                continue                                         # one-sided: unknown, above
        elif s.absent == 'with unverified':                      # "the hash when both sides have one"
            if vb is None or va is None:
                if (vb is None) != (va is None):
                    trace.append('O1')
                continue
        elif s.absent == 'none if read':                         # O2
            if not read_both:
                if raw_differs:
                    trace.append('O2-not-read:' + f)
                continue
        elif s.absent in ('required', 'only on its types'):
            if vb is None or va is None:
                raise ValueError('%r: %s missing on a %s' % (b['path'], f, t))
        if f == 'link_target' and (b.get('unreadable') or a.get('unreadable')):
            if raw_differs:                                      # rule 3: "when neither side is unreadable"
                trace.append('link-target-unreadable')
            continue
        if s.cls == DEVREL:                                      # "Devices and identity"
            rel_b, rel_a = b['dev'] == ctx['root_dev_b'], a['dev'] == ctx['root_dev_a']
            d = rel_b != rel_a
            if d:
                trace.append('dev-relation')
            elif b['dev'] != a['dev']:
                trace.append('dev-number-only')
        elif s.cls == INO:                                       # O3
            if not ctx['identity_compared']:
                if vb != va:
                    trace.append('O3-remount:' + f)
                continue
            if b['dev'] != a['dev']:
                if vb != va:
                    trace.append('O3-dev-differs:' + f)
                continue
            d = vb != va
        else:
            d = values_differ(f, vb, va)
            if f in SPELLINGS and vb is not None and va is not None and vb[0] != va[0]:
                trace.append('inline-vs-digest:' + f)            # by the formula: values_differ
        if d:
            changed.append(f)
            if s.cls == CONTENT:
                proof = True
            else:
                meta = True
    unk_scopes = {FIELDS[f].cls for f in unk_fields}
    reasons = flag_why + [f + '_unknown' for f in unk_fields]
    content_unknown = 'content' in scopes or CONTENT in unk_scopes
    meta_unknown = 'metadata' in scopes or (unk_scopes - {CONTENT})
    if 'everything' in scopes:                                   # rule 1
        return 'unknown', changed, reasons, trace + ['rule1']
    if proof:                                                    # rule 3
        return 'modified', changed, [], trace + ['rule3-proof']
    if content_unknown:
        return 'unknown', changed, reasons, trace + ['rule3-unknown']
    if meta:                                                     # rule 4
        return 'metadata_only', changed, [], trace + ['rule4-differs']
    if meta_unknown:
        return 'unknown', changed, reasons, trace + ['rule4-unknown']
    for f, s in FIELDS.items():                                  # rule 5
        if s.cls != CTIME:
            continue
        if b[f] == a[f]:
            continue
        if not s.applies(t):
            trace.append('not-for-type:' + f)
            continue
        if mount_root and not s.on_mount_roots:
            trace.append('not-on-mount-root:' + f)
            continue
        return 'metadata_only', [f], [], trace + ['rule5']
    return 'unchanged', [], [], trace + ['rule6']


def check_o4(out, b, a):
    """'Nothing above can produce `unchanged` for a path on which either side
    carries raced, unstable, unverified, unreadable, mount or xattrs_unknown,
    or iflags on one side only, nor for a path present on one side only.'"""
    if out != 'unchanged':
        return
    if b is None or a is None:
        raise AssertionError('reference bug: one-sided path unchanged')
    for f in FLAGS:
        if b.get(f) or a.get(f):
            raise AssertionError('reference bug: unchanged with %s' % f)
    for f, s in FIELDS.items():
        if s.absent == 'unknown' and (f in b) != (f in a):
            raise AssertionError('reference bug: unchanged with %s on one side' % f)


# ---------------------------------------------------------------------------
# The values a record carries: test/expect/diff-values.md (V1-V6 and its field
# table), read at run time, the words relied on checked here; the keys and
# encodings are the manifest's own (test/expect/manifest-v1.md, Keys: `a|b`
# is one spelling or the other). V4: "The values are carried, never compared
# again" -- nothing here feeds both_sides().

VALUES_PIN = os.path.join(REPO, 'test', 'expect', 'diff-values.md')
BEFORE, AFTER = 'before', 'after'


def load_values_pin():
    text = open(VALUES_PIN, encoding='utf-8').read()
    rules = {r['id'].split()[0]: r['rule'] for r in md_table(text, 'id')}
    said = {
        'V1': ['A record with `changed` also carries `"before": {...}` and `"after": {...}`, '
               'after `changed` and before `unknown`',
               "for every field `changed` names, in `changed`'s order, that side's value, under "
               'the key and in the encoding the manifest uses for it',
               'A record without `changed` carries neither. A record that carries `type_before` '
               "carries V6's values instead (V6)."],
        'V2': ["A field that side's entry does not record (iflags not read, no caps, no "
               "xattrs, a symlink's target that could not be read) is absent from that side's "
               "object; the other side's value stands alone.",
               "A side's object is therefore `{}` when the only changed field is absent on that "
               'side (caps or an xattr set added or removed); the two are never both empty',
               'an unreadable target is left out, not written as `""`'],
        'V3': ['`link_target_b64` for a target that is not UTF-8; `xattrs_sha256` for an xattr '
               'set recorded as its digest only. Each side chooses its own spelling.'],
        'V4': ['The values are carried, never compared again'],
        'V5': ['No line of diff.v1 has a fixed length bound'],
        'V6': ['A record that carries `type_before` -- every `type_changed` record, and an '
               '`unknown` one whose type also changed, as a raced swap does',
               'carries `"before"` and `"after"` (after `changed`, which is `["type"]` on every '
               "type change), each holding that side's `mode` and its type's content fields: "
               '`size` and `sha256` for `reg`, `link_target` (or `link_target_b64`) for `lnk`, '
               '`rdev` for `chr` and `blk`; `mode` alone for `dir`, `fifo` and `sock`.',
               "A field the side's entry does not record (a `sha256` not computed) is absent "
               '(V2).'],
    }
    for r, words in said.items():
        for w in words:
            if w not in rules.get(r, ''):
                raise SystemExit('pin: diff-values %s no longer says what reference.py assumes: '
                                 '%r' % (r, w))
    # The field table: every field `changed` can name (a compared field, or
    # `ctime_ns` under rule 5) has a row, and nothing else -- `type`, the one
    # name `changed` holds across a type change, has none: a record whose
    # types differ carries V6's values instead (V1, V6).
    fields = [r['field'] for r in md_table(text, 'field')]
    can_change = [f for f, s in FIELDS.items() if s.cls in COMPARED_CLASSES + (CTIME,)]
    if fields != can_change:
        raise SystemExit('pin: diff-values field table %r is not the fields `changed` can name '
                         '%r' % (fields, can_change))
    # V5's "(stated in diff-v1, "Shape")".
    spec = ' '.join(spec_prose(SPEC).split())
    if 'consumers MUST handle lines of any length' not in spec:
        raise SystemExit('spec: "Shape" no longer says consumers handle lines of any length')
    return rules


def manifest_spellings():
    """field -> the keys the manifest writes it under, in order: `a|b` in
    test/expect/manifest-v1.md's Keys table, plus the digest spelling the
    diff pin compares "as `xattrs`" (V3: `xattrs_sha256`)."""
    rows = md_table(open(MANIFEST_PIN, encoding='utf-8').read(), 'line')
    out = {}
    for r in rows:
        if r['line'] == 'entry':
            keys = r['key'].split('|')
            out[keys[0]] = keys
    for f, alts in SPELLINGS.items():
        out[f] = out[f] + alts
    # V3 names exactly these alternates.
    if [k for ks in out.values() for k in ks[1:] if k != 'path_b64'] != \
            ['xattrs_sha256', 'link_target_b64']:
        raise SystemExit('pin: the manifest\'s alternate keys are not V3\'s: %r' % out)
    return out


VALUE_RULES = load_values_pin()
MANIFEST_KEYS = manifest_spellings()
ALTERNATE_KEYS = {k for ks in MANIFEST_KEYS.values() for k in ks[1:]}
# V6, word for word: a type's content fields, after `mode`, in the order V6
# lists them (the manifest's order too).
TYPE_VALUES = {'reg': ['mode', 'size', 'sha256'], 'lnk': ['mode', 'link_target'],
               'chr': ['mode', 'rdev'], 'blk': ['mode', 'rdev'], 'dir': ['mode'],
               'fifo': ['mode'], 'sock': ['mode']}
if sorted(TYPE_VALUES) != sorted(TYPES):
    raise SystemExit('pin: V6 names types %r, the manifest %r' % (sorted(TYPE_VALUES), TYPES))
# For a symlink V6 lists `link_target` alone, though `size` is a content
# field on `lnk` in diff-fields.md (the target's length): V6's list is
# followed as written (ambiguity VA3).


def side_values(raw, names):
    """[(key, value)]: each field of `names` the side's entry records, under
    the key the manifest wrote it with (V1, V3) and its value as written
    there; a field it does not record is absent (V2)."""
    out = []
    for f in names:
        for k in MANIFEST_KEYS.get(f, [f]):
            if k in raw:
                out.append((k, raw[k]))
                break
    return out


# Ambiguity VA6 (side_values_v6()): False carries a target the manifest
# wrote on an `unreadable` link; True leaves it out as an unknown one is.
VA6_EVERY_UNREADABLE_TARGET_LEFT_OUT = False


def side_values_v6(raw, trace, side):
    """V6: one side's `mode` and its type's content fields (TYPE_VALUES), each
    the side's entry records. "A field the side's entry does not record (a
    `sha256` not computed) is absent (V2)"; V2 counts among those "a
    symlink's target that could not be read": the manifest records an
    unknown target as "" ("Empty only on an `unreadable` link, meaning the
    target is unknown"), and V2 says it "is left out, not written as `""`".

    A target the manifest did write on an `unreadable` link (it is not empty:
    the link was flagged though its bytes were read, the target "kept
    changing while being read" -- manifest-v1, `unreadable`) is recorded,
    so it is carried as written: V2 leaves out a target "that could not be
    read", and the manifest calls only the empty one unknown (ambiguity
    VA6). The other reading -- every `unreadable` link's target left out,
    as diff-fields never compares it "when either side is `unreadable`" --
    is VA6_EVERY_UNREADABLE_TARGET_LEFT_OUT = True."""
    v = side_values(raw, TYPE_VALUES[raw['type']])
    if raw['type'] == 'lnk' and raw.get('unreadable') and VA6_EVERY_UNREADABLE_TARGET_LEFT_OUT:
        v = [(k, x) for k, x in v if k not in MANIFEST_KEYS['link_target']]
    if raw['type'] == 'reg' and 'sha256' not in raw:
        trace.append('values:V6-no-sha256-' + side)
    if raw['type'] == 'lnk' and raw.get('link_target') == '':
        v = [(k, x) for k, x in v if k not in MANIFEST_KEYS['link_target']]
        trace.append('values:V2-target-unknown-' + side)
    elif raw['type'] == 'lnk' and raw.get('unreadable'):
        trace.append('values:VA6-unreadable-target-' + side)
    return v


def record_values(rb, ra, changed, trace):
    """(before, after) as [(key, value)] each, or None when the record
    carries neither.

    V6: a record that carries `type_before` -- the path is on both sides and
    its types differ, "every `type_changed` record, and an `unknown` one
    whose type also changed, as a raced swap does" -- carries each side's
    `mode` and its type's content fields (side_values_v6()); its `changed`
    is ["type"] (O7; V6: "which is `["type"]` on every type change"), and
    V1 gives way to V6 ("A record that carries `type_before` carries V6's
    values instead").

    V1: otherwise, with `changed`, the fields it names, in its order.

    V2: a field the side does not record is left out of that side's object.
    When the only field `changed` names is recorded on one side only (`caps`
    or an xattr set added or removed: absent means none where read, so it is
    compared and differs), that side's object is `{}` ("A side's object is
    therefore `{}` when the only changed field is absent on that side"). A
    link target is never in `changed` when either side is `unreadable` (the
    target is compared "when neither side is `unreadable`"), so an unknown
    target is left out under V6 only."""
    if rb['type'] != ra['type']:
        trace.append('values:V6')
        if rb.get('raced') or ra.get('raced'):
            trace.append('values:V6-raced')
        vb = side_values_v6(rb, trace, 'before')
        va = side_values_v6(ra, trace, 'after')
    elif changed:
        vb, va = side_values(rb, changed), side_values(ra, changed)
        if not vb or not va:
            trace.append('values:V2-empty-object')
        elif len(vb) != len(changed) or len(va) != len(changed):
            trace.append('values:V2-one-side')
    else:
        return None
    # V2: "the two are never both empty".
    if not vb and not va:
        raise AssertionError('reference bug: both value objects empty (%s)' % changed)
    if any(k in ALTERNATE_KEYS for k, _ in vb + va):
        trace.append('values:V3-alternate')
    return vb, va


# ---------------------------------------------------------------------------
# Interpreters, in the oracle's setting: for most pairs the driver passes NULL
# options, so the diff has NO store ("Content": reason `no_store`, "the diff
# was given no store"), and whatever needs a stored copy is
# `content_unavailable`. git's event pairs give the diff a store of their own
# (gen_corpus.py, git_events()): git's copies are read (git_explain()); no
# other interpreter's copy is ever in a store. Sources, PROSE ONLY:
# docs/spec/diff-v1.md "Interpreters" ("Which interpreter", "Content",
# "Findings", "Event records") and "What each interpreter reports"; the pins
# test/expect/finding-kinds.md (the kinds: fields, order, template, read at
# run time) and test/expect/diff-events.md (E1-E8, the text checked at
# start-up where this file relies on it). Never the generated "Kinds" or
# "diff-events" blocks of the spec.

KINDS_PIN = os.path.join(REPO, 'test', 'expect', 'finding-kinds.md')
EVENTS_PIN = os.path.join(REPO, 'test', 'expect', 'diff-events.md')


class Kind:
    def __init__(self, row):
        self.name = row['kind']
        self.interps = [x.strip() for x in row['interpreter'].split(',')]
        self.levels = [x.strip() for x in row['level'].split(',')]
        f = row['fields']
        self.fields = [] if f == '--' else \
            [tuple(x.strip() for x in part.split(':')) for part in f.split(',')]
        # "A type ending in `?` is optional"; a `bytes` field is a byte
        # string written `<name>` or `<name>_b64` (the pin's "The object").
        for _, typ in self.fields:
            if typ.rstrip('?') not in ('int', 'string', 'bool', 'bytes') or \
                    typ.count('?') > 1:
                raise SystemExit('pin: kind %s: unknown field type %r' % (self.name, typ))
        self.optional = {n for n, typ in self.fields if typ.endswith('?')}
        # The text cell: one code span, or -- "A kind whose optional fields may
        # be absent gives a second template, used when any of them is" -- the
        # template, `; `, a few words, `: ` and the second template.
        t = row['text']
        m = re.fullmatch(r'`([^`]*)`(?:; [^`:]+: `([^`]*)`)?', t)
        if not m:
            raise SystemExit('pin: kind %s: text %r is not one code span, or two' % (self.name, t))
        self.template, self.template_absent = m.group(1), m.group(2)
        named = re.findall(r'\{([a-z_]+)\}', self.template)
        # The hooks' `executable?` is in no template, and their rows give no
        # second one: read as "a second template exactly when the first
        # names an optional field" (ambiguity I10); else the one template
        # serves whether the field is present or not.
        if (self.template_absent is None) == bool(set(named) & self.optional):
            raise SystemExit('pin: kind %s: a second template exactly when the first names an '
                             'optional field' % self.name)
        if not set(named) <= {n for n, _ in self.fields}:
            raise SystemExit('pin: kind %s: template names %r' % (self.name, named))
        # "no template names a field that may be absent from it"; and no
        # rule says how a `bytes` field renders in text: none may name one.
        named2 = re.findall(r'\{([a-z_]+)\}', self.template_absent or '')
        if set(named2) & self.optional or not set(named2) <= {n for n, _ in self.fields}:
            raise SystemExit('pin: kind %s: second template names %r' % (self.name, named2))
        if any(dict(self.fields)[n] == 'bytes' for n in named + named2):
            raise SystemExit('pin: kind %s: a template names a bytes field' % self.name)


def load_kinds():
    rows = md_table(open(KINDS_PIN, encoding='utf-8').read(), 'kind')
    kinds = collections.OrderedDict((r['kind'], Kind(r)) for r in rows)
    text = ' '.join(open(KINDS_PIN, encoding='utf-8').read().split())
    # The object, as the pin states it; and the content_unavailable row's
    # rule for the per-reason event's side, which unavailable_events()
    # implements.
    for w in ['`{"kind": "<kind>", <fields, in the order listed>, "text": "<the template, '
              'filled>"}`',
              '`text` is the row\'s template with each `{field}` replaced by its value',
              '`string` fields are UTF-8, at most 1,024 bytes each',
              'A type ending in `?` is optional: absent exactly when the kind\'s meaning says. '
              'A kind whose optional fields may be absent gives a second template, used when any '
              'of them is (decision 2026-10-31, c); no template names a field that may be '
              'absent from it.',
              'A `bytes` field is a byte string of at most 4,095 bytes (the manifest\'s '
              'link-target limit, addendum A4; an exception to the 1,024-byte limit): '
              '`"<name>": "..."` when it is valid UTF-8, else `"<name>_b64": "..."`, base64, as '
              'the manifest writes bytes (decision 2026-10-31, b).',
              'side: `before` or `after`, one finding per side',
              # The kinds' meanings render() and explain() implement.
              'When the RECORD\'s outcome is `unknown` (on both sides), the event is provisional '
              'and the three counts are absent (decision 2026-10-31, c).',
              'target: the link\'s target, empty for a file. executable: the owner\'s bit, for a '
              'file; absent for a symlink, whose own mode says nothing about its target '
              '(decision 2026-10-31, a).',
              'target and executable as in git_hook_added, after.',
              # The row now names git too (decisions 126, 132): git_end()
              # emits these events as pip_end() and dpkg's do.
              'pip, dpkg and git, which emit events from that content, also emit one '
              '`content_unavailable` event per reason, with side `before` or `after` when all '
              'its paths share it, else `both`, naming the paths',
              # The git event kinds' meanings git_end() implements.
              '`HEAD` names another branch, or became or stopped being detached: from and to '
              'are the branch (`main`) or, detached, the commit (diff-events E12).',
              'In place of a deletion and a creation at the same commit, when the new branch\'s '
              'reflog of this diff says `Branch: renamed refs/heads/{from} to refs/heads/{to}`.',
              'count: one per `commit`, `commit (merge)`, `cherry-pick`, `revert` or `am` entry, '
              'present only when every entry is one of those.',
              'how: those entries\' operations, each once, in order, joined by `, `.',
              'from absent when its value before cannot be told (E12).']:
        if w not in text:
            raise SystemExit('pin: finding-kinds.md no longer says what reference.py assumes: '
                             '%r' % w)
    S, I, B = 'string', 'int', 'bool'
    need = {'content_unavailable': ([('reason', S), ('side', S)], ['text', 'pip', 'dpkg', 'git']),
            'could_not_interpret': ([], ['core']),
            'invalid_finding': ([], ['core']),
            'pip_installed': ([('name', S), ('version', S)], ['pip']),
            'pip_removed': ([('name', S), ('version', S)], ['pip']),
            'pip_upgraded': ([('name', S), ('from', S), ('to', S)], ['pip']),
            'pip_downgraded': ([('name', S), ('from', S), ('to', S)], ['pip']),
            'pip_version_changed': ([('name', S), ('from', S), ('to', S)], ['pip']),
            'pip_reinstalled': ([('name', S), ('version', S), ('files_added', I + '?'),
                                 ('files_removed', I + '?'), ('files_changed', I + '?')],
                                ['pip']),
            'git_hook_added': ([('hook', S), ('executable', B + '?'), ('target', 'bytes')],
                               ['git']),
            'git_hook_removed': ([('hook', S), ('target', 'bytes')], ['git']),
            'git_hook_changed': ([('hook', S), ('executable', B + '?'), ('target', 'bytes')],
                                 ['git']),
            'git_hook_executable_changed': ([('hook', S), ('executable', B)], ['git']),
            'git_index_changed': ([], ['git']),
            'git_reflog_rewritten': ([('ref', S)], ['git']),
            'git_head_changed': ([('from', S), ('to', S)], ['git']),
            'git_ref_created': ([('ref', S), ('to', S)], ['git']),
            'git_ref_deleted': ([('ref', S), ('from', S)], ['git']),
            'git_ref_moved': ([('ref', S), ('from', S), ('to', S)], ['git']),
            'git_reflog_appended': ([('ref', S), ('entries', I)], ['git']),
            'git_reflog_move': ([('ref', S), ('from', S), ('to', S), ('operation', S)],
                                ['git']),
            # E12's kinds (decisions 126, 132), event level.
            'git_head_switched': ([('repo', S), ('from', S), ('to', S)], ['git']),
            'git_branch_created': ([('repo', S), ('branch', S), ('at', S)], ['git']),
            'git_branch_deleted': ([('repo', S), ('branch', S), ('was', S)], ['git']),
            'git_branch_renamed': ([('repo', S), ('from', S), ('to', S), ('at', S)], ['git']),
            'git_commits_added': ([('repo', S), ('branch', S), ('count', I + '?'), ('to', S)],
                                  ['git']),
            'git_history_rewritten': ([('repo', S), ('branch', S), ('how', S), ('from', S),
                                       ('to', S)], ['git']),
            'git_branch_moved': ([('repo', S), ('branch', S), ('from', S + '?'), ('to', S)],
                                 ['git'])}
    for k, (fields, interps) in need.items():
        if k not in kinds or kinds[k].fields != fields or kinds[k].interps != interps:
            raise SystemExit('pin: kind %r no longer has what reference.py assumes' % k)
    # The core's kinds are events too (E6, E9, E10).
    for k in ('could_not_interpret', 'invalid_finding', 'and_more'):
        if kinds[k].levels != ['path', 'event']:
            raise SystemExit('pin: kind %r is no longer path and event level' % k)
    for k in GIT_EVENT_KINDS:
        if kinds[k].levels != ['event']:
            raise SystemExit('pin: kind %r is no longer event level' % k)
    return kinds


# E12's kinds, in the Kinds table's order (checked against it at start-up):
# the order "then kind" of E4 among one branch's events.
GIT_EVENT_KINDS = ['git_head_switched', 'git_branch_created', 'git_branch_deleted',
                   'git_branch_renamed', 'git_commits_added', 'git_history_rewritten',
                   'git_branch_moved']


def load_event_rules():
    rules = {r['rule'].split()[0]: r['statement'] for r in
             md_table(open(EVENTS_PIN, encoding='utf-8').read(), 'rule')}
    said = {
        'E1': ['Event records come after the last path record and before the trailer. A diff '
               'with none has none.'],
        'E2': ['`{"event": "<kind>", "interp": "<interpreter>", <the kind\'s fields, in '
               'finding-kinds.md\'s order>, "text": "<its template>", "provisional": true, '
               '"paths": [...]}`',
               '`provisional` is present, and `true`, exactly when a path the event was '
               'derived from has the outcome `unknown`'],
        'E3': ['sorted bytewise, each once', '`paths_b64` instead -- every element base64 -- '
               'when any is not valid UTF-8'],
        'E4': ['By interpreter, in the order text, pip, dpkg, git',
               'git by repository, then `HEAD` before every branch, then branch, then kind '
               '(decision 126)'],
        # E12 (decisions 126, 132, 137), each sentence git_explain() and
        # git_end() rely on.
        'E12': ['git\'s end hook derives repository-level events from the paths of this diff '
                'it explained -- loose refs, `packed-refs`, `HEAD`, reflogs -- per repository '
                '(a directory named `.git`; `repo` its path in the scope).',
                'A branch is a ref `refs/heads/<branch>`, named without `refs/heads/`.',
                'Its value on a side: its loose ref there; else its line in `packed-refs` when '
                '`packed-refs` is a path of this diff; else, before only, the old id of the '
                'first entry its reflog gained in this diff (all zeros: absent).',
                'One event per branch whose existence or commit differs: absent before by that '
                'evidence and present after, `git_branch_created`; present after with no '
                'evidence of before, `git_branch_moved` with no `from`; its loose ref removed '
                'and `packed-refs` without it (a path of this diff, or not -- git removes a '
                'branch from both), `git_branch_deleted`; a deletion and a creation at the same '
                'commit whose new reflog says `Branch: renamed`, one `git_branch_renamed`.',
                'A branch on both sides at different commits is decided by the entries its '
                'reflog gained in this diff, when they lead from its value before to its value '
                'after (each entry\'s old id the previous one\'s new, the first\'s old the value '
                'before, the last\'s new the value after): any `reset`, `commit (amend)`, '
                'operation containing `rebase`, message starting `branch: Reset to`, or message '
                'containing `forced-update` -- `git_history_rewritten`; else only commits '
                '(`commit`, `commit (merge)`, `cherry-pick`, `revert`, `am`) and fast-forwards '
                'or merges (a message containing `Fast-forward`; an operation starting with '
                '`merge` or `pull`) -- `git_commits_added`; else, or with no such entries, '
                '`git_branch_moved`.',
                '`HEAD` naming another branch, or detaching or attaching: `git_head_switched`; '
                '`HEAD` detached on both sides at different commits is the branch `HEAD`, '
                'decided by `logs/HEAD` as above.',
                'Remote-tracking refs and tags derive no event (their path findings stand).',
                'A path whose outcome is `unknown` adds no finding to its record (P8) but is '
                'read like any other where its copy can be read, as dpkg reads a status',
                'every event derived from it is provisional (E2), so a branch whose ref raced '
                'is never silent.',
                # Decision 137: "refs are proof, the reflog is evidence".
                'What git cannot read reduces what is claimed, never the fact the refs give: a '
                'reflog it cannot read is no evidence -- the move still comes from the refs, as '
                '`git_branch_moved`, without a how; a ref or `packed-refs` that cannot be read '
                'on a side gives no value there -- before, the reflog\'s evidence may still give '
                'one, and without one the event is `git_branch_moved` with no `from` (a branch '
                'only in `packed-refs` too); after, the branch derives no event.',
                'The record of a path git cannot read whose outcome is not `unknown` carries '
                '`content_unavailable`, and one `content_unavailable` event per reason names '
                'those paths (provisional when one of them is `unknown`).',
                '`paths`: every ref, `packed-refs` and `HEAD` path whose value the event uses, '
                'and a reflog only when its entries were used -- giving the value before or '
                'evidence of absence before, a rename, or how the branch moved (entries that lead '
                'from before to after but say not how are not used).'],
        'E9': ['is replaced, in its place, by `{"event": "invalid_finding", "interp": ..., '
               '"text": "invalid finding", "paths": [<its paths>]}`; the interpreter\'s other '
               'events stand'],
        'E10': ['A file an interpreter claims and cannot interpret gives one `{"event": '
                '"could_not_interpret", "interp": ..., "text": "could not interpret", "paths": '
                '[<the files>]}`; the interpreter\'s other events stand',
                'pip: a dist-info that cannot be named, or a RECORD it must read that cannot be '
                'parsed -- that RECORD\'s path record carries `could_not_interpret` too, unless '
                'its outcome is `unknown`, and nothing more is read from it; a name with '
                'RECORDs added and removed other than one of each -- one event naming them, '
                'their path records carrying nothing'],
        'E7': ['The trailer gains `events`: the number of event records.'],
        # E11, in diff(): a path not captured is given to no interpreter.
        'E11': ['A path whose outcome is `unknown` with `not_captured` as its only reason -- '
                'the side that lacks it excluded it, or it lies below an `unreadable` directory '
                'or a mount there (diff-v1, "Present on one side only") -- derives no event: '
                'that side was not looked at, so nothing was installed or removed there. Its '
                'path record stands. Any other `unknown` path still derives provisional events '
                '(E2).',
                # Decision 118: the core's events too -- what ambiguity X4
                # read "derives no event at all" as, now the pin's words.
                'No interpreter is given it, so no event of the core\'s names it either: no '
                '`could_not_interpret` (E10) nor `content_unavailable` for it, and a failed end '
                'hook\'s event (E6) never lists it.'],
        # E6, not modelled (end()): checked so that a change to what a failed
        # end hook lists is reviewed against E11 here.
        'E6': ['and no other event: `paths` the first 1,024 of the paths it had claimed '
               '(bytewise; never a path E11 withholds), `paths_truncated` the number of the '
               'rest, present only when not 0'],
    }
    for r, words in said.items():
        for w in words:
            if w not in rules.get(r, ''):
                raise SystemExit('pin: diff-events %s no longer says what reference.py assumes: '
                                 '%r' % (r, w))
    return rules


KINDS = load_kinds()
EVENT_RULES = load_event_rules()
INTERP_ORDER = ['text', 'pip', 'dpkg', 'git']           # E4
TEXT, BINARY = 'text', 'binary'

# "Which interpreter": "A path is claimed by its absolute path (scope + path):
# dpkg claims `*/var/lib/dpkg/status` and the per-package
# `*/var/lib/dpkg/info/*.list` and `*.md5sums`; pip claims `*.dist-info/RECORD` and `*.dist-info/METADATA`;
# git claims `*/.git/HEAD`, `*/.git/packed-refs`, `*/.git/refs/*`,
# `*/.git/hooks/*`, `*/.git/index` and the reflogs `*/.git/logs/HEAD` and
# `*/.git/logs/refs/*`." The prose now spells the dpkg `info/` files
# "`*/var/lib/dpkg/info/*.list` and `*.md5sums`"; the second is read as
# `*/var/lib/dpkg/info/*.md5sums` (the per-package files, ambiguity I1),
# not any `*.md5sums` anywhere. A `*` spans `/`: `*.dist-info/RECORD`
# could not match an absolute path otherwise. The absolute path is scope +
# "/" + path.
CLAIMS = [('dpkg', 'status', '*/var/lib/dpkg/status'),
          ('dpkg', 'info', '*/var/lib/dpkg/info/*.list'),
          ('dpkg', 'info', '*/var/lib/dpkg/info/*.md5sums'),
          ('pip', 'RECORD', '*.dist-info/RECORD'),
          ('pip', 'METADATA', '*.dist-info/METADATA'),
          ('git', 'HEAD', '*/.git/HEAD'),
          ('git', 'packed-refs', '*/.git/packed-refs'),
          ('git', 'ref', '*/.git/refs/*'),
          ('git', 'hook', '*/.git/hooks/*'),
          ('git', 'index', '*/.git/index'),
          ('git', 'reflog', '*/.git/logs/HEAD'),
          ('git', 'reflog', '*/.git/logs/refs/*')]


def _check_claims():
    text = ' '.join(spec_prose(SPEC).split())
    for _, _, pat in CLAIMS:
        # "the per-package `*/var/lib/dpkg/info/*.list` and `*.md5sums`"
        tail = '*.md5sums' if pat == '*/var/lib/dpkg/info/*.md5sums' else pat
        if '`%s`' % tail not in text:
            raise SystemExit('spec: "Which interpreter" no longer names %r' % tail)
    for w in ['An unclaimed path is **text** when its entry is `stored` on every side it exists '
              'on', 'any other is **binary**, which adds nothing',
              "to a path whose outcome is `unknown` or `metadata_only` it adds none (a git "
              "hook's executable bit excepted, which is metadata). pip, dpkg and git still "
              'derive events from an `unknown` path, each marked provisional -- but none from a '
              'path `unknown` only as `not_captured`, which no interpreter is given (E11).',
              # "Event records" (E11 in the prose): explain() is not called
              # for such a path, so it derives no event of any kind.
              'An event derived from a path whose outcome is `unknown` says `"provisional": '
              'true`: it may not hold. A path whose only reason is `not_captured` derives no '
              'event at all: that side was not looked at, so nothing was installed or removed '
              'there (diff-events E11).',
              'A side on which the path is not a regular file counts as absent (git hooks '
              'excepted: a symlink is a hook).',
              '`missing` covers a path whose entry records no `stored` copy (a reflog over its '
              '16 MiB bound excepted: `too_large`) as well as a copy the store lacks, and is '
              'given before `no_store` when both apply.',
              '| git | a reflog | 16 MiB: a capture keeps a reflog up to this whatever '
              '`store_max_bytes` says, and a side recorded without a copy because it is larger '
              'is `content_unavailable`, reason `too_large` |',
              "A record's `content_unavailable` findings come before side, then after",
              "an interpreter's `content_unavailable` events come one per reason, in the order "
              '`no_store`, `missing`, `too_large`, `corrupt`',
              'A `bool` field renders in `text` as `true` or `false`.',
              'Where an interpreter fails on a path (a file it claims cannot be parsed, a '
              "dist-info cannot be named), that path's record carries `could_not_interpret` "
              '(R11) unless its outcome is `unknown`, nothing more is read from it, and pip, '
              'dpkg and git emit one `could_not_interpret` event naming it (E10); their other '
              'events stand.',
              # "Content", git_explain(): which paths git's content_unavailable
              # event names, and a removed reflog's.
              'It never declines silently there: pip, dpkg and git, whose package and '
              'repository facts come from that content, also emit a `content_unavailable` event '
              'naming the paths, so a consumer never reads "no packages changed" or "no branch '
              'moved" where the change could not be read. git names only the paths it derives '
              'events from (HEAD, branches, `packed-refs`, their reflogs), and a reflog removed '
              'needs no copy.',
              'Events with no name -- `could_not_interpret` for a file, `content_unavailable` '
              '-- come before every named event, in the Kinds table\'s order, then by path '
              '(`content_unavailable`, one per reason, in the reasons\' order).',
              'The end hook fails (E6) only when the interpreter\'s per-diff state would exceed '
              '64 MiB, memory runs out, or it adds an event naming no path: its events are then '
              'one `could_not_interpret` naming '
              'the first 1,024 paths given to it (every path it claims whose outcome is not '
              '`unchanged`; none `unknown` only as `not_captured`, which it is never given: E11) '
              'and counting the rest.',
              'Only a reinstall reads content (both RECORDs); the others come from the paths '
              'alone.',
              'A RECORD whose outcome is `unknown` pairs like any other, by its directory\'s '
              'name, and every event it takes part in is provisional; one present on both '
              'sides is a provisional `pip_reinstalled` whose rows are not compared: its three '
              'counts are absent, under the kind\'s second template.',
              '`bytes` fields up to 4,095 bytes written as `<name>` when UTF-8 and `<name>_b64` '
              '(base64) otherwise; an optional field (`?`) is absent where its kind says, and '
              'then the kind\'s second template is used',
              'a finding that breaks the row (an unknown kind, a kind of another interpreter or '
              'level, a field missing, extra or over its bound) is replaced by '
              '`invalid_finding`',
              'Event order: by normalized name (none first), then kind (in the Kinds table\'s '
              'order), then directory, then the paths it lists.',
              'or a RECORD it must read that cannot be parsed, is one `could_not_interpret` '
              'event naming that RECORD; one pair key with RECORDs both added and removed other '
              'than exactly one of each (no kind says that) is one `could_not_interpret` event '
              'naming them, in that name\'s place; their records carry nothing, as the pairing '
              'is known only once every path record is written.',
              'Several added with none removed are each `pip_installed`',
              'A status whose outcome is `unknown` is read too, and every event from it is '
              'provisional.',
              'A hook, from the manifest alone, is a regular file or a symlink',
              'a directory is none: added, removed, changed (its content, a link\'s target, or '
              'a file becoming a link or back), or -- a file\'s content unchanged -- its '
              'executable bit (the owner\'s), whatever else changed. `executable` is after\'s '
              'owner bit, for a file; it is absent for a symlink, whose own mode says nothing '
              'about its target. `target` is the link\'s target, empty for a file, up to 4,095 '
              'bytes, and `target_b64` instead when it is not UTF-8: a planted hook is always '
              'reported.',
              'The index: `git_index_changed` when it is added, removed or its content changed',
              # With a store (read_copy(), git_explain(), git_end()).
              "Interpreters read the stored copies through the store given to the diff "
              "(`belay_diff`'s options): the directory a capture keeps copies in, each at "
              "`<store>/<the first two hex digits of its sha256>/<the other 62>`, named by the "
              "manifest entry's `stored`. Every copy read is hashed and must match its name, so "
              "a stale, planted or truncated copy is never read as content; one that is not a "
              "regular file (a symlink included) is `corrupt`.",
              '| git | `HEAD`, a loose ref | 64 KiB |', '| git | `packed-refs` | 64 MiB |',
              'Where an interpreter keeps the first of two equal keys (a package, a RECORD path, '
              'a packed ref), "first" is in file order.',
              'A path is placed by the part after its `.git/` (the last one that fits). `HEAD`: '
              "`git_head_changed`, from and to being the symbolic ref's name or the object id "
              '(empty on a side where it is absent); nothing when the two are equal. A loose ref '
              'or a line of `packed-refs` (in ref order): `git_ref_created`, `git_ref_deleted`, '
              '`git_ref_moved` (only when the value differs), the ref being its full name '
              '(`refs/heads/main`).',
              "A reflog (`logs/HEAD` is ref `HEAD`, `logs/refs/...` is `refs/...`): when "
              "before's bytes are a prefix of after's ending at a line's end (an absent before "
              'is empty), `git_reflog_appended` counts the entries after it, and each of those '
              'that is not a plain commit (operation `commit` or `commit (initial)`) or a '
              'fast-forward (its message contains `Fast-forward`) is a `git_reflog_move`, its '
              'operation being the message before its first `:`; otherwise, or when the reflog '
              'was removed (no copy needed), `git_reflog_rewritten`.',
              'git sees only the paths that changed, so an unchanged `packed-refs` is never '
              'read: a branch is created only by evidence that it was absent before, and a ref '
              'that appeared without that evidence is moved, with no `from`.',
              'A path whose outcome is `unknown` is read where its copy can be read, and every '
              'event from it is provisional. Tags and remote-tracking refs derive no event.',
              '(an absent before is empty)',
              'or when the reflog was removed (no copy needed), `git_reflog_rewritten`']:
        if w not in text:
            raise SystemExit('spec: "Interpreters" no longer says what reference.py assumes: %r'
                             % w)


_check_claims()
_CLAIM_RE = [(i, what, re.compile(b'.*'.join(re.escape(x.encode()) for x in pat.split('*')),
                                  re.S))
             for i, what, pat in CLAIMS]


def claim(scope, p):
    """(interpreter, what) of the claim on scope + "/" + p, or None. Two
    interpreters claiming one path is not resolved by the prose (ambiguity
    I2): the generator never makes one."""
    ab = scope + b'/' + p
    hits = [(i, what) for i, what, rx in _CLAIM_RE if rx.fullmatch(ab)]
    if len({i for i, _ in hits}) > 1:
        raise ValueError('%r: claimed by %s (the prose does not say which wins)' % (ab, hits))
    return hits[0] if hits else None


def interpreter_of(scope, p, b, a):
    """("Which interpreter") the claim's, else text when the entry is
    `stored` on every side it exists on, else binary."""
    c = claim(scope, p)
    if c:
        return c
    if all('stored' in e for e in (b, a) if e is not None):
        return (TEXT, None)
    return (BINARY, None)


def string_ok(s):
    """A `string` field's value: UTF-8, at most 1,024 bytes (no NUL, which no
    manifest line holds)."""
    if isinstance(s, bytes):
        try:
            s = s.decode('utf-8')
        except UnicodeDecodeError:
            return False
    return len(s.encode('utf-8')) <= 1024 and '\0' not in s


BYTES_MAX = 4095        # "A `bytes` field is a byte string of at most 4,095 bytes"


def fill(kind, values):
    """The kind's text: its template with each `{field}` replaced by its
    value -- the second template when an optional field is absent (None):
    "A kind whose optional fields may be absent gives a second template,
    used when any of them is". "A `bool` field renders in `text` as `true` or
    `false`"."""
    k = KINDS[kind]
    tpl = k.template
    if any(values[n] is None for n in k.optional) and k.template_absent is not None:
        tpl = k.template_absent
    show = lambda v: ('true' if v else 'false') if type(v) is bool else str(v)
    return re.sub(r'\{([a-z_]+)\}', lambda m: show(values[m.group(1)]), tpl)


def render(kind, values):
    """[(key, value)] of a finding: kind, its fields in the pin's order, text
    ("the template, filled"). An optional field whose value is None is
    absent ("A field absent from a kind's row never appears", and an optional
    one is "absent exactly when the kind's meaning says"); a `bytes` value
    is `<name>` when valid UTF-8, else `<name>_b64`, base64 ("as the manifest
    writes bytes": standard alphabet, padded)."""
    k = KINDS[kind]
    if [n for n, _ in k.fields] != list(values):
        raise AssertionError('reference bug: %s with %r' % (kind, list(values)))
    out = []
    for n, typ in k.fields:
        v = values[n]
        if v is None and n in k.optional:
            continue
        ok = {'int': lambda v: type(v) is int and v >= 0, 'bool': lambda v: type(v) is bool,
              'string': lambda v: isinstance(v, str) and string_ok(v),
              'bytes': lambda v: isinstance(v, bytes) and len(v) <= BYTES_MAX
              }[typ.rstrip('?')](v)
        if not ok:
            raise AssertionError('reference bug: %s.%s = %r' % (kind, n, v))
        if typ.rstrip('?') == 'bytes':
            try:
                out.append((n, v.decode('utf-8')))
            except UnicodeDecodeError:
                out.append((n + '_b64', base64.b64encode(v).decode('ascii')))
            continue
        out.append((n, v))
    text = fill(kind, values)
    assert len(text.encode('utf-8')) <= 1024
    return [('kind', kind)] + out + [('text', text)]


def render_event(interp, kind, values, paths, unknown=frozenset()):
    """E2: event, interp, the kind's fields, text, `"provisional": true`
    exactly when one of its paths is in `unknown` (the paths whose outcome is
    `unknown`), paths (E3: sorted bytewise, each once; `paths_b64` when any is
    not UTF-8)."""
    f = render(kind, values)
    ps = sorted(set(paths))
    # "it adds an event naming no path" fails the end hook (E6; both
    # "Event records" and "What each interpreter reports", decision 121),
    # which end() does not model: no event here may reach it.
    assert ps, 'reference: a %s %s event naming no path (E6 is not modelled)' % (interp, kind)
    try:
        pv = ('paths', [x.decode('utf-8') for x in ps])
    except UnicodeDecodeError:
        pv = ('paths_b64', [base64.b64encode(x).decode('ascii') for x in ps])
    prov = [('provisional', True)] if any(x in unknown for x in ps) else []
    return [('event', kind), ('interp', interp)] + f[1:] + prov + [pv]


def is_reg(e):
    """"A side on which the path is not a regular file counts as absent.\""""
    return e is not None and e['type'] == 'reg'


SIDES = ('before', 'after')
REASONS = ['no_store', 'missing', 'too_large', 'corrupt']   # the pin's order


REFLOG_BOUND = 16 * 1024 * 1024     # the bounds table: "| git | a reflog | 16 MiB: ..."


# The bounds table ("What each interpreter reports"): what each interpreter
# reads at most of a stored copy; "a larger one is `content_unavailable`,
# reason `too_large`". Only git's are used: no copy of another interpreter's
# path is ever readable in this corpus (read_copy()).
BOUNDS = {('git', 'HEAD'): 64 * 1024, ('git', 'ref'): 64 * 1024,
          ('git', 'packed-refs'): 64 * 1024 * 1024, ('git', 'reflog'): REFLOG_BOUND}


def read_copy(e, interp, what, store):
    """(the copy's bytes, None), or (None, why it cannot be read).

    Without a store: `missing` when the entry records no `stored` copy
    ("`missing` covers a path whose entry records no `stored` copy (a reflog
    over its 16 MiB bound excepted: `too_large`) ..., and is given before
    `no_store` when both apply"), else `no_store`. The exception: "a capture
    keeps a reflog up to this whatever `store_max_bytes` says, and a side
    recorded without a copy because it is larger is `content_unavailable`,
    reason `too_large`" -- larger than 16 MiB, read from the entry's `size`,
    so 16 MiB exactly with no copy is still `missing`. The reflog's
    `too_large` takes `missing`'s place, so it too comes before `no_store`
    (ambiguity I11, now the prose's own rule: "the reflog's `too_large`
    stands where `missing` would").

    With a store ("Content"): the copy at `<store>/<the first two hex digits
    of its sha256>/<the other 62>`, named by the entry's `stored`: absent,
    `missing` ("as well as a copy the store lacks"); not a regular file (a
    symlink included), `corrupt`; larger than the interpreter's bound,
    `too_large`; not hashing to its name, `corrupt`. The corpus never makes
    a copy both over its bound and corrupt, whose order the prose does not
    give. Only git's copies are ever readable here: the corpus stores no
    copy of a text, pip or dpkg path in a store, whose content this model
    does not compute (text_changed, a RECORD's rows, a status's stanzas)."""
    if 'stored' not in e:
        if (interp, what) == ('git', 'reflog') and e['size'] > REFLOG_BOUND:
            return None, 'too_large'
        return None, 'missing'
    if store is None:
        return None, 'no_store'
    f = os.path.join(store, e['stored'][:2], e['stored'][2:])
    if not os.path.lexists(f):
        return None, 'missing'
    if os.path.islink(f) or not os.path.isfile(f):
        return None, 'corrupt'
    if (interp, what) not in BOUNDS:
        raise AssertionError('reference: the content of a %s %s path is not modelled; the '
                             'corpus must not store it' % (interp, what))
    if os.path.getsize(f) > BOUNDS[(interp, what)]:
        return None, 'too_large'
    with open(f, 'rb') as fh:
        data = fh.read()
    if hashlib.sha256(data).hexdigest() != e['stored']:
        return None, 'corrupt'
    return data, None


def unavailable(e, interp, what, store=None):
    """Why the copy of e cannot be read, for a path whose content this model
    does not compute (text, pip, dpkg): read_copy() must say it cannot."""
    data, r = read_copy(e, interp, what, store)
    assert r is not None
    return r


def git_place(p):
    """"A path is placed by the part after its `.git/` (the last one that
    fits)": the text after the last `.git/` that starts a component."""
    i = p.rfind(b'.git/')
    while i > 0 and p[i - 1:i] != b'/':
        i = p.rfind(b'.git/', 0, i)
    return p[i + len(b'.git/'):]


def hook_name(p):
    return git_place(p)[len(b'hooks/'):].decode('utf-8')


def reflog_ref(p):
    """"`logs/HEAD` is ref `HEAD`, `logs/refs/...` is `refs/...`"."""
    return git_place(p)[len(b'logs/'):].decode('utf-8')


def is_hook(e):
    """"A hook, from the manifest alone, is a regular file or a symlink --
    git follows a symlinked hook, so it is a working hook; a directory is
    none", and "A side on which the path is not a regular file counts as
    absent (git hooks excepted: a symlink is a hook)": a fifo, socket or
    device under hooks/ is none either."""
    return e is not None and e['type'] in ('reg', 'lnk')


def render_hook(kind, values, trace):
    """A hook's finding. `target` is a `bytes` field: "up to 4,095 bytes, and
    `target_b64` instead when it is not UTF-8: a planted hook is always
    reported". Over 4,095 bytes it would break the row ("over its bound":
    `invalid_finding`), but the manifest holds no longer link target
    (addendum A4: a reader rejects one), so that branch is unreachable here."""
    t = values.get('target', b'')
    if len(t) > BYTES_MAX:
        trace.append('invalid-finding')
        return render('invalid_finding', {})
    if not is_utf8(t):
        trace.append('hook-target-b64')
    if 'executable' in values and values['executable'] is None:
        trace.append('hook-no-executable')
    return render(kind, values)


def is_utf8(b):
    try:
        b.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def explain(interp, what, p, b, a, outcome, state, trace):
    """The findings of one record of a claimed or text path; events go to
    `state`. Each needed side whose copy cannot be read is one
    content_unavailable finding: "A record's `content_unavailable` findings
    come before side, then after"."""
    bs, as_ = is_reg(b), is_reg(a)
    # "`executable` is after's owner bit, for a file; it is absent for a
    # symlink, whose own mode says nothing about its target" (None: absent).
    executable = lambda e: None if e['type'] == 'lnk' else bool(e['mode'] & 0o100)
    target = lambda e: e['link_target'] if e['type'] == 'lnk' else b''
    present = [s for s, ok in zip(SIDES, (bs, as_)) if ok]
    ent = {'before': b, 'after': a}
    # "An interpreter adds findings only to a path whose content is proven
    # changed (added, removed, modified, type_changed): to a path whose
    # outcome is `unknown` or `metadata_only` it adds none (a git hook's
    # executable bit excepted, which is metadata). pip, dpkg and git still
    # derive events from an `unknown` path, each marked provisional -- but none
    # from a path `unknown` only as `not_captured`, which no interpreter is
    # given (E11)": diff() never calls this for one.
    if outcome == 'unknown':
        trace.append('interp-unknown')
        if (interp, what) == ('dpkg', 'status'):
            # "A status whose outcome is `unknown` is read too, and every
            # event from it is provisional": with no store, each side it
            # exists on is a provisional content_unavailable event, and no
            # finding on the record.
            state['unknown'].add(p)
            for s in present:
                r = unavailable(ent[s], interp, what, state['store'])
                trace.append('event-unavailable-%s-%s' % (s, r))
                state['unavailable'].append((r, s, p))
        elif interp == 'git' and what in GIT_CONTENT:
            # E12: "A path whose outcome is `unknown` adds no finding to its
            # record (P8) but is read like any other where its copy can be
            # read ...: every event derived from it is provisional (E2)".
            state['unknown'].add(p)
            git_explain(what, p, b, a, outcome, state, trace)
        elif (interp, what) == ('pip', 'RECORD'):
            # "A RECORD whose outcome is `unknown` pairs like any other, by
            # its directory's name, and every event it takes part in is
            # provisional; one present on both sides is a provisional
            # `pip_reinstalled` whose rows are not compared: its three
            # counts are absent, under the kind's second template." Either
            # way it is named like any other: one that cannot be named is a
            # (provisional) could_not_interpret event, and its record carries
            # nothing ("that RECORD's path record carries
            # `could_not_interpret` too, unless its outcome is `unknown`",
            # E10). Its rows are not compared, so no copy is needed: no
            # content_unavailable.
            state['unknown'].add(p)
            if bs != as_:
                pip_moved(p, 'removed' if bs else 'added', state, trace)
            elif bs:
                trace.append('pip-unknown-both-sides')
                if dist_info(p) is None:
                    trace += ['pip-unnamed', 'pip-unnamed-unknown-both-sides']
                    state['unnamed'].append(p)
                else:
                    state['reinstalled'].append(p)
        return []
    if outcome == 'metadata_only':
        if (interp, what) == ('git', 'hook') and bs and as_ and executable(b) != executable(a):
            trace.append('hook-executable')
            return [render('git_hook_executable_changed',
                           {'hook': hook_name(p), 'executable': executable(a)})]
        trace.append('interp-metadata-only')
        return []
    if interp == 'git' and what in GIT_CONTENT:
        return git_explain(what, p, b, a, outcome, state, trace)
    need = []                                   # the sides whose content is needed
    if interp == TEXT or (interp, what) == ('dpkg', 'status'):
        need = present
    elif (interp, what) == ('pip', 'RECORD'):
        if (bs or as_) and dist_info(p) is None:
            # "Where an interpreter fails on a path (..., a dist-info cannot
            # be named), that path's record carries `could_not_interpret`
            # (R11) unless its outcome is `unknown`, nothing more is read
            # from it" -- a reinstall's content_unavailable included -- "and
            # pip and dpkg emit one `could_not_interpret` event naming it
            # (E10)".
            trace.append('pip-unnamed')
            state['unnamed'].append(p)
            return [render('could_not_interpret', {})]
        if bs and as_:
            need = present                      # a reinstall reads both RECORDs
        elif bs or as_:
            pip_moved(p, 'removed' if bs else 'added', state, trace)
    elif (interp, what) == ('git', 'hook'):     # "from the manifest alone"
        h, hb, ha = hook_name(p), is_hook(b), is_hook(a)
        if ha and not hb:
            trace.append('hook-added')
            return [render_hook('git_hook_added', {'hook': h, 'executable': executable(a),
                                                   'target': target(a)}, trace)]
        if hb and not ha:
            trace.append('hook-removed')
            return [render_hook('git_hook_removed', {'hook': h, 'target': target(b)}, trace)]
        if hb and ha:
            # "changed (its content, a link's target, or a file becoming a
            # link or back)": modified or type_changed, both sides a hook;
            # "target and executable as in git_hook_added, after".
            trace.append('hook-changed')
            return [render_hook('git_hook_changed', {'hook': h, 'executable': executable(a),
                                                     'target': target(a)}, trace)]
    elif (interp, what) == ('git', 'index'):
        # "The index: `git_index_changed` when it is added, removed or its
        # content changed (hashed, never stored)."
        if bs or as_:
            trace.append('index-changed')
            return [render('git_index_changed', {})]
    out = []
    for s in need:
        r = unavailable(ent[s], interp, what, state['store'])
        trace.append('unavailable-%s-%s' % (s, r))
        out.append(render('content_unavailable', {'reason': r, 'side': s}))
        state['unavailable'].append((r, s, p))
    return out


def pip_moved(p, how, state, trace):
    """A RECORD on one side only, for the end hook to pair by its directory's
    name; one whose dist-info cannot be named is one could_not_interpret
    event naming it (E10)."""
    if dist_info(p) is None:
        trace.append('pip-unnamed')
        state['unnamed'].append(p)
    else:
        state['moved'].append((p, how))


def unavailable_events(interp, state):
    """One content_unavailable event per reason (pin, content_unavailable):
    side `before` or `after` when all its paths share it, else `both`. Two
    reasons: "one per reason, in the order `no_store`, `missing`,
    `too_large`, `corrupt`". Provisional when one of its paths is unknown
    (a dpkg status)."""
    out = []
    for r in REASONS:
        hits = [(s, p) for rr, s, p in state['unavailable'] if rr == r]
        if not hits:
            continue
        sides = {s for s, _ in hits}
        side = sides.pop() if len(sides) == 1 else 'both'
        out.append(render_event(interp, 'content_unavailable', {'reason': r, 'side': side},
                                [p for _, p in hits], state['unknown']))
    return out


# PEP 440: the version scheme's grammar (the PEP's appendix) and its ordering.
_PEP440 = re.compile(r"""^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_\.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_\.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?
    \s*$""", re.VERBOSE | re.IGNORECASE)


def pep440_key(v):
    """The PEP 440 ordering key of v, or None when v is not a PEP 440 version."""
    m = _PEP440.match(v)
    if not m:
        return None
    rel = [int(x) for x in m.group('release').split('.')]
    while rel and rel[-1] == 0:                 # 1.0 == 1.0.0
        rel.pop()
    pre = post = dev = None
    if m.group('pre_l'):
        l = m.group('pre_l').lower()
        l = {'alpha': 'a', 'beta': 'b', 'c': 'rc', 'pre': 'rc', 'preview': 'rc'}.get(l, l)
        pre = (0, l, int(m.group('pre_n') or 0))
    if m.group('post'):
        post = (0, int(m.group('post_n1') or m.group('post_n2') or 0))
    if m.group('dev_l'):
        dev = (0, int(m.group('dev_n') or 0))
    NEG, POS = (-1,), (1,)
    _pre = NEG if (pre is None and post is None and dev is not None) else \
        (POS if pre is None else pre)
    local = m.group('local')
    _local = NEG if local is None else (0, tuple(
        (1, int(x), '') if x.isdigit() else (0, 0, x.lower()) for x in re.split(r'[-_.]', local)))
    return (int(m.group('epoch') or 0), tuple(rel), _pre, NEG if post is None else post,
            POS if dev is None else dev, _local)


def pep503(name):
    """"normalized as PEP 503 does (ASCII lowercase, each run of `-`, `_`,
    `.` one `-`)"."""
    return re.sub(r'[-_.]+', '-', name).lower()


def dist_info(p):
    """(holding directory, name, version) of a RECORD's dist-info directory:
    "`{name}-{version}.dist-info`, split at its first `-`"; None when it
    cannot be named ("no `-`, an empty name or version, or one that is not a
    string field's value")."""
    d = p[:-len(b'/RECORD')]
    holder, base = (d.rsplit(b'/', 1) if b'/' in d else (b'.', d))
    stem = base[:-len(b'.dist-info')]
    if b'-' not in stem:
        return None
    name, ver = stem.split(b'-', 1)
    if not name or not ver or not string_ok(name) or not string_ok(ver):
        return None
    return holder, name.decode('utf-8'), ver.decode('utf-8')


def event_or_invalid(interp, kind, values, paths, unknown, trace):
    """E9: "An event a value of which is not a string field's value, or whose
    text would exceed 1,024 bytes, is one `invalid_finding` event naming its
    paths" -- in its place. Every value here is a string field's value
    (dist_info() names no other), so only the text can break the row: a
    template filling three values of up to 1,024 bytes each."""
    if len(fill(kind, values).encode('utf-8')) > 1024:
        trace.append('pip-invalid-event')
        if kind == 'pip_reinstalled':
            trace.append('pip-invalid-event:reinstalled')
        return render_event(interp, 'invalid_finding', {}, paths, unknown)
    return render_event(interp, kind, values, paths, unknown)


def pip_end(state, trace):
    """pip's events ("What each interpreter reports", pip): the events with
    no name first -- a could_not_interpret for each RECORD whose dist-info
    cannot be named (E10), by path, then the content_unavailable events --
    then by normalized name, kind (the pin's order), directory. A pair key
    with RECORDs added and removed other than one of each is one
    could_not_interpret event naming them, "in that name's place". An
    unknown RECORD on both sides is its own provisional pip_reinstalled,
    uncounted. Every event one of whose RECORDs is unknown is provisional
    (E2)."""
    unk = state['unknown']
    if any(p in unk for p, _ in state['moved']):
        trace.append('pip-provisional')
    keys = collections.OrderedDict()
    for p, how in state['moved']:
        holder, name, ver = dist_info(p)
        keys.setdefault((holder, pep503(name)), {'added': [], 'removed': []})[how].append(
            (p, name, ver))
    named, kind_ix = [], list(KINDS).index
    for (holder, norm), d in keys.items():
        A, R = d['added'], d['removed']
        if A and R and (len(A), len(R)) != (1, 1):
            trace.append('pip-ambiguous-key')
            ps = [x[0] for x in A + R]
            if any(x in unk for x in ps):
                trace.append('pip-ambiguous-key-provisional')
            named.append(((norm, kind_ix('could_not_interpret'), holder, sorted(ps)),
                          render_event('pip', 'could_not_interpret', {}, ps, unk)))
            continue
        if A and R:
            (pa, name, to), (pr, rname, frm) = A[0], R[0]
            ka, kb = pep440_key(to), pep440_key(frm)
            if ka is None or kb is None or ka == kb:
                kind = 'pip_version_changed'
                trace.append(kind + (':equal' if ka is not None and kb is not None
                                     else ':not-pep440'))
            else:
                kind = 'pip_upgraded' if ka > kb else 'pip_downgraded'
                trace.append(kind)
            if name != rname:
                trace.append('pip-pair-spelled-differently')
            if pa in unk or pr in unk:
                trace.append('pip-provisional-pair')
            named.append(((norm, kind_ix(kind), holder, sorted([pa, pr])),
                          event_or_invalid('pip', kind, {'name': name, 'from': frm, 'to': to},
                                           [pa, pr], unk, trace)))
            continue
        if len(A + R) > 1:
            trace.append('pip-one-name-several-one-side')
        for (pp, name, ver) in A + R:
            kind = 'pip_installed' if A else 'pip_removed'
            trace.append(kind)
            if pp in unk:
                trace.append('pip-provisional-single')
            named.append(((norm, kind_ix(kind), holder, [pp]),
                          event_or_invalid('pip', kind, {'name': name, 'version': ver}, [pp],
                                           unk, trace)))
    # A RECORD present on both sides, unknown: "a provisional
    # `pip_reinstalled` whose rows are not compared: its three counts are
    # absent, under the kind's second template". It is neither added nor
    # removed, so it pairs with nothing: its own event, in its name's place.
    for pp in state['reinstalled']:
        holder, name, ver = dist_info(pp)
        trace.append('pip-reinstall-uncounted')
        if (holder, pep503(name)) in keys:
            trace.append('pip-reinstall-beside-a-move-of-its-name')
        named.append(((pep503(name), kind_ix('pip_reinstalled'), holder, [pp]),
                      event_or_invalid('pip', 'pip_reinstalled',
                                       {'name': name, 'version': ver, 'files_added': None,
                                        'files_removed': None, 'files_changed': None},
                                       [pp], unk, trace)))
    named.sort(key=lambda x: x[0])
    unnamed = [render_event('pip', 'could_not_interpret', {}, [p], unk)
               for p in sorted(state['unnamed'])]
    if unnamed:
        trace.append('pip-unnamed-event')
    return unnamed + unavailable_events('pip', state) + [e for _, e in named]


# ---------------------------------------------------------------------------
# git's content: HEAD, loose refs, packed-refs and reflogs, read from a store
# (diff-v1 "**git.**" and the paragraph after it; diff-events E12; the kinds
# of finding-kinds.md). Without a store every copy is `content_unavailable`
# and git derives no event but those: no side gives a value (E12: "a ref or
# `packed-refs` that cannot be read on a side gives no value there -- ...;
# after, the branch derives no event"), and a branch removed whose value
# before is not told has no kind to say it (ambiguity G11).
#
# The formats are git's own, which the prose does not restate: a loose ref is
# an object id and a newline; HEAD is that or `ref: <name>` and a newline;
# packed-refs is lines `<id> <name>`, its `#` header and `^<id>` peeled lines
# naming no ref; a reflog entry is `<old> <new> <identity>\t<message>` and a
# newline. An object id is 40 or 64 lowercase hex digits. Anything else
# cannot be parsed: "Where an interpreter fails on a path (a file it claims
# cannot be parsed, ...), that path's record carries `could_not_interpret`
# (R11) unless its outcome is `unknown`, nothing more is read from it, and
# pip, dpkg and git emit one `could_not_interpret` event naming it (E10)". The
# corpus writes only content git writes, and refs that are no ref at all
# (git's own parser may accept more: the documents do not define the
# formats, so the corpus stays within what git writes).

GIT_CONTENT = ('HEAD', 'ref', 'packed-refs', 'reflog')


class _Mark:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name


ABSENT = _Mark('ABSENT')                # not a regular file on that side, or no line for it
UNREADABLE = _Mark('UNREADABLE')        # content_unavailable: "gives no value there"
UNPARSED = _Mark('UNPARSED')            # could_not_interpret: "nothing more is read from it"
NO_EVIDENCE = _Mark('NO_EVIDENCE')      # no value can be told on that side
_OID = rb'(?:[0-9a-f]{40}|[0-9a-f]{64})'


def git_repo(p):
    """(the repository, the place): "per repository (a directory named
    `.git`; `repo` its path in the scope)" -- the path of the directory named
    `.git` itself, `.git` at the scope's root (ambiguity G2: not the
    working tree above it) -- and "A path is placed by the part after its
    `.git/` (the last one that fits)"."""
    place = git_place(p)
    return p[:len(p) - len(place) - 1], place


def parse_git(what, data):
    """The parsed copy, or None when it cannot be parsed."""
    if what in ('HEAD', 'ref'):
        m = re.fullmatch(b'(' + _OID + b')\n', data)
        if m:
            return ('oid', m.group(1).decode('ascii')) if what == 'HEAD' \
                else m.group(1).decode('ascii')
        m = re.fullmatch(rb'ref: ([^\n]+)\n', data) if what == 'HEAD' else None
        return ('sym', m.group(1)) if m else None
    if data and not data.endswith(b'\n'):
        return None
    lines = data.split(b'\n')[:-1]
    if what == 'packed-refs':
        refs = collections.OrderedDict()
        for line in lines:
            if line.startswith(b'#') or re.fullmatch(b'\\^' + _OID, line):
                continue
            m = re.fullmatch(b'(' + _OID + rb') ([^\n]+)', line)
            if not m:
                return None
            # "Where an interpreter keeps the first of two equal keys (..., a
            # packed ref), "first" is in file order."
            refs.setdefault(m.group(2), m.group(1).decode('ascii'))
        return refs
    entries = []                                # a reflog
    for line in lines:
        m = re.fullmatch(b'(' + _OID + b') (' + _OID + rb') [^\t\n]*\t([^\n]*)', line)
        if not m:
            return None
        msg = m.group(3)
        # "its operation being the message before its first `:`"
        entries.append((m.group(1).decode('ascii'), m.group(2).decode('ascii'), msg,
                        msg.split(b':', 1)[0]))
    return entries


def gained(before, after):
    """The entries a reflog gained: "when before's bytes are a prefix of
    after's ending at a line's end (an absent before is empty)", those after
    it; else None (git_reflog_rewritten: it gained none -- ambiguity G3)."""
    if after.startswith(before) and (before == b'' or before.endswith(b'\n')):
        return parse_git('reflog', after[len(before):])
    return None


def as_string(v):
    """A `string` field's value from bytes or str, or None when it is not one
    (not UTF-8, over 1,024 bytes, a NUL)."""
    if isinstance(v, bytes):
        try:
            v = v.decode('utf-8')
        except UnicodeDecodeError:
            return None
    return v if string_ok(v) else None


def git_finding(kind, values, trace):
    """A path finding of git's, or `invalid_finding` in its place when a value
    is not a string field's value or its text is over 1,024 bytes ("a finding
    that breaks the row ... is replaced by `invalid_finding`")."""
    vs = collections.OrderedDict()
    for n, v in values.items():
        if dict(KINDS[kind].fields)[n].rstrip('?') == 'string' and v is not None:
            v = as_string(v)
            if v is None:
                trace.append('git-invalid-finding')
                return render('invalid_finding', {})
        vs[n] = v
    if len(fill(kind, vs).encode('utf-8')) > 1024:
        trace.append('git-invalid-finding')
        return render('invalid_finding', {})
    return render(kind, vs)


def plain_or_fast_forward(entry):
    """git_reflog_move's complement: "a plain commit (operation `commit` or
    `commit (initial)`) or a fast-forward (its message contains
    `Fast-forward`)"."""
    return entry[3] in (b'commit', b'commit (initial)') or b'Fast-forward' in entry[2]


def git_explain(what, p, b, a, outcome, state, trace):
    """The findings of a HEAD, loose ref, packed-refs or reflog record, and
    what E12 needs of it, kept in state['git'][repo].

    Each side on which the path is a regular file is read ("A side on which
    the path is not a regular file counts as absent") -- but a removed
    reflog, whose finding needs no copy ("or when the reflog was removed (no
    copy needed), `git_reflog_rewritten`"). A path whose outcome is `unknown`
    is read too and adds no finding (E12, P8); one git does not need is not
    read: a tag's or a remote-tracking ref's, or their reflogs', whose only
    use is a path finding that an `unknown` record does not carry. A side
    whose copy cannot be read is `content_unavailable`: a finding (not on an
    `unknown` record), and that path gives no value on that side (E12). The
    per-reason event names it only when git derives events from that content
    -- HEAD, packed-refs, a branch's loose ref or reflog, `logs/HEAD` -- not
    a tag's or a remote-tracking ref's, whose record alone says it ("Content": "git
    names only the paths it derives events from (HEAD, branches,
    `packed-refs`, their reflogs), and a reflog removed needs no copy")."""
    store, unknown = state['store'], outcome == 'unknown'
    repo, place = git_repo(p)
    R = state['git'].setdefault(repo, {'HEAD': None, 'logs/HEAD': None, 'packed-refs': None,
                                       'loose': {}, 'logs': {}})
    if what == 'HEAD' or what == 'packed-refs':
        slot = (what, None)
    elif what == 'ref':
        slot = ('loose', place[len(b'refs/heads/'):]) if place.startswith(b'refs/heads/') \
            else None
    elif place == b'logs/HEAD':
        slot = ('logs/HEAD', None)
    else:
        slot = ('logs', place[len(b'logs/refs/heads/'):]) \
            if place.startswith(b'logs/refs/heads/') else None
    if slot is None:
        trace.append('git-no-branch')           # tags, remote-tracking refs, ...
        if unknown:
            return []
    ent = {'before': b, 'after': a}
    regs = [s for s, e in zip(SIDES, (b, a)) if is_reg(e)]
    if not regs:                                # a directory or a symlink: nothing
        return []
    if what == 'reflog' and not is_reg(a):     # removed: no copy needed, no entries gained
        trace.append('reflog-removed')
        return [] if unknown else [render('git_reflog_rewritten', {'ref': reflog_ref(p)})]
    out, raw, cannot = [], {}, False
    for s in regs:
        data, r = read_copy(ent[s], 'git', what, store)
        if r is not None:
            trace.append(('event-unavailable-%s-%s' if unknown else 'unavailable-%s-%s')
                         % (s, r))
            if not unknown:
                out.append(render('content_unavailable', {'reason': r, 'side': s}))
            if slot is not None:
                state['unavailable'].append((r, s, p))
            else:
                trace.append('git-unavailable-no-event')
            cannot = True
        else:
            raw[s] = data
    if cannot:
        # E12: "a ref or `packed-refs` that cannot be read on a side gives no
        # value there" -- on that side only: a side read gives its value (no
        # path finding, which needs both: the record says content_unavailable).
        # "a reflog it cannot read is no evidence" -- on either side, as the
        # entries it gained need both.
        trace.append('git-unread-side')
        if slot is not None:
            sides = {}
            for s in SIDES:
                if not is_reg(ent[s]):
                    sides[s] = ABSENT
                elif s not in raw:
                    sides[s] = UNREADABLE
                else:
                    sides[s] = parse_git(what, raw[s])
                    # The corpus never makes a side that cannot be parsed
                    # beside one that cannot be read (no rule orders the two).
                    assert sides[s] is not None, 'corpus: unparsed beside unread at %r' % p
            put_slot(R, slot, dict(sides, path=p, gained=None, read=False))
        return out
    trace.append('git-read' + ('-unknown' if unknown else ''))
    parsed = {s: parse_git(what, raw[s]) for s in regs}
    if any(v is None for v in parsed.values()):
        # "nothing more is read from it": no value on any side it is on --
        # given, as a side that cannot be read, no value there (ambiguity G5).
        trace.append('git-cannot-parse')
        state['cni'].append(p)
        if slot is not None:
            put_slot(R, slot, {'path': p, 'before': UNPARSED if is_reg(b) else ABSENT,
                               'after': UNPARSED if is_reg(a) else ABSENT,
                               'gained': None, 'read': False})
        return [] if unknown else [render('could_not_interpret', {})]
    pb, pa = parsed.get('before', ABSENT), parsed.get('after', ABSENT)
    g = gained(raw.get('before', b''), raw['after']) if what == 'reflog' else None
    if slot is not None:
        put_slot(R, slot, {'path': p, 'before': pb, 'after': pa, 'gained': g, 'read': True})
    if unknown:
        return []
    if what == 'HEAD':
        hv = lambda v: '' if v is ABSENT else v[1]
        if hv(pb) == hv(pa):
            trace.append('git-head-equal')
            return []
        return [git_finding('git_head_changed', collections.OrderedDict(
            [('from', hv(pb)), ('to', hv(pa))]), trace)]
    if what == 'ref':
        refs_b = {} if pb is ABSENT else {place: pb}
        refs_a = {} if pa is ABSENT else {place: pa}
    elif what == 'packed-refs':
        refs_b = {} if pb is ABSENT else pb
        refs_a = {} if pa is ABSENT else pa
    else:
        ref = reflog_ref(p)
        if g is None:
            trace.append('git-reflog-rewritten')
            return [render('git_reflog_rewritten', {'ref': ref})]
        trace.append('git-reflog-appended')
        fs = [git_finding('git_reflog_appended', collections.OrderedDict(
            [('ref', ref), ('entries', len(g))]), trace)]
        for e in g:
            if not plain_or_fast_forward(e):
                trace.append('git-reflog-move')
                fs.append(git_finding('git_reflog_move', collections.OrderedDict(
                    [('ref', ref), ('from', e[0]), ('to', e[1]), ('operation', e[3])]), trace))
        return fs
    # "A loose ref or a line of `packed-refs` (in ref order)": by the ref's
    # full name, bytewise.
    fs = []
    for name in sorted(set(refs_b) | set(refs_a)):
        vb, va = refs_b.get(name), refs_a.get(name)
        if vb is None:
            fs.append(git_finding('git_ref_created', collections.OrderedDict(
                [('ref', name), ('to', va)]), trace))
        elif va is None:
            fs.append(git_finding('git_ref_deleted', collections.OrderedDict(
                [('ref', name), ('from', vb)]), trace))
        elif vb != va:
            fs.append(git_finding('git_ref_moved', collections.OrderedDict(
                [('ref', name), ('from', vb), ('to', va)]), trace))
    if what == 'packed-refs' and len(fs) > 1:
        trace.append('git-packed-several')
    return fs


def put_slot(R, slot, v):
    kind, name = slot
    if name is None:
        R[kind] = v
    else:
        R[kind][name] = v


def short_branch(v):
    """git_head_switched's from and to: "the branch (`main`) or, detached, the
    commit"."""
    if v[0] == 'oid':
        return v[1]
    return v[1][len(b'refs/heads/'):] if v[1].startswith(b'refs/heads/') else v[1]


REWRITES = ('reset', 'commit (amend)', 'rebase', 'branch: Reset to', 'forced-update')


def rewrite_trigger(e):
    """Which of E12's rewrites an entry is, or None: "any `reset`, `commit
    (amend)`, operation containing `rebase`, message starting `branch: Reset
    to`, or message containing `forced-update`"."""
    old, new, msg, op = e
    if op == b'reset':
        return 'reset'
    if op == b'commit (amend)':
        return 'commit (amend)'
    if b'rebase' in op:
        return 'rebase'
    if msg.startswith(b'branch: Reset to'):
        return 'branch: Reset to'
    if b'forced-update' in msg:
        return 'forced-update'
    return None


COMMITS = (b'commit', b'commit (merge)', b'cherry-pick', b'revert', b'am')


def adds(e):
    """"only commits (`commit`, `commit (merge)`, `cherry-pick`, `revert`,
    `am`) and fast-forwards or merges (a message containing `Fast-forward`;
    an operation starting with `merge` or `pull`)"."""
    return e[3] in COMMITS or b'Fast-forward' in e[2] or e[3].startswith(b'merge') or \
        e[3].startswith(b'pull')


def classify(branch, vb, va, G, trace):
    """A branch on both sides at different commits, "decided by the entries
    its reflog gained in this diff, when they lead from its value before to
    its value after". (kind, values, whether the event names the reflog.)
    `paths` names "a reflog only when its entries were used -- giving the
    value before or evidence of absence before, a rename, or how the branch
    moved (entries that lead from before to after but say not how are not
    used)": here, how -- `git_commits_added` and `git_history_rewritten`;
    never a `git_branch_moved`'s, whose reflog "does not say how (none,
    another operation, or entries that do not lead ...)" (finding-kinds.md).
    "a reflog it cannot read is no evidence -- the move still comes from the
    refs, as `git_branch_moved`, without a how"."""
    entries = G['gained'] if G is not None and G['read'] else None
    moved = lambda why: (trace.append('git-ev:moved:' + why) or
                         ('git_branch_moved', collections.OrderedDict(
                             [('branch', branch), ('from', vb), ('to', va)]), False))
    if not entries:
        return moved('no entries' if G is None else 'its reflog unreadable'
                     if not G['read'] else 'a reflog that gained none')
    if entries[0][0] != vb or entries[-1][1] != va or \
            any(x[0] != y[1] for y, x in zip(entries, entries[1:])):
        return moved('entries that do not lead from before to after')
    hits = [(rewrite_trigger(e), e) for e in entries]
    if any(t for t, _ in hits):
        ops = []
        for t, e in hits:
            if t:
                trace.append('git-ev:rewritten:' + t)
                if e[3] not in ops:
                    ops.append(e[3])
        if len(ops) > 1:
            trace.append('git-ev:rewritten:several operations')
        return ('git_history_rewritten', collections.OrderedDict(
            [('branch', branch), ('how', b', '.join(ops)), ('from', vb), ('to', va)]), True)
    if all(adds(e) for e in entries):
        counted = all(e[3] in COMMITS for e in entries)
        trace.append('git-ev:commits added:' + ('counted' if counted else 'not counted'))
        return ('git_commits_added', collections.OrderedDict(
            [('branch', branch), ('count', len(entries) if counted else None), ('to', va)]),
            True)
    return moved('another operation')


def git_event(kind, repo, values, paths, unk, trace):
    """E2's record of one git event, `repo` first; E9: one whose value is not a
    string field's value, or whose text would exceed 1,024 bytes, is one
    `invalid_finding` event naming its paths, in its place."""
    vs = collections.OrderedDict([('repo', repo)])
    vs.update(values)
    for n, v in list(vs.items()):
        if v is not None and dict(KINDS[kind].fields)[n].rstrip('?') == 'string':
            vs[n] = as_string(v)
            if vs[n] is None:
                trace.append('git-ev:invalid')
                return render_event('git', 'invalid_finding', {}, paths, unk)
    if len(fill(kind, vs).encode('utf-8')) > 1024:
        trace.append('git-ev:invalid')
        return render_event('git', 'invalid_finding', {}, paths, unk)
    if any(x in unk for x in paths):
        trace.append('git-ev:provisional:' + kind)
    return render_event('git', kind, vs, paths, unk)


def side_value(R, br, side):
    """E12: "Its value on a side: its loose ref there; else its line in
    `packed-refs` when `packed-refs` is a path of this diff; else, before
    only, the old id of the first entry its reflog gained in this diff (all
    zeros: absent)". And a loose ref removed with `packed-refs` not a path of
    this diff is absent after: "its loose ref removed and `packed-refs`
    without it (a path of this diff, or not -- git removes a branch from
    both)". "packed-refs without it" counts an absent `packed-refs` too
    (ambiguity G9). (value, the paths whose value it is, which source.)

    "What git cannot read reduces what is claimed, never the fact the refs
    give: ... a ref or `packed-refs` that cannot be read on a side gives no
    value there -- before, the reflog's evidence may still give one, and
    without one the event is `git_branch_moved` with no `from`; after, the
    branch derives no event." A loose ref that is there unread is still its
    loose ref there: `packed-refs` does not stand in for it (git reads the
    loose ref first), only the reflog may. Its value after: UNREADABLE. A
    path that cannot be parsed gives none on either side (ambiguity G5).
    And a loose ref that is there before, unread, is never absent by its
    reflog's zeros: that it was there is the fact the refs give, which
    evidence does not overturn -- no value, so no `from` (ambiguity G10).

    "... without one the event is `git_branch_moved` with no `from` (a
    branch only in `packed-refs` too)": a branch named by `packed-refs` on
    the side read alone is a branch like any other.

    The paths returned are those whose value the event uses (`paths`:
    "every ref, `packed-refs` and `HEAD` path whose value the event uses,
    and a reflog only when its entries were used -- giving the value before
    or evidence of absence before, ..."): `packed-refs` where its line or its
    absence gave the value, never where it gave none; the reflog where it
    gave the value before -- an old id, or zeros."""
    L, P, G = R['loose'].get(br), R['packed-refs'], R['logs'].get(br)
    unread = None                       # which path gave no value, and why
    word = lambda v: 'unread' if v is UNREADABLE else 'unparsed'
    if L is not None and L[side] is not ABSENT:
        if L[side] is not UNREADABLE and L[side] is not UNPARSED:
            return L[side], [L['path']], 'loose'
        unread = 'its loose ref ' + word(L[side])
    elif P is not None:
        v = P[side]
        if isinstance(v, dict):
            v = v.get(b'refs/heads/' + br, ABSENT)
        if v is not UNREADABLE and v is not UNPARSED:
            return v, [P['path']], 'packed-refs'
        unread = 'packed-refs ' + word(v)
    if side == 'after':
        if unread is not None:
            return UNREADABLE, [], unread
        if L is not None:
            return ABSENT, [L['path']], 'loose removed'
        return NO_EVIDENCE, [], None
    if G is not None and G['read'] and G['gained']:
        old = G['gained'][0][0]
        how = 'reflog' + (', ' + unread if unread else '')
        if set(old) != {'0'}:
            return old, [G['path']], how
        if unread is None or not unread.startswith('its loose ref'):
            return ABSENT, [G['path']], how
        return NO_EVIDENCE, [], unread + ', its reflog from zeros'
    return NO_EVIDENCE, [], unread


def repo_events(repo, R, unk, trace):
    """One repository's events: [(sort key, record)]. E4: "git by repository,
    then `HEAD` before every branch, then branch, then kind"."""
    out, kind_ix = [], GIT_EVENT_KINDS.index
    H = R['HEAD']
    if H is not None and H['read'] and H['before'] is not ABSENT and \
            H['after'] is not ABSENT and H['before'] != H['after']:
        hb, ha = H['before'], H['after']
        if hb[0] == 'oid' and ha[0] == 'oid':
            # "`HEAD` detached on both sides at different commits is the
            # branch `HEAD`, decided by `logs/HEAD` as above."
            trace.append('git-ev:detached HEAD moved')
            kind, values, read = classify(b'HEAD', hb[1], ha[1], R['logs/HEAD'], trace)
            paths = [H['path']] + ([R['logs/HEAD']['path']] if read else [])
        else:
            trace.append('git-ev:HEAD ' + ('detached' if ha[0] == 'oid' else 'attached'
                                           if hb[0] == 'oid' else 'switched'))
            kind, paths = 'git_head_switched', [H['path']]
            values = collections.OrderedDict([('from', short_branch(hb)),
                                              ('to', short_branch(ha))])
        out.append(((repo, 0, b'', kind_ix(kind)), git_event(kind, repo, values, paths, unk,
                                                             trace)))
    elif H is not None and not H['read']:
        # A side of HEAD that cannot be read: git_head_switched's `from` and
        # `to` are both required, and "the branch `HEAD`" is HEAD detached on
        # both sides -- which a side not read cannot show (ambiguity G12).
        trace.append('git-ev:HEAD not read on a side, no event')
    P = R['packed-refs']
    names = set(R['loose']) | set(R['logs'])
    if P is not None:
        for v in (P['before'], P['after']):
            if isinstance(v, dict):
                names |= {n[len(b'refs/heads/'):] for n in v if n.startswith(b'refs/heads/')}
    ev = {}
    for br in sorted(names):
        vb, pb, how_b = side_value(R, br, 'before')
        va, pa, how_a = side_value(R, br, 'after')
        paths = pb + pa
        assert vb is not UNREADABLE and vb is not UNPARSED
        if va is UNREADABLE:
            # "after, the branch derives no event"
            trace.append('git-ev:no value after, no event: ' + how_a)
            continue
        if how_b is not None and how_b.startswith('reflog, '):
            trace.append('git-ev:value before by its reflog, ' + how_b[len('reflog, '):])
        if vb is ABSENT and isinstance(va, str):
            trace.append('git-ev:created, absent before by ' + how_b)
            ev[br] = ('git_branch_created', collections.OrderedDict(
                [('branch', br), ('at', va)]), paths)
        elif vb is NO_EVIDENCE and isinstance(va, str):
            G = R['logs'].get(br)
            if how_b is None:
                trace.append('git-ev:moved, no evidence of before')
                if G is not None and not G['read']:
                    # "a reflog it cannot read is no evidence": the value
                    # before "cannot be told" (git_branch_moved's row).
                    trace.append('git-ev:moved, its reflog unreadable')
            else:
                # "before, the reflog's evidence may still give one, and
                # without one the event is `git_branch_moved` with no `from`"
                trace.append('git-ev:moved, no value before: ' + how_b)
            ev[br] = ('git_branch_moved', collections.OrderedDict(
                [('branch', br), ('from', None), ('to', va)]), paths)
        elif vb is NO_EVIDENCE and va is ABSENT and how_b is not None:
            # Removed, its value before not told: `git_branch_deleted` needs
            # `was`, and "`git_branch_moved` with no `from`" a `to` -- no
            # kind can say it (ambiguity G11). The content_unavailable or
            # could_not_interpret event names the path.
            trace.append('git-ev:removed, no value before, no event: ' + how_b)
        elif isinstance(vb, str) and va is ABSENT:
            trace.append('git-ev:deleted, ' + {
                'loose removed': 'packed-refs not a path of this diff',
                'packed-refs': 'packed-refs a path of this diff without it'}[how_a]
                + {'loose': '', 'packed-refs': ', packed only'}.get(how_b, ', by its reflog'))
            ev[br] = ('git_branch_deleted', collections.OrderedDict(
                [('branch', br), ('was', vb)]), paths)
        elif isinstance(vb, str) and isinstance(va, str) and vb != va:
            G = R['logs'].get(br)
            kind, values, read = classify(br, vb, va, G, trace)
            ev[br] = (kind, values, paths + ([G['path']] if read else []))
        elif vb == va and isinstance(vb, str):
            trace.append('git-ev:a branch at the same commit')
    # "a deletion and a creation at the same commit whose new reflog says
    # `Branch: renamed`, one `git_branch_renamed`" -- "when the new branch's
    # reflog of this diff says `Branch: renamed refs/heads/{from} to
    # refs/heads/{to}`": an entry it gained in this diff with that message.
    for to in sorted(ev):
        if to not in ev or ev[to][0] != 'git_branch_created':
            continue
        G = R['logs'].get(to)
        for e in (G['gained'] or []) if G is not None and G['read'] else []:
            m = re.fullmatch(rb'Branch: renamed refs/heads/(.+) to refs/heads/(.+)', e[2])
            frm = m.group(1) if m and m.group(2) == to else None
            if frm in ev and ev[frm][0] == 'git_branch_deleted' and \
                    ev[frm][1]['was'] == ev[to][1]['at']:
                trace.append('git-ev:renamed')
                ev[frm] = ('git_branch_renamed', collections.OrderedDict(
                    [('from', frm), ('to', to), ('at', ev[to][1]['at'])]),
                    ev[frm][2] + ev[to][2] + [G['path']])
                del ev[to]
                break
    # The rename's place: "then branch" -- its `from`, the branch its text
    # names first ("branch {from} renamed to {to}"; ambiguity G6).
    for br, (kind, values, paths) in ev.items():
        if kind == 'git_branch_renamed' and any(values['to'] < x < br for x in ev):
            trace.append("git-ev:a rename in its from's place")
        out.append(((repo, 1, br, kind_ix(kind)), git_event(kind, repo, values, paths, unk,
                                                            trace)))
    return out


def git_end(state, trace):
    """git's events: those with no name first -- a `could_not_interpret` for
    each file that cannot be parsed, by path, then the `content_unavailable`
    events, one per reason -- then the repositories' (E4). "Events with no
    name -- `could_not_interpret` for a file, `content_unavailable` -- come
    before every named event, in the Kinds table's order, then by path"."""
    unk = state['unknown']
    named = []
    for repo, R in state['git'].items():
        named += repo_events(repo, R, unk, trace)
    if len({k[0] for k, _ in named}) > 1:
        trace.append('git-ev:two repositories')
    heads = {k[0] for k, _ in named if k[1] == 0}
    if any(k[1] == 1 and k[0] in heads and k[2] < b'HEAD' for k, _ in named):
        trace.append('git-ev:HEAD before a branch that sorts before it')
    named.sort(key=lambda x: x[0])
    unnamed = [render_event('git', 'could_not_interpret', {}, [p], unk)
               for p in sorted(state['cni'])]
    if unnamed:
        trace.append('git-ev:could_not_interpret')
    ev = unavailable_events('git', state)
    for e in ev:
        d = dict(e)
        trace.append('git-ev:content_unavailable:%s%s' % (
            d['reason'], ', provisional' if d.get('provisional') else ''))
    if (unnamed or ev) and named:
        trace.append('git-ev:events with no name before the named')
    return unnamed + ev + [e for _, e in named]


def end(interp, state, trace):
    """An interpreter's events. The end hook fails as a whole (E6) only when
    "the interpreter's per-diff state would exceed 64 MiB, memory runs out,
    or it adds an event naming no path" (decision 121: both "Event records"
    and "What each interpreter reports" now name all three). None is
    reachable from this corpus: its manifests are small and it has no
    store, and this model derives every event from the paths it was given,
    so none names no path (render_event() asserts it). Not modelled. Were
    it modelled, its event would list "the first 1,024 of the paths it had
    claimed (bytewise; never a path E11 withholds)" (E6; the prose: "none
    `unknown` only as `not_captured`, which it is never given: E11") --
    `state` already holds only what explain() was given, and diff() gives
    explain() no such path."""
    if interp == 'pip':
        return pip_end(state, trace)
    if interp == 'dpkg':
        ev = unavailable_events('dpkg', state)
        if any(dict(e).get('provisional') for e in ev):
            trace.append('dpkg-provisional-unavailable')
        return ev
    if interp == 'git':
        return git_end(state, trace)
    return []


def diff(before, after, store=None):
    """None when the scopes differ (refused). Otherwise (header, records,
    events, trailer, traces): header and trailer as [(key, value)], records
    as dicts with `path` as bytes (`findings` a list of [(key, value)]),
    events as [(key, value)] each, traces {path: [tags]} for messages and
    the coverage gate (b'' holds the end hooks' tags).

    `before` is the first manifest given and `after` the second, "whatever
    their `created_ns` say" (diff-v1.md, after the "Shape" example)."""
    rawb, rawa = {}, {}
    hb, sb, eb = load(before, rawb)
    ha, sa, ea = load(after, rawa)
    if sb != sa:
        return None
    xb, xa = excluded(hb), excluded(ha)
    for es, xs in ((eb, xb), (ea, xa)):         # V2-2: "It has no entry, nor anything below it"
        bad = [p for p in es if covering(xs, p) is not None]
        if bad:
            raise ValueError('corpus error: %r recorded at or below an excluded path' % bad[0])
    root_b, root_a = eb[b'.']['dev'], ea[b'.']['dev']
    remounted = root_b != root_a
    ctx = dict(root_dev_b=root_b, root_dev_a=root_a, identity_compared=not remounted)
    scopes_key = 'scopes_b64' if 'scopes_b64' in hb else 'scopes'   # ambiguity A9
    header = [('belay_diff', 1), (scopes_key, hb[scopes_key]),
              ('before_created_ns', hb['created_ns']), ('after_created_ns', ha['created_ns']),
              ('before_hash_max_bytes', hb['hash_max_bytes']),
              ('after_hash_max_bytes', ha['hash_max_bytes']),
              ('scope_remounted', remounted), ('identity_compared', not remounted),
              ('before_manifest_version', hb['belay_manifest']),
              ('after_manifest_version', ha['belay_manifest']),
              # V2-R7: each manifest's `excluded` as written, null for v1;
              # they decide nothing (xb and xa above are what decides).
              ('before_excluded', header_excluded(before)[0]),
              ('after_excluded', header_excluded(after)[0])]
    assert [('scopes' if k == 'scopes_b64' else k) for k, _ in header] == HEADER_KEYS
    records, counts, traces = [], collections.Counter(), {}
    states = {i: {'unavailable': [], 'moved': [], 'unnamed': [], 'reinstalled': [],
                  'unknown': set(), 'store': store, 'git': {}, 'cni': []}
              for i in INTERP_ORDER}
    paths = sorted(set(eb) | set(ea))
    for p in paths:
        b, a = eb.get(p), ea.get(p)
        if b is not None and a is not None:
            out, changed, why, trace = both_sides(b, a, ctx)
        elif a is not None:
            out, why, trace = one_sided(p, a, eb, True, xb)
            changed = []
        else:
            out, why, trace = one_sided(p, b, ea, False, xa)
            changed = []
        check_o4(out, b, a)
        if out == 'unknown' and not why:
            raise AssertionError('reference bug: unknown without a reason at %r' % p)
        counts[out] += 1
        # "A directory whose only difference is its own timestamps is
        # therefore `unchanged` and gets no record; the trailer counts it in
        # `dir_timestamps_only`, which is part of `unchanged`" -- and an absent
        # record means "for a directory, possibly with its own timestamps
        # changed": every `unchanged` directory whose O5 timestamps differ.
        if out == 'unchanged' and b['type'] == 'dir' and \
                any(b[f] != a[f] for f in DIR_TIMESTAMPS):
            counts[DIR_TIMESTAMPS_ONLY] += 1
            trace = trace + ['dir-timestamps-counted']
        traces[p] = trace + (['remount'] if remounted else [])
        if out == 'unchanged':
            continue
        e = a if a is not None else b
        rec = {'path': p, 'outcome': out, 'type': e['type']}
        # "`type_before`, for a path present on both sides whose types differ:
        # the type before, whatever the outcome -- `type_changed`, or `unknown`
        # when `raced` is on either side."
        if b is not None and a is not None and b['type'] != a['type']:
            rec['type_before'] = b['type']
        if changed:
            rec['changed'] = changed
        # diff-values V1: `before` and `after` "after `changed` and before
        # `unknown`"; V6: on a record with `type_before`, "after `changed`".
        vals = (record_values(rawb[p], rawa[p], changed, traces[p])
                if b is not None and a is not None else None)
        if vals is not None:
            rec['before'], rec['after'] = dict(vals[0]), dict(vals[1])
        if out == 'unknown':
            rec['unknown'] = why
        # "For a path that is not `unchanged`, the interpreter that claims it
        # adds **findings** to its record" -- `findings` "absent when none".
        interp, what = interpreter_of(sb, p, b, a)
        traces[p].append('interp:%s%s' % (interp, ':' + what if what else ''))
        # E11: "A path whose outcome is `unknown` with `not_captured` as its
        # only reason ... derives no event ... Its path record stands"; the
        # prose: "none from a path `unknown` only as `not_captured`, which no
        # interpreter is given". Not given to explain(): no event of any
        # kind names it -- no pip pairing, no content_unavailable, no
        # could_not_interpret -- and, `unknown`, its record carries no
        # finding either way. E11 now says so of the core's events (decision
        # 118; ambiguity X4, which read "derives no event at all" as every
        # kind, is settled the same way): "No interpreter is given it, so no
        # event of the core's names it either: no `could_not_interpret` (E10)
        # nor `content_unavailable` for it, and a failed end hook's event
        # (E6) never lists it."
        if out == 'unknown' and why == [NOT_CAPTURED]:
            traces[p].append('e11-not-interpreted')
        elif interp != BINARY:
            fs = explain(interp, what, p, b, a, out, states[interp], traces[p])
            if fs:
                rec['findings'] = fs
        records.append(rec)
    # "every path present in either manifest is counted once, so the counts
    # add up to the number of distinct paths"
    assert sum(counts[o] for o in OUTCOMES) == len(paths)
    # Event records, "emitted once every path has been seen" (E1), by
    # interpreter in E4's order.
    traces[b''] = []
    events = [ev for i in INTERP_ORDER for ev in end(i, states[i], traces[b''])]
    trailer = ([('belay_diff_end', len(records))] + [(o, counts[o]) for o in OUTCOMES]
               + [(DIR_TIMESTAMPS_ONLY, counts[DIR_TIMESTAMPS_ONLY]), (EVENTS, len(events))])
    (tb, shab), (ta, shaa) = trailer_of(before), trailer_of(after)
    inputs = [('before_' + c, tb[c]) for c in INPUT_COUNTS] + [('after_' + c, ta[c]) for c in INPUT_COUNTS]
    trailer += inputs + [('provisional', any(v != 0 for _, v in inputs)),
                         ('before_sha256', shab), ('after_sha256', shaa)]
    assert [k for k, _ in trailer] == TRAILER_KEYS
    return header, records, events, trailer, traces


def encode_record(rec):
    r = dict(rec)
    p = r.pop('path')
    try:
        head = {'path': p.decode('utf-8')}
    except UnicodeDecodeError:
        head = {'path_b64': base64.b64encode(p).decode('ascii')}
    head.update(r)
    if 'findings' in head:
        head['findings'] = [dict(f) for f in head['findings']]
    return head


def canonical(v):
    """The bytes of a JSON value as a belay writer emits it (manifest-v1
    "Encoding": no whitespace, strings by canonical_string(), `true` and
    `false`); an object is a [(key, value)] list or a dict, in its order."""
    if v is None:                      # V2-R7: `null` for a v1 manifest
        return b'null'
    if isinstance(v, bool):
        return b'true' if v else b'false'
    if isinstance(v, int):
        return str(v).encode('ascii')
    if isinstance(v, str):
        return canonical_string(v)
    if isinstance(v, dict):            # an object, empty or not (diff-values V2: `{}`)
        return b'{' + b','.join(canonical_string(k) + b':' + canonical(x)
                                for k, x in v.items()) + b'}'
    if v and all(isinstance(x, tuple) and len(x) == 2 and isinstance(x[0], str) for x in v):
        return b'{' + b','.join(canonical_string(k) + b':' + canonical(x) for k, x in v) + b'}'
    if isinstance(v, list):
        return b'[' + b','.join(canonical(x) for x in v) + b']'
    raise TypeError(repr(v))


if __name__ == '__main__':
    store = None
    if sys.argv[1] == '--store':
        store = sys.argv[2]
        del sys.argv[1:3]
    res = diff(sys.argv[1], sys.argv[2], store)
    if res is None:
        print('refused: the manifests have different scopes', file=sys.stderr)
        sys.exit(1)
    header, records, events, trailer, _ = res
    dump = lambda o: json.dumps(o, ensure_ascii=False, separators=(',', ':'))
    print(canonical(header).decode('utf-8'))
    for r in records:
        print(dump(encode_record(r)))
    for ev in events:
        print(canonical(ev).decode('utf-8'))
    print(dump(dict(trailer)))
