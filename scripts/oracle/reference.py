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
    carries and the event records, in the oracle's setting -- a diff given
    no store, so every stored copy an interpreter needs is
    `content_unavailable`. What would need content (text_changed, a RECORD's
    rows, a status file's stanzas, refs) is not modelled: it cannot occur.
Never the generated blocks of the spec, never src/ or include/.

Ambiguities this file resolves one way (questions for the author) are
marked "ambiguity I<n>" where they are decided.

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
    record table is generated): compare.py does not check it.
"""
import base64, collections, hashlib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
FIELDS_PIN = os.path.join(REPO, 'test', 'expect', 'diff-fields.md')
MANIFEST_PIN = os.path.join(REPO, 'test', 'expect', 'manifest-v1.md')
SPEC = os.path.join(REPO, 'docs', 'spec', 'diff-v1.md')

# The header's and the trailer's keys, in order. The header's from the "Shape"
# example (its first line); `scopes` is spelled `scopes_b64` when the scope
# is not UTF-8 (ambiguity A9).
HEADER_KEYS = ['belay_diff', 'scopes', 'before_created_ns', 'after_created_ns',
               'before_hash_max_bytes', 'after_hash_max_bytes', 'scope_remounted',
               'identity_compared']
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


def shape_example_keys():
    """The keys of the first (header) and last (trailer) line of the example
    under "## Shape" in docs/spec/diff-v1.md -- prose, not a generated block."""
    text = open(SPEC, encoding='utf-8').read()
    m = re.search(r'^## Shape\n.*?^```json\n(.*?)^```', text, re.S | re.M)
    if not m:
        raise SystemExit('spec: no example under "## Shape" in %s' % SPEC)
    lines = m.group(1).splitlines()
    keys = lambda line: [k for k, _ in json.loads(line, object_pairs_hook=list)]
    return keys(lines[0]), keys(lines[-1])


if shape_example_keys() != (HEADER_KEYS, TRAILER_KEYS):
    raise SystemExit('spec: the "Shape" example\'s header or trailer keys are not the ones '
                     'reference.py writes: %r' % (shape_example_keys(),))

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
    text = ' '.join(open(SPEC, encoding='utf-8').read().split())
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


def load(path):
    """(header, scope bytes, {path bytes: entry}). An entry's `path` and
    `link_target` are bytes whichever spelling the manifest used."""
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


def one_sided(p, present, lacking_entries, added):
    """The four bullets of "Present on one side only", in their order."""
    anc = nearest_ancestor(lacking_entries, p)
    trace = ['one-sided']
    if anc['type'] == 'dir' and (anc.get('unreadable') or anc.get('mount')):
        return 'unknown', [NOT_CAPTURED], trace + ['not_captured']
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
# Interpreters, in the oracle's setting: the driver passes NULL options, so
# the diff has NO store ("Content": reason `no_store`, "the diff was given no
# store"). Only what an interpreter can say without content is modelled;
# whatever needs a stored copy is `content_unavailable`. Sources, PROSE ONLY:
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
        for _, typ in self.fields:
            if typ not in ('int', 'string', 'bool'):
                raise SystemExit('pin: kind %s: unknown field type %r' % (self.name, typ))
        t = row['text']
        if not (t.startswith('`') and t.endswith('`')):
            raise SystemExit('pin: kind %s: text %r is not one code span' % (self.name, t))
        self.template = t[1:-1]
        named = re.findall(r'\{([a-z_]+)\}', self.template)
        if not set(named) <= {n for n, _ in self.fields}:
            raise SystemExit('pin: kind %s: template names %r' % (self.name, named))


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
              'side: `before` or `after`, one finding per side',
              'pip and dpkg, which emit events from that content, also emit one '
              '`content_unavailable` event per reason, with side `before` or `after` when all '
              'its paths share it, else `both`, naming the paths']:
        if w not in text:
            raise SystemExit('pin: finding-kinds.md no longer says what reference.py assumes: '
                             '%r' % w)
    need = {'content_unavailable': (['reason', 'side'], ['text', 'pip', 'dpkg', 'git']),
            'could_not_interpret': ([], ['any']),
            'pip_installed': (['name', 'version'], ['pip']),
            'pip_removed': (['name', 'version'], ['pip']),
            'pip_upgraded': (['name', 'from', 'to'], ['pip']),
            'pip_downgraded': (['name', 'from', 'to'], ['pip']),
            'pip_version_changed': (['name', 'from', 'to'], ['pip']),
            'git_hook_added': (['hook', 'executable'], ['git']),
            'git_hook_removed': (['hook'], ['git']),
            'git_hook_changed': (['hook', 'executable'], ['git']),
            'git_hook_executable_changed': (['hook', 'executable'], ['git']),
            'git_index_changed': ([], ['git']),
            'git_reflog_rewritten': (['ref'], ['git'])}
    for k, (fields, interps) in need.items():
        if k not in kinds or [n for n, _ in kinds[k].fields] != fields or \
                kinds[k].interps != interps:
            raise SystemExit('pin: kind %r no longer has what reference.py assumes' % k)
    return kinds


def load_event_rules():
    rules = {r['rule'].split()[0]: r['statement'] for r in
             md_table(open(EVENTS_PIN, encoding='utf-8').read(), 'rule')}
    said = {
        'E1': ['Event records come after the last path record and before the trailer. A diff '
               'with none has none.'],
        'E2': ['`{"event": "<kind>", "interp": "<interpreter>", <the kind\'s fields, in '
               'finding-kinds.md\'s order>, "text": "<its template>", "paths": [...]}`'],
        'E3': ['sorted bytewise, each once', '`paths_b64` instead -- every element base64 -- '
               'when any is not valid UTF-8'],
        'E4': ['By interpreter, in the order text, pip, dpkg, git'],
        'E6': ['`{"event": "could_not_interpret", "interp": ..., "text": "could not interpret", '
               '"paths": [...]}` with the paths it had claimed, and no other event'],
        'E7': ['The trailer gains `events`: the number of event records.'],
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
# dpkg claims `*/var/lib/dpkg/status` and the per-package `info/*.list` and
# `info/*.md5sums`; pip claims `*.dist-info/RECORD` and `*.dist-info/METADATA`;
# git claims `*/.git/HEAD`, `*/.git/packed-refs`, `*/.git/refs/*`,
# `*/.git/hooks/*`, `*/.git/index` and the reflogs `*/.git/logs/HEAD` and
# `*/.git/logs/refs/*`." The dpkg `info/` files are read as below
# `*/var/lib/dpkg/` (ambiguity I1). A `*` spans `/`: `*.dist-info/RECORD`
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
    text = ' '.join(open(SPEC, encoding='utf-8').read().split())
    for _, _, pat in CLAIMS:
        tail = pat[len('*/var/lib/dpkg/'):] if pat.startswith('*/var/lib/dpkg/info/') else pat
        if '`%s`' % tail not in text:
            raise SystemExit('spec: "Which interpreter" no longer names %r' % tail)
    for w in ['An unclaimed path is **text** when its entry is `stored` on every side it exists '
              'on', 'any other is **binary**, which adds nothing',
              'for a path whose outcome is `unknown` or `metadata_only` it adds nothing (a git '
              "hook's executable bit excepted, which is metadata)",
              'A side on which the path is not a regular file counts as absent.',
              '`missing` covers a path whose entry records no `stored` copy',
              'Only a reinstall reads content (both RECORDs); the others come from the paths '
              'alone.',
              'a `content_unavailable` event has no name and comes first',
              'A hook, from the manifest alone',
              'or when the reflog was removed, `git_reflog_rewritten`']:
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


def render(kind, values):
    """[(key, value)] of a finding: kind, its fields in the pin's order, text
    ("the template, filled"; a bool is filled as `true` / `false`:
    ambiguity I9)."""
    k = KINDS[kind]
    if [n for n, _ in k.fields] != list(values):
        raise AssertionError('reference bug: %s with %r' % (kind, list(values)))
    out = []
    for n, typ in k.fields:
        v = values[n]
        ok = {'int': lambda v: type(v) is int and v >= 0, 'bool': lambda v: type(v) is bool,
              'string': lambda v: isinstance(v, str) and string_ok(v)}[typ](v)
        if not ok:
            raise AssertionError('reference bug: %s.%s = %r' % (kind, n, v))
        out.append((n, v))
    show = lambda v: ('true' if v else 'false') if type(v) is bool else str(v)
    text = re.sub(r'\{([a-z_]+)\}', lambda m: show(values[m.group(1)]), k.template)
    assert len(text.encode('utf-8')) <= 1024
    return [('kind', kind)] + out + [('text', text)]


def render_event(interp, kind, values, paths):
    """E2: event, interp, the kind's fields, text, paths (E3: sorted bytewise,
    each once; `paths_b64` when any is not UTF-8)."""
    f = render(kind, values)
    ps = sorted(set(paths))
    try:
        pv = ('paths', [x.decode('utf-8') for x in ps])
    except UnicodeDecodeError:
        pv = ('paths_b64', [base64.b64encode(x).decode('ascii') for x in ps])
    return [('event', kind), ('interp', interp)] + f[1:] + [pv]


def is_reg(e):
    """"A side on which the path is not a regular file counts as absent.\""""
    return e is not None and e['type'] == 'reg'


SIDES = ('before', 'after')
REASONS = ['no_store', 'missing', 'too_large', 'corrupt']   # the pin's order


def unavailable(e):
    """Why the stored copy of e cannot be read in a diff with no store:
    `missing` when the entry records no `stored` copy ("`missing` covers a
    path whose entry records no `stored` copy"), else `no_store` (which wins
    is not said: ambiguity I3)."""
    return 'missing' if 'stored' not in e else 'no_store'


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


def explain(interp, what, p, b, a, outcome, state, trace):
    """The findings of one record of a claimed or text path; events go to
    `state`. Each needed side whose copy cannot be read is one
    content_unavailable finding, before then after (the order is not said:
    ambiguity I4)."""
    bs, as_ = is_reg(b), is_reg(a)
    state['claimed'].append(p)
    executable = lambda e: bool(e['mode'] & 0o100)          # "the owner's"
    # "Every interpreter describes only a proven change of content: for a
    # path whose outcome is `unknown` or `metadata_only` it adds nothing (a
    # git hook's executable bit excepted, which is metadata)."
    if outcome == 'unknown':
        trace.append('interp-unknown')
        return []
    if outcome == 'metadata_only':
        if (interp, what) == ('git', 'hook') and bs and as_ and executable(b) != executable(a):
            trace.append('hook-executable')
            return [render('git_hook_executable_changed',
                           {'hook': hook_name(p), 'executable': executable(a)})]
        trace.append('interp-metadata-only')
        return []
    present = [s for s, ok in zip(SIDES, (bs, as_)) if ok]
    ent = {'before': b, 'after': a}
    need = []                                   # the sides whose content is needed
    if interp == TEXT or (interp, what) in (('dpkg', 'status'), ('git', 'HEAD'),
                                            ('git', 'ref'), ('git', 'packed-refs')):
        need = present
    elif (interp, what) == ('pip', 'RECORD'):
        if bs and as_:
            need = present                      # a reinstall reads both RECORDs
        elif bs or as_:
            state['moved'].append((p, 'removed' if bs else 'added'))
    elif (interp, what) == ('git', 'reflog'):
        if as_:
            need = present                      # appended or rewritten: read
        elif bs:                                # "or when the reflog was removed"
            trace.append('reflog-removed')
            return [render('git_reflog_rewritten', {'ref': reflog_ref(p)})]
    elif (interp, what) == ('git', 'hook'):     # "from the manifest alone"
        h = hook_name(p)
        if as_ and not bs:
            trace.append('hook-added')
            return [render('git_hook_added', {'hook': h, 'executable': executable(a)})]
        if bs and not as_:
            trace.append('hook-removed')
            return [render('git_hook_removed', {'hook': h})]
        if bs and as_:
            trace.append('hook-changed')
            return [render('git_hook_changed', {'hook': h, 'executable': executable(a)})]
    elif (interp, what) == ('git', 'index'):
        # "The index: changed when its content changed (hashed, never
        # stored)" -- present on one side only is read as a change too
        # (ambiguity I6).
        if bs or as_:
            trace.append('index-changed')
            return [render('git_index_changed', {})]
    out = []
    for s in need:
        r = unavailable(ent[s])
        trace.append('unavailable-%s-%s' % (s, r))
        out.append(render('content_unavailable', {'reason': r, 'side': s}))
        state['unavailable'].append((r, s, p))
    return out


def unavailable_events(interp, state):
    """One content_unavailable event per reason (pin, content_unavailable):
    side `before` or `after` when all its paths share it, else `both`. Two
    reasons in one diff: ordered as the pin lists the reasons (ambiguity I5)."""
    out = []
    for r in REASONS:
        hits = [(s, p) for rr, s, p in state['unavailable'] if rr == r]
        if not hits:
            continue
        sides = {s for s, _ in hits}
        side = sides.pop() if len(sides) == 1 else 'both'
        out.append(render_event(interp, 'content_unavailable', {'reason': r, 'side': side},
                                [p for _, p in hits]))
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


def pip_end(state, trace):
    """pip's events ("What each interpreter reports", pip): the
    content_unavailable events first, then by normalized name, kind (the
    pin's order), directory. None when the end hook fails (E6)."""
    keys = collections.OrderedDict()
    for p, how in state['moved']:
        di = dist_info(p)
        if di is None:
            trace.append('pip-unnamed')
            return None
        holder, name, ver = di
        keys.setdefault((holder, pep503(name)), {'added': [], 'removed': []})[how].append(
            (p, name, ver))
    named, kind_ix = [], list(KINDS).index
    for (holder, norm), d in keys.items():
        A, R = d['added'], d['removed']
        if A and R and (len(A), len(R)) != (1, 1):
            # "when one pair key has more than one RECORD added and removed"
            trace.append('pip-ambiguous-key')
            return None
        if A and R:
            (pa, name, to), (pr, _, frm) = A[0], R[0]
            ka, kb = pep440_key(to), pep440_key(frm)
            if ka is None or kb is None or ka == kb:
                kind = 'pip_version_changed'
            else:
                kind = 'pip_upgraded' if ka > kb else 'pip_downgraded'
            trace.append(kind)
            named.append(((norm, kind_ix(kind), holder),
                          render_event('pip', kind, {'name': name, 'from': frm, 'to': to},
                                       [pa, pr])))
            continue
        for (pp, name, ver) in A + R:
            kind = 'pip_installed' if A else 'pip_removed'
            trace.append(kind)
            named.append(((norm, kind_ix(kind), holder),
                          render_event('pip', kind, {'name': name, 'version': ver}, [pp])))
    named.sort(key=lambda x: x[0])
    return unavailable_events('pip', state) + [e for _, e in named]


def end(interp, state, trace):
    """An interpreter's events; one could_not_interpret event naming the
    paths it had claimed -- every path it was given (ambiguity I7) -- when
    its end hook fails (E6)."""
    if interp == 'pip':
        ev = pip_end(state, trace)
    elif interp == 'dpkg':
        ev = unavailable_events('dpkg', state)
    else:
        ev = []
    if ev is None:
        return [render_event(interp, 'could_not_interpret', {}, state['claimed'])]
    return ev


def diff(before, after):
    """None when the scopes differ (refused). Otherwise (header, records,
    events, trailer, traces): header and trailer as [(key, value)], records
    as dicts with `path` as bytes (`findings` a list of [(key, value)]),
    events as [(key, value)] each, traces {path: [tags]} for messages and
    the coverage gate (b'' holds the end hooks' tags).

    `before` is the first manifest given and `after` the second, "whatever
    their `created_ns` say" (diff-v1.md, after the "Shape" example)."""
    hb, sb, eb = load(before)
    ha, sa, ea = load(after)
    if sb != sa:
        return None
    root_b, root_a = eb[b'.']['dev'], ea[b'.']['dev']
    remounted = root_b != root_a
    ctx = dict(root_dev_b=root_b, root_dev_a=root_a, identity_compared=not remounted)
    scopes_key = 'scopes_b64' if 'scopes_b64' in hb else 'scopes'   # ambiguity A9
    header = [('belay_diff', 1), (scopes_key, hb[scopes_key]),
              ('before_created_ns', hb['created_ns']), ('after_created_ns', ha['created_ns']),
              ('before_hash_max_bytes', hb['hash_max_bytes']),
              ('after_hash_max_bytes', ha['hash_max_bytes']),
              ('scope_remounted', remounted), ('identity_compared', not remounted)]
    assert [('scopes' if k == 'scopes_b64' else k) for k, _ in header] == HEADER_KEYS
    records, counts, traces = [], collections.Counter(), {}
    states = {i: {'claimed': [], 'unavailable': [], 'moved': []} for i in INTERP_ORDER}
    paths = sorted(set(eb) | set(ea))
    for p in paths:
        b, a = eb.get(p), ea.get(p)
        if b is not None and a is not None:
            out, changed, why, trace = both_sides(b, a, ctx)
        elif a is not None:
            out, why, trace = one_sided(p, a, eb, added=True)
            changed = []
        else:
            out, why, trace = one_sided(p, b, ea, added=False)
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
        if out == 'unknown':
            rec['unknown'] = why
        # "For a path that is not `unchanged`, the interpreter that claims it
        # adds **findings** to its record" -- `findings` "absent when none".
        interp, what = interpreter_of(sb, p, b, a)
        traces[p].append('interp:%s%s' % (interp, ':' + what if what else ''))
        if interp != BINARY:
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
    if isinstance(v, bool):
        return b'true' if v else b'false'
    if isinstance(v, int):
        return str(v).encode('ascii')
    if isinstance(v, str):
        return canonical_string(v)
    if isinstance(v, dict):
        v = list(v.items())
    if v and all(isinstance(x, tuple) and len(x) == 2 and isinstance(x[0], str) for x in v):
        return b'{' + b','.join(canonical_string(k) + b':' + canonical(x) for k, x in v) + b'}'
    if isinstance(v, list):
        return b'[' + b','.join(canonical(x) for x in v) + b']'
    raise TypeError(repr(v))


if __name__ == '__main__':
    res = diff(sys.argv[1], sys.argv[2])
    if res is None:
        print('refused: the manifests have different scopes', file=sys.stderr)
        sys.exit(1)
    header, records, events, trailer, _ = res
    dump = lambda o: json.dumps(o, ensure_ascii=False, separators=(',', ':'))
    print(dump(dict(header)))
    for r in records:
        print(dump(encode_record(r)))
    for ev in events:
        print(canonical(ev).decode('utf-8'))
    print(dump(dict(trailer)))
