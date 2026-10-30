#!/usr/bin/env python3
"""A naive reference comparator for diff.v1, written from the prose and the pins.

Its only sources:
  - docs/spec/diff-v1.md, PROSE ONLY: the "Shape" example (header, record and
    trailer keys), "How an outcome is decided" (one-sided paths, rules 1-6),
    "Devices and identity", "Timestamps that move on use", the `changed` /
    `unknown` paragraph and "An absent record means `unchanged`";
  - test/expect/diff-fields.md, READ AT RUN TIME: for each field its
    `compared as`, `for types`, `on mount roots` and `absent means`, and the
    outcome rules O1-O4;
  - test/expect/manifest-v1.md, read at run time for the entry types.
Never the generated blocks of the spec, never src/.

Deliberately naive: both manifests in memory as dictionaries, the union of
their paths sorted, ancestors found by walking a path's prefixes.

    reference.py <before> <after>   prints the expected diff, one JSON line each

Two things the prose leaves to generated tables are NOT predicted here and are
checked differently by compare.py: the order of the reasons in `unknown`
("in the order of the reasons table", a generated table) is compared as a set
plus one global order that every record must respect.
"""
import base64, collections, hashlib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
FIELDS_PIN = os.path.join(REPO, 'test', 'expect', 'diff-fields.md')
MANIFEST_PIN = os.path.join(REPO, 'test', 'expect', 'manifest-v1.md')

# From the prose example under "Shape" (diff-v1.md): the header's and the
# trailer's keys, in the example's order.
HEADER_KEYS = ['belay_diff', 'scopes', 'before_created_ns', 'after_created_ns',
               'before_hash_max_bytes', 'after_hash_max_bytes', 'scope_remounted',
               'identity_compared']
OUTCOMES = ['unchanged', 'added', 'removed', 'modified', 'type_changed', 'metadata_only',
            'unknown']
# After the outcome counts, from "Shape" and the trailer's prose: each
# manifest's own trailer counts, whether any is non-zero, and the sha256 of
# each input file (the bytes a diff reads are the whole file).
INPUT_COUNTS = ['vanished', 'unstable', 'raced']
TRAILER_KEYS = (['belay_diff_end'] + OUTCOMES + ['before_' + c for c in INPUT_COUNTS]
                + ['after_' + c for c in INPUT_COUNTS] + ['provisional', 'before_sha256',
                                                          'after_sha256'])
# One-sided reasons, from "Present on one side only".
NOT_CAPTURED, LISTING_INCOMPLETE, RACED = 'not_captured', 'listing_incomplete', 'raced'

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
    for r in ('O1', 'O2', 'O3', 'O4'):
        if r not in rules:
            raise SystemExit('pin: outcome rule %s missing' % r)
    return fields, rules


FIELDS, RULES = load_fields()
FIELD_ORDER = list(FIELDS)          # `changed` lists fields in this order (the
                                    # manifest's key order; the prose example's
                                    # ["size","mtime_ns","sha256"] follows it)
FLAGS = [f for f, s in FIELDS.items() if s.cls == FLAG]
SPELLINGS = collections.defaultdict(list)   # field -> its other spellings
for _f, _s in FIELDS.items():
    if _s.spelling_of:
        SPELLINGS[_s.spelling_of].append(_f)

# ---------------------------------------------------------------------------
# Manifests.


def b64(s):
    return base64.b64decode(s.encode('ascii'), validate=True)


def trailer_of(path):
    """The manifest's own trailer, and the sha256 of the file."""
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
    anc = nearest_ancestor(lacking_entries, p)
    trace = ['one-sided']
    if anc['type'] == 'dir' and (anc.get('unreadable') or anc.get('mount')):
        return 'unknown', [NOT_CAPTURED], trace + ['not_captured']
    if anc['type'] == 'dir' and anc.get('unstable'):
        return 'unknown', [LISTING_INCOMPLETE], trace + ['listing_incomplete']
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


def xattrs_digest_guess(items):
    """GUESS, never deciding a generated pair: include/belay/manifest.h says the
    digest is of "the canonical set", whose inline form is "the body of the
    manifest's xattrs array". The corpus never pairs an inline set with the
    digest of the same set, so this only matters for hand-made inputs."""
    body = ','.join(json.dumps(x, ensure_ascii=False, separators=(',', ':')) for x in items)
    return hashlib.sha256(body.encode('utf-8')).hexdigest()


def values_differ(f, vb, va):
    if f in SPELLINGS and vb is not None and va is not None and vb[0] != va[0]:
        inline, digest = (vb, va) if vb[0] == f else (va, vb)
        return xattrs_digest_guess(inline[1]) != digest[1]
    return vb != va


def both_sides(b, a, ctx):
    """(outcome, changed, unknown reasons, trace)."""
    trace = []
    flags = [f for f in FLAGS if b.get(f) or a.get(f)]
    scopes = {FIELDS[f].scope for f in flags}
    mount_root = bool(b.get('mount') or a.get('mount'))       # either side: see ambiguity A2
    if mount_root:
        trace.append('mount-root')
    # caps/xattrs "were read on both sides": no metadata-unknown flag on
    # either side and neither side a mount root (O2; prose `changed` paragraph).
    read_both = not mount_root and 'metadata' not in scopes

    # Fields whose absence means "could not be read" (`absent means: unknown`),
    # present on one side only: unknown under rule 4 (`iflags_unknown`).
    def one_sided_unknown(types):
        out = []
        for f, s in FIELDS.items():
            if s.absent == 'unknown' and all(s.applies(t) for t in types) and \
                    (f in b) != (f in a):
                out.append(f)
        return out

    if b['type'] != a['type']:                                   # rule 2 (after rule 1)
        trace.append('type')
        if 'everything' in scopes:                               # rule 1
            # "...and, when the types are the same, of every field unknown
            # under rule 4": across a type change no field is compared
            return 'unknown', ['type'], flags, trace + ['rule1']
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
        if d:
            changed.append(f)
            if s.cls == CONTENT:
                proof = True
            else:
                meta = True
    unk_scopes = {FIELDS[f].cls for f in unk_fields}
    reasons = flags + [f + '_unknown' for f in unk_fields]
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


def diff(before, after):
    """None when the scopes differ (refused). Otherwise (header, records,
    trailer, traces): header and trailer as [(key, value)], records as dicts
    with `path` as bytes, traces {path: [tags]} for messages."""
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
    records, counts, traces = [], collections.Counter(), {}
    for p in sorted(set(eb) | set(ea)):
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
        traces[p] = trace + (['remount'] if remounted else [])
        if out == 'unchanged':
            continue
        e = a if a is not None else b
        rec = {'path': p, 'outcome': out, 'type': e['type']}
        if out == 'type_changed':
            rec['type_before'] = b['type']          # ambiguity A7: the record table is generated
        if changed:
            rec['changed'] = changed
        if out == 'unknown':
            rec['unknown'] = why
        records.append(rec)
    trailer = [('belay_diff_end', len(records))] + [(o, counts[o]) for o in OUTCOMES]
    (tb, shab), (ta, shaa) = trailer_of(before), trailer_of(after)
    inputs = [('before_' + c, tb[c]) for c in INPUT_COUNTS] + [('after_' + c, ta[c]) for c in INPUT_COUNTS]
    trailer += inputs + [('provisional', any(v != 0 for _, v in inputs)),
                         ('before_sha256', shab), ('after_sha256', shaa)]
    return header, records, trailer, traces


def encode_record(rec):
    r = dict(rec)
    p = r.pop('path')
    try:
        head = {'path': p.decode('utf-8')}
    except UnicodeDecodeError:
        head = {'path_b64': base64.b64encode(p).decode('ascii')}
    head.update(r)
    return head


if __name__ == '__main__':
    res = diff(sys.argv[1], sys.argv[2])
    if res is None:
        print('refused: the manifests have different scopes', file=sys.stderr)
        sys.exit(1)
    header, records, trailer, _ = res
    dump = lambda o: json.dumps(o, ensure_ascii=False, separators=(',', ':'))
    print(dump(dict(header)))
    for r in records:
        print(dump(encode_record(r)))
    print(dump(dict(trailer)))
