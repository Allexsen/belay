#!/usr/bin/env python3
"""A naive reference comparator for diff.v1: both manifests in memory, in
dictionaries; ancestors found by walking a path's prefixes up to the root.
It follows docs/spec/diff-v1.md ("How an outcome is decided") as written,
and reads the field classes from that spec's generated table -- never from
the C code. Slow and obvious on purpose: it is the oracle for the streaming
implementation.

    reference.py <before> <after>   prints the expected records, then counts
"""
import base64, hashlib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, '..', '..', 'docs', 'spec', 'diff-v1.md')
OUTCOMES = ['unchanged', 'added', 'removed', 'modified', 'type_changed', 'metadata_only', 'unknown']


def field_table():
    """field -> (class, types or None for all, unknown scope) from the spec."""
    text = open(SPEC).read()
    block = text[text.index('<!-- BEGIN GENERATED: diff-fields -->'):text.index('<!-- END GENERATED: diff-fields -->')]
    rows, order = {}, []
    for line in block.splitlines():
        m = re.match(r'\| `([a-z0-9_]+)` \| ([a-z ]+) \| ([^|]*) \| ([a-z]*) \|', line)
        if not m:
            continue
        name, cls, types, scope = m.group(1), m.group(2), m.group(3).strip(), m.group(4)
        tset = None if types in ('', 'all') else set(t.strip() for t in types.split(','))
        rows[name] = (cls, tset, scope)
        order.append(name)
    return rows, order


def reasons_order():
    text = open(SPEC).read()
    block = text[text.index('<!-- BEGIN GENERATED: diff-reasons -->'):text.index('<!-- END GENERATED: diff-reasons -->')]
    return re.findall(r'^\| `([a-z_]+)` \|', block, re.M)


FIELDS, FIELD_ORDER = field_table()
REASONS = reasons_order()


def load(path):
    """(header, {path bytes: entry}, {path bytes: raw line})"""
    entries, raw = {}, {}
    header = None
    with open(path, encoding='utf-8') as f:
        for line in f:
            d = json.loads(line)
            if 'belay_manifest' in d:
                header = d
                continue
            if 'belay_manifest_end' in d:
                continue
            p = d['path'].encode() if 'path' in d else base64.b64decode(d['path_b64'])
            entries[p] = d
            raw[p] = line
    return header, entries, raw


def anc_kind(e):
    if e is None or e['type'] != 'dir':
        return 'none'
    if e.get('unreadable') or e.get('mount'):
        return 'sealed'
    if e.get('unstable'):
        return 'incomplete'
    return 'none'


def nearest_ancestor(entries, p):
    for i in range(len(p) - 1, 0, -1):
        if p[i:i + 1] == b'/' and p[:i] in entries:
            return anc_kind(entries[p[:i]])
    return anc_kind(entries.get(b'.'))


def xattrs_digest(e, raw):
    if 'xattrs' in e:
        start = raw.index('"xattrs":[') + len('"xattrs":[')
        end = raw.index('"]', start) + 1
        return hashlib.sha256(raw[start:end].encode()).hexdigest()
    return e.get('xattrs_sha256')


def link_target(e):
    if 'link_target' in e:
        return e['link_target'].encode()
    if 'link_target_b64' in e:
        return base64.b64decode(e['link_target_b64'])
    return None


def differs(f, b, a, rb, ra):
    """True, False, or None (not compared)."""
    xu = b.get('xattrs_unknown') or a.get('xattrs_unknown')
    if f == 'iflags':
        return b['iflags'] != a['iflags'] if 'iflags' in b and 'iflags' in a else None
    if f == 'caps':
        return None if xu else b.get('caps') != a.get('caps')
    if f == 'xattrs':
        return None if xu else xattrs_digest(b, rb) != xattrs_digest(a, ra)
    if f == 'sha256':
        return b['sha256'] != a['sha256'] if 'sha256' in b and 'sha256' in a else None
    if f == 'rdev':
        return b['rdev'] != a['rdev'] if 'rdev' in b and 'rdev' in a else None
    if f == 'link_target':
        if b.get('unreadable') or a.get('unreadable'):
            return None
        tb, ta = link_target(b), link_target(a)
        return None if tb is None or ta is None else tb != ta
    return b[f] != a[f]


def classify_both(b, a, rb, ra):
    reasons, scopes = set(), set()
    for f, (cls, _, scope) in FIELDS.items():
        if cls == 'flag' and (b.get(f) or a.get(f)):
            reasons.add(f)
            scopes.add(scope)
    if b['type'] != a['type']:
        out = 'unknown' if 'everything' in scopes else 'type_changed'
        return out, ['type'], sorted(reasons, key=REASONS.index) if out == 'unknown' else []
    t = a['type']
    changed, content_diff, meta_diff = [], False, False
    for f in FIELD_ORDER:
        cls, types, _ = FIELDS[f]
        if types is not None and t not in types:
            continue
        if cls not in ('content', 'metadata', 'identity'):
            continue
        if differs(f, b, a, rb, ra):
            changed.append(f)
            if cls == 'content':
                content_diff = True
            else:
                meta_diff = True
    if 'everything' in scopes:
        out = 'unknown'
    elif content_diff:
        out = 'modified'
    elif 'content' in scopes:
        out = 'unknown'
    elif meta_diff:
        out = 'metadata_only'
    elif 'metadata' in scopes:
        out = 'unknown'
    elif b['ctime_ns'] != a['ctime_ns']:
        out = 'metadata_only'
        changed.append('ctime_ns')
    else:
        out = 'unchanged'
    changed.sort(key=FIELD_ORDER.index)
    return out, changed, sorted(reasons, key=REASONS.index) if out == 'unknown' else []


def compare(before, after):
    hb, eb, rb = load(before)
    ha, ea, ra = load(after)
    if hb.get('scopes') != ha.get('scopes') or hb.get('scopes_b64') != ha.get('scopes_b64'):
        return None, None
    records, counts = [], {o: 0 for o in OUTCOMES}
    for p in sorted(set(eb) | set(ea)):
        b, a = eb.get(p), ea.get(p)
        if b is not None and a is not None:
            out, changed, why = classify_both(b, a, rb[p], ra[p])
        else:
            present = a if a is not None else b
            kind = nearest_ancestor(eb if b is None else ea, p)
            changed = []
            if kind == 'sealed':
                why = ['not_captured']
            elif kind == 'incomplete':
                why = ['listing_incomplete']
            elif present.get('raced'):
                why = ['raced']
            else:
                why = []
            out = 'unknown' if why else ('added' if a is not None else 'removed')
        counts[out] += 1
        if out != 'unchanged':
            e = a if a is not None else b
            rec = {'path': p, 'outcome': out, 'type': e['type']}
            if out == 'type_changed':
                rec['type_before'] = b['type']
            if changed:
                rec['changed'] = changed
            if out == 'unknown' and why:
                rec['unknown'] = why
            records.append(rec)
    return records, counts


if __name__ == '__main__':
    recs, counts = compare(sys.argv[1], sys.argv[2])
    for r in recs or []:
        print(r)
    print(counts)
