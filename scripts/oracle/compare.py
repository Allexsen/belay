#!/usr/bin/env python3
"""Runs the driver and the reference on every pair and compares everything.

    compare.py <driver> <corpus-dir>

pair-NNNNN.before/.after (same scope): the driver's diff and reference.diff()
must agree on
  - the header: every key, its value and their order (the prose example's);
  - every record: path and its spelling (path / path_b64), outcome, type,
    type_before, `changed` exactly (order included), `unknown` as a set, the
    records' order;
  - the trailer: every count, belay_diff_end, the key order.
  The order inside `unknown` is "the order of the reasons table", a
  GENERATED table this oracle may not read; instead every record of the run
  must respect one single order of the reasons (printed at the end).
  Every record of the driver is also checked against itself, whatever the
  reference says: `modified` needs a content field in `changed`,
  `metadata_only` a non-content one, `type_changed` is exactly ["type"],
  `unknown` appears only on an `unknown` outcome (rules 3 and 4).
  Disagreements are grouped by the rule that explains them; OTHER is what no
  rule of the reference's trace explains.
scope-NNNNN.before/.after (different scopes): the driver must fail and leave
no output file.

Then the COVERAGE GATE, computed from the manifests of the pairs, never from
the generator's labels:
  - every (compared field x entry type) cell of test/expect/diff-fields.md has
    a pair where only that field of one entry differs (for `type`: only the
    type and what the format forces with it); cells the frozen format cannot
    hold (manifest-v1 "all but T | no `f`") are listed, not required;
  - every two compared fields of one type differ together in some pair (the
    order of `changed`);
  - every optional field is present on one side only in some pair;
  - the named scenarios (dev relation, remounts, timestamps on fifo/sock/
    blk/chr and mount roots, iflags on one side, caps/xattrs under
    xattrs_unknown, O1 with and without a size change, ...) occur.
Exit 0 only when every pair agrees, every refusal holds, the reasons have one
order, and the gate passes.
"""
import base64, collections, concurrent.futures, glob, json, os, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reference as ref

SPECIAL = ('fifo', 'sock', 'blk', 'chr')
CELL_CLASSES = (ref.TYPE, ref.CONTENT, ref.METADATA, ref.IDENTITY, ref.DEVREL, ref.INO, ref.CTIME)


def same(x, y):
    """Equality that does not take True for 1."""
    if type(x) is not type(y):
        return False
    if isinstance(x, list):
        return len(x) == len(y) and all(same(a, b) for a, b in zip(x, y))
    return x == y


def is_utf8(b):
    try:
        b.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def rec_path(d):
    if 'path' in d:
        return d['path'].encode('utf-8'), 'path'
    return base64.b64decode(d['path_b64']), 'path_b64'


def show(d):
    d = dict(d)
    if isinstance(d.get('path'), bytes):
        d['path'] = repr(d['path'])
    return json.dumps(d, ensure_ascii=False)

# ---------------------------------------------------------------------------
# Comparing one pair.


G_DEV = 'dev: the device relation, not the number ("Devices and identity")'
G_INO_REMOUNT = 'ino: compared for no entry after a scope remount (O3)'
G_INO_DEV = 'ino: compared only within one device (O3)'
G_TS_SPECIAL = 'timestamps: not compared on fifo/sock/blk/chr'
G_TS_MOUNT = 'timestamps: not compared on mount roots'
G_O2 = 'caps/xattrs: none only if read (O2)'
G_IFLAGS = 'iflags on one side only -> unknown (iflags_unknown)'


def group_changed(f, trace, typ):
    """The rule that explains field f being listed by one side only, or None."""
    if f == 'dev':
        return G_DEV
    if f == 'ino':
        if 'remount' in trace:
            return G_INO_REMOUNT
        if any(t.startswith('O3-dev-differs') for t in trace):
            return G_INO_DEV
    if f in ('mtime_ns', 'ctime_ns'):
        if 'not-on-mount-root:' + f in trace:
            return G_TS_MOUNT
        if 'not-for-type:' + f in trace and typ in SPECIAL:
            return G_TS_SPECIAL
    if f in ('caps', 'xattrs') and any(t.startswith('O2-not-read') for t in trace):
        return G_O2
    if 'not-for-type:' + f in trace:
        return 'for types: %s not compared on %s' % (f, typ)
    return None


CONTENT_FIELDS = {f for f, s in ref.FIELDS.items() if s.cls == ref.CONTENT}


def contradicts_itself(g):
    """What in one record of the driver contradicts the prose whatever the
    inputs were (rule 3: proof gives `modified`; rule 4: `metadata_only` is a
    metadata or identity difference with content unchanged; `changed` is
    ["type"] when the types differ; `unknown` only on an `unknown` outcome;
    `changed` and `unknown` never on a path present on one side only)."""
    o, ch, un = g.get('outcome'), g.get('changed', []), g.get('unknown', [])
    if o not in ref.OUTCOMES or o == 'unchanged':
        return 'outcome %r' % o
    if o in ('added', 'removed') and ('changed' in g or 'unknown' in g):
        return '%s with changed/unknown' % o
    if o == 'type_changed' and ch != ['type']:
        return 'type_changed whose changed is %s' % ch
    if o == 'modified' and not set(ch) & CONTENT_FIELDS:
        return 'modified with no content field in changed'
    if o == 'metadata_only' and (not ch or set(ch) & (CONTENT_FIELDS | {'type'})):
        return 'metadata_only whose changed is %s' % ch
    if o == 'unknown' and not un:
        return 'unknown with no reason'
    if o != 'unknown' and 'unknown' in g:
        return '%s with reasons' % o
    return None


def compare_record(path, exp, got, trace, orders):
    """A list of rule groups for what differs; [] when the record agrees. A
    missing record is compared as the record of an unchanged path."""
    if got is None:
        got = [('path' if is_utf8(path) else 'path_b64', '?'), ('outcome', 'unchanged'),
               ('type', exp['type'])]
        missing = True
    else:
        missing = False
    g = dict(got)
    typ = (exp or {}).get('type') or g.get('type')
    if exp is None:
        exp = {'path': path, 'outcome': 'unchanged', 'type': g.get('type')}
    keys = [k for k, _ in got]
    groups = []
    want_spelling = 'path' if is_utf8(exp['path']) else 'path_b64'
    if not missing:
        bad = contradicts_itself(g)
        if bad:
            groups.append('OTHER: the record contradicts itself (%s)' % bad)
        if keys[:3] != [want_spelling, 'outcome', 'type'] or len(set(keys)) != len(keys):
            groups.append('OTHER: record keys %s' % keys)
        extra = set(keys) - {want_spelling, 'outcome', 'type', 'type_before', 'changed',
                             'unknown'}
        if extra:
            groups.append('OTHER: record has %s' % sorted(extra))
        for k in ('type', 'type_before'):
            if not same(exp.get(k), g.get(k)):
                groups.append('OTHER: %s' % k)
    # What differs; each item is blamed on the field-level rule that explains
    # it. What no field explains (an outcome, a reason, a ctime_ns listed only
    # under rule 5) is a consequence of the blamed fields when there are any
    # -- rule 5, for one, holds only when nothing else differs -- and is
    # OTHER when there are none: every new rule shows in a field or a reason.
    unexplained = []
    ce, cg = exp.get('changed', []), g.get('changed', [])
    if 'changed' in g and not cg:
        groups.append('OTHER: an empty `changed`')
    if not same(ce, cg):
        for f in [f for f in ce if f not in cg] + [f for f in cg if f not in ce]:
            grp = group_changed(f, trace, typ)
            (groups if grp else unexplained).append(grp or 'changed ' + f)
        if set(ce) == set(cg):
            groups.append('OTHER: order of `changed`')
    ue, ug = exp.get('unknown', []), g.get('unknown', [])
    if 'unknown' in g and not ug:
        groups.append('OTHER: an empty `unknown`')
    if len(set(ug)) != len(ug):
        groups.append('OTHER: a reason twice')
    if set(ue) != set(ug):
        for r in sorted(set(ue) ^ set(ug)):
            if r == 'iflags_unknown':
                groups.append(G_IFLAGS)
            else:
                unexplained.append('reason ' + r)
    elif ug:
        orders.append(ug)
    if exp['outcome'] != g.get('outcome'):
        unexplained.append('outcome %s, not %s' % (g.get('outcome'), exp['outcome']))
    if unexplained and not any(not x.startswith('OTHER') for x in groups):
        groups.append('OTHER: %s (reference: %s)' % ('; '.join(unexplained), ','.join(trace)))
    return sorted(set(groups))


def run_driver(driver, stem):
    """(exit status, stderr, the output file's bytes or None)."""
    out = stem + '.diff'
    if os.path.exists(out):
        os.unlink(out)
    r = subprocess.run([driver, stem + '.before', stem + '.after', out], capture_output=True)
    raw = open(out, 'rb').read() if os.path.exists(out) else None
    return r.returncode, r.stderr.decode('utf-8', 'replace').strip(), raw


def run_pair(ran, stem, orders):
    rc, err, raw = ran
    res = ref.diff(stem + '.before', stem + '.after')
    if res is None:
        return {'status': 'corpus-error', 'why': 'a same-scope pair with different scopes'}
    header, records, trailer, traces = res
    if rc != 0 or raw is None:
        return {'status': 'rejected', 'why': '%s (exit %d)' % (err, rc),
                'expected_trailer': trailer}
    lines = raw.split(b'\n')
    if lines[-1] != b'':
        return {'status': 'malformed', 'why': 'no final newline'}
    objs = [json.loads(l.decode('utf-8'), object_pairs_hook=list) for l in lines[:-1]]
    got_header, got_records, got_trailer = objs[0], objs[1:-1], objs[-1]
    result = {'status': 'ok', 'header': [], 'records': [], 'trailer': [],
              'expected_trailer': trailer}
    # header
    gk = [k for k, _ in got_header]
    ek = [k for k, _ in header]
    gh = dict(got_header)
    for k, v in header:
        if k not in gh:
            result['header'].append(('header: %s missing' % k, v, None))
        elif not same(v, gh[k]):
            result['header'].append(('header: %s' % k, v, gh[k]))
    for k in gk:
        if k not in dict(header):
            result['header'].append(('header: unexpected %s' % k, None, gh[k]))
    if [k for k in gk if k in ek] != [k for k in ek if k in gk] or len(set(gk)) != len(gk):
        result['header'].append(('header: key order', ek, gk))
    # records
    got_by, prev = {}, None
    for rec in got_records:
        p, _ = rec_path(dict(rec))
        if prev is not None and not prev < p:
            result['records'].append((['OTHER: records out of order or repeated'], p, None, rec))
        prev = p
        got_by[p] = rec
    exp_by = {r['path']: r for r in records}
    for p in sorted(set(exp_by) | set(got_by)):
        groups = compare_record(p, exp_by.get(p), got_by.get(p), traces.get(p, []), orders)
        if groups:
            result['records'].append((groups, p, exp_by.get(p), got_by.get(p)))
    # trailer
    gt = dict(got_trailer)
    if [k for k, _ in got_trailer] != [k for k, _ in trailer]:
        result['trailer'].append(('trailer keys', [k for k, _ in trailer],
                                  [k for k, _ in got_trailer]))
    for k, v in trailer:
        if not same(v, gt.get(k)):
            result['trailer'].append(('trailer: ' + k, v, gt.get(k)))
    if gt.get('belay_diff_end') != len(got_records):
        result['trailer'].append(('trailer: belay_diff_end is not the records emitted',
                                  len(got_records), gt.get('belay_diff_end')))
    return result

# ---------------------------------------------------------------------------
# Coverage, from the manifests.


def infeasible_cells():
    """(field, type) the frozen format cannot hold: a manifest-v1 rule
    'all but T | no `f`'."""
    text = open(ref.MANIFEST_PIN, encoding='utf-8').read()
    out = {}
    for r in ref.md_table(text, 'rule'):
        st, ap = r['statement'], r['applies to']
        if ap.startswith('all but ') and st.startswith('no `') and st.count('`') == 2:
            f = st.split('`')[1]
            keep = {t.strip() for t in ap[len('all but '):].split(',')}
            for t in ref.TYPES:
                if t not in keep:
                    out[(f, t)] = 'manifest-v1 rule %s: %s, %s' % (r['rule'], ap, st)
    return out


def required_cells():
    cells = []
    for f, s in ref.FIELDS.items():
        if s.cls in CELL_CLASSES:
            cells += [(f, t) for t in ref.TYPES if s.applies(t)]
    return cells


OPTIONAL = [f for f, s in ref.FIELDS.items() if s.absent != 'required']

SCENARIOS = (['dev relation: an entry leaves the root device',
              'dev relation: an entry joins the root device',
              'dev number changes, off the root device on both sides',
              'scope remount', 'scope remount: every entry renumbered',
              'scope remount: an entry changes device relation',
              'scope remount: content differs by hash']
             + ['only %s differs on a %s' % (f, t) for t in SPECIAL
                for f in ('mtime_ns', 'ctime_ns')]
             + ['only mtime_ns differs on a mount root', 'only ctime_ns differs on a mount root',
                'a mount root on one side only, its timestamps differ']
             + ['iflags on one side only on a ' + t for t in ref.TYPES]
             + ['caps against xattrs_unknown', 'xattrs against xattrs_unknown',
                'O1: hash on one side, unverified on the other, same size',
                'O1: hash on one side, unverified on the other, size differs',
                'hash limits differ', 'a path sorting before "."', 'a non-UTF-8 path',
                'a directory sealed on one side, with entries below it on the other',
                'a child on one side only below an unstable directory', 'a type change',
                'a raced entry on one side only',
                'a path sorting before "." on one side only, the other root sealed or unstable',
                'a path sorting before "." changes device relation',
                'a path sorting before "." in a remounted pair',
                'a one-sided path whose nearest ancestor on the other side is not a directory',
                'a one-sided path below a plain directory below an unstable one',
                'a non-UTF-8 link target that differs',
                'three or more compared fields differ on one entry'])


def only_field_cell(b, a, D):
    if 'type' in D:
        if (b['mode'] & 0o7777) != (a['mode'] & 0o7777):
            return None
        allowed = {'type', 'mode'} | {k for k in D if (k in b) != (k in a)}
        if 'lnk' in (b['type'], a['type']):
            allowed.add('size')
        return ('type', b['type']) if D <= allowed else None
    if len(D) != 1:
        return None
    f = next(iter(D))
    s = ref.FIELDS.get(f)
    if s is None or s.cls not in CELL_CLASSES:
        return None
    if s.absent in ('unknown', 'with unverified') and (f not in b or f not in a):
        return None
    return (f, b['type'])


PAIR_CLASSES = (ref.CONTENT, ref.METADATA, ref.IDENTITY, ref.DEVREL, ref.INO)


def required_field_pairs(infeasible):
    """(type, f1, f2): two compared fields of one entry differing together,
    which is what puts more than one name in `changed` and so tests its order."""
    out = []
    for t in ref.TYPES:
        fs = [f for f, s in ref.FIELDS.items() if s.cls in PAIR_CLASSES and s.applies(t)
              and (f, t) not in infeasible]
        out += [(t, f1, f2) for i, f1 in enumerate(fs) for f2 in fs[i + 1:]]
    return out


def two_field_pair(b, a, D):
    if len(D) != 2 or b['type'] != a['type']:
        return None
    for f in D:
        s = ref.FIELDS.get(f)
        if s is None or s.cls not in PAIR_CLASSES:
            return None
        if s.absent in ('unknown', 'with unverified') and (f not in b or f not in a):
            return None
    f1, f2 = sorted(D, key=ref.FIELD_ORDER.index)
    return (b['type'], f1, f2)


def pair_coverage(stem, cells, optional, scen, fpairs):
    hb, _, eb = ref.load(stem + '.before')
    ha, _, ea = ref.load(stem + '.after')
    rb, ra = eb[b'.']['dev'], ea[b'.']['dev']
    both, one = set(eb) & set(ea), set(eb) ^ set(ea)
    diffs = {}
    tags = set()
    for p in both:
        b, a = eb[p], ea[p]
        D = {k for k in set(b) | set(a) if not same(b.get(k), a.get(k))}
        if D:
            diffs[p] = D
        for f in OPTIONAL:
            if (f in b) != (f in a):
                optional[f] += 1
        if b['type'] != a['type']:
            tags.add('a type change')
            continue
        t = b['type']
        rel_b, rel_a = b['dev'] == rb, a['dev'] == ra
        if rel_b and not rel_a:
            tags.add('dev relation: an entry leaves the root device')
        if rel_a and not rel_b:
            tags.add('dev relation: an entry joins the root device')
        if rel_a != rel_b and p < b'.':
            tags.add('a path sorting before "." changes device relation')
        if rb != ra and p < b'.':
            tags.add('a path sorting before "." in a remounted pair')
        if t == 'lnk' and b['link_target'] != a['link_target'] and \
                not (is_utf8(b['link_target']) and is_utf8(a['link_target'])):
            tags.add('a non-UTF-8 link target that differs')
        if not rel_a and not rel_b and b['dev'] != a['dev'] and rb == ra:
            tags.add('dev number changes, off the root device on both sides')
        for f in ('mtime_ns', 'ctime_ns'):
            if D == {f} and t in SPECIAL:
                tags.add('only %s differs on a %s' % (f, t))
            if D == {f} and b.get('mount') and a.get('mount'):
                tags.add('only %s differs on a mount root' % f)
        if bool(b.get('mount')) != bool(a.get('mount')) and D & {'mtime_ns', 'ctime_ns'}:
            tags.add('a mount root on one side only, its timestamps differ')
        if ('iflags' in b) != ('iflags' in a):
            tags.add('iflags on one side only on a ' + t)
        for s1, s2 in ((b, a), (a, b)):
            if s1.get('xattrs_unknown') and not s2.get('xattrs_unknown'):
                if 'caps' in s2:
                    tags.add('caps against xattrs_unknown')
                if 'xattrs' in s2 or 'xattrs_sha256' in s2:
                    tags.add('xattrs against xattrs_unknown')
        if t == 'reg' and ('sha256' in b) != ('sha256' in a):
            tags.add('O1: hash on one side, unverified on the other, ' +
                     ('same size' if b['size'] == a['size'] else 'size differs'))
        if t == 'dir':
            for s1, s2, es2 in ((b, a, ea), (a, b, eb)):
                if (s1.get('unreadable') or s1.get('mount')) and \
                        not (s2.get('unreadable') or s2.get('mount')):
                    if any(q != p and (p == b'.' or q.startswith(p + b'/')) for q in es2):
                        tags.add('a directory sealed on one side, with entries below it '
                                 'on the other')
    if rb != ra:
        tags.add('scope remount')
        if all(eb[p]['dev'] != ea[p]['dev'] for p in both):
            tags.add('scope remount: every entry renumbered')
        if any((eb[p]['dev'] == rb) != (ea[p]['dev'] == ra) for p in both):
            tags.add('scope remount: an entry changes device relation')
        if any('sha256' in eb[p] and 'sha256' in ea[p] and eb[p]['sha256'] != ea[p]['sha256']
               for p in both):
            tags.add('scope remount: content differs by hash')
    if hb['hash_max_bytes'] != ha['hash_max_bytes']:
        tags.add('hash limits differ')
    for p in set(eb) | set(ea):
        if p < b'.':
            tags.add('a path sorting before "."')
        if not is_utf8(p):
            tags.add('a non-UTF-8 path')
    for p in one:
        present, lacking = (eb, ea) if p in eb else (ea, eb)
        anc = ref.nearest_ancestor(lacking, p)
        if present[p].get('raced'):
            tags.add('a raced entry on one side only')
        if anc.get('unstable'):
            tags.add('a child on one side only below an unstable directory')
        if p < b'.' and anc['path'] == b'.' and \
                (anc.get('unstable') or anc.get('unreadable')):
            tags.add('a path sorting before "." on one side only, the other root sealed or '
                     'unstable')
        if anc['type'] != 'dir':
            tags.add('a one-sided path whose nearest ancestor on the other side is not a '
                     'directory')
        if anc['type'] == 'dir' and not any(anc.get(k) for k in ('unstable', 'unreadable',
                                                                 'mount')):
            q = anc['path']
            while q != b'.':
                q = q.rsplit(b'/', 1)[0] if b'/' in q else b'.'
                if lacking.get(q, {}).get('unstable'):
                    tags.add('a one-sided path below a plain directory below an unstable one')
                    break
    for tg in tags:
        scen[tg] += 1
    if not one and len(diffs) == 1:
        (p, D), = diffs.items()
        c = only_field_cell(eb[p], ea[p], D)
        if c:
            cells[c] += 1
        fp = two_field_pair(eb[p], ea[p], D)
        if fp:
            fpairs[fp] += 1
    for p, D in diffs.items():
        n = [f for f in D if f in ref.FIELDS and ref.FIELDS[f].cls in PAIR_CLASSES]
        if len(n) >= 3:
            scen['three or more compared fields differ on one entry'] += 1

# ---------------------------------------------------------------------------


def main():
    driver, corpus = sys.argv[1], sys.argv[2]
    stems = sorted(p[:-len('.before')] for p in glob.glob(os.path.join(corpus, 'pair-*.before')))
    refusals = sorted(p[:-len('.before')] for p in
                      glob.glob(os.path.join(corpus, 'scope-*.before')))
    label = lambda s: open(s + '.label', encoding='utf-8').read().strip() \
        if os.path.exists(s + '.label') else '?'
    orders, by_group, header_issues = [], collections.defaultdict(list), collections.Counter()
    header_examples = {}
    full = header_only = differ = rejected = 0
    rejected_examples, trailer_only = [], []
    cells, optional, scen = collections.Counter(), collections.Counter(), collections.Counter()
    fpairs, outcomes = collections.Counter(), collections.Counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        ran = list(pool.map(lambda s: run_driver(driver, s), stems))
    for stem, r in zip(stems, ran):
        res = run_pair(r, stem, orders)
        pair_coverage(stem, cells, optional, scen, fpairs)
        name = os.path.basename(stem)
        for k, v in res.get('expected_trailer', [])[1:]:
            outcomes[k] += v
        if res['status'] != 'ok':
            rejected += 1
            if len(rejected_examples) < 5:
                rejected_examples.append((name, label(stem), res['status'], res['why']))
            continue
        for k, v, g in res['header']:
            header_issues[k] += 1
            header_examples.setdefault(k, (name, v, g))
        if res['records']:
            differ += 1
            for groups, p, e, g in res['records']:
                by_group[' + '.join(groups)].append((name, label(stem), p, e, g))
        elif res['trailer']:
            differ += 1
            trailer_only.append((name, label(stem), res['trailer'][:3]))
        elif res['header']:
            header_only += 1
        else:
            full += 1

    print('== %d pairs: %d agree fully; %d agree on every record and count but not the '
          'header; %d differ in records or counts; %d failed in the driver'
          % (len(stems), full, header_only, differ, rejected))
    print('   outcomes the reference expects over all pairs: %s' % dict(outcomes))
    if header_issues:
        print('== header disagreements (pairs):')
        for k, n in sorted(header_issues.items()):
            name, v, g = header_examples[k]
            print('   %-40s %5d   e.g. %s: expected %r, got %r' % (k, n, name, v, g))
    if by_group:
        print('== record disagreements, by rule (records / pairs):')
        for grp, items in sorted(by_group.items(), key=lambda kv: -len(kv[1])):
            print('   %-75s %5d / %d' % (grp, len(items), len({i[0] for i in items})))
            for name, lab, p, e, g in items[:2]:
                print('      %s [%s] %r' % (name, lab, p))
                print('         expected %s' % (show(ref.encode_record(e)) if e else '(no record)'))
                print('         got      %s' % (json.dumps(dict(g), ensure_ascii=False)
                                                if g else '(no record)'))
    for name, lab, issues in trailer_only[:5]:
        print('== trailer only: %s [%s] %s' % (name, lab, issues))
    for ex in rejected_examples:
        print('== driver failed: %s [%s] %s: %s' % ex)

    # One order of the reasons over the whole run.
    before = collections.defaultdict(set)
    for lst in orders:
        for i, x in enumerate(lst):
            for y in lst[i + 1:]:
                before[x].add(y)
    clash = sorted({(x, y) for x in before for y in before[x] if x in before.get(y, ())})
    reasons = sorted({r for lst in orders for r in lst})
    order, left = [], set(reasons)
    while left:
        head = sorted(r for r in left if not any(r in before[o] for o in left if o != r))
        if not head:
            break
        order.append(head[0])
        left.discard(head[0])
    print('== reasons in `unknown`: %s over %d records; the order observed: %s'
          % ('ONE order' if not clash else 'NO single order (%s)' % clash[:4], len(orders),
             order + sorted(left)))

    # Refusals.
    bad_refusals = []
    for stem in refusals:
        out = stem + '.diff'
        if os.path.exists(out):
            os.unlink(out)
        r = subprocess.run([driver, stem + '.before', stem + '.after', out], capture_output=True)
        ok_ref = ref.diff(stem + '.before', stem + '.after') is None
        if r.returncode == 0 or os.path.exists(out) or not ok_ref:
            bad_refusals.append((os.path.basename(stem), label(stem), r.returncode,
                                 os.path.exists(out), ok_ref))
    print('== scope refusal: %d/%d pairs of different scopes refused with no output file'
          % (len(refusals) - len(bad_refusals), len(refusals)))
    for b in bad_refusals:
        print('   NOT REFUSED: %s [%s] exit %d, output file left: %s, reference refuses: %s' % b)

    # The coverage gate.
    infeasible = infeasible_cells()
    need = [c for c in required_cells() if c not in infeasible]
    missing_cells = [c for c in need if not cells[c]]
    impossible_seen = [c for c in infeasible if cells[c]]
    missing_opt = [f for f in OPTIONAL if not optional[f]]
    missing_scen = [s for s in SCENARIOS if not scen[s]]
    need_pairs = required_field_pairs(infeasible)
    missing_pairs = [fp for fp in need_pairs if not fpairs[fp]]
    gate = not (missing_cells or missing_opt or missing_scen or impossible_seen or missing_pairs)
    print('== coverage gate: %s' % ('PASS' if gate else 'FAIL'))
    print('   cells (field x type, only that field differs): %d/%d covered, fewest pairs %d'
          % (len(need) - len(missing_cells), len(need), min(cells[c] for c in need)))
    print('   not required, the format cannot hold them: %s'
          % sorted('%s on %s (%s)' % (f, t, why.split(':')[0]) for (f, t), why in infeasible.items()
                   if (f, t) in required_cells()))
    if missing_cells:
        print('   MISSING cells: %s' % missing_cells)
    if impossible_seen:
        print('   cells the format cannot hold were seen: %s' % impossible_seen)
    print('   two compared fields of one entry differing together (the order of `changed`): '
          '%d/%d' % (len(need_pairs) - len(missing_pairs), len(need_pairs)))
    if missing_pairs:
        print('   MISSING field pairs: %s' % missing_pairs)
    print('   optional fields on one side only: %d/%d' % (len(OPTIONAL) - len(missing_opt),
                                                         len(OPTIONAL)))
    if missing_opt:
        print('   MISSING optional fields: %s' % missing_opt)
    print('   scenarios: %d/%d' % (len(SCENARIOS) - len(missing_scen), len(SCENARIOS)))
    if missing_scen:
        print('   MISSING scenarios: %s' % missing_scen)

    ok = gate and not (differ or rejected or header_only or bad_refusals or clash)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
