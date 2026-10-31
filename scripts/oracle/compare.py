#!/usr/bin/env python3
"""Runs the driver and the reference on every pair and compares everything.

    compare.py <driver> <corpus-dir>
    compare.py --gate <corpus-dir>     the coverage gate alone, no driver

pair-NNNNN.before/.after (same scope): the driver's diff and reference.diff()
must agree on
  - the header: every key, its value and their order (the "Shape" example's,
    which the reference checks at start-up);
  - every record: path and its spelling (path / path_b64), outcome, type,
    type_before, `changed` exactly (order included), `unknown` as a set, the
    records' order;
  - every record's `findings`, exactly: each finding's keys in order, values
    and JSON types, and the bytes `"findings":[...]` in the record's line;
  - the event records (E1: after the path records, before the trailer),
    byte for byte against the reference's rendering;
  - the trailer: every key, its value and their order (belay_diff_end, the
    outcome counts, dir_timestamps_only, events, each manifest's vanished,
    unstable and raced, provisional, the two sha256); and, whatever the
    reference says, the driver's trailer against the "### Trailer"
    paragraph: the outcome counts add up to the paths, dir_timestamps_only
    is among unchanged, provisional is exactly "one of the six is not 0",
    belay_diff_end is the records emitted, events the event records (E7).
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
the generator's labels (coverage(), required(), gate()):
  - every (compared field x entry type) cell of test/expect/diff-fields.md has
    a pair where only that field of one entry differs (for `type`: only the
    type and what the format forces with it); cells the frozen format cannot
    hold (manifest-v1 "all but T | no `f`") are listed, not required;
  - every two compared fields of one type differ together in some pair (the
    order of `changed`);
  - every optional field is present on one side only in some pair;
  - every named scenario (SCENARIOS) occurs: the device relation and
    remounts, timestamps on fifo/sock/blk/chr and on mount roots, a
    directory's own timestamps alone (pin O5) and beside another difference
    or a flag, iflags on one side, caps/xattrs under xattrs_unknown and
    beside a mount root, O1, one-sided paths below sealed, unstable and
    non-directory ancestors (raced or not, one and two levels down), raced
    type changes (raced on one side or both), a regular file that becomes
    or stops being a mount root, or is one on both sides, with `unverified`
    on the mount side and on the other or not (O8), a mounted regular file
    whose type changes while raced on either side or both (O8 across a type
    change), the trailer's walk counts, ...;
  - every interpreter item (INTERP_SCENARIOS): which interpreter claims a
    path, what its entries hold and the outcome, with no store -- text,
    binary, dpkg, pip and git paths, the pip and dpkg end hooks' inputs,
    events of two interpreters, and a diff with findings but no event.
gen_corpus.py builds every required item deterministically and checks each
targeted pair, and then the targeted pairs alone, with these same functions;
here the gate runs again over the whole corpus.
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
    if isinstance(x, (list, tuple)):
        return len(x) == len(y) and all(same(a, b) for a, b in zip(x, y))
    return x == y


_REF = {}


def ref_diff(stem):
    """reference.diff() of the pair at stem, computed once per process (the
    comparison and the coverage gate both read it)."""
    if stem not in _REF:
        _REF[stem] = ref.diff(stem + '.before', stem + '.after')
    return _REF[stem]


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
    return json.dumps(unpairs(d), ensure_ascii=False)


def unpairs(v):
    """A value parsed with object_pairs_hook=list, its objects as dicts (for
    messages)."""
    if isinstance(v, dict):
        return {k: unpairs(x) for k, x in v.items()}
    if isinstance(v, list) and v and all(isinstance(x, tuple) and len(x) == 2 for x in v):
        return {k: unpairs(x) for k, x in v}
    if isinstance(v, list):
        return [unpairs(x) for x in v]
    return v

# ---------------------------------------------------------------------------
# Comparing one pair.


G_DEV = 'dev: the device relation, not the number ("Devices and identity")'
G_INO_REMOUNT = 'ino: compared for no entry after a scope remount (O3)'
G_INO_DEV = 'ino: compared only within one device (O3)'
G_TS_SPECIAL = 'timestamps: not compared on fifo/sock/blk/chr'
G_TS_MOUNT = 'timestamps: not compared on mount roots'
G_O2 = 'caps/xattrs: none only if read (O2)'
G_IFLAGS = 'iflags on one side only -> unknown (iflags_unknown)'
G_IFLAGS_MOUNT = 'iflags: not compared on a mount root (pin column `on mount roots`)'
G_DIR_TS = "a directory's own timestamps: unchanged, counted in dir_timestamps_only (O5)"
G_RACED_ANC = 'one side only, below a raced non-directory: unknown, raced'
G_TYPE_BEFORE = 'type_before on every path whose types differ, raced or not'
G_DIGEST = 'xattrs: an inline set against a digest, by the formula (manifest-v1)'
G_O8 = 'unverified on a side that also carries mount: no reason; on the other side its own (O8)'


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
    if f == 'xattrs' and 'inline-vs-digest:xattrs' in trace:
        return G_DIGEST
    if 'not-for-type:' + f in trace:
        return 'for types: %s not compared on %s' % (f, typ)
    return None


CONTENT_FIELDS = {f for f, s in ref.FIELDS.items() if s.cls == ref.CONTENT}


def contradicts_itself(g):
    """What in one record of the driver contradicts the prose whatever the
    inputs were (rule 3: proof gives `modified`; rule 4: `metadata_only` is a
    metadata or identity difference with content unchanged; `changed` is
    ["type"] when the types differ; `unknown` only on an `unknown` outcome;
    `changed` and `unknown` never on a path present on one side only;
    `type_before` exactly where the types differ, "whatever the outcome --
    `type_changed`, or `unknown` when `raced` is on either side")."""
    o, ch, un = g.get('outcome'), g.get('changed', []), g.get('unknown', [])
    if o not in ref.OUTCOMES or o == 'unchanged':
        return 'outcome %r' % o
    if o in ('added', 'removed') and ('changed' in g or 'unknown' in g):
        return '%s with changed/unknown' % o
    if o == 'type_changed' and ch != ['type']:
        return 'type_changed whose changed is %s' % ch
    if o == 'type_changed' and 'type_before' not in g:
        return 'type_changed with no type_before'
    if 'type_before' in g and (o not in ('type_changed', 'unknown') or ch != ['type'] or
                               g['type_before'] == g.get('type')):
        return '%s with type_before %r, type %r and changed %s' % (o, g['type_before'],
                                                                   g.get('type'), ch)
    if o == 'modified' and not set(ch) & CONTENT_FIELDS:
        return 'modified with no content field in changed'
    if o == 'metadata_only' and (not ch or set(ch) & (CONTENT_FIELDS | {'type'})):
        return 'metadata_only whose changed is %s' % ch
    if o == 'unknown' and not un:
        return 'unknown with no reason'
    if o != 'unknown' and 'unknown' in g:
        return '%s with reasons' % o
    # "Interpreters": `findings` is "absent when none"; "for a path whose
    # outcome is `unknown` or `metadata_only` it adds nothing (a git hook's
    # executable bit excepted, which is metadata)".
    fs = g.get('findings')
    if fs is not None:
        if not isinstance(fs, list) or not fs:
            return 'an empty or malformed `findings`'
        kinds = [dict(f).get('kind') if isinstance(f, list) else None for f in fs]
        if o == 'unknown':
            return 'unknown with findings %s' % kinds
        if o == 'metadata_only' and set(kinds) - {'git_hook_executable_changed'}:
            return 'metadata_only with findings %s' % kinds
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
                             'unknown', 'findings'}
        if extra:
            groups.append('OTHER: record has %s' % sorted(extra))
        if not same(exp.get('type'), g.get('type')):
            groups.append('OTHER: type')
        if not same(exp.get('type_before'), g.get('type_before')):
            groups.append(G_TYPE_BEFORE if 'type' in trace else 'OTHER: type_before')
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
                groups.append(G_IFLAGS_MOUNT if 'not-on-mount-root:iflags' in trace else G_IFLAGS)
            elif r == 'unverified' and any(x.startswith('O8') for x in trace):
                groups.append(G_O8)
            else:
                unexplained.append('reason ' + r)
    elif ug:
        orders.append(ug)
    # Findings: exactly -- every finding, its keys in order, its values and
    # their JSON types (run_pair checks the bytes too).
    if not missing and not same(exp.get('findings'), g.get('findings')):
        it = [t for t in trace if t.startswith('interp:')]
        groups.append('FINDINGS (%s): %s' % (','.join(it) or 'no interpreter',
                                             ','.join(t for t in trace if t.startswith(
                                                 ('unavailable-', 'hook-', 'index-', 'reflog-',
                                                  'interp-'))) or '-'))
    if exp['outcome'] != g.get('outcome'):
        if 'raced-ancestor' in trace:
            groups.append(G_RACED_ANC)
        elif 'dir-timestamps-counted' in trace:
            groups.append(G_DIR_TS)
        else:
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
    res = ref_diff(stem)
    if res is None:
        return {'status': 'corpus-error', 'why': 'a same-scope pair with different scopes'}
    header, records, events, trailer, traces = res
    if rc != 0 or raw is None:
        return {'status': 'rejected', 'why': '%s (exit %d)' % (err, rc),
                'expected_trailer': trailer}
    lines = raw.split(b'\n')
    if lines[-1] != b'':
        return {'status': 'malformed', 'why': 'no final newline'}
    lines = lines[:-1]
    objs = [json.loads(l.decode('utf-8'), object_pairs_hook=list) for l in lines]
    got_header, body, got_trailer = objs[0], objs[1:-1], objs[-1]
    # E1: the path records, then the event records (a line whose first key is
    # `event`), then the trailer.
    first_event = next((i for i, o in enumerate(body) if o and o[0][0] == 'event'), len(body))
    got_records, got_events = body[:first_event], body[first_event:]
    raw_records, raw_events = lines[1:1 + first_event], lines[1 + first_event:-1]
    result = {'status': 'ok', 'header': [], 'records': [], 'trailer': [], 'events': [],
              'expected_trailer': trailer}
    if any(not o or o[0][0] != 'event' for o in got_events):
        result['events'].append(('E1: a path record after an event record', None, None))
    # Event records, byte for byte against the reference's rendering (E2-E4).
    want_events = [ref.canonical(ev) for ev in events]
    if raw_events != want_events:
        for i in range(max(len(want_events), len(raw_events))):
            w = want_events[i] if i < len(want_events) else None
            g = raw_events[i] if i < len(raw_events) else None
            if w != g:
                result['events'].append(('event record %d' % i, w, g))
    # A record's findings, byte for byte: `"findings":` and the reference's
    # rendering of the list, in the record's line.
    exp_findings = {r['path']: r['findings'] for r in records if 'findings' in r}
    for rec, line in zip(got_records, raw_records):
        p, _ = rec_path(dict(rec))
        if p in exp_findings and \
                b'"findings":' + ref.canonical(exp_findings[p]) not in line:
            result['events'].append(('the bytes of the findings of %r' % p,
                                     ref.canonical(exp_findings[p]), line))
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
    # The driver's trailer against the "### Trailer" paragraph itself, whatever
    # the reference computed.
    if gt.get('belay_diff_end') != len(got_records):
        result['trailer'].append(('trailer: belay_diff_end is not the records emitted',
                                  len(got_records), gt.get('belay_diff_end')))
    if gt.get(ref.EVENTS) != len(got_events):                   # E7
        result['trailer'].append(('trailer: events is not the event records emitted',
                                  len(got_events), gt.get(ref.EVENTS)))
    counted = [gt.get(o) for o in ref.OUTCOMES]
    npaths = len(traces) - 1                    # b'': the end hooks' tags
    if all(type(c) is int for c in counted) and sum(counted) != npaths:
        result['trailer'].append(('trailer: the outcome counts do not add up to the paths',
                                  npaths, sum(counted)))
    dto, unch = gt.get(ref.DIR_TIMESTAMPS_ONLY), gt.get('unchanged')
    if type(dto) is int and type(unch) is int and not 0 <= dto <= unch:
        result['trailer'].append(('trailer: dir_timestamps_only is not among unchanged',
                                  unch, dto))
    six = [gt.get(w + c) for w in ('before_', 'after_') for c in ref.INPUT_COUNTS]
    if all(type(c) is int for c in six) and gt.get('provisional') is not any(six):
        result['trailer'].append(('trailer: provisional is not "any of the six is not 0"',
                                  any(six), gt.get('provisional')))
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
TS = ('mtime_ns', 'ctime_ns')                   # "Timestamps that move on use"
DIR_TS = set(ref.DIR_TIMESTAMPS)                # a directory's own: the fields pin O5 names
ONE_SIDED_UNKNOWN = {f for f, s in ref.FIELDS.items() if s.absent == 'unknown'}
# Fields of a compared class that the pin compares on no directory (its size,
# its link count), and the metadata it always compares on one (mode, owner).
NOT_ON_DIR = {f for f, s in ref.FIELDS.items()
              if s.cls in CELL_CLASSES and not s.applies('dir')} - DIR_TS
ALWAYS_ON_DIR = {f for f, s in ref.FIELDS.items()
                 if s.cls == ref.METADATA and s.applies('dir') and s.absent == 'required'}
# The metadata the pin compares on every type, always present (mode, owner).
ALWAYS = {f for f, s in ref.FIELDS.items()
          if s.cls == ref.METADATA and s.types is None and s.absent == 'required'}
SPELLED = {'xattrs'} | set(ref.SPELLINGS['xattrs'])     # xattrs, xattrs_sha256


def flagged(e):
    return any(e.get(f) for f in ref.FLAGS)


def quiet(b, a):
    """Nothing on either side makes anything unknown: no flag of the pin, no
    field whose absence means unknown present on one side only."""
    return not flagged(b) and not flagged(a) and all((f in b) == (f in a)
                                                     for f in ONE_SIDED_UNKNOWN)


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
                'a type change, iflags on one side only',
                'a raced type change, iflags on one side only',
                'a path sorting before "." on one side only, the other root sealed or unstable',
                'a path sorting before "." changes device relation',
                'a path sorting before "." in a remounted pair',
                'a one-sided path whose nearest ancestor on the other side is not a directory',
                'a one-sided path below a plain directory below an unstable one',
                'a non-UTF-8 link target that differs',
                'three or more compared fields differ on one entry']
             # "A directory's own timestamps" (pin O5): no record, counted in
             # dir_timestamps_only -- unless something else differs or is unknown.
             + ['a directory whose only difference is its ' + w
                for w in ('mtime_ns', 'ctime_ns', 'mtime_ns and ctime_ns')]
             + ['the root, whose only differences are its own timestamps',
                'a directory whose timestamps and a field not compared on it differ',
                'a directory whose timestamps and a compared field differ',
                'a directory whose only difference is its timestamps, flagged alike on both sides',
                'a directory whose timestamps differ, iflags on one side only',
                'a directory whose timestamps differ, a flag on one side only']
             + ['only mtime_ns and ctime_ns differ on a %s' % t for t in SPECIAL]
             # "Present on one side only": the nearest recorded ancestor on the
             # side that lacks the path is not a directory.
             + ['a path missing below a %s non-directory, %s deep' % (r, n)
                for r in ('raced', 'non-raced') for n in ('one level', 'two levels')]
             + ['a path missing below a non-directory that carries unreadable or mount, '
                'not raced',
                # ... with names that sort between that ancestor and its
                # children (d!x, d.x between d and d/...), and a path whose
                # name extends the raced one's (d-x, d!x/y), not below it.
                'a path missing below a raced non-directory, with names sorting between it '
                'and its children',
                "a path missing beside or below a name that extends a raced non-directory's, "
                "not below it"]
             # A mount root's iflags, caps and xattrs are never read (rule 22).
             + ['a directory %s a mount root, %s on the other side' % (v, x)
                for v in ('becomes', 'stops being') for x in ('iflags', 'xattrs')]
             + ['a directory is a mount root on one side only, xattrs_unknown on the other',
                'a directory is a mount root on one side only, unstable or unreadable on the '
                'other',
                'a regular file is a mount root on one side only, caps on the other']
             # Pin O8: "`unverified` on a side that also carries `mount` adds no
             # reason ... `unverified` on the other side still gives its own".
             # The same size on both sides, so that no content field proves a
             # change and the reasons are listed.
             + ['a regular file %s a mount root, unverified %s, no other flag' % (v, w)
                for v in ('becomes', 'stops being')
                for w in ('only on the mount side', 'also on the other side (bare)')]
             + ['a regular file is a mount root on both sides, unverified on each, no other '
                'flag']
             # Rule 1 before rule 2, `raced` on one side only or on both; each
             # record keeps its `type_before` ("whatever the outcome").
             + ['a raced type change, raced %s only%s' % (s, i) for s in ('before', 'after')
                for i in ('', ', iflags on the raced side only', ', iflags on the other side only')]
             + ['a raced type change, raced on both sides']
             # O8 across a type change (O7: "its reasons are those of the flags
             # on either side"): a mounted regular file on one side, another
             # type on the other, `raced` on either side or both, no other flag.
             + ['a raced type change %s a mounted regular file, raced %s, no other flag' % (d, s)
                for d in ('from', 'to')
                for s in ('on the mount side only', 'on the other side only', 'on both sides')]
             # xattrs_sha256: "the sha256 of the bytes `xattrs` would hold between
             # its brackets", so an inline set and its digest compare equal.
             + ['xattrs: a set inline on one side and %s by digest on the other, nothing else '
                'differing' % k for k in ('the same set', 'a different set')]
             + ['xattrs: a set inline on one side and the same set by digest on the other, '
                'beside another difference',
                'xattrs: different sets by digest on both sides, nothing else differing']
             # "### Trailer", and "`before` is the first manifest given".
             + ['vanished on one side only, nothing flagged and no record',
                'every walk count differs between the two manifests',
                'provisional false: every walk count is 0',
                'the first manifest was created after the second'])


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
            if ('iflags' in b) != ('iflags' in a):
                tags.add('a raced type change, iflags on one side only'
                         if b.get('raced') or a.get('raced') else
                         'a type change, iflags on one side only')
            if bool(b.get('raced')) != bool(a.get('raced')):
                side, rc, oth = ('before', b, a) if b.get('raced') else ('after', a, b)
                tags.add('a raced type change, raced %s only' % side)
                if ('iflags' in rc) != ('iflags' in oth):
                    tags.add('a raced type change, raced %s only, iflags on the %s side only'
                             % (side, 'raced' if 'iflags' in rc else 'other'))
            elif b.get('raced'):
                tags.add('a raced type change, raced on both sides')
            # O8 across a type change: the mounted regular file's flags are
            # `mount` and `unverified` (manifest-v1 rules 5 and 21), plus
            # `raced` or not; the other side carries `raced` or nothing.
            for m, o, d in ((b, a, 'from'), (a, b, 'to')):
                if m['type'] != 'reg' or not m.get('mount'):
                    continue
                fm, fo = ({f for f in ref.FLAGS if e.get(f)} for e in (m, o))
                where = {(True, False): 'on the mount side only',
                         (False, True): 'on the other side only',
                         (True, True): 'on both sides'}.get(('raced' in fm, 'raced' in fo))
                if where and fm - {'raced'} == {'mount', 'unverified'} and fo <= {'raced'}:
                    tags.add('a raced type change %s a mounted regular file, raced %s, no other '
                             'flag' % (d, where))
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
        for f in TS:
            if D == {f} and t in SPECIAL and quiet(b, a):
                tags.add('only %s differs on a %s' % (f, t))
            if D == {f} and b.get('mount') and a.get('mount'):
                tags.add('only %s differs on a mount root' % f)
        if D == set(TS) and t in SPECIAL and quiet(b, a):
            tags.add('only mtime_ns and ctime_ns differ on a %s' % t)
        if bool(b.get('mount')) != bool(a.get('mount')) and D & {'mtime_ns', 'ctime_ns'}:
            tags.add('a mount root on one side only, its timestamps differ')
        dts = D & DIR_TS
        if t == 'dir' and dts:
            rest = D - dts
            if quiet(b, a):
                if not rest:
                    tags.add('a directory whose only difference is its ' +
                             ' and '.join(f for f in ref.DIR_TIMESTAMPS if f in dts))
                    if p == b'.':
                        tags.add('the root, whose only differences are its own timestamps')
                elif rest <= NOT_ON_DIR:
                    tags.add('a directory whose timestamps and a field not compared on it differ')
                if rest & ALWAYS_ON_DIR:
                    tags.add('a directory whose timestamps and a compared field differ')
            elif not rest and flagged(b):
                tags.add('a directory whose only difference is its timestamps, flagged alike on '
                         'both sides')
            if rest and rest <= ONE_SIDED_UNKNOWN and not flagged(b) and not flagged(a) and \
                    not quiet(b, a):
                tags.add('a directory whose timestamps differ, iflags on one side only')
            if rest & set(ref.FLAGS):
                tags.add('a directory whose timestamps differ, a flag on one side only')
        if bool(b.get('mount')) != bool(a.get('mount')):
            other, verb = (a, 'stops being') if b.get('mount') else (b, 'becomes')
            if t == 'dir' and 'iflags' in other:
                tags.add('a directory %s a mount root, iflags on the other side' % verb)
            if t == 'dir' and ('xattrs' in other or 'xattrs_sha256' in other):
                tags.add('a directory %s a mount root, xattrs on the other side' % verb)
            if t == 'dir' and other.get('xattrs_unknown'):
                tags.add('a directory is a mount root on one side only, xattrs_unknown on the other')
            if t == 'dir' and (other.get('unstable') or other.get('unreadable')):
                tags.add('a directory is a mount root on one side only, unstable or unreadable '
                         'on the other')
            if t == 'reg' and 'caps' in other:
                tags.add('a regular file is a mount root on one side only, caps on the other')
        # O8, with nothing else flagged on either side: a mounted regular file
        # always carries `unverified` (manifest-v1 rules 5 and 21).
        if t == 'reg' and b['size'] == a['size'] and (b.get('mount') or a.get('mount')):
            mu = {'mount', 'unverified'}
            fb, fa = ({f for f in ref.FLAGS if e.get(f)} for e in (b, a))
            if fb == fa == mu:
                tags.add('a regular file is a mount root on both sides, unverified on each, no '
                         'other flag')
            elif bool(b.get('mount')) != bool(a.get('mount')):
                fm, fo, verb = (fb, fa, 'stops being') if b.get('mount') else \
                    (fa, fb, 'becomes')
                if fm == mu and not fo:
                    tags.add('a regular file %s a mount root, unverified only on the mount side, '
                             'no other flag' % verb)
                if fm == mu and fo == {'unverified'}:
                    tags.add('a regular file %s a mount root, unverified also on the other side '
                             '(bare), no other flag' % verb)
        xb, xa = ref.value(b, 'xattrs'), ref.value(a, 'xattrs')
        if xb and xa and (xb[0] != xa[0] or xb[0] != 'xattrs'):
            alone = D <= SPELLED and quiet(b, a)
            same_set = ref.as_digest(xb) == ref.as_digest(xa)
            if xb[0] != xa[0] and alone:
                tags.add('xattrs: a set inline on one side and %s by digest on the other, '
                         'nothing else differing' % ('the same set' if same_set
                                                     else 'a different set'))
            if xb[0] != xa[0] and same_set and (D - SPELLED) & ALWAYS:
                tags.add('xattrs: a set inline on one side and the same set by digest on the '
                         'other, beside another difference')
            if xb[0] == xa[0] and not same_set and alone:
                tags.add('xattrs: different sets by digest on both sides, nothing else differing')
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
    # The trailer: each manifest's own walk counts.
    tb, ta = ref.trailer_of(stem + '.before')[0], ref.trailer_of(stem + '.after')[0]
    cb, ca = [tb[c] for c in ref.INPUT_COUNTS], [ta[c] for c in ref.INPUT_COUNTS]
    if not any(cb) and not any(ca):
        tags.add('provisional false: every walk count is 0')
    if all(x != y for x, y in zip(cb, ca)):
        tags.add('every walk count differs between the two manifests')
    if (tb['vanished'] == 0) != (ta['vanished'] == 0) and set(eb) == set(ea) and \
            all(eb[p] == ea[p] and not flagged(eb[p]) for p in eb):
        tags.add('vanished on one side only, nothing flagged and no record')
    if hb['created_ns'] > ha['created_ns']:
        tags.add('the first manifest was created after the second')
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
            # The path itself not raced, so that only its ancestor can decide.
            level = {1: 'one level', 2: 'two levels'}.get(p.count(b'/') -
                                                          anc['path'].count(b'/'))
            if level and not present[p].get('raced'):
                tags.add('a path missing below a %s non-directory, %s deep'
                         % ('raced' if anc.get('raced') else 'non-raced', level))
                if not anc.get('raced') and (anc.get('unreadable') or anc.get('mount')):
                    tags.add('a path missing below a non-directory that carries unreadable or '
                             'mount, not raced')
                if anc.get('raced') and any(anc['path'] < q < anc['path'] + b'/'
                                            for q in lacking):
                    tags.add('a path missing below a raced non-directory, with names sorting '
                             'between it and its children')
        if not present[p].get('raced') and not (anc['type'] != 'dir' and anc.get('raced')) \
                and any(r['type'] != 'dir' and r.get('raced') and q != b'.' and q != p and
                        p.startswith(q) and not p.startswith(q + b'/')
                        for q, r in lacking.items()):
            tags.add("a path missing beside or below a name that extends a raced "
                     "non-directory's, not below it")
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


# The interpreters in the oracle's setting, a diff given no store (diff-v1
# "Interpreters", "What each interpreter reports"; pins finding-kinds.md and
# diff-events.md). Each item names a situation of the INPUT -- which
# interpreter claims a path (reference.claim, from the scope and the path),
# what its entries hold (`stored`, type, mode) and the outcome the core
# decides -- never the findings expected, which compare_record() and
# run_pair() check. The pip and dpkg items are the kinds the end hook's
# input gives rise to (reference.pip_end's tags), for the same reason.
INTERP_SCENARIOS = (
    ['text: %s, stored on every side it exists on' % o
     for o in ('modified', 'added', 'removed', 'metadata_only', 'unknown')]
    + ['text: an unclaimed stored file below .git/, modified',
       'binary: a regular file stored on one of its two sides only, modified']
    + ['dpkg status: %s' % o for o in ('modified', 'added', 'removed', 'metadata_only',
                                       'type_changed, reg -> dir', 'type_changed, dir -> reg')]
    + ['dpkg status: added, a side with no stored copy',
       'dpkg status: removed, a side with no stored copy',
       'dpkg info: modified', 'dpkg info: added',
       'dpkg events: two status files with different sides',
       'dpkg events: two status files with the same side',
       'dpkg status: unknown, a regular file on both sides',
       'dpkg status: unknown, a regular file on one side only',
       'dpkg status: unknown, a side with no stored copy, a regular file on one side only',
       'dpkg events: two reasons in one diff']
    + ['pip events: ' + k for k in ('pip_installed', 'pip_removed', 'pip_upgraded',
                                    'pip_downgraded', 'pip_version_changed, equal by PEP 440',
                                    'pip_version_changed, not a PEP 440 version',
                                    'a pair whose names are spelled differently',
                                    'a dist-info that cannot be named (E10)',
                                    'a pair key with more than one RECORD added and removed '
                                    '(E10)',
                                    'content_unavailable first, then several names',
                                    'a dist-info that cannot be named beside a named install '
                                    '(E10)',
                                    'a pair key with more than one RECORD added and removed '
                                    'beside another name (E10)',
                                    'an unknown RECORD paired with one of the other side (E2)',
                                    'an unknown RECORD with none of the other side (E2)',
                                    'a pair key with more than one RECORD added and removed, '
                                    'one unknown (E10, E2)',
                                    'an event whose text would exceed 1,024 bytes (E9)')]
    + ['pip RECORD: modified', 'pip RECORD: unknown, a regular file on one side only',
       'pip RECORD: unknown, a regular file on both sides', 'pip METADATA: modified',
       'pip METADATA: added',
       'pip RECORD: added, a dist-info that cannot be named',
       'pip RECORD: removed, a dist-info that cannot be named',
       'pip RECORD: unknown, a regular file on one side only, a dist-info that cannot be named',
       "pip RECORD: added, a dist-info whose name or version is not a string field's value"]
    + ['git hook: added, executable', 'git hook: added, not executable', 'git hook: removed',
       'git hook: modified', 'git hook: metadata_only, the executable bit changed',
       'git hook: metadata_only, the executable bit unchanged',
       'git index: modified', 'git index: added', 'git index: removed']
    + ['git %s: %s' % (w, o) for w in ('HEAD', 'ref', 'reflog')
       for o in ('modified', 'added', 'removed')]
    + ['git packed-refs: modified', 'git HEAD: modified, a side with no stored copy',
       'git ref: added, a side with no stored copy',
       'git ref: added, not a regular file on either side (dir)',
       'git hook: added, a symlink', 'git hook: removed, a symlink',
       'git hook: modified, a symlink', 'git hook: metadata_only, a symlink',
       'git hook: added, a symlink, its target not UTF-8',
       'git hook: added, a symlink, its target over 1,024 bytes',
       'git hook: added, a symlink, its target of exactly 1,024 bytes',
       'git hook: added, not a regular file on either side (dir)',
       'git reflog: added, not a regular file on either side (dir)',
       'git reflog: added, not a regular file on either side (lnk)',
       'git hook: type_changed, reg -> lnk', 'git hook: type_changed, lnk -> reg',
       'git hook: type_changed, lnk -> dir',
       'text: a stored *.md5sums file outside var/lib/dpkg/info/, modified']
    + ['events: from pip and dpkg in one diff', 'events: none, though records carry findings'])
NEED_CONTENT = ('status', 'RECORD', 'HEAD', 'ref', 'packed-refs', 'reflog')


def interp_coverage(stem, tags):
    res = ref_diff(stem)
    if res is None:
        return
    _, eb = ref.load(stem + '.before')[1:]
    _, ea = ref.load(stem + '.after')[1:]
    _, records, events, _, traces = res
    status_sides = []
    for rec in records:
        p, o = rec['path'], rec['outcome']
        b, a = eb.get(p), ea.get(p)
        it = [t for t in traces[p] if t.startswith('interp:')][0].split(':')[1:]
        regs = [e for e in (b, a) if ref.is_reg(e)]
        if it == ['text']:
            tags.add('text: %s, stored on every side it exists on' % o)
            if b'.git/' in p:
                tags.add('text: an unclaimed stored file below .git/, %s' % o)
            if p.endswith(b'.md5sums') and b'var/lib/dpkg/info/' not in p:
                tags.add('text: a stored *.md5sums file outside var/lib/dpkg/info/, %s' % o)
        elif it == ['binary']:
            if b is not None and a is not None and b['type'] == a['type'] == 'reg' and \
                    ('stored' in b) != ('stored' in a):
                tags.add('binary: a regular file stored on one of its two sides only, %s' % o)
        else:
            interp, what = it
            tag = '%s %s: %s' % (interp, what, o)
            # A hook is a regular file or a symlink (diff-v1, git).
            hooks = [e for e in (b, a) if ref.is_hook(e)] if what == 'hook' else regs
            lnk = any(e is not None and e['type'] == 'lnk' for e in (b, a))
            if what == 'hook' and o in ('added', 'removed', 'modified', 'metadata_only') \
                    and lnk:
                tag += ', a symlink'
            elif what == 'hook' and o == 'added' and a['type'] == 'reg':
                tag += ', executable' if a['mode'] & 0o100 else ', not executable'
            elif what == 'hook' and o == 'metadata_only':
                tag += ', the executable bit %s' % ('changed' if (b['mode'] ^ a['mode']) & 0o100
                                                    else 'unchanged')
            if what in NEED_CONTENT and any('stored' not in e for e in regs):
                tag += ', a side with no stored copy'
            if o == 'type_changed':
                tag += ', %s -> %s' % (b['type'], a['type'])
            if o == 'unknown' and regs:
                tag += ', a regular file on %s' % ('both sides' if len(regs) == 2
                                                   else 'one side only')
            if not hooks:
                tag += ', not a regular file on either side (%s)' % '/'.join(
                    sorted({e['type'] for e in (b, a) if e is not None}))
            if 'pip-unnamed' in traces[p]:
                tag += ', a dist-info that cannot be named'
                stem = p[:-len(b'/RECORD')].rsplit(b'/', 1)[-1][:-len(b'.dist-info')]
                n, _, v = stem.partition(b'-')
                if n and v:
                    tags.add("%s %s: %s, a dist-info whose name or version is not a string "
                             "field's value" % (interp, what, o))
            tags.add(tag)
            if what == 'hook' and lnk:
                for x in [e['link_target'] for e in (b, a) if e is not None and
                          e['type'] == 'lnk']:
                    tags.add(tag + (', its target not UTF-8' if not is_utf8(x) else
                                    ', its target over 1,024 bytes' if len(x) > 1024 else
                                    ', its target of exactly 1,024 bytes' if len(x) == 1024
                                    else ''))
            if what == 'status' and o in ('added', 'removed', 'modified') and \
                    all('stored' in e for e in regs):
                status_sides.append(frozenset('before' if e is b else 'after' for e in regs))
    reasons = {t.split('-', 2)[2] for rec in records
               if 'interp:dpkg:status' in traces[rec['path']]
               for t in traces[rec['path']] if t.startswith('unavailable-')}
    if len(reasons) >= 2:
        tags.add('dpkg events: two reasons in one diff')
    if len(status_sides) >= 2:
        tags.add('dpkg events: two status files with %s'
                 % ('the same side' if len(set(status_sides)) == 1 else 'different sides'))
    pip_tags = {'pip_installed': 'pip_installed', 'pip_removed': 'pip_removed',
                'pip_upgraded': 'pip_upgraded', 'pip_downgraded': 'pip_downgraded',
                'pip_version_changed:equal': 'pip_version_changed, equal by PEP 440',
                'pip_version_changed:not-pep440': 'pip_version_changed, not a PEP 440 version',
                'pip-pair-spelled-differently': 'a pair whose names are spelled differently',
                'pip-unnamed-event': 'a dist-info that cannot be named (E10)',
                'pip-ambiguous-key': 'a pair key with more than one RECORD added and removed '
                                     '(E10)',
                'pip-provisional-pair': 'an unknown RECORD paired with one of the other side '
                                        '(E2)',
                'pip-provisional-single': 'an unknown RECORD with none of the other side (E2)',
                'pip-ambiguous-key-provisional': 'a pair key with more than one RECORD added '
                                                 'and removed, one unknown (E10, E2)',
                'pip-invalid-event': 'an event whose text would exceed 1,024 bytes (E9)'}
    end = traces[b'']
    for t in end:
        if t in pip_tags:
            tags.add('pip events: ' + pip_tags[t])
    # The tags a named pair key gives rise to: another name's event.
    named = {'pip_installed', 'pip_removed', 'pip_upgraded', 'pip_downgraded',
             'pip_version_changed:equal', 'pip_version_changed:not-pep440'}
    if 'pip-unnamed-event' in end and 'pip_installed' in end:
        tags.add('pip events: a dist-info that cannot be named beside a named install (E10)')
    if 'pip-ambiguous-key' in end and named & set(end):
        tags.add('pip events: a pair key with more than one RECORD added and removed beside '
                 'another name (E10)')
    pip_ev = [dict(e) for e in events if dict(e)['interp'] == 'pip']
    if pip_ev and pip_ev[0]['event'] == 'content_unavailable' and \
            len({e.get('name') for e in pip_ev[1:]} - {None}) >= 2:
        tags.add('pip events: content_unavailable first, then several names')
    if {'pip', 'dpkg'} <= {dict(e)['interp'] for e in events}:
        tags.add('events: from pip and dpkg in one diff')
    if not events and any('findings' in r for r in records):
        tags.add('events: none, though records carry findings')


KINDS = ('cell', 'field pair', 'optional', 'scenario', 'interpreter')


def coverage(stems):
    """What the pairs at these stems show, from their manifests alone (and,
    for the interpreters, the outcome the reference decides from them):
    {kind: Counter of items}. gen_corpus.py checks every targeted pair with
    this, and the targeted pairs together with gate()."""
    cov = {k: collections.Counter() for k in KINDS}
    for stem in stems:
        pair_coverage(stem, cov['cell'], cov['optional'], cov['scenario'], cov['field pair'])
        tags = set()
        interp_coverage(stem, tags)
        for t in tags:
            cov['interpreter'][t] += 1
    return cov


def required():
    """What the gate requires, [(kind, item)], and the (field, type) cells the
    frozen format cannot hold."""
    infeasible = infeasible_cells()
    need = ([('cell', c) for c in required_cells() if c not in infeasible]
            + [('field pair', fp) for fp in required_field_pairs(infeasible)]
            + [('optional', f) for f in OPTIONAL]
            + [('scenario', s) for s in SCENARIOS]
            + [('interpreter', s) for s in INTERP_SCENARIOS])
    return need, infeasible


def gate(cov):
    """(the required items cov lacks, the cells cov shows that the format
    cannot hold); the gate passes when both are empty."""
    need, infeasible = required()
    return ([n for n in need if not cov[n[0]][n[1]]],
            [c for c in infeasible if cov['cell'][c]])


def print_gate(cov):
    missing, impossible_seen = gate(cov)
    need, infeasible = required()
    print('== coverage gate: %s' % ('FAIL' if missing or impossible_seen else 'PASS'))
    for kind, title in (('cell', 'cells (field x type, only that field differs)'),
                        ('field pair', 'two compared fields of one entry differing together '
                                       '(the order of `changed`)'),
                        ('optional', 'optional fields on one side only'),
                        ('scenario', 'scenarios'),
                        ('interpreter', 'interpreters, with no store')):
        items = [i for k, i in need if k == kind]
        lack = [i for k, i in missing if k == kind]
        print('   %s: %d/%d, fewest pairs %d' % (title, len(items) - len(lack), len(items),
                                                min(cov[kind][i] for i in items)))
        if lack:
            print('   MISSING %s: %s' % (kind, lack))
    print('   not required, the format cannot hold them: %s'
          % sorted('%s on %s (%s)' % (f, t, why.split(':')[0]) for (f, t), why in infeasible.items()
                   if (f, t) in required_cells()))
    if impossible_seen:
        print('   cells the format cannot hold were seen: %s' % impossible_seen)
    return not (missing or impossible_seen)


def stems_of(corpus, kind='pair'):
    return sorted(p[:-len('.before')] for p in glob.glob(os.path.join(corpus, kind + '-*.before')))

# ---------------------------------------------------------------------------


def main():
    if sys.argv[1] == '--gate':                 # the coverage gate alone, no driver
        sys.exit(0 if print_gate(coverage(stems_of(sys.argv[2]))) else 1)
    driver, corpus = sys.argv[1], sys.argv[2]
    stems = stems_of(corpus)
    refusals = stems_of(corpus, 'scope')
    label = lambda s: open(s + '.label', encoding='utf-8').read().strip() \
        if os.path.exists(s + '.label') else '?'
    orders, by_group, header_issues = [], collections.defaultdict(list), collections.Counter()
    header_examples = {}
    full = header_only = differ = rejected = 0
    rejected_examples, trailer_only, event_issues = [], [], []
    outcomes = collections.Counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        ran = list(pool.map(lambda s: run_driver(driver, s), stems))
    for stem, r in zip(stems, ran):
        res = run_pair(r, stem, orders)
        name = os.path.basename(stem)
        for k, v in res.get('expected_trailer', [])[1:]:
            if k in ref.OUTCOMES or k == ref.DIR_TIMESTAMPS_ONLY:
                outcomes[k] += v
        if res['status'] != 'ok':
            rejected += 1
            if len(rejected_examples) < 5:
                rejected_examples.append((name, label(stem), res['status'], res['why']))
            continue
        for k, v, g in res['header']:
            header_issues[k] += 1
            header_examples.setdefault(k, (name, v, g))
        if res['events']:
            event_issues.append((name, label(stem), res['events']))
        if res['records']:
            differ += 1
            for groups, p, e, g in res['records']:
                by_group[' + '.join(groups)].append((name, label(stem), p, e, g))
        elif res['events']:
            differ += 1
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
                print('         got      %s' % (json.dumps(unpairs(g), ensure_ascii=False)
                                                if g else '(no record)'))
    if event_issues:
        print('== event records or the bytes of findings disagree in %d pairs:'
              % len(event_issues))
        for name, lab, issues in event_issues[:6]:
            print('   %s [%s]' % (name, lab))
            for what, w, g in issues[:4]:
                print('      %s\n         expected %s\n         got      %s' % (what, w, g))
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

    # The coverage gate, over every pair (gen_corpus.py has already checked it
    # over its targeted pairs alone).
    gate_ok = print_gate(coverage(stems))

    ok = gate_ok and not (differ or rejected or header_only or bad_refusals or clash)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
