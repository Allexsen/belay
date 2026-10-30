#!/usr/bin/env python3
"""Generates valid manifest pairs for the diff oracle.

    gen_corpus.py <out-dir> <n-bases> <seed>

Writes, and prints the number of, pairs:
  pair-NNNNN.before / .after   two manifests of one scope, for compare.py;
  pair-NNNNN.label             what the pair was built to exercise -- for
                               messages only: compare.py computes coverage
                               from the manifests themselves;
  scope-NNNNN.before / .after  two manifests of different scopes, which the
                               diff must refuse.

Every manifest follows test/expect/manifest-v1.md, the frozen v1 format: the
key order, spellings and kinds come from its Keys table at run time; its 22 + 2
"combinations a v1 writer produces" are implemented in violations() below and
tied to the pin's text at start-up (a changed pin stops the generator); plus
the prose's structural rules (the root `.` -- a directory, never a mount, the
only entry when unreadable --, nothing below an unreadable or mount directory,
sorted paths, trailer counts) and the decided reader changes: NO orphans and
NO unknown keys. Every tree is validated before it is written.

The corpus has three parts:
  - targeted pairs, the same for every seed (only the values vary): for every
    field of the diff pin x every entry type x every context (plain, off the
    root's device, mount root, xattrs_unknown, unverified, unstable,
    unreadable, raced), a pair where ONLY that field of one entry differs,
    both ways round -- compared cells and the cells the pin excludes (a
    FIFO's mtime, a directory's nlink); every two compared fields of a type
    differing together, and a few changes as tools make them (rewrite,
    chmod+chown, setcap, ...); every type change; every optional
    field present on one side only; and the scenarios: dev relation, scope
    remounts, timestamps on fifo/sock/blk/chr and mount roots, iflags on one
    side, caps/xattrs under xattrs_unknown, O1 with and without a size
    change, hash limits, sealing and unsealing directories, unstable listings,
    one-sided raced entries, the root itself, names sorting before ".",
    non-UTF-8 and escaped names;
  - random pairs: n-bases random trees, each with four mutated variants
    (several changes at once), compared in both directions and with
    themselves;
  - refusal pairs: different scopes.
Nothing here comes from the generated spec tables or from the C code.
"""
import base64, copy, json, os, random, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
MANIFEST_PIN = os.path.join(REPO, 'test', 'expect', 'manifest-v1.md')
FIELDS_PIN = os.path.join(REPO, 'test', 'expect', 'diff-fields.md')

# ---------------------------------------------------------------------------
# The pins (plumbing: markdown tables).


def split_row(line):
    cells, cur, i, s = [], '', 0, line.strip()[1:-1]
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s) and s[i + 1] == '|':
            cur, i = cur + '|', i + 2
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
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith('|') and split_row(line)[0] == first_header:
            head = split_row(line)
            rows = []
            for l2 in lines[i + 2:]:
                if not l2.startswith('|'):
                    break
                rows.append(dict(zip(head, split_row(l2))))
            return rows
    raise SystemExit('pin: no table starting with %r' % first_header)


def load_manifest_pin():
    text = open(MANIFEST_PIN, encoding='utf-8').read()
    keys = {'header': [], 'entry': [], 'trailer': []}
    for r in md_table(text, 'line'):
        spellings = tuple(r['key'].split('|'))
        keys[r['line']].append((int(r['position']), spellings[0], spellings, r['kind'],
                                r['presence']))
    for k in keys:
        keys[k] = [x[1:] for x in sorted(keys[k])]
    types = {r['type']: int(r['mode type bits (octal)'], 8) for r in md_table(text, 'type')}
    rules = [(r['rule'], r['applies to'], r['statement']) for r in md_table(text, 'rule')]
    return keys, types, rules


KEYS, TYPES, PIN_RULES = load_manifest_pin()
TYPE_NAMES = list(TYPES)
ENTRY_KEYS = [k[0] for k in KEYS['entry']]
REQUIRED_FIELDS = [k[0] for k in KEYS['entry']
                   if k[3].startswith('required') and k[0] not in ('path', 'type')]
OPTIONAL_FIELDS = [k[0] for k in KEYS['entry'] if k[3].startswith('optional')]
FLAG_FIELDS = [k[0] for k in KEYS['entry'] if k[2] == 'bool']

# The rules violations() implements, exactly as the pin states them.
IMPLEMENTED_RULES = [
    ('1', 'all', "`mode`'s type bits match `type`"),
    ('2', 'all', '`xattrs` and `xattrs_sha256` are never both present'),
    ('3', 'all', '`xattrs_unknown` excludes `xattrs`, `xattrs_sha256` and `caps`'),
    ('4', 'all but reg', 'no `caps`'),
    ('5', 'reg', 'exactly one of `sha256` and `unverified`'),
    ('6', 'reg', '`unstable` or `unreadable` requires `unverified`'),
    ('7', 'reg', 'never both `unstable` and `unreadable`'),
    ('8', 'reg', '`mount` excludes `unstable` and `unreadable`'),
    ('9', 'dir', 'no `sha256`, `unverified` or `stored`'),
    ('10', 'dir', '`raced` only together with `unreadable` or `mount`'),
    ('11', 'dir', 'at most one of `unreadable`, `unstable` and `mount`'),
    ('12', 'lnk', 'no `sha256`, `unverified`, `stored` or `unstable`'),
    ('13', 'fifo, sock, blk, chr', 'no `sha256`, `unverified`, `stored`, `unstable` or `unreadable`'),
    ('14', 'all', '`stored` only with `sha256`, and equal to it'),
    ('15', 'all', '`rdev` present exactly on `blk` and `chr`'),
    ('16', 'all', '`link_target` present exactly on `lnk`'),
    ('17', 'all but lnk', 'no `target_outside_scope`'),
    ('18', 'lnk', 'an empty target only when `unreadable`'),
    ('19', 'lnk', "`size` equals the target's length, unless `unreadable`"),
    ('20', 'all', '`target_outside_scope` never with an empty target'),
    ('21', 'all', '`mount` excludes `sha256`'),
    ('22', 'all', '`mount` excludes `iflags`, `caps`, `xattrs`, `xattrs_sha256` and `xattrs_unknown`'),
    ('header 1', 'reg', '`sha256` only when `size` is within `hash_max_bytes`; a bare `unverified` '
                        '(no `unstable`, `unreadable` or `mount`) only when larger'),
    ('header 2', 'lnk', '`target_outside_scope` exactly when the lexical rule says the target '
                        'leaves the scope, and never when `unreadable`'),
]
if PIN_RULES != IMPLEMENTED_RULES:
    bad = [(p, i) for p, i in zip(PIN_RULES, IMPLEMENTED_RULES) if p != i] or \
        [('count', len(PIN_RULES), len(IMPLEMENTED_RULES))]
    raise SystemExit('test/expect/manifest-v1.md changed its validity rules; review '
                     'violations() first: %r' % (bad[:3],))


def load_diff_pin():
    rows = md_table(open(FIELDS_PIN, encoding='utf-8').read(), 'field')
    compared = {'type', 'content', 'metadata', 'identity', 'identity: device relation',
                'identity: within one device', 'ctime'}
    cells = {}
    for r in rows:
        if r['compared as'] in compared:
            types = TYPE_NAMES if r['for types'] == 'all' else \
                [t.strip() for t in r['for types'].split(',')]
            cells[r['field']] = types
    return cells


CELL_FIELDS = load_diff_pin()          # field -> the types the pin compares it on

# ---------------------------------------------------------------------------
# Values.

S_IFMT = 0o170000
SPECIAL = ('fifo', 'sock', 'blk', 'chr')
PERMS = [0o644, 0o600, 0o755, 0o700, 0o4755, 0o2750, 0o1777, 0o000, 0o777, 0o444]
IDS = [0, 1, 1000, 1001, 65534, 4294967294]
IFLAGS = [0, 16, 32, 4096, 8192, 524288, 0x10000000]
RDEVS = [0, 259, 1025, 34816, 2049, (1 << 32) + 7]
ROOT_DEVS = [2049, 2050, 64768, 66306, 1 << 40]
OTHER_DEVS = [0, 37, 2051, 64769, 66307, (1 << 40) + 9, (1 << 32) + 5]
LIMITS = [0, 100, 1000, 4096, 10 ** 9]
SCOPES = [b'/scope', b'/home/u/proj', b'/srv/caf\xc3\xa9 x']
XNAMES = ['security.selinux', 'system.posix_acl_access', 'system.posix_acl_default', 'user.a',
          'user.b', 'user.mime_type']
# Names: some sort before "." (0x2e) or between "a" and "a/" ("a!b", "a-b",
# "a.b", "a."), some need JSON escapes, some are not UTF-8 (path_b64).
NAMES = [b'a', b'b', b'c', b'a!b', b'a-b', b'a.b', b'a.', b'a0', b'!x', b'-y', b'#h', b' sp',
         b'\x01ctl', b'q"t', b'b\\s', b'nl\nx', b'del\x7f', b'.h', b'..h', b'z', b'sub',
         b'caf\xc3\xa9', b'\xe6\x97\xa5', b'\xff\xfe', b'caf\xe9', b'\xc3', b'n1', b'n2', b'deep']
# Link targets whose side of the scope no lexical rule can dispute: relative
# without a `..` component (inside); absolute, not under the scope, or more
# leading `..` than the link has directories above it (outside).
INSIDE_TARGETS = [b't', b'target', b'sub/file', b'caf\xc3\xa9', b'\xfft', b'a-b', b'x.y',
                  b'dir/sub/z']
OUTSIDE_ABS = [b'/etc/passwd', b'/usr/lib/x', b'/tmp', b'/\xffabs', b'/opt/data/file']


def hexs(rng, n=64):
    return ''.join(rng.choice('0123456789abcdef') for _ in range(n))


def caps_hex(rng):
    return '0' + rng.choice('123') + '000002' + hexs(rng, 32)


def xattr_set(rng):
    names = sorted(rng.sample(XNAMES, rng.randrange(1, 4)))
    return ['%s=%s' % (n, hexs(rng)) for n in names]


def other(rng, choices, cur):
    c = [x for x in choices if x != cur]
    return rng.choice(c)


def is_utf8(b):
    try:
        b.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def depth(path):
    return path.count(b'/')


def outside_target(rng, path):
    if rng.random() < 0.5:
        return rng.choice(OUTSIDE_ABS)
    return b'../' * (depth(path) + 1 + rng.randrange(2)) + rng.choice([b'out', b'x/y'])


def lexical_outside(link_path, target, scope):
    """True / False when no reasonable lexical rule could disagree; None when
    the answer depends on the rule's details (never generated: ambiguity A10)."""
    if target == b'':
        return None
    if target.startswith(b'/'):
        if scope == b'/' or target == scope or target.startswith(scope + b'/'):
            return None
        return True
    comps = target.split(b'/')
    if b'' in comps or b'.' in comps:
        return None
    if b'..' not in comps:
        return False
    ups = 0
    while ups < len(comps) and comps[ups] == b'..':
        ups += 1
    if b'..' in comps[ups:]:
        return None
    return True if ups > depth(link_path) else None


def pick_size(rng, limit, hashed):
    if hashed:
        return rng.choice([0, 1, min(limit, 10), min(limit, 777), limit])
    return rng.choice([limit + 1, limit + 1000, limit * 2 + 3])

# ---------------------------------------------------------------------------
# Entries and trees.


def settle_hash(e, t, rng):
    """Rules 5, 6, 14 and header 1 for a regular file."""
    if e['type'] != 'reg':
        return
    if e.get('unstable') or e.get('unreadable') or e.get('mount'):
        e.pop('sha256', None)
        e['unverified'] = True
    elif e['size'] <= t.limit:
        e.pop('unverified', None)
        e.setdefault('sha256', hexs(rng))
    else:
        e.pop('sha256', None)
        e['unverified'] = True
    if 'sha256' not in e:
        e.pop('stored', None)
    elif 'stored' in e:
        e['stored'] = e['sha256']


def set_outside(e, t):
    """Rules 17, 20 and header 2."""
    if e['type'] != 'lnk' or e.get('unreadable') or e.get('link_target', b'') == b'':
        e.pop('target_outside_scope', None)
        return
    o = lexical_outside(e['path'], e['link_target'], t.scope)
    assert o is not None, (e['path'], e['link_target'])
    if o:
        e['target_outside_scope'] = True
    else:
        e.pop('target_outside_scope', None)


def new_entry(rng, t, path, typ, extras=True, dev=None):
    e = {'path': path, 'type': typ, 'mode': TYPES[typ] | rng.choice(PERMS),
         'uid': rng.choice(IDS), 'gid': rng.choice(IDS), 'size': 0,
         'mtime_ns': rng.randrange(1, 1 << 61), 'ctime_ns': rng.randrange(1, 1 << 61),
         'ino': rng.randrange(2, 1 << 40), 'dev': t.root_dev() if dev is None else dev,
         'nlink': 1}
    if typ == 'reg':
        e['size'] = pick_size(rng, t.limit, rng.random() < 0.85)
        e['nlink'] = rng.choice([1, 1, 2])
    elif typ == 'dir':
        e['size'], e['nlink'] = rng.choice([4096, 0, 60]), rng.choice([2, 3, 5])
    elif typ == 'lnk':
        e['link_target'] = rng.choice(INSIDE_TARGETS) if rng.random() < 0.8 else \
            outside_target(rng, path)
        e['size'] = len(e['link_target'])
    elif typ in ('blk', 'chr'):
        e['rdev'] = rng.choice(RDEVS)
    settle_hash(e, t, rng)
    if extras:
        if typ == 'reg' and 'sha256' in e and rng.random() < 0.3:
            e['stored'] = e['sha256']
        if typ == 'reg' and rng.random() < 0.1:
            e['caps'] = caps_hex(rng)
        if rng.random() < 0.3:
            e['iflags'] = rng.choice(IFLAGS)
        r = rng.random()
        if r < 0.2:
            e['xattrs'] = xattr_set(rng)
        elif r < 0.25:
            e['xattrs_sha256'] = hexs(rng)
        elif r < 0.28:
            e.pop('caps', None)
            e['xattrs_unknown'] = True
    set_outside(e, t)
    return e


class Tree:
    def __init__(self, rng, scope=None, limit=None, root_dev=None, extras=True):
        self.scope = scope if scope is not None else rng.choice(SCOPES)
        self.limit = limit if limit is not None else rng.choice(LIMITS)
        self.created = rng.randrange(1 << 59, 1 << 61)
        self.store_max = rng.choice([0, 4096, 65536])
        self.vanished = 0
        self.e = {}
        rd = root_dev if root_dev is not None else rng.choice(ROOT_DEVS)
        self.e[b'.'] = new_entry(rng, self, b'.', 'dir', extras, dev=rd)

    def root_dev(self):
        return self.e[b'.']['dev']

    def copy(self):
        c = copy.deepcopy(self)
        c.created += 600 * 10 ** 9 + 1          # a later capture
        return c

    def open_dirs(self):
        return [p for p, e in self.e.items()
                if e['type'] == 'dir' and not e.get('unreadable') and not e.get('mount')]

    def below(self, p):
        if p == b'.':
            return [q for q in self.e if q != b'.']
        return [q for q in self.e if q.startswith(p + b'/')]

    def drop_below(self, p):
        for q in self.below(p):
            del self.e[q]


def parent_of(p):
    return p.rsplit(b'/', 1)[0] if b'/' in p else b'.'


def fresh_path(t, rng, parent=None):
    dirs = t.open_dirs()
    if not dirs:
        return None
    for _ in range(200):
        par = parent if parent is not None else rng.choice(dirs)
        name = rng.choice(NAMES)
        if rng.random() < 0.3:
            name += b'%d' % rng.randrange(10)
        p = name if par == b'.' else par + b'/' + name
        if p not in t.e and len(p) < 200:
            return p
    return None


def random_type(rng):
    return rng.choice(['reg'] * 5 + ['dir'] * 3 + ['lnk', 'fifo', 'sock', 'blk', 'chr'])


def grow(t, rng, n, extras=True):
    for _ in range(n):
        p = fresh_path(t, rng)
        if p is None:
            return
        t.e[p] = new_entry(rng, t, p, random_type(rng), extras)
        if rng.random() < 0.08:                 # some flags among the bystanders
            t.e[p][rng.choice(['raced', 'unstable', 'unreadable', 'mount', 'unverified'])] = True
    fix(t, rng)


def fix_entry(e, t, rng):
    """Restores rules 1-22 and header 1-2 on one entry after a mutation."""
    typ = e['type']
    e['mode'] = TYPES[typ] | (e['mode'] & 0o7777)                         # 1
    if 'xattrs' in e and 'xattrs_sha256' in e:                            # 2
        del e['xattrs_sha256']
    if e.get('mount'):                                                    # 21, 22
        for k in ('iflags', 'caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown', 'sha256',
                  'stored'):
            e.pop(k, None)
    if e.get('xattrs_unknown'):                                           # 3
        for k in ('xattrs', 'xattrs_sha256', 'caps'):
            e.pop(k, None)
    if typ != 'reg':                                                      # 4, 9, 12, 13
        for k in ('caps', 'sha256', 'unverified', 'stored'):
            e.pop(k, None)
    if typ == 'reg':
        if e.get('mount'):                                                # 8
            e.pop('unstable', None)
            e.pop('unreadable', None)
        if e.get('unstable') and e.get('unreadable'):                     # 7
            del e['unreadable']
        settle_hash(e, t, rng)                                            # 5, 6, 14, header 1
    if typ == 'dir':
        seals = [k for k in ('unreadable', 'unstable', 'mount') if e.get(k)]
        for k in seals[1:]:                                               # 11
            del e[k]
        if e.get('raced') and not (e.get('unreadable') or e.get('mount')):
            del e['raced']                                                # 10
    if typ in ('lnk',) + SPECIAL:                                         # 12, 13
        e.pop('unstable', None)
    if typ in SPECIAL:
        e.pop('unreadable', None)
    if typ in ('blk', 'chr'):                                             # 15
        e.setdefault('rdev', rng.choice(RDEVS))
    else:
        e.pop('rdev', None)
    if typ == 'lnk':                                                      # 16, 18, 19
        e.setdefault('link_target', rng.choice(INSIDE_TARGETS))
        if e['link_target'] != b'' and \
                lexical_outside(e['path'], e['link_target'], t.scope) is None:
            e['link_target'] = rng.choice(INSIDE_TARGETS)
        if not e.get('unreadable'):
            if e['link_target'] == b'':
                e['link_target'] = rng.choice(INSIDE_TARGETS)
            e['size'] = len(e['link_target'])
    else:
        e.pop('link_target', None)
    set_outside(e, t)                                                     # 17, 20, header 2


def fix(t, rng):
    root = t.e[b'.']
    root.pop('mount', None)                     # the root is never a mount
    for p in list(t.e):
        fix_entry(t.e[p], t, rng)
    if root.get('unreadable'):                  # an unreadable root is the only entry
        t.e = {b'.': root}
    # No orphans, nothing below an unreadable or mount directory: keep an
    # entry only when its parent is kept, is a directory, and is not sealed.
    keep = {}
    for p in sorted(t.e, key=lambda q: (q != b'.', q.count(b'/'), q)):
        if p == b'.':
            keep[p] = t.e[p]
            continue
        pe = keep.get(parent_of(p))
        if pe is None or pe['type'] != 'dir' or pe.get('unreadable') or pe.get('mount'):
            continue
        keep[p] = t.e[p]
    t.e = keep


def entry_violations(e, t):
    v, typ = [], e['type']
    has = lambda k: k in e
    if e['mode'] & S_IFMT != TYPES[typ]:
        v.append('1')
    if has('xattrs') and has('xattrs_sha256'):
        v.append('2')
    if has('xattrs_unknown') and (has('xattrs') or has('xattrs_sha256') or has('caps')):
        v.append('3')
    if typ != 'reg' and has('caps'):
        v.append('4')
    if typ == 'reg' and has('sha256') == has('unverified'):
        v.append('5')
    if typ == 'reg' and (has('unstable') or has('unreadable')) and not has('unverified'):
        v.append('6')
    if typ == 'reg' and has('unstable') and has('unreadable'):
        v.append('7')
    if typ == 'reg' and has('mount') and (has('unstable') or has('unreadable')):
        v.append('8')
    if typ == 'dir' and (has('sha256') or has('unverified') or has('stored')):
        v.append('9')
    if typ == 'dir' and has('raced') and not (has('unreadable') or has('mount')):
        v.append('10')
    if typ == 'dir' and sum(map(has, ('unreadable', 'unstable', 'mount'))) > 1:
        v.append('11')
    if typ == 'lnk' and any(map(has, ('sha256', 'unverified', 'stored', 'unstable'))):
        v.append('12')
    if typ in SPECIAL and any(map(has, ('sha256', 'unverified', 'stored', 'unstable',
                                        'unreadable'))):
        v.append('13')
    if has('stored') and (not has('sha256') or e['stored'] != e['sha256']):
        v.append('14')
    if has('rdev') != (typ in ('blk', 'chr')):
        v.append('15')
    if has('link_target') != (typ == 'lnk'):
        v.append('16')
    if typ != 'lnk' and has('target_outside_scope'):
        v.append('17')
    if typ == 'lnk' and e['link_target'] == b'' and not has('unreadable'):
        v.append('18')
    if typ == 'lnk' and not has('unreadable') and e['size'] != len(e['link_target']):
        v.append('19')
    if has('target_outside_scope') and e.get('link_target', b'') == b'':
        v.append('20')
    if has('mount') and has('sha256'):
        v.append('21')
    if has('mount') and any(map(has, ('iflags', 'caps', 'xattrs', 'xattrs_sha256',
                                      'xattrs_unknown'))):
        v.append('22')
    if typ == 'reg':
        if has('sha256') and not e['size'] <= t.limit:
            v.append('header 1')
        bare = has('unverified') and not any(map(has, ('unstable', 'unreadable', 'mount')))
        if bare and not e['size'] > t.limit:
            v.append('header 1')
    if typ == 'lnk':
        o = lexical_outside(e['path'], e['link_target'], t.scope)
        if e['link_target'] != b'' and o is None:
            v.append('header 2 (a target no lexical rule agrees on)')
        if has('target_outside_scope') != (o is True and not has('unreadable')):
            v.append('header 2')
    # kinds, and no key the format does not have
    for k, val in e.items():
        if k not in ENTRY_KEYS:
            v.append('unknown key ' + k)
        elif k in FLAG_FIELDS and val is not True:
            v.append('flag %s not true' % k)
    return v


def violations(t):
    v = []
    root = t.e.get(b'.')
    if root is None or root['type'] != 'dir' or root.get('mount'):
        v.append('root')
    if root is not None and root.get('unreadable') and len(t.e) != 1:
        v.append('unreadable root not alone')
    for p, e in t.e.items():
        if e['path'] != p:
            v.append('path key')
        if p != b'.':
            comps = p.split(b'/')
            if p.startswith(b'/') or any(c in (b'', b'.', b'..') for c in comps) or b'\0' in p:
                v.append('bad path %r' % p)
            pe = t.e.get(parent_of(p))
            if pe is None or pe['type'] != 'dir':
                v.append('orphan %r' % p)
            elif pe.get('unreadable') or pe.get('mount'):
                v.append('below a sealed directory %r' % p)
        v += ['%r: rule %s' % (p, r) for r in entry_violations(e, t)]
    return v

# ---------------------------------------------------------------------------
# Writing (canonical encoding, manifest-v1.md "Encoding").


def jstr(s):
    return json.dumps(s, ensure_ascii=False)


def enc_obj(keys, d):
    parts, used = [], set()
    for canon, spellings, kind, presence in keys:
        if canon not in d:
            if presence.startswith('required'):
                raise SystemExit('generator bug: %s missing' % canon)
            continue
        used.add(canon)
        v = d[canon]
        name = spellings[0]
        if len(spellings) == 2:                 # `a|b`: b is base64 of non-UTF-8 bytes
            vals = v if isinstance(v, list) else [v]
            if all(is_utf8(x) for x in vals):
                vals = [x.decode('utf-8') for x in vals]
            else:
                name = spellings[1]
                vals = [base64.b64encode(x).decode('ascii') for x in vals]
            v = vals if isinstance(v, list) else vals[0]
        if kind == 'int':
            assert type(v) is int, (canon, v)
            enc = str(v)
        elif kind == 'string':
            assert isinstance(v, str), (canon, v)
            enc = jstr(v)
        elif kind == 'bool':
            assert v is True, (canon, v)
            enc = 'true'
        elif kind == 'array':
            assert isinstance(v, list) and v and all(isinstance(x, str) for x in v), (canon, v)
            enc = '[' + ','.join(jstr(x) for x in v) + ']'
        else:
            raise SystemExit('pin: unknown kind %r' % kind)
        parts.append('"%s":%s' % (name, enc))
    if set(d) - used:
        raise SystemExit('generator bug: unknown keys %r' % sorted(set(d) - used))
    return '{' + ','.join(parts) + '}'


def write_manifest(t, path):
    header = {'belay_manifest': 1, 'created_ns': t.created, 'scopes': [t.scope],
              'hash': 'sha256', 'hash_max_bytes': t.limit, 'store_max_bytes': t.store_max}
    lines = [enc_obj(KEYS['header'], header)]
    n = {'unreadable': 0, 'unstable': 0, 'mount': 0, 'raced': 0}
    for p in sorted(t.e):
        e = t.e[p]
        lines.append(enc_obj(KEYS['entry'], e))
        for k in n:
            n[k] += bool(e.get(k))
    trailer = {'belay_manifest_end': len(t.e), 'vanished': t.vanished,
               'unreadable': n['unreadable'], 'unstable': n['unstable'], 'mounts': n['mount'],
               'raced': n['raced']}
    lines.append(enc_obj(KEYS['trailer'], trailer))
    for l in lines:
        assert len(l.encode('utf-8')) < 65536 and '\0' not in l
    with open(path, 'wb') as f:
        f.write(('\n'.join(lines) + '\n').encode('utf-8'))


class Writer:
    def __init__(self, out):
        self.out, self.k, self.s = out, 0, 0

    def pair(self, b, a, label):
        assert b.scope == a.scope
        for t in (b, a):
            v = violations(t)
            if v:
                raise SystemExit('generator bug (%s): %s' % (label, v[:5]))
        stem = os.path.join(self.out, 'pair-%05d' % self.k)
        write_manifest(b, stem + '.before')
        write_manifest(a, stem + '.after')
        with open(stem + '.label', 'w', encoding='utf-8') as f:
            f.write(label + '\n')
        self.k += 1

    def both_ways(self, b, a, label):
        self.pair(b, a, label)
        self.pair(a, b, label + ' (reversed)')

    def refusal(self, b, a, label):
        assert b.scope != a.scope
        for t in (b, a):
            v = violations(t)
            if v:
                raise SystemExit('generator bug (%s): %s' % (label, v[:5]))
        stem = os.path.join(self.out, 'scope-%05d' % self.s)
        write_manifest(b, stem + '.before')
        write_manifest(a, stem + '.after')
        with open(stem + '.label', 'w', encoding='utf-8') as f:
            f.write(label + '\n')
        self.s += 1

# ---------------------------------------------------------------------------
# Targeted pairs: one field of one entry differs.

CONTEXTS = ['plain', 'offdev', 'mount', 'xattrs_unknown', 'unverified', 'unstable',
            'unreadable', 'raced']


def other_dev(t, rng, avoid=()):
    return rng.choice([d for d in OTHER_DEVS if d != t.root_dev() and d not in avoid])


def in_context(ctx, e, t, rng):
    """The entry as it is in one context (the same on both sides), or None."""
    e, typ = copy.deepcopy(e), e['type']
    if ctx == 'plain':
        pass
    elif ctx == 'offdev':
        e['dev'] = other_dev(t, rng)
    elif ctx == 'mount':
        for k in ('iflags', 'caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown', 'sha256',
                  'stored', 'unstable', 'unreadable'):
            e.pop(k, None)
        e['mount'] = True
        e['dev'] = other_dev(t, rng)
        if typ == 'reg':
            e['unverified'] = True
    elif ctx == 'xattrs_unknown':
        for k in ('caps', 'xattrs', 'xattrs_sha256'):
            e.pop(k, None)
        e['xattrs_unknown'] = True
    elif ctx == 'unverified':                  # bare: too large for this manifest
        if typ != 'reg':
            return None
        e['size'] = t.limit + 1 + rng.randrange(1000)
        for k in ('sha256', 'stored'):
            e.pop(k, None)
        e['unverified'] = True
    elif ctx in ('unstable', 'unreadable'):
        if typ == 'reg':
            for k in ('sha256', 'stored'):
                e.pop(k, None)
            e['unverified'] = True
        elif typ == 'lnk' and ctx == 'unreadable':
            e.pop('target_outside_scope', None)
            if rng.random() < 0.4:
                e['link_target'] = b''          # "target unknown"; size stays as stat'ed
        elif typ != 'dir':
            return None
        e[ctx] = True
    elif ctx == 'raced':
        e['raced'] = True
        if typ == 'dir':
            e['unreadable'] = True
    return e


def mutate(f, var, e, t, rng):
    """e with only field f changed, validity kept; None when impossible here."""
    e2, typ = copy.deepcopy(e), e['type']
    if f == 'mode':
        e2['mode'] = (e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777)
    elif f in ('uid', 'gid'):
        e2[f] = other(rng, IDS, e[f])
    elif f == 'size':
        if typ == 'reg' and 'sha256' in e:
            c = [s for s in {0, 1, t.limit // 2, t.limit} if s != e['size'] and s <= t.limit]
        elif typ == 'reg' and not any(e.get(k) for k in ('unstable', 'unreadable', 'mount')):
            c = [t.limit + 1 + i for i in (0, 5, 999) if t.limit + 1 + i != e['size']]
        elif typ == 'lnk' and not e.get('unreadable'):
            c = []                              # rule 19: the size is the target's length
        else:
            c = [s for s in (0, 1, 4096, 123456) if s != e['size']]
        if not c:
            return None
        e2['size'] = rng.choice(c)
    elif f in ('mtime_ns', 'ctime_ns'):
        e2[f] = e[f] + rng.randrange(1, 10 ** 12)
    elif f == 'ino':
        e2[f] = other(rng, [e[f] + 1, e[f] + 77777, 2], e[f])
    elif f == 'nlink':
        e2[f] = e[f] + rng.randrange(1, 4)
    elif f == 'dev':
        if var == 'flip':                       # on the root's device <-> off it
            e2['dev'] = other_dev(t, rng) if e['dev'] == t.root_dev() else t.root_dev()
        else:                                   # renumbered, still off the root's device
            if e['dev'] == t.root_dev():
                return None
            e2['dev'] = other_dev(t, rng, avoid=(e['dev'],))
    elif f == 'iflags':
        if 'iflags' not in e:
            return None
        e2['iflags'] = other(rng, IFLAGS, e['iflags'])
    elif f == 'caps':
        if typ != 'reg' or e.get('xattrs_unknown') or e.get('mount'):
            return None
        if var == 'change' and 'caps' in e:
            e2['caps'] = caps_hex(rng)
        elif var == 'add' and 'caps' not in e:
            e2['caps'] = caps_hex(rng)
        elif var == 'drop' and 'caps' in e:
            del e2['caps']
        else:
            return None
    elif f == 'xattrs':
        if e.get('xattrs_unknown') or e.get('mount') or 'xattrs_sha256' in e:
            return None
        if var == 'change' and 'xattrs' in e:
            new = xattr_set(rng)
            if new == e['xattrs']:
                return None
            e2['xattrs'] = new
        elif var == 'add' and 'xattrs' not in e:
            e2['xattrs'] = xattr_set(rng)
        elif var == 'drop' and 'xattrs' in e:
            del e2['xattrs']
        else:
            return None
    elif f == 'sha256':
        if 'sha256' not in e or 'stored' in e:
            return None
        e2['sha256'] = hexs(rng)
    elif f == 'rdev':
        if 'rdev' not in e:
            return None
        e2['rdev'] = other(rng, RDEVS, e['rdev'])
    elif f == 'link_target':
        # Same length (rule 19 ties the size to it) and the same side of the
        # scope (header 2 ties target_outside_scope to it).
        tg = e.get('link_target', b'')
        if tg == b'':
            return None
        if e.get('target_outside_scope'):
            if not tg.startswith(b'/') or len(tg) < 2:
                return None
            new = b'/' + bytes(rng.choice(b'abcdefgh') for _ in range(len(tg) - 1))
        else:                                   # a plain name: inside
            new = bytes(rng.choice(b'abcdefgh\xff') for _ in range(len(tg)))
        if new == tg:
            return None
        e2['link_target'] = new
    else:
        raise SystemExit('gen_corpus: no mutation for field %r (the pin grew a row?)' % f)
    return e2


def prepare(f, var, e, rng):
    """What the base entry must hold for field f to be changed alone."""
    e = copy.deepcopy(e)
    if f == 'iflags':
        e['iflags'] = rng.choice(IFLAGS)
    elif f == 'caps':
        if e['type'] != 'reg':                  # manifest-v1 rule 4
            return e
        e.pop('xattrs_unknown', None)
        if var in ('change', 'drop'):
            e['caps'] = caps_hex(rng)
        else:
            e.pop('caps', None)
    elif f == 'xattrs':
        for k in ('xattrs_sha256', 'xattrs_unknown', 'xattrs'):
            e.pop(k, None)
        if var in ('change', 'drop'):
            e['xattrs'] = xattr_set(rng)
    elif f == 'sha256':
        e.pop('stored', None)
    return e


VARIANTS = {'dev': ['flip', 'renumber'], 'caps': ['change', 'add', 'drop'],
            'xattrs': ['change', 'add', 'drop']}


def base_tree(rng, n=None, **kw):
    t = Tree(rng, **kw)
    grow(t, rng, rng.randrange(0, 7) if n is None else n)
    return t


def place(rng, t, typ, extras=True):
    p = fresh_path(t, rng)
    return None if p is None else new_entry(rng, t, p, typ, extras)


def try_pair(w, rng, label, build, attempts=64):
    """build(rng) -> (before tree, after tree) or None; writes both ways. Many
    attempts: a build fails when its random tree cannot hold the change (a size
    past the tree's hash limit), and the coverage gate must not depend on a
    random seed's luck -- with 4, about one seed in a dozen missed a pair."""
    for _ in range(attempts):
        r = build(rng)
        if r is None:
            continue
        b, a = r
        if violations(b) or violations(a):
            continue
        w.both_ways(b, a, label)
        return True
    return False


def cells(w, rng):
    """Every field (required ones, and every compared optional one) x every
    type x every context: only that field of one entry differs."""
    fields = REQUIRED_FIELDS + [f for f in CELL_FIELDS
                                if f not in REQUIRED_FIELDS and f != 'type']
    for f in fields:
        for typ in TYPE_NAMES:
            for ctx in CONTEXTS:
                for var in VARIANTS.get(f, [None]):
                    def build(rng, f=f, typ=typ, ctx=ctx, var=var):
                        t = base_tree(rng)
                        e = place(rng, t, typ)
                        if e is None:
                            return None
                        e = in_context(ctx, prepare(f, var, e, rng), t, rng)
                        if e is None:
                            return None
                        e2 = mutate(f, var, e, t, rng)
                        if e2 is None:
                            return None
                        a = t.copy()
                        t.e[e['path']], a.e[e['path']] = e, e2
                        return t, a
                    try_pair(w, rng, 'only %s differs on a %s (%s%s)' %
                             (f, typ, ctx, ', ' + var if var else ''), build)


PAIR_VARIANT = {'dev': 'flip', 'caps': 'change', 'xattrs': 'change'}


def field_pairs(w, rng):
    """Every two compared fields of one entry differing together, on every
    type: the order of `changed` for every pair of fields. A symlink's size
    and target change together through a target of another length."""
    for typ in TYPE_NAMES:
        fs = [f for f in CELL_FIELDS if f not in ('type', 'ctime_ns') and typ in CELL_FIELDS[f]
              and not (f == 'caps' and typ != 'reg')]          # manifest-v1 rule 4
        for i, f1 in enumerate(fs):
            for f2 in fs[i + 1:]:
                def build(rng, typ=typ, f1=f1, f2=f2):
                    v1, v2 = PAIR_VARIANT.get(f1), PAIR_VARIANT.get(f2)
                    for ctx in ('plain', 'unreadable'):
                        t = base_tree(rng)
                        e = place(rng, t, typ)
                        if e is None:
                            return None
                        e = in_context(ctx, prepare(f2, v2, prepare(f1, v1, e, rng), rng), t, rng)
                        if e is None:
                            continue
                        if typ == 'lnk' and {f1, f2} == {'size', 'link_target'}:
                            if e.get('unreadable') or not e['link_target']:
                                continue
                            e2 = dict(e, link_target=e['link_target'] + b'x')
                            e2['size'] = len(e2['link_target'])
                        else:
                            e2 = mutate(f1, v1, e, t, rng)
                            e2 = e2 and mutate(f2, v2, e2, t, rng)
                        if not e2:
                            continue
                        a = t.copy()
                        t.e[e['path']], a.e[e['path']] = e, e2
                        return t, a
                    return None
                try_pair(w, rng, 'only %s and %s differ on a %s' % (f1, f2, typ), build)

    # And a few changes as tools make them.
    tools = {'rewrite': ('size', 'mtime_ns', 'ctime_ns', 'sha256'),
             'replace': ('ino', 'size', 'mtime_ns', 'ctime_ns', 'sha256', 'mode'),
             'chmod+chown': ('mode', 'uid', 'gid', 'ctime_ns'),
             'touch': ('mtime_ns', 'ctime_ns'),
             'setfattr+chattr': ('xattrs', 'iflags', 'ctime_ns'),
             'setcap': ('caps', 'ctime_ns'),
             'everything': ('mode', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns', 'ino', 'nlink',
                            'iflags', 'caps', 'xattrs', 'sha256', 'dev')}
    for name, fields in tools.items():
        for typ in ('reg', 'dir', 'lnk', 'fifo', 'chr'):
            def build(rng, typ=typ, fields=fields):
                t = base_tree(rng)
                e = place(rng, t, typ)
                if e is None:
                    return None
                for f in fields:
                    e = prepare(f, PAIR_VARIANT.get(f), e, rng)
                e2 = e
                for f in fields:
                    e3 = mutate(f, PAIR_VARIANT.get(f), e2, t, rng)
                    e2 = e3 or e2                    # a field this type cannot change: skip it
                if e2 == e:
                    return None
                a = t.copy()
                t.e[e['path']], a.e[e['path']] = e, e2
                return t, a
            try_pair(w, rng, '%s on a %s' % (name, typ), build)


def change_type(e, t2, t, rng):
    """The entry turned into type t2, everything else kept where valid."""
    keep = ('path', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns', 'ino', 'dev', 'nlink',
            'iflags', 'xattrs', 'xattrs_sha256', 'xattrs_unknown', 'mount', 'raced',
            'unreadable', 'unstable')
    e2 = {k: v for k, v in e.items() if k in keep}
    e2['type'], e2['mode'] = t2, TYPES[t2] | (e['mode'] & 0o7777)
    if t2 == 'lnk':
        n = e['size']
        if 1 <= n <= 120:
            e2['link_target'] = bytes(rng.choice(b'abcdefgh') for _ in range(n))
        else:
            e2['link_target'] = rng.choice(INSIDE_TARGETS)
            e2['size'] = len(e2['link_target'])
    if t2 in ('blk', 'chr'):                    # blk <-> chr keeps its device number
        e2['rdev'] = e.get('rdev', rng.choice(RDEVS))
    if t2 == 'reg':
        settle_hash(e2, t, rng)
    set_outside(e2, t)
    if entry_violations(e2, t):
        return None
    return e2


def type_changes(w, rng):
    for t1 in TYPE_NAMES:
        for t2 in TYPE_NAMES:
            if t1 == t2:
                continue
            for ctx in ('plain', 'offdev', 'xattrs_unknown', 'raced', 'mount', 'unreadable'):
                # iflags read on one side only: across a type change no field
                # is compared, so it adds no reason, raced or not
                for one in ((False, True) if ctx in ('plain', 'raced') else (False,)):
                    def build(rng, t1=t1, t2=t2, ctx=ctx, one=one):
                        t = base_tree(rng)
                        e = place(rng, t, t1)
                        e = e and in_context(ctx, e, t, rng)
                        e2 = e and change_type(e, t2, t, rng)
                        if not e2:
                            return None
                        if one:
                            e = dict(e, iflags=e.get('iflags', 16))
                            e2.pop('iflags', None)
                        a = t.copy()
                        t.e[e['path']], a.e[e['path']] = e, e2
                        return t, a
                    try_pair(w, rng, 'type %s -> %s (%s%s)' % (t1, t2, ctx,
                             ', iflags on one side' if one else ''), build)


ATTRS = ('iflags', 'caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown')


def one_sided_build(f, var, typ, ctx):
    """A builder for: optional field f present on one side only. The base
    entry `e` lacks f (and whatever f excludes); `w_` is e plus f, plus only
    what the rules force to change with it."""
    def build(rng):
        t = base_tree(rng)
        e = place(rng, t, typ)
        if e is None:
            return None
        strip = set()
        if f in ('iflags', 'caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown', 'stored',
                 'unstable', 'unreadable', 'mount', 'raced', 'target_outside_scope'):
            strip.add(f)
        if f in ('caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown'):
            strip |= {'caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown'}
        if f == 'mount' or var == 'mount':      # rule 22, and 14/21 through sha256
            strip |= set(ATTRS) | {'stored'}
        for k in strip:
            e.pop(k, None)
        e = in_context(ctx, e, t, rng)
        if e is None or (f in e and f != 'sha256'):
            return None
        a = t.copy()
        w_ = copy.deepcopy(e)
        if f == 'iflags':
            w_['iflags'] = rng.choice(IFLAGS)
        elif f == 'caps':
            w_['caps'] = caps_hex(rng)
        elif f == 'xattrs':
            w_['xattrs'] = xattr_set(rng)
            if var == 'vs-digest':              # the other side spells a set by digest
                e['xattrs_sha256'] = hexs(rng)
        elif f == 'xattrs_sha256':
            w_['xattrs_sha256'] = hexs(rng)
            if var == 'vs-inline':
                e['xattrs'] = xattr_set(rng)
        elif f == 'xattrs_unknown':
            w_['xattrs_unknown'] = True
            if var == 'attrs':                  # attributes read on the other side
                e['xattrs'] = xattr_set(rng)
                if typ == 'reg':
                    e['caps'] = caps_hex(rng)
        elif f == 'stored':
            if 'sha256' not in e:
                return None
            w_['stored'] = e['sha256']
        elif f in ('unstable', 'unreadable', 'mount', 'raced'):
            w_[f] = True
            if typ == 'reg' and f != 'raced':   # rule 6, 21: no hash with these
                for k in ('sha256', 'stored'):
                    w_.pop(k, None)
                w_['unverified'] = True
            if typ == 'lnk' and f == 'unreadable':
                w_.pop('target_outside_scope', None)
        elif f == 'target_outside_scope':       # same length, the other side of the scope
            if typ != 'lnk' or e.get('unreadable'):
                return None
            out = rng.choice(OUTSIDE_ABS)
            e['link_target'] = bytes(rng.choice(b'abcdefgh') for _ in range(len(out)))
            e['size'] = len(out)
            w_['link_target'], w_['size'], w_['target_outside_scope'] = out, len(out), True
        elif f == 'sha256':                     # the other side unverified (rule O1)
            if typ != 'reg' or 'sha256' not in e:
                return None
            for k in ('sha256', 'stored'):
                w_.pop(k, None)
            w_['unverified'] = True
            if var in ('limit', 'limit+size'):  # the other manifest's limit is lower
                if e['size'] == 0:
                    return None
                a.limit = e['size'] - 1
                for x in a.e.values():
                    settle_hash(x, a, rng)
                if var == 'limit+size':
                    w_['size'] = e['size'] + 1 + rng.randrange(100)
            else:                               # could not be hashed
                w_[var] = True
        else:
            return None
        t.e[e['path']], a.e[e['path']] = e, w_
        return t, a
    return build


def optional_one_sided(w, rng):
    plan = {'iflags': [None], 'caps': [None], 'xattrs': [None, 'vs-digest'],
            'xattrs_sha256': [None, 'vs-inline'], 'xattrs_unknown': ['bare', 'attrs'],
            'sha256': ['limit', 'limit+size', 'unstable', 'unreadable', 'mount'],
            'stored': [None], 'unstable': [None], 'unreadable': [None], 'mount': [None],
            'raced': [None], 'target_outside_scope': [None]}
    # `unverified` is sha256's other side (rule 5); `rdev` and `link_target`
    # are present on one side only exactly when the type changes.
    for f in OPTIONAL_FIELDS:
        if f in ('unverified', 'rdev', 'link_target'):
            continue
        if f not in plan:
            raise SystemExit('gen_corpus: no one-sided plan for optional field %r' % f)
        for var in plan[f]:
            for typ in TYPE_NAMES:
                for ctx in ('plain', 'offdev', 'unverified', 'raced', 'xattrs_unknown',
                            'unreadable', 'mount'):
                    if ctx == f or (ctx == 'xattrs_unknown' and f in ATTRS):
                        continue
                    try_pair(w, rng, '%s on one side only, %s (%s%s)' %
                             (f, typ, ctx, ', ' + var if var else ''),
                             one_sided_build(f, var, typ, ctx))

# ---------------------------------------------------------------------------
# Scenarios.


def remount(t, rng, renumber_ino):
    """The scope remounted: every device number changes, relations kept."""
    old = t.root_dev()
    new = rng.choice([d for d in ROOT_DEVS + OTHER_DEVS if d != old])
    mapping, used = {old: new}, {old, new}
    for e in t.e.values():
        d = e['dev']
        if d not in mapping:
            mapping[d] = rng.choice([x for x in OTHER_DEVS + [d + 1000, d + 7]
                                     if x not in used])
            used.add(mapping[d])
        e['dev'] = mapping[d]
        if renumber_ino:
            e['ino'] = rng.randrange(2, 1 << 40)
    return old, new


def with_mounts(rng, t, n):
    for _ in range(n):
        e = place(rng, t, rng.choice(['dir', 'dir', 'reg', 'fifo']))
        if e is None:
            return
        e = in_context('mount', e, t, rng)
        t.e[e['path']] = e
    fix(t, rng)


def scenarios(w, rng):
    # The scope remounted.
    for variant in ('dev', 'dev+ino', 'flip-off', 'flip-on', 'content', 'root-only',
                    'mode'):
        def build(rng, variant=variant):
            t = base_tree(rng, rng.randrange(4, 14))
            with_mounts(rng, t, rng.randrange(1, 3))
            a = t.copy()
            old, new = remount(a, rng, renumber_ino=variant != 'dev')
            on = [p for p, e in a.e.items() if p != b'.' and e['dev'] == new]
            off = [p for p, e in a.e.items() if e['dev'] != new]
            if variant == 'flip-off':           # one entry stays behind: now off the root's device
                if not on:
                    return None
                a.e[rng.choice(on)]['dev'] = old
            elif variant == 'flip-on':
                if not off:
                    return None
                a.e[rng.choice(off)]['dev'] = new
            elif variant == 'content':
                regs = [p for p, e in a.e.items() if 'sha256' in e and 'stored' not in e]
                if not regs:
                    return None
                a.e[rng.choice(regs)]['sha256'] = hexs(rng)
            elif variant == 'root-only':        # only the root's number moved
                for p, e in a.e.items():
                    if p != b'.':
                        e['dev'] = t.e[p]['dev']
                        e['ino'] = t.e[p]['ino']
            elif variant == 'mode':
                p = rng.choice(list(a.e))
                a.e[p]['mode'] = (a.e[p]['mode'] & S_IFMT) | \
                    other(rng, PERMS, a.e[p]['mode'] & 0o7777)
            return t, a
        for _ in range(3):
            try_pair(w, rng, 'scope remount: ' + variant, build)

    # A device number changing while the relation stays (both off the root's
    # device), with the inode number changing too: neither is compared.
    for typ in TYPE_NAMES:
        def build(rng, typ=typ):
            t = base_tree(rng)
            e = place(rng, t, typ)
            if e is None:
                return None
            e['dev'] = other_dev(t, rng)
            a = t.copy()
            e2 = dict(e, dev=other_dev(t, rng, avoid=(e['dev'],)), ino=e['ino'] + 5)
            t.e[e['path']], a.e[e['path']] = e, e2
            return t, a
        try_pair(w, rng, 'dev renumbered off-device, with a new ino, on a %s' % typ, build)
        def build2(rng, typ=typ):                # relation flips and ino changes
            t = base_tree(rng)
            e = place(rng, t, typ)
            if e is None:
                return None
            a = t.copy()
            e2 = dict(e, dev=other_dev(t, rng), ino=e['ino'] + 5)
            t.e[e['path']], a.e[e['path']] = e, e2
            return t, a
        try_pair(w, rng, 'dev leaves the root device, with a new ino, on a %s' % typ, build2)

    # Both timestamps at once, on every type and context.
    for typ in TYPE_NAMES:
        for ctx in ('plain', 'mount', 'raced', 'offdev', 'xattrs_unknown'):
            def build(rng, typ=typ, ctx=ctx):
                t = base_tree(rng)
                e = place(rng, t, typ)
                e = e and in_context(ctx, e, t, rng)
                if not e:
                    return None
                a = t.copy()
                e2 = dict(e, mtime_ns=e['mtime_ns'] + 1, ctime_ns=e['ctime_ns'] + 1)
                t.e[e['path']], a.e[e['path']] = e, e2
                return t, a
            try_pair(w, rng, 'mtime and ctime on a %s (%s)' % (typ, ctx), build)

    # An entry that becomes a mount root, its timestamps now the mounted
    # filesystem's: a mount root on one side only (ambiguity A2).
    for typ in TYPE_NAMES:
        for same_dev in (False, True):
            def build(rng, typ=typ, same_dev=same_dev):
                t = base_tree(rng)
                e = place(rng, t, typ)
                e2 = e and in_context('mount', e, t, rng)
                if not e2:
                    return None
                e2['mtime_ns'] += 7
                e2['ctime_ns'] += 9
                if same_dev:
                    e2['dev'] = e['dev']
                a = t.copy()
                t.e[e['path']], a.e[e['path']] = e, e2
                return t, a
            try_pair(w, rng, 'becomes a mount root with new timestamps: %s%s' %
                     (typ, ', same dev' if same_dev else ''), build)

    # caps / xattrs against xattrs_unknown, alone and with another change.
    for typ in TYPE_NAMES:
        for extra in (None, 'mode', 'ctime', 'ino', 'content', 'iflags-one-sided'):
            def build(rng, typ=typ, extra=extra):
                t = base_tree(rng)
                e = place(rng, t, typ)
                if e is None:
                    return None
                e.pop('xattrs_unknown', None)
                e.pop('xattrs_sha256', None)
                e['xattrs'] = xattr_set(rng)
                if typ == 'reg':
                    e['caps'] = caps_hex(rng)
                e2 = {k: v for k, v in e.items() if k not in ('caps', 'xattrs')}
                e2['xattrs_unknown'] = True
                if extra == 'mode':
                    e2['mode'] = (e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777)
                elif extra == 'ctime':
                    e2['ctime_ns'] += 1
                elif extra == 'ino':
                    e2['ino'] += 1
                elif extra == 'content':
                    if 'sha256' not in e or 'stored' in e:
                        return None
                    e2['sha256'] = hexs(rng)
                elif extra == 'iflags-one-sided':
                    e['iflags'] = 0
                    e2.pop('iflags', None)
                a = t.copy()
                t.e[e['path']], a.e[e['path']] = e, e2
                return t, a
            try_pair(w, rng, 'caps/xattrs vs xattrs_unknown on a %s%s' %
                     (typ, ', with ' + extra if extra else ''), build)

    # iflags on one side only, with and without another change.
    for typ in TYPE_NAMES:
        for extra in (None, 'mode', 'ctime', 'content', 'unverified'):
            def build(rng, typ=typ, extra=extra):
                t = base_tree(rng)
                e = place(rng, t, typ)
                if e is None:
                    return None
                e['iflags'] = rng.choice(IFLAGS)
                e2 = {k: v for k, v in e.items() if k != 'iflags'}
                if extra == 'mode':
                    e2['mode'] = (e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777)
                elif extra == 'ctime':
                    e2['ctime_ns'] += 1
                elif extra == 'content':
                    if typ not in ('reg', 'blk', 'chr'):
                        return None
                    if typ == 'reg':
                        if 'sha256' not in e or 'stored' in e:
                            return None
                        e2['sha256'] = hexs(rng)
                    else:
                        e2['rdev'] = other(rng, RDEVS, e['rdev'])
                elif extra == 'unverified':
                    if typ != 'reg':
                        return None
                    for k in ('sha256', 'stored'):
                        e2.pop(k, None)
                    e2['unverified'], e2['unstable'] = True, True
                a = t.copy()
                t.e[e['path']], a.e[e['path']] = e, e2
                return t, a
            try_pair(w, rng, 'iflags on one side only, %s%s' %
                     (typ, ', with ' + extra if extra else ''), build)

    # Hash limits that differ without changing what was hashed.
    def build(rng):
        t = base_tree(rng, rng.randrange(3, 12), limit=10 ** 9)
        a = t.copy()
        a.limit = max(e['size'] for e in t.e.values()) + rng.randrange(0, 2)
        return t, a
    for _ in range(3):
        try_pair(w, rng, 'hash limits differ, every file within both', build)

    # Sealing, unsealing and unstable listings.
    for how in ('unreadable', 'mount', 'mount-offdev', 'unstable-missing', 'unstable-extra',
                'unstable-same', 'root-unstable', 'root-unreadable'):
        def build(rng, how=how):
            t = base_tree(rng, rng.randrange(0, 5))
            if how.startswith('root'):
                d = b'.'
            else:
                e = place(rng, t, 'dir', extras=False)
                if e is None:
                    return None
                t.e[e['path']] = e
                d = e['path']
            for _ in range(rng.randrange(1, 5)):
                p = fresh_path(t, rng, parent=d if rng.random() < 0.7 else None)
                if p:
                    t.e[p] = new_entry(rng, t, p, random_type(rng))
            fix(t, rng)
            a = t.copy()
            de = a.e[d]
            if how in ('unreadable', 'root-unreadable'):
                de.pop('unstable', None)
                de['unreadable'] = True
            elif how.startswith('mount'):
                for k in ('iflags', 'caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown'):
                    de.pop(k, None)
                de['mount'] = True
                if how == 'mount-offdev':
                    de['dev'] = other_dev(a, rng)
            else:
                de['unstable'] = True
                kids = [q for q in a.e if parent_of(q) == d and q != b'.']
                if how == 'unstable-missing' and kids:
                    victim = rng.choice(kids)
                    del a.e[victim]
                    a.drop_below(victim)
                elif how == 'unstable-extra':
                    p = fresh_path(a, rng, parent=d)
                    if p:
                        a.e[p] = new_entry(rng, a, p, random_type(rng))
            fix(a, rng)
            return t, a
        for _ in range(3):
            try_pair(w, rng, 'directory: ' + how, build)

    # Entries present on one side only that carry raced.
    for typ in TYPE_NAMES:
        def build(rng, typ=typ):
            t = base_tree(rng)
            a = t.copy()
            e = place(rng, a, typ)
            if e is None:
                return None
            e['raced'] = True
            if typ == 'dir':
                e['unreadable'] = True
            fix_entry(e, a, rng)
            a.e[e['path']] = e
            return t, a
        try_pair(w, rng, 'raced %s on one side only' % typ, build)

    # The root itself.
    for change in ('mode', 'uid', 'ctime', 'mtime', 'ino', 'nlink', 'xattrs', 'iflags-one-sided',
                   'xattrs_unknown', 'size'):
        def build(rng, change=change):
            t = base_tree(rng, rng.randrange(1, 6))
            a = t.copy()
            r = a.e[b'.']
            if change == 'mode':
                r['mode'] = (r['mode'] & S_IFMT) | other(rng, PERMS, r['mode'] & 0o7777)
            elif change == 'uid':
                r['uid'] = other(rng, IDS, r['uid'])
            elif change in ('ctime', 'mtime'):
                r[change + '_ns'] += 3
            elif change in ('ino', 'nlink', 'size'):
                r[change] += 1
            elif change == 'xattrs':
                r.pop('xattrs_unknown', None)
                r.pop('xattrs_sha256', None)
                r['xattrs'] = xattr_set(rng)
                if t.e[b'.'].get('xattrs') == r['xattrs']:
                    return None
            elif change == 'iflags-one-sided':
                if 'iflags' in r:
                    del r['iflags']
                else:
                    r['iflags'] = 0
            elif change == 'xattrs_unknown':
                for k in ('caps', 'xattrs', 'xattrs_sha256'):
                    r.pop(k, None)
                r['xattrs_unknown'] = True
            return t, a
        try_pair(w, rng, 'the root: ' + change, build)

    # Entries that sort before "." come before the root in the stream, but
    # their device relation, the header and their one-sided outcome all
    # depend on the root.
    early = [n for n in NAMES if n < b'.']
    for how in ('root-unreadable', 'root-unstable', 'flip', 'remount', 'remount-flip'):
        def build(rng, how=how):
            t = Tree(rng)
            for n in rng.sample(early, 4):
                t.e[n] = new_entry(rng, t, n, rng.choice(['reg', 'dir', 'lnk', 'fifo']))
            grow(t, rng, rng.randrange(0, 5))
            a = t.copy()
            first = [p for p in a.e if p < b'.']
            if how == 'root-unreadable':
                a.e[b'.'].pop('unstable', None)
                a.e[b'.']['unreadable'] = True
            elif how == 'root-unstable':
                a.e[b'.']['unstable'] = True
                for p in rng.sample(first, 2):
                    if p in a.e:
                        del a.e[p]
                        a.drop_below(p)
            elif how == 'flip':
                p = rng.choice(first)
                a.e[p]['dev'] = other_dev(a, rng) if a.e[p]['dev'] == a.root_dev() else \
                    a.root_dev()
            else:
                old, new = remount(a, rng, renumber_ino=True)
                if how == 'remount-flip':
                    p = rng.choice(first)
                    a.e[p]['dev'] = old if a.e[p]['dev'] == new else new
            fix(a, rng)
            return t, a
        for _ in range(2):
            try_pair(w, rng, 'names before ".": ' + how, build)

    # The nearest recorded ancestor on the lacking side is not a directory
    # (even a mount root: only a *directory* carrying mount seals), or is a
    # plain directory below an unstable one.
    for how in ('reg', 'fifo', 'reg-mount', 'lnk', 'below-unstable'):
        def build(rng, how=how):
            t = base_tree(rng, rng.randrange(0, 4))
            d = place(rng, t, 'dir', extras=False)
            if d is None:
                return None
            t.e[d['path']] = d
            if how == 'below-unstable':
                d['unstable'] = True
                sub = new_entry(rng, t, d['path'] + b'/p', 'dir', extras=False)
                t.e[sub['path']] = sub
                for q in (b'/p/f', b'/p/g', b'/q'):
                    t.e[d['path'] + q] = new_entry(rng, t, d['path'] + q, 'reg')
                a = t.copy()
                del a.e[d['path'] + b'/p/f']        # removed: its parent p is plain
                del a.e[d['path'] + b'/q']          # unknown: its parent is unstable
                return t, a
            for _ in range(rng.randrange(1, 4)):
                p = fresh_path(t, rng, parent=d['path'])
                if p:
                    t.e[p] = new_entry(rng, t, p, rng.choice(['reg', 'dir', 'fifo']))
            fix(t, rng)
            a = t.copy()
            a.drop_below(d['path'])
            e2 = change_type(a.e[d['path']], how.split('-')[0], a, rng)
            if e2 is None:
                return None
            if how == 'reg-mount':
                e2 = in_context('mount', e2, a, rng)
            a.e[d['path']] = e2
            fix(a, rng)
            return t, a
        for _ in range(2):
            try_pair(w, rng, 'one-sided below: ' + how, build)

    # Every name: before ".", between "a" and "a/", escaped, not UTF-8.
    for _ in range(3):
        def build(rng):
            t = Tree(rng)
            for n in NAMES:
                t.e[n] = new_entry(rng, t, n, rng.choice(['reg', 'dir', 'lnk', 'fifo']))
            fix(t, rng)
            for n in (b'a', b'a.', b'\xff\xfe', b'!x'):
                if t.e.get(n, {}).get('type') == 'dir' and not t.e[n].get('unreadable') and \
                        not t.e[n].get('mount'):
                    for m in rng.sample(NAMES, 4):
                        p = n + b'/' + m
                        t.e[p] = new_entry(rng, t, p, rng.choice(['reg', 'dir', 'lnk']))
            fix(t, rng)
            a = t.copy()
            mutate_random(a, rng, rng.randrange(2, 8))
            return t, a
        try_pair(w, rng, 'every name', build)

# ---------------------------------------------------------------------------
# Random pairs.

OPS = ['add', 'add', 'remove', 'content', 'size', 'mode', 'uid', 'gid', 'ino', 'dev', 'nlink',
       'ctime', 'mtime', 'type', 'flag', 'flag', 'unflag', 'iflags', 'caps', 'xattrs',
       'xattrs_sha256', 'xattrs_unknown', 'stored', 'limit', 'root_unstable', 'root_unreadable',
       'link', 'rdev', 'seal', 'unseal', 'remount', 'vanished']
RANDOM_FLAGS = ['raced', 'unstable', 'unverified', 'unreadable', 'mount', 'xattrs_unknown']


def mutate_random(t, rng, nops):
    for _ in range(nops):
        op = rng.choice(OPS)
        paths = [p for p in t.e if p != b'.']
        root = t.e[b'.']
        if op == 'add':
            grow(t, rng, rng.randrange(1, 3))
        elif op == 'limit':
            t.limit = rng.choice(LIMITS)
        elif op == 'vanished':
            t.vanished = rng.choice([0, 1, 3])
        elif op == 'root_unstable':
            root.pop('unreadable', None)
            root.pop('raced', None)
            root['unstable'] = True
        elif op == 'root_unreadable':
            if rng.random() < 0.2:
                root.pop('unstable', None)
                root['unreadable'] = True
        elif op == 'remount':
            remount(t, rng, renumber_ino=rng.random() < 0.5)
        elif not paths:
            continue
        else:
            p = rng.choice(paths)
            e = t.e[p]
            typ = e['type']
            if op == 'remove':
                del t.e[p]
                t.drop_below(p)
            elif op == 'content' and 'sha256' in e:
                e['sha256'] = hexs(rng)
            elif op == 'size':
                e['size'] = rng.choice([0, 1, 99, 1001, 5000, t.limit, t.limit + 1])
            elif op == 'mode':
                e['mode'] = (e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777)
            elif op in ('uid', 'gid'):
                e[op] = other(rng, IDS, e[op])
            elif op in ('ino', 'nlink'):
                e[op] += rng.randrange(1, 5)
            elif op in ('ctime', 'mtime'):
                e[op + '_ns'] += rng.randrange(1, 10 ** 9)
            elif op == 'dev':
                e['dev'] = other_dev(t, rng) if e['dev'] == t.root_dev() else t.root_dev()
            elif op == 'type':
                t.e[p] = new_entry(rng, t, p, other(rng, TYPE_NAMES, typ))
                t.drop_below(p)
            elif op == 'flag':
                e[rng.choice(RANDOM_FLAGS)] = True
            elif op == 'unflag':
                for k in RANDOM_FLAGS:
                    e.pop(k, None)
            elif op == 'iflags':
                if 'iflags' in e and rng.random() < 0.5:
                    del e['iflags']
                else:
                    e['iflags'] = rng.choice(IFLAGS)
            elif op == 'caps':
                if 'caps' in e and rng.random() < 0.5:
                    del e['caps']
                else:
                    e['caps'] = caps_hex(rng)
            elif op == 'xattrs':
                e.pop('xattrs_sha256', None)
                if 'xattrs' in e and rng.random() < 0.4:
                    del e['xattrs']
                else:
                    e['xattrs'] = xattr_set(rng)
            elif op == 'xattrs_sha256':
                e.pop('xattrs', None)
                e['xattrs_sha256'] = hexs(rng)
            elif op == 'xattrs_unknown':
                if e.pop('xattrs_unknown', None) is None:
                    e['xattrs_unknown'] = True
            elif op == 'stored':
                if 'stored' in e:
                    del e['stored']
                elif 'sha256' in e:
                    e['stored'] = e['sha256']
            elif op == 'link' and typ == 'lnk':
                e['link_target'] = rng.choice(INSIDE_TARGETS) if rng.random() < 0.7 else \
                    outside_target(rng, p)
            elif op == 'rdev' and 'rdev' in e:
                e['rdev'] = other(rng, RDEVS, e['rdev'])
            elif op == 'seal' and typ == 'dir':
                e[rng.choice(['unreadable', 'mount'])] = True
                e.pop('unstable', None)
                t.drop_below(p)
            elif op == 'unseal':
                e.pop('unreadable', None)
                e.pop('mount', None)
        fix(t, rng)


def randomized(w, rng, n):
    for i in range(n):
        base = Tree(rng)
        grow(base, rng, rng.randrange(3, 40))
        if rng.random() < 0.3:
            with_mounts(rng, base, rng.randrange(1, 3))
        variants = [base]
        for _ in range(4):
            v = base.copy()
            mutate_random(v, rng, rng.randrange(1, 6))
            variants.append(v)
        for x, b in enumerate(variants):
            for y, a in enumerate(variants):
                if x != y and rng.random() > 0.5:
                    continue
                w.pair(b, a, 'random base %d: variant %d -> %d' % (i, x, y))


def refusals(w, rng):
    for sb, sa in [(b'/scope', b'/scope2'), (b'/scope', b'/'), (b'/home/u/proj',
                                                                  b'/home/u/proj/sub'),
                   (b'/a/b', b'/a/c'), (b'/scope', b'/sc\xffope'), (b'/sc\xffope', b'/sc\xfeope')]:
        t = Tree(rng, scope=sb)
        for _ in range(rng.randrange(0, 6)):    # no symlinks: a scope of "/" has no outside
            e = place(rng, t, rng.choice(['reg', 'dir', 'fifo']))
            if e:
                t.e[e['path']] = e
        fix(t, rng)
        a = t.copy()
        a.scope = sa
        w.refusal(t, a, 'scopes %r and %r' % (sb, sa))


def main():
    out, n, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    os.makedirs(out, exist_ok=True)
    rng = random.Random(seed)
    w = Writer(out)
    cells(w, rng)
    field_pairs(w, rng)
    type_changes(w, rng)
    optional_one_sided(w, rng)
    scenarios(w, rng)
    randomized(w, rng, n)
    refusals(w, rng)
    print(w.k)


if __name__ == '__main__':
    main()
