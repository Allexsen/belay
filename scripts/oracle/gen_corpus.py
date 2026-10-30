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
    chmod+chown, setcap, ...); every type change, raced on both sides or on
    one; every optional field present on one side only; and the scenarios:
    dev relation, scope remounts, timestamps on fifo/sock/blk/chr, on mount
    roots and a directory's own, iflags on one side, caps/xattrs under
    xattrs_unknown and beside a mount root, an xattr set inline against
    its digest (the same set and another), O1 with and without a size
    change, hash limits, sealing and unsealing directories, unstable
    listings, one-sided paths below raced and plain non-directories,
    one-sided raced entries, the trailer's walk counts, the root itself,
    names sorting before ".", non-UTF-8 and escaped names;
  - random pairs: n-bases random trees, each with four mutated variants
    (several changes at once), compared in both directions and with
    themselves;
  - refusal pairs: different scopes.

The targeted pairs are DETERMINISTIC in what they hold. Each is built once,
with no retries: its builder cannot fail (a tree's hash limit is chosen for
the change it must hold, an entry is placed in the root, which is always
open, a new value is made to differ by construction), and the combinations
the frozen format cannot hold are left out by stated rules (*_feasible),
never by trying. Each targeted pair is written both ways round and checked,
with compare.py's own coverage code, to show what it was built for (its cell,
field pair, optional field or scenarios); then the targeted pairs ALONE must
pass compare.py's whole coverage gate. Anything else stops the generator
with an error naming the pair or what is missing. So no required case
depends on the seed or on the random pairs, which add variety only. The
same seed gives the same corpus, byte for byte.
Nothing here comes from the generated spec tables or from the C code.
"""
import base64, copy, hashlib, json, os, random, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
MANIFEST_PIN = os.path.join(REPO, 'test', 'expect', 'manifest-v1.md')
FIELDS_PIN = os.path.join(REPO, 'test', 'expect', 'diff-fields.md')
sys.path.insert(0, HERE)
import compare      # the coverage gate: what a pair shows, and what is required


def die(msg):
    raise SystemExit('gen_corpus: ' + msg)

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
POSITIVE_LIMITS = [l for l in LIMITS if l > 0]   # a hashed file can take another size within these
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
    """A path no entry of t has, below `parent` or below a random open
    directory. None only when there is no open directory (a random tree whose
    root is sealed); otherwise it cannot fail: a few random names first, for
    variety, then the first free one of n0, n1, ..."""
    dirs = [parent] if parent is not None else [d for d in t.open_dirs() if len(d) < 150]
    if not dirs:
        return None
    par = rng.choice(dirs)
    join = lambda n: n if par == b'.' else par + b'/' + n
    for _ in range(8):
        name = rng.choice(NAMES)
        if rng.random() < 0.3:
            name += b'%d' % rng.randrange(10)
        if join(name) not in t.e:
            return join(name)
    i = 0
    while join(b'n%d' % i) in t.e:
        i += 1
    return join(b'n%d' % i)


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
        self.targeted_stems = []        # which alone must pass the coverage gate

    def pair(self, b, a, label):
        assert b.scope == a.scope
        for t in (b, a):
            v = violations(t)
            if v:
                die('generator bug (%s): %s' % (label, v[:5]))
        stem = os.path.join(self.out, 'pair-%05d' % self.k)
        write_manifest(b, stem + '.before')
        write_manifest(a, stem + '.after')
        with open(stem + '.label', 'w', encoding='utf-8') as f:
            f.write(label + '\n')
        self.k += 1
        return stem

    def both_ways(self, b, a, label):
        return [self.pair(b, a, label), self.pair(a, b, label + ' (reversed)')]

    def targeted(self, rng, label, build, cells=(), pairs=(), optional=(), scenarios=()):
        """One targeted pair: built ONCE -- no retries; build(rng) is written
        so that it cannot fail -- written both ways round, and checked to show
        what it was built for, as compare.py's coverage gate sees it: its
        (field, type) cells, (type, field, field) pairs, optional fields
        present on one side only, and named scenarios. Anything else stops
        the generator, naming the pair."""
        unknown = [s for s in scenarios if s not in compare.SCENARIOS]
        if unknown:
            die('%r names scenarios the gate does not have: %s' % (label, unknown))
        r = build(rng)
        if r is None:
            die('could not build the targeted pair %r' % label)
        stems = self.both_ways(r[0], r[1], label)
        self.targeted_stems += stems
        cov = compare.coverage(stems)
        want = ([('cell', c) for c in cells] + [('field pair', p) for p in pairs]
                + [('optional', f) for f in optional] + [('scenario', s) for s in scenarios])
        lacking = [x for x in want if not cov[x[0]][x[1]]]
        if lacking:
            die('the pair built for %r (%s) does not show %s' % (label, stems[0], lacking))

    def check_gate(self):
        """compare.py's whole coverage gate, over the targeted pairs alone."""
        missing, impossible = compare.gate(compare.coverage(self.targeted_stems))
        if missing or impossible:
            die('the targeted pairs alone do not pass the coverage gate: missing %s; cells '
                'the format cannot hold: %s' % (missing, impossible))

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
# Targeted pairs. Each is built once, by Writer.targeted, which checks what it
# shows; every builder below cannot fail on a combination its *_feasible rule
# admits, and those rules exclude only what the frozen format cannot hold.

CONTEXTS = ['plain', 'offdev', 'mount', 'xattrs_unknown', 'unverified', 'unstable',
            'unreadable', 'raced']
# The entry types each context can hold: a bare `unverified` only on reg
# (manifest-v1 rule 5, header 1), `unstable` only on reg and dir (rules 12,
# 13), `unreadable` only on reg, dir and lnk (rule 13).
CONTEXT_TYPES = {'plain': TYPE_NAMES, 'offdev': TYPE_NAMES, 'mount': TYPE_NAMES,
                 'xattrs_unknown': TYPE_NAMES, 'unverified': ['reg'],
                 'unstable': ['reg', 'dir'], 'unreadable': ['reg', 'dir', 'lnk'],
                 'raced': TYPE_NAMES}
ATTRS = ('iflags', 'caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown')
TS = ('mtime_ns', 'ctime_ns')


def other_dev(t, rng, avoid=()):
    return rng.choice([d for d in OTHER_DEVS if d != t.root_dev() and d not in avoid])


def letters(rng, n):
    return bytes(rng.choice(b'abcdefgh') for _ in range(n))


def unlike(new, old):
    """new, its last character changed if it happens to equal old."""
    if new != old:
        return new
    if isinstance(new, str):
        return new[:-1] + ('0' if new[-1:] != '0' else '1')
    return new[:-1] + (b'a' if new[-1:] != b'a' else b'b')


def base_tree(rng, n=None, **kw):
    """A tree for a targeted pair. Its root is open (grow() flags only the
    entries it adds), so an entry can always be placed in it."""
    t = Tree(rng, **kw)
    grow(t, rng, rng.randrange(0, 7) if n is None else n)
    return t


def place(rng, t, typ, extras=True, parent=None):
    p = fresh_path(t, rng, parent)
    return None if p is None else new_entry(rng, t, p, typ, extras)


def subject(rng, t, typ, extras=True, parent=None):
    """A new entry for a targeted pair, at a path no entry of t has (not yet
    in t: the caller puts it there)."""
    e = place(rng, t, typ, extras, parent)
    if e is None:
        die('a targeted tree with no open directory')
    return e


def with_subject(t, e, e2):
    """The pair: t holding e, and a later copy of t holding e2 at e's path."""
    if e is None or e2 is None:
        return None
    a = t.copy()
    t.e[e['path']], a.e[e['path']] = e, e2
    return t, a


def size_limit(rng):
    """A hash limit within which a hashed file can take another size (0
    cannot): a tree's limit, chosen for a change of size."""
    return rng.choice(POSITIVE_LIMITS)


def hashed(e, t, rng, least=0):
    """The regular file e, hashed: within the limit (and at least `least`
    bytes), no flag that rules a hash out, nothing stored."""
    e['size'] = max(least, min(e['size'], t.limit))
    if e['size'] > t.limit:
        die('a limit of %d holds no hashed file of %d bytes' % (t.limit, least))
    for k in ('unstable', 'unreadable', 'mount', 'stored'):
        e.pop(k, None)
    settle_hash(e, t, rng)
    return e


def clear_flags(e, t, rng):
    """e with no flag of the diff pin: its attributes read, nothing unstable,
    unreadable, mounted or raced, a regular file hashed."""
    for k in compare.ref.FLAGS:
        e.pop(k, None)
    if e['type'] == 'reg':
        hashed(e, t, rng)
    return e


def unflagged_tree(rng):
    """A tree in which no entry carries a flag of the diff pin."""
    t = Tree(rng)
    for _ in range(rng.randrange(2, 9)):
        e = subject(rng, t, random_type(rng))
        t.e[e['path']] = clear_flags(e, t, rng)
    clear_flags(t.e[b'.'], t, rng)
    return t


def in_context(ctx, e, t, rng):
    """The entry as it is in one context, the same on both sides; None for a
    type the context cannot hold (CONTEXT_TYPES)."""
    e, typ = copy.deepcopy(e), e['type']
    if typ not in CONTEXT_TYPES[ctx]:
        return None
    if ctx == 'offdev':
        e['dev'] = other_dev(t, rng)
    elif ctx == 'mount':
        for k in ATTRS + ('sha256', 'stored', 'unstable', 'unreadable'):
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
        e['size'] = t.limit + 1 + rng.randrange(1000)
        for k in ('sha256', 'stored'):
            e.pop(k, None)
        e['unverified'] = True
    elif ctx in ('unstable', 'unreadable'):
        if typ == 'reg':
            for k in ('sha256', 'stored'):
                e.pop(k, None)
            e['unverified'] = True
        elif typ == 'lnk':                     # unreadable
            e.pop('target_outside_scope', None)
            if rng.random() < 0.4:
                e['link_target'] = b''          # "target unknown"; size stays as stat'ed
        e[ctx] = True
    elif ctx == 'raced':
        e['raced'] = True
        if typ == 'dir':                        # rule 10
            e['unreadable'] = True
    return e


VARIANTS = {'dev': ['flip', 'renumber'], 'caps': ['change', 'add', 'drop'],
            'xattrs': ['change', 'add', 'drop'], 'link_target': [None, 'non-utf8']}


def cell_feasible(f, typ, ctx, var):
    """Whether the frozen format holds a pair where only f differs, on a typ
    in context ctx: what it cannot hold is excluded here, by rule, never by
    trying."""
    if typ not in CONTEXT_TYPES[ctx]:
        return False
    if f == 'size' and typ == 'lnk':
        return ctx == 'unreadable'             # rule 19: else the size is the target's length
    if f == 'dev' and var == 'renumber':
        return ctx in ('offdev', 'mount')      # renumbered while off the root's device
    if f in ('iflags', 'caps', 'xattrs') and ctx == 'mount':
        return False                           # rule 22
    if f in ('caps', 'xattrs') and ctx == 'xattrs_unknown':
        return False                           # rule 3
    if f == 'caps':
        return typ == 'reg'                    # rule 4
    if f == 'sha256':                          # a hash: rules 5, 6, 21
        return typ == 'reg' and ctx in ('plain', 'offdev', 'xattrs_unknown', 'raced')
    if f == 'rdev':
        return typ in ('blk', 'chr')           # rule 15
    if f == 'link_target':
        return typ == 'lnk'                    # rule 16
    return True


def prepare(f, var, e, t, rng):
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
    elif f == 'sha256' and e['type'] == 'reg':
        hashed(e, t, rng)
    return e


def new_target(rng, e, var):
    """Another target for the symlink e: the same length (rule 19 ties the
    size to it unless the link is unreadable) on the same side of the scope
    (header 2 ties target_outside_scope to it). `non-utf8`: its last byte is
    0xff, which ends no UTF-8 string."""
    tg = e['link_target']
    if e.get('unreadable'):                     # target unknown or stale: any other one
        new = letters(rng, max(len(tg), 1))
    elif e.get('target_outside_scope'):
        if tg.startswith(b'/'):                 # absolute: no scope starts with these letters
            new = b'/' + letters(rng, len(tg) - 1)
        else:                                   # the same leading `..`s, other names after them
            comps, ups = tg.split(b'/'), 0
            while comps[ups] == b'..':
                ups += 1
            rest = b'/'.join(comps[ups:])
            new = b'../' * ups + bytes(c if c == 0x2f else rng.choice(b'abcdefgh') for c in rest)
    else:                                       # inside: a plain name
        new = letters(rng, len(tg))
    if var == 'non-utf8':
        new = new[:-1] + b'\xff'
    return unlike(new, tg)


def mutate(f, var, e, t, rng):
    """e with only field f changed, validity kept; a new value differs by
    construction. None only where the format cannot hold the change at all,
    which cell_feasible() excludes before."""
    e2, typ = copy.deepcopy(e), e['type']
    if f == 'mode':
        e2['mode'] = (e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777)
    elif f in ('uid', 'gid'):
        e2[f] = other(rng, IDS, e[f])
    elif f == 'size':
        if typ == 'reg' and 'sha256' in e:      # within the limit: size_limit() leaves room
            c = [s for s in {0, 1, t.limit // 2, t.limit} if s != e['size'] and s <= t.limit]
        elif typ == 'reg' and not any(e.get(k) for k in ('unstable', 'unreadable', 'mount')):
            c = [t.limit + 1 + i for i in (0, 5, 999) if t.limit + 1 + i != e['size']]
        elif typ == 'lnk' and not e.get('unreadable'):
            c = []                              # rule 19: the size is the target's length
        else:
            c = [s for s in (0, 1, 4096, 123456) if s != e['size']]
        if not c:
            return None
        e2['size'] = rng.choice(sorted(c))
    elif f in TS:
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
            e2['caps'] = unlike(caps_hex(rng), e['caps'])
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
            if new == e['xattrs']:              # one value made to differ
                n, v = new[-1].split('=', 1)
                new[-1] = '%s=%s' % (n, unlike(v, v))
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
        e2['sha256'] = unlike(hexs(rng), e['sha256'])
    elif f == 'rdev':
        if 'rdev' not in e:
            return None
        e2['rdev'] = other(rng, RDEVS, e['rdev'])
    elif f == 'link_target':
        if typ != 'lnk':
            return None
        e2['link_target'] = new_target(rng, e, var)
    else:
        die('no mutation for field %r (the pin grew a row?)' % f)
    return e2


def cells(w, rng):
    """Every field (the required ones, and every compared optional one) x every
    type x every context the format can hold it in: only that field of one
    entry differs. Each pair must show its (field, type) cell."""
    fields = REQUIRED_FIELDS + [f for f in CELL_FIELDS
                                if f not in REQUIRED_FIELDS and f != 'type']
    for f in fields:
        for typ in TYPE_NAMES:
            for ctx in CONTEXTS:
                for var in VARIANTS.get(f, [None]):
                    if not cell_feasible(f, typ, ctx, var):
                        continue
                    def build(rng, f=f, typ=typ, ctx=ctx, var=var):
                        t = base_tree(rng, limit=size_limit(rng) if f == 'size' else None)
                        e = in_context(ctx, prepare(f, var, subject(rng, t, typ), t, rng), t, rng)
                        return with_subject(t, e, e and mutate(f, var, e, t, rng))
                    scen = []
                    if f in TS and ctx == 'mount':
                        scen.append('only %s differs on a mount root' % f)
                    if var == 'non-utf8':
                        scen.append('a non-UTF-8 link target that differs')
                    w.targeted(rng, 'only %s differs on a %s (%s%s)' %
                               (f, typ, ctx, ', ' + var if var else ''), build,
                               cells=[(f, typ)], scenarios=scen)


PAIR_VARIANT = {'dev': 'flip', 'caps': 'change', 'xattrs': 'change'}


def field_pairs(w, rng):
    """Every two compared fields of one entry differing together, on every
    type: the order of `changed` for every pair of fields. A symlink's size
    moves alone only when the link is unreadable (rule 19), and with its
    target through a target of another length."""
    for typ in TYPE_NAMES:
        fs = [f for f in CELL_FIELDS if f not in ('type', 'ctime_ns') and typ in CELL_FIELDS[f]
              and not (f == 'caps' and typ != 'reg')]          # manifest-v1 rule 4
        for i, f1 in enumerate(fs):
            for f2 in fs[i + 1:]:
                both = {f1, f2}
                ctx = 'unreadable' if typ == 'lnk' and 'size' in both and \
                    'link_target' not in both else 'plain'
                def build(rng, typ=typ, f1=f1, f2=f2, ctx=ctx):
                    v1, v2 = PAIR_VARIANT.get(f1), PAIR_VARIANT.get(f2)
                    t = base_tree(rng, limit=size_limit(rng) if 'size' in (f1, f2) else None)
                    e = prepare(f2, v2, prepare(f1, v1, subject(rng, t, typ), t, rng), t, rng)
                    e = in_context(ctx, e, t, rng)
                    if {f1, f2} == {'size', 'link_target'}:
                        e2 = dict(e, link_target=e['link_target'] + b'x',
                                  size=len(e['link_target']) + 1)
                    else:
                        e2 = mutate(f1, v1, e, t, rng)
                        e2 = e2 and mutate(f2, v2, e2, t, rng)
                    return with_subject(t, e, e2)
                w.targeted(rng, 'only %s and %s differ on a %s (%s)' % (f1, f2, typ, ctx), build,
                           pairs=[(typ, f1, f2)])

    # And a few changes as tools make them (variety; a field the entry cannot
    # change is left alone).
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
                e = subject(rng, t, typ)
                for f in fields:
                    e = prepare(f, PAIR_VARIANT.get(f), e, t, rng)
                e2 = e
                for f in fields:
                    e2 = mutate(f, PAIR_VARIANT.get(f), e2, t, rng) or e2
                return with_subject(t, e, e2)
            three = name == 'chmod+chown' and typ == 'reg'      # mode, uid and gid always move
            w.targeted(rng, '%s on a %s' % (name, typ), build,
                       scenarios=['three or more compared fields differ on one entry'] if three
                       else [])


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


def type_change_feasible(t1, t2, ctx):
    """Whether a t1 in context ctx can become a t2 keeping its flags."""
    if t1 not in CONTEXT_TYPES[ctx]:
        return False
    if ctx == 'unreadable':
        return t2 in CONTEXT_TYPES['unreadable']     # rule 13
    if ctx == 'raced' and t2 == 'dir' and t1 != 'dir':
        return False        # rule 10: a raced directory is unreadable or a mount; this one is neither
    if ctx == 'raced' and t1 == 'dir' and t2 in SPECIAL:
        return False        # the raced directory is unreadable, which these cannot be (rule 13)
    return True


def type_changes(w, rng):
    """Every type change in every context the format can hold it in, the
    flags the same on both sides; in two of them also with iflags read on one
    side only (across a type change no field is compared, so it adds no
    reason, raced or not)."""
    for t1 in TYPE_NAMES:
        for t2 in TYPE_NAMES:
            if t1 == t2:
                continue
            for ctx in ('plain', 'offdev', 'xattrs_unknown', 'raced', 'mount', 'unreadable'):
                if not type_change_feasible(t1, t2, ctx):
                    continue
                for one in ((False, True) if ctx in ('plain', 'raced') else (False,)):
                    def build(rng, t1=t1, t2=t2, ctx=ctx, one=one):
                        t = base_tree(rng)
                        e = in_context(ctx, subject(rng, t, t1), t, rng)
                        e2 = change_type(e, t2, t, rng)
                        if one and e2 is not None:
                            e = dict(e, iflags=e.get('iflags', 16))
                            e2.pop('iflags', None)
                        return with_subject(t, e, e2)
                    scen = ['a type change']
                    if ctx == 'raced':
                        scen.append('a raced type change, raced on both sides')
                    if one:
                        scen.append('a raced type change, iflags on one side only' if ctx == 'raced'
                                    else 'a type change, iflags on one side only')
                    opt = [f for f, ts in (('rdev', ('blk', 'chr')), ('link_target', ('lnk',)))
                           if (t1 in ts) != (t2 in ts)]
                    w.targeted(rng, 'type %s -> %s (%s%s)' % (t1, t2, ctx,
                               ', iflags on one side' if one else ''), build,
                               cells=[('type', t1)], optional=opt, scenarios=scen)


def raced_type_changes(w, rng):
    """A type change with `raced` on one side only (written both ways round:
    the after side, then the before side), with iflags on neither side, on
    the raced side only or on the other side only. Rule 1 comes before rule
    2: `unknown`, reason `raced`, and across a type change no field is
    compared, so no iflags_unknown. A regular file on the side that did not
    race is hashed, so that no other flag gives a reason: reg {iflags,
    sha256} -> lnk {raced} is `unknown`, `changed` ["type"], `unknown`
    ["raced"] (the reviewer's case)."""
    for t1 in TYPE_NAMES:
        for t2 in TYPE_NAMES:
            if t1 == t2:
                continue
            for where in (None, 'raced', 'other'):
                def build(rng, t1=t1, t2=t2, where=where):
                    t = base_tree(rng)
                    e = subject(rng, t, t1)
                    if t1 == 'reg':
                        hashed(e, t, rng)
                    e.pop('xattrs_unknown', None)
                    e.pop('iflags', None)
                    e2 = change_type(e, t2, t, rng)
                    if e2 is None:
                        return None
                    e2['raced'] = True
                    if t2 == 'dir':
                        e2['unreadable'] = True      # rule 10
                    if where == 'raced':
                        e2['iflags'] = rng.choice(IFLAGS)
                    elif where == 'other':
                        e['iflags'] = rng.choice(IFLAGS)
                    return with_subject(t, e, e2)
                suffix = {None: '', 'raced': ', iflags on the raced side only',
                          'other': ', iflags on the other side only'}[where]
                w.targeted(rng, 'type %s -> %s, raced after only%s' % (t1, t2, suffix), build,
                           cells=[('type', t1)],
                           scenarios=['a raced type change, raced %s only%s' % (s, suffix)
                                      for s in ('after', 'before')])


def one_sided_feasible(f, var, typ, ctx):
    """Whether the format holds f on one side only, on a typ in context ctx,
    built as one_sided_build() builds it."""
    if typ not in CONTEXT_TYPES[ctx] or ctx == f or (ctx == 'xattrs_unknown' and f in ATTRS):
        return False
    if ctx == 'mount' and f in ATTRS:
        return False                                    # rule 22
    if f == 'caps':
        return typ == 'reg'                             # rule 4
    if f in ('sha256', 'stored'):                       # a hashed file: rules 5, 6, 21
        return typ == 'reg' and ctx in ('plain', 'offdev', 'raced', 'xattrs_unknown') and \
            not (var == 'mount' and ctx == 'xattrs_unknown')       # rule 22 on the mount side
    if f == 'unstable':
        if typ == 'dir':
            return ctx in ('plain', 'offdev', 'xattrs_unknown')    # rule 11 (raced: unreadable)
        return typ == 'reg' and ctx not in ('unreadable', 'mount')  # rules 7, 8, 12, 13
    if f == 'unreadable':
        if typ == 'dir':
            return ctx in ('plain', 'offdev', 'xattrs_unknown')    # rule 11
        return typ == 'lnk' or (typ == 'reg' and ctx != 'mount')   # rules 8, 13
    if f == 'mount':
        if ctx == 'xattrs_unknown':
            return False                                # rule 22
        if typ in ('reg', 'dir') and ctx == 'unreadable':
            return False                                # rules 8, 11
        return not (typ == 'dir' and ctx == 'raced')    # rule 11: the raced dir is unreadable
    if f == 'raced':
        return typ != 'dir' or ctx in ('unreadable', 'mount')       # rule 10
    if f == 'target_outside_scope':
        return typ == 'lnk' and ctx != 'unreadable'                # header 2
    return True


def one_sided_build(f, var, typ, ctx):
    """A builder for: optional field f present on one side only. The base
    entry `e` lacks f (and whatever f excludes); `w_` is e plus f, plus only
    what the rules force to change with it."""
    def build(rng):
        t = base_tree(rng, limit=size_limit(rng) if f in ('sha256', 'stored') else None)
        e = subject(rng, t, typ)
        strip = set()
        if f in ('iflags', 'caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown', 'stored',
                 'unstable', 'unreadable', 'mount', 'raced', 'target_outside_scope'):
            strip.add(f)
        if f in ('caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown'):
            strip |= {'caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown'}
        if f == 'mount' or var == 'mount':      # rule 22, and 14/21 through sha256
            strip |= set(ATTRS) | {'stored'}
        for k in sorted(strip):
            e.pop(k, None)
        if f in ('sha256', 'stored'):           # hashed, at least 1 byte (`limit` goes below it)
            hashed(e, t, rng, least=1)
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
            e['link_target'] = letters(rng, len(out))
            e['size'] = len(out)
            w_['link_target'], w_['size'], w_['target_outside_scope'] = out, len(out), True
        elif f == 'sha256':                     # the other side unverified (rule O1)
            if typ != 'reg' or 'sha256' not in e:
                return None
            for k in ('sha256', 'stored'):
                w_.pop(k, None)
            w_['unverified'] = True
            if var in ('limit', 'limit+size'):  # the other manifest's limit is lower
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


ONE_SIDED_PLAN = {'iflags': [None], 'caps': [None], 'xattrs': [None, 'vs-digest'],
                  'xattrs_sha256': [None, 'vs-inline'], 'xattrs_unknown': ['bare', 'attrs'],
                  'sha256': ['limit', 'limit+size', 'unstable', 'unreadable', 'mount'],
                  'stored': [None], 'unstable': [None], 'unreadable': [None], 'mount': [None],
                  'raced': [None], 'target_outside_scope': [None]}


def optional_one_sided(w, rng):
    # `unverified` is sha256's other side (rule 5); `rdev` and `link_target`
    # are present on one side only exactly when the type changes.
    for f in OPTIONAL_FIELDS:
        if f in ('unverified', 'rdev', 'link_target'):
            continue
        if f not in ONE_SIDED_PLAN:
            die('no one-sided plan for optional field %r' % f)
        for var in ONE_SIDED_PLAN[f]:
            for typ in TYPE_NAMES:
                for ctx in ('plain', 'offdev', 'unverified', 'raced', 'xattrs_unknown',
                            'unreadable', 'mount'):
                    if not one_sided_feasible(f, var, typ, ctx):
                        continue
                    scen = []
                    if f == 'sha256':
                        scen.append('O1: hash on one side, unverified on the other, ' +
                                    ('size differs' if var == 'limit+size' else 'same size'))
                        if var.startswith('limit'):
                            scen.append('hash limits differ')
                    w.targeted(rng, '%s on one side only, %s (%s%s)' %
                               (f, typ, ctx, ', ' + var if var else ''),
                               one_sided_build(f, var, typ, ctx),
                               optional=[f], scenarios=scen)

# ---------------------------------------------------------------------------
# Scenarios.


def remount(t, rng, renumber_ino):
    """The scope remounted: every device number changes, none keeps its own,
    and the relations are kept (one number, one new number)."""
    old = t.root_dev()
    new = rng.choice([d for d in ROOT_DEVS + OTHER_DEVS if d != old])
    mapping, used = {old: new}, {old, new}
    for e in t.e.values():
        d = e['dev']
        if d not in mapping:
            free = [x for x in OTHER_DEVS + [d + 1000, d + 7] if x not in used and x != d]
            mapping[d] = rng.choice(free) if free else max(used | {d}) + 1
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
    # The scope remounted. Each tree holds a hashed regular file on the root's
    # device, nothing stored, and (with_mounts) at least one entry off it:
    # what a variant changes is always there.
    remounts = {'dev': ['scope remount: every entry renumbered'],
                'dev+ino': ['scope remount: every entry renumbered'],
                'flip-off': ['scope remount: an entry changes device relation'],
                'flip-on': ['scope remount: an entry changes device relation'],
                'content': ['scope remount: content differs by hash',
                            'scope remount: every entry renumbered'],
                'root-only': [],
                'mode': ['scope remount: every entry renumbered']}
    for variant, tags in remounts.items():
        def build(rng, variant=variant):
            t = base_tree(rng, rng.randrange(4, 14))
            with_mounts(rng, t, rng.randrange(1, 3))
            s = hashed(subject(rng, t, 'reg', parent=b'.'), t, rng)
            t.e[s['path']] = s
            off = [p for p, e in t.e.items() if e['dev'] != t.root_dev()]
            a = t.copy()
            old, new = remount(a, rng, renumber_ino=variant != 'dev')
            if variant == 'flip-off':           # stays behind: now off the root's device
                a.e[s['path']]['dev'] = old
            elif variant == 'flip-on':          # joins the root's new device
                a.e[rng.choice(off)]['dev'] = new
            elif variant == 'content':
                a.e[s['path']]['sha256'] = unlike(hexs(rng), s['sha256'])
            elif variant == 'root-only':        # only the root's number moved
                for p, e in a.e.items():
                    if p != b'.':
                        e['dev'], e['ino'] = t.e[p]['dev'], t.e[p]['ino']
            elif variant == 'mode':
                p = rng.choice(sorted(a.e))
                a.e[p]['mode'] = (a.e[p]['mode'] & S_IFMT) | \
                    other(rng, PERMS, a.e[p]['mode'] & 0o7777)
            return t, a
        for _ in range(3):
            w.targeted(rng, 'scope remount: ' + variant, build, scenarios=['scope remount'] + tags)

    # A device number changing while the relation stays (both off the root's
    # device), with the inode number changing too: neither is compared.
    for typ in TYPE_NAMES:
        def build(rng, typ=typ):
            t = base_tree(rng)
            e = subject(rng, t, typ)
            e['dev'] = other_dev(t, rng)
            return with_subject(t, e, dict(e, dev=other_dev(t, rng, avoid=(e['dev'],)),
                                           ino=e['ino'] + 5))
        w.targeted(rng, 'dev renumbered off-device, with a new ino, on a %s' % typ, build,
                   scenarios=['dev number changes, off the root device on both sides'])
        def build2(rng, typ=typ):                # relation flips and ino changes
            t = base_tree(rng)
            e = subject(rng, t, typ)            # on the root's device
            return with_subject(t, e, dict(e, dev=other_dev(t, rng), ino=e['ino'] + 5))
        w.targeted(rng, 'dev leaves the root device, with a new ino, on a %s' % typ, build2,
                   scenarios=['dev relation: an entry leaves the root device',
                              'dev relation: an entry joins the root device'])

    # Both timestamps at once, on every type and context.
    for typ in TYPE_NAMES:
        for ctx in ('plain', 'mount', 'raced', 'offdev', 'xattrs_unknown'):
            def build(rng, typ=typ, ctx=ctx):
                t = base_tree(rng)
                e = in_context(ctx, subject(rng, t, typ), t, rng)
                return with_subject(t, e, dict(e, mtime_ns=e['mtime_ns'] + 1,
                                               ctime_ns=e['ctime_ns'] + 1))
            w.targeted(rng, 'mtime and ctime on a %s (%s)' % (typ, ctx), build)

    # An entry that becomes a mount root, its timestamps now the mounted
    # filesystem's: a mount root on one side only (ambiguity A2).
    for typ in TYPE_NAMES:
        for same_dev in (False, True):
            def build(rng, typ=typ, same_dev=same_dev):
                t = base_tree(rng)
                e = subject(rng, t, typ)
                e2 = in_context('mount', e, t, rng)
                e2['mtime_ns'] += 7
                e2['ctime_ns'] += 9
                if same_dev:
                    e2['dev'] = e['dev']
                return with_subject(t, e, e2)
            w.targeted(rng, 'becomes a mount root with new timestamps: %s%s' %
                       (typ, ', same dev' if same_dev else ''), build,
                       scenarios=['a mount root on one side only, its timestamps differ'])

    # caps / xattrs against xattrs_unknown, alone and with another change.
    for typ in TYPE_NAMES:
        for extra in (None, 'mode', 'ctime', 'ino', 'content', 'iflags-one-sided'):
            if extra == 'content' and typ != 'reg':
                continue                            # a hash: only on a regular file
            def build(rng, typ=typ, extra=extra):
                t = base_tree(rng)
                e = subject(rng, t, typ)
                e.pop('xattrs_unknown', None)
                e.pop('xattrs_sha256', None)
                e['xattrs'] = xattr_set(rng)
                if typ == 'reg':
                    e['caps'] = caps_hex(rng)
                if extra == 'content':
                    hashed(e, t, rng)
                e2 = {k: v for k, v in e.items() if k not in ('caps', 'xattrs')}
                e2['xattrs_unknown'] = True
                if extra == 'mode':
                    e2['mode'] = (e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777)
                elif extra == 'ctime':
                    e2['ctime_ns'] += 1
                elif extra == 'ino':
                    e2['ino'] += 1
                elif extra == 'content':
                    e2['sha256'] = unlike(hexs(rng), e['sha256'])
                elif extra == 'iflags-one-sided':
                    e['iflags'] = 0
                    e2.pop('iflags', None)
                return with_subject(t, e, e2)
            w.targeted(rng, 'caps/xattrs vs xattrs_unknown on a %s%s' %
                       (typ, ', with ' + extra if extra else ''), build,
                       scenarios=['xattrs against xattrs_unknown'] +
                       (['caps against xattrs_unknown'] if typ == 'reg' else []))

    # iflags on one side only, with and without another change.
    for typ in TYPE_NAMES:
        for extra in (None, 'mode', 'ctime', 'content', 'unverified'):
            if extra == 'content' and typ not in ('reg', 'blk', 'chr'):
                continue                            # no content field to change alone
            if extra == 'unverified' and typ != 'reg':
                continue
            def build(rng, typ=typ, extra=extra):
                t = base_tree(rng)
                e = subject(rng, t, typ)
                e['iflags'] = rng.choice(IFLAGS)
                if extra == 'content' and typ == 'reg':
                    hashed(e, t, rng)
                e2 = {k: v for k, v in e.items() if k != 'iflags'}
                if extra == 'mode':
                    e2['mode'] = (e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777)
                elif extra == 'ctime':
                    e2['ctime_ns'] += 1
                elif extra == 'content' and typ == 'reg':
                    e2['sha256'] = unlike(hexs(rng), e['sha256'])
                elif extra == 'content':
                    e2['rdev'] = other(rng, RDEVS, e['rdev'])
                elif extra == 'unverified':
                    for k in ('sha256', 'stored'):
                        e2.pop(k, None)
                    e2['unverified'], e2['unstable'] = True, True
                return with_subject(t, e, e2)
            w.targeted(rng, 'iflags on one side only, %s%s' %
                       (typ, ', with ' + extra if extra else ''), build,
                       scenarios=['iflags on one side only on a ' + typ])

    # Hash limits that differ without changing what was hashed: no file is
    # bare unverified, and the other limit is still above every hashed one.
    def build(rng):
        t = base_tree(rng, rng.randrange(3, 12), limit=10 ** 9)
        for e in t.e.values():
            if e['type'] == 'reg' and e.get('unverified') and \
                    not any(e.get(k) for k in ('unstable', 'unreadable', 'mount')):
                hashed(e, t, rng)
        a = t.copy()
        a.limit = max([e['size'] for e in t.e.values() if 'sha256' in e] + [0]) + \
            rng.randrange(0, 2)
        if a.limit == t.limit:
            a.limit += 1
        return t, a
    for _ in range(3):
        w.targeted(rng, 'hash limits differ, every file within both', build,
                   scenarios=['hash limits differ'])

    # Sealing, unsealing and unstable listings; the directory always has a
    # child (the first one is placed in it).
    sealed = 'a directory sealed on one side, with entries below it on the other'
    seals = {'unreadable': [sealed], 'mount': [sealed], 'mount-offdev': [sealed],
             'unstable-missing': ['a child on one side only below an unstable directory'],
             'unstable-extra': [], 'unstable-same': [], 'root-unstable': [],
             'root-unreadable': [sealed]}
    for how, tags in seals.items():
        def build(rng, how=how):
            t = base_tree(rng, rng.randrange(0, 5))
            if how.startswith('root'):
                d = b'.'
            else:
                e = subject(rng, t, 'dir', extras=False)
                t.e[e['path']] = e
                d = e['path']
            for i in range(rng.randrange(1, 5)):
                p = fresh_path(t, rng, parent=d if i == 0 or rng.random() < 0.7 else None)
                t.e[p] = new_entry(rng, t, p, random_type(rng))
            fix(t, rng)
            a = t.copy()
            de = a.e[d]
            if how in ('unreadable', 'root-unreadable'):
                de.pop('unstable', None)
                de['unreadable'] = True
            elif how.startswith('mount'):
                for k in ATTRS:
                    de.pop(k, None)
                de['mount'] = True
                if how == 'mount-offdev':
                    de['dev'] = other_dev(a, rng)
            else:
                de['unstable'] = True
                kids = sorted(q for q in a.e if parent_of(q) == d and q != b'.')
                if how == 'unstable-missing':
                    victim = rng.choice(kids)
                    del a.e[victim]
                    a.drop_below(victim)
                elif how == 'unstable-extra':
                    p = fresh_path(a, rng, parent=d)
                    a.e[p] = new_entry(rng, a, p, random_type(rng))
            fix(a, rng)
            return t, a
        for _ in range(3):
            w.targeted(rng, 'directory: ' + how, build, scenarios=tags)

    # Entries present on one side only that carry raced.
    for typ in TYPE_NAMES:
        def build(rng, typ=typ):
            t = base_tree(rng)
            a = t.copy()
            e = subject(rng, a, typ)
            e['raced'] = True
            if typ == 'dir':
                e['unreadable'] = True
            fix_entry(e, a, rng)
            a.e[e['path']] = e
            return t, a
        w.targeted(rng, 'raced %s on one side only' % typ, build,
                   scenarios=['a raced entry on one side only'])

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
                new = xattr_set(rng)
                if new == t.e[b'.'].get('xattrs'):
                    n, v = new[-1].split('=', 1)
                    new[-1] = '%s=%s' % (n, unlike(v, v))
                r['xattrs'] = new
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
        w.targeted(rng, 'the root: ' + change, build)

    # Entries that sort before "." come before the root in the stream, but
    # their device relation, the header and their one-sided outcome all
    # depend on the root. Four of them are the root's own children.
    early = [n for n in NAMES if n < b'.']
    one_early = 'a path sorting before "." on one side only, the other root sealed or unstable'
    befores = {'root-unreadable': [one_early], 'root-unstable': [one_early],
               'flip': ['a path sorting before "." changes device relation'],
               'remount': ['a path sorting before "." in a remounted pair'],
               'remount-flip': ['a path sorting before "." in a remounted pair']}
    for how, tags in befores.items():
        def build(rng, how=how):
            t = Tree(rng)
            for n in rng.sample(early, 4):
                t.e[n] = new_entry(rng, t, n, rng.choice(['reg', 'dir', 'lnk', 'fifo']))
            grow(t, rng, rng.randrange(0, 5))
            a = t.copy()
            first = sorted(p for p in a.e if p < b'.' and b'/' not in p)
            if how == 'root-unreadable':
                a.e[b'.'].pop('unstable', None)
                a.e[b'.']['unreadable'] = True
            elif how == 'root-unstable':
                a.e[b'.']['unstable'] = True
                for p in rng.sample(first, 2):
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
            w.targeted(rng, 'names before ".": ' + how, build,
                       scenarios=['a path sorting before "."'] + tags)

    # The nearest recorded ancestor on the lacking side is not a directory
    # (even a mount root: only a *directory* carrying mount seals), or is a
    # plain directory below an unstable one.
    for how in ('reg', 'fifo', 'reg-mount', 'lnk', 'below-unstable'):
        def build(rng, how=how):
            t = base_tree(rng, rng.randrange(0, 4))
            d = subject(rng, t, 'dir', extras=False)
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
                t.e[p] = new_entry(rng, t, p, rng.choice(['reg', 'dir', 'fifo']))
            fix(t, rng)
            a = t.copy()
            a.drop_below(d['path'])
            e2 = change_type(a.e[d['path']], how.split('-')[0], a, rng)
            if e2 is not None and how == 'reg-mount':
                e2 = in_context('mount', e2, a, rng)
            if e2 is None:
                return None
            a.e[d['path']] = e2
            fix(a, rng)
            return t, a
        if how == 'below-unstable':
            tags = ['a one-sided path below a plain directory below an unstable one']
        else:
            tags = ['a one-sided path whose nearest ancestor on the other side is not a '
                    'directory']
        if how == 'reg-mount':
            tags.append('a path missing below a non-directory that carries unreadable or mount, '
                        'not raced')
        for _ in range(2):
            w.targeted(rng, 'one-sided below: ' + how, build, scenarios=tags)

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
        w.targeted(rng, 'every name', build,
                   scenarios=['a path sorting before "."', 'a non-UTF-8 path'])


def dir_timestamps(w, rng):
    """A directory's own timestamps (diff-v1 "A directory's own timestamps",
    pin O5), and a FIFO's, socket's or device node's ("Timestamps that move
    on use"): alone, with nothing flagged -- no record; counted in
    dir_timestamps_only for a directory, not for the others. Then a
    directory's beside a field not compared on it (still counted), beside a
    compared field, under a flag on both sides or on one, and with iflags on
    one side only: each keeps its record."""
    for typ in ['dir'] + list(SPECIAL):
        for which in (('mtime_ns',), ('ctime_ns',), TS):
            def build(rng, typ=typ, which=which):
                t = base_tree(rng)
                e = clear_flags(subject(rng, t, typ), t, rng)
                e2 = dict(e)
                for f in which:
                    e2[f] = e[f] + rng.randrange(1, 10 ** 12)
                return with_subject(t, e, e2)
            if typ == 'dir':
                tag = 'a directory whose only difference is its ' + ' and '.join(which)
            elif len(which) == 1:
                tag = 'only %s differs on a %s' % (which[0], typ)
            else:
                tag = 'only mtime_ns and ctime_ns differ on a %s' % typ
            w.targeted(rng, 'only %s on a %s, nothing flagged' % (' and '.join(which), typ),
                       build, scenarios=[tag])
    for which in (('ctime_ns',), ('mtime_ns',), TS):
        def build(rng, which=which):
            t = base_tree(rng, rng.randrange(1, 6))
            clear_flags(t.e[b'.'], t, rng)
            a = t.copy()
            for f in which:
                a.e[b'.'][f] += rng.randrange(1, 10 ** 12)
            return t, a
        w.targeted(rng, 'the root: only its %s, nothing flagged' % ' and '.join(which), build,
                   scenarios=['the root, whose only differences are its own timestamps'])
    beside = {'nlink': 'a directory whose timestamps and a field not compared on it differ',
              'size': 'a directory whose timestamps and a field not compared on it differ',
              'mode': 'a directory whose timestamps and a compared field differ',
              'uid': 'a directory whose timestamps and a compared field differ',
              'iflags on one side': 'a directory whose timestamps differ, iflags on one side '
                                    'only',
              'unstable after': 'a directory whose timestamps differ, a flag on one side only',
              'xattrs_unknown after': 'a directory whose timestamps differ, a flag on one side '
                                      'only'}
    for extra, tag in beside.items():
        def build(rng, extra=extra):
            t = base_tree(rng)
            e = clear_flags(subject(rng, t, 'dir'), t, rng)
            if extra == 'iflags on one side':
                e['iflags'] = rng.choice(IFLAGS)
            e2 = dict(e, mtime_ns=e['mtime_ns'] + 5, ctime_ns=e['ctime_ns'] + 7)
            if extra == 'nlink':
                e2['nlink'] += 1
            elif extra == 'size':
                e2['size'] += 4096
            elif extra == 'mode':
                e2['mode'] = (e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777)
            elif extra == 'uid':
                e2['uid'] = other(rng, IDS, e['uid'])
            elif extra == 'iflags on one side':
                del e2['iflags']
            elif extra == 'unstable after':
                e2['unstable'] = True
            elif extra == 'xattrs_unknown after':
                for k in ('caps', 'xattrs', 'xattrs_sha256'):
                    e2.pop(k, None)
                e2['xattrs_unknown'] = True
            return with_subject(t, e, e2)
        w.targeted(rng, "a directory's timestamps, with %s" % extra, build, scenarios=[tag])
    for ctx in ('unstable', 'unreadable', 'xattrs_unknown', 'raced', 'mount'):
        def build(rng, ctx=ctx):
            t = base_tree(rng)
            e = in_context(ctx, clear_flags(subject(rng, t, 'dir'), t, rng), t, rng)
            return with_subject(t, e, dict(e, mtime_ns=e['mtime_ns'] + 3,
                                           ctime_ns=e['ctime_ns'] + 3))
        w.targeted(rng, "a directory's timestamps, %s on both sides" % ctx, build,
                   scenarios=['a directory whose only difference is its timestamps, flagged '
                              'alike on both sides'])


SIBLINGS = (b'!x', b'-x', b'.x')       # names that sort between d and d/...: '!', '-', '.' < '/'


def below_a_non_directory(w, rng):
    """A path present on one side only whose nearest recorded ancestor on the
    other side is not a directory (diff-v1, "Present on one side only"):
    `unknown`, reason `raced`, when that ancestor carries raced -- "it may
    have become a directory holding this path" --, else the absence is known:
    only a directory carrying unreadable or mount seals. The directory d, in
    the root, becomes the non-directory; one level below it (d/f, d/e) and
    two (d/e/g) are on the first side only, and never raced themselves.
    Beside d, names that sort between d and its children, so that the
    stream passes them before it reaches d/...: d.x with a child on both
    sides; d!x a directory with a child (d!x/y) on the first side and a
    non-raced FIFO on the second, so the absence of d!x/y is known whatever
    d is; d-x on the first side only, beside d, not below it."""
    for typ in ('reg', 'lnk', 'fifo', 'sock', 'blk', 'chr'):
        for how in ('raced', 'plain', 'unreadable', 'mount'):
            if how == 'unreadable' and typ not in CONTEXT_TYPES['unreadable']:
                continue                                # rule 13
            def build(rng, typ=typ, how=how):
                t = base_tree(rng, rng.randrange(0, 4))
                p = fresh_path(t, rng, parent=b'.')
                while p in t.e or any(p + s in t.e for s in SIBLINGS):
                    p += b'0'                           # free, and its siblings free
                t.e[p] = new_entry(rng, t, p, 'dir', extras=False)
                for q, ty in ((b'/f', random_type(rng)), (b'/e', 'dir'),
                              (b'/e/g', random_type(rng)), (b'!x', 'dir'),
                              (b'!x/y', random_type(rng)), (b'-x', random_type(rng)),
                              (b'.x', 'dir'), (b'.x/z', random_type(rng))):
                    t.e[p + q] = new_entry(rng, t, p + q, ty, extras=ty != 'dir')
                a = t.copy()
                a.drop_below(p)
                x = change_type(a.e[p], typ, a, rng)
                if x is None:
                    return None
                if how == 'raced':
                    x['raced'] = True
                elif how == 'unreadable':
                    x['unreadable'] = True
                    x.pop('target_outside_scope', None)
                    settle_hash(x, a, rng)              # a regular file: unverified
                elif how == 'mount':
                    x = in_context('mount', x, a, rng)
                a.e[p] = x
                a.drop_below(p + b'!x')
                a.e[p + b'!x'] = change_type(a.e[p + b'!x'], 'fifo', a, rng)
                del a.e[p + b'-x']
                return t, a
            kind = 'raced' if how == 'raced' else 'non-raced'
            scen = ['a path missing below a %s non-directory, %s deep' % (kind, n)
                    for n in ('one level', 'two levels')]
            if how == 'raced':
                scen += ['a path missing below a raced non-directory, with names sorting '
                         'between it and its children',
                         "a path missing beside or below a name that extends a raced "
                         "non-directory's, not below it"]
            if how in ('unreadable', 'mount'):
                scen.append('a path missing below a non-directory that carries unreadable or '
                            'mount, not raced')
            w.targeted(rng, 'below a %s %s, one and two levels, siblings between' % (how, typ),
                       build, scenarios=scen)


def mount_root_attributes(w, rng):
    """An entry that becomes a mount root (written both ways round: or stops
    being one) with iflags, caps or xattrs read on the other side, or that
    side's attributes unreadable: a mount root's own are never read
    (manifest-v1 rule 22), so whether they compare there is the pin's `on
    mount roots` column."""
    plan = [('dir', ('iflags',)), ('dir', ('xattrs',)), ('dir', ('xattrs_sha256',)),
            ('dir', ('iflags', 'xattrs')), ('dir', ('xattrs_unknown',)),
            ('dir', ('iflags', 'xattrs_unknown')), ('reg', ('caps',)),
            ('reg', ('iflags', 'caps', 'xattrs')), ('lnk', ('iflags', 'xattrs')),
            ('fifo', ('iflags',))]
    for typ, attrs in plan:
        def build(rng, typ=typ, attrs=attrs):
            t = base_tree(rng)
            e = subject(rng, t, typ)
            for k in ATTRS:
                e.pop(k, None)
            for k in attrs:
                e[k] = {'iflags': lambda: rng.choice(IFLAGS), 'caps': lambda: caps_hex(rng),
                        'xattrs': lambda: xattr_set(rng), 'xattrs_sha256': lambda: hexs(rng),
                        'xattrs_unknown': lambda: True}[k]()
            return with_subject(t, e, in_context('mount', e, t, rng))
        scen = []
        if typ == 'dir':
            for verb in ('becomes', 'stops being'):
                if 'iflags' in attrs:
                    scen.append('a directory %s a mount root, iflags on the other side' % verb)
                if 'xattrs' in attrs or 'xattrs_sha256' in attrs:
                    scen.append('a directory %s a mount root, xattrs on the other side' % verb)
            if 'xattrs_unknown' in attrs:
                scen.append('a directory is a mount root on one side only, xattrs_unknown on '
                            'the other')
        if typ == 'reg' and 'caps' in attrs:
            scen.append('a regular file is a mount root on one side only, caps on the other')
        w.targeted(rng, 'a %s becomes a mount root, %s read before' % (typ, '+'.join(attrs)),
                   build, scenarios=scen)


def digest_of(items):
    """A set's xattrs_sha256, as manifest-v1.md defines it ("Field rules a
    reader MUST enforce"): "the sha256 of the bytes `xattrs` would hold
    between its brackets, exactly as a writer emits them" -- this writer:
    enc_obj() joins jstr() of each element with ",". (The reference computes
    it on its own, from the "Encoding" grammar; each pair built here is
    checked to show that both agree.)"""
    return hashlib.sha256(','.join(jstr(x) for x in items).encode('utf-8')).hexdigest()


def large_xattr_set(rng):
    """A set whose array body is over 8192 bytes, so one a writer records by
    digest, never inline: "At most 8192 bytes of array body; a larger set is
    recorded as `xattrs_sha256` instead" (manifest-v1.md, entries table -- a
    generated block, used here only to build an input, never to decide an
    outcome). Recorded inline it would be another byte representation of the
    same state, which a reader rejects ("every manifest state has exactly one
    byte representation, and a reader MUST reject anything else",
    "Encoding"); the C reader was seen to ("xattrs longer than the inline
    limit"). So it appears here by digest only."""
    items, body = [], -1
    while body <= 8192:
        items.append('user.x%04d=%s' % (len(items), hexs(rng)))
        body += len(items[-1]) + 3                  # its quotes, and a comma
    return items


def xattrs_spellings(w, rng):
    """An xattr set inline on one side and by digest on the other: the same
    set "compares equal" (manifest-v1.md, "Field rules a reader MUST
    enforce") -- no record when nothing else differs, and not in `changed`
    beside another difference --; a different set differs, inline against a
    digest and digest against digest. Nothing is flagged, so that the set
    alone decides. Both sides are valid under test/expect/manifest-v1.md: no
    `xattrs` with a digest (rule 2), no `xattrs_unknown` (rule 3), not a
    mount (rule 22). An inline set is always one a writer inlines; so the
    same set by digest is a small one (no reader can tell a set's size from
    its digest, and no pin rule ties the digest to a size), and a set a
    writer records by digest (large_xattr_set) is on a digest side only."""
    alone = 'xattrs: a set inline on one side and %s by digest on the other, nothing else ' \
            'differing'
    tags = {'same': alone % 'the same set',
            'same, mode': 'xattrs: a set inline on one side and the same set by digest on the '
                          'other, beside another difference',
            'different': alone % 'a different set',
            'different, large by digest': alone % 'a different set',
            'both by digest, large': 'xattrs: different sets by digest on both sides, nothing '
                                     'else differing'}
    for typ in TYPE_NAMES:
        for how, tag in tags.items():
            def build(rng, typ=typ, how=how):
                t = base_tree(rng)
                e = clear_flags(subject(rng, t, typ), t, rng)
                e.pop('xattrs_sha256', None)
                s = large_xattr_set(rng) if how == 'both by digest, large' else xattr_set(rng)
                n, v = s[-1].split('=', 1)
                s2 = s[:-1] + ['%s=%s' % (n, unlike(hexs(rng), v))]     # another set
                if how == 'different, large by digest':
                    s2 = large_xattr_set(rng)
                e['xattrs'] = s
                e2 = {k: x for k, x in e.items() if k != 'xattrs'}
                if how.startswith('same'):
                    e2['xattrs_sha256'] = digest_of(s)
                    if how == 'same, mode':
                        e2['mode'] = (e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777)
                elif how.startswith('different'):
                    e2['xattrs_sha256'] = digest_of(s2)
                else:
                    del e['xattrs']
                    e['xattrs_sha256'], e2['xattrs_sha256'] = digest_of(s), digest_of(s2)
                return with_subject(t, e, e2)
            w.targeted(rng, 'xattrs inline and by digest on a %s: %s' % (typ, how), build,
                       scenarios=[tag])


def trailer_counts(w, rng):
    """What the trailer says about each walk ("### Trailer"): `vanished` on
    one side only with nothing flagged and every entry equal, so no record
    could say so; every one of the six counts different on the two sides; all
    six 0, so `provisional` is false."""
    for _ in range(2):
        def build(rng):
            t = unflagged_tree(rng)
            a = t.copy()
            a.vanished = rng.choice([1, 2, 5])
            return t, a
        w.targeted(rng, 'vanished on one side only, nothing else', build,
                   scenarios=['vanished on one side only, nothing flagged and no record'])
    def build(rng):
        t = unflagged_tree(rng)
        x = subject(rng, t, 'fifo')
        x['raced'] = True
        t.e[x['path']] = x
        t.vanished = 1
        a = t.copy()                            # 1, 0, 1 before; 3, 1, 2 after
        a.vanished = 3
        y = subject(rng, a, 'reg')
        y['raced'] = True
        a.e[y['path']] = y
        z = subject(rng, a, 'dir', extras=False)
        z['unstable'] = True
        a.e[z['path']] = z
        return t, a
    w.targeted(rng, 'every walk count differs', build,
               scenarios=['every walk count differs between the two manifests'])
    def build(rng):
        t = unflagged_tree(rng)
        a = t.copy()
        p = rng.choice(sorted(a.e))
        a.e[p]['mode'] = (a.e[p]['mode'] & S_IFMT) | other(rng, PERMS, a.e[p]['mode'] & 0o7777)
        return t, a
    w.targeted(rng, 'a mode change, every walk count 0', build,
               scenarios=['provisional false: every walk count is 0',
                          'the first manifest was created after the second'])


def targeted(w, rng):
    cells(w, rng)
    field_pairs(w, rng)
    type_changes(w, rng)
    raced_type_changes(w, rng)
    optional_one_sided(w, rng)
    scenarios(w, rng)
    dir_timestamps(w, rng)
    below_a_non_directory(w, rng)
    mount_root_attributes(w, rng)
    xattrs_spellings(w, rng)
    trailer_counts(w, rng)


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
    targeted(w, rng)
    w.check_gate()          # the targeted pairs alone: the random ones add variety only
    randomized(w, rng, n)
    refusals(w, rng)
    print(w.k)


if __name__ == '__main__':
    main()
