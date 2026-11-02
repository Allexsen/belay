#!/usr/bin/env python3
"""Generates valid manifest pairs for the diff oracle.

    gen_corpus.py <out-dir> <n-bases> <seed>

Writes, and prints the number of, pairs:
  pair-NNNNN.before / .after   two manifests of one scope, for compare.py;
  pair-NNNNN.before.alt /      the same two manifests, each in the other
             .after.alt        manifest version (see below);
  pair-NNNNN.label             what the pair was built to exercise -- for
                               messages only: compare.py computes coverage
                               from the manifests themselves;
  pair-NNNNN.store/            for a pair given a store (git's events): the
                               copies, at `<2 hex>/<62 hex>` of their sha256;
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

Manifest versions (test/expect/manifest-v2.md): a pair is written in one of
the four combinations of versions 1 and 2 (cycled), and each of its two
manifests also in the other version (.alt), so compare.py runs every pair in
all four and checks its records do not depend on them (V2-R4). A v2 manifest
is the v1 one plus the keys the pin's Lines table adds (read at run time, in
its order, after v1's): `excluded`, the tree's exclusions (Tree.x, V2-2),
`walk_start_ns` (0 on every third side), and `trusted`, `reference`,
`read_all` cycling over every kind of walk V2-5 and V2-6 name, consistent by
the spec's agreement rule (v2_violations()). Those statements decide nothing
in a diff (V2-R6) and vary freely; their numbers come from the writer's own
random stream. manifest_versions() builds the gate's version items
deterministically.

The diff header (V2-R7) carries each manifest's `excluded` as written, `null`
for v1: the exclusion pairs are built in the versions that show it (an empty
list, path_b64, both reasons, a path both sides excluded, v1 against v2).

Exclusions (V2-2; docs/spec/diff-v1.md, "Present on one side only"): a
tree's excluded paths have no entry, nothing below them is recorded (no entry, no other
exclusion), and each one's parent is a directory that was listed -- neither
unreadable nor a mount; it may be unstable (exclusion_violations()). A
manifest with exclusions has no version 1 counterpart: version 1 cannot say
what was not walked, and the same entries without `excluded` would claim a
known absence ("nothing is ever excluded silently"). So such a side is
written in version 2 only, with no .alt, and compare.py runs its pair in the
combinations of versions whose files exist (Writer.write_both_versions).
exclusions() builds the gate's exclusion items; random trees exclude entries
too (the base of a random pair, and the `exclude`/`unexclude` mutations).
And E11 (test/expect/diff-events.md): RECORDs and dpkg status files not
captured -- excluded (the venv, the dist-info, the status itself), below an
unreadable directory, below a mount -- beside ones read, which derive no
event; and, against them, ones unknown for another reason (listing_incomplete,
raced), whose events are still provisional.

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
    one-sided raced entries, a regular file mounted on one side or both,
    `unverified` on the other side or not (pin O8), a mounted regular file
    whose type changes while raced on either side or both (O8 across a type
    change), the trailer's walk counts, paths a v2 manifest excluded
    (exclusions()), the root itself,
    names sorting before ".", non-UTF-8 and escaped names; and the
    interpreters with no store (interpreters()): text paths modified, added,
    removed, metadata_only and unknown, a file stored on one side only, dpkg
    status files (one or two per diff, a side with no stored copy, a type
    change, an unknown status: provisional) and info files, pip RECORDs
    installed, removed, upgraded, downgraded, version-changed, reinstalled,
    unknown (provisional; on both sides, a reinstall whose files are not
    counted), could_not_interpret events (E10) and invalid_finding events
    (E9), git hooks, the index, HEAD, loose refs, packed-refs, reflogs (at,
    over and grown past their 16 MiB bound with no stored copy), a
    claimed directory, symlinked hooks (added, removed, retargeted, with no
    `executable`; a target not UTF-8, over 1,024 bytes, of 4,095 -- the
    manifest's limit, addendum A4, which the generator keeps to),
    directories under hooks/, symlinks and directories under logs/refs/, a
    hook that becomes a symlink or back, and an unclaimed file below .git/;
    git's repository-level events with a store (git_events(), diff-events
    E12): branches created (by their reflog's zeros, by packed-refs without
    them), moved with no evidence of before, deleted (packed-refs not a path
    of this diff, or one without them; only in packed-refs), packed at the
    same commits, renamed (with HEAD on them; another branch between the two
    names), commits added (counted, or not with a fast-forward or merge),
    each rewrite and several, reflogs that do not chain or gained none,
    another operation, HEAD switched, detached and attached, a detached
    HEAD moved, four repositories nested and side by side, `unknown` refs
    and packed-refs read from their copies (provisional) or with none,
    a reflog that cannot be read, a packed-refs touched but unchanged, a ref
    that cannot be parsed, tags and remote-tracking refs, and copies
    missing, corrupt (other bytes, a symlink) and over a loose ref's bound;
    and the values a record carries (values(), diff-values.md): link
    targets not UTF-8 on both sides, a type change whose symlink's target
    is not UTF-8, unknown or written on an unreadable link, or whose
    regular file has no hash, a raced type change to and from a symlink
    (its target unknown or not), `caps` added beside a mode change, and the
    longest record (V5);
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

# Manifest version 2 (test/expect/manifest-v2.md): a v1 manifest plus header
# and trailer keys, "v1's keys in v1's order, then the new keys in the order
# of this table", every one always present. Read from the pin's Lines table at
# run time; the statements this generator writes for them are tied to the
# pin's words below (a changed pin stops the generator).
MANIFEST_V2_PIN = os.path.join(REPO, 'test', 'expect', 'manifest-v2.md')
MANIFEST_V2_SPEC = os.path.join(REPO, 'docs', 'spec', 'manifest-v2.md')
V2_KINDS = {'int': 'int', 'string': 'string', 'array of objects': 'objects'}
# The keys v2 adds, as this generator writes them (V2-2..V2-6).
V2_IMPLEMENTED = {'header': ['excluded', 'walk_start_ns'],
                  'trailer': ['trusted', 'reference', 'read_all']}
# `read_all`'s values, V2-6 word for word; N and M are the pin's placeholders
# for numbers, filled in when written. The pin's last case, "why the previous
# manifest could not be used", is free text: V2_FREE_REASON.
V2_READ_ALL = ['check', 'no checkpoint before', 'asked for (--full)', 'every N marks',
               'ctime went backwards: newest N below the previous M',
               "the previous walk's start is unknown and the scope's timestamps are coarse"]
V2_FREE_REASON = 'the previous manifest could not be used: "caf\u00e9" \\ \u65e5'
V2_REFERENCES = ['walk_start', 'newest_ctime', 'none']
# V2-2's words this generator relies on: an `excluded` element's keys, in
# order (`path_b64` for a path not UTF-8, as for entries), its reasons, the
# order of the list, and what an excluded path leaves in the manifest.
V2_EXCLUDED_WORDS = ['`{"path": string, "reason": string, "dev": int, "ino": int}`',
                     '`path_b64` in place of `path` when not UTF-8, as for entries',
                     'sorted by path bytes', '`"state_dir"`', '`"user"`',
                     '`dev` and `ino` are those of what was there',
                     'It has no entry, nor anything below it; its name still counts in its '
                     "parent's listing"]
EXCLUDED_REASONS = ['state_dir', 'user']
# An element's keys, as enc_obj() takes them: `path` spelled as an entry's.
EXCLUDED_KEYS = [next(k for k in KEYS['entry'] if k[0] == 'path')[:3] + ('required',),
                 ('reason', ('reason',), 'string', 'required'),
                 ('dev', ('dev',), 'int', 'required'), ('ino', ('ino',), 'int', 'required')]
# The spec's agreement rule (manifest-v2.md, "The trailer"), which
# v2_violations() implements.
V2_AGREEMENT = ('The three agree, and a reader checks it: the prefilter was used exactly when '
                '`read_all` is `""`;\nthen `reference` is `walk_start` or `newest_ctime`; '
                'otherwise it is `none` and `trusted` is `0`.\n`trusted` is at most the number '
                'of entries.')


def load_manifest_v2_pin():
    rows = md_table(open(MANIFEST_V2_PIN, encoding='utf-8').read(), 'id')
    keys = {'header': [], 'trailer': []}
    v1 = {k[0] for line in KEYS.values() for k in line}
    for r in rows:
        key = r['key'].strip('`')
        if key == 'belay_manifest':
            if r['value'] != '`2`':
                die('pin: v2\'s belay_manifest is %r' % r['value'])
            continue
        if key in v1 or r['line'] not in keys or r['type'] not in V2_KINDS \
                or not r['when'].startswith('always'):
            die('pin: manifest-v2.md row %s is not one this generator writes: %r' % (r['id'], r))
        keys[r['line']].append((key, (key,), V2_KINDS[r['type']], 'required (v2)'))
    if {k: [x[0] for x in v] for k, v in keys.items()} != V2_IMPLEMENTED:
        die('pin: manifest-v2.md adds %r; this generator writes %r' % (keys, V2_IMPLEMENTED))
    text = {r['key'].strip('`'): r['value'] for r in rows}
    for reason in V2_READ_ALL + ['`""` when the prefilter was used']:
        if ('`%s`' % reason if not reason.startswith('`') else reason) not in text['read_all']:
            die('pin: V2-6 no longer names `%s`' % reason)
    if 'why the previous manifest could not be used' not in text['read_all']:
        die('pin: V2-6 no longer names a free-text reason')
    for ref_ in V2_REFERENCES:
        if '`%s`' % ref_ not in text['reference']:
            die('pin: V2-5 no longer names `%s`' % ref_)
    if '`[]` when none' not in text['excluded'] or \
            '`0` when that clock could not be read' not in text['walk_start_ns']:
        die('pin: V2-2 or V2-3 changed the words this generator relies on')
    for words in V2_EXCLUDED_WORDS:
        if words not in text['excluded']:
            die('pin: V2-2 no longer says %r; review exclusion_violations() first' % words)
    # The prose only, its generated blocks withheld (decision 119).
    if V2_AGREEMENT not in compare.ref.spec_prose(MANIFEST_V2_SPEC):
        die('spec: manifest-v2.md changed its agreement rule; review v2_violations() first')
    return {k: KEYS[k] + v for k, v in keys.items()}


KEYS_V2 = load_manifest_v2_pin()       # the v2 header's and trailer's keys, in order

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
        # Manifest v2's `excluded` (V2-2): {path bytes: {'reason', 'dev',
        # 'ino'}}. Nothing at or below such a path is in self.e; its parent
        # is a listed directory (exclusion_violations()).
        self.x = {}
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


def covered_by(x, p):
    """The path of x (exclusions) that p is at or below, or None."""
    if p in x:
        return p
    for i in range(len(p) - 1, 0, -1):
        if p[i:i + 1] == b'/' and p[:i] in x:
            return p[:i]
    return None


def exclude(t, p, reason='user', dev=None, ino=None):
    """t, as a walk that excluded p would record it (V2-2): no entry at or
    below p, p in t.x with the device and inode of what was there (p's own
    entry when t has one) -- and no exclusion below p, which that walk would
    not have reached."""
    e = t.e.pop(p, None)
    t.drop_below(p)
    for q in [q for q in t.x if q.startswith(p + b'/')]:
        del t.x[q]
    t.x[p] = {'reason': reason,
              'dev': dev if dev is not None else e['dev'] if e else t.root_dev(),
              'ino': ino if ino is not None else e['ino'] if e else 7 + len(p) * 131}
    return t


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
        if join(name) not in t.e and join(name) not in t.x:
            return join(name)
    i = 0
    while join(b'n%d' % i) in t.e or join(b'n%d' % i) in t.x:
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
        t.x = {}
    # Exclusions (V2-2): none below another; no entry at or below one.
    kept = {}
    for q in sorted(t.x, key=lambda q: (q.count(b'/'), q)):
        if covered_by(kept, q) is None:
            kept[q] = t.x[q]
    t.x = kept
    for p in [p for p in t.e if p != b'.' and covered_by(t.x, p) is not None]:
        del t.e[p]
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
    # An exclusion's name counts in its parent's listing (V2-2): the parent
    # is a directory that was listed, neither unreadable nor a mount.
    t.x = {q: x for q, x in t.x.items() if listed_dir(t, parent_of(q))}


def listed_dir(t, p):
    e = t.e.get(p)
    return e is not None and e['type'] == 'dir' and not e.get('unreadable') and \
        not e.get('mount')


def exclusion_violations(t):
    """What makes t's exclusions invalid (test/expect/manifest-v2.md V2-2,
    docs/spec/manifest-v2.md): each path canonical as an entry's and not the
    root, within addendum A3, its parent a directory that was listed ("its
    name still counts in its parent's listing": not unreadable, not a
    mount), none at or below another ("Nothing below an excluded path is
    recorded"), no entry at or below one ("It has no entry, nor anything
    below it"), a reason V2-2 names, `dev` and `ino` integers."""
    v = []
    for q, x in t.x.items():
        comps = q.split(b'/')
        if q == b'.' or q.startswith(b'/') or any(c in (b'', b'.', b'..') for c in comps) or \
                b'\0' in q or len(q) > ADDENDUM_MAX['path']:
            v.append('excluded %r: not a canonical path' % q)
        if not listed_dir(t, parent_of(q)):
            v.append('excluded %r: its parent is not a listed directory' % q)
        if covered_by({r: 1 for r in t.x if r != q}, q) is not None:
            v.append('excluded %r: below another excluded path' % q)
        if sorted(x) != ['dev', 'ino', 'reason'] or x['reason'] not in EXCLUDED_REASONS or \
                any(type(x[k]) is not int or x[k] < 0 for k in ('dev', 'ino')):
            v.append('excluded %r: %r' % (q, x))
    v += ['%r: recorded at or below an excluded path' % p for p in t.e
          if p != b'.' and covered_by(t.x, p) is not None]
    return v


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
        # test/expect/manifest-v1-addendum.md A3 and A4: a reader rejects a
        # longer path or link target.
        if len(p) > ADDENDUM_MAX['path'] or len(e.get('link_target', b'')) > \
                ADDENDUM_MAX['link_target']:
            v.append('%r: addendum A3/A4' % p)
    return v + exclusion_violations(t)


def addendum_limits():
    """The two rows of the manifest addendum pin the generator keeps to."""
    text = open(os.path.join(REPO, 'test', 'expect', 'manifest-v1-addendum.md'),
                encoding='utf-8').read()
    for w in ['| A3 | A `path` is at most 4095 bytes; a reader rejects a longer one. |',
              '| A4 | A `link_target` is at most 4095 bytes; a reader rejects a longer one. |']:
        if w not in text:
            die('pin: the manifest addendum no longer says %r' % w)
    return {'path': 4095, 'link_target': 4095}


ADDENDUM_MAX = addendum_limits()

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
        elif kind == 'objects':
            # v2's `excluded` (V2-2): flat objects, `[]` when none.
            assert isinstance(v, list) and all(isinstance(x, dict) for x in v), (canon, v)
            enc = '[' + ','.join(enc_obj(EXCLUDED_KEYS, x) for x in v) + ']'
        else:
            raise SystemExit('pin: unknown kind %r' % kind)
        parts.append('"%s":%s' % (name, enc))
    if set(d) - used:
        raise SystemExit('generator bug: unknown keys %r' % sorted(set(d) - used))
    return '{' + ','.join(parts) + '}'


def write_manifest(t, path, version=1, st=None):
    """The tree as a manifest of `version` 1 or 2; a v2 one carries the
    statements `st` (v2_statements()) under the keys V2-2..V2-6 add."""
    keys = KEYS if version == 1 else KEYS_V2
    header = {'belay_manifest': version, 'created_ns': t.created, 'scopes': [t.scope],
              'hash': 'sha256', 'hash_max_bytes': t.limit, 'store_max_bytes': t.store_max}
    lines = [None]
    n = {'unreadable': 0, 'unstable': 0, 'mount': 0, 'raced': 0}
    for p in sorted(t.e):
        e = t.e[p]
        lines.append(enc_obj(KEYS['entry'], e))
        for k in n:
            n[k] += bool(e.get(k))
    trailer = {'belay_manifest_end': len(t.e), 'vanished': t.vanished,
               'unreadable': n['unreadable'], 'unstable': n['unstable'], 'mounts': n['mount'],
               'raced': n['raced']}
    if version == 2:
        v = v2_violations(t, st)
        if v:
            die('generator bug: v2 statements %r: %s' % (st, v))
        header.update((k, st[k]) for k in V2_STATED['header'])
        header['excluded'] = excluded_list(t)
        trailer.update((k, st[k]) for k in V2_STATED['trailer'])
    else:
        # A version 1 manifest cannot say what was not walked: a tree with
        # exclusions is written in version 2 only (Writer.pair).
        assert version == 1 and not t.x, (version, sorted(t.x))
    lines[0] = enc_obj(keys['header'], header)
    lines.append(enc_obj(keys['trailer'], trailer))
    for l in lines:
        assert len(l.encode('utf-8')) < 65536 and '\0' not in l
    with open(path, 'wb') as f:
        f.write(('\n'.join(lines) + '\n').encode('utf-8'))

# ---------------------------------------------------------------------------
# Manifest versions (test/expect/manifest-v2.md). Every pair is written in one
# combination of versions (.before/.after, cycled over the four) and each side
# also in the other version (.before.alt/.after.alt), so compare.py runs every
# pair in all four and checks the records do not depend on them (V2-R4). The
# v2 statements decide nothing in a diff (V2-R6), so they vary freely: the
# kind of walk cycles over V2_WALKS, its numbers come from the writer's own
# random stream (the trees' stream is left as it was).

VERSION_PAIRS = [(1, 1), (1, 2), (2, 1), (2, 2)]
# (read_all, reference, trusted: 'some' (1 up to the regular files) or 0).
# "every N marks" and "... newest N below the previous M": numbers filled in.
V2_WALKS = ([('', 'walk_start', 'some'), ('', 'newest_ctime', 'some'), ('', 'walk_start', 0),
             ('', 'newest_ctime', 0)]
            + [(r, 'none', 0) for r in V2_READ_ALL] + [(V2_FREE_REASON, 'none', 0)])


# The v2 keys whose values are the capture's statements about itself (V2-3..
# V2-6): they decide nothing (V2-R6) and vary freely. `excluded` (V2-2) is
# not among them: it is the tree's (Tree.x), and decides what is compared.
V2_STATED = {'header': [k for k in V2_IMPLEMENTED['header'] if k != 'excluded'],
             'trailer': V2_IMPLEMENTED['trailer']}


def excluded_list(t):
    """The tree's exclusions as V2-2's elements, sorted by path bytes."""
    return [dict({'path': q}, **t.x[q]) for q in sorted(t.x)]


def v2_statements(t, rng, walk, ws_zero):
    read_all, reference, trusted = walk
    regs = sum(e['type'] == 'reg' for e in t.e.values())
    read_all = read_all.replace('every N', 'every %d' % rng.choice([2, 10, 64])) \
        .replace('newest N below the previous M', 'newest %d below the previous %d'
                 % (t.created - 10 ** 9, t.created - 10 ** 9 + rng.randrange(1, 10 ** 9)))
    return {'walk_start_ns': 0 if ws_zero else t.created - rng.randrange(1, 10 ** 10),
            'trusted': rng.randint(1, regs) if trusted == 'some' and regs else 0,
            'reference': reference, 'read_all': read_all}


def v2_violations(t, st):
    """What makes these v2 statements invalid for this tree: the pin's kinds
    and values (V2-2..V2-6) and the spec's agreement rule (V2_AGREEMENT)."""
    v = []
    if sorted(st) != sorted(V2_STATED['header'] + V2_STATED['trailer']):
        v.append('keys %r' % sorted(st))
    if type(st.get('walk_start_ns')) is not int or st['walk_start_ns'] < 0:
        v.append('walk_start_ns')
    if type(st.get('trusted')) is not int or not 0 <= st['trusted'] <= len(t.e):
        v.append('trusted is not between 0 and the number of entries')
    if st.get('reference') not in V2_REFERENCES or not isinstance(st.get('read_all'), str):
        v.append('reference or read_all')
    elif (st['read_all'] == '') != (st['reference'] in ('walk_start', 'newest_ctime')):
        v.append('the prefilter used, but reference %r' % st['reference'])
    elif st['read_all'] != '' and st['trusted'] != 0:
        v.append('every file read, but trusted %d' % st['trusted'])
    return v


def write_store(path, store):
    """A store directory: each copy at `<store>/<the first two hex digits of
    its sha256>/<the other 62>` (diff-v1, "Content"); a copy given as
    ('symlink', target) is a symbolic link there."""
    for name, data in sorted(store.items()):
        d = os.path.join(path, name[:2])
        os.makedirs(d, exist_ok=True)
        f = os.path.join(d, name[2:])
        if isinstance(data, tuple):
            os.symlink(data[1], f)
        else:
            with open(f, 'wb') as fh:
                fh.write(data)
    os.makedirs(path, exist_ok=True)


class Writer:
    def __init__(self, out, seed):
        self.out, self.k, self.s = out, 0, 0
        self.targeted_stems = []        # which alone must pass the coverage gate
        self.vrng = random.Random('manifest v2 statements %d' % seed)
        self.sides = 0                  # v2 statements written, for V2_WALKS' cycle

    def statements(self, t, walk=None, ws_zero=None):
        """v2 statements for one side: the next kind of walk in the cycle, the
        start unknown on every third side, unless given."""
        n, self.sides = self.sides, self.sides + 1
        return v2_statements(t, self.vrng, V2_WALKS[n % len(V2_WALKS)] if walk is None else walk,
                             n % 3 == 0 if ws_zero is None else ws_zero)

    def statements_for(self, walk, ws_zero):
        """Given statements (a kind of walk, the start unknown or not), for
        pair(): made for the side's tree when it is written."""
        return lambda t: v2_statements(t, self.vrng, walk, ws_zero)

    def write_both_versions(self, t, path, version, st):
        """path in `version`, path.alt in the other one, with the same v2
        statements -- but a tree with exclusions has no version 1
        counterpart (version 1 cannot say what was not walked, and the same
        entries without `excluded` would claim a known absence, which V2-2
        forbids: "nothing is ever excluded silently"): it is written in
        version 2 only, with no .alt, and compare.py runs the pair in the
        combinations of versions whose files exist."""
        write_manifest(t, path, version, st)
        if not t.x:
            write_manifest(t, path + '.alt', 3 - version, st)
        else:
            assert version == 2, version

    def pair(self, b, a, label, versions=None, statements=(None, None), store=None):
        """One pair, in `versions` (before, after) or the next combination of
        the cycle; statements: each side's v2 statements, or None for the
        next of the cycle; store: {name: bytes, or ('symlink', target)}, the
        copies of the store the diff is given (pair-NNNNN.store/, laid out as
        diff-v1 "Content" says), or None for a diff given no store."""
        assert b.scope == a.scope
        for t in (b, a):
            v = violations(t)
            if v:
                die('generator bug (%s): %s' % (label, v[:5]))
        vb, va = versions or VERSION_PAIRS[self.k % len(VERSION_PAIRS)]
        if versions is None:                    # a side with exclusions is version 2
            vb, va = (2 if b.x else vb), (2 if a.x else va)
        elif (b.x and vb != 2) or (a.x and va != 2):
            die('generator bug (%s): exclusions in a version 1 manifest' % label)
        sb, sa = (self.statements(t) if st is None else st(t)
                  for st, t in zip(statements, (b, a)))
        stem = os.path.join(self.out, 'pair-%05d' % self.k)
        self.write_both_versions(b, stem + '.before', vb, sb)
        self.write_both_versions(a, stem + '.after', va, sa)
        with open(stem + '.label', 'w', encoding='utf-8') as f:
            f.write(label + '\n')
        if store is not None:
            write_store(stem + '.store', store)
        self.k += 1
        return stem

    def both_ways(self, b, a, label, versions=None, statements=(None, None), store=None):
        """The pair and its reverse; given versions and statements go with
        their manifest; both are given the same store."""
        return [self.pair(b, a, label, versions, statements, store),
                self.pair(a, b, label + ' (reversed)', versions and versions[::-1],
                          statements[::-1], store)]

    def targeted(self, rng, label, build, cells=(), pairs=(), optional=(), scenarios=(),
                 interp=(), version=(), versions=None, statements=(None, None)):
        """One targeted pair: built ONCE -- no retries; build(rng) is written
        so that it cannot fail -- written both ways round, and checked to show
        what it was built for, as compare.py's coverage gate sees it: its
        (field, type) cells, (type, field, field) pairs, optional fields
        present on one side only, named scenarios, and interpreter items.
        Anything else stops the generator, naming the pair."""
        unknown = [s for s in scenarios if s not in compare.SCENARIOS] + \
            [s for s in interp if s not in compare.INTERP_SCENARIOS] + \
            [s for s in version if s not in compare.VERSION_SCENARIOS]
        if unknown:
            die('%r names scenarios the gate does not have: %s' % (label, unknown))
        r = build(rng)
        if r is None:
            die('could not build the targeted pair %r' % label)
        stems = self.both_ways(r[0], r[1], label, versions, statements,
                               r[2] if len(r) > 2 else None)
        self.targeted_stems += stems
        cov = compare.coverage(stems)
        want = ([('cell', c) for c in cells] + [('field pair', p) for p in pairs]
                + [('optional', f) for f in optional] + [('scenario', s) for s in scenarios]
                + [('interpreter', s) for s in interp]
                + [('manifest version', s) for s in version])
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
        vb, va = VERSION_PAIRS[self.s % len(VERSION_PAIRS)]
        self.write_both_versions(b, stem + '.before', vb, self.statements(b))
        self.write_both_versions(a, stem + '.after', va, self.statements(a))
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
    mount roots` column, and they "add no reason" ("Timestamps that move on
    use"). And a directory unstable or unreadable on the other side: the
    reason `mount`, "plus those of any flags either side carries"."""
    plan = [('dir', ('iflags',)), ('dir', ('xattrs',)), ('dir', ('xattrs_sha256',)),
            ('dir', ('iflags', 'xattrs')), ('dir', ('xattrs_unknown',)),
            ('dir', ('iflags', 'xattrs_unknown')), ('dir', ('unstable',)),
            ('dir', ('unreadable', 'iflags')), ('reg', ('caps',)),
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
                        'xattrs_unknown': lambda: True, 'unstable': lambda: True,
                        'unreadable': lambda: True}[k]()
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
            if 'unstable' in attrs or 'unreadable' in attrs:
                scen.append('a directory is a mount root on one side only, unstable or '
                            'unreadable on the other')
        if typ == 'reg' and 'caps' in attrs:
            scen.append('a regular file is a mount root on one side only, caps on the other')
        w.targeted(rng, 'a %s becomes a mount root, %s read before' % (typ, '+'.join(attrs)),
                   build, scenarios=scen)


def mount_unverified(w, rng):
    """Pin O8: "`unverified` on a side that also carries `mount` adds no
    reason: a mounted regular file carries it because it is never read
    (manifest-v1 rules 5 and 21), and `mount` is that reason. `unverified` on
    the other side still gives its own." (diff-v1.md, the `unknown` sentence,
    says the same.) A regular file that becomes a mount root (written both
    ways round: or stops being one), with no flag but `mount` and its
    `unverified` on the mount side: on the other side hashed (reasons:
    `mount` alone), or too large for that manifest's hash limit, a bare
    `unverified` (reasons: `unverified` and `mount`); and a regular file that
    is a mount root on both sides, its mode changed (reasons: `mount`). The
    size is the same on both sides -- a mount root's size is not tied to the
    hash limit (header rule 1 asks a bare `unverified` only) -- so no content
    field proves a change and the outcome is `unknown`."""
    def plain_reg(rng, t):
        return clear_flags(subject(rng, t, 'reg'), t, rng)    # hashed, no flag
    def build_hashed(rng):
        t = base_tree(rng)
        e = plain_reg(rng, t)
        return with_subject(t, e, in_context('mount', e, t, rng))
    def build_bare(rng):
        t = base_tree(rng)
        e = in_context('unverified', plain_reg(rng, t), t, rng)
        return with_subject(t, e, in_context('mount', e, t, rng))
    def build_both(rng):
        t = base_tree(rng)
        e = in_context('mount', plain_reg(rng, t), t, rng)
        e2 = copy.deepcopy(e)
        e2['mode'] = (e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777)
        return with_subject(t, e, e2)
    tag = 'a regular file %s a mount root, unverified %s, no other flag'
    for _ in range(2):
        w.targeted(rng, 'a hashed regular file becomes a mount root (O8)', build_hashed,
                   scenarios=[tag % (v, 'only on the mount side')
                              for v in ('becomes', 'stops being')])
        w.targeted(rng, 'a regular file too large to hash becomes a mount root (O8)', build_bare,
                   scenarios=[tag % (v, 'also on the other side (bare)')
                              for v in ('becomes', 'stops being')])
        w.targeted(rng, 'a regular file mounted on both sides, its mode changed (O8)', build_both,
                   scenarios=['a regular file is a mount root on both sides, unverified on each, '
                              'no other flag'])


def mount_raced_type_changes(w, rng):
    """Pin O8 across a type change. A mounted regular file (its `unverified`
    is the mount's: manifest-v1 rules 5 and 21) on one side and another type
    on the other, written both ways round (the type changes from it, then to
    it), `raced` on the mount side only, on the other side only, or on both,
    and no other flag. Rule 1 before rule 2: `unknown`; `changed` is ["type"]
    ("when the types differ, `["type"]`"); `type_before` is the type before
    ("whatever the outcome -- ... or `unknown` when `raced` is on either
    side"); the reasons are "the reasons of every flag on either side --
    except `unverified` on a side that also carries `mount`" (diff-v1.md, the
    `unknown` sentence; pins O7 and O8): `mount` and `raced`, never
    `unverified`. The other side carries no `mount`. It is a directory only
    when it does not race: a raced directory carries `unreadable` or `mount`
    (manifest-v1 rule 10), which would be a reason of its own."""
    for t2 in ('lnk', 'fifo', 'sock', 'blk', 'chr', 'dir'):
        for where in ('mount', 'other', 'both'):
            if t2 == 'dir' and where != 'mount':
                continue
            def build(rng, t2=t2, where=where):
                t = base_tree(rng)
                e = clear_flags(subject(rng, t, 'reg'), t, rng)     # hashed, no flag
                m = in_context('mount', e, t, rng)                 # mount, unverified
                o = change_type(e, t2, t, rng)
                if o is None:
                    return None
                if where in ('mount', 'both'):
                    m['raced'] = True
                if where in ('other', 'both'):
                    o['raced'] = True
                return with_subject(t, m, o)
            side = {'mount': 'on the mount side only', 'other': 'on the other side only',
                    'both': 'on both sides'}[where]
            w.targeted(rng, 'a mounted reg -> %s, raced %s (O8)' % (t2, side), build,
                       scenarios=['a raced type change %s a mounted regular file, raced %s, no '
                                  'other flag' % (d, side) for d in ('from', 'to')])


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


def inline_xattr_set_near_limit(rng, tag):
    """A set a writer records inline whose array body is as near its 8192
    bytes as these names allow (addendum A1: "An inline `xattrs` array body
    is at most 8192 bytes")."""
    items, body = [], -1
    while True:
        x = 'user.%s%04d=%s' % (tag, len(items), hexs(rng))
        if body + len(x) + 3 > 8192:
            return items
        items.append(x)
        body += len(x) + 3                              # its quotes, and a comma


def values(w, rng):
    """What a record's `before` and `after` carry (test/expect/diff-values.md)
    where the other targeted pairs do not build it deterministically: a link
    target not UTF-8 on both sides (V3: each side its own spelling, both
    `link_target_b64`); a type change whose symlink's target is not UTF-8,
    unknown (an unreadable link's empty target: V2, left out) or written on
    an unreadable link (carried, ambiguity VA6); a raced type change, an
    `unknown` record that carries V6's values, from a regular file to a
    symlink and from an unreadable symlink whose target is unknown to a
    regular file, raced on the side that is not the symlink; a type change
    from a regular file with no hash (V6: "a `sha256` not computed is
    absent");
    `caps` added beside a mode change (V2: the other side's value stands
    alone, beside a field both sides record); and V5's longest record: two
    link targets of 4,095 bytes (A4), every byte a control character the
    encoding writes as six (`\\u0001`), and two inline xattr sets near
    8,192 bytes (A1), one line over 64 KiB. Nothing else differs or is
    flagged, unless named. Each is written both ways round."""
    def lnk_targets(rng):
        t = base_tree(rng)
        e = clear_flags(subject(rng, t, 'lnk'), t, rng)
        e['link_target'] = letters(rng, 4) + b'\xff'
        e['size'] = len(e['link_target'])
        set_outside(e, t)
        e2 = dict(e, link_target=new_target(rng, e, 'non-utf8'))
        set_outside(e2, t)
        return with_subject(t, e, e2)
    w.targeted(rng, 'values: a link target not UTF-8 on both sides, differing', lnk_targets,
               scenarios=['values: a link target that differs, not UTF-8 on both sides'])

    def reg_to_lnk(how):
        def build(rng):
            t = base_tree(rng)
            e = clear_flags(subject(rng, t, 'reg'), t, rng)
            if how == 'unverified':
                e = in_context('unverified', e, t, rng)
            e2 = change_type(e, 'fifo' if how == 'unverified' else 'lnk', t, rng)
            if e2 is None:
                return None
            if how == 'non-utf8':
                e2['link_target'] = e2['link_target'][:-1] + b'\xff'
                set_outside(e2, t)
            return with_subject(t, e, e2)
        return build
    w.targeted(rng, 'values: type reg -> lnk, its target not UTF-8', reg_to_lnk('non-utf8'),
               scenarios=['values: a type change %s a symlink whose target is not UTF-8' % d
                          for d in ('from', 'to')])
    w.targeted(rng, 'values: type reg (unverified) -> fifo', reg_to_lnk('unverified'),
               scenarios=['values: a type change %s a regular file with no sha256' % d
                          for d in ('from', 'to')])

    def unknown_target(rng):
        t = base_tree(rng)
        e = in_context('unreadable', clear_flags(subject(rng, t, 'lnk'), t, rng), t, rng)
        e['link_target'] = b''                  # "target unknown"
        e2 = change_type(e, 'reg', t, rng)
        return with_subject(t, e, e2)
    w.targeted(rng, 'values: type lnk (unreadable, target unknown) -> reg', unknown_target,
               scenarios=['values: a type change %s an unreadable symlink whose target is '
                          'unknown (empty)' % d for d in ('from', 'to')])

    def written_target(rng):
        t = base_tree(rng)
        e = in_context('unreadable', clear_flags(subject(rng, t, 'lnk'), t, rng), t, rng)
        if e['link_target'] == b'':
            e['link_target'] = rng.choice(INSIDE_TARGETS)   # size stays as stat'ed
        e2 = change_type(e, 'reg', t, rng)
        return with_subject(t, e, e2)
    w.targeted(rng, 'values: type lnk (unreadable, target written) -> reg', written_target,
               scenarios=['values: a type change %s an unreadable symlink whose target is '
                          'written' % d for d in ('from', 'to')])

    def raced_to_lnk(rng):
        t = base_tree(rng)
        e = clear_flags(subject(rng, t, 'reg'), t, rng)
        e2 = change_type(e, 'lnk', t, rng)
        e2['raced'] = True
        return with_subject(t, e, e2)
    w.targeted(rng, 'values: type reg -> lnk, raced on the symlink side', raced_to_lnk,
               scenarios=['values: a raced type change %s a symlink' % d
                          for d in ('from', 'to')])

    def raced_unknown_target(rng):
        t = base_tree(rng)
        e = in_context('unreadable', clear_flags(subject(rng, t, 'lnk'), t, rng), t, rng)
        e['link_target'] = b''                  # "target unknown"
        e2 = change_type(e, 'reg', t, rng)
        e2.pop('unreadable', None)
        settle_hash(e2, t, rng)
        e2['raced'] = True
        return with_subject(t, e, e2)
    w.targeted(rng, 'values: type lnk (unreadable, target unknown) -> reg, raced on the reg side',
               raced_unknown_target,
               scenarios=['values: a raced type change %s an unreadable symlink whose target '
                          'is unknown (empty)' % d for d in ('from', 'to')])

    def caps_beside_mode(rng):
        t = base_tree(rng)
        e = clear_flags(subject(rng, t, 'reg'), t, rng)
        e.pop('caps', None)
        e2 = dict(e, caps=caps_hex(rng),
                  mode=(e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777))
        return with_subject(t, e, e2)
    w.targeted(rng, 'values: caps added beside a mode change', caps_beside_mode,
               scenarios=['values: caps recorded on one side only, beside another difference'])

    def longest(rng):
        t = base_tree(rng)
        e = clear_flags(subject(rng, t, 'lnk'), t, rng)
        e.pop('xattrs_sha256', None)
        e['link_target'], e['size'] = b'\x01' * ADDENDUM_MAX['link_target'], \
            ADDENDUM_MAX['link_target']
        e['xattrs'] = inline_xattr_set_near_limit(rng, 'a')
        set_outside(e, t)
        e2 = dict(e, link_target=b'\x02' * ADDENDUM_MAX['link_target'],
                  xattrs=inline_xattr_set_near_limit(rng, 'b'))
        return with_subject(t, e, e2)
    w.targeted(rng, 'values: the longest record, two 4,095-byte targets and two inline sets',
               longest, scenarios=['values: a record line over 64 KiB (V5)'])


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


def manifest_versions(w, rng):
    """Manifest versions (test/expect/manifest-v2.md): the four combinations
    of versions, each side also written in the other version for compare.py
    (V2-R4); identical entries in two versions, and in v2 with only the v2
    statements different (V2-R6: they decide nothing); each kind of walk the
    statements can say. Versions and statements are given here, so no
    required item depends on the cycle."""
    def tree_with_a_file(rng):
        t = unflagged_tree(rng)
        x = clear_flags(subject(rng, t, 'reg'), t, rng)
        t.e[x['path']] = x
        return t

    def same_entries(rng):
        t = tree_with_a_file(rng)
        return t, t.copy()

    def modified(rng):
        t = tree_with_a_file(rng)
        a = t.copy()
        y = clear_flags(subject(rng, a, 'fifo'), a, rng)
        a.e[y['path']] = y
        for e in a.e.values():
            if e['type'] == 'reg':
                e['mode'] = (e['mode'] & S_IFMT) | other(rng, PERMS, e['mode'] & 0o7777)
        return t, a

    walk_start = ('', 'walk_start', 'some')
    w.targeted(rng, 'v2 on both sides, the same entries, only the v2 statements differ',
               same_entries, versions=(2, 2),
               statements=(w.statements_for(walk_start, False),
                           w.statements_for(('check', 'none', 0), True)),
               version=['before v2, after v2',
                        'v2 on both sides, every entry the same, only the v2 statements differ '
                        '(V2-R6)',
                        'v2: the prefilter used, reference walk_start, trusted > 0',
                        'v2: every file read, read_all check',
                        'v2: walk_start_ns 0', 'v2: walk_start_ns not 0'])
    w.targeted(rng, 'v1 and v2, the same entries', same_entries, versions=(1, 2),
               statements=(None, w.statements_for(('', 'newest_ctime', 0), False)),
               version=['before v1, after v2', 'before v2, after v1',
                        'the versions differ, every entry the same (V2-R4)',
                        'v2: the prefilter used, reference newest_ctime',
                        'v2: the prefilter used, trusted 0'])
    w.targeted(rng, 'v1 on both sides, entries differ', modified, versions=(1, 1),
               version=['before v1, after v1'])
    w.targeted(rng, 'v2 and v1, entries differ', modified, versions=(2, 1),
               statements=(w.statements_for(('every N marks', 'none', 0), True), None),
               version=['before v2, after v1', 'before v1, after v2',
                        'the versions differ, entries differ',
                        'v2: every file read, another reason'])


def exclusions(w, rng):
    """Manifest v2's `excluded` (V2-2) and what the diff makes of it
    (diff-v1.md, "Present on one side only", its first rule: a path the side
    lacking it excluded, or below one, held by the other, is `unknown`,
    reason `not_captured`; a path both excluded is in no record):
    compare.py's EXCLUDED_SCENARIOS. A side
    with exclusions is written in version 2 only (Writer.pair). Every pair
    is written both ways round, so each one-sided path is held before in one
    and after in the other."""
    def free(t, base):
        """A name in the root that no path of t has, nor begins with."""
        p = base
        while any(q.startswith(p) for q in list(t.e) + list(t.x)):
            p += b'0'
        return p

    def put(rng, t, p, typ):
        t.e[p] = clear_flags(new_entry(rng, t, p, typ, extras=typ != 'dir'), t, rng)
        return t.e[p]

    # An excluded directory with entries one and two levels below it, an
    # excluded regular file, both held on the other side; names that extend
    # the directory's (d!x, d-x, d.x: they sort between d and d/...) on the
    # other side only, which the exclusion does not cover; belay's state
    # directory excluded on both sides; two paths excluded on both sides
    # whose order by bytes (q!r < q/r) is not their order by components.
    def build(rng):
        t = unflagged_tree(rng)
        d, f, sd, q = free(t, b'xd'), free(t, b'xf'), free(t, b'.belay'), free(t, b'xq')
        for p, typ in ((d, 'dir'), (d + b'/c', 'reg'), (d + b'/s', 'dir'),
                       (d + b'/s/g', random_type(rng)), (d + b'!x', 'dir'),
                       (d + b'!x/y', 'reg'), (d + b'-x', 'reg'), (d + b'.x', 'fifo'),
                       (f, 'reg'), (sd, 'dir'), (sd + b'/m', 'reg'), (q, 'dir'),
                       (q + b'/r', 'reg'), (q + b'!r', 'reg')):
            put(rng, t, p, typ)
        a = t.copy()
        exclude(t, d)
        exclude(t, f)
        for side in (t, a):
            exclude(side, sd, 'state_dir')
            exclude(side, q + b'/r')
            exclude(side, q + b'!r')
        t.drop_below(d + b'!x')
        for p in (d + b'!x', d + b'-x'):
            del t.e[p]
        return t, a
    w.targeted(rng, 'excluded: a directory and a file on one side, held on the other', build,
               scenarios=['excluded on one side: a directory, held on the other with entries '
                          'below it',
                          'excluded on one side: a non-directory, held on the other',
                          'excluded on one side: a path one level below it, held on the other',
                          'excluded on one side: a path two or more levels below it, held on '
                          'the other',
                          'excluded on both sides: the same path',
                          'excluded on one side: a path on one side only whose name extends it, '
                          'not below it',
                          'excluded: reason state_dir', 'excluded: reason user',
                          'excluded: two paths whose order by bytes is not their order by '
                          'components'],
               version=['v2 with exclusions on both sides',
                        'header: one excluded list with both reasons, state_dir and user',
                        'header: a path in both excluded lists',
                        'header: two non-empty excluded lists that differ'])

    # A directory whose name is not UTF-8 (path_b64), excluded on one side.
    def build(rng):
        t = unflagged_tree(rng)
        n = free(t, b'xn\xff')
        for p, typ in ((n, 'dir'), (n + b'/k', 'reg'), (n + b'/\xfe', 'dir'),
                       (n + b'/\xfe/z', 'lnk')):
            put(rng, t, p, typ)
        a = t.copy()
        exclude(t, n)
        return t, a
    w.targeted(rng, 'excluded: a directory not UTF-8 on one side, held on the other', build,
               versions=(2, 2),
               scenarios=['excluded on one side: a path not UTF-8 (path_b64), held on the other '
                          'with entries below it'],
               version=['header: an excluded element spelled path_b64 (not UTF-8)',
                        'header: a non-empty excluded list against []',
                        'header: before_excluded [] (a v2 manifest with no exclusion)',
                        'header: after_excluded [] (a v2 manifest with no exclusion)'])

    # The other one-sided rules, after it in the spec's order
    # (reference.one_sided): the excluded path's parent unstable on the
    # excluding side (u/e; beside it u/f, not excluded, held on the other
    # side only: listing_incomplete);
    # a path held raced on the other side (r); held there as a mount root
    # (m) and as an unreadable directory (z).
    def build(rng):
        t = unflagged_tree(rng)
        u, r, m, z = free(t, b'xu'), free(t, b'xr'), free(t, b'xm'), free(t, b'xz')
        for p, typ in ((u, 'dir'), (u + b'/e', 'reg'), (u + b'/f', 'reg'), (r, 'reg'),
                       (m, 'dir'), (z, 'dir')):
            put(rng, t, p, typ)
        a = t.copy()
        t.e[u]['unstable'] = True
        del t.e[u + b'/f']
        a.e[r]['raced'] = True
        a.e[m] = in_context('mount', a.e[m], a, rng)
        a.e[z]['unreadable'] = True
        for p in (u + b'/e', r, m, z):
            exclude(t, p)
        return t, a
    w.targeted(rng, 'excluded: held on the other side unstable-parented, raced, sealed', build,
               scenarios=['excluded on one side, its parent there unstable: held on the other',
                          'excluded on one side: held on the other, raced',
                          'excluded on one side: held on the other as an unreadable or mount '
                          'directory',
                          'a child on one side only below an unstable directory'])

    # Excluded on both sides at different depths: d on one, d/e on the other,
    # which holds d and the rest of it.
    def build(rng):
        t = unflagged_tree(rng)
        d = free(t, b'xd')
        for p, typ in ((d, 'dir'), (d + b'/e', 'dir'), (d + b'/e/i', 'reg'), (d + b'/f', 'reg'),
                       (d + b'/g', 'dir'), (d + b'/g/h', 'sock')):
            put(rng, t, p, typ)
        a = t.copy()
        exclude(t, d)
        exclude(a, d + b'/e')
        return t, a
    w.targeted(rng, 'excluded: a directory on one side, a path below it on the other', build,
               scenarios=['excluded on one side, a path below it excluded on the other'],
               version=['v2 with exclusions on both sides'])

    # Excluded on one side, nothing there on the other: no record. The other
    # side in version 1.
    def build(rng):
        t = unflagged_tree(rng)
        g, h = free(t, b'xg'), free(t, b'xh')
        a = t.copy()
        exclude(t, g, 'user', dev=t.root_dev(), ino=rng.randrange(2, 1 << 40))
        put(rng, a, h, 'reg')                   # and a path added
        return t, a
    w.targeted(rng, 'excluded: on one side, nothing there on the other (v1)', build,
               versions=(2, 1),
               scenarios=['excluded on one side: nothing at or below it on the other'],
               version=['v2 with exclusions against v1', 'before v2, after v1',
                        'before v1, after v2',
                        'header: before_excluded null (a v1 manifest)',
                        'header: after_excluded null (a v1 manifest)',
                        'header: a non-empty excluded list against null (v1)'])

    # Paths interpreters claim below an excluded directory (a venv, a
    # chroot): `unknown` records, `not_captured`, from which pip and dpkg
    # derive no event (diff-events E11; diff-v1 "What each interpreter
    # reports": "none from a path `unknown` only as `not_captured`").
    def build(rng):
        rec, st = SITE[0] + b'foo-1.0.dist-info/RECORD', b'chroot/var/lib/dpkg/status'
        t, a = build_items(rng, [(rec, 'added', {}), (st, 'added', {})])
        for p in (b'venv', b'chroot'):          # build_items made them on both sides
            exclude(t, p)
        return t, a
    w.targeted(rng, 'excluded: a venv and a chroot on one side, held on the other', build,
               scenarios=['excluded on one side: held on the other, a path below it an '
                          'interpreter claims'],
               interp=['pip RECORD: unknown, one side only, not captured (excluded): no event '
                       '(E11)',
                       'dpkg status: unknown, one side only, not captured (excluded): no event '
                       '(E11)',
                       'events: none, every claimed path not captured (E11)'])

    # E11 beside what is read, the exclusions at the dist-info and the
    # status file themselves, on both sides: before excludes foo's
    # dist-info, an unnamed one (x-) and the chroot's status, which after
    # holds -- no event, not even could_not_interpret or
    # content_unavailable; after excludes bar-1.0's dist-info, which before
    # holds, and adds bar-2.0: a lone pip_installed, not provisional (no
    # upgrade from a side not looked at); the root's status, modified and
    # read, is the one content_unavailable event's only path.
    def build(rng):
        s = SITE[0]
        t, a = build_items(rng, [(s + b'foo-1.0.dist-info/RECORD', 'modified', {}),
                                 (s + b'x-.dist-info/RECORD', 'modified', {}),
                                 (s + b'bar-1.0.dist-info/RECORD', 'modified', {}),
                                 (s + b'bar-2.0.dist-info/RECORD', 'added', {'own_dir': True}),
                                 (b'chroot/var/lib/dpkg/status', 'modified', {}),
                                 (b'var/lib/dpkg/status', 'modified', {})])
        for p in (s + b'foo-1.0.dist-info', s + b'x-.dist-info', b'chroot/var/lib/dpkg/status'):
            exclude(t, p)
        exclude(a, s + b'bar-1.0.dist-info')
        return t, a
    w.targeted(rng, 'excluded: dist-infos and a status, beside a RECORD and a status read', build,
               scenarios=['excluded on one side: held on the other, a path below it an '
                          'interpreter claims',
                          'excluded on one side: a non-directory, held on the other'],
               interp=['pip RECORD: unknown, one side only, not captured (excluded): no event '
                       '(E11)',
                       'dpkg status: unknown, one side only, not captured (excluded): no event '
                       '(E11)',
                       'pip RECORD: unknown, one side only, not captured, a dist-info that '
                       'cannot be named: no event (E11)',
                       'pip events: a RECORD not captured, another of its pair key known: that '
                       'one alone, not provisional (E11)',
                       'dpkg events: a status not captured beside one that is read: that one '
                       'alone (E11)'],
               version=['v2 with exclusions on both sides'])

    # The same below a directory not captured: unreadable, or a mount root,
    # on the side that lacks the path (diff-v1 "Present on one side only":
    # "That ancestor is a directory carrying `unreadable` or `mount`:
    # `unknown`, reason `not_captured`") -- E11 alike.
    def sealed(how):
        def build(rng):
            s, s0 = SITE[1], SITE[0]
            t, a = build_items(rng, [(s + b'foo-1.0.dist-info/RECORD', 'modified', {}),
                                     (s + b'x-.dist-info/RECORD', 'modified', {}),
                                     (s0 + b'bar-1.0.dist-info/RECORD', 'modified', {}),
                                     (s0 + b'bar-2.0.dist-info/RECORD', 'added',
                                      {'own_dir': True}),
                                     (b'chroot/var/lib/dpkg/status', 'modified', {}),
                                     (b'var/lib/dpkg/status', 'modified', {})])
            for side, p in ((t, s + b'foo-1.0.dist-info'), (t, s + b'x-.dist-info'),
                            (t, b'chroot/var/lib/dpkg'), (a, s0 + b'bar-1.0.dist-info')):
                side.drop_below(p)
                if how == 'unreadable':
                    side.e[p]['unreadable'] = True
                else:
                    side.e[p] = in_context('mount', side.e[p], side, rng)
            return t, a
        return build
    for how, why in (('unreadable', 'below an unreadable directory'), ('mount', 'below a mount')):
        w.targeted(rng, 'not captured: dist-infos and a status below %s directories, beside a '
                        'RECORD and a status read' % how, sealed(how),
                   interp=['pip RECORD: unknown, one side only, not captured (%s): no event '
                           '(E11)' % why,
                           'dpkg status: unknown, one side only, not captured (%s): no event '
                           '(E11)' % why,
                           'pip RECORD: unknown, one side only, not captured, a dist-info that '
                           'cannot be named: no event (E11)',
                           'pip events: a RECORD not captured, another of its pair key known: '
                           'that one alone, not provisional (E11)',
                           'dpkg events: a status not captured beside one that is read: that '
                           'one alone (E11)'])

    # Unknown for another reason, one side only: still provisional events
    # (E11: "Any other `unknown` path still derives provisional events
    # (E2)"). A RECORD and a status whose directory after is unstable and
    # lacks them (listing_incomplete); a RECORD and a status added, raced.
    def build(rng):
        s = SITE[1]
        t, a = build_items(rng, [(s + b'baz-1.0.dist-info/RECORD', 'modified', {}),
                                 (b'chroot/var/lib/dpkg/status', 'modified', {}),
                                 (SITE[0] + b'quux-1.0.dist-info/RECORD', 'raced_added',
                                  {'own_dir': True}),
                                 (b'srv/ct1/rootfs/var/lib/dpkg/status', 'raced_added', {})])
        for d, p in ((s.rstrip(b'/'), s + b'baz-1.0.dist-info'),
                     (b'chroot/var/lib/dpkg', b'chroot/var/lib/dpkg/status')):
            a.e[d]['unstable'] = True
            a.drop_below(p)
            del a.e[p]
        return t, a
    w.targeted(rng, 'unknown one side only, listing_incomplete and raced: RECORDs and statuses',
               build,
               interp=['%s: unknown, one side only, %s: provisional events (E2)' % (x, r)
                       for x in ('pip RECORD', 'dpkg status')
                       for r in ('listing_incomplete', 'raced')])


# ---------------------------------------------------------------------------
# Interpreters, with no store (diff-v1 "Interpreters"; the driver passes NULL
# options). Paths an interpreter claims are built at the names the prose
# gives (`*/var/lib/dpkg/status`, `*.dist-info/RECORD`, `*/.git/hooks/*`,
# ...), below top-level directories no random name can take (`chroot`,
# `venv`, `repo`, ...; NAMES has none of them), so no claim depends on the
# seed. Every file is a hashed regular file with no flag, `stored` or not as
# the item needs; every directory a plain one with no flag. Each pair is
# built once, and written both ways round: an `added` item is `removed` in
# the reversed pair, an upgrade a downgrade.

def interp_tree(rng, limit=None):
    """A tree for an interpreter pair: a few bystanders (unchanged on both
    sides), and a hash limit within which a file can change size (`limit`
    when given)."""
    return base_tree(rng, rng.randrange(0, 4), limit=limit or size_limit(rng))


def ensure_dirs(t, rng, path):
    """Plain directories, on the root's device and with no flag, for every
    ancestor of `path` that t lacks."""
    comps = path.split(b'/')
    for i in range(1, len(comps)):
        q = b'/'.join(comps[:i])
        e = t.e.get(q)
        if e is None:
            t.e[q] = clear_flags(new_entry(rng, t, q, 'dir', extras=False), t, rng)
        elif e['type'] != 'dir' or e.get('unreadable') or e.get('mount'):
            die('generator bug: %r is not an open directory' % q)


def file_at(rng, t, path, stored=True, mode=None):
    """A hashed regular file at `path`, at least 1 byte, no flag; `stored`
    when asked; its permission bits `mode` when given."""
    e = clear_flags(new_entry(rng, t, path, 'reg', extras=False), t, rng)
    hashed(e, t, rng, least=1)
    if stored:
        e['stored'] = e['sha256']
    if mode is not None:
        e['mode'] = TYPES['reg'] | mode
    return e


def rewritten(e, t, rng):
    """e with other content: another hash and another size within the limit."""
    e2 = dict(e)
    e2['sha256'] = unlike(hexs(rng), e['sha256'])
    e2['size'] = e['size'] + 1 if e['size'] < t.limit else e['size'] - 1
    if 'stored' in e:
        e2['stored'] = e2['sha256']
    e2['mtime_ns'] = e['mtime_ns'] + rng.randrange(1, 10 ** 9)
    e2['ctime_ns'] = e['ctime_ns'] + rng.randrange(1, 10 ** 9)
    return e2


def lnk_at(rng, t, path, target=None):
    """A symlink at `path`, no flag; its target `target` when given."""
    e = clear_flags(new_entry(rng, t, path, 'lnk', extras=False), t, rng)
    if target is not None:
        e['link_target'], e['size'] = target, len(target)
        set_outside(e, t)
    return e


def build_items(rng, items):
    """A pair from items (path, how, options): how is `added` / `removed`
    (the file on one side only; with own_dir, its directory too),
    `raced_added` (added, raced), `dir_added` / `lnk_added` (a directory or a
    symlink, after only), or the file on both sides, then `modified`
    (rewritten), `mode` (to `to_mode`), `mode+uid`, `modified+mode`, `uid`,
    `iflags` (on the after side only: unknown), `unstored` (after side
    rewritten and not stored), `to_dir` / `to_lnk` (a directory or a
    symlink after). A symlink's target is `target` when given. `lnk_*` start
    from a symlink on both sides: `lnk_retarget` (to `to_target`), `lnk_uid`
    (chown-ed), `lnk_to_dir` (a directory after). A file's size is `size`
    when given, after's `to_size` (`modified`, `unstored`): synthetic, so a
    large one costs nothing; the tree's hash limit is then 10**9, so the file
    is still hashed."""
    sized = any('size' in kw or 'to_size' in kw for _, _, kw in items)
    t = interp_tree(rng, limit=10 ** 9 if sized else None)
    for path, how, kw in items:
        ensure_dirs(t, rng, parent_of(path) if kw.get('own_dir') else path)
    a = t.copy()
    for path, how, kw in items:
        side = {'added': a, 'removed': t, 'dir_added': a, 'raced_added': a,
                'lnk_added': a}.get(how)
        if side is not None:
            ensure_dirs(side, rng, path)
            if how == 'lnk_added':
                side.e[path] = lnk_at(rng, side, path, kw.get('target'))
            elif how == 'dir_added':
                side.e[path] = clear_flags(new_entry(rng, side, path, 'dir', extras=False),
                                           side, rng)
            else:
                side.e[path] = file_at(rng, side, path, kw.get('stored', True), kw.get('mode'))
                if 'size' in kw:
                    side.e[path]['size'] = kw['size']
                    settle_hash(side.e[path], side, rng)
                if how == 'raced_added':        # unknown, reason raced
                    side.e[path]['raced'] = True
            continue
        if how.startswith('lnk_'):
            e = lnk_at(rng, t, path, kw.get('target'))
            if how == 'lnk_retarget':
                e2 = dict(e, link_target=kw['to_target'], size=len(kw['to_target']),
                          ctime_ns=e['ctime_ns'] + 1)
                set_outside(e2, a)
            elif how == 'lnk_uid':
                e2 = dict(e, uid=other(rng, IDS, e['uid']), ctime_ns=e['ctime_ns'] + 1)
            elif how == 'lnk_to_dir':
                e2 = clear_flags(new_entry(rng, a, path, 'dir', extras=False), a, rng)
            else:
                die('generator bug: %r' % how)
            t.e[path], a.e[path] = e, e2
            continue
        e = file_at(rng, t, path, kw.get('stored', True), kw.get('mode'))
        if 'size' in kw:
            e['size'] = kw['size']
            settle_hash(e, t, rng)
        if how == 'modified':
            e2 = rewritten(e, t, rng)
        elif how == 'unstored':
            e2 = rewritten(e, t, rng)
            e2.pop('stored', None)
        elif how == 'mode':
            e2 = dict(e, mode=TYPES['reg'] | kw['to_mode'])
        elif how == 'mode+uid':
            e2 = dict(e, mode=TYPES['reg'] | kw['to_mode'], uid=other(rng, IDS, e['uid']))
        elif how == 'modified+mode':
            e2 = dict(rewritten(e, t, rng), mode=TYPES['reg'] | kw['to_mode'])
        elif how == 'uid':
            e2 = dict(e, uid=other(rng, IDS, e['uid']))
        elif how == 'iflags':
            e2 = dict(e, iflags=rng.choice(IFLAGS))
        elif how == 'to_lnk':
            e2 = lnk_at(rng, a, path, kw.get('target'))
        elif how == 'to_dir':
            e2 = clear_flags(new_entry(rng, a, path, 'dir', extras=False), a, rng)
        else:
            die('generator bug: %r' % how)
        if 'to_size' in kw:
            if how not in ('modified', 'unstored'):
                die('generator bug: to_size with %r' % how)
            e2['size'] = kw['to_size']
            settle_hash(e2, a, rng)
        t.e[path], a.e[path] = e, e2
    return t, a


DPKG_ROOTS = [b'', b'chroot/', b'srv/ct1/rootfs/']
SITE = [b'venv/lib/python3.12/site-packages/', b'usr/lib/python3/dist-packages/', b'']
REPOS = [b'repo/', b'work/src/proj/']


def interpreters(w, rng):
    O = {}
    S = lambda **kw: kw
    status = lambda rng: rng.choice(DPKG_ROOTS) + b'var/lib/dpkg/status'

    def one(label, items, interp):
        w.targeted(rng, label, lambda rng: build_items(rng, items(rng)), interp=interp)

    # text: unclaimed, stored on every side it exists on.
    def text_path(rng):
        return rng.choice([b'notes.txt', b'etc/app.conf', b'src/main.c', b'caf\xc3\xa9.md',
                           b'raw\xff.txt'])
    one('text: a stored file rewritten', lambda rng: [(text_path(rng), 'modified', O)],
        ['text: modified, stored on every side it exists on',
         'events: none, though records carry findings'])
    one('text: a stored file added', lambda rng: [(text_path(rng), 'added', O)],
        ['text: added, stored on every side it exists on',
         'text: removed, stored on every side it exists on'])
    one('text: a stored file chmod-ed', lambda rng: [(text_path(rng), 'mode',
                                                      S(to_mode=0o600, mode=0o644))],
        ['text: metadata_only, stored on every side it exists on'])
    one('text: a stored file, iflags on one side only', lambda rng: [(text_path(rng), 'iflags',
                                                                      O)],
        ['text: unknown, stored on every side it exists on'])
    one('binary: stored on one side only, rewritten',
        lambda rng: [(text_path(rng), 'unstored', O)],
        ['binary: a regular file stored on one of its two sides only, modified'])

    # dpkg: the status file, with no store.
    one('dpkg: status rewritten', lambda rng: [(status(rng), 'modified', O)],
        ['dpkg status: modified'])
    one('dpkg: status added', lambda rng: [(status(rng), 'added', O)],
        ['dpkg status: added', 'dpkg status: removed'])
    one('dpkg: status added, no stored copy', lambda rng: [(status(rng), 'added',
                                                            S(stored=False))],
        ['dpkg status: added, a side with no stored copy',
         'dpkg status: removed, a side with no stored copy'])
    one('dpkg: status chmod-ed', lambda rng: [(status(rng), 'mode',
                                              S(mode=0o644, to_mode=0o640))],
        ['dpkg status: metadata_only'])
    one('dpkg: status becomes a directory', lambda rng: [(status(rng), 'to_dir', O)],
        ['dpkg status: type_changed, reg -> dir', 'dpkg status: type_changed, dir -> reg'])
    one('dpkg: two status files, one added and one removed',
        lambda rng: [(b'chroot/var/lib/dpkg/status', 'added', O),
                     (b'srv/ct1/rootfs/var/lib/dpkg/status', 'removed', O)],
        ['dpkg events: two status files with different sides'])
    one('dpkg: two status files, one rewritten and one added',
        lambda rng: [(b'var/lib/dpkg/status', 'modified', O),
                     (b'chroot/var/lib/dpkg/status', 'added', O)],
        ['dpkg events: two status files with different sides'])
    one('dpkg: two status files added',
        lambda rng: [(b'chroot/var/lib/dpkg/status', 'added', O),
                     (b'srv/ct1/rootfs/var/lib/dpkg/status', 'added', O)],
        ['dpkg events: two status files with the same side'])
    one('dpkg: info files, stored',
        lambda rng: [(b'var/lib/dpkg/info/libc6:amd64.list', 'modified', O),
                     (b'var/lib/dpkg/info/libc6:amd64.md5sums', 'added', O)],
        ['dpkg info: modified', 'dpkg info: added'])

    # pip: RECORDs added and removed (from the paths alone), and in place.
    def dist(site, base, how, own=True, with_metadata=True):
        out = [(site + base + b'.dist-info/RECORD', how, S(own_dir=own))]
        if with_metadata:
            out.append((site + base + b'.dist-info/METADATA', how, O))
        return out
    one('pip: a distribution installed',
        lambda rng: dist(rng.choice(SITE), b'requests-2.32.3', 'added'),
        ['pip events: pip_installed', 'pip events: pip_removed', 'pip METADATA: added'])
    one('pip: a distribution upgraded, spelled differently',
        lambda rng: (lambda s: dist(s, b'Foo_Bar-1.0', 'removed')
                     + dist(s, b'foo.bar-2.0', 'added'))(rng.choice(SITE)),
        ['pip events: pip_upgraded', 'pip events: pip_downgraded',
         'pip events: a pair whose names are spelled differently'])
    one('pip: pre-release to release',
        lambda rng: (lambda s: dist(s, b'pkg-1.0a1', 'removed')
                     + dist(s, b'pkg-1.0', 'added'))(rng.choice(SITE)),
        ['pip events: pip_upgraded', 'pip events: pip_downgraded'])
    one('pip: versions equal by PEP 440',
        lambda rng: (lambda s: dist(s, b'six-1.0', 'removed')
                     + dist(s, b'six-1.0.0', 'added'))(rng.choice(SITE)),
        ['pip events: pip_version_changed, equal by PEP 440'])
    one('pip: a version that is not PEP 440',
        lambda rng: (lambda s: dist(s, b'tool-1.0', 'removed')
                     + dist(s, b'tool-nightly', 'added'))(rng.choice(SITE)),
        ['pip events: pip_version_changed, not a PEP 440 version'])
    one('pip: RECORD and METADATA rewritten in place',
        lambda rng: (lambda s: [(s + b'idna-3.7.dist-info/RECORD', 'modified', O),
                                (s + b'idna-3.7.dist-info/METADATA', 'modified', O)])(
                                    rng.choice(SITE)),
        ['pip RECORD: modified', 'pip METADATA: modified'])
    one('pip: several events, one reinstall',
        lambda rng: [(SITE[0] + b'mid-1.0.dist-info/RECORD', 'modified', O)]
        + dist(SITE[0], b'zed-1.0', 'added', with_metadata=False)
        + dist(SITE[1], b'zed-1.0', 'added', with_metadata=False)
        + dist(SITE[0], b'alpha-2.0', 'removed', with_metadata=False),
        ['pip events: content_unavailable first, then several names',
         'pip RECORD: modified'])
    # A dist-info that cannot be named: its RECORD's record carries
    # could_not_interpret (R11) and pip emits one could_not_interpret event
    # naming it, before the named events; the others stand (E10).
    one('pip: a dist-info with no version (E10)',
        lambda rng: dist(rng.choice(SITE), b'nodash', 'added', with_metadata=False),
        ['pip events: a dist-info that cannot be named (E10)',
         'pip RECORD: added, a dist-info that cannot be named',
         'pip RECORD: removed, a dist-info that cannot be named'])
    one('pip: a dist-info with an empty version beside a named one (E10)',
        lambda rng: (lambda s: dist(s, b'empty-', 'removed', with_metadata=False)
                     + dist(s, b'named-0.1', 'added'))(rng.choice(SITE)),
        ['pip events: a dist-info that cannot be named beside a named install (E10)'])
    one('pip: two dist-infos that cannot be named, a reinstall and a named install (E10)',
        lambda rng: (lambda s: dist(s, b'zz', 'added', with_metadata=False)
                     + dist(s, b'aa-', 'removed', with_metadata=False)
                     + [(s + b'mid-1.0.dist-info/RECORD', 'modified', O)]
                     + dist(s, b'named-0.1', 'added'))(rng.choice(SITE)),
        ['pip events: a dist-info that cannot be named beside a named install (E10)'])
    # One name with RECORDs added and removed other than one of each: one
    # could_not_interpret event naming them, in that name's place (E10).
    one('pip: one name removed once and added twice (E10)',
        lambda rng: (lambda s: dist(s, b'dup-1.0', 'removed', with_metadata=False)
                     + dist(s, b'dup-2.0', 'added', with_metadata=False)
                     + dist(s, b'Dup-3.0', 'added', with_metadata=False))(rng.choice(SITE)),
        ['pip events: a pair key with more than one RECORD added and removed (E10)'])
    one('pip: an ambiguous name between two others (E10)',
        lambda rng: (lambda s: dist(s, b'alpha-1.0', 'added', with_metadata=False)
                     + dist(s, b'dup-1.0', 'removed', with_metadata=False)
                     + dist(s, b'dup-2.0', 'added', with_metadata=False)
                     + dist(s, b'DUP-3.0', 'added', with_metadata=False)
                     + dist(s, b'zeta-1.0', 'removed', with_metadata=False)
                     + dist(s, b'zeta-2.0', 'added', with_metadata=False))(rng.choice(SITE)),
        ['pip events: a pair key with more than one RECORD added and removed beside '
         'another name (E10)'])
    # An unknown RECORD pairs like any other, its events provisional (E2):
    # with a removed one of its name (an upgrade), alone (an install); on
    # both sides, a provisional reinstall, its files not counted.
    one('pip: one RECORD of a name removed, the other added but raced',
        lambda rng: (lambda s: dist(s, b'lazy-1.0', 'removed', with_metadata=False)
                     + [(s + b'lazy-2.0.dist-info/RECORD', 'raced_added', S(own_dir=True))])(
                         rng.choice(SITE)),
        ['pip RECORD: unknown, a regular file on one side only',
         'pip events: an unknown RECORD paired with one of the other side (E2)'])
    one('pip: a RECORD added but raced, beside a named install',
        lambda rng: (lambda s: [(s + b'quick-0.9.dist-info/RECORD', 'raced_added',
                                 S(own_dir=True))]
                     + dist(s, b'steady-1.0', 'added', with_metadata=False))(rng.choice(SITE)),
        ['pip events: an unknown RECORD with none of the other side (E2)'])
    one('pip: a RECORD in place, iflags on one side only',
        lambda rng: [(rng.choice(SITE) + b'idle-1.0.dist-info/RECORD', 'iflags', O)],
        ['pip RECORD: unknown, a regular file on both sides',
         'pip events: a provisional reinstall, its files not counted'])
    one('pip: a RECORD added but raced, its dist-info not named, beside a reinstall',
        lambda rng: (lambda s: [(s + b'x-.dist-info/RECORD', 'raced_added', S(own_dir=True)),
                                (s + b'mid-1.0.dist-info/RECORD', 'modified', O)])(
                                    rng.choice(SITE)),
        ['pip RECORD: unknown, a regular file on one side only, a dist-info that cannot be '
         'named'])
    one('pip: one name removed once and added twice, one of them raced',
        lambda rng: (lambda s: dist(s, b'dup-1.0', 'removed', with_metadata=False)
                     + dist(s, b'dup-2.0', 'added', with_metadata=False)
                     + [(s + b'dup-3.0.dist-info/RECORD', 'raced_added', S(own_dir=True))])(
                         rng.choice(SITE)),
        ['pip events: a pair key with more than one RECORD added and removed, one unknown '
         '(E10, E2)'])
    # A name and version each a string field's value whose event's text
    # would exceed 1,024 bytes: one invalid_finding event in its place, the
    # others stand (E9). A name over 1,024 bytes, or not UTF-8, cannot be
    # named (E10).
    one('pip: an upgrade whose text would exceed 1,024 bytes (E9)',
        lambda rng: (lambda s: dist(s, b'n' * 340 + b'-' + b'1' * 340, 'removed',
                                    with_metadata=False)
                     + dist(s, b'n' * 340 + b'-' + b'2' * 340, 'added', with_metadata=False)
                     + dist(s, b'other-1.0', 'added', with_metadata=False))(rng.choice(SITE)),
        ['pip events: an event whose text would exceed 1,024 bytes (E9)'])
    one('pip: an install whose text would exceed 1,024 bytes (E9)',
        lambda rng: dist(rng.choice(SITE), b'm' * 600 + b'-' + b'1' * 600, 'added',
                         with_metadata=False),
        ['pip events: an event whose text would exceed 1,024 bytes (E9)'])
    one('pip: a dist-info whose name is over 1,024 bytes',
        lambda rng: dist(rng.choice(SITE), b'm' * 1100 + b'-1.0', 'added', with_metadata=False),
        ["pip RECORD: added, a dist-info whose name or version is not a string field's value"])
    one('pip: a dist-info whose name is not UTF-8',
        lambda rng: dist(rng.choice(SITE), b'b\xffad-1.0', 'added', with_metadata=False),
        ["pip RECORD: added, a dist-info whose name or version is not a string field's value"])
    # A dist-info that cannot be named, rewritten in place: could_not_interpret
    # on its record and one event, "nothing more is read from it" (no
    # content_unavailable); unknown on both sides, named like any other: a
    # provisional could_not_interpret event, nothing on its record (E10).
    one('pip: a RECORD rewritten in place, its dist-info not named',
        lambda rng: [(rng.choice(SITE) + b'nover.dist-info/RECORD', 'modified', O)],
        ['pip RECORD: modified, a dist-info that cannot be named'])
    one('pip: a RECORD in place, iflags on one side only, its dist-info not named',
        lambda rng: [(rng.choice(SITE) + b'idle-.dist-info/RECORD', 'iflags', O)],
        ['pip RECORD: unknown, a regular file on both sides, a dist-info that cannot be named',
         'pip events: an unknown RECORD on both sides that cannot be named (E10, E2)'])
    # An unknown RECORD on both sides is a provisional pip_reinstalled with
    # its three counts absent (the kind's second template): beside other
    # names (by normalized name), beside an install of its own name in its
    # directory (then by kind), beside one that cannot be named (no name
    # first), and one whose text would exceed 1,024 bytes (E9).
    one('pip: a RECORD in place, iflags on one side only, between two other names',
        lambda rng: (lambda s: dist(s, b'alpha-2.0', 'removed', with_metadata=False)
                     + [(s + b'Mid_Pkg-1.0.dist-info/RECORD', 'iflags', O)]
                     + dist(s, b'zed-1.0', 'added', with_metadata=False))(rng.choice(SITE)),
        ['pip events: a provisional reinstall, its files not counted'])
    one('pip: a RECORD in place, iflags on one side only, its name installed beside it',
        lambda rng: (lambda s: [(s + b'same-1.0.dist-info/RECORD', 'iflags', O)]
                     + dist(s, b'Same-2.0', 'added', with_metadata=False))(rng.choice(SITE)),
        ['pip events: a provisional reinstall beside an install or removal of its name '
         '(by kind)'])
    one('pip: a RECORD in place, iflags on one side only, beside one not named',
        lambda rng: (lambda s: [(s + b'ok-1.0.dist-info/RECORD', 'iflags', O),
                                (s + b'nover.dist-info/RECORD', 'iflags', O)])(
                                    rng.choice(SITE)),
        ['pip events: a provisional reinstall beside an unknown RECORD on both sides that '
         'cannot be named'])
    one('pip: a RECORD in place, iflags on one side only, its text over 1,024 bytes (E9)',
        lambda rng: [(rng.choice(SITE) + b'r' * 600 + b'-' + b'9' * 600
                      + b'.dist-info/RECORD', 'iflags', O)],
        ['pip events: a provisional reinstall whose text would exceed 1,024 bytes (E9)'])
    # Two events of one name, kind and directory: "then the paths it lists"
    # -- here against the versions' order and the order they are written in
    # (`Twin-2.0` before `twin-1.0` bytewise); `twin_` is another name
    # (`twin-`), sorting after.
    one('pip: one name installed twice in one directory',
        lambda rng: (lambda s: dist(s, b'twin-1.0', 'added', with_metadata=False)
                     + dist(s, b'Twin-2.0', 'added', with_metadata=False)
                     + dist(s, b'twin_-0.1', 'removed', with_metadata=False))(rng.choice(SITE)),
        ['pip events: one name, several RECORDs on one side in one directory (then by paths)'])

    # git: hooks and the index from the manifest alone; HEAD, refs,
    # packed-refs and reflogs need content.
    g = lambda rng, rest: rng.choice(REPOS) + b'.git/' + rest
    one('git: an executable hook added',
        lambda rng: [(g(rng, b'hooks/pre-commit'), 'added', S(mode=0o755))],
        ['git hook: added, executable', 'git hook: removed'])
    one('git: a hook added, not executable',
        lambda rng: [(g(rng, b'hooks/post-merge.sample'), 'added', S(mode=0o644,
                                                                     stored=False))],
        ['git hook: added, not executable', 'git hook: removed'])
    one('git: a hook rewritten',
        lambda rng: [(g(rng, b'hooks/pre-push'), 'modified', S(mode=0o755))],
        ['git hook: modified'])
    one('git: a hook made executable',
        lambda rng: [(g(rng, b'hooks/commit-msg'), 'mode', S(mode=0o644, to_mode=0o755))],
        ['git hook: metadata_only, the executable bit changed'])
    one('git: a hook chown-ed',
        lambda rng: [(g(rng, b'hooks/commit-msg'), 'uid', S(mode=0o755))],
        ['git hook: metadata_only, the executable bit unchanged'])
    one('git: the index rewritten',
        lambda rng: [(g(rng, b'index'), 'modified', S(stored=False))],
        ['git index: modified'])
    one('git: the index added',
        lambda rng: [(g(rng, b'index'), 'added', S(stored=False))],
        ['git index: added', 'git index: removed'])
    one('git: HEAD rewritten', lambda rng: [(g(rng, b'HEAD'), 'modified', O)],
        ['git HEAD: modified'])
    one('git: HEAD added', lambda rng: [(g(rng, b'HEAD'), 'added', O)],
        ['git HEAD: added', 'git HEAD: removed'])
    one('git: HEAD rewritten, no stored copy',
        lambda rng: [(g(rng, b'HEAD'), 'modified', S(stored=False))],
        ['git HEAD: modified, a side with no stored copy'])
    one('git: a loose ref added', lambda rng: [(g(rng, b'refs/heads/main'), 'added', O)],
        ['git ref: added', 'git ref: removed'])
    one('git: a loose ref moved', lambda rng: [(g(rng, b'refs/tags/v1'), 'modified', O)],
        ['git ref: modified'])
    one('git: a loose ref added, no stored copy',
        lambda rng: [(g(rng, b'refs/heads/topic'), 'added', S(stored=False))],
        ['git ref: added, a side with no stored copy'])
    one('git: packed-refs rewritten', lambda rng: [(g(rng, b'packed-refs'), 'modified', O)],
        ['git packed-refs: modified'])
    one('git: a reflog appended', lambda rng: [(g(rng, b'logs/HEAD'), 'modified', O)],
        ['git reflog: modified'])
    one('git: a reflog added', lambda rng: [(g(rng, b'logs/refs/heads/main'), 'added', O)],
        ['git reflog: added', 'git reflog: removed'])
    # "| git | a reflog | 16 MiB: a capture keeps a reflog up to this
    # whatever `store_max_bytes` says, and a side recorded without a copy
    # because it is larger is `content_unavailable`, reason `too_large` |";
    # "`missing` covers a path whose entry records no `stored` copy (a reflog
    # over its 16 MiB bound excepted: `too_large`)". At the bound exactly, no
    # copy is `missing`; one byte over, `too_large`; removed, no copy needed.
    # Appended past the bound: before stored (`no_store`), after not
    # (`too_large`), and the other way round when reversed.
    MIB16 = 16 * 1024 * 1024
    one('git: a reflog over its 16 MiB bound added, no stored copy',
        lambda rng: [(g(rng, b'logs/refs/heads/big'), 'added', S(stored=False,
                                                                  size=MIB16 + 1))],
        ['git reflog: added, a side with no stored copy, over 16 MiB',
         'git reflog: removed, a side with no stored copy, over 16 MiB'])
    one('git: a reflog of exactly 16 MiB added, no stored copy',
        lambda rng: [(g(rng, b'logs/HEAD'), 'added', S(stored=False, size=MIB16))],
        ['git reflog: added, a side with no stored copy, of exactly 16 MiB'])
    one('git: a reflog appended past its 16 MiB bound, after with no stored copy',
        lambda rng: [(g(rng, b'logs/HEAD'), 'unstored', S(size=MIB16 - 100,
                                                          to_size=MIB16 + 4000))],
        ['git reflog: modified, a side with no stored copy, over 16 MiB'])
    one('git: a reflog grown past its 16 MiB bound, neither side with a stored copy',
        lambda rng: [(g(rng, b'logs/refs/heads/main'), 'modified',
                      S(stored=False, size=MIB16, to_size=MIB16 + 1))],
        ['git reflog: modified, a side with no stored copy, over 16 MiB'])
    one('git: a directory below refs/ added',
        lambda rng: [(g(rng, b'refs/remotes'), 'dir_added', O)],
        ['git ref: added, not a regular file on either side (dir)'])
    # "A hook, from the manifest alone, is a regular file or a symlink";
    # "a directory is none", and a side on which another claimed path is not
    # a regular file counts as absent: nothing from a directory under hooks/
    # or a symlink or directory under logs/refs/. A symlinked hook is added,
    # removed, changed (retargeted, or a file becoming a link or back), its
    # `target` the link's (empty for a file), `executable` absent for a
    # symlink after. `target` is a `bytes` field: up to 4,095 bytes (the
    # manifest's own limit, addendum A4, so no longer one can be built),
    # `target_b64` when not UTF-8 -- never invalid_finding.
    one('git: a symlink under hooks/ added',
        lambda rng: [(g(rng, b'hooks/pre-commit'), 'lnk_added',
                      S(target=b'tools/pre-commit.sh'))],
        ['git hook: added, a symlink', 'git hook: removed, a symlink'])
    one('git: a symlink under hooks/ with a non-ASCII target added',
        lambda rng: [(g(rng, b'hooks/post-checkout'), 'lnk_added',
                      S(target=b'caf\xc3\xa9/post-checkout'))],
        ['git hook: added, a symlink', 'git hook: removed, a symlink'])
    one('git: a symlink under hooks/ added, its target not UTF-8',
        lambda rng: [(g(rng, b'hooks/pre-commit'), 'lnk_added', S(target=b'bad\xfftarget'))],
        ['git hook: added, a symlink, its target not UTF-8'])
    one('git: a symlink under hooks/ added, its target 1,101 bytes',
        lambda rng: [(g(rng, b'hooks/pre-commit'), 'lnk_added',
                      S(target=b'd/' * 549 + b'end'))],
        ['git hook: added, a symlink, its target over 1,024 bytes'])
    one('git: a symlink under hooks/ added, its target 1,024 bytes',
        lambda rng: [(g(rng, b'hooks/pre-commit'), 'lnk_added',
                      S(target=b'd/' * 511 + b'xx'))],
        ['git hook: added, a symlink, its target of exactly 1,024 bytes'])
    one('git: a symlink under hooks/ added, its target 4,095 bytes (the manifest\'s limit)',
        lambda rng: [(g(rng, b'hooks/pre-commit'), 'lnk_added',
                      S(target=b'd/' * 2046 + b'xxx'))],
        ['git hook: added, a symlink, its target of 4,095 bytes',
         'git hook: removed, a symlink, its target of 4,095 bytes'])
    one('git: a symlink under hooks/ added, its target 4,095 bytes, not UTF-8',
        lambda rng: [(g(rng, b'hooks/post-rewrite'), 'lnk_added',
                      S(target=b'x/' * 2046 + b'\xfe\xff\xc3'))],
        ['git hook: added, a symlink, its target of 4,095 bytes, not UTF-8',
         'git hook: removed, a symlink, its target of 4,095 bytes, not UTF-8'])
    one('git: a symlinked hook retargeted to a target not UTF-8',
        lambda rng: [(g(rng, b'hooks/pre-push'), 'lnk_retarget',
                      S(target=b'hooks.d/pre-push', to_target=b'hooks.d/pre-push\xe9'))],
        ['git hook: modified, a symlink, its target not UTF-8'])
    one('git: a hook becomes a symlink whose target is not UTF-8',
        lambda rng: [(g(rng, b'hooks/pre-applypatch'), 'to_lnk',
                      S(mode=0o755, target=b'\x80\x81/pre-applypatch'))],
        ['git hook: type_changed, reg -> lnk, its target not UTF-8',
         'git hook: type_changed, lnk -> reg, executable'])
    one('git: a symlinked hook retargeted',
        lambda rng: [(g(rng, b'hooks/pre-push'), 'lnk_retarget',
                      S(target=b'hooks.d/pre-push-v1', to_target=b'hooks.d/pre-push-v2'))],
        ['git hook: modified, a symlink'])
    one('git: a symlinked hook chown-ed',
        lambda rng: [(g(rng, b'hooks/pre-push'), 'lnk_uid', S(target=b'shared/pre-push'))],
        ['git hook: metadata_only, a symlink'])
    one('git: a symlinked hook becomes a directory',
        lambda rng: [(g(rng, b'hooks/update'), 'lnk_to_dir', S(target=b'update.real'))],
        ['git hook: type_changed, lnk -> dir'])
    one('git: a directory under hooks/ added',
        lambda rng: [(g(rng, b'hooks/pre-commit.d'), 'dir_added', O)],
        ['git hook: added, not a regular file on either side (dir)'])
    one('git: a directory under logs/refs/ added',
        lambda rng: [(g(rng, b'logs/refs/remotes'), 'dir_added', O)],
        ['git reflog: added, not a regular file on either side (dir)'])
    one('git: a symlink under logs/refs/ added',
        lambda rng: [(g(rng, b'logs/refs/heads/alias'), 'lnk_added', O)],
        ['git reflog: added, not a regular file on either side (lnk)'])
    one('git: a hook becomes a symlink',
        lambda rng: [(g(rng, b'hooks/pre-push'), 'to_lnk',
                      S(mode=0o755, target=b'pre-push.d/run'))],
        ['git hook: type_changed, reg -> lnk', 'git hook: type_changed, lnk -> reg'])
    one('git: a hook not executable becomes a symlink',
        lambda rng: [(g(rng, b'hooks/prepare-commit-msg'), 'to_lnk',
                      S(mode=0o644, target=b'shared/prepare-commit-msg'))],
        ['git hook: type_changed, reg -> lnk', 'git hook: type_changed, lnk -> reg',
         'git hook: type_changed, lnk -> reg, not executable'])
    one('text: a stored *.md5sums outside var/lib/dpkg/info/',
        lambda rng: [(rng.choice([b'dist/sums.md5sums', b'var/lib/dpkg/sums.md5sums']),
                      'modified', O)],
        ['text: a stored *.md5sums file outside var/lib/dpkg/info/, modified'])
    one('git: an unclaimed file below .git/, stored',
        lambda rng: [(g(rng, b'config'), 'modified', O)],
        ['text: an unclaimed stored file below .git/, modified'])

    # A hook whose executable bit changed beside another field ("its
    # content unchanged -- its executable bit ..., whatever else changed"),
    # or beside its content (changed); a status file whose outcome is
    # unknown ("read too, and every event from it is provisional": with no
    # store, a provisional content_unavailable event and no finding on its
    # record), alone and beside a status that is not; two reasons in one
    # interpreter (one event per reason, `no_store` first).
    one('git: a hook made executable and chown-ed',
        lambda rng: [(g(rng, b'hooks/pre-rebase'), 'mode+uid', S(mode=0o644, to_mode=0o755))],
        ['git hook: metadata_only, the executable bit changed'])
    one('git: a hook rewritten and made executable',
        lambda rng: [(g(rng, b'hooks/update'), 'modified+mode', S(mode=0o644, to_mode=0o755))],
        ['git hook: modified'])
    one('dpkg: status, iflags on one side only',
        lambda rng: [(status(rng), 'iflags', O)],
        ['dpkg status: unknown, a regular file on both sides'])
    one('dpkg: status added but raced',
        lambda rng: [(status(rng), 'raced_added', O)],
        ['dpkg status: unknown, a regular file on one side only'])
    one('dpkg: status added but raced, no stored copy',
        lambda rng: [(status(rng), 'raced_added', S(stored=False))],
        ['dpkg status: unknown, a side with no stored copy, a regular file on one side only'])
    one('dpkg: status added but raced, beside a status rewritten',
        lambda rng: [(b'var/lib/dpkg/status', 'modified', O),
                     (b'chroot/var/lib/dpkg/status', 'raced_added', O)],
        ['dpkg status: unknown, a regular file on one side only'])
    one('dpkg: two status files, one with no stored copy',
        lambda rng: [(b'var/lib/dpkg/status', 'modified', O),
                     (b'chroot/var/lib/dpkg/status', 'added', S(stored=False))],
        ['dpkg events: two reasons in one diff'])

    # Events of two interpreters in one diff, in E4's order.
    one('pip and dpkg in one diff',
        lambda rng: [(b'var/lib/dpkg/status', 'modified', O)]
        + dist(SITE[1], b'attrs-23.2.0', 'added'),
        ['events: from pip and dpkg in one diff'])


# ---------------------------------------------------------------------------
# git's repository-level events (test/expect/diff-events.md E12), with a
# store: pairs whose HEAD, loose refs, packed-refs and reflogs have copies in
# the store the diff is given, so git reads them. Only git's paths are stored
# there (a text, pip or dpkg copy the reference does not compute is never in
# a store). The content is git's own format, as git writes it.

GIT_ZERO = '0' * 40
GIT_IDENT = 'A U Thor <a@example.com> %d +0000'


def git_packed(*refs):
    """packed-refs: its header, then `<id> <name>` lines (a `^<id>` peeled
    line after a tag given as (id, name, peeled))."""
    out = b'# pack-refs with: peeled fully-peeled sorted \n'
    for r in refs:
        out += ('%s %s\n' % (r[0], r[1])).encode()
        if len(r) > 2:
            out += ('^%s\n' % r[2]).encode()
    return out


def git_reflog(*entries):
    """A reflog: `<old> <new> <identity> <time> <zone>\\t<message>` lines."""
    return b''.join(('%s %s %s\t%s\n' % (old, new, GIT_IDENT % (1761000000 + i), msg)).encode()
                    for i, (old, new, msg) in enumerate(entries))


def git_loose(oid):
    return (oid + '\n').encode()


def git_head(target):
    """HEAD: `ref: refs/heads/<branch>` for a branch name (str), else the
    commit it is detached at."""
    if len(target) == 40 and all(c in '0123456789abcdef' for c in target):
        return git_loose(target)
    return ('ref: refs/heads/%s\n' % target).encode()


def content_entry(rng, t, path, data, base=None):
    """A regular file holding `data`: hashed (the tree's limit holds it),
    `stored` -- its copy named by its sha256 -- and, given `base` (the same
    path before), the same inode, owner and mode, later times."""
    e = file_at(rng, t, path, stored=True, mode=0o644)
    e['size'] = len(data)
    e['sha256'] = e['stored'] = hashlib.sha256(data).hexdigest()
    if base is not None:
        for k in ('mode', 'uid', 'gid', 'ino', 'dev', 'nlink'):
            e[k] = base[k]
        e['mtime_ns'] = base['mtime_ns'] + rng.randrange(1, 10 ** 9)
        e['ctime_ns'] = base['ctime_ns'] + rng.randrange(1, 10 ** 9)
    return e


def git_build(rng, files):
    """(before, after, store) from files [(path, before bytes or None, after
    bytes or None, options)]. Equal bytes on both sides are one unchanged
    entry. Options: raced -- the after entry `raced` (unknown, read from its
    copy); iflags -- iflags on the after side only (unknown on both sides);
    unstored -- that side's entry records no `stored` copy (`missing`);
    (iflags on one side only makes an unchanged file unknown, a changed one
    stays modified: content proves the change, so it is not used here);
    lacking -- that side's copy is stored but not in the store (`missing`);
    chmod -- equal bytes, after's mode changed (metadata_only);
    corrupt -- the store holds other bytes under that side's name;
    symlink -- the store holds a symlink there (`corrupt` both)."""
    t = interp_tree(rng, limit=10 ** 9)
    for path, _, _, _ in files:
        ensure_dirs(t, rng, path)
    a = t.copy()
    store = {}
    for path, xb, xa, kw in files:
        eb = ea = None
        if xb is not None:
            eb = t.e[path] = content_entry(rng, t, path, xb)
        if xa is not None:
            if xa == xb and kw.get('chmod'):
                ea = dict(eb, mode=eb['mode'] ^ 0o040, ctime_ns=eb['ctime_ns'] + 1)
            elif xa == xb and not kw.get('raced') and not kw.get('iflags'):
                ea = dict(eb)
            else:
                ea = content_entry(rng, a, path, xa, base=eb)
            if kw.get('raced'):
                ea['raced'] = True
            if kw.get('iflags'):
                ea['iflags'] = rng.choice(IFLAGS[1:])
                ea.pop('xattrs_unknown', None)
            a.e[path] = ea
        for side, e, x in (('before', eb, xb), ('after', ea, xa)):
            if e is None:
                continue
            if kw.get('unstored') == side:
                e.pop('stored')
            elif kw.get('lacking') == side:
                pass
            elif kw.get('corrupt') == side:
                store[e['stored']] = x + b'corrupt\n'
            elif kw.get('symlink') == side:
                store[e['stored']] = ('symlink', '../' + e['stored'][:2] + '/elsewhere')
            else:
                store[e['stored']] = x
    return t, a, store


def git_events(w, rng):
    """E12's rules, each in a pair (and its reverse, which Writer.targeted
    writes too: a creation's reverse is a deletion, an attach's a detach)."""
    oid = lambda: hexs(rng, 40)
    Z, O = GIT_ZERO, {}
    S = lambda **kw: kw
    repo = lambda rng: rng.choice([b'', b'repo/', b'work/src/proj/']) + b'.git/'

    def one(label, files, interp):
        w.targeted(rng, label, lambda rng: git_build(rng, files(rng)), interp=interp)

    def ev(x):
        return ['git events: ' + i for i in x]

    # Created: absent before by its reflog's first old id (zeros), or by
    # packed-refs, a path of this diff, without it; moved with no from
    # without that evidence. Their reverses: deleted, packed-refs not a path
    # of this diff, or a path of it without the branch.
    def created_by_reflog(rng):
        r, c1 = repo(rng), oid()
        return [(r + b'refs/heads/feat', None, git_loose(c1), O),
                (r + b'logs/refs/heads/feat', None,
                 git_reflog((Z, c1, 'branch: Created from HEAD')), O)]
    one('git: a branch created, its reflog from zeros', created_by_reflog,
        ev(['a branch created, absent before by its reflog (zeros)',
            'a branch deleted, packed-refs not a path of this diff']))

    def created_by_packed(rng):
        r, c0, c2, t1 = repo(rng), oid(), oid(), oid()
        return [(r + b'packed-refs', git_packed((c0, 'refs/heads/main')),
                 git_packed((c0, 'refs/heads/main'), (t1, 'refs/tags/v1', c0)), O),
                (r + b'refs/heads/topic', None, git_loose(c2), O)]
    one('git: a branch created, packed-refs without it', created_by_packed,
        ev(['a branch created, absent before by packed-refs',
            'a branch deleted, packed-refs a path of this diff without it']))

    def moved_no_evidence(rng):
        r = repo(rng)
        return [(r + b'refs/heads/dev', None, git_loose(oid()), O)]
    one('git: a ref appears with no evidence of before', moved_no_evidence,
        ev(['a branch moved with no evidence of before (no from)']))

    def packed_only(rng):
        r, c0, c4 = repo(rng), oid(), oid()
        return [(r + b'packed-refs', git_packed((c0, 'refs/heads/main'), (c4, 'refs/heads/old')),
                 git_packed((c0, 'refs/heads/main')), O)]
    one('git: a branch only in packed-refs, deleted', packed_only,
        ev(['a branch deleted from packed-refs, no loose ref']))

    def pack_refs(rng):
        r, c5, c6 = repo(rng), oid(), oid()
        return [(r + b'refs/heads/main', git_loose(c5), None, O),
                (r + b'refs/heads/dev', git_loose(c6), None, O),
                (r + b'packed-refs', None,
                 git_packed((c6, 'refs/heads/dev'), (c5, 'refs/heads/main')), O)]
    # packed-refs rewritten with the same bytes (metadata_only): not read, so
    # no evidence of before ("an unchanged `packed-refs` is never read").
    def touched_packed(rng):
        r, p = repo(rng), git_packed((oid(), 'refs/heads/main'))
        return [(r + b'refs/heads/dev', None, git_loose(oid()), O),
                (r + b'packed-refs', p, p, S(chmod=True))]
    one('git: a ref appears, packed-refs touched but not changed', touched_packed,
        ev(['packed-refs metadata_only, not read: no evidence of before']))
    one('git: refs packed, at the same commits', pack_refs,
        ev(['a branch at the same commit on both sides, from another place']))

    # Renamed: the new branch's reflog says `Branch: renamed`; with HEAD on
    # it, HEAD names another branch too. The reverse is a creation and a
    # deletion (the old name's reflog says nothing of a rename).
    def renamed(rng, head):
        r, c7, c6 = repo(rng), oid(), oid()
        log = [(Z, c7, 'branch: Created from HEAD')]
        msg = 'Branch: renamed refs/heads/old to refs/heads/new'
        f = [(r + b'refs/heads/old', git_loose(c7), None, O),
             (r + b'refs/heads/new', None, git_loose(c7), O),
             (r + b'logs/refs/heads/old', git_reflog(*log), None, O),
             (r + b'logs/refs/heads/new', None, git_reflog(*(log + [(c7, c7, msg)])), O)]
        if head:
            hl = [(Z, c6, 'commit (initial): root'), (c6, c7, 'checkout: moving from main to old')]
            f += [(r + b'HEAD', git_head('old'), git_head('new'), O),
                  (r + b'logs/HEAD', git_reflog(*hl), git_reflog(*(hl + [(c7, c7, msg)])), O)]
        else:                                   # `nz`: between `new` and `old`
            f.append((r + b'refs/heads/nz', None, git_loose(c6), O))
        return f
    one('git: a branch renamed, another branch between its names', lambda rng: renamed(rng, False),
        ev(['a branch renamed', 'a rename in its from\'s place']))
    one('git: the branch HEAD names renamed', lambda rng: renamed(rng, True),
        ev(['a branch renamed', 'HEAD switched to another branch']))

    # A branch on both sides at different commits, by the entries its reflog
    # gained: commits added (counted, or not with a fast-forward or merge),
    # each rewrite, several, entries that do not chain, another operation,
    # none (the reflog not a path of this diff). Each reverse: the reflog
    # is not a prefix -- it gained none.
    def moved(rng, entries_of, branch=b'main'):
        r, c = repo(rng), [oid() for _ in range(7)]
        base = [(Z, c[0], 'commit (initial): root')]
        new, last = entries_of(c)
        name = branch.decode()
        f = [(r + b'refs/heads/' + branch, git_loose(c[0]), git_loose(c[last]), O)]
        if new is not None:
            f.append((r + b'logs/refs/heads/' + branch, git_reflog(*base),
                      git_reflog(*(base + new)), O))
        return f
    one('git: commits added, counted',
        lambda rng: moved(rng, lambda c: ([(c[0], c[1], 'commit: one'),
                                           (c[1], c[2], 'cherry-pick: two'),
                                           (c[2], c[3], 'commit (merge): Merge branch x')], 3))
        + moved(rng, lambda c: ([(c[0], c[1], 'revert: Revert "one"'),
                                 (c[1], c[2], 'am: a patch')], 2), b'dev'),
        ev(['commits added, counted', 'a branch moved, its reflog gained none']))
    one('git: commits added by a fast-forward and merges, not counted',
        lambda rng: moved(rng, lambda c: ([(c[0], c[1], 'commit: one'),
                                           (c[1], c[2], 'merge topic: Fast-forward'),
                                           (c[2], c[3], "pull: Merge made by the 'ort' "
                                                        "strategy.")], 3))
        + moved(rng, lambda c: ([(c[0], c[1], "merge feature: Merge made by the 'ort' "
                                              "strategy.")], 1), b'dev'),
        ev(['commits added, not counted']))
    for trigger, msgs in [('reset', ['reset: moving to HEAD~1']),
                          ('commit (amend)', ['commit (amend): fix the typo']),
                          ('rebase', ['rebase (pick): one', 'rebase (finish): refs/heads/main '
                                                            'onto 1234']),
                          ('branch: Reset to', ['branch: Reset to topic']),
                          ('forced-update', ['fetch origin: forced-update'])]:
        one('git: history rewritten by %s' % trigger,
            lambda rng, msgs=msgs: moved(rng, lambda c: (
                [(c[i], c[i + 1], m) for i, m in enumerate(msgs)], len(msgs))),
            ev(['history rewritten by ' + trigger]))
    one('git: history rewritten by several operations',
        lambda rng: moved(rng, lambda c: ([(c[0], c[1], 'commit: one'),
                                           (c[1], c[2], 'reset: moving to HEAD~2'),
                                           (c[2], c[3], 'commit (amend): two'),
                                           (c[3], c[4], 'reset: moving to HEAD@{1}'),
                                           (c[4], c[5], 'pull --rebase (finish): x')], 5)),
        ev(['history rewritten by several operations']))
    one('git: a reflog whose entries do not lead to the value after',
        lambda rng: moved(rng, lambda c: ([(c[0], c[1], 'commit: one')], 2))
        + moved(rng, lambda c: ([(c[5], c[1], 'commit: one')], 1), b'dev')
        + moved(rng, lambda c: ([(c[0], c[1], 'commit: one'), (c[4], c[2], 'commit: two')], 2),
                b'gap'),
        ev(['a branch moved, its reflog entries not leading from before to after']))
    one('git: a branch moved by another operation',
        lambda rng: moved(rng, lambda c: ([(c[0], c[1], 'commit (initial): again')], 1)),
        ev(['a branch moved by another operation']))
    one('git: a branch moved, its reflog not a path of this diff',
        lambda rng: moved(rng, lambda c: (None, 1)),
        ev(['a branch moved, no reflog entries']))

    # HEAD: to another branch, detached (its reverse: attached), and
    # detached on both sides at different commits: the branch HEAD.
    def head(rng, frm, to, entries):
        r, c = repo(rng), [oid() for _ in range(4)]
        base = [(Z, c[0], 'commit (initial): root')]
        frm, to = (x(c) if callable(x) else x for x in (frm, to))
        return [(r + b'HEAD', git_head(frm), git_head(to), O),
                (r + b'logs/HEAD', git_reflog(*base), git_reflog(*(base + entries(c))), O)]
    one('git: HEAD switched to another branch',
        lambda rng: head(rng, 'main', 'dev', lambda c: [(c[0], c[1], 'checkout: moving from '
                                                                       'main to dev')]),
        ev(['HEAD switched to another branch']))
    one('git: HEAD detached',
        lambda rng: head(rng, 'main', lambda c: c[1],
                         lambda c: [(c[0], c[1], 'checkout: moving from main to ' + c[1])]),
        ev(['HEAD detached', 'HEAD attached']))
    one('git: a detached HEAD moved by commits',
        lambda rng: head(rng, lambda c: c[0], lambda c: c[2],
                         lambda c: [(c[0], c[1], 'commit: one'), (c[1], c[2], 'commit: two')]),
        ev(['a detached HEAD moved (the branch HEAD)', 'commits added, counted']))
    one('git: a detached HEAD reset',
        lambda rng: head(rng, lambda c: c[0], lambda c: c[1],
                         lambda c: [(c[0], c[1], 'reset: moving to HEAD~1')]),
        ev(['a detached HEAD moved (the branch HEAD)', 'history rewritten by reset']))

    # Repositories, nested and side by side, in their order (E4): the root's,
    # `g-h/` (`-` before `/`), `g/` and `g/h/` inside its working tree (names
    # no bystander of interp_tree() takes); in `g/`, HEAD's event before
    # branch `A` (which sorts before `HEAD`).
    def repos(rng):
        c = [oid() for _ in range(6)]
        return [(b'.git/refs/heads/zz', None, git_loose(c[0]), O),
                (b'.git/logs/refs/heads/zz', None,
                 git_reflog((Z, c[0], 'branch: Created from HEAD')), O),
                (b'g-h/.git/HEAD', git_head('main'), git_head('dev'), O),
                (b'g/.git/HEAD', git_head('main'), git_head('A'), O),
                (b'g/.git/refs/heads/A', None, git_loose(c[1]), O),
                (b'g/.git/logs/refs/heads/A', None,
                 git_reflog((Z, c[1], 'branch: Created from HEAD')), O),
                (b'g/h/.git/refs/heads/aa', None, git_loose(c[2]), O)]
    one('git: four repositories, nested', repos,
        ev(['events of two repositories', 'HEAD before a branch that sorts before it']))

    # An unknown ref: read where its copy can be (provisional events); with
    # no copy, a provisional content_unavailable event and nothing else.
    def raced(rng, **kw):
        r, c1 = repo(rng), oid()
        return [(r + b'refs/heads/hot', None, git_loose(c1), dict(raced=True, **kw)),
                (r + b'logs/refs/heads/hot', None,
                 git_reflog((Z, c1, 'branch: Created from main')), O)]
    one('git: a branch created, its ref raced', raced,
        ev(['an unknown ref read from its copy: provisional']))
    one('git: a branch created, its ref raced, no stored copy',
        lambda rng: raced(rng, unstored='after'),
        ev(['an unknown ref with no copy: a provisional content_unavailable event']))
    one('git: commits added, the ref raced on both sides',
        lambda rng: [(f[0], f[1], f[2], S(raced=True) if b'/logs/' not in b'/' + f[0] else f[3])
                     for f in moved(rng, lambda c: ([(c[0], c[1], 'commit: one')], 1))],
        ev(['an unknown ref read from its copy: provisional']))

    # packed-refs raced: the creation it is the evidence of is provisional.
    one('git: a branch created, packed-refs without it but raced',
        lambda rng: [(f[0], f[1], f[2], S(raced=True) if f[0].endswith(b'packed-refs') else f[3])
                     for f in created_by_packed(rng)],
        ev(['an unknown packed-refs read from its copy: provisional']))
    # A reflog that cannot be read decides nothing: no evidence of before.
    one('git: a branch created, its reflog\'s copy missing',
        lambda rng: [(f[0], f[1], f[2], S(lacking='after') if b'logs/' in f[0] else f[3])
                     for f in created_by_reflog(rng)],
        ev(['a branch whose reflog cannot be read: no evidence of before']))

    # A ref that is no ref: could_not_interpret, its record and one event.
    one('git: a ref that cannot be parsed',
        lambda rng: [(repo(rng) + b'refs/heads/bad', None, b'not an object id\n', O)],
        ev(['a ref that cannot be parsed']))

    # Tags and remote-tracking refs: their path findings, no event.
    def tags(rng):
        r, c = repo(rng), [oid() for _ in range(4)]
        return [(r + b'refs/tags/v2', None, git_loose(c[0]), O),
                (r + b'refs/remotes/origin/main', git_loose(c[1]), git_loose(c[2]), O),
                (r + b'logs/refs/remotes/origin/main',
                 git_reflog((Z, c[1], 'fetch: storing head')),
                 git_reflog((Z, c[1], 'fetch: storing head'), (c[1], c[2], 'fetch: fast-forward')),
                 O),
                (r + b'packed-refs', git_packed((c[3], 'refs/tags/v0')),
                 git_packed((c[3], 'refs/tags/v0'), (c[0], 'refs/tags/v1', c[1])), O)]
    one('git: tags and remote-tracking refs', tags,
        ev(['tags and remote-tracking refs read: no event']))

    # Copies the store cannot give: missing, corrupt (other bytes, a
    # symlink), over a loose ref's 64 KiB bound; one event per reason,
    # before a branch's own event.
    def unreadable(rng):
        r, c = repo(rng), [oid() for _ in range(6)]
        big = git_loose(c[5])[:-1] + b' ' * (64 * 1024 - 40) + b'\n'
        return [(r + b'refs/heads/w', git_loose(c[0]), git_loose(c[1]), S(lacking='after')),
                (r + b'refs/heads/x', git_loose(c[0]), git_loose(c[2]), S(corrupt='after')),
                (r + b'refs/heads/y', None, git_loose(c[3]), S(symlink='after')),
                (r + b'refs/heads/z', None, big, O),
                (r + b'refs/heads/new', None, git_loose(c[4]), O),
                (r + b'logs/refs/heads/new', None,
                 git_reflog((Z, c[4], 'branch: Created from HEAD')), O)]
    one('git: copies the store cannot give', unreadable,
        ev(['content_unavailable, missing', 'content_unavailable, corrupt',
            'content_unavailable, too_large', 'events with no name before the named']))


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
    mount_unverified(w, rng)
    mount_raced_type_changes(w, rng)
    xattrs_spellings(w, rng)
    values(w, rng)
    trailer_counts(w, rng)
    manifest_versions(w, rng)
    exclusions(w, rng)
    interpreters(w, rng)
    git_events(w, rng)


# ---------------------------------------------------------------------------
# Random pairs.

OPS = ['add', 'add', 'remove', 'content', 'size', 'mode', 'uid', 'gid', 'ino', 'dev', 'nlink',
       'ctime', 'mtime', 'type', 'flag', 'flag', 'unflag', 'iflags', 'caps', 'xattrs',
       'xattrs_sha256', 'xattrs_unknown', 'stored', 'limit', 'root_unstable', 'root_unreadable',
       'link', 'rdev', 'seal', 'unseal', 'remount', 'vanished', 'exclude', 'unexclude']
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
        elif op == 'unexclude':
            # The exclusion dropped: that path is walked again, and holds
            # something (a new entry, a directory with entries below it) or
            # nothing.
            if t.x:
                q = rng.choice(sorted(t.x))
                del t.x[q]
                if rng.random() < 0.7:
                    t.e[q] = new_entry(rng, t, q, random_type(rng))
                    if t.e[q]['type'] == 'dir':
                        for _ in range(rng.randrange(0, 3)):
                            r = fresh_path(t, rng, q)
                            t.e[r] = new_entry(rng, t, r, random_type(rng))
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
            elif op == 'exclude':
                exclude(t, p, 'state_dir' if rng.random() < 0.15 else 'user')
        fix(t, rng)


def randomized(w, rng, n):
    for i in range(n):
        base = Tree(rng)
        grow(base, rng, rng.randrange(3, 40))
        if rng.random() < 0.3:
            with_mounts(rng, base, rng.randrange(1, 3))
        if rng.random() < 0.3:                  # exclusions every variant starts from
            for _ in range(rng.randrange(1, 3)):
                ps = sorted(p for p in base.e if p != b'.')
                if ps:
                    exclude(base, rng.choice(ps), rng.choice(EXCLUDED_REASONS))
            fix(base, rng)
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
    w = Writer(out, seed)
    targeted(w, rng)
    w.check_gate()          # the targeted pairs alone: the random ones add variety only
    randomized(w, rng, n)
    refusals(w, rng)
    print(w.k)


if __name__ == '__main__':
    main()
