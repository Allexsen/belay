#!/usr/bin/env python3
"""Generates valid manifest pairs for the diff oracle.

    gen_corpus.py <out-dir> <n-bases> <seed>

Each base is a random tree written as a manifest that belay's reader
accepts (every rule of manifest-v1.md: field order, types and flags, header
rules, sorted paths, nothing below a sealed directory, the root, trailer
counts). Each base gets several mutated "after" manifests, one kind of
change or several at once -- content, metadata, identity, ctime alone, type
changes, every flag, sealing and unsealing directories, hash limits that
differ, names sorting before ".", non-UTF-8 names -- and explicitly
**orphans**: entries whose parent is missing from their own manifest.
Writes pair-NNNNN.before / .after; prints the number of pairs.
"""
import base64, copy, hashlib, json, os, random, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, '..', '..', 'docs', 'spec', 'manifest-v1.md')
TBITS = {'reg': 0o100000, 'dir': 0o040000, 'lnk': 0o120000, 'fifo': 0o010000,
         'sock': 0o140000, 'blk': 0o060000, 'chr': 0o020000}
NAMES = [b'a', b'b', b'c', b'a!b', b'a-b', b'a.b', b'!x', b'-y', b'.h', b'z', b'sub', b'caf\xc3\xa9',
         b'\xff\xfe', b'n1', b'n2', b'deep']


def key_order():
    """Entry keys in canonical order, from the spec's generated line."""
    text = open(SPEC).read()
    i = text.index('**Entry fields appear in one fixed order**')
    para = text[i:text.index('.\n', text.index('`raced`', i))]
    return re.findall(r'`([a-z0-9_]+)`', para)


ORDER = key_order()


def hexs(rng, n=64):
    return ''.join(rng.choice('0123456789abcdef') for _ in range(n))


def is_utf8(b):
    try:
        b.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def new_entry(rng, path, typ):
    e = {'type': typ, 'mode': TBITS[typ] | rng.choice([0o644, 0o600, 0o755, 0o700]),
         'uid': rng.choice([0, 1000]), 'gid': rng.choice([0, 1000]), 'size': 0,
         'mtime_ns': rng.randrange(1, 10**18), 'ctime_ns': rng.randrange(1, 10**18),
         'ino': rng.randrange(1, 10**6), 'dev': 2049, 'nlink': 1}
    if typ == 'reg':
        e['size'] = rng.randrange(0, 3000)
    elif typ == 'dir':
        e['size'], e['nlink'] = 4096, 2
    elif typ == 'lnk':
        e['link_target'] = 't%d' % rng.randrange(100)
        e['size'] = len(e['link_target'])
    elif typ in ('blk', 'chr'):
        e['rdev'] = rng.randrange(1, 70000)
    if typ in ('reg', 'dir') and rng.random() < 0.2:
        e['iflags'] = rng.choice([0, 16, 8192])
    if rng.random() < 0.15:
        names = sorted(rng.sample(['user.a', 'user.b', 'user.mime'], rng.randrange(1, 3)))
        e['xattrs'] = ['%s=%s' % (n, hexs(rng)) for n in names]
    elif rng.random() < 0.05:
        e['xattrs_sha256'] = hexs(rng)
    if typ == 'reg' and rng.random() < 0.05:
        e['caps'] = '0100000200200000'
    return e


class Tree:
    def __init__(self, rng):
        self.rng = rng
        self.limit = rng.choice([1000, 2000, 10**9])
        self.e = {b'.': new_entry(rng, b'.', 'dir')}
        for _ in range(rng.randrange(3, 40)):
            self.add_random()
        self.fix()

    def dirs(self):
        return [p for p, e in self.e.items() if e['type'] == 'dir' and not sealed(e)]

    def add_random(self, orphan=False):
        rng = self.rng
        if self.e[b'.'].get('unreadable') or not self.dirs():
            return                          # an unreadable root is the only entry
        parent = None if orphan else rng.choice(self.dirs())
        name = rng.choice(NAMES) + (b'%d' % rng.randrange(3) if rng.random() < 0.3 else b'')
        if orphan:
            base = rng.choice(NAMES) + b'_orphan%d' % rng.randrange(1000)
            path = base + b'/' + name                      # base itself never recorded
        else:
            path = name if parent == b'.' else parent + b'/' + name
        if path in self.e or len(path) > 200 or self.below_sealed(path):
            return
        typ = rng.choice(['reg'] * 5 + ['dir'] * 3 + ['lnk', 'fifo', 'sock', 'blk', 'chr'])
        self.e[path] = new_entry(rng, path, typ)

    def below_sealed(self, path):
        for p, e in self.e.items():
            if p != b'.' and e['type'] == 'dir' and sealed(e) and path.startswith(p + b'/'):
                return True
        return False

    def drop_below(self, path):
        for p in list(self.e):
            if p.startswith(path + b'/'):
                del self.e[p]

    def fix(self):
        """Restores every rule after a mutation."""
        root = self.e[b'.']
        root.pop('mount', None)
        root.pop('raced', None) if not (root.get('unreadable')) else None
        if root.get('unreadable'):
            self.e = {b'.': root}
        for p, e in list(self.e.items()):
            if p not in self.e:
                continue
            t = e['type']
            if t == 'dir' and sealed(e) and p != b'.':
                self.drop_below(p)
            if t == 'reg':
                reason = e.get('unstable') or e.get('unreadable') or e.get('mount')
                if reason:
                    e.pop('sha256', None)
                    e['unverified'] = True
                elif e['size'] <= self.limit:
                    e.pop('unverified', None)
                    e.setdefault('sha256', hexs(self.rng))
                else:
                    e.pop('sha256', None)
                    e['unverified'] = True
                if e.get('unstable') and e.get('unreadable'):
                    del e['unreadable']
                if e.get('mount'):
                    e.pop('unstable', None)
                    e.pop('unreadable', None)
            if t == 'dir':
                kinds = [k for k in ('unreadable', 'unstable', 'mount') if e.get(k)]
                for k in kinds[1:]:
                    del e[k]
                if e.get('raced') and not (e.get('unreadable') or e.get('mount')):
                    del e['raced']
            if t == 'lnk':
                if e.get('unreadable'):
                    if self.rng.random() < 0.5:
                        e['link_target'] = ''
                else:
                    if not e.get('link_target'):
                        e['link_target'] = 't1'
                    e['size'] = len(e['link_target'])
            if t not in ('reg', 'dir', 'lnk'):
                e.pop('unstable', None)
                e.pop('unreadable', None)
            if t != 'reg':
                for k in ('sha256', 'unverified', 'caps'):
                    e.pop(k, None)
                if t != 'dir':
                    e.pop('unstable', None)
            if e.get('mount'):
                for k in ('iflags', 'caps', 'xattrs', 'xattrs_sha256', 'xattrs_unknown', 'sha256'):
                    e.pop(k, None)
            if e.get('xattrs_unknown'):
                for k in ('xattrs', 'xattrs_sha256', 'caps'):
                    e.pop(k, None)

    def write(self, path):
        counts = dict(entries=0, unreadable=0, unstable=0, mounts=0, raced=0)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(json.dumps({'belay_manifest': 1, 'created_ns': 1, 'scopes': ['/scope'],
                                'hash': 'sha256', 'hash_max_bytes': self.limit,
                                'store_max_bytes': 0}, separators=(',', ':')) + '\n')
            for p in sorted(self.e):
                e = dict(self.e[p])
                if is_utf8(p):
                    e['path'] = p.decode()
                else:
                    e['path_b64'] = base64.b64encode(p).decode()
                f.write('{' + ','.join('"%s":%s' % (k, json.dumps(e[k], ensure_ascii=False,
                                                                     separators=(',', ':')))
                                       for k in ORDER if k in e) + '}\n')
                counts['entries'] += 1
                counts['unreadable'] += bool(e.get('unreadable'))
                counts['unstable'] += bool(e.get('unstable'))
                counts['mounts'] += bool(e.get('mount'))
                counts['raced'] += bool(e.get('raced'))
            f.write('{"belay_manifest_end":%d,"vanished":0,"unreadable":%d,"unstable":%d,'
                    '"mounts":%d,"raced":%d}\n' % (counts['entries'], counts['unreadable'],
                                                   counts['unstable'], counts['mounts'],
                                                   counts['raced']))


def sealed(e):
    return e.get('unreadable') or e.get('mount')


FLAGS = ['raced', 'unstable', 'unverified', 'unreadable', 'mount', 'xattrs_unknown']


def mutate(t, rng, ops):
    for _ in range(ops):
        paths = [p for p in t.e if p != b'.']
        op = rng.choice(['add', 'add', 'orphan', 'remove', 'remove_keep_children', 'content',
                         'size', 'mode', 'ino', 'ctime', 'mtime', 'type', 'flag', 'flag',
                         'unflag', 'xattrs', 'limit', 'root_unstable', 'root_unreadable',
                         'link'])
        if op == 'add':
            t.add_random()
        elif op == 'orphan':
            t.add_random(orphan=True)
        elif op == 'limit':
            t.limit = rng.choice([100, 1000, 2000, 10**9])
        elif op == 'root_unstable':
            t.e[b'.']['unstable'] = True
        elif op == 'root_unreadable' and rng.random() < 0.2:
            t.e[b'.'] = {k: v for k, v in t.e[b'.'].items() if k not in ('unstable',)}
            t.e[b'.']['unreadable'] = True
        elif not paths:
            continue
        else:
            p = rng.choice(paths)
            e = t.e[p]
            if op == 'remove':
                del t.e[p]
                t.drop_below(p)
            elif op == 'remove_keep_children':
                del t.e[p]                                  # its children become orphans
            elif op == 'content' and e['type'] == 'reg':
                e['sha256'] = hexs(rng)
            elif op == 'size' and e['type'] == 'reg':
                e['size'] = rng.randrange(0, 3000)
                e.pop('sha256', None)
            elif op == 'mode':
                e['mode'] = TBITS[e['type']] | rng.choice([0o644, 0o600, 0o755, 0o700, 0o4755])
            elif op == 'ino':
                e['ino'] = rng.randrange(1, 10**6)
            elif op == 'ctime':
                e['ctime_ns'] = rng.randrange(1, 10**18)
            elif op == 'mtime':
                e['mtime_ns'] = rng.randrange(1, 10**18)
            elif op == 'type':
                typ = rng.choice([x for x in TBITS if x != e['type']])
                t.e[p] = new_entry(rng, p, typ)
            elif op == 'flag':
                e[rng.choice(FLAGS)] = True
            elif op == 'unflag':
                for k in FLAGS:
                    e.pop(k, None)
            elif op == 'xattrs':
                e['xattrs'] = ['user.z=%s' % hexs(rng)]
                e.pop('xattrs_sha256', None)
            elif op == 'link' and e['type'] == 'lnk':
                e['link_target'] = 't%d' % rng.randrange(100)
        t.fix()


def main():
    out, n, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    os.makedirs(out, exist_ok=True)
    rng = random.Random(seed)
    k = 0
    for _ in range(n):
        base = Tree(rng)
        variants = [base]
        for _ in range(4):
            v = copy.deepcopy(base)
            v.rng = rng
            mutate(v, rng, rng.randrange(1, 6))
            variants.append(v)
        # every ordered pair of the five: identical, one change, many changes, reversed
        for i, b in enumerate(variants):
            for j, a in enumerate(variants):
                if rng.random() > 0.5 and i != j:
                    continue
                b.write(os.path.join(out, 'pair-%05d.before' % k))
                a.write(os.path.join(out, 'pair-%05d.after' % k))
                k += 1
    print(k)


if __name__ == '__main__':
    main()
