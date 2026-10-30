#!/usr/bin/env python3
"""Runs the driver and the reference on every pair; compares everything.
usage: compare.py <driver> <corpus-dir>"""
import base64, collections, glob, json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reference

driver, corpus = sys.argv[1], sys.argv[2]
pairs = sorted(glob.glob(os.path.join(corpus, 'pair-*.before')))
agree = differ = rejected = 0
outcomes = collections.Counter()
cover = collections.Counter()
examples = []
for b in pairs:
    a = b[:-len('.before')] + '.after'
    out = b[:-len('.before')] + '.diff'
    r = subprocess.run([driver, b, a, out], capture_output=True, text=True)
    if r.returncode != 0:
        rejected += 1
        if len(examples) < 5: examples.append(('rejected', os.path.basename(b), r.stderr.strip()))
        continue
    lines = [json.loads(l) for l in open(out, encoding='utf-8')]
    got = []
    for d in lines[1:-1]:
        d = dict(d)
        d['path'] = d['path'].encode() if 'path' in d else base64.b64decode(d.pop('path_b64'))
        got.append(d)
    trailer = lines[-1]
    want, counts = reference.compare(b, a)
    same = got == want and all(trailer[o] == counts[o] for o in counts) and \
        trailer['belay_diff_end'] == len(want)
    if same:
        agree += 1
        for o, c in counts.items(): outcomes[o] += c
        # coverage: what the agreeing pairs exercised
        eb = reference.load(b)[1]; ea = reference.load(a)[1]
        for rec in want:
            p = rec['path']
            side = ea if p in ea else eb
            parent = p.rsplit(b'/', 1)[0] if b'/' in p else b'.'
            if parent not in side: cover['orphan record'] += 1
            if p < b'.': cover['path sorting before "."'] += 1
            try: p.decode()
            except UnicodeDecodeError: cover['non-UTF-8 path'] += 1
            for r_ in rec.get('unknown', []): cover['reason ' + r_] += 1
        if reference.load(b)[0]['hash_max_bytes'] != reference.load(a)[0]['hash_max_bytes']:
            cover['pair with different hash limits'] += 1
    else:
        differ += 1
        if len(examples) < 5:
            gm = {x['path']: x for x in got}; wm = {x['path']: x for x in want}
            bad = [(p, gm.get(p), wm.get(p)) for p in sorted(set(gm) | set(wm)) if gm.get(p) != wm.get(p)][:3]
            examples.append(('differ', os.path.basename(b), bad, trailer, counts))
print(f"pairs: {len(pairs)}; agree {agree}; DIFFER {differ}; rejected by the reader {rejected}")
print("outcomes over agreeing pairs:", dict(outcomes))
print("coverage:", dict(sorted(cover.items())))
for e in examples: print(e)
sys.exit(1 if differ or rejected else 0)
