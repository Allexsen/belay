"""For each clean-hash mismatch against the truth, is the recorded hash the
sha256 of a prefix of the final file (a real intermediate state of a file
being written front to back) or not (bytes the file never held: torn)?"""
import json, sys, base64, hashlib, collections, os
root, truthp, *ms = sys.argv[1:]
def entries(p):
    with open(p) as f:
        for line in f:
            d = json.loads(line)
            if 'type' not in d: continue
            yield (d.get('path') or base64.b64decode(d['path_b64']).decode('latin1')), d
truth = {p: d.get('sha256') for p, d in entries(truthp) if d['type'] == 'reg'}
res = collections.Counter(); torn = []
for m in ms:
    for p, d in entries(m):
        if d['type'] != 'reg' or 'sha256' not in d or d.get('unstable') or d.get('raced') or d.get('unreadable'): continue
        t = truth.get(p)
        if t is None or t == d['sha256']: continue
        try: data = open(os.path.join(root, p), 'rb').read()
        except OSError: res['gone'] += 1; continue
        if d['size'] <= len(data) and hashlib.sha256(data[:d['size']]).hexdigest() == d['sha256']:
            res['prefix (real intermediate state)'] += 1
        else:
            res['NOT a prefix (torn)'] += 1; torn.append((m.rsplit('/',1)[-1], p, d['size'], len(data)))
print(dict(res)); print(torn[:20])
