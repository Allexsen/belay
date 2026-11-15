"""Torn-and-passed detector against a ground-truth manifest.

For every regular file recorded with a clean hash (sha256, none of
unstable/raced/unreadable) in a mid-workload manifest, compare with the
ground-truth manifest taken when the tree was quiet. Same path, same size and
same mtime_ns, different sha256: the recorded hash is of bytes the final file
never held while carrying its final metadata. Valid where the workload's
content is deterministic per path (npm ci from a lockfile; npm pins mtimes).
usage: oracle.py <truth.ndjson> <manifest>...
"""
import json, sys, base64, collections
def entries(p):
    with open(p) as f:
        for line in f:
            d = json.loads(line)
            if 'type' not in d: continue
            path = d.get('path') or base64.b64decode(d['path_b64']).decode('latin1')
            yield path, d
truth = {p: d for p, d in entries(sys.argv[1]) if d['type'] == 'reg'}
tot = collections.Counter(); bad = collections.Counter(); badsz = []
for m in sys.argv[2:]:
    for p, d in entries(m):
        if d['type'] != 'reg' or 'sha256' not in d: continue
        if d.get('unstable') or d.get('raced') or d.get('unreadable'): continue
        tot['clean_hashes'] += 1
        t = truth.get(p)
        if t is None or 'sha256' not in t: tot['no_truth'] += 1; continue
        if t['size'] != d['size'] or t['mtime_ns'] != d['mtime_ns']: tot['metadata_differs'] += 1; continue
        tot['comparable'] += 1
        if t['sha256'] != d['sha256']:
            bad[p] += 1; badsz.append(d['size'])
print(json.dumps({**tot, 'torn_passed': sum(bad.values()), 'torn_files': len(bad),
                  'examples': bad.most_common(10), 'sizes': sorted(badsz)[:20]}, indent=1))
